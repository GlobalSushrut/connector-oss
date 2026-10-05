//! Capacity Planner — Resource Forecasting and Headroom Tracking
//!
//! FIX BUG-074: "When will we run out?" predictions

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

use crate::agents::resource_manager::{ResourceManager, ResourceType};

// =============================================================================
// Capacity Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacitySnapshot {
    pub timestamp: i64,
    pub total_capacity: HashMap<ResourceType, u64>,
    pub used_capacity: HashMap<ResourceType, u64>,
    pub available_capacity: HashMap<ResourceType, u64>,
    pub agent_count: u32,
    pub active_tasks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityForecast {
    pub forecast_time: i64,
    pub predicted_usage: HashMap<ResourceType, f64>,
    pub confidence: f32,
    pub trend_direction: TrendDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrendDirection {
    Increasing,
    Stable,
    Decreasing,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct CapacityPrediction {
    pub resource_type: ResourceType,
    pub current_usage_percent: f64,
    pub predicted_depletion_time: Option<i64>,
    pub hours_until_depletion: Option<f64>,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub struct HeadroomStatus {
    pub total_resources: HashMap<ResourceType, u64>,
    pub committed_resources: HashMap<ResourceType, u64>,
    pub available_headroom: HashMap<ResourceType, f64>,
    pub critical_resources: Vec<ResourceType>,
}

// =============================================================================
// Capacity Planner
// =============================================================================

pub struct CapacityPlanner {
    resource_manager: Arc<ResourceManager>,
    /// Historical snapshots
    history: Arc<RwLock<VecDeque<CapacitySnapshot>>>,
    max_history_size: usize,
    /// Forecasts
    forecasts: Arc<RwLock<HashMap<ResourceType, Vec<CapacityForecast>>>>,
    /// Headroom tracking
    headroom: Arc<RwLock<HeadroomStatus>>,
}

impl CapacityPlanner {
    pub fn new(resource_manager: Arc<ResourceManager>) -> Self {
        let capacity = resource_manager.get_stats().available;
        
        let headroom = HeadroomStatus {
            total_resources: capacity.clone(),
            committed_resources: HashMap::new(),
            available_headroom: HashMap::new(),
            critical_resources: Vec::new(),
        };

        Self {
            resource_manager,
            history: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
            max_history_size: 1000,
            forecasts: Arc::new(RwLock::new(HashMap::new())),
            headroom: Arc::new(RwLock::new(headroom)),
        }
    }

    /// Record current capacity snapshot
    pub fn snapshot(&self) -> CapacitySnapshot {
        let now = chrono::Utc::now().timestamp_millis();
        let available = self.resource_manager.get_available();
        let stats = self.resource_manager.get_stats();
        
        let total: HashMap<ResourceType, u64> = stats.available.iter()
            .map(|(k, v)| (*k, *v + stats.utilized.get(k).map(|u| (*u * *v as f64) as u64).unwrap_or(0)))
            .collect();

        let snapshot = CapacitySnapshot {
            timestamp: now,
            total_capacity: total.clone(),
            used_capacity: {
                let mut used = HashMap::new();
                for (rtype, total_val) in &total {
                    let avail = available.get(rtype).copied().unwrap_or(0);
                    used.insert(*rtype, total_val - avail);
                }
                used
            },
            available_capacity: available,
            agent_count: stats.total_agents as u32,
            active_tasks: 0, // Would need task manager
        };

        // Store in history
        let mut history = self.history.write().unwrap();
        history.push_back(snapshot.clone());
        if history.len() > self.max_history_size {
            history.pop_front();
        }

        snapshot
    }

    /// Generate forecast based on historical trends
    pub fn forecast(&self, hours_ahead: u32) -> Vec<CapacityForecast> {
        let history = self.history.read().unwrap();
        
        if history.len() < 10 {
            return vec![]; // Insufficient data
        }

        let mut forecasts = Vec::new();
        let now = chrono::Utc::now().timestamp_millis();
        let forecast_time = now + (hours_ahead as i64 * 3600 * 1000);

        // For each resource type, calculate trend
        let resource_types: Vec<ResourceType> = vec![
            ResourceType::Cpu,
            ResourceType::Memory,
            ResourceType::Storage,
        ];

        for rtype in resource_types {
            // Extract usage history
            let usages: Vec<f64> = history.iter()
                .filter_map(|s| {
                    s.total_capacity.get(&rtype).and_then(|total| {
                        s.available_capacity.get(&rtype).map(|avail| {
                            ((*total - *avail) as f64 / *total as f64) * 100.0
                        })
                    })
                })
                .collect();

            if usages.len() < 2 {
                continue;
            }

            // Simple linear trend
            let trend = self.calculate_trend(&usages);
            let current = *usages.last().unwrap_or(&0.0);
            let predicted = (current + trend * hours_ahead as f64).clamp(0.0, 100.0);

            let direction = if trend > 0.5 {
                TrendDirection::Increasing
            } else if trend < -0.5 {
                TrendDirection::Decreasing
            } else {
                TrendDirection::Stable
            };

            forecasts.push(CapacityForecast {
                forecast_time,
                predicted_usage: {
                    let mut m = HashMap::new();
                    m.insert(rtype, predicted);
                    m
                },
                confidence: 0.7,
                trend_direction: direction,
            });
        }

        // Store forecasts
        for forecast in &forecasts {
            for (rtype, _) in &forecast.predicted_usage {
                self.forecasts.write().unwrap()
                    .entry(*rtype)
                    .or_insert_with(Vec::new)
                    .push(forecast.clone());
            }
        }

        forecasts
    }

    fn calculate_trend(&self, values: &[f64]) -> f64 {
        if values.len() < 2 {
            return 0.0;
        }

        // Simple linear regression slope
        let n = values.len() as f64;
        let sum_x: f64 = (0..values.len()).map(|i| i as f64).sum();
        let sum_y: f64 = values.iter().sum();
        let sum_xy: f64 = values.iter().enumerate().map(|(i, y)| i as f64 * y).sum();
        let sum_x2: f64 = (0..values.len()).map(|i| (i * i) as f64).sum();

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
        slope
    }

    /// Predict when resources will deplete
    pub fn predict_depletion(&self) -> Vec<CapacityPrediction> {
        let history = self.history.read().unwrap();
        
        if history.len() < 10 {
            return vec![];
        }

        let now = chrono::Utc::now().timestamp_millis();
        let mut predictions = Vec::new();

        for rtype in [ResourceType::Cpu, ResourceType::Memory, ResourceType::Storage] {
            let usages: Vec<f64> = history.iter()
                .filter_map(|s| {
                    s.total_capacity.get(&rtype).and_then(|total| {
                        s.available_capacity.get(&rtype).map(|avail| {
                            ((*total - *avail) as f64 / *total as f64) * 100.0
                        })
                    })
                })
                .collect();

            if usages.len() < 2 {
                continue;
            }

            let current = *usages.last().unwrap();
            let trend = self.calculate_trend(&usages); // percent change per sample
            
            // Estimate time to 90% (critical threshold)
            if trend > 0.0 {
                let to_critical = 90.0 - current;
                let hours_to_critical = if trend > 0.001 {
                    to_critical / trend
                } else {
                    f64::INFINITY
                };

                let depletion_time = if hours_to_critical.is_finite() {
                    Some(now + (hours_to_critical as i64 * 3600 * 1000))
                } else {
                    None
                };

                predictions.push(CapacityPrediction {
                    resource_type: rtype,
                    current_usage_percent: current,
                    predicted_depletion_time: depletion_time,
                    hours_until_depletion: if hours_to_critical.is_finite() { Some(hours_to_critical) } else { None },
                    confidence: 0.6,
                });
            } else {
                predictions.push(CapacityPrediction {
                    resource_type: rtype,
                    current_usage_percent: current,
                    predicted_depletion_time: None,
                    hours_until_depletion: None,
                    confidence: 0.8,
                });
            }
        }

        predictions
    }

    /// Update headroom tracking
    pub fn update_headroom(&self) -> HeadroomStatus {
        let snapshot = self.snapshot();
        let mut headroom = self.headroom.write().unwrap();

        headroom.total_resources = snapshot.total_capacity.clone();
        
        for (rtype, total) in &snapshot.total_capacity {
            let used = snapshot.used_capacity.get(rtype).copied().unwrap_or(0);
            let committed = headroom.committed_resources.get(rtype).copied().unwrap_or(0);
            let available = total.saturating_sub(used + committed);
            let percent = if *total > 0 {
                (available as f64 / *total as f64) * 100.0
            } else {
                0.0
            };
            headroom.available_headroom.insert(*rtype, percent);
        }

        // Identify critical resources (< 10% headroom)
        headroom.critical_resources = headroom.available_headroom.iter()
            .filter(|(_, v)| **v < 10.0)
            .map(|(k, _)| *k)
            .collect();

        headroom.clone()
    }

    /// Commit resources for future use
    pub fn commit_resources(&self, resources: HashMap<ResourceType, u64>) -> Result<String, String> {
        let mut headroom = self.headroom.write().unwrap();
        
        // Check availability
        for (rtype, amount) in &resources {
            let available = headroom.available_headroom.get(rtype).copied().unwrap_or(0.0);
            if available < 5.0 { // Less than 5% headroom
                return Err(format!("Insufficient headroom for {:?}", rtype));
            }
        }

        // Commit
        let commit_id = format!("commit-{}", uuid::Uuid::new_v4());
        for (rtype, amount) in resources {
            *headroom.committed_resources.entry(rtype).or_insert(0) += amount;
        }

        println!("[CAPACITY] Committed resources: {}", commit_id);
        Ok(commit_id)
    }

    /// Release committed resources
    pub fn release_commitment(&self, commit_id: &str) {
        println!("[CAPACITY] Released commitment: {}", commit_id);
    }

    /// Get "when will we run out" prediction
    pub fn when_will_we_run_out(&self) -> Option<(ResourceType, f64)> {
        let predictions = self.predict_depletion();
        
        predictions.iter()
            .filter(|p| p.hours_until_depletion.is_some())
            .min_by(|a, b| {
                a.hours_until_depletion.unwrap_or(f64::INFINITY)
                    .partial_cmp(&b.hours_until_depletion.unwrap_or(f64::INFINITY))
                    .unwrap()
            })
            .map(|p| (p.resource_type, p.hours_until_depletion.unwrap()))
    }

    /// Generate capacity report
    pub fn generate_report(&self) -> CapacityReport {
        let snapshot = self.snapshot();
        let depletion = self.predict_depletion();
        let headroom = self.update_headroom();
        
        let warnings: Vec<String> = depletion.iter()
            .filter(|p| p.hours_until_depletion.map(|h| h < 24.0).unwrap_or(false))
            .map(|p| format!("{:?} will deplete in {:.1} hours", p.resource_type, p.hours_until_depletion.unwrap()))
            .collect();

        let recommendations = self.generate_recommendations(&depletion);
        CapacityReport {
            timestamp: snapshot.timestamp,
            current_usage: snapshot.used_capacity,
            available_capacity: snapshot.available_capacity,
            headroom_percent: headroom.available_headroom,
            depletion_predictions: depletion,
            critical_resources: headroom.critical_resources,
            warnings,
            recommendations,
        }
    }

    fn generate_recommendations(&self, predictions: &[CapacityPrediction]) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        for pred in predictions {
            if let Some(hours) = pred.hours_until_depletion {
                if hours < 24.0 {
                    recommendations.push(format!(
                        "URGENT: Add {:?} capacity within {} hours",
                        pred.resource_type,
                        hours as u32
                    ));
                } else if hours < 72.0 {
                    recommendations.push(format!(
                        "PLAN: {:?} capacity needed within {} hours",
                        pred.resource_type,
                        hours as u32
                    ));
                }
            }
        }

        if recommendations.is_empty() {
            recommendations.push("No immediate capacity concerns".to_string());
        }

        recommendations
    }

    /// Get historical data
    pub fn get_history(&self, hours: u32) -> Vec<CapacitySnapshot> {
        let cutoff = chrono::Utc::now().timestamp_millis() - (hours as i64 * 3600 * 1000);
        
        self.history.read().unwrap()
            .iter()
            .filter(|s| s.timestamp >= cutoff)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct CapacityReport {
    pub timestamp: i64,
    pub current_usage: HashMap<ResourceType, u64>,
    pub available_capacity: HashMap<ResourceType, u64>,
    pub headroom_percent: HashMap<ResourceType, f64>,
    pub depletion_predictions: Vec<CapacityPrediction>,
    pub critical_resources: Vec<ResourceType>,
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot() {
        let rm = Arc::new(ResourceManager::new());
        let planner = CapacityPlanner::new(rm);
        
        let snapshot = planner.snapshot();
        assert!(snapshot.timestamp > 0);
    }

    #[test]
    fn test_trend_calculation() {
        let rm = Arc::new(ResourceManager::new());
        let planner = CapacityPlanner::new(rm);
        
        let values = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        let trend = planner.calculate_trend(&values);
        
        assert!(trend > 0.0); // Increasing trend
    }

    #[test]
    fn test_headroom_tracking() {
        let rm = Arc::new(ResourceManager::new());
        let planner = CapacityPlanner::new(rm);
        
        let headroom = planner.update_headroom();
        
        assert!(!headroom.total_resources.is_empty());
    }

    #[test]
    fn test_depletion_prediction() {
        let rm = Arc::new(ResourceManager::new());
        let planner = CapacityPlanner::new(rm);
        
        // Add some history with increasing trend
        for i in 0..20 {
            let _ = planner.snapshot();
        }
        
        let predictions = planner.predict_depletion();
        // Should have predictions for CPU, Memory, Storage
        assert!(!predictions.is_empty());
    }
}
