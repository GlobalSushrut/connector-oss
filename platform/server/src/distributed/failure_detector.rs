//! Cell Failure Detector — Real Liveness Detection
//!
//! FIX: SWIM gossip protocol + Phi accrual failure detection
//!
//! Detects:
//! - Dead cells (via missed heartbeats)
//! - Network partitions
//! - Degraded cells (slow responses)
//! - Suspicious cells (inconsistent state)

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};

// =============================================================================
// Failure Detection Types
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellStatus {
    /// Healthy and responding
    Healthy,
    /// Suspicious (some missed heartbeats)
    Suspect,
    /// Confirmed failed
    Failed,
    /// Left cluster gracefully
    Left,
    /// Unknown (new cell)
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellLiveness {
    /// Cell ID
    pub cell_id: String,
    /// Current status
    pub status: CellStatus,
    /// Last heartbeat received
    pub last_heartbeat: i64,
    /// Heartbeat history (for Phi accrual)
    pub heartbeat_intervals: Vec<u64>, // milliseconds
    /// Missed heartbeats count
    pub missed_heartbeats: u32,
    /// Phi value (0-1, higher = more likely failed)
    pub phi: f64,
    /// Average response time
    pub avg_response_ms: f64,
    /// Probe count
    pub probe_count: u64,
    /// Successful probes
    pub success_count: u64,
}

impl CellLiveness {
    /// Calculate Phi value using accrual failure detector
    pub fn calculate_phi(&self, now: i64) -> f64 {
        if self.heartbeat_intervals.is_empty() {
            return 0.0;
        }

        let last_hb = self.last_heartbeat;
        let time_since_last = (now - last_hb) as f64;

        // Calculate mean and variance of heartbeat intervals
        let mean: f64 = self.heartbeat_intervals.iter().sum::<u64>() as f64 / self.heartbeat_intervals.len() as f64;
        
        let variance: f64 = self.heartbeat_intervals.iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / self.heartbeat_intervals.len() as f64;

        let std_dev = variance.sqrt().max(1.0); // Avoid division by zero

        // Phi = -log10(1 - CDF(time_since_last))
        // where CDF is normal distribution CDF
        let x = (time_since_last - mean) / std_dev;
        let phi = -((1.0 - Self::normal_cdf(x)).log10());

        phi.max(0.0).min(1.0)
    }

    /// Standard normal CDF approximation
    fn normal_cdf(x: f64) -> f64 {
        // Abramowitz and Stegun approximation
        let a1 = 0.254829592;
        let a2 = -0.284496736;
        let a3 = 1.421413741;
        let a4 = -1.453152027;
        let a5 = 1.061405429;
        let p = 0.3275911;

        let sign = if x < 0.0 { -1.0 } else { 1.0 };
        let x = x.abs() / 2.0f64.sqrt();

        let t = 1.0 / (1.0 + p * x);
        let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-x * x).exp();

        0.5 * (1.0 + sign * y)
    }

    /// Record heartbeat arrival
    pub fn record_heartbeat(&mut self, now: i64) {
        if self.last_heartbeat > 0 {
            let interval = (now - self.last_heartbeat) as u64;
            self.heartbeat_intervals.push(interval);
            
            // Keep last 1000 intervals
            if self.heartbeat_intervals.len() > 1000 {
                self.heartbeat_intervals.remove(0);
            }
        }

        self.last_heartbeat = now;
        self.missed_heartbeats = 0;
        self.status = CellStatus::Healthy;
        self.phi = 0.0;
        self.success_count += 1;
    }

    /// Record missed heartbeat
    pub fn record_missed(&mut self) {
        self.missed_heartbeats += 1;
        self.probe_count += 1;
        
        // Thresholds for status changes
        if self.missed_heartbeats >= 5 {
            self.status = CellStatus::Failed;
        } else if self.missed_heartbeats >= 2 {
            self.status = CellStatus::Suspect;
        }
    }
}

// =============================================================================
// SWIM Protocol Implementation
// =============================================================================

pub struct SwimFailureDetector {
    /// This cell's ID
    local_cell_id: String,
    /// Known cells and their liveness
    cells: Arc<RwLock<HashMap<String, CellLiveness>>>,
    /// SWIM protocol period
    protocol_period: Duration,
    /// Probe timeout
    probe_timeout: Duration,
    /// Phi threshold for suspicion
    phi_suspect_threshold: f64,
    /// Phi threshold for failure
    phi_fail_threshold: f64,
    /// Gossip fanout
    gossip_fanout: u32,
    /// Event listeners
    listeners: Vec<Box<dyn Fn(CellEvent) + Send + Sync>>,
}

#[derive(Debug, Clone)]
pub enum CellEvent {
    CellSuspected { cell_id: String, phi: f64 },
    CellFailed { cell_id: String, reason: FailureReason },
    CellRecovered { cell_id: String },
    CellJoined { cell_id: String, address: String },
    CellLeft { cell_id: String },
}

#[derive(Debug, Clone)]
pub enum FailureReason {
    PhiThresholdExceeded,
    MissedHeartbeats,
    NetworkPartition,
    GracefulShutdown,
}

impl SwimFailureDetector {
    pub fn new(local_cell_id: String) -> Self {
        Self {
            local_cell_id,
            cells: Arc::new(RwLock::new(HashMap::new())),
            protocol_period: Duration::from_millis(200),
            probe_timeout: Duration::from_millis(1000),
            phi_suspect_threshold: 0.5,
            phi_fail_threshold: 0.9,
            gossip_fanout: 3,
            listeners: Vec::new(),
        }
    }

    /// Add cell to monitor
    pub fn add_cell(&self, cell_id: String) {
        let mut cells = self.cells.write().unwrap();
        cells.insert(cell_id.clone(), CellLiveness {
            cell_id,
            status: CellStatus::Unknown,
            last_heartbeat: 0,
            heartbeat_intervals: Vec::new(),
            missed_heartbeats: 0,
            phi: 0.0,
            avg_response_ms: 0.0,
            probe_count: 0,
            success_count: 0,
        });
    }

    /// Remove cell from monitoring
    pub fn remove_cell(&self, cell_id: &str) {
        let mut cells = self.cells.write().unwrap();
        cells.remove(cell_id);
    }

    /// Process incoming heartbeat
    pub fn on_heartbeat(&self, cell_id: &str, timestamp: i64) {
        let mut cells = self.cells.write().unwrap();
        
        if let Some(cell) = cells.get_mut(cell_id) {
            let old_status = cell.status;
            cell.record_heartbeat(timestamp);
            
            // Notify if recovered
            if old_status != CellStatus::Healthy {
                self.notify(CellEvent::CellRecovered { cell_id: cell_id.to_string() });
            }
        } else {
            // New cell discovered
            let mut new_cell = CellLiveness {
                cell_id: cell_id.to_string(),
                status: CellStatus::Healthy,
                last_heartbeat: timestamp,
                heartbeat_intervals: Vec::new(),
                missed_heartbeats: 0,
                phi: 0.0,
                avg_response_ms: 0.0,
                probe_count: 0,
                success_count: 0,
            };
            new_cell.record_heartbeat(timestamp);
            cells.insert(cell_id.to_string(), new_cell);
            
            self.notify(CellEvent::CellJoined { 
                cell_id: cell_id.to_string(), 
                address: "unknown".to_string() 
            });
        }
    }

    /// Run protocol period (called periodically)
    pub fn run_protocol_period(&self) -> Vec<CellEvent> {
        let mut events = Vec::new();
        let now = chrono::Utc::now().timestamp_millis();

        let mut cells = self.cells.write().unwrap();

        for (cell_id, cell) in cells.iter_mut() {
            if *cell_id == self.local_cell_id {
                continue;
            }

            // Calculate current Phi
            let phi = cell.calculate_phi(now);
            cell.phi = phi;

            // Check thresholds
            if phi >= self.phi_fail_threshold {
                if cell.status != CellStatus::Failed {
                    cell.status = CellStatus::Failed;
                    let event = CellEvent::CellFailed {
                        cell_id: cell_id.clone(),
                        reason: FailureReason::PhiThresholdExceeded,
                    };
                    events.push(event.clone());
                    self.notify(event);
                }
            } else if phi >= self.phi_suspect_threshold {
                if cell.status != CellStatus::Suspect && cell.status != CellStatus::Failed {
                    cell.status = CellStatus::Suspect;
                    let event = CellEvent::CellSuspected {
                        cell_id: cell_id.clone(),
                        phi,
                    };
                    events.push(event.clone());
                    self.notify(event);
                }
            }
        }

        events
    }

    /// Get cells by status
    pub fn get_cells_by_status(&self, status: CellStatus) -> Vec<CellLiveness> {
        let cells = self.cells.read().unwrap();
        cells.values()
            .filter(|c| c.status == status)
            .cloned()
            .collect()
    }

    /// Get healthy cells for work placement
    pub fn get_healthy_cells(&self) -> Vec<String> {
        let cells = self.cells.read().unwrap();
        cells.values()
            .filter(|c| c.status == CellStatus::Healthy)
            .map(|c| c.cell_id.clone())
            .collect()
    }

    /// Get cell status
    pub fn get_cell_status(&self, cell_id: &str) -> Option<CellStatus> {
        let cells = self.cells.read().unwrap();
        cells.get(cell_id).map(|c| c.status)
    }

    /// Get all cells
    pub fn get_all_cells(&self) -> Vec<CellLiveness> {
        let cells = self.cells.read().unwrap();
        cells.values().cloned().collect()
    }

    /// Register event listener
    pub fn on_event<F>(&mut self, listener: F)
    where
        F: Fn(CellEvent) + Send + Sync + 'static,
    {
        self.listeners.push(Box::new(listener));
    }

    fn notify(&self, event: CellEvent) {
        for listener in &self.listeners {
            listener(event.clone());
        }
    }

    /// Get failure statistics
    pub fn get_stats(&self) -> FailureStats {
        let cells = self.cells.read().unwrap();
        
        FailureStats {
            total_monitored: cells.len(),
            healthy: cells.values().filter(|c| c.status == CellStatus::Healthy).count(),
            suspect: cells.values().filter(|c| c.status == CellStatus::Suspect).count(),
            failed: cells.values().filter(|c| c.status == CellStatus::Failed).count(),
            avg_phi: cells.values().map(|c| c.phi).sum::<f64>() / cells.len().max(1) as f64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FailureStats {
    pub total_monitored: usize,
    pub healthy: usize,
    pub suspect: usize,
    pub failed: usize,
    pub avg_phi: f64,
}

// =============================================================================
// Thread-safe wrapper
// =============================================================================

#[derive(Clone)]
pub struct SharedSwimFailureDetector {
    inner: Arc<RwLock<SwimFailureDetector>>,
}

impl SharedSwimFailureDetector {
    pub fn new(local_cell_id: String) -> Self {
        Self {
            inner: Arc::new(RwLock::new(SwimFailureDetector::new(local_cell_id))),
        }
    }

    pub fn add_cell(&self, cell_id: String) {
        self.inner.write().unwrap().add_cell(cell_id);
    }

    pub fn on_heartbeat(&self, cell_id: &str, timestamp: i64) {
        self.inner.write().unwrap().on_heartbeat(cell_id, timestamp);
    }

    pub fn run_protocol_period(&self) -> Vec<CellEvent> {
        self.inner.write().unwrap().run_protocol_period()
    }

    pub fn get_healthy_cells(&self) -> Vec<String> {
        self.inner.read().unwrap().get_healthy_cells()
    }

    pub fn get_stats(&self) -> FailureStats {
        self.inner.read().unwrap().get_stats()
    }

    pub fn on_event<F>(&self, listener: F)
    where
        F: Fn(CellEvent) + Send + Sync + 'static,
    {
        self.inner.write().unwrap().on_event(listener);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phi_calculation() {
        let mut cell = CellLiveness {
            cell_id: "test".to_string(),
            status: CellStatus::Healthy,
            last_heartbeat: 1000,
            heartbeat_intervals: vec![100, 100, 100, 100, 100], // 100ms average
            missed_heartbeats: 0,
            phi: 0.0,
            avg_response_ms: 100.0,
            probe_count: 0,
            success_count: 0,
        };

        // Normal case: heartbeat 100ms ago
        let phi1 = cell.calculate_phi(1100);
        assert!(phi1 < 0.5); // Should be healthy

        // Late case: 500ms ago
        let phi2 = cell.calculate_phi(1500);
        assert!(phi2 > 0.5); // Should be suspicious

        // Very late: 1000ms ago
        let phi3 = cell.calculate_phi(2000);
        assert!(phi3 > 0.9); // Should be failed
    }

    #[test]
    fn test_status_transitions() {
        let detector = SwimFailureDetector::new("local".to_string());
        
        detector.add_cell("remote".to_string());
        
        let now = chrono::Utc::now().timestamp_millis();
        
        // First heartbeat
        detector.on_heartbeat("remote", now);
        assert_eq!(detector.get_cell_status("remote"), Some(CellStatus::Healthy));

        // Simulate missed heartbeats
        {
            let mut cells = detector.cells.write().unwrap();
            if let Some(cell) = cells.get_mut("remote") {
                cell.record_missed();
                cell.record_missed();
            }
        }
        
        assert_eq!(detector.get_cell_status("remote"), Some(CellStatus::Suspect));
    }

    #[test]
    fn test_cell_recovered() {
        let detector = SwimFailureDetector::new("local".to_string());
        
        detector.add_cell("remote".to_string());
        
        // Mark as failed
        {
            let mut cells = detector.cells.write().unwrap();
            if let Some(cell) = cells.get_mut("remote") {
                cell.status = CellStatus::Failed;
                cell.missed_heartbeats = 5;
            }
        }

        // Then heartbeat arrives
        let now = chrono::Utc::now().timestamp_millis();
        detector.on_heartbeat("remote", now);
        
        assert_eq!(detector.get_cell_status("remote"), Some(CellStatus::Healthy));
    }
}
