//! Topology Discovery — Network Topology & Latency Measurement

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyLink {
    pub from_cell: String,
    pub to_cell: String,
    pub rtt_ms: u64,
    pub bandwidth_mbps: u32,
    pub health: LinkHealth,
    pub last_measured: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkHealth { Excellent, Good, Fair, Poor, Failed }

impl LinkHealth {
    pub fn from_metrics(rtt_ms: u64, loss: f64) -> Self {
        match (rtt_ms, loss) {
            (r, l) if r < 10 && l < 0.001 => LinkHealth::Excellent,
            (r, l) if r < 50 && l < 0.001 => LinkHealth::Good,
            (r, l) if r < 100 && l < 0.01 => LinkHealth::Fair,
            (r, l) if r < 500 && l < 0.05 => LinkHealth::Poor,
            _ => LinkHealth::Failed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPath {
    pub path_id: String,
    pub from_cell: String,
    pub to_cell: String,
    pub hops: Vec<String>,
    pub total_rtt_ms: u64,
    pub health: PathHealth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathHealth { Optimal, Usable, Degraded, Avoid }

pub struct TopologyDiscovery {
    local_cell_id: String,
    links: Arc<RwLock<HashMap<(String, String), TopologyLink>>>,
    paths: Arc<RwLock<HashMap<(String, String), Vec<NetworkPath>>>>,
}

impl TopologyDiscovery {
    pub fn new(local_cell_id: String) -> Self {
        Self {
            local_cell_id,
            links: Arc::new(RwLock::new(HashMap::new())),
            paths: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn measure_link(&self, cell_id: &str) -> Result<TopologyLink, String> {
        let start = Instant::now();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let elapsed = start.elapsed().as_millis() as u64;
        
        Ok(TopologyLink {
            from_cell: self.local_cell_id.clone(),
            to_cell: cell_id.to_string(),
            rtt_ms: elapsed.max(5),
            bandwidth_mbps: 1000,
            health: LinkHealth::Good,
            last_measured: chrono::Utc::now().timestamp_millis(),
        })
    }

    pub fn add_link(&self, link: TopologyLink) {
        let mut links = self.links.write().unwrap();
        links.insert((link.from_cell.clone(), link.to_cell.clone()), link);
    }

    pub fn compute_paths(&self) {
        let links = self.links.read().unwrap();
        let mut paths = self.paths.write().unwrap();
        paths.clear();
        
        for ((from, to), link) in links.iter() {
            let path = NetworkPath {
                path_id: format!("path-{}-{}", from, to),
                from_cell: from.clone(),
                to_cell: to.clone(),
                hops: vec![from.clone(), to.clone()],
                total_rtt_ms: link.rtt_ms,
                health: PathHealth::Usable,
            };
            paths.insert((from.clone(), to.clone()), vec![path]);
        }
    }

    pub fn get_best_path(&self, from: &str, to: &str) -> Option<NetworkPath> {
        let paths = self.paths.read().unwrap();
        paths.get(&(from.to_string(), to.to_string()))?.first().cloned()
    }

    pub fn detect_partitions(&self) -> Vec<HashSet<String>> {
        let links = self.links.read().unwrap();
        let mut adj: HashMap<String, HashSet<String>> = HashMap::new();
        
        for ((from, to), link) in links.iter() {
            if link.health != LinkHealth::Failed {
                adj.entry(from.clone()).or_default().insert(to.clone());
                adj.entry(to.clone()).or_default().insert(from.clone());
            }
        }

        let mut visited = HashSet::new();
        let mut partitions = Vec::new();

        for cell in adj.keys() {
            if visited.contains(cell) { continue; }
            
            let mut component = HashSet::new();
            let mut stack = vec![cell.clone()];
            
            while let Some(current) = stack.pop() {
                if visited.insert(current.clone()) {
                    component.insert(current.clone());
                    if let Some(neighbors) = adj.get(&current) {
                        for n in neighbors {
                            if !visited.contains(n) { stack.push(n.clone()); }
                        }
                    }
                }
            }
            partitions.push(component);
        }
        partitions
    }

    pub fn get_nearest(&self, from: &str, n: usize) -> Vec<(String, u64)> {
        let links = self.links.read().unwrap();
        let mut neighbors: Vec<_> = links.iter()
            .filter(|((f, _), _)| f == from)
            .map(|((_, to), link)| (to.clone(), link.rtt_ms))
            .collect();
        neighbors.sort_by_key(|(_, rtt)| *rtt);
        neighbors.truncate(n);
        neighbors
    }
}

#[derive(Clone)]
pub struct SharedTopologyDiscovery {
    inner: Arc<TopologyDiscovery>,
}

impl SharedTopologyDiscovery {
    pub fn new(local_cell_id: String) -> Self {
        Self { inner: Arc::new(TopologyDiscovery::new(local_cell_id)) }
    }
    pub fn get_best_path(&self, from: &str, to: &str) -> Option<NetworkPath> {
        self.inner.get_best_path(from, to)
    }
    pub fn detect_partitions(&self) -> Vec<HashSet<String>> {
        self.inner.detect_partitions()
    }
}
