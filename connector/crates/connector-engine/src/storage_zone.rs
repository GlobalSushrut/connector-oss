//! # Storage Zones — OS Folder Model for the Agent Kernel
//!
//! Just as Linux organizes data into mount points (`/proc`, `/var/log`, `/etc`, `/home`),
//! the Agent OS organizes data into **StorageZones** — each zone has its own:
//! - **Durability** requirements (volatile, persistent, append-only)
//! - **Replication** policy (local-only, cluster-wide, quorum-write)
//! - **Retention** policy (forever, TTL-based, quota-based)
//! - **Backend** preference (in-memory, redb, SQLite)
//!
//! ## Cell-Scoped Layout
//!
//! Every piece of data belongs to a **Cell** (the distribution unit from `vac-cluster`).
//! The layout mirrors a filesystem:
//!
//! ```text
//! /cell:{cell_id}/
//! ├── audit/                     → append-only compliance trail
//! ├── agents/{pid}/
//! │   ├── behavior/              → behavioral profiles + scores
//! │   ├── breakers/              → circuit breaker state
//! │   ├── thresholds/            → adaptive threshold baselines
//! │   └── secrets/               → encrypted secrets (TTL)
//! ├── economy/
//! │   ├── escrow/                → financial escrow (ACID critical)
//! │   ├── reputation/            → feedback + stakes
//! │   └── negotiations/          → multi-round negotiations
//! ├── discovery/
//! │   ├── index/                 → agent capabilities (FTS)
//! │   └── knowledge/             → ingested knowledge docs (FTS)
//! ├── pipelines/                 → saga pipeline state
//! ├── routing/
//! │   ├── sessions/              → sticky session routes
//! │   └── messages/              → cross-cell message log
//! ├── config/
//! │   ├── policies/              → deny/allow rules
//! │   ├── tools/                 → tool definitions
//! │   └── watchdog/              → watchdog rules + fired history
//! ├── snapshots/                 → evicted agent context snapshots
//! └── kernel/                    → Ring 0 data (KernelStore)
//! ```
//!
//! ## Integration with Cell Architecture
//!
//! The `ClusterKernelStore` in `vac-cluster` uses the VFS trick: the kernel doesn't
//! know it's distributed. We follow the same pattern here:
//! - `EngineStore` is the local backend (SQLite/InMemory)
//! - `CellEngineStore` wraps local + replication (mirrors `ClusterKernelStore`)
//! - Zone replication policies control what gets replicated across cells

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Storage Zone — the "folders" of the Agent OS
// ═══════════════════════════════════════════════════════════════

/// A storage zone — analogous to a mount point in Linux.
///
/// Each zone has distinct durability, replication, and retention characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageZone {
    /// `/audit/` — append-only compliance trail. NEVER deleted.
    /// Durability: persistent. Replication: cluster-wide. Retention: forever.
    Audit,

    /// `/agents/{pid}/behavior/` — per-agent behavioral profiles.
    /// Durability: persistent. Replication: cluster-wide (agent migration).
    AgentBehavior,

    /// `/agents/{pid}/breakers/` — circuit breaker state.
    /// Durability: persistent. Replication: local-only (cell-specific).
    AgentBreakers,

    /// `/agents/{pid}/thresholds/` — adaptive threshold baselines.
    /// Durability: persistent. Replication: cluster-wide.
    AgentThresholds,

    /// `/agents/{pid}/secrets/` — encrypted secrets with TTL.
    /// Durability: persistent + encrypted. Replication: NEVER (security).
    AgentSecrets,

    /// `/economy/escrow/` — financial escrow accounts + settlements.
    /// Durability: persistent + ACID. Replication: quorum-write.
    EconomyEscrow,

    /// `/economy/reputation/` — feedback scores + stakes.
    /// Durability: persistent. Replication: cluster-wide.
    EconomyReputation,

    /// `/economy/negotiations/` — active multi-round negotiations.
    /// Durability: persistent. Replication: cluster-wide.
    EconomyNegotiations,

    /// `/discovery/index/` — agent capability index (FTS searchable).
    /// Durability: persistent. Replication: cluster-wide.
    DiscoveryIndex,

    /// `/discovery/knowledge/` — ingested knowledge documents (FTS).
    /// Durability: persistent. Replication: cluster-wide.
    DiscoveryKnowledge,

    /// `/pipelines/` — saga pipeline execution state.
    /// Durability: persistent. Replication: local-only (cell runs pipeline).
    Pipelines,

    /// `/routing/sessions/` — sticky session routes.
    /// Durability: volatile (TTL). Replication: local-only.
    RoutingSessions,

    /// `/routing/messages/` — cross-cell message log.
    /// Durability: persistent. Replication: cluster-wide.
    RoutingMessages,

    /// `/config/policies/` — deny/allow rules.
    /// Durability: persistent. Replication: cluster-wide.
    ConfigPolicies,

    /// `/config/tools/` — tool definitions.
    /// Durability: persistent. Replication: cluster-wide.
    ConfigTools,

    /// `/config/watchdog/` — watchdog rules + fired action history.
    /// Durability: persistent. Replication: cluster-wide.
    ConfigWatchdog,

    /// `/snapshots/` — evicted agent context snapshots.
    /// Durability: persistent. Replication: on-demand (agent migration).
    Snapshots,

    /// `/kernel/` — Ring 0 kernel data (packets, windows, SVs, audit).
    /// Managed by `KernelStore`, not `EngineStore`. Listed for completeness.
    Kernel,
}

impl StorageZone {
    /// The filesystem-style path prefix for this zone.
    pub fn path(&self) -> &'static str {
        match self {
            Self::Audit => "/audit",
            Self::AgentBehavior => "/agents/behavior",
            Self::AgentBreakers => "/agents/breakers",
            Self::AgentThresholds => "/agents/thresholds",
            Self::AgentSecrets => "/agents/secrets",
            Self::EconomyEscrow => "/economy/escrow",
            Self::EconomyReputation => "/economy/reputation",
            Self::EconomyNegotiations => "/economy/negotiations",
            Self::DiscoveryIndex => "/discovery/index",
            Self::DiscoveryKnowledge => "/discovery/knowledge",
            Self::Pipelines => "/pipelines",
            Self::RoutingSessions => "/routing/sessions",
            Self::RoutingMessages => "/routing/messages",
            Self::ConfigPolicies => "/config/policies",
            Self::ConfigTools => "/config/tools",
            Self::ConfigWatchdog => "/config/watchdog",
            Self::Snapshots => "/snapshots",
            Self::Kernel => "/kernel",
        }
    }

    /// Full cell-scoped path: `/cell:{cell_id}{zone_path}`
    pub fn cell_path(&self, cell_id: &str) -> String {
        format!("/cell:{}{}", cell_id, self.path())
    }

    /// All zones (excluding Kernel, which is managed by KernelStore).
    pub fn engine_zones() -> &'static [StorageZone] {
        &[
            Self::Audit, Self::AgentBehavior, Self::AgentBreakers,
            Self::AgentThresholds, Self::AgentSecrets,
            Self::EconomyEscrow, Self::EconomyReputation, Self::EconomyNegotiations,
            Self::DiscoveryIndex, Self::DiscoveryKnowledge,
            Self::Pipelines, Self::RoutingSessions, Self::RoutingMessages,
            Self::ConfigPolicies, Self::ConfigTools, Self::ConfigWatchdog,
            Self::Snapshots,
        ]
    }
}

impl std::fmt::Display for StorageZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path())
    }
}

// ═══════════════════════════════════════════════════════════════
// Zone Properties — durability, replication, retention
// ═══════════════════════════════════════════════════════════════

/// Durability requirement for a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Durability {
    /// Data lives only in memory. Lost on restart. (like `/tmp`)
    Volatile,
    /// Data persisted to disk. Survives restart. (like `/var/lib`)
    Persistent,
    /// Data persisted and NEVER deleted. (like `/var/log/audit`)
    AppendOnly,
}

/// Replication policy for a zone across cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationPolicy {
    /// Data stays on this cell only. No replication. (like local `/tmp`)
    LocalOnly,
    /// Data replicated to all cells (async, eventual consistency).
    ClusterWide,
    /// Data replicated with quorum acknowledgment (strong consistency).
    QuorumWrite,
    /// Data NEVER leaves this cell. Security-critical. (like `/etc/shadow`)
    NeverReplicate,
    /// Data replicated on-demand (e.g., when agent migrates between cells).
    OnDemand,
}

/// Retention policy for data in a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionPolicy {
    /// Keep forever. Never auto-delete.
    Forever,
    /// Auto-delete after TTL expires.
    TtlBased,
    /// Auto-evict oldest when quota exceeded.
    QuotaBased,
    /// Keep for a fixed number of entries, prune oldest.
    SlidingWindow,
}

/// Complete configuration for a storage zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneConfig {
    pub zone: StorageZone,
    pub durability: Durability,
    pub replication: ReplicationPolicy,
    pub retention: RetentionPolicy,
    /// Whether data in this zone should be encrypted at rest.
    pub encrypted: bool,
    /// Maximum entries before pruning (for QuotaBased/SlidingWindow).
    pub max_entries: Option<u64>,
    /// TTL in milliseconds (for TtlBased retention).
    pub ttl_ms: Option<i64>,
}

impl ZoneConfig {
    /// Get the default configuration for a zone.
    pub fn default_for(zone: StorageZone) -> Self {
        match zone {
            StorageZone::Audit => Self {
                zone, durability: Durability::AppendOnly,
                replication: ReplicationPolicy::ClusterWide,
                retention: RetentionPolicy::Forever,
                encrypted: false, max_entries: None, ttl_ms: None,
            },
            StorageZone::AgentBehavior => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::ClusterWide,
                retention: RetentionPolicy::Forever,
                encrypted: false, max_entries: None, ttl_ms: None,
            },
            StorageZone::AgentBreakers => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::LocalOnly,
                retention: RetentionPolicy::Forever,
                encrypted: false, max_entries: None, ttl_ms: None,
            },
            StorageZone::AgentThresholds => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::ClusterWide,
                retention: RetentionPolicy::SlidingWindow,
                encrypted: false, max_entries: Some(1000), ttl_ms: None,
            },
            StorageZone::AgentSecrets => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::NeverReplicate,
                retention: RetentionPolicy::TtlBased,
                encrypted: true, max_entries: None, ttl_ms: None,
            },
            StorageZone::EconomyEscrow => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::QuorumWrite,
                retention: RetentionPolicy::Forever,
                encrypted: false, max_entries: None, ttl_ms: None,
            },
            StorageZone::EconomyReputation => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::ClusterWide,
                retention: RetentionPolicy::Forever,
                encrypted: false, max_entries: None, ttl_ms: None,
            },
            StorageZone::EconomyNegotiations => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::ClusterWide,
                retention: RetentionPolicy::TtlBased,
                encrypted: false, max_entries: None, ttl_ms: Some(86_400_000),
            },
            StorageZone::DiscoveryIndex => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::ClusterWide,
                retention: RetentionPolicy::Forever,
                encrypted: false, max_entries: None, ttl_ms: None,
            },
            StorageZone::DiscoveryKnowledge => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::ClusterWide,
                retention: RetentionPolicy::QuotaBased,
                encrypted: false, max_entries: Some(100_000), ttl_ms: None,
            },
            StorageZone::Pipelines => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::LocalOnly,
                retention: RetentionPolicy::TtlBased,
                encrypted: false, max_entries: None, ttl_ms: Some(3_600_000),
            },
            StorageZone::RoutingSessions => Self {
                zone, durability: Durability::Volatile,
                replication: ReplicationPolicy::LocalOnly,
                retention: RetentionPolicy::TtlBased,
                encrypted: false, max_entries: None, ttl_ms: Some(300_000),
            },
            StorageZone::RoutingMessages => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::ClusterWide,
                retention: RetentionPolicy::SlidingWindow,
                encrypted: false, max_entries: Some(10_000), ttl_ms: None,
            },
            StorageZone::ConfigPolicies => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::ClusterWide,
                retention: RetentionPolicy::Forever,
                encrypted: false, max_entries: None, ttl_ms: None,
            },
            StorageZone::ConfigTools => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::ClusterWide,
                retention: RetentionPolicy::Forever,
                encrypted: false, max_entries: None, ttl_ms: None,
            },
            StorageZone::ConfigWatchdog => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::ClusterWide,
                retention: RetentionPolicy::SlidingWindow,
                encrypted: false, max_entries: Some(5_000), ttl_ms: None,
            },
            StorageZone::Snapshots => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::OnDemand,
                retention: RetentionPolicy::QuotaBased,
                encrypted: false, max_entries: Some(1_000), ttl_ms: None,
            },
            StorageZone::Kernel => Self {
                zone, durability: Durability::Persistent,
                replication: ReplicationPolicy::ClusterWide,
                retention: RetentionPolicy::Forever,
                encrypted: false, max_entries: None, ttl_ms: None,
            },
        }
    }

    /// Whether this zone should be replicated across cells.
    pub fn should_replicate(&self) -> bool {
        matches!(self.replication,
            ReplicationPolicy::ClusterWide | ReplicationPolicy::QuorumWrite)
    }

    /// Whether this zone requires strong consistency (quorum writes).
    pub fn requires_quorum(&self) -> bool {
        self.replication == ReplicationPolicy::QuorumWrite
    }
}

// ═══════════════════════════════════════════════════════════════
// Storage Layout — the complete "filesystem" for a cell
// ═══════════════════════════════════════════════════════════════

/// The complete storage layout for a cell — all zones with their configs.
///
/// Analogous to `/etc/fstab` in Linux — declares what's mounted where.
#[derive(Debug, Clone)]
pub struct StorageLayout {
    /// The cell this layout belongs to.
    pub cell_id: String,
    /// Per-zone configuration. Missing zones use defaults.
    pub zones: HashMap<StorageZone, ZoneConfig>,
}

impl StorageLayout {
    /// Create a default layout for a cell — all zones with production defaults.
    pub fn default_for_cell(cell_id: impl Into<String>) -> Self {
        let cell_id = cell_id.into();
        let mut zones = HashMap::new();
        for zone in StorageZone::engine_zones() {
            zones.insert(*zone, ZoneConfig::default_for(*zone));
        }
        zones.insert(StorageZone::Kernel, ZoneConfig::default_for(StorageZone::Kernel));
        Self { cell_id, zones }
    }

    /// Get the config for a zone (falls back to default if not configured).
    pub fn zone_config(&self, zone: StorageZone) -> ZoneConfig {
        self.zones.get(&zone)
            .cloned()
            .unwrap_or_else(|| ZoneConfig::default_for(zone))
    }

    /// Override the config for a specific zone.
    pub fn set_zone_config(&mut self, config: ZoneConfig) {
        self.zones.insert(config.zone, config);
    }

    /// Get the full path for a zone on this cell.
    pub fn zone_path(&self, zone: StorageZone) -> String {
        zone.cell_path(&self.cell_id)
    }

    /// List all zones that should be replicated.
    pub fn replicated_zones(&self) -> Vec<StorageZone> {
        self.zones.iter()
            .filter(|(_, cfg)| cfg.should_replicate())
            .map(|(zone, _)| *zone)
            .collect()
    }

    /// List all zones that require quorum writes.
    pub fn quorum_zones(&self) -> Vec<StorageZone> {
        self.zones.iter()
            .filter(|(_, cfg)| cfg.requires_quorum())
            .map(|(zone, _)| *zone)
            .collect()
    }

    /// List all zones with encrypted-at-rest requirement.
    pub fn encrypted_zones(&self) -> Vec<StorageZone> {
        self.zones.iter()
            .filter(|(_, cfg)| cfg.encrypted)
            .map(|(zone, _)| *zone)
            .collect()
    }

    /// List all zones that are append-only.
    pub fn append_only_zones(&self) -> Vec<StorageZone> {
        self.zones.iter()
            .filter(|(_, cfg)| cfg.durability == Durability::AppendOnly)
            .map(|(zone, _)| *zone)
            .collect()
    }

    /// Print the layout as a tree (for diagnostics).
    pub fn to_tree(&self) -> String {
        let mut lines = vec![format!("/cell:{}/", self.cell_id)];
        let mut sorted_zones: Vec<_> = self.zones.iter().collect();
        sorted_zones.sort_by_key(|(z, _)| z.path());
        for (zone, cfg) in sorted_zones {
            let flags = format!(
                "[{} | {} | {}{}]",
                match cfg.durability {
                    Durability::Volatile => "volatile",
                    Durability::Persistent => "persist",
                    Durability::AppendOnly => "append",
                },
                match cfg.replication {
                    ReplicationPolicy::LocalOnly => "local",
                    ReplicationPolicy::ClusterWide => "cluster",
                    ReplicationPolicy::QuorumWrite => "quorum",
                    ReplicationPolicy::NeverReplicate => "NEVER",
                    ReplicationPolicy::OnDemand => "on-demand",
                },
                match cfg.retention {
                    RetentionPolicy::Forever => "forever",
                    RetentionPolicy::TtlBased => "ttl",
                    RetentionPolicy::QuotaBased => "quota",
                    RetentionPolicy::SlidingWindow => "window",
                },
                if cfg.encrypted { " | encrypted" } else { "" },
            );
            lines.push(format!("├── {}  {}", zone.path(), flags));
        }
        lines.join("\n")
    }
}

// ═══════════════════════════════════════════════════════════════
// Zone-Aware Write Event (for cell replication)
// ═══════════════════════════════════════════════════════════════

/// A write event tagged with its storage zone.
/// Used by `CellEngineStore` to decide whether to replicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonedWriteEvent {
    /// Which zone this write belongs to.
    pub zone: StorageZone,
    /// The cell that originated this write.
    pub cell_id: String,
    /// Monotonic sequence number (from Cell.next_seq()).
    pub seq: u64,
    /// Serialized write operation.
    pub operation: String,
    /// Timestamp of the write.
    pub timestamp: i64,
}

impl ZonedWriteEvent {
    pub fn new(zone: StorageZone, cell_id: impl Into<String>, seq: u64, operation: impl Into<String>) -> Self {
        Self {
            zone,
            cell_id: cell_id.into(),
            seq,
            operation: operation.into(),
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zone_paths() {
        assert_eq!(StorageZone::Audit.path(), "/audit");
        assert_eq!(StorageZone::AgentSecrets.path(), "/agents/secrets");
        assert_eq!(StorageZone::EconomyEscrow.path(), "/economy/escrow");
        assert_eq!(StorageZone::Kernel.path(), "/kernel");
    }

    #[test]
    fn test_cell_scoped_paths() {
        assert_eq!(StorageZone::Audit.cell_path("cell_0"), "/cell:cell_0/audit");
        assert_eq!(StorageZone::AgentSecrets.cell_path("prod_1"), "/cell:prod_1/agents/secrets");
    }

    #[test]
    fn test_engine_zones_excludes_kernel() {
        let zones = StorageZone::engine_zones();
        assert!(!zones.contains(&StorageZone::Kernel));
        assert_eq!(zones.len(), 17);
    }

    #[test]
    fn test_default_layout() {
        let layout = StorageLayout::default_for_cell("cell_alpha");
        assert_eq!(layout.cell_id, "cell_alpha");
        // 17 engine zones + 1 kernel = 18 total
        assert_eq!(layout.zones.len(), 18);
    }

    #[test]
    fn test_zone_durability_defaults() {
        let cfg = ZoneConfig::default_for(StorageZone::Audit);
        assert_eq!(cfg.durability, Durability::AppendOnly);

        let cfg = ZoneConfig::default_for(StorageZone::RoutingSessions);
        assert_eq!(cfg.durability, Durability::Volatile);

        let cfg = ZoneConfig::default_for(StorageZone::EconomyEscrow);
        assert_eq!(cfg.durability, Durability::Persistent);
    }

    #[test]
    fn test_zone_replication_defaults() {
        let cfg = ZoneConfig::default_for(StorageZone::AgentSecrets);
        assert_eq!(cfg.replication, ReplicationPolicy::NeverReplicate);
        assert!(!cfg.should_replicate());

        let cfg = ZoneConfig::default_for(StorageZone::EconomyEscrow);
        assert_eq!(cfg.replication, ReplicationPolicy::QuorumWrite);
        assert!(cfg.should_replicate());
        assert!(cfg.requires_quorum());

        let cfg = ZoneConfig::default_for(StorageZone::Audit);
        assert_eq!(cfg.replication, ReplicationPolicy::ClusterWide);
        assert!(cfg.should_replicate());
        assert!(!cfg.requires_quorum());

        let cfg = ZoneConfig::default_for(StorageZone::RoutingSessions);
        assert_eq!(cfg.replication, ReplicationPolicy::LocalOnly);
        assert!(!cfg.should_replicate());
    }

    #[test]
    fn test_encrypted_zones() {
        let layout = StorageLayout::default_for_cell("cell_0");
        let encrypted = layout.encrypted_zones();
        assert_eq!(encrypted.len(), 1);
        assert!(encrypted.contains(&StorageZone::AgentSecrets));
    }

    #[test]
    fn test_replicated_zones() {
        let layout = StorageLayout::default_for_cell("cell_0");
        let replicated = layout.replicated_zones();
        // Audit, AgentBehavior, AgentThresholds, EconomyEscrow, EconomyReputation,
        // EconomyNegotiations, DiscoveryIndex, DiscoveryKnowledge, RoutingMessages,
        // ConfigPolicies, ConfigTools, ConfigWatchdog, Kernel = 13
        assert!(replicated.contains(&StorageZone::Audit));
        assert!(replicated.contains(&StorageZone::EconomyEscrow));
        assert!(!replicated.contains(&StorageZone::AgentSecrets));
        assert!(!replicated.contains(&StorageZone::RoutingSessions));
    }

    #[test]
    fn test_quorum_zones() {
        let layout = StorageLayout::default_for_cell("cell_0");
        let quorum = layout.quorum_zones();
        assert_eq!(quorum.len(), 1);
        assert!(quorum.contains(&StorageZone::EconomyEscrow));
    }

    #[test]
    fn test_append_only_zones() {
        let layout = StorageLayout::default_for_cell("cell_0");
        let ao = layout.append_only_zones();
        assert_eq!(ao.len(), 1);
        assert!(ao.contains(&StorageZone::Audit));
    }

    #[test]
    fn test_override_zone_config() {
        let mut layout = StorageLayout::default_for_cell("cell_0");
        let original = layout.zone_config(StorageZone::RoutingSessions);
        assert_eq!(original.durability, Durability::Volatile);

        // Override: make sessions persistent for production
        layout.set_zone_config(ZoneConfig {
            zone: StorageZone::RoutingSessions,
            durability: Durability::Persistent,
            replication: ReplicationPolicy::ClusterWide,
            retention: RetentionPolicy::TtlBased,
            encrypted: false,
            max_entries: None,
            ttl_ms: Some(600_000),
        });

        let updated = layout.zone_config(StorageZone::RoutingSessions);
        assert_eq!(updated.durability, Durability::Persistent);
        assert_eq!(updated.replication, ReplicationPolicy::ClusterWide);
    }

    #[test]
    fn test_tree_output() {
        let layout = StorageLayout::default_for_cell("demo_cell");
        let tree = layout.to_tree();
        assert!(tree.contains("/cell:demo_cell/"));
        assert!(tree.contains("/audit"));
        assert!(tree.contains("/agents/secrets"));
        assert!(tree.contains("NEVER"));
        assert!(tree.contains("encrypted"));
        assert!(tree.contains("quorum"));
    }

    #[test]
    fn test_zoned_write_event() {
        let evt = ZonedWriteEvent::new(
            StorageZone::Audit,
            "cell_0",
            42,
            "append_audit:{...}",
        );
        assert_eq!(evt.zone, StorageZone::Audit);
        assert_eq!(evt.cell_id, "cell_0");
        assert_eq!(evt.seq, 42);
        assert!(evt.timestamp > 0);
    }

    #[test]
    fn test_zone_display() {
        assert_eq!(format!("{}", StorageZone::Audit), "/audit");
        assert_eq!(format!("{}", StorageZone::EconomyEscrow), "/economy/escrow");
    }
}
