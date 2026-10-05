//! Database & Kernel State Migrations
//!
//! This module implements versioned migrations for:
//! - Database schema migrations
//! - Kernel state migrations
//! - Backward compatibility management
//!
//! Design sources: Rails migrations, Flyway, Alembic

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Migration Types
// =============================================================================

/// Migration version (semver-like)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MigrationVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl MigrationVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err("Version must be in format X.Y.Z".into());
        }
        Ok(Self {
            major: parts[0].parse().map_err(|_| "Invalid major version")?,
            minor: parts[1].parse().map_err(|_| "Invalid minor version")?,
            patch: parts[2].parse().map_err(|_| "Invalid patch version")?,
        })
    }

    pub fn to_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }
}

impl std::fmt::Display for MigrationVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Migration status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    Pending,
    Running,
    Completed,
    Failed,
    RolledBack,
}

/// Migration type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationType {
    Schema,
    Data,
    Kernel,
    Config,
}

// =============================================================================
// Schema Migration
// =============================================================================

/// Database schema migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaMigration {
    /// Migration ID (timestamp-based)
    pub id: String,
    /// Version
    pub version: MigrationVersion,
    /// Description
    pub description: String,
    /// Up SQL
    pub up_sql: String,
    /// Down SQL (rollback)
    pub down_sql: String,
    /// Checksum
    pub checksum: String,
    /// Dependencies
    pub depends_on: Vec<String>,
    /// Reversible flag
    pub reversible: bool,
}

impl SchemaMigration {
    pub fn new(id: &str, version: MigrationVersion, description: &str) -> Self {
        Self {
            id: id.into(),
            version,
            description: description.into(),
            up_sql: String::new(),
            down_sql: String::new(),
            checksum: String::new(),
            depends_on: vec![],
            reversible: true,
        }
    }

    pub fn with_up(mut self, sql: &str) -> Self {
        self.up_sql = sql.into();
        self.checksum = Self::compute_checksum(sql);
        self
    }

    pub fn with_down(mut self, sql: &str) -> Self {
        self.down_sql = sql.into();
        self
    }

    pub fn irreversible(mut self) -> Self {
        self.reversible = false;
        self
    }

    fn compute_checksum(sql: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        sql.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }
}

/// Migration record (stored in DB)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub id: String,
    pub version: String,
    pub description: String,
    pub checksum: String,
    pub status: MigrationStatus,
    pub applied_at: Option<i64>,
    pub rolled_back_at: Option<i64>,
    pub execution_time_ms: u64,
    pub error: Option<String>,
}

// =============================================================================
// Kernel State Migration
// =============================================================================

/// Kernel state migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelMigration {
    /// Migration ID
    pub id: String,
    /// From version
    pub from_version: MigrationVersion,
    /// To version
    pub to_version: MigrationVersion,
    /// Description
    pub description: String,
    /// Migration steps
    pub steps: Vec<KernelMigrationStep>,
    /// Reversible
    pub reversible: bool,
}

/// Kernel migration step
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KernelMigrationStep {
    /// Transform MemPacket format
    TransformPacket {
        field: String,
        transform: String,
    },
    /// Add new field with default
    AddField {
        field: String,
        default_value: serde_json::Value,
    },
    /// Remove field
    RemoveField {
        field: String,
    },
    /// Rename field
    RenameField {
        from: String,
        to: String,
    },
    /// Reindex
    Reindex {
        index_name: String,
    },
    /// Custom migration function
    Custom {
        function: String,
        params: HashMap<String, serde_json::Value>,
    },
}

impl KernelMigration {
    pub fn new(id: &str, from: MigrationVersion, to: MigrationVersion, description: &str) -> Self {
        Self {
            id: id.into(),
            from_version: from,
            to_version: to,
            description: description.into(),
            steps: vec![],
            reversible: true,
        }
    }

    pub fn add_step(mut self, step: KernelMigrationStep) -> Self {
        self.steps.push(step);
        self
    }
}

// =============================================================================
// Migration Manager
// =============================================================================

/// Migration manager
#[derive(Debug, Default)]
pub struct MigrationManager {
    /// Schema migrations
    schema_migrations: Vec<SchemaMigration>,
    /// Kernel migrations
    kernel_migrations: Vec<KernelMigration>,
    /// Applied migrations
    applied: HashMap<String, MigrationRecord>,
    /// Current schema version
    current_schema_version: Option<MigrationVersion>,
    /// Current kernel version
    current_kernel_version: Option<MigrationVersion>,
}

impl MigrationManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a schema migration
    pub fn register_schema(&mut self, migration: SchemaMigration) {
        self.schema_migrations.push(migration);
        self.schema_migrations.sort_by(|a, b| a.version.cmp(&b.version));
    }

    /// Register a kernel migration
    pub fn register_kernel(&mut self, migration: KernelMigration) {
        self.kernel_migrations.push(migration);
        self.kernel_migrations.sort_by(|a, b| a.to_version.cmp(&b.to_version));
    }

    /// Set current versions
    pub fn set_current_versions(&mut self, schema: MigrationVersion, kernel: MigrationVersion) {
        self.current_schema_version = Some(schema);
        self.current_kernel_version = Some(kernel);
    }

    /// Mark migration as applied
    pub fn mark_applied(&mut self, record: MigrationRecord) {
        self.applied.insert(record.id.clone(), record);
    }

    /// Get pending schema migrations
    pub fn pending_schema(&self) -> Vec<&SchemaMigration> {
        self.schema_migrations.iter()
            .filter(|m| !self.applied.contains_key(&m.id))
            .collect()
    }

    /// Get pending kernel migrations
    pub fn pending_kernel(&self) -> Vec<&KernelMigration> {
        let current = self.current_kernel_version.as_ref();
        self.kernel_migrations.iter()
            .filter(|m| {
                !self.applied.contains_key(&m.id) &&
                current.map(|c| m.from_version <= *c).unwrap_or(true)
            })
            .collect()
    }

    /// Check if migration is needed
    pub fn needs_migration(&self) -> bool {
        !self.pending_schema().is_empty() || !self.pending_kernel().is_empty()
    }

    /// Get migration plan
    pub fn plan(&self) -> MigrationPlan {
        MigrationPlan {
            schema_migrations: self.pending_schema().into_iter().cloned().collect(),
            kernel_migrations: self.pending_kernel().into_iter().cloned().collect(),
            estimated_time_ms: self.estimate_time(),
            requires_downtime: self.requires_downtime(),
        }
    }

    fn estimate_time(&self) -> u64 {
        let schema_time: u64 = self.pending_schema().len() as u64 * 1000;
        let kernel_time: u64 = self.pending_kernel().iter()
            .map(|m| m.steps.len() as u64 * 500)
            .sum();
        schema_time + kernel_time
    }

    fn requires_downtime(&self) -> bool {
        self.pending_schema().iter().any(|m| !m.reversible) ||
        self.pending_kernel().iter().any(|m| !m.reversible)
    }

    /// Execute schema migration
    pub fn execute_schema(&mut self, migration: &SchemaMigration) -> Result<MigrationRecord, String> {
        let start = std::time::Instant::now();

        // In real implementation, execute SQL
        // For now, simulate success
        let record = MigrationRecord {
            id: migration.id.clone(),
            version: migration.version.to_string(),
            description: migration.description.clone(),
            checksum: migration.checksum.clone(),
            status: MigrationStatus::Completed,
            applied_at: Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64),
            rolled_back_at: None,
            execution_time_ms: start.elapsed().as_millis() as u64,
            error: None,
        };

        self.applied.insert(record.id.clone(), record.clone());
        self.current_schema_version = Some(migration.version.clone());

        Ok(record)
    }

    /// Rollback schema migration
    pub fn rollback_schema(&mut self, migration_id: &str) -> Result<(), String> {
        let migration = self.schema_migrations.iter()
            .find(|m| m.id == migration_id)
            .ok_or("Migration not found")?;

        if !migration.reversible {
            return Err("Migration is not reversible".into());
        }

        // In real implementation, execute down SQL
        if let Some(record) = self.applied.get_mut(migration_id) {
            record.status = MigrationStatus::RolledBack;
            record.rolled_back_at = Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64);
        }

        Ok(())
    }

    /// Get applied migrations
    pub fn applied(&self) -> Vec<&MigrationRecord> {
        self.applied.values().collect()
    }
}

/// Migration plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub schema_migrations: Vec<SchemaMigration>,
    pub kernel_migrations: Vec<KernelMigration>,
    pub estimated_time_ms: u64,
    pub requires_downtime: bool,
}

// =============================================================================
// Backward Compatibility
// =============================================================================

/// Compatibility window definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityWindow {
    /// Minimum supported version
    pub min_version: MigrationVersion,
    /// Maximum supported version
    pub max_version: MigrationVersion,
    /// Deprecation warnings
    pub deprecations: Vec<Deprecation>,
    /// Breaking changes
    pub breaking_changes: Vec<BreakingChange>,
}

/// Deprecation notice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deprecation {
    /// Feature being deprecated
    pub feature: String,
    /// Deprecated in version
    pub deprecated_in: MigrationVersion,
    /// Removed in version
    pub removed_in: Option<MigrationVersion>,
    /// Replacement
    pub replacement: Option<String>,
    /// Migration guide
    pub migration_guide: Option<String>,
}

/// Breaking change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakingChange {
    /// Change description
    pub description: String,
    /// Introduced in version
    pub version: MigrationVersion,
    /// Affected components
    pub affected: Vec<String>,
    /// Migration steps
    pub migration_steps: Vec<String>,
}

impl CompatibilityWindow {
    pub fn new(min: MigrationVersion, max: MigrationVersion) -> Self {
        Self {
            min_version: min,
            max_version: max,
            deprecations: vec![],
            breaking_changes: vec![],
        }
    }

    pub fn is_compatible(&self, version: &MigrationVersion) -> bool {
        version >= &self.min_version && version <= &self.max_version
    }

    pub fn add_deprecation(&mut self, deprecation: Deprecation) {
        self.deprecations.push(deprecation);
    }

    pub fn add_breaking_change(&mut self, change: BreakingChange) {
        self.breaking_changes.push(change);
    }

    pub fn get_deprecations_for(&self, version: &MigrationVersion) -> Vec<&Deprecation> {
        self.deprecations.iter()
            .filter(|d| &d.deprecated_in <= version)
            .collect()
    }
}

// =============================================================================
// Built-in Migrations
// =============================================================================

/// Get built-in schema migrations
pub fn builtin_schema_migrations() -> Vec<SchemaMigration> {
    vec![
        SchemaMigration::new(
            "20240101000000_initial",
            MigrationVersion::new(0, 1, 0),
            "Initial schema"
        ).with_up(r#"
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (agent_id) REFERENCES agents(id)
            );
            CREATE TABLE IF NOT EXISTS migrations (
                id TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                checksum TEXT NOT NULL,
                applied_at INTEGER NOT NULL
            );
        "#).with_down(r#"
            DROP TABLE IF EXISTS migrations;
            DROP TABLE IF EXISTS sessions;
            DROP TABLE IF EXISTS agents;
        "#),

        SchemaMigration::new(
            "20240102000000_add_token_budget",
            MigrationVersion::new(0, 2, 0),
            "Add token budget columns"
        ).with_up(r#"
            ALTER TABLE agents ADD COLUMN token_budget INTEGER DEFAULT 100000;
            ALTER TABLE agents ADD COLUMN tokens_used INTEGER DEFAULT 0;
            ALTER TABLE sessions ADD COLUMN token_budget INTEGER DEFAULT 10000;
            ALTER TABLE sessions ADD COLUMN tokens_used INTEGER DEFAULT 0;
        "#).with_down(r#"
            -- SQLite doesn't support DROP COLUMN, would need table recreation
        "#),

        SchemaMigration::new(
            "20240103000000_add_audit_log",
            MigrationVersion::new(0, 3, 0),
            "Add audit log table"
        ).with_up(r#"
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                agent_id TEXT,
                session_id TEXT,
                action TEXT NOT NULL,
                details TEXT,
                hash TEXT NOT NULL
            );
            CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
            CREATE INDEX idx_audit_agent ON audit_log(agent_id);
        "#).with_down(r#"
            DROP INDEX IF EXISTS idx_audit_agent;
            DROP INDEX IF EXISTS idx_audit_timestamp;
            DROP TABLE IF EXISTS audit_log;
        "#),
    ]
}

/// Get built-in kernel migrations
pub fn builtin_kernel_migrations() -> Vec<KernelMigration> {
    vec![
        KernelMigration::new(
            "kernel_0_1_to_0_2",
            MigrationVersion::new(0, 1, 0),
            MigrationVersion::new(0, 2, 0),
            "Add metadata field to MemPackets"
        ).add_step(KernelMigrationStep::AddField {
            field: "metadata".into(),
            default_value: serde_json::json!({}),
        }),

        KernelMigration::new(
            "kernel_0_2_to_0_3",
            MigrationVersion::new(0, 2, 0),
            MigrationVersion::new(0, 3, 0),
            "Rename timestamp to created_at"
        ).add_step(KernelMigrationStep::RenameField {
            from: "timestamp".into(),
            to: "created_at".into(),
        }).add_step(KernelMigrationStep::AddField {
            field: "updated_at".into(),
            default_value: serde_json::json!(0),
        }),
    ]
}

/// Get default compatibility window
pub fn default_compatibility_window() -> CompatibilityWindow {
    let mut window = CompatibilityWindow::new(
        MigrationVersion::new(0, 1, 0),
        MigrationVersion::new(1, 0, 0),
    );

    window.add_deprecation(Deprecation {
        feature: "legacy_auth".into(),
        deprecated_in: MigrationVersion::new(0, 3, 0),
        removed_in: Some(MigrationVersion::new(1, 0, 0)),
        replacement: Some("ucan_auth".into()),
        migration_guide: Some("See docs/MIGRATION_AUTH.md".into()),
    });

    window
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_version() {
        let v1 = MigrationVersion::new(1, 2, 3);
        let v2 = MigrationVersion::parse("1.2.3").unwrap();
        assert_eq!(v1, v2);
        assert_eq!(v1.to_string(), "1.2.3");

        let v3 = MigrationVersion::new(1, 3, 0);
        assert!(v3 > v1);
        assert!(v1.is_compatible_with(&v3));
    }

    #[test]
    fn test_schema_migration() {
        let migration = SchemaMigration::new(
            "test_001",
            MigrationVersion::new(0, 1, 0),
            "Test migration"
        ).with_up("CREATE TABLE test (id INT);")
         .with_down("DROP TABLE test;");

        assert!(!migration.checksum.is_empty());
        assert!(migration.reversible);
    }

    #[test]
    fn test_migration_manager() {
        let mut manager = MigrationManager::new();

        let m1 = SchemaMigration::new("m1", MigrationVersion::new(0, 1, 0), "First");
        let m2 = SchemaMigration::new("m2", MigrationVersion::new(0, 2, 0), "Second");

        manager.register_schema(m1);
        manager.register_schema(m2);

        assert_eq!(manager.pending_schema().len(), 2);
        assert!(manager.needs_migration());

        let plan = manager.plan();
        assert_eq!(plan.schema_migrations.len(), 2);
    }

    #[test]
    fn test_execute_migration() {
        let mut manager = MigrationManager::new();

        let migration = SchemaMigration::new(
            "test_001",
            MigrationVersion::new(0, 1, 0),
            "Test"
        ).with_up("SELECT 1;");

        manager.register_schema(migration.clone());

        let record = manager.execute_schema(&migration).unwrap();
        assert_eq!(record.status, MigrationStatus::Completed);
        assert!(record.applied_at.is_some());

        assert_eq!(manager.pending_schema().len(), 0);
    }

    #[test]
    fn test_compatibility_window() {
        let window = default_compatibility_window();

        assert!(window.is_compatible(&MigrationVersion::new(0, 2, 0)));
        assert!(!window.is_compatible(&MigrationVersion::new(2, 0, 0)));

        let deps = window.get_deprecations_for(&MigrationVersion::new(0, 5, 0));
        assert!(!deps.is_empty());
    }

    #[test]
    fn test_kernel_migration() {
        let migration = KernelMigration::new(
            "k1",
            MigrationVersion::new(0, 1, 0),
            MigrationVersion::new(0, 2, 0),
            "Add field"
        ).add_step(KernelMigrationStep::AddField {
            field: "new_field".into(),
            default_value: serde_json::json!("default"),
        });

        assert_eq!(migration.steps.len(), 1);
    }
}
