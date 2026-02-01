//! Storage backends for IndexDB

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Sqlite, SqlitePool, Row};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use aapi_core::types::EffectBucket;
use crate::error::IndexDbResult;
use crate::models::*;
use crate::merkle::MerkleTree;

/// Storage trait for IndexDB backends
#[async_trait]
pub trait IndexDbStore: Send + Sync {
    /// Store a VĀKYA record
    async fn store_vakya(&self, record: VakyaRecord) -> IndexDbResult<VakyaRecord>;
    
    /// Get a VĀKYA record by ID
    async fn get_vakya(&self, vakya_id: &str) -> IndexDbResult<Option<VakyaRecord>>;
    
    /// Store an effect record
    async fn store_effect(&self, record: EffectRecord) -> IndexDbResult<EffectRecord>;
    
    /// Get effects for a VĀKYA
    async fn get_effects(&self, vakya_id: &str) -> IndexDbResult<Vec<EffectRecord>>;
    
    /// Store a receipt record
    async fn store_receipt(&self, record: ReceiptRecord) -> IndexDbResult<ReceiptRecord>;
    
    /// Get a receipt by VĀKYA ID
    async fn get_receipt(&self, vakya_id: &str) -> IndexDbResult<Option<ReceiptRecord>>;
    
    /// Store an audit log entry
    async fn store_audit_log(&self, entry: AuditLogEntry) -> IndexDbResult<()>;
    
    /// Get the current Merkle root for a tree type
    async fn get_merkle_root(&self, tree_type: TreeType) -> IndexDbResult<Option<String>>;
    
    /// Store a Merkle checkpoint
    async fn store_merkle_checkpoint(&self, checkpoint: MerkleCheckpoint) -> IndexDbResult<()>;
    
    /// Get inclusion proof for a record
    async fn get_inclusion_proof(&self, tree_type: TreeType, leaf_index: i64) -> IndexDbResult<Option<InclusionProof>>;
}

/// SQLite-based IndexDB store
pub struct SqliteIndexDb {
    pool: SqlitePool,
    vakya_tree: Arc<RwLock<MerkleTree>>,
    effect_tree: Arc<RwLock<MerkleTree>>,
    receipt_tree: Arc<RwLock<MerkleTree>>,
}

impl SqliteIndexDb {
    /// Create a new SQLite IndexDB
    pub async fn new(database_url: &str) -> IndexDbResult<Self> {
        let pool = SqlitePool::connect(database_url).await?;
        
        // Run migrations
        Self::run_migrations(&pool).await?;
        
        // Initialize Merkle trees
        let vakya_tree = Arc::new(RwLock::new(MerkleTree::new()));
        let effect_tree = Arc::new(RwLock::new(MerkleTree::new()));
        let receipt_tree = Arc::new(RwLock::new(MerkleTree::new()));
        
        let store = Self {
            pool,
            vakya_tree,
            effect_tree,
            receipt_tree,
        };
        
        // Rebuild Merkle trees from existing data
        store.rebuild_merkle_trees().await?;
        
        info!("SQLite IndexDB initialized");
        Ok(store)
    }

    /// Create an in-memory SQLite IndexDB (for testing)
    pub async fn in_memory() -> IndexDbResult<Self> {
        Self::new("sqlite::memory:").await
    }

    /// Run database migrations
    async fn run_migrations(pool: &SqlitePool) -> IndexDbResult<()> {
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS vakya_records (
                id TEXT PRIMARY KEY,
                vakya_id TEXT UNIQUE NOT NULL,
                vakya_hash TEXT NOT NULL,
                karta_pid TEXT NOT NULL,
                karta_type TEXT NOT NULL,
                karma_rid TEXT NOT NULL,
                karma_kind TEXT,
                kriya_action TEXT NOT NULL,
                expected_effect TEXT NOT NULL,
                cap_ref TEXT,
                vakya_json TEXT NOT NULL,
                signature TEXT,
                key_id TEXT,
                trace_id TEXT,
                span_id TEXT,
                parent_span_id TEXT,
                created_at TEXT NOT NULL,
                leaf_index INTEGER,
                merkle_root TEXT
            )
        "#).execute(pool).await?;

        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS effect_records (
                id TEXT PRIMARY KEY,
                vakya_id TEXT NOT NULL,
                effect_bucket TEXT NOT NULL,
                target_rid TEXT NOT NULL,
                target_kind TEXT,
                before_hash TEXT,
                after_hash TEXT,
                before_state TEXT,
                after_state TEXT,
                delta TEXT,
                reversible INTEGER NOT NULL DEFAULT 0,
                reversal_instructions TEXT,
                created_at TEXT NOT NULL,
                leaf_index INTEGER,
                FOREIGN KEY (vakya_id) REFERENCES vakya_records(vakya_id)
            )
        "#).execute(pool).await?;

        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS receipt_records (
                id TEXT PRIMARY KEY,
                vakya_id TEXT UNIQUE NOT NULL,
                vakya_hash TEXT NOT NULL,
                reason_code TEXT NOT NULL,
                message TEXT,
                duration_ms INTEGER,
                effect_ids TEXT,
                executor_id TEXT NOT NULL,
                signature TEXT,
                key_id TEXT,
                created_at TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                leaf_index INTEGER,
                FOREIGN KEY (vakya_id) REFERENCES vakya_records(vakya_id)
            )
        "#).execute(pool).await?;

        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS merkle_checkpoints (
                id TEXT PRIMARY KEY,
                tree_type TEXT NOT NULL,
                tree_size INTEGER NOT NULL,
                root_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                previous_id TEXT,
                signature TEXT
            )
        "#).execute(pool).await?;

        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS merkle_nodes (
                tree_type TEXT NOT NULL,
                level INTEGER NOT NULL,
                index_in_level INTEGER NOT NULL,
                hash TEXT NOT NULL,
                left_child TEXT,
                right_child TEXT,
                PRIMARY KEY (tree_type, level, index_in_level)
            )
        "#).execute(pool).await?;

        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                actor TEXT,
                target TEXT,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL,
                source_ip TEXT,
                user_agent TEXT
            )
        "#).execute(pool).await?;

        // Create indexes
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_vakya_karta ON vakya_records(karta_pid)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_vakya_karma ON vakya_records(karma_rid)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_vakya_action ON vakya_records(kriya_action)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_vakya_created ON vakya_records(created_at)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_vakya_trace ON vakya_records(trace_id)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_effect_vakya ON effect_records(vakya_id)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_receipt_vakya ON receipt_records(vakya_id)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(event_type)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)")
            .execute(pool).await?;

        debug!("Database migrations completed");
        Ok(())
    }

    /// Rebuild Merkle trees from existing data
    async fn rebuild_merkle_trees(&self) -> IndexDbResult<()> {
        // Rebuild VĀKYA tree
        let vakya_hashes: Vec<(i64, String)> = sqlx::query_as(
            "SELECT leaf_index, vakya_hash FROM vakya_records WHERE leaf_index IS NOT NULL ORDER BY leaf_index"
        ).fetch_all(&self.pool).await?;
        
        let mut vakya_tree = self.vakya_tree.write().await;
        for (_, hash) in vakya_hashes {
            vakya_tree.append(&hash);
        }
        drop(vakya_tree);

        // Rebuild effect tree
        let effect_hashes: Vec<(i64, String)> = sqlx::query_as(
            "SELECT leaf_index, id FROM effect_records WHERE leaf_index IS NOT NULL ORDER BY leaf_index"
        ).fetch_all(&self.pool).await?;
        
        let mut effect_tree = self.effect_tree.write().await;
        for (_, id) in effect_hashes {
            effect_tree.append(&id);
        }
        drop(effect_tree);

        // Rebuild receipt tree
        let receipt_hashes: Vec<(i64, String)> = sqlx::query_as(
            "SELECT leaf_index, vakya_hash FROM receipt_records WHERE leaf_index IS NOT NULL ORDER BY leaf_index"
        ).fetch_all(&self.pool).await?;
        
        let mut receipt_tree = self.receipt_tree.write().await;
        for (_, hash) in receipt_hashes {
            receipt_tree.append(&hash);
        }

        info!("Merkle trees rebuilt from existing data");
        Ok(())
    }

    /// Get the Merkle tree for a given type
    fn get_tree(&self, tree_type: TreeType) -> &Arc<RwLock<MerkleTree>> {
        match tree_type {
            TreeType::Vakya => &self.vakya_tree,
            TreeType::Effect => &self.effect_tree,
            TreeType::Receipt => &self.receipt_tree,
        }
    }
}

#[async_trait]
impl IndexDbStore for SqliteIndexDb {
    async fn store_vakya(&self, mut record: VakyaRecord) -> IndexDbResult<VakyaRecord> {
        // Add to Merkle tree
        let mut tree = self.vakya_tree.write().await;
        let leaf_index = tree.append(&record.vakya_hash);
        let merkle_root = tree.root().map(|h| h.to_string());
        drop(tree);

        record.leaf_index = Some(leaf_index as i64);
        record.merkle_root = merkle_root;

        let effect_bucket_str = serde_json::to_string(&record.expected_effect)?;
        let vakya_json_str = serde_json::to_string(&record.vakya_json)?;

        sqlx::query(r#"
            INSERT INTO vakya_records (
                id, vakya_id, vakya_hash, karta_pid, karta_type, karma_rid, karma_kind,
                kriya_action, expected_effect, cap_ref, vakya_json, signature, key_id,
                trace_id, span_id, parent_span_id, created_at, leaf_index, merkle_root
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(record.id.to_string())
        .bind(&record.vakya_id)
        .bind(&record.vakya_hash)
        .bind(&record.karta_pid)
        .bind(&record.karta_type)
        .bind(&record.karma_rid)
        .bind(&record.karma_kind)
        .bind(&record.kriya_action)
        .bind(&effect_bucket_str)
        .bind(&record.cap_ref)
        .bind(&vakya_json_str)
        .bind(&record.signature)
        .bind(&record.key_id)
        .bind(&record.trace_id)
        .bind(&record.span_id)
        .bind(&record.parent_span_id)
        .bind(record.created_at.to_rfc3339())
        .bind(record.leaf_index)
        .bind(&record.merkle_root)
        .execute(&self.pool)
        .await?;

        debug!(vakya_id = %record.vakya_id, "Stored VĀKYA record");
        Ok(record)
    }

    async fn get_vakya(&self, vakya_id: &str) -> IndexDbResult<Option<VakyaRecord>> {
        let row = sqlx::query(
            "SELECT * FROM vakya_records WHERE vakya_id = ?"
        )
        .bind(vakya_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let effect_str: String = row.get("expected_effect");
                let vakya_json_str: String = row.get("vakya_json");
                
                Ok(Some(VakyaRecord {
                    id: row.get::<String, _>("id").parse().unwrap_or_default(),
                    vakya_id: row.get("vakya_id"),
                    vakya_hash: row.get("vakya_hash"),
                    karta_pid: row.get("karta_pid"),
                    karta_type: row.get("karta_type"),
                    karma_rid: row.get("karma_rid"),
                    karma_kind: row.get("karma_kind"),
                    kriya_action: row.get("kriya_action"),
                    expected_effect: serde_json::from_str(&effect_str).unwrap_or(EffectBucket::None),
                    cap_ref: row.get("cap_ref"),
                    vakya_json: serde_json::from_str(&vakya_json_str).unwrap_or_default(),
                    signature: row.get("signature"),
                    key_id: row.get("key_id"),
                    trace_id: row.get("trace_id"),
                    span_id: row.get("span_id"),
                    parent_span_id: row.get("parent_span_id"),
                    created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    leaf_index: row.get("leaf_index"),
                    merkle_root: row.get("merkle_root"),
                }))
            }
            None => Ok(None),
        }
    }

    async fn store_effect(&self, mut record: EffectRecord) -> IndexDbResult<EffectRecord> {
        // Add to Merkle tree
        let mut tree = self.effect_tree.write().await;
        let leaf_index = tree.append(&record.id.to_string());
        drop(tree);

        record.leaf_index = Some(leaf_index as i64);

        let effect_bucket_str = serde_json::to_string(&record.effect_bucket)?;
        let before_state_str = record.before_state.as_ref().map(|v| serde_json::to_string(v)).transpose()?;
        let after_state_str = record.after_state.as_ref().map(|v| serde_json::to_string(v)).transpose()?;
        let delta_str = record.delta.as_ref().map(|v| serde_json::to_string(v)).transpose()?;
        let reversal_str = record.reversal_instructions.as_ref().map(|v| serde_json::to_string(v)).transpose()?;

        sqlx::query(r#"
            INSERT INTO effect_records (
                id, vakya_id, effect_bucket, target_rid, target_kind,
                before_hash, after_hash, before_state, after_state, delta,
                reversible, reversal_instructions, created_at, leaf_index
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(record.id.to_string())
        .bind(&record.vakya_id)
        .bind(&effect_bucket_str)
        .bind(&record.target_rid)
        .bind(&record.target_kind)
        .bind(&record.before_hash)
        .bind(&record.after_hash)
        .bind(&before_state_str)
        .bind(&after_state_str)
        .bind(&delta_str)
        .bind(record.reversible)
        .bind(&reversal_str)
        .bind(record.created_at.to_rfc3339())
        .bind(record.leaf_index)
        .execute(&self.pool)
        .await?;

        debug!(effect_id = %record.id, vakya_id = %record.vakya_id, "Stored effect record");
        Ok(record)
    }

    async fn get_effects(&self, vakya_id: &str) -> IndexDbResult<Vec<EffectRecord>> {
        let rows = sqlx::query(
            "SELECT * FROM effect_records WHERE vakya_id = ? ORDER BY created_at"
        )
        .bind(vakya_id)
        .fetch_all(&self.pool)
        .await?;

        let mut effects = Vec::with_capacity(rows.len());
        for row in rows {
            let effect_str: String = row.get("effect_bucket");
            let before_state_str: Option<String> = row.get("before_state");
            let after_state_str: Option<String> = row.get("after_state");
            let delta_str: Option<String> = row.get("delta");
            let reversal_str: Option<String> = row.get("reversal_instructions");

            effects.push(EffectRecord {
                id: row.get::<String, _>("id").parse().unwrap_or_default(),
                vakya_id: row.get("vakya_id"),
                effect_bucket: serde_json::from_str(&effect_str).unwrap_or(EffectBucket::None),
                target_rid: row.get("target_rid"),
                target_kind: row.get("target_kind"),
                before_hash: row.get("before_hash"),
                after_hash: row.get("after_hash"),
                before_state: before_state_str.and_then(|s| serde_json::from_str(&s).ok()),
                after_state: after_state_str.and_then(|s| serde_json::from_str(&s).ok()),
                delta: delta_str.and_then(|s| serde_json::from_str(&s).ok()),
                reversible: row.get("reversible"),
                reversal_instructions: reversal_str.and_then(|s| serde_json::from_str(&s).ok()),
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                leaf_index: row.get("leaf_index"),
            });
        }

        Ok(effects)
    }

    async fn store_receipt(&self, mut record: ReceiptRecord) -> IndexDbResult<ReceiptRecord> {
        // Add to Merkle tree
        let mut tree = self.receipt_tree.write().await;
        let leaf_index = tree.append(&record.vakya_hash);
        drop(tree);

        record.leaf_index = Some(leaf_index as i64);

        let reason_code_str = serde_json::to_string(&record.reason_code)?;
        let effect_ids_str = serde_json::to_string(&record.effect_ids)?;
        let receipt_json_str = serde_json::to_string(&record.receipt_json)?;

        sqlx::query(r#"
            INSERT INTO receipt_records (
                id, vakya_id, vakya_hash, reason_code, message, duration_ms,
                effect_ids, executor_id, signature, key_id, created_at, receipt_json, leaf_index
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(record.id.to_string())
        .bind(&record.vakya_id)
        .bind(&record.vakya_hash)
        .bind(&reason_code_str)
        .bind(&record.message)
        .bind(record.duration_ms)
        .bind(&effect_ids_str)
        .bind(&record.executor_id)
        .bind(&record.signature)
        .bind(&record.key_id)
        .bind(record.created_at.to_rfc3339())
        .bind(&receipt_json_str)
        .bind(record.leaf_index)
        .execute(&self.pool)
        .await?;

        debug!(vakya_id = %record.vakya_id, "Stored receipt record");
        Ok(record)
    }

    async fn get_receipt(&self, vakya_id: &str) -> IndexDbResult<Option<ReceiptRecord>> {
        let row = sqlx::query(
            "SELECT * FROM receipt_records WHERE vakya_id = ?"
        )
        .bind(vakya_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let reason_code_str: String = row.get("reason_code");
                let effect_ids_str: String = row.get("effect_ids");
                let receipt_json_str: String = row.get("receipt_json");

                Ok(Some(ReceiptRecord {
                    id: row.get::<String, _>("id").parse().unwrap_or_default(),
                    vakya_id: row.get("vakya_id"),
                    vakya_hash: row.get("vakya_hash"),
                    reason_code: serde_json::from_str(&reason_code_str).unwrap_or(aapi_core::error::ReasonCode::InternalError),
                    message: row.get("message"),
                    duration_ms: row.get("duration_ms"),
                    effect_ids: serde_json::from_str(&effect_ids_str).unwrap_or_default(),
                    executor_id: row.get("executor_id"),
                    signature: row.get("signature"),
                    key_id: row.get("key_id"),
                    created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    receipt_json: serde_json::from_str(&receipt_json_str).unwrap_or_default(),
                    leaf_index: row.get("leaf_index"),
                }))
            }
            None => Ok(None),
        }
    }

    async fn store_audit_log(&self, entry: AuditLogEntry) -> IndexDbResult<()> {
        let event_type_str = serde_json::to_string(&entry.event_type)?;
        let details_str = serde_json::to_string(&entry.details)?;

        sqlx::query(r#"
            INSERT INTO audit_log (
                id, event_type, actor, target, details, created_at, source_ip, user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(entry.id.to_string())
        .bind(&event_type_str)
        .bind(&entry.actor)
        .bind(&entry.target)
        .bind(&details_str)
        .bind(entry.created_at.to_rfc3339())
        .bind(&entry.source_ip)
        .bind(&entry.user_agent)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_merkle_root(&self, tree_type: TreeType) -> IndexDbResult<Option<String>> {
        let tree = self.get_tree(tree_type).read().await;
        Ok(tree.root().map(|h| h.to_string()))
    }

    async fn store_merkle_checkpoint(&self, checkpoint: MerkleCheckpoint) -> IndexDbResult<()> {
        let tree_type_str = checkpoint.tree_type.to_string();

        sqlx::query(r#"
            INSERT INTO merkle_checkpoints (
                id, tree_type, tree_size, root_hash, created_at, previous_id, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(checkpoint.id.to_string())
        .bind(&tree_type_str)
        .bind(checkpoint.tree_size)
        .bind(&checkpoint.root_hash)
        .bind(checkpoint.created_at.to_rfc3339())
        .bind(checkpoint.previous_id.map(|id| id.to_string()))
        .bind(&checkpoint.signature)
        .execute(&self.pool)
        .await?;

        info!(tree_type = %tree_type_str, root = %checkpoint.root_hash, "Stored Merkle checkpoint");
        Ok(())
    }

    async fn get_inclusion_proof(&self, tree_type: TreeType, leaf_index: i64) -> IndexDbResult<Option<InclusionProof>> {
        let tree = self.get_tree(tree_type).read().await;
        
        if let Some(proof) = tree.get_proof(leaf_index as usize) {
            let root = tree.root().unwrap_or_default();
            
            Ok(Some(InclusionProof {
                leaf_hash: proof.leaf_hash,
                leaf_index,
                tree_size: tree.size() as i64,
                proof_hashes: proof.path.into_iter().map(|(hash, is_right)| {
                    ProofNode {
                        hash,
                        position: if is_right { ProofPosition::Right } else { ProofPosition::Left },
                    }
                }).collect(),
                root_hash: root,
            }))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aapi_core::types::EffectBucket;

    #[tokio::test]
    async fn test_sqlite_store_vakya() {
        let store = SqliteIndexDb::in_memory().await.unwrap();
        
        let record = VakyaRecord::new(
            "vakya-test-1".to_string(),
            "hash-abc123".to_string(),
            "user:alice".to_string(),
            "file:/test.txt".to_string(),
            "file.read".to_string(),
            serde_json::json!({"test": true}),
        );
        
        let stored = store.store_vakya(record).await.unwrap();
        assert!(stored.leaf_index.is_some());
        assert!(stored.merkle_root.is_some());
        
        let retrieved = store.get_vakya("vakya-test-1").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().vakya_id, "vakya-test-1");
    }

    #[tokio::test]
    async fn test_sqlite_store_effect() {
        let store = SqliteIndexDb::in_memory().await.unwrap();
        
        // First store a VĀKYA
        let vakya = VakyaRecord::new(
            "vakya-test-2".to_string(),
            "hash-def456".to_string(),
            "user:bob".to_string(),
            "file:/data.json".to_string(),
            "file.write".to_string(),
            serde_json::json!({}),
        );
        store.store_vakya(vakya).await.unwrap();
        
        // Store an effect
        let mut effect = EffectRecord::new(
            "vakya-test-2".to_string(),
            EffectBucket::Update,
            "file:/data.json".to_string(),
        );
        effect.before_hash = Some("before-hash".to_string());
        effect.after_hash = Some("after-hash".to_string());
        
        let stored = store.store_effect(effect).await.unwrap();
        assert!(stored.leaf_index.is_some());
        
        let effects = store.get_effects("vakya-test-2").await.unwrap();
        assert_eq!(effects.len(), 1);
    }

    #[tokio::test]
    async fn test_merkle_root_updates() {
        let store = SqliteIndexDb::in_memory().await.unwrap();
        
        let root1 = store.get_merkle_root(TreeType::Vakya).await.unwrap();
        assert!(root1.is_none()); // Empty tree
        
        let record1 = VakyaRecord::new(
            "v1".to_string(),
            "h1".to_string(),
            "u1".to_string(),
            "r1".to_string(),
            "a.b".to_string(),
            serde_json::json!({}),
        );
        store.store_vakya(record1).await.unwrap();
        
        let root2 = store.get_merkle_root(TreeType::Vakya).await.unwrap();
        assert!(root2.is_some());
        
        let record2 = VakyaRecord::new(
            "v2".to_string(),
            "h2".to_string(),
            "u2".to_string(),
            "r2".to_string(),
            "c.d".to_string(),
            serde_json::json!({}),
        );
        store.store_vakya(record2).await.unwrap();
        
        let root3 = store.get_merkle_root(TreeType::Vakya).await.unwrap();
        assert!(root3.is_some());
        assert_ne!(root2, root3); // Root should change
    }
}
