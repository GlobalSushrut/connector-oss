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
    
    /// Store a MemPacket record (3D envelope)
    async fn store_packet(&self, record: MemPacketRecord) -> IndexDbResult<MemPacketRecord>;
    
    /// Get a MemPacket by CID
    async fn get_packet(&self, packet_cid: &str) -> IndexDbResult<Option<MemPacketRecord>>;
    
    /// Get all MemPackets for a pipeline
    async fn get_packets_by_pipeline(&self, pipeline_id: &str) -> IndexDbResult<Vec<MemPacketRecord>>;
    
    /// Get all MemPackets for a subject
    async fn get_packets_by_subject(&self, subject_id: &str) -> IndexDbResult<Vec<MemPacketRecord>>;
    
    /// Get all MemPackets of a given type for a subject
    async fn get_packets_by_type(&self, subject_id: &str, packet_type: &str) -> IndexDbResult<Vec<MemPacketRecord>>;
    
    /// Store a session record
    async fn store_session(&self, session: SessionRecord) -> IndexDbResult<SessionRecord>;
    
    /// Get a session by ID
    async fn get_session(&self, session_id: &str) -> IndexDbResult<Option<SessionRecord>>;
    
    /// Get active sessions for an agent
    async fn get_active_sessions(&self, agent_id: &str) -> IndexDbResult<Vec<SessionRecord>>;
    
    /// Store an action record (complete action documentation)
    async fn store_action_record(&self, record: ActionRecordEntry) -> IndexDbResult<ActionRecordEntry>;
    
    /// Get an action record by record_id
    async fn get_action_record(&self, record_id: &str) -> IndexDbResult<Option<ActionRecordEntry>>;
    
    /// Store a kernel audit entry
    async fn store_kernel_audit(&self, entry: KernelAuditRecord) -> IndexDbResult<KernelAuditRecord>;
    
    /// Get kernel audit entries for an agent
    async fn get_kernel_audits_by_agent(&self, agent_pid: &str, limit: u32) -> IndexDbResult<Vec<KernelAuditRecord>>;
    
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
    packet_tree: Arc<RwLock<MerkleTree>>,
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
        let packet_tree = Arc::new(RwLock::new(MerkleTree::new()));
        
        let store = Self {
            pool,
            vakya_tree,
            effect_tree,
            receipt_tree,
            packet_tree,
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
            CREATE TABLE IF NOT EXISTS packet_records (
                id TEXT PRIMARY KEY,
                packet_cid TEXT UNIQUE NOT NULL,
                packet_type TEXT NOT NULL,
                pipeline_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                payload_cid TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                entities TEXT DEFAULT '[]',
                tags TEXT DEFAULT '[]',
                source_kind TEXT NOT NULL,
                source_principal TEXT NOT NULL,
                trust_tier INTEGER NOT NULL DEFAULT 1,
                confidence REAL,
                epistemic TEXT NOT NULL DEFAULT 'observed',
                evidence_cids TEXT DEFAULT '[]',
                supersedes_cid TEXT,
                reasoning TEXT,
                domain_code TEXT,
                vakya_id TEXT,
                actor TEXT,
                capability_ref TEXT,
                signature TEXT,
                policy_ref TEXT,
                prolly_key TEXT NOT NULL,
                seq_index INTEGER NOT NULL DEFAULT 0,
                block_no INTEGER NOT NULL DEFAULT -1,
                leaf_index INTEGER,
                created_at TEXT NOT NULL
            )
        "#).execute(pool).await?;

        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS session_records (
                id TEXT PRIMARY KEY,
                session_id TEXT UNIQUE NOT NULL,
                agent_id TEXT NOT NULL,
                namespace TEXT NOT NULL,
                label TEXT,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                tier TEXT NOT NULL DEFAULT 'hot',
                scope TEXT NOT NULL DEFAULT 'episodic',
                packet_count INTEGER NOT NULL DEFAULT 0,
                total_tokens INTEGER NOT NULL DEFAULT 0,
                summary TEXT,
                parent_session_id TEXT,
                metadata TEXT DEFAULT '{}',
                created_at TEXT NOT NULL
            )
        "#).execute(pool).await?;

        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS action_records (
                id TEXT PRIMARY KEY,
                record_id TEXT UNIQUE NOT NULL,
                intent TEXT NOT NULL,
                action TEXT NOT NULL,
                target_resource TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                namespace TEXT NOT NULL,
                vakya_id TEXT,
                session_id TEXT,
                pipeline_id TEXT,
                outcome TEXT NOT NULL,
                error TEXT,
                duration_ms INTEGER,
                human_approved INTEGER NOT NULL DEFAULT 0,
                evidence_cids TEXT DEFAULT '[]',
                regulations TEXT DEFAULT '[]',
                data_classification TEXT,
                retention_days INTEGER NOT NULL DEFAULT 0,
                reversible INTEGER NOT NULL DEFAULT 0,
                merkle_root TEXT,
                initiated_at TEXT NOT NULL,
                completed_at TEXT
            )
        "#).execute(pool).await?;

        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS kernel_audit (
                id TEXT PRIMARY KEY,
                audit_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                operation TEXT NOT NULL,
                agent_pid TEXT NOT NULL,
                target TEXT,
                outcome TEXT NOT NULL,
                reason TEXT,
                error TEXT,
                duration_us INTEGER,
                vakya_id TEXT,
                merkle_root TEXT
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
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_packet_cid ON packet_records(packet_cid)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_packet_type ON packet_records(packet_type)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_packet_pipeline ON packet_records(pipeline_id)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_packet_subject ON packet_records(subject_id)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_packet_vakya ON packet_records(vakya_id)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_packet_prolly ON packet_records(prolly_key)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_packet_created ON packet_records(created_at)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_session_id ON session_records(session_id)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_session_agent ON session_records(agent_id)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_session_ns ON session_records(namespace)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_session_tier ON session_records(tier)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_action_record_id ON action_records(record_id)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_action_agent ON action_records(agent_id)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_action_vakya ON action_records(vakya_id)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_action_outcome ON action_records(outcome)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_action_ns ON action_records(namespace)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_kernel_audit_id ON kernel_audit(audit_id)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_kernel_audit_agent ON kernel_audit(agent_pid)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_kernel_audit_op ON kernel_audit(operation)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_kernel_audit_outcome ON kernel_audit(outcome)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_kernel_audit_ts ON kernel_audit(timestamp)")
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

        // Rebuild packet tree
        let packet_hashes: Vec<(i64, String)> = sqlx::query_as(
            "SELECT leaf_index, packet_cid FROM packet_records WHERE leaf_index IS NOT NULL ORDER BY leaf_index"
        ).fetch_all(&self.pool).await?;
        
        let mut packet_tree = self.packet_tree.write().await;
        for (_, cid) in packet_hashes {
            packet_tree.append(&cid);
        }
        drop(packet_tree);

        info!("Merkle trees rebuilt from existing data");
        Ok(())
    }

    /// Convert a SQLite row to a SessionRecord
    fn row_to_session_record(row: &sqlx::sqlite::SqliteRow) -> IndexDbResult<SessionRecord> {
        let metadata_str: String = row.get("metadata");
        let ended_at_str: Option<String> = row.get("ended_at");

        Ok(SessionRecord {
            id: row.get::<String, _>("id").parse().unwrap_or_default(),
            session_id: row.get("session_id"),
            agent_id: row.get("agent_id"),
            namespace: row.get("namespace"),
            label: row.get("label"),
            started_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("started_at"))
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            ended_at: ended_at_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
            tier: row.get("tier"),
            scope: row.get("scope"),
            packet_count: row.get("packet_count"),
            total_tokens: row.get("total_tokens"),
            summary: row.get("summary"),
            parent_session_id: row.get("parent_session_id"),
            metadata: serde_json::from_str(&metadata_str).unwrap_or_default(),
            created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
    }

    /// Convert a SQLite row to a MemPacketRecord
    fn row_to_packet_record(row: &sqlx::sqlite::SqliteRow) -> IndexDbResult<MemPacketRecord> {
        let entities_str: String = row.get("entities");
        let tags_str: String = row.get("tags");
        let evidence_cids_str: String = row.get("evidence_cids");
        let payload_json_str: String = row.get("payload_json");

        Ok(MemPacketRecord {
            id: row.get::<String, _>("id").parse().unwrap_or_default(),
            packet_cid: row.get("packet_cid"),
            packet_type: row.get("packet_type"),
            pipeline_id: row.get("pipeline_id"),
            subject_id: row.get("subject_id"),
            payload_cid: row.get("payload_cid"),
            payload_json: serde_json::from_str(&payload_json_str).unwrap_or_default(),
            entities: serde_json::from_str(&entities_str).unwrap_or_default(),
            tags: serde_json::from_str(&tags_str).unwrap_or_default(),
            source_kind: row.get("source_kind"),
            source_principal: row.get("source_principal"),
            trust_tier: row.get::<i32, _>("trust_tier") as u8,
            confidence: row.get("confidence"),
            epistemic: row.get("epistemic"),
            evidence_cids: serde_json::from_str(&evidence_cids_str).unwrap_or_default(),
            supersedes_cid: row.get("supersedes_cid"),
            reasoning: row.get("reasoning"),
            domain_code: row.get("domain_code"),
            vakya_id: row.get("vakya_id"),
            actor: row.get("actor"),
            capability_ref: row.get("capability_ref"),
            signature: row.get("signature"),
            policy_ref: row.get("policy_ref"),
            prolly_key: row.get("prolly_key"),
            seq_index: row.get("seq_index"),
            block_no: row.get("block_no"),
            leaf_index: row.get("leaf_index"),
            created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
    }

    /// Get the Merkle tree for a given type
    fn get_tree(&self, tree_type: TreeType) -> &Arc<RwLock<MerkleTree>> {
        match tree_type {
            TreeType::Vakya => &self.vakya_tree,
            TreeType::Effect => &self.effect_tree,
            TreeType::Receipt => &self.receipt_tree,
            TreeType::Packet => &self.packet_tree,
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

    async fn store_packet(&self, mut record: MemPacketRecord) -> IndexDbResult<MemPacketRecord> {
        // Add to Merkle tree
        let mut tree = self.packet_tree.write().await;
        let leaf_index = tree.append(&record.packet_cid);
        drop(tree);

        record.leaf_index = Some(leaf_index as i64);

        let entities_str = serde_json::to_string(&record.entities)?;
        let tags_str = serde_json::to_string(&record.tags)?;
        let evidence_cids_str = serde_json::to_string(&record.evidence_cids)?;
        let payload_json_str = serde_json::to_string(&record.payload_json)?;

        sqlx::query(r#"
            INSERT INTO packet_records (
                id, packet_cid, packet_type, pipeline_id, subject_id,
                payload_cid, payload_json, entities, tags,
                source_kind, source_principal, trust_tier, confidence, epistemic,
                evidence_cids, supersedes_cid, reasoning, domain_code,
                vakya_id, actor, capability_ref, signature, policy_ref,
                prolly_key, seq_index, block_no, leaf_index, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(record.id.to_string())
        .bind(&record.packet_cid)
        .bind(&record.packet_type)
        .bind(&record.pipeline_id)
        .bind(&record.subject_id)
        .bind(&record.payload_cid)
        .bind(&payload_json_str)
        .bind(&entities_str)
        .bind(&tags_str)
        .bind(&record.source_kind)
        .bind(&record.source_principal)
        .bind(record.trust_tier as i32)
        .bind(record.confidence)
        .bind(&record.epistemic)
        .bind(&evidence_cids_str)
        .bind(&record.supersedes_cid)
        .bind(&record.reasoning)
        .bind(&record.domain_code)
        .bind(&record.vakya_id)
        .bind(&record.actor)
        .bind(&record.capability_ref)
        .bind(&record.signature)
        .bind(&record.policy_ref)
        .bind(&record.prolly_key)
        .bind(record.seq_index)
        .bind(record.block_no)
        .bind(record.leaf_index)
        .bind(record.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        debug!(packet_cid = %record.packet_cid, packet_type = %record.packet_type, "Stored MemPacket record");
        Ok(record)
    }

    async fn get_packet(&self, packet_cid: &str) -> IndexDbResult<Option<MemPacketRecord>> {
        let row = sqlx::query(
            "SELECT * FROM packet_records WHERE packet_cid = ?"
        )
        .bind(packet_cid)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(Self::row_to_packet_record(&row)?)),
            None => Ok(None),
        }
    }

    async fn get_packets_by_pipeline(&self, pipeline_id: &str) -> IndexDbResult<Vec<MemPacketRecord>> {
        let rows = sqlx::query(
            "SELECT * FROM packet_records WHERE pipeline_id = ? ORDER BY seq_index"
        )
        .bind(pipeline_id)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(|r| Self::row_to_packet_record(r)).collect()
    }

    async fn get_packets_by_subject(&self, subject_id: &str) -> IndexDbResult<Vec<MemPacketRecord>> {
        let rows = sqlx::query(
            "SELECT * FROM packet_records WHERE subject_id = ? ORDER BY created_at"
        )
        .bind(subject_id)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(|r| Self::row_to_packet_record(r)).collect()
    }

    async fn get_packets_by_type(&self, subject_id: &str, packet_type: &str) -> IndexDbResult<Vec<MemPacketRecord>> {
        let rows = sqlx::query(
            "SELECT * FROM packet_records WHERE subject_id = ? AND packet_type = ? ORDER BY created_at"
        )
        .bind(subject_id)
        .bind(packet_type)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(|r| Self::row_to_packet_record(r)).collect()
    }

    async fn store_session(&self, record: SessionRecord) -> IndexDbResult<SessionRecord> {
        let metadata_str = serde_json::to_string(&record.metadata)?;

        sqlx::query(r#"
            INSERT INTO session_records (
                id, session_id, agent_id, namespace, label,
                started_at, ended_at, tier, scope,
                packet_count, total_tokens, summary,
                parent_session_id, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(record.id.to_string())
        .bind(&record.session_id)
        .bind(&record.agent_id)
        .bind(&record.namespace)
        .bind(&record.label)
        .bind(record.started_at.to_rfc3339())
        .bind(record.ended_at.map(|t| t.to_rfc3339()))
        .bind(&record.tier)
        .bind(&record.scope)
        .bind(record.packet_count)
        .bind(record.total_tokens)
        .bind(&record.summary)
        .bind(&record.parent_session_id)
        .bind(&metadata_str)
        .bind(record.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        debug!(session_id = %record.session_id, agent_id = %record.agent_id, "Stored session record");
        Ok(record)
    }

    async fn get_session(&self, session_id: &str) -> IndexDbResult<Option<SessionRecord>> {
        let row = sqlx::query(
            "SELECT * FROM session_records WHERE session_id = ?"
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(Self::row_to_session_record(&row)?)),
            None => Ok(None),
        }
    }

    async fn get_active_sessions(&self, agent_id: &str) -> IndexDbResult<Vec<SessionRecord>> {
        let rows = sqlx::query(
            "SELECT * FROM session_records WHERE agent_id = ? AND ended_at IS NULL ORDER BY started_at DESC"
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(|r| Self::row_to_session_record(r)).collect()
    }

    async fn store_action_record(&self, record: ActionRecordEntry) -> IndexDbResult<ActionRecordEntry> {
        let evidence_str = serde_json::to_string(&record.evidence_cids)?;
        let regulations_str = serde_json::to_string(&record.regulations)?;

        sqlx::query(r#"
            INSERT INTO action_records (
                id, record_id, intent, action, target_resource,
                agent_id, namespace, vakya_id, session_id, pipeline_id,
                outcome, error, duration_ms, human_approved,
                evidence_cids, regulations, data_classification,
                retention_days, reversible, merkle_root,
                initiated_at, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(record.id.to_string())
        .bind(&record.record_id)
        .bind(&record.intent)
        .bind(&record.action)
        .bind(&record.target_resource)
        .bind(&record.agent_id)
        .bind(&record.namespace)
        .bind(&record.vakya_id)
        .bind(&record.session_id)
        .bind(&record.pipeline_id)
        .bind(&record.outcome)
        .bind(&record.error)
        .bind(record.duration_ms)
        .bind(record.human_approved)
        .bind(&evidence_str)
        .bind(&regulations_str)
        .bind(&record.data_classification)
        .bind(record.retention_days)
        .bind(record.reversible)
        .bind(&record.merkle_root)
        .bind(record.initiated_at.to_rfc3339())
        .bind(record.completed_at.map(|t| t.to_rfc3339()))
        .execute(&self.pool)
        .await?;

        debug!(record_id = %record.record_id, action = %record.action, "Stored action record");
        Ok(record)
    }

    async fn get_action_record(&self, record_id: &str) -> IndexDbResult<Option<ActionRecordEntry>> {
        let row = sqlx::query(
            "SELECT * FROM action_records WHERE record_id = ?"
        )
        .bind(record_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let evidence_str: String = row.get("evidence_cids");
                let regulations_str: String = row.get("regulations");
                let completed_str: Option<String> = row.get("completed_at");

                Ok(Some(ActionRecordEntry {
                    id: row.get::<String, _>("id").parse().unwrap_or_default(),
                    record_id: row.get("record_id"),
                    intent: row.get("intent"),
                    action: row.get("action"),
                    target_resource: row.get("target_resource"),
                    agent_id: row.get("agent_id"),
                    namespace: row.get("namespace"),
                    vakya_id: row.get("vakya_id"),
                    session_id: row.get("session_id"),
                    pipeline_id: row.get("pipeline_id"),
                    outcome: row.get("outcome"),
                    error: row.get("error"),
                    duration_ms: row.get("duration_ms"),
                    human_approved: row.get("human_approved"),
                    evidence_cids: serde_json::from_str(&evidence_str).unwrap_or_default(),
                    regulations: serde_json::from_str(&regulations_str).unwrap_or_default(),
                    data_classification: row.get("data_classification"),
                    retention_days: row.get("retention_days"),
                    reversible: row.get("reversible"),
                    merkle_root: row.get("merkle_root"),
                    initiated_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("initiated_at"))
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    completed_at: completed_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
                }))
            }
            None => Ok(None),
        }
    }

    async fn store_kernel_audit(&self, entry: KernelAuditRecord) -> IndexDbResult<KernelAuditRecord> {
        sqlx::query(r#"
            INSERT INTO kernel_audit (
                id, audit_id, timestamp, operation, agent_pid,
                target, outcome, reason, error, duration_us,
                vakya_id, merkle_root
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(entry.id.to_string())
        .bind(&entry.audit_id)
        .bind(entry.timestamp.to_rfc3339())
        .bind(&entry.operation)
        .bind(&entry.agent_pid)
        .bind(&entry.target)
        .bind(&entry.outcome)
        .bind(&entry.reason)
        .bind(&entry.error)
        .bind(entry.duration_us)
        .bind(&entry.vakya_id)
        .bind(&entry.merkle_root)
        .execute(&self.pool)
        .await?;

        debug!(audit_id = %entry.audit_id, op = %entry.operation, "Stored kernel audit entry");
        Ok(entry)
    }

    async fn get_kernel_audits_by_agent(&self, agent_pid: &str, limit: u32) -> IndexDbResult<Vec<KernelAuditRecord>> {
        let rows = sqlx::query(
            "SELECT * FROM kernel_audit WHERE agent_pid = ? ORDER BY timestamp DESC LIMIT ?"
        )
        .bind(agent_pid)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(|row| {
            Ok(KernelAuditRecord {
                id: row.get::<String, _>("id").parse().unwrap_or_default(),
                audit_id: row.get("audit_id"),
                timestamp: DateTime::parse_from_rfc3339(&row.get::<String, _>("timestamp"))
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                operation: row.get("operation"),
                agent_pid: row.get("agent_pid"),
                target: row.get("target"),
                outcome: row.get("outcome"),
                reason: row.get("reason"),
                error: row.get("error"),
                duration_us: row.get("duration_us"),
                vakya_id: row.get("vakya_id"),
                merkle_root: row.get("merkle_root"),
            })
        }).collect()
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
