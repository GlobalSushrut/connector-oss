//! COPG — Connector Operation Persistence Graph.
//!
//! Dual operation store: native **graph** (worldline / FSM edges) + **SQL-ish** tabular
//! select. Backed by **redb** (lighter than SQLite; same family as `kernel.redb`).
//!
//! Enable: `CONNECTOR_ARC_STORE=copg` + `CONNECTOR_ARC_DURABLE=1`.
//! Docs: `platform/docs/arch/CONNECTOR_COPG.md`

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::durable;
use super::transaction::AgencyTransaction;
use super::worldline::WorldlineCommit;
use super::worldline_store::WorldlineStore;

pub const SCHEMA: &str = "connector.copg.v1";

const RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("copg_records");
const CHAIN_TIP: TableDefinition<&str, &[u8]> = TableDefinition::new("copg_chain_tip");
const GRAPH_EDGES: TableDefinition<&str, &[u8]> = TableDefinition::new("copg_graph_edges");
const AGENT_HEAD: TableDefinition<&str, &[u8]> = TableDefinition::new("copg_agent_head");
const AGENT_SEQ: TableDefinition<&str, u64> = TableDefinition::new("copg_agent_seq");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopgTable {
    WorldlineCommits,
    AgencyTransactions,
    GraphEdges,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopgRecord {
    pub schema: String,
    pub kind: String,
    pub id: String,
    pub agent_id: Option<String>,
    pub at_ms: i64,
    pub prev_digest: Option<String>,
    pub digest: String,
    pub body: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CopgGraphEdge {
    pub schema: String,
    pub edge_id: String,
    pub agent_id: String,
    pub from_id: String,
    pub to_id: String,
    pub label: String,
    pub seq: u64,
}

pub fn store_mode() -> &'static str {
    static MODE: OnceLock<String> = OnceLock::new();
    MODE.get_or_init(|| {
        if let Ok(v) = std::env::var("CONNECTOR_ARC_STORE") {
            let t = v.trim().to_ascii_lowercase();
            if t == "copg" || t == "redb" {
                return "copg".into();
            }
        }
        if super::flags::ArcFlags::from_env().harden {
            "copg".into()
        } else {
            "jsonl".into()
        }
    })
}

pub fn copg_enabled() -> bool {
    durable::durable_enabled() && store_mode() == "copg"
}

fn db_path() -> PathBuf {
    durable::durable_dir().join("arc.redb")
}

fn chain_mac(prev: Option<&str>, digest: &str, body: &[u8]) -> Option<String> {
    let key = std::env::var("CONNECTOR_ARC_STORE_MAC_KEY")
        .ok()
        .filter(|s| !s.trim().is_empty())?;
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).ok()?;
    mac.update(prev.unwrap_or("genesis").as_bytes());
    mac.update(digest.as_bytes());
    mac.update(body);
    Some(hex::encode(mac.finalize().into_bytes()))
}

fn record_digest(prev: Option<&str>, kind: &str, id: &str, body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(prev.unwrap_or("genesis").as_bytes());
    h.update(kind.as_bytes());
    h.update(id.as_bytes());
    h.update(body);
    format!("{:x}", h.finalize())
}

pub struct CopgStore {
    db: Database,
}

impl CopgStore {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, String> {
        std::fs::create_dir_all(dir.as_ref()).map_err(|e| e.to_string())?;
        let path = dir.as_ref().join("arc.redb");
        let db = Database::create(&path).map_err(|e| format!("copg open: {e}"))?;
        let txn = db.begin_write().map_err(|e| e.to_string())?;
        txn.open_table(RECORDS).map_err(|e| e.to_string())?;
        txn.open_table(CHAIN_TIP).map_err(|e| e.to_string())?;
        txn.open_table(GRAPH_EDGES).map_err(|e| e.to_string())?;
        txn.open_table(AGENT_HEAD).map_err(|e| e.to_string())?;
        txn.open_table(AGENT_SEQ).map_err(|e| e.to_string())?;
        txn.commit().map_err(|e| e.to_string())?;
        Ok(Self { db })
    }

    fn chain_tip(&self) -> Result<Option<String>, String> {
        let txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = txn.open_table(CHAIN_TIP).map_err(|e| e.to_string())?;
        Ok(table
            .get("tip")
            .map_err(|e| e.to_string())?
            .map(|v| String::from_utf8_lossy(v.value()).into_owned()))
    }

    fn set_chain_tip(&self, digest: &str) -> Result<(), String> {
        let txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = txn.open_table(CHAIN_TIP).map_err(|e| e.to_string())?;
            table
                .insert("tip", digest.as_bytes())
                .map_err(|e| e.to_string())?;
        }
        txn.commit().map_err(|e| e.to_string())
    }

    fn next_agent_seq(&self, agent_id: &str) -> Result<u64, String> {
        let txn = self.db.begin_write().map_err(|e| e.to_string())?;
        let seq = {
            let mut table = txn.open_table(AGENT_SEQ).map_err(|e| e.to_string())?;
            let next = match table.get(agent_id).map_err(|e| e.to_string())? {
                Some(v) => v.value().saturating_add(1),
                None => 1,
            };
            table.insert(agent_id, next).map_err(|e| e.to_string())?;
            next
        };
        txn.commit().map_err(|e| e.to_string())?;
        Ok(seq)
    }

    pub fn append_record(&self, kind: &str, id: &str, agent_id: Option<&str>, body: Value) -> Result<CopgRecord, String> {
        let prev = self.chain_tip()?;
        let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
        let digest = record_digest(prev.as_deref(), kind, id, &body_bytes);
        let mac = chain_mac(prev.as_deref(), &digest, &body_bytes);
        let rec = CopgRecord {
            schema: SCHEMA.into(),
            kind: kind.into(),
            id: id.into(),
            agent_id: agent_id.map(str::to_string),
            at_ms: chrono::Utc::now().timestamp_millis(),
            prev_digest: prev,
            digest: digest.clone(),
            body,
            mac,
        };
        let key = format!("{kind}:{id}");
        let val = serde_json::to_vec(&rec).map_err(|e| e.to_string())?;
        let txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = txn.open_table(RECORDS).map_err(|e| e.to_string())?;
            table.insert(key.as_str(), val.as_slice()).map_err(|e| e.to_string())?;
        }
        txn.commit().map_err(|e| e.to_string())?;
        self.set_chain_tip(&digest)?;
        Ok(rec)
    }

    pub fn put_graph_edge(
        &self,
        agent_id: &str,
        from_id: &str,
        to_id: &str,
        label: &str,
    ) -> Result<(), String> {
        let seq = self.next_agent_seq(agent_id)?;
        let edge_id = format!("{from_id}->{to_id}:{label}");
        let edge = CopgGraphEdge {
            schema: "connector.copg.graph_edge.v1".into(),
            edge_id: edge_id.clone(),
            agent_id: agent_id.into(),
            from_id: from_id.into(),
            to_id: to_id.into(),
            label: label.into(),
            seq,
        };
        let key = format!("{agent_id}:{seq:08}:{edge_id}");
        let val = serde_json::to_vec(&edge).map_err(|e| e.to_string())?;
        let txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = txn.open_table(GRAPH_EDGES).map_err(|e| e.to_string())?;
            table.insert(key.as_str(), val.as_slice()).map_err(|e| e.to_string())?;
        }
        txn.commit().map_err(|e| e.to_string())?;
        let _ = self.append_record(
            "graph_edge",
            &key,
            Some(agent_id),
            json!({ "edge": edge }),
        );
        Ok(())
    }

    pub fn set_agent_head(&self, agent_id: &str, digest: &str) -> Result<(), String> {
        let txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = txn.open_table(AGENT_HEAD).map_err(|e| e.to_string())?;
            table.insert(agent_id, digest.as_bytes()).map_err(|e| e.to_string())?;
        }
        txn.commit().map_err(|e| e.to_string())
    }

    pub fn agent_head(&self, agent_id: &str) -> Option<String> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(AGENT_HEAD).ok()?;
        table
            .get(agent_id)
            .ok()?
            .map(|v| String::from_utf8_lossy(v.value()).into_owned())
    }

    pub fn select(&self, table: CopgTable, agent_id: Option<&str>, limit: usize) -> Result<Vec<Value>, String> {
        let kind = match table {
            CopgTable::WorldlineCommits => "worldline_commit",
            CopgTable::AgencyTransactions => "agency_tx",
            CopgTable::GraphEdges => "graph_edge",
        };
        let txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let records = txn.open_table(RECORDS).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for item in records.iter().map_err(|e| e.to_string())? {
            let (_, v) = item.map_err(|e| e.to_string())?;
            let rec: CopgRecord = serde_json::from_slice(v.value()).map_err(|e| e.to_string())?;
            if rec.kind != kind {
                continue;
            }
            if let Some(a) = agent_id {
                if rec.agent_id.as_deref() != Some(a) {
                    continue;
                }
            }
            out.push(json!({
                "kind": rec.kind,
                "id": rec.id,
                "agent_id": rec.agent_id,
                "digest": rec.digest,
                "prev_digest": rec.prev_digest,
                "at_ms": rec.at_ms,
                "body": rec.body,
            }));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    pub fn graph_export(&self, agent_id: &str) -> Value {
        let txn = match self.db.begin_read() {
            Ok(t) => t,
            Err(e) => return json!({ "ok": false, "error": e.to_string() }),
        };
        let table = match txn.open_table(GRAPH_EDGES) {
            Ok(t) => t,
            Err(e) => return json!({ "ok": false, "error": e.to_string() }),
        };
        let prefix = format!("{agent_id}:");
        let mut edges = Vec::new();
        if let Ok(iter) = table.iter() {
            for item in iter.flatten() {
                let (k, v) = item;
                let key = k.value();
                if !key.starts_with(prefix.as_str()) {
                    continue;
                }
                if let Ok(edge) = serde_json::from_slice::<CopgGraphEdge>(v.value()) {
                    edges.push(json!({
                        "from": edge.from_id,
                        "to": edge.to_id,
                        "label": edge.label,
                        "seq": edge.seq,
                    }));
                }
            }
        }
        edges.sort_by_key(|e| e.get("seq").and_then(|x| x.as_u64()).unwrap_or(0));
        json!({
            "schema": "connector.copg.graph_export.v1",
            "agent_id": agent_id,
            "head_digest": self.agent_head(agent_id),
            "edges": edges,
            "chain_tip": self.chain_tip().ok().flatten(),
            "store": "copg",
            "honesty": "Native operation graph — lighter than SQLite; integrity-chained append",
        })
    }
}

fn global_store() -> Result<&'static Mutex<CopgStore>, String> {
    static STORE: OnceLock<Result<Mutex<CopgStore>, String>> = OnceLock::new();
    STORE
        .get_or_init(|| CopgStore::open(durable::durable_dir()).map(Mutex::new))
        .as_ref()
        .map_err(|e| e.clone())
}

pub fn persist_worldline_commit(commit: &WorldlineCommit) {
    if !copg_enabled() {
        return;
    }
    let store = match global_store() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "copg: store unavailable");
            return;
        }
    };
    let Ok(guard) = store.lock() else {
        return;
    };
    let agent_id = &commit.agent_id;
    if let Some(prev) = &commit.prev_head {
        let _ = guard.put_graph_edge(agent_id, prev, &commit.digest, "worldline_next");
    }
    for edge in &commit.worldline_edges {
        if let Some((from, to)) = edge.split_once('→') {
            let _ = guard.put_graph_edge(agent_id, from, to, "tx_fsm");
        }
    }
    let body = commit.to_json();
    if let Err(e) = guard.append_record(
        "worldline_commit",
        &commit.commit_id,
        Some(agent_id),
        body,
    ) {
        tracing::warn!(error = %e, "copg: worldline append failed");
        return;
    }
    let _ = guard.set_agent_head(agent_id, &commit.digest);
}

/// SVF / evidence edges on the COPG (no parallel graph). Soft no-op when COPG off.
pub fn record_svf_edge(
    agent_id: &str,
    from_id: &str,
    to_id: &str,
    label: &str,
    body: Value,
) {
    if !copg_enabled() {
        return;
    }
    let store = match global_store() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "copg: store unavailable for svf edge");
            return;
        }
    };
    let Ok(guard) = store.lock() else {
        return;
    };
    if let Err(e) = guard.put_graph_edge(agent_id, from_id, to_id, label) {
        tracing::warn!(error = %e, label, "copg: svf put_graph_edge failed");
    }
    let edge_id = format!(
        "svf:{}:{}:{}:{}",
        label,
        &from_id.chars().take(24).collect::<String>(),
        &to_id.chars().take(24).collect::<String>(),
        chrono::Utc::now().timestamp_millis()
    );
    if let Err(e) = guard.append_record("svf_event", &edge_id, Some(agent_id), body) {
        tracing::warn!(error = %e, "copg: svf_event append failed");
    }
}

pub fn persist_agency_tx(tx: &AgencyTransaction) {
    if !copg_enabled() {
        return;
    }
    let store = match global_store() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "copg: store unavailable");
            return;
        }
    };
    let Ok(guard) = store.lock() else {
        return;
    };
    let body = serde_json::to_value(tx).unwrap_or_else(|_| tx.to_json());
    if let Err(e) = guard.append_record(
        "agency_tx",
        &tx.tx_id,
        Some(&tx.agent_id),
        body,
    ) {
        tracing::warn!(error = %e, "copg: agency_tx append failed");
    }
}

/// Load latest agency transactions from COPG (dedupe by tx_id, last wins).
pub fn load_agency_transactions() -> Vec<AgencyTransaction> {
    if !copg_enabled() {
        return Vec::new();
    }
    let copg = match global_store() {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let Ok(guard) = copg.lock() else {
        return Vec::new();
    };
    let Ok(rows) = guard.select(CopgTable::AgencyTransactions, None, 50_000) else {
        return Vec::new();
    };
    let mut by_id: std::collections::HashMap<String, AgencyTransaction> =
        std::collections::HashMap::new();
    for row in rows {
        if let Some(body) = row.get("body") {
            if let Ok(tx) = serde_json::from_value::<AgencyTransaction>(body.clone()) {
                by_id.insert(tx.tx_id.clone(), tx);
            }
        }
    }
    by_id.into_values().collect()
}

pub fn load_worldline_into(store: &WorldlineStore) {
    if !copg_enabled() {
        return;
    }
    let copg = match global_store() {
        Ok(s) => s,
        Err(_) => return,
    };
    let Ok(guard) = copg.lock() else {
        return;
    };
    let Ok(rows) = guard.select(CopgTable::WorldlineCommits, None, 10_000) else {
        return;
    };
    let mut n = 0usize;
    for row in rows {
        if let Some(body) = row.get("body") {
            if let Ok(c) = serde_json::from_value::<WorldlineCommit>(body.clone()) {
                store.append_memory_only(c);
                n += 1;
            }
        }
    }
    if n > 0 {
        tracing::info!(commits = n, "copg: loaded worldline into memory");
    }
}

pub fn graph_export(agent_id: &str) -> Value {
    if !copg_enabled() {
        return json!({
            "schema": "connector.copg.graph_export.v1",
            "agent_id": agent_id,
            "store": store_mode(),
            "honesty": "COPG off — use CONNECTOR_ARC_STORE=copg",
        });
    }
    match global_store() {
        Ok(s) => s
            .lock()
            .map(|g| g.graph_export(agent_id))
            .unwrap_or_else(|_| json!({"ok": false, "error": "copg_lock"})),
        Err(e) => json!({ "ok": false, "error": e }),
    }
}

pub fn sql_select(table: CopgTable, agent_id: Option<&str>, limit: usize) -> Value {
    if !copg_enabled() {
        return json!({
            "schema": "connector.copg.select.v1",
            "rows": [],
            "honesty": "COPG off",
        });
    }
    match global_store() {
        Ok(s) => match s.lock() {
            Ok(g) => match g.select(table, agent_id, limit) {
                Ok(rows) => json!({
                    "schema": "connector.copg.select.v1",
                    "table": format!("{table:?}"),
                    "agent_id": agent_id,
                    "rows": rows,
                    "count": rows.len(),
                }),
                Err(e) => json!({ "ok": false, "error": e }),
            },
            Err(_) => json!({ "ok": false, "error": "copg_lock" }),
        },
        Err(e) => json!({ "ok": false, "error": e }),
    }
}

pub fn posture_json() -> Value {
    let path = db_path();
    let file_exists = path.exists();
    let opened = copg_enabled() && global_store().is_ok();
    json!({
        "schema": SCHEMA,
        "enabled": copg_enabled(),
        "store_mode": store_mode(),
        "db_path": path.display().to_string(),
        "backend": "redb",
        "dual": {
            "graph": "copg_graph_edges + traverse/export",
            "sql_ish": "select(table, agent_id, limit) — not full SQL",
        },
        "security": {
            "integrity_chain": true,
            "hmac": std::env::var("CONNECTOR_ARC_STORE_MAC_KEY")
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false),
            "db_file_exists": file_exists,
            "store_opened": opened,
            "cow_crash_safe": {
                "claimed_by_redb": true,
                "measured_open": opened,
                "fsync_api_exposed": false,
                "honesty": "redb COW is library property; Connector does not expose/prove process-kill fsync here",
            },
        },
        "honesty": if copg_enabled() {
            "COPG — Connector Operation Persistence Graph (redb; lighter than SQLite)"
        } else if store_mode() == "copg" {
            "COPG configured — set CONNECTOR_ARC_DURABLE=1"
        } else {
            "Soft jsonl — set CONNECTOR_ARC_STORE=copg for graph+SQL-ish redb store"
        },
        "doc": "platform/docs/arch/CONNECTOR_COPG.md",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::substrate::arc::transaction::{AgencyTransaction, TxState};

    fn temp_copg_dir() -> PathBuf {
        std::env::temp_dir().join(format!("copg-test-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn copg_graph_and_select_roundtrip() {
        let dir = temp_copg_dir();
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("CONNECTOR_ARC_DURABLE_DIR", dir.display().to_string());
        std::env::set_var("CONNECTOR_ARC_DURABLE", "1");
        std::env::set_var("CONNECTOR_ARC_STORE", "copg");

        let store = CopgStore::open(&dir).unwrap();
        store
            .put_graph_edge("agent-1", "genesis", "c1", "worldline_next")
            .unwrap();
        let mut tx = AgencyTransaction::new("agent-1", 1, Some("p".into()));
        tx.transition(TxState::Validated).unwrap();
        store
            .append_record("agency_tx", &tx.tx_id, Some("agent-1"), tx.to_json())
            .unwrap();

        let g = store.graph_export("agent-1");
        assert!(g.get("edges").and_then(|e| e.as_array()).unwrap().len() >= 1);

        let rows = store
            .select(CopgTable::AgencyTransactions, Some("agent-1"), 10)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert!(store.chain_tip().unwrap().is_some());

        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("CONNECTOR_ARC_DURABLE_DIR");
        std::env::remove_var("CONNECTOR_ARC_DURABLE");
        std::env::remove_var("CONNECTOR_ARC_STORE");
    }
}
