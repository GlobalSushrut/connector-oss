//! Durable persistence facade — JSONL (Soft) or COPG/redb (graph + SQL-ish).
//! Enable: `CONNECTOR_ARC_DURABLE=1`; store: `CONNECTOR_ARC_STORE=jsonl|copg`.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use super::copg;
use super::flags::ArcFlags;
use super::transaction::AgencyTransaction;
use super::worldline::WorldlineCommit;
use super::worldline_store::WorldlineStore;

fn env_on(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

pub fn durable_enabled() -> bool {
    env_on("CONNECTOR_ARC_DURABLE")
        || std::env::var("CONNECTOR_ARC_DURABLE_DIR")
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
        || ArcFlags::from_env().harden
}

pub fn durable_dir() -> PathBuf {
    if let Ok(d) = std::env::var("CONNECTOR_ARC_DURABLE_DIR") {
        let t = d.trim();
        if !t.is_empty() {
            return PathBuf::from(t);
        }
    }
    if let Ok(d) = std::env::var("CONNECTOR_DATA_DIR") {
        return PathBuf::from(d).join("arc");
    }
    PathBuf::from(".connector-arc-data")
}

fn jsonl_enabled() -> bool {
    durable_enabled() && !copg::copg_enabled()
}

fn worldline_path() -> PathBuf {
    durable_dir().join("worldline.jsonl")
}

/// Append one commit (best-effort; never panics).
pub fn persist_worldline_commit(commit: &WorldlineCommit) {
    if copg::copg_enabled() {
        copg::persist_worldline_commit(commit);
        return;
    }
    if !jsonl_enabled() {
        return;
    }
    let dir = durable_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        tracing::warn!(error = %e, "arc_durable: mkdir failed");
        return;
    }
    let line = match serde_json::to_string(commit) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "arc_durable: serialize failed");
            return;
        }
    };
    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(worldline_path())
    {
        Ok(mut f) => {
            let _ = writeln!(f, "{line}");
        }
        Err(e) => tracing::warn!(error = %e, "arc_durable: open worldline.jsonl failed"),
    }
}

pub fn persist_agency_tx(tx: &AgencyTransaction) {
    copg::persist_agency_tx(tx);
    // Mirror JSON so boot hydrate works without COPG / without PlatformState.
    let dir = durable_dir().join("agency_txs");
    if let Err(e) = fs::create_dir_all(&dir) {
        tracing::warn!(error = %e, "arc_durable: agency_txs mkdir failed");
        return;
    }
    if let Ok(s) = serde_json::to_string(tx) {
        let path = dir.join(format!("{}.json", tx.tx_id));
        if let Err(e) = fs::write(&path, s) {
            tracing::warn!(error = %e, path = %path.display(), "arc_durable: agency_tx write failed");
        }
    }
}

/// Load agency txs from durable_dir JSON mirror.
pub fn load_agency_txs_from_disk() -> Vec<AgencyTransaction> {
    let dir = durable_dir().join("agency_txs");
    let Ok(rd) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ent in rd.flatten() {
        let path = ent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(bytes) = fs::read(&path) {
            if let Ok(tx) = serde_json::from_slice::<AgencyTransaction>(&bytes) {
                out.push(tx);
            }
        }
    }
    out
}

pub fn persist_lease(lease: &super::lease::ConsequenceLease) {
    let dir = durable_dir().join("leases");
    if let Err(e) = fs::create_dir_all(&dir) {
        tracing::warn!(error = %e, "arc_durable: leases mkdir failed");
        return;
    }
    if let Ok(s) = serde_json::to_string(lease) {
        let path = dir.join(format!("{}.json", lease.lease_id));
        let _ = fs::write(path, s);
    }
}

pub fn load_leases_from_disk() -> Vec<super::lease::ConsequenceLease> {
    let dir = durable_dir().join("leases");
    let Ok(rd) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ent in rd.flatten() {
        let path = ent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(bytes) = fs::read(&path) {
            if let Ok(l) = serde_json::from_slice::<super::lease::ConsequenceLease>(&bytes) {
                out.push(l);
            }
        }
    }
    out
}

/// Also mirror into engine_store when a PlatformState is available (boot recovery path).
pub fn persist_agency_tx_with_state(state: &crate::state::PlatformState, tx: &AgencyTransaction) {
    persist_agency_tx(tx);
    crate::substrate::crash_recovery::persist_tx_engine(state, tx);
}

/// Load durable state into in-memory store once per process.
pub fn load_worldline_into(store: &WorldlineStore) {
    if !durable_enabled() {
        return;
    }
    if copg::copg_enabled() {
        copg::load_worldline_into(store);
        return;
    }
    use std::sync::OnceLock;
    static LOADED: OnceLock<()> = OnceLock::new();
    let _ = LOADED.get_or_init(|| {
        let path = worldline_path();
        let Ok(f) = fs::File::open(&path) else {
            return;
        };
        let reader = BufReader::new(f);
        let mut n = 0usize;
        for line in reader.lines().flatten() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(c) = serde_json::from_str::<WorldlineCommit>(line) {
                store.append_memory_only(c);
                n += 1;
            }
        }
        if n > 0 {
            tracing::info!(commits = n, path = %path.display(), "arc_durable: loaded worldline");
        }
    });
}

pub fn posture_json() -> serde_json::Value {
    serde_json::json!({
        "enabled": durable_enabled(),
        "dir": durable_dir().display().to_string(),
        "store": copg::store_mode(),
        "worldline_file": worldline_path().display().to_string(),
        "copg_db": copg::posture_json().get("db_path"),
        "honesty": if copg::copg_enabled() {
            "COPG redb — graph + SQL-ish + integrity chain (see CONNECTOR_COPG.md)"
        } else if durable_enabled() {
            "JSONL Soft — set CONNECTOR_ARC_STORE=copg for graph store"
        } else {
            "Soft — set CONNECTOR_ARC_DURABLE=1 or CONNECTOR_ARC_DURABLE_DIR"
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::substrate::arc::runtime;
    use crate::substrate::arc::transaction::{AgencyTransaction, TxState};
    use crate::substrate::arc::worldline;

    #[test]
    fn durable_jsonl_roundtrip_file() {
        let dir = std::env::temp_dir().join(format!("arc-durable-{}", uuid::Uuid::new_v4()));
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("CONNECTOR_ARC_DURABLE_DIR", dir.display().to_string());
        std::env::set_var("CONNECTOR_ARC_DURABLE", "1");
        std::env::set_var("CONNECTOR_ARC_STORE", "jsonl");

        let agent = "arc-durable-agent";
        let mut tx = AgencyTransaction::new(agent, 1, Some("p".into()));
        for s in [
            TxState::Validated,
            TxState::Reserved,
            TxState::Leased,
            TxState::Redeeming,
            TxState::EffectStarted,
            TxState::Settled,
            TxState::Committed,
        ] {
            tx.transition(s).unwrap();
        }
        runtime::transactions().insert(tx.clone());
        let c = worldline::commit_from_tx(&tx.tx_id, 2).unwrap();
        assert!(worldline_path().exists());

        let store = WorldlineStore::new();
        let f = fs::File::open(worldline_path()).unwrap();
        for line in BufReader::new(f).lines().flatten() {
            let got: WorldlineCommit = serde_json::from_str(&line).unwrap();
            assert_eq!(got.commit_id, c.commit_id);
            store.append_memory_only(got);
        }
        assert_eq!(store.head(agent).unwrap().digest, c.digest);

        let _ = fs::remove_dir_all(&dir);
        std::env::remove_var("CONNECTOR_ARC_DURABLE_DIR");
        std::env::remove_var("CONNECTOR_ARC_DURABLE");
        std::env::remove_var("CONNECTOR_ARC_STORE");
    }
}
