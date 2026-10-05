//! AACR compat layer (E4) — no double-write corruption on worldline head.

use std::sync::Arc;

use dashmap::DashMap;

use crate::error::{ConnectorError, DenialReason};

static LAST_WRITE: std::sync::OnceLock<Arc<DashMap<String, String>>> = std::sync::OnceLock::new();

fn map() -> &'static Arc<DashMap<String, String>> {
    LAST_WRITE.get_or_init(|| Arc::new(DashMap::new()))
}

/// Fence: concurrent AACR + ARC worldline writers for same agent must not fork.
pub fn assert_single_writer_worldline(agent_id: &str, commit_id: &str) -> Result<(), ConnectorError> {
    if let Some(existing) = map().get(agent_id) {
        // Same commit retry is ok; different in-flight commit_id without clear = refuse.
        if existing.as_str() != commit_id && existing.starts_with("inflight:") {
            return Err(ConnectorError::new(
                DenialReason::InternalError,
                format!(
                    "aacr_compat: double-write refused for agent {agent_id} (inflight {})",
                    existing.as_str()
                ),
            )
            .with_denied_resource("arc.aacr")
            .with_hint("Worldline is single-writer; wait for prior commit"));
        }
    }
    map().insert(agent_id.to_string(), format!("inflight:{commit_id}"));
    Ok(())
}

pub fn record_worldline_write(agent_id: &str, commit_id: &str) {
    map().insert(agent_id.to_string(), commit_id.to_string());
}

pub fn last_write(agent_id: &str) -> Option<String> {
    map().get(agent_id).map(|e| e.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_inflight_denied() {
        let agent = "arc-e-aacr";
        map().remove(agent);
        assert_single_writer_worldline(agent, "c1").unwrap();
        let err = assert_single_writer_worldline(agent, "c2").unwrap_err();
        assert!(err.human_readable.contains("double-write"));
        record_worldline_write(agent, "c1");
        // After seal, new commit may start.
        assert_single_writer_worldline(agent, "c3").unwrap();
        record_worldline_write(agent, "c3");
    }
}
