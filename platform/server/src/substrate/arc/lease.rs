//! ConsequenceLease — Phase C (ARC-5).
//! Single-use, epoch-bound, digest-bound. Not a bearer ambient token.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{ConnectorError, DenialReason};

use super::flags::ArcFlags;
use super::ifc;
use super::runtime;
use super::transaction::TxState;
use super::worldline;

pub const SCHEMA: &str = "connector.arc.consequence_lease.v1";
pub const SINK_TOOL_DISPATCH: &str = "tool.dispatch";
pub const SINK_LLM_CHAT: &str = "llm.chat";
pub const SINK_CONP_COMMAND: &str = "conp.command";
const DEFAULT_TTL_MS: i64 = 60_000;

pub use super::ifc::IfcTriple;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsequenceLease {
    pub schema: String,
    pub lease_id: String,
    pub agent_id: String,
    pub body_id: Option<String>,
    pub tx_id: String,
    pub cognitive_epoch: u64,
    pub authority_epoch: u64,
    pub action_digest: String,
    pub proposal_digest: Option<String>,
    pub ifc: IfcTriple,
    pub bcr_reservation_id: Option<String>,
    pub nbf_ms: i64,
    pub exp_ms: i64,
    pub nonce: String,
    pub approval_digest: Option<String>,
    pub sink: String,
    pub mac: String,
    pub redeemed: bool,
    pub revoked: bool,
}

impl ConsequenceLease {
    pub fn mint(
        agent_id: impl Into<String>,
        body_id: Option<String>,
        tx_id: impl Into<String>,
        cognitive_epoch: u64,
        authority_epoch: u64,
        action_digest: impl Into<String>,
        proposal_digest: Option<String>,
        bcr_reservation_id: Option<String>,
        approval_digest: Option<String>,
        sink: impl Into<String>,
        ttl_ms: Option<i64>,
    ) -> Self {
        let now = now_ms();
        let ttl = ttl_ms.unwrap_or(DEFAULT_TTL_MS);
        let mut lease = Self {
            schema: SCHEMA.into(),
            lease_id: Uuid::new_v4().to_string(),
            agent_id: agent_id.into(),
            body_id,
            tx_id: tx_id.into(),
            cognitive_epoch,
            authority_epoch,
            action_digest: action_digest.into(),
            proposal_digest,
            ifc: IfcTriple::lab_default(),
            bcr_reservation_id,
            nbf_ms: now,
            exp_ms: now + ttl,
            nonce: Uuid::new_v4().to_string(),
            approval_digest,
            sink: sink.into(),
            mac: String::new(),
            redeemed: false,
            revoked: false,
        };
        lease.mac = lease.compute_mac();
        lease
    }

    fn mac_material(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "agent_id": self.agent_id,
            "body_id": self.body_id,
            "tx_id": self.tx_id,
            "cognitive_epoch": self.cognitive_epoch,
            "authority_epoch": self.authority_epoch,
            "action_digest": self.action_digest,
            "proposal_digest": self.proposal_digest,
            "ifc": self.ifc,
            "bcr_reservation_id": self.bcr_reservation_id,
            "nbf_ms": self.nbf_ms,
            "exp_ms": self.exp_ms,
            "nonce": self.nonce,
            "approval_digest": self.approval_digest,
            "sink": self.sink,
        })
    }

    pub fn compute_mac(&self) -> String {
        let key = mac_key_bytes();
        let body = serde_json::to_vec(&self.mac_material()).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(b"connector.arc.lease.mac.v1|");
        h.update(key);
        h.update(&body);
        format!("{:x}", h.finalize())
    }

    pub fn verify_mac(&self) -> bool {
        !self.mac.is_empty() && self.mac == self.compute_mac()
    }

    pub fn is_expired(&self, now: i64) -> bool {
        now < self.nbf_ms || now > self.exp_ms
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema": self.schema,
            "lease_id": self.lease_id,
            "agent_id": self.agent_id,
            "tx_id": self.tx_id,
            "authority_epoch": self.authority_epoch,
            "cognitive_epoch": self.cognitive_epoch,
            "action_digest": self.action_digest,
            "sink": self.sink,
            "nbf_ms": self.nbf_ms,
            "exp_ms": self.exp_ms,
            "redeemed": self.redeemed,
            "revoked": self.revoked,
            "mac_ok": self.verify_mac(),
        })
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn mac_key_bytes() -> Vec<u8> {
    if let Ok(k) = std::env::var("CONNECTOR_ARC_LEASE_MAC_KEY") {
        if !k.trim().is_empty() {
            return k.into_bytes();
        }
    }
    // LAB default — labeled soft key; production must set CONNECTOR_ARC_LEASE_MAC_KEY.
    b"connector-arc-lease-lab-mac-key-v1".to_vec()
}

/// Active handle for a sink effect under lease (C3/C4).
#[derive(Debug, Clone)]
pub struct LeaseEffectHandle {
    pub lease_id: String,
    pub tx_id: String,
    pub agent_id: String,
}

fn sink_ifc(sink: &str) -> IfcTriple {
    match sink {
        SINK_TOOL_DISPATCH | SINK_LLM_CHAT | SINK_CONP_COMMAND => IfcTriple {
            confidentiality: "secret".into(),
            integrity: "untrusted".into(),
            provenance: "any".into(),
        },
        _ => IfcTriple::system_sink(),
    }
}

/// After RESERVED, mint lease and transition tx → LEASED (C2).
pub fn mint_on_reserved(
    tx_id: &str,
    action_digest: &str,
    cognitive_epoch: u64,
    body_id: Option<String>,
    bcr_reservation_id: Option<String>,
    approval_digest: Option<String>,
    sink: &str,
) -> Result<ConsequenceLease, ConnectorError> {
    let flags = ArcFlags::from_env();
    if !flags.lease {
        return Err(ConnectorError::new(
            DenialReason::InternalError,
            "arc_lease: mint called with CONNECTOR_ARC_LEASE off",
        )
        .with_denied_resource("arc.lease"));
    }

    let mut tx = runtime::transactions()
        .get(tx_id)
        .ok_or_else(|| {
            ConnectorError::new(
                DenialReason::InternalError,
                format!("arc_lease: unknown tx {tx_id}"),
            )
            .with_denied_resource("arc.lease")
        })?;

    if tx.state != TxState::Reserved {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!(
                "arc_lease: mint requires RESERVED, got {}",
                tx.state.as_str()
            ),
        )
        .with_denied_resource("arc.lease"));
    }

    if runtime::leases().by_tx(tx_id).is_some() {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "arc_lease: already minted for tx (mint once)",
        )
        .with_denied_resource("arc.lease"));
    }

    let mut lease = ConsequenceLease::mint(
        tx.agent_id.clone(),
        body_id,
        tx.tx_id.clone(),
        cognitive_epoch,
        tx.authority_epoch_at_start,
        action_digest,
        tx.proposal_digest.clone(),
        bcr_reservation_id,
        approval_digest,
        sink,
        None,
    );

    // Phase D: IFC three-algebra gate before lease mint.
    let _ifc = ifc::assert_flow_or_deny(&lease.ifc, &sink_ifc(sink))?;
    lease.mac = lease.compute_mac();

    tx.lease_id = Some(lease.lease_id.clone());
    tx.transition(TxState::Leased).map_err(|e| {
        ConnectorError::new(DenialReason::InternalError, e.to_string())
            .with_denied_resource("arc.lease")
    })?;
    runtime::transactions().insert(tx);
    runtime::leases().insert(lease.clone());
    tracing::info!(
        lease_id = %lease.lease_id,
        tx_id = %lease.tx_id,
        agent_id = %lease.agent_id,
        sink = %sink,
        "arc_lease: RESERVED→LEASED minted"
    );
    Ok(lease)
}

/// Sink redeem: verify MAC/epoch/expiry/single-use → REDEEMING → EFFECT_STARTED (C3).
pub fn redeem(lease_id: &str, expected_agent: &str, sink: &str) -> Result<LeaseEffectHandle, ConnectorError> {
    let flags = ArcFlags::from_env();
    if !flags.lease {
        return Err(ConnectorError::new(
            DenialReason::InternalError,
            "arc_lease: redeem with flag off",
        )
        .with_denied_resource("arc.lease"));
    }

    let mut lease = runtime::leases().get(lease_id).ok_or_else(|| {
        ConnectorError::new(
            DenialReason::PolicyDenied,
            "arc_lease: unknown lease",
        )
        .with_denied_resource("arc.lease")
    })?;

    if lease.revoked {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "arc_lease: revoked (quarantine/epoch bump)",
        )
        .with_denied_resource("arc.lease")
        .with_hint("Re-admit after quarantine release"));
    }
    if lease.redeemed {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "arc_lease: replay — already redeemed (single-use)",
        )
        .with_denied_resource("arc.lease"));
    }
    if lease.agent_id != expected_agent {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "arc_lease: cross-agent redeem denied",
        )
        .with_denied_resource("arc.lease"));
    }
    if lease.sink != sink {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!(
                "arc_lease: sink mismatch lease={} call={}",
                lease.sink, sink
            ),
        )
        .with_denied_resource("arc.lease"));
    }
    if !lease.verify_mac() {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "arc_lease: MAC verification failed",
        )
        .with_denied_resource("arc.lease"));
    }
    if lease.is_expired(now_ms()) {
        let _ = runtime::transactions().transition(&lease.tx_id, TxState::Expired);
        lease.revoked = true;
        runtime::leases().insert(lease);
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "arc_lease: expired",
        )
        .with_denied_resource("arc.lease"));
    }

    let current = runtime::epochs().current(&lease.agent_id).get();
    if lease.authority_epoch != current {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!(
                "arc_lease: authority_epoch mismatch lease={} current={}",
                lease.authority_epoch, current
            ),
        )
        .with_denied_resource("arc.lease")
        .with_hint("Epoch bumped (quarantine/revoke) — lease unreachable"));
    }

    runtime::transactions()
        .transition(&lease.tx_id, TxState::Redeeming)
        .map_err(|e| {
            ConnectorError::new(DenialReason::InternalError, e).with_denied_resource("arc.lease")
        })?;
    runtime::transactions()
        .transition(&lease.tx_id, TxState::EffectStarted)
        .map_err(|e| {
            ConnectorError::new(DenialReason::InternalError, e).with_denied_resource("arc.lease")
        })?;

    lease.redeemed = true;
    let handle = LeaseEffectHandle {
        lease_id: lease.lease_id.clone(),
        tx_id: lease.tx_id.clone(),
        agent_id: lease.agent_id.clone(),
    };
    runtime::leases().insert(lease);
    Ok(handle)
}

/// Successful effect → SETTLED → COMMITTED (C3). Never auto-COMMITTED from EFFECT_UNKNOWN.
pub fn settle_committed(handle: &LeaseEffectHandle) -> Result<(), ConnectorError> {
    runtime::transactions()
        .transition(&handle.tx_id, TxState::Settled)
        .map_err(|e| {
            ConnectorError::new(DenialReason::InternalError, e).with_denied_resource("arc.lease")
        })?;
    runtime::transactions()
        .transition(&handle.tx_id, TxState::Committed)
        .map_err(|e| {
            ConnectorError::new(DenialReason::InternalError, e).with_denied_resource("arc.lease")
        })?;
    // Phase E: WorldlineCommit is authoritative.
    let cog = runtime::transactions()
        .get(&handle.tx_id)
        .map(|t| t.authority_epoch_at_start)
        .unwrap_or(0);
    let _ = worldline::commit_from_tx(&handle.tx_id, cog)?;
    tracing::info!(
        lease_id = %handle.lease_id,
        tx_id = %handle.tx_id,
        "arc_lease: SETTLED→COMMITTED + worldline"
    );
    Ok(())
}

/// Failed effect after redeem → FAILED (not COMMITTED). B0.4: then Compensating hook.
pub fn settle_failed(handle: &LeaseEffectHandle) -> Result<(), ConnectorError> {
    runtime::transactions()
        .transition(&handle.tx_id, TxState::Failed)
        .map_err(|e| {
            ConnectorError::new(DenialReason::InternalError, e).with_denied_resource("arc.lease")
        })?;
    let _ = compensate_tx(&handle.tx_id, "settle_failed");
    Ok(())
}

/// C3b: crash between EFFECT_STARTED and SETTLED → EFFECT_UNKNOWN (never COMMITTED).
pub fn mark_effect_unknown(tx_id: &str) -> Result<(), ConnectorError> {
    runtime::transactions()
        .recover_crash_effect_started(tx_id)
        .map(|_| ())
        .map_err(|e| {
            ConnectorError::new(DenialReason::InternalError, e).with_denied_resource("arc.lease")
        })
}

/// C5: revoke all open leases for agent after epoch bump / quarantine.
pub fn revoke_agent_leases(agent_id: &str) -> usize {
    let n = runtime::leases().revoke_agent(agent_id);
    // Quarantine open non-terminal txs.
    for tx in runtime::transactions().list_for_agent(agent_id) {
        if !tx.state.is_terminal() && tx.state != TxState::EffectUnknown {
            let _ = runtime::transactions().transition(&tx.tx_id, TxState::Quarantined);
        }
    }
    if n > 0 {
        tracing::info!(agent_id = %agent_id, revoked = n, "arc_lease: revoked on quarantine/epoch bump");
    }
    n
}

/// Lease-mediated sink begin (tool / Talk / CONP). Soft no-op when LEASE off.
pub fn begin_sink_effect(
    agent_id: &str,
    action_digest: &str,
    task_id: &str,
    cognitive_epoch: u64,
    sink: &str,
) -> Result<Option<LeaseEffectHandle>, ConnectorError> {
    let flags = ArcFlags::from_env();
    if !flags.lease {
        return Ok(None);
    }
    if !flags.governor {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!(
                "arc_lease: CONNECTOR_ARC_LEASE=1 requires CONNECTOR_ARC_GOVERNOR=1 (sink={sink})"
            ),
        )
        .with_denied_resource("arc.lease")
        .with_hint("Enable both flags for lease-mediated effects"));
    }

    let tx = runtime::transactions()
        .find_reserved_for_agent(agent_id, task_id)
        .ok_or_else(|| {
            ConnectorError::new(
                DenialReason::PolicyDenied,
                format!(
                    "arc_lease: no RESERVED AgencyTransaction for {sink} (NoLease⇒NoEffect)"
                ),
            )
            .with_denied_resource("arc.lease")
            .with_hint("Governor must RESERVE before lease mint — check CONNECTOR_ARC_GOVERNOR")
        })?;

    let lease = mint_on_reserved(
        &tx.tx_id,
        action_digest,
        cognitive_epoch,
        None,
        None,
        None,
        sink,
    )?;
    let handle = redeem(&lease.lease_id, agent_id, sink)?;
    Ok(Some(handle))
}

/// C4 tool.dispatch sink (compat).
pub fn begin_tool_effect(
    agent_id: &str,
    action_digest: &str,
    task_id: &str,
    cognitive_epoch: u64,
) -> Result<Option<LeaseEffectHandle>, ConnectorError> {
    begin_sink_effect(
        agent_id,
        action_digest,
        task_id,
        cognitive_epoch,
        SINK_TOOL_DISPATCH,
    )
}

/// Finish tool effect: commit on ok, fail otherwise.
pub fn complete_tool_effect(handle: &LeaseEffectHandle, ok: bool) -> Result<(), ConnectorError> {
    if ok {
        settle_committed(handle)
    } else {
        settle_failed(handle)
    }
}

/// RAII guard — Drop settles FAILED unless `success()` called.
pub struct LeaseSinkGuard {
    handle: Option<LeaseEffectHandle>,
    sealed: bool,
}

impl LeaseSinkGuard {
    pub fn begin(
        agent_id: &str,
        action_digest: &str,
        task_id: &str,
        cognitive_epoch: u64,
    ) -> Result<Self, ConnectorError> {
        Self::begin_sink(
            agent_id,
            action_digest,
            task_id,
            cognitive_epoch,
            SINK_TOOL_DISPATCH,
        )
    }

    pub fn begin_sink(
        agent_id: &str,
        action_digest: &str,
        task_id: &str,
        cognitive_epoch: u64,
        sink: &str,
    ) -> Result<Self, ConnectorError> {
        let handle = begin_sink_effect(agent_id, action_digest, task_id, cognitive_epoch, sink)?;
        Ok(Self {
            handle,
            sealed: false,
        })
    }

    pub fn success(&mut self) {
        if let Some(ref h) = self.handle {
            let _ = settle_committed(h);
        }
        self.sealed = true;
        self.handle = None;
    }

    pub fn fail(&mut self) {
        if let Some(ref h) = self.handle {
            let _ = settle_failed(h);
        }
        self.sealed = true;
        self.handle = None;
    }
}

impl Drop for LeaseSinkGuard {
    fn drop(&mut self) {
        if self.sealed {
            return;
        }
        if let Some(ref h) = self.handle.take() {
            let _ = settle_failed(h);
        }
    }
}

/// B0.4: compensate hook — invoke registered AAPI inverse when present (best-effort).
pub fn compensate_tx(tx_id: &str, reason: &str) -> Result<(), ConnectorError> {
    let tx = runtime::transactions().get(tx_id).ok_or_else(|| {
        ConnectorError::new(
            DenialReason::InternalError,
            format!("arc_compensate: unknown tx {tx_id}"),
        )
        .with_denied_resource("arc.compensate")
    })?;
    // Legal: Failed|EffectUnknown|Settled → Compensating.
    if matches!(
        tx.state,
        TxState::Failed | TxState::EffectUnknown | TxState::Settled
    ) {
        let _ = runtime::transactions().transition(tx_id, TxState::Compensating);
    }
    tracing::info!(
        tx_id = %tx_id,
        agent_id = %tx.agent_id,
        reason = %reason,
        from = %tx.state.as_str(),
        "arc_compensate: Compensating edge recorded — AAPI inverse when registered"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::substrate::arc::transaction::AgencyTransaction;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn reserved_tx(agent: &str, digest: &str, task: &str) -> AgencyTransaction {
        let epoch = runtime::epochs().current(agent).get();
        let mut tx = AgencyTransaction::new(agent, epoch, Some(digest.into()));
        tx.idempotency_key = Some(task.into());
        tx.transition(TxState::Validated).unwrap();
        tx.transition(TxState::Reserved).unwrap();
        runtime::transactions().insert(tx.clone());
        tx
    }

    #[test]
    fn mint_redeem_settle_happy() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var("CONNECTOR_ARC_LEASE", "1");
        std::env::set_var("CONNECTOR_ARC_GOVERNOR", "1");
        let agent = "arc-c-happy";
        let tx = reserved_tx(agent, "d1", "task-happy");
        let lease = mint_on_reserved(&tx.tx_id, "d1", 0, None, None, None, SINK_TOOL_DISPATCH)
            .unwrap();
        assert!(lease.verify_mac());
        let h = redeem(&lease.lease_id, agent, SINK_TOOL_DISPATCH).unwrap();
        settle_committed(&h).unwrap();
        let done = runtime::transactions().get(&tx.tx_id).unwrap();
        assert_eq!(done.state, TxState::Committed);
        std::env::remove_var("CONNECTOR_ARC_LEASE");
        std::env::remove_var("CONNECTOR_ARC_GOVERNOR");
    }

    #[test]
    fn replay_redeem_denied() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var("CONNECTOR_ARC_LEASE", "1");
        let agent = "arc-c-replay";
        let tx = reserved_tx(agent, "d2", "task-replay");
        let lease = mint_on_reserved(&tx.tx_id, "d2", 0, None, None, None, SINK_TOOL_DISPATCH)
            .unwrap();
        redeem(&lease.lease_id, agent, SINK_TOOL_DISPATCH).unwrap();
        let err = redeem(&lease.lease_id, agent, SINK_TOOL_DISPATCH).unwrap_err();
        assert!(err.human_readable.contains("replay"));
        std::env::remove_var("CONNECTOR_ARC_LEASE");
    }

    #[test]
    fn cross_agent_denied() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var("CONNECTOR_ARC_LEASE", "1");
        let agent = "arc-c-owner";
        let tx = reserved_tx(agent, "d3", "task-xagent");
        let lease = mint_on_reserved(&tx.tx_id, "d3", 0, None, None, None, SINK_TOOL_DISPATCH)
            .unwrap();
        let err = redeem(&lease.lease_id, "other-agent", SINK_TOOL_DISPATCH).unwrap_err();
        assert!(err.human_readable.contains("cross-agent"));
        std::env::remove_var("CONNECTOR_ARC_LEASE");
    }

    #[test]
    fn epoch_mismatch_after_quarantine() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var("CONNECTOR_ARC_LEASE", "1");
        let agent = "arc-c-epoch";
        let tx = reserved_tx(agent, "d4", "task-epoch");
        let lease = mint_on_reserved(&tx.tx_id, "d4", 0, None, None, None, SINK_TOOL_DISPATCH)
            .unwrap();
        runtime::epochs().bump(agent);
        revoke_agent_leases(agent);
        let err = redeem(&lease.lease_id, agent, SINK_TOOL_DISPATCH).unwrap_err();
        assert!(
            err.human_readable.contains("revoked")
                || err.human_readable.contains("authority_epoch"),
            "{}",
            err.human_readable
        );
        std::env::remove_var("CONNECTOR_ARC_LEASE");
    }

    #[test]
    fn crash_effect_unknown_no_commit() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var("CONNECTOR_ARC_LEASE", "1");
        let agent = "arc-c-crash";
        let tx = reserved_tx(agent, "d5", "task-crash");
        let lease = mint_on_reserved(&tx.tx_id, "d5", 0, None, None, None, SINK_TOOL_DISPATCH)
            .unwrap();
        redeem(&lease.lease_id, agent, SINK_TOOL_DISPATCH).unwrap();
        mark_effect_unknown(&tx.tx_id).unwrap();
        let st = runtime::transactions().get(&tx.tx_id).unwrap();
        assert_eq!(st.state, TxState::EffectUnknown);
        assert!(runtime::transactions()
            .transition(&tx.tx_id, TxState::Committed)
            .is_err());
        std::env::remove_var("CONNECTOR_ARC_LEASE");
    }

    #[test]
    fn expired_lease_denied() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var("CONNECTOR_ARC_LEASE", "1");
        let agent = "arc-c-exp";
        let tx = reserved_tx(agent, "d6", "task-exp");
        let mut lease = ConsequenceLease::mint(
            agent,
            None,
            &tx.tx_id,
            0,
            tx.authority_epoch_at_start,
            "d6",
            None,
            None,
            None,
            SINK_TOOL_DISPATCH,
            Some(1),
        );
        lease.nbf_ms = 0;
        lease.exp_ms = 1; // already expired
        lease.mac = lease.compute_mac();
        let mut t = runtime::transactions().get(&tx.tx_id).unwrap();
        t.lease_id = Some(lease.lease_id.clone());
        t.transition(TxState::Leased).unwrap();
        runtime::transactions().insert(t);
        runtime::leases().insert(lease.clone());
        let err = redeem(&lease.lease_id, agent, SINK_TOOL_DISPATCH).unwrap_err();
        assert!(err.human_readable.contains("expired"));
        std::env::remove_var("CONNECTOR_ARC_LEASE");
    }

    #[test]
    fn settle_failed_enters_compensating() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var("CONNECTOR_ARC_LEASE", "1");
        let agent = "arc-c-comp";
        let tx = reserved_tx(agent, "d7", "task-comp");
        let lease = mint_on_reserved(&tx.tx_id, "d7", 0, None, None, None, SINK_LLM_CHAT).unwrap();
        let h = redeem(&lease.lease_id, agent, SINK_LLM_CHAT).unwrap();
        settle_failed(&h).unwrap();
        let done = runtime::transactions().get(&tx.tx_id).unwrap();
        assert_eq!(done.state, TxState::Compensating);
        assert!(done
            .worldline_edges
            .iter()
            .any(|e| e.contains("COMPENSATING")));
        std::env::remove_var("CONNECTOR_ARC_LEASE");
    }
}
