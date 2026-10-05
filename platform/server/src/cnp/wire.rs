//! L2 CNP wire — length-prefixed TCP frames + L5 static 1-hop routing.
//!
//! Live: bytes on a socket (`CNP1` + u32be + JSON envelope), route table from
//! `CONNECTOR_CNP_PEERS`, inbound forward when `to != local_cell`.
//! Not live: multi-hop mesh, mTLS product, SWIM, cluster replication.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cnp::stack::{CnpStack, ProcessResult, StackError};
use crate::state::SharedState;

const MAGIC: &[u8; 4] = b"CNP1";
const MAX_FRAME: u32 = 1_048_576;
const INBOX_CAP: usize = 256;
pub const INBOX_FOLDER: &str = "cnp_wire_inbox";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEnvelope {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub payload: Value,
    pub ts_ms: i64,
    /// Seven Pillars §7 — optional CNP authority metadata (not ambient trust).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cls_contract_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantum_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Agent Packet DNA — seven genome params bound to payload (LLM/tools cannot forge).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dna: Option<connector_trust::AgentPacketDnaV1>,
}

/// Canonical signing for CNP wire envelopes. Malformed/unsigned metadata cannot mint authority.
pub fn sign_wire_envelope(env: &mut WireEnvelope) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let dna_digest = env
        .dna
        .as_ref()
        .map(|d| d.digest_hex.clone())
        .unwrap_or_default();
    let preimage = json!({
        "from": env.from,
        "to": env.to,
        "kind": env.kind,
        "payload": env.payload,
        "ts_ms": env.ts_ms,
        "principal_id": env.principal_id,
        "workload_id": env.workload_id,
        "cls_contract_hash": env.cls_contract_hash,
        "quantum_id": env.quantum_id,
        "flow_lease_id": env.flow_lease_id,
        "nonce": env.nonce,
        "expires_at_ms": env.expires_at_ms,
        "dna_digest": dna_digest,
    });
    let bytes = serde_json::to_vec(&preimage).unwrap_or_default();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let key = std::env::var("CONNECTOR_CNP_HMAC")
        .or_else(|_| std::env::var("CONNECTOR_AUDIT_HMAC_SECRET"))
        .unwrap_or_else(|_| "connector-cnp-dev".into());
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"fallback").expect("hmac"));
    mac.update(digest.as_bytes());
    env.digest_hex = Some(digest);
    env.signature = Some(hex::encode(mac.finalize().into_bytes()));
}

pub fn verify_wire_envelope(env: &WireEnvelope) -> Result<(), String> {
    // DNA genome gate runs regardless of envelope signature mode.
    crate::substrate::packet_dna::assert_dna_or_refuse(env.dna.as_ref(), Some(&env.payload))?;

    let Some(sig) = env.signature.as_deref() else {
        if std::env::var("CONNECTOR_CNP_REQUIRE_SIGNATURE")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
        {
            return Err("cnp_signature_required".into());
        }
        return Ok(());
    };
    let mut probe = env.clone();
    probe.digest_hex = None;
    probe.signature = None;
    sign_wire_envelope(&mut probe);
    if probe.digest_hex.as_deref() != env.digest_hex.as_deref() {
        return Err("cnp_digest_mismatch".into());
    }
    if probe.signature.as_deref() != Some(sig) {
        return Err("cnp_signature_invalid".into());
    }
    if let Some(exp) = env.expires_at_ms {
        let now = chrono::Utc::now().timestamp_millis();
        if now > exp {
            return Err("cnp_envelope_expired".into());
        }
    }
    Ok(())
}

fn inbox() -> &'static Mutex<VecDeque<Value>> {
    static INBOX: OnceLock<Mutex<VecDeque<Value>>> = OnceLock::new();
    INBOX.get_or_init(|| Mutex::new(VecDeque::new()))
}

static BIND_STATUS: OnceLock<Mutex<Value>> = OnceLock::new();
static ENGINE: OnceLock<SharedState> = OnceLock::new();
static STACK: OnceLock<Mutex<CnpStack>> = OnceLock::new();

fn bind_status_slot() -> &'static Mutex<Value> {
    BIND_STATUS.get_or_init(|| Mutex::new(json!({"listening": false})))
}

pub fn local_cell_id() -> String {
    std::env::var("CONNECTOR_CELL_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "cell_local".into())
}

pub fn global_stack() -> &'static Mutex<CnpStack> {
    STACK.get_or_init(|| {
        let mut s = CnpStack::new(local_cell_id(), crate::cnp::stack::CnpConfig::default());
        s.seed_static_routes();
        Mutex::new(s)
    })
}

pub fn l5_static_routing_live() -> bool {
    !peer_map().is_empty()
}

pub fn boot(local_cell_id: &str, state: SharedState) {
    let _ = ENGINE.set(state);
    let mut stack = CnpStack::new(
        local_cell_id.to_string(),
        crate::cnp::stack::CnpConfig::default(),
    );
    stack.seed_static_routes();
    let routes = stack.routing.route_count();
    let peers = peer_map().len();
    if let Some(slot) = STACK.get() {
        if let Ok(mut g) = slot.lock() {
            *g = stack;
            tracing::info!(
                routes,
                peers,
                local_cell_id,
                "CNP L5 static routes seeded from CONNECTOR_CNP_PEERS (stack replaced)"
            );
            return;
        }
    }
    let _ = STACK.set(Mutex::new(stack));
    tracing::info!(
        routes,
        peers,
        local_cell_id,
        "CNP L5 static routes seeded from CONNECTOR_CNP_PEERS"
    );
}

/// Mint Agent Packet DNA for a CNP payload when engine + agent context exist.
pub fn try_mint_dna_for_payload(
    payload: &Value,
    agent_hint: &str,
) -> Option<connector_trust::AgentPacketDnaV1> {
    let state = ENGINE.get()?;
    let agent_pid = payload
        .get("agent_pid")
        .or_else(|| payload.get("from_agent"))
        .and_then(|v| v.as_str())
        .unwrap_or(agent_hint);
    let params = payload
        .get("parameters")
        .cloned()
        .unwrap_or_else(|| json!({}));
    crate::substrate::packet_dna::mint_for_agent(
        state.as_ref(),
        agent_pid,
        "cnp.send",
        "cnp:wire",
        &params,
        payload,
        None,
        None,
        60_000,
    )
    .ok()
}

pub fn encode_frame(body: &[u8]) -> Result<Vec<u8>, String> {
    if body.len() > MAX_FRAME as usize {
        return Err("cnp_frame_too_large".into());
    }
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

pub fn decode_frame(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 8 {
        return Err("cnp_frame_truncated".into());
    }
    if &data[..4] != MAGIC {
        return Err("cnp_frame_bad_magic".into());
    }
    let len = u32::from_be_bytes(data[4..8].try_into().unwrap_or([0; 4]));
    if len == 0 || len > MAX_FRAME {
        return Err("cnp_frame_bad_len".into());
    }
    let end = 8usize.saturating_add(len as usize);
    if data.len() < end {
        return Err("cnp_frame_truncated".into());
    }
    Ok(data[8..end].to_vec())
}

pub fn parse_envelope(data: &[u8]) -> Result<WireEnvelope, String> {
    let body = decode_frame(data)?;
    serde_json::from_slice(&body).map_err(|e| format!("cnp_envelope_json: {e}"))
}

pub fn inbox_push(env: &WireEnvelope) -> Value {
    let id = format!(
        "cnp_{}_{}",
        env.ts_ms,
        env.from.chars().take(24).collect::<String>()
    );
    let rec = json!({
        "id": id,
        "from": env.from,
        "to": env.to,
        "kind": env.kind,
        "payload": env.payload,
        "ts_ms": env.ts_ms,
    });
    if let Ok(mut g) = inbox().lock() {
        g.push_back(rec.clone());
        while g.len() > INBOX_CAP {
            g.pop_front();
        }
    }
    rec
}

pub fn inbox_snapshot() -> Vec<Value> {
    inbox()
        .lock()
        .map(|g| g.iter().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
pub fn inbox_clear() {
    if let Ok(mut g) = inbox().lock() {
        g.clear();
    }
}

/// Serialize CNP wire tests — inbox + `CONNECTOR_CNP_PEERS` are process-global.
#[cfg(test)]
pub fn test_serial_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn l5_honesty_text() -> &'static str {
    "L2 TCP + L5 static 1-hop when CONNECTOR_CNP_PEERS is set. No multi-hop mesh, mTLS product, or cluster replication."
}

pub fn peer_map() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let raw = std::env::var("CONNECTOR_CNP_PEERS").unwrap_or_default();
    for part in raw.split(',') {
        let seg = part.trim();
        if seg.is_empty() {
            continue;
        }
        if let Some((cell, addr)) = seg.split_once('=') {
            let cell = cell.trim();
            let addr = addr.trim();
            if !cell.is_empty() && !addr.is_empty() {
                m.insert(cell.to_string(), addr.to_string());
            }
        }
    }
    m
}

pub fn lookup_peer(cell: &str) -> Option<SocketAddr> {
    let spec = peer_map().get(cell).cloned()?;
    parse_host_port(&spec)
}

pub fn parse_host_port(spec: &str) -> Option<SocketAddr> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    if let Ok(addr) = spec.parse::<SocketAddr>() {
        return Some(addr);
    }
    spec.to_socket_addrs().ok()?.next()
}

pub fn bind_addr() -> Option<SocketAddr> {
    let raw = std::env::var("CONNECTOR_CNP_BIND").unwrap_or_else(|_| "127.0.0.1:9410".into());
    let t = raw.trim();
    if t.is_empty() || t == "-" || t.eq_ignore_ascii_case("off") {
        return None;
    }
    parse_host_port(t)
}

pub fn tcp_send(addr: SocketAddr, frame: &[u8]) -> Result<(), String> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|e| format!("cnp_connect: {e}"))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("cnp_timeout: {e}"))?;
    s.write_all(frame).map_err(|e| format!("cnp_write: {e}"))?;
    s.flush().map_err(|e| format!("cnp_flush: {e}"))?;
    Ok(())
}

fn persist_inbox(rec: &Value) {
    let Some(state) = ENGINE.get() else {
        return;
    };
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    let id = rec
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("cnp_unknown");
    let _ = es.folder_put(INBOX_FOLDER, id, rec);
}

fn deliver_local(env: &WireEnvelope) -> Result<ProcessResult, StackError> {
    if env.kind == "actuation" || env.kind == "cnp.actuation" {
        let ticket = env
            .payload
            .get("pate_task_id")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty());
        if ticket.is_none() {
            return Err(StackError::Transport(
                "cnp_actuation_requires_pate_task".into(),
            ));
        }
    }
    let rec = inbox_push(env);
    persist_inbox(&rec);
    Ok(ProcessResult::Delivered)
}

fn forward_frame(dest_cell: &str, data: &[u8]) -> Result<ProcessResult, StackError> {
    if let Some(addr) = lookup_peer(dest_cell) {
        tcp_send(addr, data).map_err(StackError::Transport)?;
        return Ok(ProcessResult::Forwarded(dest_cell.to_string()));
    }
    if let Ok(stack) = global_stack().lock() {
        if let Some(route) = stack.routing.get_best_route(dest_cell) {
            if let Some(addr) = parse_host_port(&route.next_hop) {
                tcp_send(addr, data).map_err(StackError::Transport)?;
                return Ok(ProcessResult::Forwarded(dest_cell.to_string()));
            }
        }
    }
    Err(StackError::Transport(format!("no_route:{dest_cell}")))
}

fn effective_local_cell_id() -> String {
    global_stack()
        .lock()
        .map(|s| s.routing.local_cell_id().to_string())
        .unwrap_or_else(|_| local_cell_id())
}

/// L5: local inbox when `to == local`; else static 1-hop TCP forward.
pub fn route_inbound_bytes(data: &[u8]) -> Result<ProcessResult, StackError> {
    route_inbound_bytes_for(data, &effective_local_cell_id())
}

pub fn route_inbound_bytes_for(data: &[u8], local_cell: &str) -> Result<ProcessResult, StackError> {
    let env = parse_envelope(data).map_err(StackError::Transport)?;
    verify_wire_envelope(&env).map_err(StackError::Transport)?;
    if crate::cnp::peer_overlay::overlay_enforced() {
        let _ = crate::cnp::peer_overlay::verify_peer_identity(&env.from, None, None)
            .map_err(|e| StackError::Transport(e))?;
    }
    if env.to == local_cell || env.to == "local" {
        return deliver_local(&env);
    }
    forward_frame(&env.to, data)
}

pub fn deliver_bytes(data: &[u8]) -> Result<ProcessResult, StackError> {
    route_inbound_bytes(data)
}

async fn read_frame(sock: &mut tokio::net::TcpStream) -> Result<Vec<u8>, String> {
    let mut hdr = [0u8; 8];
    sock.read_exact(&mut hdr)
        .await
        .map_err(|e| format!("cnp_read_hdr: {e}"))?;
    if &hdr[..4] != MAGIC {
        return Err("cnp_frame_bad_magic".into());
    }
    let len = u32::from_be_bytes(hdr[4..8].try_into().unwrap_or([0; 4]));
    if len == 0 || len > MAX_FRAME {
        return Err("cnp_frame_bad_len".into());
    }
    let mut body = vec![0u8; len as usize];
    sock.read_exact(&mut body)
        .await
        .map_err(|e| format!("cnp_read_body: {e}"))?;
    let mut frame = Vec::with_capacity(8 + body.len());
    frame.extend_from_slice(&hdr);
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn wire_status() -> Value {
    let routes = global_stack()
        .lock()
        .map(|s| s.routing.route_count())
        .unwrap_or(0);
    bind_status_slot()
        .lock()
        .map(|g| {
            let mut v = g.clone();
            if let Some(obj) = v.as_object_mut() {
                obj.insert("l5_static_routes".into(), json!(routes));
                obj.insert("l5_static_live".into(), json!(l5_static_routing_live()));
                obj.insert(
                    "cnp_l5_mode".into(),
                    json!(if l5_static_routing_live() {
                        "static_1hop"
                    } else {
                        "local_only"
                    }),
                );
                obj.insert("honesty".into(), json!(l5_honesty_text()));
            }
            v
        })
        .unwrap_or(json!({"listening": false}))
}

pub async fn listen_loop() {
    let Some(addr) = bind_addr() else {
        if let Ok(mut g) = bind_status_slot().lock() {
            *g = json!({
                "listening": false,
                "reason": "CONNECTOR_CNP_BIND off",
            });
        }
        tracing::info!("CNP L2 TCP listener disabled (CONNECTOR_CNP_BIND off)");
        return;
    };
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            if let Ok(mut g) = bind_status_slot().lock() {
                *g = json!({
                    "listening": false,
                    "bind": addr.to_string(),
                    "error": e.to_string(),
                });
            }
            tracing::error!(%addr, error = %e, "CNP L2 TCP bind failed");
            return;
        }
    };
    let routes = global_stack()
        .lock()
        .map(|s| s.routing.route_count())
        .unwrap_or(0);
    if let Ok(mut g) = bind_status_slot().lock() {
        *g = json!({
            "listening": true,
            "bind": addr.to_string(),
            "l5_static_routes": routes,
            "l5_static_live": l5_static_routing_live(),
            "cnp_l5_mode": if l5_static_routing_live() { "static_1hop" } else { "local_only" },
            "honesty": l5_honesty_text(),
        });
    }
    tracing::info!(%addr, routes, "CNP L2 TCP listener bound (L5 static routes seeded)");
    loop {
        match listener.accept().await {
            Ok((mut sock, peer)) => {
                tokio::spawn(async move {
                    match read_frame(&mut sock).await {
                        Ok(frame) => match route_inbound_bytes(&frame) {
                            Ok(ProcessResult::Delivered) => {
                                let _ = sock.write_all(b"OK").await;
                            }
                            Ok(ProcessResult::Forwarded(dest)) => {
                                let _ = sock.write_all(format!("FWD:{dest}").as_bytes()).await;
                            }
                            Ok(ProcessResult::Dropped(reason)) => {
                                tracing::warn!(%peer, %reason, "CNP frame dropped");
                            }
                            Err(e) => {
                                tracing::warn!(%peer, error = ?e, "CNP frame rejected");
                            }
                        },
                        Err(e) => {
                            tracing::warn!(%peer, error = %e, "CNP read failed");
                        }
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "CNP accept failed");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let _guard = test_serial_lock();
        let body = br#"{"from":"a","to":"b","kind":"cognitive","payload":{"x":1},"ts_ms":1}"#;
        let frame = encode_frame(body).unwrap();
        assert_eq!(decode_frame(&frame).unwrap(), body);
        let env = parse_envelope(&frame).unwrap();
        assert_eq!(env.from, "a");
        assert_eq!(env.to, "b");
    }

    #[test]
    fn garbage_rejected() {
        let _guard = test_serial_lock();
        assert!(decode_frame(b"").is_err());
        assert!(decode_frame(b"XXXX\x00\x00\x00\x01!").is_err());
    }

    #[test]
    fn local_delivery_when_to_matches_cell() {
        let _guard = test_serial_lock();
        inbox_clear();
        let body = br#"{"from":"b","to":"cell_a","kind":"cognitive","payload":{"t":"hi"},"ts_ms":2}"#;
        let frame = encode_frame(body).unwrap();
        let r = route_inbound_bytes_for(&frame, "cell_a").unwrap();
        assert!(matches!(r, ProcessResult::Delivered));
        assert!(inbox_snapshot().iter().any(|v| format!("{v}").contains("hi")));
    }

    #[test]
    fn actuation_without_a_pate_task_is_refused() {
        let _guard = test_serial_lock();
        inbox_clear();
        let body = br#"{"from":"b","to":"cell_a","kind":"actuation","payload":{"cmd":"stop"},"ts_ms":2}"#;
        let frame = encode_frame(body).unwrap();
        let err = route_inbound_bytes_for(&frame, "cell_a").expect_err("ticket");
        assert!(format!("{err:?}").contains("cnp_actuation_requires_pate_task"));
        assert!(inbox_snapshot().is_empty());
    }

    #[test]
    fn forward_errors_without_peer() {
        let _guard = test_serial_lock();
        inbox_clear();
        std::env::remove_var("CONNECTOR_CNP_PEERS");
        let body = br#"{"from":"x","to":"cell_remote","kind":"cognitive","payload":{},"ts_ms":3}"#;
        let frame = encode_frame(body).unwrap();
        assert!(route_inbound_bytes_for(&frame, "cell_a").is_err());
        assert!(inbox_snapshot().is_empty());
    }

    #[tokio::test]
    async fn l5_listen_loop_delivers_locally() {
        let _guard = test_serial_lock();
        inbox_clear();
        std::env::remove_var("CONNECTOR_CNP_PEERS");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let frame = read_frame(&mut sock).await.expect("read frame");
            let result = route_inbound_bytes_for(&frame, "cell_listen").expect("route");
            assert!(matches!(result, ProcessResult::Delivered));
            let _ = sock.write_all(b"OK").await;
        });

        let body = br#"{"from":"tokio","to":"cell_listen","kind":"cognitive","payload":{"text":"listen-loop"},"ts_ms":5}"#;
        let frame = encode_frame(body).unwrap();
        let mut client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect");
        client.write_all(&frame).await.expect("write frame");
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.expect("read ack");
        assert_eq!(&resp, b"OK");
        server.await.expect("server task");

        assert!(
            inbox_snapshot()
                .iter()
                .any(|v| format!("{v}").contains("listen-loop")),
            "listen_loop path should deliver to inbox"
        );
    }

    #[test]
    fn l5_static_forward_reaches_peer_inbox() {
        use std::io::Read;

        let _guard = test_serial_lock();
        inbox_clear();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind peer listener");
        listener
            .set_nonblocking(false)
            .expect("blocking listener");
        let addr = listener.local_addr().expect("peer addr");
        let peer_cell = "cell_b";
        std::env::set_var("CONNECTOR_CNP_PEERS", format!("{peer_cell}={addr}"));

        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("peer accept");
            let mut hdr = [0u8; 8];
            stream.read_exact(&mut hdr).expect("read hdr");
            let len = u32::from_be_bytes(hdr[4..8].try_into().unwrap()) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).expect("read body");
            let mut frame = Vec::with_capacity(8 + len);
            frame.extend_from_slice(&hdr);
            frame.extend_from_slice(&body);
            route_inbound_bytes_for(&frame, peer_cell).expect("peer deliver")
        });

        let body =
            br#"{"from":"cell_a","to":"cell_b","kind":"cognitive","payload":{"text":"l5-hop"},"ts_ms":4}"#;
        let frame = encode_frame(body).unwrap();
        let r = route_inbound_bytes_for(&frame, "cell_a").expect("forward");
        assert!(matches!(r, ProcessResult::Forwarded(ref d) if d == "cell_b"));
        assert!(matches!(peer.join().expect("peer thread"), ProcessResult::Delivered));
        assert!(
            inbox_snapshot()
                .iter()
                .any(|v| format!("{v}").contains("l5-hop")),
            "forwarded frame should land in peer inbox"
        );
        std::env::remove_var("CONNECTOR_CNP_PEERS");
    }
}
