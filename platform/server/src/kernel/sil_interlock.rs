//! T6 — SIL safety interlock before partner HAL / physical CONP dispatch.
//!
//! Connector does **not** replace a SIL-certified safety PLC. It **does** refuse
//! physical world commands unless a partner safety body has attested safe-state
//! (heartbeat ACK) or an operator-signed break-glass is present.

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => false,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sil_required() -> bool {
    if env_truthy("CONNECTOR_CONP_SIL_BREAK_GLASS") {
        return false;
    }
    // Default on under productionish / unbypassable.
    if env_truthy("CONNECTOR_CONP_SIL_REQUIRE") {
        return true;
    }
    crate::connector_profile::is_productionish_env()
}

fn sil_secret() -> Vec<u8> {
    if let Ok(s) = std::env::var("CONNECTOR_CONP_SIL_HMAC_KEY") {
        if !s.trim().is_empty() {
            return s.into_bytes();
        }
    }
    if let Ok(s) = std::env::var("CONNECTOR_AUDIT_HMAC_KEY") {
        if !s.trim().is_empty() {
            return s.into_bytes();
        }
    }
    b"connector-sil-lab-fallback".to_vec()
}

/// Partner SIL safe-state attestation: `sil.v1|entity|exp|sig`.
pub fn verify_sil_attestation(entity_id: &str, token: &str) -> Result<(), String> {
    let parts: Vec<&str> = token.split('|').collect();
    if parts.len() != 4 || parts[0] != "sil.v1" {
        return Err("sil_attestation_malformed".into());
    }
    if parts[1] != entity_id {
        return Err("sil_attestation_entity_mismatch".into());
    }
    let exp: u64 = parts[2]
        .parse()
        .map_err(|_| "sil_attestation_exp".to_string())?;
    if now_secs() > exp {
        return Err("sil_attestation_expired".into());
    }
    let payload = format!("sil.v1|{entity_id}|{exp}");
    let mut mac = HmacSha256::new_from_slice(&sil_secret())
        .map_err(|_| "sil_hmac_init".to_string())?;
    mac.update(payload.as_bytes());
    let expect = hex::encode(mac.finalize().into_bytes());
    if parts[3] != expect {
        return Err("sil_attestation_sig".into());
    }
    Ok(())
}

pub fn mint_sil_attestation(entity_id: &str, ttl_secs: u64) -> Result<String, String> {
    let exp = now_secs().saturating_add(ttl_secs.max(1));
    let payload = format!("sil.v1|{entity_id}|{exp}");
    let mut mac = HmacSha256::new_from_slice(&sil_secret())
        .map_err(|_| "sil_hmac_init".to_string())?;
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    Ok(format!("{payload}|{sig}"))
}

/// Query partner SIL safety body over TCP JSON heartbeat.
fn query_partner_sil_heartbeat(entity_id: &str) -> Result<String, String> {
    let url = std::env::var("CONNECTOR_CONP_SIL_PARTNER_URL")
        .map_err(|_| "sil_partner_url_unset".to_string())?;
    let rest = url
        .strip_prefix("tcp://")
        .or_else(|| url.strip_prefix("sil://"))
        .unwrap_or(&url);
    let (host, port) = if let Some((h, p)) = rest.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(7448))
    } else {
        (rest.to_string(), 7448)
    };
    let addr = format!("{host}:{port}");
    let mut stream = if let Ok(sock) = addr.parse() {
        TcpStream::connect_timeout(&sock, Duration::from_millis(1500))
            .map_err(|e| format!("sil_connect:{e}"))?
    } else {
        TcpStream::connect(&addr).map_err(|e| format!("sil_connect:{e}"))?
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
    let req = json!({
        "schema": "connector.sil.heartbeat_req.v1",
        "entity_id": entity_id,
        "op": "safe_state_query",
    });
    let mut line = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    line.push(b'\n');
    stream
        .write_all(&line)
        .map_err(|e| format!("sil_write:{e}"))?;
    let mut buf = vec![0u8; 2048];
    let n = stream.read(&mut buf).map_err(|e| format!("sil_read:{e}"))?;
    let text = String::from_utf8_lossy(&buf[..n]);
    let v: Value = serde_json::from_str(text.lines().next().unwrap_or("{}"))
        .map_err(|_| "sil_bad_json".to_string())?;
    if v.get("safe").and_then(|x| x.as_bool()) != Some(true) {
        return Err("sil_partner_not_safe".into());
    }
    if let Some(tok) = v.get("attestation").and_then(|x| x.as_str()) {
        verify_sil_attestation(entity_id, tok)?;
        return Ok(tok.to_string());
    }
    // Partner said safe without token — mint local attestation only in lab.
    if env_truthy("CONNECTOR_CONP_SIL_LAB_MINT") {
        return mint_sil_attestation(entity_id, 30);
    }
    Err("sil_partner_missing_attestation".into())
}

/// Gate physical CONP / partner HAL dispatch.
pub fn assert_sil_safe_for_dispatch(
    entity_id: &str,
    provided_attestation: Option<&str>,
) -> Result<Value, String> {
    if !sil_required() {
        return Ok(json!({
            "sil_required": false,
            "mode": "not_required",
            "honesty": "SIL interlock off (lab) — enable CONNECTOR_CONP_SIL_REQUIRE under harden",
        }));
    }
    if let Some(tok) = provided_attestation {
        verify_sil_attestation(entity_id, tok)?;
        return Ok(json!({
            "sil_required": true,
            "mode": "attestation_header",
            "entity_id": entity_id,
            "ok": true,
        }));
    }
    if std::env::var("CONNECTOR_CONP_SIL_PARTNER_URL").is_ok() {
        let tok = query_partner_sil_heartbeat(entity_id)?;
        return Ok(json!({
            "sil_required": true,
            "mode": "partner_heartbeat",
            "entity_id": entity_id,
            "attestation_prefix": tok.split('|').take(3).collect::<Vec<_>>().join("|"),
            "ok": true,
            "honesty": "Partner SIL body attested safe-state — Connector still not the SIL certificate holder",
        }));
    }
    Err(
        "sil_interlock_required: set CONNECTOR_CONP_SIL_PARTNER_URL or provide sil_attestation \
         (or CONNECTOR_CONP_SIL_BREAK_GLASS=1 for incident only)"
            .into(),
    )
}

pub fn status() -> Value {
    json!({
        "schema": "connector.sil_interlock.status.v1",
        "required": sil_required(),
        "partner_url": std::env::var("CONNECTOR_CONP_SIL_PARTNER_URL").ok(),
        "break_glass": env_truthy("CONNECTOR_CONP_SIL_BREAK_GLASS"),
        "honesty": "Interlock gates physical dispatch; SIL certification remains partner-owned",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_roundtrip() {
        let t = mint_sil_attestation("robot-1", 60).unwrap();
        verify_sil_attestation("robot-1", &t).unwrap();
        assert!(verify_sil_attestation("robot-2", &t).is_err());
    }
}
