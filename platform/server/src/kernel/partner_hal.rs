//! T6 — Partner HAL protocol adapters (ROS bridge / Modbus TCP / MQTT).
//!
//! These are **real on-the-wire protocol adapters** that speak CONP envelopes to
//! partner endpoints. They are **not** SIL-certified safety bodies — SIL loops
//! remain partner-owned; Connector admits and forwards.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartnerHalKind {
    Ros,
    Modbus,
    Mqtt,
    GenericTcp,
}

impl PartnerHalKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ros" | "rosbridge" | "ros_bridge" => Some(Self::Ros),
            "modbus" | "modbus_tcp" => Some(Self::Modbus),
            "mqtt" => Some(Self::Mqtt),
            "tcp" | "generic" | "1" | "true" | "on" | "yes" => Some(Self::GenericTcp),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ros => "ros",
            Self::Modbus => "modbus",
            Self::Mqtt => "mqtt",
            Self::GenericTcp => "tcp",
        }
    }
}

pub fn configured_kind() -> Option<PartnerHalKind> {
    let raw = std::env::var("CONNECTOR_CONP_PARTNER_HAL").ok()?;
    PartnerHalKind::parse(&raw)
}

pub fn partner_endpoint() -> Option<String> {
    std::env::var("CONNECTOR_CONP_PARTNER_HAL_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
}

fn timeout() -> Duration {
    let ms: u64 = std::env::var("CONNECTOR_CONP_PARTNER_HAL_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3_000);
    Duration::from_millis(ms)
}

fn parse_host_port(url: &str) -> Result<(String, u16), String> {
    let s = url.trim();
    let rest = s
        .strip_prefix("tcp://")
        .or_else(|| s.strip_prefix("mqtt://"))
        .or_else(|| s.strip_prefix("ros://"))
        .or_else(|| s.strip_prefix("modbus://"))
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let hostport = rest.split('/').next().unwrap_or(rest);
    if let Some((h, p)) = hostport.rsplit_once(':') {
        let port: u16 = p
            .parse()
            .map_err(|_| "partner_hal_bad_port".to_string())?;
        Ok((h.to_string(), port))
    } else {
        let default = if s.starts_with("mqtt") {
            1883
        } else if s.starts_with("modbus") {
            502
        } else if s.starts_with("ros") {
            9090
        } else {
            7447
        };
        Ok((hostport.to_string(), default))
    }
}

fn connect(url: &str) -> Result<TcpStream, String> {
    let (host, port) = parse_host_port(url)?;
    let addr = format!("{host}:{port}");
    let stream = if let Ok(sock) = addr.parse() {
        TcpStream::connect_timeout(&sock, timeout())
            .map_err(|e| format!("partner_hal_connect:{e}"))?
    } else {
        TcpStream::connect(&addr).map_err(|e| format!("partner_hal_connect:{e}"))?
    };
    let _ = stream.set_read_timeout(Some(timeout()));
    let _ = stream.set_write_timeout(Some(timeout()));
    Ok(stream)
}

/// Dispatch a CONP command through the configured partner HAL adapter.
pub fn dispatch_conp_command(
    command_id: &str,
    capability_id: &str,
    entity_id: &str,
    parameters: &Value,
    action_digest: &str,
) -> Result<Value, String> {
    let kind = configured_kind().ok_or_else(|| "partner_hal_kind_unset".to_string())?;
    let endpoint = partner_endpoint().ok_or_else(|| "partner_hal_url_unset".to_string())?;
    let envelope = json!({
        "schema": "connector.conp.partner_hal.v1",
        "protocol": "CP/1.0",
        "message_type": "Command",
        "command_id": command_id,
        "capability_id": capability_id,
        "entity_id": entity_id,
        "parameters": parameters,
        "action_digest": action_digest,
    });
    match kind {
        PartnerHalKind::Ros => dispatch_ros(&endpoint, &envelope),
        PartnerHalKind::Modbus => dispatch_modbus(&endpoint, &envelope),
        PartnerHalKind::Mqtt => dispatch_mqtt(&endpoint, &envelope),
        PartnerHalKind::GenericTcp => dispatch_generic_tcp(&endpoint, &envelope),
    }
}

fn dispatch_generic_tcp(endpoint: &str, envelope: &Value) -> Result<Value, String> {
    let mut stream = connect(endpoint)?;
    let mut line = serde_json::to_vec(envelope).map_err(|e| e.to_string())?;
    line.push(b'\n');
    stream
        .write_all(&line)
        .map_err(|e| format!("partner_hal_write:{e}"))?;
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).unwrap_or(0);
    let ack_raw = if n > 0 {
        String::from_utf8_lossy(&buf[..n]).to_string()
    } else {
        "{}".into()
    };
    Ok(json!({
        "hal": "partner_tcp",
        "endpoint": endpoint,
        "bytes_written": line.len(),
        "ack_raw": ack_raw,
        "envelope": envelope,
        "honesty": "T6 — CONP envelope written on TCP to partner HAL (not SIL body loop)",
        "isolation": isolation_posture(),
    }))
}

/// rosbridge-style: `{"op":"publish","topic":"...","msg":{...}}`
fn dispatch_ros(endpoint: &str, envelope: &Value) -> Result<Value, String> {
    let topic = std::env::var("CONNECTOR_CONP_PARTNER_ROS_TOPIC")
        .unwrap_or_else(|_| "/connector/conp/command".into());
    let frame = json!({
        "op": "publish",
        "topic": topic,
        "msg": {
            "data": serde_json::to_string(envelope).unwrap_or_default(),
        }
    });
    let mut stream = connect(endpoint)?;
    let mut line = serde_json::to_vec(&frame).map_err(|e| e.to_string())?;
    line.push(b'\n');
    stream
        .write_all(&line)
        .map_err(|e| format!("partner_hal_ros_write:{e}"))?;
    Ok(json!({
        "hal": "partner_ros",
        "endpoint": endpoint,
        "topic": topic,
        "bytes_written": line.len(),
        "envelope": envelope,
        "honesty": "T6 — rosbridge publish of CONP command (partner owns robot body / SIL)",
    }))
}

/// Minimal Modbus TCP: FC16 write registers carrying digest prefix.
fn dispatch_modbus(endpoint: &str, envelope: &Value) -> Result<Value, String> {
    let mut stream = connect(endpoint)?;
    let dig = envelope
        .get("action_digest")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let mut regs = [0u16; 4];
    for (i, chunk) in dig.as_bytes().chunks(2).take(4).enumerate() {
        let hi = *chunk.first().unwrap_or(&0);
        let lo = *chunk.get(1).unwrap_or(&0);
        regs[i] = u16::from_be_bytes([hi, lo]);
    }
    // MBAP + PDU Write Multiple Registers (FC 16), unit id 1, start 0, qty 4
    let mut pdu = vec![0x10u8, 0x00, 0x00, 0x00, 0x04, 0x08];
    for r in regs {
        pdu.extend_from_slice(&r.to_be_bytes());
    }
    let len = (pdu.len() + 1) as u16; // unit id + pdu
    let mut frame = vec![0x00, 0x01, 0x00, 0x00]; // tx id, protocol
    frame.extend_from_slice(&len.to_be_bytes());
    frame.push(0x01); // unit
    frame.extend_from_slice(&pdu);
    stream
        .write_all(&frame)
        .map_err(|e| format!("partner_hal_modbus_write:{e}"))?;
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).unwrap_or(0);
    Ok(json!({
        "hal": "partner_modbus",
        "endpoint": endpoint,
        "bytes_written": frame.len(),
        "response_len": n,
        "registers": regs,
        "envelope": envelope,
        "honesty": "T6 — Modbus TCP FC16 carrying digest bytes (partner owns PLC safety)",
    }))
}

/// MQTT CONNECT + PUBLISH (QoS0) of CONP JSON payload.
fn dispatch_mqtt(endpoint: &str, envelope: &Value) -> Result<Value, String> {
    let mut stream = connect(endpoint)?;
    let client_id = b"connector-conp";
    // CONNECT
    let mut rem = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c];
    rem.push(0x00);
    rem.push(client_id.len() as u8);
    rem.extend_from_slice(client_id);
    let mut connect_pkt = vec![0x10];
    encode_remaining(&mut connect_pkt, rem.len());
    connect_pkt.extend_from_slice(&rem);
    stream
        .write_all(&connect_pkt)
        .map_err(|e| format!("partner_hal_mqtt_connect:{e}"))?;
    let mut ack = [0u8; 4];
    let _ = stream.read(&mut ack);

    let topic = std::env::var("CONNECTOR_CONP_PARTNER_MQTT_TOPIC")
        .unwrap_or_else(|_| "connector/conp/command".into());
    let payload = serde_json::to_vec(envelope).map_err(|e| e.to_string())?;
    let mut pub_rem = Vec::new();
    pub_rem.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    pub_rem.extend_from_slice(topic.as_bytes());
    pub_rem.extend_from_slice(&payload);
    let mut pub_pkt = vec![0x30]; // PUBLISH QoS0
    encode_remaining(&mut pub_pkt, pub_rem.len());
    pub_pkt.extend_from_slice(&pub_rem);
    stream
        .write_all(&pub_pkt)
        .map_err(|e| format!("partner_hal_mqtt_pub:{e}"))?;
    Ok(json!({
        "hal": "partner_mqtt",
        "endpoint": endpoint,
        "topic": topic,
        "bytes_written": pub_pkt.len(),
        "envelope": envelope,
        "honesty": "T6 — MQTT PUBLISH of CONP command (partner owns device loop)",
    }))
}

fn encode_remaining(out: &mut Vec<u8>, mut len: usize) {
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
}

pub fn status() -> Value {
    json!({
        "schema": "connector.partner_hal.status.v1",
        "configured": configured_kind().map(|k| k.as_str()),
        "endpoint": partner_endpoint(),
        "adapters": ["ros", "modbus", "mqtt", "tcp"],
        "isolation": isolation_posture(),
        "honesty": "Protocol adapters on the wire — SIL certification stays partner-side",
    })
}

/// NP-6 — HAL process plane is DockLock/Landlock, never the SIL body claim.
pub fn isolation_posture() -> Value {
    let landlock = connector_plugin_runtime::linux_hardening::landlock_posture_snapshot();
    json!({
        "schema": "connector.partner_hal.isolation.v1",
        "plane": "partner_hal",
        "sil_certified": false,
        "separate_from_sil_claim": true,
        "docklock_enforce": crate::kernel::docklock::docklock_enforce_enabled(),
        "landlock": landlock,
        "high_risk_prefer_microvm": ["machine.program_run", "machine.rapid"],
        "honesty": "Partner HAL runs as a DockLock/Landlock-admitted process — not a SIL safety body",
    })
}

pub fn prefer_microvm_cell(capability_id: &str) -> bool {
    crate::kernel::action_binding::prefers_microvm_hal(capability_id)
}

/// Deny partner HAL when Landlock fail-closed is on but the kernel ABI is missing.
pub fn assert_dispatch_isolation() -> Result<Value, String> {
    let posture = isolation_posture();
    let landlock = posture.get("landlock").cloned().unwrap_or_else(|| json!({}));
    let fail_closed = landlock
        .get("fail_closed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let abi = landlock
        .get("kernel_abi_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if fail_closed && crate::kernel::docklock::docklock_enforce_enabled() && !abi {
        return Err("partner_hal_landlock_required".into());
    }
    Ok(posture)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kinds() {
        assert_eq!(PartnerHalKind::parse("ros"), Some(PartnerHalKind::Ros));
        assert_eq!(
            PartnerHalKind::parse("modbus_tcp"),
            Some(PartnerHalKind::Modbus)
        );
        let iso = isolation_posture();
        assert_eq!(iso.get("sil_certified").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(
            iso.get("separate_from_sil_claim").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(prefer_microvm_cell("machine.program_run"));
    }

    #[test]
    fn mqtt_remaining_encode() {
        let mut v = vec![];
        encode_remaining(&mut v, 0);
        assert_eq!(v, vec![0]);
        let mut v = vec![];
        encode_remaining(&mut v, 200);
        assert_eq!(v.len(), 2);
    }
}
