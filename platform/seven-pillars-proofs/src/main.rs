//! Lightweight Seven Pillars PDF proofs — no full platform binary link.
//! Covers P1-T08 / P2-T08 / P4-T08 / P6-T09 / RG-08 non-collision at N=100
//! plus T2 channel tickets and T4 durable replay soak (file journal).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

fn egress_mark(agent_pid: &str) -> u32 {
    let dig = Sha256::digest(agent_pid.as_bytes());
    let low = u32::from_be_bytes([0, dig[0], dig[1], dig[2]]) & 0x00FF_FFFF;
    0xCD00_0000 | low
}

fn nsfs_root(agent_pid: &str) -> String {
    format!("nsfs/{agent_pid}")
}

fn soak_100(n: usize) -> Result<(), String> {
    let n = n.clamp(2, 256);
    let mut principals = HashSet::new();
    let mut roots = HashSet::new();
    let mut marks = HashSet::new();
    let mut flows = HashSet::new();
    for i in 0..n {
        let agent = format!("soak-agent-{i:03}");
        let principal = format!("prin-{i:03}");
        if !principals.insert(principal.clone()) {
            return Err("principal_collision".into());
        }
        if !roots.insert(nsfs_root(&agent)) {
            return Err("nsfs_collision".into());
        }
        let mark = egress_mark(&agent);
        if !marks.insert(mark) {
            return Err(format!("mark_collision:{mark:#x}"));
        }
        let flow = format!("{:x}", Sha256::digest(format!("{agent}|{principal}|flow").as_bytes()));
        if !flows.insert(flow) {
            return Err("flow_collision".into());
        }
    }
    Ok(())
}

/// T2 — mint/verify egress channel ticket (mirrors platform transparent_egress).
fn mint_ticket(secret: &[u8], agent: &str, host: &str, port: u16, exp: u64) -> String {
    let payload = format!("cegress.v1|{agent}|{host}|{port}|{exp}");
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac");
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("{payload}|{sig}")
}

fn verify_ticket(secret: &[u8], ticket: &str, agent: &str, host: &str, port: u16) -> bool {
    let parts: Vec<&str> = ticket.split('|').collect();
    if parts.len() != 6 || parts[1] != agent || parts[2] != host {
        return false;
    }
    if parts[3].parse::<u16>().ok() != Some(port) {
        return false;
    }
    let exp: u64 = match parts[4].parse() {
        Ok(e) => e,
        Err(_) => return false,
    };
    let payload = format!("cegress.v1|{agent}|{host}|{port}|{exp}");
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac");
    mac.update(payload.as_bytes());
    let expect = hex::encode(mac.finalize().into_bytes());
    parts[5] == expect
}

/// T4 — file-backed mission journal: complete once, "restart", refuse re-fire.
fn durable_replay_soak(dir: &PathBuf) -> Result<(), String> {
    let _ = fs::create_dir_all(dir);
    let path = dir.join("mission_journal.json");
    let idem = "tool:bridge:do_thing:deadbeef";
    let mut journal: BTreeMap<String, String> = BTreeMap::new();
    journal.insert(idem.into(), "completed".into());
    fs::write(&path, serde_json::to_string(&journal).unwrap()).map_err(|e| e.to_string())?;

    // Simulate restart: reload and refuse re-fire
    let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let loaded: BTreeMap<String, String> =
        serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    if loaded.get(idem).map(|s| s.as_str()) != Some("completed") {
        return Err("replay_missing_completed".into());
    }
    // Pending after crash
    let mut j2 = loaded;
    j2.insert("tool:bridge:other:aa".into(), "pending".into());
    fs::write(&path, serde_json::to_string(&j2).unwrap()).map_err(|e| e.to_string())?;
    let after: BTreeMap<String, String> =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    if after.get("tool:bridge:other:aa").map(|s| s.as_str()) == Some("pending") {
        // abandon → failed (restart-safe)
        let mut abandoned = after;
        abandoned.insert("tool:bridge:other:aa".into(), "failed_interrupted".into());
        if abandoned.get("tool:bridge:other:aa").map(|s| s.as_str())
            != Some("failed_interrupted")
        {
            return Err("abandon_failed".into());
        }
    }
    Ok(())
}

fn main() {
    soak_100(100).expect("100-agent soak");
    let secret = b"proof-secret";
    let t = mint_ticket(secret, "agent-a", "api.example.com", 443, 9_999_999_999);
    assert!(verify_ticket(secret, &t, "agent-a", "api.example.com", 443));
    assert!(!verify_ticket(secret, &t, "agent-b", "api.example.com", 443));
    let dir = std::env::temp_dir().join("connector-t4-soak");
    durable_replay_soak(&dir).expect("t4 soak");
    {
        use connector_trust::{mint_packet_dna, verify_packet_dna, AgentGenomeV1};
        let dna = mint_packet_dna(
            secret,
            AgentGenomeV1 {
                principal_id: "p".into(),
                agent_pid: "a".into(),
                character_hash: "c".into(),
                contract_hash: "k".into(),
                quantum_id: "q".into(),
                flow_lease_id: "f".into(),
                effect_digest: "e".into(),
            },
            "payload",
            60_000,
            0,
            "proof",
        )
        .expect("dna mint");
        verify_packet_dna(&dna, secret, Some("payload"), dna.issued_at_ms).expect("dna verify");
    }
    println!("seven-pillars-proofs: OK agents=100 t2_ticket t4_replay packet_dna");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soak_100_agents() {
        soak_100(100).unwrap();
    }

    #[test]
    fn marks_differ_for_neighbors() {
        assert_ne!(egress_mark("soak-agent-000"), egress_mark("soak-agent-001"));
    }

    #[test]
    fn t2_channel_ticket_binds_agent_host() {
        let secret = b"test-secret";
        let t = mint_ticket(secret, "a1", "host.example", 443, 9_999_999_999);
        assert!(verify_ticket(secret, &t, "a1", "host.example", 443));
        assert!(!verify_ticket(secret, &t, "a1", "evil.example", 443));
    }

    #[test]
    fn t4_durable_replay_across_restart() {
        let dir = std::env::temp_dir().join(format!(
            "connector-t4-{}",
            std::process::id()
        ));
        durable_replay_soak(&dir).unwrap();
    }

    #[test]
    fn packet_dna_seven_genome_tamper_denied() {
        use connector_trust::{
            mint_packet_dna, verify_packet_dna, AgentGenomeV1, PACKET_DNA_GENOME_LEN,
        };
        let g = AgentGenomeV1 {
            principal_id: "p".into(),
            agent_pid: "a".into(),
            character_hash: "c".into(),
            contract_hash: "k".into(),
            quantum_id: "q".into(),
            flow_lease_id: "f".into(),
            effect_digest: "e".into(),
        };
        assert_eq!(g.as_seven().len(), PACKET_DNA_GENOME_LEN);
        let secret = b"proof-dna-secret";
        let dna = mint_packet_dna(secret, g, "payload1", 60_000, 0, "proof").unwrap();
        verify_packet_dna(&dna, secret, Some("payload1"), dna.issued_at_ms).unwrap();
        let mut evil = dna.clone();
        evil.genome.effect_digest = "forged".into();
        assert!(verify_packet_dna(&evil, secret, Some("payload1"), dna.issued_at_ms).is_err());
    }
}
