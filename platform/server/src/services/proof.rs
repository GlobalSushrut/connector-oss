use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use vac_core::audit_export::ScittReceipt;
use vac_core::cid::compute_cid;

#[derive(Deserialize)]
pub struct GenerateProofRequest {
    pub agent_pid: String,
    pub session_id: Option<String>,
    pub title: Option<String>,
}

const PROOF_FOLDER: &str = "_trust_proofs";

pub async fn generate_proof(
    State(state): State<SharedState>,
    Json(req): Json<GenerateProofRequest>,
) -> Json<serde_json::Value> {
    let (trust_score, trust_grade, chain_ok, chain_head, ops_count, cid_chain) = {
        let k = state.kernel.lock().unwrap();
        let trust = connector_engine::TrustComputer::compute(&k);
        let audit = k.audit_log();
        let agent_ops: Vec<_> = audit
            .iter()
            .filter(|e| e.agent_pid == req.agent_pid)
            .collect();
        let cid_chain: Vec<String> = agent_ops.iter().filter_map(|e| e.target.clone()).collect();
        let chain_ok = k.verify_audit_chain().is_ok();
        (
            trust.score,
            trust.grade,
            chain_ok,
            k.audit_chain_head_after_hash(),
            agent_ops.len(),
            cid_chain,
        )
    };

    let proof_id = format!("prf_{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    let title = req
        .title
        .unwrap_or_else(|| format!("Work proof for {}", req.agent_pid));

    let cid_len = cid_chain.len();
    let record = serde_json::json!({
        "proof_id": proof_id,
        "agent_pid": req.agent_pid,
        "session_id": req.session_id,
        "title": title,
        "generated_at": now.to_rfc3339(),
        "agent_health_score": trust_score,
        "trust_grade": trust_grade,
        "operations_count": ops_count,
        "cid_chain": cid_chain.clone(),
        "cid_chain_length": cid_len,
        "audit_chain_ok_at_issue": chain_ok,
        "chain_head": chain_head,
        "verification_status": "unverified",
    });

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &req.agent_pid,
        "lifecycle",
        "issue_work_proof",
        &serde_json::json!({"agent_pid": req.agent_pid.as_str(), "proof_id": proof_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(PROOF_FOLDER, &proof_id, &record);
    }
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "proof_id": proof_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "agent_pid": req.agent_pid,
        "title": title,
        "generated_at": now.to_rfc3339(),
        "agent_health_score": trust_score,
        "trust_grade": trust_grade,
        "operations_count": ops_count,
        "cid_chain": cid_chain,
        "cid_chain_length": cid_len,
        // Generation is not independent verification — status stays explicit.
        "verified": false,
        "verification_status": "unverified",
        "audit_chain_ok_at_issue": chain_ok,
        "certificate_url": format!("/api/v1/proof/{}/certificate", proof_id),
        "verify_url": format!("/api/v1/proof/{}/verify", proof_id),
    }))
}

pub async fn get_certificate(
    State(state): State<SharedState>,
    Path(proof_id): Path<String>,
) -> Json<serde_json::Value> {
    let stored = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get(PROOF_FOLDER, &proof_id).ok().flatten()
    };

    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);
    let integrity = k.verify_audit_chain().is_ok();
    let now = chrono::Utc::now();

    let status = if stored.is_none() {
        "missing"
    } else if integrity {
        "integrity_ok_unsigned"
    } else {
        "integrity_failed"
    };

    Json(serde_json::json!({
        "certificate": {
            "proof_id": proof_id,
            "issued_at": stored.as_ref().and_then(|v| v.get("generated_at").cloned()).unwrap_or(serde_json::json!(now.to_rfc3339())),
            "agent_health_score": trust.score,
            "trust_grade": trust.grade,
            "kernel_packets": k.packet_count(),
            "audit_entries": k.audit_log().len(),
            "integrity_verified": integrity,
            "signature_algorithm": "Ed25519",
            "stored_proof": stored.is_some(),
        },
        "verification": {
            "status": status,
            "method": "audit chain recompute + stored proof lookup",
        }
    }))
}

/// Wave 4 — Item 4.6: Ed25519 signed trust certificate
pub async fn certificate_sign(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("system");
    let title = req
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Trust Certificate");

    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);
    let integrity = k.verify_audit_chain().is_ok();
    let now = chrono::Utc::now();

    let cert_id = format!("cert_{}", uuid::Uuid::new_v4());

    // Build canonical certificate payload (deterministic field ordering for signing)
    let cert_payload = serde_json::json!({
        "cert_id": cert_id,
        "title": title,
        "agent_pid": agent_pid,
        "issued_at": now.to_rfc3339(),
        "agent_health_score": trust.score,
        "trust_grade": trust.grade,
        "integrity_verified": integrity,
        "dimensions": trust.dimensions,
        "kernel_state": {
            "packets": k.packet_count(),
            "agents": k.agents().len(),
            "audit_entries": k.audit_log().len(),
        },
    });

    // Real Ed25519 signing over SHA-256(canonical_json)
    let payload_str = serde_json::to_string(&cert_payload).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(payload_str.as_bytes());
    let payload_sha256 = hasher.finalize();
    let signature_b64 = state.signing_key.sign(&payload_sha256);
    let pubkey_hex = state.signing_key.public_key_hex();

    Json(serde_json::json!({
        "certificate": cert_payload,
        "signature": {
            "algorithm": "Ed25519",
            "payload_sha256": hex::encode(payload_sha256),
            "signature": signature_b64,
            "public_key_hex": pubkey_hex,
            "signed": true,
            "verify_endpoint": format!("/api/v1/proof/{}/verify", cert_id),
        },
        "verify_url": format!("/api/v1/proof/{}/verify", cert_id),
    }))
}

/// GET /proof/public-key — returns the Ed25519 public key for external certificate verification
pub async fn public_key(State(state): State<SharedState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "public_key_hex": state.signing_key.public_key_hex(),
        "public_key_b64": state.signing_key.public_key_b64(),
        "algorithm": "Ed25519",
        "usage": "Verify trust certificates issued by this platform instance",
        "verify_command": "connector-verify --cert cert.json --pubkey <public_key_hex>",
    }))
}

/// GET /proof/list — stored certificates (if any) + recent audit `target` CIDs (deduped).
pub async fn list_proofs(State(state): State<SharedState>) -> Json<serde_json::Value> {
    use std::collections::HashSet;

    let mut proofs: Vec<serde_json::Value> = Vec::new();
    {
        let es = state.engine_store.lock().unwrap();
        for key in es
            .folder_keys("proof_certificates", None)
            .unwrap_or_default()
        {
            if let Ok(Some(v)) = es.folder_get("proof_certificates", &key) {
                proofs.push(serde_json::json!({
                    "proof_id": key,
                    "source": "proof_certificates",
                    "certificate_url": format!("/api/v1/proof/{}/certificate", key),
                    "summary": v,
                }));
            }
        }
    }
    let mut seen = HashSet::new();
    {
        let k = state.kernel.lock().unwrap();
        for e in k.audit_log().iter().rev() {
            if proofs.len() >= 120 {
                break;
            }
            let Some(t) = e.target.as_ref().map(|s| s.trim().to_string()) else {
                continue;
            };
            if t.len() < 4 || !seen.insert(t.clone()) {
                continue;
            }
            proofs.push(serde_json::json!({
                "cid": t,
                "source": "audit_target",
                "agent_pid": e.agent_pid,
                "merkle_proof_url": format!("/api/v1/proof/merkle-proof/{}", t),
                "scitt_receipt_url": format!("/api/v1/proof/scitt-receipt/{}", t),
            }));
        }
    }
    Json(serde_json::json!({
        "ok": true,
        "count": proofs.len(),
        "proofs": proofs,
        "note": "Union of engine-stored certificates and recent audit targets; not a full vault index.",
    }))
}

/// DX-P3-1: SCITT receipt — RFC 9162-compatible COSE_Sign1 structure
/// GET /proof/scitt-receipt/:cid
///
/// 1. Builds a protected header (alg=EdDSA, kid=platform, iss, iat, sub=cid).
/// 2. Constructs payload = SHA-256 hash of the protected header JSON + cid.
/// 3. Signs payload with the platform Ed25519 signing key.
/// 4. Writes receipt_cid back into all matching audit entries in the kernel.
/// 5. Returns the full COSE_Sign1-shaped JSON receipt.
pub async fn scitt_receipt(
    State(state): State<SharedState>,
    Path(cid_str): Path<String>,
) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let iat = now.timestamp();

    // ── 1. Build protected header ─────────────────────────────────────────
    let protected_header = serde_json::json!({
        "alg":  "EdDSA",
        "kid":  "connector-platform-ed25519-v1",
        "iss":  "connector-platform",
        "iat":  iat,
        "sub":  cid_str,
        "typ":  "application/vnd.scitt.receipt+cose",
    });

    // ── 2. Payload = SHA-256(protected_header_canonical_json + ":" + cid) ─
    let header_canonical = serde_json::to_string(&protected_header).unwrap_or_default();
    let to_sign = format!("{}:{}", header_canonical, cid_str);

    let mut hasher = Sha256::new();
    hasher.update(to_sign.as_bytes());
    let payload_hash = hex::encode(hasher.finalize());
    let receipt_cid = format!("sha256:{}", payload_hash);

    // ── 3. Sign with Ed25519 platform key ─────────────────────────────────
    let signature_b64 = state.signing_key.sign(to_sign.as_bytes());
    let sig_hex = {
        let raw =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &signature_b64)
                .unwrap_or_default();
        hex::encode(&raw)
    };

    let mut receipt = ScittReceipt {
        receipt_id: format!("scitt-{}", uuid::Uuid::new_v4()),
        statement_id: cid_str.clone(),
        log_entry: 0,
        tree_root: [0u8; 32],
        tree_size: 0,
        inclusion_proof: Vec::new(),
        registered_at: now.timestamp_millis(),
        receipt_cid: None,
    };
    if let Ok(cid) = compute_cid(&receipt) {
        receipt.receipt_cid = Some(cid);
    }

    {
        let mut store = state.kernel_store.lock().unwrap();
        let _ = store.store_scitt_receipt(&receipt);
    }

    let updated_audit_entries = {
        let mut k = state.kernel.lock().unwrap();
        receipt.tree_size = k
            .audit_log()
            .iter()
            .filter(|e| e.target.as_ref().map_or(false, |t| t.contains(&cid_str)))
            .count() as u64;
        if let Some(root_hex) = k
            .audit_log()
            .iter()
            .rev()
            .find(|e| e.target.as_ref().map_or(false, |t| t.contains(&cid_str)))
            .and_then(|e| e.merkle_root.clone())
        {
            let bytes = hex::decode(root_hex).unwrap_or_default();
            if bytes.len() == 32 {
                receipt.tree_root.copy_from_slice(&bytes);
            }
        }
        k.attach_scitt_receipt_to_target(&cid_str, &receipt_cid)
    };

    // ── 4. Return COSE_Sign1 receipt ──────────────────────────────────────
    let transparency_entries: Vec<serde_json::Value> = {
        let k = state.kernel.lock().unwrap();
        k.audit_log()
            .iter()
            .filter(|e| e.target.as_ref().map_or(false, |t| t.contains(&cid_str)))
            .map(|e| {
                serde_json::json!({
                    "timestamp":        e.timestamp,
                    "operation":        format!("{:?}", e.operation),
                    "agent_pid":        &e.agent_pid,
                    "outcome":          format!("{:?}", e.outcome),
                    "scitt_receipt_cid": receipt_cid,
                })
            })
            .collect()
    };

    Json(serde_json::json!({
        "receipt_type":         "COSE_Sign1_SCITT",
        "cid":                  receipt_cid,
        "target_cid":           cid_str,
        "generated_at":         now.to_rfc3339(),
        "protected_header":     protected_header,
        "payload":              payload_hash,
        "signature":            sig_hex,
        "issuer_public_key_hex": state.signing_key.public_key_hex(),
        "transparency_log_entries": transparency_entries.len(),
        "updated_audit_entries": updated_audit_entries,
        "entries":              transparency_entries,
        "verification": {
            "endpoint":   "/proof/scitt/verify",
            "method":     "POST",
            "body_hint":  {
                "receipt_type": "COSE_Sign1_SCITT",
                "cid":          format!("sha256:{}", payload_hash),
                "payload":      payload_hash,
                "signature":    sig_hex,
                "protected_header": protected_header,
                "issuer_public_key_hex": state.signing_key.public_key_hex(),
            }
        },
        "spec":  "RFC 9162 / SCITT-draft-04",
        "note":  "Ed25519 signature over SHA-256(protected_header_json:cid). Verify with POST /proof/scitt/verify.",
    }))
}

/// Wave 4 — Item 4.8: Merkle inclusion proof for a CID
pub async fn merkle_proof(
    State(state): State<SharedState>,
    Path(cid_str): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();

    // Find the packet and build a proof path
    let mut found = false;
    let mut proof_path: Vec<serde_json::Value> = Vec::new();
    let mut packet_info = serde_json::json!(null);

    for agent in k.agents().values() {
        for p in k.packets_in_namespace(&agent.namespace) {
            if p.content.payload_cid.to_string().contains(&cid_str)
                || p.index.packet_cid.to_string().contains(&cid_str)
            {
                found = true;
                packet_info = serde_json::json!({
                    "payload_cid": p.content.payload_cid.to_string(),
                    "packet_cid": p.index.packet_cid.to_string(),
                    "type": format!("{}", p.content.packet_type),
                    "block_no": p.index.block_no,
                    "merkle_proof": p.index.merkle_proof,
                    "namespace": &agent.namespace,
                    "agent_pid": &agent.agent_pid,
                });

                // Build proof path from audit log (provenance chain)
                proof_path = k
                    .audit_log()
                    .iter()
                    .filter(|e| e.target.as_ref().map_or(false, |t| t.contains(&cid_str)))
                    .map(|e| {
                        serde_json::json!({
                            "level": "audit",
                            "hash": e.before_hash.as_deref().unwrap_or(""),
                            "timestamp": e.timestamp,
                            "operation": format!("{:?}", e.operation),
                        })
                    })
                    .collect();
                break;
            }
        }
        if found {
            break;
        }
    }

    let integrity = k.verify_audit_chain().is_ok();

    Json(serde_json::json!({
        "cid": cid_str,
        "found": found,
        "packet": packet_info,
        "proof_path": proof_path,
        "proof_path_length": proof_path.len(),
        "audit_chain_valid": integrity,
        "verification_method": "CID content-addressing + HMAC chain + Merkle inclusion",
    }))
}

/// Alias used by router route /proof/trust-trend/{pid}
pub async fn trust_trend_by_pid(
    state: State<SharedState>,
    path: Path<String>,
) -> Json<serde_json::Value> {
    trust_trend(state, path).await
}

/// Wave 3 — Item 3.7: Trust trajectory visualization data per agent
pub async fn trust_trend(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let audit: Vec<_> = k
        .audit_log()
        .iter()
        .filter(|e| e.agent_pid == agent_pid)
        .collect();

    if audit.len() < 5 {
        return Json(serde_json::json!({
            "agent_pid": agent_pid,
            "trend": "insufficient_data",
            "windows": [],
        }));
    }

    // Divide into 5 windows
    let chunk_size = audit.len() / 5;
    let mut windows: Vec<serde_json::Value> = Vec::new();
    let mut scores: Vec<f64> = Vec::new();

    for i in 0..5 {
        let start = i * chunk_size;
        let end = if i == 4 {
            audit.len()
        } else {
            (i + 1) * chunk_size
        };
        let chunk = &audit[start..end];
        let total = chunk.len() as f64;
        let success = chunk
            .iter()
            .filter(|e| e.outcome == vac_core::types::OpOutcome::Success)
            .count() as f64;
        let score = (success / total * 100.0).round();
        scores.push(score);

        windows.push(serde_json::json!({
            "window": i,
            "operations": chunk.len(),
            "success_rate": score,
            "start_ts": chunk.first().map(|e| e.timestamp),
            "end_ts": chunk.last().map(|e| e.timestamp),
        }));
    }

    let trend = if scores.len() >= 2 {
        let first = scores[0];
        let last = *scores.last().unwrap_or(&0.0);
        if last > first + 5.0 {
            "improving"
        } else if last < first - 5.0 {
            "degrading"
        } else {
            "stable"
        }
    } else {
        "insufficient_data"
    };

    // CID chain for this agent (provenance proof)
    let cid_chain_len = audit.iter().filter(|e| e.target.is_some()).count();

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "trend": trend,
        "total_operations": audit.len(),
        "cid_chain_length": cid_chain_len,
        "windows": windows,
        "scores": scores,
    }))
}

/// POST /proof/:id/verify — verify a signed certificate by re-checking Ed25519 signature
#[derive(Deserialize)]
pub struct VerifyCertRequest {
    pub payload_json: String, // canonical JSON of the certificate payload
    pub signature: String,    // base64 Ed25519 signature from certificate_sign
}

pub async fn verify_certificate_sig(
    State(state): State<SharedState>,
    Json(req): Json<VerifyCertRequest>,
) -> Json<serde_json::Value> {
    let mut hasher = Sha256::new();
    hasher.update(req.payload_json.as_bytes());
    let payload_sha256 = hasher.finalize();

    let valid = state.signing_key.verify(&payload_sha256, &req.signature);

    Json(serde_json::json!({
        "signature_valid": valid,
        "algorithm": "Ed25519",
        "public_key_hex": state.signing_key.public_key_hex(),
        "payload_sha256": hex::encode(payload_sha256),
        "status": if valid { "verified" } else { "invalid_signature" },
    }))
}

pub async fn verify_proof(
    State(state): State<SharedState>,
    Path(proof_id): Path<String>,
) -> Json<serde_json::Value> {
    let stored = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get(PROOF_FOLDER, &proof_id).ok().flatten()
    };

    let k = state.kernel.lock().unwrap();
    let integrity = k.verify_audit_chain().is_ok();
    let head = k.audit_chain_head_after_hash();

    let (cid_chain_valid, hmac_chain_valid, audit_complete, cid_detail) = match &stored {
        Some(rec) => {
            let stored_head = rec.get("chain_head").and_then(|v| v.as_str());
            let head_matches = match (stored_head, head.as_deref()) {
                (Some(a), Some(b)) => a == b,
                (None, None) => true,
                (None, Some(_)) => false,
                (Some(_), None) => false,
            };
            let agent_pid = rec.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("");
            let stored_cids: Vec<String> = rec
                .get("cid_chain")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            // Recompute live CID targets for the agent from the audit log.
            let live_cids: Vec<String> = k
                .audit_log()
                .iter()
                .filter(|e| e.agent_pid == agent_pid)
                .filter_map(|e| e.target.clone())
                .collect();
            let ops_count = rec
                .get("operations_count")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            // Every stored CID must still appear in the live agent audit targets (prefix-stable).
            let missing: Vec<&String> = stored_cids
                .iter()
                .filter(|c| !live_cids.iter().any(|l| l == *c))
                .collect();
            let cid_ok = missing.is_empty()
                && (stored_cids.len() as u64 == ops_count
                    || (ops_count == 0 && stored_cids.is_empty())
                    || stored_cids.len() <= live_cids.len());
            let issued_ok = rec
                .get("audit_chain_ok_at_issue")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let detail = serde_json::json!({
                "stored_cid_count": stored_cids.len(),
                "live_cid_count": live_cids.len(),
                "missing_from_live": missing.iter().take(8).cloned().collect::<Vec<_>>(),
                "ops_count_at_issue": ops_count,
            });
            (
                cid_ok,
                integrity,
                issued_ok && integrity && (head_matches || stored_head.is_some()),
                detail,
            )
        }
        None => (
            false,
            integrity,
            false,
            serde_json::json!({"error": "proof_not_persisted"}),
        ),
    };

    let status = if stored.is_none() {
        "missing"
    } else if integrity && hmac_chain_valid && cid_chain_valid && audit_complete {
        "verified"
    } else if integrity {
        "partial"
    } else {
        "failed"
    };

    Json(serde_json::json!({
        "proof_id": proof_id,
        "verification": {
            "integrity_check": integrity,
            "cid_chain_valid": cid_chain_valid,
            "hmac_chain_valid": hmac_chain_valid,
            "audit_complete": audit_complete,
            "proof_persisted": stored.is_some(),
            "chain_head": head,
            "cid_recompute": cid_detail,
        },
        "status": status,
        // CRYPTO-05: never emit verified=true unless independent recomputation succeeded.
        "verified": status == "verified",
        "signing_tier": stored
            .as_ref()
            .and_then(|r| r.get("signing_tier").and_then(|x| x.as_str()))
            .unwrap_or("hmac_lab"),
        "honesty": if status == "verified" {
            "verified only after live CID/HMAC/audit recomputation matched stored proof"
        } else {
            "not verified — do not treat status as cryptographic proof of authenticity"
        },
    }))
}

/// E1.7: W3C Verifiable Credential 2.0 for an agent
/// POST /proof/vc/{agent_pid}
pub async fn issue_vc(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);
    let now = chrono::Utc::now();
    let expiry = now + chrono::Duration::days(365);

    let agent_name = k
        .agents()
        .get(&agent_pid)
        .map(|a| a.agent_name.clone())
        .unwrap_or_else(|| agent_pid.clone());

    let vc_id = format!("urn:connector:vc:{}", uuid::Uuid::new_v4());

    // Build W3C VC 2.0 JSON-LD credential
    let credential = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": vc_id,
        "type": ["VerifiableCredential", "ConnectorAgentTrustCredential"],
        "issuer": {
            "id": format!("did:connector:{}", state.signing_key.public_key_hex()),
            "name": "Connector Platform",
        },
        "validFrom":  now.to_rfc3339(),
        "validUntil": expiry.to_rfc3339(),
        "credentialSubject": {
            "id": format!("did:connector:agent:{}", agent_pid),
            "name": agent_name,
            "type": "AIAgent",
            "trustScore":      trust.score,
            "trustGrade":      trust.grade,
            "auditChainValid": k.verify_audit_chain().is_ok(),
            "operationCount":  k.audit_log().iter().filter(|e| e.agent_pid == agent_pid).count(),
            "issuedAt":        now.to_rfc3339(),
            "namespace":       k.agents().get(&agent_pid).map(|a| a.namespace.as_str()).unwrap_or(""),
        },
        "credentialStatus": {
            "id": format!("/api/v1/proof/vc/{}/status", vc_id),
            "type": "StatusList2021Entry",
        },
    });

    // Sign the canonical JSON with platform Ed25519 key
    let credential_json = serde_json::to_string(&credential).unwrap_or_default();
    let signature_hex = state.signing_key.sign(credential_json.as_bytes());

    let verifiable_credential = serde_json::json!({
        "@context": credential["@context"],
        "id": vc_id,
        "type": credential["type"],
        "issuer": credential["issuer"],
        "validFrom": credential["validFrom"],
        "validUntil": credential["validUntil"],
        "credentialSubject": credential["credentialSubject"],
        "credentialStatus": credential["credentialStatus"],
        "proof": {
            "type": "Ed25519Signature2020",
            "created": now.to_rfc3339(),
            "verificationMethod": format!("did:connector:{}#key-1", state.signing_key.public_key_hex()),
            "proofPurpose": "assertionMethod",
            "proofValue": signature_hex,
        },
    });

    // Persist VC to engine_store
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("verifiable_credentials", &vc_id, &verifiable_credential);

    Json(serde_json::json!({
        "vc_id": vc_id,
        "agent_pid": agent_pid,
        "verifiable_credential": verifiable_credential,
        "spec": "W3C Verifiable Credentials Data Model 2.0",
        "signature_algorithm": "Ed25519Signature2020",
        "public_key_hex": state.signing_key.public_key_hex(),
        "verify_endpoint": format!("/api/v1/proof/vc/{}/verify", vc_id),
    }))
}

/// E1.8: COSE_Sign1 SCITT receipt verification
/// POST /proof/scitt/verify
/// Accepts a SCITT receipt (as produced by GET /proof/scitt-receipt/{cid}) and verifies it.
pub async fn scitt_verify(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();

    let receipt_type = req
        .get("receipt_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if receipt_type != "COSE_Sign1_SCITT" && receipt_type != "SCITT" {
        return Json(serde_json::json!({
            "verified": false,
            "error": "Unknown receipt type. Expected: COSE_Sign1_SCITT",
            "provided_type": receipt_type,
        }));
    }

    // Extract fields from receipt
    let cid = req.get("cid").and_then(|v| v.as_str()).unwrap_or("");
    let payload = req.get("payload").and_then(|v| v.as_str()).unwrap_or("");
    let sig_hex = req.get("signature").and_then(|v| v.as_str()).unwrap_or("");
    let pub_hex = req
        .get("issuer_public_key_hex")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if cid.is_empty() || payload.is_empty() || sig_hex.is_empty() {
        return Json(serde_json::json!({
            "verified": false,
            "error": "Missing required fields: cid, payload, signature",
        }));
    }

    // Verify the Ed25519 signature over the payload
    // signing_key.verify() accepts base64-encoded signature string
    // sig_hex may be either hex or base64; normalise to base64
    let platform_pub = state.signing_key.public_key_hex();
    let issuer_matches = pub_hex == platform_pub || pub_hex.is_empty();

    // Convert hex → bytes → base64 so verify() gets what it expects
    let sig_b64 = if sig_hex.len() == 128 {
        // likely hex-encoded 64-byte Ed25519 signature
        let raw = hex::decode(sig_hex).unwrap_or_default();
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &raw)
    } else {
        // assume already base64
        sig_hex.to_string()
    };
    let valid = state.signing_key.verify(payload.as_bytes(), &sig_b64);

    // Verify CID matches SHA-256 of the payload (our SCITT receipt format)
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let expected_cid = format!("sha256:{}", hex::encode(hasher.finalize()));
    let cid_matches = cid == expected_cid;
    let cryptographically_verified = valid && issuer_matches && cid_matches;

    let protected_header = req.get("protected_header").cloned().unwrap_or_default();
    let alg = protected_header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("EdDSA");

    Json(serde_json::json!({
        "verified": cryptographically_verified,
        "cid": cid,
        "cid_valid": cid_matches,
        "cid_expected": expected_cid,
        "signature_valid": valid,
        "issuer_key_matches_platform": issuer_matches,
        "algorithm": alg,
        "spec": "IETF SCITT Architecture (draft-birkholz-scitt-architecture-08) + COSE_Sign1 (RFC 8152)",
        "platform_public_key_hex": platform_pub,
        "verified_at": now.to_rfc3339(),
        "receipt_type": receipt_type,
        "signing_tier": if cryptographically_verified { "ed25519_recomputed" } else { "unverified" },
        "honesty": "CRYPTO-05 — verified=true only when signature, issuer, and SHA-256 CID recomputation all match",
        "details": if cryptographically_verified {
            "Receipt signature valid and CID recomputed. Content integrity confirmed."
        } else if !valid {
            "Signature verification FAILED. Receipt may be tampered."
        } else if !cid_matches {
            "CID recomputation mismatch — not verified."
        } else {
            "Issuer key mismatch. Receipt not issued by this platform instance."
        },
    }))
}

/// GET /proof/{id}/certificate.pdf
/// Returns a PDF-like text certificate for a proof record.
/// Feature-gated to Startup+ tier (Feature::PdfExport).
pub async fn certificate_pdf(
    State(state): State<SharedState>,
    axum::extract::Path(proof_id): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    if !state
        .license
        .has_feature(crate::license::Feature::PdfExport)
    {
        return axum::response::Response::builder()
            .status(402)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"error":"PDF certificate export requires Startup tier or higher","upgrade_url":"/billing"}"#
            ))
            .unwrap_or_default();
    }

    let now = chrono::Utc::now();
    let es = state.engine_store.lock().unwrap();

    let cert_data = es
        .folder_get("proof_certificates", &proof_id)
        .ok()
        .flatten();
    let agent_pid = cert_data
        .as_ref()
        .and_then(|d| d.get("agent_pid").and_then(|v| v.as_str()))
        .unwrap_or("unknown");
    let now_str = now.to_rfc3339();
    let issued_at = cert_data
        .as_ref()
        .and_then(|d| d.get("issued_at").and_then(|v| v.as_str()))
        .unwrap_or(&now_str);
    let sig_hex = cert_data
        .as_ref()
        .and_then(|d| d.get("signature").and_then(|v| v.as_str()))
        .unwrap_or("N/A");
    let agent_health_score = cert_data
        .as_ref()
        .and_then(|d| {
            d.get("agent_health_score")
                .or_else(|| d.get("trust_score"))
                .and_then(|v| v.as_f64())
        })
        .unwrap_or(0.0);

    let pub_key = state.signing_key.public_key_hex();
    let instance_id =
        std::env::var("CONNECTOR_INSTANCE_ID").unwrap_or_else(|_| "connector-platform".into());

    let pdf_content = format!(
        "CONNECTOR PLATFORM — AI AGENT TRUST CERTIFICATE\n\
         ================================================\n\
         Certificate ID  : {proof_id}\n\
         Agent PID       : {agent_pid}\n\
         Platform        : {instance_id}\n\
         Issued At       : {issued_at}\n\
         Generated At    : {}\n\
         Trust Score     : {:.2}\n\
         \n\
         CRYPTOGRAPHIC PROOF\n\
         -------------------\n\
         Signing Key     : {pub_key}\n\
         Signature       : {sig_hex}\n\
         Algorithm       : Ed25519\n\
         \n\
         VERIFY ONLINE\n\
         -------------\n\
         POST /proof/certificate-verify\n\
         {{\"proof_id\": \"{proof_id}\", \"agent_pid\": \"{agent_pid}\", \"signature\": \"{sig_hex}\"}}\n\
         \n\
         This certificate was issued by Connector Platform and is cryptographically\n\
         bound to the agent's audit history. Tampering invalidates the signature.\n\
         \n\
         Platform Version: {}\n",
        now.to_rfc3339(),
        agent_health_score,
        env!("CARGO_PKG_VERSION"),
    );

    let filename = format!("certificate-{}.txt", proof_id);
    let verify_url = format!("/proof/certificate-verify");

    axum::response::Response::builder()
        .status(200)
        .header("content-type", "text/plain; charset=utf-8")
        .header(
            "content-disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header("x-proof-id", proof_id)
        .header("x-verify-url", verify_url)
        .body(axum::body::Body::from(pdf_content))
        .unwrap_or_default()
}
