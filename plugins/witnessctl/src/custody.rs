use sqlx::{PgPool, Row};
use std::time::Duration;
use uuid::Uuid;

use crate::custody_node::{self, replicate_url, CustodyHonestyStrip, QuorumResult, ReplicateRequest};

pub fn start_worker(db: PgPool, replicas: Vec<String>) {
    tokio::spawn(async move {
        let tick = Duration::from_secs(15);
        loop {
            let _ = process_replication_batch(&db, &replicas).await;
            let _ = write_checkpoints(&db, replicas.len()).await;
            tokio::time::sleep(tick).await;
        }
    });
}

async fn process_replication_batch(db: &PgPool, replicas: &[String]) -> anyhow::Result<()> {
    let rows = sqlx::query(
        "SELECT id, session_id, payload_hash FROM witness_custody_queue WHERE status = 'pending' ORDER BY created_at ASC LIMIT 100"
    )
    .fetch_all(db)
    .await?;

    let secret = custody_replicate_secret();

    for row in rows {
        let id: Uuid = row.get("id");
        let session_id: Uuid = row.get("session_id");
        let payload_hash: String = row.get("payload_hash");
        let mut ok_count = 0usize;
        for replica in replicas {
            if let Some(proof) = push_replica(replica, session_id, &payload_hash, &secret).await {
                let _ = store_custody_proof(db, session_id, &proof).await;
                ok_count += 1;
            }
        }
        let status = if replicas.is_empty() {
            "replicated"
        } else if ok_count == 0 {
            "failed"
        } else {
            "replicated"
        };
        let err = if status == "failed" {
            Some("all replica writes failed".to_string())
        } else {
            None
        };
        sqlx::query(
            "UPDATE witness_custody_queue SET status = $1, attempts = attempts + 1, last_error = $2, updated_at = NOW() WHERE id = $3"
        )
        .bind(status)
        .bind(err)
        .bind(id)
        .execute(db)
        .await?;
    }
    Ok(())
}

fn custody_replicate_secret() -> String {
    std::env::var("WITNESSCTL_CUSTODY_NODE_SECRET")
        .or_else(|_| std::env::var("WITNESSCTL_HMAC_SECRET"))
        .unwrap_or_else(|_| "witnessctl-custody-dev-secret".to_string())
}

async fn push_replica(
    replica: &str,
    session_id: Uuid,
    payload_hash: &str,
    secret: &str,
) -> Option<custody_node::CustodyProof> {
    let url = replicate_url(replica);
    let body = ReplicateRequest {
        session_id: session_id.to_string(),
        payload_hash: payload_hash.to_string(),
        node_id: None,
    };
    let client = reqwest::Client::new();
    let resp = client
        .post(url)
        .header("X-WitnessCtl-Custody-Secret", secret)
        .json(&body)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let parsed: custody_node::ReplicateResponse = resp.json().await.ok()?;
    if parsed.ok {
        Some(parsed.proof)
    } else {
        None
    }
}

pub async fn store_custody_proof(
    db: &PgPool,
    session_id: Uuid,
    proof: &custody_node::CustodyProof,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO witness_custody_proofs (session_id, node_id, capture_hash, signature, proof_at) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
    )
    .bind(session_id)
    .bind(&proof.node_id)
    .bind(&proof.capture_hash)
    .bind(&proof.signature)
    .bind(proof.timestamp)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn load_session_proofs(db: &PgPool, session_id: Uuid) -> anyhow::Result<Vec<custody_node::CustodyProof>> {
    let rows = sqlx::query(
        "SELECT node_id, capture_hash, signature, proof_at FROM witness_custody_proofs \
         WHERE session_id = $1 ORDER BY proof_at ASC",
    )
    .bind(session_id)
    .fetch_all(db)
    .await?;
    Ok(rows
        .iter()
        .map(|r| custody_node::CustodyProof {
            session_id: session_id.to_string(),
            node_id: r.get("node_id"),
            capture_hash: r.get("capture_hash"),
            signature: r.get("signature"),
            timestamp: r.get("proof_at"),
        })
        .collect())
}

pub async fn handle_replicate_request(
    secret: &str,
    node_id: &str,
    req: &ReplicateRequest,
) -> anyhow::Result<custody_node::ReplicateResponse> {
    let proof = custody_node::build_proof_from_request(req, node_id, secret);
    Ok(custody_node::ReplicateResponse { ok: true, proof })
}

async fn write_checkpoints(db: &PgPool, replica_count: usize) -> anyhow::Result<()> {
    let sessions = sqlx::query("SELECT id, chain_head_hmac FROM witness_sessions ORDER BY created_at DESC LIMIT 250")
        .fetch_all(db)
        .await?;
    for s in sessions {
        let session_id: Uuid = s.get("id");
        let local_head: Option<String> = s.get("chain_head_hmac");
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) FROM witness_custody_queue WHERE session_id = $1 AND status = 'pending'"
        )
        .bind(session_id)
        .fetch_one(db)
        .await
        .unwrap_or(0);
        let failed: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) FROM witness_custody_queue WHERE session_id = $1 AND status = 'failed'"
        )
        .bind(session_id)
        .fetch_one(db)
        .await
        .unwrap_or(0);
        let replicated_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) FROM witness_custody_queue WHERE session_id = $1 AND status = 'replicated'"
        )
        .bind(session_id)
        .fetch_one(db)
        .await
        .unwrap_or(0);

        let quorum_status = if replica_count == 0 {
            "local_only"
        } else if replicated_count == 0 {
            "local_only"
        } else if pending > 0 || failed > 0 {
            "replicated_partial"
        } else {
            "replicated_quorum"
        };
        let signed_hash = sha256::digest(format!(
            "{}:{}:{}:{}",
            session_id,
            local_head.clone().unwrap_or_default(),
            pending,
            failed
        ));
        sqlx::query(
            "INSERT INTO witness_custody_checkpoints (session_id, local_chain_head, replicated_head, pending_count, failed_count, quorum_status, signed_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(session_id)
        .bind(&local_head)
        .bind(local_head.clone())
        .bind(pending)
        .bind(failed)
        .bind(quorum_status)
        .bind(signed_hash)
        .execute(db)
        .await?;
    }
    Ok(())
}

pub async fn custody_status(db: &PgPool, session_id: Uuid) -> anyhow::Result<serde_json::Value> {
    let row = sqlx::query(
        "SELECT local_chain_head, replicated_head, pending_count, failed_count, quorum_status, signed_hash, created_at \
         FROM witness_custody_checkpoints WHERE session_id = $1 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(session_id)
    .fetch_optional(db)
    .await?;
    let replicated_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM witness_custody_queue WHERE session_id = $1 AND status = 'replicated'"
    )
    .bind(session_id)
    .fetch_one(db)
    .await
    .unwrap_or(0);
    let proofs = load_session_proofs(db, session_id).await.unwrap_or_default();
    let replica_count = std::env::var("WITNESSCTL_CUSTODY_REPLICAS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .count();
    let required = replica_count.max(1);
    let quorum_report = custody_node::verify_quorum(&proofs, required, &custody_replicate_secret());

    if let Some(r) = row {
        let pending_count = r.get::<i64, _>("pending_count");
        let failed_count = r.get::<i64, _>("failed_count");
        let quorum_target = replicated_count + pending_count + failed_count;
        let quorum_achieved = replicated_count;
        // Replica-count heuristic (queue ack) — separate from independent verify.
        let queue_quorum_met = quorum_target > 0 && quorum_achieved >= quorum_target;
        // Court path: only after verify_quorum says QuorumMet (distinct keys + hash).
        let verify_quorum_met = quorum_report.result == QuorumResult::QuorumMet;
        let honesty_strip = CustodyHonestyStrip::from_quorum(&quorum_report, true);
        let court_export_ready = verify_quorum_met;
        Ok(serde_json::json!({
            "session_id": session_id,
            "local_chain_head": r.get::<Option<String>, _>("local_chain_head"),
            "replicated_head": r.get::<Option<String>, _>("replicated_head"),
            "pending_count": pending_count,
            "failed_count": failed_count,
            "acknowledged_count": replicated_count,
            "quorum_status": r.get::<String, _>("quorum_status"),
            "quorum_target": quorum_target,
            "quorum_achieved": quorum_achieved,
            "quorum_met": queue_quorum_met,
            "verify_quorum_met": verify_quorum_met,
            "honesty_strip": honesty_strip.as_str(),
            "court_export_ready": court_export_ready,
            "custody_proofs": proofs.len(),
            "quorum_verification": quorum_report,
            "signed_hash": r.get::<String, _>("signed_hash"),
            "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
            "honesty": [
                "honesty_strip is local_only|partial|quorum_met — never label court-grade until quorum_met + independent verify.",
                "court_export_ready is true only when verify_quorum_met (QuorumResult::QuorumMet).",
            ],
        }))
    } else {
        let honesty_strip = CustodyHonestyStrip::from_quorum(&quorum_report, false);
        Ok(serde_json::json!({
            "session_id": session_id,
            "quorum_status": "local_only",
            "pending_count": 0,
            "failed_count": 0,
            "acknowledged_count": 0,
            "quorum_target": 0,
            "quorum_achieved": 0,
            "quorum_met": false,
            "verify_quorum_met": false,
            "honesty_strip": honesty_strip.as_str(),
            "court_export_ready": false,
            "quorum_verification": quorum_report,
            "honesty": [
                "honesty_strip is local_only|partial|quorum_met — never label court-grade until quorum_met + independent verify.",
                "court_export_ready is true only when verify_quorum_met (QuorumResult::QuorumMet).",
            ],
        }))
    }
}

pub async fn is_legal_hold(db: &PgPool, session_id: Uuid) -> anyhow::Result<bool> {
    let policy = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT policy FROM witness_sessions WHERE id = $1"
    )
    .bind(session_id)
    .fetch_optional(db)
    .await?;
    let held = policy
        .and_then(|v| v.get("legal_hold").cloned())
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Ok(held)
}
