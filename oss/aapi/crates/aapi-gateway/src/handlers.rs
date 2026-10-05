//! HTTP request handlers for the Gateway

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};

use aapi_adapters::ExecutionContext;
use aapi_core::{
    Vakya, VakyaId, canonicalize,
    error::ReasonCode,
    types::{PrincipalId, Timestamp},
};
use aapi_crypto::{CapabilityToken, SignedVakya};
use aapi_indexdb::{
    VakyaRecord, EffectRecord, ReceiptRecord,
    TreeType, IndexDbStore,
};
use aapi_metarules::{EvaluationContext, DecisionType};

use crate::error::{GatewayError, GatewayResult};
use crate::state::AppState;

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub gateway_id: String,
    pub version: String,
    pub timestamp: String,
}

/// Health check handler
pub async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        gateway_id: state.config.gateway_id.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: Utc::now().to_rfc3339(),
    })
}

/// Submit VĀKYA request
#[derive(Debug, Deserialize)]
pub struct SubmitVakyaRequest {
    pub vakya: Vakya,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// UCAN capability token (required when `GatewayConfig.require_capabilities = true`).
    /// Issue via `POST /aapi/capabilities/issue`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_token: Option<String>,
}

/// Submit VĀKYA response
#[derive(Debug, Serialize)]
pub struct SubmitVakyaResponse {
    pub vakya_id: String,
    pub vakya_hash: String,
    pub status: String,
    pub receipt: Option<ReceiptResponse>,
    pub merkle_root: Option<String>,
    pub leaf_index: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_decision: Option<PolicyDecisionResponse>,
}

/// Policy decision response (for deny/pending_approval)
#[derive(Debug, Serialize)]
pub struct PolicyDecisionResponse {
    pub decision: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rules: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
}

/// Receipt response
#[derive(Debug, Serialize)]
pub struct ReceiptResponse {
    pub vakya_id: String,
    pub vakya_hash: String,
    pub reason_code: ReasonCode,
    pub message: Option<String>,
    pub duration_ms: Option<i64>,
    pub effect_ids: Vec<String>,
    pub executor_id: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct IssueCapabilityRequest {
    pub subject: String,
    pub action: String,
    pub resource: String,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct IssueCapabilityResponse {
    pub token_id: String,
    pub capability_token: CapabilityToken,
}

#[derive(Debug, Serialize)]
pub struct DeleteCapabilityResponse {
    pub token_id: String,
    pub deleted: bool,
}

pub async fn issue_capability(
    State(state): State<Arc<AppState>>,
    Json(request): Json<IssueCapabilityRequest>,
) -> GatewayResult<Json<IssueCapabilityResponse>> {
    let token = state
        .issue_capability_token(
            PrincipalId::new(request.subject),
            request.action,
            request.resource,
            request.ttl_seconds,
        )
        .await
        .map_err(|e| GatewayError::Capability(e.to_string()))?;

    Ok(Json(IssueCapabilityResponse {
        token_id: token.token_id.clone(),
        capability_token: token,
    }))
}

pub async fn delete_capability(
    State(state): State<Arc<AppState>>,
    Path(token_id): Path<String>,
) -> GatewayResult<Json<DeleteCapabilityResponse>> {
    let removed = state.issued_capability_tokens.write().await.remove(&token_id).is_some();
    if !removed {
        return Err(GatewayError::NotFound(format!("Capability token not found: {}", token_id)));
    }

    state.revoked_capability_tokens.write().await.insert(token_id.clone());

    Ok(Json(DeleteCapabilityResponse {
        token_id,
        deleted: true,
    }))
}

/// Submit a VĀKYA for execution
pub async fn submit_vakya(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SubmitVakyaRequest>,
) -> GatewayResult<Json<SubmitVakyaResponse>> {
    let start = std::time::Instant::now();
    let vakya = request.vakya;
    
    info!(vakya_id = %vakya.vakya_id, action = %vakya.v3_kriya.action, "Received VĀKYA submission");

    // Validate the VĀKYA
    if let Err(e) = vakya.validate() {
        warn!(vakya_id = %vakya.vakya_id, error = %e, "VĀKYA validation failed");
        return Err(GatewayError::Validation(e.to_string()));
    }

    // Production mode security checks
    if state.config.signatures_required() {
        match (&request.signature, &request.key_id) {
            (Some(sig), Some(key_id)) => {
                // Build SignedVakya for verification
                let signed = SignedVakya {
                    vakya: vakya.clone(),
                    vakya_hash: {
                        let sandhi = canonicalize(&vakya)
                            .map_err(|e| GatewayError::Internal(e.to_string()))?;
                        sandhi.vakya_hash.value.clone()
                    },
                    signature: aapi_crypto::VakyaSignature {
                        key_id: aapi_crypto::KeyId(key_id.clone()),
                        algorithm: aapi_crypto::SignatureAlgorithm::Ed25519,
                        value: sig.clone(),
                        signed_at: chrono::Utc::now(),
                    },
                };

                match state.verifier.verify(&signed) {
                    Ok(result) if result.valid => {
                        info!(vakya_id = %vakya.vakya_id, "Signature verified");
                    }
                    Ok(result) => {
                        warn!(
                            vakya_id = %vakya.vakya_id,
                            key_id = %key_id,
                            reason = ?result.reason,
                            "Signature verification failed"
                        );
                        return Err(GatewayError::AuthorizationDenied(
                            format!("Invalid signature: {}", result.reason.unwrap_or_default()),
                        ));
                    }
                    Err(e) => {
                        warn!(
                            vakya_id = %vakya.vakya_id,
                            key_id = %key_id,
                            "Signature verification error: {}",
                            e
                        );
                        return Err(GatewayError::AuthorizationDenied(
                            format!("Signature verification error: {}", e),
                        ));
                    }
                }
            }
            _ => {
                warn!(vakya_id = %vakya.vakya_id, "Missing signature or key_id in production mode");
                return Err(GatewayError::AuthorizationDenied(
                    "Signature required in production mode".to_string(),
                ));
            }
        }
    }

    // Capability verification (S1 fix — resolves TODO).
    // When require_capabilities=true (production mode), every Vakya must carry a
    // capability_token that has been issued by POST /aapi/capabilities/issue and
    // is still valid (not revoked, not expired).
    if state.config.capabilities_required() {
        match &request.capability_token {
            Some(token_json) => {
                // Deserialize the JSON-encoded CapabilityToken
                let cap_token: aapi_crypto::CapabilityToken = match serde_json::from_str(token_json) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(
                            vakya_id = %vakya.vakya_id,
                            error = %e,
                            "capability_token is not valid JSON"
                        );
                        return Err(GatewayError::AuthorizationDenied(
                            format!("capability_token is malformed JSON: {}. \
                                     Issue a valid token via POST /aapi/capabilities/issue.", e)
                        ));
                    }
                };

                if state
                    .revoked_capability_tokens
                    .read()
                    .await
                    .contains(&cap_token.token_id)
                {
                    return Err(GatewayError::AuthorizationDenied(
                        format!(
                            "Capability token denied: token '{}' has been revoked. Issue a fresh token via POST /aapi/capabilities/issue.",
                            cap_token.token_id
                        )
                    ));
                }

                // Verify signature + expiry + action + resource in one call
                match state.cap_verifier.verify_access(
                    &cap_token,
                    &vakya.v3_kriya.action,
                    &vakya.v2_karma.rid.0,
                ) {
                    Ok(decision) if decision.allowed => {
                        info!(
                            vakya_id = %vakya.vakya_id,
                            token_id = %cap_token.token_id,
                            "Capability token verified"
                        );
                    }
                    Ok(decision) => {
                        warn!(
                            vakya_id = %vakya.vakya_id,
                            reason = %decision.reason,
                            action = %vakya.v3_kriya.action,
                            resource = %vakya.v2_karma.rid.0,
                            "Capability token denied"
                        );
                        return Err(GatewayError::AuthorizationDenied(
                            format!(
                                "Capability token denied: {}. \
                                 Issue a token that authorizes action '{}' on resource '{}'.",
                                decision.reason,
                                vakya.v3_kriya.action,
                                vakya.v2_karma.rid.0,
                            )
                        ));
                    }
                    Err(e) => {
                        warn!(
                            vakya_id = %vakya.vakya_id,
                            error = %e,
                            "Capability token verification error"
                        );
                        return Err(GatewayError::AuthorizationDenied(
                            format!("Capability token verification error: {}. \
                                     Issue a valid token via POST /aapi/capabilities/issue.", e)
                        ));
                    }
                }
            }
            None => {
                warn!(
                    vakya_id = %vakya.vakya_id,
                    "Missing capability_token in production mode"
                );
                return Err(GatewayError::AuthorizationDenied(
                    "capability_token is required in production mode. \
                     Issue one via POST /aapi/capabilities/issue.".to_string()
                ));
            }
        }
    }

    // Canonicalize and hash
    let sandhi = canonicalize(&vakya)
        .map_err(|e| GatewayError::Internal(e.to_string()))?;
    
    let vakya_hash = sandhi.vakya_hash.value.clone();

    // Store the VĀKYA record
    let mut record = VakyaRecord::new(
        vakya.vakya_id.0.clone(),
        vakya_hash.clone(),
        vakya.v1_karta.pid.0.clone(),
        vakya.v2_karma.rid.0.clone(),
        vakya.v3_kriya.action.clone(),
        serde_json::to_value(&vakya).unwrap_or_default(),
    );
    
    record.karta_type = format!("{:?}", vakya.v1_karta.actor_type).to_lowercase();
    record.karma_kind = vakya.v2_karma.kind.clone();
    record.expected_effect = vakya.v3_kriya.expected_effect;
    record.signature = request.signature;
    record.key_id = request.key_id;
    
    if let Some(ref trace) = vakya.meta.trace {
        record.trace_id = Some(trace.trace_id.clone());
        record.span_id = Some(trace.span_id.clone());
        record.parent_span_id = trace.parent_span_id.clone();
    }

    let stored = state.index_db.store_vakya(record).await
        .map_err(|e| GatewayError::Database(e.to_string()))?;

    // Evaluate policy before execution
    let eval_ctx = EvaluationContext::new(vakya.clone());
    let policy_decision = state.policy_engine.evaluate(&eval_ctx).await
        .map_err(|e| GatewayError::Internal(format!("Policy evaluation failed: {}", e)))?;

    info!(
        vakya_id = %vakya.vakya_id,
        decision = ?policy_decision.decision,
        "Policy evaluation complete"
    );

    // Handle deny/pending_approval before execution
    match policy_decision.decision {
        DecisionType::Deny => {
            let duration_ms = start.elapsed().as_millis() as i64;
            
            // Record denial in metrics
            {
                let mut metrics = state.metrics.write().await;
                metrics.record_auth_denial();
                metrics.record_request(&vakya.v3_kriya.action, &vakya.v1_karta.pid.0, false, duration_ms as f64);
            }

            // Create denial receipt
            let receipt = ReceiptRecord::new(
                vakya.vakya_id.0.clone(),
                vakya_hash.clone(),
                ReasonCode::PolicyDenied,
                state.config.gateway_id.clone(),
                serde_json::json!({
                    "status": "denied",
                    "reason": policy_decision.reason,
                }),
            );
            let stored_receipt = state.index_db.store_receipt(receipt).await
                .map_err(|e| GatewayError::Database(e.to_string()))?;

            return Ok(Json(SubmitVakyaResponse {
                vakya_id: vakya.vakya_id.0,
                vakya_hash,
                status: "denied".to_string(),
                receipt: Some(ReceiptResponse {
                    vakya_id: stored_receipt.vakya_id,
                    vakya_hash: stored_receipt.vakya_hash,
                    reason_code: stored_receipt.reason_code,
                    message: Some(policy_decision.reason.clone()),
                    duration_ms: Some(duration_ms),
                    effect_ids: vec![],
                    executor_id: stored_receipt.executor_id,
                    created_at: stored_receipt.created_at.to_rfc3339(),
                }),
                merkle_root: stored.merkle_root,
                leaf_index: stored.leaf_index,
                policy_decision: Some(PolicyDecisionResponse {
                    decision: "deny".to_string(),
                    message: policy_decision.reason,
                    matched_rules: Some(policy_decision.matched_rules.iter().map(|r| r.rule_name.clone()).collect()),
                    approval_id: None,
                }),
            }));
        }
        DecisionType::PendingApproval => {
            let duration_ms = start.elapsed().as_millis() as i64;
            let approval_id = uuid::Uuid::new_v4().to_string();

            // Create pending approval receipt
            let receipt = ReceiptRecord::new(
                vakya.vakya_id.0.clone(),
                vakya_hash.clone(),
                ReasonCode::ApprovalRequired,
                state.config.gateway_id.clone(),
                serde_json::json!({
                    "status": "pending_approval",
                    "approval_id": approval_id,
                    "reason": policy_decision.reason,
                }),
            );
            let stored_receipt = state.index_db.store_receipt(receipt).await
                .map_err(|e| GatewayError::Database(e.to_string()))?;

            return Ok(Json(SubmitVakyaResponse {
                vakya_id: vakya.vakya_id.0,
                vakya_hash,
                status: "pending_approval".to_string(),
                receipt: Some(ReceiptResponse {
                    vakya_id: stored_receipt.vakya_id,
                    vakya_hash: stored_receipt.vakya_hash,
                    reason_code: stored_receipt.reason_code,
                    message: Some(policy_decision.reason.clone()),
                    duration_ms: Some(duration_ms),
                    effect_ids: vec![],
                    executor_id: stored_receipt.executor_id,
                    created_at: stored_receipt.created_at.to_rfc3339(),
                }),
                merkle_root: stored.merkle_root,
                leaf_index: stored.leaf_index,
                policy_decision: Some(PolicyDecisionResponse {
                    decision: "pending_approval".to_string(),
                    message: policy_decision.reason,
                    matched_rules: Some(policy_decision.matched_rules.iter().map(|r| r.rule_name.clone()).collect()),
                    approval_id: Some(approval_id),
                }),
            }));
        }
        _ => {
            // Allow or NotApplicable - proceed with execution
        }
    }

    // Execute the action via adapter dispatcher
    let mut exec_ctx = ExecutionContext::new(vakya.vakya_id.0.clone());
    exec_ctx.timeout_ms = Some(state.config.request_timeout_secs.saturating_mul(1000));
    exec_ctx.capture_state = true;
    exec_ctx.dry_run = false;
    if let Some(ref trace) = vakya.meta.trace {
        exec_ctx.trace_id = Some(trace.trace_id.clone());
        exec_ctx.span_id = Some(trace.span_id.clone());
    }

    let execution = state
        .dispatcher
        .dispatch(&vakya, &exec_ctx)
        .await;

    let mut effect_ids: Vec<String> = Vec::new();
    let mut stored_effects: Vec<EffectRecord> = Vec::new();

    let (reason_code, message, result_json, duration_ms, success_for_metrics) = match execution {
        Ok(exec_result) => {
            // Store effects
            for eff in exec_result.effects.iter() {
                let mut rec = EffectRecord::new(
                    eff.vakya_id.clone(),
                    eff.bucket,
                    eff.target.clone(),
                );

                rec.target_kind = eff.target_type.clone();
                rec.before_hash = eff.before.as_ref().map(|s| s.hash.clone());
                rec.after_hash = eff.after.as_ref().map(|s| s.hash.clone());
                rec.before_state = eff.before.as_ref().and_then(|s| s.content.clone());
                rec.after_state = eff.after.as_ref().and_then(|s| s.content.clone());
                rec.delta = eff.delta.as_ref().and_then(|d| serde_json::to_value(d).ok());
                rec.reversible = eff.reversible;
                rec.reversal_instructions = eff.reversal.as_ref().and_then(|r| serde_json::to_value(r).ok());
                rec.created_at = eff.timestamp;

                let stored_eff = state
                    .index_db
                    .store_effect(rec)
                    .await
                    .map_err(|e| GatewayError::Database(e.to_string()))?;
                effect_ids.push(stored_eff.id.to_string());
                stored_effects.push(stored_eff);
            }

            let duration_ms = start.elapsed().as_millis() as i64;
            let reason_code = if exec_result.success {
                ReasonCode::Success
            } else {
                ReasonCode::AdapterError
            };
            let message = exec_result.error.clone();
            let receipt_json = serde_json::json!({
                "status": if exec_result.success { "success" } else { "failed" },
                "duration_ms": duration_ms,
                "result": exec_result.data,
                "metadata": exec_result.metadata,
            });

            (reason_code, message, receipt_json, duration_ms, exec_result.success)
        }
        Err(e) => {
            let duration_ms = start.elapsed().as_millis() as i64;
            let receipt_json = serde_json::json!({
                "status": "failed",
                "duration_ms": duration_ms,
                "error": e.to_string(),
            });
            (ReasonCode::AdapterError, Some(e.to_string()), receipt_json, duration_ms, false)
        }
    };

    // Create and store receipt
    let mut receipt = ReceiptRecord::new(
        vakya.vakya_id.0.clone(),
        vakya_hash.clone(),
        reason_code,
        state.config.gateway_id.clone(),
        result_json,
    );
    receipt.message = message;
    receipt.duration_ms = Some(duration_ms);
    receipt.effect_ids = effect_ids;

    let stored_receipt = state
        .index_db
        .store_receipt(receipt)
        .await
        .map_err(|e| GatewayError::Database(e.to_string()))?;

    // Update metrics
    {
        let mut metrics = state.metrics.write().await;
        metrics.record_request(
            &vakya.v3_kriya.action,
            &vakya.v1_karta.pid.0,
            success_for_metrics,
            duration_ms as f64,
        );
    }

    Ok(Json(SubmitVakyaResponse {
        vakya_id: vakya.vakya_id.0,
        vakya_hash,
        status: if stored_receipt.reason_code.is_success() { "accepted".to_string() } else { "failed".to_string() },
        receipt: Some(ReceiptResponse {
            vakya_id: stored_receipt.vakya_id,
            vakya_hash: stored_receipt.vakya_hash,
            reason_code: stored_receipt.reason_code,
            message: stored_receipt.message,
            duration_ms: Some(duration_ms),
            effect_ids: stored_receipt.effect_ids,
            executor_id: stored_receipt.executor_id,
            created_at: stored_receipt.created_at.to_rfc3339(),
        }),
        merkle_root: stored.merkle_root,
        leaf_index: stored.leaf_index,
        policy_decision: None,
    }))
}

/// Get VĀKYA by ID
pub async fn get_vakya(
    State(state): State<Arc<AppState>>,
    Path(vakya_id): Path<String>,
) -> GatewayResult<Json<VakyaRecord>> {
    let record = state.index_db.get_vakya(&vakya_id).await
        .map_err(|e| GatewayError::Database(e.to_string()))?
        .ok_or_else(|| GatewayError::NotFound(format!("VĀKYA not found: {}", vakya_id)))?;

    Ok(Json(record))
}

/// Get receipt by VĀKYA ID
pub async fn get_receipt(
    State(state): State<Arc<AppState>>,
    Path(vakya_id): Path<String>,
) -> GatewayResult<Json<ReceiptRecord>> {
    let record = state.index_db.get_receipt(&vakya_id).await
        .map_err(|e| GatewayError::Database(e.to_string()))?
        .ok_or_else(|| GatewayError::NotFound(format!("Receipt not found for: {}", vakya_id)))?;

    Ok(Json(record))
}

/// Get effects for a VĀKYA
pub async fn get_effects(
    State(state): State<Arc<AppState>>,
    Path(vakya_id): Path<String>,
) -> GatewayResult<Json<Vec<EffectRecord>>> {
    let records = state.index_db.get_effects(&vakya_id).await
        .map_err(|e| GatewayError::Database(e.to_string()))?;

    Ok(Json(records))
}

/// Get Merkle root for a tree type
#[derive(Debug, Deserialize)]
pub struct MerkleRootQuery {
    pub tree_type: String,
}

#[derive(Debug, Serialize)]
pub struct MerkleRootResponse {
    pub tree_type: String,
    pub root_hash: Option<String>,
    pub timestamp: String,
}

pub async fn get_merkle_root(
    State(state): State<Arc<AppState>>,
    Query(query): Query<MerkleRootQuery>,
) -> GatewayResult<Json<MerkleRootResponse>> {
    let tree_type = match query.tree_type.as_str() {
        "vakya" => TreeType::Vakya,
        "effect" => TreeType::Effect,
        "receipt" => TreeType::Receipt,
        _ => return Err(GatewayError::Validation(format!("Invalid tree type: {}", query.tree_type))),
    };

    let root = state.index_db.get_merkle_root(tree_type).await
        .map_err(|e| GatewayError::Database(e.to_string()))?;

    Ok(Json(MerkleRootResponse {
        tree_type: query.tree_type,
        root_hash: root,
        timestamp: Utc::now().to_rfc3339(),
    }))
}

/// Get inclusion proof
#[derive(Debug, Deserialize)]
pub struct InclusionProofQuery {
    pub tree_type: String,
    pub leaf_index: i64,
}

pub async fn get_inclusion_proof(
    State(state): State<Arc<AppState>>,
    Query(query): Query<InclusionProofQuery>,
) -> GatewayResult<Json<serde_json::Value>> {
    let tree_type = match query.tree_type.as_str() {
        "vakya" => TreeType::Vakya,
        "effect" => TreeType::Effect,
        "receipt" => TreeType::Receipt,
        _ => return Err(GatewayError::Validation(format!("Invalid tree type: {}", query.tree_type))),
    };

    let proof = state.index_db.get_inclusion_proof(tree_type, query.leaf_index).await
        .map_err(|e| GatewayError::Database(e.to_string()))?
        .ok_or_else(|| GatewayError::NotFound("Proof not found".to_string()))?;

    Ok(Json(serde_json::to_value(proof).unwrap_or_default()))
}

/// Gateway metrics response
#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub requests_total: u64,
    pub requests_success: u64,
    pub requests_failed: u64,
    pub auth_denials: u64,
    pub avg_latency_ms: f64,
    pub top_actions: Vec<(String, u64)>,
    pub top_actors: Vec<(String, u64)>,
}

pub async fn get_metrics(
    State(state): State<Arc<AppState>>,
) -> Json<MetricsResponse> {
    let metrics = state.metrics.read().await;
    
    let mut top_actions: Vec<_> = metrics.requests_by_action.iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    top_actions.sort_by(|a, b| b.1.cmp(&a.1));
    top_actions.truncate(10);

    let mut top_actors: Vec<_> = metrics.requests_by_actor.iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    top_actors.sort_by(|a, b| b.1.cmp(&a.1));
    top_actors.truncate(10);

    Json(MetricsResponse {
        requests_total: metrics.requests_total,
        requests_success: metrics.requests_success,
        requests_failed: metrics.requests_failed,
        auth_denials: metrics.auth_denials,
        avg_latency_ms: metrics.avg_latency_ms,
        top_actions,
        top_actors,
    })
}

/// List adapters
#[derive(Debug, Serialize)]
pub struct AdapterListResponse {
    pub adapters: Vec<AdapterResponse>,
}

#[derive(Debug, Serialize)]
pub struct AdapterResponse {
    pub domain: String,
    pub version: String,
    pub actions: Vec<String>,
    pub healthy: bool,
}

pub async fn list_adapters(
    State(state): State<Arc<AppState>>,
) -> Json<AdapterListResponse> {
    let infos = state.dispatcher.adapter_info().await;
    let health = state.dispatcher.health_check_all().await;

    let adapter_list: Vec<AdapterResponse> = infos
        .into_iter()
        .map(|a| {
            let healthy = health
                .get(&a.domain)
                .map(|h| h.healthy)
                .unwrap_or(true);
            AdapterResponse {
                domain: a.domain,
                version: a.version,
                actions: a.actions,
                healthy,
            }
        })
        .collect();

    Json(AdapterListResponse {
        adapters: adapter_list,
    })
}
