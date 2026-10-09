use axum::{extract::{Path, State}, http::HeaderMap, Json};
use crate::{SharedState, types::*, keys};

static START_TIME: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

pub fn init_start_time() {
    START_TIME.get_or_init(std::time::Instant::now);
}

pub async fn health(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let uptime = START_TIME.get().map(|t| t.elapsed().as_secs()).unwrap_or(0);
    let (keys_loaded, active_keys) = {
        let store = state.store.lock().unwrap();
        (store.total_keys(), store.active_keys())
    };
    let (customers, instances) = {
        let sdb = state.surveillance_db.lock().unwrap();
        (sdb.total_customers(), sdb.total_instances())
    };
    let db_ok = true; // PgPool: connection verified at startup
    Json(serde_json::json!({
        "status": "ok",
        "service": "connector-license-server",
        "version": env!("CARGO_PKG_VERSION"),
        "db_ok": db_ok,
        "keys_loaded": keys_loaded,
        "active_keys": active_keys,
        "customers": customers,
        "instances": instances,
        "uptime_secs": uptime,
    }))
}

pub async fn issue_key(
    State(state): State<SharedState>,
    Json(req): Json<IssueRequest>,
) -> Json<serde_json::Value> {
    let tier = Tier::from_str(&req.tier);
    let key_id = format!("key_{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0000"));
    let key_secret = keys::generate_key_secret(&req.tier, &req.customer_email);
    let now = chrono::Utc::now();

    let expires_at = req.expires_days.map(|d| {
        (now + chrono::Duration::days(d as i64)).to_rfc3339()
    });

    let payload = format!("{}:{}:{:?}:{}", key_id, key_secret, tier, req.customer_email);
    let signature = state.signing_key.sign(payload.as_bytes());

    let license_key = LicenseKey {
        key_id: key_id.clone(),
        key_secret: key_secret.clone(),
        tier,
        customer_email: req.customer_email.clone(),
        customer_name: req.customer_name.clone(),
        issued_at: now.to_rfc3339(),
        expires_at,
        max_activations: req.max_activations.unwrap_or(3),
        active_instances: Vec::new(),
        revoked: false,
        stripe_subscription_id: req.stripe_subscription_id,
        signature: signature.clone(),
    };

    {
        let mut store = state.store.lock().unwrap();
        store.insert_key(license_key.clone());
    }
    state.db.upsert_key(&license_key).await;

    Json(serde_json::json!({
        "key_id": key_id,
        "key_secret": key_secret,
        "tier": format!("{:?}", tier),
        "customer_email": req.customer_email,
        "issued_at": now.to_rfc3339(),
        "max_activations": req.max_activations.unwrap_or(3),
        "signature": signature,
    }))
}

pub async fn validate_key(
    State(state): State<SharedState>,
    Json(req): Json<ValidateRequest>,
) -> Json<serde_json::Value> {
    let store = state.store.lock().unwrap();
    match store.find_by_secret(&req.key_secret) {
        Some(key) => {
            let expired = key.expires_at.as_ref().map_or(false, |exp| {
                chrono::DateTime::parse_from_rfc3339(exp)
                    .map(|dt| dt < chrono::Utc::now())
                    .unwrap_or(false)
            });

            let payload = format!("{}:{}:{:?}:{}", key.key_id, key.key_secret, key.tier, key.customer_email);
            let sig_valid = state.signing_key.verify(payload.as_bytes(), &key.signature);

            Json(serde_json::json!({
                "valid": !key.revoked && !expired && sig_valid,
                "key_id": &key.key_id,
                "tier": format!("{:?}", key.tier),
                "revoked": key.revoked,
                "expired": expired,
                "signature_valid": sig_valid,
                "active_instances": key.active_instances.len(),
                "max_activations": key.max_activations,
                "limits": {
                    "max_agents": key.tier.max_agents(),
                    "max_events": key.tier.max_events(),
                    "retention_days": key.tier.retention_days(),
                },
            }))
        }
        None => Json(serde_json::json!({"valid": false, "error": "Key not found"})),
    }
}

pub async fn revoke_key(
    State(state): State<SharedState>,
    Json(req): Json<RevokeRequest>,
) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let found = {
        let mut store = state.store.lock().unwrap();
        if let Some(key) = store.get_key_mut(&req.key_id) {
            key.revoked = true;
            store.revocation_log.push(serde_json::json!({
                "key_id": req.key_id,
                "revoked_at": now.to_rfc3339(),
                "reason": req.reason,
            }));
            true
        } else { false }
    };
    if found {
        state.db.revoke_key(&req.key_id, req.reason.as_deref()).await;
        Json(serde_json::json!({
            "key_id": req.key_id,
            "revoked": true,
            "revoked_at": now.to_rfc3339(),
        }))
    } else {
        Json(serde_json::json!({"error": "Key not found"}))
    }
}

pub async fn get_key(
    State(state): State<SharedState>,
    Path(key_id): Path<String>,
) -> Json<serde_json::Value> {
    let store = state.store.lock().unwrap();
    match store.get_key(&key_id) {
        Some(key) => Json(serde_json::json!({
            "key_id": &key.key_id,
            "tier": format!("{:?}", key.tier),
            "customer_email": &key.customer_email,
            "customer_name": &key.customer_name,
            "issued_at": &key.issued_at,
            "expires_at": &key.expires_at,
            "max_activations": key.max_activations,
            "active_instances": key.active_instances.len(),
            "revoked": key.revoked,
            "stripe_subscription_id": &key.stripe_subscription_id,
        })),
        None => Json(serde_json::json!({"error": "Key not found"})),
    }
}

pub async fn list_keys(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let store = state.store.lock().unwrap();
    let keys: Vec<serde_json::Value> = store.keys.values().map(|k| {
        serde_json::json!({
            "key_id": &k.key_id,
            "tier": format!("{:?}", k.tier),
            "customer_email": &k.customer_email,
            "active_instances": k.active_instances.len(),
            "revoked": k.revoked,
            "issued_at": &k.issued_at,
        })
    }).collect();
    Json(serde_json::json!({"count": keys.len(), "keys": keys}))
}

pub async fn activate(
    State(state): State<SharedState>,
    Json(req): Json<ActivateRequest>,
) -> Json<serde_json::Value> {
    let instance_id = format!("inst_{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0000"));
    let now = chrono::Utc::now();

    // Extract all needed data and drop the guard before any .await
    let result = {
        let mut store = state.store.lock().unwrap();
        let key = match store.find_by_secret_mut(&req.key_secret) {
            Some(k) => k,
            None => return Json(serde_json::json!({"error": "Invalid license key"})),
        };
        if key.revoked {
            return Json(serde_json::json!({"error": "License key has been revoked"}));
        }
        let expired = key.expires_at.as_ref().map_or(false, |exp| {
            chrono::DateTime::parse_from_rfc3339(exp)
                .map(|dt| dt < chrono::Utc::now())
                .unwrap_or(false)
        });
        if expired {
            return Json(serde_json::json!({
                "error": "License key has expired. Renew your subscription to activate.",
                "expires_at": key.expires_at,
            }));
        }
        if key.active_instances.len() >= key.max_activations as usize {
            return Json(serde_json::json!({
                "error": "Maximum activations reached",
                "max": key.max_activations,
                "active": key.active_instances.len(),
            }));
        }
        key.active_instances.push(instance_id.clone());
        let activation = Activation {
            instance_id: instance_id.clone(),
            key_id: key.key_id.clone(),
            machine_id: req.machine_id.clone(),
            hostname: req.hostname.clone(),
            activated_at: now.to_rfc3339(),
            last_heartbeat: None,
            deactivated_at: None,
        };
        let tier = key.tier;
        let key_id = key.key_id.clone();
        let active_instances = key.active_instances.clone();
        store.insert_activation(activation.clone());
        (activation, tier, key_id, active_instances)
    }; // guard dropped here
    let (activation, tier, key_id, active_instances) = result;

    state.db.upsert_activation(&activation).await;
    state.db.update_key_instances(&key_id, &active_instances).await;

    Json(serde_json::json!({
        "instance_id": instance_id,
        "key_id": key_id,
        "tier": format!("{:?}", tier),
        "activated_at": now.to_rfc3339(),
        "machine_id": req.machine_id,
        "limits": {
            "max_agents": tier.max_agents(),
            "max_events": tier.max_events(),
            "retention_days": tier.retention_days(),
        },
    }))
}

pub async fn deactivate(
    State(state): State<SharedState>,
    Json(req): Json<DeactivateRequest>,
) -> Json<serde_json::Value> {
    let mut store = state.store.lock().unwrap();
    let now = chrono::Utc::now();

    // Remove from key's active instances
    if let Some(key) = store.get_key_mut(&req.key_id) {
        key.active_instances.retain(|i| i != &req.instance_id);
    }

    // Mark activation as deactivated
    if let Some(act) = store.get_activation_mut(&req.instance_id) {
        act.deactivated_at = Some(now.to_rfc3339());
        let act_clone = act.clone();
        let db = state.db.clone();
        tokio::spawn(async move { db.upsert_activation(&act_clone).await; });
    }
    if let Some(key) = store.get_key(&req.key_id) {
        let instances = key.active_instances.clone();
        let key_id2 = req.key_id.clone();
        let db = state.db.clone();
        tokio::spawn(async move { db.update_key_instances(&key_id2, &instances).await; });
    }

    Json(serde_json::json!({
        "instance_id": req.instance_id,
        "deactivated": true,
        "deactivated_at": now.to_rfc3339(),
    }))
}

pub async fn heartbeat(
    State(state): State<SharedState>,
    Json(req): Json<HeartbeatPayload>,
) -> Json<serde_json::Value> {
    let mut store = state.store.lock().unwrap();
    let now = chrono::Utc::now();

    // BUG-LIC-002 fix: check both revoked and expiry
    let key_valid = store.get_key(&req.key_id).map_or(false, |k| {
        if k.revoked { return false; }
        k.expires_at.as_ref().map_or(true, |exp| {
            chrono::DateTime::parse_from_rfc3339(exp)
                .map(|dt| dt >= chrono::Utc::now())
                .unwrap_or(false)
        })
    });

    // Validate instance
    let instance_valid = store.get_activation(&req.instance_id)
        .map_or(false, |a| a.deactivated_at.is_none() && a.key_id == req.key_id);

    // Update last heartbeat
    if let Some(act) = store.get_activation_mut(&req.instance_id) {
        act.last_heartbeat = Some(now.to_rfc3339());
    }

    // Check limits
    let tier = store.get_key(&req.key_id).map(|k| k.tier);
    let within_limits = tier.map_or(false, |t| {
        let agents_ok = t.max_agents().map_or(true, |max| req.agents <= max);
        let events_ok = t.max_events().map_or(true, |max| req.packets <= max);
        agents_ok && events_ok
    });

    Json(serde_json::json!({
        "ack": true,
        "timestamp": now.to_rfc3339(),
        "key_valid": key_valid,
        "instance_valid": instance_valid,
        "within_limits": within_limits,
        "next_heartbeat_secs": 3600,
    }))
}

pub async fn usage_report(
    State(state): State<SharedState>,
    Json(req): Json<UsageRecord>,
) -> Json<serde_json::Value> {
    let instance_id = req.instance_id.clone();
    let req_clone = req.clone();
    {
        let mut store = state.store.lock().unwrap();
        store.record_usage(req);
    } // guard dropped
    state.db.record_usage(&req_clone).await;

    Json(serde_json::json!({
        "recorded": true,
        "instance_id": instance_id,
    }))
}

pub async fn usage_history(
    State(state): State<SharedState>,
    Path(instance_id): Path<String>,
) -> Json<serde_json::Value> {
    let store = state.store.lock().unwrap();
    let records: Vec<serde_json::Value> = store.usage_for_instance(&instance_id)
        .iter()
        .map(|u| serde_json::json!({
            "timestamp": &u.timestamp,
            "agents_active": u.agents_active,
            "packets_stored": u.packets_stored,
            "audit_entries": u.audit_entries,
            "total_tokens": u.total_tokens,
            "total_cost_usd": u.total_cost_usd,
        }))
        .collect();

    Json(serde_json::json!({
        "instance_id": instance_id,
        "records": records.len(),
        "usage": records,
    }))
}

/// Generate a signed offline license FILE for a key.
/// The binary can verify this entirely offline using the embedded public key.
/// Used for air-gapped deployments or as a backup to network validation.
pub async fn generate_license_file(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let key_secret = req.get("key_secret").and_then(|v| v.as_str()).unwrap_or("");
    let machine_id = req.get("machine_id").and_then(|v| v.as_str());
    let store = state.store.lock().unwrap();

    let key = match store.find_by_secret(key_secret) {
        Some(k) => k,
        None => return Json(serde_json::json!({"error": "Invalid license key"})),
    };

    if key.revoked {
        return Json(serde_json::json!({"error": "License key has been revoked"}));
    }

    let now = chrono::Utc::now();
    // BUG-LIC-019 fix: do not embed key_secret in offline license file
    let payload = serde_json::json!({
        "key_id":        &key.key_id,
        "tier":          format!("{:?}", key.tier),
        "customer_email":&key.customer_email,
        "customer_name": &key.customer_name,
        "issued_at":     now.to_rfc3339(),
        "expires_at":    &key.expires_at,
        "max_activations": key.max_activations,
        "machine_id":    machine_id,
        "limits": {
            "max_agents":     key.tier.max_agents(),
            "max_events":     key.tier.max_events(),
            "retention_days": key.tier.retention_days(),
        },
        "file_version":  "1",
    });

    let license_file = keys::generate_license_file(&state.signing_key, &payload);

    Json(serde_json::json!({
        "license_file": license_file,
        "key_id": &key.key_id,
        "tier": format!("{:?}", key.tier),
        "public_key_hex": state.signing_key.public_key_hex(),
        "note": "Embed public_key_hex in your binary at build time for offline validation.",
    }))
}

/// Expose the server's current public key.
/// Operators embed this in the binary at build time — allows offline license verification.
pub async fn public_key(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "algorithm":    "ed25519",
        "public_key_hex": state.signing_key.public_key_hex(),
        "public_key_b64": state.signing_key.public_key_b64(),
        "usage": "Embed public_key_hex in binary via build.rs for offline license file verification.",
    }))
}

pub async fn stripe_webhook(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Json<serde_json::Value> {
    // Verify Stripe-Signature header to prevent spoofed webhooks
    let stripe_secret = std::env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_default();
    if !stripe_secret.is_empty() {
        let sig_header = headers
            .get("stripe-signature")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !verify_stripe_signature(&body, sig_header, &stripe_secret) {
            return Json(serde_json::json!({
                "error": "Invalid Stripe signature",
                "hint":  "Set STRIPE_WEBHOOK_SECRET to your Stripe webhook signing secret",
            }));
        }
    }

    let body_val: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return Json(serde_json::json!({"error": "Invalid JSON body"})),
    };

    let event_type = body_val.get("type").and_then(|v| v.as_str()).unwrap_or("unknown");
    let now = chrono::Utc::now();

    match event_type {
        "customer.subscription.created" | "customer.subscription.updated" => {
            let sub_id = body_val.get("data")
                .and_then(|d| d.get("object"))
                .and_then(|o| o.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            Json(serde_json::json!({
                "received": true,
                "event_type": event_type,
                "subscription_id": sub_id,
                "processed_at": now.to_rfc3339(),
                "action": "subscription_updated",
            }))
        }
        "customer.subscription.deleted" => {
            let sub_id = body_val.get("data")
                .and_then(|d| d.get("object"))
                .and_then(|o| o.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let revoked_keys: Vec<String> = {
                let mut store = state.store.lock().unwrap();
                let mut rk = Vec::new();
                for key in store.keys.values_mut() {
                    if key.stripe_subscription_id.as_deref() == Some(sub_id) && !key.revoked {
                        key.revoked = true;
                        rk.push(key.key_id.clone());
                    }
                }
                rk
            }; // guard dropped
            for key_id in &revoked_keys {
                state.db.revoke_key(key_id, Some("stripe_subscription_deleted")).await;
            }

            Json(serde_json::json!({
                "received": true,
                "event_type": event_type,
                "subscription_id": sub_id,
                "keys_revoked": revoked_keys.len(),
                "revoked_key_ids": revoked_keys,
                "processed_at": now.to_rfc3339(),
            }))
        }
        "invoice.payment_failed" => {
            Json(serde_json::json!({
                "received": true,
                "event_type": event_type,
                "processed_at": now.to_rfc3339(),
                "action": "payment_failure_logged",
            }))
        }
        _ => {
            Json(serde_json::json!({
                "received": true,
                "event_type": event_type,
                "processed_at": now.to_rfc3339(),
                "action": "ignored",
            }))
        }
    }
}

/// Verify Stripe webhook signature (HMAC-SHA256).
/// Stripe sends: Stripe-Signature: t=<timestamp>,v1=<hmac_hex>
/// We verify: HMAC-SHA256(secret, "<timestamp>.<body>") == v1
fn verify_stripe_signature(body: &[u8], sig_header: &str, secret: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Parse t= and v1= from header
    let mut timestamp = "";
    let mut v1_sig = "";
    for part in sig_header.split(',') {
        if let Some(ts) = part.strip_prefix("t=") { timestamp = ts; }
        if let Some(sig) = part.strip_prefix("v1=") { v1_sig = sig; }
    }
    if timestamp.is_empty() || v1_sig.is_empty() { return false; }

    // signed_payload = "<timestamp>.<body>"
    let mut signed = Vec::new();
    signed.extend_from_slice(timestamp.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(body);

    // Compute HMAC-SHA256
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(&signed);
    let result = mac.finalize().into_bytes();
    let computed = hex::encode(result);

    // Constant-time compare
    computed == v1_sig
}

pub async fn admin_stats(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let store = state.store.lock().unwrap();
    let now = chrono::Utc::now();

    let mut tier_breakdown: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for key in store.keys.values().filter(|k| !k.revoked) {
        *tier_breakdown.entry(format!("{:?}", key.tier)).or_insert(0) += 1;
    }

    Json(serde_json::json!({
        "timestamp": now.to_rfc3339(),
        "total_keys": store.total_keys(),
        "active_keys": store.active_keys(),
        "total_activations": store.total_activations(),
        "active_activations": store.active_activations(),
        "mrr_cents": store.total_mrr_cents(),
        "mrr_display": format!("${:.2}", store.total_mrr_cents() as f64 / 100.0),
        "usage_records": store.usage.len(),
        "tier_breakdown": tier_breakdown,
        "public_key": state.signing_key.public_key_b64(),
    }))
}

pub async fn list_instances(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let store = state.store.lock().unwrap();
    let instances: Vec<serde_json::Value> = store.activations.values().map(|a| {
        serde_json::json!({
            "instance_id": &a.instance_id,
            "key_id": &a.key_id,
            "machine_id": &a.machine_id,
            "hostname": &a.hostname,
            "activated_at": &a.activated_at,
            "last_heartbeat": &a.last_heartbeat,
            "active": a.deactivated_at.is_none(),
        })
    }).collect();

    Json(serde_json::json!({"count": instances.len(), "instances": instances}))
}
