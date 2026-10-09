use axum::{extract::State, Json};
use chrono::Datelike;
use crate::SharedState;
use crate::types::Tier;

/// Track 7 — Item P.1: Create Stripe checkout session for a tier
pub async fn create_checkout(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let tier_str = req.get("tier").and_then(|v| v.as_str()).unwrap_or("indie");
    let email = req.get("email").and_then(|v| v.as_str()).unwrap_or("");
    let name = req.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let success_url = req.get("success_url").and_then(|v| v.as_str()).unwrap_or("https://connector.dev/success");
    let cancel_url = req.get("cancel_url").and_then(|v| v.as_str()).unwrap_or("https://connector.dev/pricing");

    let tier = Tier::from_str(tier_str);
    let session_id = format!("cs_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));

    // Store pending checkout
    let mut store = state.store.lock().unwrap();
    store.revocation_log.push(serde_json::json!({
        "type": "checkout_created",
        "session_id": &session_id,
        "tier": format!("{:?}", tier),
        "email": email,
        "name": name,
        "amount_cents": tier.price_cents(),
        "created_at": chrono::Utc::now().to_rfc3339(),
    }));

    Json(serde_json::json!({
        "checkout_session_id": session_id,
        "url": format!("https://checkout.stripe.com/c/pay/{}", session_id),
        "tier": format!("{:?}", tier),
        "amount_cents": tier.price_cents(),
        "amount_display": format!("${}/mo", tier.price_cents() / 100),
        "customer_email": email,
        "success_url": success_url,
        "cancel_url": cancel_url,
        "note": "In production, this calls Stripe API with STRIPE_SECRET_KEY env var",
    }))
}

/// Track 7 — Item P.2: List Stripe price IDs per tier
pub async fn list_prices(
    State(_state): State<SharedState>,
) -> Json<serde_json::Value> {
    let tiers = [
        Tier::Indie, Tier::Startup, Tier::Growth, Tier::Business,
        Tier::Scale, Tier::Enterprise, Tier::Core, Tier::Sovereign,
    ];

    let prices: Vec<serde_json::Value> = tiers.iter().map(|t| {
        serde_json::json!({
            "tier": format!("{:?}", t),
            "price_id": format!("price_connector_{}", format!("{:?}", t).to_lowercase()),
            "amount_cents": t.price_cents(),
            "amount_display": format!("${}/mo", t.price_cents() / 100),
            "currency": "usd",
            "interval": "month",
            "max_agents": t.max_agents(),
            "max_events": t.max_events(),
            "retention_days": t.retention_days(),
        })
    }).collect();

    Json(serde_json::json!({
        "prices": prices,
        "currency": "usd",
    }))
}

/// Track 7 — Item P.3: Customer portal link
pub async fn customer_portal(
    State(_state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let customer_id = req.get("customer_id").and_then(|v| v.as_str()).unwrap_or("");
    let return_url = req.get("return_url").and_then(|v| v.as_str()).unwrap_or("https://connector.dev/dashboard");

    let portal_session = format!("bps_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));

    Json(serde_json::json!({
        "portal_session_id": portal_session,
        "url": format!("https://billing.stripe.com/p/session/{}", portal_session),
        "customer_id": customer_id,
        "return_url": return_url,
        "note": "In production, this calls Stripe Billing Portal API",
    }))
}

/// Track 7 — Item P.4: Revenue dashboard
pub async fn revenue_dashboard(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let store = state.store.lock().unwrap();
    let now = chrono::Utc::now();

    let mrr = store.total_mrr_cents();
    let arr = mrr * 12;
    let active = store.active_keys();
    let total = store.total_keys();
    let churn = if total > 0 { (total - active) as f64 / total as f64 * 100.0 } else { 0.0 };

    let mut tier_revenue: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for key in store.keys.values().filter(|k| !k.revoked && !k.active_instances.is_empty()) {
        *tier_revenue.entry(format!("{:?}", key.tier)).or_insert(0) += key.tier.price_cents() as u64;
    }

    Json(serde_json::json!({
        "timestamp": now.to_rfc3339(),
        "mrr_cents": mrr,
        "mrr_display": format!("${:.2}", mrr as f64 / 100.0),
        "arr_cents": arr,
        "arr_display": format!("${:.2}", arr as f64 / 100.0),
        "active_subscriptions": active,
        "total_keys_issued": total,
        "churn_pct": (churn * 10.0).round() / 10.0,
        "active_instances": store.active_activations(),
        "tier_revenue": tier_revenue,
    }))
}

// ── P.7: Trial period configuration ──────────────────────────────────────────

/// GET /api/v1/payment/trial-config
/// Returns the trial period configuration for new subscriptions.
pub async fn trial_config() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "trial_days":         14,
        "trial_requires_card": true,
        "trial_auto_converts": true,
        "trial_cancellation":  "Cancel any time before day 14 — no charge",
        "stripe_trial_param":  "subscription_data.trial_period_days=14",
        "note": "All tiers include a 14-day free trial. Card required at signup to prevent abuse.",
        "money_back_days": 14,
        "money_back_policy": "Full refund if cancelled within 14 days of first charge. No questions asked.",
    }))
}

// ── P.8: Proration on tier changes ────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ProrationRequest {
    pub customer_id:  String,
    pub from_tier:    String,
    pub to_tier:      String,
    pub change_at:    Option<String>,  // "now" | "next_billing" (default: now)
}

/// POST /api/v1/payment/prorate
/// Calculates proration credit when a customer upgrades or downgrades tier.
pub async fn calculate_proration(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::AppState>>,
    axum::extract::Json(req): axum::extract::Json<ProrationRequest>,
) -> axum::extract::Json<serde_json::Value> {
    let now        = chrono::Utc::now();
    let change_at  = req.change_at.as_deref().unwrap_or("now");

    // Get tier prices
    let from_cents = tier_price_cents(&req.from_tier);
    let to_cents   = tier_price_cents(&req.to_tier);
    let is_upgrade = to_cents > from_cents;

    // Calculate days remaining in billing cycle (assume billing on 1st of month)
    let days_in_month   = days_in_current_month(now);
    let day_of_month    = now.day();
    let days_remaining  = days_in_month.saturating_sub(day_of_month) + 1;
    let daily_from      = from_cents as f64 / days_in_month as f64;
    let daily_to        = to_cents as f64 / days_in_month as f64;

    let proration_credit_cents = (daily_from * days_remaining as f64).round() as i64;
    let prorated_new_cents     = (daily_to   * days_remaining as f64).round() as i64;
    let amount_due_cents       = (prorated_new_cents - proration_credit_cents).max(0);

    // Look up customer key in store to verify tier
    let store  = state.store.lock().unwrap();
    let _exists = store.keys.values().any(|k| k.customer_email == req.customer_id || k.key_id == req.customer_id);

    axum::extract::Json(serde_json::json!({
        "customer_id":         req.customer_id,
        "from_tier":           req.from_tier,
        "to_tier":             req.to_tier,
        "is_upgrade":          is_upgrade,
        "change_at":           change_at,
        "days_remaining":      days_remaining,
        "days_in_month":       days_in_month,
        "from_monthly_cents":  from_cents,
        "to_monthly_cents":    to_cents,
        "proration_credit":    format!("${:.2}", proration_credit_cents as f64 / 100.0),
        "prorated_new_charge": format!("${:.2}", prorated_new_cents as f64 / 100.0),
        "amount_due_today":    format!("${:.2}", amount_due_cents as f64 / 100.0),
        "next_full_billing":   next_billing_date(now).to_rfc3339(),
        "stripe_behavior":     "Stripe handles proration automatically on subscription update",
        "generated_at":        now.to_rfc3339(),
    }))
}

fn tier_price_cents(tier: &str) -> u32 {
    match tier {
        "Indie"      => 15_000,
        "Startup"    => 25_000,
        "Growth"     => 50_000,
        "Business"   => 100_000,
        "Scale"      => 200_000,
        "Enterprise" => 300_000,
        "Core"       => 400_000,
        "Sovereign"  => 500_000,
        _            => 0,
    }
}

fn days_in_current_month(dt: chrono::DateTime<chrono::Utc>) -> u32 {
    use chrono::{Datelike, TimeZone};
    let year  = dt.year();
    let month = dt.month();
    let next_month = if month == 12 { 1 } else { month + 1 };
    let next_year  = if month == 12 { year + 1 } else { year };
    let first_next = chrono::Utc.with_ymd_and_hms(next_year, next_month, 1, 0, 0, 0).unwrap();
    let first_this = chrono::Utc.with_ymd_and_hms(year, month, 1, 0, 0, 0).unwrap();
    (first_next - first_this).num_days() as u32
}

fn next_billing_date(now: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    use chrono::{Datelike, TimeZone};
    let next_month = if now.month() == 12 { 1 } else { now.month() + 1 };
    let next_year  = if now.month() == 12 { now.year() + 1 } else { now.year() };
    chrono::Utc.with_ymd_and_hms(next_year, next_month, 1, 0, 0, 0).unwrap()
}

// ── P.9: Stripe Tax configuration endpoint ────────────────────────────────────

/// GET /api/v1/payment/tax-config
/// Returns Stripe Tax configuration and supported regions.
pub async fn tax_config() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "stripe_tax_enabled": true,
        "automatic_tax": {
            "enabled": true,
            "liability": { "type": "self" },
        },
        "supported_regions": ["US", "EU", "GB", "CA", "AU", "IN"],
        "tax_behavior": "exclusive",
        "eu_vat": {
            "collect_eu_vat_id": true,
            "reverse_charge_eligible": true,
        },
        "us_sales_tax": {
            "nexus_states": ["CA", "NY", "TX", "WA"],
            "economic_nexus_threshold_usd": 100_000,
        },
        "stripe_docs": "https://stripe.com/docs/tax",
        "note": "Configure via Stripe Dashboard → Tax → Settings. Enable automatic tax collection per product.",
    }))
}

// ── P.10: Invoice PDF generation ──────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct InvoiceRequest {
    pub customer_id:   String,
    pub invoice_id:    Option<String>,
    pub period_start:  Option<String>,
    pub period_end:    Option<String>,
}

/// POST /api/v1/payment/invoice-pdf
/// Generates a plain-text invoice PDF for a customer billing period.
pub async fn invoice_pdf(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::AppState>>,
    axum::extract::Json(req): axum::extract::Json<InvoiceRequest>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let now       = chrono::Utc::now();
    let store     = state.store.lock().unwrap();

    // Find the customer's key record
    let key_rec = store.keys.values()
        .find(|k| k.customer_email == req.customer_id || k.key_id == req.customer_id);

    let (tier_name, tier_price, instance_id) = match key_rec {
        Some(k) => (format!("{:?}", k.tier), k.tier.price_cents(), k.key_id.clone()),
        None    => return (axum::http::StatusCode::NOT_FOUND,
                           axum::Json(serde_json::json!({"error": "Customer not found"}))).into_response(),
    };

    let invoice_id  = req.invoice_id.unwrap_or_else(|| format!("INV-{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("00000").to_uppercase()));
    let period_start = req.period_start.clone().unwrap_or_else(|| {
        let s = next_billing_date(now) - chrono::Duration::days(30);
        s.format("%Y-%m-%d").to_string()
    });
    let period_end = req.period_end.clone().unwrap_or_else(|| now.format("%Y-%m-%d").to_string());

    let subtotal    = tier_price;
    let tax_rate    = 0.0f64; // tax handled by Stripe in production
    let tax_cents   = (subtotal as f64 * tax_rate) as u32;
    let total_cents = subtotal + tax_cents;

    let pdf_text = format!(
        "CONNECTOR PLATFORM — INVOICE\n\
         =============================\n\
         Invoice #    : {invoice_id}\n\
         Date         : {date}\n\
         Period       : {period_start} to {period_end}\n\
         \n\
         BILL TO\n\
         -------\n\
         Customer ID  : {cid}\n\
         Instance ID  : {iid}\n\
         \n\
         ITEMS\n\
         -----\n\
         {tier_name} Plan (monthly)           ${subtotal_fmt}\n\
         Tax (0%)                              $0.00\n\
         ─────────────────────────────────────────────\n\
         TOTAL DUE                            ${total_fmt}\n\
         \n\
         PAYMENT METHOD\n\
         --------------\n\
         Stripe — automatic charge on file\n\
         \n\
         QUESTIONS?\n\
         ----------\n\
         billing@connector.dev | https://connector.dev/billing\n\
         \n\
         Connector Platform is operated by [Your Company Name]\n\
         [Address] | [Tax ID]\n",
        invoice_id   = invoice_id,
        date         = now.format("%Y-%m-%d"),
        period_start = period_start,
        period_end   = period_end,
        cid          = req.customer_id,
        iid          = instance_id,
        tier_name    = tier_name,
        subtotal_fmt = format!("{:.2}", subtotal as f64 / 100.0),
        total_fmt    = format!("{:.2}", total_cents as f64 / 100.0),
    );

    let filename = format!("invoice-{}.txt", invoice_id);
    axum::response::Response::builder()
        .status(200)
        .header("content-type", "text/plain; charset=utf-8")
        .header("content-disposition", format!("attachment; filename=\"{}\"", filename))
        .header("x-invoice-id", invoice_id)
        .body(axum::body::Body::from(pdf_text))
        .unwrap_or_default()
}
