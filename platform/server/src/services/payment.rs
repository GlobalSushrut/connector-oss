// ── Payment Service ────────────────────────────────────────────────────────────
//
// Open-source Rust Stripe client: async-stripe (github.com/arlyon/async-stripe)
// License: MIT / Apache-2.0
//
// Architecture:
//   - PaymentProvider trait: dyn-compatible via BoxFuture (no async-trait dep needed)
//   - StripeProvider: concrete impl using async-stripe 0.40
//   - All card data goes directly to Stripe hosted checkout (PCI DSS Level 1)
//     — raw card numbers never touch this server
//   - Webhook handler: HMAC-SHA256 signature verified before processing
//   - NoopProvider: graceful fallback when STRIPE_SECRET_KEY is not set
//
// Routes:
//   GET  /payment/plans    → list available plans + prices
//   POST /payment/checkout → create Stripe Checkout Session, return redirect URL
//   POST /payment/portal   → create Stripe Billing Portal session
//   POST /payment/webhook  → Stripe webhook receiver (signature-verified)
//   GET  /payment/status   → current subscription status for authenticated user

use std::future::Future;
use std::pin::Pin;

use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};
use stripe::{
    BillingPortalSession, CheckoutSession, CheckoutSessionMode, Client as StripeClient,
    CreateBillingPortalSession, CreateCheckoutSession, CreateCheckoutSessionLineItems,
    CreateCheckoutSessionLineItemsPriceData, CreateCheckoutSessionLineItemsPriceDataProductData,
    CreateCheckoutSessionLineItemsPriceDataRecurring,
    CreateCheckoutSessionLineItemsPriceDataRecurringInterval, Currency, EventObject, EventType,
    Webhook,
};

use crate::state::SharedState;

// ── BoxFuture alias (avoids async-trait dep, keeps trait dyn-compatible) ─────

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ── Plan definitions (server-side source of truth) ───────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub id: &'static str,
    pub name: &'static str,
    pub price_monthly: u64, // cents USD
    pub price_annual: u64,  // cents USD  (10× monthly = 2 months free)
    pub agents: &'static str,
    pub events: &'static str,
    pub retention: &'static str,
    pub support: &'static str,
    pub popular: bool,
}

pub const PLANS: &[Plan] = &[
    Plan {
        id: "indie",
        name: "Indie",
        price_monthly: 15000,
        price_annual: 150000,
        agents: "3",
        events: "50K/mo",
        retention: "30 days",
        support: "Community",
        popular: false,
    },
    Plan {
        id: "startup",
        name: "Startup",
        price_monthly: 25000,
        price_annual: 250000,
        agents: "10",
        events: "200K/mo",
        retention: "90 days",
        support: "Email",
        popular: false,
    },
    Plan {
        id: "growth",
        name: "Growth",
        price_monthly: 50000,
        price_annual: 500000,
        agents: "50",
        events: "1M/mo",
        retention: "180 days",
        support: "Priority",
        popular: true,
    },
    Plan {
        id: "business",
        name: "Business",
        price_monthly: 100000,
        price_annual: 1000000,
        agents: "200",
        events: "5M/mo",
        retention: "1 year",
        support: "Dedicated",
        popular: false,
    },
    Plan {
        id: "enterprise",
        name: "Enterprise",
        price_monthly: 300000,
        price_annual: 3000000,
        agents: "Unlimited",
        events: "Unlimited",
        retention: "7 years",
        support: "White-glove",
        popular: false,
    },
];

fn find_plan(id: &str) -> Option<&'static Plan> {
    PLANS
        .iter()
        .find(|p| p.id.eq_ignore_ascii_case(id) || p.name.eq_ignore_ascii_case(id))
}

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CheckoutRequest {
    pub tier: String,
    pub billing_cycle: Option<String>, // "monthly" | "annual"
    pub customer_email: Option<String>,
    pub customer_name: Option<String>,
    pub company: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PortalRequest {
    pub customer_id: Option<String>,
    pub customer_email: Option<String>,
    pub return_url: Option<String>,
}

// ── PaymentProvider trait — dyn-compatible, provider-agnostic ────────────────
//
// Uses explicit BoxFuture returns instead of `async fn` so the trait is
// object-safe (dyn PaymentProvider works) without async-trait.

pub trait PaymentProvider: Send + Sync {
    fn create_checkout_url<'a>(
        &'a self,
        req: &'a CheckoutRequest,
    ) -> BoxFut<'a, Result<String, String>>;

    fn create_portal_url<'a>(
        &'a self,
        customer_id: &'a str,
        return_url: &'a str,
    ) -> BoxFut<'a, Result<String, String>>;

    fn verify_webhook(&self, payload: &[u8], sig_header: &str) -> Result<stripe::Event, String>;
}

// ── Stripe provider ───────────────────────────────────────────────────────────

pub struct StripeProvider {
    client: StripeClient,
    webhook_secret: String,
    success_url: String,
    cancel_url: String,
}

impl StripeProvider {
    pub fn new(secret_key: String, webhook_secret: String, base_url: String) -> Self {
        Self {
            client: StripeClient::new(secret_key),
            webhook_secret,
            success_url: format!("{}/checkout/success", base_url),
            cancel_url: format!("{}/dashboard/billing", base_url),
        }
    }

    async fn do_checkout(&self, req: &CheckoutRequest) -> Result<String, String> {
        let plan = find_plan(&req.tier).ok_or_else(|| format!("Unknown plan: {}", req.tier))?;

        let annual = req.billing_cycle.as_deref() == Some("annual");
        let unit_amount = if annual {
            plan.price_annual
        } else {
            plan.price_monthly
        } as i64;
        let interval = if annual {
            CreateCheckoutSessionLineItemsPriceDataRecurringInterval::Year
        } else {
            CreateCheckoutSessionLineItemsPriceDataRecurringInterval::Month
        };

        let product_name = format!("Connector Platform — {} Plan", plan.name);
        let description = format!(
            "{} agents · {} events · {} retention",
            plan.agents, plan.events, plan.retention
        );

        let line_item = CreateCheckoutSessionLineItems {
            quantity: Some(1),
            price_data: Some(CreateCheckoutSessionLineItemsPriceData {
                currency: Currency::USD,
                unit_amount: Some(unit_amount),
                recurring: Some(CreateCheckoutSessionLineItemsPriceDataRecurring {
                    interval,
                    ..Default::default()
                }),
                product_data: Some(CreateCheckoutSessionLineItemsPriceDataProductData {
                    name: product_name,
                    description: Some(description),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("tier".to_string(), plan.id.to_string());
        metadata.insert(
            "billing_cycle".to_string(),
            req.billing_cycle
                .clone()
                .unwrap_or_else(|| "monthly".to_string()),
        );
        if let Some(ref name) = req.customer_name {
            metadata.insert("customer_name".to_string(), name.clone());
        }

        let success_url = self.success_url.as_str();
        let cancel_url = self.cancel_url.as_str();

        let mut params = CreateCheckoutSession::new();
        params.mode = Some(CheckoutSessionMode::Subscription);
        params.success_url = Some(success_url);
        params.cancel_url = Some(cancel_url);
        params.customer_email = req.customer_email.as_deref();
        params.line_items = Some(vec![line_item]);
        params.metadata = Some(metadata);

        let session = CheckoutSession::create(&self.client, params)
            .await
            .map_err(|e| format!("Stripe checkout error: {e}"))?;

        session
            .url
            .ok_or_else(|| "Stripe did not return a session URL".to_string())
    }

    async fn do_portal(&self, customer_id: &str, _return_url: &str) -> Result<String, String> {
        let customer: stripe::CustomerId = customer_id
            .parse()
            .map_err(|_| format!("Invalid customer_id: {}", customer_id))?;
        let params = CreateBillingPortalSession::new(customer);

        let session = BillingPortalSession::create(&self.client, params)
            .await
            .map_err(|e| format!("Stripe portal error: {e}"))?;

        Ok(session.url)
    }
}

impl PaymentProvider for StripeProvider {
    fn create_checkout_url<'a>(
        &'a self,
        req: &'a CheckoutRequest,
    ) -> BoxFut<'a, Result<String, String>> {
        Box::pin(self.do_checkout(req))
    }

    fn create_portal_url<'a>(
        &'a self,
        customer_id: &'a str,
        return_url: &'a str,
    ) -> BoxFut<'a, Result<String, String>> {
        Box::pin(self.do_portal(customer_id, return_url))
    }

    fn verify_webhook(&self, payload: &[u8], sig_header: &str) -> Result<stripe::Event, String> {
        Webhook::construct_event(
            std::str::from_utf8(payload).map_err(|_| "Invalid UTF-8 in webhook body")?,
            sig_header,
            &self.webhook_secret,
        )
        .map_err(|e| format!("Webhook signature invalid: {e}"))
    }
}

// ── NoopProvider — graceful fallback when Stripe is not configured ────────────

pub struct NoopProvider;

impl PaymentProvider for NoopProvider {
    fn create_checkout_url<'a>(
        &'a self,
        _req: &'a CheckoutRequest,
    ) -> BoxFut<'a, Result<String, String>> {
        Box::pin(async {
            Err("Payment not configured — set STRIPE_SECRET_KEY to enable".to_string())
        })
    }

    fn create_portal_url<'a>(
        &'a self,
        _customer_id: &'a str,
        _return_url: &'a str,
    ) -> BoxFut<'a, Result<String, String>> {
        Box::pin(async {
            Err("Payment not configured — set STRIPE_SECRET_KEY to enable".to_string())
        })
    }

    fn verify_webhook(&self, _payload: &[u8], _sig_header: &str) -> Result<stripe::Event, String> {
        Err("Payment not configured".to_string())
    }
}

// ── Provider factory — reads env vars once at startup ─────────────────────────

pub fn build_provider() -> Box<dyn PaymentProvider> {
    match std::env::var("STRIPE_SECRET_KEY") {
        Ok(key) if !key.is_empty() => {
            let webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_default();
            let base_url = std::env::var("CONNECTOR_PUBLIC_URL")
                .unwrap_or_else(|_| "https://portal.connector.dev".to_string());
            tracing::info!("payment: Stripe provider active (async-stripe 0.40)");
            Box::new(StripeProvider::new(key, webhook_secret, base_url))
        }
        _ => {
            tracing::warn!("payment: STRIPE_SECRET_KEY not set — payment endpoints return errors until configured");
            Box::new(NoopProvider)
        }
    }
}

// ── Axum route handlers ───────────────────────────────────────────────────────

pub async fn list_plans(State(_state): State<SharedState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "plans": PLANS,
        "currency": "USD",
        "note": "Prices in cents. Annual = 10× monthly (2 months free).",
    }))
}

pub async fn checkout(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CheckoutRequest>,
) -> Json<serde_json::Value> {
    if find_plan(&req.tier).is_none() {
        return Json(serde_json::json!({
            "error": format!("Unknown plan '{}'. Valid: indie, startup, growth, business, enterprise", req.tier)
        }));
    }

    let _claims = match crate::auth::extract_claims(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };

    match state.payment.create_checkout_url(&req).await {
        Ok(url) => Json(serde_json::json!({
            "url": url,
            "tier": req.tier,
            "billing_cycle": req.billing_cycle.unwrap_or_else(|| "monthly".to_string()),
        })),
        Err(e) => Json(serde_json::json!({"error": e, "status": 500})),
    }
}

pub async fn portal(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<PortalRequest>,
) -> Json<serde_json::Value> {
    let claims = match crate::auth::extract_claims(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };

    let customer_id = req.customer_email.unwrap_or_else(|| claims.email.clone());
    let return_url = req
        .return_url
        .unwrap_or_else(|| "/dashboard/billing".to_string());

    match state
        .payment
        .create_portal_url(&customer_id, &return_url)
        .await
    {
        Ok(url) => Json(serde_json::json!({"url": url})),
        Err(e) => Json(serde_json::json!({"error": e, "status": 500})),
    }
}

pub async fn webhook(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Json<serde_json::Value> {
    let sig = match headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_string(),
        None => {
            return Json(
                serde_json::json!({"error": "Missing Stripe-Signature header", "status": 400}),
            )
        }
    };

    let event = match state.payment.verify_webhook(&body, &sig) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("webhook: signature verification failed: {}", e);
            return Json(serde_json::json!({"error": e, "status": 401}));
        }
    };

    tracing::info!("payment webhook: {:?} id={}", event.type_, event.id);

    match event.type_ {
        // D6: CheckoutSessionCompleted → set tier + activate license
        EventType::CheckoutSessionCompleted => {
            if let EventObject::CheckoutSession(session) = event.data.object {
                let tier = session
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("tier"))
                    .map(|s| s.as_str())
                    .unwrap_or("pro")
                    .to_string();
                let email = session.customer_email.clone().unwrap_or_default();
                let customer_id = session
                    .customer
                    .as_ref()
                    .and_then(|c| match c {
                        stripe::Expandable::Id(id) => Some(id.to_string()),
                        _ => None,
                    })
                    .unwrap_or_default();

                tracing::info!(tier = %tier, customer = %email, "checkout complete — activating tier");

                // Wire: update user tier in UserStore
                let mut user_store = state.user_store.lock().unwrap();
                if let Some(user) = user_store.find_by_email_mut(&email) {
                    user.tier = tier.clone();
                    user.billing_state = "active".to_string();
                    user.stripe_customer_id = Some(customer_id.clone());
                    tracing::info!(email = %email, tier = %tier, "user tier activated");
                } else {
                    tracing::warn!(email = %email, "checkout completed but user not found in store");
                }

                // Record in engine store for audit trail
                let mut es = state.engine_store.lock().unwrap();
                let _ = es.folder_put(
                    "billing_events",
                    &format!("checkout_{}", event.id),
                    &serde_json::json!({
                        "event": "checkout_completed",
                        "tier": tier,
                        "email": email,
                        "customer_id": customer_id,
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                    }),
                );
            }
        }

        // D6: InvoicePaymentFailed → Degraded after 3 attempts, Suspended after 7
        EventType::InvoicePaymentFailed => {
            if let EventObject::Invoice(inv) = event.data.object {
                let email = inv.customer_email.clone().unwrap_or_default();
                let attempt = inv.attempt_count.unwrap_or(0);
                tracing::warn!(email = %email, attempt = attempt, "invoice payment failed");

                let new_state = if attempt > 7 {
                    "suspended"
                } else if attempt > 3 {
                    "degraded"
                } else {
                    "payment_failed"
                };

                let mut user_store = state.user_store.lock().unwrap();
                if let Some(user) = user_store.find_by_email_mut(&email) {
                    user.billing_state = new_state.to_string();
                    tracing::warn!(email = %email, state = new_state, attempt = attempt, "billing state updated");
                }

                let mut es = state.engine_store.lock().unwrap();
                let _ = es.folder_put(
                    "billing_events",
                    &format!("failed_{}", event.id),
                    &serde_json::json!({
                        "event": "payment_failed",
                        "email": email,
                        "attempt": attempt,
                        "billing_state": new_state,
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                    }),
                );
            }
        }

        // D6: CustomerSubscriptionDeleted → downgrade to Community, preserve data
        EventType::CustomerSubscriptionDeleted => {
            if let EventObject::Subscription(sub) = event.data.object {
                let customer_id = match &sub.customer {
                    stripe::Expandable::Id(id) => id.to_string(),
                    stripe::Expandable::Object(c) => c.id.to_string(),
                };
                tracing::info!(subscription = %sub.id, customer = %customer_id, "subscription cancelled — downgrading to Community");

                let mut user_store = state.user_store.lock().unwrap();
                if let Some(user) = user_store.find_by_stripe_customer_id_mut(&customer_id) {
                    user.tier = "community".to_string();
                    user.billing_state = "cancelled".to_string();
                    tracing::info!(email = %user.email, "downgraded to community tier — data preserved");
                }

                let mut es = state.engine_store.lock().unwrap();
                let _ = es.folder_put(
                    "billing_events",
                    &format!("cancelled_{}", event.id),
                    &serde_json::json!({
                        "event": "subscription_cancelled",
                        "customer_id": customer_id,
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                    }),
                );
            }
        }

        // D6: CustomerSubscriptionUpdated → update tier from metadata
        EventType::CustomerSubscriptionUpdated => {
            if let EventObject::Subscription(sub) = event.data.object {
                let customer_id = match &sub.customer {
                    stripe::Expandable::Id(id) => id.to_string(),
                    stripe::Expandable::Object(c) => c.id.to_string(),
                };
                let new_tier = sub.metadata.get("tier").cloned().unwrap_or_default();
                tracing::info!(subscription = %sub.id, tier = %new_tier, "subscription updated");

                if !new_tier.is_empty() {
                    let mut user_store = state.user_store.lock().unwrap();
                    if let Some(user) = user_store.find_by_stripe_customer_id_mut(&customer_id) {
                        user.tier = new_tier.clone();
                        user.billing_state = "active".to_string();
                    }
                }
            }
        }

        other => {
            tracing::debug!("unhandled webhook event: {:?}", other);
        }
    }

    Json(serde_json::json!({"received": true}))
}

pub async fn payment_status(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let claims = match crate::auth::extract_claims(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };

    let user_store = state.user_store.lock().unwrap();
    match user_store.get_user(&claims.sub) {
        Some(user) => Json(serde_json::json!({
            "user_id": user.user_id,
            "email": user.email,
            "tier": "Community",
            "billing_state": "Community",
            "provider": if std::env::var("STRIPE_SECRET_KEY").is_ok() { "stripe" } else { "none" },
            "payment_configured": std::env::var("STRIPE_SECRET_KEY").is_ok(),
        })),
        None => Json(serde_json::json!({"error": "User not found", "status": 404})),
    }
}
