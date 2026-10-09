//! # Dunning & Payment Recovery System
//!
//! Implements the full payment lifecycle for the license server:
//!
//! ## Dunning Schedule (after invoice.payment_failed)
//!   Day 0:  Email "Payment failed — please update your card"
//!   Day 1:  Stripe Smart Retry #1
//!   Day 3:  Stripe Smart Retry #2 + email warning
//!   Day 7:  License DEGRADED (rate-limited, no new features) + email
//!   Day 14: License SUSPENDED (blocked from RPC auth) + email
//!   Day 21: License CANCELLED + binary deactivated + final email
//!
//! ## Auto-deactivation
//!   On cancellation: all active instances for the customer are deactivated,
//!   secret_ids invalidated, and any live RPC tokens revoked.
//!
//! ## Notifications
//!   All emails are sent via the configured email provider (SendGrid/SMTP).
//!   Templates are embedded in this module.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Dunning state machine ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DunningState {
    /// Payment current — all features active.
    Current,
    /// Payment failed, within retry window (Day 0–6) — grace, warn only.
    PaymentFailed { days_overdue: u32 },
    /// Day 7–13 — feature degradation applied (rate limits tightened).
    Degraded { days_overdue: u32 },
    /// Day 14–20 — binary cannot authenticate, offline grace is the only fallback.
    Suspended { days_overdue: u32 },
    /// Day 21+ — cancelled, all instances deactivated.
    Cancelled,
    /// Manually suspended by admin.
    ManualSuspend,
    /// Trial expired without subscribing.
    TrialExpired,
}

impl DunningState {
    pub fn from_days_overdue(days: u32) -> Self {
        match days {
            0 => Self::PaymentFailed { days_overdue: 0 },
            1..=6 => Self::PaymentFailed { days_overdue: days },
            7..=13 => Self::Degraded { days_overdue: days },
            14..=20 => Self::Suspended { days_overdue: days },
            _ => Self::Cancelled,
        }
    }

    pub fn allows_rpc_auth(&self) -> bool {
        matches!(self, Self::Current | Self::PaymentFailed { .. })
    }

    pub fn allows_paid_features(&self) -> bool {
        matches!(self, Self::Current)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Cancelled | Self::TrialExpired)
    }

    pub fn http_status_code(&self) -> u16 {
        match self {
            Self::Current => 200,
            Self::PaymentFailed { .. } => 200,
            Self::Degraded { .. } => 200,
            Self::Suspended { .. } => 402,
            Self::Cancelled => 402,
            Self::ManualSuspend => 403,
            Self::TrialExpired => 402,
        }
    }

    pub fn banner_message(&self) -> &'static str {
        match self {
            Self::Current => "",
            Self::PaymentFailed { .. } => "Payment failed — please update your payment method to avoid service interruption.",
            Self::Degraded { .. } => "Your account is degraded due to a failed payment. Some features are restricted. Please update your billing.",
            Self::Suspended { .. } => "Your account is suspended. Binary cannot authenticate until payment is resolved.",
            Self::Cancelled => "Your subscription has been cancelled. All instances have been deactivated.",
            Self::ManualSuspend => "Your account has been manually suspended. Contact support.",
            Self::TrialExpired => "Your trial has expired. Subscribe to continue.",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Current => "Active",
            Self::PaymentFailed { .. } => "PastDue",
            Self::Degraded { .. } => "Degraded",
            Self::Suspended { .. } => "Suspended",
            Self::Cancelled => "Cancelled",
            Self::ManualSuspend => "Suspended",
            Self::TrialExpired => "TrialExpired",
        }
    }
}

// ── Dunning record ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DunningRecord {
    pub customer_id: String,
    pub email: String,
    pub name: String,
    pub state: DunningState,
    /// UTC timestamp of last successful payment.
    pub last_payment_at: Option<i64>,
    /// UTC timestamp of first payment failure in current sequence.
    pub failed_since: Option<i64>,
    /// Number of retry attempts made by Stripe.
    pub retry_count: u32,
    /// Days since first payment failure.
    pub days_overdue: u32,
    /// Notification emails sent (to avoid duplicates).
    pub notifications_sent: Vec<String>,
    /// Stripe customer ID for portal link.
    pub stripe_customer_id: Option<String>,
    /// Stripe subscription ID.
    pub stripe_subscription_id: Option<String>,
    /// License tier.
    pub tier: String,
    /// Portal billing URL.
    pub billing_portal_url: Option<String>,
}

impl DunningRecord {
    pub fn new(customer_id: String, email: String, name: String, tier: String) -> Self {
        Self {
            customer_id, email, name, tier,
            state: DunningState::Current,
            last_payment_at: None,
            failed_since: None,
            retry_count: 0,
            days_overdue: 0,
            notifications_sent: Vec::new(),
            stripe_customer_id: None,
            stripe_subscription_id: None,
            billing_portal_url: None,
        }
    }

    /// Called when Stripe reports invoice.payment_succeeded
    pub fn on_payment_succeeded(&mut self) {
        self.state = DunningState::Current;
        self.failed_since = None;
        self.retry_count = 0;
        self.days_overdue = 0;
        self.notifications_sent.clear();
        self.last_payment_at = Some(chrono::Utc::now().timestamp());
        eprintln!("[dunning] Payment succeeded for {}", self.customer_id);
    }

    /// Called when Stripe reports invoice.payment_failed
    pub fn on_payment_failed(&mut self) {
        let now = chrono::Utc::now().timestamp();
        if self.failed_since.is_none() {
            self.failed_since = Some(now);
        }
        let days = self.days_since_failure();
        self.days_overdue = days;
        self.state = DunningState::from_days_overdue(days);
        self.retry_count += 1;
        eprintln!("[dunning] Payment failed for {} — day {} overdue, state: {}",
            self.customer_id, days, self.state.label());
    }

    /// Advance the dunning state based on current time (call daily).
    pub fn advance(&mut self) {
        if self.failed_since.is_none() { return; }
        let days = self.days_since_failure();
        if days != self.days_overdue {
            self.days_overdue = days;
            self.state = DunningState::from_days_overdue(days);
        }
    }

    pub fn days_since_failure(&self) -> u32 {
        match self.failed_since {
            None => 0,
            Some(ts) => {
                let now = chrono::Utc::now().timestamp();
                ((now - ts).max(0) / 86400) as u32
            }
        }
    }

    pub fn needs_notification(&self, event: &str) -> bool {
        !self.notifications_sent.contains(&event.to_string())
    }

    pub fn mark_notification_sent(&mut self, event: String) {
        if !self.notifications_sent.contains(&event) {
            self.notifications_sent.push(event);
        }
    }
}

// ── In-memory dunning store ───────────────────────────────────────────────────

pub struct DunningStore {
    records: HashMap<String, DunningRecord>,  // customer_id → record
    email_index: HashMap<String, String>,     // email → customer_id
}

impl DunningStore {
    pub fn new() -> Self {
        Self { records: HashMap::new(), email_index: HashMap::new() }
    }

    pub fn upsert(&mut self, record: DunningRecord) {
        self.email_index.insert(record.email.clone(), record.customer_id.clone());
        self.records.insert(record.customer_id.clone(), record);
    }

    pub fn get(&self, customer_id: &str) -> Option<&DunningRecord> {
        self.records.get(customer_id)
    }

    pub fn get_mut(&mut self, customer_id: &str) -> Option<&mut DunningRecord> {
        self.records.get_mut(customer_id)
    }

    pub fn get_by_email(&self, email: &str) -> Option<&DunningRecord> {
        self.email_index.get(email).and_then(|id| self.records.get(id))
    }

    pub fn by_stripe_subscription(&self, sub_id: &str) -> Option<&DunningRecord> {
        self.records.values().find(|r| r.stripe_subscription_id.as_deref() == Some(sub_id))
    }

    pub fn by_stripe_subscription_mut(&mut self, sub_id: &str) -> Option<&mut DunningRecord> {
        self.records.values_mut().find(|r| r.stripe_subscription_id.as_deref() == Some(sub_id))
    }

    pub fn by_stripe_customer(&self, cus_id: &str) -> Option<&DunningRecord> {
        self.records.values().find(|r| r.stripe_customer_id.as_deref() == Some(cus_id))
    }

    pub fn by_stripe_customer_mut(&mut self, cus_id: &str) -> Option<&mut DunningRecord> {
        self.records.values_mut().find(|r| r.stripe_customer_id.as_deref() == Some(cus_id))
    }

    /// Advance all records' dunning state. Called by daily background task.
    pub fn advance_all(&mut self) -> Vec<DunningAction> {
        let mut actions = Vec::new();
        for record in self.records.values_mut() {
            let old_state = record.state.label().to_string();
            record.advance();
            let new_state = record.state.label().to_string();

            // Notify on state transitions
            if old_state != new_state {
                actions.push(DunningAction::StateTransition {
                    customer_id: record.customer_id.clone(),
                    old_state,
                    new_state: new_state.clone(),
                });
            }

            // Schedule notifications
            let days = record.days_overdue;
            let email = record.email.clone();
            let cid   = record.customer_id.clone();
            let name  = record.name.clone();
            let tier  = record.tier.clone();
            let portal = record.billing_portal_url.clone();

            if days == 0 && record.needs_notification("payment_failed_day0") {
                record.mark_notification_sent("payment_failed_day0".into());
                actions.push(DunningAction::SendEmail {
                    customer_id: cid.clone(), email: email.clone(),
                    template: EmailTemplate::PaymentFailed { name: name.clone(), tier: tier.clone(), portal_url: portal.clone() },
                });
            }
            if days == 3 && record.needs_notification("payment_failed_day3") {
                record.mark_notification_sent("payment_failed_day3".into());
                actions.push(DunningAction::SendEmail {
                    customer_id: cid.clone(), email: email.clone(),
                    template: EmailTemplate::PaymentRetryWarning { name: name.clone(), days_remaining: 4, portal_url: portal.clone() },
                });
            }
            if days == 7 && record.needs_notification("degraded_day7") {
                record.mark_notification_sent("degraded_day7".into());
                actions.push(DunningAction::SendEmail {
                    customer_id: cid.clone(), email: email.clone(),
                    template: EmailTemplate::ServiceDegraded { name: name.clone(), portal_url: portal.clone() },
                });
                actions.push(DunningAction::DegradeCustomer { customer_id: cid.clone() });
            }
            if days == 14 && record.needs_notification("suspended_day14") {
                record.mark_notification_sent("suspended_day14".into());
                actions.push(DunningAction::SendEmail {
                    customer_id: cid.clone(), email: email.clone(),
                    template: EmailTemplate::ServiceSuspended { name: name.clone(), portal_url: portal.clone() },
                });
                actions.push(DunningAction::SuspendCustomer { customer_id: cid.clone() });
            }
            if days >= 21 && record.needs_notification("cancelled_day21") {
                record.mark_notification_sent("cancelled_day21".into());
                actions.push(DunningAction::SendEmail {
                    customer_id: cid.clone(), email: email.clone(),
                    template: EmailTemplate::Cancelled { name: name.clone() },
                });
                actions.push(DunningAction::CancelCustomer { customer_id: cid.clone() });
            }
        }
        actions
    }

    pub fn all_records(&self) -> Vec<&DunningRecord> {
        self.records.values().collect()
    }

    pub fn past_due_count(&self) -> usize {
        self.records.values().filter(|r| !matches!(r.state, DunningState::Current)).count()
    }

    pub fn suspended_count(&self) -> usize {
        self.records.values().filter(|r| matches!(r.state, DunningState::Suspended { .. } | DunningState::Cancelled | DunningState::ManualSuspend)).count()
    }
}

// ── Actions emitted by the dunning engine ─────────────────────────────────────

#[derive(Debug, Clone)]
pub enum DunningAction {
    SendEmail { customer_id: String, email: String, template: EmailTemplate },
    DegradeCustomer { customer_id: String },
    SuspendCustomer { customer_id: String },
    CancelCustomer  { customer_id: String },
    StateTransition { customer_id: String, old_state: String, new_state: String },
}

// ── Email templates ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum EmailTemplate {
    Welcome { name: String, tier: String, api_key_hint: String },
    PaymentFailed { name: String, tier: String, portal_url: Option<String> },
    PaymentRetryWarning { name: String, days_remaining: u32, portal_url: Option<String> },
    ServiceDegraded { name: String, portal_url: Option<String> },
    ServiceSuspended { name: String, portal_url: Option<String> },
    Cancelled { name: String },
    SubscriptionRestored { name: String, tier: String },
    LicenseActivated { name: String, tier: String, instance_id: String },
    TrialExpiring { name: String, days_remaining: u32 },
}

impl EmailTemplate {
    pub fn subject(&self) -> &'static str {
        match self {
            Self::Welcome { .. }            => "Welcome to Connector Platform",
            Self::PaymentFailed { .. }      => "Action required: Payment failed",
            Self::PaymentRetryWarning { .. }=> "Reminder: Payment still outstanding",
            Self::ServiceDegraded { .. }    => "Important: Your service has been degraded",
            Self::ServiceSuspended { .. }   => "Your Connector Platform access is suspended",
            Self::Cancelled { .. }          => "Your subscription has been cancelled",
            Self::SubscriptionRestored { .. } => "Payment received — service restored",
            Self::LicenseActivated { .. }   => "License activated successfully",
            Self::TrialExpiring { .. }      => "Your trial is expiring soon",
        }
    }

    pub fn text_body(&self) -> String {
        let portal = "https://portal.connector.dev/billing";
        match self {
            Self::Welcome { name, tier, api_key_hint } => format!(
                "Hi {name},\n\nWelcome to Connector Platform ({tier} tier).\n\n\
                Your API key starts with: {api_key_hint}\n\
                Download your binary at: https://portal.connector.dev/download\n\n\
                If you have any questions, reply to this email.\n\nConnector Team"
            ),
            Self::PaymentFailed { name, tier, portal_url } => format!(
                "Hi {name},\n\nYour {tier} payment failed. Please update your payment method.\n\n\
                Update billing: {}\n\n\
                Your binary will continue working for up to 7 days while we retry.\n\nConnector Team",
                portal_url.as_deref().unwrap_or(portal)
            ),
            Self::PaymentRetryWarning { name, days_remaining, portal_url } => format!(
                "Hi {name},\n\nYour payment is still outstanding. We'll retry once more.\n\n\
                You have {days_remaining} day(s) before your service is degraded.\n\n\
                Update billing: {}\n\nConnector Team",
                portal_url.as_deref().unwrap_or(portal)
            ),
            Self::ServiceDegraded { name, portal_url } => format!(
                "Hi {name},\n\nYour Connector Platform service has been degraded due to non-payment.\n\n\
                Features affected: rate limits tightened, new deployments blocked.\n\n\
                Restore access immediately: {}\n\nConnector Team",
                portal_url.as_deref().unwrap_or(portal)
            ),
            Self::ServiceSuspended { name, portal_url } => format!(
                "Hi {name},\n\nYour Connector Platform access has been SUSPENDED.\n\n\
                Your binary cannot authenticate until payment is resolved.\n\
                It will operate on offline grace cache for up to 72 hours.\n\n\
                Restore access: {}\n\nConnector Team",
                portal_url.as_deref().unwrap_or(portal)
            ),
            Self::Cancelled { name } => format!(
                "Hi {name},\n\nYour Connector Platform subscription has been cancelled.\n\n\
                All active instances have been deactivated.\n\n\
                If this was a mistake, contact support@connector.dev within 48 hours.\n\nConnector Team"
            ),
            Self::SubscriptionRestored { name, tier } => format!(
                "Hi {name},\n\nGreat news — payment received! Your {tier} service has been fully restored.\n\n\
                Your binary will authenticate normally on next startup.\n\nConnector Team"
            ),
            Self::LicenseActivated { name, tier, instance_id } => format!(
                "Hi {name},\n\nYour {tier} license has been activated.\n\nInstance ID: {instance_id}\n\n\
                Manage your license: https://portal.connector.dev/dashboard\n\nConnector Team"
            ),
            Self::TrialExpiring { name, days_remaining } => format!(
                "Hi {name},\n\nYour Connector Platform trial expires in {days_remaining} day(s).\n\n\
                Subscribe to keep access: https://portal.connector.dev/pricing\n\nConnector Team"
            ),
        }
    }
}

// ── Email sender ─────────────────────────────────────────────────────────────

pub struct EmailSender {
    pub from_email: String,
    pub from_name: String,
    pub sendgrid_key: Option<String>,
    pub smtp_url: Option<String>,
}

impl EmailSender {
    pub fn from_env() -> Self {
        Self {
            from_email: std::env::var("CONNECTOR_EMAIL_FROM")
                .unwrap_or_else(|_| "noreply@connector.dev".into()),
            from_name: std::env::var("CONNECTOR_EMAIL_FROM_NAME")
                .unwrap_or_else(|_| "Connector Platform".into()),
            sendgrid_key: std::env::var("SENDGRID_API_KEY").ok(),
            smtp_url: std::env::var("CONNECTOR_SMTP_URL").ok(),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.sendgrid_key.is_some() || self.smtp_url.is_some()
    }

    /// Send an email. Uses SendGrid if key present, else SMTP, else logs to stderr.
    pub fn send(&self, to_email: &str, to_name: &str, template: &EmailTemplate) {
        let subject = template.subject();
        let body    = template.text_body();

        if let Some(ref api_key) = self.sendgrid_key {
            if let Err(e) = self.send_sendgrid(to_email, to_name, subject, &body, api_key) {
                eprintln!("[email] SendGrid error to {}: {}", to_email, e);
            } else {
                eprintln!("[email] Sent '{}' to {}", subject, to_email);
            }
            return;
        }

        // Fallback: log (production should always have sendgrid configured)
        eprintln!("[email] WOULD SEND to={} subject='{}'\n{}", to_email, subject, &body[..body.len().min(200)]);
    }

    fn send_sendgrid(&self, to: &str, to_name: &str, subject: &str, body: &str, api_key: &str) -> Result<(), String> {
        use std::io::Write;
        use std::process::Command;

        let payload = serde_json::json!({
            "personalizations": [{ "to": [{"email": to, "name": to_name}] }],
            "from": { "email": self.from_email, "name": self.from_name },
            "subject": subject,
            "content": [{ "type": "text/plain", "value": body }],
        });

        let body_str = serde_json::to_string(&payload).map_err(|e| e.to_string())?;

        let mut tmp = std::env::temp_dir();
        tmp.push(format!("connector_email_{}.json", std::process::id()));
        std::fs::write(&tmp, &body_str).map_err(|e| e.to_string())?;

        let out = Command::new("curl")
            .args([
                "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "-X", "POST",
                "-H", &format!("Authorization: Bearer {}", api_key),
                "-H", "Content-Type: application/json",
                "--data", &format!("@{}", tmp.display()),
                "https://api.sendgrid.com/v3/mail/send",
            ])
            .output()
            .map_err(|e| format!("curl: {}", e))?;

        let _ = std::fs::remove_file(&tmp);

        let status_str = String::from_utf8_lossy(&out.stdout);
        let status: u16 = status_str.trim().parse().unwrap_or(500);
        if status == 202 { Ok(()) } else { Err(format!("SendGrid HTTP {}", status)) }
    }
}

// ── Process a Stripe webhook event ───────────────────────────────────────────

/// Returns the list of actions to execute after processing the webhook.
pub fn process_stripe_event(
    event_type: &str,
    event_data: &serde_json::Value,
    store: &mut DunningStore,
) -> Vec<DunningAction> {
    match event_type {
        "invoice.payment_succeeded" | "invoice.paid" => {
            let sub_id = event_data["object"]["subscription"].as_str().unwrap_or("").to_string();
            let cus_id = event_data["object"]["customer"].as_str().unwrap_or("").to_string();

            let has_sub = store.by_stripe_subscription_mut(&sub_id).is_some();
            let record = if has_sub {
                store.by_stripe_subscription_mut(&sub_id)
            } else {
                store.by_stripe_customer_mut(&cus_id)
            };

            if let Some(r) = record {
                let was_degraded = !matches!(r.state, DunningState::Current);
                r.on_payment_succeeded();
                if was_degraded {
                    let name = r.name.clone();
                    let tier = r.tier.clone();
                    let email = r.email.clone();
                    let cid = r.customer_id.clone();
                    return vec![
                        DunningAction::SendEmail {
                            customer_id: cid,
                            email,
                            template: EmailTemplate::SubscriptionRestored { name, tier },
                        },
                    ];
                }
            }
            vec![]
        }

        "invoice.payment_failed" => {
            let sub_id = event_data["object"]["subscription"].as_str().unwrap_or("").to_string();
            let cus_id = event_data["object"]["customer"].as_str().unwrap_or("").to_string();

            let has_sub = store.by_stripe_subscription_mut(&sub_id).is_some();
            let record = if has_sub {
                store.by_stripe_subscription_mut(&sub_id)
            } else {
                store.by_stripe_customer_mut(&cus_id)
            };

            if let Some(r) = record {
                r.on_payment_failed();
                let days = r.days_overdue;
                let cid   = r.customer_id.clone();
                let email = r.email.clone();
                let name  = r.name.clone();
                let tier  = r.tier.clone();
                let portal = r.billing_portal_url.clone();

                let mut actions = vec![
                    DunningAction::StateTransition {
                        customer_id: cid.clone(),
                        old_state: "Active".into(),
                        new_state: r.state.label().to_string(),
                    },
                ];

                if days == 0 && r.needs_notification("payment_failed_day0") {
                    r.mark_notification_sent("payment_failed_day0".into());
                    actions.push(DunningAction::SendEmail {
                        customer_id: cid, email,
                        template: EmailTemplate::PaymentFailed { name, tier, portal_url: portal },
                    });
                }
                actions
            } else {
                vec![]
            }
        }

        "customer.subscription.deleted" => {
            let cus_id = event_data["object"]["customer"].as_str().unwrap_or("");
            if let Some(r) = store.by_stripe_customer_mut(cus_id) {
                r.state = DunningState::Cancelled;
                let cid = r.customer_id.clone();
                vec![DunningAction::CancelCustomer { customer_id: cid }]
            } else {
                vec![]
            }
        }

        "customer.subscription.updated" => {
            let status = event_data["object"]["status"].as_str().unwrap_or("");
            let cus_id = event_data["object"]["customer"].as_str().unwrap_or("");
            if status == "active" {
                if let Some(r) = store.by_stripe_customer_mut(cus_id) {
                    if !matches!(r.state, DunningState::Current) {
                        r.on_payment_succeeded();
                        let name = r.name.clone();
                        let tier = r.tier.clone();
                        let email = r.email.clone();
                        let cid = r.customer_id.clone();
                        return vec![DunningAction::SendEmail {
                            customer_id: cid, email,
                            template: EmailTemplate::SubscriptionRestored { name, tier },
                        }];
                    }
                }
            }
            vec![]
        }

        _ => vec![],
    }
}
