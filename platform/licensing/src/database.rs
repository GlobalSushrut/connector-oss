use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Server-side persistent database for payment surveillance.
/// Tracks every deployed instance, usage, payment status, and compliance.
/// In production this would be backed by SQLite/Postgres — here it's in-memory
/// with serialization support for disk persistence.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerRecord {
    pub customer_id: String,
    pub email: String,
    pub name: String,
    pub stripe_customer_id: Option<String>,
    pub created_at: String,
    pub payment_status: PaymentStatus,
    pub last_payment_at: Option<String>,
    pub total_paid_cents: u64,
    pub key_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PaymentStatus {
    Active,
    PastDue,
    Suspended,
    Cancelled,
    Trial,
    Delinquent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceRecord {
    pub instance_id: String,
    pub key_id: String,
    pub customer_id: String,
    pub machine_id: String,
    pub hostname: String,
    pub binary_hash: String,
    pub binary_id: String,
    pub license_address: String,
    pub tier: String,
    pub permissions: Vec<String>,
    pub activated_at: String,
    pub last_heartbeat: Option<String>,
    pub last_usage_report: Option<String>,
    pub status: InstanceStatus,
    pub agents_last: u32,
    pub packets_last: u32,
    pub trust_score_last: u32,
    pub total_tokens_lifetime: u64,
    pub total_cost_lifetime: f64,
    pub warnings_issued: u32,
    pub grace_period_ends: Option<String>,
    pub kill_issued: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InstanceStatus {
    Active,
    Degraded,       // past due — limited features
    GracePeriod,    // payment failed — 7 day grace
    Suspended,      // kill signal sent
    Deactivated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurveillanceEvent {
    pub event_id: String,
    pub instance_id: String,
    pub event_type: SurveillanceEventType,
    pub timestamp: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SurveillanceEventType {
    Heartbeat,
    UsageReport,
    PaymentReceived,
    PaymentFailed,
    GracePeriodStart,
    GracePeriodEnd,
    DegradeSent,
    KillSent,
    Reactivated,
    TamperDetected,
    BinaryMismatch,
    OverLimitWarning,
    LicenseExpired,
}

/// Central surveillance database
pub struct SurveillanceDb {
    pub customers: HashMap<String, CustomerRecord>,
    pub instances: HashMap<String, InstanceRecord>,
    pub events: Vec<SurveillanceEvent>,
    pub email_to_customer: HashMap<String, String>,
    pub key_to_customer: HashMap<String, String>,
    pub instance_to_key: HashMap<String, String>,
    pub blocked_binary_hashes: Vec<String>,
}

impl SurveillanceDb {
    pub fn new() -> Self {
        Self {
            customers: HashMap::new(),
            instances: HashMap::new(),
            events: Vec::new(),
            email_to_customer: HashMap::new(),
            key_to_customer: HashMap::new(),
            instance_to_key: HashMap::new(),
            blocked_binary_hashes: Vec::new(),
        }
    }

    pub fn upsert_customer(&mut self, record: CustomerRecord) {
        self.email_to_customer.insert(record.email.clone(), record.customer_id.clone());
        for kid in &record.key_ids {
            self.key_to_customer.insert(kid.clone(), record.customer_id.clone());
        }
        self.customers.insert(record.customer_id.clone(), record);
    }

    pub fn upsert_instance(&mut self, record: InstanceRecord) {
        self.instance_to_key.insert(record.instance_id.clone(), record.key_id.clone());
        self.instances.insert(record.instance_id.clone(), record);
    }

    pub fn log_event(&mut self, event: SurveillanceEvent) {
        self.events.push(event);
    }

    pub fn get_customer_by_email(&self, email: &str) -> Option<&CustomerRecord> {
        self.email_to_customer.get(email).and_then(|id| self.customers.get(id))
    }

    pub fn get_customer_by_key(&self, key_id: &str) -> Option<&CustomerRecord> {
        self.key_to_customer.get(key_id).and_then(|id| self.customers.get(id))
    }

    pub fn get_instance(&self, instance_id: &str) -> Option<&InstanceRecord> {
        self.instances.get(instance_id)
    }

    pub fn get_instance_mut(&mut self, instance_id: &str) -> Option<&mut InstanceRecord> {
        self.instances.get_mut(instance_id)
    }

    pub fn instances_for_customer(&self, customer_id: &str) -> Vec<&InstanceRecord> {
        self.instances.values()
            .filter(|i| i.customer_id == customer_id)
            .collect()
    }

    pub fn active_instances(&self) -> Vec<&InstanceRecord> {
        self.instances.values()
            .filter(|i| i.status == InstanceStatus::Active || i.status == InstanceStatus::Degraded)
            .collect()
    }

    pub fn stale_instances(&self, stale_secs: i64) -> Vec<&InstanceRecord> {
        let now = chrono::Utc::now().timestamp();
        self.instances.values()
            .filter(|i| {
                if let Some(ref hb) = i.last_heartbeat {
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(hb) {
                        return now - dt.timestamp() > stale_secs;
                    }
                }
                true
            })
            .filter(|i| i.status == InstanceStatus::Active)
            .collect()
    }

    pub fn delinquent_customers(&self) -> Vec<&CustomerRecord> {
        self.customers.values()
            .filter(|c| c.payment_status == PaymentStatus::PastDue
                     || c.payment_status == PaymentStatus::Delinquent
                     || c.payment_status == PaymentStatus::Suspended)
            .collect()
    }

    pub fn is_binary_blocked(&self, hash: &str) -> bool {
        self.blocked_binary_hashes.contains(&hash.to_string())
    }

    pub fn total_mrr(&self) -> u64 {
        self.customers.values()
            .filter(|c| c.payment_status == PaymentStatus::Active)
            .filter_map(|c| {
                // Sum tier prices for active instances
                let customer_instances = self.instances_for_customer(&c.customer_id);
                Some(customer_instances.iter()
                    .filter(|i| i.status == InstanceStatus::Active)
                    .map(|i| tier_price_cents(&i.tier))
                    .sum::<u64>())
            })
            .sum()
    }

    pub fn is_payment_active(&self, key_id: &str) -> bool {
        self.customers.values().any(|c| {
            c.key_ids.contains(&key_id.to_string())
                && (c.payment_status == PaymentStatus::Active
                    || c.payment_status == PaymentStatus::Trial)
        })
    }

    pub fn total_customers(&self) -> usize { self.customers.len() }
    pub fn total_instances(&self) -> usize { self.instances.len() }
    pub fn total_events(&self) -> usize { self.events.len() }
}

fn tier_price_cents(tier: &str) -> u64 {
    match tier.to_lowercase().as_str() {
        "indie" => 15_000,
        "startup" => 25_000,
        "growth" => 50_000,
        "business" => 100_000,
        "scale" => 200_000,
        "enterprise" => 300_000,
        "core" => 400_000,
        "sovereign" => 500_000,
        _ => 0,
    }
}
