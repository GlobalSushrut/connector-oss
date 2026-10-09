use std::collections::HashMap;
use crate::types::*;

pub struct LicenseStore {
    pub keys: HashMap<String, LicenseKey>,
    pub activations: HashMap<String, Activation>,
    pub usage: Vec<UsageRecord>,
    pub revocation_log: Vec<serde_json::Value>,
}

impl LicenseStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            activations: HashMap::new(),
            usage: Vec::new(),
            revocation_log: Vec::new(),
        }
    }

    pub fn insert_key(&mut self, key: LicenseKey) {
        self.keys.insert(key.key_id.clone(), key);
    }

    pub fn get_key(&self, key_id: &str) -> Option<&LicenseKey> {
        self.keys.get(key_id)
    }

    pub fn get_key_mut(&mut self, key_id: &str) -> Option<&mut LicenseKey> {
        self.keys.get_mut(key_id)
    }

    pub fn find_by_secret(&self, secret: &str) -> Option<&LicenseKey> {
        self.keys.values().find(|k| k.key_secret == secret)
    }

    pub fn find_by_secret_mut(&mut self, secret: &str) -> Option<&mut LicenseKey> {
        self.keys.values_mut().find(|k| k.key_secret == secret)
    }

    pub fn insert_activation(&mut self, activation: Activation) {
        self.activations.insert(activation.instance_id.clone(), activation);
    }

    pub fn get_activation(&self, instance_id: &str) -> Option<&Activation> {
        self.activations.get(instance_id)
    }

    pub fn get_activation_mut(&mut self, instance_id: &str) -> Option<&mut Activation> {
        self.activations.get_mut(instance_id)
    }

    pub fn record_usage(&mut self, record: UsageRecord) {
        self.usage.push(record);
    }

    pub fn usage_for_instance(&self, instance_id: &str) -> Vec<&UsageRecord> {
        self.usage.iter().filter(|u| u.instance_id == instance_id).collect()
    }

    pub fn get_key_by_id(&self, key_id: &str) -> Option<&LicenseKey> {
        self.keys.get(key_id)
    }

    pub fn total_keys(&self) -> usize { self.keys.len() }
    pub fn active_keys(&self) -> usize { self.keys.values().filter(|k| !k.revoked).count() }
    pub fn total_activations(&self) -> usize { self.activations.len() }
    pub fn active_activations(&self) -> usize {
        self.activations.values().filter(|a| a.deactivated_at.is_none()).count()
    }

    pub fn total_mrr_cents(&self) -> u64 {
        self.keys.values()
            .filter(|k| !k.revoked && !k.active_instances.is_empty())
            .map(|k| k.tier.price_cents() as u64)
            .sum()
    }
}
