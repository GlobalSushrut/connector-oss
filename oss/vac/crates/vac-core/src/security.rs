//! Security Module — Capability Delegation, Sandbox, MAC, Secure Boot
//!
//! Design sources: Linux capabilities, SELinux, UEFI Secure Boot, UCAN

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::process::Pid;

// === Part 1: Capability Delegation ===

pub type CapabilityId = String;
static CAP_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn generate_cap_id() -> CapabilityId {
    format!("cap:{:016x}", CAP_ID_COUNTER.fetch_add(1, Ordering::SeqCst))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityType {
    MemRead, MemWrite, MemDelete, SessionCreate, SessionManage,
    PortCreate, PortSend, PortReceive, ToolInvoke, ToolRegister,
    AgentSpawn, AgentTerminate, KnowledgeAccess, KnowledgeModify,
    SysAdmin, AuditAccess, NetAccess, RawIo, SetRlimit,
    SetSecurityContext, CapDelegate, CapAll,
}

impl CapabilityType {
    pub fn implies(&self, other: &CapabilityType) -> bool {
        self == other || matches!(self, CapabilityType::CapAll)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: CapabilityId,
    pub cap_type: CapabilityType,
    pub owner: Pid,
    pub issuer: Pid,
    pub delegation_chain: Vec<Pid>,
    pub depth: u32,
    pub max_depth: u32,
    pub delegatable: bool,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub revoked: bool,
    pub parent_id: Option<CapabilityId>,
    pub child_ids: Vec<CapabilityId>,
}

impl Capability {
    pub fn root(cap_type: CapabilityType, owner: Pid) -> Self {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_millis() as i64;
        Self {
            id: generate_cap_id(), cap_type, owner: owner.clone(),
            issuer: "system".into(), delegation_chain: vec![owner],
            depth: 0, max_depth: 3, delegatable: true, expires_at: None,
            created_at: now, revoked: false, parent_id: None, child_ids: vec![],
        }
    }

    pub fn delegate(&mut self, to: Pid) -> Result<Capability, String> {
        if !self.delegatable || self.revoked || self.depth >= self.max_depth {
            return Err("Cannot delegate".into());
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_millis() as i64;
        let mut chain = self.delegation_chain.clone();
        chain.push(to.clone());
        let child = Capability {
            id: generate_cap_id(), cap_type: self.cap_type, owner: to,
            issuer: self.owner.clone(), delegation_chain: chain,
            depth: self.depth + 1, max_depth: self.max_depth,
            delegatable: self.depth + 1 < self.max_depth,
            expires_at: self.expires_at, created_at: now, revoked: false,
            parent_id: Some(self.id.clone()), child_ids: vec![],
        };
        self.child_ids.push(child.id.clone());
        Ok(child)
    }

    pub fn revoke(&mut self) { self.revoked = true; }
    pub fn is_valid(&self) -> bool { !self.revoked }
}

#[derive(Debug, Default)]
pub struct CapabilityStore {
    capabilities: HashMap<CapabilityId, Capability>,
    by_owner: HashMap<Pid, Vec<CapabilityId>>,
}

impl CapabilityStore {
    pub fn new() -> Self { Self::default() }

    pub fn grant_root(&mut self, cap_type: CapabilityType, owner: Pid) -> CapabilityId {
        let cap = Capability::root(cap_type, owner.clone());
        let id = cap.id.clone();
        self.by_owner.entry(owner).or_default().push(id.clone());
        self.capabilities.insert(id.clone(), cap);
        id
    }

    pub fn delegate(&mut self, cap_id: &str, to: Pid) -> Result<CapabilityId, String> {
        let parent = self.capabilities.get_mut(cap_id).ok_or("Not found")?;
        let child = parent.delegate(to.clone())?;
        let child_id = child.id.clone();
        self.by_owner.entry(to).or_default().push(child_id.clone());
        self.capabilities.insert(child_id.clone(), child);
        Ok(child_id)
    }

    pub fn revoke(&mut self, cap_id: &str) {
        if let Some(cap) = self.capabilities.get_mut(cap_id) {
            cap.revoke();
            for child_id in cap.child_ids.clone() {
                self.revoke(&child_id);
            }
        }
    }

    pub fn has_capability(&self, owner: &str, cap_type: CapabilityType) -> bool {
        self.by_owner.get(owner).map(|ids| {
            ids.iter().any(|id| self.capabilities.get(id)
                .map(|c| c.is_valid() && c.cap_type.implies(&cap_type)).unwrap_or(false))
        }).unwrap_or(false)
    }
}

// === Part 2: Sandbox Enforcement ===

/// Sandbox operation (string-based to avoid Hash requirement on MemoryKernelOp)
pub type SandboxOp = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub id: String,
    pub allowed_ops: HashSet<SandboxOp>,
    pub denied_ops: HashSet<SandboxOp>,
    pub allowed_namespaces: Vec<String>,
    pub max_memory: u64,
    pub network_allowed: bool,
    pub tools_allowed: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            id: "default".into(), allowed_ops: HashSet::new(), denied_ops: HashSet::new(),
            allowed_namespaces: vec!["/m/*".into()], max_memory: 512 * 1024 * 1024,
            network_allowed: true, tools_allowed: true,
        }
    }
}

impl SandboxPolicy {
    pub fn is_op_allowed(&self, op: &str) -> bool {
        !self.denied_ops.contains(op) && (self.allowed_ops.is_empty() || self.allowed_ops.contains(op))
    }
}

#[derive(Debug, Default)]
pub struct SandboxEnforcer {
    policies: HashMap<String, SandboxPolicy>,
    agent_policies: HashMap<Pid, String>,
}

impl SandboxEnforcer {
    pub fn new() -> Self {
        let mut e = Self::default();
        e.policies.insert("default".into(), SandboxPolicy::default());
        e
    }

    pub fn assign_policy(&mut self, agent: Pid, policy_id: &str) {
        self.agent_policies.insert(agent, policy_id.into());
    }

    pub fn check(&self, agent: &str, op: &str) -> bool {
        let policy_id = self.agent_policies.get(agent).cloned().unwrap_or("default".into());
        self.policies.get(&policy_id).map(|p| p.is_op_allowed(op)).unwrap_or(false)
    }
}

// === Part 3: MAC (Bell-LaPadula + Biba) ===

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum SecurityLevel { #[default] Unclassified, Confidential, Secret, TopSecret }

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum IntegrityLevel { Untrusted, Low, #[default] Medium, High, System }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityLabel {
    pub security: SecurityLevel,
    pub integrity: IntegrityLevel,
}

impl SecurityLabel {
    pub fn new(s: SecurityLevel, i: IntegrityLevel) -> Self { Self { security: s, integrity: i } }
    pub fn blp_can_read(&self, obj: &Self) -> bool { self.security >= obj.security }
    pub fn blp_can_write(&self, obj: &Self) -> bool { self.security <= obj.security }
    pub fn biba_can_read(&self, obj: &Self) -> bool { self.integrity <= obj.integrity }
    pub fn biba_can_write(&self, obj: &Self) -> bool { self.integrity >= obj.integrity }
}

#[derive(Debug, Default)]
pub struct MacEnforcer {
    subjects: HashMap<Pid, SecurityLabel>,
    objects: HashMap<String, SecurityLabel>,
    enforcing: bool,
}

impl MacEnforcer {
    pub fn new(enforcing: bool) -> Self { Self { enforcing, ..Default::default() } }
    pub fn set_subject(&mut self, s: Pid, l: SecurityLabel) { self.subjects.insert(s, l); }
    pub fn set_object(&mut self, o: String, l: SecurityLabel) { self.objects.insert(o, l); }

    pub fn check_read(&self, subj: &str, obj: &str) -> bool {
        let sl = self.subjects.get(subj).cloned().unwrap_or_default();
        let ol = self.objects.get(obj).cloned().unwrap_or_default();
        !self.enforcing || (sl.blp_can_read(&ol) && sl.biba_can_read(&ol))
    }

    pub fn check_write(&self, subj: &str, obj: &str) -> bool {
        let sl = self.subjects.get(subj).cloned().unwrap_or_default();
        let ol = self.objects.get(obj).cloned().unwrap_or_default();
        !self.enforcing || (sl.blp_can_write(&ol) && sl.biba_can_write(&ol))
    }
}

// === Part 4: Secure Boot ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootComponent {
    pub name: String,
    pub hash: String,
    pub signature: Option<String>,
    pub signer_key: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Default)]
pub struct SecureBootChain {
    trusted_keys: HashSet<String>,
    components: Vec<BootComponent>,
    measurements: Vec<String>,
}

impl SecureBootChain {
    pub fn new() -> Self { Self::default() }

    pub fn add_trusted_key(&mut self, key: String) { self.trusted_keys.insert(key); }

    pub fn verify_component(&mut self, mut comp: BootComponent) -> bool {
        // Simplified: check if signer key is trusted
        let verified = comp.signer_key.as_ref()
            .map(|k| self.trusted_keys.contains(k)).unwrap_or(false);
        comp.verified = verified;
        self.measurements.push(comp.hash.clone());
        self.components.push(comp);
        verified
    }

    pub fn all_verified(&self) -> bool { self.components.iter().all(|c| c.verified) }
    pub fn measurements(&self) -> &[String] { &self.measurements }
}

// === Tests ===

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_delegation() {
        let mut store = CapabilityStore::new();
        let cap_id = store.grant_root(CapabilityType::MemRead, "pid:001".into());
        assert!(store.has_capability("pid:001", CapabilityType::MemRead));

        let child_id = store.delegate(&cap_id, "pid:002".into()).unwrap();
        assert!(store.has_capability("pid:002", CapabilityType::MemRead));

        store.revoke(&cap_id);
        assert!(!store.has_capability("pid:001", CapabilityType::MemRead));
        assert!(!store.has_capability("pid:002", CapabilityType::MemRead));
    }

    #[test]
    fn test_sandbox() {
        let enforcer = SandboxEnforcer::new();
        assert!(enforcer.check("pid:001", "mem_read"));
    }

    #[test]
    fn test_mac() {
        let mut mac = MacEnforcer::new(true);
        // Subject: Secret clearance, High integrity
        // Object: Confidential classification, Medium integrity
        // BLP read: Secret >= Confidential ✓
        // Biba read: High <= Medium ✗ (can't read down in integrity)
        // So we need subject integrity <= object integrity for Biba read
        mac.set_subject("agent".into(), SecurityLabel::new(SecurityLevel::Secret, IntegrityLevel::Medium));
        mac.set_object("/data".into(), SecurityLabel::new(SecurityLevel::Confidential, IntegrityLevel::High));
        assert!(mac.check_read("agent", "/data")); // BLP: Secret >= Confidential, Biba: Medium <= High
        
        // For write: BLP requires subject <= object, Biba requires subject >= object
        mac.set_subject("writer".into(), SecurityLabel::new(SecurityLevel::Confidential, IntegrityLevel::High));
        mac.set_object("/target".into(), SecurityLabel::new(SecurityLevel::Secret, IntegrityLevel::Medium));
        assert!(mac.check_write("writer", "/target")); // BLP: Confidential <= Secret, Biba: High >= Medium
    }

    #[test]
    fn test_secure_boot() {
        let mut boot = SecureBootChain::new();
        boot.add_trusted_key("key:platform".into());
        let comp = BootComponent {
            name: "kernel".into(), hash: "abc123".into(),
            signature: Some("sig".into()), signer_key: Some("key:platform".into()), verified: false,
        };
        assert!(boot.verify_component(comp));
        assert!(boot.all_verified());
    }
}
