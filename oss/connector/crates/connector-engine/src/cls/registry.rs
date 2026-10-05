//! CLS Registry — stores, discovers, and manages SolutionContracts.
//!
//! The ContractRegistry provides:
//!   - Register/deregister contracts
//!   - Lookup by CID, name, version, domain, capability
//!   - Version management (latest, compatible)
//!   - Validation on registration
//!   - Contract status lifecycle (Draft → Active → Deprecated → Archived)

use std::collections::HashMap;
use crate::cls::types::*;

// ═══════════════════════════════════════════════════════════════
// Contract Status
// ═══════════════════════════════════════════════════════════════

/// Lifecycle status of a registered contract.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    /// Contract is in draft — not yet executable.
    Draft,
    /// Contract is active and executable.
    Active,
    /// Contract is deprecated — still executable but flagged for replacement.
    Deprecated { replacement_cid: Option<String> },
    /// Contract is archived — no longer executable.
    Archived,
}

/// A registered contract entry.
#[derive(Debug, Clone)]
pub struct ContractEntry {
    pub contract: SolutionContract,
    pub status: ContractStatus,
    pub registered_at: i64,
    pub execution_count: u64,
    pub last_executed: Option<i64>,
}

// ═══════════════════════════════════════════════════════════════
// Contract Registry
// ═══════════════════════════════════════════════════════════════

/// Central registry for SolutionContracts.
pub struct ContractRegistry {
    /// CID → entry
    contracts: HashMap<String, ContractEntry>,
    /// Name → list of CIDs (for version lookup)
    name_index: HashMap<String, Vec<String>>,
    /// Domain → list of CIDs
    domain_index: HashMap<String, Vec<String>>,
    /// Tool → list of CIDs (contracts that require this tool)
    tool_index: HashMap<String, Vec<String>>,
}

impl ContractRegistry {
    pub fn new() -> Self {
        Self {
            contracts: HashMap::new(),
            name_index: HashMap::new(),
            domain_index: HashMap::new(),
            tool_index: HashMap::new(),
        }
    }

    /// Register a new contract.
    ///
    /// Validates the contract before registration.
    pub fn register(&mut self, contract: SolutionContract) -> ClsResult<String> {
        let errors = contract.validate();
        if !errors.is_empty() {
            return Err(ClsError::ValidationError {
                errors: errors.iter().map(|e| format!("[{}] {}", e.code, e.message)).collect(),
            });
        }

        let cid = contract.id.cid.clone();
        let name = contract.id.name.clone();
        let domain = contract.domain.clone();

        // Index by tool
        for tool in &contract.interface.required_tools {
            self.tool_index.entry(tool.clone()).or_default().push(cid.clone());
        }

        // Index by name
        self.name_index.entry(name).or_default().push(cid.clone());

        // Index by domain
        if let Some(d) = domain {
            self.domain_index.entry(d).or_default().push(cid.clone());
        }

        let entry = ContractEntry {
            contract,
            status: ContractStatus::Active,
            registered_at: now_ms(),
            execution_count: 0,
            last_executed: None,
        };

        self.contracts.insert(cid.clone(), entry);
        Ok(cid)
    }

    /// Look up a contract by CID.
    pub fn get(&self, cid: &str) -> Option<&ContractEntry> {
        self.contracts.get(cid)
    }

    /// Look up a contract by CID (mutable).
    pub fn get_mut(&mut self, cid: &str) -> Option<&mut ContractEntry> {
        self.contracts.get_mut(cid)
    }

    /// Find the latest version of a contract by name.
    pub fn latest(&self, name: &str) -> Option<&ContractEntry> {
        self.name_index.get(name)?
            .iter()
            .filter_map(|cid| self.contracts.get(cid))
            .filter(|e| matches!(e.status, ContractStatus::Active))
            .max_by(|a, b| {
                let va = &a.contract.id.version;
                let vb = &b.contract.id.version;
                (va.major, va.minor, va.patch).cmp(&(vb.major, vb.minor, vb.patch))
            })
    }

    /// Find all contracts by name.
    pub fn find_by_name(&self, name: &str) -> Vec<&ContractEntry> {
        self.name_index.get(name)
            .map(|cids| cids.iter().filter_map(|c| self.contracts.get(c)).collect())
            .unwrap_or_default()
    }

    /// Find all contracts in a domain.
    pub fn find_by_domain(&self, domain: &str) -> Vec<&ContractEntry> {
        self.domain_index.get(domain)
            .map(|cids| cids.iter().filter_map(|c| self.contracts.get(c)).collect())
            .unwrap_or_default()
    }

    /// Find all contracts that require a specific tool.
    pub fn find_by_tool(&self, tool_id: &str) -> Vec<&ContractEntry> {
        self.tool_index.get(tool_id)
            .map(|cids| cids.iter().filter_map(|c| self.contracts.get(c)).collect())
            .unwrap_or_default()
    }

    /// Deprecate a contract, optionally pointing to a replacement.
    pub fn deprecate(&mut self, cid: &str, replacement_cid: Option<String>) -> ClsResult<()> {
        let entry = self.contracts.get_mut(cid).ok_or_else(|| ClsError::ContractNotFound {
            contract_id: cid.to_string(),
        })?;
        entry.status = ContractStatus::Deprecated { replacement_cid };
        Ok(())
    }

    /// Archive a contract (no longer executable).
    pub fn archive(&mut self, cid: &str) -> ClsResult<()> {
        let entry = self.contracts.get_mut(cid).ok_or_else(|| ClsError::ContractNotFound {
            contract_id: cid.to_string(),
        })?;
        entry.status = ContractStatus::Archived;
        Ok(())
    }

    /// Record that a contract was executed.
    pub fn record_execution(&mut self, cid: &str) {
        if let Some(entry) = self.contracts.get_mut(cid) {
            entry.execution_count += 1;
            entry.last_executed = Some(now_ms());
        }
    }

    /// Get total number of registered contracts.
    pub fn count(&self) -> usize {
        self.contracts.len()
    }

    /// Get all active contract CIDs.
    pub fn active_contracts(&self) -> Vec<&str> {
        self.contracts.iter()
            .filter(|(_, e)| matches!(e.status, ContractStatus::Active))
            .map(|(cid, _)| cid.as_str())
            .collect()
    }

    /// Remove a contract from the registry entirely.
    pub fn remove(&mut self, cid: &str) -> ClsResult<SolutionContract> {
        let entry = self.contracts.remove(cid).ok_or_else(|| ClsError::ContractNotFound {
            contract_id: cid.to_string(),
        })?;

        // Clean up indexes
        let name = &entry.contract.id.name;
        if let Some(cids) = self.name_index.get_mut(name) {
            cids.retain(|c| c != cid);
        }
        if let Some(d) = &entry.contract.domain {
            if let Some(cids) = self.domain_index.get_mut(d) {
                cids.retain(|c| c != cid);
            }
        }
        for tool in &entry.contract.interface.required_tools {
            if let Some(cids) = self.tool_index.get_mut(tool) {
                cids.retain(|c| c != cid);
            }
        }

        Ok(entry.contract)
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cls::compiler::ClsCompiler;

    fn compile_test(name: &str, version: &str, domain: Option<&str>) -> SolutionContract {
        let domain_line = domain.map(|d| format!("domain: {}", d)).unwrap_or_default();
        let yaml = format!(r#"
name: {}
version: "{}"
description: "test contract"
{}
tools:
  - tool_a
  - tool_b
memory:
  - ns_a
states:
  initial: init
  terminal: [done]
  transitions:
    - from: init
      to: done
      trigger: go
steps:
  - id: step1
    type: set_var
    var: x
    value: 42
  - id: done_step
    type: transition
    to: done
budget:
  tokens: 1000
  cost_usd: 0.10
  tool_calls: 5
  time_ms: 10000
  memory_mb: 32
"#, name, version, domain_line);
        ClsCompiler::compile(&yaml).unwrap()
    }

    #[test]
    fn test_register_and_get() {
        let mut reg = ContractRegistry::new();
        let contract = compile_test("my_contract", "1.0.0", Some("medical"));
        let cid = reg.register(contract).unwrap();

        assert_eq!(reg.count(), 1);
        let entry = reg.get(&cid).unwrap();
        assert_eq!(entry.contract.id.name, "my_contract");
        assert!(matches!(entry.status, ContractStatus::Active));
    }

    #[test]
    fn test_find_by_name() {
        let mut reg = ContractRegistry::new();
        reg.register(compile_test("triage", "1.0.0", None)).unwrap();
        reg.register(compile_test("triage", "1.1.0", None)).unwrap();
        reg.register(compile_test("other", "1.0.0", None)).unwrap();

        let found = reg.find_by_name("triage");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_latest_version() {
        let mut reg = ContractRegistry::new();
        reg.register(compile_test("triage", "1.0.0", None)).unwrap();
        reg.register(compile_test("triage", "2.0.0", None)).unwrap();
        reg.register(compile_test("triage", "1.5.0", None)).unwrap();

        let latest = reg.latest("triage").unwrap();
        assert_eq!(latest.contract.id.version, ContractVersion::new(2, 0, 0));
    }

    #[test]
    fn test_find_by_domain() {
        let mut reg = ContractRegistry::new();
        reg.register(compile_test("a", "1.0.0", Some("medical"))).unwrap();
        reg.register(compile_test("b", "1.0.0", Some("medical"))).unwrap();
        reg.register(compile_test("c", "1.0.0", Some("finance"))).unwrap();

        assert_eq!(reg.find_by_domain("medical").len(), 2);
        assert_eq!(reg.find_by_domain("finance").len(), 1);
    }

    #[test]
    fn test_find_by_tool() {
        let mut reg = ContractRegistry::new();
        reg.register(compile_test("a", "1.0.0", None)).unwrap();

        let found = reg.find_by_tool("tool_a");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_deprecate_and_archive() {
        let mut reg = ContractRegistry::new();
        let cid = reg.register(compile_test("old", "1.0.0", None)).unwrap();

        reg.deprecate(&cid, Some("new-cid".into())).unwrap();
        assert!(matches!(reg.get(&cid).unwrap().status, ContractStatus::Deprecated { .. }));

        reg.archive(&cid).unwrap();
        assert!(matches!(reg.get(&cid).unwrap().status, ContractStatus::Archived));

        // Archived contract should not appear in latest
        assert!(reg.latest("old").is_none());
    }

    #[test]
    fn test_record_execution() {
        let mut reg = ContractRegistry::new();
        let cid = reg.register(compile_test("x", "1.0.0", None)).unwrap();

        reg.record_execution(&cid);
        reg.record_execution(&cid);
        reg.record_execution(&cid);

        let entry = reg.get(&cid).unwrap();
        assert_eq!(entry.execution_count, 3);
        assert!(entry.last_executed.is_some());
    }

    #[test]
    fn test_remove() {
        let mut reg = ContractRegistry::new();
        let cid = reg.register(compile_test("removeme", "1.0.0", Some("test"))).unwrap();
        assert_eq!(reg.count(), 1);

        let removed = reg.remove(&cid).unwrap();
        assert_eq!(removed.id.name, "removeme");
        assert_eq!(reg.count(), 0);
        assert!(reg.get(&cid).is_none());
    }

    #[test]
    fn test_active_contracts() {
        let mut reg = ContractRegistry::new();
        let cid1 = reg.register(compile_test("a", "1.0.0", None)).unwrap();
        let cid2 = reg.register(compile_test("b", "1.0.0", None)).unwrap();
        reg.archive(&cid1).unwrap();

        let active = reg.active_contracts();
        assert_eq!(active.len(), 1);
        assert!(active.contains(&cid2.as_str()));
    }
}
