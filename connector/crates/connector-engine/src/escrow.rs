//! Escrow & Settlement — trustless payment between agents.
//!
//! Funds are locked in escrow before invocation. On success, funds release
//! to provider. On SLA violation, funds are slashed and returned to requester.
//!
//! Research: Akash Network escrow (DeCloud), Ethereum payment channels,
//! Lightning Network HTLCs, traditional escrow patterns.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Escrow Account
// ═══════════════════════════════════════════════════════════════

/// State of an escrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscrowState {
    /// Funds locked, awaiting invocation result.
    Locked,
    /// Invocation succeeded, funds released to provider.
    Released,
    /// SLA violated, funds returned to requester (minus slash).
    Slashed,
    /// Expired without resolution — funds returned to requester.
    Expired,
    /// Disputed — requires arbitration.
    Disputed,
}

/// A single escrow account between requester and provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowAccount {
    pub escrow_id: String,
    pub requester_pid: String,
    pub provider_pid: String,
    pub amount: u64,
    pub state: EscrowState,
    pub created_at: i64,
    pub expires_at: i64,
    pub contract_id: String,
    pub invocation_id: Option<String>,
    pub resolution_reason: Option<String>,
    pub resolved_at: Option<i64>,
}

// ═══════════════════════════════════════════════════════════════
// Settlement Record
// ═══════════════════════════════════════════════════════════════

/// Record of a completed settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementRecord {
    pub escrow_id: String,
    pub to_provider: u64,
    pub to_requester: u64,
    pub slashed: u64,
    pub settled_at: i64,
}

// ═══════════════════════════════════════════════════════════════
// Escrow Manager
// ═══════════════════════════════════════════════════════════════

/// Manages escrow accounts and settlements.
pub struct EscrowManager {
    escrows: HashMap<String, EscrowAccount>,
    balances: HashMap<String, u64>,
    settlements: Vec<SettlementRecord>,
    next_id: u64,
}

impl EscrowManager {
    pub fn new() -> Self {
        Self {
            escrows: HashMap::new(),
            balances: HashMap::new(),
            settlements: Vec::new(),
            next_id: 1,
        }
    }

    /// Deposit funds into an agent's balance.
    pub fn deposit(&mut self, agent_pid: &str, amount: u64) {
        *self.balances.entry(agent_pid.to_string()).or_insert(0) += amount;
    }

    /// Get an agent's available balance.
    pub fn balance(&self, agent_pid: &str) -> u64 {
        self.balances.get(agent_pid).copied().unwrap_or(0)
    }

    /// Lock funds in escrow for an invocation.
    pub fn lock(
        &mut self,
        requester: &str,
        provider: &str,
        amount: u64,
        contract_id: &str,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<String, String> {
        let bal = self.balances.get(requester).copied().unwrap_or(0);
        if bal < amount {
            return Err(format!(
                "Insufficient balance: {} has {} but needs {}",
                requester, bal, amount
            ));
        }
        // Debit requester
        *self.balances.get_mut(requester).unwrap() -= amount;

        let escrow_id = format!("escrow_{}", self.next_id);
        self.next_id += 1;

        let account = EscrowAccount {
            escrow_id: escrow_id.clone(),
            requester_pid: requester.to_string(),
            provider_pid: provider.to_string(),
            amount,
            state: EscrowState::Locked,
            created_at: now_ms,
            expires_at: now_ms + ttl_ms,
            contract_id: contract_id.to_string(),
            invocation_id: None,
            resolution_reason: None,
            resolved_at: None,
        };
        self.escrows.insert(escrow_id.clone(), account);
        Ok(escrow_id)
    }

    /// Release escrow funds to provider (invocation succeeded).
    pub fn release(&mut self, escrow_id: &str, now_ms: i64) -> Result<SettlementRecord, String> {
        let account = self.escrows.get_mut(escrow_id)
            .ok_or_else(|| format!("Escrow {} not found", escrow_id))?;
        if account.state != EscrowState::Locked {
            return Err(format!("Escrow {} is {:?}, not Locked", escrow_id, account.state));
        }
        account.state = EscrowState::Released;
        account.resolved_at = Some(now_ms);
        account.resolution_reason = Some("Invocation succeeded".into());

        // Credit provider
        *self.balances.entry(account.provider_pid.clone()).or_insert(0) += account.amount;

        let record = SettlementRecord {
            escrow_id: escrow_id.to_string(),
            to_provider: account.amount,
            to_requester: 0,
            slashed: 0,
            settled_at: now_ms,
        };
        self.settlements.push(record.clone());
        Ok(record)
    }

    /// Slash escrow (SLA violation). slash_pct is 0.0 to 1.0.
    pub fn slash(
        &mut self,
        escrow_id: &str,
        slash_pct: f64,
        reason: &str,
        now_ms: i64,
    ) -> Result<SettlementRecord, String> {
        if slash_pct < 0.0 || slash_pct > 1.0 {
            return Err("slash_pct must be in [0.0, 1.0]".into());
        }
        let account = self.escrows.get_mut(escrow_id)
            .ok_or_else(|| format!("Escrow {} not found", escrow_id))?;
        if account.state != EscrowState::Locked {
            return Err(format!("Escrow {} is {:?}, not Locked", escrow_id, account.state));
        }
        account.state = EscrowState::Slashed;
        account.resolved_at = Some(now_ms);
        account.resolution_reason = Some(reason.to_string());

        let slashed = (account.amount as f64 * slash_pct) as u64;
        let to_requester = account.amount - slashed;

        // Return remainder to requester
        *self.balances.entry(account.requester_pid.clone()).or_insert(0) += to_requester;

        let record = SettlementRecord {
            escrow_id: escrow_id.to_string(),
            to_provider: 0,
            to_requester,
            slashed,
            settled_at: now_ms,
        };
        self.settlements.push(record.clone());
        Ok(record)
    }

    /// Expire stale escrows — returns funds to requester.
    pub fn expire_stale(&mut self, now_ms: i64) -> Vec<String> {
        let expired: Vec<String> = self.escrows.iter()
            .filter(|(_, e)| e.state == EscrowState::Locked && now_ms > e.expires_at)
            .map(|(id, _)| id.clone())
            .collect();

        for id in &expired {
            if let Some(account) = self.escrows.get_mut(id) {
                account.state = EscrowState::Expired;
                account.resolved_at = Some(now_ms);
                account.resolution_reason = Some("Expired without resolution".into());
                *self.balances.entry(account.requester_pid.clone()).or_insert(0) += account.amount;
                self.settlements.push(SettlementRecord {
                    escrow_id: id.clone(),
                    to_provider: 0,
                    to_requester: account.amount,
                    slashed: 0,
                    settled_at: now_ms,
                });
            }
        }
        expired
    }

    /// Raise a dispute on an escrow.
    pub fn dispute(&mut self, escrow_id: &str, reason: &str) -> Result<(), String> {
        let account = self.escrows.get_mut(escrow_id)
            .ok_or_else(|| format!("Escrow {} not found", escrow_id))?;
        if account.state != EscrowState::Locked {
            return Err(format!("Can only dispute Locked escrows"));
        }
        account.state = EscrowState::Disputed;
        account.resolution_reason = Some(reason.to_string());
        Ok(())
    }

    // ── Accessors ───────────────────────────────────────────
    pub fn get_escrow(&self, id: &str) -> Option<&EscrowAccount> { self.escrows.get(id) }
    pub fn active_escrow_count(&self) -> usize {
        self.escrows.values().filter(|e| e.state == EscrowState::Locked).count()
    }
    pub fn settlement_count(&self) -> usize { self.settlements.len() }
    pub fn total_locked(&self) -> u64 {
        self.escrows.values()
            .filter(|e| e.state == EscrowState::Locked)
            .map(|e| e.amount)
            .sum()
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> EscrowManager {
        let mut m = EscrowManager::new();
        m.deposit("requester", 10000);
        m.deposit("provider", 500);
        m
    }

    #[test]
    fn test_lock_and_release() {
        let mut m = make_manager();
        let id = m.lock("requester", "provider", 1000, "sc_1", 1000, 60000).unwrap();
        assert_eq!(m.balance("requester"), 9000);
        assert_eq!(m.active_escrow_count(), 1);
        assert_eq!(m.total_locked(), 1000);

        let record = m.release(&id, 2000).unwrap();
        assert_eq!(record.to_provider, 1000);
        assert_eq!(record.to_requester, 0);
        assert_eq!(m.balance("provider"), 1500); // 500 + 1000
        assert_eq!(m.active_escrow_count(), 0);
    }

    #[test]
    fn test_insufficient_balance() {
        let mut m = make_manager();
        let result = m.lock("requester", "provider", 99999, "sc_1", 1000, 60000);
        assert!(result.is_err());
    }

    #[test]
    fn test_slash_partial() {
        let mut m = make_manager();
        let id = m.lock("requester", "provider", 1000, "sc_1", 1000, 60000).unwrap();
        let record = m.slash(&id, 0.3, "SLA latency exceeded", 2000).unwrap();
        assert_eq!(record.slashed, 300);
        assert_eq!(record.to_requester, 700);
        assert_eq!(record.to_provider, 0);
        assert_eq!(m.balance("requester"), 9700); // 9000 + 700 returned
    }

    #[test]
    fn test_slash_full() {
        let mut m = make_manager();
        let id = m.lock("requester", "provider", 1000, "sc_1", 1000, 60000).unwrap();
        let record = m.slash(&id, 1.0, "Critical failure", 2000).unwrap();
        assert_eq!(record.slashed, 1000);
        assert_eq!(record.to_requester, 0);
    }

    #[test]
    fn test_expire_stale() {
        let mut m = make_manager();
        let id = m.lock("requester", "provider", 500, "sc_1", 1000, 5000).unwrap();
        assert_eq!(m.active_escrow_count(), 1);
        let expired = m.expire_stale(7000); // After TTL
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], id);
        assert_eq!(m.balance("requester"), 10000); // Full refund: 9500 + 500
        assert_eq!(m.active_escrow_count(), 0);
    }

    #[test]
    fn test_dispute() {
        let mut m = make_manager();
        let id = m.lock("requester", "provider", 1000, "sc_1", 1000, 60000).unwrap();
        assert!(m.dispute(&id, "Provider delivered wrong result").is_ok());
        assert_eq!(m.get_escrow(&id).unwrap().state, EscrowState::Disputed);
        // Cannot release a disputed escrow
        assert!(m.release(&id, 2000).is_err());
    }

    #[test]
    fn test_double_release_rejected() {
        let mut m = make_manager();
        let id = m.lock("requester", "provider", 1000, "sc_1", 1000, 60000).unwrap();
        assert!(m.release(&id, 2000).is_ok());
        assert!(m.release(&id, 3000).is_err()); // Already released
    }

    #[test]
    fn test_multiple_escrows() {
        let mut m = make_manager();
        let id1 = m.lock("requester", "provider", 2000, "sc_1", 1000, 60000).unwrap();
        let id2 = m.lock("requester", "provider", 3000, "sc_2", 1000, 60000).unwrap();
        assert_eq!(m.balance("requester"), 5000);
        assert_eq!(m.active_escrow_count(), 2);
        assert_eq!(m.total_locked(), 5000);

        m.release(&id1, 2000).unwrap();
        assert_eq!(m.active_escrow_count(), 1);
        m.slash(&id2, 0.5, "Timeout", 3000).unwrap();
        assert_eq!(m.active_escrow_count(), 0);
        assert_eq!(m.settlement_count(), 2);
    }
}
