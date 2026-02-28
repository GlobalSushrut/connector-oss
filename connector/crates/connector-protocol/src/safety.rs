//! Safety Architecture (Layer 5+) — SIL levels, E-Stop, Watchdog, Geofence, Interlock, LOTO.
//!
//! Safety is first-class in the Connector Protocol. E-Stop is an ambient capability
//! that cannot be denied by policy. Every entity has a safety integrity level.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, ProtoResult};
use crate::identity::EntityId;

// ── Safety Integrity Level (IEC 61508) ──────────────────────────────

/// Safety Integrity Level per IEC 61508.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SafetyIntegrityLevel {
    /// No safety requirements (software agents, data processing)
    SIL0,
    /// Low risk (sensors, low-risk devices). PFH < 10⁻⁵
    SIL1,
    /// Medium risk (industrial machines, AGVs). PFH < 10⁻⁶
    SIL2,
    /// High risk (surgical robots, CNC). PFH < 10⁻⁷
    SIL3,
    /// Critical (nuclear, aerospace). PFH < 10⁻⁸
    SIL4,
}

impl std::fmt::Display for SafetyIntegrityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SIL0 => write!(f, "SIL-0"),
            Self::SIL1 => write!(f, "SIL-1"),
            Self::SIL2 => write!(f, "SIL-2"),
            Self::SIL3 => write!(f, "SIL-3"),
            Self::SIL4 => write!(f, "SIL-4"),
        }
    }
}

impl SafetyIntegrityLevel {
    /// Whether this SIL requires real-time total ordering.
    pub fn requires_total_ordering(&self) -> bool {
        *self >= Self::SIL2
    }

    /// Whether this SIL requires BFT consensus.
    pub fn requires_bft(&self) -> bool {
        *self >= Self::SIL3
    }

    /// Whether this SIL requires hardware attestation.
    pub fn requires_attestation(&self) -> bool {
        *self >= Self::SIL2
    }
}

// ── Emergency Stop ──────────────────────────────────────────────────

/// Scope of an emergency stop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EStopScope {
    /// Stop a single entity.
    Entity(EntityId),
    /// Stop all entities in a cell.
    Cell(String),
    /// Stop all entities in a federation.
    Federation(String),
    /// Stop everything globally.
    Global,
}

/// An emergency stop command. This is the ONLY ambient capability —
/// it requires no token and cannot be denied by policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyStop {
    pub initiator: EntityId,
    pub scope: EStopScope,
    pub reason: String,
    pub timestamp: i64,
    pub signature: Vec<u8>,
}

/// A clear-stop command. Requires 2-person authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearStop {
    pub authorizer_1: EntityId,
    pub authorizer_2: EntityId,
    pub scope: EStopScope,
    pub reason: String,
    pub timestamp: i64,
    pub signature_1: Vec<u8>,
    pub signature_2: Vec<u8>,
}

// ── Watchdog ────────────────────────────────────────────────────────

/// Watchdog state for an entity.
#[derive(Debug, Clone)]
pub struct WatchdogState {
    pub entity_id: EntityId,
    pub timeout_ms: u64,
    pub last_heartbeat: i64,
    pub missed_count: u32,
    pub max_missed: u32,
    pub in_safe_state: bool,
}

// ── Geofence ────────────────────────────────────────────────────────

/// A 3D bounding box geofence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Geofence {
    pub min_x: f64,
    pub max_x: f64,
    pub min_y: f64,
    pub max_y: f64,
    pub min_z: f64,
    pub max_z: f64,
}

impl Geofence {
    pub fn new(min_x: f64, max_x: f64, min_y: f64, max_y: f64, min_z: f64, max_z: f64) -> Self {
        Self { min_x, max_x, min_y, max_y, min_z, max_z }
    }

    /// Check if a point is within the geofence.
    pub fn contains(&self, x: f64, y: f64, z: f64) -> bool {
        x >= self.min_x && x <= self.max_x
            && y >= self.min_y && y <= self.max_y
            && z >= self.min_z && z <= self.max_z
    }

    /// Check if a motion path (start → end) stays within the geofence.
    pub fn path_within(&self, start: (f64, f64, f64), end: (f64, f64, f64)) -> bool {
        self.contains(start.0, start.1, start.2)
            && self.contains(end.0, end.1, end.2)
    }
}

// ── Interlock ───────────────────────────────────────────────────────

/// A logical or physical interlock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interlock {
    pub interlock_id: String,
    pub description: String,
    pub satisfied: bool,
    pub required_for: Vec<String>,
}

// ── Lockout/Tagout ──────────────────────────────────────────────────

/// Digital Lockout/Tagout state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockoutTagout {
    pub entity_id: EntityId,
    pub locked_by: EntityId,
    pub reason: String,
    pub locked_at: i64,
    pub requires_two_person: bool,
    pub second_authorizer: Option<EntityId>,
}

// ── Safety Manager ──────────────────────────────────────────────────

/// Manages safety state for all entities in a cell.
pub struct SafetyManager {
    /// Active e-stops by scope
    active_estops: Vec<EmergencyStop>,
    /// Watchdog states per entity
    watchdogs: HashMap<EntityId, WatchdogState>,
    /// Geofences per entity
    geofences: HashMap<EntityId, Geofence>,
    /// Interlocks per entity
    interlocks: HashMap<EntityId, Vec<Interlock>>,
    /// Active lockouts
    lockouts: HashMap<EntityId, LockoutTagout>,
    /// Entities in safe state
    safe_state_entities: HashSet<EntityId>,
}

impl SafetyManager {
    pub fn new() -> Self {
        Self {
            active_estops: Vec::new(),
            watchdogs: HashMap::new(),
            geofences: HashMap::new(),
            interlocks: HashMap::new(),
            lockouts: HashMap::new(),
            safe_state_entities: HashSet::new(),
        }
    }

    // ── E-Stop ──────────────────────────────────────────────────

    /// Trigger an emergency stop. Always succeeds (ambient capability).
    pub fn trigger_estop(&mut self, estop: EmergencyStop) {
        match &estop.scope {
            EStopScope::Entity(id) => {
                self.safe_state_entities.insert(id.clone());
            }
            EStopScope::Cell(_) | EStopScope::Federation(_) | EStopScope::Global => {
                for id in self.watchdogs.keys().cloned().collect::<Vec<_>>() {
                    self.safe_state_entities.insert(id);
                }
            }
        }
        self.active_estops.push(estop);
    }

    /// Clear an e-stop. Requires 2-person authorization.
    pub fn clear_estop(&mut self, clear: &ClearStop) -> ProtoResult<()> {
        if clear.authorizer_1 == clear.authorizer_2 {
            return Err(ProtocolError::SafetyViolation(
                "Clear-stop requires two different authorizers".into(),
            ));
        }

        self.active_estops.retain(|e| e.scope != clear.scope);

        match &clear.scope {
            EStopScope::Entity(id) => {
                self.safe_state_entities.remove(id);
            }
            _ => {
                self.safe_state_entities.clear();
            }
        }
        Ok(())
    }

    /// Check if an entity is e-stopped.
    pub fn is_estopped(&self, entity_id: &EntityId) -> bool {
        self.safe_state_entities.contains(entity_id)
    }

    /// Count active e-stops.
    pub fn active_estop_count(&self) -> usize {
        self.active_estops.len()
    }

    // ── Watchdog ────────────────────────────────────────────────

    /// Register a watchdog for an entity.
    pub fn register_watchdog(&mut self, entity_id: EntityId, timeout_ms: u64, max_missed: u32) {
        self.watchdogs.insert(entity_id.clone(), WatchdogState {
            entity_id,
            timeout_ms,
            last_heartbeat: chrono::Utc::now().timestamp_millis(),
            missed_count: 0,
            max_missed,
            in_safe_state: false,
        });
    }

    /// Reset watchdog (heartbeat received).
    pub fn watchdog_heartbeat(&mut self, entity_id: &EntityId) -> ProtoResult<()> {
        let state = self.watchdogs.get_mut(entity_id)
            .ok_or_else(|| ProtocolError::NotFound(format!("Watchdog for {}", entity_id)))?;
        state.last_heartbeat = chrono::Utc::now().timestamp_millis();
        state.missed_count = 0;
        Ok(())
    }

    /// Check watchdogs and transition timed-out entities to safe state.
    pub fn check_watchdogs(&mut self) -> Vec<EntityId> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut timed_out = Vec::new();

        for state in self.watchdogs.values_mut() {
            if now - state.last_heartbeat > state.timeout_ms as i64 {
                state.missed_count += 1;
                if state.missed_count >= state.max_missed && !state.in_safe_state {
                    state.in_safe_state = true;
                    timed_out.push(state.entity_id.clone());
                }
            }
        }

        for id in &timed_out {
            self.safe_state_entities.insert(id.clone());
        }
        timed_out
    }

    // ── Geofence ────────────────────────────────────────────────

    /// Set geofence for an entity.
    pub fn set_geofence(&mut self, entity_id: EntityId, geofence: Geofence) {
        self.geofences.insert(entity_id, geofence);
    }

    /// Check if a motion is within the entity's geofence.
    pub fn check_geofence(
        &self,
        entity_id: &EntityId,
        x: f64, y: f64, z: f64,
    ) -> ProtoResult<()> {
        if let Some(fence) = self.geofences.get(entity_id) {
            if !fence.contains(x, y, z) {
                return Err(ProtocolError::GeofenceViolation(format!(
                    "({}, {}, {}) outside geofence for {}",
                    x, y, z, entity_id
                )));
            }
        }
        Ok(())
    }

    // ── Interlock ───────────────────────────────────────────────

    /// Set interlocks for an entity.
    pub fn set_interlocks(&mut self, entity_id: EntityId, interlocks: Vec<Interlock>) {
        self.interlocks.insert(entity_id, interlocks);
    }

    /// Check if all interlocks are satisfied for an entity.
    pub fn check_interlocks(&self, entity_id: &EntityId) -> ProtoResult<()> {
        if let Some(locks) = self.interlocks.get(entity_id) {
            for lock in locks {
                if !lock.satisfied {
                    return Err(ProtocolError::InterlockViolation(format!(
                        "Interlock '{}' not satisfied for {}",
                        lock.interlock_id, entity_id
                    )));
                }
            }
        }
        Ok(())
    }

    /// Update an interlock state.
    pub fn update_interlock(&mut self, entity_id: &EntityId, interlock_id: &str, satisfied: bool) {
        if let Some(locks) = self.interlocks.get_mut(entity_id) {
            for lock in locks.iter_mut() {
                if lock.interlock_id == interlock_id {
                    lock.satisfied = satisfied;
                }
            }
        }
    }

    // ── Lockout/Tagout ──────────────────────────────────────────

    /// Apply lockout to an entity.
    pub fn lockout(&mut self, loto: LockoutTagout) {
        let id = loto.entity_id.clone();
        self.lockouts.insert(id.clone(), loto);
        self.safe_state_entities.insert(id);
    }

    /// Release lockout. Requires same authorizer(s).
    pub fn release_lockout(&mut self, entity_id: &EntityId, releaser: &EntityId) -> ProtoResult<()> {
        let loto = self.lockouts.get(entity_id)
            .ok_or_else(|| ProtocolError::NotFound(format!("Lockout for {}", entity_id)))?;

        if loto.requires_two_person {
            return Err(ProtocolError::SafetyViolation(
                "Two-person lockout requires ClearStop procedure".into(),
            ));
        }

        if &loto.locked_by != releaser {
            return Err(ProtocolError::SafetyViolation(
                "Only the locking entity can release".into(),
            ));
        }

        self.lockouts.remove(entity_id);
        self.safe_state_entities.remove(entity_id);
        Ok(())
    }

    /// Check if an entity is locked out.
    pub fn is_locked_out(&self, entity_id: &EntityId) -> bool {
        self.lockouts.contains_key(entity_id)
    }

    // ── Composite safety check ──────────────────────────────────

    /// Full safety gate: checks e-stop, lockout, interlocks, and geofence.
    pub fn safety_gate(
        &self,
        entity_id: &EntityId,
        target_pos: Option<(f64, f64, f64)>,
    ) -> ProtoResult<()> {
        // E-stop check
        if self.is_estopped(entity_id) {
            return Err(ProtocolError::EmergencyStop(
                format!("Entity {} is in e-stop state", entity_id),
            ));
        }

        // Lockout check
        if self.is_locked_out(entity_id) {
            return Err(ProtocolError::LockoutActive(
                format!("Entity {} is locked out", entity_id),
            ));
        }

        // Interlock check
        self.check_interlocks(entity_id)?;

        // Geofence check
        if let Some((x, y, z)) = target_pos {
            self.check_geofence(entity_id, x, y, z)?;
        }

        Ok(())
    }
}

impl Default for SafetyManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine_id(name: &str) -> EntityId {
        EntityId::new(crate::identity::EntityClass::Machine, name)
    }

    fn agent_id(name: &str) -> EntityId {
        EntityId::new(crate::identity::EntityClass::Agent, name)
    }

    #[test]
    fn test_sil_levels() {
        assert!(!SafetyIntegrityLevel::SIL0.requires_total_ordering());
        assert!(!SafetyIntegrityLevel::SIL1.requires_total_ordering());
        assert!(SafetyIntegrityLevel::SIL2.requires_total_ordering());
        assert!(SafetyIntegrityLevel::SIL3.requires_bft());
        assert!(SafetyIntegrityLevel::SIL4.requires_bft());
        assert!(!SafetyIntegrityLevel::SIL1.requires_attestation());
        assert!(SafetyIntegrityLevel::SIL2.requires_attestation());
    }

    #[test]
    fn test_estop_entity() {
        let mut mgr = SafetyManager::new();
        let m1 = machine_id("m1");
        mgr.register_watchdog(m1.clone(), 5000, 3);

        assert!(!mgr.is_estopped(&m1));

        mgr.trigger_estop(EmergencyStop {
            initiator: agent_id("operator"),
            scope: EStopScope::Entity(m1.clone()),
            reason: "manual stop".into(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: vec![],
        });

        assert!(mgr.is_estopped(&m1));
        assert_eq!(mgr.active_estop_count(), 1);
    }

    #[test]
    fn test_estop_cell_scope() {
        let mut mgr = SafetyManager::new();
        let m1 = machine_id("m1");
        let m2 = machine_id("m2");
        mgr.register_watchdog(m1.clone(), 5000, 3);
        mgr.register_watchdog(m2.clone(), 5000, 3);

        mgr.trigger_estop(EmergencyStop {
            initiator: agent_id("op"),
            scope: EStopScope::Cell("factory-1".into()),
            reason: "fire alarm".into(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: vec![],
        });

        assert!(mgr.is_estopped(&m1));
        assert!(mgr.is_estopped(&m2));
    }

    #[test]
    fn test_clear_estop_requires_two_persons() {
        let mut mgr = SafetyManager::new();
        let m1 = machine_id("m1");
        mgr.register_watchdog(m1.clone(), 5000, 3);
        mgr.trigger_estop(EmergencyStop {
            initiator: agent_id("op"),
            scope: EStopScope::Entity(m1.clone()),
            reason: "test".into(),
            timestamp: 0,
            signature: vec![],
        });

        // Same person twice should fail
        let clear = ClearStop {
            authorizer_1: agent_id("op"),
            authorizer_2: agent_id("op"),
            scope: EStopScope::Entity(m1.clone()),
            reason: "resume".into(),
            timestamp: 0,
            signature_1: vec![],
            signature_2: vec![],
        };
        assert!(mgr.clear_estop(&clear).is_err());

        // Two different persons should succeed
        let clear2 = ClearStop {
            authorizer_1: agent_id("op1"),
            authorizer_2: agent_id("op2"),
            scope: EStopScope::Entity(m1.clone()),
            reason: "resume".into(),
            timestamp: 0,
            signature_1: vec![],
            signature_2: vec![],
        };
        assert!(mgr.clear_estop(&clear2).is_ok());
        assert!(!mgr.is_estopped(&m1));
    }

    #[test]
    fn test_watchdog_timeout() {
        let mut mgr = SafetyManager::new();
        let m1 = machine_id("m1");
        mgr.register_watchdog(m1.clone(), 0, 1); // 0ms timeout = instant

        // Simulate old heartbeat
        if let Some(state) = mgr.watchdogs.get_mut(&m1) {
            state.last_heartbeat = chrono::Utc::now().timestamp_millis() - 1000;
        }

        let timed_out = mgr.check_watchdogs();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0], m1);
        assert!(mgr.is_estopped(&m1));
    }

    #[test]
    fn test_watchdog_heartbeat_resets() {
        let mut mgr = SafetyManager::new();
        let m1 = machine_id("m1");
        mgr.register_watchdog(m1.clone(), 5000, 3);
        assert!(mgr.watchdog_heartbeat(&m1).is_ok());
    }

    #[test]
    fn test_geofence() {
        let mut mgr = SafetyManager::new();
        let m1 = machine_id("m1");
        mgr.set_geofence(m1.clone(), Geofence::new(-500.0, 500.0, -300.0, 300.0, -200.0, 0.0));

        assert!(mgr.check_geofence(&m1, 0.0, 0.0, -100.0).is_ok());
        assert!(mgr.check_geofence(&m1, 499.0, 299.0, -1.0).is_ok());
        assert!(mgr.check_geofence(&m1, 600.0, 0.0, 0.0).is_err()); // outside X
        assert!(mgr.check_geofence(&m1, 0.0, 0.0, 10.0).is_err());  // outside Z
    }

    #[test]
    fn test_interlock() {
        let mut mgr = SafetyManager::new();
        let m1 = machine_id("m1");
        mgr.set_interlocks(m1.clone(), vec![
            Interlock {
                interlock_id: "door_closed".into(),
                description: "Safety door must be closed".into(),
                satisfied: false,
                required_for: vec!["machine.spindle_on".into()],
            },
        ]);

        assert!(mgr.check_interlocks(&m1).is_err());
        mgr.update_interlock(&m1, "door_closed", true);
        assert!(mgr.check_interlocks(&m1).is_ok());
    }

    #[test]
    fn test_lockout_tagout() {
        let mut mgr = SafetyManager::new();
        let m1 = machine_id("m1");
        let maintainer = agent_id("maint");

        mgr.lockout(LockoutTagout {
            entity_id: m1.clone(),
            locked_by: maintainer.clone(),
            reason: "maintenance".into(),
            locked_at: chrono::Utc::now().timestamp_millis(),
            requires_two_person: false,
            second_authorizer: None,
        });

        assert!(mgr.is_locked_out(&m1));
        assert!(mgr.is_estopped(&m1)); // lockout → safe state

        // Wrong person can't release
        assert!(mgr.release_lockout(&m1, &agent_id("other")).is_err());

        // Right person can release
        assert!(mgr.release_lockout(&m1, &maintainer).is_ok());
        assert!(!mgr.is_locked_out(&m1));
    }

    #[test]
    fn test_safety_gate_composite() {
        let mut mgr = SafetyManager::new();
        let m1 = machine_id("m1");
        mgr.register_watchdog(m1.clone(), 5000, 3);
        mgr.set_geofence(m1.clone(), Geofence::new(-100.0, 100.0, -100.0, 100.0, -100.0, 0.0));
        mgr.set_interlocks(m1.clone(), vec![
            Interlock {
                interlock_id: "door".into(),
                description: "Door".into(),
                satisfied: true,
                required_for: vec![],
            },
        ]);

        // All clear
        assert!(mgr.safety_gate(&m1, Some((50.0, 50.0, -50.0))).is_ok());

        // Geofence violation
        assert!(mgr.safety_gate(&m1, Some((200.0, 0.0, 0.0))).is_err());

        // E-stop
        mgr.trigger_estop(EmergencyStop {
            initiator: agent_id("op"),
            scope: EStopScope::Entity(m1.clone()),
            reason: "test".into(),
            timestamp: 0,
            signature: vec![],
        });
        assert!(mgr.safety_gate(&m1, None).is_err());
    }

    #[test]
    fn test_geofence_path() {
        let fence = Geofence::new(0.0, 100.0, 0.0, 100.0, 0.0, 100.0);
        assert!(fence.path_within((10.0, 10.0, 10.0), (90.0, 90.0, 90.0)));
        assert!(!fence.path_within((10.0, 10.0, 10.0), (110.0, 10.0, 10.0)));
    }
}
