//! PID Namespace — Process ID isolation and namespace hierarchy
//!
//! This module implements PID namespaces for agent isolation:
//! - Hierarchical namespace structure (global → cell → sandbox)
//! - PID translation between namespaces
//! - Process groups (PGID) and sessions (SID)
//! - Namespace-aware process table
//!
//! Design sources: Linux PID namespaces, clone(CLONE_NEWPID)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::process::Pid;

// =============================================================================
// Namespace Types
// =============================================================================

/// Namespace ID
pub type NamespaceId = String;

/// Local PID within a namespace
pub type LocalPid = u64;

/// Process Group ID
pub type Pgid = String;

/// Session ID
pub type Sid = String;

/// Namespace ID counter
static NAMESPACE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a new namespace ID
pub fn generate_namespace_id(ns_type: NamespaceType) -> NamespaceId {
    let id = NAMESPACE_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    match ns_type {
        NamespaceType::Global => "ns:global".into(),
        NamespaceType::Cell => format!("ns:cell:{:08x}", id),
        NamespaceType::Sandbox => format!("ns:sandbox:{:08x}", id),
        NamespaceType::Container => format!("ns:container:{:08x}", id),
    }
}

/// Namespace type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceType {
    /// Global namespace (root, platform-wide)
    Global,
    /// Cell namespace (per-cell isolation)
    Cell,
    /// Sandbox namespace (nested within cell)
    Sandbox,
    /// Container namespace (external runtime bridge)
    Container,
}

impl Default for NamespaceType {
    fn default() -> Self {
        Self::Global
    }
}

// =============================================================================
// PID Namespace
// =============================================================================

/// PID Namespace — isolates process IDs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PidNamespace {
    /// Namespace ID
    pub id: NamespaceId,
    /// Namespace type
    pub ns_type: NamespaceType,
    /// Parent namespace (None for global)
    pub parent: Option<NamespaceId>,
    /// Child namespaces
    pub children: Vec<NamespaceId>,
    /// Next local PID to allocate
    next_local_pid: LocalPid,
    /// Global PID → Local PID mapping
    global_to_local: HashMap<Pid, LocalPid>,
    /// Local PID → Global PID mapping
    local_to_global: HashMap<LocalPid, Pid>,
    /// Init process (PID 1 in this namespace)
    pub init_pid: Option<Pid>,
    /// Created timestamp
    pub created_at: i64,
}

impl PidNamespace {
    /// Create a new namespace
    pub fn new(ns_type: NamespaceType, parent: Option<NamespaceId>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            id: generate_namespace_id(ns_type),
            ns_type,
            parent,
            children: vec![],
            next_local_pid: 1, // Start at 1 (init)
            global_to_local: HashMap::new(),
            local_to_global: HashMap::new(),
            init_pid: None,
            created_at: now,
        }
    }

    /// Create the global namespace
    pub fn global() -> Self {
        Self {
            id: "ns:global".into(),
            ns_type: NamespaceType::Global,
            parent: None,
            children: vec![],
            next_local_pid: 1,
            global_to_local: HashMap::new(),
            local_to_global: HashMap::new(),
            init_pid: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        }
    }

    /// Allocate a local PID for a global PID
    pub fn allocate(&mut self, global_pid: Pid) -> LocalPid {
        if let Some(&local) = self.global_to_local.get(&global_pid) {
            return local;
        }

        let local_pid = self.next_local_pid;
        self.next_local_pid += 1;

        // First process becomes init
        if local_pid == 1 {
            self.init_pid = Some(global_pid.clone());
        }

        self.global_to_local.insert(global_pid.clone(), local_pid);
        self.local_to_global.insert(local_pid, global_pid);

        local_pid
    }

    /// Deallocate a PID
    pub fn deallocate(&mut self, global_pid: &Pid) {
        if let Some(local_pid) = self.global_to_local.remove(global_pid) {
            self.local_to_global.remove(&local_pid);
        }
    }

    /// Translate global PID to local PID
    pub fn translate(&self, global_pid: &Pid) -> Option<LocalPid> {
        self.global_to_local.get(global_pid).copied()
    }

    /// Resolve local PID to global PID
    pub fn resolve(&self, local_pid: LocalPid) -> Option<&Pid> {
        self.local_to_global.get(&local_pid)
    }

    /// Check if PID is visible in this namespace
    pub fn is_visible(&self, global_pid: &Pid) -> bool {
        self.global_to_local.contains_key(global_pid)
    }

    /// Get all PIDs in this namespace
    pub fn pids(&self) -> Vec<(LocalPid, &Pid)> {
        let mut pids: Vec<_> = self.local_to_global.iter()
            .map(|(&local, global)| (local, global))
            .collect();
        pids.sort_by_key(|(local, _)| *local);
        pids
    }

    /// Count of processes in namespace
    pub fn len(&self) -> usize {
        self.global_to_local.len()
    }

    pub fn is_empty(&self) -> bool {
        self.global_to_local.is_empty()
    }
}

// =============================================================================
// Process Group
// =============================================================================

/// Process Group — for job control and collective signals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessGroup {
    /// Process group ID (usually leader's PID)
    pub pgid: Pgid,
    /// Group leader PID
    pub leader: Pid,
    /// All member PIDs
    pub members: Vec<Pid>,
    /// Parent session
    pub session: Sid,
    /// Created timestamp
    pub created_at: i64,
}

impl ProcessGroup {
    /// Create a new process group
    pub fn new(leader: Pid, session: Sid) -> Self {
        let pgid = format!("pgid:{}", leader.trim_start_matches("pid:"));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            pgid,
            leader: leader.clone(),
            members: vec![leader],
            session,
            created_at: now,
        }
    }

    /// Add a member to the group
    pub fn add_member(&mut self, pid: Pid) {
        if !self.members.contains(&pid) {
            self.members.push(pid);
        }
    }

    /// Remove a member from the group
    pub fn remove_member(&mut self, pid: &Pid) {
        self.members.retain(|p| p != pid);
    }

    /// Check if PID is a member
    pub fn is_member(&self, pid: &Pid) -> bool {
        self.members.contains(pid)
    }

    /// Check if group is empty
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

// =============================================================================
// Session
// =============================================================================

/// Session — groups related process groups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID (leader's PID)
    pub sid: Sid,
    /// Session leader PID
    pub leader: Pid,
    /// Process groups in this session
    pub groups: Vec<Pgid>,
    /// Controlling port (like controlling terminal)
    pub controlling_port: Option<String>,
    /// Foreground process group
    pub foreground_group: Option<Pgid>,
    /// Created timestamp
    pub created_at: i64,
}

impl Session {
    /// Create a new session
    pub fn new(leader: Pid) -> Self {
        let sid = format!("sid:{}", leader.trim_start_matches("pid:"));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Create initial process group for leader
        let pgid = format!("pgid:{}", leader.trim_start_matches("pid:"));

        Self {
            sid,
            leader,
            groups: vec![pgid.clone()],
            controlling_port: None,
            foreground_group: Some(pgid),
            created_at: now,
        }
    }

    /// Add a process group to the session
    pub fn add_group(&mut self, pgid: Pgid) {
        if !self.groups.contains(&pgid) {
            self.groups.push(pgid);
        }
    }

    /// Remove a process group from the session
    pub fn remove_group(&mut self, pgid: &Pgid) {
        self.groups.retain(|g| g != pgid);
        if self.foreground_group.as_ref() == Some(pgid) {
            self.foreground_group = None;
        }
    }

    /// Set foreground group
    pub fn set_foreground(&mut self, pgid: Pgid) -> Result<(), String> {
        if !self.groups.contains(&pgid) {
            return Err("Group not in session".into());
        }
        self.foreground_group = Some(pgid);
        Ok(())
    }

    /// Set controlling port
    pub fn set_controlling_port(&mut self, port: String) {
        self.controlling_port = Some(port);
    }
}

// =============================================================================
// Namespace Manager
// =============================================================================

/// Namespace Manager — manages all namespaces, groups, and sessions
#[derive(Debug, Default)]
pub struct NamespaceManager {
    /// Namespaces by ID
    namespaces: HashMap<NamespaceId, PidNamespace>,
    /// Process groups by PGID
    groups: HashMap<Pgid, ProcessGroup>,
    /// Sessions by SID
    sessions: HashMap<Sid, Session>,
    /// PID to namespace mapping
    pid_namespace: HashMap<Pid, NamespaceId>,
    /// PID to PGID mapping
    pid_group: HashMap<Pid, Pgid>,
    /// PID to SID mapping
    pid_session: HashMap<Pid, Sid>,
}

impl NamespaceManager {
    pub fn new() -> Self {
        let mut manager = Self::default();
        // Create global namespace
        let global = PidNamespace::global();
        manager.namespaces.insert(global.id.clone(), global);
        manager
    }

    /// Create a new namespace
    pub fn create_namespace(&mut self, ns_type: NamespaceType, parent: Option<&str>) -> NamespaceId {
        let parent_id = parent.map(|p| p.to_string());
        let ns = PidNamespace::new(ns_type, parent_id.clone());
        let id = ns.id.clone();

        // Add to parent's children
        if let Some(ref parent_id) = parent_id {
            if let Some(parent_ns) = self.namespaces.get_mut(parent_id) {
                parent_ns.children.push(id.clone());
            }
        }

        self.namespaces.insert(id.clone(), ns);
        id
    }

    /// Get namespace
    pub fn get_namespace(&self, id: &str) -> Option<&PidNamespace> {
        self.namespaces.get(id)
    }

    /// Get mutable namespace
    pub fn get_namespace_mut(&mut self, id: &str) -> Option<&mut PidNamespace> {
        self.namespaces.get_mut(id)
    }

    /// Register a process in a namespace
    pub fn register_process(&mut self, global_pid: Pid, namespace_id: &str) -> Result<LocalPid, String> {
        let ns = self.namespaces.get_mut(namespace_id)
            .ok_or_else(|| format!("Namespace {} not found", namespace_id))?;

        let local_pid = ns.allocate(global_pid.clone());
        self.pid_namespace.insert(global_pid, namespace_id.to_string());

        Ok(local_pid)
    }

    /// Unregister a process
    pub fn unregister_process(&mut self, global_pid: &Pid) {
        if let Some(ns_id) = self.pid_namespace.remove(global_pid) {
            if let Some(ns) = self.namespaces.get_mut(&ns_id) {
                ns.deallocate(global_pid);
            }
        }

        // Remove from group
        if let Some(pgid) = self.pid_group.remove(global_pid) {
            if let Some(group) = self.groups.get_mut(&pgid) {
                group.remove_member(global_pid);
                if group.is_empty() {
                    self.groups.remove(&pgid);
                }
            }
        }

        self.pid_session.remove(global_pid);
    }

    /// Get process's namespace
    pub fn get_process_namespace(&self, pid: &Pid) -> Option<&PidNamespace> {
        self.pid_namespace.get(pid)
            .and_then(|ns_id| self.namespaces.get(ns_id))
    }

    /// Translate PID for a namespace
    pub fn translate_pid(&self, global_pid: &Pid, namespace_id: &str) -> Option<LocalPid> {
        self.namespaces.get(namespace_id)
            .and_then(|ns| ns.translate(global_pid))
    }

    /// Resolve local PID to global PID
    pub fn resolve_pid(&self, local_pid: LocalPid, namespace_id: &str) -> Option<Pid> {
        self.namespaces.get(namespace_id)
            .and_then(|ns| ns.resolve(local_pid))
            .cloned()
    }

    // === Process Groups ===

    /// Create a new process group
    pub fn create_group(&mut self, leader: Pid, session: Sid) -> Pgid {
        let group = ProcessGroup::new(leader.clone(), session.clone());
        let pgid = group.pgid.clone();

        self.groups.insert(pgid.clone(), group);
        self.pid_group.insert(leader, pgid.clone());

        // Add to session
        if let Some(sess) = self.sessions.get_mut(&session) {
            sess.add_group(pgid.clone());
        }

        pgid
    }

    /// Set process group (setpgid)
    pub fn setpgid(&mut self, pid: Pid, pgid: Pgid) -> Result<(), String> {
        // Remove from old group
        if let Some(old_pgid) = self.pid_group.get(&pid).cloned() {
            if let Some(old_group) = self.groups.get_mut(&old_pgid) {
                old_group.remove_member(&pid);
                if old_group.is_empty() {
                    self.groups.remove(&old_pgid);
                }
            }
        }

        // Add to new group
        let group = self.groups.get_mut(&pgid)
            .ok_or_else(|| format!("Group {} not found", pgid))?;
        group.add_member(pid.clone());
        self.pid_group.insert(pid, pgid);

        Ok(())
    }

    /// Get process group (getpgid)
    pub fn getpgid(&self, pid: &Pid) -> Option<&Pgid> {
        self.pid_group.get(pid)
    }

    /// Get process group
    pub fn get_group(&self, pgid: &Pgid) -> Option<&ProcessGroup> {
        self.groups.get(pgid)
    }

    // === Sessions ===

    /// Create a new session (setsid)
    pub fn setsid(&mut self, leader: Pid) -> Result<Sid, String> {
        // Check if already a session leader
        if self.sessions.values().any(|s| s.leader == leader) {
            return Err("Already a session leader".into());
        }

        let session = Session::new(leader.clone());
        let sid = session.sid.clone();

        // Create initial process group
        let pgid = format!("pgid:{}", leader.trim_start_matches("pid:"));
        let group = ProcessGroup::new(leader.clone(), sid.clone());
        self.groups.insert(pgid.clone(), group);
        self.pid_group.insert(leader.clone(), pgid);

        self.sessions.insert(sid.clone(), session);
        self.pid_session.insert(leader, sid.clone());

        Ok(sid)
    }

    /// Get session (getsid)
    pub fn getsid(&self, pid: &Pid) -> Option<&Sid> {
        self.pid_session.get(pid)
    }

    /// Get session
    pub fn get_session(&self, sid: &Sid) -> Option<&Session> {
        self.sessions.get(sid)
    }

    /// Get mutable session
    pub fn get_session_mut(&mut self, sid: &Sid) -> Option<&mut Session> {
        self.sessions.get_mut(sid)
    }

    /// List all namespaces
    pub fn list_namespaces(&self) -> Vec<&PidNamespace> {
        self.namespaces.values().collect()
    }

    /// List all groups
    pub fn list_groups(&self) -> Vec<&ProcessGroup> {
        self.groups.values().collect()
    }

    /// List all sessions
    pub fn list_sessions(&self) -> Vec<&Session> {
        self.sessions.values().collect()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pid_namespace() {
        let mut ns = PidNamespace::new(NamespaceType::Cell, Some("ns:global".into()));

        let local1 = ns.allocate("pid:001".into());
        let local2 = ns.allocate("pid:002".into());

        assert_eq!(local1, 1); // First is init
        assert_eq!(local2, 2);
        assert_eq!(ns.init_pid, Some("pid:001".into()));

        assert_eq!(ns.translate(&"pid:001".into()), Some(1));
        assert_eq!(ns.resolve(2), Some(&"pid:002".into()));

        ns.deallocate(&"pid:001".into());
        assert_eq!(ns.translate(&"pid:001".into()), None);
    }

    #[test]
    fn test_process_group() {
        let mut group = ProcessGroup::new("pid:001".into(), "sid:001".into());

        assert_eq!(group.leader, "pid:001");
        assert!(group.is_member(&"pid:001".into()));

        group.add_member("pid:002".into());
        assert!(group.is_member(&"pid:002".into()));
        assert_eq!(group.members.len(), 2);

        group.remove_member(&"pid:002".into());
        assert!(!group.is_member(&"pid:002".into()));
    }

    #[test]
    fn test_session() {
        let mut session = Session::new("pid:001".into());

        assert_eq!(session.leader, "pid:001");
        assert!(session.groups.len() >= 1);

        session.add_group("pgid:002".into());
        assert!(session.groups.contains(&"pgid:002".into()));

        session.set_foreground("pgid:002".into()).unwrap();
        assert_eq!(session.foreground_group, Some("pgid:002".into()));
    }

    #[test]
    fn test_namespace_manager() {
        let mut manager = NamespaceManager::new();

        // Create cell namespace
        let cell_ns = manager.create_namespace(NamespaceType::Cell, Some("ns:global"));

        // Register processes
        let local1 = manager.register_process("pid:001".into(), &cell_ns).unwrap();
        let local2 = manager.register_process("pid:002".into(), &cell_ns).unwrap();

        assert_eq!(local1, 1);
        assert_eq!(local2, 2);

        // Translate
        assert_eq!(manager.translate_pid(&"pid:001".into(), &cell_ns), Some(1));
        assert_eq!(manager.resolve_pid(2, &cell_ns), Some("pid:002".into()));
    }

    #[test]
    fn test_process_groups_and_sessions() {
        let mut manager = NamespaceManager::new();

        // Create session
        let sid = manager.setsid("pid:001".into()).unwrap();
        assert!(manager.getsid(&"pid:001".into()).is_some());

        // Create another group in session
        let pgid = manager.create_group("pid:002".into(), sid.clone());
        manager.setpgid("pid:003".into(), pgid.clone()).unwrap();

        let group = manager.get_group(&pgid).unwrap();
        assert!(group.is_member(&"pid:002".into()));
        assert!(group.is_member(&"pid:003".into()));
    }

    #[test]
    fn test_nested_namespaces() {
        let mut manager = NamespaceManager::new();

        let cell_ns = manager.create_namespace(NamespaceType::Cell, Some("ns:global"));
        let sandbox_ns = manager.create_namespace(NamespaceType::Sandbox, Some(&cell_ns));

        // Same global PID can have different local PIDs in different namespaces
        manager.register_process("pid:001".into(), &cell_ns).unwrap();
        manager.register_process("pid:001".into(), &sandbox_ns).unwrap();

        // Both namespaces see pid:001 as local PID 1
        assert_eq!(manager.translate_pid(&"pid:001".into(), &cell_ns), Some(1));
        assert_eq!(manager.translate_pid(&"pid:001".into(), &sandbox_ns), Some(1));

        // Check parent-child relationship
        let cell = manager.get_namespace(&cell_ns).unwrap();
        assert!(cell.children.contains(&sandbox_ns));
    }
}
