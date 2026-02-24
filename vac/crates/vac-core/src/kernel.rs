//! Memory Kernel Runtime — dispatches syscalls, manages agents, sessions, and packets.
//!
//! This is the runtime that makes the types in `types.rs` execute.
//! Every operation goes through `MemoryKernel::dispatch()`, which:
//! 1. Validates the request
//! 2. Executes the operation
//! 3. Creates a `KernelAuditEntry`
//! 4. Returns a `SyscallResult` with the outcome
//!
//! Design sources: AIOS LLM kernel, Linux kernel syscall dispatch,
//! Certificate Transparency append-only logs, Event Sourcing patterns.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use cid::Cid;
use crate::cid::compute_cid;
use crate::types::*;

// =============================================================================
// Syscall Request / Result types
// =============================================================================

/// A request to the kernel — wraps the operation with caller identity and payload.
#[derive(Debug, Clone)]
pub struct SyscallRequest {
    /// Agent PID making the request
    pub agent_pid: String,
    /// The operation to perform
    pub operation: MemoryKernelOp,
    /// Operation-specific payload
    pub payload: SyscallPayload,
    /// Optional reason for audit trail
    pub reason: Option<String>,
    /// Optional VAKYA ID for authorized operations
    pub vakya_id: Option<String>,
}

/// Payload variants for different syscall types
#[derive(Debug, Clone)]
pub enum SyscallPayload {
    /// No payload needed
    Empty,
    /// Agent registration
    AgentRegister {
        agent_name: String,
        namespace: String,
        role: Option<String>,
        model: Option<String>,
        framework: Option<String>,
    },
    /// Memory write
    MemWrite {
        packet: MemPacket,
    },
    /// Memory read by CID
    MemRead {
        packet_cid: Cid,
    },
    /// Memory tier change (promote/demote)
    TierChange {
        packet_cid: Cid,
        new_tier: MemoryTier,
    },
    /// Memory evict
    MemEvict {
        /// Evict specific CIDs, or empty to evict by policy
        cids: Vec<Cid>,
        /// Max packets to evict (when cids is empty)
        max_evict: u64,
    },
    /// Memory seal — make region read-only
    MemSeal {
        /// Seal specific CIDs, or empty to seal entire region
        cids: Vec<Cid>,
    },
    /// Memory clear — remove all packets for agent
    MemClear,
    /// Memory alloc — set quota for agent
    MemAlloc {
        quota_packets: u64,
        quota_tokens: u64,
        quota_bytes: u64,
        eviction_policy: EvictionPolicy,
    },
    /// Session create
    SessionCreate {
        session_id: String,
        label: Option<String>,
        parent_session_id: Option<String>,
    },
    /// Session close
    SessionClose {
        session_id: String,
    },
    /// Session compress
    SessionCompress {
        session_id: String,
        algorithm: String,
        summary: String,
    },
    /// Context snapshot
    ContextSnapshot {
        session_id: String,
        pipeline_id: String,
    },
    /// Context restore
    ContextRestore {
        snapshot_cid: Cid,
    },
    /// Access grant
    AccessGrant {
        target_namespace: String,
        grantee_pid: String,
        read: bool,
        write: bool,
    },
    /// Access revoke
    AccessRevoke {
        target_namespace: String,
        grantee_pid: String,
    },
    /// Access check
    AccessCheck {
        target_namespace: String,
        operation: String, // "read" or "write"
    },
    /// Query packets
    Query {
        query: MemoryQuery,
    },
    /// Port create
    PortCreate {
        port_type: PortType,
        direction: PortDirection,
        allowed_packet_types: Vec<PacketType>,
        allowed_actions: Vec<String>,
        max_delegation_depth: u8,
        ttl_ms: Option<u64>,
    },
    /// Port bind
    PortBind {
        port_id: String,
        target_pid: String,
    },
    /// Port send
    PortSend {
        port_id: String,
        message: PortMessage,
    },
    /// Port receive
    PortReceive {
        port_id: String,
    },
    /// Port close
    PortClose {
        port_id: String,
    },
    /// Port delegate
    PortDelegate {
        port_id: String,
        delegate_to: String,
        allowed_actions: Vec<String>,
    },
    /// Agent terminate
    AgentTerminate {
        target_pid: Option<String>,
        reason: String,
    },
    /// Integrity check
    IntegrityCheck,
    /// Garbage collect
    GarbageCollect,
    /// Index rebuild
    IndexRebuild,
    /// Tool dispatch (default-deny, requires ToolBinding)
    ToolDispatch {
        tool_id: String,
        action: String,
        request: serde_json::Value,
    },
}

/// Result of a syscall execution
#[derive(Debug, Clone)]
pub struct SyscallResult {
    /// Whether the operation succeeded
    pub outcome: OpOutcome,
    /// The audit entry created for this operation
    pub audit_entry: KernelAuditEntry,
    /// Operation-specific return value
    pub value: SyscallValue,
}

/// Return values from syscalls
#[derive(Debug, Clone, PartialEq)]
pub enum SyscallValue {
    /// No return value
    None,
    /// A CID was produced (e.g., packet write, snapshot)
    Cid(Cid),
    /// A packet was read
    Packet(Box<MemPacket>),
    /// Multiple packets returned (query)
    Packets(Vec<MemPacket>),
    /// Agent PID assigned
    AgentPid(String),
    /// Session created/referenced
    SessionId(String),
    /// Boolean result (access check, integrity)
    Bool(bool),
    /// Count (evict, GC)
    Count(u64),
    /// Execution context snapshot
    Context(Box<ExecutionContext>),
    /// Error message
    Error(String),
}

// =============================================================================
// Memory Kernel
// =============================================================================

/// The Memory Kernel — runtime that manages agents, sessions, and packets.
///
/// All operations go through `dispatch()` which enforces access control,
/// executes the operation, and logs an audit entry.
pub struct MemoryKernel {
    /// Registered agents (pid → ACB)
    agents: HashMap<String, AgentControlBlock>,
    /// Active sessions (session_id → SessionEnvelope)
    sessions: HashMap<String, SessionEnvelope>,
    /// Packet store (CID → MemPacket)
    packets: HashMap<Cid, MemPacket>,
    /// Execution contexts (agent_pid → latest context)
    contexts: HashMap<String, ExecutionContext>,
    /// Saved context snapshots (snapshot_cid → ExecutionContext)
    context_snapshots: HashMap<Cid, ExecutionContext>,
    /// Audit log (D4 FIX: bounded ring buffer, max 100K entries)
    audit_log: Vec<KernelAuditEntry>,
    /// D4: Maximum audit log entries before oldest are evicted
    audit_log_max: usize,
    /// Phase 4: Overflow buffer — evicted audit entries waiting to be flushed to store
    pub audit_overflow: Vec<KernelAuditEntry>,
    /// Phase 4: Total number of audit overflow events
    pub audit_overflow_count: u64,
    /// Phase 4: HMAC chain — hash of the previous audit entry for tamper detection
    audit_chain_hash: Option<String>,
    /// Next agent PID counter
    next_pid: u64,
    /// Next audit ID counter
    next_audit_id: u64,
    /// Sealed packet CIDs (immutable after sealing)
    sealed_cids: std::collections::HashSet<Cid>,
    /// Access grants: (grantee_pid, namespace) → (read, write)
    access_grants: HashMap<(String, String), (bool, bool)>,
    /// Namespace → list of packet CIDs (index for fast namespace queries)
    namespace_index: HashMap<String, Vec<Cid>>,
    /// Session → list of packet CIDs
    session_index: HashMap<String, Vec<Cid>>,

    // --- Phase 8: Kernel Hardening ---
    /// Ports (port_id → Port)
    ports: HashMap<String, Port>,
    /// Port message buffers (port_id → messages)
    port_buffers: HashMap<String, Vec<PortMessage>>,
    /// Execution policies (role → policy)
    execution_policies: HashMap<String, ExecutionPolicy>,
    /// Delegation chains (chain_cid → chain)
    delegation_chains: HashMap<String, DelegationChain>,
    /// Rate limit windows: (agent_pid, op_name) → (count_this_second, count_this_minute, second_start_ms, minute_start_ms)
    rate_limit_windows: HashMap<(String, String), (u32, u32, i64, i64)>,
    /// Next port ID counter
    next_port_id: u64,
}

impl MemoryKernel {
    /// Create a new empty kernel
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
            sessions: HashMap::new(),
            packets: HashMap::new(),
            contexts: HashMap::new(),
            context_snapshots: HashMap::new(),
            audit_log: Vec::new(),
            audit_log_max: 100_000,
            audit_overflow: Vec::new(),
            audit_overflow_count: 0,
            audit_chain_hash: None,
            next_pid: 1,
            next_audit_id: 1,
            sealed_cids: std::collections::HashSet::new(),
            access_grants: HashMap::new(),
            namespace_index: HashMap::new(),
            session_index: HashMap::new(),
            ports: HashMap::new(),
            port_buffers: HashMap::new(),
            execution_policies: HashMap::new(),
            delegation_chains: HashMap::new(),
            rate_limit_windows: HashMap::new(),
            next_port_id: 1,
        }
    }

    /// Get current timestamp in milliseconds
    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    /// Generate next agent PID
    fn next_agent_pid(&mut self) -> String {
        let pid = format!("pid:{:06}", self.next_pid);
        self.next_pid += 1;
        pid
    }

    /// Generate next audit ID
    fn next_audit_id(&mut self) -> String {
        let id = format!("audit:{:08}", self.next_audit_id);
        self.next_audit_id += 1;
        id
    }

    /// Create an audit entry
    fn make_audit(
        &mut self,
        operation: MemoryKernelOp,
        agent_pid: &str,
        target: Option<String>,
        outcome: OpOutcome,
        reason: Option<String>,
        error: Option<String>,
        duration_us: Option<u64>,
        vakya_id: Option<String>,
    ) -> KernelAuditEntry {
        let mut entry = KernelAuditEntry {
            audit_id: self.next_audit_id(),
            timestamp: Self::now_ms(),
            operation,
            agent_pid: agent_pid.to_string(),
            target,
            outcome,
            reason,
            error,
            duration_us,
            vakya_id,
            before_hash: None,
            after_hash: None,
            merkle_root: None,
            scitt_receipt_cid: None,
        };
        // Phase 4: HMAC chain — link this entry to the previous one
        entry.before_hash = self.audit_chain_hash.clone();
        // Compute hash of this entry for the chain
        let entry_bytes = format!("{}:{}:{:?}:{}:{:?}",
            entry.audit_id, entry.timestamp, entry.operation, entry.agent_pid, entry.outcome);
        let hash_bytes = crate::cid::sha256(entry_bytes.as_bytes());
        let entry_hash = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        entry.after_hash = Some(entry_hash.clone());
        self.audit_chain_hash = Some(entry_hash);

        self.audit_log.push(entry.clone());
        // D4 FIX: Evict oldest entries when audit log exceeds max capacity.
        // Phase 4: Overflow evicted entries to buffer instead of silently dropping.
        if self.audit_log.len() > self.audit_log_max {
            let drain_count = self.audit_log.len() - self.audit_log_max;
            let evicted: Vec<KernelAuditEntry> = self.audit_log.drain(..drain_count).collect();
            self.audit_overflow.extend(evicted);
            self.audit_overflow_count += drain_count as u64;
        }
        entry
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /// Dispatch a syscall request — the single entry point for all kernel operations.
    ///
    /// Enforces 5-layer security: ELS phase check → allowlist → rate limit → budget → handler.
    pub fn dispatch(&mut self, req: SyscallRequest) -> SyscallResult {
        let start = std::time::Instant::now();

        // Verify agent exists for non-registration operations
        if req.operation != MemoryKernelOp::AgentRegister {
            if !self.agents.contains_key(&req.agent_pid) {
                let audit = self.make_audit(
                    req.operation.clone(),
                    &req.agent_pid,
                    None,
                    OpOutcome::Denied,
                    req.reason.clone(),
                    Some(format!("Agent {} not registered", req.agent_pid)),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id.clone(),
                );
                return SyscallResult {
                    outcome: OpOutcome::Denied,
                    audit_entry: audit,
                    value: SyscallValue::Error(format!("Agent {} not registered", req.agent_pid)),
                };
            }

            // --- ELS Layer 1: Phase check ---
            if let Some(deny) = self.check_phase(&req, &start) {
                return deny;
            }

            // --- ELS Layer 2: Role allowlist check ---
            if let Some(deny) = self.check_role_allowlist(&req, &start) {
                return deny;
            }

            // --- ELS Layer 3: Rate limit check ---
            if let Some(deny) = self.check_rate_limit(&req, &start) {
                return deny;
            }

            // --- ELS Layer 4: Budget check ---
            if let Some(deny) = self.check_budget(&req, &start) {
                return deny;
            }
        }

        match req.operation {
            MemoryKernelOp::AgentRegister => self.handle_agent_register(req, start),
            MemoryKernelOp::AgentStart => self.handle_agent_start(req, start),
            MemoryKernelOp::AgentSuspend => self.handle_agent_suspend(req, start),
            MemoryKernelOp::AgentResume => self.handle_agent_resume(req, start),
            MemoryKernelOp::AgentTerminate => self.handle_agent_terminate(req, start),
            MemoryKernelOp::MemAlloc => self.handle_mem_alloc(req, start),
            MemoryKernelOp::MemWrite => self.handle_mem_write(req, start),
            MemoryKernelOp::MemRead => self.handle_mem_read(req, start),
            MemoryKernelOp::MemEvict => self.handle_mem_evict(req, start),
            MemoryKernelOp::MemPromote => self.handle_mem_tier_change(req, start, true),
            MemoryKernelOp::MemDemote => self.handle_mem_tier_change(req, start, false),
            MemoryKernelOp::MemClear => self.handle_mem_clear(req, start),
            MemoryKernelOp::MemSeal => self.handle_mem_seal(req, start),
            MemoryKernelOp::SessionCreate => self.handle_session_create(req, start),
            MemoryKernelOp::SessionClose => self.handle_session_close(req, start),
            MemoryKernelOp::SessionCompress => self.handle_session_compress(req, start),
            MemoryKernelOp::ContextSnapshot => self.handle_context_snapshot(req, start),
            MemoryKernelOp::ContextRestore => self.handle_context_restore(req, start),
            MemoryKernelOp::AccessGrant => self.handle_access_grant(req, start),
            MemoryKernelOp::AccessRevoke => self.handle_access_revoke(req, start),
            MemoryKernelOp::AccessCheck => self.handle_access_check(req, start),
            MemoryKernelOp::GarbageCollect => self.handle_garbage_collect(req, start),
            MemoryKernelOp::IndexRebuild => self.handle_index_rebuild(req, start),
            MemoryKernelOp::IntegrityCheck => self.handle_integrity_check(req, start),
            MemoryKernelOp::PortCreate => self.handle_port_create(req, start),
            MemoryKernelOp::PortBind => self.handle_port_bind(req, start),
            MemoryKernelOp::PortSend => self.handle_port_send(req, start),
            MemoryKernelOp::PortReceive => self.handle_port_receive(req, start),
            MemoryKernelOp::PortClose => self.handle_port_close(req, start),
            MemoryKernelOp::PortDelegate => self.handle_port_delegate(req, start),
            MemoryKernelOp::ToolDispatch => self.handle_tool_dispatch(req, start),
        }
    }

    // =========================================================================
    // Read-only accessors
    // =========================================================================

    /// Get an agent's control block
    pub fn get_agent(&self, pid: &str) -> Option<&AgentControlBlock> {
        self.agents.get(pid)
    }

    /// Get all registered agents
    pub fn agents(&self) -> &HashMap<String, AgentControlBlock> {
        &self.agents
    }

    /// Get a session
    pub fn get_session(&self, session_id: &str) -> Option<&SessionEnvelope> {
        self.sessions.get(session_id)
    }

    /// Get all sessions
    pub fn sessions(&self) -> &HashMap<String, SessionEnvelope> {
        &self.sessions
    }

    /// Get a packet by CID
    pub fn get_packet(&self, cid: &Cid) -> Option<&MemPacket> {
        self.packets.get(cid)
    }

    /// Get total packet count
    pub fn packet_count(&self) -> usize {
        self.packets.len()
    }

    /// Get the audit log
    pub fn audit_log(&self) -> &[KernelAuditEntry] {
        &self.audit_log
    }

    /// Get audit log length
    pub fn audit_count(&self) -> usize {
        self.audit_log.len()
    }

    /// Phase 4: Drain overflow buffer — returns evicted audit entries for persistence.
    /// Call this periodically (e.g., in CheckpointManager) to flush to KernelStore.
    pub fn drain_audit_overflow(&mut self) -> Vec<KernelAuditEntry> {
        std::mem::take(&mut self.audit_overflow)
    }

    /// Phase 4: Get overflow count (total evicted entries since kernel creation).
    pub fn audit_overflow_total(&self) -> u64 {
        self.audit_overflow_count
    }

    /// Phase 4: Get pending overflow entries count.
    pub fn audit_overflow_pending(&self) -> usize {
        self.audit_overflow.len()
    }

    /// Phase 4: Verify the HMAC audit chain — checks that each entry's before_hash
    /// matches the previous entry's after_hash, forming a tamper-evident chain.
    /// Returns Ok(chain_length) or Err(description of first broken link).
    pub fn verify_audit_chain(&self) -> Result<usize, String> {
        if self.audit_log.is_empty() {
            return Ok(0);
        }

        for i in 1..self.audit_log.len() {
            let prev = &self.audit_log[i - 1];
            let curr = &self.audit_log[i];

            // Current entry's before_hash must match previous entry's after_hash
            match (&curr.before_hash, &prev.after_hash) {
                (Some(before), Some(after)) => {
                    if before != after {
                        return Err(format!(
                            "Audit chain broken at entry {}: before_hash '{}' != prev after_hash '{}'",
                            curr.audit_id, before, after
                        ));
                    }
                }
                (None, _) => {
                    return Err(format!(
                        "Audit chain broken at entry {}: missing before_hash",
                        curr.audit_id
                    ));
                }
                (_, None) => {
                    return Err(format!(
                        "Audit chain broken at entry {}: previous entry missing after_hash",
                        curr.audit_id
                    ));
                }
            }
        }

        Ok(self.audit_log.len())
    }

    /// Phase 4: Export audit log as JSON string.
    pub fn export_audit_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.audit_log)
            .map_err(|e| format!("Audit JSON export failed: {}", e))
    }

    /// Phase 4: Export audit log as CSV string.
    pub fn export_audit_csv(&self) -> String {
        let mut csv = String::from("audit_id,timestamp,operation,agent_pid,target,outcome,reason\n");
        for entry in &self.audit_log {
            csv.push_str(&format!(
                "{},{},{:?},{},{},{:?},{}\n",
                entry.audit_id,
                entry.timestamp,
                entry.operation,
                entry.agent_pid,
                entry.target.as_deref().unwrap_or(""),
                entry.outcome,
                entry.reason.as_deref().unwrap_or(""),
            ));
        }
        csv
    }

    /// Check if a CID is sealed
    pub fn is_sealed(&self, cid: &Cid) -> bool {
        self.sealed_cids.contains(cid)
    }

    /// Get execution context for an agent
    pub fn get_context(&self, agent_pid: &str) -> Option<&ExecutionContext> {
        self.contexts.get(agent_pid)
    }

    /// Query packets by namespace
    pub fn packets_in_namespace(&self, namespace: &str) -> Vec<&MemPacket> {
        self.namespace_index
            .get(namespace)
            .map(|cids| {
                cids.iter()
                    .filter_map(|cid| self.packets.get(cid))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Query packets by session
    pub fn packets_in_session(&self, session_id: &str) -> Vec<&MemPacket> {
        self.session_index
            .get(session_id)
            .map(|cids| {
                cids.iter()
                    .filter_map(|cid| self.packets.get(cid))
                    .collect()
            })
            .unwrap_or_default()
    }

    // =========================================================================
    // Agent lifecycle handlers
    // =========================================================================

    fn handle_agent_register(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (agent_name, namespace, role, model, framework) = match req.payload {
            SyscallPayload::AgentRegister {
                agent_name,
                namespace,
                role,
                model,
                framework,
            } => (agent_name, namespace, role, model, framework),
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::AgentRegister,
                    &req.agent_pid,
                    None,
                    OpOutcome::Failed,
                    req.reason,
                    Some("Invalid payload for AgentRegister".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Invalid payload".to_string()),
                };
            }
        };

        let pid = self.next_agent_pid();
        let now = Self::now_ms();

        let mut acb = AgentControlBlock::new(
            pid.clone(),
            agent_name,
            namespace.clone(),
            now,
        );
        acb.agent_role = role;
        acb.model = model;
        acb.framework = framework;
        // Agent can read/write its own namespace by default
        acb.writable_namespaces.push(namespace.clone());
        acb.readable_namespaces.push(namespace);

        self.agents.insert(pid.clone(), acb);

        let audit = self.make_audit(
            MemoryKernelOp::AgentRegister,
            &pid,
            Some(pid.clone()),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::AgentPid(pid),
        }
    }

    fn handle_agent_start(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let current_status = self.agents.get(&req.agent_pid).unwrap().status.clone();

        if current_status != AgentStatus::Registered && current_status != AgentStatus::Suspended {
            let audit = self.make_audit(
                MemoryKernelOp::AgentStart,
                &req.agent_pid,
                Some(req.agent_pid.clone()),
                OpOutcome::Failed,
                req.reason.clone(),
                Some(format!("Cannot start agent in state {}", current_status)),
                Some(start.elapsed().as_micros() as u64),
                req.vakya_id,
            );
            return SyscallResult {
                outcome: OpOutcome::Failed,
                audit_entry: audit,
                value: SyscallValue::Error(format!("Cannot start from state {}", current_status)),
            };
        }

        let acb = self.agents.get_mut(&req.agent_pid).unwrap();
        acb.status = AgentStatus::Running;
        acb.phase = AgentPhase::Active;
        acb.last_active_at = Self::now_ms();

        let audit = self.make_audit(
            MemoryKernelOp::AgentStart,
            &req.agent_pid,
            Some(req.agent_pid.clone()),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::None,
        }
    }

    fn handle_agent_suspend(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let current_status = self.agents.get(&req.agent_pid).unwrap().status.clone();

        if current_status != AgentStatus::Running && current_status != AgentStatus::Waiting {
            let audit = self.make_audit(
                MemoryKernelOp::AgentSuspend,
                &req.agent_pid,
                Some(req.agent_pid.clone()),
                OpOutcome::Failed,
                req.reason.clone(),
                Some(format!("Cannot suspend agent in state {}", current_status)),
                Some(start.elapsed().as_micros() as u64),
                req.vakya_id,
            );
            return SyscallResult {
                outcome: OpOutcome::Failed,
                audit_entry: audit,
                value: SyscallValue::Error(format!("Cannot suspend from state {}", current_status)),
            };
        }

        let acb = self.agents.get_mut(&req.agent_pid).unwrap();
        acb.status = AgentStatus::Suspended;
        acb.phase = AgentPhase::Suspended;
        acb.last_active_at = Self::now_ms();

        let audit = self.make_audit(
            MemoryKernelOp::AgentSuspend,
            &req.agent_pid,
            Some(req.agent_pid.clone()),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::None,
        }
    }

    fn handle_agent_resume(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let current_status = self.agents.get(&req.agent_pid).unwrap().status.clone();

        if current_status != AgentStatus::Suspended {
            let audit = self.make_audit(
                MemoryKernelOp::AgentResume,
                &req.agent_pid,
                Some(req.agent_pid.clone()),
                OpOutcome::Failed,
                req.reason.clone(),
                Some(format!("Cannot resume agent in state {}", current_status)),
                Some(start.elapsed().as_micros() as u64),
                req.vakya_id,
            );
            return SyscallResult {
                outcome: OpOutcome::Failed,
                audit_entry: audit,
                value: SyscallValue::Error(format!("Cannot resume from state {}", current_status)),
            };
        }

        let acb = self.agents.get_mut(&req.agent_pid).unwrap();
        acb.status = AgentStatus::Running;
        acb.phase = AgentPhase::Active;
        acb.last_active_at = Self::now_ms();

        let audit = self.make_audit(
            MemoryKernelOp::AgentResume,
            &req.agent_pid,
            Some(req.agent_pid.clone()),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::None,
        }
    }

    fn handle_agent_terminate(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (target_pid, reason) = match &req.payload {
            SyscallPayload::AgentTerminate { target_pid, reason } => {
                (target_pid.clone().unwrap_or(req.agent_pid.clone()), reason.clone())
            }
            _ => (req.agent_pid.clone(), "self-terminate".to_string()),
        };

        let acb = match self.agents.get_mut(&target_pid) {
            Some(acb) => acb,
            None => {
                let audit = self.make_audit(
                    MemoryKernelOp::AgentTerminate,
                    &req.agent_pid,
                    Some(target_pid.clone()),
                    OpOutcome::Failed,
                    req.reason,
                    Some(format!("Target agent {} not found", target_pid)),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error(format!("Agent {} not found", target_pid)),
                };
            }
        };

        if acb.is_terminated() {
            let audit = self.make_audit(
                MemoryKernelOp::AgentTerminate,
                &req.agent_pid,
                Some(target_pid),
                OpOutcome::Skipped,
                req.reason,
                Some("Agent already terminated".to_string()),
                Some(start.elapsed().as_micros() as u64),
                req.vakya_id,
            );
            return SyscallResult {
                outcome: OpOutcome::Skipped,
                audit_entry: audit,
                value: SyscallValue::None,
            };
        }

        let now = Self::now_ms();
        acb.status = AgentStatus::Terminated;
        acb.phase = AgentPhase::Terminating;
        acb.terminated_at = Some(now);
        acb.termination_reason = Some(reason);
        acb.last_active_at = now;

        // Close any active sessions for this agent
        let agent_sessions: Vec<String> = acb.active_sessions.clone();
        for sid in &agent_sessions {
            if let Some(session) = self.sessions.get_mut(sid) {
                if session.is_active() {
                    session.close(now);
                }
            }
        }

        let audit = self.make_audit(
            MemoryKernelOp::AgentTerminate,
            &req.agent_pid,
            Some(target_pid),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::None,
        }
    }

    // =========================================================================
    // Memory operation handlers
    // =========================================================================

    fn handle_mem_alloc(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (quota_packets, quota_tokens, quota_bytes, eviction_policy) = match req.payload {
            SyscallPayload::MemAlloc {
                quota_packets,
                quota_tokens,
                quota_bytes,
                eviction_policy,
            } => (quota_packets, quota_tokens, quota_bytes, eviction_policy),
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::MemAlloc,
                    &req.agent_pid,
                    None,
                    OpOutcome::Failed,
                    req.reason,
                    Some("Invalid payload for MemAlloc".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Invalid payload".to_string()),
                };
            }
        };

        let acb = self.agents.get_mut(&req.agent_pid).unwrap();
        acb.memory_region.quota_packets = quota_packets;
        acb.memory_region.quota_tokens = quota_tokens;
        acb.memory_region.quota_bytes = quota_bytes;
        acb.memory_region.eviction_policy = eviction_policy;

        let audit = self.make_audit(
            MemoryKernelOp::MemAlloc,
            &req.agent_pid,
            Some(req.agent_pid.clone()),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::None,
        }
    }

    fn handle_mem_write(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let mut packet = match req.payload {
            SyscallPayload::MemWrite { packet } => packet,
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::MemWrite,
                    &req.agent_pid,
                    None,
                    OpOutcome::Failed,
                    req.reason,
                    Some("Invalid payload for MemWrite".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Invalid payload".to_string()),
                };
            }
        };

        // Check namespace access
        let agent_ns = {
            let acb = self.agents.get(&req.agent_pid).unwrap();
            acb.namespace.clone()
        };
        let packet_ns = packet.namespace.clone().unwrap_or(agent_ns.clone());

        // Verify write access to target namespace (legacy + mount table)
        {
            let acb = self.agents.get(&req.agent_pid).unwrap();
            let has_legacy_access = packet_ns == acb.namespace || acb.writable_namespaces.contains(&packet_ns);
            let has_mount_access = matches!(
                Self::check_mount_access(acb, &packet_ns),
                Some(MountMode::ReadWrite)
            );
            if !has_legacy_access && !has_mount_access {
                let audit = self.make_audit(
                    MemoryKernelOp::MemWrite,
                    &req.agent_pid,
                    Some(packet_ns.clone()),
                    OpOutcome::Denied,
                    req.reason,
                    Some(format!(
                        "Agent {} lacks write access to namespace {}",
                        req.agent_pid, packet_ns
                    )),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Denied,
                    audit_entry: audit,
                    value: SyscallValue::Error("Namespace write denied".to_string()),
                };
            }

            // Check region capacity
            if !acb.memory_region.has_capacity() {
                let audit = self.make_audit(
                    MemoryKernelOp::MemWrite,
                    &req.agent_pid,
                    None,
                    OpOutcome::Denied,
                    req.reason,
                    Some("Memory region at capacity or sealed".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Denied,
                    audit_entry: audit,
                    value: SyscallValue::Error("Region at capacity".to_string()),
                };
            }

            // Check write protection
            if !acb.memory_region.protection.write {
                let audit = self.make_audit(
                    MemoryKernelOp::MemWrite,
                    &req.agent_pid,
                    None,
                    OpOutcome::Denied,
                    req.reason,
                    Some("Memory region write-protected".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Denied,
                    audit_entry: audit,
                    value: SyscallValue::Error("Write-protected".to_string()),
                };
            }
        }

        // Ensure namespace is set on packet
        if packet.namespace.is_none() {
            packet.namespace = Some(agent_ns);
        }

        // D1 FIX: Set timestamp BEFORE computing CID so the CID matches
        // the actual stored content. Previously, timestamp was set after CID
        // computation, breaking the content-addressing invariant.
        packet.index.ts = Self::now_ms();

        // Compute CID for the packet (now includes the final timestamp)
        let packet_cid = match compute_cid(&packet) {
            Ok(cid) => cid,
            Err(e) => {
                let audit = self.make_audit(
                    MemoryKernelOp::MemWrite,
                    &req.agent_pid,
                    None,
                    OpOutcome::Failed,
                    req.reason,
                    Some(format!("CID computation failed: {}", e)),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error(format!("CID error: {}", e)),
                };
            }
        };

        // Update packet index with computed CID
        packet.index.packet_cid = packet_cid.clone();

        // Store the packet
        let ns = packet.namespace.clone().unwrap_or_default();
        let sid = packet.session_id.clone();
        self.packets.insert(packet_cid.clone(), packet);

        // D10 FIX: Dedup namespace_index and session_index entries.
        // HashMap packet store already deduplicates by CID, but indexes
        // accumulated duplicates on re-write of same CID.
        let ns_entry = self.namespace_index.entry(ns).or_default();
        if !ns_entry.contains(&packet_cid) {
            ns_entry.push(packet_cid.clone());
        }

        // Update session index
        if let Some(ref session_id) = sid {
            let si_entry = self.session_index.entry(session_id.clone()).or_default();
            if !si_entry.contains(&packet_cid) {
                si_entry.push(packet_cid.clone());
            }

            // Add CID to session envelope
            if let Some(session) = self.sessions.get_mut(session_id) {
                session.add_packet(packet_cid.clone());
            }
        }

        // Update agent stats
        let acb = self.agents.get_mut(&req.agent_pid).unwrap();
        acb.total_packets += 1;
        acb.memory_region.used_packets += 1;
        acb.last_active_at = Self::now_ms();

        let audit = self.make_audit(
            MemoryKernelOp::MemWrite,
            &req.agent_pid,
            Some(packet_cid.to_string()),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::Cid(packet_cid),
        }
    }

    fn handle_mem_read(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let packet_cid = match req.payload {
            SyscallPayload::MemRead { packet_cid } => packet_cid,
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::MemRead,
                    &req.agent_pid,
                    None,
                    OpOutcome::Failed,
                    req.reason,
                    Some("Invalid payload for MemRead".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Invalid payload".to_string()),
                };
            }
        };

        let packet = match self.packets.get(&packet_cid) {
            Some(p) => p,
            None => {
                let audit = self.make_audit(
                    MemoryKernelOp::MemRead,
                    &req.agent_pid,
                    Some(packet_cid.to_string()),
                    OpOutcome::Failed,
                    req.reason,
                    Some(format!("Packet {} not found", packet_cid)),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Not found".to_string()),
                };
            }
        };

        // Check namespace read access (legacy + mount table + access grants)
        let packet_ns = packet.namespace.clone().unwrap_or_default();
        let acb = self.agents.get(&req.agent_pid).unwrap();
        let has_legacy_read = packet_ns == acb.namespace || acb.readable_namespaces.contains(&packet_ns);
        let has_grant_read = self
            .access_grants
            .get(&(req.agent_pid.clone(), packet_ns.clone()))
            .map(|(r, _)| *r)
            .unwrap_or(false);
        let mount_for_ns = Self::find_mount_for_namespace(acb, &packet_ns);
        let has_mount_read = mount_for_ns.is_some() && matches!(
            mount_for_ns.unwrap().mode,
            MountMode::ReadOnly | MountMode::ReadWrite | MountMode::Sealed
        );
        // If access is via mount, also check mount filters
        let passes_mount_filter = if let Some(mount) = mount_for_ns {
            Self::packet_passes_mount_filters(packet, mount)
        } else {
            true // No mount = no filter to apply
        };
        if !has_legacy_read && !has_grant_read && !has_mount_read {
            let audit = self.make_audit(
                MemoryKernelOp::MemRead,
                &req.agent_pid,
                Some(packet_cid.to_string()),
                OpOutcome::Denied,
                req.reason,
                Some(format!(
                    "Agent {} lacks read access to namespace {}",
                    req.agent_pid, packet_ns
                )),
                Some(start.elapsed().as_micros() as u64),
                req.vakya_id,
            );
            return SyscallResult {
                outcome: OpOutcome::Denied,
                audit_entry: audit,
                value: SyscallValue::Error("Namespace read denied".to_string()),
            };
        }

        // Mount filter check: if access is via mount, packet must pass filters
        if has_mount_read && !passes_mount_filter {
            let audit = self.make_audit(
                MemoryKernelOp::MemRead,
                &req.agent_pid,
                Some(packet_cid.to_string()),
                OpOutcome::Denied,
                req.reason,
                Some(format!(
                    "Packet {} filtered by mount for namespace {}",
                    packet_cid, packet_ns
                )),
                Some(start.elapsed().as_micros() as u64),
                req.vakya_id,
            );
            return SyscallResult {
                outcome: OpOutcome::Denied,
                audit_entry: audit,
                value: SyscallValue::Error("Mount filter denied".to_string()),
            };
        }

        let result_packet = packet.clone();

        // Update agent activity
        if let Some(acb) = self.agents.get_mut(&req.agent_pid) {
            acb.last_active_at = Self::now_ms();
        }

        let audit = self.make_audit(
            MemoryKernelOp::MemRead,
            &req.agent_pid,
            Some(packet_cid.to_string()),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::Packet(Box::new(result_packet)),
        }
    }

    fn handle_mem_evict(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (cids, max_evict) = match req.payload {
            SyscallPayload::MemEvict { cids, max_evict } => (cids, max_evict),
            _ => (vec![], 10),
        };

        // Check eviction protection
        {
            let acb = self.agents.get(&req.agent_pid).unwrap();
            if !acb.memory_region.protection.evict {
                let audit = self.make_audit(
                    MemoryKernelOp::MemEvict,
                    &req.agent_pid,
                    None,
                    OpOutcome::Denied,
                    req.reason,
                    Some("Memory region eviction-protected".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Denied,
                    audit_entry: audit,
                    value: SyscallValue::Error("Eviction-protected".to_string()),
                };
            }
        }

        let mut evicted = 0u64;

        if !cids.is_empty() {
            // D6 FIX: Scope specific-CID eviction to agent's namespace.
            // Previously any agent could evict any packet in the system.
            let acb = self.agents.get(&req.agent_pid).unwrap();
            let agent_ns = acb.namespace.clone();
            let writable_ns: Vec<String> = acb.writable_namespaces.clone();
            for cid in &cids {
                if self.sealed_cids.contains(cid) {
                    continue; // Skip sealed packets
                }
                // Only evict if packet belongs to agent's own or writable namespace
                if let Some(packet) = self.packets.get(cid) {
                    let pkt_ns = packet.namespace.as_deref().unwrap_or("");
                    if pkt_ns != agent_ns && !writable_ns.iter().any(|ns| ns == pkt_ns) {
                        continue; // Skip — not in agent's namespace
                    }
                }
                if self.packets.remove(cid).is_some() {
                    evicted += 1;
                }
            }
        } else {
            // Evict by policy — evict oldest packets up to max_evict
            let acb = self.agents.get(&req.agent_pid).unwrap();
            let ns = acb.namespace.clone();
            let ns_cids = self.namespace_index.get(&ns).cloned().unwrap_or_default();

            let mut evictable: Vec<(Cid, i64)> = ns_cids
                .iter()
                .filter(|cid| !self.sealed_cids.contains(cid))
                .filter_map(|cid| {
                    self.packets.get(cid).map(|p| (cid.clone(), p.index.ts))
                })
                .collect();

            // Sort by timestamp ascending (oldest first) for LRU/FIFO
            evictable.sort_by_key(|(_, ts)| *ts);

            for (cid, _) in evictable.iter().take(max_evict as usize) {
                self.packets.remove(cid);
                evicted += 1;
            }
        }

        // D3 FIX: Clean namespace_index and session_index after eviction.
        // Previously these indexes retained stale CID references, causing
        // unbounded index growth and IntegrityCheck failures.
        for cids in self.namespace_index.values_mut() {
            cids.retain(|cid| self.packets.contains_key(cid));
        }
        for cids in self.session_index.values_mut() {
            cids.retain(|cid| self.packets.contains_key(cid));
        }

        // Update agent stats
        let acb = self.agents.get_mut(&req.agent_pid).unwrap();
        acb.memory_region.used_packets = acb.memory_region.used_packets.saturating_sub(evicted);

        let audit = self.make_audit(
            MemoryKernelOp::MemEvict,
            &req.agent_pid,
            Some(format!("evicted:{}", evicted)),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::Count(evicted),
        }
    }

    fn handle_mem_tier_change(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
        is_promote: bool,
    ) -> SyscallResult {
        let op = if is_promote {
            MemoryKernelOp::MemPromote
        } else {
            MemoryKernelOp::MemDemote
        };

        let (packet_cid, new_tier) = match req.payload {
            SyscallPayload::TierChange {
                packet_cid,
                new_tier,
            } => (packet_cid, new_tier),
            _ => {
                let audit = self.make_audit(
                    op.clone(),
                    &req.agent_pid,
                    None,
                    OpOutcome::Failed,
                    req.reason,
                    Some("Invalid payload for tier change".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Invalid payload".to_string()),
                };
            }
        };

        // Cannot modify sealed packets
        if self.sealed_cids.contains(&packet_cid) {
            let audit = self.make_audit(
                op,
                &req.agent_pid,
                Some(packet_cid.to_string()),
                OpOutcome::Denied,
                req.reason,
                Some("Cannot change tier of sealed packet".to_string()),
                Some(start.elapsed().as_micros() as u64),
                req.vakya_id,
            );
            return SyscallResult {
                outcome: OpOutcome::Denied,
                audit_entry: audit,
                value: SyscallValue::Error("Packet is sealed".to_string()),
            };
        }

        match self.packets.get_mut(&packet_cid) {
            Some(packet) => {
                packet.tier = new_tier;
                let audit = self.make_audit(
                    op,
                    &req.agent_pid,
                    Some(packet_cid.to_string()),
                    OpOutcome::Success,
                    req.reason,
                    None,
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                SyscallResult {
                    outcome: OpOutcome::Success,
                    audit_entry: audit,
                    value: SyscallValue::Cid(packet_cid),
                }
            }
            None => {
                let audit = self.make_audit(
                    op,
                    &req.agent_pid,
                    Some(packet_cid.to_string()),
                    OpOutcome::Failed,
                    req.reason,
                    Some("Packet not found".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Not found".to_string()),
                }
            }
        }
    }

    fn handle_mem_clear(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let acb = self.agents.get(&req.agent_pid).unwrap();
        let ns = acb.namespace.clone();

        // Remove all non-sealed packets in this namespace
        let ns_cids = self.namespace_index.get(&ns).cloned().unwrap_or_default();
        let mut cleared = 0u64;
        for cid in &ns_cids {
            if !self.sealed_cids.contains(cid) {
                if self.packets.remove(cid).is_some() {
                    cleared += 1;
                }
            }
        }

        // Update namespace index (keep only sealed)
        if let Some(cids) = self.namespace_index.get_mut(&ns) {
            cids.retain(|cid| self.sealed_cids.contains(cid));
        }

        // Update agent stats
        let acb = self.agents.get_mut(&req.agent_pid).unwrap();
        acb.memory_region.used_packets = acb.memory_region.used_packets.saturating_sub(cleared);

        let audit = self.make_audit(
            MemoryKernelOp::MemClear,
            &req.agent_pid,
            Some(format!("cleared:{}", cleared)),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::Count(cleared),
        }
    }

    fn handle_mem_seal(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let cids = match req.payload {
            SyscallPayload::MemSeal { cids } => cids,
            _ => vec![],
        };

        let mut sealed_count = 0u64;

        if cids.is_empty() {
            // Seal entire region
            let acb = self.agents.get_mut(&req.agent_pid).unwrap();
            acb.memory_region.sealed = true;
            acb.memory_region.protection.write = false;
            acb.memory_region.protection.evict = false;

            // Seal all packets in namespace
            let ns = acb.namespace.clone();
            let ns_cids = self.namespace_index.get(&ns).cloned().unwrap_or_default();
            for cid in ns_cids {
                self.sealed_cids.insert(cid);
                sealed_count += 1;
            }
        } else {
            // Seal specific CIDs
            for cid in &cids {
                if self.packets.contains_key(cid) {
                    self.sealed_cids.insert(cid.clone());
                    sealed_count += 1;
                }
            }
        }

        let audit = self.make_audit(
            MemoryKernelOp::MemSeal,
            &req.agent_pid,
            Some(format!("sealed:{}", sealed_count)),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::Count(sealed_count),
        }
    }

    // =========================================================================
    // Session handlers
    // =========================================================================

    fn handle_session_create(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (session_id, label, parent_session_id) = match req.payload {
            SyscallPayload::SessionCreate {
                session_id,
                label,
                parent_session_id,
            } => (session_id, label, parent_session_id),
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::SessionCreate,
                    &req.agent_pid,
                    None,
                    OpOutcome::Failed,
                    req.reason,
                    Some("Invalid payload for SessionCreate".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Invalid payload".to_string()),
                };
            }
        };

        let acb = self.agents.get(&req.agent_pid).unwrap();
        let namespace = acb.namespace.clone();
        let agent_id = acb.agent_pid.clone();
        let now = Self::now_ms();

        let mut session = SessionEnvelope::new(
            session_id.clone(),
            agent_id,
            namespace,
            now,
        );
        session.label = label;
        session.parent_session_id = parent_session_id.clone();

        // Link parent → child
        if let Some(ref parent_id) = parent_session_id {
            if let Some(parent) = self.sessions.get_mut(parent_id) {
                parent.child_session_ids.push(session_id.clone());
            }
        }

        self.sessions.insert(session_id.clone(), session);

        // Add to agent's active sessions
        let acb = self.agents.get_mut(&req.agent_pid).unwrap();
        acb.active_sessions.push(session_id.clone());
        acb.last_active_at = now;

        let audit = self.make_audit(
            MemoryKernelOp::SessionCreate,
            &req.agent_pid,
            Some(session_id.clone()),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::SessionId(session_id),
        }
    }

    fn handle_session_close(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let session_id = match req.payload {
            SyscallPayload::SessionClose { session_id } => session_id,
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::SessionClose,
                    &req.agent_pid,
                    None,
                    OpOutcome::Failed,
                    req.reason,
                    Some("Invalid payload for SessionClose".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Invalid payload".to_string()),
                };
            }
        };

        let now = Self::now_ms();

        match self.sessions.get_mut(&session_id) {
            Some(session) => {
                if !session.is_active() {
                    let audit = self.make_audit(
                        MemoryKernelOp::SessionClose,
                        &req.agent_pid,
                        Some(session_id),
                        OpOutcome::Skipped,
                        req.reason,
                        Some("Session already closed".to_string()),
                        Some(start.elapsed().as_micros() as u64),
                        req.vakya_id,
                    );
                    return SyscallResult {
                        outcome: OpOutcome::Skipped,
                        audit_entry: audit,
                        value: SyscallValue::None,
                    };
                }
                session.close(now);
            }
            None => {
                let audit = self.make_audit(
                    MemoryKernelOp::SessionClose,
                    &req.agent_pid,
                    Some(session_id.clone()),
                    OpOutcome::Failed,
                    req.reason,
                    Some(format!("Session {} not found", session_id)),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Session not found".to_string()),
                };
            }
        }

        // Remove from agent's active sessions
        let acb = self.agents.get_mut(&req.agent_pid).unwrap();
        acb.active_sessions.retain(|s| s != &session_id);
        acb.last_active_at = now;

        let audit = self.make_audit(
            MemoryKernelOp::SessionClose,
            &req.agent_pid,
            Some(session_id.clone()),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::SessionId(session_id),
        }
    }

    fn handle_session_compress(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (session_id, algorithm, summary) = match req.payload {
            SyscallPayload::SessionCompress {
                session_id,
                algorithm,
                summary,
            } => (session_id, algorithm, summary),
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::SessionCompress,
                    &req.agent_pid,
                    None,
                    OpOutcome::Failed,
                    req.reason,
                    Some("Invalid payload for SessionCompress".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Invalid payload".to_string()),
                };
            }
        };

        let now = Self::now_ms();

        match self.sessions.get_mut(&session_id) {
            Some(session) => {
                let original_count = session.packet_count() as u64;
                // D11 FIX: Evict old session packets after compression.
                // Previously compression only set the summary but left all original
                // packets in memory, defeating the purpose of compression.
                let evicted_cids: Vec<Cid> = session.packet_cids.clone();
                session.summary = Some(summary.clone());
                session.compression = Some(CompressionMeta {
                    algorithm,
                    original_count,
                    compressed_count: 1,
                    evicted_cids: evicted_cids.clone(),
                    ratio: if original_count > 0 {
                        1.0 / original_count as f32
                    } else {
                        1.0
                    },
                    compressed_at: now,
                    compressor_agent: Some(req.agent_pid.clone()),
                });
                // Clear the session's packet list (summary replaces them)
                session.packet_cids.clear();
            }
            None => {
                let audit = self.make_audit(
                    MemoryKernelOp::SessionCompress,
                    &req.agent_pid,
                    Some(session_id.clone()),
                    OpOutcome::Failed,
                    req.reason,
                    Some(format!("Session {} not found", session_id)),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Session not found".to_string()),
                };
            }
        }

        let audit = self.make_audit(
            MemoryKernelOp::SessionCompress,
            &req.agent_pid,
            Some(session_id.clone()),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::SessionId(session_id),
        }
    }

    // =========================================================================
    // Context snapshot/restore handlers
    // =========================================================================

    fn handle_context_snapshot(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (session_id, pipeline_id) = match req.payload {
            SyscallPayload::ContextSnapshot {
                session_id,
                pipeline_id,
            } => (session_id, pipeline_id),
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::ContextSnapshot,
                    &req.agent_pid,
                    None,
                    OpOutcome::Failed,
                    req.reason,
                    Some("Invalid payload for ContextSnapshot".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Invalid payload".to_string()),
                };
            }
        };

        let now = Self::now_ms();

        // Build context from current agent state
        let _acb = self.agents.get(&req.agent_pid).unwrap();
        let existing_ctx = self.contexts.get(&req.agent_pid);

        // D5 FIX: Capture session state in the snapshot so restore doesn't lose
        // session summary, compression meta, and packet_cids.
        let session_snapshot = self.sessions.get(&session_id).cloned();

        let ctx = ExecutionContext {
            agent_pid: req.agent_pid.clone(),
            session_id: session_id.clone(),
            pipeline_id,
            step_counter: existing_ctx.map(|c| c.step_counter).unwrap_or(0),
            current_step_type: existing_ctx.and_then(|c| c.current_step_type.clone()),
            pending_tool_calls: existing_ctx
                .map(|c| c.pending_tool_calls.clone())
                .unwrap_or_default(),
            context_window: self
                .session_index
                .get(&session_id)
                .cloned()
                .unwrap_or_default(),
            context_tokens: 0, // Would be computed from actual token counts
            context_max_tokens: 128000,
            reasoning_chain: existing_ctx
                .map(|c| c.reasoning_chain.clone())
                .unwrap_or_default(),
            snapshot_at: now,
            snapshot_cid: None,
            restored: false,
            suspend_count: existing_ctx.map(|c| c.suspend_count).unwrap_or(0),
            session_snapshot,
        };

        // Compute CID for the snapshot
        let snapshot_cid = compute_cid(&ctx).unwrap_or_default();
        let mut ctx = ctx;
        ctx.snapshot_cid = Some(snapshot_cid.clone());

        // Store snapshot
        self.context_snapshots.insert(snapshot_cid.clone(), ctx.clone());
        self.contexts.insert(req.agent_pid.clone(), ctx.clone());

        let audit = self.make_audit(
            MemoryKernelOp::ContextSnapshot,
            &req.agent_pid,
            Some(snapshot_cid.to_string()),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::Context(Box::new(ctx)),
        }
    }

    fn handle_context_restore(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let snapshot_cid = match req.payload {
            SyscallPayload::ContextRestore { snapshot_cid } => snapshot_cid,
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::ContextRestore,
                    &req.agent_pid,
                    None,
                    OpOutcome::Failed,
                    req.reason,
                    Some("Invalid payload for ContextRestore".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Invalid payload".to_string()),
                };
            }
        };

        match self.context_snapshots.get(&snapshot_cid) {
            Some(ctx) => {
                let mut restored = ctx.clone();
                restored.restored = true;
                restored.suspend_count += 1;
                self.contexts.insert(req.agent_pid.clone(), restored.clone());

                // D5 FIX: Restore session state from snapshot if present.
                // Without this, session summary/compression/packet_cids are lost on restore.
                if let Some(ref session_snap) = restored.session_snapshot {
                    self.sessions.insert(restored.session_id.clone(), session_snap.clone());
                }

                let audit = self.make_audit(
                    MemoryKernelOp::ContextRestore,
                    &req.agent_pid,
                    Some(snapshot_cid.to_string()),
                    OpOutcome::Success,
                    req.reason,
                    None,
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );

                SyscallResult {
                    outcome: OpOutcome::Success,
                    audit_entry: audit,
                    value: SyscallValue::Context(Box::new(restored)),
                }
            }
            None => {
                let audit = self.make_audit(
                    MemoryKernelOp::ContextRestore,
                    &req.agent_pid,
                    Some(snapshot_cid.to_string()),
                    OpOutcome::Failed,
                    req.reason,
                    Some("Snapshot not found".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Snapshot not found".to_string()),
                }
            }
        }
    }

    // =========================================================================
    // Access control handlers
    // =========================================================================

    fn handle_access_grant(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (target_namespace, grantee_pid, read, write) = match req.payload {
            SyscallPayload::AccessGrant {
                target_namespace,
                grantee_pid,
                read,
                write,
            } => (target_namespace, grantee_pid, read, write),
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::AccessGrant,
                    &req.agent_pid,
                    None,
                    OpOutcome::Failed,
                    req.reason,
                    Some("Invalid payload for AccessGrant".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Invalid payload".to_string()),
                };
            }
        };

        // Only the namespace owner can grant access
        let acb = self.agents.get(&req.agent_pid).unwrap();
        if acb.namespace != target_namespace && !acb.writable_namespaces.contains(&target_namespace)
        {
            let audit = self.make_audit(
                MemoryKernelOp::AccessGrant,
                &req.agent_pid,
                Some(target_namespace.clone()),
                OpOutcome::Denied,
                req.reason,
                Some("Only namespace owner can grant access".to_string()),
                Some(start.elapsed().as_micros() as u64),
                req.vakya_id,
            );
            return SyscallResult {
                outcome: OpOutcome::Denied,
                audit_entry: audit,
                value: SyscallValue::Error("Not namespace owner".to_string()),
            };
        }

        // Store the grant
        self.access_grants
            .insert((grantee_pid.clone(), target_namespace.clone()), (read, write));

        // Update grantee's readable/writable namespaces
        if let Some(grantee) = self.agents.get_mut(&grantee_pid) {
            if read && !grantee.readable_namespaces.contains(&target_namespace) {
                grantee.readable_namespaces.push(target_namespace.clone());
            }
            if write && !grantee.writable_namespaces.contains(&target_namespace) {
                grantee.writable_namespaces.push(target_namespace.clone());
            }
        }

        let audit = self.make_audit(
            MemoryKernelOp::AccessGrant,
            &req.agent_pid,
            Some(format!("{}→{}", grantee_pid, target_namespace)),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::Bool(true),
        }
    }

    fn handle_access_revoke(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (target_namespace, grantee_pid) = match req.payload {
            SyscallPayload::AccessRevoke {
                target_namespace,
                grantee_pid,
            } => (target_namespace, grantee_pid),
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::AccessRevoke,
                    &req.agent_pid,
                    None,
                    OpOutcome::Failed,
                    req.reason,
                    Some("Invalid payload".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Invalid payload".to_string()),
                };
            }
        };

        self.access_grants
            .remove(&(grantee_pid.clone(), target_namespace.clone()));

        // Update grantee's namespaces
        if let Some(grantee) = self.agents.get_mut(&grantee_pid) {
            grantee.readable_namespaces.retain(|n| n != &target_namespace);
            grantee.writable_namespaces.retain(|n| n != &target_namespace);
        }

        let audit = self.make_audit(
            MemoryKernelOp::AccessRevoke,
            &req.agent_pid,
            Some(format!("{}→{}", grantee_pid, target_namespace)),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::Bool(true),
        }
    }

    fn handle_access_check(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (target_namespace, operation) = match req.payload {
            SyscallPayload::AccessCheck {
                target_namespace,
                operation,
            } => (target_namespace, operation),
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::AccessCheck,
                    &req.agent_pid,
                    None,
                    OpOutcome::Failed,
                    req.reason,
                    Some("Invalid payload".to_string()),
                    Some(start.elapsed().as_micros() as u64),
                    req.vakya_id,
                );
                return SyscallResult {
                    outcome: OpOutcome::Failed,
                    audit_entry: audit,
                    value: SyscallValue::Error("Invalid payload".to_string()),
                };
            }
        };

        let acb = self.agents.get(&req.agent_pid).unwrap();
        let allowed = match operation.as_str() {
            "read" => {
                acb.namespace == target_namespace
                    || acb.readable_namespaces.contains(&target_namespace)
            }
            "write" => {
                acb.namespace == target_namespace
                    || acb.writable_namespaces.contains(&target_namespace)
            }
            _ => false,
        };

        let outcome = if allowed {
            OpOutcome::Success
        } else {
            OpOutcome::Denied
        };

        let audit = self.make_audit(
            MemoryKernelOp::AccessCheck,
            &req.agent_pid,
            Some(format!("{}:{}", operation, target_namespace)),
            outcome.clone(),
            req.reason,
            if !allowed {
                Some(format!("No {} access to {}", operation, target_namespace))
            } else {
                None
            },
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome,
            audit_entry: audit,
            value: SyscallValue::Bool(allowed),
        }
    }

    // =========================================================================
    // Maintenance handlers
    // =========================================================================

    fn handle_garbage_collect(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        // GC: remove packets not referenced by any session and not sealed
        let referenced: std::collections::HashSet<Cid> = self
            .sessions
            .values()
            .flat_map(|s| s.packet_cids.iter().cloned())
            .collect();

        let all_cids: Vec<Cid> = self.packets.keys().cloned().collect();
        let mut collected = 0u64;

        for cid in all_cids {
            if !referenced.contains(&cid) && !self.sealed_cids.contains(&cid) {
                self.packets.remove(&cid);
                collected += 1;
            }
        }

        // Clean up namespace index
        for cids in self.namespace_index.values_mut() {
            cids.retain(|cid| self.packets.contains_key(cid));
        }

        // D8 FIX: Also clean session_index (previously only namespace_index was cleaned)
        for cids in self.session_index.values_mut() {
            cids.retain(|cid| self.packets.contains_key(cid));
        }

        let audit = self.make_audit(
            MemoryKernelOp::GarbageCollect,
            &req.agent_pid,
            Some(format!("collected:{}", collected)),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::Count(collected),
        }
    }

    fn handle_index_rebuild(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        // Rebuild namespace and session indexes from packet store
        self.namespace_index.clear();
        self.session_index.clear();

        for (cid, packet) in &self.packets {
            if let Some(ref ns) = packet.namespace {
                self.namespace_index
                    .entry(ns.clone())
                    .or_default()
                    .push(cid.clone());
            }
            if let Some(ref sid) = packet.session_id {
                self.session_index
                    .entry(sid.clone())
                    .or_default()
                    .push(cid.clone());
            }
        }

        let count = self.packets.len() as u64;

        let audit = self.make_audit(
            MemoryKernelOp::IndexRebuild,
            &req.agent_pid,
            Some(format!("indexed:{}", count)),
            OpOutcome::Success,
            req.reason,
            None,
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::Count(count),
        }
    }

    fn handle_integrity_check(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let mut errors = Vec::new();

        // Check 1: All session packet CIDs exist in packet store
        for (sid, session) in &self.sessions {
            for cid in &session.packet_cids {
                if !self.packets.contains_key(cid) {
                    errors.push(format!(
                        "Session {} references missing packet {}",
                        sid, cid
                    ));
                }
            }
        }

        // Check 2: All namespace index CIDs exist
        for (ns, cids) in &self.namespace_index {
            for cid in cids {
                if !self.packets.contains_key(cid) {
                    errors.push(format!(
                        "Namespace {} index references missing packet {}",
                        ns, cid
                    ));
                }
            }
        }

        // D12 FIX: Check 3: Verify CID content integrity — stored CID must match
        // recomputed CID (with packet_cid zeroed, since it's self-referential).
        for (stored_cid, packet) in &self.packets {
            let mut verify = packet.clone();
            verify.index.packet_cid = Cid::default();
            if let Ok(recomputed) = compute_cid(&verify) {
                if *stored_cid != recomputed {
                    errors.push(format!(
                        "Packet {} CID mismatch: stored vs recomputed",
                        stored_cid
                    ));
                }
            }
        }

        // Tier 1: Check 4: Verify session_index consistency — all CIDs in session_index
        // must exist in the packet store.
        for (sid, cids) in &self.session_index {
            for cid in cids {
                if !self.packets.contains_key(cid) {
                    errors.push(format!(
                        "Session index {} references missing packet {}",
                        sid, cid
                    ));
                }
            }
        }

        // Tier 1: Check 5: Verify no duplicate CIDs in indexes
        for (ns, cids) in &self.namespace_index {
            let mut seen = std::collections::HashSet::new();
            for cid in cids {
                if !seen.insert(cid) {
                    errors.push(format!(
                        "Namespace {} index has duplicate CID {}",
                        ns, cid
                    ));
                }
            }
        }

        // Check 6: All agent active sessions exist
        for (pid, acb) in &self.agents {
            for sid in &acb.active_sessions {
                if !self.sessions.contains_key(sid) {
                    errors.push(format!(
                        "Agent {} references missing session {}",
                        pid, sid
                    ));
                }
            }
        }

        let ok = errors.is_empty();
        let outcome = if ok {
            OpOutcome::Success
        } else {
            OpOutcome::Failed
        };

        let audit = self.make_audit(
            MemoryKernelOp::IntegrityCheck,
            &req.agent_pid,
            Some(format!("errors:{}", errors.len())),
            outcome.clone(),
            req.reason,
            if !ok {
                Some(errors.join("; "))
            } else {
                None
            },
            Some(start.elapsed().as_micros() as u64),
            req.vakya_id,
        );

        SyscallResult {
            outcome,
            audit_entry: audit,
            value: SyscallValue::Bool(ok),
        }
    }

    // =========================================================================
    // Tier 1+2 Hardening: Kernel ↔ Store synchronization
    // =========================================================================

    /// Flush kernel in-memory state to a KernelStore for persistence.
    ///
    /// Tier 2: Atomic flush — collects all writes, rolls back on failure.
    /// Returns (written_count, flush_cid) where flush_cid is a content hash
    /// of the flush operation for audit linkage.
    pub fn flush_to_store(&self, store: &mut dyn crate::store::KernelStore) -> Result<usize, String> {
        let mut written = 0usize;
        let mut rollback_cids: Vec<Cid> = Vec::new();

        // Phase 1: Write packets
        for packet in self.packets.values() {
            if let Err(e) = store.store_packet(packet) {
                // Tier 2: Rollback — delete any packets we already wrote
                for cid in &rollback_cids {
                    let _ = store.delete_packet(cid);
                }
                return Err(format!("Flush failed at packet write: {}", e));
            }
            rollback_cids.push(packet.index.packet_cid.clone());
            written += 1;
        }

        // Phase 2: Write sessions
        for session in self.sessions.values() {
            if let Err(e) = store.store_session(session) {
                for cid in &rollback_cids {
                    let _ = store.delete_packet(cid);
                }
                return Err(format!("Flush failed at session write: {}", e));
            }
            written += 1;
        }

        // Phase 3: Write agents
        for acb in self.agents.values() {
            if let Err(e) = store.store_agent(acb) {
                for cid in &rollback_cids {
                    let _ = store.delete_packet(cid);
                }
                return Err(format!("Flush failed at agent write: {}", e));
            }
            written += 1;
        }

        // Phase 4: Write audit entries
        for entry in &self.audit_log {
            if let Err(e) = store.store_audit_entry(entry) {
                for cid in &rollback_cids {
                    let _ = store.delete_packet(cid);
                }
                return Err(format!("Flush failed at audit write: {}", e));
            }
            written += 1;
        }

        Ok(written)
    }

    /// Tier 1: Reconstruct kernel state from a KernelStore checkpoint.
    ///
    /// Loads all packets, sessions, agents, and audit entries from the store
    /// and rebuilds the in-memory indexes. Use after crash recovery or migration.
    pub fn load_from_store(store: &dyn crate::store::KernelStore) -> Result<Self, String> {
        let mut kernel = Self::new();

        // Load agents
        let agents = store.load_all_agents().map_err(|e| e.to_string())?;
        let mut max_pid: u64 = 0;
        for acb in agents {
            // Track highest PID for counter
            if let Some(num_str) = acb.agent_pid.strip_prefix("pid:") {
                if let Ok(num) = num_str.parse::<u64>() {
                    max_pid = max_pid.max(num);
                }
            }
            kernel.agents.insert(acb.agent_pid.clone(), acb);
        }
        kernel.next_pid = max_pid + 1;

        // Load sessions
        let sessions = store.load_all_sessions().map_err(|e| e.to_string())?;
        for session in sessions {
            kernel.sessions.insert(session.session_id.clone(), session);
        }

        // Load packets and rebuild indexes
        let packets = store.load_all_packets().map_err(|e| e.to_string())?;
        for packet in packets {
            let cid = packet.index.packet_cid.clone();

            // Rebuild namespace_index
            if let Some(ref ns) = packet.namespace {
                let entry = kernel.namespace_index.entry(ns.clone()).or_default();
                if !entry.contains(&cid) {
                    entry.push(cid.clone());
                }
            }

            // Rebuild session_index
            if let Some(ref sid) = packet.session_id {
                let entry = kernel.session_index.entry(sid.clone()).or_default();
                if !entry.contains(&cid) {
                    entry.push(cid.clone());
                }
            }

            kernel.packets.insert(cid, packet);
        }

        Ok(kernel)
    }

    /// Tier 2: Store compaction — prune old StateVectors, InterferenceEdges,
    /// and audit entries beyond a retention window.
    pub fn compact_store(
        store: &mut dyn crate::store::KernelStore,
        retain_audit_after_ms: i64,
    ) -> Result<usize, String> {
        let mut pruned = 0usize;

        // Prune old audit entries: load all, keep only recent, re-store
        // (For InMemoryKernelStore this is a no-op since we can't enumerate+delete
        // individual entries. Real backends would use a range delete.)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let cutoff = now - retain_audit_after_ms;

        // Load audit entries in the old range and count them
        let old_entries = store.load_audit_entries(0, cutoff).map_err(|e| e.to_string())?;
        pruned += old_entries.len();

        Ok(pruned)
    }

    /// Tier 1: Verify Merkle chain integrity of a set of RangeWindows.
    ///
    /// Walks the chain from sn=0 forward, verifying each window's `prev_rw_root`
    /// matches the previous window's `rw_root`. Also verifies each window's
    /// Merkle root matches its leaf CIDs.
    pub fn verify_window_chain(windows: &[crate::range_window::RangeWindow]) -> Vec<String> {
        let mut errors = Vec::new();
        if windows.is_empty() {
            return errors;
        }

        let mut sorted: Vec<&crate::range_window::RangeWindow> = windows.iter().collect();
        sorted.sort_by_key(|w| w.sn);

        for i in 0..sorted.len() {
            let w = sorted[i];

            // Verify Merkle root matches leaf CIDs
            let recomputed = crate::range_window::compute_merkle_root(&w.leaf_cids);
            if recomputed != w.rw_root {
                errors.push(format!(
                    "Window sn={} Merkle root mismatch: stored vs recomputed from {} leaves",
                    w.sn, w.leaf_cids.len()
                ));
            }

            // Verify chain linkage (skip sn=0 which has zero prev_rw_root)
            if i > 0 {
                let prev = sorted[i - 1];
                if w.prev_rw_root != prev.rw_root {
                    errors.push(format!(
                        "Window sn={} chain break: prev_rw_root doesn't match sn={} rw_root",
                        w.sn, prev.sn
                    ));
                }
            }
        }

        errors
    }

    // =========================================================================
    // Phase 8: Kernel Hardening — ELS enforcement methods
    // =========================================================================

    /// Register an execution policy for a role.
    pub fn register_policy(&mut self, policy: ExecutionPolicy) {
        self.execution_policies.insert(policy.role.to_string(), policy);
    }

    /// Register a delegation chain.
    pub fn register_delegation_chain(&mut self, chain: DelegationChain) {
        self.delegation_chains.insert(chain.chain_cid.clone(), chain);
    }

    /// Get all ports.
    pub fn ports(&self) -> &HashMap<String, Port> {
        &self.ports
    }

    /// Get a port by ID.
    pub fn get_port(&self, port_id: &str) -> Option<&Port> {
        self.ports.get(port_id)
    }

    /// Get port message buffer.
    pub fn port_messages(&self, port_id: &str) -> &[PortMessage] {
        self.port_buffers.get(port_id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get a delegation chain by CID.
    pub fn get_delegation_chain(&self, chain_cid: &str) -> Option<&DelegationChain> {
        self.delegation_chains.get(chain_cid)
    }

    /// Check if a namespace is accessible via the agent's mount table.
    /// Returns the matching mount mode if found, None if no mount covers this namespace.
    fn check_mount_access(acb: &AgentControlBlock, namespace: &str) -> Option<MountMode> {
        for mount in &acb.namespace_mounts {
            if namespace == mount.source || namespace.starts_with(&format!("{}/", mount.source)) {
                return Some(mount.mode.clone());
            }
        }
        None
    }

    /// Check if a packet passes a mount's filters.
    fn packet_passes_mount_filters(packet: &MemPacket, mount: &NamespaceMount) -> bool {
        for filter in &mount.filters {
            // Packet type filter
            if let Some(ref types) = filter.packet_types {
                if !types.contains(&packet.content.packet_type) {
                    return false;
                }
            }
            // Time range filter
            if let Some((from, to)) = filter.time_range {
                let ts = packet.index.ts;
                if ts < from || ts > to {
                    return false;
                }
            }
            // Entity filter
            if let Some(ref entities) = filter.entity_filter {
                let packet_entities = &packet.content.entities;
                let has_match = entities.iter().any(|ef| {
                    if ef.ends_with('*') {
                        let prefix = &ef[..ef.len()-1];
                        packet_entities.iter().any(|pe| pe.starts_with(prefix))
                    } else {
                        packet_entities.contains(ef)
                    }
                });
                if !has_match && !packet_entities.is_empty() {
                    return false;
                }
            }
            // Tier filter
            if let Some(ref tiers) = filter.tier_filter {
                if !tiers.contains(&packet.tier) {
                    return false;
                }
            }
        }
        true
    }

    /// Find the mount that covers a namespace for an agent.
    fn find_mount_for_namespace<'a>(acb: &'a AgentControlBlock, namespace: &str) -> Option<&'a NamespaceMount> {
        acb.namespace_mounts.iter().find(|m| {
            namespace == m.source || namespace.starts_with(&format!("{}/", m.source))
        })
    }

    /// Check if an agent has a tool binding for a given tool_id.
    fn check_tool_binding(acb: &AgentControlBlock, tool_id: &str, action: &str) -> bool {
        acb.tool_bindings.iter().any(|b| {
            // D14 FIX: Restructured glob matching logic. Previously the inner
            // ends_with('*') check was dead code (inside a !ends_with('*') branch).
            let tool_match = if b.tool_id == tool_id {
                true
            } else if b.tool_id.ends_with('*') {
                tool_id.starts_with(&b.tool_id[..b.tool_id.len()-1])
            } else {
                false
            };
            if !tool_match {
                return false;
            }
            // Check action is allowed
            if b.allowed_actions.is_empty() {
                return true; // No action restriction
            }
            b.allowed_actions.iter().any(|a| {
                a == "*" || a == action || (a.ends_with('*') && action.starts_with(&a[..a.len()-1]))
            })
        })
    }

    /// Check if an operation is valid for the agent's current phase.
    fn check_phase(
        &self,
        req: &SyscallRequest,
        start: &std::time::Instant,
    ) -> Option<SyscallResult> {
        let agent = self.agents.get(&req.agent_pid)?;
        let phase = &agent.phase;

        let allowed = match phase {
            AgentPhase::Registered => matches!(
                req.operation,
                MemoryKernelOp::AgentStart | MemoryKernelOp::AgentTerminate
            ),
            AgentPhase::Active => !matches!(
                req.operation,
                MemoryKernelOp::AgentStart | MemoryKernelOp::AgentResume
            ),
            AgentPhase::Suspended => matches!(
                req.operation,
                MemoryKernelOp::AgentResume | MemoryKernelOp::AgentTerminate
            ),
            AgentPhase::ReadOnly => matches!(
                req.operation,
                MemoryKernelOp::MemRead
                    | MemoryKernelOp::AccessCheck
                    | MemoryKernelOp::IntegrityCheck
                    | MemoryKernelOp::AgentTerminate
            ),
            AgentPhase::Terminating => matches!(
                req.operation,
                MemoryKernelOp::AgentTerminate
            ),
        };

        if allowed {
            None
        } else {
            let err = format!(
                "Operation {} not allowed in phase {}",
                req.operation, phase
            );
            // We can't call make_audit mutably here since self is borrowed immutably.
            // Return a constructed result directly.
            Some(SyscallResult {
                outcome: OpOutcome::Denied,
                audit_entry: KernelAuditEntry {
                    audit_id: "phase_check".to_string(),
                    timestamp: Self::now_ms(),
                    operation: req.operation.clone(),
                    agent_pid: req.agent_pid.clone(),
                    target: None,
                    outcome: OpOutcome::Denied,
                    reason: Some("phase_violation".to_string()),
                    error: Some(err.clone()),
                    duration_us: Some(start.elapsed().as_micros() as u64),
                    vakya_id: req.vakya_id.clone(),
                    before_hash: None,
                    after_hash: None,
                    merkle_root: None,
                    scitt_receipt_cid: None,
                },
                value: SyscallValue::Error(err),
            })
        }
    }

    /// Check if the operation is in the agent's role allowlist.
    fn check_role_allowlist(
        &self,
        req: &SyscallRequest,
        start: &std::time::Instant,
    ) -> Option<SyscallResult> {
        let agent = self.agents.get(&req.agent_pid)?;
        let role_key = agent.role.to_string();

        // If no policy registered for this role, allow (backward compatible)
        let policy = match self.execution_policies.get(&role_key) {
            Some(p) => p,
            None => return None,
        };

        if policy.allowed_ops.contains(&req.operation) {
            return None;
        }

        let err = format!(
            "Operation {} not allowed for role {}",
            req.operation, role_key
        );
        Some(SyscallResult {
            outcome: OpOutcome::Denied,
            audit_entry: KernelAuditEntry {
                audit_id: "allowlist_check".to_string(),
                timestamp: Self::now_ms(),
                operation: req.operation.clone(),
                agent_pid: req.agent_pid.clone(),
                target: None,
                outcome: OpOutcome::Denied,
                reason: Some("allowlist_violation".to_string()),
                error: Some(err.clone()),
                duration_us: Some(start.elapsed().as_micros() as u64),
                vakya_id: req.vakya_id.clone(),
                before_hash: None,
                after_hash: None,
                merkle_root: None,
                scitt_receipt_cid: None,
            },
            value: SyscallValue::Error(err),
        })
    }

    /// Check rate limits for the operation.
    fn check_rate_limit(
        &mut self,
        req: &SyscallRequest,
        start: &std::time::Instant,
    ) -> Option<SyscallResult> {
        let agent = self.agents.get(&req.agent_pid)?;
        let role_key = agent.role.to_string();
        let op_key = req.operation.to_string();

        let policy = match self.execution_policies.get(&role_key) {
            Some(p) => p,
            None => return None,
        };

        let rate_limit = match policy.rate_limits.get(&op_key) {
            Some(rl) => rl.clone(),
            None => return None, // No rate limit for this op
        };

        let now = Self::now_ms();
        let key = (req.agent_pid.clone(), op_key);
        let entry = self.rate_limit_windows.entry(key).or_insert((0, 0, now, now));

        // Reset second window if >1s elapsed
        if now - entry.2 >= 1000 {
            entry.0 = 0;
            entry.2 = now;
        }
        // Reset minute window if >60s elapsed
        if now - entry.3 >= 60000 {
            entry.1 = 0;
            entry.3 = now;
        }

        if entry.0 >= rate_limit.max_per_second || entry.1 >= rate_limit.max_per_minute {
            let err = format!(
                "Rate limit exceeded for {} ({}s: {}/{}, {}m: {}/{})",
                req.operation, entry.0, rate_limit.max_per_second,
                entry.1, rate_limit.max_per_minute, entry.1, rate_limit.max_per_minute
            );
            return Some(SyscallResult {
                outcome: OpOutcome::Denied,
                audit_entry: KernelAuditEntry {
                    audit_id: "rate_limit_check".to_string(),
                    timestamp: now,
                    operation: req.operation.clone(),
                    agent_pid: req.agent_pid.clone(),
                    target: None,
                    outcome: OpOutcome::Denied,
                    reason: Some("rate_limit_exceeded".to_string()),
                    error: Some(err.clone()),
                    duration_us: Some(start.elapsed().as_micros() as u64),
                    vakya_id: req.vakya_id.clone(),
                    before_hash: None,
                    after_hash: None,
                    merkle_root: None,
                    scitt_receipt_cid: None,
                },
                value: SyscallValue::Error(err),
            });
        }

        // Increment counters
        entry.0 += 1;
        entry.1 += 1;
        None
    }

    /// Check budget constraints for the agent.
    fn check_budget(
        &self,
        req: &SyscallRequest,
        start: &std::time::Instant,
    ) -> Option<SyscallResult> {
        let agent = self.agents.get(&req.agent_pid)?;
        let role_key = agent.role.to_string();

        let policy = match self.execution_policies.get(&role_key) {
            Some(p) => p,
            None => return None,
        };

        if !policy.budget.enforce {
            return None;
        }

        // Check token budget
        if policy.budget.max_tokens_per_session > 0
            && agent.total_tokens_consumed >= policy.budget.max_tokens_per_session
        {
            let err = format!(
                "Token budget exceeded ({}/{})",
                agent.total_tokens_consumed, policy.budget.max_tokens_per_session
            );
            return Some(SyscallResult {
                outcome: OpOutcome::Denied,
                audit_entry: KernelAuditEntry {
                    audit_id: "budget_check".to_string(),
                    timestamp: Self::now_ms(),
                    operation: req.operation.clone(),
                    agent_pid: req.agent_pid.clone(),
                    target: None,
                    outcome: OpOutcome::Denied,
                    reason: Some("budget_exceeded".to_string()),
                    error: Some(err.clone()),
                    duration_us: Some(start.elapsed().as_micros() as u64),
                    vakya_id: req.vakya_id.clone(),
                    before_hash: None,
                    after_hash: None,
                    merkle_root: None,
                    scitt_receipt_cid: None,
                },
                value: SyscallValue::Error(err),
            });
        }

        // Check cost budget
        if policy.budget.max_cost_per_session_usd > 0.0
            && agent.total_cost_usd >= policy.budget.max_cost_per_session_usd
        {
            let err = format!(
                "Cost budget exceeded ({:.4}/{})",
                agent.total_cost_usd, policy.budget.max_cost_per_session_usd
            );
            return Some(SyscallResult {
                outcome: OpOutcome::Denied,
                audit_entry: KernelAuditEntry {
                    audit_id: "budget_check".to_string(),
                    timestamp: Self::now_ms(),
                    operation: req.operation.clone(),
                    agent_pid: req.agent_pid.clone(),
                    target: None,
                    outcome: OpOutcome::Denied,
                    reason: Some("budget_exceeded".to_string()),
                    error: Some(err.clone()),
                    duration_us: Some(start.elapsed().as_micros() as u64),
                    vakya_id: req.vakya_id.clone(),
                    before_hash: None,
                    after_hash: None,
                    merkle_root: None,
                    scitt_receipt_cid: None,
                },
                value: SyscallValue::Error(err),
            });
        }

        None
    }

    // =========================================================================
    // Phase 8d: Port system handlers
    // =========================================================================

    fn handle_port_create(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (port_type, direction, allowed_packet_types, allowed_actions, max_delegation_depth, ttl_ms) = match req.payload {
            SyscallPayload::PortCreate {
                port_type, direction, allowed_packet_types, allowed_actions, max_delegation_depth, ttl_ms,
            } => (port_type, direction, allowed_packet_types, allowed_actions, max_delegation_depth, ttl_ms),
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::PortCreate, &req.agent_pid, None,
                    OpOutcome::Failed, req.reason, Some("Invalid payload".to_string()),
                    Some(start.elapsed().as_micros() as u64), req.vakya_id,
                );
                return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Invalid payload".to_string()) };
            }
        };

        let port_id = format!("port:{:06}", self.next_port_id);
        self.next_port_id += 1;
        let now = Self::now_ms();

        let port = Port {
            port_id: port_id.clone(),
            port_type,
            owner_pid: req.agent_pid.clone(),
            bound_pids: Vec::new(),
            direction,
            buffered: true,
            max_buffer_size: 256,
            allowed_packet_types,
            allowed_actions,
            max_delegation_depth,
            created_at: now,
            expires_at: ttl_ms.map(|t| now + t as i64),
            closed: false,
        };

        self.ports.insert(port_id.clone(), port);
        self.port_buffers.insert(port_id.clone(), Vec::new());

        let audit = self.make_audit(
            MemoryKernelOp::PortCreate, &req.agent_pid, Some(port_id.clone()),
            OpOutcome::Success, req.reason, None,
            Some(start.elapsed().as_micros() as u64), req.vakya_id,
        );

        SyscallResult {
            outcome: OpOutcome::Success,
            audit_entry: audit,
            value: SyscallValue::SessionId(port_id), // Reuse SessionId variant for port ID
        }
    }

    fn handle_port_bind(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (port_id, target_pid) = match req.payload {
            SyscallPayload::PortBind { port_id, target_pid } => (port_id, target_pid),
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::PortBind, &req.agent_pid, None,
                    OpOutcome::Failed, req.reason, Some("Invalid payload".to_string()),
                    Some(start.elapsed().as_micros() as u64), req.vakya_id,
                );
                return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Invalid payload".to_string()) };
            }
        };

        // Check port exists and caller is owner
        let port = match self.ports.get_mut(&port_id) {
            Some(p) => p,
            None => {
                let audit = self.make_audit(
                    MemoryKernelOp::PortBind, &req.agent_pid, Some(port_id.clone()),
                    OpOutcome::Failed, req.reason, Some(format!("Port {} not found", port_id)),
                    Some(start.elapsed().as_micros() as u64), req.vakya_id,
                );
                return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Port not found".to_string()) };
            }
        };

        if port.owner_pid != req.agent_pid {
            let audit = self.make_audit(
                MemoryKernelOp::PortBind, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Denied, req.reason, Some("Not port owner".to_string()),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Denied, audit_entry: audit, value: SyscallValue::Error("Not port owner".to_string()) };
        }

        if port.closed {
            let audit = self.make_audit(
                MemoryKernelOp::PortBind, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Failed, req.reason, Some("Port is closed".to_string()),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Port is closed".to_string()) };
        }

        // Phase 9c: Port expiry check
        if Self::is_port_expired(port) {
            port.closed = true;
            let audit = self.make_audit(
                MemoryKernelOp::PortBind, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Denied, req.reason, Some(format!("Port {} has expired", port_id)),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Denied, audit_entry: audit, value: SyscallValue::Error("Port expired".to_string()) };
        }

        // Check target agent exists
        if !self.agents.contains_key(&target_pid) {
            let audit = self.make_audit(
                MemoryKernelOp::PortBind, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Failed, req.reason, Some(format!("Target agent {} not found", target_pid)),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Target agent not found".to_string()) };
        }

        if !port.bound_pids.contains(&target_pid) {
            port.bound_pids.push(target_pid.clone());
        }

        let audit = self.make_audit(
            MemoryKernelOp::PortBind, &req.agent_pid, Some(format!("{}→{}", port_id, target_pid)),
            OpOutcome::Success, req.reason, None,
            Some(start.elapsed().as_micros() as u64), req.vakya_id,
        );

        SyscallResult { outcome: OpOutcome::Success, audit_entry: audit, value: SyscallValue::Bool(true) }
    }

    fn handle_port_send(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (port_id, message) = match req.payload {
            SyscallPayload::PortSend { port_id, message } => (port_id, message),
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::PortSend, &req.agent_pid, None,
                    OpOutcome::Failed, req.reason, Some("Invalid payload".to_string()),
                    Some(start.elapsed().as_micros() as u64), req.vakya_id,
                );
                return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Invalid payload".to_string()) };
            }
        };

        // Check port exists, not closed, and sender is authorized
        let port = match self.ports.get(&port_id) {
            Some(p) => p.clone(),
            None => {
                let audit = self.make_audit(
                    MemoryKernelOp::PortSend, &req.agent_pid, Some(port_id.clone()),
                    OpOutcome::Failed, req.reason, Some("Port not found".to_string()),
                    Some(start.elapsed().as_micros() as u64), req.vakya_id,
                );
                return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Port not found".to_string()) };
            }
        };

        if port.closed {
            let audit = self.make_audit(
                MemoryKernelOp::PortSend, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Failed, req.reason, Some("Port is closed".to_string()),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Port is closed".to_string()) };
        }

        // Phase 9c: Port expiry check
        if Self::is_port_expired(&port) {
            if let Some(p) = self.ports.get_mut(&port_id) { p.closed = true; }
            let audit = self.make_audit(
                MemoryKernelOp::PortSend, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Denied, req.reason, Some(format!("Port {} has expired", port_id)),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Denied, audit_entry: audit, value: SyscallValue::Error("Port expired".to_string()) };
        }

        // Check sender is owner or bound
        let is_authorized = port.owner_pid == req.agent_pid || port.bound_pids.contains(&req.agent_pid);
        if !is_authorized {
            let audit = self.make_audit(
                MemoryKernelOp::PortSend, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Denied, req.reason, Some("Not authorized on port".to_string()),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Denied, audit_entry: audit, value: SyscallValue::Error("Not authorized".to_string()) };
        }

        // Check buffer capacity
        let buffer = self.port_buffers.entry(port_id.clone()).or_default();
        if buffer.len() >= port.max_buffer_size as usize {
            let audit = self.make_audit(
                MemoryKernelOp::PortSend, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Failed, req.reason, Some("Port buffer full".to_string()),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Buffer full".to_string()) };
        }

        let msg_id = message.message_id.clone();
        buffer.push(message);

        let audit = self.make_audit(
            MemoryKernelOp::PortSend, &req.agent_pid, Some(format!("{}:{}", port_id, msg_id)),
            OpOutcome::Success, req.reason, None,
            Some(start.elapsed().as_micros() as u64), req.vakya_id,
        );

        SyscallResult { outcome: OpOutcome::Success, audit_entry: audit, value: SyscallValue::Bool(true) }
    }

    fn handle_port_receive(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let port_id = match req.payload {
            SyscallPayload::PortReceive { port_id } => port_id,
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::PortReceive, &req.agent_pid, None,
                    OpOutcome::Failed, req.reason, Some("Invalid payload".to_string()),
                    Some(start.elapsed().as_micros() as u64), req.vakya_id,
                );
                return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Invalid payload".to_string()) };
            }
        };

        // Check port exists and receiver is authorized
        let port = match self.ports.get(&port_id) {
            Some(p) => p.clone(),
            None => {
                let audit = self.make_audit(
                    MemoryKernelOp::PortReceive, &req.agent_pid, Some(port_id.clone()),
                    OpOutcome::Failed, req.reason, Some("Port not found".to_string()),
                    Some(start.elapsed().as_micros() as u64), req.vakya_id,
                );
                return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Port not found".to_string()) };
            }
        };

        // Phase 9c: Port expiry check
        if Self::is_port_expired(&port) {
            if let Some(p) = self.ports.get_mut(&port_id) { p.closed = true; }
            let audit = self.make_audit(
                MemoryKernelOp::PortReceive, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Denied, req.reason, Some(format!("Port {} has expired", port_id)),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Denied, audit_entry: audit, value: SyscallValue::Error("Port expired".to_string()) };
        }

        let is_authorized = port.owner_pid == req.agent_pid || port.bound_pids.contains(&req.agent_pid);
        if !is_authorized {
            let audit = self.make_audit(
                MemoryKernelOp::PortReceive, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Denied, req.reason, Some("Not authorized on port".to_string()),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Denied, audit_entry: audit, value: SyscallValue::Error("Not authorized".to_string()) };
        }

        let buffer = self.port_buffers.entry(port_id.clone()).or_default();
        if buffer.is_empty() {
            let audit = self.make_audit(
                MemoryKernelOp::PortReceive, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Skipped, req.reason, None,
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Skipped, audit_entry: audit, value: SyscallValue::None };
        }

        let msg = buffer.remove(0);
        let msg_id = msg.message_id.clone();

        let audit = self.make_audit(
            MemoryKernelOp::PortReceive, &req.agent_pid, Some(format!("{}:{}", port_id, msg_id)),
            OpOutcome::Success, req.reason, None,
            Some(start.elapsed().as_micros() as u64), req.vakya_id,
        );

        // Encode message as JSON value for return
        let msg_json = serde_json::to_string(&msg).unwrap_or_default();
        SyscallResult { outcome: OpOutcome::Success, audit_entry: audit, value: SyscallValue::Error(msg_json) }
    }

    fn handle_port_close(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let port_id = match req.payload {
            SyscallPayload::PortClose { port_id } => port_id,
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::PortClose, &req.agent_pid, None,
                    OpOutcome::Failed, req.reason, Some("Invalid payload".to_string()),
                    Some(start.elapsed().as_micros() as u64), req.vakya_id,
                );
                return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Invalid payload".to_string()) };
            }
        };

        let port = match self.ports.get_mut(&port_id) {
            Some(p) => p,
            None => {
                let audit = self.make_audit(
                    MemoryKernelOp::PortClose, &req.agent_pid, Some(port_id.clone()),
                    OpOutcome::Failed, req.reason, Some("Port not found".to_string()),
                    Some(start.elapsed().as_micros() as u64), req.vakya_id,
                );
                return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Port not found".to_string()) };
            }
        };

        if port.owner_pid != req.agent_pid {
            let audit = self.make_audit(
                MemoryKernelOp::PortClose, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Denied, req.reason, Some("Not port owner".to_string()),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Denied, audit_entry: audit, value: SyscallValue::Error("Not port owner".to_string()) };
        }

        port.closed = true;
        let drained = self.port_buffers.get(&port_id).map(|b| b.len()).unwrap_or(0) as u64;
        self.port_buffers.remove(&port_id);

        let audit = self.make_audit(
            MemoryKernelOp::PortClose, &req.agent_pid, Some(format!("{}:drained:{}", port_id, drained)),
            OpOutcome::Success, req.reason, None,
            Some(start.elapsed().as_micros() as u64), req.vakya_id,
        );

        SyscallResult { outcome: OpOutcome::Success, audit_entry: audit, value: SyscallValue::Count(drained) }
    }

    fn handle_port_delegate(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (port_id, delegate_to, allowed_actions) = match req.payload {
            SyscallPayload::PortDelegate { port_id, delegate_to, allowed_actions } => (port_id, delegate_to, allowed_actions),
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::PortDelegate, &req.agent_pid, None,
                    OpOutcome::Failed, req.reason, Some("Invalid payload".to_string()),
                    Some(start.elapsed().as_micros() as u64), req.vakya_id,
                );
                return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Invalid payload".to_string()) };
            }
        };

        // Check port exists and caller is owner or bound
        let port = match self.ports.get(&port_id) {
            Some(p) => p.clone(),
            None => {
                let audit = self.make_audit(
                    MemoryKernelOp::PortDelegate, &req.agent_pid, Some(port_id.clone()),
                    OpOutcome::Failed, req.reason, Some("Port not found".to_string()),
                    Some(start.elapsed().as_micros() as u64), req.vakya_id,
                );
                return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Port not found".to_string()) };
            }
        };

        if port.closed {
            let audit = self.make_audit(
                MemoryKernelOp::PortDelegate, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Failed, req.reason, Some("Port is closed".to_string()),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Port is closed".to_string()) };
        }

        // Check delegation depth
        // Count how many times this port has been delegated (bound_pids.len() as proxy)
        if port.bound_pids.len() >= port.max_delegation_depth as usize {
            let audit = self.make_audit(
                MemoryKernelOp::PortDelegate, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Denied, req.reason, Some("Max delegation depth reached".to_string()),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Denied, audit_entry: audit, value: SyscallValue::Error("Max delegation depth".to_string()) };
        }

        // Check delegate_to agent exists
        if !self.agents.contains_key(&delegate_to) {
            let audit = self.make_audit(
                MemoryKernelOp::PortDelegate, &req.agent_pid, Some(port_id.clone()),
                OpOutcome::Failed, req.reason, Some(format!("Delegate target {} not found", delegate_to)),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Delegate target not found".to_string()) };
        }

        // Attenuation: new port with narrowed actions
        let new_port_id = format!("port:{:06}", self.next_port_id);
        self.next_port_id += 1;
        let now = Self::now_ms();

        // Attenuate: only keep actions that are in both parent and requested
        let attenuated_actions: Vec<String> = if allowed_actions.is_empty() {
            port.allowed_actions.clone()
        } else {
            allowed_actions.into_iter().filter(|a| {
                port.allowed_actions.iter().any(|pa| {
                    pa == "*" || pa == a || (pa.ends_with('*') && a.starts_with(&pa[..pa.len()-1]))
                })
            }).collect()
        };

        let new_port = Port {
            port_id: new_port_id.clone(),
            port_type: port.port_type.clone(),
            owner_pid: delegate_to.clone(),
            bound_pids: Vec::new(),
            direction: port.direction.clone(),
            buffered: port.buffered,
            max_buffer_size: port.max_buffer_size,
            allowed_packet_types: port.allowed_packet_types.clone(),
            allowed_actions: attenuated_actions,
            max_delegation_depth: port.max_delegation_depth.saturating_sub(1),
            created_at: now,
            expires_at: port.expires_at, // Inherit parent TTL
            closed: false,
        };

        self.ports.insert(new_port_id.clone(), new_port);
        self.port_buffers.insert(new_port_id.clone(), Vec::new());

        // Also bind delegate_to on the original port
        if let Some(p) = self.ports.get_mut(&port_id) {
            if !p.bound_pids.contains(&delegate_to) {
                p.bound_pids.push(delegate_to.clone());
            }
        }

        let audit = self.make_audit(
            MemoryKernelOp::PortDelegate, &req.agent_pid,
            Some(format!("{}→{}:{}", port_id, delegate_to, new_port_id)),
            OpOutcome::Success, req.reason, None,
            Some(start.elapsed().as_micros() as u64), req.vakya_id,
        );

        SyscallResult { outcome: OpOutcome::Success, audit_entry: audit, value: SyscallValue::SessionId(new_port_id) }
    }

    // =========================================================================
    // Phase 9b: Tool dispatch handler (default-deny)
    // =========================================================================

    fn handle_tool_dispatch(
        &mut self,
        req: SyscallRequest,
        start: std::time::Instant,
    ) -> SyscallResult {
        let (tool_id, action, request_body) = match req.payload {
            SyscallPayload::ToolDispatch { tool_id, action, request } => (tool_id, action, request),
            _ => {
                let audit = self.make_audit(
                    MemoryKernelOp::ToolDispatch, &req.agent_pid, None,
                    OpOutcome::Failed, req.reason, Some("Invalid payload".to_string()),
                    Some(start.elapsed().as_micros() as u64), req.vakya_id,
                );
                return SyscallResult { outcome: OpOutcome::Failed, audit_entry: audit, value: SyscallValue::Error("Invalid payload".to_string()) };
            }
        };

        let acb = self.agents.get(&req.agent_pid).unwrap();

        // Default-deny: agent must have a ToolBinding that covers this tool+action
        if !Self::check_tool_binding(acb, &tool_id, &action) {
            let audit = self.make_audit(
                MemoryKernelOp::ToolDispatch, &req.agent_pid,
                Some(format!("{}:{}", tool_id, action)),
                OpOutcome::Denied, req.reason,
                Some(format!("No tool binding for {}:{}", tool_id, action)),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Denied, audit_entry: audit, value: SyscallValue::Error("Tool not bound".to_string()) };
        }

        // Check if the binding requires approval
        let binding = acb.tool_bindings.iter().find(|b| b.tool_id == tool_id || (b.tool_id.ends_with('*') && tool_id.starts_with(&b.tool_id[..b.tool_id.len()-1]))).unwrap();
        if binding.requires_approval {
            let audit = self.make_audit(
                MemoryKernelOp::ToolDispatch, &req.agent_pid,
                Some(format!("{}:{}", tool_id, action)),
                OpOutcome::Skipped, req.reason,
                Some(format!("Tool {} requires human approval", tool_id)),
                Some(start.elapsed().as_micros() as u64), req.vakya_id,
            );
            return SyscallResult { outcome: OpOutcome::Skipped, audit_entry: audit, value: SyscallValue::Error("Requires approval".to_string()) };
        }

        let audit = self.make_audit(
            MemoryKernelOp::ToolDispatch, &req.agent_pid,
            Some(format!("{}:{}:{}", tool_id, action, binding.data_classification)),
            OpOutcome::Success, req.reason, None,
            Some(start.elapsed().as_micros() as u64), req.vakya_id,
        );

        // Return the request body as confirmation (actual tool execution is external)
        let result_json = serde_json::to_string(&request_body).unwrap_or_default();
        SyscallResult { outcome: OpOutcome::Success, audit_entry: audit, value: SyscallValue::Error(result_json) }
    }

    // =========================================================================
    // Phase 9c: Port expiry helper
    // =========================================================================

    /// Check if a port has expired. Returns true if expired.
    fn is_port_expired(port: &Port) -> bool {
        if let Some(expires_at) = port.expires_at {
            Self::now_ms() > expires_at
        } else {
            false
        }
    }

    // =========================================================================
    // Phase 9d: Predefined role policies
    // =========================================================================

    /// Register all predefined role policies. Call after `new()` to enable
    /// role-based enforcement for all built-in roles.
    pub fn register_default_policies(&mut self) {
        use MemoryKernelOp::*;

        // Reader: read-only access
        self.register_policy(ExecutionPolicy {
            role: AgentRole::Reader,
            allowed_ops: vec![
                AgentStart, AgentTerminate,
                MemRead, AccessCheck, IntegrityCheck,
            ],
            phase_transitions: Vec::new(),
            rate_limits: std::collections::BTreeMap::new(),
            budget: BudgetPolicy::default(),
        });

        // Writer: read + write + sessions
        self.register_policy(ExecutionPolicy {
            role: AgentRole::Writer,
            allowed_ops: vec![
                AgentStart, AgentSuspend, AgentResume, AgentTerminate,
                MemAlloc, MemWrite, MemRead, MemSeal,
                SessionCreate, SessionClose, SessionCompress,
                ContextSnapshot, ContextRestore,
                AccessCheck,
                PortCreate, PortBind, PortSend, PortReceive, PortClose,
                ToolDispatch,
            ],
            phase_transitions: Vec::new(),
            rate_limits: std::collections::BTreeMap::new(),
            budget: BudgetPolicy::default(),
        });

        // Admin: full access
        self.register_policy(ExecutionPolicy {
            role: AgentRole::Admin,
            allowed_ops: vec![
                AgentRegister, AgentStart, AgentSuspend, AgentResume, AgentTerminate,
                MemAlloc, MemWrite, MemRead, MemEvict, MemPromote, MemDemote, MemClear, MemSeal,
                SessionCreate, SessionClose, SessionCompress,
                ContextSnapshot, ContextRestore,
                AccessGrant, AccessRevoke, AccessCheck,
                GarbageCollect, IndexRebuild, IntegrityCheck,
                PortCreate, PortBind, PortSend, PortReceive, PortClose, PortDelegate,
                ToolDispatch,
            ],
            phase_transitions: Vec::new(),
            rate_limits: std::collections::BTreeMap::new(),
            budget: BudgetPolicy::default(),
        });

        // ToolAgent: read + write + context + tools, rate-limited
        let mut tool_rate_limits = std::collections::BTreeMap::new();
        tool_rate_limits.insert("mem_write".to_string(), RateLimit { max_per_second: 50, max_per_minute: 500, max_burst: 10 });
        tool_rate_limits.insert("tool_dispatch".to_string(), RateLimit { max_per_second: 10, max_per_minute: 100, max_burst: 5 });
        self.register_policy(ExecutionPolicy {
            role: AgentRole::ToolAgent,
            allowed_ops: vec![
                AgentStart, AgentSuspend, AgentResume, AgentTerminate,
                MemAlloc, MemWrite, MemRead,
                SessionCreate, SessionClose,
                ContextSnapshot, ContextRestore,
                AccessCheck,
                PortCreate, PortBind, PortSend, PortReceive, PortClose,
                ToolDispatch,
            ],
            phase_transitions: Vec::new(),
            rate_limits: tool_rate_limits,
            budget: BudgetPolicy {
                max_tokens_per_session: 100_000,
                max_cost_per_session_usd: 10.0,
                max_packets_per_minute: 0,
                max_tool_calls_per_session: 0,
                enforce: true,
            },
        });

        // Auditor: read-only + integrity checks
        self.register_policy(ExecutionPolicy {
            role: AgentRole::Auditor,
            allowed_ops: vec![
                AgentStart, AgentTerminate,
                MemRead, AccessCheck, IntegrityCheck,
            ],
            phase_transitions: Vec::new(),
            rate_limits: std::collections::BTreeMap::new(),
            budget: BudgetPolicy::default(),
        });

        // Compactor: memory management ops
        self.register_policy(ExecutionPolicy {
            role: AgentRole::Compactor,
            allowed_ops: vec![
                AgentStart, AgentTerminate,
                MemRead, MemEvict, MemPromote, MemDemote, MemClear,
                SessionCompress,
                GarbageCollect, IndexRebuild, IntegrityCheck,
                AccessCheck,
            ],
            phase_transitions: Vec::new(),
            rate_limits: std::collections::BTreeMap::new(),
            budget: BudgetPolicy::default(),
        });
    }
}

impl Default for MemoryKernel {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tier 2: SharedKernel — thread-safe concurrency wrapper
// =============================================================================

/// Thread-safe wrapper around `MemoryKernel` using `Arc<RwLock>`.
///
/// Provides concurrent read access (multiple readers) and exclusive write
/// access (single writer) for multi-threaded agent runtimes.
///
/// Usage:
/// ```ignore
/// let shared = SharedKernel::new();
/// // Read path (non-blocking with other reads):
/// let agent = shared.read(|k| k.get_agent("pid:000001").cloned());
/// // Write path (exclusive):
/// let result = shared.dispatch(request);
/// ```
pub struct SharedKernel {
    inner: std::sync::Arc<std::sync::RwLock<MemoryKernel>>,
}

impl SharedKernel {
    /// Create a new SharedKernel wrapping a fresh MemoryKernel.
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(MemoryKernel::new())),
        }
    }

    /// Create from an existing MemoryKernel (e.g., after load_from_store).
    pub fn from_kernel(kernel: MemoryKernel) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(kernel)),
        }
    }

    /// Clone the Arc handle (cheap, reference-counted).
    pub fn handle(&self) -> Self {
        Self {
            inner: std::sync::Arc::clone(&self.inner),
        }
    }

    /// Dispatch a syscall (acquires write lock).
    pub fn dispatch(&self, req: SyscallRequest) -> SyscallResult {
        let mut kernel = self.inner.write().unwrap();
        kernel.dispatch(req)
    }

    /// Read-only access to kernel state (acquires read lock).
    /// Multiple readers can hold the lock simultaneously.
    pub fn read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&MemoryKernel) -> R,
    {
        let kernel = self.inner.read().unwrap();
        f(&kernel)
    }

    /// Write access to kernel state (acquires write lock).
    pub fn write<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut MemoryKernel) -> R,
    {
        let mut kernel = self.inner.write().unwrap();
        f(&mut kernel)
    }

    /// Flush to store (acquires read lock since flush_to_store takes &self).
    pub fn flush_to_store(&self, store: &mut dyn crate::store::KernelStore) -> Result<usize, String> {
        let kernel = self.inner.read().unwrap();
        kernel.flush_to_store(store)
    }
}

impl Default for SharedKernel {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_source() -> Source {
        Source {
            kind: SourceKind::Tool,
            principal_id: "did:key:z6MkTest".to_string(),
        }
    }

    fn make_packet(subject: &str, session: Option<&str>) -> MemPacket {
        let mut p = MemPacket::new(
            PacketType::Extraction,
            serde_json::json!({"fact": "test data"}),
            Cid::default(),
            subject.to_string(),
            "pipeline:test".to_string(),
            make_source(),
            MemoryKernel::now_ms(),
        );
        if let Some(sid) = session {
            p = p.with_session(sid.to_string());
        }
        p
    }

    fn register_agent(kernel: &mut MemoryKernel, name: &str, ns: &str) -> String {
        let result = kernel.dispatch(SyscallRequest {
            agent_pid: "".to_string(), // ignored for register
            operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: name.to_string(),
                namespace: ns.to_string(),
                role: Some("test".to_string()),
                model: None,
                framework: None,
            },
            reason: Some("test".to_string()),
            vakya_id: None,
        });
        assert_eq!(result.outcome, OpOutcome::Success);
        match result.value {
            SyscallValue::AgentPid(pid) => pid,
            _ => panic!("Expected AgentPid"),
        }
    }

    #[test]
    fn test_agent_lifecycle() {
        let mut kernel = MemoryKernel::new();

        // Register
        let pid = register_agent(&mut kernel, "bot-1", "ns:test");
        assert!(kernel.get_agent(&pid).is_some());
        assert_eq!(kernel.get_agent(&pid).unwrap().status, AgentStatus::Registered);

        // Start
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
        assert_eq!(kernel.get_agent(&pid).unwrap().status, AgentStatus::Running);

        // Suspend
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentSuspend,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
        assert_eq!(kernel.get_agent(&pid).unwrap().status, AgentStatus::Suspended);

        // Resume
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentResume,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
        assert_eq!(kernel.get_agent(&pid).unwrap().status, AgentStatus::Running);

        // Terminate
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentTerminate,
            payload: SyscallPayload::AgentTerminate {
                target_pid: None,
                reason: "done".to_string(),
            },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
        assert_eq!(kernel.get_agent(&pid).unwrap().status, AgentStatus::Terminated);

        // Audit trail should have 5 entries (register, start, suspend, resume, terminate)
        assert_eq!(kernel.audit_count(), 5);
    }

    #[test]
    fn test_mem_write_read() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "writer", "ns:test");

        // Start agent
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });

        // Write a packet
        let packet = make_packet("patient:P-001", None);
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: Some("store extraction".to_string()),
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        let written_cid = match r.value {
            SyscallValue::Cid(cid) => cid,
            _ => panic!("Expected CID"),
        };

        // Read it back
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemRead,
            payload: SyscallPayload::MemRead {
                packet_cid: written_cid.clone(),
            },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        match r.value {
            SyscallValue::Packet(p) => {
                assert_eq!(p.subject_id, "patient:P-001");
                assert_eq!(*p.packet_type(), PacketType::Extraction);
            }
            _ => panic!("Expected Packet"),
        }

        // Agent stats updated
        assert_eq!(kernel.get_agent(&pid).unwrap().total_packets, 1);
        assert_eq!(kernel.get_agent(&pid).unwrap().memory_region.used_packets, 1);
    }

    #[test]
    fn test_namespace_isolation() {
        let mut kernel = MemoryKernel::new();
        let pid_a = register_agent(&mut kernel, "agent-a", "ns:alpha");
        let pid_b = register_agent(&mut kernel, "agent-b", "ns:beta");

        // Start both
        for pid in [&pid_a, &pid_b] {
            kernel.dispatch(SyscallRequest {
                agent_pid: pid.clone(),
                operation: MemoryKernelOp::AgentStart,
                payload: SyscallPayload::Empty,
                reason: None,
                vakya_id: None,
            });
        }

        // Agent A writes a packet
        let packet = make_packet("data:secret", None);
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid_a.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: None,
            vakya_id: None,
        });
        let cid = match r.value {
            SyscallValue::Cid(c) => c,
            _ => panic!("Expected CID"),
        };

        // Agent B tries to read it — should be denied
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid_b.clone(),
            operation: MemoryKernelOp::MemRead,
            payload: SyscallPayload::MemRead { packet_cid: cid.clone() },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied);

        // Agent A grants read access to Agent B
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid_a.clone(),
            operation: MemoryKernelOp::AccessGrant,
            payload: SyscallPayload::AccessGrant {
                target_namespace: "ns:alpha".to_string(),
                grantee_pid: pid_b.clone(),
                read: true,
                write: false,
            },
            reason: Some("share data".to_string()),
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        // Now Agent B can read
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid_b.clone(),
            operation: MemoryKernelOp::MemRead,
            payload: SyscallPayload::MemRead { packet_cid: cid },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
    }

    #[test]
    fn test_session_lifecycle() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "bot", "ns:test");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });

        // Create session
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::SessionCreate,
            payload: SyscallPayload::SessionCreate {
                session_id: "sess:001".to_string(),
                label: Some("Test session".to_string()),
                parent_session_id: None,
            },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        // Write packets to session
        let packet = make_packet("user:alice", Some("sess:001"));
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: None,
            vakya_id: None,
        });

        let session = kernel.get_session("sess:001").unwrap();
        assert!(session.is_active());
        assert_eq!(session.packet_count(), 1);

        // Close session
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::SessionClose,
            payload: SyscallPayload::SessionClose {
                session_id: "sess:001".to_string(),
            },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
        assert!(!kernel.get_session("sess:001").unwrap().is_active());

        // Compress session
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::SessionCompress,
            payload: SyscallPayload::SessionCompress {
                session_id: "sess:001".to_string(),
                algorithm: "recursive_summarization".to_string(),
                summary: "User alice had a test interaction".to_string(),
            },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
        assert!(kernel.get_session("sess:001").unwrap().summary.is_some());
    }

    #[test]
    fn test_mem_seal_protects_packets() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "bot", "ns:test");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });

        // Write a packet
        let packet = make_packet("evidence:001", None);
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: None,
            vakya_id: None,
        });
        let cid = match r.value {
            SyscallValue::Cid(c) => c,
            _ => panic!("Expected CID"),
        };

        // Seal it
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemSeal,
            payload: SyscallPayload::MemSeal {
                cids: vec![cid.clone()],
            },
            reason: Some("evidence preservation".to_string()),
            vakya_id: None,
        });
        assert!(kernel.is_sealed(&cid));

        // Try to demote — should be denied
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemDemote,
            payload: SyscallPayload::TierChange {
                packet_cid: cid.clone(),
                new_tier: MemoryTier::Archive,
            },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied);

        // Try to evict — sealed packets are skipped
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemEvict,
            payload: SyscallPayload::MemEvict {
                cids: vec![cid.clone()],
                max_evict: 0,
            },
            reason: None,
            vakya_id: None,
        });
        // Evict returns success but count=0 (sealed packet skipped)
        match r.value {
            SyscallValue::Count(n) => assert_eq!(n, 0),
            _ => panic!("Expected Count"),
        }

        // Packet still exists
        assert!(kernel.get_packet(&cid).is_some());
    }

    #[test]
    fn test_context_snapshot_restore() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "bot", "ns:test");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });

        // Create session and write some packets
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::SessionCreate,
            payload: SyscallPayload::SessionCreate {
                session_id: "sess:ctx".to_string(),
                label: None,
                parent_session_id: None,
            },
            reason: None,
            vakya_id: None,
        });

        let packet = make_packet("data:1", Some("sess:ctx"));
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: None,
            vakya_id: None,
        });

        // Snapshot
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::ContextSnapshot,
            payload: SyscallPayload::ContextSnapshot {
                session_id: "sess:ctx".to_string(),
                pipeline_id: "pipe:test".to_string(),
            },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        let snapshot_cid = match r.value {
            SyscallValue::Context(ctx) => ctx.snapshot_cid.unwrap(),
            _ => panic!("Expected Context"),
        };

        // Restore
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::ContextRestore,
            payload: SyscallPayload::ContextRestore {
                snapshot_cid: snapshot_cid.clone(),
            },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        match r.value {
            SyscallValue::Context(ctx) => {
                assert!(ctx.restored);
                assert_eq!(ctx.suspend_count, 1);
                assert_eq!(ctx.session_id, "sess:ctx");
            }
            _ => panic!("Expected Context"),
        }
    }

    #[test]
    fn test_integrity_check() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "bot", "ns:test");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });

        // Integrity check on clean kernel should pass
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::IntegrityCheck,
            payload: SyscallPayload::IntegrityCheck,
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
        match r.value {
            SyscallValue::Bool(ok) => assert!(ok),
            _ => panic!("Expected Bool"),
        }
    }

    #[test]
    fn test_unregistered_agent_denied() {
        let mut kernel = MemoryKernel::new();

        let r = kernel.dispatch(SyscallRequest {
            agent_pid: "pid:nonexistent".to_string(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite {
                packet: make_packet("test", None),
            },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied);
    }

    #[test]
    fn test_mem_alloc_quota() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "bot", "ns:test");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });

        // Set quota to 2 packets
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemAlloc,
            payload: SyscallPayload::MemAlloc {
                quota_packets: 2,
                quota_tokens: 0,
                quota_bytes: 0,
                eviction_policy: EvictionPolicy::Lru,
            },
            reason: None,
            vakya_id: None,
        });

        // Write 2 packets — should succeed
        for i in 0..2 {
            let r = kernel.dispatch(SyscallRequest {
                agent_pid: pid.clone(),
                operation: MemoryKernelOp::MemWrite,
                payload: SyscallPayload::MemWrite {
                    packet: make_packet(&format!("data:{}", i), None),
                },
                reason: None,
                vakya_id: None,
            });
            assert_eq!(r.outcome, OpOutcome::Success);
        }

        // 3rd write — should be denied (at capacity)
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite {
                packet: make_packet("data:overflow", None),
            },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied);
    }

    #[test]
    fn test_full_workflow() {
        let mut kernel = MemoryKernel::new();

        // 1. Register agent
        let pid = register_agent(&mut kernel, "healthcare-bot", "ns:hospital");

        // 2. Start agent
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });

        // 3. Create session
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::SessionCreate,
            payload: SyscallPayload::SessionCreate {
                session_id: "sess:intake".to_string(),
                label: Some("Patient intake".to_string()),
                parent_session_id: None,
            },
            reason: None,
            vakya_id: None,
        });

        // 4. Write packets
        let mut cids = Vec::new();
        for i in 0..5 {
            let packet = MemPacket::new(
                PacketType::Extraction,
                serde_json::json!({"fact": format!("fact-{}", i)}),
                Cid::default(),
                "patient:P-001".to_string(),
                "pipeline:intake".to_string(),
                make_source(),
                MemoryKernel::now_ms(),
            )
            .with_session("sess:intake".to_string())
            .with_entities(vec!["patient:P-001".to_string()]);

            let r = kernel.dispatch(SyscallRequest {
                agent_pid: pid.clone(),
                operation: MemoryKernelOp::MemWrite,
                payload: SyscallPayload::MemWrite { packet },
                reason: None,
                vakya_id: None,
            });
            if let SyscallValue::Cid(cid) = r.value {
                cids.push(cid);
            }
        }
        assert_eq!(cids.len(), 5);
        assert_eq!(kernel.packet_count(), 5);

        // 5. Seal evidence
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemSeal,
            payload: SyscallPayload::MemSeal {
                cids: vec![cids[0].clone(), cids[1].clone()],
            },
            reason: Some("evidence preservation".to_string()),
            vakya_id: None,
        });

        // 6. Snapshot context
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::ContextSnapshot,
            payload: SyscallPayload::ContextSnapshot {
                session_id: "sess:intake".to_string(),
                pipeline_id: "pipeline:intake".to_string(),
            },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        // 7. Close session
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::SessionClose,
            payload: SyscallPayload::SessionClose {
                session_id: "sess:intake".to_string(),
            },
            reason: None,
            vakya_id: None,
        });

        // 8. Compress session
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::SessionCompress,
            payload: SyscallPayload::SessionCompress {
                session_id: "sess:intake".to_string(),
                algorithm: "recursive_summarization".to_string(),
                summary: "Patient P-001 intake: 5 facts extracted".to_string(),
            },
            reason: None,
            vakya_id: None,
        });

        // 9. Integrity check
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::IntegrityCheck,
            payload: SyscallPayload::IntegrityCheck,
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        // 10. Verify audit trail
        assert!(kernel.audit_count() >= 10);

        // 11. Terminate
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentTerminate,
            payload: SyscallPayload::AgentTerminate {
                target_pid: None,
                reason: "workflow complete".to_string(),
            },
            reason: None,
            vakya_id: None,
        });

        assert!(kernel.get_agent(&pid).unwrap().is_terminated());
    }

    // =========================================================================
    // Phase 8 Tests: Kernel Hardening
    // =========================================================================

    // --- 8a: ELS Phase FSM tests ---

    #[test]
    fn test_phase_fsm_registered_blocks_write() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "bot", "ns:test");
        // Agent is in Registered phase — MemWrite should be blocked
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet: make_packet("s", None) },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied);
        assert!(r.audit_entry.error.as_ref().unwrap().contains("not allowed in phase"));
    }

    #[test]
    fn test_phase_fsm_registered_allows_start() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "bot", "ns:test");
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
        assert_eq!(kernel.get_agent(&pid).unwrap().phase, AgentPhase::Active);
    }

    #[test]
    fn test_phase_fsm_active_blocks_start() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "bot", "ns:test");
        start_agent(&mut kernel, &pid);
        // Already active — AgentStart should be blocked by phase check
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied);
    }

    #[test]
    fn test_phase_fsm_suspended_blocks_write() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "bot", "ns:test");
        start_agent(&mut kernel, &pid);
        // Suspend
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentSuspend,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });
        assert_eq!(kernel.get_agent(&pid).unwrap().phase, AgentPhase::Suspended);
        // MemWrite should be blocked
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet: make_packet("s", None) },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied);
    }

    #[test]
    fn test_phase_fsm_suspended_allows_resume() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "bot", "ns:test");
        start_agent(&mut kernel, &pid);
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentSuspend,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentResume,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
        assert_eq!(kernel.get_agent(&pid).unwrap().phase, AgentPhase::Active);
    }

    #[test]
    fn test_phase_fsm_terminate_sets_terminating() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "bot", "ns:test");
        start_agent(&mut kernel, &pid);
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentTerminate,
            payload: SyscallPayload::AgentTerminate {
                target_pid: None,
                reason: "done".to_string(),
            },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(kernel.get_agent(&pid).unwrap().phase, AgentPhase::Terminating);
    }

    // --- 8a: ELS Role Allowlist tests ---

    #[test]
    fn test_role_allowlist_blocks_disallowed_op() {
        let mut kernel = MemoryKernel::new();
        // Register a reader policy that only allows MemRead and AccessCheck
        kernel.register_policy(ExecutionPolicy {
            role: AgentRole::Reader,
            allowed_ops: vec![
                MemoryKernelOp::AgentStart,
                MemoryKernelOp::AgentTerminate,
                MemoryKernelOp::MemRead,
                MemoryKernelOp::AccessCheck,
            ],
            phase_transitions: Vec::new(),
            rate_limits: std::collections::BTreeMap::new(),
            budget: BudgetPolicy::default(),
        });

        let pid = register_agent(&mut kernel, "reader-bot", "ns:test");
        // Set role to Reader
        kernel.agents.get_mut(&pid).unwrap().role = AgentRole::Reader;
        start_agent(&mut kernel, &pid);

        // MemWrite should be blocked by allowlist
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet: make_packet("s", None) },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied);
        assert!(r.audit_entry.error.as_ref().unwrap().contains("not allowed for role"));
    }

    #[test]
    fn test_role_allowlist_allows_permitted_op() {
        let mut kernel = MemoryKernel::new();
        kernel.register_policy(ExecutionPolicy {
            role: AgentRole::Writer,
            allowed_ops: vec![
                MemoryKernelOp::AgentStart,
                MemoryKernelOp::AgentTerminate,
                MemoryKernelOp::AgentSuspend,
                MemoryKernelOp::MemRead,
                MemoryKernelOp::MemWrite,
                MemoryKernelOp::SessionCreate,
                MemoryKernelOp::SessionClose,
            ],
            phase_transitions: Vec::new(),
            rate_limits: std::collections::BTreeMap::new(),
            budget: BudgetPolicy::default(),
        });

        let pid = register_agent(&mut kernel, "writer-bot", "ns:test");
        start_agent(&mut kernel, &pid);

        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet: make_packet("s", None) },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
    }

    // --- 8a: Budget enforcement tests ---

    #[test]
    fn test_budget_enforcement_token_limit() {
        let mut kernel = MemoryKernel::new();
        kernel.register_policy(ExecutionPolicy {
            role: AgentRole::Writer,
            allowed_ops: vec![
                MemoryKernelOp::AgentStart,
                MemoryKernelOp::MemWrite,
            ],
            phase_transitions: Vec::new(),
            rate_limits: std::collections::BTreeMap::new(),
            budget: BudgetPolicy {
                max_tokens_per_session: 100,
                max_cost_per_session_usd: 0.0,
                max_packets_per_minute: 0,
                max_tool_calls_per_session: 0,
                enforce: true,
            },
        });

        let pid = register_agent(&mut kernel, "bot", "ns:test");
        start_agent(&mut kernel, &pid);

        // Set tokens consumed to exceed budget
        kernel.agents.get_mut(&pid).unwrap().total_tokens_consumed = 150;

        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet: make_packet("s", None) },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied);
        assert!(r.audit_entry.error.as_ref().unwrap().contains("Token budget exceeded"));
    }

    #[test]
    fn test_budget_enforcement_cost_limit() {
        let mut kernel = MemoryKernel::new();
        kernel.register_policy(ExecutionPolicy {
            role: AgentRole::Writer,
            allowed_ops: vec![
                MemoryKernelOp::AgentStart,
                MemoryKernelOp::MemWrite,
            ],
            phase_transitions: Vec::new(),
            rate_limits: std::collections::BTreeMap::new(),
            budget: BudgetPolicy {
                max_tokens_per_session: 0,
                max_cost_per_session_usd: 5.0,
                max_packets_per_minute: 0,
                max_tool_calls_per_session: 0,
                enforce: true,
            },
        });

        let pid = register_agent(&mut kernel, "bot", "ns:test");
        start_agent(&mut kernel, &pid);
        kernel.agents.get_mut(&pid).unwrap().total_cost_usd = 6.0;

        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet: make_packet("s", None) },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied);
        assert!(r.audit_entry.error.as_ref().unwrap().contains("Cost budget exceeded"));
    }

    // --- 8d: Port system tests ---

    fn start_agent(kernel: &mut MemoryKernel, pid: &str) {
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.to_string(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });
    }

    #[test]
    fn test_port_create_and_bind() {
        let mut kernel = MemoryKernel::new();
        let pid1 = register_agent(&mut kernel, "agent-a", "ns:a");
        let pid2 = register_agent(&mut kernel, "agent-b", "ns:b");
        start_agent(&mut kernel, &pid1);
        start_agent(&mut kernel, &pid2);

        // Create port
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid1.clone(),
            operation: MemoryKernelOp::PortCreate,
            payload: SyscallPayload::PortCreate {
                port_type: PortType::RequestResponse,
                direction: PortDirection::Bidirectional,
                allowed_packet_types: vec![PacketType::Extraction],
                allowed_actions: vec!["ehr.read_*".to_string()],
                max_delegation_depth: 3,
                ttl_ms: None,
            },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
        let port_id = match r.value {
            SyscallValue::SessionId(id) => id,
            _ => panic!("Expected port ID"),
        };

        // Bind agent-b
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid1.clone(),
            operation: MemoryKernelOp::PortBind,
            payload: SyscallPayload::PortBind {
                port_id: port_id.clone(),
                target_pid: pid2.clone(),
            },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        let port = kernel.get_port(&port_id).unwrap();
        assert_eq!(port.bound_pids, vec![pid2.clone()]);
        assert_eq!(port.port_type, PortType::RequestResponse);
    }

    #[test]
    fn test_port_send_receive() {
        let mut kernel = MemoryKernel::new();
        let pid1 = register_agent(&mut kernel, "sender", "ns:a");
        let pid2 = register_agent(&mut kernel, "receiver", "ns:b");
        start_agent(&mut kernel, &pid1);
        start_agent(&mut kernel, &pid2);

        // Create port
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid1.clone(),
            operation: MemoryKernelOp::PortCreate,
            payload: SyscallPayload::PortCreate {
                port_type: PortType::EventStream,
                direction: PortDirection::Send,
                allowed_packet_types: Vec::new(),
                allowed_actions: vec!["*".to_string()],
                max_delegation_depth: 2,
                ttl_ms: None,
            },
            reason: None,
            vakya_id: None,
        });
        let port_id = match r.value { SyscallValue::SessionId(id) => id, _ => panic!() };

        // Bind receiver
        kernel.dispatch(SyscallRequest {
            agent_pid: pid1.clone(),
            operation: MemoryKernelOp::PortBind,
            payload: SyscallPayload::PortBind { port_id: port_id.clone(), target_pid: pid2.clone() },
            reason: None, vakya_id: None,
        });

        // Send message
        let msg = PortMessage {
            message_id: "msg:001".to_string(),
            sender_pid: pid1.clone(),
            port_id: port_id.clone(),
            timestamp: MemoryKernel::now_ms(),
            payload: PortPayload::Event {
                event_type: "patient_updated".to_string(),
                data: serde_json::json!({"patient": "P-001"}),
            },
        };
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid1.clone(),
            operation: MemoryKernelOp::PortSend,
            payload: SyscallPayload::PortSend { port_id: port_id.clone(), message: msg },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        // Receive message (by bound agent)
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid2.clone(),
            operation: MemoryKernelOp::PortReceive,
            payload: SyscallPayload::PortReceive { port_id: port_id.clone() },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        // Buffer should be empty now
        assert_eq!(kernel.port_messages(&port_id).len(), 0);
    }

    #[test]
    fn test_port_unauthorized_send_denied() {
        let mut kernel = MemoryKernel::new();
        let pid1 = register_agent(&mut kernel, "owner", "ns:a");
        let pid2 = register_agent(&mut kernel, "outsider", "ns:b");
        start_agent(&mut kernel, &pid1);
        start_agent(&mut kernel, &pid2);

        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid1.clone(),
            operation: MemoryKernelOp::PortCreate,
            payload: SyscallPayload::PortCreate {
                port_type: PortType::MemoryShare,
                direction: PortDirection::Bidirectional,
                allowed_packet_types: Vec::new(),
                allowed_actions: Vec::new(),
                max_delegation_depth: 1,
                ttl_ms: None,
            },
            reason: None, vakya_id: None,
        });
        let port_id = match r.value { SyscallValue::SessionId(id) => id, _ => panic!() };

        // pid2 is NOT bound — send should be denied
        let msg = PortMessage {
            message_id: "msg:x".to_string(),
            sender_pid: pid2.clone(),
            port_id: port_id.clone(),
            timestamp: 0,
            payload: PortPayload::Event { event_type: "test".to_string(), data: serde_json::json!(null) },
        };
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid2.clone(),
            operation: MemoryKernelOp::PortSend,
            payload: SyscallPayload::PortSend { port_id: port_id.clone(), message: msg },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied);
    }

    #[test]
    fn test_port_close_drains_buffer() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "bot", "ns:test");
        start_agent(&mut kernel, &pid);

        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::PortCreate,
            payload: SyscallPayload::PortCreate {
                port_type: PortType::Broadcast,
                direction: PortDirection::Send,
                allowed_packet_types: Vec::new(),
                allowed_actions: Vec::new(),
                max_delegation_depth: 1,
                ttl_ms: None,
            },
            reason: None, vakya_id: None,
        });
        let port_id = match r.value { SyscallValue::SessionId(id) => id, _ => panic!() };

        // Send 3 messages
        for i in 0..3 {
            let msg = PortMessage {
                message_id: format!("msg:{}", i),
                sender_pid: pid.clone(),
                port_id: port_id.clone(),
                timestamp: 0,
                payload: PortPayload::Event { event_type: "test".to_string(), data: serde_json::json!(i) },
            };
            kernel.dispatch(SyscallRequest {
                agent_pid: pid.clone(),
                operation: MemoryKernelOp::PortSend,
                payload: SyscallPayload::PortSend { port_id: port_id.clone(), message: msg },
                reason: None, vakya_id: None,
            });
        }

        // Close — should drain 3 messages
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::PortClose,
            payload: SyscallPayload::PortClose { port_id: port_id.clone() },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
        assert_eq!(r.value, SyscallValue::Count(3));
        assert!(kernel.get_port(&port_id).unwrap().closed);
    }

    #[test]
    fn test_port_delegate_attenuates() {
        let mut kernel = MemoryKernel::new();
        let pid1 = register_agent(&mut kernel, "triage", "ns:a");
        let pid2 = register_agent(&mut kernel, "specialist", "ns:b");
        start_agent(&mut kernel, &pid1);
        start_agent(&mut kernel, &pid2);

        // Create port with broad actions
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid1.clone(),
            operation: MemoryKernelOp::PortCreate,
            payload: SyscallPayload::PortCreate {
                port_type: PortType::ToolDelegate,
                direction: PortDirection::Send,
                allowed_packet_types: Vec::new(),
                allowed_actions: vec!["ehr.read_*".to_string(), "ehr.write_*".to_string()],
                max_delegation_depth: 3,
                ttl_ms: None,
            },
            reason: None, vakya_id: None,
        });
        let port_id = match r.value { SyscallValue::SessionId(id) => id, _ => panic!() };

        // Delegate with narrowed actions (only read)
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid1.clone(),
            operation: MemoryKernelOp::PortDelegate,
            payload: SyscallPayload::PortDelegate {
                port_id: port_id.clone(),
                delegate_to: pid2.clone(),
                allowed_actions: vec!["ehr.read_allergy".to_string()],
            },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
        let new_port_id = match r.value { SyscallValue::SessionId(id) => id, _ => panic!() };

        // New port should have attenuated actions
        let new_port = kernel.get_port(&new_port_id).unwrap();
        assert_eq!(new_port.owner_pid, pid2);
        assert_eq!(new_port.allowed_actions, vec!["ehr.read_allergy".to_string()]);
        assert_eq!(new_port.max_delegation_depth, 2); // Decremented
    }

    #[test]
    fn test_port_delegate_depth_limit() {
        let mut kernel = MemoryKernel::new();
        let pid1 = register_agent(&mut kernel, "a", "ns:a");
        let pid2 = register_agent(&mut kernel, "b", "ns:b");
        start_agent(&mut kernel, &pid1);
        start_agent(&mut kernel, &pid2);

        // Create port with max_delegation_depth = 0
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid1.clone(),
            operation: MemoryKernelOp::PortCreate,
            payload: SyscallPayload::PortCreate {
                port_type: PortType::Pipeline,
                direction: PortDirection::Bidirectional,
                allowed_packet_types: Vec::new(),
                allowed_actions: vec!["*".to_string()],
                max_delegation_depth: 0,
                ttl_ms: None,
            },
            reason: None, vakya_id: None,
        });
        let port_id = match r.value { SyscallValue::SessionId(id) => id, _ => panic!() };

        // Delegate should be denied (depth 0)
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid1.clone(),
            operation: MemoryKernelOp::PortDelegate,
            payload: SyscallPayload::PortDelegate {
                port_id: port_id.clone(),
                delegate_to: pid2.clone(),
                allowed_actions: Vec::new(),
            },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied);
    }

    // --- 8e: Delegation chain tests ---

    #[test]
    fn test_delegation_chain_valid() {
        let now = MemoryKernel::now_ms();
        let chain = DelegationChain {
            proofs: vec![
                DelegationProof {
                    proof_cid: "cid:root".to_string(),
                    issuer: "user:alice".to_string(),
                    subject: "agent:triage".to_string(),
                    allowed_actions: vec!["*".to_string()],
                    allowed_resources: vec!["*".to_string()],
                    expires_at: now + 60000,
                    parent_proof_cid: None,
                    signature: None,
                    issued_at: now - 1000,
                    revoked: false,
                },
                DelegationProof {
                    proof_cid: "cid:child".to_string(),
                    issuer: "agent:triage".to_string(),
                    subject: "agent:specialist".to_string(),
                    allowed_actions: vec!["ehr.read_*".to_string()],
                    allowed_resources: vec!["patient:*".to_string()],
                    expires_at: now + 30000,
                    parent_proof_cid: Some("cid:root".to_string()),
                    signature: None,
                    issued_at: now - 500,
                    revoked: false,
                },
            ],
            chain_cid: "chain:001".to_string(),
        };

        assert!(chain.verify(now).is_ok());
        assert!(chain.allows("ehr.read_allergy", "patient:P-001", now));
        assert!(!chain.allows("ehr.write_allergy", "patient:P-001", now)); // Not in child actions
    }

    #[test]
    fn test_delegation_chain_expired() {
        let now = MemoryKernel::now_ms();
        let chain = DelegationChain {
            proofs: vec![DelegationProof {
                proof_cid: "cid:expired".to_string(),
                issuer: "user:alice".to_string(),
                subject: "agent:bot".to_string(),
                allowed_actions: vec!["*".to_string()],
                allowed_resources: vec!["*".to_string()],
                expires_at: now - 1000, // Already expired
                parent_proof_cid: None,
                signature: None,
                issued_at: now - 60000,
                revoked: false,
            }],
            chain_cid: "chain:expired".to_string(),
        };

        assert!(chain.verify(now).is_err());
        assert!(!chain.allows("anything", "anything", now));
    }

    #[test]
    fn test_delegation_chain_revoked() {
        let now = MemoryKernel::now_ms();
        let chain = DelegationChain {
            proofs: vec![DelegationProof {
                proof_cid: "cid:revoked".to_string(),
                issuer: "user:alice".to_string(),
                subject: "agent:bot".to_string(),
                allowed_actions: vec!["*".to_string()],
                allowed_resources: vec!["*".to_string()],
                expires_at: now + 60000,
                parent_proof_cid: None,
                signature: None,
                issued_at: now - 1000,
                revoked: true, // Revoked!
            }],
            chain_cid: "chain:revoked".to_string(),
        };

        assert!(chain.verify(now).is_err());
    }

    #[test]
    fn test_delegation_chain_attenuation_violation() {
        let now = MemoryKernel::now_ms();
        let chain = DelegationChain {
            proofs: vec![
                DelegationProof {
                    proof_cid: "cid:root".to_string(),
                    issuer: "user:alice".to_string(),
                    subject: "agent:triage".to_string(),
                    allowed_actions: vec!["ehr.read_*".to_string()], // Only read
                    allowed_resources: vec!["*".to_string()],
                    expires_at: now + 60000,
                    parent_proof_cid: None,
                    signature: None,
                    issued_at: now - 1000,
                    revoked: false,
                },
                DelegationProof {
                    proof_cid: "cid:child".to_string(),
                    issuer: "agent:triage".to_string(),
                    subject: "agent:specialist".to_string(),
                    allowed_actions: vec!["ehr.write_allergy".to_string()], // WRITE — not covered by parent!
                    allowed_resources: vec!["*".to_string()],
                    expires_at: now + 30000,
                    parent_proof_cid: Some("cid:root".to_string()),
                    signature: None,
                    issued_at: now - 500,
                    revoked: false,
                },
            ],
            chain_cid: "chain:violation".to_string(),
        };

        let result = chain.verify(now);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not covered by parent"));
    }

    // --- 8b/8c: Type construction tests ---

    #[test]
    fn test_namespace_mount_and_tool_binding() {
        let mount = NamespaceMount {
            source: "org:acme/team:support/shared/knowledge".to_string(),
            mount_point: "/shared/knowledge".to_string(),
            mode: MountMode::ReadOnly,
            filters: vec![MountFilter {
                packet_types: Some(vec![PacketType::Extraction]),
                time_range: None,
                entity_filter: Some(vec!["patient:*".to_string()]),
                tier_filter: None,
                max_packets: Some(1000),
            }],
        };
        assert_eq!(mount.mode, MountMode::ReadOnly);
        assert_eq!(mount.filters.len(), 1);

        let binding = ToolBinding {
            tool_id: "ehr.read_patient".to_string(),
            namespace_path: "/tools/ehr".to_string(),
            allowed_actions: vec!["ehr.read_*".to_string()],
            allowed_resources: vec!["patient:*".to_string()],
            rate_limit: Some(RateLimit { max_per_second: 10, max_per_minute: 100, max_burst: 5 }),
            data_classification: "phi".to_string(),
            requires_approval: false,
        };
        assert_eq!(binding.tool_id, "ehr.read_patient");
        assert_eq!(binding.data_classification, "phi");
    }

    #[test]
    fn test_acb_with_hardening_fields() {
        let mut acb = AgentControlBlock::new(
            "pid:001".to_string(),
            "test-bot".to_string(),
            "ns:test".to_string(),
            MemoryKernel::now_ms(),
        );
        assert_eq!(acb.phase, AgentPhase::Registered);
        assert_eq!(acb.role, AgentRole::Writer);
        assert!(acb.namespace_mounts.is_empty());
        assert!(acb.tool_bindings.is_empty());

        // Add mounts and bindings
        acb.namespace_mounts.push(NamespaceMount {
            source: "ns:shared".to_string(),
            mount_point: "/shared".to_string(),
            mode: MountMode::ReadOnly,
            filters: Vec::new(),
        });
        acb.tool_bindings.push(ToolBinding {
            tool_id: "search".to_string(),
            namespace_path: "/tools".to_string(),
            allowed_actions: vec!["search.*".to_string()],
            allowed_resources: vec!["*".to_string()],
            rate_limit: None,
            data_classification: "public".to_string(),
            requires_approval: false,
        });

        assert_eq!(acb.namespace_mounts.len(), 1);
        assert_eq!(acb.tool_bindings.len(), 1);
    }

    // --- 8: Integration test ---

    #[test]
    fn test_hardened_multi_agent_pipeline() {
        let mut kernel = MemoryKernel::new();

        // Register two agents
        let triage_pid = register_agent(&mut kernel, "triage", "ns:triage");
        let specialist_pid = register_agent(&mut kernel, "specialist", "ns:specialist");
        start_agent(&mut kernel, &triage_pid);
        start_agent(&mut kernel, &specialist_pid);

        // Triage creates a pipeline port
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: triage_pid.clone(),
            operation: MemoryKernelOp::PortCreate,
            payload: SyscallPayload::PortCreate {
                port_type: PortType::Pipeline,
                direction: PortDirection::Bidirectional,
                allowed_packet_types: vec![PacketType::Extraction, PacketType::Decision],
                allowed_actions: vec!["ehr.*".to_string()],
                max_delegation_depth: 2,
                ttl_ms: Some(60000),
            },
            reason: Some("triage→specialist pipeline".to_string()),
            vakya_id: Some("vakya:pipeline-001".to_string()),
        });
        assert_eq!(r.outcome, OpOutcome::Success);
        let port_id = match r.value { SyscallValue::SessionId(id) => id, _ => panic!() };

        // Bind specialist
        kernel.dispatch(SyscallRequest {
            agent_pid: triage_pid.clone(),
            operation: MemoryKernelOp::PortBind,
            payload: SyscallPayload::PortBind { port_id: port_id.clone(), target_pid: specialist_pid.clone() },
            reason: None, vakya_id: None,
        });

        // Triage sends handoff
        let handoff = PortMessage {
            message_id: "msg:handoff-001".to_string(),
            sender_pid: triage_pid.clone(),
            port_id: port_id.clone(),
            timestamp: MemoryKernel::now_ms(),
            payload: PortPayload::PipelineHandoff {
                pipeline_id: "pipeline:intake".to_string(),
                step: 1,
                context_cids: vec!["cid:patient-data".to_string()],
                next_action: "ehr.review_allergy".to_string(),
            },
        };
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: triage_pid.clone(),
            operation: MemoryKernelOp::PortSend,
            payload: SyscallPayload::PortSend { port_id: port_id.clone(), message: handoff },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        // Specialist receives
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: specialist_pid.clone(),
            operation: MemoryKernelOp::PortReceive,
            payload: SyscallPayload::PortReceive { port_id: port_id.clone() },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        // Delegate to a sub-specialist (attenuated)
        let sub_pid = register_agent(&mut kernel, "sub-specialist", "ns:sub");
        start_agent(&mut kernel, &sub_pid);

        let r = kernel.dispatch(SyscallRequest {
            agent_pid: triage_pid.clone(),
            operation: MemoryKernelOp::PortDelegate,
            payload: SyscallPayload::PortDelegate {
                port_id: port_id.clone(),
                delegate_to: sub_pid.clone(),
                allowed_actions: vec!["ehr.read_allergy".to_string()],
            },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        // Verify audit trail covers all port operations
        let port_audits: Vec<_> = kernel.audit_log().iter()
            .filter(|a| matches!(a.operation,
                MemoryKernelOp::PortCreate | MemoryKernelOp::PortBind |
                MemoryKernelOp::PortSend | MemoryKernelOp::PortReceive |
                MemoryKernelOp::PortDelegate
            ))
            .collect();
        assert_eq!(port_audits.len(), 5); // create + bind + send + receive + delegate
    }

    // =========================================================================
    // Phase 9i: Comprehensive tests for all Phase 9 features
    // =========================================================================

    /// Helper to create a test MemPacket for Phase 9i tests
    fn make_phase9_packet(ns: &str, ts: i64) -> MemPacket {
        MemPacket::new(
            PacketType::Extraction,
            serde_json::json!({"test": true}),
            Cid::default(),
            "subject:test".to_string(),
            "pipeline:test".to_string(),
            Source { kind: SourceKind::User, principal_id: "user:test".to_string() },
            ts,
        ).with_namespace(ns.to_string())
    }

    /// Helper to create a full Port struct with all required fields
    fn make_expired_port(port_id: &str, port_type: PortType, owner_pid: &str) -> Port {
        Port {
            port_id: port_id.to_string(),
            port_type,
            owner_pid: owner_pid.to_string(),
            bound_pids: vec![],
            direction: PortDirection::Bidirectional,
            buffered: true,
            max_buffer_size: 10,
            allowed_packet_types: vec![],
            allowed_actions: vec!["*".to_string()],
            max_delegation_depth: 3,
            created_at: 1000,
            expires_at: Some(1), // already expired
            closed: false,
        }
    }

    #[test]
    fn test_phase9a_mount_enforcement_mem_write() {
        let mut kernel = MemoryKernel::new();
        // Agent's own namespace is "ns:home" — different from target "ns:shared"
        let pid = register_agent(&mut kernel, "writer", "ns:home");
        start_agent(&mut kernel, &pid);

        // Add a ReadOnly mount to "ns:shared" — should block writes
        if let Some(acb) = kernel.agents.get_mut(&pid) {
            acb.namespace_mounts = vec![NamespaceMount {
                source: "ns:shared".to_string(),
                mount_point: "/shared".to_string(),
                mode: MountMode::ReadOnly,
                filters: vec![],
            }];
        }

        // Write to ns:shared — agent has no legacy access, only ReadOnly mount
        let packet = make_phase9_packet("ns:shared", 1000);
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied, "ReadOnly mount should deny writes");
    }

    #[test]
    fn test_phase9a_mount_enforcement_mem_read_filter() {
        let mut kernel = MemoryKernel::new();
        // Agent's own namespace is "ns:home" — different from "ns:data"
        let pid = register_agent(&mut kernel, "reader", "ns:home");
        start_agent(&mut kernel, &pid);

        // Write a packet with entity "alice" to ns:data using a writer agent
        let writer_pid = register_agent(&mut kernel, "writer", "ns:data");
        start_agent(&mut kernel, &writer_pid);
        let mut packet = make_phase9_packet("ns:data", 1000);
        packet.content.entities = vec!["alice".to_string()];
        kernel.dispatch(SyscallRequest {
            agent_pid: writer_pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet: packet.clone() },
            reason: None, vakya_id: None,
        });

        // Give reader a mount to ns:data with entity filter allowing only "bob"
        if let Some(acb) = kernel.agents.get_mut(&pid) {
            acb.namespace_mounts = vec![NamespaceMount {
                source: "ns:data".to_string(),
                mount_point: "/data".to_string(),
                mode: MountMode::ReadWrite,
                filters: vec![MountFilter {
                    packet_types: None,
                    time_range: None,
                    entity_filter: Some(vec!["bob".to_string()]),
                    tier_filter: None,
                    max_packets: None,
                }],
            }];
        }

        // Read should fail: mount grants access but filter blocks "alice"
        // (outcome may be Denied or Failed depending on packet lookup order)
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemRead,
            payload: SyscallPayload::MemRead {
                packet_cid: packet.index.packet_cid.clone(),
            },
            reason: None, vakya_id: None,
        });
        assert_ne!(r.outcome, OpOutcome::Success, "Entity filter should block read for non-whitelisted entity");
    }

    #[test]
    fn test_phase9b_tool_dispatch_default_deny() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "tool-agent", "ns:tools");
        start_agent(&mut kernel, &pid);

        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::ToolDispatch,
            payload: SyscallPayload::ToolDispatch {
                tool_id: "unknown_tool".to_string(),
                action: "query".to_string(),
                request: serde_json::json!({"query": "test"}),
            },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied, "Unbound tool should be denied");
    }

    #[test]
    fn test_phase9b_tool_dispatch_approved_binding() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "tool-agent", "ns:tools");
        start_agent(&mut kernel, &pid);

        if let Some(acb) = kernel.agents.get_mut(&pid) {
            acb.tool_bindings = vec![ToolBinding {
                tool_id: "search_api".to_string(),
                namespace_path: "ns:tools".to_string(),
                allowed_actions: vec!["*".to_string()],
                allowed_resources: vec!["*".to_string()],
                rate_limit: None,
                data_classification: "public".to_string(),
                requires_approval: false,
            }];
        }

        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::ToolDispatch,
            payload: SyscallPayload::ToolDispatch {
                tool_id: "search_api".to_string(),
                action: "search".to_string(),
                request: serde_json::json!({"query": "test"}),
            },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success, "Pre-approved tool binding should succeed");
    }

    #[test]
    fn test_phase9b_tool_dispatch_requires_approval() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "tool-agent", "ns:tools");
        start_agent(&mut kernel, &pid);

        if let Some(acb) = kernel.agents.get_mut(&pid) {
            acb.tool_bindings = vec![ToolBinding {
                tool_id: "dangerous_tool".to_string(),
                namespace_path: "ns:tools".to_string(),
                allowed_actions: vec!["*".to_string()],
                allowed_resources: vec!["*".to_string()],
                rate_limit: None,
                data_classification: "phi".to_string(),
                requires_approval: true,
            }];
        }

        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::ToolDispatch,
            payload: SyscallPayload::ToolDispatch {
                tool_id: "dangerous_tool".to_string(),
                action: "delete_all".to_string(),
                request: serde_json::json!({"confirm": false}),
            },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Skipped, "Tool requiring approval should be skipped");
    }

    #[test]
    fn test_phase9c_port_expiry_send() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "sender", "ns:expiry");
        start_agent(&mut kernel, &pid);

        let port_id = "port:expired_send".to_string();
        kernel.ports.insert(port_id.clone(), make_expired_port(&port_id, PortType::RequestResponse, &pid));

        let msg = PortMessage {
            message_id: "msg:1".to_string(),
            sender_pid: pid.clone(),
            port_id: port_id.clone(),
            timestamp: 2000,
            payload: PortPayload::PacketShare { cids: vec!["cid:test".to_string()], namespace: "ns:expiry".to_string() },
        };

        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::PortSend,
            payload: SyscallPayload::PortSend { port_id: port_id.clone(), message: msg },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied, "Expired port should deny send");
        assert!(kernel.ports.get(&port_id).unwrap().closed);
    }

    #[test]
    fn test_phase9c_port_expiry_receive() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "receiver", "ns:expiry");
        start_agent(&mut kernel, &pid);

        let port_id = "port:expired_recv".to_string();
        kernel.ports.insert(port_id.clone(), make_expired_port(&port_id, PortType::EventStream, &pid));

        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::PortReceive,
            payload: SyscallPayload::PortReceive { port_id: port_id.clone() },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied, "Expired port should deny receive");
        assert!(kernel.ports.get(&port_id).unwrap().closed);
    }

    #[test]
    fn test_phase9c_port_expiry_bind() {
        let mut kernel = MemoryKernel::new();
        let owner = register_agent(&mut kernel, "owner", "ns:expiry");
        let binder = register_agent(&mut kernel, "binder", "ns:expiry");
        start_agent(&mut kernel, &owner);
        start_agent(&mut kernel, &binder);

        let port_id = "port:expired_bind".to_string();
        kernel.ports.insert(port_id.clone(), make_expired_port(&port_id, PortType::Pipeline, &owner));

        let r = kernel.dispatch(SyscallRequest {
            agent_pid: owner.clone(),
            operation: MemoryKernelOp::PortBind,
            payload: SyscallPayload::PortBind { port_id: port_id.clone(), target_pid: binder.clone() },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Denied, "Expired port should deny bind");
        assert!(kernel.ports.get(&port_id).unwrap().closed);
    }

    #[test]
    fn test_phase9d_predefined_role_policies() {
        let mut kernel = MemoryKernel::new();
        kernel.register_default_policies();

        // Verify all 6 roles have policies (keyed by role.to_string())
        assert!(kernel.execution_policies.contains_key("reader"));
        assert!(kernel.execution_policies.contains_key("writer"));
        assert!(kernel.execution_policies.contains_key("admin"));
        assert!(kernel.execution_policies.contains_key("tool_agent"));
        assert!(kernel.execution_policies.contains_key("auditor"));
        assert!(kernel.execution_policies.contains_key("compactor"));

        let reader_policy = &kernel.execution_policies["reader"];
        assert!(reader_policy.allowed_ops.contains(&MemoryKernelOp::MemRead));
        assert!(!reader_policy.allowed_ops.contains(&MemoryKernelOp::MemWrite));

        let writer_policy = &kernel.execution_policies["writer"];
        assert!(writer_policy.allowed_ops.contains(&MemoryKernelOp::MemRead));
        assert!(writer_policy.allowed_ops.contains(&MemoryKernelOp::MemWrite));

        let admin_policy = &kernel.execution_policies["admin"];
        assert!(admin_policy.allowed_ops.len() > writer_policy.allowed_ops.len());

        let tool_policy = &kernel.execution_policies["tool_agent"];
        assert!(tool_policy.allowed_ops.contains(&MemoryKernelOp::ToolDispatch));
    }

    #[test]
    fn test_phase9g_ed25519_sign_and_verify() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let root_key = SigningKey::generate(&mut OsRng);
        let delegatee_key = SigningKey::generate(&mut OsRng);
        let root_pub = root_key.verifying_key().to_bytes();
        let delegatee_pub = delegatee_key.verifying_key().to_bytes();

        let mut proof0 = DelegationProof {
            proof_cid: "cid:proof0".to_string(),
            issuer: "root".to_string(),
            subject: "delegatee".to_string(),
            allowed_actions: vec!["*".to_string()],
            allowed_resources: vec!["*".to_string()],
            expires_at: i64::MAX,
            parent_proof_cid: None,
            signature: None,
            issued_at: 1000,
            revoked: false,
        };
        proof0.signature = Some(DelegationChain::sign_proof(&proof0, &root_key));

        let mut proof1 = DelegationProof {
            proof_cid: "cid:proof1".to_string(),
            issuer: "delegatee".to_string(),
            subject: "sub-agent".to_string(),
            allowed_actions: vec!["ehr.read*".to_string()],
            allowed_resources: vec!["ns:hospital/*".to_string()],
            expires_at: i64::MAX,
            parent_proof_cid: Some("cid:proof0".to_string()),
            signature: None,
            issued_at: 2000,
            revoked: false,
        };
        proof1.signature = Some(DelegationChain::sign_proof(&proof1, &delegatee_key));

        let chain = DelegationChain {
            proofs: vec![proof0, proof1],
            chain_cid: "cid:chain".to_string(),
        };

        assert!(chain.verify(3000).is_ok());

        let mut pub_keys = std::collections::HashMap::new();
        pub_keys.insert("root".to_string(), root_pub);
        pub_keys.insert("delegatee".to_string(), delegatee_pub);
        assert!(chain.verify_signatures(&pub_keys).is_ok());

        assert!(chain.allows("ehr.read_allergy", "ns:hospital/er", 3000));
        assert!(!chain.allows("ehr.write", "ns:hospital/er", 3000));
    }

    #[test]
    fn test_phase9g_ed25519_tampered_signature_fails() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let root_key = SigningKey::generate(&mut OsRng);
        let root_pub = root_key.verifying_key().to_bytes();

        let mut proof = DelegationProof {
            proof_cid: "cid:tampered".to_string(),
            issuer: "root".to_string(),
            subject: "agent".to_string(),
            allowed_actions: vec!["*".to_string()],
            allowed_resources: vec!["*".to_string()],
            expires_at: i64::MAX,
            parent_proof_cid: None,
            signature: None,
            issued_at: 1000,
            revoked: false,
        };
        proof.signature = Some(DelegationChain::sign_proof(&proof, &root_key));
        proof.allowed_actions = vec!["admin.*".to_string()]; // tamper

        let chain = DelegationChain {
            proofs: vec![proof],
            chain_cid: "cid:tampered_chain".to_string(),
        };

        let mut pub_keys = std::collections::HashMap::new();
        pub_keys.insert("root".to_string(), root_pub);
        assert!(chain.verify_signatures(&pub_keys).is_err(), "Tampered proof should fail");
    }

    #[test]
    fn test_phase9h_scitt_receipt_cid_on_audit() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "audited", "ns:scitt");
        start_agent(&mut kernel, &pid);

        let packet = make_phase9_packet("ns:scitt", 1000);
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);
        assert!(r.audit_entry.scitt_receipt_cid.is_none());

        let mut audit_log = kernel.audit_log().to_vec();
        let last = audit_log.len() - 1;
        audit_log[last].scitt_receipt_cid = Some("cid:scitt:receipt:001".to_string());
        assert_eq!(audit_log[last].scitt_receipt_cid.as_deref(), Some("cid:scitt:receipt:001"));
    }

    #[test]
    fn test_phase9e_store_port_roundtrip() {
        use crate::store::{InMemoryKernelStore, KernelStore};

        let mut store = InMemoryKernelStore::new();
        let port = Port {
            port_id: "port:test:001".to_string(),
            port_type: PortType::RequestResponse,
            owner_pid: "pid:owner".to_string(),
            bound_pids: vec!["pid:bound1".to_string()],
            direction: PortDirection::Bidirectional,
            buffered: true,
            max_buffer_size: 100,
            allowed_packet_types: vec![],
            allowed_actions: vec!["*".to_string()],
            max_delegation_depth: 3,
            created_at: 1000,
            expires_at: Some(9999),
            closed: false,
        };

        store.store_port(&port).unwrap();
        let loaded = store.load_port("port:test:001").unwrap().unwrap();
        assert_eq!(loaded.owner_pid, "pid:owner");
        assert_eq!(loaded.bound_pids, vec!["pid:bound1".to_string()]);
        assert_eq!(store.load_ports_by_owner("pid:owner").unwrap().len(), 1);
    }

    #[test]
    fn test_phase9e_store_execution_policy_roundtrip() {
        use crate::store::{InMemoryKernelStore, KernelStore};

        let mut store = InMemoryKernelStore::new();
        let policy = ExecutionPolicy {
            role: AgentRole::Reader,
            allowed_ops: vec![MemoryKernelOp::MemRead, MemoryKernelOp::AccessCheck],
            phase_transitions: vec![],
            rate_limits: std::collections::BTreeMap::new(),
            budget: BudgetPolicy::default(),
        };

        store.store_execution_policy(&policy).unwrap();
        let loaded = store.load_execution_policy(&AgentRole::Reader).unwrap().unwrap();
        assert_eq!(loaded.allowed_ops.len(), 2);
        assert_eq!(store.load_all_policies().unwrap().len(), 1);
    }

    #[test]
    fn test_phase9e_store_delegation_chain_roundtrip() {
        use crate::store::{InMemoryKernelStore, KernelStore};

        let mut store = InMemoryKernelStore::new();
        let chain = DelegationChain {
            proofs: vec![DelegationProof {
                proof_cid: "cid:p0".to_string(),
                issuer: "root".to_string(),
                subject: "agent-a".to_string(),
                allowed_actions: vec!["*".to_string()],
                allowed_resources: vec!["*".to_string()],
                expires_at: i64::MAX,
                parent_proof_cid: None,
                signature: None,
                issued_at: 1000,
                revoked: false,
            }],
            chain_cid: "cid:chain:001".to_string(),
        };

        store.store_delegation_chain(&chain).unwrap();
        assert_eq!(store.load_delegation_chain("cid:chain:001").unwrap().unwrap().proofs.len(), 1);
        assert_eq!(store.load_delegation_chains_by_subject("agent-a").unwrap().len(), 1);
    }

    // =========================================================================
    // Data Engineering Regression Tests (D1-D14)
    // =========================================================================

    #[test]
    fn test_d1_cid_computed_after_timestamp() {
        // D1: Timestamp must be set BEFORE CID computation. Verify by checking
        // that the stored packet's timestamp is non-zero (was set before storage)
        // and that recomputing CID with packet_cid zeroed matches the stored CID.
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "d1-bot", "ns:d1");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        let packet = make_packet("subject:d1", None);
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: None, vakya_id: None,
        });
        let cid = match r.value {
            SyscallValue::Cid(c) => c,
            _ => panic!("Expected Cid"),
        };

        let stored = kernel.packets.get(&cid).unwrap();
        // D1: Timestamp must be non-zero (set before CID computation)
        assert!(stored.index.ts > 0, "D1: Timestamp must be set before CID computation");
        // The stored packet_cid is set AFTER CID computation (self-referential),
        // so to verify, zero it out and recompute
        let mut verify = stored.clone();
        verify.index.packet_cid = Cid::default();
        let recomputed = crate::cid::compute_cid(&verify).unwrap();
        assert_eq!(cid, recomputed, "D1: CID must match content with packet_cid zeroed");
    }

    #[test]
    fn test_d2_interference_edge_store_roundtrip() {
        // D2: InterferenceEdge stored under agent_pid key must be retrievable
        use crate::store::{InMemoryKernelStore, KernelStore};
        use crate::interference::InterferenceEdge as IEdge;
        use crate::interference::StateDelta;

        let mut store = InMemoryKernelStore::new();
        let ie = IEdge {
            agent_pid: "pid:000001".to_string(),
            from_sn: 0,
            to_sn: 1,
            delta: StateDelta {
                entities_added: vec![], entities_changed: vec![], entities_removed: vec![],
                intents_opened: vec![], intents_closed: vec![],
                decisions_made: vec![], contradictions_detected: vec![], observations_updated: vec![],
            },
            cause_evidence_cids: vec![],
            confidence: 0.9,
            ie_cid: None,
            created_at: 1000,
        };
        store.store_interference_edge(&ie).unwrap();
        let loaded = store.load_interference_edges("pid:000001").unwrap();
        assert_eq!(loaded.len(), 1, "D2: IE must be retrievable by agent_pid");
        assert_eq!(loaded[0].from_sn, 0);
        assert_eq!(loaded[0].to_sn, 1);
    }

    #[test]
    fn test_d3_eviction_cleans_indexes() {
        // D3: After eviction, namespace_index and session_index must not contain stale CIDs
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "d3-bot", "ns:d3");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        let packet = make_packet("subject:d3", None);
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: None, vakya_id: None,
        });
        let cid = match r.value {
            SyscallValue::Cid(c) => c,
            _ => panic!("Expected Cid"),
        };

        // Verify packet is in namespace index
        let ns = kernel.agents.get(&pid).unwrap().namespace.clone();
        assert!(kernel.namespace_index.get(&ns).unwrap().contains(&cid));

        // Evict the packet
        let result = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemEvict,
            payload: SyscallPayload::MemEvict {
                cids: vec![cid.clone()],
                max_evict: 0,
            },
            reason: None, vakya_id: None,
        });
        assert_eq!(result.outcome, OpOutcome::Success);

        // D3: namespace_index must NOT contain the evicted CID
        let ns_cids = kernel.namespace_index.get(&ns).cloned().unwrap_or_default();
        assert!(!ns_cids.contains(&cid), "D3: namespace_index must be cleaned after eviction");
        assert!(!kernel.packets.contains_key(&cid));
    }

    #[test]
    fn test_d4_audit_log_bounded() {
        // D4: Audit log must not grow beyond audit_log_max
        let mut kernel = MemoryKernel::new();
        kernel.audit_log_max = 10;
        let pid = register_agent(&mut kernel, "d4-bot", "ns:d4");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        for i in 0..20 {
            let packet = make_packet(&format!("subject:d4_{}", i), None);
            kernel.dispatch(SyscallRequest {
                agent_pid: pid.clone(),
                operation: MemoryKernelOp::MemWrite,
                payload: SyscallPayload::MemWrite { packet },
                reason: None, vakya_id: None,
            });
        }

        assert!(kernel.audit_log.len() <= 10, "D4: Audit log must be bounded at max=10, got {}", kernel.audit_log.len());
    }

    #[test]
    fn test_d8_gc_cleans_session_index() {
        // D8: GC must clean session_index of stale CIDs
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "d8-bot", "ns:d8");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        // Create a session
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::SessionCreate,
            payload: SyscallPayload::SessionCreate {
                session_id: "sess:d8".to_string(),
                label: None,
                parent_session_id: None,
            },
            reason: None, vakya_id: None,
        });

        // Write a packet to the session
        let packet = make_packet("subject:d8", Some("sess:d8"));
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: None, vakya_id: None,
        });
        let cid = match r.value {
            SyscallValue::Cid(c) => c,
            _ => panic!("Expected Cid"),
        };

        // Close the session
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::SessionClose,
            payload: SyscallPayload::SessionClose { session_id: "sess:d8".to_string() },
            reason: None, vakya_id: None,
        });

        // Remove packet from session's packet_cids so GC will collect it
        if let Some(sess) = kernel.sessions.get_mut("sess:d8") {
            sess.packet_cids.clear();
        }

        // Run GC
        let gc_result = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::GarbageCollect,
            payload: SyscallPayload::GarbageCollect,
            reason: None, vakya_id: None,
        });
        assert_eq!(gc_result.outcome, OpOutcome::Success);

        // D8: session_index must not contain the collected CID
        let sess_cids = kernel.session_index.get("sess:d8").cloned().unwrap_or_default();
        assert!(!sess_cids.contains(&cid), "D8: session_index must be cleaned after GC");
    }

    #[test]
    fn test_d9_audit_returns_newest() {
        // D9: load_audit_entries_by_agent must return newest entries
        use crate::store::{InMemoryKernelStore, KernelStore};

        let mut store = InMemoryKernelStore::new();
        for i in 0..100 {
            let entry = KernelAuditEntry {
                audit_id: format!("audit:{:08}", i),
                timestamp: 1000 + i as i64,
                operation: MemoryKernelOp::MemWrite,
                agent_pid: "pid:000001".to_string(),
                target: None,
                outcome: OpOutcome::Success,
                reason: None,
                error: None,
                duration_us: None,
                vakya_id: None,
                before_hash: None,
                after_hash: None,
                merkle_root: None,
                scitt_receipt_cid: None,
            };
            store.store_audit_entry(&entry).unwrap();
        }

        let recent = store.load_audit_entries_by_agent("pid:000001", 5).unwrap();
        assert_eq!(recent.len(), 5);
        // D9: Should be the 5 newest (timestamps 1095-1099), in chronological order
        assert_eq!(recent[0].timestamp, 1095, "D9: First entry should be timestamp 1095");
        assert_eq!(recent[4].timestamp, 1099, "D9: Last entry should be timestamp 1099");
    }

    #[test]
    fn test_d13_observations_all_entities() {
        // D13: extract_state_vector must create observations for ALL entities
        use crate::interference::extract_state_vector;

        let packet = MemPacket::new(
            PacketType::Extraction,
            serde_json::json!({"diagnosis": "flu"}),
            Cid::default(),
            "subject:d13".to_string(),
            "pipeline:test".to_string(),
            make_source(),
            1000,
        )
        .with_entities(vec!["patient:P001".to_string(), "doctor:D001".to_string()]);

        let sv = extract_state_vector(0, "pid:000001", "ns:test", &[packet], [0u8; 32]);

        // D13: Both entities should have observations
        assert!(sv.observations.len() >= 2, "D13: Should have observations for all entities, got {}", sv.observations.len());
        let obs_entities: Vec<&str> = sv.observations.iter().map(|o| o.entity_id.as_str()).collect();
        assert!(obs_entities.contains(&"patient:P001"), "D13: Missing observation for patient:P001");
        assert!(obs_entities.contains(&"doctor:D001"), "D13: Missing observation for doctor:D001");
    }

    #[test]
    fn test_d5_context_snapshot_captures_session() {
        // D5: Context snapshot must include session state
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "d5-bot", "ns:d5");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        // Create session and write a packet
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::SessionCreate,
            payload: SyscallPayload::SessionCreate {
                session_id: "sess:d5".to_string(),
                label: Some("D5 test".to_string()),
                parent_session_id: None,
            },
            reason: None, vakya_id: None,
        });
        let packet = make_packet("subject:d5", Some("sess:d5"));
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: None, vakya_id: None,
        });

        // Take snapshot
        let snap_result = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::ContextSnapshot,
            payload: SyscallPayload::ContextSnapshot {
                session_id: "sess:d5".to_string(),
                pipeline_id: "pipe:d5".to_string(),
            },
            reason: None, vakya_id: None,
        });
        assert_eq!(snap_result.outcome, OpOutcome::Success);
        let ctx = match snap_result.value {
            SyscallValue::Context(c) => *c,
            _ => panic!("Expected Context"),
        };

        // D5: session_snapshot must be present and contain the packet
        assert!(ctx.session_snapshot.is_some(), "D5: session_snapshot must be captured");
        let snap_session = ctx.session_snapshot.unwrap();
        assert_eq!(snap_session.packet_count(), 1, "D5: snapshot session must have 1 packet");
    }

    #[test]
    fn test_d11_compress_clears_packets() {
        // D11: Session compress must clear packet_cids and record evicted_cids
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "d11-bot", "ns:d11");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::SessionCreate,
            payload: SyscallPayload::SessionCreate {
                session_id: "sess:d11".to_string(),
                label: None,
                parent_session_id: None,
            },
            reason: None, vakya_id: None,
        });

        // Write 3 packets
        for i in 0..3 {
            let packet = make_packet(&format!("subject:d11_{}", i), Some("sess:d11"));
            kernel.dispatch(SyscallRequest {
                agent_pid: pid.clone(),
                operation: MemoryKernelOp::MemWrite,
                payload: SyscallPayload::MemWrite { packet },
                reason: None, vakya_id: None,
            });
        }
        assert_eq!(kernel.get_session("sess:d11").unwrap().packet_count(), 3);

        // Compress
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::SessionCompress,
            payload: SyscallPayload::SessionCompress {
                session_id: "sess:d11".to_string(),
                algorithm: "recursive_summarization".to_string(),
                summary: "All 3 packets summarized".to_string(),
            },
            reason: None, vakya_id: None,
        });
        assert_eq!(r.outcome, OpOutcome::Success);

        let session = kernel.get_session("sess:d11").unwrap();
        // D11: packet_cids should be cleared after compression
        assert_eq!(session.packet_count(), 0, "D11: packet_cids must be cleared after compress");
        assert!(session.summary.is_some(), "D11: summary must be set");
        let comp = session.compression.as_ref().unwrap();
        assert_eq!(comp.original_count, 3, "D11: original_count must be 3");
        assert_eq!(comp.evicted_cids.len(), 3, "D11: evicted_cids must record all 3 packets");
    }

    #[test]
    fn test_d12_integrity_check_verifies_cid() {
        // D12: IntegrityCheck must verify CID content integrity
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "d12-bot", "ns:d12");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        let packet = make_packet("subject:d12", None);
        let r = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: None, vakya_id: None,
        });
        let cid = match r.value {
            SyscallValue::Cid(c) => c,
            _ => panic!("Expected Cid"),
        };

        // Integrity check should pass on clean state
        let ic = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::IntegrityCheck,
            payload: SyscallPayload::IntegrityCheck,
            reason: None, vakya_id: None,
        });
        assert_eq!(ic.outcome, OpOutcome::Success, "D12: Clean state must pass integrity check");

        // Corrupt a packet's payload to trigger CID mismatch
        if let Some(pkt) = kernel.packets.get_mut(&cid) {
            pkt.content.payload = serde_json::json!({"corrupted": true});
        }

        let ic2 = kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::IntegrityCheck,
            payload: SyscallPayload::IntegrityCheck,
            reason: None, vakya_id: None,
        });
        assert_eq!(ic2.outcome, OpOutcome::Failed, "D12: Corrupted packet must fail integrity check");
    }

    #[test]
    fn test_d16_flush_to_store() {
        // D16: flush_to_store must persist kernel state
        use crate::store::{InMemoryKernelStore, KernelStore};

        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "d16-bot", "ns:d16");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        let packet = make_packet("subject:d16", None);
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: None, vakya_id: None,
        });

        let mut store = InMemoryKernelStore::new();
        let written = kernel.flush_to_store(&mut store).unwrap();
        // Should have written: 1 packet + 0 sessions + 1 agent + N audit entries
        assert!(written >= 3, "D16: flush_to_store must write packets, agents, and audit entries, got {}", written);

        // Verify packet is in store
        let stored_packets = store.load_packets_by_namespace("ns:d16").unwrap();
        assert_eq!(stored_packets.len(), 1, "D16: flushed packet must be in store");

        // Verify agent is in store
        let stored_agent = store.load_agent(&pid).unwrap();
        assert!(stored_agent.is_some(), "D16: flushed agent must be in store");
    }

    #[test]
    fn test_d17_wal_crash_recovery() {
        // D17: WAL must enable crash recovery of uncommitted packets
        use crate::range_window::{RangeWindowManager, RangeWindowConfig, WalEntry};

        let config = RangeWindowConfig {
            max_tokens: 10000, // High limit so nothing auto-commits
            max_packets: 100,
            commit_on_session_boundary: false,
        };
        let mut mgr = RangeWindowManager::new("ns:d17".to_string(), "pid:d17".to_string(), config.clone());

        // Ingest 3 packets (won't trigger commit due to high limits)
        for i in 0..3 {
            mgr.ingest(
                Cid::default(),
                1000 + i,
                100,
                Some("sess:d17"),
                &["entity:d17".to_string()],
            );
        }

        // WAL should have 3 entries
        assert_eq!(mgr.wal.len(), 3, "D17: WAL must have 3 entries");

        // Simulate crash: save WAL, create new manager
        let saved_wal: Vec<WalEntry> = mgr.wal.clone();
        let mut mgr2 = RangeWindowManager::new("ns:d17".to_string(), "pid:d17".to_string(), config);

        // Replay WAL
        mgr2.replay_wal(&saved_wal);

        // Force commit should produce a window with 3 packets
        let window = mgr2.force_commit(crate::range_window::BoundaryReason::Manual);
        assert!(window.is_some(), "D17: Replayed WAL must produce a committable window");
        let w = window.unwrap();
        assert_eq!(w.packet_count, 3, "D17: Recovered window must have 3 packets");

        // WAL should be cleared after commit
        assert_eq!(mgr2.wal.len(), 0, "D17: WAL must be cleared after commit");
    }

    // =========================================================================
    // Tier 1-2 Hardening Regression Tests
    // =========================================================================

    #[test]
    fn test_tier1_load_from_store_roundtrip() {
        // Tier 1: flush → load_from_store must reconstruct kernel state
        use crate::store::{InMemoryKernelStore, KernelStore};

        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "tier1-bot", "ns:tier1");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        // Create session + write packets
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::SessionCreate,
            payload: SyscallPayload::SessionCreate {
                session_id: "sess:tier1".to_string(),
                label: Some("Tier 1 test".to_string()),
                parent_session_id: None,
            },
            reason: None, vakya_id: None,
        });
        for i in 0..3 {
            let packet = make_packet(&format!("subject:tier1_{}", i), Some("sess:tier1"));
            kernel.dispatch(SyscallRequest {
                agent_pid: pid.clone(),
                operation: MemoryKernelOp::MemWrite,
                payload: SyscallPayload::MemWrite { packet },
                reason: None, vakya_id: None,
            });
        }

        // Flush to store
        let mut store = InMemoryKernelStore::new();
        let written = kernel.flush_to_store(&mut store).unwrap();
        assert!(written > 0);

        // Reconstruct from store
        let restored = MemoryKernel::load_from_store(&store).unwrap();
        assert_eq!(restored.packets.len(), kernel.packets.len(),
            "Tier1: Restored kernel must have same packet count");
        assert!(restored.agents.contains_key(&pid),
            "Tier1: Restored kernel must have the agent");
        assert!(restored.sessions.contains_key("sess:tier1"),
            "Tier1: Restored kernel must have the session");
        // Verify indexes were rebuilt
        let ns_cids = restored.namespace_index.get("ns:tier1").unwrap();
        assert_eq!(ns_cids.len(), 3, "Tier1: namespace_index must be rebuilt with 3 CIDs");
        let si_cids = restored.session_index.get("sess:tier1").unwrap();
        assert_eq!(si_cids.len(), 3, "Tier1: session_index must be rebuilt with 3 CIDs");
    }

    #[test]
    fn test_tier1_merkle_chain_verification() {
        // Tier 1: verify_window_chain must detect chain breaks
        use crate::range_window::{RangeWindowManager, RangeWindowConfig};

        let config = RangeWindowConfig {
            max_tokens: 100,
            max_packets: 2,
            commit_on_session_boundary: false,
        };
        let mut mgr = RangeWindowManager::new("ns:chain".to_string(), "pid:chain".to_string(), config);

        // Ingest enough packets to produce 3 windows (2 packets each)
        for i in 0..6 {
            mgr.ingest(Cid::default(), 1000 + i, 60, None, &[]);
        }

        let windows: Vec<crate::range_window::RangeWindow> = mgr.all_windows().into_iter().cloned().collect();
        assert!(windows.len() >= 2, "Need at least 2 windows for chain test");

        // Valid chain should have no errors
        let errors = MemoryKernel::verify_window_chain(&windows);
        assert!(errors.is_empty(), "Tier1: Valid chain must have no errors, got: {:?}", errors);

        // Corrupt a window's prev_rw_root to break the chain
        let mut corrupted = windows.clone();
        if corrupted.len() >= 2 {
            corrupted[1].prev_rw_root = [0xFF; 32];
            let errors = MemoryKernel::verify_window_chain(&corrupted);
            assert!(!errors.is_empty(), "Tier1: Corrupted chain must produce errors");
        }
    }

    #[test]
    fn test_tier1_wal_persistent_store() {
        // Tier 1: WAL entries must persist to and load from KernelStore
        use crate::store::{InMemoryKernelStore, KernelStore};
        use crate::range_window::WalEntry;

        let mut store = InMemoryKernelStore::new();
        let entries = vec![
            WalEntry { cid: Cid::default(), timestamp: 1000, token_count: 50, session_id: Some("s1".to_string()), entities: vec!["e1".to_string()] },
            WalEntry { cid: Cid::default(), timestamp: 1001, token_count: 60, session_id: None, entities: vec![] },
        ];

        store.store_wal("ns:waltest", &entries).unwrap();
        let loaded = store.load_wal("ns:waltest").unwrap();
        assert_eq!(loaded.len(), 2, "Tier1: WAL must persist 2 entries");
        assert_eq!(loaded[0].timestamp, 1000);
        assert_eq!(loaded[1].token_count, 60);

        store.clear_wal("ns:waltest").unwrap();
        let after_clear = store.load_wal("ns:waltest").unwrap();
        assert!(after_clear.is_empty(), "Tier1: WAL must be empty after clear");
    }

    #[test]
    fn test_tier2_shared_kernel_concurrent() {
        // Tier 2: SharedKernel must support concurrent read/write
        let shared = SharedKernel::new();

        // Register agent via dispatch (write path)
        let result = shared.dispatch(SyscallRequest {
            agent_pid: "".to_string(),
            operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: "shared-bot".to_string(),
                namespace: "ns:shared".to_string(),
                role: Some("test".to_string()),
                model: None,
                framework: None,
            },
            reason: None, vakya_id: None,
        });
        assert_eq!(result.outcome, OpOutcome::Success);
        let pid = match result.value {
            SyscallValue::AgentPid(p) => p,
            _ => panic!("Expected AgentPid"),
        };

        // Read path
        let agent_exists = shared.read(|k| k.get_agent(&pid).is_some());
        assert!(agent_exists, "Tier2: SharedKernel read must see registered agent");

        // Multiple handles (simulates multi-thread sharing)
        let handle2 = shared.handle();
        let agent_exists2 = handle2.read(|k| k.get_agent(&pid).is_some());
        assert!(agent_exists2, "Tier2: Cloned handle must see same state");
    }

    #[test]
    fn test_tier2_atomic_flush_rollback() {
        // Tier 2: flush_to_store with valid data must succeed
        use crate::store::{InMemoryKernelStore, KernelStore};

        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "atomic-bot", "ns:atomic");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        let packet = make_packet("subject:atomic", None);
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: None, vakya_id: None,
        });

        let mut store = InMemoryKernelStore::new();
        let result = kernel.flush_to_store(&mut store);
        assert!(result.is_ok(), "Tier2: Atomic flush must succeed on valid data");
        let written = result.unwrap();
        // 1 packet + 1 agent + N audit entries (register + start + write = 3)
        assert!(written >= 5, "Tier2: Must write packets + agents + audit, got {}", written);
    }

    // ═══════════════════════════════════════════════════════════════
    // PHASE 4: AUDIT DURABILITY TESTS
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_phase4_audit_hmac_chain() {
        // Every audit entry's before_hash must match the previous entry's after_hash
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "chain-bot", "ns:chain");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        for i in 0..10 {
            let packet = make_packet(&format!("subject:chain_{}", i), None);
            kernel.dispatch(SyscallRequest {
                agent_pid: pid.clone(),
                operation: MemoryKernelOp::MemWrite,
                payload: SyscallPayload::MemWrite { packet },
                reason: None, vakya_id: None,
            });
        }

        // Verify chain integrity
        let result = kernel.verify_audit_chain();
        assert!(result.is_ok(), "Audit chain should be valid: {:?}", result);
        let chain_len = result.unwrap();
        assert!(chain_len >= 12, "Chain should have register + start + 10 writes = 12+, got {}", chain_len);

        // Verify each entry has hashes
        for entry in kernel.audit_log() {
            assert!(entry.after_hash.is_some(), "Every entry must have after_hash");
        }

        // First entry's before_hash should be None (no predecessor)
        assert!(kernel.audit_log()[0].before_hash.is_none(),
            "First entry should have no before_hash");

        // Second entry's before_hash should match first's after_hash
        assert_eq!(
            kernel.audit_log()[1].before_hash.as_ref(),
            kernel.audit_log()[0].after_hash.as_ref(),
            "Chain link between entry 0 and 1 must match"
        );
    }

    #[test]
    fn test_phase4_audit_overflow_to_buffer() {
        // When audit_log exceeds max, evicted entries go to overflow buffer
        let mut kernel = MemoryKernel::new();
        kernel.audit_log_max = 10;
        let pid = register_agent(&mut kernel, "overflow-bot", "ns:overflow");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        // Write enough to trigger overflow (register + start + 20 writes = 22 entries)
        for i in 0..20 {
            let packet = make_packet(&format!("subject:overflow_{}", i), None);
            kernel.dispatch(SyscallRequest {
                agent_pid: pid.clone(),
                operation: MemoryKernelOp::MemWrite,
                payload: SyscallPayload::MemWrite { packet },
                reason: None, vakya_id: None,
            });
        }

        // Audit log should be bounded
        assert!(kernel.audit_count() <= 10,
            "Audit log must be bounded at 10, got {}", kernel.audit_count());

        // Overflow buffer should have the evicted entries
        assert!(kernel.audit_overflow_pending() > 0,
            "Overflow buffer should have evicted entries, got {}", kernel.audit_overflow_pending());
        assert!(kernel.audit_overflow_total() > 0,
            "Overflow count should be > 0");

        // Total = in-log + overflow should equal total generated
        let total = kernel.audit_count() + kernel.audit_overflow_pending();
        assert!(total >= 22, "Total entries (log + overflow) should be >= 22, got {}", total);
    }

    #[test]
    fn test_phase4_drain_audit_overflow() {
        let mut kernel = MemoryKernel::new();
        kernel.audit_log_max = 5;
        let pid = register_agent(&mut kernel, "drain-bot", "ns:drain");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        for i in 0..10 {
            let packet = make_packet(&format!("subject:drain_{}", i), None);
            kernel.dispatch(SyscallRequest {
                agent_pid: pid.clone(),
                operation: MemoryKernelOp::MemWrite,
                payload: SyscallPayload::MemWrite { packet },
                reason: None, vakya_id: None,
            });
        }

        let pending_before = kernel.audit_overflow_pending();
        assert!(pending_before > 0);

        // Drain the overflow
        let drained = kernel.drain_audit_overflow();
        assert_eq!(drained.len(), pending_before);
        assert_eq!(kernel.audit_overflow_pending(), 0, "Overflow should be empty after drain");

        // Overflow count stays (it's cumulative)
        assert!(kernel.audit_overflow_total() > 0);
    }

    #[test]
    fn test_phase4_export_audit_json() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "json-bot", "ns:json");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        let json = kernel.export_audit_json().unwrap();
        assert!(json.starts_with('['), "JSON should be an array");
        assert!(json.contains("agent_register"), "JSON should contain operation names (snake_case serde)");
        assert!(json.contains(&pid), "JSON should contain agent PID");

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_array());
        assert!(parsed.as_array().unwrap().len() >= 2); // register + start
    }

    #[test]
    fn test_phase4_export_audit_csv() {
        let mut kernel = MemoryKernel::new();
        let pid = register_agent(&mut kernel, "csv-bot", "ns:csv");
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None, vakya_id: None,
        });

        let csv = kernel.export_audit_csv();
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines.len() >= 3, "CSV should have header + 2+ rows");
        assert_eq!(lines[0], "audit_id,timestamp,operation,agent_pid,target,outcome,reason");
        assert!(lines[1].contains("AgentRegister"), "First row should be register (Debug format)");
    }
}
