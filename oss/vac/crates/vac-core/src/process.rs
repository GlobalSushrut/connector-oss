//! Process Model — POSIX-like process abstraction for agents
//!
//! This module implements a formal process model with:
//! - Process hierarchy (parent/child relationships)
//! - Process groups and sessions (pgid/sid)
//! - Process states (Running, Sleeping, Stopped, Zombie)
//! - Resource limits (rlimit equivalent)
//! - Standard I/O streams (stdin/stdout/stderr)
//! - File descriptor table
//!
//! Design sources: POSIX.1-2017, Linux kernel task_struct, Plan 9 processes

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, RwLock};

// =============================================================================
// Process Identity
// =============================================================================

/// Process ID type (agent PID)
pub type Pid = String;

/// Process Group ID
pub type Pgid = String;

/// Session ID
pub type Sid = String;

/// User ID (principal)
pub type Uid = String;

/// Group ID (role)
pub type Gid = String;

// =============================================================================
// Process State
// =============================================================================

/// Process state — mirrors Linux task states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    /// Process is runnable or running
    Running,
    /// Process is waiting for I/O or event
    Sleeping,
    /// Process is stopped (SIGSTOP/SIGTSTP)
    Stopped,
    /// Process has terminated but not yet reaped
    Zombie,
    /// Process is being traced/debugged
    Traced,
    /// Process is in uninterruptible sleep (D state)
    DiskSleep,
    /// Process is idle (kernel thread)
    Idle,
    /// Process is being created
    New,
}

impl Default for ProcessState {
    fn default() -> Self {
        Self::New
    }
}

impl std::fmt::Display for ProcessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Running => "R",
            Self::Sleeping => "S",
            Self::Stopped => "T",
            Self::Zombie => "Z",
            Self::Traced => "t",
            Self::DiskSleep => "D",
            Self::Idle => "I",
            Self::New => "N",
        };
        write!(f, "{}", s)
    }
}

// =============================================================================
// Resource Limits (rlimit)
// =============================================================================

/// Resource limit — soft and hard limits
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Rlimit {
    /// Current (soft) limit
    pub soft: u64,
    /// Maximum (hard) limit
    pub hard: u64,
}

impl Rlimit {
    pub const INFINITY: u64 = u64::MAX;

    pub fn new(soft: u64, hard: u64) -> Self {
        Self { soft, hard }
    }

    pub fn unlimited() -> Self {
        Self { soft: Self::INFINITY, hard: Self::INFINITY }
    }

    /// Check if value exceeds soft limit
    pub fn exceeds_soft(&self, value: u64) -> bool {
        self.soft != Self::INFINITY && value > self.soft
    }

    /// Check if value exceeds hard limit
    pub fn exceeds_hard(&self, value: u64) -> bool {
        self.hard != Self::INFINITY && value > self.hard
    }
}

impl Default for Rlimit {
    fn default() -> Self {
        Self::unlimited()
    }
}

/// Resource limit type — POSIX rlimit resources
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RlimitResource {
    /// Max CPU time in seconds
    RlimitCpu,
    /// Max file size in bytes
    RlimitFsize,
    /// Max data segment size
    RlimitData,
    /// Max stack size
    RlimitStack,
    /// Max core dump size
    RlimitCore,
    /// Max resident set size
    RlimitRss,
    /// Max number of processes (child agents)
    RlimitNproc,
    /// Max open file descriptors
    RlimitNofile,
    /// Max locked memory
    RlimitMemlock,
    /// Max address space
    RlimitAs,
    /// Max file locks
    RlimitLocks,
    /// Max pending signals
    RlimitSigpending,
    /// Max message queue bytes
    RlimitMsgqueue,
    /// Max nice priority
    RlimitNice,
    /// Max realtime priority
    RlimitRtprio,
    /// Max realtime timeout
    RlimitRttime,
    // --- Connector-specific limits ---
    /// Max sessions
    RlimitSessions,
    /// Max tool calls per second
    RlimitToolRate,
    /// Max tokens per day
    RlimitTokensDaily,
    /// Max tokens per hour
    RlimitTokensHourly,
    /// Max memory packets
    RlimitPackets,
    /// Max port connections
    RlimitPorts,
    /// Max delegation depth
    RlimitDelegation,
}

/// Resource limits collection
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub limits: HashMap<RlimitResource, Rlimit>,
}

impl ResourceLimits {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with sensible defaults for agents
    pub fn agent_defaults() -> Self {
        let mut limits = HashMap::new();
        limits.insert(RlimitResource::RlimitNproc, Rlimit::new(64, 256));
        limits.insert(RlimitResource::RlimitNofile, Rlimit::new(1024, 4096));
        limits.insert(RlimitResource::RlimitSessions, Rlimit::new(16, 64));
        limits.insert(RlimitResource::RlimitToolRate, Rlimit::new(100, 1000));
        limits.insert(RlimitResource::RlimitTokensDaily, Rlimit::new(1_000_000, 10_000_000));
        limits.insert(RlimitResource::RlimitTokensHourly, Rlimit::new(100_000, 1_000_000));
        limits.insert(RlimitResource::RlimitPackets, Rlimit::new(10_000, 100_000));
        limits.insert(RlimitResource::RlimitPorts, Rlimit::new(32, 128));
        limits.insert(RlimitResource::RlimitDelegation, Rlimit::new(3, 5));
        Self { limits }
    }

    pub fn get(&self, resource: RlimitResource) -> Rlimit {
        self.limits.get(&resource).copied().unwrap_or_default()
    }

    pub fn set(&mut self, resource: RlimitResource, limit: Rlimit) {
        self.limits.insert(resource, limit);
    }

    /// Check if a resource usage exceeds soft limit
    pub fn check_soft(&self, resource: RlimitResource, value: u64) -> bool {
        self.get(resource).exceeds_soft(value)
    }

    /// Check if a resource usage exceeds hard limit
    pub fn check_hard(&self, resource: RlimitResource, value: u64) -> bool {
        self.get(resource).exceeds_hard(value)
    }
}

// =============================================================================
// File Descriptor Table
// =============================================================================

/// File descriptor number
pub type Fd = i32;

/// Standard file descriptors
pub const STDIN_FILENO: Fd = 0;
pub const STDOUT_FILENO: Fd = 1;
pub const STDERR_FILENO: Fd = 2;

/// File descriptor flags
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct FdFlags {
    /// Close on exec
    pub cloexec: bool,
    /// Non-blocking I/O
    pub nonblock: bool,
    /// Append mode
    pub append: bool,
}

/// File descriptor type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FdType {
    /// Standard input stream
    Stdin,
    /// Standard output stream
    Stdout,
    /// Standard error stream
    Stderr,
    /// Memory packet reference
    MemoryPacket { cid: String },
    /// Port connection
    Port { port_id: String },
    /// Session reference
    Session { session_id: String },
    /// Tool binding
    Tool { tool_id: String },
    /// Pipe (IPC)
    Pipe { pipe_id: String, read_end: bool },
    /// Socket (network)
    Socket { socket_id: String },
    /// Directory handle
    Directory { path: String },
    /// Event queue (epoll/kqueue)
    EventQueue { eq_id: String },
}

/// File descriptor entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdEntry {
    pub fd: Fd,
    pub fd_type: FdType,
    pub flags: FdFlags,
    pub offset: u64,
    pub ref_count: u32,
}

impl FdEntry {
    pub fn new(fd: Fd, fd_type: FdType) -> Self {
        Self {
            fd,
            fd_type,
            flags: FdFlags::default(),
            offset: 0,
            ref_count: 1,
        }
    }
}

/// File descriptor table
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FdTable {
    entries: BTreeMap<Fd, FdEntry>,
    next_fd: Fd,
}

impl FdTable {
    pub fn new() -> Self {
        let mut table = Self {
            entries: BTreeMap::new(),
            next_fd: 3, // 0, 1, 2 reserved for stdin/stdout/stderr
        };
        // Initialize standard streams
        table.entries.insert(STDIN_FILENO, FdEntry::new(STDIN_FILENO, FdType::Stdin));
        table.entries.insert(STDOUT_FILENO, FdEntry::new(STDOUT_FILENO, FdType::Stdout));
        table.entries.insert(STDERR_FILENO, FdEntry::new(STDERR_FILENO, FdType::Stderr));
        table
    }

    /// Allocate a new file descriptor
    pub fn alloc(&mut self, fd_type: FdType) -> Fd {
        let fd = self.next_fd;
        self.entries.insert(fd, FdEntry::new(fd, fd_type));
        self.next_fd += 1;
        fd
    }

    /// Get a file descriptor entry
    pub fn get(&self, fd: Fd) -> Option<&FdEntry> {
        self.entries.get(&fd)
    }

    /// Get a mutable file descriptor entry
    pub fn get_mut(&mut self, fd: Fd) -> Option<&mut FdEntry> {
        self.entries.get_mut(&fd)
    }

    /// Close a file descriptor
    pub fn close(&mut self, fd: Fd) -> bool {
        self.entries.remove(&fd).is_some()
    }

    /// Duplicate a file descriptor
    pub fn dup(&mut self, old_fd: Fd) -> Option<Fd> {
        let entry = self.entries.get(&old_fd)?.clone();
        let new_fd = self.next_fd;
        self.entries.insert(new_fd, FdEntry {
            fd: new_fd,
            ..entry
        });
        self.next_fd += 1;
        Some(new_fd)
    }

    /// Duplicate to specific fd (dup2)
    pub fn dup2(&mut self, old_fd: Fd, new_fd: Fd) -> Option<Fd> {
        let entry = self.entries.get(&old_fd)?.clone();
        self.entries.insert(new_fd, FdEntry {
            fd: new_fd,
            ..entry
        });
        if new_fd >= self.next_fd {
            self.next_fd = new_fd + 1;
        }
        Some(new_fd)
    }

    /// List all open file descriptors
    pub fn list(&self) -> Vec<&FdEntry> {
        self.entries.values().collect()
    }

    /// Count open file descriptors
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

// =============================================================================
// Standard I/O Streams
// =============================================================================

/// I/O stream buffer
#[derive(Debug, Clone, Default)]
pub struct StreamBuffer {
    buffer: VecDeque<u8>,
    max_size: usize,
}

impl StreamBuffer {
    pub fn new(max_size: usize) -> Self {
        Self {
            buffer: VecDeque::new(),
            max_size,
        }
    }

    pub fn write(&mut self, data: &[u8]) -> usize {
        let available = self.max_size.saturating_sub(self.buffer.len());
        let to_write = data.len().min(available);
        self.buffer.extend(&data[..to_write]);
        to_write
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.buffer.len());
        for (i, byte) in self.buffer.drain(..to_read).enumerate() {
            buf[i] = byte;
        }
        to_read
    }

    pub fn read_line(&mut self) -> Option<String> {
        let pos = self.buffer.iter().position(|&b| b == b'\n')?;
        let line: Vec<u8> = self.buffer.drain(..=pos).collect();
        String::from_utf8(line).ok()
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// Standard I/O streams for a process
#[derive(Debug, Default)]
pub struct StdioStreams {
    pub stdin: StreamBuffer,
    pub stdout: StreamBuffer,
    pub stderr: StreamBuffer,
}

impl StdioStreams {
    pub fn new() -> Self {
        Self {
            stdin: StreamBuffer::new(65536),
            stdout: StreamBuffer::new(1048576),
            stderr: StreamBuffer::new(1048576),
        }
    }
}

// =============================================================================
// Process Control Block (PCB)
// =============================================================================

/// Process credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCredentials {
    /// Real user ID
    pub uid: Uid,
    /// Effective user ID
    pub euid: Uid,
    /// Saved set-user-ID
    pub suid: Uid,
    /// Real group ID
    pub gid: Gid,
    /// Effective group ID
    pub egid: Gid,
    /// Saved set-group-ID
    pub sgid: Gid,
    /// Supplementary groups
    pub groups: Vec<Gid>,
}

impl Default for ProcessCredentials {
    fn default() -> Self {
        Self {
            uid: "root".to_string(),
            euid: "root".to_string(),
            suid: "root".to_string(),
            gid: "root".to_string(),
            egid: "root".to_string(),
            sgid: "root".to_string(),
            groups: vec![],
        }
    }
}

/// Process times (rusage)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessTimes {
    /// User CPU time in microseconds
    pub utime_us: u64,
    /// System CPU time in microseconds
    pub stime_us: u64,
    /// Children user CPU time
    pub cutime_us: u64,
    /// Children system CPU time
    pub cstime_us: u64,
    /// Start time (epoch ms)
    pub start_time_ms: i64,
    /// Wall clock time in microseconds
    pub real_time_us: u64,
}

/// Process statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessStats {
    /// Number of voluntary context switches
    pub nvcsw: u64,
    /// Number of involuntary context switches
    pub nivcsw: u64,
    /// Number of page faults
    pub minflt: u64,
    /// Number of major page faults
    pub majflt: u64,
    /// Peak memory usage in bytes
    pub maxrss: u64,
    /// Number of syscalls made
    pub syscall_count: u64,
    /// Number of signals received
    pub signal_count: u64,
    /// Number of I/O operations
    pub io_ops: u64,
}

/// Exit status
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ExitStatus {
    /// Exit code (0-255)
    pub code: i32,
    /// Signal that caused termination (if any)
    pub signal: Option<i32>,
    /// Core dumped flag
    pub core_dumped: bool,
}

impl ExitStatus {
    pub fn success() -> Self {
        Self { code: 0, signal: None, core_dumped: false }
    }

    pub fn failure(code: i32) -> Self {
        Self { code, signal: None, core_dumped: false }
    }

    pub fn signaled(signal: i32) -> Self {
        Self { code: 128 + signal, signal: Some(signal), core_dumped: false }
    }
}

/// Process Control Block — the core process abstraction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessControlBlock {
    // --- Identity ---
    /// Process ID
    pub pid: Pid,
    /// Parent process ID
    pub ppid: Option<Pid>,
    /// Process group ID
    pub pgid: Pgid,
    /// Session ID
    pub sid: Sid,
    /// Process name
    pub name: String,
    /// Command line arguments
    pub argv: Vec<String>,
    /// Environment variables
    pub envp: HashMap<String, String>,
    /// Current working directory
    pub cwd: String,
    /// Root directory (for chroot)
    pub root: String,

    // --- State ---
    /// Current process state
    pub state: ProcessState,
    /// Exit status (set when state is Zombie)
    pub exit_status: Option<ExitStatus>,
    /// Pending signals mask
    pub pending_signals: u64,
    /// Blocked signals mask
    pub blocked_signals: u64,

    // --- Credentials ---
    pub credentials: ProcessCredentials,

    // --- Resource Limits ---
    pub rlimits: ResourceLimits,

    // --- Timing ---
    pub times: ProcessTimes,

    // --- Statistics ---
    pub stats: ProcessStats,

    // --- Scheduling ---
    /// Nice value (-20 to 19)
    pub nice: i8,
    /// Scheduling priority (0-139)
    pub priority: u8,
    /// Scheduling policy
    pub sched_policy: SchedPolicy,
    /// CPU affinity mask
    pub cpu_affinity: u64,

    // --- Children ---
    /// Child process IDs
    pub children: Vec<Pid>,

    // --- Namespace ---
    /// Namespace the process belongs to
    pub namespace: String,
}

/// Scheduling policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SchedPolicy {
    /// Normal time-sharing (CFS)
    SchedNormal,
    /// FIFO real-time
    SchedFifo,
    /// Round-robin real-time
    SchedRr,
    /// Batch processing
    SchedBatch,
    /// Idle priority
    SchedIdle,
    /// Deadline scheduling
    SchedDeadline,
}

impl Default for SchedPolicy {
    fn default() -> Self {
        Self::SchedNormal
    }
}

impl Default for ProcessControlBlock {
    fn default() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            pid: String::new(),
            ppid: None,
            pgid: String::new(),
            sid: String::new(),
            name: String::new(),
            argv: vec![],
            envp: HashMap::new(),
            cwd: "/".to_string(),
            root: "/".to_string(),
            state: ProcessState::New,
            exit_status: None,
            pending_signals: 0,
            blocked_signals: 0,
            credentials: ProcessCredentials::default(),
            rlimits: ResourceLimits::agent_defaults(),
            times: ProcessTimes {
                start_time_ms: now,
                ..Default::default()
            },
            stats: ProcessStats::default(),
            nice: 0,
            priority: 120,
            sched_policy: SchedPolicy::default(),
            cpu_affinity: u64::MAX,
            children: vec![],
            namespace: "/m/".to_string(),
        }
    }
}

impl ProcessControlBlock {
    /// Create a new process
    pub fn new(pid: Pid, name: String) -> Self {
        let mut pcb = Self::default();
        pcb.pid = pid.clone();
        pcb.pgid = pid.clone();
        pcb.sid = pid;
        pcb.name = name;
        pcb
    }

    /// Fork a child process
    pub fn fork(&self, child_pid: Pid) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            pid: child_pid.clone(),
            ppid: Some(self.pid.clone()),
            pgid: self.pgid.clone(),
            sid: self.sid.clone(),
            name: self.name.clone(),
            argv: self.argv.clone(),
            envp: self.envp.clone(),
            cwd: self.cwd.clone(),
            root: self.root.clone(),
            state: ProcessState::New,
            exit_status: None,
            pending_signals: 0,
            blocked_signals: self.blocked_signals,
            credentials: self.credentials.clone(),
            rlimits: self.rlimits.clone(),
            times: ProcessTimes {
                start_time_ms: now,
                ..Default::default()
            },
            stats: ProcessStats::default(),
            nice: self.nice,
            priority: self.priority,
            sched_policy: self.sched_policy,
            cpu_affinity: self.cpu_affinity,
            children: vec![],
            namespace: self.namespace.clone(),
        }
    }

    /// Set process state
    pub fn set_state(&mut self, state: ProcessState) {
        self.state = state;
    }

    /// Exit the process
    pub fn exit(&mut self, code: i32) {
        self.state = ProcessState::Zombie;
        self.exit_status = Some(ExitStatus::failure(code));
    }

    /// Check if process is alive
    pub fn is_alive(&self) -> bool {
        !matches!(self.state, ProcessState::Zombie)
    }

    /// Add a child process
    pub fn add_child(&mut self, child_pid: Pid) {
        self.children.push(child_pid);
    }

    /// Remove a child process (after wait)
    pub fn remove_child(&mut self, child_pid: &Pid) {
        self.children.retain(|p| p != child_pid);
    }

    /// Record a syscall
    pub fn record_syscall(&mut self) {
        self.stats.syscall_count += 1;
    }

    /// Record CPU time
    pub fn record_cpu_time(&mut self, user_us: u64, sys_us: u64) {
        self.times.utime_us += user_us;
        self.times.stime_us += sys_us;
    }
}

// =============================================================================
// Process Table
// =============================================================================

/// Process table — manages all processes
#[derive(Debug, Default)]
pub struct ProcessTable {
    processes: HashMap<Pid, ProcessControlBlock>,
    /// PID to FdTable mapping (separate for thread safety)
    fd_tables: HashMap<Pid, FdTable>,
    /// PID to StdioStreams mapping
    stdio: HashMap<Pid, Arc<RwLock<StdioStreams>>>,
    /// Next PID counter
    next_pid: u64,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a new unique PID
    pub fn alloc_pid(&mut self) -> Pid {
        let pid = format!("pid_{}", self.next_pid);
        self.next_pid += 1;
        pid
    }

    /// Create a new process
    pub fn create(&mut self, name: String, parent: Option<&Pid>) -> Pid {
        let pid = self.alloc_pid();
        let mut pcb = ProcessControlBlock::new(pid.clone(), name);
        
        if let Some(ppid) = parent {
            pcb.ppid = Some(ppid.clone());
            if let Some(parent_pcb) = self.processes.get_mut(ppid) {
                pcb.pgid = parent_pcb.pgid.clone();
                pcb.sid = parent_pcb.sid.clone();
                parent_pcb.add_child(pid.clone());
            }
        }

        self.processes.insert(pid.clone(), pcb);
        self.fd_tables.insert(pid.clone(), FdTable::new());
        self.stdio.insert(pid.clone(), Arc::new(RwLock::new(StdioStreams::new())));
        
        pid
    }

    /// Fork a process
    pub fn fork(&mut self, parent_pid: &Pid) -> Option<Pid> {
        // First, allocate child PID and clone parent data
        let child_pid = self.alloc_pid();
        
        let parent = self.processes.get(parent_pid)?;
        let child_pcb = parent.fork(child_pid.clone());
        let parent_fds = self.fd_tables.get(parent_pid)?.clone();
        
        // Now we can mutate
        if let Some(parent) = self.processes.get_mut(parent_pid) {
            parent.add_child(child_pid.clone());
        }

        self.processes.insert(child_pid.clone(), child_pcb);
        self.fd_tables.insert(child_pid.clone(), parent_fds);
        self.stdio.insert(child_pid.clone(), Arc::new(RwLock::new(StdioStreams::new())));
        
        Some(child_pid)
    }

    /// Get a process by PID
    pub fn get(&self, pid: &Pid) -> Option<&ProcessControlBlock> {
        self.processes.get(pid)
    }

    /// Get a mutable process by PID
    pub fn get_mut(&mut self, pid: &Pid) -> Option<&mut ProcessControlBlock> {
        self.processes.get_mut(pid)
    }

    /// Get file descriptor table for a process
    pub fn get_fds(&self, pid: &Pid) -> Option<&FdTable> {
        self.fd_tables.get(pid)
    }

    /// Get mutable file descriptor table
    pub fn get_fds_mut(&mut self, pid: &Pid) -> Option<&mut FdTable> {
        self.fd_tables.get_mut(pid)
    }

    /// Get stdio streams for a process
    pub fn get_stdio(&self, pid: &Pid) -> Option<Arc<RwLock<StdioStreams>>> {
        self.stdio.get(pid).cloned()
    }

    /// Exit a process
    pub fn exit(&mut self, pid: &Pid, code: i32) {
        if let Some(pcb) = self.processes.get_mut(pid) {
            pcb.exit(code);
        }
    }

    /// Wait for a child process (reap zombie)
    pub fn wait(&mut self, parent_pid: &Pid, child_pid: &Pid) -> Option<ExitStatus> {
        let child = self.processes.get(child_pid)?;
        if child.ppid.as_ref() != Some(parent_pid) {
            return None; // Not our child
        }
        if child.state != ProcessState::Zombie {
            return None; // Not dead yet
        }

        let exit_status = child.exit_status;
        
        // Remove child from parent's list
        if let Some(parent) = self.processes.get_mut(parent_pid) {
            parent.remove_child(child_pid);
        }

        // Clean up child
        self.processes.remove(child_pid);
        self.fd_tables.remove(child_pid);
        self.stdio.remove(child_pid);

        exit_status
    }

    /// List all processes
    pub fn list(&self) -> Vec<&ProcessControlBlock> {
        self.processes.values().collect()
    }

    /// List children of a process
    pub fn children(&self, pid: &Pid) -> Vec<&ProcessControlBlock> {
        self.processes.values()
            .filter(|p| p.ppid.as_ref() == Some(pid))
            .collect()
    }

    /// Get process tree (hierarchical view)
    pub fn tree(&self, root_pid: Option<&Pid>) -> Vec<(usize, &ProcessControlBlock)> {
        let mut result = vec![];
        
        fn collect_tree<'a>(
            table: &'a ProcessTable,
            pid: &Pid,
            depth: usize,
            result: &mut Vec<(usize, &'a ProcessControlBlock)>,
        ) {
            if let Some(pcb) = table.get(pid) {
                result.push((depth, pcb));
                for child_pid in &pcb.children {
                    collect_tree(table, child_pid, depth + 1, result);
                }
            }
        }

        if let Some(root) = root_pid {
            collect_tree(self, root, 0, &mut result);
        } else {
            // Find all root processes (no parent)
            for pcb in self.processes.values() {
                if pcb.ppid.is_none() {
                    collect_tree(self, &pcb.pid, 0, &mut result);
                }
            }
        }

        result
    }

    /// Count processes
    pub fn count(&self) -> usize {
        self.processes.len()
    }

    /// Count processes by state
    pub fn count_by_state(&self, state: ProcessState) -> usize {
        self.processes.values().filter(|p| p.state == state).count()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rlimit() {
        let limit = Rlimit::new(100, 200);
        assert!(!limit.exceeds_soft(50));
        assert!(limit.exceeds_soft(150));
        assert!(!limit.exceeds_hard(150));
        assert!(limit.exceeds_hard(250));
    }

    #[test]
    fn test_fd_table() {
        let mut table = FdTable::new();
        assert_eq!(table.count(), 3); // stdin, stdout, stderr

        let fd = table.alloc(FdType::MemoryPacket { cid: "test".to_string() });
        assert_eq!(fd, 3);
        assert_eq!(table.count(), 4);

        let fd2 = table.dup(fd).unwrap();
        assert_eq!(fd2, 4);

        table.close(fd);
        assert_eq!(table.count(), 4); // fd2 still open
    }

    #[test]
    fn test_process_table() {
        let mut table = ProcessTable::new();
        
        let pid1 = table.create("init".to_string(), None);
        assert_eq!(table.count(), 1);

        let pid2 = table.create("child".to_string(), Some(&pid1));
        assert_eq!(table.count(), 2);

        let parent = table.get(&pid1).unwrap();
        assert!(parent.children.contains(&pid2));

        let child = table.get(&pid2).unwrap();
        assert_eq!(child.ppid, Some(pid1.clone()));
    }

    #[test]
    fn test_fork_and_wait() {
        let mut table = ProcessTable::new();
        
        let parent_pid = table.create("parent".to_string(), None);
        let child_pid = table.fork(&parent_pid).unwrap();
        
        assert_eq!(table.count(), 2);
        
        // Child exits
        table.exit(&child_pid, 42);
        
        // Parent waits
        let status = table.wait(&parent_pid, &child_pid).unwrap();
        assert_eq!(status.code, 42);
        
        // Child is reaped
        assert_eq!(table.count(), 1);
    }

    #[test]
    fn test_process_tree() {
        let mut table = ProcessTable::new();
        
        let root = table.create("init".to_string(), None);
        let child1 = table.create("child1".to_string(), Some(&root));
        let child2 = table.create("child2".to_string(), Some(&root));
        let _grandchild = table.create("grandchild".to_string(), Some(&child1));
        
        let tree = table.tree(Some(&root));
        assert_eq!(tree.len(), 4);
        assert_eq!(tree[0].0, 0); // root at depth 0
        assert_eq!(tree[0].1.name, "init");
    }

    #[test]
    fn test_stream_buffer() {
        let mut buf = StreamBuffer::new(1024);
        
        buf.write(b"Hello\nWorld\n");
        assert_eq!(buf.len(), 12);
        
        let line = buf.read_line().unwrap();
        assert_eq!(line, "Hello\n");
        assert_eq!(buf.len(), 6);
    }
}
