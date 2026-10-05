//! Thread Abstraction — Sub-agent = Thread Mapping
//!
//! This module implements a thread abstraction for agents:
//! - Sub-agents map to threads within a parent agent (process)
//! - Thread Control Block (TCB) analogous to Linux task_struct for threads
//! - Thread-local storage (TLS) for sub-agent state
//! - Thread synchronization primitives (mutex, semaphore, barrier)
//! - Thread pool for parallel sub-agent execution
//!
//! Design sources: Linux threads (clone()), POSIX pthreads, Go goroutines

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::process::Pid;

// =============================================================================
// Thread ID Types
// =============================================================================

/// Thread ID (unique within a process/agent)
pub type Tid = String;

/// Thread Group ID (same as parent agent PID)
pub type Tgid = String;

/// Generate a new thread ID
static THREAD_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn generate_tid(parent_pid: &str) -> Tid {
    let id = THREAD_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{}:tid:{:08}", parent_pid, id)
}

// =============================================================================
// Thread State
// =============================================================================

/// Thread state (subset of process states, thread-specific)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadState {
    /// Thread is being created
    Creating,
    /// Thread is runnable (ready to execute)
    Runnable,
    /// Thread is currently running
    Running,
    /// Thread is blocked on I/O or synchronization
    Blocked,
    /// Thread is waiting for a condition
    Waiting,
    /// Thread is sleeping (timed wait)
    Sleeping,
    /// Thread has exited but not yet joined
    Zombie,
    /// Thread has been terminated
    Dead,
}

impl Default for ThreadState {
    fn default() -> Self {
        Self::Creating
    }
}

/// Thread type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadType {
    /// Main thread (the original agent)
    Main,
    /// Worker thread (sub-agent for parallel work)
    Worker,
    /// I/O thread (handles async I/O operations)
    Io,
    /// Timer thread (handles scheduled tasks)
    Timer,
    /// Background thread (low-priority tasks)
    Background,
}

impl Default for ThreadType {
    fn default() -> Self {
        Self::Worker
    }
}

// =============================================================================
// Thread Control Block (TCB)
// =============================================================================

/// Thread Control Block — per-thread state (Linux task_struct for threads)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadControlBlock {
    // --- Identity ---
    /// Thread ID (unique within process)
    pub tid: Tid,
    /// Thread Group ID (parent agent PID)
    pub tgid: Tgid,
    /// Thread name (for debugging)
    pub name: String,
    /// Thread type
    pub thread_type: ThreadType,

    // --- State ---
    /// Current thread state
    pub state: ThreadState,
    /// Exit code (if exited)
    pub exit_code: Option<i32>,

    // --- Scheduling ---
    /// Thread priority (0-99, higher = more priority)
    pub priority: u8,
    /// Nice value (-20 to 19)
    pub nice: i8,
    /// CPU affinity mask (bit per CPU)
    pub cpu_affinity: u64,
    /// Time slice remaining (microseconds)
    pub time_slice_us: u64,

    // --- Statistics ---
    /// User CPU time (microseconds)
    pub utime_us: u64,
    /// System CPU time (microseconds)
    pub stime_us: u64,
    /// Voluntary context switches
    pub voluntary_switches: u64,
    /// Involuntary context switches
    pub involuntary_switches: u64,
    /// Number of syscalls made
    pub syscall_count: u64,

    // --- Timestamps ---
    /// Creation time (epoch ms)
    pub created_at: i64,
    /// Last scheduled time (epoch ms)
    pub last_scheduled_at: Option<i64>,
    /// Last blocked time (epoch ms)
    pub last_blocked_at: Option<i64>,

    // --- Stack ---
    /// Stack size (bytes)
    pub stack_size: u64,
    /// Stack usage (bytes)
    pub stack_used: u64,

    // --- Thread-local storage ---
    /// Thread-local variables
    pub tls: HashMap<String, serde_json::Value>,

    // --- Synchronization ---
    /// Mutex currently held (if any)
    pub held_mutex: Option<String>,
    /// Waiting on mutex (if blocked)
    pub waiting_mutex: Option<String>,
    /// Join target (if waiting to join another thread)
    pub join_target: Option<Tid>,

    // --- Parent/Child ---
    /// Threads spawned by this thread
    pub child_threads: Vec<Tid>,
    /// Detached (no join required)
    pub detached: bool,
}

impl ThreadControlBlock {
    /// Create a new thread
    pub fn new(tgid: Tgid, name: String, thread_type: ThreadType) -> Self {
        let tid = generate_tid(&tgid);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            tid,
            tgid,
            name,
            thread_type,
            state: ThreadState::Creating,
            exit_code: None,
            priority: 50,
            nice: 0,
            cpu_affinity: u64::MAX, // All CPUs
            time_slice_us: 100_000, // 100ms default
            utime_us: 0,
            stime_us: 0,
            voluntary_switches: 0,
            involuntary_switches: 0,
            syscall_count: 0,
            created_at: now,
            last_scheduled_at: None,
            last_blocked_at: None,
            stack_size: 8 * 1024 * 1024, // 8MB default
            stack_used: 0,
            tls: HashMap::new(),
            held_mutex: None,
            waiting_mutex: None,
            join_target: None,
            child_threads: vec![],
            detached: false,
        }
    }

    /// Create main thread for an agent
    pub fn main_thread(agent_pid: Pid, agent_name: String) -> Self {
        let mut tcb = Self::new(agent_pid.clone(), agent_name, ThreadType::Main);
        tcb.tid = format!("{}:tid:main", agent_pid);
        tcb.state = ThreadState::Runnable;
        tcb
    }

    /// Start the thread
    pub fn start(&mut self) {
        if self.state == ThreadState::Creating {
            self.state = ThreadState::Runnable;
        }
    }

    /// Mark thread as running
    pub fn run(&mut self) {
        if self.state == ThreadState::Runnable {
            self.state = ThreadState::Running;
            self.last_scheduled_at = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64
            );
        }
    }

    /// Block the thread
    pub fn block(&mut self, reason: Option<String>) {
        if self.state == ThreadState::Running {
            self.state = ThreadState::Blocked;
            self.last_blocked_at = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64
            );
            self.voluntary_switches += 1;
            if let Some(mutex) = reason {
                self.waiting_mutex = Some(mutex);
            }
        }
    }

    /// Unblock the thread
    pub fn unblock(&mut self) {
        if self.state == ThreadState::Blocked || self.state == ThreadState::Waiting {
            self.state = ThreadState::Runnable;
            self.waiting_mutex = None;
        }
    }

    /// Sleep the thread
    pub fn sleep(&mut self) {
        if self.state == ThreadState::Running {
            self.state = ThreadState::Sleeping;
            self.voluntary_switches += 1;
        }
    }

    /// Wake the thread
    pub fn wake(&mut self) {
        if self.state == ThreadState::Sleeping {
            self.state = ThreadState::Runnable;
        }
    }

    /// Exit the thread
    pub fn exit(&mut self, code: i32) {
        self.state = ThreadState::Zombie;
        self.exit_code = Some(code);
    }

    /// Reap the thread (after join)
    pub fn reap(&mut self) {
        self.state = ThreadState::Dead;
    }

    /// Detach the thread
    pub fn detach(&mut self) {
        self.detached = true;
        if self.state == ThreadState::Zombie {
            self.state = ThreadState::Dead;
        }
    }

    /// Set thread-local variable
    pub fn set_tls(&mut self, key: &str, value: serde_json::Value) {
        self.tls.insert(key.to_string(), value);
    }

    /// Get thread-local variable
    pub fn get_tls(&self, key: &str) -> Option<&serde_json::Value> {
        self.tls.get(key)
    }

    /// Acquire a mutex
    pub fn acquire_mutex(&mut self, mutex_id: &str) {
        self.held_mutex = Some(mutex_id.to_string());
        self.waiting_mutex = None;
    }

    /// Release a mutex
    pub fn release_mutex(&mut self) {
        self.held_mutex = None;
    }

    /// Check if thread is alive
    pub fn is_alive(&self) -> bool {
        !matches!(self.state, ThreadState::Zombie | ThreadState::Dead)
    }

    /// Check if thread is joinable
    pub fn is_joinable(&self) -> bool {
        self.state == ThreadState::Zombie && !self.detached
    }
}

// =============================================================================
// Thread Table
// =============================================================================

/// Thread table — manages all threads for an agent
#[derive(Debug, Default)]
pub struct ThreadTable {
    /// Threads by TID
    threads: HashMap<Tid, ThreadControlBlock>,
    /// Thread group ID (parent agent PID)
    tgid: Tgid,
    /// Main thread TID
    main_tid: Option<Tid>,
}

impl ThreadTable {
    /// Create a new thread table for an agent
    pub fn new(agent_pid: Pid, agent_name: String) -> Self {
        let main_thread = ThreadControlBlock::main_thread(agent_pid.clone(), agent_name);
        let main_tid = main_thread.tid.clone();
        
        let mut threads = HashMap::new();
        threads.insert(main_tid.clone(), main_thread);

        Self {
            threads,
            tgid: agent_pid,
            main_tid: Some(main_tid),
        }
    }

    /// Spawn a new thread
    pub fn spawn(&mut self, name: String, thread_type: ThreadType) -> Tid {
        let tcb = ThreadControlBlock::new(self.tgid.clone(), name, thread_type);
        let tid = tcb.tid.clone();
        self.threads.insert(tid.clone(), tcb);
        tid
    }

    /// Spawn a worker thread
    pub fn spawn_worker(&mut self, name: String) -> Tid {
        self.spawn(name, ThreadType::Worker)
    }

    /// Get a thread by TID
    pub fn get(&self, tid: &str) -> Option<&ThreadControlBlock> {
        self.threads.get(tid)
    }

    /// Get a mutable thread by TID
    pub fn get_mut(&mut self, tid: &str) -> Option<&mut ThreadControlBlock> {
        self.threads.get_mut(tid)
    }

    /// Get main thread
    pub fn main_thread(&self) -> Option<&ThreadControlBlock> {
        self.main_tid.as_ref().and_then(|tid| self.threads.get(tid))
    }

    /// Get main thread (mutable)
    pub fn main_thread_mut(&mut self) -> Option<&mut ThreadControlBlock> {
        let tid = self.main_tid.clone()?;
        self.threads.get_mut(&tid)
    }

    /// Start a thread
    pub fn start(&mut self, tid: &str) -> bool {
        if let Some(tcb) = self.threads.get_mut(tid) {
            tcb.start();
            true
        } else {
            false
        }
    }

    /// Join a thread (wait for completion)
    pub fn join(&mut self, tid: &str) -> Option<i32> {
        let tcb = self.threads.get_mut(tid)?;
        if tcb.is_joinable() {
            let code = tcb.exit_code;
            tcb.reap();
            code
        } else {
            None
        }
    }

    /// Detach a thread
    pub fn detach(&mut self, tid: &str) -> bool {
        if let Some(tcb) = self.threads.get_mut(tid) {
            tcb.detach();
            true
        } else {
            false
        }
    }

    /// Exit a thread
    pub fn exit(&mut self, tid: &str, code: i32) -> bool {
        if let Some(tcb) = self.threads.get_mut(tid) {
            tcb.exit(code);
            true
        } else {
            false
        }
    }

    /// List all threads
    pub fn list(&self) -> Vec<&ThreadControlBlock> {
        self.threads.values().collect()
    }

    /// List alive threads
    pub fn list_alive(&self) -> Vec<&ThreadControlBlock> {
        self.threads.values().filter(|t| t.is_alive()).collect()
    }

    /// Count threads
    pub fn count(&self) -> usize {
        self.threads.len()
    }

    /// Count alive threads
    pub fn count_alive(&self) -> usize {
        self.threads.values().filter(|t| t.is_alive()).count()
    }

    /// Get thread group ID
    pub fn tgid(&self) -> &str {
        &self.tgid
    }

    /// Clean up dead threads
    pub fn cleanup_dead(&mut self) {
        self.threads.retain(|_, t| t.state != ThreadState::Dead);
    }
}

// =============================================================================
// Synchronization Primitives
// =============================================================================

/// Mutex state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadMutex {
    /// Mutex ID
    pub id: String,
    /// Owner thread (if locked)
    pub owner: Option<Tid>,
    /// Waiting threads
    pub waiters: Vec<Tid>,
    /// Lock count (for recursive mutexes)
    pub lock_count: u32,
    /// Is recursive mutex
    pub recursive: bool,
}

impl ThreadMutex {
    pub fn new(id: String, recursive: bool) -> Self {
        Self {
            id,
            owner: None,
            waiters: vec![],
            lock_count: 0,
            recursive,
        }
    }

    /// Try to lock the mutex
    pub fn try_lock(&mut self, tid: &str) -> bool {
        match &self.owner {
            None => {
                self.owner = Some(tid.to_string());
                self.lock_count = 1;
                true
            }
            Some(owner) if owner == tid && self.recursive => {
                self.lock_count += 1;
                true
            }
            _ => false,
        }
    }

    /// Add to waiters
    pub fn wait(&mut self, tid: &str) {
        if !self.waiters.contains(&tid.to_string()) {
            self.waiters.push(tid.to_string());
        }
    }

    /// Unlock the mutex
    pub fn unlock(&mut self, tid: &str) -> Option<Tid> {
        if self.owner.as_deref() == Some(tid) {
            self.lock_count -= 1;
            if self.lock_count == 0 {
                self.owner = None;
                // Wake first waiter
                if !self.waiters.is_empty() {
                    return Some(self.waiters.remove(0));
                }
            }
        }
        None
    }

    pub fn is_locked(&self) -> bool {
        self.owner.is_some()
    }
}

/// Semaphore
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadSemaphore {
    /// Semaphore ID
    pub id: String,
    /// Current count
    pub count: i32,
    /// Maximum count
    pub max_count: i32,
    /// Waiting threads
    pub waiters: Vec<Tid>,
}

impl ThreadSemaphore {
    pub fn new(id: String, initial: i32, max: i32) -> Self {
        Self {
            id,
            count: initial,
            max_count: max,
            waiters: vec![],
        }
    }

    /// Try to acquire (decrement)
    pub fn try_acquire(&mut self) -> bool {
        if self.count > 0 {
            self.count -= 1;
            true
        } else {
            false
        }
    }

    /// Wait for semaphore
    pub fn wait(&mut self, tid: &str) {
        if !self.waiters.contains(&tid.to_string()) {
            self.waiters.push(tid.to_string());
        }
    }

    /// Release (increment)
    pub fn release(&mut self) -> Option<Tid> {
        if self.count < self.max_count {
            self.count += 1;
            if !self.waiters.is_empty() && self.count > 0 {
                self.count -= 1;
                return Some(self.waiters.remove(0));
            }
        }
        None
    }
}

/// Barrier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadBarrier {
    /// Barrier ID
    pub id: String,
    /// Number of threads required
    pub count: usize,
    /// Threads currently waiting
    pub waiting: Vec<Tid>,
    /// Generation (increments each time barrier is released)
    pub generation: u64,
}

impl ThreadBarrier {
    pub fn new(id: String, count: usize) -> Self {
        Self {
            id,
            count,
            waiting: vec![],
            generation: 0,
        }
    }

    /// Wait at barrier, returns true if this thread released the barrier
    pub fn wait(&mut self, tid: &str) -> (bool, Vec<Tid>) {
        self.waiting.push(tid.to_string());
        
        if self.waiting.len() >= self.count {
            // Release all threads
            let released = std::mem::take(&mut self.waiting);
            self.generation += 1;
            (true, released)
        } else {
            (false, vec![])
        }
    }
}

// =============================================================================
// Thread Pool
// =============================================================================

/// Thread pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadPoolConfig {
    /// Minimum number of threads
    pub min_threads: usize,
    /// Maximum number of threads
    pub max_threads: usize,
    /// Thread idle timeout (seconds)
    pub idle_timeout_secs: u64,
    /// Stack size per thread (bytes)
    pub stack_size: u64,
}

impl Default for ThreadPoolConfig {
    fn default() -> Self {
        Self {
            min_threads: 2,
            max_threads: 16,
            idle_timeout_secs: 60,
            stack_size: 2 * 1024 * 1024, // 2MB
        }
    }
}

/// Thread pool for parallel sub-agent execution
#[derive(Debug)]
pub struct ThreadPool {
    /// Pool configuration
    config: ThreadPoolConfig,
    /// Thread table
    threads: ThreadTable,
    /// Idle threads (ready for work)
    idle_threads: Vec<Tid>,
    /// Busy threads (currently executing)
    busy_threads: Vec<Tid>,
    /// Pending tasks
    pending_tasks: Vec<String>,
}

impl ThreadPool {
    /// Create a new thread pool
    pub fn new(agent_pid: Pid, agent_name: String, config: ThreadPoolConfig) -> Self {
        let mut threads = ThreadTable::new(agent_pid, agent_name);
        let mut idle_threads = vec![];

        // Create minimum threads
        for i in 0..config.min_threads {
            let tid = threads.spawn_worker(format!("pool-worker-{}", i));
            threads.start(&tid);
            idle_threads.push(tid);
        }

        Self {
            config,
            threads,
            idle_threads,
            busy_threads: vec![],
            pending_tasks: vec![],
        }
    }

    /// Submit a task to the pool
    pub fn submit(&mut self, task_id: String) -> Option<Tid> {
        // Try to get an idle thread
        if let Some(tid) = self.idle_threads.pop() {
            if let Some(tcb) = self.threads.get_mut(&tid) {
                tcb.run();
            }
            self.busy_threads.push(tid.clone());
            return Some(tid);
        }

        // Try to spawn a new thread if under max
        if self.threads.count_alive() < self.config.max_threads {
            let tid = self.threads.spawn_worker(format!("pool-worker-{}", self.threads.count()));
            self.threads.start(&tid);
            if let Some(tcb) = self.threads.get_mut(&tid) {
                tcb.run();
            }
            self.busy_threads.push(tid.clone());
            return Some(tid);
        }

        // Queue the task
        self.pending_tasks.push(task_id);
        None
    }

    /// Complete a task and return thread to pool
    pub fn complete(&mut self, tid: &str) -> Option<String> {
        // Remove from busy
        self.busy_threads.retain(|t| t != tid);

        // Check for pending tasks
        if let Some(task_id) = self.pending_tasks.pop() {
            self.busy_threads.push(tid.to_string());
            return Some(task_id);
        }

        // Return to idle
        if let Some(tcb) = self.threads.get_mut(tid) {
            tcb.state = ThreadState::Runnable;
        }
        self.idle_threads.push(tid.to_string());
        None
    }

    /// Get pool statistics
    pub fn stats(&self) -> ThreadPoolStats {
        ThreadPoolStats {
            total_threads: self.threads.count_alive(),
            idle_threads: self.idle_threads.len(),
            busy_threads: self.busy_threads.len(),
            pending_tasks: self.pending_tasks.len(),
            min_threads: self.config.min_threads,
            max_threads: self.config.max_threads,
        }
    }
}

/// Thread pool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadPoolStats {
    pub total_threads: usize,
    pub idle_threads: usize,
    pub busy_threads: usize,
    pub pending_tasks: usize,
    pub min_threads: usize,
    pub max_threads: usize,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_creation() {
        let tcb = ThreadControlBlock::new(
            "pid:001".to_string(),
            "worker-1".to_string(),
            ThreadType::Worker,
        );
        assert_eq!(tcb.tgid, "pid:001");
        assert_eq!(tcb.state, ThreadState::Creating);
        assert!(tcb.is_alive());
    }

    #[test]
    fn test_thread_lifecycle() {
        let mut tcb = ThreadControlBlock::new(
            "pid:001".to_string(),
            "worker-1".to_string(),
            ThreadType::Worker,
        );

        tcb.start();
        assert_eq!(tcb.state, ThreadState::Runnable);

        tcb.run();
        assert_eq!(tcb.state, ThreadState::Running);

        tcb.block(Some("mutex:001".to_string()));
        assert_eq!(tcb.state, ThreadState::Blocked);
        assert_eq!(tcb.waiting_mutex, Some("mutex:001".to_string()));

        tcb.unblock();
        assert_eq!(tcb.state, ThreadState::Runnable);

        tcb.run();
        tcb.exit(0);
        assert_eq!(tcb.state, ThreadState::Zombie);
        assert!(tcb.is_joinable());

        tcb.reap();
        assert_eq!(tcb.state, ThreadState::Dead);
        assert!(!tcb.is_alive());
    }

    #[test]
    fn test_thread_table() {
        let mut table = ThreadTable::new("pid:001".to_string(), "main-agent".to_string());
        
        assert_eq!(table.count(), 1);
        assert!(table.main_thread().is_some());

        let tid = table.spawn_worker("worker-1".to_string());
        assert_eq!(table.count(), 2);

        table.start(&tid);
        let tcb = table.get(&tid).unwrap();
        assert_eq!(tcb.state, ThreadState::Runnable);

        table.exit(&tid, 42);
        assert_eq!(table.join(&tid), Some(42));
    }

    #[test]
    fn test_mutex() {
        let mut mutex = ThreadMutex::new("mutex:001".to_string(), false);
        
        assert!(mutex.try_lock("tid:001"));
        assert!(!mutex.try_lock("tid:002"));
        
        mutex.wait("tid:002");
        assert_eq!(mutex.waiters.len(), 1);

        let woken = mutex.unlock("tid:001");
        assert_eq!(woken, Some("tid:002".to_string()));
    }

    #[test]
    fn test_semaphore() {
        let mut sem = ThreadSemaphore::new("sem:001".to_string(), 2, 2);
        
        assert!(sem.try_acquire());
        assert!(sem.try_acquire());
        assert!(!sem.try_acquire());

        sem.wait("tid:001");
        let woken = sem.release();
        assert_eq!(woken, Some("tid:001".to_string()));
    }

    #[test]
    fn test_barrier() {
        let mut barrier = ThreadBarrier::new("barrier:001".to_string(), 3);
        
        let (released, _) = barrier.wait("tid:001");
        assert!(!released);
        
        let (released, _) = barrier.wait("tid:002");
        assert!(!released);
        
        let (released, threads) = barrier.wait("tid:003");
        assert!(released);
        assert_eq!(threads.len(), 3);
    }

    #[test]
    fn test_thread_pool() {
        let config = ThreadPoolConfig {
            min_threads: 2,
            max_threads: 4,
            ..Default::default()
        };
        let mut pool = ThreadPool::new("pid:001".to_string(), "agent".to_string(), config);
        
        let stats = pool.stats();
        assert_eq!(stats.idle_threads, 2);
        assert_eq!(stats.busy_threads, 0);

        let tid = pool.submit("task:001".to_string());
        assert!(tid.is_some());
        
        let stats = pool.stats();
        assert_eq!(stats.busy_threads, 1);
    }
}
