//! Isolation Model — Container Runtime, WASM Sandbox, Resource Cgroups
//!
//! This module implements comprehensive isolation:
//! - Container runtime integration (Docker/containerd/OCI)
//! - WASM sandbox for untrusted code execution
//! - Resource cgroups (cgroup v2 hierarchy)
//!
//! Design sources: OCI runtime spec, Wasmtime, Linux cgroups v2

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::process::Pid;

// =============================================================================
// Part 1: Container Runtime Integration
// =============================================================================

/// Container runtime type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerRuntime {
    /// Docker runtime
    Docker,
    /// containerd runtime
    Containerd,
    /// Podman runtime
    Podman,
    /// Native (no container)
    Native,
}

impl Default for ContainerRuntime {
    fn default() -> Self {
        Self::Native
    }
}

/// Container state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerState {
    /// Container is being created
    Creating,
    /// Container created but not started
    Created,
    /// Container is running
    Running,
    /// Container is paused
    Paused,
    /// Container is stopped
    Stopped,
    /// Container has exited
    Exited,
    /// Container is being removed
    Removing,
}

/// OCI container configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// Container ID
    pub id: String,
    /// Container name
    pub name: String,
    /// Image reference
    pub image: String,
    /// Command to run
    pub command: Vec<String>,
    /// Environment variables
    pub env: HashMap<String, String>,
    /// Working directory
    pub working_dir: String,
    /// User (uid:gid)
    pub user: Option<String>,
    /// Hostname
    pub hostname: Option<String>,
    /// Network mode
    pub network_mode: NetworkMode,
    /// Volume mounts
    pub mounts: Vec<Mount>,
    /// Resource limits
    pub resources: ContainerResources,
    /// Security options
    pub security: ContainerSecurity,
    /// Labels
    pub labels: HashMap<String, String>,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            image: String::new(),
            command: vec![],
            env: HashMap::new(),
            working_dir: "/".into(),
            user: None,
            hostname: None,
            network_mode: NetworkMode::Bridge,
            mounts: vec![],
            resources: ContainerResources::default(),
            security: ContainerSecurity::default(),
            labels: HashMap::new(),
        }
    }
}

/// Network mode
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Bridge network
    Bridge,
    /// Host network
    Host,
    /// No network
    None,
    /// Custom network
    Custom(String),
}

impl Default for NetworkMode {
    fn default() -> Self {
        Self::Bridge
    }
}

/// Volume mount
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mount {
    /// Source path (host)
    pub source: String,
    /// Target path (container)
    pub target: String,
    /// Mount type
    pub mount_type: MountType,
    /// Read-only
    pub readonly: bool,
}

/// Mount type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountType {
    Bind,
    Volume,
    Tmpfs,
}

/// Container resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerResources {
    /// CPU shares (relative weight)
    pub cpu_shares: u64,
    /// CPU quota (microseconds per period)
    pub cpu_quota: Option<i64>,
    /// CPU period (microseconds)
    pub cpu_period: u64,
    /// CPU count limit
    pub cpus: Option<f64>,
    /// Memory limit (bytes)
    pub memory_limit: u64,
    /// Memory reservation (bytes)
    pub memory_reservation: u64,
    /// Memory swap limit (bytes, -1 = unlimited)
    pub memory_swap: i64,
    /// PIDs limit
    pub pids_limit: i64,
    /// Block I/O weight
    pub blkio_weight: u16,
}

impl Default for ContainerResources {
    fn default() -> Self {
        Self {
            cpu_shares: 1024,
            cpu_quota: None,
            cpu_period: 100000,
            cpus: None,
            memory_limit: 512 * 1024 * 1024, // 512MB
            memory_reservation: 0,
            memory_swap: -1,
            pids_limit: 100,
            blkio_weight: 500,
        }
    }
}

/// Container security options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecurity {
    /// Privileged mode
    pub privileged: bool,
    /// Read-only root filesystem
    pub readonly_rootfs: bool,
    /// No new privileges
    pub no_new_privileges: bool,
    /// Seccomp profile
    pub seccomp_profile: Option<String>,
    /// AppArmor profile
    pub apparmor_profile: Option<String>,
    /// SELinux options
    pub selinux_options: Option<SelinuxOptions>,
    /// Capabilities to add
    pub cap_add: Vec<String>,
    /// Capabilities to drop
    pub cap_drop: Vec<String>,
}

impl Default for ContainerSecurity {
    fn default() -> Self {
        Self {
            privileged: false,
            readonly_rootfs: false,
            no_new_privileges: true,
            seccomp_profile: None,
            apparmor_profile: None,
            selinux_options: None,
            cap_add: vec![],
            cap_drop: vec!["ALL".into()],
        }
    }
}

/// SELinux options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelinuxOptions {
    pub user: Option<String>,
    pub role: Option<String>,
    pub type_: Option<String>,
    pub level: Option<String>,
}

/// Container instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Container {
    /// Container ID
    pub id: String,
    /// Configuration
    pub config: ContainerConfig,
    /// Current state
    pub state: ContainerState,
    /// Runtime type
    pub runtime: ContainerRuntime,
    /// Process ID (if running)
    pub pid: Option<u32>,
    /// Exit code (if exited)
    pub exit_code: Option<i32>,
    /// Created timestamp
    pub created_at: i64,
    /// Started timestamp
    pub started_at: Option<i64>,
    /// Finished timestamp
    pub finished_at: Option<i64>,
    /// Associated agent PID
    pub agent_pid: Option<Pid>,
}

impl Container {
    pub fn new(config: ContainerConfig, runtime: ContainerRuntime) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            id: config.id.clone(),
            config,
            state: ContainerState::Creating,
            runtime,
            pid: None,
            exit_code: None,
            created_at: now,
            started_at: None,
            finished_at: None,
            agent_pid: None,
        }
    }
}

/// Container runtime manager
#[derive(Debug, Default)]
pub struct ContainerManager {
    containers: HashMap<String, Container>,
    runtime: ContainerRuntime,
}

impl ContainerManager {
    pub fn new(runtime: ContainerRuntime) -> Self {
        Self {
            containers: HashMap::new(),
            runtime,
        }
    }

    /// Create a container
    pub fn create(&mut self, config: ContainerConfig) -> Result<String, String> {
        let id = if config.id.is_empty() {
            format!("cnt-{:016x}", rand_id())
        } else {
            config.id.clone()
        };

        let mut cfg = config;
        cfg.id = id.clone();

        let mut container = Container::new(cfg, self.runtime);
        container.state = ContainerState::Created;

        self.containers.insert(id.clone(), container);
        Ok(id)
    }

    /// Start a container
    pub fn start(&mut self, id: &str) -> Result<(), String> {
        let container = self.containers.get_mut(id)
            .ok_or_else(|| format!("Container {} not found", id))?;

        if container.state != ContainerState::Created && container.state != ContainerState::Stopped {
            return Err(format!("Container {} not in startable state", id));
        }

        container.state = ContainerState::Running;
        container.started_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64
        );

        Ok(())
    }

    /// Stop a container
    pub fn stop(&mut self, id: &str) -> Result<(), String> {
        let container = self.containers.get_mut(id)
            .ok_or_else(|| format!("Container {} not found", id))?;

        if container.state != ContainerState::Running {
            return Err(format!("Container {} not running", id));
        }

        container.state = ContainerState::Stopped;
        container.finished_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64
        );

        Ok(())
    }

    /// Remove a container
    pub fn remove(&mut self, id: &str) -> Result<Container, String> {
        let container = self.containers.get(id)
            .ok_or_else(|| format!("Container {} not found", id))?;

        if container.state == ContainerState::Running {
            return Err("Cannot remove running container".into());
        }

        self.containers.remove(id).ok_or_else(|| "Remove failed".into())
    }

    /// Get container
    pub fn get(&self, id: &str) -> Option<&Container> {
        self.containers.get(id)
    }

    /// List containers
    pub fn list(&self) -> Vec<&Container> {
        self.containers.values().collect()
    }

    /// Bind agent to container
    pub fn bind_agent(&mut self, container_id: &str, agent_pid: Pid) -> Result<(), String> {
        let container = self.containers.get_mut(container_id)
            .ok_or_else(|| format!("Container {} not found", container_id))?;
        container.agent_pid = Some(agent_pid);
        Ok(())
    }
}

fn rand_id() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut hasher);
    hasher.finish()
}

// =============================================================================
// Part 2: WASM Sandbox
// =============================================================================

/// WASM runtime type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmRuntime {
    /// Wasmtime runtime
    Wasmtime,
    /// Wasmer runtime
    Wasmer,
    /// WasmEdge runtime
    WasmEdge,
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::Wasmtime
    }
}

/// WASM module state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmModuleState {
    /// Module is loaded
    Loaded,
    /// Module is instantiated
    Instantiated,
    /// Module is running
    Running,
    /// Module is suspended
    Suspended,
    /// Module has completed
    Completed,
    /// Module has trapped/errored
    Trapped,
}

/// WASM sandbox configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmSandboxConfig {
    /// Maximum memory pages (64KB each)
    pub max_memory_pages: u32,
    /// Maximum table elements
    pub max_table_elements: u32,
    /// Maximum instances
    pub max_instances: u32,
    /// Fuel limit (instruction count)
    pub fuel_limit: Option<u64>,
    /// Epoch deadline (for interruption)
    pub epoch_deadline: Option<u64>,
    /// Enable WASI
    pub wasi_enabled: bool,
    /// WASI preopened directories
    pub wasi_preopens: Vec<WasiPreopen>,
    /// WASI environment variables
    pub wasi_env: HashMap<String, String>,
    /// WASI arguments
    pub wasi_args: Vec<String>,
    /// Enable SIMD
    pub simd_enabled: bool,
    /// Enable threads
    pub threads_enabled: bool,
}

impl Default for WasmSandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_pages: 256, // 16MB
            max_table_elements: 10000,
            max_instances: 10,
            fuel_limit: Some(1_000_000_000), // 1B instructions
            epoch_deadline: Some(1000), // 1 second
            wasi_enabled: true,
            wasi_preopens: vec![],
            wasi_env: HashMap::new(),
            wasi_args: vec![],
            simd_enabled: false,
            threads_enabled: false,
        }
    }
}

/// WASI preopened directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasiPreopen {
    /// Host path
    pub host_path: String,
    /// Guest path
    pub guest_path: String,
    /// Read-only
    pub readonly: bool,
}

/// WASM module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmModule {
    /// Module ID
    pub id: String,
    /// Module name
    pub name: String,
    /// Module hash (SHA-256)
    pub hash: String,
    /// Module size (bytes)
    pub size: u64,
    /// Exports
    pub exports: Vec<WasmExport>,
    /// Imports
    pub imports: Vec<WasmImport>,
    /// State
    pub state: WasmModuleState,
    /// Loaded timestamp
    pub loaded_at: i64,
}

/// WASM export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmExport {
    pub name: String,
    pub kind: WasmExternKind,
}

/// WASM import
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
    pub kind: WasmExternKind,
}

/// WASM extern kind
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmExternKind {
    Func,
    Global,
    Table,
    Memory,
}

/// WASM sandbox instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmSandbox {
    /// Sandbox ID
    pub id: String,
    /// Configuration
    pub config: WasmSandboxConfig,
    /// Runtime type
    pub runtime: WasmRuntime,
    /// Loaded modules
    pub modules: Vec<WasmModule>,
    /// Fuel consumed
    pub fuel_consumed: u64,
    /// Memory used (bytes)
    pub memory_used: u64,
    /// Associated agent PID
    pub agent_pid: Option<Pid>,
    /// Created timestamp
    pub created_at: i64,
}

impl WasmSandbox {
    pub fn new(config: WasmSandboxConfig, runtime: WasmRuntime) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            id: format!("wasm-{:016x}", rand_id()),
            config,
            runtime,
            modules: vec![],
            fuel_consumed: 0,
            memory_used: 0,
            agent_pid: None,
            created_at: now,
        }
    }

    /// Load a module
    pub fn load_module(&mut self, name: String, hash: String, size: u64) -> String {
        let module = WasmModule {
            id: format!("mod-{:08x}", self.modules.len()),
            name,
            hash,
            size,
            exports: vec![],
            imports: vec![],
            state: WasmModuleState::Loaded,
            loaded_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        };
        let id = module.id.clone();
        self.modules.push(module);
        id
    }

    /// Check fuel remaining
    pub fn fuel_remaining(&self) -> Option<u64> {
        self.config.fuel_limit.map(|limit| limit.saturating_sub(self.fuel_consumed))
    }

    /// Consume fuel
    pub fn consume_fuel(&mut self, amount: u64) -> Result<(), String> {
        if let Some(limit) = self.config.fuel_limit {
            if self.fuel_consumed + amount > limit {
                return Err("Fuel exhausted".into());
            }
        }
        self.fuel_consumed += amount;
        Ok(())
    }
}

/// WASM sandbox manager
#[derive(Debug, Default)]
pub struct WasmSandboxManager {
    sandboxes: HashMap<String, WasmSandbox>,
    default_runtime: WasmRuntime,
}

impl WasmSandboxManager {
    pub fn new(runtime: WasmRuntime) -> Self {
        Self {
            sandboxes: HashMap::new(),
            default_runtime: runtime,
        }
    }

    /// Create a sandbox
    pub fn create(&mut self, config: WasmSandboxConfig) -> String {
        let sandbox = WasmSandbox::new(config, self.default_runtime);
        let id = sandbox.id.clone();
        self.sandboxes.insert(id.clone(), sandbox);
        id
    }

    /// Get sandbox
    pub fn get(&self, id: &str) -> Option<&WasmSandbox> {
        self.sandboxes.get(id)
    }

    /// Get mutable sandbox
    pub fn get_mut(&mut self, id: &str) -> Option<&mut WasmSandbox> {
        self.sandboxes.get_mut(id)
    }

    /// Remove sandbox
    pub fn remove(&mut self, id: &str) -> Option<WasmSandbox> {
        self.sandboxes.remove(id)
    }

    /// List sandboxes
    pub fn list(&self) -> Vec<&WasmSandbox> {
        self.sandboxes.values().collect()
    }

    /// Bind agent to sandbox
    pub fn bind_agent(&mut self, sandbox_id: &str, agent_pid: Pid) -> Result<(), String> {
        let sandbox = self.sandboxes.get_mut(sandbox_id)
            .ok_or_else(|| format!("Sandbox {} not found", sandbox_id))?;
        sandbox.agent_pid = Some(agent_pid);
        Ok(())
    }
}

// =============================================================================
// Part 3: Resource Cgroups (cgroup v2)
// =============================================================================

/// Cgroup controller type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupController {
    /// CPU controller
    Cpu,
    /// Memory controller
    Memory,
    /// I/O controller
    Io,
    /// PIDs controller
    Pids,
    /// RDMA controller
    Rdma,
    /// HugeTLB controller
    Hugetlb,
    /// Cpuset controller
    Cpuset,
}

/// Cgroup path
pub type CgroupPath = String;

/// CPU controller settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuController {
    /// CPU weight (1-10000, default 100)
    pub weight: u32,
    /// CPU weight for nice 0 (1-10000)
    pub weight_nice: u32,
    /// CPU max (quota period)
    pub max: Option<CpuMax>,
    /// CPU burst
    pub burst: Option<u64>,
}

impl Default for CpuController {
    fn default() -> Self {
        Self {
            weight: 100,
            weight_nice: 100,
            max: None,
            burst: None,
        }
    }
}

/// CPU max (quota/period)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuMax {
    /// Quota in microseconds (or "max" for unlimited)
    pub quota: Option<u64>,
    /// Period in microseconds
    pub period: u64,
}

/// Memory controller settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryController {
    /// Memory limit (bytes)
    pub max: Option<u64>,
    /// Memory high threshold (bytes)
    pub high: Option<u64>,
    /// Memory low threshold (bytes)
    pub low: Option<u64>,
    /// Memory minimum (bytes)
    pub min: Option<u64>,
    /// Swap max (bytes)
    pub swap_max: Option<u64>,
    /// OOM group kill
    pub oom_group: bool,
}

impl Default for MemoryController {
    fn default() -> Self {
        Self {
            max: None,
            high: None,
            low: None,
            min: None,
            swap_max: None,
            oom_group: false,
        }
    }
}

/// I/O controller settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoController {
    /// I/O weight (1-10000, default 100)
    pub weight: u32,
    /// Per-device limits
    pub device_limits: Vec<IoDeviceLimit>,
}

impl Default for IoController {
    fn default() -> Self {
        Self {
            weight: 100,
            device_limits: vec![],
        }
    }
}

/// I/O device limit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoDeviceLimit {
    /// Device major:minor
    pub device: String,
    /// Read BPS limit
    pub rbps: Option<u64>,
    /// Write BPS limit
    pub wbps: Option<u64>,
    /// Read IOPS limit
    pub riops: Option<u64>,
    /// Write IOPS limit
    pub wiops: Option<u64>,
}

/// PIDs controller settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PidsController {
    /// Maximum number of PIDs
    pub max: Option<u64>,
}

impl Default for PidsController {
    fn default() -> Self {
        Self { max: None }
    }
}

/// Cgroup settings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CgroupSettings {
    pub cpu: Option<CpuController>,
    pub memory: Option<MemoryController>,
    pub io: Option<IoController>,
    pub pids: Option<PidsController>,
}

/// Cgroup statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CgroupStats {
    /// CPU usage (microseconds)
    pub cpu_usage_usec: u64,
    /// User CPU usage (microseconds)
    pub cpu_user_usec: u64,
    /// System CPU usage (microseconds)
    pub cpu_system_usec: u64,
    /// Number of periods
    pub nr_periods: u64,
    /// Number of throttled periods
    pub nr_throttled: u64,
    /// Throttled time (microseconds)
    pub throttled_usec: u64,
    /// Memory current (bytes)
    pub memory_current: u64,
    /// Memory peak (bytes)
    pub memory_peak: u64,
    /// Swap current (bytes)
    pub swap_current: u64,
    /// PIDs current
    pub pids_current: u64,
    /// I/O read bytes
    pub io_read_bytes: u64,
    /// I/O write bytes
    pub io_write_bytes: u64,
}

/// Cgroup node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cgroup {
    /// Cgroup path
    pub path: CgroupPath,
    /// Parent path
    pub parent: Option<CgroupPath>,
    /// Children paths
    pub children: Vec<CgroupPath>,
    /// Enabled controllers
    pub controllers: Vec<CgroupController>,
    /// Settings
    pub settings: CgroupSettings,
    /// Statistics
    pub stats: CgroupStats,
    /// Member PIDs
    pub members: Vec<Pid>,
    /// Created timestamp
    pub created_at: i64,
}

impl Cgroup {
    pub fn new(path: CgroupPath, parent: Option<CgroupPath>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            path,
            parent,
            children: vec![],
            controllers: vec![],
            settings: CgroupSettings::default(),
            stats: CgroupStats::default(),
            members: vec![],
            created_at: now,
        }
    }

    /// Enable a controller
    pub fn enable_controller(&mut self, controller: CgroupController) {
        if !self.controllers.contains(&controller) {
            self.controllers.push(controller);
        }
    }

    /// Add a member
    pub fn add_member(&mut self, pid: Pid) {
        if !self.members.contains(&pid) {
            self.members.push(pid);
        }
    }

    /// Remove a member
    pub fn remove_member(&mut self, pid: &Pid) {
        self.members.retain(|p| p != pid);
    }
}

/// Cgroup hierarchy manager
#[derive(Debug, Default)]
pub struct CgroupManager {
    /// Cgroups by path
    cgroups: HashMap<CgroupPath, Cgroup>,
    /// PID to cgroup mapping
    pid_cgroup: HashMap<Pid, CgroupPath>,
}

impl CgroupManager {
    pub fn new() -> Self {
        let mut manager = Self::default();
        // Create root cgroup
        let root = Cgroup::new("/".into(), None);
        manager.cgroups.insert("/".into(), root);
        manager
    }

    /// Create a cgroup
    pub fn create(&mut self, path: CgroupPath) -> Result<(), String> {
        if self.cgroups.contains_key(&path) {
            return Err(format!("Cgroup {} already exists", path));
        }

        // Find parent
        let parent_path = path.rsplit_once('/')
            .map(|(p, _)| if p.is_empty() { "/" } else { p })
            .unwrap_or("/")
            .to_string();

        if !self.cgroups.contains_key(&parent_path) {
            return Err(format!("Parent cgroup {} not found", parent_path));
        }

        let cgroup = Cgroup::new(path.clone(), Some(parent_path.clone()));
        self.cgroups.insert(path.clone(), cgroup);

        // Add to parent's children
        if let Some(parent) = self.cgroups.get_mut(&parent_path) {
            parent.children.push(path);
        }

        Ok(())
    }

    /// Remove a cgroup
    pub fn remove(&mut self, path: &str) -> Result<(), String> {
        let cgroup = self.cgroups.get(path)
            .ok_or_else(|| format!("Cgroup {} not found", path))?;

        if !cgroup.children.is_empty() {
            return Err("Cannot remove cgroup with children".into());
        }
        if !cgroup.members.is_empty() {
            return Err("Cannot remove cgroup with members".into());
        }

        // Remove from parent's children
        if let Some(parent_path) = cgroup.parent.clone() {
            if let Some(parent) = self.cgroups.get_mut(&parent_path) {
                parent.children.retain(|c| c != path);
            }
        }

        self.cgroups.remove(path);
        Ok(())
    }

    /// Get cgroup
    pub fn get(&self, path: &str) -> Option<&Cgroup> {
        self.cgroups.get(path)
    }

    /// Get mutable cgroup
    pub fn get_mut(&mut self, path: &str) -> Option<&mut Cgroup> {
        self.cgroups.get_mut(path)
    }

    /// Move process to cgroup
    pub fn attach(&mut self, pid: Pid, path: &str) -> Result<(), String> {
        // Remove from old cgroup
        if let Some(old_path) = self.pid_cgroup.get(&pid).cloned() {
            if let Some(old_cgroup) = self.cgroups.get_mut(&old_path) {
                old_cgroup.remove_member(&pid);
            }
        }

        // Add to new cgroup
        let cgroup = self.cgroups.get_mut(path)
            .ok_or_else(|| format!("Cgroup {} not found", path))?;
        cgroup.add_member(pid.clone());
        self.pid_cgroup.insert(pid, path.to_string());

        Ok(())
    }

    /// Get process's cgroup
    pub fn get_pid_cgroup(&self, pid: &Pid) -> Option<&str> {
        self.pid_cgroup.get(pid).map(|s| s.as_str())
    }

    /// Set CPU settings
    pub fn set_cpu(&mut self, path: &str, settings: CpuController) -> Result<(), String> {
        let cgroup = self.cgroups.get_mut(path)
            .ok_or_else(|| format!("Cgroup {} not found", path))?;
        cgroup.enable_controller(CgroupController::Cpu);
        cgroup.settings.cpu = Some(settings);
        Ok(())
    }

    /// Set memory settings
    pub fn set_memory(&mut self, path: &str, settings: MemoryController) -> Result<(), String> {
        let cgroup = self.cgroups.get_mut(path)
            .ok_or_else(|| format!("Cgroup {} not found", path))?;
        cgroup.enable_controller(CgroupController::Memory);
        cgroup.settings.memory = Some(settings);
        Ok(())
    }

    /// Set I/O settings
    pub fn set_io(&mut self, path: &str, settings: IoController) -> Result<(), String> {
        let cgroup = self.cgroups.get_mut(path)
            .ok_or_else(|| format!("Cgroup {} not found", path))?;
        cgroup.enable_controller(CgroupController::Io);
        cgroup.settings.io = Some(settings);
        Ok(())
    }

    /// Set PIDs settings
    pub fn set_pids(&mut self, path: &str, settings: PidsController) -> Result<(), String> {
        let cgroup = self.cgroups.get_mut(path)
            .ok_or_else(|| format!("Cgroup {} not found", path))?;
        cgroup.enable_controller(CgroupController::Pids);
        cgroup.settings.pids = Some(settings);
        Ok(())
    }

    /// List all cgroups
    pub fn list(&self) -> Vec<&Cgroup> {
        self.cgroups.values().collect()
    }

    /// List cgroups under a path
    pub fn list_children(&self, path: &str) -> Vec<&Cgroup> {
        self.cgroups.get(path)
            .map(|cg| cg.children.iter()
                .filter_map(|p| self.cgroups.get(p))
                .collect())
            .unwrap_or_default()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_manager() {
        let mut manager = ContainerManager::new(ContainerRuntime::Docker);

        let config = ContainerConfig {
            name: "test-container".into(),
            image: "alpine:latest".into(),
            ..Default::default()
        };

        let id = manager.create(config).unwrap();
        assert!(manager.get(&id).is_some());

        manager.start(&id).unwrap();
        assert_eq!(manager.get(&id).unwrap().state, ContainerState::Running);

        manager.stop(&id).unwrap();
        assert_eq!(manager.get(&id).unwrap().state, ContainerState::Stopped);

        manager.remove(&id).unwrap();
        assert!(manager.get(&id).is_none());
    }

    #[test]
    fn test_wasm_sandbox() {
        let mut manager = WasmSandboxManager::new(WasmRuntime::Wasmtime);

        let config = WasmSandboxConfig::default();
        let id = manager.create(config);

        let sandbox = manager.get_mut(&id).unwrap();
        sandbox.load_module("test.wasm".into(), "abc123".into(), 1024);

        assert_eq!(sandbox.modules.len(), 1);
        assert_eq!(sandbox.fuel_remaining(), Some(1_000_000_000));

        sandbox.consume_fuel(100).unwrap();
        assert_eq!(sandbox.fuel_remaining(), Some(999_999_900));
    }

    #[test]
    fn test_cgroup_manager() {
        let mut manager = CgroupManager::new();

        // Create hierarchy
        manager.create("/agents".into()).unwrap();
        manager.create("/agents/agent-001".into()).unwrap();

        // Set limits
        manager.set_memory("/agents/agent-001", MemoryController {
            max: Some(512 * 1024 * 1024),
            ..Default::default()
        }).unwrap();

        manager.set_cpu("/agents/agent-001", CpuController {
            weight: 200,
            ..Default::default()
        }).unwrap();

        // Attach process
        manager.attach("pid:001".into(), "/agents/agent-001").unwrap();

        let cgroup = manager.get("/agents/agent-001").unwrap();
        assert!(cgroup.members.contains(&"pid:001".into()));
        assert!(cgroup.controllers.contains(&CgroupController::Memory));
        assert!(cgroup.controllers.contains(&CgroupController::Cpu));
    }

    #[test]
    fn test_cgroup_hierarchy() {
        let mut manager = CgroupManager::new();

        manager.create("/system".into()).unwrap();
        manager.create("/system/kernel".into()).unwrap();
        manager.create("/agents".into()).unwrap();

        let children = manager.list_children("/");
        assert_eq!(children.len(), 2);

        // Can't remove non-empty cgroup
        assert!(manager.remove("/system").is_err());

        // Can remove leaf
        manager.remove("/system/kernel").unwrap();
        manager.remove("/system").unwrap();
    }
}
