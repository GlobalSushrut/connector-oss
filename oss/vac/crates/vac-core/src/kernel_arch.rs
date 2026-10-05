//! Kernel Architecture — Separation, Modules, Configuration
//!
//! This module implements a modular kernel architecture:
//! - Kernel separation (MemoryKernel, ExecutionKernel, VerificationKernel)
//! - Loadable kernel modules
//! - Runtime kernel configuration (/proc/sys equivalent)
//!
//! Design sources: Linux kernel modules, microkernel architecture, sysctl

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

// =============================================================================
// Part 1: Kernel Separation
// =============================================================================

/// Kernel subsystem type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelSubsystem {
    /// Memory kernel — state management, storage, caching
    Memory,
    /// Execution kernel — agent scheduling, syscall dispatch
    Execution,
    /// Verification kernel — proofs, attestations, integrity
    Verification,
    /// Network kernel — ports, messaging, cross-cell
    Network,
    /// Security kernel — MAC, capabilities, sandboxing
    Security,
}

/// Memory Kernel — manages state and storage
#[derive(Debug)]
pub struct MemoryKernel {
    /// Kernel ID
    pub id: String,
    /// Version
    pub version: String,
    /// Configuration
    pub config: MemoryKernelConfig,
    /// Statistics
    pub stats: MemoryKernelStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryKernelConfig {
    /// Maximum memory per agent (bytes)
    pub max_agent_memory: u64,
    /// Cache size (bytes)
    pub cache_size: u64,
    /// Eviction policy
    pub eviction_policy: String,
    /// Compression enabled
    pub compression: bool,
    /// Write-ahead log enabled
    pub wal_enabled: bool,
}

impl Default for MemoryKernelConfig {
    fn default() -> Self {
        Self {
            max_agent_memory: 512 * 1024 * 1024,
            cache_size: 128 * 1024 * 1024,
            eviction_policy: "lru".into(),
            compression: true,
            wal_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryKernelStats {
    pub total_allocations: u64,
    pub total_deallocations: u64,
    pub bytes_allocated: u64,
    pub bytes_cached: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub evictions: u64,
}

impl MemoryKernel {
    pub fn new(config: MemoryKernelConfig) -> Self {
        Self {
            id: "memory-kernel".into(),
            version: "1.0.0".into(),
            config,
            stats: MemoryKernelStats::default(),
        }
    }
}

/// Execution Kernel — manages agent execution and scheduling
#[derive(Debug)]
pub struct ExecutionKernel {
    /// Kernel ID
    pub id: String,
    /// Version
    pub version: String,
    /// Configuration
    pub config: ExecutionKernelConfig,
    /// Statistics
    pub stats: ExecutionKernelStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionKernelConfig {
    /// Maximum concurrent agents
    pub max_agents: u32,
    /// Default time slice (ms)
    pub default_time_slice_ms: u64,
    /// Scheduler type
    pub scheduler: String,
    /// Preemption enabled
    pub preemption: bool,
    /// Syscall timeout (ms)
    pub syscall_timeout_ms: u64,
}

impl Default for ExecutionKernelConfig {
    fn default() -> Self {
        Self {
            max_agents: 1000,
            default_time_slice_ms: 100,
            scheduler: "cfs".into(),
            preemption: true,
            syscall_timeout_ms: 30000,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionKernelStats {
    pub agents_created: u64,
    pub agents_terminated: u64,
    pub syscalls_dispatched: u64,
    pub syscalls_completed: u64,
    pub syscalls_failed: u64,
    pub context_switches: u64,
    pub preemptions: u64,
}

impl ExecutionKernel {
    pub fn new(config: ExecutionKernelConfig) -> Self {
        Self {
            id: "execution-kernel".into(),
            version: "1.0.0".into(),
            config,
            stats: ExecutionKernelStats::default(),
        }
    }
}

/// Verification Kernel — manages proofs and attestations
#[derive(Debug)]
pub struct VerificationKernel {
    /// Kernel ID
    pub id: String,
    /// Version
    pub version: String,
    /// Configuration
    pub config: VerificationKernelConfig,
    /// Statistics
    pub stats: VerificationKernelStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationKernelConfig {
    /// Proof generation enabled
    pub proofs_enabled: bool,
    /// Attestation signing key ID
    pub signing_key_id: Option<String>,
    /// Verification strictness level
    pub strictness: String,
    /// SCITT ledger enabled
    pub scitt_enabled: bool,
    /// Merkle tree depth
    pub merkle_depth: u32,
}

impl Default for VerificationKernelConfig {
    fn default() -> Self {
        Self {
            proofs_enabled: true,
            signing_key_id: None,
            strictness: "standard".into(),
            scitt_enabled: false,
            merkle_depth: 32,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerificationKernelStats {
    pub proofs_generated: u64,
    pub proofs_verified: u64,
    pub proofs_failed: u64,
    pub attestations_signed: u64,
    pub attestations_verified: u64,
}

impl VerificationKernel {
    pub fn new(config: VerificationKernelConfig) -> Self {
        Self {
            id: "verification-kernel".into(),
            version: "1.0.0".into(),
            config,
            stats: VerificationKernelStats::default(),
        }
    }
}

/// Unified kernel interface
pub struct KernelManager {
    pub memory: MemoryKernel,
    pub execution: ExecutionKernel,
    pub verification: VerificationKernel,
    modules: HashMap<String, KernelModule>,
    sysctl: KernelSysctl,
}

impl KernelManager {
    pub fn new() -> Self {
        Self {
            memory: MemoryKernel::new(MemoryKernelConfig::default()),
            execution: ExecutionKernel::new(ExecutionKernelConfig::default()),
            verification: VerificationKernel::new(VerificationKernelConfig::default()),
            modules: HashMap::new(),
            sysctl: KernelSysctl::new(),
        }
    }

    pub fn with_configs(
        memory: MemoryKernelConfig,
        execution: ExecutionKernelConfig,
        verification: VerificationKernelConfig,
    ) -> Self {
        Self {
            memory: MemoryKernel::new(memory),
            execution: ExecutionKernel::new(execution),
            verification: VerificationKernel::new(verification),
            modules: HashMap::new(),
            sysctl: KernelSysctl::new(),
        }
    }

    pub fn load_module(&mut self, module: KernelModule) -> Result<(), String> {
        if self.modules.contains_key(&module.name) {
            return Err(format!("Module {} already loaded", module.name));
        }
        self.modules.insert(module.name.clone(), module);
        Ok(())
    }

    pub fn unload_module(&mut self, name: &str) -> Result<KernelModule, String> {
        self.modules.remove(name).ok_or_else(|| format!("Module {} not found", name))
    }

    pub fn get_module(&self, name: &str) -> Option<&KernelModule> {
        self.modules.get(name)
    }

    pub fn list_modules(&self) -> Vec<&KernelModule> {
        self.modules.values().collect()
    }

    pub fn sysctl(&self) -> &KernelSysctl {
        &self.sysctl
    }

    pub fn sysctl_mut(&mut self) -> &mut KernelSysctl {
        &mut self.sysctl
    }
}

impl Default for KernelManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Part 2: Kernel Modules
// =============================================================================

/// Module ID counter
static MODULE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Kernel module state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleState {
    /// Module is loaded but not initialized
    Loaded,
    /// Module is initializing
    Initializing,
    /// Module is running
    Running,
    /// Module is stopping
    Stopping,
    /// Module is stopped
    Stopped,
    /// Module encountered an error
    Error,
}

/// Kernel module type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleType {
    /// Core module (required)
    Core,
    /// Extension module (optional)
    Extension,
    /// Driver module (hardware/external)
    Driver,
    /// Protocol module (communication)
    Protocol,
    /// Security module
    Security,
}

/// Kernel module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelModule {
    /// Module ID
    pub id: u64,
    /// Module name
    pub name: String,
    /// Module version
    pub version: String,
    /// Module type
    pub module_type: ModuleType,
    /// Target subsystem
    pub subsystem: KernelSubsystem,
    /// Current state
    pub state: ModuleState,
    /// Dependencies (module names)
    pub dependencies: Vec<String>,
    /// Parameters
    pub params: HashMap<String, String>,
    /// Description
    pub description: String,
    /// Author
    pub author: Option<String>,
    /// License
    pub license: String,
    /// Loaded at (epoch ms)
    pub loaded_at: i64,
    /// Error message (if state is Error)
    pub error: Option<String>,
}

impl KernelModule {
    pub fn new(name: String, module_type: ModuleType, subsystem: KernelSubsystem) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            id: MODULE_ID_COUNTER.fetch_add(1, Ordering::SeqCst),
            name,
            version: "1.0.0".into(),
            module_type,
            subsystem,
            state: ModuleState::Loaded,
            dependencies: vec![],
            params: HashMap::new(),
            description: String::new(),
            author: None,
            license: "Apache-2.0".into(),
            loaded_at: now,
            error: None,
        }
    }

    pub fn with_version(mut self, version: &str) -> Self {
        self.version = version.into();
        self
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_dependency(mut self, dep: &str) -> Self {
        self.dependencies.push(dep.into());
        self
    }

    pub fn with_param(mut self, key: &str, value: &str) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }

    pub fn init(&mut self) -> Result<(), String> {
        if self.state != ModuleState::Loaded {
            return Err("Module not in Loaded state".into());
        }
        self.state = ModuleState::Initializing;
        // Initialization logic would go here
        self.state = ModuleState::Running;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), String> {
        if self.state != ModuleState::Running {
            return Err("Module not running".into());
        }
        self.state = ModuleState::Stopping;
        // Cleanup logic would go here
        self.state = ModuleState::Stopped;
        Ok(())
    }

    pub fn set_error(&mut self, error: &str) {
        self.state = ModuleState::Error;
        self.error = Some(error.into());
    }
}

/// Module registry
#[derive(Debug, Default)]
pub struct ModuleRegistry {
    modules: HashMap<String, KernelModule>,
    by_subsystem: HashMap<KernelSubsystem, Vec<String>>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, module: KernelModule) -> Result<(), String> {
        if self.modules.contains_key(&module.name) {
            return Err(format!("Module {} already registered", module.name));
        }

        // Check dependencies
        for dep in &module.dependencies {
            if !self.modules.contains_key(dep) {
                return Err(format!("Missing dependency: {}", dep));
            }
        }

        let name = module.name.clone();
        let subsystem = module.subsystem;
        
        self.modules.insert(name.clone(), module);
        self.by_subsystem.entry(subsystem).or_default().push(name);
        
        Ok(())
    }

    pub fn unregister(&mut self, name: &str) -> Result<KernelModule, String> {
        // Check if any module depends on this one
        for (mod_name, module) in &self.modules {
            if module.dependencies.contains(&name.to_string()) {
                return Err(format!("Module {} depends on {}", mod_name, name));
            }
        }

        let module = self.modules.remove(name)
            .ok_or_else(|| format!("Module {} not found", name))?;

        if let Some(mods) = self.by_subsystem.get_mut(&module.subsystem) {
            mods.retain(|n| n != name);
        }

        Ok(module)
    }

    pub fn get(&self, name: &str) -> Option<&KernelModule> {
        self.modules.get(name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut KernelModule> {
        self.modules.get_mut(name)
    }

    pub fn list(&self) -> Vec<&KernelModule> {
        self.modules.values().collect()
    }

    pub fn list_by_subsystem(&self, subsystem: KernelSubsystem) -> Vec<&KernelModule> {
        self.by_subsystem.get(&subsystem)
            .map(|names| names.iter().filter_map(|n| self.modules.get(n)).collect())
            .unwrap_or_default()
    }
}

// =============================================================================
// Part 3: Kernel Configuration (sysctl)
// =============================================================================

/// Sysctl value type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SysctlValue {
    Int(i64),
    Uint(u64),
    Bool(bool),
    String(String),
}

impl SysctlValue {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            Self::Uint(v) => Some(*v as i64),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Uint(v) => Some(*v),
            Self::Int(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            Self::Int(v) => Some(*v != 0),
            Self::Uint(v) => Some(*v != 0),
            _ => None,
        }
    }

    pub fn as_string(&self) -> String {
        match self {
            Self::Int(v) => v.to_string(),
            Self::Uint(v) => v.to_string(),
            Self::Bool(v) => v.to_string(),
            Self::String(v) => v.clone(),
        }
    }
}

/// Sysctl parameter definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysctlParam {
    /// Parameter path (e.g., "kernel.memory.max_cache")
    pub path: String,
    /// Current value
    pub value: SysctlValue,
    /// Default value
    pub default: SysctlValue,
    /// Description
    pub description: String,
    /// Read-only
    pub readonly: bool,
    /// Minimum value (for numeric)
    pub min: Option<i64>,
    /// Maximum value (for numeric)
    pub max: Option<i64>,
}

impl SysctlParam {
    pub fn new_int(path: &str, value: i64, description: &str) -> Self {
        Self {
            path: path.into(),
            value: SysctlValue::Int(value),
            default: SysctlValue::Int(value),
            description: description.into(),
            readonly: false,
            min: None,
            max: None,
        }
    }

    pub fn new_uint(path: &str, value: u64, description: &str) -> Self {
        Self {
            path: path.into(),
            value: SysctlValue::Uint(value),
            default: SysctlValue::Uint(value),
            description: description.into(),
            readonly: false,
            min: Some(0),
            max: None,
        }
    }

    pub fn new_bool(path: &str, value: bool, description: &str) -> Self {
        Self {
            path: path.into(),
            value: SysctlValue::Bool(value),
            default: SysctlValue::Bool(value),
            description: description.into(),
            readonly: false,
            min: None,
            max: None,
        }
    }

    pub fn new_string(path: &str, value: &str, description: &str) -> Self {
        Self {
            path: path.into(),
            value: SysctlValue::String(value.into()),
            default: SysctlValue::String(value.into()),
            description: description.into(),
            readonly: false,
            min: None,
            max: None,
        }
    }

    pub fn readonly(mut self) -> Self {
        self.readonly = true;
        self
    }

    pub fn with_range(mut self, min: i64, max: i64) -> Self {
        self.min = Some(min);
        self.max = Some(max);
        self
    }
}

/// Kernel sysctl — runtime configuration
#[derive(Debug)]
pub struct KernelSysctl {
    params: HashMap<String, SysctlParam>,
}

impl KernelSysctl {
    pub fn new() -> Self {
        let mut sysctl = Self { params: HashMap::new() };
        sysctl.register_defaults();
        sysctl
    }

    fn register_defaults(&mut self) {
        // Memory kernel parameters
        self.register(SysctlParam::new_uint(
            "kernel.memory.max_cache_size",
            128 * 1024 * 1024,
            "Maximum cache size in bytes",
        ));
        self.register(SysctlParam::new_uint(
            "kernel.memory.max_agent_memory",
            512 * 1024 * 1024,
            "Maximum memory per agent in bytes",
        ));
        self.register(SysctlParam::new_bool(
            "kernel.memory.compression",
            true,
            "Enable memory compression",
        ));
        self.register(SysctlParam::new_string(
            "kernel.memory.eviction_policy",
            "lru",
            "Cache eviction policy (lru, lfu, fifo)",
        ));

        // Execution kernel parameters
        self.register(SysctlParam::new_uint(
            "kernel.exec.max_agents",
            1000,
            "Maximum concurrent agents",
        ).with_range(1, 100000));
        self.register(SysctlParam::new_uint(
            "kernel.exec.time_slice_ms",
            100,
            "Default time slice in milliseconds",
        ).with_range(10, 10000));
        self.register(SysctlParam::new_bool(
            "kernel.exec.preemption",
            true,
            "Enable preemptive scheduling",
        ));
        self.register(SysctlParam::new_uint(
            "kernel.exec.syscall_timeout_ms",
            30000,
            "Syscall timeout in milliseconds",
        ));

        // Verification kernel parameters
        self.register(SysctlParam::new_bool(
            "kernel.verify.proofs_enabled",
            true,
            "Enable proof generation",
        ));
        self.register(SysctlParam::new_bool(
            "kernel.verify.scitt_enabled",
            false,
            "Enable SCITT ledger",
        ));
        self.register(SysctlParam::new_string(
            "kernel.verify.strictness",
            "standard",
            "Verification strictness (relaxed, standard, strict)",
        ));

        // Security parameters
        self.register(SysctlParam::new_bool(
            "kernel.security.mac_enforcing",
            true,
            "Enforce Mandatory Access Control",
        ));
        self.register(SysctlParam::new_bool(
            "kernel.security.sandbox_enabled",
            true,
            "Enable sandbox enforcement",
        ));
        self.register(SysctlParam::new_uint(
            "kernel.security.max_capability_depth",
            3,
            "Maximum capability delegation depth",
        ).with_range(1, 10));

        // Network parameters
        self.register(SysctlParam::new_uint(
            "kernel.net.max_connections",
            10000,
            "Maximum network connections",
        ));
        self.register(SysctlParam::new_uint(
            "kernel.net.port_buffer_size",
            65536,
            "Port buffer size in bytes",
        ));
        self.register(SysctlParam::new_bool(
            "kernel.net.cross_cell_enabled",
            true,
            "Enable cross-cell communication",
        ));

        // Debug parameters
        self.register(SysctlParam::new_bool(
            "kernel.debug.trace_syscalls",
            false,
            "Trace all syscalls",
        ));
        self.register(SysctlParam::new_bool(
            "kernel.debug.audit_enabled",
            true,
            "Enable audit logging",
        ));
        self.register(SysctlParam::new_uint(
            "kernel.debug.log_level",
            2,
            "Log level (0=error, 1=warn, 2=info, 3=debug, 4=trace)",
        ).with_range(0, 4));
    }

    pub fn register(&mut self, param: SysctlParam) {
        self.params.insert(param.path.clone(), param);
    }

    pub fn get(&self, path: &str) -> Option<&SysctlParam> {
        self.params.get(path)
    }

    pub fn get_value(&self, path: &str) -> Option<&SysctlValue> {
        self.params.get(path).map(|p| &p.value)
    }

    pub fn set(&mut self, path: &str, value: SysctlValue) -> Result<(), String> {
        let param = self.params.get_mut(path)
            .ok_or_else(|| format!("Unknown parameter: {}", path))?;

        if param.readonly {
            return Err(format!("Parameter {} is read-only", path));
        }

        // Validate range for numeric values
        if let (Some(min), Some(max)) = (param.min, param.max) {
            if let Some(v) = value.as_int() {
                if v < min || v > max {
                    return Err(format!("Value {} out of range [{}, {}]", v, min, max));
                }
            }
        }

        param.value = value;
        Ok(())
    }

    pub fn reset(&mut self, path: &str) -> Result<(), String> {
        let param = self.params.get_mut(path)
            .ok_or_else(|| format!("Unknown parameter: {}", path))?;

        if param.readonly {
            return Err(format!("Parameter {} is read-only", path));
        }

        param.value = param.default.clone();
        Ok(())
    }

    pub fn list(&self) -> Vec<&SysctlParam> {
        let mut params: Vec<_> = self.params.values().collect();
        params.sort_by_key(|p| &p.path);
        params
    }

    pub fn list_by_prefix(&self, prefix: &str) -> Vec<&SysctlParam> {
        let mut params: Vec<_> = self.params.values()
            .filter(|p| p.path.starts_with(prefix))
            .collect();
        params.sort_by_key(|p| &p.path);
        params
    }

    /// Format as /proc/sys style output
    pub fn to_proc_sys(&self) -> String {
        let mut out = String::new();
        for param in self.list() {
            out.push_str(&format!("{} = {}\n", param.path, param.value.as_string()));
        }
        out
    }
}

impl Default for KernelSysctl {
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

    #[test]
    fn test_kernel_manager() {
        let manager = KernelManager::new();
        assert_eq!(manager.memory.id, "memory-kernel");
        assert_eq!(manager.execution.id, "execution-kernel");
        assert_eq!(manager.verification.id, "verification-kernel");
    }

    #[test]
    fn test_kernel_module() {
        let mut module = KernelModule::new(
            "test-module".into(),
            ModuleType::Extension,
            KernelSubsystem::Memory,
        )
        .with_version("1.2.3")
        .with_description("Test module");

        assert_eq!(module.state, ModuleState::Loaded);
        
        module.init().unwrap();
        assert_eq!(module.state, ModuleState::Running);
        
        module.stop().unwrap();
        assert_eq!(module.state, ModuleState::Stopped);
    }

    #[test]
    fn test_module_registry() {
        let mut registry = ModuleRegistry::new();

        let module1 = KernelModule::new("mod1".into(), ModuleType::Core, KernelSubsystem::Memory);
        let module2 = KernelModule::new("mod2".into(), ModuleType::Extension, KernelSubsystem::Memory)
            .with_dependency("mod1");

        registry.register(module1).unwrap();
        registry.register(module2).unwrap();

        assert_eq!(registry.list().len(), 2);
        assert_eq!(registry.list_by_subsystem(KernelSubsystem::Memory).len(), 2);

        // Can't unregister mod1 because mod2 depends on it
        assert!(registry.unregister("mod1").is_err());
        
        // Can unregister mod2
        registry.unregister("mod2").unwrap();
        registry.unregister("mod1").unwrap();
    }

    #[test]
    fn test_sysctl() {
        let mut sysctl = KernelSysctl::new();

        // Get default value
        let val = sysctl.get_value("kernel.exec.max_agents").unwrap();
        assert_eq!(val.as_uint(), Some(1000));

        // Set new value
        sysctl.set("kernel.exec.max_agents", SysctlValue::Uint(2000)).unwrap();
        let val = sysctl.get_value("kernel.exec.max_agents").unwrap();
        assert_eq!(val.as_uint(), Some(2000));

        // Reset to default
        sysctl.reset("kernel.exec.max_agents").unwrap();
        let val = sysctl.get_value("kernel.exec.max_agents").unwrap();
        assert_eq!(val.as_uint(), Some(1000));
    }

    #[test]
    fn test_sysctl_range_validation() {
        let mut sysctl = KernelSysctl::new();

        // Valid range
        sysctl.set("kernel.debug.log_level", SysctlValue::Uint(4)).unwrap();

        // Out of range
        let result = sysctl.set("kernel.debug.log_level", SysctlValue::Uint(10));
        assert!(result.is_err());
    }

    #[test]
    fn test_sysctl_list_by_prefix() {
        let sysctl = KernelSysctl::new();
        
        let memory_params = sysctl.list_by_prefix("kernel.memory");
        assert!(memory_params.len() >= 3);
        
        let exec_params = sysctl.list_by_prefix("kernel.exec");
        assert!(exec_params.len() >= 3);
    }
}
