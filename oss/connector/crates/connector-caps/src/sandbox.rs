//! Sandbox configuration — maps to real Linux kernel primitives.
//!
//! Defines filesystem, network, resource, and device isolation boundaries.

use serde::{Deserialize, Serialize};

use crate::error::{CapsError, CapsResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SandboxBackendKind {
    #[default]
    Native,
    Nsjail,
}

impl SandboxBackendKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Nsjail => "nsjail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsjailConfig {
    pub binary_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

impl Default for NsjailConfig {
    fn default() -> Self {
        Self {
            binary_path: "nsjail".to_string(),
            config_path: None,
            profile: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxExecutionPlan {
    pub backend: SandboxBackendKind,
    pub isolation_profile: String,
    pub runtime_hints: Vec<String>,
}

pub trait SandboxBackend: Send + Sync {
    fn kind(&self) -> SandboxBackendKind;
    fn validate(&self, sandbox: &SandboxConfig) -> CapsResult<()>;
    fn execution_plan(&self, sandbox: &SandboxConfig, capability_id: &str) -> CapsResult<SandboxExecutionPlan>;
}

#[derive(Debug, Default)]
pub struct NativeSandboxBackend;

#[derive(Debug, Default)]
pub struct NsjailSandboxBackend;

/// Sandbox configuration for runner execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    #[serde(default)]
    pub backend: SandboxBackendKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsjail: Option<NsjailConfig>,
    /// Allowed filesystem paths (glob patterns)
    pub allowed_paths: Vec<String>,
    /// Bind mount specifications (host_path:container_path)
    pub bind_mounts: Vec<String>,
    /// Allowed network domains (empty = unrestricted)
    pub allowed_domains: Vec<String>,
    /// Whether network is completely disabled
    pub network_disabled: bool,
    /// Max memory in bytes (maps to cgroup memory.max)
    pub max_memory_bytes: Option<u64>,
    /// Max CPU percentage (maps to cgroup cpu.max)
    pub max_cpu_percent: Option<u32>,
    /// Max execution duration in ms (timer + SIGKILL)
    pub max_duration_ms: Option<u64>,
    /// Max number of processes (maps to cgroup pids.max)
    pub max_pids: Option<u32>,
    /// Max I/O bytes (maps to cgroup io.max)
    pub max_io_bytes: Option<u64>,
    /// Device allowlist for hardware runners
    pub device_allowlist: Vec<String>,
    /// Max GPU VRAM in bytes
    pub max_vram_bytes: Option<u64>,
    /// Max GPU compute duration in ms
    pub max_gpu_duration_ms: Option<u64>,
    /// Tenant org_id — memory namespace access is restricted to `org/{org_id}/*` prefixes.
    /// When `Some`, `is_namespace_allowed()` blocks cross-org namespace access.
    /// When `None`, no tenant isolation is enforced (single-tenant / test mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_org_id: Option<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            backend: SandboxBackendKind::Native,
            nsjail: None,
            allowed_paths: vec![],
            bind_mounts: vec![],
            allowed_domains: vec![],
            network_disabled: false,
            max_memory_bytes: Some(256 * 1024 * 1024), // 256 MB
            max_cpu_percent: Some(50),
            max_duration_ms: Some(30_000), // 30 seconds
            max_pids: Some(100),
            max_io_bytes: None,
            device_allowlist: vec![],
            max_vram_bytes: None,
            max_gpu_duration_ms: None,
            tenant_org_id: None,
        }
    }
}

impl SandboxConfig {
    /// Fully unrestricted sandbox (for testing).
    pub fn unrestricted() -> Self {
        Self {
            backend: SandboxBackendKind::Native,
            nsjail: None,
            allowed_paths: vec![],
            bind_mounts: vec![],
            allowed_domains: vec![],
            network_disabled: false,
            max_memory_bytes: None,
            max_cpu_percent: None,
            max_duration_ms: None,
            max_pids: None,
            max_io_bytes: None,
            device_allowlist: vec![],
            max_vram_bytes: None,
            max_gpu_duration_ms: None,
            tenant_org_id: None,
        }
    }

    /// Construct a tenant-scoped sandbox locked to a specific `org_id`.
    ///
    /// All namespace access checks via `is_namespace_allowed()` will reject
    /// any namespace that does not match `org/{org_id}/*`.
    pub fn for_tenant(org_id: impl Into<String>) -> Self {
        Self {
            tenant_org_id: Some(org_id.into()),
            ..Self::default()
        }
    }

    /// Check if a memory namespace is accessible by this sandbox's tenant.
    ///
    /// Rules:
    /// - If `tenant_org_id` is `None`: all namespaces are allowed (single-tenant/test mode).
    /// - If `tenant_org_id` is `Some(org)`: the namespace must start with `org/{org}/` or
    ///   equal `org/{org}`. Namespaces belonging to any other org are **denied**.
    ///
    /// ```
    /// # use connector_caps::sandbox::SandboxConfig;
    /// let s = SandboxConfig::for_tenant("acme");
    /// assert!(s.is_namespace_allowed("org/acme/memory"));
    /// assert!(!s.is_namespace_allowed("org/rival/memory"));
    /// assert!(!s.is_namespace_allowed("global"));
    /// ```
    pub fn is_namespace_allowed(&self, namespace: &str) -> bool {
        let Some(org_id) = &self.tenant_org_id else {
            return true; // no tenant scoping
        };
        let expected_prefix = format!("org/{}/", org_id);
        let expected_exact  = format!("org/{}",  org_id);
        namespace.starts_with(&expected_prefix) || namespace == expected_exact
    }

    /// Check if a path is allowed by this sandbox.
    pub fn is_path_allowed(&self, path: &str) -> bool {
        if self.allowed_paths.is_empty() {
            return true; // no restrictions
        }
        self.allowed_paths.iter().any(|p| {
            if p.ends_with('*') {
                path.starts_with(&p[..p.len() - 1])
            } else {
                path == p
            }
        })
    }

    /// Check if a domain is allowed by this sandbox.
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        if self.network_disabled {
            return false;
        }
        if self.allowed_domains.is_empty() {
            return true;
        }
        self.allowed_domains.iter().any(|d| domain.contains(d))
    }

    /// Check if a device is in the allowlist.
    pub fn is_device_allowed(&self, device_id: &str) -> bool {
        if self.device_allowlist.is_empty() {
            return false; // no devices allowed by default
        }
        self.device_allowlist.contains(&device_id.to_string())
    }

    pub fn execution_plan(&self, capability_id: &str) -> CapsResult<SandboxExecutionPlan> {
        match self.backend {
            SandboxBackendKind::Native => NativeSandboxBackend.execution_plan(self, capability_id),
            SandboxBackendKind::Nsjail => NsjailSandboxBackend.execution_plan(self, capability_id),
        }
    }
}

impl SandboxBackend for NativeSandboxBackend {
    fn kind(&self) -> SandboxBackendKind {
        SandboxBackendKind::Native
    }

    fn validate(&self, _sandbox: &SandboxConfig) -> CapsResult<()> {
        Ok(())
    }

    fn execution_plan(&self, sandbox: &SandboxConfig, capability_id: &str) -> CapsResult<SandboxExecutionPlan> {
        Ok(SandboxExecutionPlan {
            backend: self.kind(),
            isolation_profile: format!("native:{}", capability_id),
            runtime_hints: sandbox_runtime_hints(sandbox),
        })
    }
}

impl SandboxBackend for NsjailSandboxBackend {
    fn kind(&self) -> SandboxBackendKind {
        SandboxBackendKind::Nsjail
    }

    fn validate(&self, sandbox: &SandboxConfig) -> CapsResult<()> {
        let cfg = sandbox.nsjail.clone().unwrap_or_default();
        if cfg.binary_path.trim().is_empty() {
            return Err(CapsError::RunnerError("nsjail backend requires a non-empty binary_path".to_string()));
        }
        Ok(())
    }

    fn execution_plan(&self, sandbox: &SandboxConfig, capability_id: &str) -> CapsResult<SandboxExecutionPlan> {
        self.validate(sandbox)?;
        let cfg = sandbox.nsjail.clone().unwrap_or_default();
        let mut runtime_hints = sandbox_runtime_hints(sandbox);
        runtime_hints.push(format!("nsjail_binary:{}", cfg.binary_path));
        if let Some(config_path) = cfg.config_path {
            runtime_hints.push(format!("nsjail_config:{}", config_path));
        }
        if let Some(profile) = cfg.profile {
            runtime_hints.push(format!("nsjail_profile:{}", profile));
        }
        Ok(SandboxExecutionPlan {
            backend: self.kind(),
            isolation_profile: format!("nsjail:{}", capability_id),
            runtime_hints,
        })
    }
}

fn sandbox_runtime_hints(sandbox: &SandboxConfig) -> Vec<String> {
    let mut hints = Vec::new();
    if sandbox.network_disabled {
        hints.push("network:disabled".to_string());
    }
    if !sandbox.allowed_domains.is_empty() {
        hints.push(format!("domains:{}", sandbox.allowed_domains.join(",")));
    }
    if !sandbox.allowed_paths.is_empty() {
        hints.push(format!("paths:{}", sandbox.allowed_paths.join(",")));
    }
    if let Some(max_memory_bytes) = sandbox.max_memory_bytes {
        hints.push(format!("memory:{}", max_memory_bytes));
    }
    if let Some(max_cpu_percent) = sandbox.max_cpu_percent {
        hints.push(format!("cpu:{}", max_cpu_percent));
    }
    if let Some(max_duration_ms) = sandbox.max_duration_ms {
        hints.push(format!("duration:{}", max_duration_ms));
    }
    hints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_default() {
        let s = SandboxConfig::default();
        assert_eq!(s.backend, SandboxBackendKind::Native);
        assert_eq!(s.max_memory_bytes, Some(256 * 1024 * 1024));
        assert_eq!(s.max_duration_ms, Some(30_000));
        assert!(!s.network_disabled);
    }

    #[test]
    fn test_sandbox_path_check() {
        let s = SandboxConfig {
            allowed_paths: vec!["/tmp/*".into(), "/var/data/file.txt".into()],
            ..SandboxConfig::default()
        };
        assert!(s.is_path_allowed("/tmp/test.txt"));
        assert!(s.is_path_allowed("/tmp/subdir/file"));
        assert!(s.is_path_allowed("/var/data/file.txt"));
        assert!(!s.is_path_allowed("/etc/passwd"));
    }

    #[test]
    fn test_sandbox_domain_check() {
        let s = SandboxConfig {
            allowed_domains: vec!["api.example.com".into()],
            ..SandboxConfig::default()
        };
        assert!(s.is_domain_allowed("api.example.com"));
        assert!(!s.is_domain_allowed("evil.com"));
    }

    #[test]
    fn test_sandbox_network_disabled() {
        let s = SandboxConfig {
            network_disabled: true,
            ..SandboxConfig::default()
        };
        assert!(!s.is_domain_allowed("api.example.com"));
    }

    #[test]
    fn test_sandbox_device_allowlist() {
        let s = SandboxConfig {
            device_allowlist: vec!["gpio-1".into(), "serial-0".into()],
            ..SandboxConfig::default()
        };
        assert!(s.is_device_allowed("gpio-1"));
        assert!(!s.is_device_allowed("gpio-2"));
        assert!(!SandboxConfig::default().is_device_allowed("gpio-1"));
    }

    #[test]
    fn test_tenant_isolation_allows_own_org() {
        let s = SandboxConfig::for_tenant("acme");
        assert!(s.is_namespace_allowed("org/acme/memory"));
        assert!(s.is_namespace_allowed("org/acme/sessions"));
        assert!(s.is_namespace_allowed("org/acme"));
    }

    #[test]
    fn test_tenant_isolation_blocks_other_org() {
        let s = SandboxConfig::for_tenant("acme");
        assert!(!s.is_namespace_allowed("org/rival/memory"));
        assert!(!s.is_namespace_allowed("org/rival"));
        assert!(!s.is_namespace_allowed("global"));
        assert!(!s.is_namespace_allowed(""));
    }

    #[test]
    fn test_tenant_isolation_no_org_id_allows_all() {
        let s = SandboxConfig::default();
        assert!(s.tenant_org_id.is_none());
        assert!(s.is_namespace_allowed("org/acme/memory"));
        assert!(s.is_namespace_allowed("org/rival/memory"));
        assert!(s.is_namespace_allowed("global"));
    }

    #[test]
    fn test_tenant_isolation_prefix_not_substring() {
        let s = SandboxConfig::for_tenant("acme");
        assert!(!s.is_namespace_allowed("org/acme-evil/memory"),
            "org/acme-evil should not match org/acme prefix");
    }

    #[test]
    fn test_nsjail_backend_execution_plan() {
        let s = SandboxConfig {
            backend: SandboxBackendKind::Nsjail,
            nsjail: Some(NsjailConfig {
                binary_path: "/usr/bin/nsjail".into(),
                config_path: Some("/etc/nsjail.cfg".into()),
                profile: Some("strict".into()),
            }),
            allowed_domains: vec!["api.example.com".into()],
            ..SandboxConfig::default()
        };
        let plan = s.execution_plan("net.http_get").unwrap();
        assert_eq!(plan.backend, SandboxBackendKind::Nsjail);
        assert!(plan.runtime_hints.iter().any(|hint| hint == "nsjail_binary:/usr/bin/nsjail"));
        assert!(plan.runtime_hints.iter().any(|hint| hint == "nsjail_config:/etc/nsjail.cfg"));
        assert!(plan.runtime_hints.iter().any(|hint| hint == "nsjail_profile:strict"));
    }
}
