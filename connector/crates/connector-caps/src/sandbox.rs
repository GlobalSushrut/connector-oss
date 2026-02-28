//! Sandbox configuration — maps to real Linux kernel primitives.
//!
//! Defines filesystem, network, resource, and device isolation boundaries.

use serde::{Deserialize, Serialize};

/// Sandbox configuration for runner execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
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
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
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
        }
    }
}

impl SandboxConfig {
    /// Fully unrestricted sandbox (for testing).
    pub fn unrestricted() -> Self {
        Self {
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
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_default() {
        let s = SandboxConfig::default();
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
}
