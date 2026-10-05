//! Compile sandbox egress intent for host projection (nft/eBPF allowlists).
//!
//! DNS resolution happens outside this module at apply time; here we only normalize
//! hostnames and carry flags for checklist §10.6 unit coverage.

use crate::sandbox::SandboxConfig;

/// Normalized egress contract derived from [`SandboxConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledEgressSpec {
    /// Caller-supplied monotonic revision (e.g. from `KernelHostState` policy_revision).
    pub revision: u64,
    pub network_disabled: bool,
    /// Lowercased, trimmed, sorted unique hostnames from `allowed_domains`.
    pub normalized_hostnames: Vec<String>,
}

/// Build a deterministic egress spec for host policy compilers (`connector-kerneld`).
pub fn compile_sandbox_egress(config: &SandboxConfig, revision: u64) -> CompiledEgressSpec {
    let mut hosts: Vec<String> = config
        .allowed_domains
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    hosts.sort();
    hosts.dedup();
    CompiledEgressSpec {
        revision,
        network_disabled: config.network_disabled,
        normalized_hostnames: hosts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxConfig;

    #[test]
    fn sorts_dedups_hostnames() {
        let mut c = SandboxConfig::default();
        c.allowed_domains = vec![
            "API.OpenAI.com".into(),
            "api.openai.com".into(),
            " Anthropic.com ".into(),
        ];
        let spec = compile_sandbox_egress(&c, 7);
        assert_eq!(spec.revision, 7);
        assert_eq!(
            spec.normalized_hostnames,
            vec!["anthropic.com".to_string(), "api.openai.com".to_string()]
        );
    }

    #[test]
    fn network_disabled_flag_preserved() {
        let mut c = SandboxConfig::default();
        c.network_disabled = true;
        let spec = compile_sandbox_egress(&c, 1);
        assert!(spec.network_disabled);
        assert!(spec.normalized_hostnames.is_empty());
    }
}
