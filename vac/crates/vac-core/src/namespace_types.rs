//! Namespace Type Taxonomy & Filesystem Hierarchy — Linux-like namespace isolation for agents.
//!
//! Every namespace path MUST begin with a type prefix that determines default security policy.
//! Modeled on Linux mount namespaces + cgroup hierarchy.
//!
//! Research: OWASP Agentic ASI03/ASI06, NIST SP 800-207 Zero Trust,
//! NVIDIA Agentic Sandboxing (2026), Linux namespace/cgroup isolation.
//!
//! Type prefixes:
//!   /m/ — Memory (private agent data, owner RW)
//!   /k/ — Knowledge (shared knowledge bases, read-many)
//!   /a/ — Agent (control plane, owner-only)
//!   /t/ — Tool (tool I/O, execute-scoped)
//!   /s/ — System (kernel-reserved, kernel-only write)
//!   /p/ — Public (read-all)

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
// Security Level — BLP + Biba lattice (integer, no floats)
// ═══════════════════════════════════════════════════════════════

/// Security clearance level for the Bell-LaPadula + Biba lattice model.
/// Integer-based — no floating-point ambiguity. Higher = more restricted.
///
/// Research: Bell-LaPadula (DoD, 1973), Biba Integrity Model (1977)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SecurityLevel {
    /// Level 0: Public — readable by any agent
    Public    = 0,
    /// Level 1: Tool I/O — ephemeral tool input/output
    ToolIO    = 1,
    /// Level 2: Standard — agent working memory (default for most agents)
    Standard  = 2,
    /// Level 3: Protected — knowledge bases, integrity-critical
    Protected = 3,
    /// Level 4: Control — agent control plane, owner-only
    Control   = 4,
    /// Level 5: Kernel — system/kernel namespace, kernel-only write
    Kernel    = 5,
}

impl SecurityLevel {
    /// Numeric value for comparison (avoids float entirely).
    pub fn level(&self) -> u8 {
        *self as u8
    }
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityLevel::Public    => write!(f, "PUBLIC(0)"),
            SecurityLevel::ToolIO    => write!(f, "TOOL_IO(1)"),
            SecurityLevel::Standard  => write!(f, "STANDARD(2)"),
            SecurityLevel::Protected => write!(f, "PROTECTED(3)"),
            SecurityLevel::Control   => write!(f, "CONTROL(4)"),
            SecurityLevel::Kernel    => write!(f, "KERNEL(5)"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Namespace Type
// ═══════════════════════════════════════════════════════════════

/// Type of a namespace, derived from its path prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceType {
    /// /m/ — Private agent memory (scratch, long-term, context)
    Memory,
    /// /k/ — Knowledge bases (RAG, facts, embeddings)
    Knowledge,
    /// /a/ — Agent control plane (ACB, signals, checkpoints)
    Agent,
    /// /t/ — Tool I/O (input, output, audit)
    Tool,
    /// /s/ — System/kernel (audit, compute, firewall, health)
    System,
    /// /p/ — Public (announcements, directory)
    Public,
}

impl NamespaceType {
    /// Parse namespace type from path prefix. Returns None for invalid/missing prefix.
    pub fn from_path(path: &str) -> Option<Self> {
        let trimmed = path.trim_start_matches('/');
        if trimmed.starts_with("m/") || trimmed == "m" {
            Some(NamespaceType::Memory)
        } else if trimmed.starts_with("k/") || trimmed == "k" {
            Some(NamespaceType::Knowledge)
        } else if trimmed.starts_with("a/") || trimmed == "a" {
            Some(NamespaceType::Agent)
        } else if trimmed.starts_with("t/") || trimmed == "t" {
            Some(NamespaceType::Tool)
        } else if trimmed.starts_with("s/") || trimmed == "s" {
            Some(NamespaceType::System)
        } else if trimmed.starts_with("p/") || trimmed == "p" {
            Some(NamespaceType::Public)
        } else {
            None
        }
    }

    /// Single-letter prefix for this type.
    pub fn prefix(&self) -> &'static str {
        match self {
            NamespaceType::Memory    => "m",
            NamespaceType::Knowledge => "k",
            NamespaceType::Agent     => "a",
            NamespaceType::Tool      => "t",
            NamespaceType::System    => "s",
            NamespaceType::Public    => "p",
        }
    }

    /// Map namespace type to BLP/Biba security level.
    pub fn security_level(&self) -> SecurityLevel {
        match self {
            NamespaceType::Public    => SecurityLevel::Public,
            NamespaceType::Tool      => SecurityLevel::ToolIO,
            NamespaceType::Memory    => SecurityLevel::Standard,
            NamespaceType::Knowledge => SecurityLevel::Protected,
            NamespaceType::Agent     => SecurityLevel::Control,
            NamespaceType::System    => SecurityLevel::Kernel,
        }
    }

    /// Get the default ACL for this namespace type.
    pub fn default_acl(&self) -> NamespaceAcl {
        match self {
            NamespaceType::Memory => NamespaceAcl {
                owner_read: true, owner_write: true,
                others_read: false, others_write: false,
                kernel_only_write: false,
                description: "Private agent memory - owner read/write only",
            },
            NamespaceType::Knowledge => NamespaceAcl {
                owner_read: true, owner_write: true,
                others_read: true, others_write: false,
                kernel_only_write: false,
                description: "Knowledge base - read-many, write restricted",
            },
            NamespaceType::Agent => NamespaceAcl {
                owner_read: true, owner_write: true,
                others_read: false, others_write: false,
                kernel_only_write: false,
                description: "Agent control plane - owner-only",
            },
            NamespaceType::Tool => NamespaceAcl {
                owner_read: true, owner_write: true,
                others_read: false, others_write: false,
                kernel_only_write: false,
                description: "Tool I/O - execute-scoped access",
            },
            NamespaceType::System => NamespaceAcl {
                owner_read: true, owner_write: false,
                others_read: false, others_write: false,
                kernel_only_write: true,
                description: "System/kernel - kernel-only write, restricted read",
            },
            NamespaceType::Public => NamespaceAcl {
                owner_read: true, owner_write: true,
                others_read: true, others_write: false,
                kernel_only_write: false,
                description: "Public - read-all, admin-write",
            },
        }
    }
}

impl std::fmt::Display for NamespaceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "/{}/", self.prefix())
    }
}

// ═══════════════════════════════════════════════════════════════
// Namespace ACL
// ═══════════════════════════════════════════════════════════════

/// Default access control list for a namespace type.
#[derive(Debug, Clone)]
pub struct NamespaceAcl {
    pub owner_read: bool,
    pub owner_write: bool,
    pub others_read: bool,
    pub others_write: bool,
    /// If true, only the kernel can write (agents cannot, even the owner).
    pub kernel_only_write: bool,
    pub description: &'static str,
}

impl NamespaceAcl {
    /// Check if an agent has read access under this ACL.
    pub fn can_read(&self, is_owner: bool) -> bool {
        if is_owner { self.owner_read } else { self.others_read }
    }

    /// Check if an agent has write access under this ACL.
    pub fn can_write(&self, is_owner: bool, is_kernel: bool) -> bool {
        if self.kernel_only_write {
            return is_kernel;
        }
        if is_owner { self.owner_write } else { self.others_write }
    }
}

// ═══════════════════════════════════════════════════════════════
// Namespace Validator
// ═══════════════════════════════════════════════════════════════

/// Result of validating a namespace path.
#[derive(Debug, Clone)]
pub struct ValidatedNamespace {
    pub path: String,
    pub ns_type: NamespaceType,
    pub security_level: SecurityLevel,
    pub was_migrated: bool,
}

/// Validates and normalizes namespace paths with type-awareness.
pub struct NamespaceValidator;

impl NamespaceValidator {
    /// Validate a namespace path: must have valid type prefix, no traversal, no null bytes.
    /// Automatically migrates legacy `ns:X` and `sys:X` prefixes.
    pub fn validate(path: &str) -> Result<ValidatedNamespace, String> {
        if path.is_empty() {
            return Err("Empty namespace path".into());
        }
        if path.contains('\0') {
            return Err("Namespace path contains null byte".into());
        }

        // Check for legacy prefix and migrate
        let (effective_path, was_migrated) = Self::migrate_legacy(path);

        // Normalize: collapse //, strip trailing /, reject ..
        let segments: Vec<&str> = effective_path.split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect();

        for seg in &segments {
            if *seg == ".." {
                return Err(format!("Path traversal '..' rejected in namespace: {}", path));
            }
        }

        if segments.is_empty() {
            return Err("Namespace path resolves to empty after normalization".into());
        }

        let normalized = segments.join("/");

        // Parse type prefix
        let ns_type = NamespaceType::from_path(&normalized)
            .ok_or_else(|| format!(
                "Invalid namespace type prefix in '{}'. Must start with m/, k/, a/, t/, s/, or p/",
                normalized
            ))?;

        Ok(ValidatedNamespace {
            path: normalized,
            ns_type,
            security_level: ns_type.security_level(),
            was_migrated,
        })
    }

    /// Migrate legacy namespace prefixes to new type-prefixed paths.
    fn migrate_legacy(path: &str) -> (String, bool) {
        // sys:compute:cgroups → s/compute/cgroups
        if path.starts_with("sys:") {
            let rest = &path[4..];
            let converted = rest.replace(':', "/");
            return (format!("s/{}", converted), true);
        }
        // ns:shared → m/shared
        if path.starts_with("ns:") {
            let rest = &path[3..];
            let converted = rest.replace(':', "/");
            return (format!("m/{}", converted), true);
        }
        (path.to_string(), false)
    }

    /// Check if `child` namespace is a descendant of `parent` namespace.
    pub fn is_descendant(parent: &str, child: &str) -> bool {
        child == parent || child.starts_with(&format!("{}/", parent))
    }

    /// Extract owner agent_pid from a namespace path if it follows the convention
    /// `/m/{agent_pid}/...` or `/a/{agent_pid}/...`
    pub fn extract_owner(path: &str) -> Option<String> {
        let trimmed = path.trim_start_matches('/');
        let segments: Vec<&str> = trimmed.split('/').collect();
        if segments.len() >= 2 {
            let prefix = segments[0];
            if prefix == "m" || prefix == "a" {
                return Some(segments[1].to_string());
            }
        }
        None
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_type_from_path() {
        assert_eq!(NamespaceType::from_path("m/agent1/scratch"), Some(NamespaceType::Memory));
        assert_eq!(NamespaceType::from_path("/m/agent1/scratch"), Some(NamespaceType::Memory));
        assert_eq!(NamespaceType::from_path("k/medical/facts"), Some(NamespaceType::Knowledge));
        assert_eq!(NamespaceType::from_path("a/agent1/acb"), Some(NamespaceType::Agent));
        assert_eq!(NamespaceType::from_path("t/web_search/output"), Some(NamespaceType::Tool));
        assert_eq!(NamespaceType::from_path("s/audit/log"), Some(NamespaceType::System));
        assert_eq!(NamespaceType::from_path("p/announcements"), Some(NamespaceType::Public));
        assert_eq!(NamespaceType::from_path("invalid/path"), None);
        assert_eq!(NamespaceType::from_path(""), None);
        assert_eq!(NamespaceType::from_path("m"), Some(NamespaceType::Memory));
    }

    #[test]
    fn test_security_level_mapping() {
        assert_eq!(NamespaceType::Public.security_level(), SecurityLevel::Public);
        assert_eq!(NamespaceType::Tool.security_level(), SecurityLevel::ToolIO);
        assert_eq!(NamespaceType::Memory.security_level(), SecurityLevel::Standard);
        assert_eq!(NamespaceType::Knowledge.security_level(), SecurityLevel::Protected);
        assert_eq!(NamespaceType::Agent.security_level(), SecurityLevel::Control);
        assert_eq!(NamespaceType::System.security_level(), SecurityLevel::Kernel);
    }

    #[test]
    fn test_security_level_ordering() {
        assert!(SecurityLevel::Public < SecurityLevel::ToolIO);
        assert!(SecurityLevel::ToolIO < SecurityLevel::Standard);
        assert!(SecurityLevel::Standard < SecurityLevel::Protected);
        assert!(SecurityLevel::Protected < SecurityLevel::Control);
        assert!(SecurityLevel::Control < SecurityLevel::Kernel);
        assert_eq!(SecurityLevel::Public.level(), 0);
        assert_eq!(SecurityLevel::Kernel.level(), 5);
    }

    #[test]
    fn test_default_acl_memory() {
        let acl = NamespaceType::Memory.default_acl();
        assert!(acl.can_read(true));
        assert!(!acl.can_read(false));
        assert!(acl.can_write(true, false));
        assert!(!acl.can_write(false, false));
        assert!(!acl.kernel_only_write);
    }

    #[test]
    fn test_default_acl_knowledge() {
        let acl = NamespaceType::Knowledge.default_acl();
        assert!(acl.can_read(true));
        assert!(acl.can_read(false)); // others CAN read knowledge
        assert!(acl.can_write(true, false));
        assert!(!acl.can_write(false, false)); // others CANNOT write
    }

    #[test]
    fn test_default_acl_system_kernel_only() {
        let acl = NamespaceType::System.default_acl();
        assert!(acl.kernel_only_write);
        assert!(!acl.can_write(true, false));  // even owner cannot write
        assert!(!acl.can_write(false, false)); // others cannot write
        assert!(acl.can_write(true, true));    // kernel CAN write
        assert!(acl.can_write(false, true));   // kernel CAN write (regardless of ownership)
    }

    #[test]
    fn test_default_acl_public() {
        let acl = NamespaceType::Public.default_acl();
        assert!(acl.can_read(true));
        assert!(acl.can_read(false));  // everyone can read
        assert!(acl.can_write(true, false));
        assert!(!acl.can_write(false, false)); // non-owners cannot write
    }

    #[test]
    fn test_validator_valid_paths() {
        let v = NamespaceValidator::validate("m/agent1/scratch").unwrap();
        assert_eq!(v.ns_type, NamespaceType::Memory);
        assert_eq!(v.security_level, SecurityLevel::Standard);
        assert!(!v.was_migrated);
        assert_eq!(v.path, "m/agent1/scratch");

        let v = NamespaceValidator::validate("/k/medical/facts").unwrap();
        assert_eq!(v.ns_type, NamespaceType::Knowledge);
        assert_eq!(v.security_level, SecurityLevel::Protected);
    }

    #[test]
    fn test_validator_rejects_invalid() {
        assert!(NamespaceValidator::validate("").is_err());
        assert!(NamespaceValidator::validate("x/invalid").is_err());
        assert!(NamespaceValidator::validate("m/../../../etc/passwd").is_err());
        assert!(NamespaceValidator::validate("m/test\0bad").is_err());
        assert!(NamespaceValidator::validate("random/path").is_err());
    }

    #[test]
    fn test_validator_legacy_migration() {
        let v = NamespaceValidator::validate("ns:shared").unwrap();
        assert_eq!(v.ns_type, NamespaceType::Memory);
        assert_eq!(v.path, "m/shared");
        assert!(v.was_migrated);

        let v = NamespaceValidator::validate("sys:compute:cgroups").unwrap();
        assert_eq!(v.ns_type, NamespaceType::System);
        assert_eq!(v.path, "s/compute/cgroups");
        assert!(v.was_migrated);

        let v = NamespaceValidator::validate("sys:compute:usage").unwrap();
        assert_eq!(v.path, "s/compute/usage");
    }

    #[test]
    fn test_validator_normalizes_paths() {
        let v = NamespaceValidator::validate("//m///agent1///scratch//").unwrap();
        assert_eq!(v.path, "m/agent1/scratch");

        let v = NamespaceValidator::validate("m/./agent1/./scratch").unwrap();
        assert_eq!(v.path, "m/agent1/scratch");
    }

    #[test]
    fn test_extract_owner() {
        assert_eq!(NamespaceValidator::extract_owner("m/agent1/scratch"), Some("agent1".to_string()));
        assert_eq!(NamespaceValidator::extract_owner("/a/agent2/acb"), Some("agent2".to_string()));
        assert_eq!(NamespaceValidator::extract_owner("k/medical/facts"), None);
        assert_eq!(NamespaceValidator::extract_owner("s/audit"), None);
    }

    #[test]
    fn test_is_descendant() {
        assert!(NamespaceValidator::is_descendant("m/agent1", "m/agent1/scratch"));
        assert!(NamespaceValidator::is_descendant("m/agent1", "m/agent1"));
        assert!(!NamespaceValidator::is_descendant("m/agent1", "m/agent2/scratch"));
        assert!(!NamespaceValidator::is_descendant("m/agent1/scratch", "m/agent1"));
    }
}
