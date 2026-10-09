//! DevGuard configuration loader — parses devguard.yaml with full RBAC.
//!
//! This is DevGuard's config format. Connector OS knows nothing about it.
//! DevGuard compiles this config into Connector API calls at runtime.

use std::collections::HashMap;
use std::path::Path;
use serde::{Serialize, Deserialize};
use anyhow::{Context, Result};

// ── Top-level config ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DevGuardConfig {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub workspace: String,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub roles: HashMap<String, RoleConfig>,
    #[serde(default)]
    pub default_role: String,
    #[serde(default)]
    pub assignments: Vec<Assignment>,
    #[serde(default)]
    pub tool_overrides: HashMap<String, ToolOverride>,
    #[serde(default)]
    pub files: GlobalFileConfig,
    #[serde(default)]
    pub secrets: SecretConfig,
    #[serde(default)]
    pub git: GitConfig,
    #[serde(default)]
    pub budget: GlobalBudgetConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub enforcement: EnforcementConfig,
}

fn default_version() -> String { "2.0".into() }

impl DevGuardConfig {
    /// Load from a YAML file path.
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read {}", path))?;
        Self::from_yaml(&content)
    }

    /// Parse from YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        serde_yaml::from_str(yaml)
            .with_context(|| "Failed to parse devguard.yaml")
    }

    /// Resolve the effective role for an identity + tool combination.
    pub fn resolve_role(&self, identity: &str, tool: &str) -> Option<ResolvedRole> {
        // Find matching assignment (most specific first)
        let assignment = self.find_assignment(identity, tool)?;
        let role_name = &assignment.role;

        // Load role definition
        let role = self.roles.get(role_name)?;

        // If role extends another, merge
        let mut effective = role.clone();
        if let Some(ref parent_name) = role.extends {
            if let Some(parent) = self.roles.get(parent_name) {
                effective = Self::merge_roles(parent, &effective);
            }
        }

        // Apply assignment overrides
        if let Some(ref overrides) = assignment.overrides {
            effective = Self::apply_overrides(&effective, overrides);
        }

        // Apply tool overrides
        if let Some(tool_override) = self.tool_overrides.get(tool) {
            effective = Self::apply_tool_override(&effective, tool_override);
        }

        // Apply global always_hidden / always_read_only
        if !self.files.always_hidden.is_empty() {
            effective.files.hidden.extend(self.files.always_hidden.iter().cloned());
        }
        if !self.files.always_read_only.is_empty() {
            effective.files.read_only.extend(self.files.always_read_only.iter().cloned());
        }

        Some(ResolvedRole {
            role_name: role_name.clone(),
            identity: identity.to_string(),
            tool: tool.to_string(),
            config: effective,
        })
    }

    /// Find the best matching assignment for identity + tool.
    fn find_assignment(&self, identity: &str, tool: &str) -> Option<&Assignment> {
        // Priority: exact identity match > team match > wildcard
        let tool_norm = tool.to_lowercase().replace('-', "_");

        // Exact match
        if let Some(a) = self.assignments.iter().find(|a| {
            a.identity == identity && a.tools.iter().any(|t| t.replace('-', "_") == tool_norm || t == "*")
        }) {
            return Some(a);
        }

        // Wildcard match
        if let Some(a) = self.assignments.iter().find(|a| {
            a.identity == "*" && a.tools.iter().any(|t| t.replace('-', "_") == tool_norm || t == "*")
        }) {
            return Some(a);
        }

        None
    }

    /// Merge parent role into child (child overrides parent).
    fn merge_roles(parent: &RoleConfig, child: &RoleConfig) -> RoleConfig {
        let mut merged = parent.clone();

        // Child overrides parent for non-empty fields
        if !child.files.read.is_empty() { merged.files.read = child.files.read.clone(); }
        if !child.files.write.is_empty() { merged.files.write = child.files.write.clone(); }
        if !child.files.hidden.is_empty() { merged.files.hidden = child.files.hidden.clone(); }
        if !child.files.read_only.is_empty() { merged.files.read_only = child.files.read_only.clone(); }
        if !child.execution.allow.is_empty() { merged.execution.allow = child.execution.allow.clone(); }
        if !child.execution.deny.is_empty() { merged.execution.deny = child.execution.deny.clone(); }
        if !child.execution.require_approval.is_empty() { merged.execution.require_approval = child.execution.require_approval.clone(); }
        if !child.branches.allow.is_empty() { merged.branches.allow = child.branches.allow.clone(); }
        if !child.branches.deny.is_empty() { merged.branches.deny = child.branches.deny.clone(); }
        if child.clearance > 0 { merged.clearance = child.clearance; }
        if child.budget.max_tokens_per_task > 0 { merged.budget = child.budget.clone(); }
        if !child.secrets.is_default() { merged.secrets = child.secrets.clone(); }
        if !child.network.allow.is_empty() { merged.network = child.network.clone(); }
        if !child.approvals.is_empty() { merged.approvals = child.approvals.clone(); }
        if !child.context.scope.is_empty() { merged.context = child.context.clone(); }

        merged
    }

    /// Apply assignment-level overrides to a role.
    fn apply_overrides(role: &RoleConfig, overrides: &RoleOverride) -> RoleConfig {
        let mut r = role.clone();
        if let Some(ref fo) = overrides.files {
            if !fo.read.is_empty() { r.files.read = fo.read.clone(); }
            if !fo.write.is_empty() { r.files.write = fo.write.clone(); }
            if !fo.hidden.is_empty() { r.files.hidden = fo.hidden.clone(); }
            if !fo.read_only.is_empty() { r.files.read_only = fo.read_only.clone(); }
        }
        if let Some(ref eo) = overrides.execution {
            if !eo.allow.is_empty() { r.execution.allow = eo.allow.clone(); }
            if !eo.deny.is_empty() { r.execution.deny = eo.deny.clone(); }
        }
        r
    }

    /// Apply tool-level overrides.
    fn apply_tool_override(role: &RoleConfig, tool_override: &ToolOverride) -> RoleConfig {
        let mut r = role.clone();
        if let Some(ref eo) = tool_override.execution {
            if let Some(ref deny_append) = eo.deny_append {
                r.execution.deny.extend(deny_append.iter().cloned());
            }
        }
        r
    }

    /// Validate the configuration for errors.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.roles.is_empty() {
            errors.push("No roles defined".into());
        }

        // Check assignments reference valid roles
        for (i, a) in self.assignments.iter().enumerate() {
            if a.identity.is_empty() {
                errors.push(format!("Assignment #{}: empty identity", i));
            }
            if !self.roles.contains_key(&a.role) && a.role != "*" {
                errors.push(format!("Assignment #{}: role '{}' not defined", i, a.role));
            }
            if a.tools.is_empty() {
                errors.push(format!("Assignment #{}: no tools specified", i));
            }
        }

        // Check role inheritance
        for (name, role) in &self.roles {
            if let Some(ref parent) = role.extends {
                if !self.roles.contains_key(parent) {
                    errors.push(format!("Role '{}' extends '{}' which is not defined", name, parent));
                }
            }
        }

        // Check for catch-all
        let has_catchall = self.assignments.iter().any(|a| a.identity == "*");
        if !has_catchall && !self.default_role.is_empty() {
            // OK — default_role serves as catch-all
        } else if !has_catchall && self.default_role.is_empty() {
            errors.push("No catch-all assignment (identity: '*') and no default_role — unmatched users will be denied".into());
        }

        errors
    }

    /// Compute SHA-256 fingerprint of the compiled policy.
    pub fn fingerprint(&self) -> String {
        use sha2::{Sha256, Digest};
        let serialized = serde_json::to_string(self).unwrap_or_default();
        let hash = Sha256::digest(serialized.as_bytes());
        format!("{:x}", hash)
    }
}

// ── Identity ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityConfig {
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub require_auth: bool,
    #[serde(default)]
    pub mfa_required: bool,
}

fn default_provider() -> String { "local".into() }

// ── Role ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoleConfig {
    #[serde(default)]
    pub clearance: u8,
    #[serde(default)]
    pub extends: Option<String>,
    #[serde(default)]
    pub files: FilePermissions,
    #[serde(default)]
    pub execution: ExecPermissions,
    #[serde(default)]
    pub branches: BranchPermissions,
    #[serde(default)]
    pub secrets: SecretPermissions,
    #[serde(default)]
    pub network: NetworkPermissions,
    #[serde(default)]
    pub budget: BudgetConfig,
    #[serde(default)]
    pub context: ContextConfig,
    #[serde(default)]
    pub approvals: HashMap<String, ApprovalRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FilePermissions {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub hidden: Vec<String>,
    #[serde(default)]
    pub read_only: Vec<String>,
    #[serde(default)]
    pub no_delete: Vec<String>,
    #[serde(default)]
    pub suggest_only: Vec<String>,
    #[serde(default)]
    pub max_files_per_change: Option<u32>,
    #[serde(default)]
    pub max_lines_per_file: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecPermissions {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub require_approval: Vec<String>,
    #[serde(default)]
    pub limits: Option<ExecLimits>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecLimits {
    #[serde(default)]
    pub max_runtime_seconds: u32,
    #[serde(default)]
    pub max_output_bytes: u64,
    #[serde(default)]
    pub deny_background: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BranchPermissions {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

/// SecretPermissions supports both `secrets: none` (string) and `secrets: { allowed_via_broker: [...] }` (struct).
#[derive(Debug, Clone, Serialize, Default)]
pub struct SecretPermissions {
    pub allowed_via_broker: Vec<String>,
    pub direct_access: Option<String>,
}

impl<'de> serde::Deserialize<'de> for SecretPermissions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'de>
    {
        use serde::de;

        struct SecretVisitor;

        #[derive(Deserialize)]
        struct SecretStruct {
            #[serde(default)]
            allowed_via_broker: Vec<String>,
            #[serde(default)]
            direct_access: Option<String>,
        }

        impl<'de> de::Visitor<'de> for SecretVisitor {
            type Value = SecretPermissions;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "\"none\" or a secrets mapping")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<SecretPermissions, E> {
                if v == "none" || v == "None" || v.is_empty() {
                    Ok(SecretPermissions { allowed_via_broker: vec![], direct_access: Some("none".into()) })
                } else {
                    Err(E::custom(format!("unknown secrets value: {}", v)))
                }
            }

            fn visit_unit<E: de::Error>(self) -> Result<SecretPermissions, E> {
                Ok(SecretPermissions::default())
            }

            fn visit_map<M: de::MapAccess<'de>>(self, map: M) -> Result<SecretPermissions, M::Error> {
                let s: SecretStruct = de::Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(SecretPermissions { allowed_via_broker: s.allowed_via_broker, direct_access: s.direct_access })
            }
        }

        deserializer.deserialize_any(SecretVisitor)
    }
}

impl SecretPermissions {
    pub fn is_default(&self) -> bool {
        self.allowed_via_broker.is_empty() && self.direct_access.is_none()
    }

    pub fn is_none(&self) -> bool {
        self.allowed_via_broker.is_empty()
            && (self.direct_access.as_deref() == Some("none") || self.direct_access.is_none())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkPermissions {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BudgetConfig {
    #[serde(default)]
    pub max_tokens_per_task: u64,
    #[serde(default)]
    pub max_cost_usd_per_day: f64,
    #[serde(default)]
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContextConfig {
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub max_tokens: u64,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub inject: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRule {
    #[serde(default)]
    pub require: ApprovalTarget,
    #[serde(default)]
    pub quorum: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(untagged)]
pub enum ApprovalTarget {
    #[default]
    None,
    Single(String),
    Multiple(Vec<String>),
}

// ── Assignment ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assignment {
    pub identity: String,
    pub role: String,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub overrides: Option<RoleOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoleOverride {
    #[serde(default)]
    pub files: Option<FilePermissions>,
    #[serde(default)]
    pub execution: Option<ExecPermissions>,
}

// ── Tool override ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolOverride {
    #[serde(default)]
    pub execution: Option<ToolExecOverride>,
    #[serde(default)]
    pub mcp_governed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolExecOverride {
    #[serde(default)]
    pub deny_append: Option<Vec<String>>,
}

// ── Global configs ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalFileConfig {
    #[serde(default)]
    pub always_hidden: Vec<String>,
    #[serde(default)]
    pub always_read_only: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretConfig {
    #[serde(default = "default_true")]
    pub detect_and_redact: bool,
    #[serde(default)]
    pub patterns: String,
    #[serde(default)]
    pub vault_backend: String,
    #[serde(default)]
    pub rotation_alert: bool,
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GitConfig {
    #[serde(default)]
    pub no_force_push: bool,
    #[serde(default)]
    pub max_diff_lines: u32,
    #[serde(default)]
    pub require_signed_commits: bool,
    #[serde(default)]
    pub protected_branches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalBudgetConfig {
    #[serde(default)]
    pub max_tokens_per_day: u64,
    #[serde(default)]
    pub max_cost_usd_per_day: f64,
    #[serde(default)]
    pub alert_at_percent: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditConfig {
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub receipts: bool,
    #[serde(default)]
    pub proof: bool,
    #[serde(default)]
    pub retention_days: u32,
    #[serde(default)]
    pub export: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementConfig {
    #[serde(default = "default_enforcement_mode")]
    pub mode: String,
    #[serde(default = "default_true")]
    pub deny_by_default: bool,
    #[serde(default = "default_true")]
    pub least_privilege: bool,
    #[serde(default = "default_true")]
    pub no_raw_secret_exposure: bool,
    #[serde(default = "default_true")]
    pub all_actions_receipted: bool,
}

fn default_enforcement_mode() -> String { "hooks".into() }

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            mode: default_enforcement_mode(),
            deny_by_default: true,
            least_privilege: true,
            no_raw_secret_exposure: true,
            all_actions_receipted: true,
        }
    }
}

// ── Resolved role (the compiled effective permissions for a session) ───────

#[derive(Debug, Clone)]
pub struct ResolvedRole {
    pub role_name: String,
    pub identity: String,
    pub tool: String,
    pub config: RoleConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct PermissionCheck {
    pub allowed: bool,
    pub verdict: &'static str,
    pub reason: String,
    pub requires_approval: bool,
    pub approval_from: Vec<String>,
}

impl PermissionCheck {
    pub fn allow(reason: &str) -> Self {
        Self {
            allowed: true,
            verdict: "ALLOW",
            reason: reason.to_string(),
            requires_approval: false,
            approval_from: vec![],
        }
    }

    pub fn deny(reason: &str) -> Self {
        Self {
            allowed: false,
            verdict: "DENY",
            reason: reason.to_string(),
            requires_approval: false,
            approval_from: vec![],
        }
    }

    pub fn needs_approval(reason: &str, from: Vec<String>) -> Self {
        Self {
            allowed: false,
            verdict: "NEEDS_APPROVAL",
            reason: reason.to_string(),
            requires_approval: true,
            approval_from: from,
        }
    }
}

impl ResolvedRole {
    pub fn check_file(&self, operation: &str, path: &str) -> PermissionCheck {
        if matches_any_glob(path, &self.config.files.hidden) {
            return PermissionCheck::deny(&format!("File '{}' is hidden by policy", path));
        }
        if operation == "read" {
            if !self.config.files.read.is_empty() && !matches_any_glob(path, &self.config.files.read) {
                return PermissionCheck::deny(&format!("Read denied for '{}'", path));
            }
            return PermissionCheck::allow("Permitted by role file-read policy");
        }
        if self.config.files.write.is_empty() {
            return PermissionCheck::deny("Role has no write permissions");
        }
        if !matches_any_glob(path, &self.config.files.write) {
            return PermissionCheck::deny(&format!("Write denied for '{}'", path));
        }
        if matches_any_glob(path, &self.config.files.read_only) {
            return PermissionCheck::deny(&format!("'{}' is read-only", path));
        }
        if operation == "delete" && matches_any_glob(path, &self.config.files.no_delete) {
            return PermissionCheck::deny(&format!("Delete denied for '{}'", path));
        }
        if matches_any_glob(path, &self.config.files.suggest_only) {
            return PermissionCheck::needs_approval(
                &format!("'{}' is suggest-only", path),
                vec!["code_owner".to_string()],
            );
        }
        PermissionCheck::allow("Permitted by role file-write policy")
    }

    pub fn check_exec(&self, command: &str) -> PermissionCheck {
        if let Some((verdict, reason, _network)) = crate::guard_patterns::classify_command(command) {
            return match verdict {
                crate::guard_patterns::PatternVerdict::Deny => {
                    PermissionCheck::deny(&format!("DANGEROUS: {}", reason))
                }
                crate::guard_patterns::PatternVerdict::Flagged => {
                    PermissionCheck::deny(&format!("FLAGGED: {}", reason))
                }
            };
        }
        for pat in &self.config.execution.deny {
            if command_matches(pat, command) {
                return PermissionCheck::deny(&format!("Command '{}' denied by '{}'", command, pat));
            }
        }
        for pat in &self.config.execution.require_approval {
            if command_matches(pat, command) {
                return PermissionCheck::needs_approval(
                    &format!("Command '{}' requires approval", command),
                    vec!["tech_lead".to_string()],
                );
            }
        }
        if !self.config.execution.allow.is_empty() {
            let allowed = self
                .config
                .execution
                .allow
                .iter()
                .any(|pat| command_matches(pat, command));
            if !allowed {
                return PermissionCheck::deny(&format!(
                    "Command '{}' not in allowed list for role '{}'",
                    command, self.role_name
                ));
            }
        }
        PermissionCheck::allow("Permitted by role execution policy")
    }

    pub fn check_git(&self, operation: &str, branch: &str) -> PermissionCheck {
        if matches_any_glob(branch, &self.config.branches.deny) {
            return PermissionCheck::deny(&format!("Branch '{}' denied by role policy", branch));
        }
        if !self.config.branches.allow.is_empty() && !matches_any_glob(branch, &self.config.branches.allow) {
            return PermissionCheck::deny(&format!("Branch '{}' is not allowed", branch));
        }
        if operation.contains("force") {
            return PermissionCheck::needs_approval(
                "Force operations require approval",
                vec!["tech_lead".to_string()],
            );
        }
        PermissionCheck::allow("Permitted by role git policy")
    }
}

fn matches_any_glob(path: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|p| glob::Pattern::new(p).map(|g| g.matches(path)).unwrap_or(p == path))
}

fn command_matches(pattern: &str, command: &str) -> bool {
    let pat = pattern.trim();
    let cmd = command.trim();
    if pat.ends_with('*') {
        cmd.starts_with(&pat[..pat.len().saturating_sub(1)])
    } else {
        cmd == pat || cmd.starts_with(&format!("{} ", pat))
    }
}
