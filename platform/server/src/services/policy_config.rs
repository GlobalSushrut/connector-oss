//! DevGuard Policy Config — YAML policy loader, role compiler, permission resolver.
//!
//! Loads `.connector/policy.yaml`, compiles roles into enforceable rules,
//! and provides runtime permission checks for file access, command execution,
//! git operations, and secret handling.
//!
//! This is a REAL production controller, not a demo.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub use crate::services::secret_broker::SecretPattern;

// ── Policy data structures ──────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DevGuardPolicy {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub workspace: String,
    #[serde(default)]
    pub roles: HashMap<String, RolePolicy>,
    #[serde(default)]
    pub default_role: String,
    #[serde(default)]
    pub files: FilePolicy,
    #[serde(default)]
    pub writes: WritePolicy,
    #[serde(default)]
    pub execution: ExecPolicy,
    #[serde(default)]
    pub secrets: SecretPolicy,
    #[serde(default)]
    pub context: ContextPolicy,
    #[serde(default)]
    pub git: GitPolicy,
    #[serde(default)]
    pub approvals: HashMap<String, ApprovalRule>,
    #[serde(default)]
    pub budget: BudgetPolicy,
    #[serde(default)]
    pub audit: AuditPolicy,
    #[serde(default)]
    pub verification: VerificationPolicy,
    #[serde(default)]
    pub defaults: DefaultsPolicy,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RolePolicy {
    #[serde(default)]
    pub clearance: u8,
    #[serde(default)]
    pub files: RoleFilePolicy,
    #[serde(default)]
    pub execution: RoleExecPolicy,
    #[serde(default)]
    pub branches: BranchPolicy,
    #[serde(default)]
    pub secrets: String,
    #[serde(default)]
    pub budget: RoleBudgetPolicy,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RoleFilePolicy {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RoleExecPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub require_approval: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BranchPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RoleBudgetPolicy {
    #[serde(default)]
    pub max_tokens_per_task: u64,
    #[serde(default)]
    pub model: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FilePolicy {
    #[serde(default)]
    pub visible: Vec<String>,
    #[serde(default)]
    pub hidden: Vec<String>,
    #[serde(default)]
    pub read_only: Vec<String>,
    #[serde(default)]
    pub metadata_only: Vec<String>,
    #[serde(default)]
    pub masked: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct WritePolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub suggest_only: Vec<String>,
    #[serde(default)]
    pub no_delete: Vec<String>,
    #[serde(default)]
    pub no_rename: Vec<String>,
    #[serde(default)]
    pub max_files_per_change: usize,
    #[serde(default)]
    pub max_lines_per_file: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ExecPolicy {
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub denied: Vec<String>,
    #[serde(default)]
    pub require_approval: Vec<String>,
    #[serde(default)]
    pub limits: ExecLimits,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ExecLimits {
    #[serde(default = "default_max_runtime")]
    pub max_runtime_seconds: u64,
    #[serde(default = "default_max_output")]
    pub max_output_bytes: u64,
    #[serde(default)]
    pub deny_background: bool,
}

fn default_max_runtime() -> u64 {
    300
}
fn default_max_output() -> u64 {
    1_048_576
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SecretPolicy {
    #[serde(default)]
    pub detect_and_redact: bool,
    #[serde(default = "default_patterns_mode")]
    pub patterns: String,
    #[serde(default)]
    pub custom_patterns: Vec<SecretPattern>,
}

fn default_patterns_mode() -> String {
    "default".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ContextPolicy {
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u64,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub inject: Vec<String>,
}

fn default_max_tokens() -> u64 {
    32000
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct GitPolicy {
    #[serde(default)]
    pub allowed_branches: Vec<String>,
    #[serde(default)]
    pub denied_branches: Vec<String>,
    #[serde(default)]
    pub require_pr: bool,
    #[serde(default)]
    pub no_force_push: bool,
    #[serde(default = "default_max_diff")]
    pub max_diff_lines: usize,
}

fn default_max_diff() -> usize {
    2000
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ApprovalRule {
    #[serde(default)]
    pub require: Vec<String>,
    #[serde(default = "default_quorum")]
    pub quorum: usize,
}

fn default_quorum() -> usize {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BudgetPolicy {
    #[serde(default = "default_daily_tokens")]
    pub max_tokens_per_day: u64,
    #[serde(default = "default_daily_cost")]
    pub max_cost_usd: f64,
}

fn default_daily_tokens() -> u64 {
    1_000_000
}
fn default_daily_cost() -> f64 {
    10.0
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AuditPolicy {
    #[serde(default = "default_audit_level")]
    pub level: String,
    #[serde(default)]
    pub receipts: bool,
    #[serde(default)]
    pub proof: bool,
    #[serde(default = "default_retention")]
    pub retention_days: u64,
}

fn default_audit_level() -> String {
    "full".to_string()
}
fn default_retention() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct VerificationPolicy {
    #[serde(default)]
    pub after_changes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DefaultsPolicy {
    #[serde(default = "bool_true")]
    pub deny_by_default: bool,
    #[serde(default = "bool_true")]
    pub least_privilege: bool,
    #[serde(default = "bool_true")]
    pub no_raw_secret_exposure: bool,
    #[serde(default = "bool_true")]
    pub all_actions_receipted: bool,
    #[serde(default = "bool_true")]
    pub roles_separated: bool,
}

fn bool_true() -> bool {
    true
}

impl Default for DefaultsPolicy {
    fn default() -> Self {
        Self {
            deny_by_default: true,
            least_privilege: true,
            no_raw_secret_exposure: true,
            all_actions_receipted: true,
            roles_separated: true,
        }
    }
}

// ── Policy loading ──────────────────────────────────────────────────────────

impl DevGuardPolicy {
    /// Load policy from a YAML file path.
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read policy file '{}': {}", path, e))?;
        Self::load_from_str(&content)
    }

    /// Load policy from a YAML string.
    pub fn load_from_str(yaml: &str) -> Result<Self, String> {
        serde_yaml::from_str(yaml).map_err(|e| format!("Invalid policy YAML: {}", e))
    }

    /// Validate the policy and return any errors.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.version.is_empty() {
            errors.push("Missing 'version' field".into());
        }
        if !self.default_role.is_empty() && !self.roles.contains_key(&self.default_role) {
            errors.push(format!(
                "default_role '{}' not found in roles",
                self.default_role
            ));
        }
        for (name, role) in &self.roles {
            if role.files.read.is_empty() && role.files.write.is_empty() {
                errors.push(format!("Role '{}' has no file permissions defined", name));
            }
        }
        errors
    }

    /// Get the effective role policy, falling back to default_role if role not found.
    pub fn role(&self, role_name: &str) -> Option<&RolePolicy> {
        self.roles
            .get(role_name)
            .or_else(|| self.roles.get(&self.default_role))
    }
}

// ── Permission check result ────────────────────────────────────────────────

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
            reason: reason.into(),
            requires_approval: false,
            approval_from: vec![],
        }
    }
    pub fn deny(reason: &str) -> Self {
        Self {
            allowed: false,
            verdict: "DENY",
            reason: reason.into(),
            requires_approval: false,
            approval_from: vec![],
        }
    }
    pub fn needs_approval(reason: &str, from: Vec<String>) -> Self {
        Self {
            allowed: false,
            verdict: "NEEDS_APPROVAL",
            reason: reason.into(),
            requires_approval: true,
            approval_from: from,
        }
    }
}

// ── Glob matching helper ────────────────────────────────────────────────────

/// Match a file path against a glob pattern list.
fn matches_any_glob(path: &str, patterns: &[String]) -> bool {
    for pat in patterns {
        if glob_match(pat, path) {
            return true;
        }
    }
    false
}

/// Simple glob matching: supports *, **, and ?
fn glob_match(pattern: &str, path: &str) -> bool {
    if path.contains("..") || path.contains('\0') {
        return false;
    }
    let path = path.trim_start_matches("./");
    let pattern = pattern.trim();
    if pattern == "**" || pattern == "**/*" || pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path
            .strip_prefix(&format!("{prefix}/"))
            .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'));
    }
    if let Some(star) = pattern.find('*') {
        let (pre, rest) = pattern.split_at(star);
        let post = rest.trim_start_matches('*');
        if path.starts_with(pre) && (post.is_empty() || path.ends_with(post)) {
            return true;
        }
    }
    if let Ok(p) = glob::Pattern::new(pattern) {
        return p.matches(path);
    }
    pattern == path
}

/// True when the command string can be interpreted as a shell chain or substitution.
fn command_has_shell_metacharacters(command: &str) -> bool {
    let c = command.trim();
    c.contains("&&")
        || c.contains("||")
        || c.contains(';')
        || c.contains('|')
        || c.contains('`')
        || c.contains("$(")
        || c.contains("${")
        || c.contains('\n')
        || c.contains('\r')
        || c.contains('>')
        || c.contains('<')
        || (c.contains('&') && !c.contains("&&"))
}

/// Match a command against a pattern (supports trailing * on argv prefix).
/// Shell metacharacters never match an allow pattern; `check_exec` denies them first.
fn command_matches(pattern: &str, command: &str) -> bool {
    if command_has_shell_metacharacters(command) {
        return false;
    }
    let pat = pattern.trim();
    let cmd = command.trim();
    if pat.ends_with('*') {
        let prefix = pat[..pat.len() - 1].trim_end();
        cmd == prefix || cmd.starts_with(&format!("{prefix} "))
    } else {
        cmd == pat || cmd.starts_with(&format!("{pat} "))
    }
}

// ── File permission check ──────────────────────────────────────────────────

impl DevGuardPolicy {
    /// Check if a role can perform a file operation.
    pub fn check_file(&self, role_name: &str, operation: &str, path: &str) -> PermissionCheck {
        // Always deny hidden files
        if matches_any_glob(path, &self.files.hidden) {
            return PermissionCheck::deny(&format!("File '{}' is hidden by policy", path));
        }

        // Check role-specific permissions
        if let Some(role) = self.role(role_name) {
            match operation {
                "read" => {
                    if role.files.read.is_empty() && self.defaults.deny_by_default {
                        return PermissionCheck::deny("Role has no read permissions");
                    }
                    if !role.files.read.is_empty() && !matches_any_glob(path, &role.files.read) {
                        return PermissionCheck::deny(&format!(
                            "Role '{}' cannot read '{}' — not in allowed paths",
                            role_name, path
                        ));
                    }
                }
                "write" | "delete" | "rename" => {
                    // Check role write permissions
                    if role.files.write.is_empty() {
                        return PermissionCheck::deny(&format!(
                            "Role '{}' has no write permissions",
                            role_name
                        ));
                    }
                    if !matches_any_glob(path, &role.files.write) {
                        return PermissionCheck::deny(&format!(
                            "Role '{}' cannot write '{}' — not in allowed paths",
                            role_name, path
                        ));
                    }
                    // Check global write policy
                    if matches_any_glob(path, &self.writes.deny) {
                        return PermissionCheck::deny(&format!(
                            "File '{}' is write-denied by policy",
                            path
                        ));
                    }
                    if matches_any_glob(path, &self.files.read_only) {
                        return PermissionCheck::deny(&format!(
                            "File '{}' is read-only by policy",
                            path
                        ));
                    }
                    if operation == "delete" && matches_any_glob(path, &self.writes.no_delete) {
                        return PermissionCheck::deny(&format!(
                            "File '{}' is delete-protected by policy",
                            path
                        ));
                    }
                    if operation == "rename" && matches_any_glob(path, &self.writes.no_rename) {
                        return PermissionCheck::deny(&format!(
                            "File '{}' is rename-protected by policy",
                            path
                        ));
                    }
                    if matches_any_glob(path, &self.writes.suggest_only) {
                        return PermissionCheck::needs_approval(
                            &format!("File '{}' is suggest-only — requires approval", path),
                            vec!["code_owner".into()],
                        );
                    }
                    // Check approval triggers
                    if let Some(rule) = self.approvals.get("write_protected") {
                        if matches_any_glob(path, &self.files.read_only)
                            || matches_any_glob(path, &self.writes.suggest_only)
                        {
                            return PermissionCheck::needs_approval(
                                &format!("Write to '{}' requires approval", path),
                                rule.require.clone(),
                            );
                        }
                    }
                }
                _ => {}
            }
        } else if self.defaults.deny_by_default {
            return PermissionCheck::deny(&format!(
                "Role '{}' not found and deny_by_default is enabled",
                role_name
            ));
        }

        // Check visibility rules (for reads)
        if operation == "read" && !self.files.visible.is_empty() {
            if !matches_any_glob(path, &self.files.visible) {
                return PermissionCheck::deny(&format!("File '{}' not in visible set", path));
            }
        }

        PermissionCheck::allow("Permitted by policy")
    }

    /// Check if a role can execute a command.
    pub fn check_exec(&self, role_name: &str, command: &str) -> PermissionCheck {
        if command_has_shell_metacharacters(command) {
            return PermissionCheck::deny(&format!(
                "Command '{}' denied: shell chaining, pipes, redirection, or substitution are not allowed",
                command
            ));
        }
        // Check role-specific exec policy first
        if let Some(role) = self.role(role_name) {
            for pat in &role.execution.deny {
                if command_matches(pat, command) {
                    return PermissionCheck::deny(&format!(
                        "Command '{}' denied for role '{}' (matches '{}')",
                        command, role_name, pat
                    ));
                }
            }
            for pat in &role.execution.require_approval {
                if command_matches(pat, command) {
                    return PermissionCheck::needs_approval(
                        &format!(
                            "Command '{}' requires approval for role '{}'",
                            command, role_name
                        ),
                        vec!["tech_lead".into()],
                    );
                }
            }
            // Check if allowed
            if !role.execution.allow.is_empty() {
                let mut found = false;
                for pat in &role.execution.allow {
                    if command_matches(pat, command) {
                        found = true;
                        break;
                    }
                }
                if !found && self.defaults.deny_by_default {
                    return PermissionCheck::deny(&format!(
                        "Command '{}' not in allowed list for role '{}'",
                        command, role_name
                    ));
                }
            }
        }

        // Check global exec policy
        for pat in &self.execution.denied {
            if command_matches(pat, command) {
                return PermissionCheck::deny(&format!(
                    "Command '{}' denied by global policy (matches '{}')",
                    command, pat
                ));
            }
        }
        for pat in &self.execution.require_approval {
            if command_matches(pat, command) {
                return PermissionCheck::needs_approval(
                    &format!("Command '{}' requires approval", command),
                    vec!["tech_lead".into()],
                );
            }
        }
        if !self.execution.allowed.is_empty() {
            let mut found = false;
            for pat in &self.execution.allowed {
                if command_matches(pat, command) {
                    found = true;
                    break;
                }
            }
            if !found && self.defaults.deny_by_default {
                return PermissionCheck::deny(&format!(
                    "Command '{}' not in global allowed list",
                    command
                ));
            }
        }

        PermissionCheck::allow("Permitted by policy")
    }

    /// Check if a role can perform a git operation on a branch.
    pub fn check_git(&self, role_name: &str, branch: &str, operation: &str) -> PermissionCheck {
        // Check denied branches
        if matches_any_glob(branch, &self.git.denied_branches) {
            return PermissionCheck::deny(&format!("Branch '{}' is denied by policy", branch));
        }
        // Check role branch permissions
        if let Some(role) = self.role(role_name) {
            if !role.branches.allow.is_empty() && !matches_any_glob(branch, &role.branches.allow) {
                return PermissionCheck::deny(&format!(
                    "Role '{}' cannot access branch '{}'",
                    role_name, branch
                ));
            }
            if matches_any_glob(branch, &role.branches.deny) {
                return PermissionCheck::deny(&format!(
                    "Branch '{}' denied for role '{}'",
                    branch, role_name
                ));
            }
        }
        // Check force push
        if self.git.no_force_push && operation.contains("force") {
            return PermissionCheck::deny("Force push denied by policy");
        }
        PermissionCheck::allow("Permitted by git policy")
    }
}

// ── HTTP endpoints ──────────────────────────────────────────────────────────

use crate::state::SharedState;
use axum::{extract::State, Json};

/// POST /api/v1/devguard/policy/load — Load policy YAML for an agent
pub async fn policy_load(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let yaml_str = req
        .get("policy_yaml")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let role = req.get("role").and_then(|v| v.as_str()).unwrap_or("");

    if yaml_str.is_empty() {
        return Json(serde_json::json!({
            "ok": false,
            "error": "policy_yaml is required"
        }));
    }

    match DevGuardPolicy::load_from_str(yaml_str) {
        Ok(policy) => {
            let errors = policy.validate();
            if !errors.is_empty() {
                return Json(serde_json::json!({
                    "ok": false,
                    "errors": errors,
                }));
            }
            let effective_role = if role.is_empty() {
                &policy.default_role
            } else {
                role
            };

            // Store policy in engine_store
            {
                let mut es = match crate::util_lock::mutex_lock(&state.engine_store, "engine_store")
                {
                    Ok(g) => g,
                    Err(e) => {
                        return Json(serde_json::json!({ "ok": false, "error": e, "status": 503 }));
                    }
                };
                let bundle_id = policy_bundle_id_with_source(&policy, effective_role, "yaml_load");
                let record = serde_json::json!({
                    "policy": serde_json::to_value(&policy).unwrap_or_default(),
                    "role": effective_role,
                    "policy_bundle_id": bundle_id,
                    "source": "yaml_load",
                    "loaded_at": chrono::Utc::now().to_rfc3339(),
                    "honesty": "Enforcement source is compiled yaml — local-profile is never included (DG-06/DG-08)",
                });
                let _ = es.folder_put("devguard_policies", agent_pid, &record);
                store_policy_version(es.as_mut(), agent_pid, &record);
            }

            Json(serde_json::json!({
                "ok": true,
                "agent_pid": agent_pid,
                "role": effective_role,
                "policy_bundle_id": policy_bundle_id_with_source(&policy, effective_role, "yaml_load"),
                "source": "yaml_load",
                "roles_defined": policy.roles.keys().collect::<Vec<_>>(),
                "file_rules": {
                    "visible": policy.files.visible.len(),
                    "hidden": policy.files.hidden.len(),
                    "read_only": policy.files.read_only.len(),
                },
                "exec_rules": {
                    "allowed": policy.execution.allowed.len(),
                    "denied": policy.execution.denied.len(),
                    "require_approval": policy.execution.require_approval.len(),
                },
                "secret_detection": policy.secrets.detect_and_redact,
                "audit_level": policy.audit.level,
                "schema": "connector.devguard_policy_bundle.v1",
            }))
        }
        Err(e) => Json(serde_json::json!({
            "ok": false,
            "error": e,
        })),
    }
}

/// POST /api/v1/devguard/policy/validate — Validate without applying
pub async fn policy_validate(Json(req): Json<serde_json::Value>) -> Json<serde_json::Value> {
    let yaml_str = req
        .get("policy_yaml")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if yaml_str.is_empty() {
        return Json(serde_json::json!({ "ok": false, "error": "policy_yaml is required" }));
    }
    match DevGuardPolicy::load_from_str(yaml_str) {
        Ok(policy) => {
            let errors = policy.validate();
            Json(serde_json::json!({
                "ok": errors.is_empty(),
                "errors": errors,
                "roles": policy.roles.keys().collect::<Vec<_>>(),
                "version": policy.version,
            }))
        }
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
    }
}

/// POST /api/v1/devguard/policy/check — Dry-run permission check
pub async fn policy_check(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let role = req.get("role").and_then(|v| v.as_str()).unwrap_or("");
    let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let resource = req.get("resource").and_then(|v| v.as_str()).unwrap_or("");

    // Load policy
    let policy_data = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("devguard_policies", agent_pid).ok().flatten()
    };
    let stored_bundle = policy_data
        .as_ref()
        .and_then(|d| d.get("policy_bundle_id").and_then(|x| x.as_str()))
        .map(|s| s.to_string());
    let stored_source = policy_data
        .as_ref()
        .and_then(|d| d.get("source").and_then(|x| x.as_str()))
        .unwrap_or("unknown")
        .to_string();
    let (policy, effective_role) = match policy_data {
        Some(data) => {
            let p: DevGuardPolicy =
                serde_json::from_value(data.get("policy").cloned().unwrap_or_default())
                    .unwrap_or_default();
            let r = if role.is_empty() {
                data.get("role")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            } else {
                role.to_string()
            };
            (p, r)
        }
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "error": format!("No policy loaded for agent '{}'", agent_pid),
            }));
        }
    };

    let check = match action {
        "read" | "write" | "delete" | "rename" => {
            policy.check_file(&effective_role, action, resource)
        }
        "exec" | "run" | "shell" => policy.check_exec(&effective_role, resource),
        "git" => {
            let branch = req.get("branch").and_then(|v| v.as_str()).unwrap_or("main");
            policy.check_git(&effective_role, branch, resource)
        }
        _ => PermissionCheck::deny(&format!("Unknown action '{}'", action)),
    };

    Json(serde_json::json!({
        "ok": true,
        "agent_pid": agent_pid,
        "role": effective_role,
        "action": action,
        "resource": resource,
        "allowed": check.allowed,
        "verdict": check.verdict,
        "reason": check.reason,
        "requires_approval": check.requires_approval,
        "approval_from": check.approval_from,
        "policy_bundle_id": stored_bundle
            .unwrap_or_else(|| policy_bundle_id(&policy, &effective_role)),
        "rule_id": format!("devguard.policy_check.{action}"),
        "source": stored_source,
    }))
}

/// Helper: get active policy for an agent from engine_store
pub fn get_active_policy(state: &SharedState, agent_pid: &str) -> Option<(DevGuardPolicy, String)> {
    let es = state.engine_store.lock().unwrap();
    let data = es.folder_get("devguard_policies", agent_pid).ok()??;
    let policy: DevGuardPolicy =
        serde_json::from_value(data.get("policy").cloned().unwrap_or_default()).ok()?;
    let role = data
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Some((policy, role))
}

/// DG-06: stable fingerprint for a compiled DevGuard policy + assigned role.
/// Optional `source` distinguishes yaml_load vs owner_roles_compile (local-profile never hashes in).
pub fn policy_bundle_id(policy: &DevGuardPolicy, role: &str) -> String {
    policy_bundle_id_with_source(policy, role, "yaml_or_compiled")
}

pub fn policy_bundle_id_with_source(policy: &DevGuardPolicy, role: &str, source: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut role_names: Vec<_> = policy.roles.keys().cloned().collect();
    role_names.sort();
    let payload = serde_json::json!({
        "schema": "connector.devguard_policy_bundle.v1",
        "source": source,
        "role": role,
        "version": policy.version,
        "default_role": policy.default_role,
        "files": policy.files,
        "execution": policy.execution,
        "secrets": policy.secrets,
        "audit": policy.audit,
        "roles": role_names,
        // Explicit non-inputs: local-profile JSON must never affect this fingerprint (DG-08/DG-06).
        "excludes": ["local_profile"],
    });
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    format!("pb_{:x}", Sha256::digest(&bytes))
}

const POLICY_VERSION_FOLDER: &str = "devguard_policy_versions";

/// Persist a versioned snapshot for rollback (DG-06). Keeps last 20 per agent.
pub fn store_policy_version(
    es: &mut dyn connector_engine::engine_store::EngineStore,
    agent_pid: &str,
    record: &serde_json::Value,
) {
    let bundle_id = record
        .get("policy_bundle_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let key = format!("{agent_pid}:{bundle_id}");
    let mut snap = record.clone();
    if let Some(obj) = snap.as_object_mut() {
        obj.insert(
            "versioned_at".into(),
            serde_json::json!(chrono::Utc::now().to_rfc3339()),
        );
        obj.insert(
            "honesty".into(),
            serde_json::json!(
                "Version log for rollback — local-profile is never a policy source (DG-06/DG-08)"
            ),
        );
    }
    let _ = es.folder_put(POLICY_VERSION_FOLDER, &key, &snap);

    // Trim older than 20 for this agent.
    let keys = es
        .folder_keys(POLICY_VERSION_FOLDER, None)
        .unwrap_or_default();
    let mut mine: Vec<String> = keys
        .into_iter()
        .filter(|k| k.starts_with(&format!("{agent_pid}:")))
        .collect();
    if mine.len() > 20 {
        mine.sort();
        let excess = mine.len() - 20;
        for old in mine.into_iter().take(excess) {
            let _ = es.folder_delete(POLICY_VERSION_FOLDER, &old);
        }
    }
}

/// POST /api/v1/devguard/policy/history — list versioned bundles for an agent.
pub async fn policy_history(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let es = match crate::util_lock::mutex_lock(&state.engine_store, "engine_store") {
        Ok(g) => g,
        Err(e) => {
            return Json(serde_json::json!({ "ok": false, "error": e, "status": 503 }));
        }
    };
    let keys = es
        .folder_keys(POLICY_VERSION_FOLDER, None)
        .unwrap_or_default();
    let mut versions = Vec::new();
    for k in keys {
        if !k.starts_with(&format!("{agent_pid}:")) {
            continue;
        }
        if let Ok(Some(v)) = es.folder_get(POLICY_VERSION_FOLDER, &k) {
            versions.push(serde_json::json!({
                "key": k,
                "policy_bundle_id": v.get("policy_bundle_id"),
                "role": v.get("role"),
                "source": v.get("source"),
                "versioned_at": v.get("versioned_at").or_else(|| v.get("loaded_at")),
            }));
        }
    }
    versions.sort_by(|a, b| {
        let aa = a.get("versioned_at").and_then(|x| x.as_str()).unwrap_or("");
        let bb = b.get("versioned_at").and_then(|x| x.as_str()).unwrap_or("");
        bb.cmp(aa)
    });
    Json(serde_json::json!({
        "ok": true,
        "agent_pid": agent_pid,
        "versions": versions,
        "count": versions.len(),
        "schema": "connector.devguard_policy_bundle.v1",
        "honesty": "local-profile is excluded from enforcement and from these fingerprints",
    }))
}

/// POST /api/v1/devguard/policy/rollback — restore a prior bundle by policy_bundle_id.
pub async fn policy_rollback(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("");
    let bundle_id = req
        .get("policy_bundle_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if agent_pid.is_empty() || bundle_id.is_empty() {
        return Json(serde_json::json!({
            "ok": false,
            "error": "agent_pid and policy_bundle_id required",
        }));
    }
    let key = format!("{agent_pid}:{bundle_id}");
    let mut es = match crate::util_lock::mutex_lock(&state.engine_store, "engine_store") {
        Ok(g) => g,
        Err(e) => {
            return Json(serde_json::json!({ "ok": false, "error": e, "status": 503 }));
        }
    };
    let Some(mut snap) = es.folder_get(POLICY_VERSION_FOLDER, &key).ok().flatten() else {
        return Json(serde_json::json!({
            "ok": false,
            "error": "version_not_found",
            "agent_pid": agent_pid,
            "policy_bundle_id": bundle_id,
        }));
    };
    if let Some(obj) = snap.as_object_mut() {
        obj.insert(
            "loaded_at".into(),
            serde_json::json!(chrono::Utc::now().to_rfc3339()),
        );
        obj.insert("rolled_back".into(), serde_json::json!(true));
        obj.insert(
            "source".into(),
            serde_json::json!(format!(
                "rollback:{}",
                obj.get("source")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown")
            )),
        );
    }
    let _ = es.folder_put("devguard_policies", agent_pid, &snap);
    store_policy_version(es.as_mut(), agent_pid, &snap);
    Json(serde_json::json!({
        "ok": true,
        "agent_pid": agent_pid,
        "policy_bundle_id": bundle_id,
        "rolled_back": true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_chaining_is_never_an_allow_match() {
        assert!(!command_matches("git status", "git status && rm -rf /"));
        assert!(!command_matches("git*", "git status || cat /etc/passwd"));
        assert!(!command_matches("git status", "git status; id"));
        assert!(!command_matches("echo", "echo $(whoami)"));
        assert!(command_matches("git status", "git status"));
        assert!(command_matches("git status", "git status --short"));
        assert!(command_matches("git*", "git status"));
    }

    #[test]
    fn check_exec_denies_shell_meta_before_allowlist() {
        let policy = DevGuardPolicy::default();
        let check = policy.check_exec("reader", "git status && rm -rf /");
        assert!(!check.allowed);
        assert!(check.reason.contains("shell"));
    }

    #[test]
    fn glob_match_rejects_parent_dir_traversal() {
        assert!(!glob_match("**/*", "../etc/passwd"));
        assert!(!glob_match("src/**", "src/../../etc/passwd"));
        assert!(glob_match("src/**", "src/main.rs"));
    }

    #[test]
    fn policy_bundle_id_is_stable_and_role_sensitive() {
        let p = DevGuardPolicy::default();
        let a = policy_bundle_id(&p, "junior");
        let b = policy_bundle_id(&p, "junior");
        let c = policy_bundle_id(&p, "senior");
        assert!(a.starts_with("pb_"));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn policy_bundle_source_changes_fingerprint() {
        let p = DevGuardPolicy::default();
        let a = policy_bundle_id_with_source(&p, "junior", "yaml_load");
        let b = policy_bundle_id_with_source(&p, "junior", "owner_roles_compile");
        assert_ne!(a, b);
    }
}
