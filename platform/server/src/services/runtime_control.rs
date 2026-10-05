use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use chrono::{Duration, Utc};
use connector_engine::engine_store::EngineStore;
use serde::{Deserialize, Serialize};

use crate::{
    auth::{self, PlatformRole},
    binary_id,
    license::LicenseInfo,
    state::SharedState,
};

const RUNTIME_FOLDER: &str = "_runtime_control";
const RUNTIME_MODE_KEY: &str = "mode";
const ISOLATION_RUNTIME_KEY: &str = "isolation_runtime";
const RUNTIME_POLICY_KEY: &str = "policy";

/// Dev runtime: free tier agent ceiling (Ring-0 + HTTP gates). Product default; not raised by license.
pub const DEV_RUNTIME_FREE_AGENT_MAX: u32 = 3;

/// Dev agent cap: default [`DEV_RUNTIME_FREE_AGENT_MAX`], overridable via `CONNECTOR_DEV_AGENT_CAP`
/// (clamped 1..=64) for court/soak gates that register many short-lived agents on one node.
pub fn dev_runtime_agent_cap() -> u32 {
    std::env::var("CONNECTOR_DEV_AGENT_CAP")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEV_RUNTIME_FREE_AGENT_MAX)
        .clamp(1, 64)
}
const PILOT_FOLDER: &str = "_pilot_access";
const PACKAGE_LEDGER_FOLDER: &str = "_package_identity";
const ACTIVATION_KEY: &str = "activation";

/// How [`apply_runtime_mode`] should treat process environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeModeApplySource {
    /// Values loaded from the engine store at process start. Preserves a lab shell when
    /// `connector_profile` / the operator already set `CONNECTOR_ENV=development` (e.g.
    /// `CONNECTOR_PRESET=local`) even if the persisted control-plane mode is production.
    InitialBoot,
    /// Admin activation or runtime switch — always sync `CONNECTOR_*` env to the requested mode.
    OperatorAction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Dev,
    Pilots,
    Production,
}

/// Execution backend for plugin / lab workloads (Phase 5.1–5.3).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IsolationRuntime {
    /// Legacy name — same execution class as [`Subprocess`](Self::Subprocess).
    Internal,
    /// Default in **dev**: separate OS process (`tokio::process` + process group on Unix).
    Subprocess,
    /// Lab convenience: `docker run` (Section 5.2).
    DockerLab,
    /// Production target: Firecracker microVM (stub until 5.3.x completes).
    Microvm,
    /// Wasmtime + WASI preview1 for `.wasm` plugin binaries (Phase **5.6**).
    Wasm,
}

impl IsolationRuntime {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::Subprocess => "subprocess",
            Self::DockerLab => "docker_lab",
            Self::Microvm => "microvm",
            Self::Wasm => "wasm",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "internal" => Some(Self::Internal),
            "subprocess" | "proc" | "process" => Some(Self::Subprocess),
            "docker_lab" | "docker-lab" | "docker" => Some(Self::DockerLab),
            "microvm" | "firecracker" | "fc" => Some(Self::Microvm),
            "wasm" | "wasmtime" | "wasi" => Some(Self::Wasm),
            _ => None,
        }
    }
}

pub fn load_runtime_policy(es: &(dyn EngineStore + Send)) -> RuntimePolicy {
    es.folder_get(RUNTIME_FOLDER, RUNTIME_POLICY_KEY)
        .ok()
        .flatten()
        .and_then(|value| serde_json::from_value::<RuntimePolicy>(value).ok())
        .map(|mut p| {
            p.kecs_suspend_threshold = p.kecs_suspend_threshold.clamp(0.05, 0.99);
            p.dev_agent_limit = p.dev_agent_limit.max(1).min(dev_runtime_agent_cap());
            p
        })
        .unwrap_or_default()
}

pub fn persist_runtime_policy(es: &mut (dyn EngineStore + Send), policy: &RuntimePolicy) {
    let _ = es.folder_put(
        RUNTIME_FOLDER,
        RUNTIME_POLICY_KEY,
        &serde_json::to_value(policy).unwrap_or_default(),
    );
}

pub fn effective_agent_limit(mode: RuntimeMode, license_tier: &str, policy: &RuntimePolicy) -> u32 {
    match mode {
        RuntimeMode::Dev => {
            let cap = dev_runtime_agent_cap();
            // CONNECTOR_DEV_AGENT_CAP raises the effective Dev limit for court/soak gates
            // (stored policy alone stays at the free default of 3).
            if std::env::var("CONNECTOR_DEV_AGENT_CAP").is_ok() {
                cap
            } else {
                policy.dev_agent_limit.max(1).min(cap)
            }
        }
        RuntimeMode::Pilots => policy.pilot_agent_limit,
        RuntimeMode::Production => match license_tier.trim().to_ascii_lowercase().as_str() {
            "growth" => policy.growth_agent_limit,
            "business" | "scale" => policy.business_agent_limit,
            "enterprise" | "core" | "sovereign" => policy.enterprise_agent_limit,
            _ => policy.production_default_agent_limit,
        },
    }
}

fn apply_runtime_policy_update(policy: &mut RuntimePolicy, req: UpdateRuntimePolicyRequest) {
    if let Some(limit) = req.dev_agent_limit {
        policy.dev_agent_limit = limit.max(1).min(dev_runtime_agent_cap());
    }
    if let Some(limit) = req.pilot_agent_limit {
        policy.pilot_agent_limit = limit.max(1);
    }
    if let Some(limit) = req.production_default_agent_limit {
        policy.production_default_agent_limit = limit.max(1);
    }
    if let Some(limit) = req.growth_agent_limit {
        policy.growth_agent_limit = limit.max(1);
    }
    if let Some(limit) = req.business_agent_limit {
        policy.business_agent_limit = limit.max(1);
    }
    if let Some(limit) = req.enterprise_agent_limit {
        policy.enterprise_agent_limit = limit.max(1);
    }
    if let Some(th) = req.kecs_suspend_threshold {
        policy.kecs_suspend_threshold = th.clamp(0.05, 0.99);
    }
}

impl RuntimeMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Pilots => "pilots",
            Self::Production => "production",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "dev" | "development" => Some(Self::Dev),
            "pilots" | "pilot" => Some(Self::Pilots),
            "production" | "prod" => Some(Self::Production),
            _ => None,
        }
    }

    pub fn auth_type(&self) -> &'static str {
        match self {
            Self::Dev => "dev-bypass",
            Self::Pilots => "scoped-api-keys",
            Self::Production => "strict-jwt-api-key",
        }
    }

    pub fn debug_enabled(&self) -> bool {
        matches!(self, Self::Dev)
    }

    pub fn relaxed_policy(&self) -> bool {
        matches!(self, Self::Dev | Self::Pilots)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotRecord {
    pub pilot_id: String,
    pub name: String,
    pub email: String,
    pub phone: String,
    pub api_key: String,
    pub expires_at: String,
    pub access_scope: Vec<String>,
    pub mode: String,
    pub created_at: String,
    pub issued_by_user_id: String,
    pub issued_by_email: String,
    pub revoked: bool,
}

impl PilotRecord {
    pub fn is_expired(&self) -> bool {
        chrono::DateTime::parse_from_rfc3339(&self.expires_at)
            .map(|exp| Utc::now() > exp.with_timezone(&Utc))
            .unwrap_or(false)
    }

    pub fn masked_api_key(&self) -> String {
        if self.api_key.len() <= 10 {
            return "••••••".to_string();
        }
        format!(
            "{}••••{}",
            &self.api_key[..6],
            &self.api_key[self.api_key.len() - 4..]
        )
    }
}

#[derive(Debug, Deserialize)]
pub struct SetRuntimeModeRequest {
    pub mode: String,
}

#[derive(Debug, Deserialize)]
pub struct SetIsolationRuntimeRequest {
    pub runtime: String,
}

#[derive(Debug, Deserialize)]
pub struct CreatePilotRequest {
    pub name: String,
    pub email: String,
    pub phone: String,
    pub duration_months: u32,
    pub access_scope: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExtendPilotRequest {
    pub months: u32,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePilotScopeRequest {
    pub add: Option<Vec<String>>,
    pub remove: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessKeyKind {
    None,
    Pilot,
    Production,
}

impl AccessKeyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pilot => "pilot",
            Self::Production => "production",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageActivationRecord {
    pub package_id: String,
    pub machine_id: String,
    pub hostname: String,
    pub mode: String,
    pub key_kind: String,
    pub key_ref: String,
    pub active: bool,
    pub activated_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ActivateNodeRequest {
    pub mode: String,
    pub access_key: Option<String>,
    pub package_id: Option<String>,
    pub machine_id: Option<String>,
    pub hostname: Option<String>,
}

fn default_kecs_suspend_threshold() -> f64 {
    0.60
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimePolicy {
    pub dev_agent_limit: u32,
    pub pilot_agent_limit: u32,
    pub production_default_agent_limit: u32,
    pub growth_agent_limit: u32,
    pub business_agent_limit: u32,
    pub enterprise_agent_limit: u32,
    /// KECS score below this triggers auto-suspend in `kecs_suspend_sweep` (BF2-L02).
    #[serde(default = "default_kecs_suspend_threshold")]
    pub kecs_suspend_threshold: f64,
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self {
            // Tier limits per product spec:
            // dev/free/oss: 3, pilots: 30, general: 30, growth: 50, growth+: 100
            // mid-up: 200, mid-enterprise: 500, enterprise+: custom
            dev_agent_limit: 3,
            pilot_agent_limit: 30,
            production_default_agent_limit: 30, // general tier
            growth_agent_limit: 50,
            business_agent_limit: 100,   // growth+ tier
            enterprise_agent_limit: 500, // mid-enterprise
            kecs_suspend_threshold: default_kecs_suspend_threshold(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateRuntimePolicyRequest {
    pub dev_agent_limit: Option<u32>,
    pub pilot_agent_limit: Option<u32>,
    pub production_default_agent_limit: Option<u32>,
    pub growth_agent_limit: Option<u32>,
    pub business_agent_limit: Option<u32>,
    pub enterprise_agent_limit: Option<u32>,
    pub kecs_suspend_threshold: Option<f64>,
}

fn detect_key_kind(access_key: &str) -> Option<AccessKeyKind> {
    if access_key.is_empty() {
        return Some(AccessKeyKind::None);
    }
    if access_key.starts_with("cpk_pilot_") {
        return Some(AccessKeyKind::Pilot);
    }
    if access_key.starts_with("lic_") {
        return Some(AccessKeyKind::Production);
    }
    None
}

fn load_package_activation(
    es: &(dyn EngineStore + Send),
    package_id: &str,
) -> Option<PackageActivationRecord> {
    es.folder_get(PACKAGE_LEDGER_FOLDER, package_id)
        .ok()
        .flatten()
        .and_then(|value| serde_json::from_value::<PackageActivationRecord>(value).ok())
}

fn persist_package_activation(es: &mut (dyn EngineStore + Send), record: &PackageActivationRecord) {
    let _ = es.folder_put(
        PACKAGE_LEDGER_FOLDER,
        &record.package_id,
        &serde_json::to_value(record).unwrap_or_default(),
    );
    let _ = es.folder_put(
        RUNTIME_FOLDER,
        ACTIVATION_KEY,
        &serde_json::to_value(record).unwrap_or_default(),
    );
}

fn default_package_identity(req: &ActivateNodeRequest) -> (String, String, String) {
    let identity = binary_id::BinaryIdentity::from_env();
    let package_id = req
        .package_id
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(identity.binary_id);
    let machine_id = req
        .machine_id
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(identity.machine_id);
    let hostname = req
        .hostname
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(identity.hostname);
    (package_id, machine_id, hostname)
}

fn activation_status_payload(
    record: Option<PackageActivationRecord>,
    mode: RuntimeMode,
) -> serde_json::Value {
    match record {
        Some(record) => serde_json::json!({
            "ok": true,
            "active": record.active,
            "mode": mode.as_str(),
            "auth_type": mode.auth_type(),
            "package_id": record.package_id,
            "machine_id": record.machine_id,
            "hostname": record.hostname,
            "key_kind": record.key_kind,
            "key_ref": record.key_ref,
            "activated_at": record.activated_at,
            "last_seen_at": record.last_seen_at,
        }),
        None => serde_json::json!({
            "ok": true,
            "active": matches!(mode, RuntimeMode::Dev),
            "mode": mode.as_str(),
            "auth_type": mode.auth_type(),
            "key_kind": if matches!(mode, RuntimeMode::Dev) { "none" } else { "unactivated" },
        }),
    }
}

fn initial_boot_preserves_lab_process_env() -> bool {
    matches!(
        std::env::var("CONNECTOR_ENV")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "development" | "dev"
    )
}

pub fn apply_runtime_mode(mode: RuntimeMode, source: RuntimeModeApplySource) {
    match mode {
        RuntimeMode::Dev => {
            // Never clobber an already-productionish process env on boot from a
            // missing/legacy store row that defaulted to Dev.
            if source == RuntimeModeApplySource::InitialBoot
                && crate::connector_profile::is_productionish_env()
                && !initial_boot_preserves_lab_process_env()
            {
                tracing::warn!(
                    "runtime mode store says Dev but CONNECTOR_ENV is productionish; preserving process env"
                );
                return;
            }
            #[allow(unused_unsafe)]
            unsafe {
                std::env::set_var("CONNECTOR_DEV_MODE", "1");
                std::env::set_var("CONNECTOR_ENV", "dev");
            }
        }
        RuntimeMode::Pilots => {
            #[allow(unused_unsafe)]
            unsafe {
                std::env::remove_var("CONNECTOR_DEV_MODE");
                std::env::set_var("CONNECTOR_ENV", "pilots");
            }
            apply_production_substrate_defaults();
        }
        RuntimeMode::Production => {
            if source == RuntimeModeApplySource::InitialBoot
                && initial_boot_preserves_lab_process_env()
            {
                return;
            }
            #[allow(unused_unsafe)]
            unsafe {
                std::env::remove_var("CONNECTOR_DEV_MODE");
                std::env::set_var("CONNECTOR_ENV", "production");
            }
            apply_production_substrate_defaults();
        }
    }
}

/// Default production/pilots substrate knobs when not explicitly set by operator.
fn apply_production_substrate_defaults() {
    #[allow(unused_unsafe)]
    unsafe {
        if std::env::var("CONNECTOR_HANDOFF_REQUIRED").is_err() {
            std::env::set_var("CONNECTOR_HANDOFF_REQUIRED", "1");
        }
        if crate::services::kernel_host::kernel_enforce_enabled()
            && std::env::var("CONNECTOR_MCP_EGRESS_ENFORCE").is_err()
        {
            std::env::set_var("CONNECTOR_MCP_EGRESS_ENFORCE", "1");
        }
    }
}

pub fn env_flag_true(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

/// **Ultimate Free / community self-host:** no login wall in production — same handler behavior as dev bypass.
///
/// Enable with any of:
/// - `CONNECTOR_ULTIMATE_FREE=1`
/// - `CONNECTOR_FREE_TIER_OPEN_AUTH=1`
/// - `CONNECTOR_OPEN_AUTH=1`
/// - `CONNECTOR_LICENSE_TIER=ultimate_free` (or `ultimate-free`, `free`, `community_open`)
/// - `connector.yaml` → `connector.open_auth: true`
///
/// Always disabled when `CONNECTOR_DEFENSE_STRICT=1`.
pub fn free_tier_open_auth_enabled() -> bool {
    if defense_strict_enabled() {
        return false;
    }
    // Hosted trial uses per-email session keys, not "any Bearer".
    if crate::services::playground::is_playground_mode() {
        return false;
    }
    if env_flag_true("CONNECTOR_ULTIMATE_FREE")
        || env_flag_true("CONNECTOR_FREE_TIER_OPEN_AUTH")
        || env_flag_true("CONNECTOR_OPEN_AUTH")
    {
        return true;
    }
    matches!(
        std::env::var("CONNECTOR_LICENSE_TIER")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "ultimate_free" | "ultimate-free" | "free" | "community_open" | "open"
    )
}

/// Classic dev/lab bypass (`CONNECTOR_DEV_MODE` / `CONNECTOR_ENV=development`). Not active in production env.
fn classic_dev_auth_bypass_allowed() -> bool {
    if defense_strict_enabled() {
        return false;
    }
    // Playground must never inherit persisted RuntimeMode::Dev open-auth on 0.0.0.0.
    if crate::services::playground::is_playground_mode() {
        return false;
    }
    if let Ok(e) = std::env::var("CONNECTOR_ENV") {
        match e.trim().to_ascii_lowercase().as_str() {
            "production" | "prod" | "pilots" | "pilot" => return false,
            _ => {}
        }
    }
    if std::env::var("CONNECTOR_DEV_MODE").is_ok() {
        return true;
    }
    matches!(
        std::env::var("CONNECTOR_ENV")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "development" | "dev"
    )
}

/// Whether handlers may use **open auth** (no JWT wall): dev/lab **or** Ultimate Free tier.
///
/// For **defense / sovereign / distributed** deployments set **`CONNECTOR_DEFENSE_STRICT=1`** to disable.
pub fn dev_auth_bypass_allowed() -> bool {
    if crate::services::playground::is_playground_mode() {
        return false;
    }
    free_tier_open_auth_enabled() || classic_dev_auth_bypass_allowed()
}

/// Dev runtime signup: relaxed password rules so internal testers can onboard quickly.
pub fn dev_signup_relaxed(state: &SharedState) -> bool {
    if defense_strict_enabled() {
        return false;
    }
    matches!(*state.runtime_mode.read().unwrap(), RuntimeMode::Dev)
}

/// Lab operator auth / dashboard: inject `data-dev` + Dev Bypass on the login page.
pub fn operator_lab_auth_gate(runtime_mode: RuntimeMode) -> bool {
    if defense_strict_enabled() {
        return false;
    }
    if free_tier_open_auth_enabled() {
        return true;
    }
    if !classic_dev_auth_bypass_allowed() {
        return false;
    }
    if matches!(runtime_mode, RuntimeMode::Dev) {
        return true;
    }
    matches!(
        std::env::var("CONNECTOR_ENV")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "development" | "dev"
    )
}

pub fn defense_strict_enabled() -> bool {
    std::env::var("CONNECTOR_DEFENSE_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Open auth (dev bypass / ultimate free) must not bind to non-loopback unless explicitly allowed.
pub fn reject_open_auth_non_loopback_bind(addr: &str) -> Result<(), String> {
    if !dev_auth_bypass_allowed() {
        return Ok(());
    }
    if std::env::var("CONNECTOR_ALLOW_OPEN_AUTH_NONLOCAL")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
    {
        return Ok(());
    }
    let host = addr
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']'))
        .unwrap_or(addr)
        .trim();
    let loopback = matches!(host, "127.0.0.1" | "::1" | "localhost") || host.starts_with("127.");
    if loopback {
        return Ok(());
    }
    Err(format!(
        "Open auth is enabled but bind address '{addr}' is not loopback. \
         Bind to 127.0.0.1, disable open auth, or set CONNECTOR_ALLOW_OPEN_AUTH_NONLOCAL=1 \
         (not recommended)."
    ))
}

#[cfg(test)]
mod open_auth_bind_tests {
    use super::*;

    #[test]
    fn loopback_allowed_under_open_auth() {
        std::env::set_var("CONNECTOR_OPEN_AUTH", "1");
        std::env::remove_var("CONNECTOR_DEFENSE_STRICT");
        std::env::remove_var("CONNECTOR_ALLOW_OPEN_AUTH_NONLOCAL");
        assert!(reject_open_auth_non_loopback_bind("127.0.0.1:9091").is_ok());
        std::env::remove_var("CONNECTOR_OPEN_AUTH");
    }

    #[test]
    fn nonlocal_rejected_under_open_auth() {
        std::env::set_var("CONNECTOR_OPEN_AUTH", "1");
        std::env::remove_var("CONNECTOR_DEFENSE_STRICT");
        std::env::remove_var("CONNECTOR_ALLOW_OPEN_AUTH_NONLOCAL");
        assert!(reject_open_auth_non_loopback_bind("0.0.0.0:9091").is_err());
        std::env::remove_var("CONNECTOR_OPEN_AUTH");
    }
}

pub fn load_runtime_mode_from_store(es: &(dyn EngineStore + Send)) -> RuntimeMode {
    es.folder_get(RUNTIME_FOLDER, RUNTIME_MODE_KEY)
        .ok()
        .flatten()
        .and_then(|value| {
            value
                .get("mode")
                .and_then(|v| v.as_str())
                .and_then(RuntimeMode::from_str)
        })
        .unwrap_or_else(default_runtime_mode_from_process_env)
}

/// When the store has no mode row, honor process env instead of forcing Dev.
fn default_runtime_mode_from_process_env() -> RuntimeMode {
    let env = std::env::var("CONNECTOR_ENV")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match env.as_str() {
        "production" | "prod" | "staging" => RuntimeMode::Production,
        "pilots" | "pilot" => RuntimeMode::Pilots,
        "development" | "dev" | "" => RuntimeMode::Dev,
        _ if crate::connector_profile::is_productionish_env() => RuntimeMode::Production,
        _ => RuntimeMode::Dev,
    }
}

pub fn persist_runtime_mode(es: &mut (dyn EngineStore + Send), mode: RuntimeMode) {
    let _ = es.folder_put(
        RUNTIME_FOLDER,
        RUNTIME_MODE_KEY,
        &serde_json::json!({
            "mode": mode.as_str(),
            "updated_at": Utc::now().to_rfc3339(),
        }),
    );
}

pub fn load_isolation_runtime_from_store(
    es: &(dyn EngineStore + Send),
    fallback: IsolationRuntime,
) -> IsolationRuntime {
    es.folder_get(RUNTIME_FOLDER, ISOLATION_RUNTIME_KEY)
        .ok()
        .flatten()
        .and_then(|value| {
            value
                .get("runtime")
                .and_then(|v| v.as_str())
                .and_then(IsolationRuntime::from_str)
        })
        .unwrap_or(fallback)
}

pub fn persist_isolation_runtime(es: &mut (dyn EngineStore + Send), runtime: IsolationRuntime) {
    let _ = es.folder_put(
        RUNTIME_FOLDER,
        ISOLATION_RUNTIME_KEY,
        &serde_json::json!({
            "runtime": runtime.as_str(),
            "updated_at": Utc::now().to_rfc3339(),
        }),
    );
}

/// True when a Firecracker binary is present. Production also requires `/dev/kvm`.
pub fn microvm_host_available() -> bool {
    let binary = firecracker_binary_present();
    if !binary {
        return false;
    }
    let production = matches!(
        std::env::var("CONNECTOR_ENV")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "production" | "prod" | "staging" | "airgap" | "defense-strict" | "unbypassable"
    ) || matches!(
        std::env::var("CONNECTOR_RUNTIME_MODE")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "production" | "pilots"
    );
    if !production {
        return true;
    }
    std::path::Path::new("/dev/kvm").exists()
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok()
}

fn firecracker_binary_present() -> bool {
    if let Ok(p) = std::env::var("CONNECTOR_FIRECRACKER_BIN") {
        let path = std::path::Path::new(p.trim());
        if path.is_file() {
            return true;
        }
    }
    std::process::Command::new("firecracker")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// In productionish modes, MicroVM without a host binary must not silently downgrade.
/// Returns Ok(effective_runtime) or Err(message) when fail-closed.
pub fn resolve_isolation_fail_closed(
    requested: IsolationRuntime,
    runtime_mode: RuntimeMode,
) -> Result<IsolationRuntime, String> {
    let prodish = matches!(runtime_mode, RuntimeMode::Production | RuntimeMode::Pilots)
        || defense_strict_enabled()
        || matches!(
            std::env::var("CONNECTOR_ENV")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "production" | "prod" | "staging" | "pilots" | "pilot"
        );
    if !prodish {
        return Ok(requested);
    }
    // Hosted playground: tenant namespaces on one shared VM — subprocess is intentional.
    if crate::services::playground::is_playground_mode() {
        if matches!(requested, IsolationRuntime::Microvm) && !microvm_host_available() {
            tracing::warn!(
                "playground: MicroVM unavailable on host — using subprocess (tenant session isolation)"
            );
            return Ok(IsolationRuntime::Subprocess);
        }
        if matches!(
            requested,
            IsolationRuntime::Subprocess | IsolationRuntime::Internal
        ) {
            return Ok(requested);
        }
    }
    if matches!(
        requested,
        IsolationRuntime::Subprocess | IsolationRuntime::Internal
    ) {
        if !env_flag_true("CONNECTOR_ALLOW_SUBPROCESS_ISOLATION") {
            return Err("isolation runtime=subprocess is denied in production. \
                 Use microvm or docker_lab, or set CONNECTOR_ALLOW_SUBPROCESS_ISOLATION=1 \
                 (break-glass only)."
                .into());
        }
    }
    if matches!(requested, IsolationRuntime::Microvm) && !microvm_host_available() {
        if env_flag_true("CONNECTOR_ALLOW_ISOLATION_DOWNGRADE") && !prodish {
            tracing::warn!(
                "MicroVM requested but Firecracker host unavailable — downgrading to subprocess \
                 because CONNECTOR_ALLOW_ISOLATION_DOWNGRADE=1"
            );
            return Ok(IsolationRuntime::Subprocess);
        }
        return Err(
            "isolation runtime=microvm but Firecracker host is unavailable. \
             Set CONNECTOR_FIRECRACKER_BIN, install firecracker, choose docker_lab, \
             or use CONNECTOR_ALLOW_ISOLATION_DOWNGRADE=1 in non-production only."
                .into(),
        );
    }
    if matches!(requested, IsolationRuntime::DockerLab) && !docker_available() {
        if env_flag_true("CONNECTOR_ALLOW_ISOLATION_DOWNGRADE") && !prodish {
            tracing::warn!(
                "DockerLab requested but docker unavailable — downgrading to subprocess \
                 because CONNECTOR_ALLOW_ISOLATION_DOWNGRADE=1"
            );
            return Ok(IsolationRuntime::Subprocess);
        }
        return Err(
            "isolation runtime=docker_lab but docker is unavailable. \
             Install docker, choose microvm, or use CONNECTOR_ALLOW_ISOLATION_DOWNGRADE=1 in non-production only."
                .into(),
        );
    }
    Ok(requested)
}

pub fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn apply_isolation_runtime(runtime: IsolationRuntime) {
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("CONNECTOR_ISOLATION_RUNTIME", runtime.as_str());
        std::env::set_var(
            "CONNECTOR_DOCKER_LAB_AVAILABLE",
            if docker_available() { "1" } else { "0" },
        );
    }
}

pub fn load_pilots(es: &(dyn EngineStore + Send)) -> Vec<PilotRecord> {
    let keys = es.folder_keys(PILOT_FOLDER, None).unwrap_or_default();
    let mut pilots: Vec<PilotRecord> = keys
        .iter()
        .filter_map(|key| es.folder_get(PILOT_FOLDER, key).ok().flatten())
        .filter_map(|value| serde_json::from_value::<PilotRecord>(value).ok())
        .collect();
    pilots.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    pilots
}

pub fn register_pilot_api_keys(es: &(dyn EngineStore + Send)) {
    for pilot in load_pilots(es) {
        if pilot.revoked || pilot.is_expired() {
            continue;
        }
        auth::register_api_key(
            &pilot.api_key,
            &pilot.pilot_id,
            pilot.access_scope.clone(),
            Some(pilot.expires_at.clone()),
        );
    }
}

fn persist_pilot(es: &mut (dyn EngineStore + Send), pilot: &PilotRecord) {
    let _ = es.folder_put(
        PILOT_FOLDER,
        &pilot.pilot_id,
        &serde_json::to_value(pilot).unwrap_or_default(),
    );
}

fn require_admin(headers: &HeaderMap) -> Result<auth::Claims, serde_json::Value> {
    if std::env::var("CONNECTOR_ENV")
        .ok()
        .as_deref()
        .and_then(RuntimeMode::from_str)
        .map(|mode| matches!(mode, RuntimeMode::Dev))
        .unwrap_or_else(|| std::env::var("CONNECTOR_DEV_MODE").is_ok())
    {
        return Ok(auth::Claims {
            sub: "dev-admin".to_string(),
            email: "dev@connector.local".to_string(),
            role: PlatformRole::Admin.to_str().to_string(),
            permissions: PlatformRole::SuperAdmin.permissions(),
            instance_id: None,
            tenant_id: std::env::var("CONNECTOR_DEFAULT_TENANT_ID").ok(),
            token_type: "dev".to_string(),
            jti: "dev-runtime-control".to_string(),
            iat: 0,
            exp: usize::MAX,
        });
    }

    let claims = auth::extract_claims(headers).ok_or_else(|| {
        serde_json::json!({
            "ok": false,
            "error": "Unauthorized",
        })
    })?;

    let role = PlatformRole::from_str(&claims.role);
    if role.rank() < PlatformRole::Admin.rank() {
        return Err(serde_json::json!({
            "ok": false,
            "error": "Admin privileges required",
        }));
    }

    Ok(claims)
}

fn scopes_are_valid(scopes: &[String]) -> bool {
    scopes.iter().all(|scope| {
        matches!(
            scope.as_str(),
            "login" | "auth" | "chat" | "tools" | "memory" | "audit"
        )
    })
}

pub fn pilot_scope_allows(path: &str, method: &str, scopes: &[String]) -> bool {
    let path = path.strip_prefix("/api/v1").unwrap_or(path);
    let allows = |scope: &str| scopes.iter().any(|value| value == scope);

    if path.starts_with("/auth") {
        return allows("login") || allows("auth");
    }
    if path.starts_with("/gateway") || path.starts_with("/playground") {
        return allows("chat");
    }
    if path.starts_with("/tools") || path.starts_with("/protocols") {
        return allows("tools");
    }
    if path.starts_with("/memory") || path.starts_with("/context") {
        return allows("memory");
    }
    if path.starts_with("/actionlog")
        || path.starts_with("/history")
        || path.starts_with("/monitor")
    {
        return method == "GET" && allows("audit");
    }

    true
}

pub async fn get_runtime_mode(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let mode = *state.runtime_mode.read().unwrap();
    let isolation_runtime = *state.isolation_runtime.read().unwrap();
    let first_run_needs_setup = {
        let users = state.user_store.lock().unwrap();
        users.users.is_empty()
    };
    let (activation, policy) = {
        let es = state.engine_store.lock().unwrap();
        (
            es.folder_get(RUNTIME_FOLDER, ACTIVATION_KEY)
                .ok()
                .flatten()
                .and_then(|value| serde_json::from_value::<PackageActivationRecord>(value).ok()),
            load_runtime_policy(&**es),
        )
    };
    Json(serde_json::json!({
        "ok": true,
        "mode": mode.as_str(),
        "isolation_runtime": isolation_runtime.as_str(),
        "docker_available": docker_available(),
        "auth_type": mode.auth_type(),
        "debug_enabled": mode.debug_enabled(),
        "relaxed_policy": mode.relaxed_policy(),
        "banner": if first_run_needs_setup {
            serde_json::json!({
                "show": true,
                "level": "info",
                "title": "First-run setup pending",
                "message": "Create or verify SuperAdmin and plugin admin tokens before switching to production."
            })
        } else {
            serde_json::json!({"show": false})
        },
        "agent_limit": crate::services::agents::resolved_kernel_agent_cap(state.as_ref()),
        "policy": policy,
        "activation": activation,
    }))
}

pub async fn get_runtime_policy(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    if require_admin(&headers).is_err() {
        return Json(serde_json::json!({"ok": false, "error": "Admin privileges required"}));
    }
    let es = state.engine_store.lock().unwrap();
    let policy = load_runtime_policy(&**es);
    let dev_eject_suspended = std::env::var("CONNECTOR_DEV_EJECT_SUSPENDED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    Json(serde_json::json!({
        "ok": true,
        "policy": policy,
        "server_env": {
            "CONNECTOR_DEV_EJECT_SUSPENDED": dev_eject_suspended,
            "note": "When true, Dev mode may evict Suspended agents to free slots (BF2-G02)"
        }
    }))
}

pub async fn update_runtime_policy(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<UpdateRuntimePolicyRequest>,
) -> Json<serde_json::Value> {
    if require_admin(&headers).is_err() {
        return Json(serde_json::json!({"ok": false, "error": "Admin privileges required"}));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "runtime",
        "runtime",
        "update_runtime_policy",
        &serde_json::json!({"policy": "update"}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mut es = state.engine_store.lock().unwrap();
    let mut policy = load_runtime_policy(&**es);
    apply_runtime_policy_update(&mut policy, req);
    persist_runtime_policy(&mut **es, &policy);
    drop(es);
    crate::services::agents::sync_kernel_agent_registration_cap(state.as_ref());
    open_proceed.finish_observed(true);
    Json(serde_json::json!({
        "ok": true,
        "policy": policy,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

pub async fn get_activation_status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let mode = *state.runtime_mode.read().unwrap();
    let record = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get(RUNTIME_FOLDER, ACTIVATION_KEY)
            .ok()
            .flatten()
            .and_then(|value| serde_json::from_value::<PackageActivationRecord>(value).ok())
    };
    Json(activation_status_payload(record, mode))
}

pub async fn activate_node(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<ActivateNodeRequest>,
) -> Json<serde_json::Value> {
    if let Err(err) = require_admin(&headers) {
        return Json(err);
    }
    let Some(mode) = RuntimeMode::from_str(&req.mode) else {
        return Json(
            serde_json::json!({"ok": false, "error": "Invalid mode. Use dev, pilots, or production"}),
        );
    };

    let access_key = req.access_key.clone().unwrap_or_default();
    let Some(key_kind) = detect_key_kind(&access_key) else {
        return Json(serde_json::json!({
            "ok": false,
            "error": "Unsupported access key format",
            "expected_prefixes": ["cpk_pilot_", "lic_"],
        }));
    };

    if matches!(mode, RuntimeMode::Pilots) && !matches!(key_kind, AccessKeyKind::Pilot) {
        return Json(
            serde_json::json!({"ok": false, "error": "Pilots mode requires a cpk_pilot_ key"}),
        );
    }
    if matches!(mode, RuntimeMode::Production) && !matches!(key_kind, AccessKeyKind::Production) {
        return Json(
            serde_json::json!({"ok": false, "error": "Production mode requires a lic_ key"}),
        );
    }
    if !matches!(mode, RuntimeMode::Dev) && access_key.trim().is_empty() {
        return Json(
            serde_json::json!({"ok": false, "error": "An activation key is required for pilots or production"}),
        );
    }

    let (package_id, machine_id, hostname) = default_package_identity(&req);
    let now = Utc::now().to_rfc3339();

    let key_ref = match mode {
        RuntimeMode::Dev => "dev-boot".to_string(),
        RuntimeMode::Pilots => {
            let es = state.engine_store.lock().unwrap();
            let Some(pilot) = load_pilots(&**es)
                .into_iter()
                .find(|pilot| pilot.api_key == access_key)
            else {
                return Json(serde_json::json!({"ok": false, "error": "Pilot key not found"}));
            };
            if pilot.revoked || pilot.is_expired() {
                return Json(
                    serde_json::json!({"ok": false, "error": "Pilot key is revoked or expired"}),
                );
            }
            pilot.pilot_id
        }
        RuntimeMode::Production => match LicenseInfo::try_validate_key(&access_key) {
            Ok(validated) => validated.instance_id,
            Err(_) => {
                return Json(serde_json::json!({
                    "ok": false,
                    "error": "Invalid or unsigned production license key",
                }));
            }
        },
    };

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "runtime",
        "runtime",
        "activate_node",
        &serde_json::json!({"mode": mode.as_str(), "package_id": package_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    if let Some(existing) = load_package_activation(&**es, &package_id) {
        let same_location = existing.machine_id == machine_id && existing.hostname == hostname;
        if existing.active && !same_location {
            drop(es);
            open_proceed.finish_observed(false);
            return Json(serde_json::json!({
                "ok": false,
                "error": "Package identity is already active on another machine",
                "package_id": package_id,
                "current_machine_id": existing.machine_id,
                "current_hostname": existing.hostname,
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }));
        }
    }

    let record = PackageActivationRecord {
        package_id: package_id.clone(),
        machine_id,
        hostname,
        mode: mode.as_str().to_string(),
        key_kind: key_kind.as_str().to_string(),
        key_ref,
        active: true,
        activated_at: now.clone(),
        last_seen_at: now,
    };
    persist_package_activation(&mut **es, &record);
    drop(es);

    apply_runtime_mode(mode, RuntimeModeApplySource::OperatorAction);
    {
        let mut current = state.runtime_mode.write().unwrap();
        *current = mode;
    }
    {
        let mut es = state.engine_store.lock().unwrap();
        persist_runtime_mode(&mut **es, mode);
    }
    crate::services::agents::sync_kernel_agent_registration_cap(state.as_ref());
    open_proceed.finish_observed(true);

    let mut payload = activation_status_payload(Some(record), mode);
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("task_id".into(), serde_json::json!(admitted.task_id));
        obj.insert("executed".into(), serde_json::json!(true));
        obj.insert("admits".into(), serde_json::json!(false));
    }
    Json(payload)
}

pub async fn set_runtime_mode(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SetRuntimeModeRequest>,
) -> Json<serde_json::Value> {
    if require_admin(&headers).is_err() {
        return Json(serde_json::json!({"ok": false, "error": "Admin privileges required"}));
    }

    let Some(mode) = RuntimeMode::from_str(&req.mode) else {
        return Json(
            serde_json::json!({"ok": false, "error": "Invalid mode. Use dev, pilots, or production"}),
        );
    };

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "runtime",
        "runtime",
        "set_runtime_mode",
        &serde_json::json!({"mode": mode.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    apply_runtime_mode(mode, RuntimeModeApplySource::OperatorAction);
    {
        let mut current = state.runtime_mode.write().unwrap();
        *current = mode;
    }
    {
        let mut es = state.engine_store.lock().unwrap();
        persist_runtime_mode(&mut **es, mode);
    }
    crate::services::agents::sync_kernel_agent_registration_cap(state.as_ref());
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "ok": true,
        "mode": mode.as_str(),
        "message": format!("Runtime mode switched to {}", mode.as_str()),
        "hot_reloaded": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// TG-6: GET /runtime/isolation/:agent_pid — tier + applied_truth (per agent).
pub async fn get_agent_isolation_tier(
    State(state): State<SharedState>,
    axum::extract::Path(agent_pid): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    Json(crate::kernel::isolation_tiers::isolation_for_agent(
        state.as_ref(),
        &agent_pid,
    ))
}

pub async fn get_isolation_runtime(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let runtime = *state.isolation_runtime.read().unwrap();
    let phase5_operator = serde_json::json!({
        "isolation_runtime": runtime.as_str(),
        "tier_idle_suspend_policy_after_ms": state.plugin_tier_scheduler.idle_suspend_policy_after_ms(),
        "docker_lab_egress": crate::services::phase5_operator_env::docker_lab_egress_mode_label(),
        "docker_lab_egress_enforce": crate::services::phase5_operator_env::docker_lab_egress_enforce_label(),
        "microvm_egress_enforce": crate::services::phase5_operator_env::microvm_egress_enforce_label(),
        "microvm_egress_enforce_required": crate::services::phase5_operator_env::microvm_egress_enforce_required_label(),
        "microvm_guest_iface": crate::services::phase5_operator_env::microvm_guest_iface_label(),
        "plugin_subprocess_seccomp": crate::services::phase5_operator_env::plugin_subprocess_seccomp_label(),
        "plugin_subprocess_seccomp_intent": crate::services::phase5_operator_env::plugin_subprocess_seccomp_intent_label_from_raw(
            &std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT").unwrap_or_default()
        ),
        "plugin_subprocess_seccomp_resolution": crate::services::phase5_operator_env::plugin_subprocess_seccomp_resolution(),
        "connectorctl_plugin_run_backend": crate::services::phase5_operator_env::connectorctl_plugin_run_backend_label(),
        "supervisor_node_crash_plugin_id": crate::services::phase5_operator_env::supervisor_node_crash_plugin_id_label(),
        "microvm_tier_state_file": crate::services::phase5_operator_env::microvm_tier_state_file_operator_label(),
        "microvm_tier_state_sync": crate::services::phase5_operator_env::microvm_tier_state_sync_operator_label(),
        "connect_connector_env": crate::services::phase5_operator_env::connect_connector_env_label(),
        "connect_env_production_like": crate::services::phase5_operator_env::connect_env_production_like(),
        "connect_dev_mode_truthy": crate::services::phase5_operator_env::connect_dev_mode_truthy(),
        "connect_production_reject_dev_mode_truthy": crate::services::phase5_operator_env::connect_production_reject_dev_mode_truthy(),
        "production_dev_mode_hygiene": crate::services::phase5_operator_env::production_dev_mode_hygiene_level(),
    });
    let phase5_preflight_warnings =
        crate::services::phase5_operator_env::phase5_preflight_warnings_from_operator(
            &phase5_operator,
        );
    let phase5_preflight_warning_count = phase5_preflight_warnings.len();
    let phase5_preflight_warning_level =
        crate::services::phase5_operator_env::phase5_preflight_warning_level_from_warnings(
            &phase5_preflight_warnings,
        );
    Json(serde_json::json!({
        "ok": true,
        "runtime": runtime.as_str(),
        "docker_available": docker_available(),
        "core_services_docker_required": false,
        "operator_env": {
            "docker_lab_egress": crate::services::phase5_operator_env::docker_lab_egress_mode_label(),
            "docker_lab_egress_enforce": crate::services::phase5_operator_env::docker_lab_egress_enforce_label(),
            "microvm_egress_enforce": crate::services::phase5_operator_env::microvm_egress_enforce_label(),
            "microvm_egress_enforce_required": crate::services::phase5_operator_env::microvm_egress_enforce_required_label(),
            "microvm_guest_iface": crate::services::phase5_operator_env::microvm_guest_iface_label(),
            "plugin_subprocess_seccomp": crate::services::phase5_operator_env::plugin_subprocess_seccomp_label(),
            "plugin_subprocess_seccomp_intent": crate::services::phase5_operator_env::plugin_subprocess_seccomp_intent_label_from_raw(
                &std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT").unwrap_or_default()
            ),
            "plugin_subprocess_seccomp_resolution": crate::services::phase5_operator_env::plugin_subprocess_seccomp_resolution(),
            "connectorctl_plugin_run_backend": crate::services::phase5_operator_env::connectorctl_plugin_run_backend_label(),
            "supervisor_node_crash_plugin_id": crate::services::phase5_operator_env::supervisor_node_crash_plugin_id_label(),
            "microvm_tier_state_file": crate::services::phase5_operator_env::microvm_tier_state_file_operator_label(),
            "microvm_tier_state_sync": crate::services::phase5_operator_env::microvm_tier_state_sync_operator_label(),
            "tier_idle_suspend_policy_after_ms": state.plugin_tier_scheduler.idle_suspend_policy_after_ms(),
        },
        "phase_5_operator_preflight_warnings": phase5_preflight_warnings,
        "phase_5_operator_preflight_warning_count": phase5_preflight_warning_count,
        "phase_5_operator_preflight_warning_level": phase5_preflight_warning_level,
        "phase_5": {
            "subprocess": "dev default when no persisted isolation_runtime (POST /api/v1/runtime/isolation)",
            "microvm": "production fallback when no persisted value; uses connector-microvm + vendored assets (5.3)",
            "tier_scheduler": "GET /api/v1/kernel/plugin-tier-scheduler — connectorctl tier show|admit|touch; status --json tier_scheduler; doctor --json doctor_extensions.tier_scheduler; dashboard Service Map #tier-scheduler + Plugins hub (lazy load)",
            "tier_idle_suspend_env": "CONNECTOR_PLUGIN_IDLE_SUSPEND_AFTER_MS (Warm/Hot→Cold after idle; 0=off; microVM guests also receive connector.plugin_idle_suspend_after_ms on kernel cmdline when >0)",
            "docker_lab_egress_env": "CONNECTOR_DOCKER_LAB_EGRESS=unrestricted|deny_all|allowlist_strict (plugin-runtime docker spawn)",
            "docker_lab_egress_enforce_env": "CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE=iptables (Linux; iptables+ip6tables DOCKER-USER when IPv6 caps; foreground or detached + docker wait)",
            "microvm_egress_env": "CONNECTOR_MICROVM_EGRESS_MODE=deny_all|allowlist_strict|custom (deny_all rejects outbound caps; allowlist_strict requires valid non-wildcard network.outbound list)",
            "microvm_egress_enforce_env": "CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables (Linux Firecracker: TAP + ip= + iptables FORWARD TCPv4 + MASQUERADE; AAAA caps add ip6tables TCPv6 + NAT MASQUERADE + guest ULA via connector.microvm_guest_ipv6 / vm-agent ip -6 addr; host needs routable IPv6; optional CONNECTOR_MICROVM_ALLOW_RESOLVER_DNS)",
            "microvm_egress_enforce_required_env": "CONNECTOR_MICROVM_EGRESS_ENFORCE_REQUIRED=1 (fail-closed when egress enforce is requested but unavailable on this host path)",
            "microvm_guest_iface_env": "CONNECTOR_MICROVM_GUEST_IFACE=eth0 (optional; when IPv6 TAP egress is active, sets connector.microvm_guest_iface for vm-agent static ULA)",
            "subprocess_seccomp_env": "CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP=off|strict|deny_dangerous|network_deny|network_ingress_deny (Linux; deny_* available on x86_64/aarch64)",
            "subprocess_seccomp_intent_env": "CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT=off|strict|safe_default|no_network|no_ingress (takes precedence over CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP)",
            "wasm_env": "CONNECTOR_PLUGIN_RUN_BACKEND=wasm (connectorctl); CONNECTOR_WASM_FUEL_UNITS optional fuel budget (connector-plugin-runtime wasm backend)",
            "microvm_assets_env": "CONNECTOR_FIRECRACKER_BIN, CONNECTOR_MICROVM_KERNEL, CONNECTOR_MICROVM_ROOTFS, CONNECTOR_VM_AGENT_GUEST_PATH, CONNECTOR_WSL_DISTRO, CONNECTOR_MICROVM_WSL_STATE_DIR, CONNECTOR_WSL_PYTHON, CONNECTOR_WSL_LAUNCHER, CONNECTOR_MACOS_VZ_SIDECAR",
            "subprocess_cgroup_v2_env": "CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PARENT, CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_MAX_BYTES, CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_HIGH_BYTES, CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_SWAP_MAX_BYTES, CONNECTOR_PLUGIN_SUBPROCESS_CPU_PCT, CONNECTOR_PLUGIN_SUBPROCESS_CPU_WEIGHT, CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PIDS_MAX, CONNECTOR_PLUGIN_SUBPROCESS_IO_MAX, CONNECTOR_PLUGIN_SUBPROCESS_WORKSPACE_MAX_BYTES, CONNECTOR_PLUGIN_SUBPROCESS_WORKSPACE_MAX_ENFORCE, CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_ENFORCE, CONNECTOR_PLUGIN_TIER_CGROUP_SCAN",
            "supervisor_node_env": "CONNECTOR_SUPERVISOR_RESTART_MAX, CONNECTOR_SUPERVISOR_RESTART_BASE_MS, CONNECTOR_SUPERVISOR_RESTART_CAP_MS, CONNECTOR_SUPERVISOR_LOGS, CONNECTOR_SUPERVISOR_NODE_CRASH_PLUGIN_ID (optional; background connectorctl start → plugin-crash-recovery/record on non-success exit)",
            "microvm_tier_state_file_env": "CONNECTOR_MICROVM_TIER_STATE_FILE (optional JSON map vendor/slug→cold|warm; kernel periodic sync + immediate write on POST …/plugin-tier-touch|plugin-tier-admit); CONNECTOR_MICROVM_TIER_STATE_SYNC_MS (default 2000)",
            "plugins_status_operator": "GET /api/v1/plugins/status → phase_5_operator (connect_* + production_dev_mode_hygiene + process_env_operator_display_line; same labels as connectorctl status Process env (API))",
        },
    }))
}

pub async fn set_isolation_runtime(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SetIsolationRuntimeRequest>,
) -> Json<serde_json::Value> {
    if require_admin(&headers).is_err() {
        return Json(serde_json::json!({"ok": false, "error": "Admin privileges required"}));
    }
    let Some(runtime) = IsolationRuntime::from_str(&req.runtime) else {
        return Json(
            serde_json::json!({"ok": false, "error": "Invalid runtime. Use internal, subprocess, docker_lab, microvm, or wasm"}),
        );
    };

    let mode = *state.runtime_mode.read().unwrap();
    let runtime = match resolve_isolation_fail_closed(runtime, mode) {
        Ok(r) => r,
        Err(msg) => {
            return Json(serde_json::json!({
                "ok": false,
                "error": "isolation_fail_closed",
                "message": msg,
            }));
        }
    };

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "runtime",
        "runtime",
        "set_isolation_runtime",
        &serde_json::json!({"runtime": runtime.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    apply_isolation_runtime(runtime);
    {
        let mut current = state.isolation_runtime.write().unwrap();
        *current = runtime;
    }
    {
        let mut es = state.engine_store.lock().unwrap();
        persist_isolation_runtime(&mut **es, runtime);
    }
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "ok": true,
        "runtime": runtime.as_str(),
        "docker_available": docker_available(),
        "core_services_docker_required": false,
        "message": format!("Isolation runtime switched to {}", runtime.as_str()),
        "hot_reloaded": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

pub async fn list_pilots(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    if require_admin(&headers).is_err() {
        return Json(serde_json::json!({"ok": false, "error": "Admin privileges required"}));
    }

    let es = state.engine_store.lock().unwrap();
    let pilots: Vec<_> = load_pilots(&**es)
        .into_iter()
        .map(|pilot| {
            serde_json::json!({
                "pilot_id": pilot.pilot_id,
                "name": pilot.name,
                "email": pilot.email,
                "phone": pilot.phone,
                "api_key_masked": pilot.masked_api_key(),
                "expires_at": pilot.expires_at,
                "access_scope": pilot.access_scope,
                "mode": pilot.mode,
                "revoked": pilot.revoked,
                "expired": pilot.is_expired(),
                "created_at": pilot.created_at,
            })
        })
        .collect();

    Json(serde_json::json!({"ok": true, "pilots": pilots, "count": pilots.len()}))
}

pub async fn create_pilot(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CreatePilotRequest>,
) -> Json<serde_json::Value> {
    let claims = match require_admin(&headers) {
        Ok(claims) => claims,
        Err(_) => {
            return Json(serde_json::json!({"ok": false, "error": "Admin privileges required"}));
        }
    };

    let issuer_role = PlatformRole::from_str(&claims.role);
    if !matches!(issuer_role, PlatformRole::Admin | PlatformRole::SuperAdmin) {
        return Json(serde_json::json!({"ok": false, "error": "Admin privileges required"}));
    }

    if !(1..=6).contains(&req.duration_months) {
        return Json(
            serde_json::json!({"ok": false, "error": "duration_months must be between 1 and 6"}),
        );
    }
    if req.name.trim().is_empty() || req.email.trim().is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "name and email are required"}));
    }
    if !scopes_are_valid(&req.access_scope) {
        return Json(
            serde_json::json!({"ok": false, "error": "Unsupported pilot scope. Use login, auth, chat, tools, memory, or audit"}),
        );
    }

    let now = Utc::now();
    let pilot_id = format!("plt_{}", uuid::Uuid::new_v4().simple());
    let api_key = auth::generate_api_key("cpk_pilot");
    let expires_at = (now + Duration::days((req.duration_months as i64) * 30)).to_rfc3339();
    let pilot = PilotRecord {
        pilot_id: pilot_id.clone(),
        name: req.name.trim().to_string(),
        email: req.email.trim().to_string(),
        phone: req.phone.trim().to_string(),
        api_key: api_key.clone(),
        expires_at: expires_at.clone(),
        access_scope: req.access_scope.clone(),
        mode: RuntimeMode::Pilots.as_str().to_string(),
        created_at: now.to_rfc3339(),
        issued_by_user_id: claims.sub,
        issued_by_email: claims.email,
        revoked: false,
    };

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "runtime",
        "runtime",
        "create_pilot",
        &serde_json::json!({"pilot_id": pilot_id.as_str(), "duration_months": req.duration_months}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    {
        let mut es = state.engine_store.lock().unwrap();
        persist_pilot(&mut **es, &pilot);
    }
    auth::register_api_key(
        &api_key,
        &pilot_id,
        pilot.access_scope.clone(),
        Some(expires_at.clone()),
    );
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "ok": true,
        "pilot_id": pilot_id,
        "api_key": api_key,
        "expires_at": expires_at,
        "allowed_scopes": pilot.access_scope,
        "mode": "pilots",
        "issued_by": pilot.issued_by_email,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

pub async fn revoke_pilot(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pilot_id): Path<String>,
) -> Json<serde_json::Value> {
    if require_admin(&headers).is_err() {
        return Json(serde_json::json!({"ok": false, "error": "Admin privileges required"}));
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "runtime",
        "runtime",
        "revoke_pilot",
        &serde_json::json!({"pilot_id": pilot_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let Some(value) = es.folder_get(PILOT_FOLDER, &pilot_id).ok().flatten() else {
        drop(es);
        open_proceed.finish_observed(false);
        return Json(serde_json::json!({
            "ok": false,
            "error": "Pilot not found",
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
        }));
    };
    let Ok(mut pilot) = serde_json::from_value::<PilotRecord>(value) else {
        drop(es);
        open_proceed.finish_observed(false);
        return Json(serde_json::json!({
            "ok": false,
            "error": "Pilot record is corrupt",
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
        }));
    };
    pilot.revoked = true;
    persist_pilot(&mut **es, &pilot);
    auth::revoke_api_key(&pilot.api_key);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "ok": true,
        "pilot_id": pilot_id,
        "revoked": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

pub async fn extend_pilot(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pilot_id): Path<String>,
    Json(req): Json<ExtendPilotRequest>,
) -> Json<serde_json::Value> {
    if require_admin(&headers).is_err() {
        return Json(serde_json::json!({"ok": false, "error": "Admin privileges required"}));
    }
    if !(1..=6).contains(&req.months) {
        return Json(serde_json::json!({"ok": false, "error": "months must be between 1 and 6"}));
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "runtime",
        "runtime",
        "extend_pilot",
        &serde_json::json!({"pilot_id": pilot_id.as_str(), "months": req.months}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let Some(value) = es.folder_get(PILOT_FOLDER, &pilot_id).ok().flatten() else {
        drop(es);
        open_proceed.finish_observed(false);
        return Json(serde_json::json!({
            "ok": false,
            "error": "Pilot not found",
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
        }));
    };
    let Ok(mut pilot) = serde_json::from_value::<PilotRecord>(value) else {
        drop(es);
        open_proceed.finish_observed(false);
        return Json(serde_json::json!({
            "ok": false,
            "error": "Pilot record is corrupt",
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
        }));
    };

    let base = chrono::DateTime::parse_from_rfc3339(&pilot.expires_at)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let effective = if base < Utc::now() { Utc::now() } else { base };
    pilot.expires_at = (effective + Duration::days((req.months as i64) * 30)).to_rfc3339();
    persist_pilot(&mut **es, &pilot);
    auth::register_api_key(
        &pilot.api_key,
        &pilot.pilot_id,
        pilot.access_scope.clone(),
        Some(pilot.expires_at.clone()),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "ok": true,
        "pilot_id": pilot.pilot_id,
        "expires_at": pilot.expires_at,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

pub async fn update_pilot_scope(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pilot_id): Path<String>,
    Json(req): Json<UpdatePilotScopeRequest>,
) -> Json<serde_json::Value> {
    if require_admin(&headers).is_err() {
        return Json(serde_json::json!({"ok": false, "error": "Admin privileges required"}));
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "runtime",
        "runtime",
        "update_pilot_scope",
        &serde_json::json!({"pilot_id": pilot_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let Some(value) = es.folder_get(PILOT_FOLDER, &pilot_id).ok().flatten() else {
        drop(es);
        open_proceed.finish_observed(false);
        return Json(serde_json::json!({
            "ok": false,
            "error": "Pilot not found",
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
        }));
    };
    let Ok(mut pilot) = serde_json::from_value::<PilotRecord>(value) else {
        drop(es);
        open_proceed.finish_observed(false);
        return Json(serde_json::json!({
            "ok": false,
            "error": "Pilot record is corrupt",
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
        }));
    };

    let mut scopes = pilot.access_scope.clone();
    if let Some(add) = req.add {
        if !scopes_are_valid(&add) {
            drop(es);
            open_proceed.finish_observed(false);
            return Json(serde_json::json!({
                "ok": false,
                "error": "Unsupported scope in add list",
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }));
        }
        for scope in add {
            if !scopes.contains(&scope) {
                scopes.push(scope);
            }
        }
    }
    if let Some(remove) = req.remove {
        scopes.retain(|scope| !remove.contains(scope));
    }
    scopes.sort();
    scopes.dedup();
    pilot.access_scope = scopes;
    persist_pilot(&mut **es, &pilot);
    auth::register_api_key(
        &pilot.api_key,
        &pilot.pilot_id,
        pilot.access_scope.clone(),
        Some(pilot.expires_at.clone()),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "ok": true,
        "pilot_id": pilot.pilot_id,
        "access_scope": pilot.access_scope,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

#[cfg(test)]
mod open_auth_tests {
    use super::*;

    fn with_env<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(val) => unsafe { std::env::set_var(k, val) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
        f();
        for (k, prev) in saved {
            match prev {
                Some(v) => unsafe { std::env::set_var(&k, v) },
                None => unsafe { std::env::remove_var(&k) },
            }
        }
    }

    #[test]
    fn open_auth_policy_env_matrix() {
        with_env(
            &[
                ("CONNECTOR_ENV", Some("production")),
                ("CONNECTOR_DEV_MODE", None),
                ("CONNECTOR_ULTIMATE_FREE", Some("1")),
                ("CONNECTOR_DEFENSE_STRICT", None),
            ],
            || {
                assert!(free_tier_open_auth_enabled());
                assert!(dev_auth_bypass_allowed());
                assert!(!classic_dev_auth_bypass_allowed());
                assert!(operator_lab_auth_gate(RuntimeMode::Production));
            },
        );
        with_env(
            &[
                ("CONNECTOR_ULTIMATE_FREE", Some("1")),
                ("CONNECTOR_DEFENSE_STRICT", Some("1")),
            ],
            || {
                assert!(!free_tier_open_auth_enabled());
                assert!(!dev_auth_bypass_allowed());
            },
        );
    }
}
