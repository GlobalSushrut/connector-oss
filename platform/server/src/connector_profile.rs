//! Layered configuration: optional `connector.yaml` + `CONNECTOR_PRESET` (12 modes).
//! Precedence: explicit environment variables win; YAML and presets only fill gaps.
//!
//! Enterprise: set `CONNECTOR_CONFIG_STRICT=1` to fail boot on invalid YAML, oversize files,
//! or unknown presets. Set `CONNECTOR_ENFORCE_PRODUCTION_PRESETS=1` to reject dev-oriented
//! presets when `CONNECTOR_ENV` is production.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Maximum connector.yaml size (deny oversized / malicious files in strict mode; always enforced cap on read).
const MAX_CONNECTOR_YAML_BYTES: usize = 512 * 1024;

fn config_strict() -> bool {
    std::env::var("CONNECTOR_CONFIG_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn enforce_production_presets() -> bool {
    std::env::var("CONNECTOR_ENFORCE_PRODUCTION_PRESETS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Call once at process start, after tracing is initialized, before `PlatformConfig::from_env()`.
/// Exits the process on fatal config errors (strict mode or enterprise validation failure).
pub fn bootstrap_configuration() {
    if let Err(msg) = bootstrap_configuration_inner() {
        eprintln!("\n[connector config] FATAL: {msg}");
        eprintln!(
            "  Docs: platform/docs/CONNECTOR_CAGE_NODE_AND_PLUGINS.md (enterprise section). \
             For diagnostics, unset CONNECTOR_CONFIG_STRICT and CONNECTOR_ENFORCE_PRODUCTION_PRESETS. \
             Production + CONNECTOR_DEV_MODE: unset CONNECTOR_DEV_MODE or CONNECTOR_PRODUCTION_REJECT_DEV_MODE=1 (see connector.yaml.example)."
        );
        std::process::exit(1);
    }
}

fn bootstrap_configuration_inner() -> Result<(), String> {
    let strict = config_strict();

    if let Some(path) = resolve_config_path() {
        let meta = std::fs::metadata(&path)
            .map_err(|e| format!("CONNECTOR_CONFIG_FILE / connector.yaml: metadata: {e}"))?;
        let len = meta.len() as usize;
        if len > MAX_CONNECTOR_YAML_BYTES {
            return Err(format!(
                "connector config file exceeds {} KiB (got {} bytes): {}",
                MAX_CONNECTOR_YAML_BYTES / 1024,
                len,
                path.display()
            ));
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => apply_yaml(&content, path.display().to_string(), strict)?,
            Err(e) if strict => return Err(format!("could not read {}: {e}", path.display())),
            Err(e) => tracing::warn!(path = %path.display(), error = %e, "CONNECTOR: could not read config file"),
        }
    }

    apply_implicit_local_preset();
    apply_preset_from_env(strict)?;
    // U15 — VJ on whenever the node is production-like, even if preset was skipped.
    // Hosted trial uses CONNECTOR_ENV=pilots but must not inherit the setup-gate:
    // that leaves the seeded demo Registered and Talk returns agent_not_activated.
    let playground = std::env::var("CONNECTOR_PLAYGROUND")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
        || std::env::var("CONNECTOR_PRESET").map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "playground" | "trial" | "saas-trial"
            )
        })
        .unwrap_or(false);
    if is_productionish_env() && !playground {
        apply_production_hardening_defaults();
    }
    // Real augmented env (not lab): force production membrane + START_REFUSED when gates unmet.
    let augmented = std::env::var("CONNECTOR_AUGMENTED_ENV")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if augmented && !playground {
        apply_production_hardening_defaults();
        set_if_absent("CONNECTOR_HARDEN_REFUSE_START", "1");
        set_if_absent("CONNECTOR_SANDBOX_UNBYPASSABLE", "1");
        tracing::warn!(
            "CONNECTOR_AUGMENTED_ENV=1 — production hardening + harden refuse-start enabled"
        );
    }
    validate_production_preset_combination()?;
    validate_production_dev_mode_hygiene()?;
    validate_production_secrets_fail_closed()?;
    Ok(())
}

/// Production / defense-strict refuse lab defaults and mock runners (U1.1 / U1.2).
fn validate_production_secrets_fail_closed() -> Result<(), String> {
    if !prodish_secret_enforcement() {
        return Ok(());
    }

    if std::env::var("CONNECTOR_CAPS_ALLOW_MOCK")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
    {
        return Err(
            "CONNECTOR_CAPS_ALLOW_MOCK is set but production / defense-strict forbids mock capability runners. \
             Unset CONNECTOR_CAPS_ALLOW_MOCK."
                .into(),
        );
    }

    let audit = std::env::var("CONNECTOR_AUDIT_HMAC_KEY").unwrap_or_default();
    let audit = audit.trim();
    if audit.is_empty() {
        return Err(
            "CONNECTOR_AUDIT_HMAC_KEY is required under production / defense-strict (≥64 hex chars). \
             Lab default audit key is rejected."
                .into(),
        );
    }
    if audit.len() < 64 || !audit.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(
            "CONNECTOR_AUDIT_HMAC_KEY must be at least 64 hexadecimal characters (32-byte key)."
                .into(),
        );
    }

    let cfni = std::env::var("CONNECTOR_CFNI_SECRET").unwrap_or_default();
    if cfni.trim().is_empty() {
        return Err(
            "CONNECTOR_CFNI_SECRET is required under production / defense-strict \
             (do not fall back to JWT or connector-cfni-dev-only)."
                .into(),
        );
    }

    let cage = std::env::var("CONNECTOR_CAGE_CAP_SECRET").unwrap_or_default();
    if cage.trim().is_empty() {
        return Err(
            "CONNECTOR_CAGE_CAP_SECRET is required under production / defense-strict \
             (do not fall back to JWT or connector-cage-cap-dev-only)."
                .into(),
        );
    }

    let effect = std::env::var("CONNECTOR_EFFECT_AUTHZ_HMAC")
        .or_else(|_| std::env::var("CONNECTOR_AUDIT_HMAC_SECRET"))
        .or_else(|_| std::env::var("CONNECTOR_AUDIT_HMAC_KEY"))
        .unwrap_or_default();
    if effect.trim().is_empty() {
        return Err(
            "CONNECTOR_EFFECT_AUTHZ_HMAC (or CONNECTOR_AUDIT_HMAC_KEY) is required under \
             production / defense-strict; lab effect-authz key is rejected."
                .into(),
        );
    }

    Ok(())
}

fn prodish_secret_enforcement() -> bool {
    // Hosted trial is production-like for receipts, not for enterprise secret gates.
    // CONNECTOR_ENV=pilots would otherwise refuse to boot without CFNI/cage keys.
    let playground = std::env::var("CONNECTOR_PLAYGROUND")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
        || std::env::var("CONNECTOR_PRESET")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "playground" | "trial" | "saas-trial"))
            .unwrap_or(false);
    if playground {
        return false;
    }
    is_productionish_env()
}

/// True for production / prod / defense-strict / staging-like CONNECTOR_ENV.
pub fn is_productionish_env() -> bool {
    let env = std::env::var("CONNECTOR_ENV")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let defense = std::env::var("CONNECTOR_DEFENSE_STRICT")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    matches!(
        env.as_str(),
        "production" | "prod" | "staging" | "pilots" | "pilot"
    ) || defense
}

/// Apply hardening defaults shared by production-like presets (U2.1 / U5.1).
/// Linux unbypassable bar — FS Landlock, kernel enforce, eBPF/nft, vsock tickets, microVM.
fn apply_unbypassable_hardening_defaults() {
    set_if_absent("CONNECTOR_SANDBOX_UNBYPASSABLE", "1");
    set_if_absent("CONNECTOR_KERNEL_ENFORCE", "1");
    set_if_absent("CONNECTOR_FLOW_LEASE_ENFORCE", "1");
    set_if_absent("CONNECTOR_VSOCK_TICKET_REQUIRE", "1");
    set_if_absent("CONNECTOR_PEER_OVERLAY", "1");
    set_if_absent("CONNECTOR_EBPF_REQUIRE", "1");
    set_if_absent("CONNECTOR_MATRIX_HOST_EGRESS", "1");
    set_if_absent("CONNECTOR_CGROUP_ROOT", "/sys/fs/cgroup/connector");
    set_if_absent("CONNECTOR_TRANSPARENT_EGRESS", "1");
    set_if_absent("CONNECTOR_TRANSPARENT_EGRESS_KERNEL", "1");
    set_if_absent("CONNECTOR_EGRESS_PROXY_PORT", "19090");
    set_if_absent("CONNECTOR_EGRESS_TLS_TERMINATE", "1");
    set_if_absent("CONNECTOR_CONP_SIL_REQUIRE", "1");
    // T4 — abandon Pending on resume so restart cannot duplicate effects
    set_if_absent("CONNECTOR_MISSION_ABANDON_STALE_PENDING", "1");
    // T6 — no lab echo HAL under harden
    set_if_absent("CONNECTOR_CONP_LAB_ECHO", "0");
    // T7 — hosted MCP out-of-process (microVM) default
    set_if_absent("CONNECTOR_TOOLS_IN_MICROVM_STRICT", "1");
    // Default Landlock paths — operators must still bind real nsfs trees per agent.
    let data = std::env::var("CONNECTOR_DATA_DIR").unwrap_or_else(|_| "./data".into());
    set_if_absent(
        "CONNECTOR_DOCKLOCK_FS_READ",
        &format!("{data}/nsfs"),
    );
    set_if_absent(
        "CONNECTOR_DOCKLOCK_FS_WRITE",
        &format!("{data}/nsfs"),
    );
}

fn apply_production_hardening_defaults() {
    set_if_absent("CONNECTOR_MEMWRITE_SYNC_FLUSH", "1");
    set_if_absent("CONNECTOR_CFNI_ENFORCE", "1");
    // B8 — IIA Ring-1 / QPR / DockLock / HITL on by default for production-like presets.
    set_if_absent("CONNECTOR_IIA_RING1", "1");
    set_if_absent("CONNECTOR_IIA_QPR_ENFORCE", "1");
    set_if_absent("CONNECTOR_IIA_DOCKLOCK_ENFORCE", "1");
    set_if_absent("CONNECTOR_IIA_HITL_ENFORCE", "1");
    set_if_absent("CONNECTOR_AGENT_SETUP_GATE", "1");
    set_if_absent("CONNECTOR_GATEWAY_BAN_ANON", "1");
    set_if_absent("CONNECTOR_KERNEL_FAIL_CLOSED", "1");
    set_if_absent("CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED", "1");
    set_if_absent("CONNECTOR_L7_EGRESS_PROXY", "1");
    set_if_absent("CONNECTOR_MCP_EGRESS_ENFORCE", "1");
    set_if_absent("CONNECTOR_EFFECT_EXCLUSIVITY", "1");
    set_if_absent("CONNECTOR_MATRIX_HW_ENFORCE", "1");
    set_if_absent("CONNECTOR_ZT_HANDSHAKE", "1");
    set_if_absent("CONNECTOR_LLM_DISTRUST", "1");
    set_if_absent("CONNECTOR_DOCKER_LAB_EGRESS", "deny_all");
    set_if_absent("CONNECTOR_MICROVM_EGRESS_MODE", "deny_all");
    set_if_absent("CONNECTOR_DOCKLOCK_DOCKER_SECURITY", "1");
    set_if_absent("CONNECTOR_ZT_HANDSHAKE_BIND_MANIFEST", "1");
    set_if_absent("CONNECTOR_MICROVM_REQUIRE_HEARTBEAT", "1");
    set_if_absent("CONNECTOR_ISOLATION_RUNTIME", "microvm");
    set_if_absent("CONNECTOR_TOOLS_IN_MICROVM", "1");
    set_if_absent("CONNECTOR_WORLD_CHANNEL_VIA_MICROVM", "1");
    // Host MCP broker is a soft prod default; unbypassable overrides with STRICT.
    set_if_absent("CONNECTOR_ALLOW_HOST_MCP_BROKER", "1");
    set_if_absent("CONNECTOR_AGENTIC_CONTEXT_REQUIRE", "1");
    // Seven Pillars unbypassable bar (Linux FS/net/VM — not L7 alone).
    apply_unbypassable_hardening_defaults();
    // After unbypassable: prefer OOPC — clear host broker when STRICT is on.
    if std::env::var("CONNECTOR_TOOLS_IN_MICROVM_STRICT")
        .map(|v| {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
    {
        #[allow(unused_unsafe)]
        unsafe {
            std::env::set_var("CONNECTOR_ALLOW_HOST_MCP_BROKER", "0");
        }
    }
    // Prod must never look like a live LLM when stub is on.
    if std::env::var("CONNECTOR_LLM_STUB")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        && !std::env::var("CONNECTOR_LLM_STUB_ALLOW_IN_PROD")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    {
        #[allow(unused_unsafe)]
        unsafe {
            std::env::remove_var("CONNECTOR_LLM_STUB");
        }
        tracing::warn!(
            "CONNECTOR_LLM_STUB cleared under production hardening (set CONNECTOR_LLM_STUB_ALLOW_IN_PROD=1 to keep)"
        );
    }
}

/// DI-3 — one-click: **force** intelligence hardening flags on (overrides lab defaults).
/// Returns the list of env keys set. In-process only until restart reloads from env file.
pub fn enable_intelligence_hardening() -> Vec<&'static str> {
    let forced = [
        ("CONNECTOR_PRESET", "production"),
        ("CONNECTOR_IIA_RING1", "1"),
        ("CONNECTOR_IIA_QPR_ENFORCE", "1"),
        ("CONNECTOR_IIA_DOCKLOCK_ENFORCE", "1"),
        ("CONNECTOR_IIA_HITL_ENFORCE", "1"),
        ("CONNECTOR_AGENT_SETUP_GATE", "1"),
        ("CONNECTOR_GATEWAY_BAN_ANON", "1"),
        ("CONNECTOR_KERNEL_FAIL_CLOSED", "1"),
        ("CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED", "1"),
        ("CONNECTOR_CFNI_ENFORCE", "1"),
        ("CONNECTOR_L7_EGRESS_PROXY", "1"),
        ("CONNECTOR_MCP_EGRESS_ENFORCE", "1"),
        ("CONNECTOR_EFFECT_EXCLUSIVITY", "1"),
        ("CONNECTOR_MATRIX_HW_ENFORCE", "1"),
        ("CONNECTOR_ZT_HANDSHAKE", "1"),
        ("CONNECTOR_LLM_DISTRUST", "1"),
        ("CONNECTOR_DOCKER_LAB_EGRESS", "deny_all"),
        ("CONNECTOR_MICROVM_EGRESS_MODE", "deny_all"),
        ("CONNECTOR_DOCKLOCK_DOCKER_SECURITY", "1"),
        ("CONNECTOR_ZT_HANDSHAKE_BIND_MANIFEST", "1"),
        ("CONNECTOR_MICROVM_REQUIRE_HEARTBEAT", "1"),
        ("CONNECTOR_ISOLATION_RUNTIME", "microvm"),
        ("CONNECTOR_PLUGIN_RUN_BACKEND", "microvm"),
        ("CONNECTOR_TOOLS_IN_MICROVM", "1"),
        ("CONNECTOR_WORLD_CHANNEL_VIA_MICROVM", "1"),
        ("CONNECTOR_TOOLS_IN_MICROVM_STRICT", "1"),
        ("CONNECTOR_ALLOW_HOST_MCP_BROKER", "0"),
        ("CONNECTOR_TRANSPARENT_EGRESS", "1"),
        ("CONNECTOR_MISSION_ABANDON_STALE_PENDING", "1"),
        ("CONNECTOR_CONP_LAB_ECHO", "0"),
        ("CONNECTOR_AGENTIC_CONTEXT_REQUIRE", "1"),
        ("CONNECTOR_MEMWRITE_SYNC_FLUSH", "1"),
        ("CONNECTOR_SANDBOX_UNBYPASSABLE", "1"),
        ("CONNECTOR_KERNEL_ENFORCE", "1"),
        ("CONNECTOR_FLOW_LEASE_ENFORCE", "1"),
        ("CONNECTOR_VSOCK_TICKET_REQUIRE", "1"),
        ("CONNECTOR_PEER_OVERLAY", "1"),
        ("CONNECTOR_EBPF_REQUIRE", "1"),
        ("CONNECTOR_MATRIX_HOST_EGRESS", "1"),
    ];
    let mut set = Vec::new();
    for (k, v) in forced {
        force_set(k, v);
        set.push(k);
    }
    if std::env::var("CONNECTOR_LLM_STUB")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        && !std::env::var("CONNECTOR_LLM_STUB_ALLOW_IN_PROD")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    {
        #[allow(unused_unsafe)]
        unsafe {
            std::env::remove_var("CONNECTOR_LLM_STUB");
        }
    }
    tracing::warn!(
        keys = ?set,
        "DI-3: intelligence hardening forced on (Ring-1/QPR/DockLock/HITL/setup-gate)"
    );
    set
}

fn force_set(key: &str, value: &str) {
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var(key, value);
    }
}

/// Phase 1.9 / §3 — zero-config first run: if the operator did not set a preset, did not pin a
/// production-style `CONNECTOR_ENV`, and did not supply license material in the environment,
/// default to **`local`** so `apply_preset_from_env` enables development + `CONNECTOR_DEV_MODE`.
///
/// Opt out: `CONNECTOR_DISABLE_AUTO_LOCAL_PRESET=1` (or `true`). Does not override an existing
/// `CONNECTOR_PRESET`.
fn apply_implicit_local_preset() {
    if std::env::var_os("CONNECTOR_PRESET").is_some() {
        return;
    }
    if std::env::var("CONNECTOR_DISABLE_AUTO_LOCAL_PRESET")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return;
    }
    if std::env::var_os("CONNECTOR_LICENSE").is_some()
        || std::env::var_os("CONNECTOR_LICENSE_KEY").is_some()
    {
        return;
    }
    if let Ok(env) = std::env::var("CONNECTOR_ENV") {
        let e = env.trim().to_ascii_lowercase();
        if matches!(e.as_str(), "production" | "prod" | "pilots" | "pilot") {
            return;
        }
    }
    if std::env::var("CONNECTOR_LAB")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        std::env::set_var("CONNECTOR_PRESET", "local");
        tracing::info!("CONNECTOR: CONNECTOR_LAB=1 → CONNECTOR_PRESET=local (VJ lab-off is explicit)");
        return;
    }
    std::env::set_var("CONNECTOR_PRESET", "local");
    tracing::info!(
        "CONNECTOR: implicit CONNECTOR_PRESET=local (first-run dev defaults; set CONNECTOR_PRESET or CONNECTOR_DISABLE_AUTO_LOCAL_PRESET=1 to skip)"
    );
}

fn resolve_config_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CONNECTOR_CONFIG_FILE") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
        tracing::warn!(path = %pb.display(), "CONNECTOR_CONFIG_FILE set but file missing");
    }
    for candidate in [Path::new("connector.yaml"), Path::new(".connector/connector.yaml")] {
        if candidate.is_file() {
            return Some(candidate.to_path_buf());
        }
    }
    None
}

fn set_if_absent(key: &str, value: &str) {
    if std::env::var_os(key).is_none() {
        std::env::set_var(key, value);
    }
}

#[derive(Debug, Deserialize, Default)]
struct ConnectorYamlFile {
    #[serde(default)]
    #[allow(dead_code)]
    version: Option<u32>,
    #[serde(default)]
    preset: Option<String>,
    #[serde(default)]
    connector: Option<ConnectorYamlConnector>,
    /// First-party plugin enablement + optional lab compose hints (see `connector.yaml.example`).
    #[serde(default)]
    plugins: Vec<ConnectorYamlPluginEntry>,
}

#[derive(Debug, Deserialize)]
struct ConnectorYamlPluginEntry {
    id: String,
    /// When `false`, the plugin is omitted from the derived `CONNECTOR_PLUGINS_ENABLED` list.
    #[serde(default)]
    enabled: Option<bool>,
    /// Repo-relative path to a lab-only compose file or fragment (optional; filled into env when unset).
    #[serde(default)]
    lab_compose: Option<String>,
}

/// Ids allowed in `connector.yaml` `plugins:` (strict mode); matches `plugin_matrix::KNOWN_PLUGINS`.
const YAML_KNOWN_PLUGIN_IDS: &[&str] = &["devguard", "tracetramp", "witnessctl"];

fn validate_yaml_plugin_id(id: &str, strict: bool) -> Result<(), String> {
    let slug = id.trim().to_ascii_lowercase();
    if slug.is_empty() {
        return Err("connector.yaml plugins[] entry has empty id".into());
    }
    if YAML_KNOWN_PLUGIN_IDS.contains(&slug.as_str()) {
        return Ok(());
    }
    let msg = format!(
        "connector.yaml plugins[] unknown id {:?} — allowed: {}",
        id,
        YAML_KNOWN_PLUGIN_IDS.join(", ")
    );
    if strict {
        return Err(msg);
    }
    tracing::warn!(message = %msg, "CONNECTOR: unknown plugin id in connector.yaml (ignored)");
    Ok(())
}

fn plugin_lab_compose_env_key(id: &str) -> String {
    let upper = id
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .to_ascii_uppercase();
    format!("CONNECTOR_PLUGIN_{upper}_LAB_COMPOSE")
}

#[derive(Debug, Deserialize, Default)]
struct ConnectorYamlConnector {
    host: Option<String>,
    port: Option<u16>,
    #[serde(default)]
    public_url: Option<String>,
    #[serde(default)]
    protocol_port: Option<u16>,
    #[serde(default)]
    ui_rpc_port: Option<u16>,
    #[serde(default)]
    data_dir: Option<String>,
    #[serde(default)]
    engine_storage: Option<String>,
    #[serde(default)]
    kernel_storage: Option<String>,
    #[serde(default)]
    runtime_mode: Option<String>,
    /// Internal-only DNS label for plugin cage hosts (`<slug>.<cage_tld>`). Maps to `CONNECTOR_CAGE_TLD` (default `cnktros`).
    #[serde(default)]
    cage_tld: Option<String>,
    /// Ultimate Free: no login (`CONNECTOR_ULTIMATE_FREE=1`). Works with `runtime_mode: production`.
    #[serde(default)]
    open_auth: Option<bool>,
}

fn normalize_env_runtime_mode(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// Whitelist CONNECTOR_ENV values applied from YAML (enterprise: no arbitrary strings).
fn validate_yaml_runtime_mode(mode: &str) -> Result<(), String> {
    let m = normalize_env_runtime_mode(mode);
    match m.as_str() {
        "development" | "dev" | "production" | "prod" | "pilots" | "pilot" => Ok(()),
        _ => Err(format!(
            "connector.yaml connector.runtime_mode invalid: {:?} — allowed: development, dev, production, prod, pilots, pilot",
            mode
        )),
    }
}

fn apply_yaml(content: &str, path_label: String, strict: bool) -> Result<(), String> {
    let parsed: ConnectorYamlFile = match serde_yaml::from_str(content) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("invalid YAML in {path_label}: {e}");
            if strict {
                return Err(msg);
            }
            tracing::warn!(path = %path_label, error = %e, "CONNECTOR: invalid YAML — ignoring file");
            return Ok(());
        }
    };

    if let Some(p) = parsed.preset.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        set_if_absent("CONNECTOR_PRESET", p);
    }

    if let Some(c) = parsed.connector {
        if let Some(m) = c.runtime_mode.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            validate_yaml_runtime_mode(m)?;
        }
        if let Some(h) = c.host.filter(|s| !s.is_empty()) {
            set_if_absent("CONNECTOR_HOST", &h);
        }
        if let Some(p) = c.port {
            set_if_absent("CONNECTOR_PORT", &p.to_string());
        }
        if let Some(u) = c.public_url.filter(|s| !s.is_empty()) {
            set_if_absent("CONNECTOR_PUBLIC_URL", &u);
        }
        if let Some(p) = c.protocol_port {
            set_if_absent("CONNECTOR_PROTOCOL_PORT", &p.to_string());
        }
        if let Some(p) = c.ui_rpc_port {
            set_if_absent("CONNECTOR_UI_RPC_PORT", &p.to_string());
        }
        if let Some(d) = c.data_dir.filter(|s| !s.is_empty()) {
            set_if_absent("CONNECTOR_DATA_DIR", &d);
        }
        if let Some(s) = c.engine_storage.filter(|s| !s.is_empty()) {
            set_if_absent("CONNECTOR_ENGINE_STORAGE", &s);
        }
        if let Some(s) = c.kernel_storage.filter(|s| !s.is_empty()) {
            set_if_absent("CONNECTOR_KERNEL_STORAGE", &s);
        }
        if let Some(m) = c.runtime_mode.filter(|s| !s.is_empty()) {
            set_if_absent("CONNECTOR_ENV", &normalize_env_runtime_mode(&m));
        }
        if let Some(tld) = c.cage_tld.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            set_if_absent("CONNECTOR_CAGE_TLD", tld);
        }
        if c.open_auth == Some(true) {
            set_if_absent("CONNECTOR_ULTIMATE_FREE", "1");
        }
    }

    if !parsed.plugins.is_empty() {
        for entry in &parsed.plugins {
            validate_yaml_plugin_id(&entry.id, strict)?;
            let slug = entry.id.trim().to_ascii_lowercase();
            if let Some(path) = entry
                .lab_compose
                .as_ref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            {
                let key = plugin_lab_compose_env_key(&slug);
                set_if_absent(&key, path);
            }
        }

        if std::env::var_os("CONNECTOR_PLUGINS_ENABLED").is_none() {
            let mut enabled: Vec<String> = Vec::new();
            for entry in &parsed.plugins {
                let slug = entry.id.trim().to_ascii_lowercase();
                if !YAML_KNOWN_PLUGIN_IDS.contains(&slug.as_str()) {
                    continue;
                }
                if entry.enabled == Some(false) {
                    continue;
                }
                enabled.push(slug);
            }
            if !enabled.is_empty() {
                set_if_absent("CONNECTOR_PLUGINS_ENABLED", &enabled.join(","));
            }
        }
    }

    tracing::info!(
        path = %path_label,
        strict = strict,
        "CONNECTOR: applied connector.yaml (unset env vars only; no secrets logged)"
    );
    Ok(())
}

fn apply_preset_from_env(strict: bool) -> Result<(), String> {
    let Ok(raw) = std::env::var("CONNECTOR_PRESET") else {
        return Ok(());
    };
    let id = raw.trim().to_ascii_lowercase().replace('_', "-");

    let applied = match id.as_str() {
        "local" | "development" | "dev" => {
            set_if_absent("CONNECTOR_ENV", "development");
            set_if_absent("CONNECTOR_DEV_MODE", "1");
            set_if_absent("CONNECTOR_PLUGIN_LAB_AUTO_START", "1");
            set_if_absent(
                "CONNECTOR_TRACETRAMP_MANAGEMENT_URL",
                "http://127.0.0.1:19742",
            );
            set_if_absent(
                "CONNECTOR_TRACETRAMP_ADMIN_TOKEN",
                "lab_tracetramp_admin_token_change_me",
            );
            set_if_absent(
                "CONNECTOR_WITNESSCTL_MANAGEMENT_URL",
                "http://127.0.0.1:17443",
            );
            "local"
        }
        "local-live-llm" | "locallive" => {
            set_if_absent("CONNECTOR_ENV", "development");
            set_if_absent("CONNECTOR_DEV_MODE", "1");
            "local-live-llm"
        }
        "docker-local" | "dockerlocal" => {
            set_if_absent("CONNECTOR_ENV", "development");
            set_if_absent("CONNECTOR_DEV_MODE", "1");
            set_if_absent("CONNECTOR_HOST", "0.0.0.0");
            set_if_absent("CONNECTOR_PLUGIN_LAB_AUTO_START", "1");
            "docker-local"
        }
        "ci" => {
            set_if_absent("CONNECTOR_ENV", "development");
            set_if_absent("CONNECTOR_DEV_MODE", "1");
            set_if_absent("CONNECTOR_LLM_STUB", "1");
            set_if_absent("CONNECTOR_AIRGAP", "1");
            "ci"
        }
        "preview" => {
            set_if_absent("CONNECTOR_ENV", "pilots");
            "preview"
        }
        "staging" => {
            set_if_absent("CONNECTOR_ENV", "production");
            set_if_absent("CONNECTOR_PLUGIN_RUN_BACKEND", "microvm");
            apply_production_hardening_defaults();
            "staging"
        }
        "production" | "prod" => {
            set_if_absent("CONNECTOR_ENV", "production");
            set_if_absent("CONNECTOR_PLUGIN_RUN_BACKEND", "microvm");
            apply_production_hardening_defaults();
            "production"
        }
        "airgap" => {
            set_if_absent("CONNECTOR_ENV", "production");
            set_if_absent("CONNECTOR_AIRGAP", "1");
            set_if_absent("CONNECTOR_PLUGIN_RUN_BACKEND", "microvm");
            apply_production_hardening_defaults();
            "airgap"
        }
        "defense-strict" | "defensestrict" | "unbypassable" => {
            set_if_absent("CONNECTOR_ENV", "production");
            set_if_absent("CONNECTOR_DEFENSE_STRICT", "1");
            set_if_absent("CONNECTOR_PLUGIN_RUN_BACKEND", "microvm");
            apply_production_hardening_defaults();
            "defense-strict"
        }
        "multi-tenant" | "multitenant" => {
            set_if_absent("CONNECTOR_MULTI_TENANT", "1");
            "multi-tenant"
        }
        "plugin-workbench" | "pluginworkbench" => {
            set_if_absent("CONNECTOR_ENV", "development");
            set_if_absent("CONNECTOR_DEV_MODE", "1");
            set_if_absent("CONNECTOR_PLUGIN_LAB_AUTO_START", "1");
            "plugin-workbench"
        }
        "edge-satellite" | "edgesatellite" => {
            set_if_absent("CONNECTOR_ENV", "production");
            set_if_absent("CONNECTOR_DEFENSE_STRICT", "1");
            set_if_absent("CONNECTOR_PLUGIN_RUN_BACKEND", "microvm");
            apply_production_hardening_defaults();
            "edge-satellite"
        }
        "ultimate-free" | "ultimatefree" | "free" => {
            set_if_absent("CONNECTOR_ENV", "production");
            set_if_absent("CONNECTOR_ULTIMATE_FREE", "1");
            set_if_absent("CONNECTOR_LICENSE_TIER", "ultimate_free");
            "ultimate-free"
        }
        // ── Playground: vendor-hosted SaaS trial mode ──────────────────────
        // Real connector-platform, real APIs, real behaviour — but sandboxed:
        //   - LLM stub (no real LLM spend unless CONNECTOR_LLM_API_KEY set by operator)
        //   - Dev auth bypass OFF (visitors get scoped playground tokens, not superadmin)
        //   - CONNECTOR_PLAYGROUND=1 enables session TTL, per-session namespace isolation,
        //     agent/token caps, vault export block — enforced in playground middleware
        //   - CONNECTOR_MULTI_TENANT=1 so each session lives in its own tenant namespace
        //   - Pre-seeds sample catalog on first boot (devguard + reference workflows)
        "playground" | "trial" | "saas-trial" => {
            set_if_absent("CONNECTOR_ENV", "pilots");
            set_if_absent("CONNECTOR_PLAYGROUND", "1");
            set_if_absent("CONNECTOR_MULTI_TENANT", "1");
            set_if_absent("CONNECTOR_LLM_STUB", "1");
            set_if_absent("CONNECTOR_HOST", "0.0.0.0");
            // Hard caps (overridable by operator env before binary start)
            set_if_absent("CONNECTOR_PLAYGROUND_SESSION_TTL_SECS", "5400");   // 90 min idle
            set_if_absent("CONNECTOR_PLAYGROUND_MAX_AGENTS", "1");
            set_if_absent("CONNECTOR_PLAYGROUND_MAX_SESSIONS", "10");
            set_if_absent("CONNECTOR_PLAYGROUND_SESSION_LIMIT_PER_EMAIL", "3");
            set_if_absent("CONNECTOR_PLAYGROUND_UNLIMITED_EMAILS", "umeshlamton@gmail.com");
            set_if_absent("CONNECTOR_PLAYGROUND_SEED_DEMO", "1");
            set_if_absent("CONNECTOR_PLAYGROUND_TOKEN_BUDGET", "100000");     // tokens/session
            // Shared hosted node: no Firecracker / no kerneld — subprocess + tenant namespaces
            set_if_absent("CONNECTOR_ALLOW_SUBPROCESS_ISOLATION", "1");
            set_if_absent("CONNECTOR_KERNEL_EGRESS_DEGRADED", "1");
            set_if_absent("CONNECTOR_KERNEL_ENFORCE", "0");
            // Hosted trial binds 0.0.0.0; JWT secret should be a Fly secret.
            // If unset, jwt_secret() uses a per-process fallback (sessions reset on restart).
            // Seed the catalog on boot
            set_if_absent("CONNECTOR_PLAYGROUND_SEED_CATALOG", "1");
            set_if_absent("CONNECTOR_LLM_STUB_ALLOW_IN_PROD", "1");
            // Shared cloud VM: normal DNS + bounded vendor wait (no SSRF pin / retry storms).
            set_if_absent("CONNECTOR_LLM_DNS_PIN", "0");
            set_if_absent("CONNECTOR_LLM_TIMEOUT_SECS", "45");
            set_if_absent("CONNECTOR_LLM_MAX_RETRIES", "1");
            set_if_absent("CONNECTOR_PLAYGROUND_TALK_LLM_TIMEOUT_SECS", "75");
            // Fly playground sets CONNECTOR_PLAYGROUND_LLM_LINK_SKIP_PING=0 so Talk
            // is Live only after a vendor ping. Local playground default matches Fly.
            set_if_absent("CONNECTOR_PLAYGROUND_LLM_LINK_SKIP_PING", "0");
            // Hosted trial: RAG off by default so Talk cannot freeze /health.
            set_if_absent("CONNECTOR_PLAYGROUND_RAG", "0");
            // Talk must work on the seeded demo. A setup-gate draft leaves
            // the agent Registered and POST /completions returns agent_not_activated.
            std::env::remove_var("CONNECTOR_AGENT_SETUP_GATE");
            // Shared Fly VM: clear Linux unbypassable / Landlock bar leftovers that
            // deny Talk with fs_allowlist_required when pilots+empty DOCKLOCK_FS_*.
            for k in [
                "CONNECTOR_SANDBOX_UNBYPASSABLE",
                "CONNECTOR_LLM_BROKER_UNBYPASSABLE",
                "CONNECTOR_EFFECT_EXCLUSIVITY",
                "CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED",
                "CONNECTOR_LLM_DISTRUST",
                "CONNECTOR_IIA_RING1",
            ] {
                std::env::remove_var(k);
            }
            let data = std::env::var("CONNECTOR_DATA_DIR").unwrap_or_else(|_| "./data".into());
            set_if_absent(
                "CONNECTOR_DOCKLOCK_FS_READ",
                &format!("{data}/nsfs"),
            );
            set_if_absent(
                "CONNECTOR_DOCKLOCK_FS_WRITE",
                &format!("{data}/nsfs"),
            );
            // Wire plugin sidecar management planes (tracetramp :9742, witnessctl :7443)
            // so the dashboard proxy works without extra env configuration.
            set_if_absent("CONNECTOR_TRACETRAMP_MANAGEMENT_URL", "http://127.0.0.1:9742");
            set_if_absent("CONNECTOR_WITNESSCTL_MANAGEMENT_URL", "http://127.0.0.1:7443");
            // Bridge sidecar admin tokens → connector-platform proxy env vars.
            // On Fly the secrets are named CONNECTOR_*_ADMIN_TOKEN and are already
            // in the process env; on local dev they may be named TRACETRAMP_ADMIN_TOKEN
            // / WITNESSCTL_ADMIN_TOKEN.  Either way we promote them so the proxy
            // handlers (witnessctl_proxy / tracetramp_proxy) can find them.
            if std::env::var("CONNECTOR_TRACETRAMP_ADMIN_TOKEN").is_err() {
                if let Ok(tok) = std::env::var("TRACETRAMP_ADMIN_TOKEN") {
                    if !tok.trim().is_empty() {
                        std::env::set_var("CONNECTOR_TRACETRAMP_ADMIN_TOKEN", tok);
                    }
                }
            }
            if std::env::var("CONNECTOR_WITNESSCTL_ADMIN_TOKEN").is_err() {
                if let Ok(tok) = std::env::var("WITNESSCTL_ADMIN_TOKEN") {
                    if !tok.trim().is_empty() {
                        std::env::set_var("CONNECTOR_WITNESSCTL_ADMIN_TOKEN", tok);
                    }
                }
            }
            "playground"
        }
        // Pilot: selective tokenize + anon ban + budget floors — not full harden/microVM.
        "pilot" | "pilots" => {
            set_if_absent("CONNECTOR_ENV", "pilots");
            set_if_absent("CONNECTOR_GATEWAY_BAN_ANON", "1");
            set_if_absent("CONNECTOR_LLM_DATA_TOKENIZE", "1");
            set_if_absent("CONNECTOR_LLM_CONTEXT_BROKER", "1");
            set_if_absent("CONNECTOR_AUTONOMY_TIER", "2");
            set_if_absent("CONNECTOR_WORLD_GRANTS_FAIL_CLOSED", "1");
            set_if_absent("CONNECTOR_ALLOW_SUBPROCESS_ISOLATION", "1");
            // Soft matrix — no microVM require; LAB banner via hardening off unless operator sets it.
            set_if_absent("CONNECTOR_KERNEL_EGRESS_DEGRADED", "1");
            "pilot"
        }
        other => {
            let msg = format!(
                "unknown CONNECTOR_PRESET {:?} — allowed: local, local-live-llm, docker-local, ci, preview, staging, production, airgap, defense-strict, unbypassable, multi-tenant, plugin-workbench, edge-satellite, ultimate-free, playground, pilot",
                other
            );
            if strict {
                return Err(msg);
            }
            tracing::warn!(preset = %other, "CONNECTOR_PRESET {}", msg);
            return Ok(());
        }
    };

    tracing::info!(
        preset = %applied,
        strict = strict,
        "CONNECTOR_PRESET applied (only filled unset env vars)"
    );
    Ok(())
}

/// Production hygiene: `CONNECTOR_ENV=production` with `CONNECTOR_DEV_MODE` still set is a common
/// foot-gun. [`crate::services::runtime_control::dev_auth_bypass_allowed`] already disables bypass
/// in production — this surfaces a **boot warning** and optional **fatal** rejection.
fn validate_production_dev_mode_hygiene() -> Result<(), String> {
    let env = std::env::var("CONNECTOR_ENV")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let prod_like = matches!(env.as_str(), "production" | "prod");
    if !prod_like {
        return Ok(());
    }
    let dev_mode = std::env::var("CONNECTOR_DEV_MODE")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    if !dev_mode {
        return Ok(());
    }

    let reject = std::env::var("CONNECTOR_PRODUCTION_REJECT_DEV_MODE")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if reject {
        return Err(
            "CONNECTOR_PRODUCTION_REJECT_DEV_MODE: CONNECTOR_ENV is production but CONNECTOR_DEV_MODE is enabled. \
             Unset CONNECTOR_DEV_MODE (dev auth bypass is already disabled in production — see runtime_control::dev_auth_bypass_allowed)."
                .into(),
        );
    }

    tracing::warn!(
        "CONNECTOR_ENV=production with CONNECTOR_DEV_MODE set — dev auth bypass is OFF (runtime policy); unset CONNECTOR_DEV_MODE for a clean prod environment. \
         Fail boot on this combo: CONNECTOR_PRODUCTION_REJECT_DEV_MODE=1."
    );

    Ok(())
}

/// Reject dev-oriented presets when running in production-like CONNECTOR_ENV (optional enterprise guard).
fn validate_production_preset_combination() -> Result<(), String> {
    if !enforce_production_presets() {
        return Ok(());
    }
    let env = std::env::var("CONNECTOR_ENV")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let prod_like = matches!(env.as_str(), "production" | "prod");
    if !prod_like {
        return Ok(());
    }
    let preset_raw = std::env::var("CONNECTOR_PRESET").unwrap_or_default();
    let preset = preset_raw.trim().to_ascii_lowercase().replace('_', "-");
    if preset.is_empty() {
        return Ok(());
    }
    let dev_presets = [
        "local",
        "development",
        "dev",
        "local-live-llm",
        "locallive",
        "docker-local",
        "dockerlocal",
        "ci",
        "plugin-workbench",
        "pluginworkbench",
    ];
    if dev_presets.contains(&preset.as_str()) {
        return Err(format!(
            "CONNECTOR_ENFORCE_PRODUCTION_PRESETS: CONNECTOR_ENV is production but CONNECTOR_PRESET is {:?} (dev-oriented). \
             Use production, staging, airgap, defense-strict, edge-satellite, preview, or multi-tenant as appropriate.",
            preset_raw
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_applies_preset_and_connector() {
        let y = r#"
version: 1
preset: ci
connector:
  port: 9876
  host: "127.0.0.1"
"#;
        std::env::remove_var("CONNECTOR_PRESET");
        std::env::remove_var("CONNECTOR_PORT");
        std::env::remove_var("CONNECTOR_HOST");
        apply_yaml(y, "test".into(), false).unwrap();
        assert_eq!(std::env::var("CONNECTOR_PRESET").unwrap(), "ci");
        assert_eq!(std::env::var("CONNECTOR_PORT").unwrap(), "9876");
        assert_eq!(std::env::var("CONNECTOR_HOST").unwrap(), "127.0.0.1");
        std::env::remove_var("CONNECTOR_PRESET");
        std::env::remove_var("CONNECTOR_PORT");
        std::env::remove_var("CONNECTOR_HOST");
    }

    #[test]
    fn yaml_does_not_override_existing_env() {
        std::env::set_var("CONNECTOR_PORT", "1111");
        let y = "connector:\n  port: 2222\n";
        apply_yaml(y, "test".into(), false).unwrap();
        assert_eq!(std::env::var("CONNECTOR_PORT").unwrap(), "1111");
        std::env::remove_var("CONNECTOR_PORT");
    }

    #[test]
    fn yaml_runtime_mode_invalid_errors() {
        let y = "connector:\n  runtime_mode: \"hacker\"\n";
        let r = apply_yaml(y, "test".into(), false);
        assert!(r.is_err());
    }

    #[test]
    fn preset_local_sets_dev() {
        std::env::remove_var("CONNECTOR_ENV");
        std::env::remove_var("CONNECTOR_DEV_MODE");
        std::env::set_var("CONNECTOR_PRESET", "local");
        apply_preset_from_env(false).unwrap();
        assert_eq!(std::env::var("CONNECTOR_ENV").unwrap(), "development");
        assert_eq!(std::env::var("CONNECTOR_DEV_MODE").unwrap(), "1");
        std::env::remove_var("CONNECTOR_PRESET");
        std::env::remove_var("CONNECTOR_ENV");
        std::env::remove_var("CONNECTOR_DEV_MODE");
    }

    #[test]
    fn preset_ci_stub_and_airgap() {
        std::env::remove_var("CONNECTOR_LLM_STUB");
        std::env::remove_var("CONNECTOR_AIRGAP");
        std::env::set_var("CONNECTOR_PRESET", "ci");
        apply_preset_from_env(false).unwrap();
        assert_eq!(std::env::var("CONNECTOR_LLM_STUB").unwrap(), "1");
        assert_eq!(std::env::var("CONNECTOR_AIRGAP").unwrap(), "1");
        std::env::remove_var("CONNECTOR_PRESET");
        std::env::remove_var("CONNECTOR_LLM_STUB");
        std::env::remove_var("CONNECTOR_AIRGAP");
    }

    #[test]
    fn strict_unknown_preset_errors() {
        std::env::set_var("CONNECTOR_PRESET", "not-a-real-preset");
        let r = apply_preset_from_env(true);
        assert!(r.is_err());
        std::env::remove_var("CONNECTOR_PRESET");
    }

    #[test]
    fn enforce_prod_rejects_local_preset() {
        std::env::set_var("CONNECTOR_ENFORCE_PRODUCTION_PRESETS", "1");
        std::env::set_var("CONNECTOR_ENV", "production");
        std::env::set_var("CONNECTOR_PRESET", "local");
        let r = validate_production_preset_combination();
        assert!(r.is_err());
        std::env::remove_var("CONNECTOR_ENFORCE_PRODUCTION_PRESETS");
        std::env::remove_var("CONNECTOR_ENV");
        std::env::remove_var("CONNECTOR_PRESET");
    }

    #[test]
    fn yaml_plugins_sets_env_and_respects_existing_plugins_enabled() {
        // Single test: `CONNECTOR_*` is process-global; other tests may run in parallel.
        std::env::remove_var("CONNECTOR_PLUGINS_ENABLED");
        std::env::remove_var("CONNECTOR_PLUGIN_TRACETRAMP_LAB_COMPOSE");
        let y = r#"
version: 1
plugins:
  - id: tracetramp
    lab_compose: lab/docker-compose.premium-lab.yml
  - id: witnessctl
    enabled: true
  - id: devguard
    enabled: false
"#;
        apply_yaml(y, "test".into(), false).unwrap();
        assert_eq!(
            std::env::var("CONNECTOR_PLUGINS_ENABLED").unwrap(),
            "tracetramp,witnessctl"
        );
        assert_eq!(
            std::env::var("CONNECTOR_PLUGIN_TRACETRAMP_LAB_COMPOSE").unwrap(),
            "lab/docker-compose.premium-lab.yml"
        );
        std::env::remove_var("CONNECTOR_PLUGINS_ENABLED");
        std::env::remove_var("CONNECTOR_PLUGIN_TRACETRAMP_LAB_COMPOSE");

        std::env::set_var("CONNECTOR_PLUGINS_ENABLED", "devguard");
        let y2 = r#"plugins:
  - id: tracetramp
    lab_compose: lab/docker-compose.premium-lab.yml
"#;
        apply_yaml(y2, "test".into(), false).unwrap();
        assert_eq!(std::env::var("CONNECTOR_PLUGINS_ENABLED").unwrap(), "devguard");
        assert_eq!(
            std::env::var("CONNECTOR_PLUGIN_TRACETRAMP_LAB_COMPOSE").unwrap(),
            "lab/docker-compose.premium-lab.yml"
        );
        std::env::remove_var("CONNECTOR_PLUGINS_ENABLED");
        std::env::remove_var("CONNECTOR_PLUGIN_TRACETRAMP_LAB_COMPOSE");
    }

    #[test]
    fn yaml_plugins_unknown_id_strict_errors() {
        let y = r#"plugins:
  - id: not-a-plugin
"#;
        let r = apply_yaml(y, "test".into(), true);
        assert!(r.is_err());
    }

    #[test]
    fn implicit_local_preset_behavior() {
        for k in [
            "CONNECTOR_PRESET",
            "CONNECTOR_ENV",
            "CONNECTOR_DEV_MODE",
            "CONNECTOR_LICENSE",
            "CONNECTOR_LICENSE_KEY",
            "CONNECTOR_DISABLE_AUTO_LOCAL_PRESET",
        ] {
            std::env::remove_var(k);
        }
        apply_implicit_local_preset();
        assert_eq!(std::env::var("CONNECTOR_PRESET").unwrap(), "local");
        apply_preset_from_env(false).unwrap();
        assert_eq!(std::env::var("CONNECTOR_ENV").unwrap(), "development");
        std::env::remove_var("CONNECTOR_PRESET");
        std::env::remove_var("CONNECTOR_ENV");
        std::env::remove_var("CONNECTOR_DEV_MODE");

        std::env::set_var("CONNECTOR_ENV", "production");
        apply_implicit_local_preset();
        assert!(std::env::var("CONNECTOR_PRESET").is_err());
        std::env::remove_var("CONNECTOR_ENV");

        std::env::set_var("CONNECTOR_LICENSE", "test-license-material");
        apply_implicit_local_preset();
        assert!(std::env::var("CONNECTOR_PRESET").is_err());
        std::env::remove_var("CONNECTOR_LICENSE");

        std::env::set_var("CONNECTOR_DISABLE_AUTO_LOCAL_PRESET", "1");
        apply_implicit_local_preset();
        assert!(std::env::var("CONNECTOR_PRESET").is_err());
        std::env::remove_var("CONNECTOR_DISABLE_AUTO_LOCAL_PRESET");

        std::env::set_var("CONNECTOR_PRESET", "ci");
        apply_implicit_local_preset();
        assert_eq!(std::env::var("CONNECTOR_PRESET").unwrap(), "ci");
        std::env::remove_var("CONNECTOR_PRESET");
    }

    #[test]
    fn prod_dev_mode_hygiene_matrix() {
        // Single test: `std::env` is process-global; parallel tests race on these keys.
        std::env::remove_var("CONNECTOR_PRODUCTION_REJECT_DEV_MODE");
        std::env::set_var("CONNECTOR_ENV", "development");
        std::env::set_var("CONNECTOR_DEV_MODE", "1");
        assert!(validate_production_dev_mode_hygiene().is_ok());

        std::env::set_var("CONNECTOR_ENV", "production");
        std::env::remove_var("CONNECTOR_DEV_MODE");
        assert!(validate_production_dev_mode_hygiene().is_ok());

        std::env::set_var("CONNECTOR_ENV", "production");
        std::env::set_var("CONNECTOR_DEV_MODE", "1");
        std::env::remove_var("CONNECTOR_PRODUCTION_REJECT_DEV_MODE");
        assert!(validate_production_dev_mode_hygiene().is_ok());

        std::env::set_var("CONNECTOR_ENV", "production");
        std::env::set_var("CONNECTOR_DEV_MODE", "1");
        std::env::set_var("CONNECTOR_PRODUCTION_REJECT_DEV_MODE", "1");
        let r = validate_production_dev_mode_hygiene();
        assert!(r.is_err(), "expected err, got {r:?}");

        std::env::remove_var("CONNECTOR_ENV");
        std::env::remove_var("CONNECTOR_DEV_MODE");
        std::env::remove_var("CONNECTOR_PRODUCTION_REJECT_DEV_MODE");
    }

    #[test]
    fn production_secrets_require_audit_cfni_cage_keys() {
        for k in [
            "CONNECTOR_ENV",
            "CONNECTOR_DEFENSE_STRICT",
            "CONNECTOR_AUDIT_HMAC_KEY",
            "CONNECTOR_CFNI_SECRET",
            "CONNECTOR_CAGE_CAP_SECRET",
            "CONNECTOR_CAPS_ALLOW_MOCK",
        ] {
            std::env::remove_var(k);
        }

        std::env::set_var("CONNECTOR_ENV", "development");
        assert!(validate_production_secrets_fail_closed().is_ok());

        std::env::set_var("CONNECTOR_ENV", "production");
        assert!(validate_production_secrets_fail_closed().is_err());

        std::env::set_var(
            "CONNECTOR_AUDIT_HMAC_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        assert!(validate_production_secrets_fail_closed().is_err());

        std::env::set_var("CONNECTOR_CFNI_SECRET", "cfni-test-secret-not-for-prod");
        assert!(validate_production_secrets_fail_closed().is_err());

        std::env::set_var("CONNECTOR_CAGE_CAP_SECRET", "cage-test-secret-not-for-prod");
        assert!(validate_production_secrets_fail_closed().is_ok());

        std::env::set_var("CONNECTOR_CAPS_ALLOW_MOCK", "1");
        assert!(validate_production_secrets_fail_closed().is_err());

        for k in [
            "CONNECTOR_ENV",
            "CONNECTOR_DEFENSE_STRICT",
            "CONNECTOR_AUDIT_HMAC_KEY",
            "CONNECTOR_CFNI_SECRET",
            "CONNECTOR_CAGE_CAP_SECRET",
            "CONNECTOR_CAPS_ALLOW_MOCK",
        ] {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn production_preset_sets_memwrite_and_cfni_enforce() {
        for k in [
            "CONNECTOR_PRESET",
            "CONNECTOR_ENV",
            "CONNECTOR_PLUGIN_RUN_BACKEND",
            "CONNECTOR_MEMWRITE_SYNC_FLUSH",
            "CONNECTOR_CFNI_ENFORCE",
        ] {
            std::env::remove_var(k);
        }
        std::env::set_var("CONNECTOR_PRESET", "production");
        apply_preset_from_env(false).unwrap();
        assert_eq!(std::env::var("CONNECTOR_MEMWRITE_SYNC_FLUSH").unwrap(), "1");
        assert_eq!(std::env::var("CONNECTOR_CFNI_ENFORCE").unwrap(), "1");
        for k in [
            "CONNECTOR_PRESET",
            "CONNECTOR_ENV",
            "CONNECTOR_PLUGIN_RUN_BACKEND",
            "CONNECTOR_MEMWRITE_SYNC_FLUSH",
            "CONNECTOR_CFNI_ENFORCE",
        ] {
            std::env::remove_var(k);
        }
    }
}
