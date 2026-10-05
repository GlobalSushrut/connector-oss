//! Normalized Phase 5 operator env labels for **`GET /api/v1/plugins/status`** (`phase_5_operator`).
//! Keeps parity with `connector-plugin-runtime` **`CONNECTOR_DOCKER_LAB_EGRESS`** / **`CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE`**
//! and **`CONNECTOR_MICROVM_EGRESS_MODE`** / **`CONNECTOR_MICROVM_EGRESS_ENFORCE`** parsing.

/// Classify **`CONNECTOR_DOCKER_LAB_EGRESS`** (aligned with `connector-plugin-runtime` `docker_lab_egress_mode`).
pub fn docker_lab_egress_mode_label_from_raw(raw: &str) -> &'static str {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() || s == "unrestricted" || s == "open" {
        "unrestricted"
    } else if matches!(s.as_str(), "deny_all" | "deny-all" | "none" | "isolated") {
        "deny_all"
    } else if matches!(
        s.as_str(),
        "allowlist_strict" | "allowlist-strict" | "manifest_strict"
    ) {
        "allowlist_strict"
    } else {
        "custom"
    }
}

#[inline]
pub fn docker_lab_egress_mode_label() -> &'static str {
    docker_lab_egress_mode_label_from_raw(
        &std::env::var("CONNECTOR_DOCKER_LAB_EGRESS").unwrap_or_default(),
    )
}

/// **`CONNECTOR_PLUGIN_RUN_BACKEND`** for operator display; empty → **`subprocess`**.
/// Opt-in host **`iptables`** enforcement for Docker lab allowlists (`CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE`).
pub fn docker_lab_egress_enforce_label_from_raw(raw: &str) -> &'static str {
    let s = raw.trim();
    if s.eq_ignore_ascii_case("iptables")
        || s.eq_ignore_ascii_case("iptables_docker_user")
        || s.eq_ignore_ascii_case("docker_user")
    {
        "iptables"
    } else {
        "off"
    }
}

#[inline]
pub fn docker_lab_egress_enforce_label() -> &'static str {
    docker_lab_egress_enforce_label_from_raw(
        &std::env::var("CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE").unwrap_or_default(),
    )
}

pub fn default_plugin_run_backend_label() -> String {
    let run_backend = std::env::var("CONNECTOR_PLUGIN_RUN_BACKEND").unwrap_or_default();
    let run_backend = run_backend.trim();
    if run_backend.is_empty() {
        let env = connect_connector_env_label();
        let e = env.to_ascii_lowercase();
        if matches!(e.as_str(), "production" | "prod" | "pilots" | "pilot") {
            "microvm (default for production-like CONNECTOR_ENV)".to_string()
        } else {
            "subprocess (default for development CONNECTOR_ENV)".to_string()
        }
    } else {
        run_backend.to_string()
    }
}

pub fn connectorctl_plugin_run_backend_label() -> String {
    default_plugin_run_backend_label()
}

/// Trimmed **`CONNECTOR_ENV`** for operator surfaces (empty if unset).
pub fn connect_connector_env_label() -> String {
    std::env::var("CONNECTOR_ENV")
        .unwrap_or_default()
        .trim()
        .to_string()
}

#[inline]
pub fn connect_env_production_like() -> bool {
    let e = std::env::var("CONNECTOR_ENV")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    matches!(e.as_str(), "production" | "prod")
}

#[inline]
pub fn connect_dev_mode_truthy() -> bool {
    std::env::var("CONNECTOR_DEV_MODE")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[inline]
pub fn connect_production_reject_dev_mode_truthy() -> bool {
    std::env::var("CONNECTOR_PRODUCTION_REJECT_DEV_MODE")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Parity with [`crate::connector_profile::validate_production_dev_mode_hygiene`].
pub fn production_dev_mode_hygiene_level() -> &'static str {
    if !connect_env_production_like() || !connect_dev_mode_truthy() {
        return "ok";
    }
    if connect_production_reject_dev_mode_truthy() {
        "fatal_on_boot"
    } else {
        "warn_on_boot"
    }
}

pub fn microvm_vendor_assets_configured() -> bool {
    std::env::var("CONNECTOR_MICROVM_KERNEL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .is_some()
        || option_env!("CONNECTOR_VENDORED_MICROVM_KERNEL_PATH").is_some()
}

pub fn microvm_vm_agent_guest_path_label() -> String {
    std::env::var("CONNECTOR_VM_AGENT_GUEST_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/sbin/connector-vm-agent".to_string())
}

pub fn microvm_wsl_distro_label() -> String {
    std::env::var("CONNECTOR_WSL_DISTRO")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "Ubuntu".to_string())
}

pub fn microvm_wsl_state_dir_label() -> String {
    std::env::var("CONNECTOR_MICROVM_WSL_STATE_DIR")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/tmp/connector-microvm".to_string())
}

pub fn microvm_egress_mode_label() -> String {
    microvm_egress_mode_label_from_raw(
        &std::env::var("CONNECTOR_MICROVM_EGRESS_MODE").unwrap_or_default(),
    )
    .to_string()
}

pub fn microvm_egress_mode_label_from_raw(raw: &str) -> &'static str {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() || matches!(s.as_str(), "deny_all" | "deny-all" | "none" | "off") {
        "deny_all"
    } else if matches!(
        s.as_str(),
        "allowlist_strict" | "allowlist-strict" | "manifest_strict"
    ) {
        "allowlist_strict"
    } else {
        "custom"
    }
}

/// **`CONNECTOR_MICROVM_EGRESS_ENFORCE`** — Linux TAP + **`iptables` `FORWARD`** (aligned with `connector-plugin-runtime`).
pub fn microvm_egress_enforce_label_from_raw(raw: &str) -> &'static str {
    let s = raw.trim();
    if s.eq_ignore_ascii_case("iptables")
        || s.eq_ignore_ascii_case("iptables_forward")
        || s.eq_ignore_ascii_case("forward")
    {
        "iptables"
    } else {
        "off"
    }
}

#[inline]
pub fn microvm_egress_enforce_label() -> String {
    microvm_egress_enforce_label_from_raw(
        &std::env::var("CONNECTOR_MICROVM_EGRESS_ENFORCE").unwrap_or_default(),
    )
    .to_string()
}

pub fn microvm_egress_enforce_required_label() -> String {
    microvm_egress_enforce_required_label_from_raw(
        &std::env::var("CONNECTOR_MICROVM_EGRESS_ENFORCE_REQUIRED").unwrap_or_default(),
    )
    .to_string()
}

pub fn microvm_egress_enforce_required_label_from_raw(raw: &str) -> &'static str {
    let s = raw.trim().to_ascii_lowercase();
    if matches!(s.as_str(), "1" | "true" | "yes" | "on") {
        "on"
    } else {
        "off"
    }
}

/// **`CONNECTOR_MICROVM_GUEST_IFACE`** — guest interface for static ULA (`connector.microvm_guest_iface`); default **`eth0`**.
#[inline]
pub fn microvm_guest_iface_label() -> String {
    microvm_guest_iface_label_from_raw(
        &std::env::var("CONNECTOR_MICROVM_GUEST_IFACE").unwrap_or_default(),
    )
    .to_string()
}

pub fn microvm_guest_iface_label_from_raw(raw: &str) -> &'static str {
    if raw.trim().is_empty() {
        "default(eth0)"
    } else {
        "set"
    }
}

pub fn plugin_subprocess_cgroup_parent_label() -> String {
    plugin_subprocess_cgroup_parent_label_from_raw(
        &std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PARENT").unwrap_or_default(),
    )
    .to_string()
}

pub fn plugin_subprocess_cgroup_parent_label_from_raw(raw: &str) -> &'static str {
    if raw.trim().is_empty() {
        "off"
    } else {
        "set"
    }
}

/// Raw **`CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PIDS_MAX`** for operator telemetry (Phase **5.8**); empty → **`off`**.
pub fn plugin_subprocess_cgroup_pids_max_label() -> String {
    let raw = std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PIDS_MAX").unwrap_or_default();
    let t = raw.trim();
    if t.is_empty() {
        "off".to_string()
    } else {
        t.to_string()
    }
}

/// Raw **`CONNECTOR_PLUGIN_SUBPROCESS_CPU_WEIGHT`** (Phase **5.8** **`cpu.weight`**); empty → **`off`**.
pub fn plugin_subprocess_cpu_weight_label() -> String {
    let raw = std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_CPU_WEIGHT").unwrap_or_default();
    let t = raw.trim();
    if t.is_empty() {
        "off".to_string()
    } else {
        t.to_string()
    }
}

/// Raw **`CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_HIGH_BYTES`** (Phase **5.8** **`memory.high`**); empty → **`off`**.
pub fn plugin_subprocess_memory_high_bytes_label() -> String {
    let raw = std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_HIGH_BYTES").unwrap_or_default();
    let t = raw.trim();
    if t.is_empty() {
        "off".to_string()
    } else {
        t.to_string()
    }
}

/// Raw **`CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_SWAP_MAX_BYTES`** (Phase **5.8** **`memory.swap.max`**); empty → **`off`**.
pub fn plugin_subprocess_memory_swap_max_bytes_label() -> String {
    let raw =
        std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_SWAP_MAX_BYTES").unwrap_or_default();
    let t = raw.trim();
    if t.is_empty() {
        "off".to_string()
    } else {
        t.to_string()
    }
}

/// Raw **`CONNECTOR_SUPERVISOR_NODE_CRASH_PLUGIN_ID`** (Phase **5.10.6** — background **`connectorctl start`** crash POST id); empty → **`off`**.
pub fn supervisor_node_crash_plugin_id_label() -> String {
    let raw = std::env::var("CONNECTOR_SUPERVISOR_NODE_CRASH_PLUGIN_ID").unwrap_or_default();
    let t = raw.trim();
    if t.is_empty() {
        "off".to_string()
    } else {
        t.to_string()
    }
}

/// **`CONNECTOR_MICROVM_TIER_STATE_FILE`** set on the node → **`set`** (kernel syncs tier JSON for microVM vsock); else **`off`**.
pub fn microvm_tier_state_file_operator_label() -> &'static str {
    let raw = std::env::var("CONNECTOR_MICROVM_TIER_STATE_FILE").unwrap_or_default();
    if raw.trim().is_empty() {
        "off"
    } else {
        "set"
    }
}

/// Kernel tier JSON sync for vsock **`tier_signal`**: **`off`** or **`on:<ms>ms`** (interval from **`CONNECTOR_MICROVM_TIER_STATE_SYNC_MS`**).
pub fn microvm_tier_state_sync_operator_label() -> String {
    if crate::services::plugin_tier_scheduler::microvm_tier_state_file_path_from_env().is_none() {
        return "off".to_string();
    }
    let ms = crate::services::plugin_tier_scheduler::microvm_tier_state_sync_interval_ms_from_env();
    format!("on:{ms}ms")
}

pub fn plugin_tier_cgroup_scan_label() -> String {
    plugin_tier_cgroup_scan_label_from_raw(
        &std::env::var("CONNECTOR_PLUGIN_TIER_CGROUP_SCAN").unwrap_or_default(),
    )
    .to_string()
}

pub fn plugin_tier_cgroup_scan_label_from_raw(raw: &str) -> &'static str {
    let s = raw.trim().to_ascii_lowercase();
    if matches!(s.as_str(), "1" | "true" | "yes" | "on") {
        "on"
    } else {
        "off"
    }
}

/// **`CONNECTOR_PLUGIN_TIER_CGROUP_IDLE_DEMOTE`** — cgroup-accelerated Warm/Hot → Cold (Phase **5.4.3**).
#[inline]
pub fn plugin_tier_cgroup_idle_demote_label() -> String {
    plugin_tier_cgroup_idle_demote_label_from_raw(
        &std::env::var("CONNECTOR_PLUGIN_TIER_CGROUP_IDLE_DEMOTE").unwrap_or_default(),
    )
    .to_string()
}

pub fn plugin_tier_cgroup_idle_demote_label_from_raw(raw: &str) -> &'static str {
    let s = raw.trim().to_ascii_lowercase();
    if matches!(s.as_str(), "1" | "true" | "yes" | "on") {
        "on"
    } else {
        "off"
    }
}

pub fn plugin_subprocess_seccomp_label() -> String {
    let intent_raw =
        std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT").unwrap_or_default();
    let intent_label = plugin_subprocess_seccomp_intent_label_from_raw(&intent_raw);
    if intent_label != "off" {
        return plugin_subprocess_seccomp_from_intent_label(intent_label).to_string();
    }
    plugin_subprocess_seccomp_label_from_raw(
        &std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP").unwrap_or_default(),
    )
    .to_string()
}

pub fn plugin_subprocess_seccomp_resolution() -> serde_json::Value {
    let intent_raw =
        std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT").unwrap_or_default();
    let mode_raw = std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP").unwrap_or_default();
    let intent_label = plugin_subprocess_seccomp_intent_label_from_raw(&intent_raw);
    let mode_label = plugin_subprocess_seccomp_label_from_raw(&mode_raw);
    let (effective_policy, source) = if intent_label != "off" {
        (
            plugin_subprocess_seccomp_from_intent_label(intent_label),
            "intent",
        )
    } else {
        (mode_label, "mode")
    };
    let arch = std::env::consts::ARCH;
    let supported_arch = arch == "x86_64" || arch == "aarch64";
    let deny_profiles_supported = supported_arch;
    serde_json::json!({
        "intent_raw": intent_raw,
        "intent": intent_label,
        "mode_raw": mode_raw,
        "mode": mode_label,
        "effective_policy": effective_policy,
        "source": source,
        "arch": arch,
        "deny_profiles_supported": deny_profiles_supported,
    })
}

/// Structured preflight warnings derived from `phase_5_operator` labels for UI/API consumers.
pub fn phase5_preflight_warnings_from_operator(p5: &serde_json::Value) -> Vec<String> {
    let mut warnings = Vec::new();
    match p5
        .get("production_dev_mode_hygiene")
        .and_then(|x| x.as_str())
    {
        Some("warn_on_boot") => {
            warnings.push(
                "production hygiene: CONNECTOR_ENV is production and CONNECTOR_DEV_MODE is truthy — unset DEV_MODE in unit files; dev auth bypass is OFF; set CONNECTOR_PRODUCTION_REJECT_DEV_MODE=1 to fail boot until fixed"
                    .into(),
            );
        }
        Some("fatal_on_boot") => {
            warnings.push(
                "production hygiene: production + truthy CONNECTOR_DEV_MODE with CONNECTOR_PRODUCTION_REJECT_DEV_MODE — future boots will exit until DEV_MODE is cleared (this process already passed boot)"
                    .into(),
            );
        }
        _ => {}
    }
    let seccomp_policy = p5
        .get("plugin_subprocess_seccomp")
        .and_then(|x| x.as_str())
        .unwrap_or("?");
    let seccomp_intent = p5
        .get("plugin_subprocess_seccomp_intent")
        .and_then(|x| x.as_str())
        .unwrap_or("off");
    if seccomp_intent == "custom" {
        warnings.push(
            "seccomp intent is custom/unknown; expected off|strict|safe_default|no_network|no_ingress"
                .to_string(),
        );
    }
    if seccomp_policy == "custom" {
        warnings.push(
            "seccomp policy resolved to custom/unknown; subprocess launches may fail on unsupported mode"
                .to_string(),
        );
    }
    if let Some(res) = p5.get("plugin_subprocess_seccomp_resolution") {
        let deny_supported = res
            .get("deny_profiles_supported")
            .and_then(|x| x.as_bool())
            .unwrap_or(true);
        let eff = res
            .get("effective_policy")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let arch = res.get("arch").and_then(|x| x.as_str()).unwrap_or("?");
        if !deny_supported
            && matches!(
                eff,
                "deny_dangerous" | "network_deny" | "network_ingress_deny"
            )
        {
            warnings.push(format!(
                "seccomp policy `{}` is not supported on arch `{}` (supported: x86_64/aarch64)",
                eff, arch
            ));
        }
    }
    let microvm_egress_enforce = p5
        .get("microvm_egress_enforce")
        .and_then(|x| x.as_str())
        .unwrap_or("off");
    let microvm_egress_enforce_required = p5
        .get("microvm_egress_enforce_required")
        .and_then(|x| x.as_str())
        .unwrap_or("off");
    if microvm_egress_enforce == "iptables"
        && microvm_egress_enforce_required == "on"
        && std::env::consts::OS != "linux"
    {
        warnings.push(format!(
            "microvm egress enforce is required but host OS `{}` cannot provide Linux iptables enforcement (set CONNECTOR_MICROVM_EGRESS_ENFORCE_REQUIRED=off or use Linux host path)",
            std::env::consts::OS
        ));
    }
    #[cfg(target_os = "linux")]
    if microvm_egress_enforce == "iptables" {
        if !phase5_host_tool_responds("iptables", &["-V"]) {
            warnings.push(
                "CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables but `iptables -V` failed; TAP egress will not apply until fixed"
                    .to_string(),
            );
        }
        if !phase5_host_tool_responds("ip", &["-V"]) {
            warnings.push(
                "CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables but `ip -V` failed; TAP setup requires iproute2"
                    .to_string(),
            );
        }
        if !phase5_host_tool_responds("ip6tables", &["-V"]) {
            warnings.push(
                "CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables but `ip6tables -V` failed; IPv6 TCP allowlists (AAAA) need ip6tables — install legacy ip6tables or use IPv4-only caps"
                    .to_string(),
            );
        }
    }
    warnings
}

#[cfg(target_os = "linux")]
fn phase5_host_tool_responds(bin: &str, probe: &[&str]) -> bool {
    std::process::Command::new(bin)
        .args(probe)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn phase5_preflight_warning_level_from_warnings(warnings: &[String]) -> &'static str {
    if warnings.is_empty() {
        "ok"
    } else {
        "warn"
    }
}

pub fn plugin_subprocess_seccomp_label_from_raw(raw: &str) -> &'static str {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() || matches!(s.as_str(), "off" | "0" | "false") {
        "off"
    } else if matches!(s.as_str(), "strict" | "mode_strict") {
        "strict"
    } else if matches!(s.as_str(), "deny_dangerous" | "deny-dangerous" | "baseline") {
        "deny_dangerous"
    } else if matches!(s.as_str(), "network_deny" | "network-deny") {
        "network_deny"
    } else if matches!(
        s.as_str(),
        "network_ingress_deny" | "network-ingress-deny" | "ingress_deny" | "ingress-deny"
    ) {
        "network_ingress_deny"
    } else {
        "custom"
    }
}

pub fn plugin_subprocess_seccomp_intent_label_from_raw(raw: &str) -> &'static str {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() || matches!(s.as_str(), "off" | "0" | "false" | "none" | "disabled") {
        "off"
    } else if matches!(s.as_str(), "strict") {
        "strict"
    } else if matches!(s.as_str(), "safe_default" | "safe-default" | "safe") {
        "safe_default"
    } else if matches!(s.as_str(), "no_network" | "no-network") {
        "no_network"
    } else if matches!(s.as_str(), "no_ingress" | "no-ingress") {
        "no_ingress"
    } else {
        "custom"
    }
}

fn plugin_subprocess_seccomp_from_intent_label(intent: &str) -> &'static str {
    match intent {
        "strict" => "strict",
        "safe_default" => "deny_dangerous",
        "no_network" => "network_deny",
        "no_ingress" => "network_ingress_deny",
        "off" => "off",
        _ => "custom",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_egress_labels_match_runtime_semantics() {
        assert_eq!(docker_lab_egress_mode_label_from_raw(""), "unrestricted");
        assert_eq!(docker_lab_egress_mode_label_from_raw("  "), "unrestricted");
        assert_eq!(
            docker_lab_egress_mode_label_from_raw("OPEN"),
            "unrestricted"
        );
        assert_eq!(
            docker_lab_egress_mode_label_from_raw("deny_all"),
            "deny_all"
        );
        assert_eq!(
            docker_lab_egress_mode_label_from_raw("Deny-All"),
            "deny_all"
        );
        assert_eq!(docker_lab_egress_mode_label_from_raw("none"), "deny_all");
        assert_eq!(
            docker_lab_egress_mode_label_from_raw("allowlist_strict"),
            "allowlist_strict"
        );
        assert_eq!(docker_lab_egress_mode_label_from_raw("bogus"), "custom");
    }

    #[test]
    fn docker_egress_enforce_labels_match_runtime_semantics() {
        assert_eq!(docker_lab_egress_enforce_label_from_raw(""), "off");
        assert_eq!(
            docker_lab_egress_enforce_label_from_raw("iptables"),
            "iptables"
        );
        assert_eq!(
            docker_lab_egress_enforce_label_from_raw("Docker_User"),
            "iptables"
        );
        assert_eq!(docker_lab_egress_enforce_label_from_raw("bogus"), "off");
    }

    #[test]
    fn cgroup_labels_normalize_raw_values() {
        assert_eq!(plugin_subprocess_cgroup_parent_label_from_raw(""), "off");
        assert_eq!(plugin_subprocess_cgroup_parent_label_from_raw("   "), "off");
        assert_eq!(
            plugin_subprocess_cgroup_parent_label_from_raw("/sys/fs/cgroup/x"),
            "set"
        );
        assert_eq!(plugin_tier_cgroup_scan_label_from_raw(""), "off");
        assert_eq!(plugin_tier_cgroup_scan_label_from_raw("0"), "off");
        assert_eq!(plugin_tier_cgroup_scan_label_from_raw("false"), "off");
        assert_eq!(plugin_tier_cgroup_scan_label_from_raw("yes"), "on");
        assert_eq!(plugin_tier_cgroup_scan_label_from_raw("ON"), "on");
        assert_eq!(plugin_tier_cgroup_idle_demote_label_from_raw(""), "off");
        assert_eq!(plugin_tier_cgroup_idle_demote_label_from_raw("0"), "off");
        assert_eq!(plugin_tier_cgroup_idle_demote_label_from_raw("yes"), "on");
    }

    #[test]
    fn subprocess_seccomp_labels_normalize_values() {
        assert_eq!(plugin_subprocess_seccomp_label_from_raw(""), "off");
        assert_eq!(plugin_subprocess_seccomp_label_from_raw("off"), "off");
        assert_eq!(plugin_subprocess_seccomp_label_from_raw("strict"), "strict");
        assert_eq!(
            plugin_subprocess_seccomp_label_from_raw("MODE_STRICT"),
            "strict"
        );
        assert_eq!(
            plugin_subprocess_seccomp_label_from_raw("deny-dangerous"),
            "deny_dangerous"
        );
        assert_eq!(
            plugin_subprocess_seccomp_label_from_raw("baseline"),
            "deny_dangerous"
        );
        assert_eq!(
            plugin_subprocess_seccomp_label_from_raw("network_deny"),
            "network_deny"
        );
        assert_eq!(
            plugin_subprocess_seccomp_label_from_raw("ingress-deny"),
            "network_ingress_deny"
        );
        assert_eq!(plugin_subprocess_seccomp_label_from_raw("weird"), "custom");
    }

    #[test]
    fn subprocess_seccomp_intent_labels_normalize_values() {
        assert_eq!(plugin_subprocess_seccomp_intent_label_from_raw(""), "off");
        assert_eq!(
            plugin_subprocess_seccomp_intent_label_from_raw("safe-default"),
            "safe_default"
        );
        assert_eq!(
            plugin_subprocess_seccomp_intent_label_from_raw("no_network"),
            "no_network"
        );
        assert_eq!(
            plugin_subprocess_seccomp_intent_label_from_raw("no-ingress"),
            "no_ingress"
        );
        assert_eq!(
            plugin_subprocess_seccomp_intent_label_from_raw("bogus"),
            "custom"
        );
    }

    #[test]
    fn subprocess_seccomp_resolution_prefers_intent() {
        std::env::set_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP", "strict");
        std::env::set_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT", "safe_default");
        let r = plugin_subprocess_seccomp_resolution();
        assert_eq!(
            r.get("effective_policy").and_then(|v| v.as_str()),
            Some("deny_dangerous")
        );
        assert_eq!(r.get("source").and_then(|v| v.as_str()), Some("intent"));
        std::env::remove_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP");
        std::env::remove_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT");
    }

    #[test]
    fn microvm_egress_labels_normalize_values() {
        assert_eq!(microvm_egress_mode_label_from_raw(""), "deny_all");
        assert_eq!(microvm_egress_mode_label_from_raw("none"), "deny_all");
        assert_eq!(microvm_egress_mode_label_from_raw("deny-all"), "deny_all");
        assert_eq!(
            microvm_egress_mode_label_from_raw("allowlist_strict"),
            "allowlist_strict"
        );
        assert_eq!(microvm_egress_mode_label_from_raw("allowlist"), "custom");
    }

    #[test]
    fn microvm_egress_enforce_labels_match_runtime_semantics() {
        assert_eq!(microvm_egress_enforce_label_from_raw(""), "off");
        assert_eq!(
            microvm_egress_enforce_label_from_raw("iptables"),
            "iptables"
        );
        assert_eq!(
            microvm_egress_enforce_label_from_raw("IPTABLES_FORWARD"),
            "iptables"
        );
        assert_eq!(microvm_egress_enforce_label_from_raw("bogus"), "off");
    }

    #[test]
    fn microvm_egress_enforce_required_label_normalizes_truthy_values() {
        assert_eq!(microvm_egress_enforce_required_label_from_raw(""), "off");
        assert_eq!(microvm_egress_enforce_required_label_from_raw("0"), "off");
        assert_eq!(microvm_egress_enforce_required_label_from_raw("1"), "on");
        assert_eq!(microvm_egress_enforce_required_label_from_raw("TRUE"), "on");
    }

    #[test]
    fn microvm_guest_iface_label_normalizes_raw_values() {
        assert_eq!(
            super::microvm_guest_iface_label_from_raw(""),
            "default(eth0)"
        );
        assert_eq!(
            super::microvm_guest_iface_label_from_raw("  "),
            "default(eth0)"
        );
        assert_eq!(super::microvm_guest_iface_label_from_raw("eth1"), "set");
    }

    #[test]
    fn phase5_preflight_warnings_report_custom_seccomp_inputs() {
        let p5 = serde_json::json!({
            "plugin_subprocess_seccomp": "custom",
            "plugin_subprocess_seccomp_intent": "custom",
            "plugin_subprocess_seccomp_resolution": {
                "deny_profiles_supported": true,
                "effective_policy": "custom",
                "arch": "x86_64"
            },
            "microvm_egress_enforce": "off",
            "microvm_egress_enforce_required": "off"
        });
        let ws = phase5_preflight_warnings_from_operator(&p5);
        assert!(ws
            .iter()
            .any(|w| w.contains("seccomp intent is custom/unknown")));
        assert!(ws
            .iter()
            .any(|w| w.contains("seccomp policy resolved to custom/unknown")));
    }

    #[test]
    fn phase5_preflight_warns_on_production_dev_mode_hygiene_labels() {
        let p5_warn = serde_json::json!({
            "production_dev_mode_hygiene": "warn_on_boot",
            "plugin_subprocess_seccomp": "off",
            "plugin_subprocess_seccomp_intent": "off",
            "microvm_egress_enforce": "off",
            "microvm_egress_enforce_required": "off"
        });
        let ws = phase5_preflight_warnings_from_operator(&p5_warn);
        assert!(ws.iter().any(|w| w.contains("production hygiene")));

        let p5_fatal = serde_json::json!({
            "production_dev_mode_hygiene": "fatal_on_boot",
            "plugin_subprocess_seccomp": "off",
            "plugin_subprocess_seccomp_intent": "off",
            "microvm_egress_enforce": "off",
            "microvm_egress_enforce_required": "off"
        });
        let ws2 = phase5_preflight_warnings_from_operator(&p5_fatal);
        assert!(ws2
            .iter()
            .any(|w| w.contains("CONNECTOR_PRODUCTION_REJECT_DEV_MODE")));
    }

    #[test]
    fn phase5_preflight_warning_level_matches_warning_count() {
        assert_eq!(phase5_preflight_warning_level_from_warnings(&[]), "ok");
        assert_eq!(
            phase5_preflight_warning_level_from_warnings(&["x".to_string()]),
            "warn"
        );
    }
}
