//! MicroVM tool / channel plane — every tool effect and world channel runs via microVM.
//!
//! Under `CONNECTOR_TOOLS_IN_MICROVM=1` (production / distrust default):
//! - Local I/O (shell / filesystem / exec) → microVM guest
//! - Robotics / IoT / MQTT / Modbus / machine HAL → microVM channel (agentic brain never
//!   holds a direct host socket to the device)
//! - Remote MCP HTTPS may stay on host broker only when `CONNECTOR_ALLOW_HOST_MCP_BROKER=1`
//! - WM memory syscalls stay on Connector kernel

use serde_json::{json, Value};

use crate::services::runtime_control::IsolationRuntime;
use crate::state::{PlatformState, SharedState};
use crate::substrate::effect_exclusivity::EffectClass;

pub const SCHEMA: &str = "connector.microvm_tool_plane.v1";

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Master switch — all tools (incl. I/O + physical channels) must run via microVM.
pub fn tools_in_microvm_enforced() -> bool {
    if env_flag("CONNECTOR_ALLOW_IN_PROCESS_EFFECTS") {
        return false;
    }
    env_flag("CONNECTOR_TOOLS_IN_MICROVM")
        || crate::substrate::probabilistic_llm::distrust_enforced()
        || crate::substrate::effect_exclusivity::effect_exclusivity_enforced()
}

/// Whether a microVM host runtime appears available on this node (honesty probe).
pub fn host_available() -> bool {
    let binary = ["firecracker", "jailer", "connector-microvm"]
        .into_iter()
        .any(which_bin);
    let kvm = std::path::Path::new("/dev/kvm").exists()
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok();
    let production = matches!(
        std::env::var("CONNECTOR_ENV")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "production" | "prod" | "staging" | "airgap" | "defense-strict" | "unbypassable"
    );
    if production {
        return binary && kvm;
    }
    if env_flag("CONNECTOR_MICROVM_HOST_AVAILABLE") {
        return true;
    }
    binary
}

fn which_bin(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p).any(|dir| {
                let candidate = dir.join(name);
                candidate.is_file()
            })
        })
        .unwrap_or(false)
}

/// World channels (robot / IoT / mqtt / …) must traverse microVM.
pub fn world_channel_via_microvm() -> bool {
    if env_flag("CONNECTOR_ALLOW_IN_PROCESS_EFFECTS") {
        return false;
    }
    env_flag("CONNECTOR_WORLD_CHANNEL_VIA_MICROVM") || tools_in_microvm_enforced()
}

/// Narrow exception: host may dial remote MCP over HTTPS (broker). Local I/O + physical channels still forbidden.
pub fn host_mcp_broker_allowed() -> bool {
    env_flag("CONNECTOR_ALLOW_HOST_MCP_BROKER") && !env_flag("CONNECTOR_TOOLS_IN_MICROVM_STRICT")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    LocalIo,
    Robotics,
    Iot,
    Mqtt,
    Modbus,
    Machine,
    Device,
    McpHttps,
    KernelMemory,
}

impl ChannelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalIo => "local_io",
            Self::Robotics => "robotics",
            Self::Iot => "iot",
            Self::Mqtt => "mqtt",
            Self::Modbus => "modbus",
            Self::Machine => "machine",
            Self::Device => "device",
            Self::McpHttps => "mcp_https",
            Self::KernelMemory => "kernel_memory",
        }
    }

    pub fn is_physical_world(self) -> bool {
        matches!(
            self,
            Self::Robotics | Self::Iot | Self::Mqtt | Self::Modbus | Self::Machine | Self::Device
        )
    }
}

/// Classify from MCP bridge / tool name.
pub fn classify_channel(bridge_id: &str, tool_name: &str) -> ChannelKind {
    let t = tool_name.to_ascii_lowercase();
    let b = bridge_id.to_ascii_lowercase();
    if b == "wm" && t.starts_with("memory.") {
        return ChannelKind::KernelMemory;
    }
    if matches!(
        b.as_str(),
        "robot" | "robotics" | "robot_hal" | "hal" | "ros" | "ros2"
    ) || t.contains("robot")
        || t.starts_with("hal.")
        || t.contains("move_axis")
        || t.contains("joint")
    {
        return ChannelKind::Robotics;
    }
    if matches!(b.as_str(), "iot" | "iot_endpoint" | "sensor" | "actuator")
        || t.contains("iot")
        || t.starts_with("sensor.")
        || t.starts_with("actuator.")
    {
        return ChannelKind::Iot;
    }
    if b.contains("mqtt") || t.contains("mqtt") || t.starts_with("topic.") {
        return ChannelKind::Mqtt;
    }
    if b.contains("modbus") || t.contains("modbus") {
        return ChannelKind::Modbus;
    }
    if matches!(b.as_str(), "machine" | "cnc" | "plc")
        || t.contains("machine.")
        || t.starts_with("cnc.")
    {
        return ChannelKind::Machine;
    }
    if matches!(b.as_str(), "device" | "edge") || t.starts_with("device.") {
        return ChannelKind::Device;
    }
    if t.contains("shell")
        || t.contains("bash")
        || t.contains("exec")
        || t.contains("run_command")
        || t == "execute"
        || b == "shell"
        || t.contains("read_file")
        || t.contains("write_file")
        || t.contains("file_edit")
        || t.contains("multi_edit")
        || t == "read"
        || t == "write"
        || t == "edit"
        || t.contains("filesystem")
        || t.starts_with("fs.")
    {
        return ChannelKind::LocalIo;
    }
    ChannelKind::McpHttps
}

/// Classify from a CNP / world address (robot:…, iot:…, mqtt://…).
pub fn classify_address_channel(address: &str, address_type: Option<&str>) -> ChannelKind {
    if let Some(t) = address_type {
        let t = t.to_ascii_lowercase();
        match t.as_str() {
            "robot" | "robot_hal" => return ChannelKind::Robotics,
            "iot" | "iot_endpoint" => return ChannelKind::Iot,
            "mqtt" => return ChannelKind::Mqtt,
            "modbus" => return ChannelKind::Modbus,
            "machine" => return ChannelKind::Machine,
            "device" => return ChannelKind::Device,
            _ => {}
        }
    }
    let lower = address.trim().to_ascii_lowercase();
    if lower.starts_with("robot:") || lower.starts_with("robot_hal:") {
        ChannelKind::Robotics
    } else if lower.starts_with("iot:") {
        ChannelKind::Iot
    } else if lower.starts_with("mqtt:") || lower.starts_with("mqtt://") {
        ChannelKind::Mqtt
    } else if lower.starts_with("modbus:") {
        ChannelKind::Modbus
    } else if lower.starts_with("machine:") {
        ChannelKind::Machine
    } else if lower.starts_with("device:") {
        ChannelKind::Device
    } else {
        let caged = crate::kernel::address_cage::classify_address(address, "_");
        match caged.address_type.as_str() {
            "robot" | "robot_hal" => ChannelKind::Robotics,
            "iot" | "iot_endpoint" => ChannelKind::Iot,
            "mqtt" => ChannelKind::Mqtt,
            "modbus" => ChannelKind::Modbus,
            "machine" => ChannelKind::Machine,
            "device" => ChannelKind::Device,
            _ => ChannelKind::McpHttps,
        }
    }
}

pub fn classify_tool(bridge_id: &str, tool_name: &str) -> EffectClass {
    match classify_channel(bridge_id, tool_name) {
        ChannelKind::LocalIo => {
            let t = tool_name.to_ascii_lowercase();
            if t.contains("shell")
                || t.contains("bash")
                || t.contains("exec")
                || t.contains("run_command")
                || t == "execute"
            {
                EffectClass::Shell
            } else {
                EffectClass::FileSystem
            }
        }
        ChannelKind::KernelMemory => EffectClass::Memory,
        ChannelKind::Robotics
        | ChannelKind::Iot
        | ChannelKind::Mqtt
        | ChannelKind::Modbus
        | ChannelKind::Machine
        | ChannelKind::Device => EffectClass::Network,
        ChannelKind::McpHttps => EffectClass::Mcp,
    }
}

pub fn is_local_io(effect: EffectClass) -> bool {
    matches!(
        effect,
        EffectClass::Shell | EffectClass::FileSystem | EffectClass::Subprocess
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolExecPlan {
    /// Shell / FS / exec → microVM guest.
    MicrovmIo,
    /// Robotics / IoT / MQTT / Modbus / machine / device → microVM channel.
    MicrovmChannel,
    /// Remote MCP HTTPS brokered by host (no local I/O, no physical channel).
    HostMcpBroker,
    /// Memory / WM syscalls stay on Connector kernel (not host FS).
    ConnectorKernel,
}

pub fn plan_execution(bridge_id: &str, tool_name: &str) -> ToolExecPlan {
    match classify_channel(bridge_id, tool_name) {
        ChannelKind::KernelMemory => ToolExecPlan::ConnectorKernel,
        ChannelKind::LocalIo => ToolExecPlan::MicrovmIo,
        k if k.is_physical_world() => ToolExecPlan::MicrovmChannel,
        ChannelKind::McpHttps => ToolExecPlan::HostMcpBroker,
        _ => ToolExecPlan::HostMcpBroker,
    }
}

/// Declared isolation must be microVM when tools-in-microvm is on.
pub fn assert_microvm_isolation(state: &PlatformState, agent_pid: &str) -> Result<(), Value> {
    if !tools_in_microvm_enforced() && !world_channel_via_microvm() {
        return Ok(());
    }
    let runtime = *state.isolation_runtime.read().unwrap();
    if matches!(runtime, IsolationRuntime::Microvm) {
        return Ok(());
    }
    Err(json!({
        "ok": false,
        "error": "tools_require_microvm",
        "denial_reason": "in_process_effect_path",
        "schema": SCHEMA,
        "agent_pid": agent_pid,
        "declared_isolation": runtime.as_str(),
        "required_isolation": "microvm",
        "message": "All tools and world channels (robot/IoT/I/O) must run via microVM. Set CONNECTOR_ISOLATION_RUNTIME=microvm.",
        "honesty": "docker_lab alone is insufficient when CONNECTOR_TOOLS_IN_MICROVM / WORLD_CHANNEL_VIA_MICROVM is on",
        "remediation": "CONNECTOR_ISOLATION_RUNTIME=microvm CONNECTOR_PLUGIN_RUN_BACKEND=microvm",
    }))
}

/// Gate CONP / world gateway physical effects — agentic brain only via microVM channel.
pub fn assert_world_channel_via_microvm(
    state: &PlatformState,
    agent_pid: &str,
    entity_id: &str,
    capability_id: &str,
) -> Result<ChannelKind, Value> {
    let kind = classify_address_channel(entity_id, None);
    if !kind.is_physical_world() {
        return Ok(kind);
    }
    if !world_channel_via_microvm() {
        return Ok(kind);
    }
    assert_microvm_isolation(state, agent_pid)?;
    Ok(kind)
}

/// Preflight before host-side tool work.
pub fn assert_preflight(
    state: &PlatformState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
) -> Result<ToolExecPlan, Value> {
    if !tools_in_microvm_enforced() && !world_channel_via_microvm() {
        return Ok(plan_execution(bridge_id, tool_name));
    }
    assert_microvm_isolation(state, agent_pid)?;
    let plan = plan_execution(bridge_id, tool_name);
    match plan {
        ToolExecPlan::MicrovmIo | ToolExecPlan::MicrovmChannel | ToolExecPlan::ConnectorKernel => {
            Ok(plan)
        }
        ToolExecPlan::HostMcpBroker => {
            if host_mcp_broker_allowed() {
                Ok(plan)
            } else {
                Err(json!({
                    "ok": false,
                    "error": "mcp_must_run_in_microvm",
                    "denial_reason": "in_process_effect_path",
                    "schema": SCHEMA,
                    "agent_pid": agent_pid,
                    "bridge_id": bridge_id,
                    "tool": tool_name,
                    "message": "MCP must run in microVM (or CONNECTOR_ALLOW_HOST_MCP_BROKER=1). Robotics/IoT/I/O always microVM.",
                }))
            }
        }
    }
}

async fn spawn_microvm_job(
    state: &SharedState,
    agent_pid: &str,
    plugin_id: &str,
    job: Value,
) -> Result<Value, Value> {
    if let Err(e) =
        crate::substrate::sandbox_unbypassable::assert_sandbox_unbypassable(state.as_ref(), agent_pid)
    {
        return Err(e);
    }
    let (kd, rd) = crate::kernel::isolation_manifest::assert_microvm_assets_measured().map_err(
        |e| {
            json!({
                "ok": false,
                "error": "microvm_assets_unmeasured",
                "denial_reason": e,
                "schema": SCHEMA,
            })
        },
    )?;

    let principal_id = agent_pid.to_string();

    let channel_id = job
        .get("channel")
        .and_then(|v| v.as_str())
        .unwrap_or("tool");
    let op_class = job
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("microvm_job");
    let ticket = crate::kernel::isolation_manifest::authorize_vsock_channel(
        state.as_ref(),
        agent_pid,
        &principal_id,
        channel_id,
        op_class,
    )
    .map_err(|e| {
        json!({
            "ok": false,
            "error": "vsock_authorize_failed",
            "denial_reason": e,
            "schema": SCHEMA,
        })
    })?;

    let desired = crate::kernel::isolation_manifest::build_desired(
        agent_pid,
        &principal_id,
        Some(format!("vm-{agent_pid}")),
    );
    let mut measured = desired.clone();
    measured.microvm_kernel_digest = kd.clone();
    measured.microvm_rootfs_digest = rd.clone();
    measured.digest_hex.clear();
    if let Err(e) = crate::kernel::isolation_manifest::apply_and_check_drift(
        state.as_ref(),
        &desired,
        &measured,
    ) {
        return Err(json!({
            "ok": false,
            "error": "isolation_manifest_drift",
            "denial_reason": e,
            "schema": SCHEMA,
        }));
    }

    let kernel = std::env::var("CONNECTOR_MICROVM_KERNEL").unwrap_or_default();
    let rootfs = std::env::var("CONNECTOR_MICROVM_ROOTFS").unwrap_or_default();
    if kernel.trim().is_empty() || rootfs.trim().is_empty() {
        if crate::substrate::probabilistic_llm::distrust_enforced() {
            let _ = crate::substrate::probabilistic_llm::quarantine_for_bypass(
                state,
                agent_pid,
                "microvm_assets_missing",
                "Tool/channel required microVM but CONNECTOR_MICROVM_KERNEL/ROOTFS are unset",
            );
        }
        return Err(json!({
            "ok": false,
            "error": "microvm_assets_required",
            "denial_reason": "in_process_effect_path",
            "schema": SCHEMA,
            "message": "Set CONNECTOR_MICROVM_KERNEL and CONNECTOR_MICROVM_ROOTFS — host path refused",
        }));
    }

    let work_dir = std::env::temp_dir().join(format!(
        "connector-microvm-ch-{}-{}",
        agent_pid.replace('/', "_"),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&work_dir).map_err(|e| {
        json!({"error": format!("workdir: {e}"), "denial_reason": "internal_error"})
    })?;
    let mut job = job;
    if let Some(o) = job.as_object_mut() {
        o.insert("vsock_ticket".into(), json!(ticket));
        o.insert("kernel_digest".into(), json!(kd));
        o.insert("rootfs_digest".into(), json!(rd));
    }
    let job_path = work_dir.join("job.json");
    std::fs::write(&job_path, job.to_string()).map_err(|e| {
        json!({"error": format!("job write: {e}"), "denial_reason": "internal_error"})
    })?;

    let program = std::env::var("CONNECTOR_MICROVM_TOOL_ENTRY")
        .unwrap_or_else(|_| "/sbin/connector-vm-agent".into());
    let backend = connector_plugin_runtime::backend_for(
        connector_plugin_runtime::IsolationRuntime::Microvm,
        None,
        None,
    );
    let mut env = crate::kernel::docklock::cage_env_for_intelligence("tool-channel", agent_pid, agent_pid);
    env.push(("CONNECTOR_LLM_DISTRUST".into(), "1".into()));
    env.push(("CONNECTOR_TOOLS_IN_MICROVM".into(), "1".into()));
    env.push(("CONNECTOR_WORLD_CHANNEL_VIA_MICROVM".into(), "1".into()));
    env.push(("CONNECTOR_BROKER_ONLY".into(), "1".into()));
    env.push(("CONNECTOR_VSOCK_TICKET".into(), ticket.clone()));
    if crate::kernel::isolation_manifest::vsock_ticket_required() {
        env.push(("CONNECTOR_VSOCK_TICKET_REQUIRE".into(), "1".into()));
    }
    env.push((
        "CONNECTOR_MICROVM_TOOL_JOB".into(),
        job_path.to_string_lossy().into(),
    ));

    let receipt = backend
        .spawn(connector_plugin_runtime::SpawnRequest {
            plugin_id: plugin_id.into(),
            program: std::path::PathBuf::from(&program),
            args: vec![
                "--tool-job".into(),
                job_path.to_string_lossy().into_owned(),
            ],
            cwd: Some(work_dir.clone()),
            env,
            egress_allowlist: vec![],
            workspace_host_mount: Some(work_dir.clone()),
            docker_run_detached: false,
        })
        .await
        .map_err(|e| {
            json!({
                "ok": false,
                "error": "microvm_channel_spawn_failed",
                "denial_reason": "in_process_effect_path",
                "message": e.to_string(),
                "schema": SCHEMA,
            })
        })?;

    Ok(json!({
        "ok": true,
        "schema": SCHEMA,
        "executed_in": "microvm",
        "receipt": receipt,
        "vsock_ticket_bound": true,
        "isolation_manifest_digest": desired.digest_hex,
        "honesty": "Effect dispatched into microVM guest; vsock ticket + measured assets required; guest has no ambient host path.",
    }))
}

/// Host PATE ticket. The guest does not admit.
#[derive(Debug, Clone, Copy)]
pub struct ExecutionTicket<'a> {
    pub task_id: &'a str,
    pub action_digest: &'a str,
}

fn require_ticket(ticket: Option<ExecutionTicket<'_>>) -> Result<ExecutionTicket<'_>, Value> {
    if let Some(ticket) = ticket {
        if !ticket.task_id.is_empty() && !ticket.action_digest.is_empty() {
            return Ok(ticket);
        }
    }
    if crate::connector_profile::is_productionish_env() {
        return Err(json!({
            "ok": false,
            "error": "execution_ticket_required",
            "executed": false,
            "honesty": "Production microVM execution requires a host PATE task id and action digest.",
        }));
    }
    Err(json!({
        "ok": false,
        "error": "execution_ticket_required",
        "executed": false,
    }))
}

/// Execute local I/O inside a microVM guest.
pub async fn invoke_io_in_microvm(
    state: &SharedState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    input: &Value,
    ticket: Option<ExecutionTicket<'_>>,
) -> Result<Value, Value> {
    let ticket = require_ticket(ticket)?;
    assert_microvm_isolation(state.as_ref(), agent_pid)?;
    if let Err(e) = crate::kernel::isolation_manifest::assert_microvm_assets_measured() {
        return Err(json!({
            "error": "microvm_assets_unmeasured",
            "denial_reason": e,
            "honesty": "Production microVM requires measured kernel/rootfs digests at launch",
        }));
    }
    let channel = classify_channel(bridge_id, tool_name);
    if channel != ChannelKind::LocalIo {
        return Err(json!({
            "error": "not_local_io",
            "message": "invoke_io_in_microvm is only for shell/filesystem tools",
        }));
    }
    let effect = classify_tool(bridge_id, tool_name);
    let job = json!({
        "schema": SCHEMA,
        "kind": "local_io",
        "channel": channel.as_str(),
        "agent_pid": agent_pid,
        "bridge_id": bridge_id,
        "tool": tool_name,
        "effect_class": effect.as_str(),
        "input": input,
        "broker_only": true,
        "pate_task_id": ticket.task_id,
        "action_digest": ticket.action_digest,
        "admits": false,
    });
    let mut out = spawn_microvm_job(
        state,
        agent_pid,
        &format!("tool-io/{agent_pid}/{tool_name}"),
        job,
    )
    .await?;
    if let Some(o) = out.as_object_mut() {
        o.insert("effect_class".into(), json!(effect.as_str()));
        o.insert("bridge_id".into(), json!(bridge_id));
        o.insert("tool".into(), json!(tool_name));
        o.insert("agent_pid".into(), json!(agent_pid));
        o.insert("channel".into(), json!(channel.as_str()));
    }
    Ok(out)
}

/// Execute robotics / IoT / MQTT / Modbus / machine channel via microVM.
pub async fn invoke_channel_in_microvm(
    state: &SharedState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    input: &Value,
    ticket: Option<ExecutionTicket<'_>>,
) -> Result<Value, Value> {
    let ticket = require_ticket(ticket)?;
    assert_microvm_isolation(state.as_ref(), agent_pid)?;
    if let Err(e) = crate::kernel::isolation_manifest::assert_microvm_assets_measured() {
        return Err(json!({
            "error": "microvm_assets_unmeasured",
            "denial_reason": e,
            "honesty": "Production microVM requires measured kernel/rootfs digests at launch",
        }));
    }
    let channel = classify_channel(bridge_id, tool_name);
    if !channel.is_physical_world() {
        return Err(json!({
            "error": "not_world_channel",
            "message": "invoke_channel_in_microvm is for robotics/IoT/mqtt/modbus/machine/device",
            "channel": channel.as_str(),
        }));
    }
    let job = json!({
        "schema": SCHEMA,
        "kind": "world_channel",
        "channel": channel.as_str(),
        "agent_pid": agent_pid,
        "bridge_id": bridge_id,
        "tool": tool_name,
        "input": input,
        "broker_only": true,
        "pate_task_id": ticket.task_id,
        "action_digest": ticket.action_digest,
        "admits": false,
        "stance": "Agentic brain reaches devices only through Connector → microVM channel",
    });
    let mut out = spawn_microvm_job(
        state,
        agent_pid,
        &format!("channel/{}/{agent_pid}/{tool_name}", channel.as_str()),
        job,
    )
    .await?;
    if let Some(o) = out.as_object_mut() {
        o.insert("channel".into(), json!(channel.as_str()));
        o.insert("bridge_id".into(), json!(bridge_id));
        o.insert("tool".into(), json!(tool_name));
        o.insert("agent_pid".into(), json!(agent_pid));
    }
    Ok(out)
}

/// CONP command / world effect via microVM channel.
pub async fn invoke_conp_channel_in_microvm(
    state: &SharedState,
    agent_pid: &str,
    capability_id: &str,
    entity_id: &str,
    parameters: &Value,
    action_digest: &str,
) -> Result<Value, Value> {
    let kind = assert_world_channel_via_microvm(state.as_ref(), agent_pid, entity_id, capability_id)?;
    if !kind.is_physical_world() {
        return Ok(json!({
            "ok": true,
            "schema": SCHEMA,
            "channel": kind.as_str(),
            "via_microvm": false,
            "message": "Non-physical address — microVM channel not required",
        }));
    }
    let job = json!({
        "schema": SCHEMA,
        "kind": "conp_channel",
        "channel": kind.as_str(),
        "agent_pid": agent_pid,
        "capability_id": capability_id,
        "entity_id": entity_id,
        "parameters": parameters,
        "action_digest": action_digest,
        "broker_only": true,
        "stance": "CONP HAL traffic leaves the microVM guest only; host is broker/admission only",
    });
    let mut out = spawn_microvm_job(
        state,
        agent_pid,
        &format!("conp/{}/{agent_pid}/{capability_id}", kind.as_str()),
        job,
    )
    .await?;
    if let Some(o) = out.as_object_mut() {
        o.insert("channel".into(), json!(kind.as_str()));
        o.insert("capability_id".into(), json!(capability_id));
        o.insert("entity_id".into(), json!(entity_id));
        o.insert("action_digest".into(), json!(action_digest));
        o.insert("agent_pid".into(), json!(agent_pid));
    }
    Ok(out)
}

pub fn status(state: &PlatformState) -> Value {
    let runtime = *state.isolation_runtime.read().unwrap();
    json!({
        "schema": SCHEMA,
        "tools_in_microvm": tools_in_microvm_enforced(),
        "world_channel_via_microvm": world_channel_via_microvm(),
        "host_mcp_broker_allowed": host_mcp_broker_allowed(),
        "declared_isolation": runtime.as_str(),
        "microvm_ready": matches!(runtime, IsolationRuntime::Microvm),
        "kernel_set": std::env::var("CONNECTOR_MICROVM_KERNEL").map(|s| !s.trim().is_empty()).unwrap_or(false),
        "rootfs_set": std::env::var("CONNECTOR_MICROVM_ROOTFS").map(|s| !s.trim().is_empty()).unwrap_or(false),
        "channels_via_microvm": [
            "local_io", "robotics", "iot", "mqtt", "modbus", "machine", "device"
        ],
        "stance": "Agentic brain reaches tools and devices only through Connector → microVM channels.",
        "break_glass": [
            "CONNECTOR_ALLOW_IN_PROCESS_EFFECTS=1",
            "CONNECTOR_ALLOW_HOST_MCP_BROKER=1"
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_robot_iot() {
        assert_eq!(
            classify_channel("robotics", "move_axis"),
            ChannelKind::Robotics
        );
        assert_eq!(classify_channel("iot", "sensor.read"), ChannelKind::Iot);
        assert_eq!(classify_channel("mqtt", "publish"), ChannelKind::Mqtt);
        assert_eq!(
            classify_address_channel("robot:bay-3", None),
            ChannelKind::Robotics
        );
        assert_eq!(
            classify_address_channel("iot:sensor-9", Some("iot_endpoint")),
            ChannelKind::Iot
        );
        assert_eq!(
            plan_execution("robot", "hal.move"),
            ToolExecPlan::MicrovmChannel
        );
        assert_eq!(plan_execution("default", "read_file"), ToolExecPlan::MicrovmIo);
    }
}
