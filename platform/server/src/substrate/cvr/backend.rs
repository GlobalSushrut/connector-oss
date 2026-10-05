//! MicroVmBackend trait + FirecrackerBackend (default — real MicrovmHost).

use serde_json::{json, Value};

use super::host_probe::probe_host;
use super::micro_cell;
use super::runtime_bundle::RuntimeBundlePosture;
use crate::state::PlatformState;

#[derive(Debug, Clone, Default)]
pub struct MicroVmMeasure {
    pub backend: String,
    pub version_hint: Option<String>,
    pub bundle_id: Option<String>,
    pub ready: bool,
}

/// Backend-neutral VMM interface (architecture §8 / §37.10).
pub trait MicroVmBackend {
    fn name(&self) -> &'static str;
    fn probe(&self) -> ProbeResult;
    fn measure(&self) -> Value;
    fn prepare(&self) -> Result<(), String>;
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct FirecrackerBackend;

impl MicroVmBackend for FirecrackerBackend {
    fn name(&self) -> &'static str {
        "firecracker"
    }

    fn probe(&self) -> ProbeResult {
        let host = probe_host();
        if host.microcell_ready() {
            ProbeResult {
                ok: true,
                detail: "KVM + firecracker + kernel + rootfs ready".into(),
            }
        } else {
            ProbeResult {
                ok: false,
                detail: format!(
                    "not ready: kvm_usable={} fc={} kernel={} rootfs={} jailer={}",
                    host.kvm_usable,
                    host.firecracker_bin.is_some(),
                    host.guest_kernel.is_some(),
                    host.guest_rootfs.is_some(),
                    host.jailer_bin.is_some(),
                ),
            }
        }
    }

    fn measure(&self) -> Value {
        let bundle = RuntimeBundlePosture::discover();
        let host = probe_host();
        json!({
            "backend": self.name(),
            "ready": host.microcell_ready(),
            "probe": self.probe().detail,
            "bundle": bundle.to_json(),
            "host_paths": {
                "instances": "/var/lib/connector/microvm/instances",
                "snapshots": "/var/lib/connector/microvm/snapshots/clean",
                "overlays": "/var/lib/connector/microvm/overlays",
            },
            "ops": ["create_and_start", "pause", "resume", "stop"],
            "phase": "C_live",
            "honesty": "FirecrackerBackend drives connector-microvm::MicrovmHost — real InstanceStart when assets+KVM present",
        })
    }

    fn prepare(&self) -> Result<(), String> {
        let p = self.probe();
        if p.ok {
            Ok(())
        } else {
            Err(p.detail)
        }
    }
}

impl FirecrackerBackend {
    /// Create and start a MicroCell (real Firecracker).
    pub fn create_and_start(
        &self,
        state: &PlatformState,
        microcell_id: &str,
        agent_pid: &str,
        dedicated: bool,
    ) -> Result<Value, Value> {
        self.create_and_start_with_resources(
            state,
            microcell_id,
            agent_pid,
            dedicated,
            super::resources::ResourceProfile::Default,
        )
    }

    pub fn create_and_start_with_resources(
        &self,
        state: &PlatformState,
        microcell_id: &str,
        agent_pid: &str,
        dedicated: bool,
        resource: super::resources::ResourceProfile,
    ) -> Result<Value, Value> {
        let inst = micro_cell::create_and_start_with_resources(
            state,
            microcell_id,
            agent_pid,
            dedicated,
            resource,
        )?;
        Ok(json!({
            "ok": true,
            "microcell": inst.to_json(),
            "backend": "firecracker",
            "applied": true,
            "dedicated": dedicated,
            "resources": resource.to_json(dedicated),
        }))
    }

    pub fn pause(&self, state: &PlatformState, microcell_id: &str) -> Value {
        micro_cell::pause(state, microcell_id)
    }

    pub fn resume(&self, state: &PlatformState, microcell_id: &str) -> Value {
        micro_cell::resume(state, microcell_id)
    }

    pub fn stop(&self, state: &PlatformState, microcell_id: &str) -> Value {
        micro_cell::stop(state, microcell_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firecracker_is_default_name() {
        assert_eq!(FirecrackerBackend.name(), "firecracker");
    }

    #[test]
    fn measure_reports_live_phase() {
        let m = FirecrackerBackend.measure();
        assert_eq!(m.get("phase").and_then(|v| v.as_str()), Some("C_live"));
    }
}
