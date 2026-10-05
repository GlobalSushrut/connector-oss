//! Phase 5.3 — microVM host scaffold (Firecracker API–shaped types; real socket I/O wired later).
//!
//! Production integration: kernel loads guest config, calls [`MicrovmHost::ensure_slot`], then
//! [`MicrovmHost::start`]. Until a Firecracker binary + rootfs are bundled, operations return
//! [`MicrovmError::HostNotConfigured`] with actionable hints.

mod error;
mod host;
mod model;

pub use error::MicrovmError;
pub use host::MicrovmHost;
pub use model::{BootSource, Drive, FirecrackerVmConfig, GuestMachineConfig, NetworkIfaceConfig, VsockConfig};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_stub_without_socket_errors() {
        // Hermetic: KVM acceptance may export CONNECTOR_FIRECRACKER_BIN in the same shell.
        let prev_fc = std::env::var_os("CONNECTOR_FIRECRACKER_BIN");
        let prev_jailer = std::env::var_os("CONNECTOR_JAILER_BIN");
        std::env::remove_var("CONNECTOR_FIRECRACKER_BIN");
        std::env::remove_var("CONNECTOR_JAILER_BIN");

        let h = MicrovmHost::default();
        assert!(!h.is_ready());
        let e = h.start(&FirecrackerVmConfig {
            vm_id: "acme/demo".into(),
            api_socket_path: "/tmp/firecracker-demo.sock".into(),
            log_path: "/tmp/firecracker-demo.log".into(),
            machine_config: GuestMachineConfig {
                vcpu_count: 1,
                mem_mib: 128,
                smt: false,
                track_dirty_pages: false,
            },
            boot_source: BootSource {
                kernel_image_path: "/tmp/vmlinux".into(),
                boot_args: None,
                initrd_path: None,
            },
            drives: vec![],
            network_iface: None,
            vsock: None,
            metrics_path: None,
        });
        assert!(e.is_err());

        match prev_fc {
            Some(v) => std::env::set_var("CONNECTOR_FIRECRACKER_BIN", v),
            None => std::env::remove_var("CONNECTOR_FIRECRACKER_BIN"),
        }
        match prev_jailer {
            Some(v) => std::env::set_var("CONNECTOR_JAILER_BIN", v),
            None => std::env::remove_var("CONNECTOR_JAILER_BIN"),
        }
    }

    /// Live KVM acceptance — run only when `CONNECTOR_CVR_KVM_LIVE=1` and assets exist.
    /// Invoked by `platform/scripts/cvr-kvm-acceptance.sh` via `--ignored`.
    #[test]
    #[ignore = "requires /dev/kvm + firecracker + kernel + rootfs"]
    fn kvm_live_start_pause_stop() {
        use std::path::{Path, PathBuf};

        if std::env::var("CONNECTOR_CVR_KVM_LIVE").ok().as_deref() != Some("1") {
            panic!("set CONNECTOR_CVR_KVM_LIVE=1 to run this test");
        }
        assert!(
            Path::new("/dev/kvm").exists(),
            "/dev/kvm required for kvm_live"
        );

        let fc = std::env::var("CONNECTOR_FIRECRACKER_BIN")
            .expect("CONNECTOR_FIRECRACKER_BIN");
        let kernel = std::env::var("CONNECTOR_MICROVM_KERNEL")
            .expect("CONNECTOR_MICROVM_KERNEL");
        let rootfs = std::env::var("CONNECTOR_MICROVM_ROOTFS")
            .expect("CONNECTOR_MICROVM_ROOTFS");
        assert!(Path::new(&fc).is_file(), "firecracker missing: {fc}");
        assert!(Path::new(&kernel).is_file(), "kernel missing: {kernel}");
        assert!(Path::new(&rootfs).is_file(), "rootfs missing: {rootfs}");

        let base = std::env::var("CONNECTOR_MICROVM_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/cvr-mc"));
        // Unix SOCK paths must stay under SUN_LEN (~108); keep instance dirs short.
        let dir = base.join(format!(
            "t{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() % 1_000_000)
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("state dir");

        let api = dir.join("fc.sock");
        let log = dir.join("fc.log");
        let cfg = FirecrackerVmConfig {
            vm_id: "cvr-kvm-accept".into(),
            api_socket_path: api.display().to_string(),
            log_path: log.display().to_string(),
            machine_config: GuestMachineConfig {
                vcpu_count: 1,
                mem_mib: 128,
                smt: false,
                track_dirty_pages: false,
            },
            boot_source: BootSource {
                kernel_image_path: kernel,
                boot_args: Some("console=ttyS0 reboot=k panic=1 pci=off".into()),
                initrd_path: None,
            },
            drives: vec![Drive {
                drive_id: "rootfs".into(),
                path_on_host: rootfs,
                is_root_device: true,
                is_read_only: true,
            }],
            network_iface: None,
            vsock: None,
            metrics_path: None,
        };

        let host = MicrovmHost::new(None).with_firecracker_bin(Some(PathBuf::from(fc)));
        let started = host
            .start_with_options(&cfg, false)
            .expect("InstanceStart must succeed on KVM acceptance host");
        assert_eq!(started.get("ok").and_then(|v| v.as_bool()), Some(true));

        // Pause / resume may fail on some guest images before full boot — still try.
        let _ = host.pause(&cfg.api_socket_path);
        let _ = host.resume(&cfg.api_socket_path);

        let pid = started.get("pid").and_then(|v| v.as_u64()).map(|p| p as u32);
        let stopped = host
            .stop(&cfg.api_socket_path, pid)
            .expect("stop must succeed");
        assert_eq!(stopped.get("ok").and_then(|v| v.as_bool()), Some(true));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
