use serde::{Deserialize, Serialize};

/// Guest kernel + initrd / boot args (Firecracker `boot-source` payload subset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootSource {
    pub kernel_image_path: String,
    #[serde(default)]
    pub boot_args: Option<String>,
    #[serde(default)]
    pub initrd_path: Option<String>,
}

/// Block device backed by host path (Firecracker `drives` subset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Drive {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    #[serde(default)]
    pub is_read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VsockConfig {
    pub guest_cid: u32,
    pub uds_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestMachineConfig {
    pub vcpu_count: u8,
    pub mem_mib: u32,
    #[serde(default)]
    pub smt: bool,
    #[serde(default)]
    pub track_dirty_pages: bool,
}

/// Virtio network device backed by a host TAP (`PUT /network-interfaces/{iface_id}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIfaceConfig {
    pub iface_id: String,
    pub host_dev_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirecrackerVmConfig {
    pub vm_id: String,
    /// Firecracker API Unix socket path for this VM.
    pub api_socket_path: String,
    /// Firecracker process logs sink path.
    pub log_path: String,
    pub machine_config: GuestMachineConfig,
    pub boot_source: BootSource,
    #[serde(default)]
    pub drives: Vec<Drive>,
    /// When set, Firecracker attaches this host TAP before `InstanceStart`.
    #[serde(default)]
    pub network_iface: Option<NetworkIfaceConfig>,
    #[serde(default)]
    pub vsock: Option<VsockConfig>,
    #[serde(default)]
    pub metrics_path: Option<String>,
}
