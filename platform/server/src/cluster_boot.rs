//! P8.2 local cell fabric boot (feature = `cluster`).
//!
//! Constructs a minimal [`vac_cluster::Cell`] so the optional `vac-cluster` dep is
//! exercised on the platform boot path. Full `ClusterKernelStore` + replication
//! bus wiring remains deferred until multi-node soak (needs EventBus + store).

use std::sync::OnceLock;

use vac_cluster::Cell;

static LOCAL_CELL: OnceLock<Cell> = OnceLock::new();

/// Resolve local cell id: `CONNECTOR_CELL_ID`, else `fallback` (platform config / `cell_local`).
pub fn resolve_local_cell_id(fallback: &str) -> String {
    std::env::var("CONNECTOR_CELL_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

/// Construct (once) a local vac-cluster [`Cell`] and log `cell_id`.
///
/// Returns a reference retained for the process lifetime. Does **not** claim
/// mesh fabric / multi-node replication — honesty APIs stay `single_node`.
pub fn boot_local_cell(fallback_cell_id: &str) -> &'static Cell {
    let cell_id = resolve_local_cell_id(fallback_cell_id);
    LOCAL_CELL.get_or_init(|| {
        let cell = Cell::new(cell_id.clone());
        tracing::info!(
            cell_id = %cell.cell_id,
            cluster_feature_compiled = true,
            "vac-cluster local Cell constructed (P8.2); ClusterKernelStore / replicate deferred until soak"
        );
        cell
    })
}

/// Substrate / mesh honesty fragment for feature=`cluster` boot.
pub fn cluster_boot_status(fallback_cell_id: &str) -> serde_json::Value {
    let local_cell_id = LOCAL_CELL
        .get()
        .map(|c| c.cell_id.clone())
        .unwrap_or_else(|| resolve_local_cell_id(fallback_cell_id));
    serde_json::json!({
        "cluster_feature_compiled": true,
        "local_cell_id": local_cell_id,
        "local_cell_constructed": LOCAL_CELL.get().is_some(),
        "mesh_fabric": false,
        "honesty": "Local Cell constructed under feature=cluster; product_sot remains single_node until multi-node soak",
    })
}
