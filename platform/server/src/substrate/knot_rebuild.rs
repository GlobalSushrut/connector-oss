//! Rebuild KnotEngine + vector indexes from kernel packets on boot (I-04 / P2 persistence).

use vac_core::types::MemPacket;

use crate::state::SharedState;

/// Replay all kernel packets into KnotEngine so graph state survives restart.
pub fn rebuild_knot_from_kernel(state: &SharedState) -> usize {
    let packets: Vec<MemPacket> = {
        let kernel = state.kernel.lock().unwrap();
        // Rebuild shared vector index before releasing exclusive kernel lock.
        kernel.rebuild_vector_index();
        kernel.all_packets().into_iter().cloned().collect()
    };
    if packets.is_empty() {
        tracing::info!("Knot/vector rebuild: no packets (cold store)");
        return 0;
    }
    let count = packets.len();
    let mut knot = state.knot.lock().unwrap();
    knot.ingest_packets(&packets, 0);
    let nodes = knot.node_count();
    tracing::info!(
        packet_count = count,
        knot_nodes = nodes,
        "Knot + vector index rebuilt from kernel packets on boot"
    );
    count
}

pub fn knot_node_count(state: &SharedState) -> usize {
    state.knot.lock().unwrap().node_count()
}

/// Explicit vector-only rebuild (e.g. after memwrite without knot ingest).
pub fn rebuild_vector_index(state: &SharedState) {
    if let Ok(kernel) = state.kernel.lock() {
        kernel.rebuild_vector_index();
    }
}
