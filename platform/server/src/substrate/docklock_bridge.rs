//! DockLock bridge — re-exports Ring-1 kernel (legacy import path).

pub use crate::kernel::docklock::{
    compile_cage_profile, docklock_enforce_enabled, extract_quantum_id, probe_bypass_denied,
    ring1_enforce_enabled, status_snapshot, DOCKLOCK_BINDING_HEADER, QUANTUM_HEADER,
};
