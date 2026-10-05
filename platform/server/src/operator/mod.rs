//! Universal operator APIs — surface manifests, capability registry, edge plane, pulse.
//!
//! See [BACKEND_UNIVERSAL_CHECKLIST.md](../../../BACKEND_UNIVERSAL_CHECKLIST.md).

pub mod capability;
pub mod capability_seed;
pub mod edge;
pub mod fix_queue;
pub mod honesty;
pub mod lint_surface;
pub mod pulse;
pub mod setup_summary;
pub mod surface;
pub mod surface_merge;
pub mod watch_events;

pub use capability::{get_operator_capabilities, get_workflow_capabilities};
pub use edge::{
    delete_operator_edge_record, get_agent_edge, get_operator_edge_dns_hints,
    get_operator_edge_plane, get_operator_edge_records, get_workflow_edge,
    post_operator_edge_record, prove_operator_edge_record,
};
pub use fix_queue::get_operator_fix_queue;
pub use pulse::get_operator_pulse;
pub use setup_summary::get_operator_setup_summary;
pub use surface::{
    get_operator_panel_types, get_workflow_surface, list_workflow_surfaces, put_workflow_surface,
};
pub use watch_events::get_operator_watch_events;
