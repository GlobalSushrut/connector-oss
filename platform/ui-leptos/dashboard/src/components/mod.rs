pub mod layout;
pub mod cards;
pub mod icons;
pub mod actions;
pub mod status_banner;
pub mod live_dot_pill;
pub mod system_health_card;
pub mod wizard;
pub mod empty_state;
pub mod install_card;
pub mod featured_slot;
pub mod countdown_pill;
pub mod session_end_modal;
pub mod capacity_meters;
pub mod mode_banner;
pub mod update_toast;
pub mod whats_new_toast;
pub mod recommendations;
pub mod page_title;
pub mod sidebar_personal;
pub mod surface;
pub mod connector_yaml_editor;
// Next/React-grade UX primitives.
pub mod skeleton;
pub mod toaster;
pub mod error_boundary;
// Industry-standard primitive library (Button, TextField, Dialog, …).
// New code should compose against `ui::*` rather than re-implementing
// per-page state machines / classnames.
pub mod ui;
pub mod operator;
