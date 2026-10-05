//! Global UI state: search palette, drawer topics, create modals, developer view.

#![allow(dead_code)]

use leptos::prelude::*;

#[derive(Debug, Clone, Copy)]
pub struct SearchOverlay {
    pub open: ReadSignal<bool>,
    pub set_open: WriteSignal<bool>,
}

pub fn provide_search_overlay() {
    let (open, set_open) = signal(false);
    provide_context(SearchOverlay { open, set_open });
}

pub fn use_search_overlay() -> SearchOverlay {
    use_context::<SearchOverlay>().expect(
        "SearchOverlay context not provided — call `ui_state::provide_search_overlay()` in App",
    )
}

pub type SessionEndModalState = (ReadSignal<bool>, WriteSignal<bool>);

pub fn provide_session_end_modal() {
    let (open, set_open) = signal(false);
    provide_context::<SessionEndModalState>((open, set_open));
}

pub fn use_session_end_modal() -> SessionEndModalState {
    use_context::<SessionEndModalState>().expect(
        "SessionEndModalState context not provided — call `ui_state::provide_session_end_modal()`",
    )
}

pub type DeveloperViewState = (ReadSignal<bool>, WriteSignal<bool>);

const DEVELOPER_VIEW_KEY: &str = "developer_view_enabled";

pub fn provide_developer_view() {
    use gloo_storage::{LocalStorage, Storage};

    let initial: bool = LocalStorage::get(DEVELOPER_VIEW_KEY).unwrap_or(false);
    let (read, write) = signal(initial);
    Effect::new(move |_| {
        let v = read.get();
        let _ = LocalStorage::set(DEVELOPER_VIEW_KEY, v);
    });
    provide_context::<DeveloperViewState>((read, write));
}

pub fn use_developer_view() -> DeveloperViewState {
    use_context::<DeveloperViewState>().expect(
        "DeveloperViewState context not provided — call `ui_state::provide_developer_view()`",
    )
}

pub type MobileDrawerState = (ReadSignal<bool>, WriteSignal<bool>);

pub fn provide_mobile_drawer() {
    let (open, set_open) = signal(false);
    provide_context::<MobileDrawerState>((open, set_open));
}

pub fn use_mobile_drawer() -> MobileDrawerState {
    use_context::<MobileDrawerState>().expect(
        "MobileDrawerState context not provided — call `ui_state::provide_mobile_drawer()`",
    )
}

/// Drawer topic kinds — workflow detail plus demoted page topics.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DrawerTopic {
    #[default]
    None,
    Workflow(String),
    Agent(String),
    Settings(String),
    Memory,
    Trust,
    Cost,
    Safety,
    Monitor,
    Conductor,
    Notifications,
    Secrets,
    Webhooks,
    License,
    Billing,
}

impl DrawerTopic {
    pub fn is_open(&self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OperatorDrawer {
    pub topic: ReadSignal<DrawerTopic>,
    pub set_topic: WriteSignal<DrawerTopic>,
    pub tab: ReadSignal<String>,
    pub set_tab: WriteSignal<String>,
}

pub fn provide_operator_drawer() {
    let (topic, set_topic) = signal(DrawerTopic::None);
    let (tab, set_tab) = signal("overview".to_string());
    provide_context(OperatorDrawer {
        topic,
        set_topic,
        tab,
        set_tab,
    });
}

pub fn use_operator_drawer() -> OperatorDrawer {
    use_context::<OperatorDrawer>().expect(
        "OperatorDrawer context not provided — call `ui_state::provide_operator_drawer()` in App",
    )
}

pub fn open_workflow_drawer(workflow_id: impl Into<String>) {
    let drawer = use_operator_drawer();
    drawer.set_tab.set("overview".into());
    drawer.set_topic.set(DrawerTopic::Workflow(workflow_id.into()));
}

/// Live "what is happening / who blocked it" popup.
///
/// Holds the agent pid currently being explained. `None` = closed.
#[derive(Debug, Clone, Copy)]
pub struct AgentExplain {
    pub pid: ReadSignal<Option<String>>,
    pub set_pid: WriteSignal<Option<String>>,
}

pub fn provide_agent_explain() {
    let (pid, set_pid) = signal(None::<String>);
    provide_context(AgentExplain { pid, set_pid });
}

pub fn use_agent_explain() -> AgentExplain {
    use_context::<AgentExplain>().expect(
        "AgentExplain context not provided — call `ui_state::provide_agent_explain()` in App",
    )
}

/// Open the live explain popup for an agent. Safe to call from anywhere the
/// operator "touches" an agent.
pub fn open_agent_explain(pid: impl Into<String>) {
    if let Some(explain) = use_context::<AgentExplain>() {
        explain.set_pid.set(Some(pid.into()));
    }
}

pub fn close_agent_explain() {
    if let Some(explain) = use_context::<AgentExplain>() {
        explain.set_pid.set(None);
    }
}

/// Touching an agent opens both the working drawer and the live status popup,
/// so a quarantined / blocked agent explains itself before the operator acts.
pub fn open_agent_drawer(pid: impl Into<String>) {
    let pid = pid.into();
    let drawer = use_operator_drawer();
    drawer.set_tab.set("action".into());
    drawer.set_topic.set(DrawerTopic::Agent(pid.clone()));
    open_agent_explain(pid);
}

/// Navigate to the Operations Theater Workbench for this agent.
pub fn open_agent_workbench(pid: impl Into<String>) {
    open_agent_workbench_session(pid, None::<String>);
}

/// Navigate to theater with an optional Workbench session selected.
pub fn open_agent_workbench_session(pid: impl Into<String>, session_id: Option<impl Into<String>>) {
    let pid = pid.into();
    let sid = session_id.map(|s| s.into()).unwrap_or_default();
    if let Some(window) = web_sys::window() {
        let href = if sid.is_empty() {
            format!("/run/workbench/{pid}")
        } else {
            format!("/run/workbench/{pid}?session={sid}")
        };
        let _ = window.location().set_href(&href);
    }
}

/// Shared Workbench session focus so theater and drawer Talk use the same journal.
#[derive(Debug, Clone, Copy)]
pub struct WorkbenchFocusBus {
    pub agent_pid: ReadSignal<String>,
    pub set_agent_pid: WriteSignal<String>,
    pub session_id: ReadSignal<String>,
    pub set_session_id: WriteSignal<String>,
}

pub fn provide_workbench_focus() {
    let (agent_pid, set_agent_pid) = signal(String::new());
    let (session_id, set_session_id) = signal(String::new());
    provide_context(WorkbenchFocusBus {
        agent_pid,
        set_agent_pid,
        session_id,
        set_session_id,
    });
}

pub fn use_workbench_focus() -> Option<WorkbenchFocusBus> {
    use_context::<WorkbenchFocusBus>()
}

pub fn focus_workbench_session(agent_pid: &str, session_id: &str) {
    let Some(bus) = use_workbench_focus() else {
        return;
    };
    bus.set_agent_pid.set(agent_pid.to_string());
    bus.set_session_id.set(session_id.to_string());
}

pub fn workbench_session_for(agent_pid: &str) -> Option<String> {
    let bus = use_workbench_focus()?;
    if bus.agent_pid.get_untracked() == agent_pid {
        let sid = bus.session_id.get_untracked();
        if sid.is_empty() {
            None
        } else {
            Some(sid)
        }
    } else {
        None
    }
}

/// Open agent drawer on the Action tab (DAL / proposals).
pub fn open_agent_action(pid: impl Into<String>) {
    open_agent_drawer(pid);
}

/// Open the agent drawer on overview (inspect, not Talk).
pub fn open_agent_view(pid: impl Into<String>) {
    let pid = pid.into();
    let drawer = use_operator_drawer();
    drawer.set_tab.set("overview".into());
    drawer.set_topic.set(DrawerTopic::Agent(pid.clone()));
    open_agent_explain(pid);
}

/// Pending Talk tool_calls waiting for DAL admit (not executed).
#[derive(Debug, Clone, Copy)]
pub struct ToolProposalsBus {
    pub proposals_json: ReadSignal<String>,
    pub set_proposals_json: WriteSignal<String>,
    pub agent_pid: ReadSignal<String>,
    pub set_agent_pid: WriteSignal<String>,
}

pub fn provide_tool_proposals() {
    let (proposals_json, set_proposals_json) = signal(String::new());
    let (agent_pid, set_agent_pid) = signal(String::new());
    provide_context(ToolProposalsBus {
        proposals_json,
        set_proposals_json,
        agent_pid,
        set_agent_pid,
    });
}

pub fn use_tool_proposals() -> ToolProposalsBus {
    use_context::<ToolProposalsBus>().expect(
        "ToolProposalsBus not provided — call ui_state::provide_tool_proposals()",
    )
}

pub fn stash_tool_proposals(agent_pid: &str, tool_calls: &[serde_json::Value]) {
    let Some(bus) = use_context::<ToolProposalsBus>() else {
        return;
    };
    bus.set_agent_pid.set(agent_pid.to_string());
    bus.set_proposals_json.set(
        serde_json::to_string_pretty(tool_calls).unwrap_or_else(|_| "[]".into()),
    );
}

pub fn open_topic_drawer(topic: DrawerTopic) {
    let drawer = use_operator_drawer();
    drawer.set_tab.set("overview".into());
    drawer.set_topic.set(topic);
}

pub fn close_drawer() {
    let drawer = use_operator_drawer();
    drawer.set_topic.set(DrawerTopic::None);
}

/// Create-workflow / create-agent modal host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CreateModalKind {
    #[default]
    None,
    Workflow,
    Agent,
}

#[derive(Debug, Clone, Copy)]
pub struct CreateModal {
    pub kind: ReadSignal<CreateModalKind>,
    pub set_kind: WriteSignal<CreateModalKind>,
}

pub fn provide_create_modal() {
    let (kind, set_kind) = signal(CreateModalKind::None);
    provide_context(CreateModal { kind, set_kind });
}

pub fn use_create_modal() -> CreateModal {
    use_context::<CreateModal>().expect(
        "CreateModal context not provided — call `ui_state::provide_create_modal()` in App",
    )
}

pub fn open_create_workflow() {
    use_create_modal().set_kind.set(CreateModalKind::Workflow);
}

pub fn open_create_agent() {
    use_create_modal().set_kind.set(CreateModalKind::Agent);
}

/// Notification popup open state (hosted at shell root so it is not clipped).
#[derive(Debug, Clone, Copy)]
pub struct NotifyOverlay {
    pub open: ReadSignal<bool>,
    pub set_open: WriteSignal<bool>,
}

pub fn provide_notify_overlay() {
    let (open, set_open) = signal(false);
    provide_context(NotifyOverlay { open, set_open });
}

pub fn use_notify_overlay() -> NotifyOverlay {
    use_context::<NotifyOverlay>().expect(
        "NotifyOverlay context not provided — call `ui_state::provide_notify_overlay()` in App",
    )
}

pub fn toggle_notify_overlay() {
    use_notify_overlay().set_open.update(|v| *v = !*v);
}

pub fn install_search_overlay_hotkey() {
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::JsCast;
    use web_sys::KeyboardEvent;

    let overlay = use_search_overlay();
    let cb = Closure::<dyn FnMut(_)>::new(move |ev: KeyboardEvent| {
        let combo = ev.key().eq_ignore_ascii_case("k") && (ev.meta_key() || ev.ctrl_key());
        if combo {
            ev.prevent_default();
            overlay.set_open.update(|v| *v = !*v);
        }
    });

    if let Some(window) = web_sys::window() {
        let _ = window.add_event_listener_with_callback("keydown", cb.as_ref().unchecked_ref());
    }
    cb.forget();
}
