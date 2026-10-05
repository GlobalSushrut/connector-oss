//! Central route registry for the Leptos dashboard.
//!
//! Operator IA is the five-mode rail: **RUN · WATCH · FIX · SETUP · DEV**.
//! Consumed by:
//!
//! - `OpModeRail` — primary navigation (paths live on the enum too)
//! - ⌘K palette via `search_items_for_mode`
//! - `mounted_*_path_patterns()` — CI guard against registry drift
//!
//! Legacy Overview/Trust/Build URLs remain as Hidden redirects (wired in `lib.rs`).

#![allow(dead_code)]

/// Section the entry lives under. Primary operator modes match OpModeRail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavSectionId {
    Run,
    Watch,
    Fix,
    Setup,
    Dev,
    /// Reachable by URL but not in mode-section lists (wizards, plugins, legacy aliases).
    Hidden,
}

impl NavSectionId {
    pub fn title(&self) -> &'static str {
        match self {
            NavSectionId::Run => "Run",
            NavSectionId::Watch => "Watch",
            NavSectionId::Fix => "Fix",
            NavSectionId::Setup => "Setup",
            NavSectionId::Dev => "Dev",
            NavSectionId::Hidden => "",
        }
    }

    pub fn is_collapsible(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeVisibility {
    Both,
    PlaygroundOnly,
    SelfDeployOnly,
}

#[derive(Debug, Clone)]
pub struct RouteDescriptor {
    pub path: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub icon_key: &'static str,
    pub section: NavSectionId,
    pub exact: bool,
    pub mode: ModeVisibility,
    pub requires_role: Option<&'static str>,
    pub indexable: bool,
}

impl RouteDescriptor {
    pub const fn is_nav_visible(&self) -> bool {
        !matches!(self.section, NavSectionId::Hidden)
    }
}

/// Full registry — five modes first; everything else Hidden (still routed / redirected).
pub fn registry() -> Vec<RouteDescriptor> {
    use ModeVisibility::*;
    use NavSectionId::*;

    let any = |path, label, description, icon_key, section, exact| RouteDescriptor {
        path,
        label,
        description,
        icon_key,
        section,
        exact,
        mode: Both,
        requires_role: None,
        indexable: true,
    };
    let self_only = |path, label, description, icon_key, section, exact| RouteDescriptor {
        path,
        label,
        description,
        icon_key,
        section,
        exact,
        mode: SelfDeployOnly,
        requires_role: None,
        indexable: true,
    };
    let hidden = |path, label, description, icon_key| RouteDescriptor {
        path,
        label,
        description,
        icon_key,
        section: Hidden,
        exact: false,
        mode: Both,
        requires_role: None,
        indexable: false,
    };
    let hidden_indexable = |path, label, description, icon_key| RouteDescriptor {
        path,
        label,
        description,
        icon_key,
        section: Hidden,
        exact: false,
        mode: Both,
        requires_role: None,
        indexable: true,
    };
    let hidden_playground_only = |path, label, description, icon_key| RouteDescriptor {
        path,
        label,
        description,
        icon_key,
        section: Hidden,
        exact: false,
        mode: PlaygroundOnly,
        requires_role: None,
        indexable: false,
    };

    vec![
        // ── Five modes ──────────────────────────────────────────────
        any(
            "/run",
            "Run",
            "Agents · Workbench · Action · Talk proposals → DAL/PATE → ToolDispatch",
            "agents",
            Run,
            true,
        ),
        hidden_indexable(
            "/run/workbench",
            "Workbench",
            "Operations theater — consult · admit · chart",
            "agents",
        ),
        hidden_indexable(
            "/run/workbench/:pid",
            "Workbench agent",
            "Workbench for one intelligence principal",
            "agents",
        ),
        hidden_indexable(
            "/run/trail",
            "Action Trail",
            "Track and manage action loops — journal · Admit · Cease · Expometer",
            "actionlog",
        ),
        hidden_indexable(
            "/run/trail/:pid",
            "Action Trail agent",
            "Action trail for one agent / session",
            "actionlog",
        ),
        any(
            "/watch",
            "Watch",
            "Planes · fuel · forensics · denials (machine truth)",
            "monitor",
            Watch,
            false,
        ),
        any(
            "/fix",
            "Fix",
            "PATE Ask · HITL · tool approvals · digests",
            "safety",
            Fix,
            false,
        ),
        any(
            "/setup",
            "Setup",
            "LLM · identity · DAC · MCP · institutions",
            "settings",
            Setup,
            true,
        ),
        any(
            "/dev",
            "Dev",
            "Packages · CLS · catalog · SDK · console · lab",
            "debug",
            Dev,
            true,
        ),
        // SETUP / DEV deep links (palette + rail context)
        any(
            "/setup/uplink",
            "Uplink",
            "Models · MCP bridges · scoped bindings",
            "tools",
            Setup,
            false,
        ),
        any(
            "/setup/access",
            "Access · DAC",
            "RULES + HITL per address · identity stack",
            "safety",
            Setup,
            false,
        ),
        any(
            "/dev/components",
            "Component gallery",
            "Operator primitive gallery",
            "notebook",
            Dev,
            false,
        ),
        // Self-deploy admin (redirect into SETUP in UI; keep registry for mode filter)
        self_only(
            "/billing",
            "Billing",
            "Billing and usage (→ Setup)",
            "billing",
            Hidden,
            false,
        ),
        self_only(
            "/license",
            "License",
            "License management (→ Setup)",
            "license",
            Hidden,
            false,
        ),
        self_only(
            "/settings",
            "Settings",
            "Node settings (→ Setup)",
            "settings",
            Hidden,
            false,
        ),
        // ── Wizards / plugins / legacy aliases ───────────────────────
        hidden("/setup/first-run", "First run", "Bootstrap wizard", "settings"),
        hidden(
            "/setup/connect-tool",
            "Connect tool",
            "MCP register wizard",
            "tools",
        ),
        hidden(
            "/setup/install-workflow/:template_id",
            "Install workflow",
            "Template install wizard",
            "orchestrator",
        ),
        hidden("/setup/invite", "Invite", "Invite teammate", "settings"),
        hidden("/agents/create", "Create agent", "Create agent wizard", "agents"),
        hidden(
            "/agents/:pid/charter",
            "Agent charter",
            "Charter studio",
            "agents",
        ),
        hidden(
            "/billing/setup-budget",
            "Setup budget",
            "Budget wizard",
            "billing",
        ),
        hidden("/install", "Install", "Node install commands", "settings"),
        hidden("/books", "Books & Meters", "→ Watch Fuel", "books"),
        hidden("/console", "System Console", "→ Dev Console", "debug"),
        hidden("/console/:id", "Plugin console", "Per-plugin console", "tools"),
        hidden("/guard", "Access Control", "→ Setup Access", "safety"),
        hidden("/connect", "Connect landing", "First-time connection", "marketplace"),
        hidden_playground_only("/trial", "Trial", "Hosted trial onboarding", "marketplace"),
        hidden("/plugins", "Plugins", "→ Setup", "tools"),
        hidden("/plugins/devguard", "DevGuard", "DevGuard light console", "tools"),
        hidden(
            "/plugins/devguard/setup",
            "DevGuard setup",
            "DevGuard wizard",
            "tools",
        ),
        hidden("/plugins/tracetramp", "TraceTramp", "TraceTramp light console", "tools"),
        hidden(
            "/plugins/tracetramp/setup",
            "TraceTramp setup",
            "TraceTramp wizard",
            "tools",
        ),
        hidden("/plugins/witnessctl", "WitnessCtl", "WitnessCtl light console", "tools"),
        hidden(
            "/plugins/witnessctl/setup",
            "WitnessCtl setup",
            "WitnessCtl wizard",
            "tools",
        ),
        hidden("/plugins/:id", "Plugin", "Generic plugin console", "tools"),
        // Legacy bookmarks → mode redirects (lib.rs)
        hidden_indexable("/", "Home", "Redirects to Run", "overview"),
        hidden("/home", "Home alias", "→ Run", "overview"),
        hidden("/command-center", "Command Center", "→ Run", "overview"),
        hidden("/agents", "Agents", "→ Run", "agents"),
        hidden("/workflows", "Workflows", "→ Run", "orchestrator"),
        hidden("/activity", "Activity", "→ Watch", "actionlog"),
        hidden("/actionlog", "Action Log", "→ Watch", "actionlog"),
        hidden("/history", "History", "→ Watch", "history"),
        hidden("/monitor", "Monitor", "→ Watch", "monitor"),
        hidden("/memory", "Memory", "→ Watch", "memory"),
        hidden("/runtime-enforcement", "Runtime Enforcement", "→ Watch", "monitor"),
        hidden("/compliance", "Compliance", "→ Fix", "compliance"),
        hidden("/safety", "Safety", "→ Fix", "safety"),
        hidden("/firewall", "Firewall", "→ Fix", "firewall"),
        hidden("/disputes", "Disputes", "→ Fix", "disputes"),
        hidden("/apps", "Apps", "→ Setup", "marketplace"),
        hidden("/tools", "Tools", "→ Setup Uplink", "tools"),
        hidden("/trust", "Trust", "→ Setup", "trust"),
        hidden("/secrets", "Secrets", "→ Setup", "secrets"),
        hidden("/notifications", "Notifications", "→ Setup", "notifications"),
        hidden("/webhooks", "Webhooks", "→ Setup", "webhooks"),
        hidden("/debug", "Debug", "→ Dev", "debug"),
        hidden("/protocols", "Protocols", "→ Dev", "protocols"),
        hidden("/infra", "Infra", "→ Dev", "infra"),
        hidden("/cls-catalog", "CLS Catalog", "→ Dev Catalog", "pipeline"),
        hidden("/cls-builder", "CLS Builder", "→ Dev Author", "notebook"),
        hidden("/cls-packages", "CLS Packages", "→ Dev CLS", "books"),
        hidden("/marketplace", "Marketplace", "→ Setup", "marketplace"),
        hidden("/notebook", "Notebook", "→ Dev", "notebook"),
        hidden("/pipeline", "Bring your agent", "→ Connect existing", "pipeline"),
        hidden("/experiments", "Experiments", "→ Dev", "experiments"),
        hidden("/prompts", "Prompts", "→ Dev", "prompts"),
        hidden("/insights", "Insights", "→ Run", "insights"),
        hidden("/economy", "Economy", "→ Setup", "economy"),
        hidden("/verify", "Verify", "→ Fix", "verify"),
        hidden("/orchestrator", "Orchestrator", "→ Run", "orchestrator"),
        hidden("/grounding", "Grounding", "→ Watch", "grounding"),
        hidden("/context", "Context", "→ Run", "context"),
        hidden("/multiagent", "Multi-Agent", "→ Run", "multiagent"),
        hidden("/service-map", "Service Map", "→ Dev", "infra"),
        hidden("/topology-center", "Topology Center", "→ Dev", "infra"),
        hidden("/report-center", "Report Center", "→ Watch", "books"),
    ]
}

#[derive(Debug, Clone)]
pub struct NavItem {
    pub label: &'static str,
    pub path: &'static str,
    pub icon_key: &'static str,
    pub exact: bool,
}

#[derive(Debug, Clone)]
pub struct NavSection {
    pub title: &'static str,
    pub items: Vec<NavItem>,
    pub collapsible: bool,
}

use crate::deployment::DeploymentMode;

pub fn is_visible_in(mode: DeploymentMode, descriptor: &RouteDescriptor) -> bool {
    match (descriptor.mode, mode) {
        (ModeVisibility::Both, _) => true,
        (ModeVisibility::PlaygroundOnly, DeploymentMode::Playground) => true,
        (ModeVisibility::PlaygroundOnly, _) => false,
        (ModeVisibility::SelfDeployOnly, DeploymentMode::Playground) => false,
        (ModeVisibility::SelfDeployOnly, _) => true,
    }
}

/// Mode-section tree for secondary nav / palette grouping (rail owns primary IA).
pub fn nav_sections_for_mode(mode: DeploymentMode) -> Vec<NavSection> {
    let order = [
        NavSectionId::Run,
        NavSectionId::Watch,
        NavSectionId::Fix,
        NavSectionId::Setup,
        NavSectionId::Dev,
    ];
    let reg = registry();
    let mut out = Vec::with_capacity(order.len());
    for sid in order {
        let items: Vec<NavItem> = reg
            .iter()
            .filter(|r| r.section == sid && is_visible_in(mode, r))
            .map(|r| NavItem {
                label: r.label,
                path: r.path,
                icon_key: r.icon_key,
                exact: r.exact,
            })
            .collect();
        if items.is_empty() {
            continue;
        }
        out.push(NavSection {
            title: sid.title(),
            items,
            collapsible: sid.is_collapsible(),
        });
    }
    out
}

pub fn nav_sections_from_registry() -> Vec<NavSection> {
    nav_sections_for_mode(DeploymentMode::Unknown)
}

pub fn search_items_from_registry() -> Vec<(&'static str, &'static str, &'static str, &'static str)>
{
    search_items_for_mode(DeploymentMode::Unknown)
}

pub fn search_items_for_mode(
    mode: DeploymentMode,
) -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    registry()
        .into_iter()
        .filter(|r| r.indexable && is_visible_in(mode, r))
        .map(|r| ("page", r.label, r.description, r.path))
        .collect()
}

pub fn mounted_public_path_patterns() -> &'static [&'static str] {
    &["/login", "/connect", "/trial"]
}

/// Keep in sync with `<Route>` mounts in `lib.rs`.
pub fn mounted_auth_path_patterns() -> &'static [&'static str] {
    &[
        "/",
        "/run",
        "/run/workbench",
        "/run/workbench/:pid",
        "/run/trail",
        "/run/trail/:pid",
        "/watch",
        "/fix",
        "/setup",
        "/setup/uplink",
        "/setup/access",
        "/setup/first-run",
        "/setup/connect-tool",
        "/setup/install-workflow/:template_id",
        "/setup/invite",
        "/dev",
        "/dev/components",
        "/guard",
        "/console",
        "/console/:id",
        "/books",
        "/monitor",
        "/install",
        "/agents/create",
        "/agents/:pid/charter",
        "/billing/setup-budget",
        // Legacy redirects
        "/home",
        "/agents",
        "/memory",
        "/compliance",
        "/debug",
        "/tools",
        "/protocols",
        "/safety",
        "/infra",
        "/activity",
        "/actionlog",
        "/history",
        "/pipeline",
        "/trust",
        "/disputes",
        "/insights",
        "/experiments",
        "/prompts",
        "/notebook",
        "/multiagent",
        "/notifications",
        "/webhooks",
        "/grounding",
        "/economy",
        "/marketplace",
        "/runtime-enforcement",
        "/topology-center",
        "/service-map",
        "/report-center",
        "/apps",
        "/workflows",
        "/cls-catalog",
        "/cls-builder",
        "/cls-packages",
        "/context",
        "/command-center",
        "/connect",
        "/firewall",
        "/orchestrator",
        "/verify",
        "/secrets",
        "/billing",
        "/license",
        "/settings",
        "/plugins/devguard",
        "/plugins/devguard/setup",
        "/plugins/tracetramp",
        "/plugins/tracetramp/setup",
        "/plugins/witnessctl",
        "/plugins/witnessctl/setup",
        "/plugins/:id",
        "/plugins",
    ]
}

pub fn registry_path_is_routed(registry_path: &str, mounted: &[&str]) -> bool {
    mounted
        .iter()
        .any(|pattern| route_pattern_covers(pattern, registry_path))
}

fn route_pattern_covers(mounted: &str, registry_path: &str) -> bool {
    if mounted == registry_path {
        return true;
    }
    // Dynamic segment match: /plugins/:id covers /plugins/foo conceptually for equality
    // of the pattern itself when registry stores the pattern.
    if mounted.contains("/:") {
        let m_parts: Vec<&str> = mounted.split('/').collect();
        let r_parts: Vec<&str> = registry_path.split('/').collect();
        if m_parts.len() == r_parts.len()
            && m_parts
                .iter()
                .zip(r_parts.iter())
                .all(|(m, r)| m.starts_with(':') || m == r)
        {
            return true;
        }
    }
    if !mounted.starts_with(registry_path) {
        return false;
    }
    mounted
        .get(registry_path.len()..)
        .is_some_and(|rest| rest.starts_with('/'))
}

pub fn title_for_path(path: &str) -> String {
    let trimmed = path.trim_start_matches('/').trim_end_matches('/');
    if trimmed.is_empty() {
        return registry()
            .iter()
            .find(|r| r.path == "/run")
            .map(|r| r.label.to_string())
            .unwrap_or_else(|| "Run".into());
    }

    let full = format!("/{trimmed}");
    if let Some(r) = registry().iter().find(|r| r.path == full) {
        return r.label.to_string();
    }

    // Longest static prefix (so /run/trail/:pid → Action Trail, not Run).
    let regs = registry();
    let mut best: Option<&RouteDescriptor> = None;
    for r in &regs {
        if r.path.contains(':') {
            let prefix = r
                .path
                .split('/')
                .take_while(|s| !s.starts_with(':'))
                .collect::<Vec<_>>()
                .join("/");
            let prefix = if prefix.is_empty() {
                "/".to_string()
            } else {
                prefix
            };
            if full == prefix || full.starts_with(&format!("{prefix}/")) {
                let score = prefix.len();
                if best.map(|b| b.path.len()).unwrap_or(0) < score {
                    best = Some(r);
                }
            }
            continue;
        }
        if full == r.path || full.starts_with(&format!("{}/", r.path)) {
            if best.map(|b| b.path.len()).unwrap_or(0) < r.path.len() {
                best = Some(r);
            }
        }
    }
    if let Some(r) = best {
        return r.label.to_string();
    }

    trimmed
        .split('/')
        .filter(|s| !s.starts_with(':') && !s.is_empty())
        .map(|seg| {
            let mut chars = seg.replace(['-', '_'], " ");
            if let Some(c) = chars.get_mut(0..1) {
                c.make_ascii_uppercase();
            }
            chars
        })
        .collect::<Vec<_>>()
        .join(" / ")
}

#[cfg(test)]
mod route_coverage_tests {
    use super::*;

    #[test]
    fn every_registry_path_has_router_entry() {
        let mounted: Vec<&str> = mounted_public_path_patterns()
            .iter()
            .chain(mounted_auth_path_patterns())
            .copied()
            .collect();
        for descriptor in registry() {
            assert!(
                registry_path_is_routed(descriptor.path, &mounted),
                "registry path {} has no matching <Route> in lib.rs",
                descriptor.path
            );
        }
    }

    #[test]
    fn root_path_maps_to_run_home() {
        assert_eq!(title_for_path("/"), "Run");
    }

    #[test]
    fn five_mode_labels() {
        assert_eq!(title_for_path("/run"), "Run");
        assert_eq!(title_for_path("/watch"), "Watch");
        assert_eq!(title_for_path("/fix"), "Fix");
        assert_eq!(title_for_path("/setup"), "Setup");
        assert_eq!(title_for_path("/dev"), "Dev");
        assert_eq!(title_for_path("/run/trail"), "Action Trail");
        assert_eq!(title_for_path("/run/trail/BankOps"), "Action Trail agent");
    }

    #[test]
    fn registry_labels_used_for_known_paths() {
        assert_eq!(title_for_path("/setup/access"), "Access · DAC");
        assert_eq!(title_for_path("/actionlog"), "Action Log");
    }

    #[test]
    fn unknown_paths_titlecase() {
        assert_eq!(title_for_path("/some-page"), "Some page");
    }

    #[test]
    fn nav_sections_are_five_modes() {
        let titles: Vec<_> = nav_sections_for_mode(DeploymentMode::SelfHosted)
            .into_iter()
            .map(|s| s.title)
            .collect();
        assert_eq!(titles, vec!["Run", "Watch", "Fix", "Setup", "Dev"]);
    }
}
