//! Tier-aware entitlements (Phase 7.5 / P2-13).
//!
//! Derives a single [`Tier`] enum from `DeploymentInfo` so pages can
//! gate features (and render the "Upgrade" pill) without each one
//! re-implementing the rules. Computed entirely client-side from data
//! already fetched by `deployment::provide_deployment_signals()` — no
//! extra round-trips.
//!
//! Mapping:
//!
//! - `mode == Playground`   → [`Tier::Trial`]
//! - `mode == SelfHosted`   → tier read from `license_tier`
//!   * unset / `"community"` / `"free"` / `"oss"` → [`Tier::Community`]
//!   * `"team"` / `"pro"`                           → [`Tier::Team`]
//!   * `"business"` / `"enterprise"` / `"ent"`      → [`Tier::Enterprise`]
//!   * anything else                                → [`Tier::Community`]
//! - `mode == Unknown`      → [`Tier::Unknown`] (UI defaults to the
//!   most conservative behaviour: hide everything that requires a tier
//!   check until the response lands)
//!
//! Pages consume entitlements via [`use_entitlements`] (a `Memo`) and
//! render [`UpgradePill`] next to gated controls.

#![allow(dead_code)]

use leptos::prelude::*;

use crate::deployment::{use_deployment, DeploymentMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Hosted 90-minute trial. CTAs route to `/install`.
    Trial,
    /// Free self-hosted node. CTAs route to `/billing` (upgrade flow).
    Community,
    /// Paid team tier. Unlocks most features but not enterprise SSO,
    /// custom-domains, etc.
    Team,
    /// Enterprise — everything unlocked.
    Enterprise,
    /// First `/deployment/info` fetch is still in flight. Pages should
    /// fall back to the most conservative subset.
    Unknown,
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::Trial => "Trial",
            Tier::Community => "Community",
            Tier::Team => "Team",
            Tier::Enterprise => "Enterprise",
            Tier::Unknown => "Detecting…",
        }
    }

    /// Where the global "Upgrade" pill should send the operator. Trial
    /// users get the install/conversion page; paid self-hosted users
    /// get the billing flow.
    pub fn upgrade_path(self) -> &'static str {
        match self {
            Tier::Trial => "/install",
            Tier::Community | Tier::Team | Tier::Unknown => "/billing",
            Tier::Enterprise => "/billing", // already top tier, but link to contact
        }
    }

    pub fn is_trial(self) -> bool {
        matches!(self, Tier::Trial)
    }
    pub fn is_community(self) -> bool {
        matches!(self, Tier::Community)
    }
    pub fn is_team(self) -> bool {
        matches!(self, Tier::Team)
    }
    pub fn is_enterprise(self) -> bool {
        matches!(self, Tier::Enterprise)
    }

    /// True when the operator can buy more capability by clicking
    /// "Upgrade" — i.e. they are not already on the top tier.
    pub fn can_upgrade(self) -> bool {
        matches!(self, Tier::Trial | Tier::Community | Tier::Team)
    }

    /// Tier-comparison: is the running node *at least* this tier?
    /// Conservative on `Unknown` — returns `false` for any non-trivial
    /// comparison so feature-gated UI stays hidden until we know.
    pub fn at_least(self, required: Tier) -> bool {
        rank(self) >= rank(required)
    }
}

fn rank(t: Tier) -> u8 {
    match t {
        Tier::Unknown => 0,
        Tier::Trial => 1,
        Tier::Community => 2,
        Tier::Team => 3,
        Tier::Enterprise => 4,
    }
}

/// Compute the current tier as a `Memo` so it re-evaluates whenever
/// `DeploymentInfo` ticks (every 60 s).
pub fn use_entitlements() -> Memo<Tier> {
    let info = use_deployment();
    Memo::new(move |_| {
        let dep = info.get();
        match dep.mode {
            DeploymentMode::Playground => Tier::Trial,
            DeploymentMode::SelfHosted => match dep
                .license_tier
                .as_deref()
                .map(str::to_ascii_lowercase)
                .as_deref()
            {
                Some("team" | "pro") => Tier::Team,
                Some("business" | "enterprise" | "ent") => Tier::Enterprise,
                _ => Tier::Community,
            },
            DeploymentMode::Unknown => Tier::Unknown,
        }
    })
}

/// Visual indicator that a control is gated behind a higher tier.
///
/// Renders the pill only when the current tier is below `required`.
/// Already-entitled operators see nothing — no nag. Clicking the pill
/// routes to the right page for the current tier (install vs billing).
///
/// Usage:
///
/// ```ignore
/// view! {
///     <div class="flex items-center gap-2">
///         <button disabled=move || !ent.get().at_least(Tier::Team)>
///             "Export to S3"
///         </button>
///         <UpgradePill required=Tier::Team label="Team" />
///     </div>
/// }
/// ```
#[component]
pub fn UpgradePill(
    /// Minimum tier required to unlock the adjacent control.
    required: Tier,
    /// Short label shown inside the pill (e.g. "Team", "Enterprise").
    #[prop(into, default = "Upgrade".to_string())]
    label: String,
) -> impl IntoView {
    let ent = use_entitlements();
    let label_for_anchor = label.clone();
    let label_for_title = label.clone();
    let label_for_aria = label.clone();
    let aria_label = move || {
        format!(
            "Requires {} tier — currently on {}. Click to upgrade.",
            label_for_aria,
            ent.get().label()
        )
    };
    let title_text = move || {
        format!(
            "Requires {} tier — currently on {}. Click to upgrade.",
            label_for_title,
            ent.get().label()
        )
    };
    view! {
        <Show when=move || !ent.get().at_least(required)>
            <a
                href=move || ent.get().upgrade_path().to_string()
                aria-label=aria_label.clone()
                title=title_text.clone()
                class="inline-flex items-center gap-1 rounded-full border border-brand/40 bg-brand-10 px-2 py-0.5 text-[10px] font-semibold text-brand hover:bg-brand-20 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 no-underline"
            >
                <span aria-hidden="true">"↑"</span>
                <span>{label_for_anchor.clone()}</span>
            </a>
        </Show>
    }
}
