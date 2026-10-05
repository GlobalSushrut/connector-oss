//! `ui::*` — industry-grade primitive component library.
//!
//! This is the Connector design system: a small, opinionated set of
//! Leptos components every page should compose against. It mirrors the
//! Radix UI / shadcn / Vercel approach of building a flat namespace of
//! accessible, themed primitives — `Button`, `TextField`, `Tabs`,
//! `Dialog`, etc. — so the rest of the app doesn't reinvent the same
//! state machines per page.
//!
//! ## Why a primitive layer?
//!
//! The previous component layer was task-specific (`SessionEndModal`,
//! `CapacityMeters`, `RecommendationsPanel`, …). Useful, but tasks own
//! their own button colours, focus management, ARIA roles, etc., which
//! means every new page either re-implements them or — much more
//! commonly — silently ships UI that's missing them. The primitives
//! here close that gap:
//!
//! * Every interactive primitive renders the brand focus ring, hover,
//!   active, and disabled states with no opt-in.
//! * Every primitive exposes typed variants (`Variant`, `Size`) so the
//!   call site can't reach for an inconsistent class string.
//! * Every primitive embeds the correct ARIA roles + keyboard
//!   handling (Escape closes Dialog, Enter/Space activates Switch,
//!   arrow keys move Tabs, …).
//!
//! ## Conventions
//!
//! - Variants are enums (`ButtonVariant`, `BadgeVariant`) so adding a
//!   new variant is one match arm everywhere, not a string hunt.
//! - Sizes follow the t-shirt scale `Sm` / `Md` / `Lg`. `Md` is the
//!   default and is the only size optimised for keyboard accessibility
//!   — anywhere else, `Sm` lives in tight UI like badges and `Lg` in
//!   hero call-to-action slots.
//! - All animations honour `prefers-reduced-motion` via the global
//!   CSS in `input.css`.
//! - All event handlers accept `MouseEvent` and don't intercept
//!   bubbling — composition still works.
//!
//! ## Migration guidance
//!
//! Pages should consume primitives directly:
//!
//! ```ignore
//! use crate::components::ui::{Button, ButtonVariant};
//!
//! view! {
//!     <Button variant=ButtonVariant::Primary on:click=on_save>
//!         "Save changes"
//!     </Button>
//! }
//! ```
//!
//! Pre-existing components keep their CSS classes (`.btn-primary`,
//! `.card`, …) — those continue to work and are now considered the
//! "raw" layer below the primitives.

// Primitives are introduced ahead of their per-page adoption — pages
// migrate to them incrementally, so we silence the "unused"
// warnings for the convenience re-exports until coverage is broader.
#![allow(dead_code, unused_imports)]

// ── Atoms ────────────────────────────────────────────────────────
pub mod avatar;
pub mod badge;
pub mod button;
pub mod card;
pub mod dialog;
pub mod kbd;
pub mod separator;
pub mod spinner;
pub mod switch;
pub mod tabs;
pub mod text_field;
pub mod tooltip;

// ── Layout & page chrome (level-10 additions) ────────────────────
pub mod alert;
pub mod app_shell;
pub mod empty_state;
pub mod layout;
pub mod page;
pub mod progress;

// ── Documents (binary preview + download) ────────────────────────
pub mod download_button;
pub mod pdf_viewer;

// Convenience re-exports so call sites can `use crate::components::ui::*;`
pub use alert::{Alert, AlertVariant, Banner};
pub use app_shell::AppShell;
pub use avatar::{Avatar, AvatarSize};
pub use badge::{Badge, BadgeVariant};
pub use button::{Button, ButtonSize, ButtonVariant, OnClick};
pub use card::{Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle};
pub use dialog::{Dialog, DialogBody, DialogFooter, DialogHeader};
pub use download_button::{DownloadButton, DownloadMethod};
pub use empty_state::EmptyState;
pub use pdf_viewer::PdfViewer;
pub use kbd::Kbd;
pub use layout::{
    Align, Center, Cluster, Container, ContainerSize, Grid, Inline, Justify, Space, Spacer, Stack,
};
pub use page::{Breadcrumbs, PageHeader, PageSection};
pub use progress::{Progress, ProgressSize};
pub use separator::Separator;
pub use spinner::{Spinner, SpinnerSize};
pub use switch::Switch;
pub use tabs::{TabList, TabPanel, TabTrigger, Tabs};
pub use text_field::{TextField, TextFieldKind};
pub use tooltip::Tooltip;
