//! Product catalog — single source of truth (Phase 2.1).
//!
//! The 9 marketed plugins and the 3 reference workflows live in
//! `platform/products/catalog.json`. That file is the canonical
//! definition consumed by:
//!
//! - This module (`include_str!` into the WASM binary).
//! - The platform server's `GET /api/v1/products` endpoint
//!   (same file, served verbatim).
//! - The marketing landing page `Nav.tsx` (Vite JSON import).
//!
//! Adding / renaming a product is a one-file edit; the dashboard
//! sidebar, Apps Hub, ⌘K palette, server endpoint, and marketing
//! megamenu all update automatically.

#![allow(dead_code)]

use std::sync::OnceLock;

use serde::Deserialize;

const CATALOG_JSON: &str = include_str!("../../../products/catalog.json");

/// Plugin entry from the catalog. Marketing fields (`tagline`,
/// `short_desc`, `long_desc`) feed both the megamenu and the sidebar
/// search/ARIA labels.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginCatalogItem {
    pub slug: String,
    pub name: String,
    pub short_desc: String,
    pub long_desc: String,
    pub icon_key: String,
    pub category: String,
    #[serde(default)]
    pub marketed: bool,
    /// Best-guess enablement when `/plugins/status` has no entry. The
    /// authoritative source is still the server endpoint.
    #[serde(default)]
    pub default_enabled: bool,
    #[serde(default)]
    pub tagline: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReferenceWorkflow {
    pub slug: String,
    pub name: String,
    pub short_desc: String,
    #[serde(default)]
    pub tagline: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CatalogFile {
    #[serde(default)]
    plugins: Vec<PluginCatalogItem>,
    #[serde(default)]
    reference_workflows: Vec<ReferenceWorkflow>,
}

fn parsed() -> &'static CatalogFile {
    static CELL: OnceLock<CatalogFile> = OnceLock::new();
    CELL.get_or_init(|| {
        serde_json::from_str(CATALOG_JSON).unwrap_or_else(|e| {
            // The catalog JSON is bundled at compile time and validated
            // by the server side at startup. A parse error here means
            // somebody shipped a syntactically-broken release artefact —
            // fail loud rather than hide it behind a default.
            panic!("products/catalog.json failed to parse at boot: {e}");
        })
    })
}

/// All marketed plugins, in catalog order. Treat as `&'static`.
pub fn plugins() -> &'static [PluginCatalogItem] {
    &parsed().plugins
}

/// Reference workflow templates (the 3 pre-built showcases).
pub fn reference_workflows() -> &'static [ReferenceWorkflow] {
    &parsed().reference_workflows
}

/// Lookup helper — None for unknown slug.
pub fn plugin_by_slug(slug: &str) -> Option<&'static PluginCatalogItem> {
    plugins().iter().find(|p| p.slug == slug)
}

/// Plugins filtered by category (`"trust"`, `"build"`, …).
pub fn plugins_by_category(category: &str) -> Vec<&'static PluginCatalogItem> {
    plugins().iter().filter(|p| p.category == category).collect()
}

/// Canonical sidebar path for a plugin (`/plugins/<slug>`).
pub fn plugin_path(slug: &str) -> String {
    format!("/plugins/{slug}")
}
