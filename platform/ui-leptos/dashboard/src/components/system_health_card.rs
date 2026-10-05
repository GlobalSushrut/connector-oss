//! Full health detail card.
//!
//! Phase 0 ships this as a thin re-export of the existing `StatusBanner`
//! so we can promote it onto pages (Overview, Monitor) in later phases
//! without another rename. The global header now uses the compact
//! `LiveDotPill` instead of embedding this card.

#[allow(unused_imports)] // first consumer lands in Phase 6 (Monitor / Overview rewrites).
pub use crate::components::status_banner::StatusBanner as SystemHealthCard;
