//! Protocol Systems — MCP/A2A/CNP/CONP live under `substrate/protocol_drivers`.
//!
//! The legacy `protocols/glue.rs` translation layer was removed; use
//! `crate::substrate::protocol_drivers` for authority-preserving overlays.

/// Placeholder module so `pub mod protocols` remains stable for docs/imports.
pub fn honesty() -> &'static str {
    "protocol_drivers replace protocols/glue — CNP/MCP/A2A/CONP admit via native_invoker"
}
