//! P01 — Operator design tokens (CSS vars live in `input.css`).

/// Tailwind utility classes referencing `--op-*` custom properties.
pub mod classes {
    pub const BG: &str = "bg-[var(--op-bg)]";
    pub const SURFACE: &str = "op-surface";
    pub const CARD: &str = "op-card";
    pub const PULSE_BAR: &str = "op-pulse-bar";
    pub const MODE_BTN_ACTIVE: &str = "op-mode-btn-active";
    pub const GLOW_RUNNING: &str = "op-glow-running";
    pub const GLOW_ATTENTION: &str = "op-glow-attention";
}
