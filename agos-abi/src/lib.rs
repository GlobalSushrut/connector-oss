//! **AGOS ABI** — Phase **6.1** stable, semver-governed contract identifiers the kernel exposes to clients
//! (see **`GET /api/v1`** → **`agos_abi`**).
//!
//! - **`AGOS_CONTRACT_ID`** (`agos.v1`) names the **protocol** contract; bump only when breaking plugin-facing rules.
//! - **`CRATE_PKG_VERSION`** tracks this crate’s **Cargo semver** (release cadence can differ from contract id).
//! - Handshake JSON **`schema_version`** remains **`1`** per **`PLUGIN_CONTRACT.md`** (repo root).

/// Public contract id for plugin bootstrap + kernel capability negotiation (**`agos.v1`**).
pub const AGOS_CONTRACT_ID: &str = "agos.v1";

/// Reserved id for the next breaking contract (**`agos.v2`**) — not yet advertised in
/// [`SUPPORTED_AGOS_CONTRACT_IDS`]. Plugins must not ship with this until the kernel lists it in **`supported_contract_ids`**.
pub const AGOS_CONTRACT_ID_V2: &str = "agos.v2";

/// Contract ids the kernel accepts for new installs today (Phase **6.9**).
pub const SUPPORTED_AGOS_CONTRACT_IDS: &[&str] = &[AGOS_CONTRACT_ID];

/// Contracts in public preview / staged rollout (empty until **`agos.v2`** ships).
pub const STAGED_AGOS_CONTRACT_IDS: &[&str] = &[];

/// `CONNECTOR_AGOS_HANDSHAKE` / FD payload **`schema_version`** (normative: **`1`**).
pub const HANDSHAKE_SCHEMA_VERSION: u32 = 1;

/// This crate’s semver from Cargo (build-time); use for support / compatibility diagnostics.
pub const CRATE_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Human pointer for authors (not loaded at runtime).
pub const PLUGIN_CONTRACT_REF: &str = "PLUGIN_CONTRACT.md";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_id_stable() {
        assert_eq!(AGOS_CONTRACT_ID, "agos.v1");
        assert_eq!(AGOS_CONTRACT_ID_V2, "agos.v2");
        assert!(SUPPORTED_AGOS_CONTRACT_IDS.contains(&AGOS_CONTRACT_ID));
        assert!(!SUPPORTED_AGOS_CONTRACT_IDS.contains(&AGOS_CONTRACT_ID_V2));
        assert!(STAGED_AGOS_CONTRACT_IDS.is_empty());
        assert_eq!(HANDSHAKE_SCHEMA_VERSION, 1);
        assert!(!CRATE_PKG_VERSION.is_empty());
    }
}
