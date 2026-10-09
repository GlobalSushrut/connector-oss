//! Reference stub: `acme/datadog-forwarder` — public **`agos-sdk`** only.

use std::path::Path;

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let m = agos_sdk::load_manifest_path(dir.join("plugin.toml")).expect("plugin.toml");
    agos_sdk::assert_manifest_matches_abi(&m).expect("agos_abi");
    eprintln!(
        "{} v{} — reference stub (no Datadog traffic)",
        m.plugin.id,
        env!("CARGO_PKG_VERSION")
    );
}
