//! AGOS `plugin.toml` manifest — parse with [`toml`], validate semver and contract rules (CONNECTOR_OS_ROADMAP §6).
//!
//! Consumers (kernel, Hub, `connectorctl`) should call [`PluginManifest::parse`] then [`PluginManifest::validate`].

mod error;
mod types;

pub use error::ManifestError;
pub use types::{
    AddressingSection, CapabilitiesSection, DependsTable, HealthSection, MigrationsSection, PluginManifest,
    PluginSection, PortsSection, ProvidesTable, RoutesSection, RuntimeSection, RuntimeType, SettingsSection,
    SigningSection, UiPage, UiSection,
};

impl PluginManifest {
    /// Parse `plugin.toml` body (UTF-8).
    pub fn parse(src: &str) -> Result<Self, ManifestError> {
        Ok(toml::from_str(src)?)
    }

    /// Structural + policy checks from the roadmap contract.
    pub fn validate(&self) -> Result<(), ManifestError> {
        self.plugin.validate_id()?;
        self.plugin.validate_versions()?;
        self.plugin.validate_vendor_namespace()?;
        self.runtime.validate()?;
        if self.capabilities.required.iter().any(|c| is_wildcard_network_capability(c)) {
            return Err(ManifestError::WildcardNetworkCapability(
                self.capabilities
                    .required
                    .iter()
                    .find(|c| is_wildcard_network_capability(c))
                    .cloned()
                    .unwrap_or_default(),
            ));
        }
        Ok(())
    }
}

fn is_wildcard_network_capability(s: &str) -> bool {
    let t = s.trim();
    t.starts_with("network.outbound:*") || t == "network.outbound:*"
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[plugin]
id = "acme/hello"
name = "Hello"
version = "0.1.0"
author = "acme"
license = "MIT"
min_kernel = "0.1.0"
agos_abi = "agos.v1"

[runtime]
type = "subprocess"
entrypoint = "bin/hello"
memory_mb = 32
vcpus = 1
shared = false
max_concurrency = 4
idle_window = "30s"
cold_start_budget_ms = 500

[routes]
prefix = "/plugins/hello"
admin = "/plugins/hello/admin/*"

[capabilities]
required = ["audit.write"]

[ui]
pages = [{ path = "/plugins/hello", title = "Hello", role = "operator" }]
"#;

    #[test]
    fn parse_and_validate_minimal() {
        let m = PluginManifest::parse(MINIMAL).expect("parse");
        m.validate().expect("validate");
    }

    #[test]
    fn rejects_bad_id() {
        let mut m = PluginManifest::parse(MINIMAL).unwrap();
        m.plugin.id = "nope".into();
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_wildcard_network() {
        let mut m = PluginManifest::parse(MINIMAL).unwrap();
        m.capabilities.required = vec!["network.outbound:*:443".into()];
        assert!(matches!(
            m.validate(),
            Err(ManifestError::WildcardNetworkCapability(_))
        ));
    }

    #[test]
    fn rejects_connector_vendor_for_non_connector_author() {
        let mut m = PluginManifest::parse(MINIMAL).unwrap();
        m.plugin.id = "connector/evil".into();
        m.plugin.author = "Evil".into();
        assert!(matches!(
            m.validate(),
            Err(ManifestError::ReservedVendorNamespace { .. })
        ));
    }

    #[test]
    fn example_sample_parses_and_validates() {
        const SAMPLE: &str = include_str!("../examples/sample.plugin.toml");
        let m = PluginManifest::parse(SAMPLE).expect("parse sample");
        m.validate().expect("validate sample");
    }
}
