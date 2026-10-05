//! Security-conformance unit gates for native package admission.

#[cfg(test)]
mod tests {
    use connector_native_contract::{
        admit_package_for_effect, gate_allows, PackagePin, RuntimeProfile,
    };

    #[test]
    fn production_native_invoke_requires_signed_package() {
        let decision = admit_package_for_effect(RuntimeProfile::Production, None, true);
        assert!(!gate_allows(&decision));
        assert!(decision.honesty.contains("package") || decision.honesty.contains("digest") || !decision.honesty.is_empty());
    }

    #[test]
    fn production_accepts_signed_pin() {
        let pin = PackagePin::new("app-1", "cpkg-sha256-0123456789abcdef0123456789abcdef", "app")
            .with_signature(true);
        let decision = admit_package_for_effect(RuntimeProfile::Production, Some(&pin), true);
        assert!(gate_allows(&decision), "{:?}", decision);
    }

    #[test]
    fn production_rejects_unsigned_pin() {
        let pin = PackagePin::new("app-1", "cpkg-sha256-0123456789abcdef0123456789abcdef", "app")
            .with_signature(false);
        let decision = admit_package_for_effect(RuntimeProfile::Production, Some(&pin), true);
        assert!(!gate_allows(&decision));
    }

    #[test]
    fn lab_allows_unpackaged() {
        let decision = admit_package_for_effect(RuntimeProfile::Lab, None, true);
        assert!(gate_allows(&decision));
        assert!(decision.lab_labeled);
    }
}
