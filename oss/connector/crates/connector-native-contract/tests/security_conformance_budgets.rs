//! Extended security-conformance: BudgetSpec narrowing + confidence never widens.

#[cfg(test)]
mod tests {
    use connector_native_contract::{
        admit_package_for_effect, gate_allows, BudgetSpec, PackagePin, RuntimeProfile,
        SemanticConfidence,
    };

    #[test]
    fn budget_spec_defaults_are_narrowable() {
        let mut b = BudgetSpec::new("b1");
        b.max_calls = Some(3);
        b.max_bytes = Some(1024);
        b.max_hops = Some(2);
        b.max_duration_ms = Some(500);
        assert_eq!(b.max_calls, Some(3));
        assert_eq!(b.max_hops, Some(2));
    }

    #[test]
    fn confidence_narrower_never_widens() {
        let a = SemanticConfidence::TransportOnly;
        let b = SemanticConfidence::AdapterVerified;
        let n = SemanticConfidence::narrower(a, b);
        assert_eq!(n, SemanticConfidence::TransportOnly);
        let n2 = SemanticConfidence::narrower(b, SemanticConfidence::NativeVerified);
        assert!(n2.rank() <= b.rank());
    }

    #[test]
    fn production_rejects_missing_digest_even_with_id() {
        let pin = PackagePin::new("app-1", "short", "app").with_signature(true);
        let decision = admit_package_for_effect(RuntimeProfile::Production, Some(&pin), true);
        assert!(!gate_allows(&decision));
    }
}
