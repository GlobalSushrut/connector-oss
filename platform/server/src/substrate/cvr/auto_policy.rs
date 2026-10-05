//! Configurable `isolation: auto` policy table (Phase E3).
//!
//! Maps risk hints → IsolationProfile. **Never grants authority** — only selects
//! execution-body posture. Authority remains NF³ / grants / membrane.

use serde_json::{json, Value};

use super::profile::{IsolationProfile, RiskHint};

#[derive(Debug, Clone)]
pub struct AutoPolicyTable {
    pub r0: IsolationProfile,
    pub r1: IsolationProfile,
    pub r2: IsolationProfile,
    pub untrusted: IsolationProfile,
    pub r3: IsolationProfile,
    pub source: String,
}

impl Default for AutoPolicyTable {
    fn default() -> Self {
        Self {
            r0: IsolationProfile::V1,
            r1: IsolationProfile::V2,
            r2: IsolationProfile::V3,
            untrusted: IsolationProfile::V3,
            r3: IsolationProfile::V4,
            source: "builtin_default".into(),
        }
    }
}

impl AutoPolicyTable {
    pub fn load() -> Self {
        let mut t = Self::default();
        // Per-risk env overrides: CONNECTOR_ISOLATION_AUTO_R0=V1 ...
        for (key, slot) in [
            ("CONNECTOR_ISOLATION_AUTO_R0", &mut t.r0),
            ("CONNECTOR_ISOLATION_AUTO_R1", &mut t.r1),
            ("CONNECTOR_ISOLATION_AUTO_R2", &mut t.r2),
            ("CONNECTOR_ISOLATION_AUTO_UNTRUSTED", &mut t.untrusted),
            ("CONNECTOR_ISOLATION_AUTO_R3", &mut t.r3),
        ] {
            if let Ok(v) = std::env::var(key) {
                if let Some(p) = parse_profile(&v) {
                    *slot = p;
                    t.source = "env_overrides".into();
                }
            }
        }
        // Full JSON: {"R0":"V1","R1":"V2","R2":"V3","UNTRUSTED":"V3","R3":"V4"}
        if let Ok(raw) = std::env::var("CONNECTOR_ISOLATION_AUTO_POLICY_JSON") {
            if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                apply_json(&mut t, &v);
                t.source = "CONNECTOR_ISOLATION_AUTO_POLICY_JSON".into();
            }
        }
        t
    }

    pub fn resolve(&self, risk: RiskHint) -> (IsolationProfile, String) {
        let (p, label) = match risk {
            RiskHint::R0 => (self.r0, "R0"),
            RiskHint::R1 => (self.r1, "R1"),
            RiskHint::R2 => (self.r2, "R2"),
            RiskHint::UntrustedCode => (self.untrusted, "UNTRUSTED"),
            RiskHint::R3 => (self.r3, "R3"),
        };
        (
            p,
            format!("auto: {label} → {} ({})", p.as_str(), p.title()),
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema": "connector.cvr.auto_policy.v1",
            "source": self.source,
            "table": {
                "R0": self.r0.as_str(),
                "R1": self.r1.as_str(),
                "R2": self.r2.as_str(),
                "UNTRUSTED": self.untrusted.as_str(),
                "R3": self.r3.as_str(),
            },
            "default_builtin": {
                "R0": "V1",
                "R1": "V2",
                "R2": "V3",
                "UNTRUSTED": "V3",
                "R3": "V4",
            },
            "honesty": "Auto policy selects IsolationProfile only — never grants WorldGrant, spend, or effect authority",
            "configure": {
                "json_env": "CONNECTOR_ISOLATION_AUTO_POLICY_JSON",
                "per_risk_env": [
                    "CONNECTOR_ISOLATION_AUTO_R0",
                    "CONNECTOR_ISOLATION_AUTO_R1",
                    "CONNECTOR_ISOLATION_AUTO_R2",
                    "CONNECTOR_ISOLATION_AUTO_UNTRUSTED",
                    "CONNECTOR_ISOLATION_AUTO_R3",
                ],
            },
        })
    }
}

fn parse_profile(s: &str) -> Option<IsolationProfile> {
    match s.trim().to_ascii_uppercase().as_str() {
        "V0" => Some(IsolationProfile::V0),
        "V1" => Some(IsolationProfile::V1),
        "V2" => Some(IsolationProfile::V2),
        "V3" => Some(IsolationProfile::V3),
        "V4" => Some(IsolationProfile::V4),
        _ => None,
    }
}

fn apply_json(t: &mut AutoPolicyTable, v: &Value) {
    let map = |key: &str| {
        v.get(key)
            .or_else(|| v.get(&key.to_ascii_lowercase()))
            .and_then(|x| x.as_str())
            .and_then(parse_profile)
    };
    if let Some(p) = map("R0") {
        t.r0 = p;
    }
    if let Some(p) = map("R1") {
        t.r1 = p;
    }
    if let Some(p) = map("R2") {
        t.r2 = p;
    }
    if let Some(p) = map("UNTRUSTED").or_else(|| map("Untrusted")) {
        t.untrusted = p;
    }
    if let Some(p) = map("R3") {
        t.r3 = p;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_table_matches_architecture() {
        let t = AutoPolicyTable::default();
        assert_eq!(t.resolve(RiskHint::R0).0, IsolationProfile::V1);
        assert_eq!(t.resolve(RiskHint::R1).0, IsolationProfile::V2);
        assert_eq!(t.resolve(RiskHint::R2).0, IsolationProfile::V3);
        assert_eq!(t.resolve(RiskHint::UntrustedCode).0, IsolationProfile::V3);
        assert_eq!(t.resolve(RiskHint::R3).0, IsolationProfile::V4);
    }

    #[test]
    fn json_override() {
        let mut t = AutoPolicyTable::default();
        apply_json(
            &mut t,
            &json!({"R0":"V0","R3":"V3"}),
        );
        assert_eq!(t.r0, IsolationProfile::V0);
        assert_eq!(t.r3, IsolationProfile::V3);
        assert_eq!(t.r1, IsolationProfile::V2);
    }
}
