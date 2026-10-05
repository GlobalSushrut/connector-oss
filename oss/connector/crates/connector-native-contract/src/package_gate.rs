//! Mandatory AppPackageV2 `.cpkg` activation gate.
//!
//! Outside explicit lab mode, consequential effects require a signed package
//! digest. Lab exceptions must be labeled on receipts as advisory/lab.

use serde::{Deserialize, Serialize};

/// Schema for package gate decisions recorded on receipts / meta.
pub const PACKAGE_GATE_SCHEMA: &str = "connector.package_gate.v1";

/// Runtime profile that decides whether unpackaged execution is allowed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProfile {
    Lab,
    Development,
    Staging,
    Production,
    Hardened,
    DefenseStrict,
}

impl RuntimeProfile {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "lab" | "playground" | "trial" => Self::Lab,
            "development" | "dev" | "local" => Self::Development,
            "staging" | "preview" => Self::Staging,
            "hardened" => Self::Hardened,
            "defense-strict" | "defense_strict" | "airgap" => Self::DefenseStrict,
            "production" | "prod" | _ => Self::Production,
        }
    }

    /// Profiles that refuse unpackaged consequential effects.
    pub fn requires_signed_package(self) -> bool {
        matches!(
            self,
            Self::Staging | Self::Production | Self::Hardened | Self::DefenseStrict
        )
    }

    pub fn allows_lab_unpackaged(self) -> bool {
        matches!(self, Self::Lab | Self::Development)
    }
}

/// Package identity pinned onto operations and receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackagePin {
    pub schema: String,
    pub package_id: String,
    pub package_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ir_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_present: Option<bool>,
    #[serde(default)]
    pub kind: String,
}

impl PackagePin {
    pub fn new(
        package_id: impl Into<String>,
        package_digest: impl Into<String>,
        kind: impl Into<String>,
    ) -> Self {
        Self {
            schema: PACKAGE_GATE_SCHEMA.into(),
            package_id: package_id.into(),
            package_digest: package_digest.into(),
            ir_digest: None,
            signature_present: None,
            kind: kind.into(),
        }
    }

    pub fn with_ir(mut self, ir_digest: impl Into<String>) -> Self {
        self.ir_digest = Some(ir_digest.into());
        self
    }

    pub fn with_signature(mut self, present: bool) -> Self {
        self.signature_present = Some(present);
        self
    }

    pub fn is_valid_pin(&self) -> bool {
        !self.package_id.trim().is_empty()
            && !self.package_digest.trim().is_empty()
            && self.package_digest.len() >= 16
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PackageGateVerdict {
    AllowPackaged,
    AllowLabUnpackaged,
    DenyMissingPackage,
    DenyInvalidPin,
    DenyUnsignedInEnforced,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageGateDecision {
    pub schema: String,
    pub verdict: PackageGateVerdict,
    pub profile: RuntimeProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<PackagePin>,
    pub honesty: String,
    pub lab_labeled: bool,
}

/// Admit a consequential effect only when package policy is satisfied.
pub fn admit_package_for_effect(
    profile: RuntimeProfile,
    package: Option<&PackagePin>,
    require_signature_in_enforced: bool,
) -> PackageGateDecision {
    match package {
        None => {
            if profile.allows_lab_unpackaged() {
                PackageGateDecision {
                    schema: PACKAGE_GATE_SCHEMA.into(),
                    verdict: PackageGateVerdict::AllowLabUnpackaged,
                    profile,
                    package: None,
                    honesty: "lab/dev unpackaged execution — receipt must stay advisory/lab; not production"
                        .into(),
                    lab_labeled: true,
                }
            } else {
                PackageGateDecision {
                    schema: PACKAGE_GATE_SCHEMA.into(),
                    verdict: PackageGateVerdict::DenyMissingPackage,
                    profile,
                    package: None,
                    honesty: "consequential effects require signed AppPackageV2 .cpkg outside lab"
                        .into(),
                    lab_labeled: false,
                }
            }
        }
        Some(pin) if !pin.is_valid_pin() => PackageGateDecision {
            schema: PACKAGE_GATE_SCHEMA.into(),
            verdict: PackageGateVerdict::DenyInvalidPin,
            profile,
            package: Some(pin.clone()),
            honesty: "package_id and package_digest are required and must be content-addressed"
                .into(),
            lab_labeled: false,
        },
        Some(pin)
            if require_signature_in_enforced
                && profile.requires_signed_package()
                && pin.signature_present == Some(false) =>
        {
            PackageGateDecision {
                schema: PACKAGE_GATE_SCHEMA.into(),
                verdict: PackageGateVerdict::DenyUnsignedInEnforced,
                profile,
                package: Some(pin.clone()),
                honesty: "enforced profiles require signature_present=true on AppPackageV2".into(),
                lab_labeled: false,
            }
        }
        Some(pin) => PackageGateDecision {
            schema: PACKAGE_GATE_SCHEMA.into(),
            verdict: PackageGateVerdict::AllowPackaged,
            profile,
            package: Some(pin.clone()),
            honesty: "effect admitted under package digest pin".into(),
            lab_labeled: false,
        },
    }
}

pub fn gate_allows(decision: &PackageGateDecision) -> bool {
    matches!(
        decision.verdict,
        PackageGateVerdict::AllowPackaged | PackageGateVerdict::AllowLabUnpackaged
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_denies_missing_package() {
        let d = admit_package_for_effect(RuntimeProfile::Production, None, true);
        assert!(!gate_allows(&d));
        assert_eq!(d.verdict, PackageGateVerdict::DenyMissingPackage);
    }

    #[test]
    fn lab_allows_unpackaged_with_label() {
        let d = admit_package_for_effect(RuntimeProfile::Lab, None, true);
        assert!(gate_allows(&d));
        assert!(d.lab_labeled);
    }

    #[test]
    fn enforced_rejects_unsigned_pin() {
        let pin = PackagePin::new("demo", "sha256:abcdefghijklmnopqrstuvwxyz012345", "app")
            .with_signature(false);
        let d = admit_package_for_effect(RuntimeProfile::Hardened, Some(&pin), true);
        assert!(!gate_allows(&d));
        assert_eq!(d.verdict, PackageGateVerdict::DenyUnsignedInEnforced);
    }

    #[test]
    fn packaged_allow() {
        let pin = PackagePin::new("demo", "sha256:abcdefghijklmnopqrstuvwxyz012345", "app")
            .with_ir("cir1-sha256-abc")
            .with_signature(true);
        let d = admit_package_for_effect(RuntimeProfile::Production, Some(&pin), true);
        assert!(gate_allows(&d));
        assert!(!d.lab_labeled);
    }
}
