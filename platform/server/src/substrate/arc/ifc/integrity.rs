//! Integrity lattice — no write-up from untrusted (Biba style; opposite of conf).

use serde::{Deserialize, Serialize};

/// Higher rank = more trusted. Flow into target allowed iff `source.rank() >= target.rank()`
/// (untrusted must not write-up into high-integrity decisions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegLevel {
    Untrusted = 0,
    User = 1,
    Verified = 2,
    System = 3,
}

impl IntegLevel {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "untrusted" | "lab" | "llm" | "model" => Some(Self::Untrusted),
            "user" | "operator" => Some(Self::User),
            "verified" | "attest" => Some(Self::Verified),
            "system" | "kernel" => Some(Self::System),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::User => "user",
            Self::Verified => "verified",
            Self::System => "system",
        }
    }

    pub fn rank(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegVerdict {
    Allow,
    DenyWriteUp { source: IntegLevel, target: IntegLevel },
    DenyUnknownLabel,
}

pub fn may_flow(source: IntegLevel, target: IntegLevel) -> IntegVerdict {
    if source.rank() >= target.rank() {
        IntegVerdict::Allow
    } else {
        IntegVerdict::DenyWriteUp { source, target }
    }
}

pub fn may_flow_labels(source: &str, target: &str) -> IntegVerdict {
    match (IntegLevel::parse(source), IntegLevel::parse(target)) {
        (Some(s), Some(t)) => may_flow(s, t),
        _ => IntegVerdict::DenyUnknownLabel,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_write_up_denied() {
        let v = may_flow(IntegLevel::Untrusted, IntegLevel::System);
        assert!(matches!(v, IntegVerdict::DenyWriteUp { .. }));
    }

    #[test]
    fn system_to_user_ok() {
        assert_eq!(
            may_flow(IntegLevel::System, IntegLevel::User),
            IntegVerdict::Allow
        );
    }
}
