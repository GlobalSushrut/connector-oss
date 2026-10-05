//! Confidentiality lattice — no write-down without declassification (Bell-LaPadula style).

use serde::{Deserialize, Serialize};

/// Higher rank = more sensitive. Flow to sink allowed iff `data.rank() <= sink.rank()`
/// (sink clearance must dominate data sensitivity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfLevel {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Secret = 3,
    Pii = 4,
}

impl ConfLevel {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "public" | "lab" | "open" => Some(Self::Public),
            "internal" => Some(Self::Internal),
            "confidential" | "conf" => Some(Self::Confidential),
            "secret" => Some(Self::Secret),
            "pii" | "restricted" => Some(Self::Pii),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
            Self::Secret => "secret",
            Self::Pii => "pii",
        }
    }

    pub fn rank(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfVerdict {
    Allow,
    DenyWriteDown { data: ConfLevel, sink: ConfLevel },
    DenyUnknownLabel,
}

/// May `data` flow to `sink` under confidentiality?
pub fn may_flow(data: ConfLevel, sink: ConfLevel) -> ConfVerdict {
    if data.rank() <= sink.rank() {
        ConfVerdict::Allow
    } else {
        ConfVerdict::DenyWriteDown { data, sink }
    }
}

pub fn may_flow_labels(data: &str, sink: &str) -> ConfVerdict {
    match (ConfLevel::parse(data), ConfLevel::parse(sink)) {
        (Some(d), Some(s)) => may_flow(d, s),
        _ => ConfVerdict::DenyUnknownLabel,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pii_to_external_denied() {
        let v = may_flow(ConfLevel::Pii, ConfLevel::Public);
        assert!(matches!(v, ConfVerdict::DenyWriteDown { .. }));
    }

    #[test]
    fn internal_to_secret_ok() {
        assert_eq!(
            may_flow(ConfLevel::Internal, ConfLevel::Secret),
            ConfVerdict::Allow
        );
    }
}
