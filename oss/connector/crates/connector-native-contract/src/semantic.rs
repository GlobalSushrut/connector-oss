//! Semantic confidence and provenance for observed/claimed meaning.

use serde::{Deserialize, Serialize};

/// Confidence that observed traffic has been semantically resolved.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticConfidence {
    #[default]
    TransportOnly,
    ProtocolObserved,
    AdapterVerified,
    NativeVerified,
}

impl SemanticConfidence {
    /// Ordinal rank `0..=3` (higher = stronger verification).
    pub fn rank(self) -> u8 {
        match self {
            Self::TransportOnly => 0,
            Self::ProtocolObserved => 1,
            Self::AdapterVerified => 2,
            Self::NativeVerified => 3,
        }
    }

    /// Whether `other` is an allowed upgrade from `self` (non-decreasing rank).
    pub fn can_upgrade_to(self, other: Self) -> bool {
        other.rank() >= self.rank()
    }

    /// Narrower of two confidences (minimum rank).
    pub fn narrower(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    /// Monotonic merge for conflicting claims: take the narrower (min rank).
    pub fn merge_monotonic(a: Self, b: Self) -> Self {
        a.narrower(b)
    }

    /// Guidance: lower confidence may only keep equal or narrower authority claims.
    pub fn may_widen_authority_for(self) -> bool {
        matches!(self, Self::AdapterVerified | Self::NativeVerified)
    }
}

/// Where semantic meaning was established.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SemanticProvenance {
    NativeCaller,
    SignedAdapter { adapter_ref: String },
    ProtocolDecoder { decoder_ref: String },
    KernelObservation,
    OperatorDeclaration,
    NegotiatedPeer,
}

impl Default for SemanticProvenance {
    fn default() -> Self {
        Self::KernelObservation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn from_rank(r: u8) -> SemanticConfidence {
        match r % 4 {
            0 => SemanticConfidence::TransportOnly,
            1 => SemanticConfidence::ProtocolObserved,
            2 => SemanticConfidence::AdapterVerified,
            _ => SemanticConfidence::NativeVerified,
        }
    }

    #[test]
    fn narrower_never_higher_than_inputs() {
        for a in 0..4u8 {
            for b in 0..4u8 {
                let ca = from_rank(a);
                let cb = from_rank(b);
                let n = ca.narrower(cb);
                assert!(n.rank() <= ca.rank());
                assert!(n.rank() <= cb.rank());
                assert_eq!(n.rank(), ca.rank().min(cb.rank()));
            }
        }
    }

    proptest! {
        #[test]
        fn narrower_prop(a in 0u8..4, b in 0u8..4) {
            let ca = from_rank(a);
            let cb = from_rank(b);
            let n = SemanticConfidence::narrower(ca, cb);
            assert!(n.rank() <= ca.rank());
            assert!(n.rank() <= cb.rank());
        }
    }

    #[test]
    fn can_upgrade_monotonic() {
        assert!(SemanticConfidence::TransportOnly.can_upgrade_to(SemanticConfidence::NativeVerified));
        assert!(!SemanticConfidence::NativeVerified.can_upgrade_to(SemanticConfidence::TransportOnly));
        assert!(SemanticConfidence::AdapterVerified.can_upgrade_to(SemanticConfidence::AdapterVerified));
    }
}
