//! Protocol driver identifiers — overlays are not ontology.
//!
//! Drivers authenticate/decode peers and report semantic confidence.
//! They never mint grants or suppress EdgeReceipts.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_DRIVER_SCHEMA: &str = "connector.protocol_driver.v1";

/// Known protocol overlays that lower into the native invocation kernel.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolDriverId {
    Mcp,
    Conp,
    A2a,
    Cnp,
    /// HTTP/SDK and other future overlays.
    Other,
}

impl ProtocolDriverId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
            Self::Conp => "conp",
            Self::A2a => "a2a",
            Self::Cnp => "cnp",
            Self::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mcp" => Some(Self::Mcp),
            "conp" | "cp" => Some(Self::Conp),
            "a2a" => Some(Self::A2a),
            "cnp" => Some(Self::Cnp),
            "other" | "http" | "sdk" => Some(Self::Other),
            _ => None,
        }
    }

    pub fn decoder_ref(self) -> &'static str {
        match self {
            Self::Mcp => "protocol_driver:mcp@2026",
            Self::Conp => "protocol_driver:conp@cp1",
            Self::A2a => "protocol_driver:a2a@v1",
            Self::Cnp => "protocol_driver:cnp@l2",
            Self::Other => "protocol_driver:other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trip() {
        for id in [
            ProtocolDriverId::Mcp,
            ProtocolDriverId::Conp,
            ProtocolDriverId::A2a,
            ProtocolDriverId::Cnp,
        ] {
            assert_eq!(ProtocolDriverId::parse(id.as_str()), Some(id));
        }
        assert_eq!(ProtocolDriverId::parse("CP"), Some(ProtocolDriverId::Conp));
    }
}
