//! GovernedStreamGate — never pipe raw provider bytes to the operator (INV-04 / INV-19).
//!
//! Current production path buffers the full provider completion, runs Principal
//! Projection, then emits governed chunks. High-assurance mode is the default.

use serde_json::json;

pub const GOVERNED_STREAM_SCHEMA: &str = "connector.governed_stream_gate.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamAssurance {
    /// Buffer full provider output → project → emit chunks.
    HighAssurance,
    /// Future: sentence/chunk boundary projection (not yet enabled).
    Segmented,
}

impl StreamAssurance {
    pub fn from_env() -> Self {
        match std::env::var("CONNECTOR_STREAM_ASSURANCE")
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("segmented") | Some("chunk") => Self::Segmented,
            _ => Self::HighAssurance,
        }
    }
}

/// Split projected operator text into SSE-sized chunks (post-governance only).
pub fn chunk_projected_text(text: &str, max_chars: usize) -> Vec<String> {
    let max = max_chars.max(16);
    if text.is_empty() {
        return vec![];
    }
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let mut end = rest.len().min(max);
        if end < rest.len() {
            if let Some(space) = rest[..end].rfind(char::is_whitespace) {
                if space > max / 4 {
                    end = space + 1;
                }
            }
        }
        out.push(rest[..end].to_string());
        rest = &rest[end..];
    }
    out
}

pub fn posture_json() -> serde_json::Value {
    json!({
        "schema": GOVERNED_STREAM_SCHEMA,
        "assurance": format!("{:?}", StreamAssurance::from_env()).to_ascii_lowercase(),
        "honesty": "Raw provider socket is never forwarded to the browser; projection runs before emit",
        "inv": ["INV-04", "INV-19"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_cover_full_text() {
        let t = "Hello world. This is a governed stream.";
        let parts = chunk_projected_text(t, 12);
        assert!(!parts.is_empty());
        assert_eq!(parts.concat(), t);
    }

    #[test]
    fn empty_yields_nothing() {
        assert!(chunk_projected_text("", 32).is_empty());
    }
}
