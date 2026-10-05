//! ConnectorMemory — the simplified, universal memory format.
//!
//! Converts between the complex MemPacket (45+ fields) and a simple 10-field
//! struct that any developer can understand and that's compatible with
//! LangChain Document, CrewAI Memory, and OpenAI messages.

use serde::{Deserialize, Serialize};
use vac_core::types::{MemPacket, SourceKind};

/// ConnectorMemory — 10 fields. That's it.
///
/// This is what developers see. Behind it is a full MemPacket with 3D envelope,
/// CID, Merkle proof, provenance chain, and authority plane — all invisible.
///
/// Compatible with:
/// - LangChain `Document(page_content, metadata)`
/// - CrewAI `Memory(content, metadata, score)`
/// - OpenAI `{"role": "...", "content": "..."}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConnectorMemory {
    /// Unique memory ID (CID of the underlying MemPacket)
    pub id: String,
    /// The actual content (text, JSON stringified)
    pub content: String,
    /// User/subject this memory belongs to
    pub user: String,
    /// Kind of memory: "input", "decision", "extraction", "tool_result", etc.
    pub kind: String,
    /// Classification tags
    pub tags: Vec<String>,
    /// Relevance/importance score (0.0 - 1.0)
    pub score: f32,
    /// Creation timestamp (ISO 8601)
    pub created: String,
    /// Source: "user", "llm", "tool", "system"
    pub source: String,
    /// Whether this memory has been cryptographically verified (CID + Merkle)
    pub verified: bool,
    /// Session this memory belongs to
    pub session: String,
}

impl ConnectorMemory {
    /// Convert a MemPacket into a ConnectorMemory (lossy compression).
    ///
    /// The full MemPacket is preserved in the kernel — this is just the
    /// developer-facing view.
    pub fn from_packet(packet: &MemPacket) -> Self {
        let content = match &packet.content.payload {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };

        let source = match &packet.provenance.source.kind {
            SourceKind::User => "user".to_string(),
            SourceKind::SelfSource => "llm".to_string(),
            SourceKind::Tool => "tool".to_string(),
            SourceKind::Web => "web".to_string(),
            SourceKind::Untrusted => "untrusted".to_string(),
        };

        let verified = packet.authority.signature.is_some()
            || packet.provenance.trust_tier >= 2;

        let score = packet.provenance.confidence.unwrap_or(0.5);

        let created = {
            let ts = packet.index.ts;
            chrono::DateTime::from_timestamp_millis(ts)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| ts.to_string())
        };

        ConnectorMemory {
            id: packet.index.packet_cid.to_string(),
            content,
            user: packet.subject_id.clone(),
            kind: packet.content.packet_type.to_string(),
            tags: packet.content.tags.clone(),
            score,
            created,
            source,
            verified,
            session: packet.session_id.clone().unwrap_or_default(),
        }
    }

    /// Convert to LangChain-compatible Document format.
    pub fn to_langchain_doc(&self) -> serde_json::Value {
        serde_json::json!({
            "page_content": self.content,
            "metadata": {
                "id": self.id,
                "user": self.user,
                "kind": self.kind,
                "tags": self.tags,
                "score": self.score,
                "created": self.created,
                "source": self.source,
                "verified": self.verified,
                "session": self.session,
            }
        })
    }

    /// Convert to OpenAI message format.
    pub fn to_openai_message(&self) -> serde_json::Value {
        let role = match self.source.as_str() {
            "user" => "user",
            "llm" => "assistant",
            "tool" => "tool",
            _ => "system",
        };
        serde_json::json!({
            "role": role,
            "content": self.content,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vac_core::types::*;
    use vac_core::cid::compute_cid;

    fn make_test_packet() -> MemPacket {
        let payload = serde_json::json!("User prefers dark mode");
        let cid = compute_cid(&payload).unwrap();
        let now_ms = chrono::Utc::now().timestamp_millis();

        MemPacket::new(
            PacketType::Extraction,
            payload,
            cid,
            "user:alice".to_string(),
            "pipe:001".to_string(),
            Source {
                kind: SourceKind::SelfSource,
                principal_id: "agent:bot".to_string(),
            },
            now_ms,
        )
        .with_tags(vec!["preference".to_string(), "ui".to_string()])
        .with_confidence(0.95)
        .with_session("sess:001".to_string())
    }

    #[test]
    fn test_from_packet() {
        let packet = make_test_packet();
        let mem = ConnectorMemory::from_packet(&packet);

        assert_eq!(mem.content, "User prefers dark mode");
        assert_eq!(mem.user, "user:alice");
        assert_eq!(mem.kind, "extraction");
        assert_eq!(mem.tags, vec!["preference", "ui"]);
        assert!((mem.score - 0.95).abs() < 0.001);
        assert_eq!(mem.source, "llm");
        assert!(mem.verified); // trust_tier >= 2
        assert_eq!(mem.session, "sess:001");
    }

    #[test]
    fn test_to_langchain_doc() {
        let packet = make_test_packet();
        let mem = ConnectorMemory::from_packet(&packet);
        let doc = mem.to_langchain_doc();

        assert_eq!(doc["page_content"], "User prefers dark mode");
        assert_eq!(doc["metadata"]["kind"], "extraction");
        assert_eq!(doc["metadata"]["verified"], true);
    }

    #[test]
    fn test_to_openai_message() {
        let packet = make_test_packet();
        let mem = ConnectorMemory::from_packet(&packet);
        let msg = mem.to_openai_message();

        assert_eq!(msg["role"], "assistant"); // source = "llm"
        assert_eq!(msg["content"], "User prefers dark mode");
    }
}
