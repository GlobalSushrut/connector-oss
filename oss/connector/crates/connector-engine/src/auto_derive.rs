//! Auto-Derivation Engine — derives PacketType, MemoryScope, MemoryTier, CID, and tags
//! from simple developer inputs.
//!
//! The developer provides: text + user_id
//! The engine derives: everything else needed for a full MemPacket.

use cid::Cid;
use vac_core::cid::{compute_cid, sha256};
use vac_core::types::*;

use crate::error::{EngineError, EngineResult};

/// Auto-derivation engine that converts simple inputs into full kernel types.
pub struct AutoDerive;

impl AutoDerive {
    /// Derive PacketType from the calling context.
    ///
    /// Rules:
    /// - User input → Input
    /// - LLM response → LlmRaw
    /// - Extracted fact → Extraction
    /// - Agent decision → Decision
    /// - Tool invocation → ToolCall
    /// - Tool response → ToolResult
    /// - AAPI action → Action
    /// - Human feedback → Feedback
    /// - Conflict detected → Contradiction
    /// - State mutation → StateChange
    pub fn packet_type(context: &DerivationContext) -> PacketType {
        match context {
            DerivationContext::UserInput => PacketType::Input,
            DerivationContext::LlmResponse => PacketType::LlmRaw,
            DerivationContext::FactExtraction => PacketType::Extraction,
            DerivationContext::AgentDecision => PacketType::Decision,
            DerivationContext::ToolInvocation => PacketType::ToolCall,
            DerivationContext::ToolResponse => PacketType::ToolResult,
            DerivationContext::AuthorizedAction => PacketType::Action,
            DerivationContext::HumanFeedback => PacketType::Feedback,
            DerivationContext::ConflictDetected => PacketType::Contradiction,
            DerivationContext::StateMutation => PacketType::StateChange,
        }
    }

    /// Derive MemoryScope from PacketType (same logic as MemPacket::new).
    pub fn memory_scope(packet_type: &PacketType) -> MemoryScope {
        match packet_type {
            PacketType::Input | PacketType::LlmRaw | PacketType::ToolResult => MemoryScope::Working,
            PacketType::Extraction | PacketType::Contradiction => MemoryScope::Semantic,
            PacketType::Decision | PacketType::Action | PacketType::Feedback => MemoryScope::Episodic,
            PacketType::ToolCall | PacketType::StateChange => MemoryScope::Episodic,
        }
    }

    /// Derive SourceKind from the calling context.
    pub fn source_kind(context: &DerivationContext) -> SourceKind {
        match context {
            DerivationContext::UserInput | DerivationContext::HumanFeedback => SourceKind::User,
            DerivationContext::LlmResponse
            | DerivationContext::FactExtraction
            | DerivationContext::AgentDecision => SourceKind::SelfSource,
            DerivationContext::ToolInvocation
            | DerivationContext::ToolResponse => SourceKind::Tool,
            DerivationContext::AuthorizedAction
            | DerivationContext::ConflictDetected
            | DerivationContext::StateMutation => SourceKind::SelfSource,
        }
    }

    /// Compute CID from a serializable object.
    pub fn compute_cid_for<T: serde::Serialize>(obj: &T) -> EngineResult<Cid> {
        compute_cid(obj).map_err(|e| EngineError::KernelError(e.to_string()))
    }

    /// Compute SHA-256 hash as hex string.
    pub fn sha256_hex(content: &[u8]) -> String {
        let hash = sha256(content);
        hex::encode(hash)
    }

    /// Build a complete MemPacket from simple inputs.
    ///
    /// This is the core auto-derivation: developer provides text + user + context,
    /// engine builds the full 3D envelope MemPacket with CID, provenance, and index.
    pub fn build_packet(
        text: &str,
        subject_id: &str,
        pipeline_id: &str,
        agent_pid: &str,
        context: DerivationContext,
        session_id: Option<&str>,
        namespace: Option<&str>,
    ) -> EngineResult<MemPacket> {
        let packet_type = Self::packet_type(&context);
        let source_kind = Self::source_kind(&context);

        let payload = serde_json::Value::String(text.to_string());
        let payload_cid = Self::compute_cid_for(&payload)?;

        let now_ms = chrono::Utc::now().timestamp_millis();

        let source = Source {
            kind: source_kind,
            principal_id: agent_pid.to_string(),
        };

        let mut packet = MemPacket::new(
            packet_type,
            payload,
            payload_cid,
            subject_id.to_string(),
            pipeline_id.to_string(),
            source,
            now_ms,
        );

        if let Some(sid) = session_id {
            packet = packet.with_session(sid.to_string());
        }
        if let Some(ns) = namespace {
            packet = packet.with_namespace(ns.to_string());
        }

        Ok(packet)
    }
}

/// Context for auto-derivation — tells the engine what kind of operation this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationContext {
    /// User typed something
    UserInput,
    /// LLM generated a response
    LlmResponse,
    /// Facts were extracted from LLM output
    FactExtraction,
    /// Agent made a decision
    AgentDecision,
    /// Agent is calling a tool
    ToolInvocation,
    /// Tool returned a result
    ToolResponse,
    /// AAPI-authorized action
    AuthorizedAction,
    /// Human provided feedback/correction
    HumanFeedback,
    /// Conflict detected between facts
    ConflictDetected,
    /// State was mutated
    StateMutation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_type_derivation() {
        assert_eq!(AutoDerive::packet_type(&DerivationContext::UserInput), PacketType::Input);
        assert_eq!(AutoDerive::packet_type(&DerivationContext::LlmResponse), PacketType::LlmRaw);
        assert_eq!(AutoDerive::packet_type(&DerivationContext::FactExtraction), PacketType::Extraction);
        assert_eq!(AutoDerive::packet_type(&DerivationContext::AgentDecision), PacketType::Decision);
        assert_eq!(AutoDerive::packet_type(&DerivationContext::ToolInvocation), PacketType::ToolCall);
        assert_eq!(AutoDerive::packet_type(&DerivationContext::ToolResponse), PacketType::ToolResult);
    }

    #[test]
    fn test_scope_derivation() {
        assert_eq!(AutoDerive::memory_scope(&PacketType::Input), MemoryScope::Working);
        assert_eq!(AutoDerive::memory_scope(&PacketType::Extraction), MemoryScope::Semantic);
        assert_eq!(AutoDerive::memory_scope(&PacketType::Decision), MemoryScope::Episodic);
    }

    #[test]
    fn test_source_kind_derivation() {
        assert_eq!(AutoDerive::source_kind(&DerivationContext::UserInput), SourceKind::User);
        assert_eq!(AutoDerive::source_kind(&DerivationContext::LlmResponse), SourceKind::SelfSource);
        assert_eq!(AutoDerive::source_kind(&DerivationContext::ToolResponse), SourceKind::Tool);
    }

    #[test]
    fn test_cid_deterministic() {
        let content = "hello world";
        let cid1 = AutoDerive::compute_cid_for(&content).unwrap();
        let cid2 = AutoDerive::compute_cid_for(&content).unwrap();
        assert_eq!(cid1, cid2);
    }

    #[test]
    fn test_cid_different_content() {
        let cid1 = AutoDerive::compute_cid_for(&"hello").unwrap();
        let cid2 = AutoDerive::compute_cid_for(&"world").unwrap();
        assert_ne!(cid1, cid2);
    }

    #[test]
    fn test_build_packet() {
        let packet = AutoDerive::build_packet(
            "Patient has chest pain",
            "patient:P-123",
            "pipe:001",
            "agent:triage",
            DerivationContext::UserInput,
            Some("sess:001"),
            Some("ns:hospital/er"),
        ).unwrap();

        assert_eq!(*packet.packet_type(), PacketType::Input);
        assert_eq!(packet.subject_id, "patient:P-123");
        assert_eq!(packet.pipeline_id, "pipe:001");
        assert_eq!(packet.session_id, Some("sess:001".to_string()));
        assert_eq!(packet.namespace, Some("ns:hospital/er".to_string()));
        assert_eq!(packet.scope, MemoryScope::Working);
        assert_eq!(packet.tier, MemoryTier::Hot);
        assert_eq!(packet.provenance.source.kind, SourceKind::User);
    }

    #[test]
    fn test_sha256_hex() {
        let hash = AutoDerive::sha256_hex(b"test");
        assert_eq!(hash.len(), 64); // 32 bytes = 64 hex chars
    }
}
