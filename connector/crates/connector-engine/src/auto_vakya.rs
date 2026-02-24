//! Auto-Vakya Generator — constructs AAPI Vakya from simple method calls.
//!
//! The developer calls: `agent.run("Hello", "user:alice")`
//! The engine constructs a complete 8-slot Vakya with zero developer effort.

use aapi_core::types::*;
use aapi_core::vakya::*;

/// Auto-Vakya generator — converts simple method calls into full AAPI Vakya envelopes.
pub struct AutoVakya;

impl AutoVakya {
    /// Build a Vakya for an agent.run() call.
    pub fn for_agent_run(
        agent_pid: &str,
        agent_role: Option<&str>,
        resource_id: &str,
        action: &str,
        compliance: &[String],
        namespace: Option<&str>,
        _session_id: Option<&str>,
        _pipeline_id: Option<&str>,
        model: Option<&str>,
    ) -> Result<Vakya, aapi_core::error::AapiError> {
        let karta = Self::build_karta(agent_pid, agent_role, namespace);

        let karma = Karma {
            rid: ResourceId::new(resource_id),
            kind: None,
            ns: namespace.map(|n| Namespace::new(n)),
            version: None,
            labels: std::collections::HashMap::new(),
        };

        let kriya = Kriya::new("agent", action);
        let adhikarana = Self::build_adhikarana(compliance);

        let mut builder = Vakya::builder()
            .karta(karta)
            .karma(karma)
            .kriya(kriya)
            .adhikarana(adhikarana);

        if let Some(model_name) = model {
            builder = builder.hetu(Hetu {
                reason: format!("Agent {} executing {} via {}", agent_pid, action, model_name),
                chain: Vec::new(),
                confidence: None,
                evidence_cids: Vec::new(),
            });
        }

        builder.build()
    }

    /// Build a Vakya for a tool call.
    pub fn for_tool_call(
        agent_pid: &str,
        agent_role: Option<&str>,
        tool_id: &str,
        tool_action: &str,
        target_resource: &str,
        compliance: &[String],
        namespace: Option<&str>,
    ) -> Result<Vakya, aapi_core::error::AapiError> {
        let karta = Self::build_karta(agent_pid, agent_role, namespace);

        let karma = Karma {
            rid: ResourceId::new(target_resource),
            kind: Some("tool_target".to_string()),
            ns: namespace.map(|n| Namespace::new(n)),
            version: None,
            labels: std::collections::HashMap::new(),
        };

        let kriya = Kriya::new("tool", tool_action);

        let karana = Karana {
            via: Some("connector-engine".to_string()),
            adapter: Some(tool_id.to_string()),
            tool: Some(tool_id.to_string()),
            metadata: std::collections::HashMap::new(),
        };

        let adhikarana = Self::build_adhikarana(compliance);

        Vakya::builder()
            .karta(karta)
            .karma(karma)
            .kriya(kriya)
            .karana(karana)
            .adhikarana(adhikarana)
            .build()
    }

    /// Build a Vakya for an LLM inference call.
    pub fn for_llm_call(
        agent_pid: &str,
        agent_role: Option<&str>,
        model: &str,
        provider: &str,
        compliance: &[String],
        namespace: Option<&str>,
    ) -> Result<Vakya, aapi_core::error::AapiError> {
        let karta = Self::build_karta(agent_pid, agent_role, namespace);

        let karma = Karma {
            rid: ResourceId::new(format!("{}:{}", provider, model)),
            kind: Some("llm_model".to_string()),
            ns: None,
            version: None,
            labels: std::collections::HashMap::new(),
        };

        let kriya = Kriya::new("llm", "inference");

        let karana = Karana {
            via: Some("https".to_string()),
            adapter: Some(provider.to_string()),
            tool: Some(format!("{}/{}", provider, model)),
            metadata: std::collections::HashMap::new(),
        };

        let adhikarana = Self::build_adhikarana(compliance);

        Vakya::builder()
            .karta(karta)
            .karma(karma)
            .kriya(kriya)
            .karana(karana)
            .adhikarana(adhikarana)
            .build()
    }

    /// Build a Vakya for memory operations (remember/recall).
    pub fn for_memory_op(
        agent_pid: &str,
        agent_role: Option<&str>,
        op: &str, // "write" or "read"
        subject_id: &str,
        compliance: &[String],
        namespace: Option<&str>,
    ) -> Result<Vakya, aapi_core::error::AapiError> {
        let karta = Self::build_karta(agent_pid, agent_role, namespace);

        let karma = Karma {
            rid: ResourceId::new(subject_id),
            kind: Some("memory".to_string()),
            ns: namespace.map(|n| Namespace::new(n)),
            version: None,
            labels: std::collections::HashMap::new(),
        };

        let kriya = Kriya::new("memory", op);
        let adhikarana = Self::build_adhikarana(compliance);

        Vakya::builder()
            .karta(karta)
            .karma(karma)
            .kriya(kriya)
            .adhikarana(adhikarana)
            .build()
    }

    /// Build Karta (V1) — the actor performing the action.
    fn build_karta(agent_pid: &str, agent_role: Option<&str>, namespace: Option<&str>) -> Karta {
        Karta {
            pid: PrincipalId::new(agent_pid),
            role: agent_role.map(|r| r.to_string()),
            realm: namespace.map(|n| n.to_string()),
            key_id: None,
            actor_type: ActorType::Agent,
            delegation_chain: Vec::new(),
        }
    }

    /// Build Adhikarana (V7) — authority context from compliance config.
    ///
    /// Creates a default capability reference and populates scopes.
    /// For production, the CapabilityRef would reference a real token.
    fn build_adhikarana(_compliance: &[String]) -> Adhikarana {
        let cap = CapabilityRef::Reference {
            cap_ref: "cap:connector-engine-default".to_string(),
        };

        Adhikarana {
            cap,
            policy_ref: None,
            ttl: None,
            budgets: Vec::new(),
            approval_lane: ApprovalLane::None,
            scopes: vec!["*".to_string()],
            context: None,
            delegation_chain_cid: None,
            execution_constraints: None,
            port_id: None,
            required_phase: None,
            required_role: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_for_agent_run() {
        let vakya = AutoVakya::for_agent_run(
            "agent:triage",
            Some("writer"),
            "user:alice",
            "run",
            &["hipaa".to_string()],
            Some("ns:hospital"),
            Some("sess:001"),
            Some("pipe:001"),
            Some("gpt-4o"),
        ).unwrap();

        assert_eq!(vakya.v1_karta.pid.as_str(), "agent:triage");
        assert_eq!(vakya.v1_karta.role.as_deref(), Some("writer"));
        assert_eq!(vakya.v2_karma.rid.as_str(), "user:alice");
        assert_eq!(vakya.v3_kriya.action, "agent.run");
        assert_eq!(vakya.v1_karta.actor_type, ActorType::Agent);
    }

    #[test]
    fn test_for_tool_call() {
        let vakya = AutoVakya::for_tool_call(
            "agent:doctor",
            Some("tool_agent"),
            "read_ehr",
            "query",
            "ehr:patient:P-123",
            &["hipaa".to_string()],
            Some("ns:hospital/er"),
        ).unwrap();

        assert_eq!(vakya.v3_kriya.action, "tool.query");
        assert!(vakya.v4_karana.is_some());
        assert_eq!(vakya.v4_karana.as_ref().unwrap().tool.as_deref(), Some("read_ehr"));
    }

    #[test]
    fn test_for_llm_call() {
        let vakya = AutoVakya::for_llm_call(
            "agent:bot",
            None,
            "gpt-4o",
            "openai",
            &[],
            None,
        ).unwrap();

        assert_eq!(vakya.v3_kriya.action, "llm.inference");
        assert_eq!(vakya.v2_karma.rid.as_str(), "openai:gpt-4o");
    }

    #[test]
    fn test_for_memory_op() {
        let vakya = AutoVakya::for_memory_op(
            "agent:bot",
            Some("writer"),
            "write",
            "user:alice",
            &[],
            None,
        ).unwrap();

        assert_eq!(vakya.v3_kriya.action, "memory.write");
        assert_eq!(vakya.v2_karma.kind.as_deref(), Some("memory"));
    }
}
