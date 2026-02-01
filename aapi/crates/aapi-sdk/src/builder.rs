//! Fluent builders for VĀKYA construction

use chrono::{Duration, Utc};

use aapi_core::{
    Vakya, VakyaBuilder, VakyaId,
    Karta, Karma, Kriya, Karana, Sampradana, Apadana, Adhikarana,
    CapabilityRef, TtlConstraint, BodyType,
    ActorType, ApprovalLane,
};
use aapi_core::types::{PrincipalId, ResourceId, Namespace, Timestamp, SemanticVersion, Budget};

/// Fluent builder for creating VĀKYA requests
pub struct VakyaRequestBuilder {
    actor_pid: Option<String>,
    actor_role: Option<String>,
    actor_type: ActorType,
    resource_id: Option<String>,
    resource_kind: Option<String>,
    resource_ns: Option<String>,
    action: Option<String>,
    capability_ref: Option<String>,
    ttl_secs: Option<i64>,
    body: serde_json::Value,
    trace_id: Option<String>,
    reason: Option<String>,
}

impl Default for VakyaRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl VakyaRequestBuilder {
    pub fn new() -> Self {
        Self {
            actor_pid: None,
            actor_role: None,
            actor_type: ActorType::Human,
            resource_id: None,
            resource_kind: None,
            resource_ns: None,
            action: None,
            capability_ref: None,
            ttl_secs: Some(3600), // 1 hour default
            body: serde_json::json!({}),
            trace_id: None,
            reason: None,
        }
    }

    /// Set the actor (who is performing the action)
    pub fn actor(mut self, pid: impl Into<String>) -> Self {
        self.actor_pid = Some(pid.into());
        self
    }

    /// Set the actor with role
    pub fn actor_with_role(mut self, pid: impl Into<String>, role: impl Into<String>) -> Self {
        self.actor_pid = Some(pid.into());
        self.actor_role = Some(role.into());
        self
    }

    /// Set actor type
    pub fn actor_type(mut self, actor_type: ActorType) -> Self {
        self.actor_type = actor_type;
        self
    }

    /// Mark actor as an AI agent
    pub fn as_agent(mut self) -> Self {
        self.actor_type = ActorType::Agent;
        self
    }

    /// Set the resource (what is being acted upon)
    pub fn resource(mut self, rid: impl Into<String>) -> Self {
        self.resource_id = Some(rid.into());
        self
    }

    /// Set resource with kind (only sets kind, preserves existing resource_id)
    pub fn resource_with_kind(mut self, rid: impl Into<String>, kind: impl Into<String>) -> Self {
        let rid_str = rid.into();
        if !rid_str.is_empty() {
            self.resource_id = Some(rid_str);
        }
        self.resource_kind = Some(kind.into());
        self
    }

    /// Set resource namespace
    pub fn namespace(mut self, ns: impl Into<String>) -> Self {
        self.resource_ns = Some(ns.into());
        self
    }

    /// Set the action (what is being done)
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Set capability reference
    pub fn capability(mut self, cap_ref: impl Into<String>) -> Self {
        self.capability_ref = Some(cap_ref.into());
        self
    }

    /// Set TTL in seconds
    pub fn ttl_secs(mut self, secs: i64) -> Self {
        self.ttl_secs = Some(secs);
        self
    }

    /// Set TTL in minutes
    pub fn ttl_minutes(mut self, minutes: i64) -> Self {
        self.ttl_secs = Some(minutes * 60);
        self
    }

    /// Set TTL in hours
    pub fn ttl_hours(mut self, hours: i64) -> Self {
        self.ttl_secs = Some(hours * 3600);
        self
    }

    /// Set the request body
    pub fn body(mut self, body: serde_json::Value) -> Self {
        self.body = body;
        self
    }

    /// Set a body field
    pub fn body_field(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        if let serde_json::Value::Object(ref mut map) = self.body {
            map.insert(key.into(), value);
        }
        self
    }

    /// Set trace ID for distributed tracing
    pub fn trace(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    /// Set reason/justification for the action
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Build the VĀKYA
    pub fn build(self) -> Result<Vakya, String> {
        let actor_pid = self.actor_pid.ok_or("Actor PID is required")?;
        let resource_id = self.resource_id.ok_or("Resource ID is required")?;
        let action = self.action.ok_or("Action is required")?;

        // Parse action into domain.verb
        let (domain, verb) = if action.contains('.') {
            let parts: Vec<&str> = action.splitn(2, '.').collect();
            (parts[0].to_string(), parts[1].to_string())
        } else {
            ("default".to_string(), action.clone())
        };

        let ttl = self.ttl_secs.map(|secs| TtlConstraint {
            expires_at: Timestamp(Utc::now() + Duration::seconds(secs)),
            max_duration_ms: Some((secs * 1000) as u64),
        });

        let cap_ref = self.capability_ref.unwrap_or_else(|| "cap:default".to_string());

        let mut builder = Vakya::builder()
            .karta(Karta {
                pid: PrincipalId::new(actor_pid),
                role: self.actor_role,
                realm: None,
                key_id: None,
                actor_type: self.actor_type,
                delegation_chain: vec![],
            })
            .karma(Karma {
                rid: ResourceId::new(resource_id),
                kind: self.resource_kind,
                ns: self.resource_ns.map(Namespace::new),
                version: None,
                labels: std::collections::HashMap::new(),
            })
            .kriya(Kriya {
                action,
                domain: Some(domain),
                verb: Some(verb),
                expected_effect: aapi_core::types::EffectBucket::None,
                idempotent: false,
            })
            .adhikarana(Adhikarana {
                cap: CapabilityRef::Reference { cap_ref },
                policy_ref: None,
                ttl,
                budgets: vec![],
                approval_lane: ApprovalLane::None,
                scopes: vec![],
                context: None,
            })
            .body(self.body);

        if let Some(trace_id) = self.trace_id {
            builder = builder.trace(aapi_core::types::TraceContext {
                trace_id,
                span_id: uuid::Uuid::new_v4().to_string(),
                parent_span_id: None,
                sampled: true,
            });
        }

        if let Some(reason) = self.reason {
            builder = builder.hetu(aapi_core::vakya::Hetu {
                reason,
                chain: vec![],
                confidence: None,
            });
        }

        builder.build().map_err(|e| e.to_string())
    }
}

/// Quick builder for common file operations
pub struct FileActionBuilder;

impl FileActionBuilder {
    /// Read a file
    pub fn read(actor: impl Into<String>, path: impl Into<String>) -> VakyaRequestBuilder {
        VakyaRequestBuilder::new()
            .actor(actor)
            .resource(format!("file:{}", path.into()))
            .resource_with_kind(String::new(), "file")
            .action("file.read")
    }

    /// Write to a file
    pub fn write(actor: impl Into<String>, path: impl Into<String>, content: impl Into<String>) -> VakyaRequestBuilder {
        VakyaRequestBuilder::new()
            .actor(actor)
            .resource(format!("file:{}", path.into()))
            .resource_with_kind(String::new(), "file")
            .action("file.write")
            .body(serde_json::json!({"content": content.into()}))
    }

    /// Delete a file
    pub fn delete(actor: impl Into<String>, path: impl Into<String>) -> VakyaRequestBuilder {
        VakyaRequestBuilder::new()
            .actor(actor)
            .resource(format!("file:{}", path.into()))
            .resource_with_kind(String::new(), "file")
            .action("file.delete")
    }

    /// List directory
    pub fn list(actor: impl Into<String>, path: impl Into<String>) -> VakyaRequestBuilder {
        VakyaRequestBuilder::new()
            .actor(actor)
            .resource(format!("file:{}", path.into()))
            .resource_with_kind(String::new(), "directory")
            .action("file.list")
    }
}

/// Quick builder for HTTP operations
pub struct HttpActionBuilder;

impl HttpActionBuilder {
    /// HTTP GET request
    pub fn get(actor: impl Into<String>, url: impl Into<String>) -> VakyaRequestBuilder {
        VakyaRequestBuilder::new()
            .actor(actor)
            .resource(url)
            .resource_with_kind(String::new(), "http")
            .action("http.get")
    }

    /// HTTP POST request
    pub fn post(actor: impl Into<String>, url: impl Into<String>, body: serde_json::Value) -> VakyaRequestBuilder {
        VakyaRequestBuilder::new()
            .actor(actor)
            .resource(url)
            .resource_with_kind(String::new(), "http")
            .action("http.post")
            .body(serde_json::json!({"body": body}))
    }

    /// HTTP PUT request
    pub fn put(actor: impl Into<String>, url: impl Into<String>, body: serde_json::Value) -> VakyaRequestBuilder {
        VakyaRequestBuilder::new()
            .actor(actor)
            .resource(url)
            .resource_with_kind(String::new(), "http")
            .action("http.put")
            .body(serde_json::json!({"body": body}))
    }

    /// HTTP DELETE request
    pub fn delete(actor: impl Into<String>, url: impl Into<String>) -> VakyaRequestBuilder {
        VakyaRequestBuilder::new()
            .actor(actor)
            .resource(url)
            .resource_with_kind(String::new(), "http")
            .action("http.delete")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vakya_builder() {
        let vakya = VakyaRequestBuilder::new()
            .actor("user:alice")
            .resource("file:/home/alice/test.txt")
            .action("file.read")
            .ttl_hours(1)
            .reason("Reading configuration file")
            .build();

        assert!(vakya.is_ok());
        let vakya = vakya.unwrap();
        assert_eq!(vakya.v1_karta.pid.0, "user:alice");
        assert_eq!(vakya.v3_kriya.action, "file.read");
    }

    #[test]
    fn test_file_action_builder() {
        let vakya = FileActionBuilder::read("user:bob", "/data/report.csv")
            .ttl_minutes(30)
            .build();

        assert!(vakya.is_ok());
    }

    #[test]
    fn test_http_action_builder() {
        let vakya = HttpActionBuilder::post(
            "agent:assistant",
            "https://api.example.com/v1/data",
            serde_json::json!({"key": "value"}),
        )
        .as_agent()
        .build();

        assert!(vakya.is_ok());
        let vakya = vakya.unwrap();
        assert_eq!(vakya.v1_karta.actor_type, ActorType::Agent);
    }

    #[test]
    fn test_missing_required_fields() {
        let result = VakyaRequestBuilder::new()
            .actor("user:test")
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Resource ID"));
    }
}
