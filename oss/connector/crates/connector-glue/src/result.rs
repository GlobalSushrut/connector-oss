//! GlueResult - Canonical success envelope

use connector_engine::PipelineOutput;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Canonical success result from any GLUE operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlueResult {
    /// Always true for success
    pub ok: bool,
    /// The intent that produced this result
    pub intent: ResultIntent,
    /// The resource affected/returned
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    /// Audit receipt
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<GlueReceipt>,
    /// Product-level summary of what happened, why, and what next
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<ResultSummary>,
    /// Trust is first-class in every packaged result
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustInfo>,
    /// Evidence references attached to the operation
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceRef>,
    /// Next-action or related links
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub links: HashMap<String, String>,
    /// Role-aware rendering and redaction hints
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub render: Option<RenderHints>,
    /// Presentation hints for list/detail/receipt/report output
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation: Option<ResultPresentation>,
    /// Metadata about the packaged result contract
    #[serde(default)]
    pub meta: ResultMeta,
    /// Operation-specific result data
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub data: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultIntent {
    pub verb: String,
    pub noun: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    /// Human-readable ID (e.g., "claims-review-001")
    pub id: String,
    /// Machine UID (e.g., "agt_abc123...")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// Current state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Resource type
    pub kind: String,
}

/// Audit receipt for every operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlueReceipt {
    /// Receipt ID
    pub id: String,
    /// Trace ID for distributed tracing
    pub trace_id: String,
    /// Timestamp (ms since epoch)
    pub timestamp_ms: i64,
    /// CID of the operation record
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// Policy that was applied
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Whether the receipt is verified
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultSummary {
    pub title: String,
    pub message: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grade: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub kind: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderHints {
    pub role: String,
    pub redacted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultPresentation {
    pub mode: String,
    pub table_safe: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultMeta {
    pub schema: String,
    pub family: String,
    pub package_first: bool,
    pub view: String,
    pub source: String,
}

impl Default for ResultMeta {
    fn default() -> Self {
        Self {
            schema: "connector.result.v1".to_string(),
            family: "canonical_semantic_package".to_string(),
            package_first: true,
            view: "package".to_string(),
            source: "glue".to_string(),
        }
    }
}

impl GlueResult {
    pub fn success(verb: &str, noun: &str, target: &str) -> Self {
        Self {
            ok: true,
            intent: ResultIntent {
                verb: verb.to_string(),
                noun: noun.to_string(),
                target: target.to_string(),
            },
            resource: None,
            receipt: None,
            summary: Some(ResultSummary {
                title: format!("{} {}", capitalize(verb), noun),
                message: format!("{} {} completed", capitalize(verb), noun),
                status: "completed".to_string(),
                why: None,
                next: Vec::new(),
            }),
            trust: None,
            evidence: Vec::new(),
            links: HashMap::new(),
            render: Some(RenderHints {
                role: "developer".to_string(),
                redacted: false,
                redacted_fields: Vec::new(),
            }),
            presentation: Some(ResultPresentation {
                mode: "receipt".to_string(),
                table_safe: false,
                row_count: None,
                columns: Vec::new(),
            }),
            meta: ResultMeta::default(),
            data: HashMap::new(),
        }
    }

    pub fn with_resource(mut self, id: &str, uid: &str, kind: &str) -> Self {
        self.resource = Some(ResourceInfo {
            id: id.to_string(),
            uid: if uid.is_empty() {
                None
            } else {
                Some(uid.to_string())
            },
            state: None,
            kind: kind.to_string(),
        });
        self
    }

    pub fn with_state(mut self, state: &str) -> Self {
        if let Some(ref mut r) = self.resource {
            r.state = Some(state.to_string());
        }
        self
    }

    pub fn with_receipt(mut self, receipt: GlueReceipt) -> Self {
        self.receipt = Some(receipt);
        self
    }

    pub fn with_summary(mut self, title: &str, message: &str, status: &str) -> Self {
        self.summary = Some(ResultSummary {
            title: title.to_string(),
            message: message.to_string(),
            status: status.to_string(),
            why: self.summary.as_ref().and_then(|s| s.why.clone()),
            next: self
                .summary
                .as_ref()
                .map(|s| s.next.clone())
                .unwrap_or_default(),
        });
        self
    }

    pub fn with_reason(mut self, why: impl Into<String>) -> Self {
        let reason = Some(why.into());
        if let Some(ref mut summary) = self.summary {
            summary.why = reason;
        }
        self
    }

    pub fn with_next_step(mut self, next: impl Into<String>) -> Self {
        if let Some(ref mut summary) = self.summary {
            summary.next.push(next.into());
        }
        self
    }

    pub fn with_trust(mut self, score: Option<u32>, grade: Option<&str>, verified: bool) -> Self {
        self.trust = Some(TrustInfo {
            score,
            grade: grade.map(|g| g.to_string()),
            verified,
        });
        self
    }

    pub fn add_evidence(
        mut self,
        kind: &str,
        id: &str,
        label: Option<&str>,
        verified: bool,
    ) -> Self {
        self.evidence.push(EvidenceRef {
            kind: kind.to_string(),
            id: id.to_string(),
            label: label.map(|v| v.to_string()),
            verified,
        });
        self
    }

    pub fn with_link(mut self, name: &str, value: impl Into<String>) -> Self {
        self.links.insert(name.to_string(), value.into());
        self
    }

    pub fn with_render_role(mut self, role: &str) -> Self {
        if let Some(ref mut render) = self.render {
            render.role = role.to_string();
        }
        self
    }

    pub fn with_redacted_field(mut self, field: &str) -> Self {
        if let Some(ref mut render) = self.render {
            render.redacted = true;
            render.redacted_fields.push(field.to_string());
        }
        self
    }

    pub fn with_presentation(
        mut self,
        mode: &str,
        table_safe: bool,
        row_count: Option<usize>,
        columns: Vec<String>,
    ) -> Self {
        self.presentation = Some(ResultPresentation {
            mode: mode.to_string(),
            table_safe,
            row_count,
            columns,
        });
        self
    }

    pub fn with_source(mut self, source: &str) -> Self {
        self.meta.source = source.to_string();
        self
    }

    pub fn with_data<K: Into<String>, V: Serialize>(mut self, key: K, value: V) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.data.insert(key.into(), v);
        }
        self
    }

    /// Get a data field
    pub fn get<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        self.data
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    pub fn from_pipeline_output(output: &PipelineOutput, noun: &str, target: &str) -> Self {
        let verified = output.all_observations_verified();
        let state = if !output.status.ok || !output.errors.is_empty() {
            "failed"
        } else if !output.warnings.is_empty() {
            "completed_with_warnings"
        } else {
            "completed"
        };
        let why = output
            .errors
            .first()
            .cloned()
            .or_else(|| output.warnings.first().cloned())
            .unwrap_or_else(|| output.status.summary.clone());
        let title = match noun {
            "pipeline" => "Pipeline completed",
            _ => "Agent run completed",
        };

        let mut result = GlueResult::success("run", noun, target)
            .with_resource(target, "", noun)
            .with_state(state)
            .with_receipt(GlueReceipt::new(&output.trace.trace_id).with_verified(verified))
            .with_summary(title, &output.status.summary, state)
            .with_reason(why)
            .with_next_step("Inspect the audit trail for evidence and follow-up actions")
            .with_link("audit", "/audit")
            .with_trust(
                Some(output.status.trust),
                Some(&output.status.trust_grade),
                verified,
            )
            .with_render_role("operator")
            .with_source("connector-server")
            .with_data("text", &output.text)
            .with_data("state", state)
            .with_data("warnings", &output.warnings)
            .with_data("errors", &output.errors)
            .with_data("provenance", output.provenance_summary())
            .with_data("execution", output.to_json())
            .with_data("actors", output.status.actors)
            .with_data("steps", output.status.steps)
            .with_data("duration_ms", output.status.duration_ms)
            .with_data("event_count", output.events.len())
            .with_data("span_count", output.trace.spans.len())
            .with_data("verified", verified);

        result = result.add_evidence(
            "trace",
            &output.trace.trace_id,
            Some("execution_trace"),
            verified,
        );

        if let Some(cid) = output.events.iter().find_map(|event| event.cid.clone()) {
            result = result.add_evidence("cid", &cid, Some("kernel_evidence"), true);
        }

        result
    }
}

impl GlueReceipt {
    pub fn new(trace_id: &str) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        Self {
            id: format!("rcpt_{}", &trace_id[..8.min(trace_id.len())]),
            trace_id: trace_id.to_string(),
            timestamp_ms: ts,
            cid: None,
            policy: None,
            verified: None,
        }
    }

    pub fn with_cid(mut self, cid: impl Into<String>) -> Self {
        self.cid = Some(cid.into());
        self
    }

    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policy = Some(policy.into());
        self
    }

    pub fn with_verified(mut self, verified: bool) -> Self {
        self.verified = Some(verified);
        self
    }
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}
