//! Static seed for `institution_capability.v1` — ground truth for TT/WC/DG/kernel.

use serde_json::{json, Value};

pub const INSTITUTION_CAPABILITY_SCHEMA: &str = "institution_capability.v1";

pub fn seed_capabilities() -> Vec<Value> {
    vec![
        kernel_capabilities(),
        witnessctl_capabilities(),
        tracetramp_capabilities(),
        devguard_capabilities(),
    ]
}

fn kernel_capabilities() -> Value {
    json!({
        "schema": INSTITUTION_CAPABILITY_SCHEMA,
        "institution_id": "kernel",
        "archetype": "kernel",
        "label": "Connector Kernel",
        "capabilities": [
            {
                "id": "audit.export",
                "kind": "export",
                "label": "Export audit log",
                "formats": ["jsonl", "otel", "cloudevents"],
                "method": "GET",
                "paths": [
                    "/actionlog/export/jsonl",
                    "/actionlog/export/otel",
                    "/actionlog/export/cloudevents"
                ]
            },
            {
                "id": "proof.merkle",
                "kind": "forensics",
                "label": "Merkle proof",
                "method": "GET",
                "path": "/proof/merkle-proof/{cid}",
                "requires": { "cid": "string" }
            },
            {
                "id": "compliance.pdf",
                "kind": "export",
                "label": "Compliance PDF",
                "formats": ["pdf"],
                "method": "GET",
                "paths": ["/compliance/report/pdf", "/compliance/brief/pdf"]
            },
            {
                "id": "report.center",
                "kind": "export",
                "label": "Report center",
                "method": "GET",
                "path": "/reports/center"
            },
            {
                "id": "cls.execution.export",
                "kind": "export",
                "label": "CLS execution export",
                "method": "GET",
                "path": "/cls/packages/{package_id}/execution/export",
                "requires": { "package_id": "string" }
            }
        ]
    })
}

fn witnessctl_capabilities() -> Value {
    json!({
        "schema": INSTITUTION_CAPABILITY_SCHEMA,
        "institution_id": "witnessctl",
        "archetype": "witness",
        "label": "WitnessCtl",
        "capabilities": [
            {
                "id": "evidence.export",
                "kind": "export",
                "label": "Session export",
                "formats": ["pdf", "json", "csv", "md", "di_audit_middle"],
                "method": "GET",
                "path": "/plugins/witnessctl/sessions/{session_id}/export",
                "requires": { "session_id": "string" }
            },
            {
                "id": "compliance.report",
                "kind": "export",
                "label": "Compliance report",
                "formats": ["pdf"],
                "method": "GET",
                "path": "/plugins/witnessctl/sessions/{session_id}/report",
                "requires": { "session_id": "string", "framework": "string" }
            },
            {
                "id": "custody.status",
                "kind": "forensics",
                "label": "Custody chain",
                "method": "GET",
                "path": "/plugins/witnessctl/custody/{session_id}/status",
                "requires": { "session_id": "string" },
                "produces": "kv"
            },
            {
                "id": "session.list",
                "kind": "forensics",
                "label": "List sessions",
                "method": "GET",
                "path": "/plugins/witnessctl/sessions"
            }
        ]
    })
}

fn tracetramp_capabilities() -> Value {
    json!({
        "schema": INSTITUTION_CAPABILITY_SCHEMA,
        "institution_id": "tracetramp",
        "archetype": "enforcer",
        "label": "TraceTramp",
        "capabilities": [
            {
                "id": "compliance.export",
                "kind": "export",
                "label": "Compliance export",
                "formats": ["csv", "json", "html", "pdf"],
                "method": "GET",
                "path": "/plugins/tracetramp/admin/compliance/export"
            },
            {
                "id": "trace.list",
                "kind": "forensics",
                "label": "Trace list",
                "method": "GET",
                "path": "/plugins/tracetramp/admin/traces"
            },
            {
                "id": "approval.queue",
                "kind": "perform",
                "label": "Approval queue",
                "method": "GET",
                "path": "/plugins/tracetramp/admin/approvals"
            },
            {
                "id": "policy.manage",
                "kind": "perform",
                "label": "Policy management",
                "method": "GET",
                "path": "/plugins/tracetramp/admin/policies"
            }
        ]
    })
}

fn devguard_capabilities() -> Value {
    json!({
        "schema": INSTITUTION_CAPABILITY_SCHEMA,
        "institution_id": "devguard",
        "archetype": "actor",
        "label": "DevGuard",
        "capabilities": [
            {
                "id": "connect.tool",
                "kind": "perform",
                "label": "Connect coding tool",
                "method": "POST",
                "path": "/devguard/connect",
                "note": "No PDF export — perform only"
            },
            {
                "id": "profile.local",
                "kind": "perform",
                "label": "Local profile",
                "method": "GET",
                "paths": [
                    "/plugins/devguard/local-profile"
                ]
            },
            {
                "id": "extension.status",
                "kind": "forensics",
                "label": "Extension status",
                "method": "GET",
                "path": "/plugins/devguard/extension/status"
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devguard_has_no_evidence_export() {
        let caps = seed_capabilities();
        let dg = caps
            .iter()
            .find(|c| c.get("institution_id").and_then(|v| v.as_str()) == Some("devguard"))
            .expect("devguard");
        let has_export = dg
            .get("capabilities")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().any(|c| {
                    c.get("id")
                        .and_then(|v| v.as_str())
                        .map(|id| id.contains("evidence.export"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        assert!(!has_export);
    }

    #[test]
    fn witnessctl_has_pdf_export() {
        let caps = seed_capabilities();
        let wc = caps
            .iter()
            .find(|c| c.get("institution_id").and_then(|v| v.as_str()) == Some("witnessctl"))
            .expect("witnessctl");
        let export = wc
            .get("capabilities")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.iter().find(|c| c.get("id").and_then(|v| v.as_str()) == Some("evidence.export")));
        assert!(export.is_some());
        let formats = export.unwrap().get("formats").and_then(|v| v.as_array()).unwrap();
        assert!(formats.iter().any(|f| f == "pdf"));
    }
}
