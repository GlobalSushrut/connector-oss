//! The seven industry tools are Connector backends.
//!
//! An operator calls Connector. Connector calls OpenShell, the in-process IAM
//! verifier, Firecracker, SPIRE, OpenTelemetry, and cosign. OPA stays inside
//! OpenShell. `operator_runs_it` is false on every row.

use serde_json::{json, Value};

use super::runtime_adapter::{self, RuntimeKind, RuntimeProbe};

pub const SCHEMA: &str = "connector.backends.v1";

pub fn live() -> Value {
    assemble(
        &runtime_adapter::probe_all(),
        &runtime_adapter::cosign_status(),
    )
}

pub fn assemble(probes: &[RuntimeProbe], cosign: &Value) -> Value {
    let openshell = find(probes, RuntimeKind::OpenShell);
    let firecracker = find(probes, RuntimeKind::Firecracker);
    let rows = vec![
        iam_row(),
        spire_row(),
        tool_row(
            "openshell",
            "execution boundary",
            "NVIDIA OpenShell",
            openshell.map(|p| p.present).unwrap_or(false),
            openshell.map(|p| p.ready).unwrap_or(false),
            "Connector calls openshell version, policy set, sandbox create, and logs --source sandbox.",
            openshell
                .map(|p| p.detail.clone())
                .unwrap_or_else(|| "not_installed".into()),
        ),
        tool_row(
            "opa",
            "network and L7 policy",
            "OPA/Rego inside OpenShell",
            openshell.map(|p| p.present).unwrap_or(false),
            false,
            "OPA is inside the OpenShell supervisor. Connector does not ship opa and does not run opa eval.",
            "Deny lines count only when the OpenShell log says denied by policy.".into(),
        ),
        tool_row(
            "firecracker",
            "hardware isolation",
            "Firecracker + jailer",
            firecracker.map(|p| p.present).unwrap_or(false),
            firecracker.map(|p| p.ready).unwrap_or(false),
            "Connector calls FirecrackerBackend. There is no second hypervisor.",
            firecracker
                .map(|p| p.detail.clone())
                .unwrap_or_else(|| "firecracker probe missing".into()),
        ),
        tool_row(
            "otel",
            "telemetry",
            "OpenTelemetry and W3C Trace Context",
            true,
            false,
            "Connector stores the effect trace and the explain request traceparent. The operator does not run a collector to ask for explain.",
            "present means the code path exists. ready stays false until an exporter endpoint is probed.".into(),
        ),
        cosign_row(cosign),
    ];
    json!({
        "schema": SCHEMA,
        "operator": "Call connectorctl. These seven tools are backends. Do not operate them yourself.",
        "operator_runs_it": false,
        "backends": rows,
        "honesty": "present means Connector can see the tool. ready means that tool reported success. A missing binary is not emulated.",
    })
}

fn find(probes: &[RuntimeProbe], kind: RuntimeKind) -> Option<&RuntimeProbe> {
    probes.iter().find(|p| p.kind == kind)
}

fn iam_row() -> Value {
    let ready = std::env::var("CONNECTOR_JWT_SECRET")
        .map(|s| s.trim().len() >= 32)
        .unwrap_or(false);
    tool_row(
        "iam",
        "operator identity",
        "OIDC / OAuth / JWT / SCIM",
        true,
        ready,
        "The operator sends Authorization: Bearer to Connector. auth::verify_token checks it. Connector does not ask the operator to run an identity CLI.",
        if ready {
            "CONNECTOR_JWT_SECRET is at least 32 characters. SSO still uses the provider JWKS inside Connector.".into()
        } else {
            "In-process JWT verification is present. ready requires CONNECTOR_JWT_SECRET of at least 32 characters.".into()
        },
    )
}

fn spire_row() -> Value {
    let present = crate::services::cell_spiffe::spire_agent_present();
    let socket = std::env::var("SPIFFE_ENDPOINT_SOCKET")
        .ok()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    tool_row(
        "spire",
        "workload identity",
        "SPIRE",
        present,
        false,
        "Explain fetches the X.509 SPIFFE ID. Connector does not issue SVIDs. ready stays false on this catalog; a fetched id appears on explain.",
        if !present {
            "not_installed: spire-agent".into()
        } else if socket {
            "spire-agent is installed and SPIFFE_ENDPOINT_SOCKET is set. This catalog does not fetch an SVID.".into()
        } else {
            "spire-agent is installed. SPIFFE_ENDPOINT_SOCKET is unset.".into()
        },
    )
}

fn cosign_row(cosign: &Value) -> Value {
    tool_row(
        "cosign",
        "supply chain",
        "Sigstore cosign",
        cosign.get("present").and_then(|v| v.as_bool()).unwrap_or(false),
        cosign.get("verified").and_then(|v| v.as_bool()).unwrap_or(false),
        "Connector runs cosign verify-blob when the blob and signature paths are set.",
        cosign
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("cosign status has no reason")
            .to_string(),
    )
}

fn tool_row(
    id: &str,
    role: &str,
    upstream: &str,
    present: bool,
    ready: bool,
    connector_calls: &str,
    detail: String,
) -> Value {
    json!({
        "id": id,
        "role": role,
        "upstream": upstream,
        "operator_runs_it": false,
        "present": present,
        "ready": ready,
        "connector_calls": connector_calls,
        "detail": detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seven_backends_are_operated_by_connector() {
        let view = assemble(&[], &serde_json::json!({"present": false, "verified": false, "reason": "not_installed"}));
        assert_eq!(view.get("operator_runs_it").and_then(|v| v.as_bool()), Some(false));
        let rows = view.get("backends").and_then(|v| v.as_array()).unwrap();
        assert_eq!(rows.len(), 7);
        let ids: Vec<&str> = rows.iter().filter_map(|r| r.get("id").and_then(|v| v.as_str())).collect();
        assert_eq!(
            ids,
            ["iam", "spire", "openshell", "opa", "firecracker", "otel", "cosign"]
        );
        for row in rows {
            assert_eq!(row.get("operator_runs_it").and_then(|v| v.as_bool()), Some(false));
        }
        let opa = rows.iter().find(|r| r.get("id").and_then(|v| v.as_str()) == Some("opa")).unwrap();
        assert_eq!(opa.get("ready").and_then(|v| v.as_bool()), Some(false));
        assert!(opa.get("connector_calls").and_then(|v| v.as_str()).unwrap().contains("does not run opa eval"));
    }
}
