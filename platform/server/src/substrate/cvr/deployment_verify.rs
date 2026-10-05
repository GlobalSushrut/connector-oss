//! Fail-closed operational verification for Connector's seven backends.
//!
//! `/readyz` answers whether the Connector process booted. This module answers
//! a different question: did every required upstream perform its real job?

use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::state::PlatformState;

use super::runtime_adapter::{self, RuntimeKind};

pub const SCHEMA: &str = "connector.backends_deployment.v1";
pub const EVIDENCE_FOLDER: &str = "backend_operational_evidence_v1";
static OTEL_EXPORT_VERIFIED: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub struct EvidenceSpanExporter<E> {
    inner: E,
}

impl<E> EvidenceSpanExporter<E> {
    pub fn new(inner: E) -> Self {
        Self { inner }
    }
}

impl<E> opentelemetry_sdk::export::trace::SpanExporter for EvidenceSpanExporter<E>
where
    E: opentelemetry_sdk::export::trace::SpanExporter + 'static,
{
    fn export(
        &mut self,
        batch: Vec<opentelemetry_sdk::export::trace::SpanData>,
    ) -> futures::future::BoxFuture<
        'static,
        opentelemetry_sdk::export::trace::ExportResult,
    > {
        let future = self.inner.export(batch);
        Box::pin(async move {
            let result = future.await;
            if result.is_ok() {
                OTEL_EXPORT_VERIFIED.store(true, Ordering::Release);
            }
            result
        })
    }

    fn shutdown(&mut self) {
        self.inner.shutdown();
    }

    fn force_flush(
        &mut self,
    ) -> futures::future::BoxFuture<
        'static,
        opentelemetry_sdk::export::trace::ExportResult,
    > {
        self.inner.force_flush()
    }
}

pub fn otel_export_verified() -> bool {
    OTEL_EXPORT_VERIFIED.load(Ordering::Acquire)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployProfile {
    LinuxKvm,
    Kubernetes,
}

impl DeployProfile {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "linux-kvm" | "linux_kvm" | "linux" => Some(Self::LinuxKvm),
            "kubernetes" | "k8s" => Some(Self::Kubernetes),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinuxKvm => "linux-kvm",
            Self::Kubernetes => "kubernetes",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct OperationalInputs {
    pub iam_jwt_ready: bool,
    pub iam_oidc_verified: bool,
    pub spire_svid: Option<String>,
    pub openshell_policy_applied: bool,
    pub firecracker_host_ready: bool,
    pub firecracker_microd_ready: bool,
    pub firecracker_lifecycle_verified: bool,
    pub otel_export_verified: bool,
    pub cosign_verified: bool,
}

pub fn live(state: &PlatformState, profile: DeployProfile) -> Value {
    let probes = runtime_adapter::probe_all();
    let openshell_policy_applied = any_policy_applied(state);
    let firecracker_host_ready = probes
        .iter()
        .find(|probe| probe.kind == RuntimeKind::Firecracker)
        .is_some_and(|probe| probe.ready);
    let microd = super::microd_client::status();
    let firecracker_microd_ready = microd.get("ok").and_then(Value::as_bool) == Some(true)
        && super::microd_client::microd_verified_ready();
    let spire = crate::services::cell_spiffe::fetch_spire_x509();
    let inputs = OperationalInputs {
        iam_jwt_ready: std::env::var("CONNECTOR_JWT_SECRET")
            .map(|secret| secret.trim().len() >= 32)
            .unwrap_or(false),
        iam_oidc_verified: evidence_success(state, "iam", "oidc_jwks_token_verified"),
        spire_svid: spire.spiffe_id,
        openshell_policy_applied,
        firecracker_host_ready,
        firecracker_microd_ready,
        firecracker_lifecycle_verified: evidence_success(
            state,
            "firecracker",
            "create_start_pause_destroy",
        ),
        otel_export_verified: otel_export_verified()
            || evidence_success(state, "otel", "otlp_export"),
        cosign_verified: runtime_adapter::cosign_status()
            .get("verified")
            .and_then(Value::as_bool)
            == Some(true),
    };
    evaluate(profile, &inputs)
}

pub fn evaluate(profile: DeployProfile, input: &OperationalInputs) -> Value {
    let iam = input.iam_jwt_ready && input.iam_oidc_verified;
    let spire = input
        .spire_svid
        .as_deref()
        .is_some_and(valid_spiffe_id);
    let openshell = input.openshell_policy_applied;
    let firecracker = input.firecracker_host_ready
        && input.firecracker_microd_ready
        && input.firecracker_lifecycle_verified;
    let rows = vec![
        row(
            "iam",
            iam,
            "Keycloak OIDC/JWKS token verified through Connector auth",
            if iam {
                "verified"
            } else {
                "requires JWT secret >=32 and oidc_jwks_token_verified evidence"
            },
        ),
        row(
            "spire",
            spire,
            "SPIRE Workload API returned an X.509 SVID",
            input.spire_svid.as_deref().unwrap_or("no fetched SPIFFE ID"),
        ),
        row(
            "openshell",
            openshell,
            "NVIDIA OpenShell accepted Connector policy with --wait",
            if openshell {
                "persisted successful policy set"
            } else {
                "no successful OpenShell policy set evidence"
            },
        ),
        row(
            "opa",
            openshell,
            "OPA/Rego is the policy controller inside OpenShell",
            if openshell {
                "ready follows the successful OpenShell policy operation"
            } else {
                "Connector does not run opa eval; OpenShell policy evidence is missing"
            },
        ),
        row(
            "firecracker",
            firecracker,
            "Firecracker+jailer through connector-microd",
            if firecracker {
                "KVM/assets, verified microd, and lifecycle acceptance are present"
            } else {
                "requires KVM/assets, verified microd, and create_start_pause_destroy evidence"
            },
        ),
        row(
            "otel",
            input.otel_export_verified,
            "OpenTelemetry OTLP export",
            if input.otel_export_verified {
                "collector accepted an exported span"
            } else {
                "OTEL_EXPORTER_OTLP_ENDPOINT configuration alone is not evidence"
            },
        ),
        row(
            "cosign",
            input.cosign_verified,
            "Sigstore cosign verify-blob",
            if input.cosign_verified {
                "configured release manifest signature verified"
            } else {
                "cosign verify-blob did not succeed"
            },
        ),
    ];
    let blockers: Vec<Value> = rows
        .iter()
        .filter(|row| row.get("ready").and_then(Value::as_bool) != Some(true))
        .map(|row| {
            json!({
                "backend": row.get("id").cloned().unwrap_or(Value::Null),
                "reason": row.get("detail").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    let operational_ready = blockers.is_empty();
    let upstream_experimental = profile == DeployProfile::Kubernetes;
    let production_eligible = operational_ready && !upstream_experimental;
    json!({
        "schema": SCHEMA,
        "profile": profile.as_str(),
        "operational_ready": operational_ready,
        "production_eligible": production_eligible,
        "operator_runs_it": false,
        "backends": rows,
        "blockers": blockers,
        "upstream_constraints": if upstream_experimental {
            json!([{
                "backend": "openshell",
                "status": "upstream_experimental",
                "detail": "NVIDIA documents the OpenShell Kubernetes Helm chart as experimental and not for production."
            }])
        } else {
            json!([])
        },
        "honesty": "Process readiness is separate. Every backend is required. Presence and configuration are not operational evidence. PATE remains the only admission authority.",
    })
}

/// Record evidence only from a code path that completed the named operation.
/// There is deliberately no public HTTP endpoint that accepts these records.
pub fn record_operation_success(
    state: &PlatformState,
    backend: &str,
    operation: &str,
    evidence: Value,
) {
    let record = json!({
        "schema": "connector.backend_operational_evidence.v1",
        "backend": backend,
        "operation": operation,
        "success": true,
        "evidence": evidence,
        "recorded_at_ms": chrono::Utc::now().timestamp_millis(),
    });
    if let Ok(mut store) = state.engine_store.lock() {
        let _ = store.folder_put(EVIDENCE_FOLDER, backend, &record);
    }
}

/// Require the actual create/start -> pause -> destroy sequence before the
/// Firecracker row can become ready.
pub fn record_firecracker_stage(
    state: &PlatformState,
    microcell_id: &str,
    stage: &str,
) {
    let prior = {
        let Ok(store) = state.engine_store.lock() else {
            return;
        };
        store
            .folder_get(EVIDENCE_FOLDER, "firecracker")
            .ok()
            .flatten()
            .and_then(|value| {
                let operation = value
                    .get("operation")
                    .and_then(Value::as_str)
                    .map(str::to_string)?;
                let id = value
                    .pointer("/evidence/microcell_id")
                    .and_then(Value::as_str)
                    .map(str::to_string)?;
                Some((operation, id))
            })
    };
    let same_cell_prior = prior
        .as_ref()
        .filter(|(_, id)| id == microcell_id)
        .map(|(operation, _)| operation.as_str());
    let operation = match (same_cell_prior, stage) {
        (_, "create_start") => "create_start",
        (Some("create_start"), "pause") => "create_start_pause",
        (Some("create_start_pause"), "destroy") => "create_start_pause_destroy",
        _ => return,
    };
    record_operation_success(
        state,
        "firecracker",
        operation,
        json!({"microcell_id": microcell_id, "stage": stage}),
    );
}

fn row(id: &str, ready: bool, operation: &str, detail: &str) -> Value {
    json!({
        "id": id,
        "ready": ready,
        "required": true,
        "operator_runs_it": false,
        "admits": false,
        "operation": operation,
        "detail": detail,
    })
}

fn valid_spiffe_id(value: &str) -> bool {
    value.starts_with("spiffe://")
        && value.len() > "spiffe://".len()
        && !value.chars().any(char::is_whitespace)
}

fn evidence_success(state: &PlatformState, backend: &str, operation: &str) -> bool {
    let Ok(store) = state.engine_store.lock() else {
        return false;
    };
    store
        .folder_get(EVIDENCE_FOLDER, backend)
        .ok()
        .flatten()
        .is_some_and(|value| {
            value.get("operation").and_then(Value::as_str) == Some(operation)
                && value.get("success").and_then(Value::as_bool) == Some(true)
        })
}

fn any_policy_applied(state: &PlatformState) -> bool {
    let Ok(store) = state.engine_store.lock() else {
        return false;
    };
    let Ok(keys) = store.folder_keys(runtime_adapter::POLICY_GEN_FOLDER, Some("latest:")) else {
        return false;
    };
    keys.into_iter().any(|key| {
        store
            .folder_get(runtime_adapter::POLICY_GEN_FOLDER, &key)
            .ok()
            .flatten()
            .is_some_and(|value| {
                value.get("openshell_ready").and_then(Value::as_bool) == Some(true)
                    && value.get("pushed").and_then(Value::as_bool) == Some(true)
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> OperationalInputs {
        OperationalInputs {
            iam_jwt_ready: true,
            iam_oidc_verified: true,
            spire_svid: Some("spiffe://example.org/ns/connector/sa/platform".into()),
            openshell_policy_applied: true,
            firecracker_host_ready: true,
            firecracker_microd_ready: true,
            firecracker_lifecycle_verified: true,
            otel_export_verified: true,
            cosign_verified: true,
        }
    }

    #[test]
    fn linux_requires_real_operations_from_all_seven_backends() {
        let report = evaluate(DeployProfile::LinuxKvm, &complete());
        assert_eq!(report["operational_ready"], true);
        assert_eq!(report["production_eligible"], true);
        let rows = report["backends"].as_array().unwrap();
        assert_eq!(rows.len(), 7);
        assert_eq!(
            rows.iter()
                .filter_map(|row| row["id"].as_str())
                .collect::<Vec<_>>(),
            ["iam", "spire", "openshell", "opa", "firecracker", "otel", "cosign"]
        );
    }

    #[test]
    fn presence_or_configuration_cannot_make_a_backend_ready() {
        let mut input = complete();
        input.iam_oidc_verified = false;
        input.firecracker_lifecycle_verified = false;
        input.otel_export_verified = false;
        let report = evaluate(DeployProfile::LinuxKvm, &input);
        assert_eq!(report["operational_ready"], false);
        let blocked: Vec<&str> = report["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value["backend"].as_str())
            .collect();
        assert_eq!(blocked, ["iam", "firecracker", "otel"]);
    }

    #[test]
    fn opa_cannot_be_ready_without_openshell_policy_evidence() {
        let mut input = complete();
        input.openshell_policy_applied = false;
        let report = evaluate(DeployProfile::LinuxKvm, &input);
        let rows = report["backends"].as_array().unwrap();
        for id in ["openshell", "opa"] {
            let row = rows.iter().find(|row| row["id"] == id).unwrap();
            assert_eq!(row["ready"], false);
            assert_eq!(row["admits"], false);
        }
    }

    #[test]
    fn no_backend_can_mint_pate_allow() {
        let report = evaluate(DeployProfile::LinuxKvm, &complete());
        for row in report["backends"].as_array().unwrap() {
            assert_eq!(row["admits"], false);
        }
        assert!(report["honesty"]
            .as_str()
            .unwrap()
            .contains("PATE remains the only admission authority"));
    }

    #[test]
    fn local_or_malformed_spiffe_values_are_not_svids() {
        let mut input = complete();
        input.spire_svid = Some("spiffe://".into());
        assert_eq!(
            evaluate(DeployProfile::LinuxKvm, &input)["operational_ready"],
            false
        );
        input.spire_svid = Some("spiffe://example.org/bad id".into());
        assert_eq!(
            evaluate(DeployProfile::LinuxKvm, &input)["operational_ready"],
            false
        );
    }

    #[test]
    fn kubernetes_is_not_production_eligible_while_openshell_chart_is_experimental() {
        let report = evaluate(DeployProfile::Kubernetes, &complete());
        assert_eq!(report["operational_ready"], true);
        assert_eq!(report["production_eligible"], false);
        assert_eq!(
            report.pointer("/upstream_constraints/0/status"),
            Some(&json!("upstream_experimental"))
        );
    }
}
