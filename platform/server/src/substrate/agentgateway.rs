//! Fail-closed agentgateway decision. The binary is not installed.
//! A missing task, a non-Proceed verdict, or a missing process all deny forwarding.

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::{PlatformState, SharedState};
use crate::substrate::pate::{
    finish_task_record, host_admission_allows_execution, AugmentedTaskUnit, EffectKind, TaskAttempt,
    TaskRefs, TaskVerdict, ToolFootprint, PATE_SCHEMA,
};
use crate::substrate::spend_cease::{continue_after_cease, generation_is_live, ContinueAfterCease};

const PIN_FILE: &str = include_str!("../../../deploy/seven-backends/linux/agentgateway.pin");

pub fn pinned_reference() -> &'static str {
    PIN_FILE
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .unwrap_or("")
}

pub fn pinned_digest_verified(reference: &str) -> bool {
    let Some(digest) = reference.rsplit_once("@sha256:") else {
        return false;
    };
    let hex = digest.1;
    hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) && reference.contains('/')
}

/// Live supervision is absent. A pinned digest does not make the process ready.
pub fn process_ready() -> bool {
    false
}

fn adapter_forwards() -> bool {
    false
}

/// A tool catalog is not an effect admission.
pub fn mcp_discovery_admits_effect() -> bool {
    false
}

/// Strip bearer tokens, tool secrets, and PEM private keys from a normal log line.
pub fn redact_normal_log(text: &str) -> String {
    let without_keys = redact_pem(text);
    let without_bearer = redact_token_after(&without_keys, "Bearer ");
    redact_token_after(&without_bearer, "sk-")
}

fn redact_token_after(text: &str, marker: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(idx) = rest.find(marker) {
        out.push_str(&rest[..idx]);
        out.push_str(marker);
        out.push_str("[redacted]");
        let tail = &rest[idx + marker.len()..];
        let skip = tail.find(char::is_whitespace).unwrap_or(tail.len());
        rest = &tail[skip..];
    }
    out.push_str(rest);
    out
}

fn redact_pem(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        if let Some(end_rel) = after.find("-----END ") {
            let from_end = &after[end_rel..];
            if let Some(close) = from_end.find("-----") {
                let tail_from = from_end[close + 5..].find('\n').map(|n| n + 1).unwrap_or(0);
                rest = &from_end[close + 5 + tail_from..];
                out.push_str("[redacted_private_key]");
                continue;
            }
        }
        out.push_str(after);
        rest = "";
        break;
    }
    out.push_str(rest);
    out
}

fn acceptance_unit(task_id: &str, verdict: TaskVerdict) -> AugmentedTaskUnit {
    AugmentedTaskUnit {
        schema: PATE_SCHEMA.into(),
        task_id: task_id.into(),
        agent_pid: "agent-acceptance".into(),
        broker_epoch: 1,
        iac_epoch: 1,
        consistency_level: 2,
        effect_kind: EffectKind::ToolDispatch,
        action_digest: "digest-acceptance".into(),
        tool_footprint: ToolFootprint::default(),
        mission_id: None,
        mission_step_id: None,
        verdict,
        autonomy: None,
        minted_at_ms: 1,
        context_ref: None,
        spine: Default::default(),
    }
}

fn check(id: &str, passed: bool, status: &str, detail: &str) -> Value {
    json!({
        "id": id,
        "passed": passed,
        "status": status,
        "detail": detail,
    })
}

fn connector_side_checks() -> Vec<Value> {
    let mutation_refused = !host_admission_allows_execution(TaskVerdict::AskHitl)
        && !host_admission_allows_execution(TaskVerdict::Block)
        && !host_admission_allows_execution(TaskVerdict::DeferRedo)
        && !host_admission_allows_execution(TaskVerdict::Quarantine)
        && host_admission_allows_execution(TaskVerdict::Proceed);
    let ask = finish_task_record(
        acceptance_unit("pate_acceptance_ask", TaskVerdict::AskHitl),
        &TaskAttempt {
            idempotency_key: "pate_acceptance_ask".into(),
            mutating: true,
            observed: true,
        },
        TaskRefs::default(),
    );
    let ask_held = ask.is_ok_and(|row| {
        row.spine.execution_attempts == 0 && !row.spine.observed && row.spine.spend == "released"
    });
    let task_id = "pate_acceptance_effect";
    let first = finish_task_record(
        acceptance_unit(task_id, TaskVerdict::Proceed),
        &TaskAttempt {
            idempotency_key: task_id.into(),
            mutating: true,
            observed: true,
        },
        TaskRefs {
            receipt_id: Some(format!("receipt:{task_id}")),
            trace_id: Some(format!("trace:{task_id}")),
            ..TaskRefs::default()
        },
    );
    let (one_effect, no_retry) = match first {
        Ok(row) => {
            let again = finish_task_record(
                row.clone(),
                &TaskAttempt {
                    idempotency_key: task_id.into(),
                    mutating: true,
                    observed: true,
                },
                TaskRefs::default(),
            );
            let one = row.spine.execution_attempts == 1
                && row.spine.spend == "committed"
                && row.spine.observed
                && row.spine.receipt_id.as_deref() == Some("receipt:pate_acceptance_effect")
                && row.spine.trace_id.as_deref() == Some("trace:pate_acceptance_effect");
            (one, again.err() == Some("one_execution_attempt"))
        }
        Err(_) => (false, false),
    };
    let provider_denied =
        crate::substrate::egress_policy::assert_direct_provider_egress_denied("api.openai.com")
            .is_err();
    let stale_refused = !generation_is_live("1", 2)
        && continue_after_cease("1", Some(2)) == ContinueAfterCease::DeniedStaleGeneration
        && continue_after_cease("2", Some(2)) == ContinueAfterCease::NotDenied;
    let fixture = "Bearer abcdefghijklmnop sk-live-secret -----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----";
    let redacted = redact_normal_log(fixture);
    let secrets_stripped = !redacted.contains("abcdefghijklmnop")
        && !redacted.contains("sk-live-secret")
        && !redacted.contains("\nabc\n");
    vec![
        check(
            "fail_closed_adapter",
            !adapter_forwards(),
            "holds",
            "ext-auth forward stays false, including after PATE Proceed. The adapter does not mint Proceed.",
        ),
        check(
            "mcp_discovery_does_not_admit",
            !mcp_discovery_admits_effect(),
            "catalog",
            "The MCP tool catalog does not admit an effect. A remote discovery call was not made.",
        ),
        check(
            "mutation_before_proceed",
            mutation_refused,
            "host",
            "Ask, defer, quarantine, and block do not execute. A live target was not contacted.",
        ),
        check(
            "hitl",
            ask_held,
            "host",
            "An Ask closes unobserved with no execution attempt. Target invocation was not counted on a live gateway.",
        ),
        check(
            "one_mutation_task_spend_trace",
            one_effect,
            "in_process",
            "One Proceed commits one attempt, one spend, one receipt, and one trace id. An external target was not called.",
        ),
        check(
            "no_non_idempotent_retry",
            no_retry,
            "in_process",
            "A second observed close of the same task is refused. A gateway retry was not sent.",
        ),
        check(
            "a2a",
            false,
            "not_run",
            "A2A discovery, authentication, stream, cancellation, and grant were not run against a supervised gateway.",
        ),
        check(
            "egress_deny",
            false,
            if provider_denied { "provider_denied" } else { "not_held" },
            "Direct LLM provider hosts are denied. Unregistered egress through a supervised gateway was not proven.",
        ),
        check(
            "cease",
            stale_refused,
            "host",
            "A ceased generation is not live, and continue on that generation is denied. Stale gateway traffic was not sent.",
        ),
        check(
            "secret_redaction",
            false,
            if secrets_stripped { "fixture" } else { "not_held" },
            "Bearer tokens, tool secrets, and PEM private keys are removed from a fixture. Prompt text and live process logs were not proven absent.",
        ),
    ]
}

pub fn acceptance() -> Value {
    let reference = pinned_reference();
    let digest_pinned = pinned_digest_verified(reference);
    let configured = std::env::var("AGENTGATEWAY_IMAGE").unwrap_or_default();
    let configured_matches = !configured.is_empty() && configured == reference;
    let ready = process_ready();
    let mut checks = vec![
        check(
            "version_and_digest",
            false,
            if digest_pinned { "pinned" } else { "absent" },
            "The registry index digest is pinned. The process has not been installed from it.",
        ),
        check(
            "supervised_process",
            false,
            "absent",
            "No supervised process is running.",
        ),
        check(
            "dead_process_not_ready",
            false,
            "holds",
            "ready stays false while the process is absent. A live kill was not performed.",
        ),
    ];
    checks.extend(connector_side_checks());
    let passed = checks.iter().all(|row| row["passed"] == true);
    json!({
        "schema": "connector.agentgateway_acceptance.v1",
        "passed": passed,
        "status": "TARGET",
        "installed": false,
        "ready": ready,
        "seven_backend": false,
        "pinned_reference": reference,
        "configured_image_matches_pin": configured_matches,
        "checks": checks,
        "honesty": "Connector-side proofs run in this report. The supervised process, live kill, A2A, unregistered egress, secret logs, and operator journey have not passed. This row is not one of the seven backends."
    })
}

pub fn status() -> Value {
    let acceptance = acceptance();
    json!({
        "schema": "connector.agentgateway_status.v1",
        "installed": false,
        "ready": false,
        "status": "TARGET",
        "seven_backend": false,
        "production_eligible": false,
        "inventory_complete": true,
        "pinned_reference": acceptance["pinned_reference"],
        "acceptance_passed": false,
        "honesty": "The HTTP effect inventory is mediated. A registry digest is pinned. agentgateway is not installed. This row is not one of the seven backends. Forwarding stays denied.",
    })
}

pub async fn get_status() -> Json<Value> {
    Json(status())
}

#[derive(Debug, Deserialize)]
pub struct ExtAuthBody {
    #[serde(default)]
    pub pate_task_id: Option<String>,
}

/// POST /api/v1/runtime/agentgateway/ext-auth — deny forwarding.
pub async fn post_ext_auth(
    State(state): State<SharedState>,
    Json(body): Json<ExtAuthBody>,
) -> Json<Value> {
    Json(ext_auth(state.as_ref(), body.pate_task_id.as_deref()))
}

pub fn ext_auth(state: &PlatformState, task_id: Option<&str>) -> Value {
    let Some(task_id) = task_id.map(str::trim).filter(|id| !id.is_empty()) else {
        return json!({
            "allow": false,
            "forward": adapter_forwards(),
            "installed": false,
            "reason": "pate_task_required",
        });
    };
    let record = state.engine_store.lock().ok().and_then(|store| {
        store
            .folder_get(crate::substrate::pate::ATU_FOLDER, task_id)
            .ok()
            .flatten()
    });
    let Some(record) = record else {
        return json!({
            "allow": false,
            "forward": adapter_forwards(),
            "installed": false,
            "reason": "pate_task_absent",
        });
    };
    let verdict = record.get("verdict").and_then(|value| value.as_str()).unwrap_or("absent");
    let observed = record
        .pointer("/spine/observed")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if verdict != "Proceed" || observed {
        return json!({
            "allow": false,
            "forward": adapter_forwards(),
            "installed": false,
            "reason": "pate_not_open_proceed",
            "verdict": verdict,
        });
    }
    json!({
        "allow": false,
        "forward": adapter_forwards(),
        "installed": false,
        "pate": "proceed",
        "reason": "agentgateway_not_installed",
        "honesty": "PATE Proceed does not let agentgateway forward. The process is not installed.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_is_not_a_seventh_backend() {
        let body = status();
        assert_eq!(body["installed"], false);
        assert_eq!(body["ready"], false);
        assert_eq!(body["seven_backend"], false);
        assert_eq!(body["inventory_complete"], true);
        assert_eq!(body["acceptance_passed"], false);
        let reference = body["pinned_reference"].as_str().unwrap_or("");
        assert!(pinned_digest_verified(reference));
        assert!(reference.ends_with(
            "@sha256:9d3e6044ddcdc0878b1787f77bd401252b95e22684203fb5e874c4c42d2ed90c"
        ));
    }

    #[test]
    fn acceptance_suite_stays_unpassed_after_the_pin() {
        let body = acceptance();
        assert_eq!(body["passed"], false);
        assert_eq!(body["installed"], false);
        assert_eq!(body["ready"], false);
        assert_eq!(body["status"], "TARGET");
        let checks = body["checks"].as_array().expect("checks");
        let row = |id: &str| checks.iter().find(|row| row["id"] == id).expect(id);
        assert_eq!(row("version_and_digest")["status"], "pinned");
        assert_eq!(row("version_and_digest")["passed"], false);
        assert_eq!(row("supervised_process")["passed"], false);
        assert_eq!(row("dead_process_not_ready")["passed"], false);
        assert_eq!(row("a2a")["passed"], false);
        assert_eq!(row("egress_deny")["passed"], false);
        assert_eq!(row("secret_redaction")["passed"], false);
        assert_eq!(row("fail_closed_adapter")["passed"], true);
        assert_eq!(row("mcp_discovery_does_not_admit")["passed"], true);
        assert_eq!(row("mutation_before_proceed")["passed"], true);
        assert_eq!(row("hitl")["passed"], true);
        assert_eq!(row("one_mutation_task_spend_trace")["passed"], true);
        assert_eq!(row("no_non_idempotent_retry")["passed"], true);
        assert_eq!(row("cease")["passed"], true);
        let fixture = "Bearer abcdefghijklmnop sk-live-secret -----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----";
        let redacted = redact_normal_log(fixture);
        assert!(!redacted.contains("abcdefghijklmnop"));
        assert!(!redacted.contains("sk-live-secret"));
        assert!(!redacted.contains("\nabc\n"));
        assert!(!adapter_forwards());
        assert!(!pinned_digest_verified("cr.agentgateway.dev/agentgateway:v1.6.0"));
        assert!(!process_ready());
        assert!(!body.to_string().contains("CONNECTOR READY"));
    }
}
