//! Route shell for mutating HTTP methods whose handler does not already open a PATE task.
//! A handler that already admits is left alone. A declared non-effect is left alone.
//! Ask stays open and the handler does not run. A 2xx closes the shell task observed.

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

use crate::state::SharedState;

const SHELL_PATHS: &[&str] = &[
    "/aacr/mint",
    "/aacr/verify",
    "/aapi/budgets",
    "/aapi/budgets/commit",
    "/aapi/budgets/consume",
    "/aapi/budgets/release",
    "/aapi/budgets/reserve",
    "/aapi/capabilities/:token_id",
    "/aapi/capabilities/delegate",
    "/aapi/capabilities/issue",
    "/aapi/compensate",
    "/aapi/compliance",
    "/aapi/interactions",
    "/aapi/inverse/register",
    "/aapi/policies",
    "/aapi/policies/:id",
    "/aapi/policies/evaluate",
    "/aapi/policies/financial",
    "/aapi/policies/hipaa",
    "/aapi/tools/authorize",
    "/aapi/tools/register",
    "/adaptive/agents/:pid/config",
    "/agents/:agent_id/contract/from-template",
    "/agents/:agent_id/contract/simple",
    "/agents/:pid/aliases",
    "/agents/:pid/audit/receipts/verify",
    "/agents/:pid/character",
    "/agents/:pid/clone",
    "/agents/:pid/completions",
    "/agents/:pid/contract",
    "/agents/:pid/data",
    "/agents/:pid/directives",
    "/agents/:pid/episodes",
    "/agents/:pid/episodes/:episode_id/close",
    "/agents/:pid/kill-switch",
    "/agents/:pid/memory/search",
    "/agents/:pid/policy/check",
    "/agents/:pid/situation",
    "/agents/:pid/sources/:cid/active",
    "/agents/:pid/sources/:cid/eligible",
    "/agents/:pid/workbench/sessions/:sid/cancel-orders",
    "/agents/:pid/workbench/sessions/:sid/demo",
    "/agents/:pid/workbench/sessions/:sid/hitl-deny",
    "/agents/:pid/workbench/sessions/:sid/hitl-resume",
    "/agents/:pid/workbench/sessions/:sid/turn",
    "/aipsprt/verify",
    "/api/v1/devguard/admit",
    "/api/v1/devguard/connect",
    "/api/v1/devguard/exec/check",
    "/api/v1/devguard/fs/check",
    "/api/v1/devguard/fs/guard",
    "/api/v1/devguard/github/checks/evaluate",
    "/api/v1/devguard/policy/check",
    "/api/v1/devguard/policy/history",
    "/api/v1/devguard/policy/load",
    "/api/v1/devguard/policy/rollback",
    "/api/v1/devguard/policy/validate",
    "/api/v1/devguard/repos/:repo_id/agents",
    "/api/v1/devguard/repos/:repo_id/roles",
    "/api/v1/devguard/secrets/scan",
    "/api/v1/plugins/devguard/local-profile",
    "/assets/containers",
    "/auth/signup",
    "/billing/record-usage",
    "/billing/stripe/webhook",
    "/books/close/:session_id",
    "/books/reconcile",
    "/certs/:key",
    "/cls/compile",
    "/cls/playground",
    "/cnp/messages",
    "/cognitive/cycle",
    "/cognitive/judgment",
    "/cognitive/observe",
    "/cognitive/plan",
    "/cognitive/reasoning/conclude",
    "/cognitive/reasoning/step",
    "/compliance/baa/accept",
    "/compliance/dpa/accept",
    "/compliance/eu-ai-act/risk-classification",
    "/compliance/eu_ai_act/log_incident",
    "/compliance/eu_ai_act/risk_classification",
    "/compliance/evidence-pack",
    "/compliance/findings/:id",
    "/compliance/gdpr/forget/:pid",
    "/compliance/report",
    "/context/:pid/compress",
    "/context/:pid/evict",
    "/context/:pid/restore/:cid",
    "/context/:pid/resume",
    "/context/:pid/snapshot",
    "/debug/agents/:agent_pid/bind-tool",
    "/debug/agents/:agent_pid/role",
    "/deploy",
    "/deploy/rollback",
    "/deploy/upgrade",
    "/deploy/upgrade/promote",
    "/deploy/validate",
    "/disputes/judgment",
    "/disputes/regulations-report",
    "/disputes/risk-check",
    "/disputes/scan-gdpr-art22",
    "/economy/budget-gate",
    "/economy/deposit",
    "/economy/escrow/:id/dispute",
    "/economy/escrow/:id/release",
    "/economy/escrow/:id/slash",
    "/economy/escrow/lock",
    "/economy/negotiate/:id/accept",
    "/economy/negotiate/:id/counter",
    "/economy/negotiate/:id/reject",
    "/economy/negotiate/propose",
    "/economy/quote",
    "/economy/reputation/feedback",
    "/economy/reputation/slash/:pid",
    "/economy/reputation/stake",
    "/experiments/:experiment_id/compare",
    "/firewall/inspect",
    "/grounding/claims/ground-and-verify",
    "/grounding/claims/verify",
    "/grounding/claims/verify-batch",
    "/grounding/ground-output",
    "/grounding/lookup",
    "/grounding/tables",
    "/history/replay",
    "/hub/workflows/publish",
    "/import/playground-session",
    "/infra/cells/route",
    "/infra/consensus/propose",
    "/infra/consensus/validators",
    "/infra/consensus/vote",
    "/infra/context/evict",
    "/infra/context/register",
    "/infra/context/restore",
    "/infra/context/snapshot",
    "/infra/orchestrator/sagas/:id/rollback",
    "/infra/orchestrator/submit",
    "/infra/quota/set",
    "/infra/reputation/feedback",
    "/infra/reputation/slash",
    "/infra/reputation/stake",
    "/infra/router/metrics",
    "/infra/router/route",
    "/infra/tc/issue",
    "/infra/tc/reduce",
    "/infra/tc/revoke",
    "/infra/tc/rotate",
    "/infra/vault/redact",
    "/infra/vault/resolve",
    "/infra/vault/secrets",
    "/insights/apply-fix/:pid/:fix_id",
    "/intelligence/apply",
    "/kernel/aios/operate",
    "/kernel/aios/syscall",
    "/knowledge-graph/transfer",
    "/license/activate",
    "/marketplace/contracts",
    "/marketplace/discover",
    "/marketplace/index/:pid/health",
    "/marketplace/modules/:module_id",
    "/marketplace/modules/install",
    "/marketplace/tools/register",
    "/memory/access/revoke",
    "/memory/enrich/:agent_pid",
    "/memory/eviction-policy",
    "/memory/knowledge/query",
    "/memory/knowledge/query2",
    "/memory/packets/:cid/seal",
    "/memory/region/configure",
    "/monitor/native/charts/pin",
    "/n4/cognize",
    "/n4/hello",
    "/n4/qualify",
    "/native/extensions/:id/actions",
    "/notebook/execute",
    "/notifications/:id/acknowledge",
    "/notifications/dedup/:key",
    "/notifications/oncall-schedules",
    "/notifications/schedule",
    "/notifications/schedule-dedup",
    "/notifications/templates/render",
    "/orchestrator/dag",
    "/orchestrator/dag/:id/advance",
    "/orchestrator/dag/:id/retry",
    "/orchestrator/sagas/:id/rollback",
    "/payment/checkout",
    "/payment/portal",
    "/payment/webhook",
    "/pipeline/:pipeline_id/replay-from-step/:step_n",
    "/pipeline/pre-deploy-diff",
    "/playground/execute",
    "/playground/session",
    "/plugins/cpkg/bundle/export",
    "/plugins/cpkg/bundle/import",
    "/plugins/cpkg/install",
    "/plugins/cpkg/preflight",
    "/product/tasks",
    "/prompts/:id/lint",
    "/prompts/:id/render",
    "/proof/certificate-sign",
    "/proof/certificate-verify",
    "/proof/scitt/verify",
    "/proof/vc/:agent_pid",
    "/protocol/conp/estop",
    "/protocol/conp/message",
    "/protocol/conp/safety/estop",
    "/protocols/a2a/tasks/:task_id/cancel",
    "/protocols/acp/messages",
    "/protocols/anp/dids",
    "/protocols/ap2/mandates",
    "/qpr/intent",
    "/run-example",
    "/runtime/continuity/evaluate",
    "/runtime/delegate",
    "/runtime/nsfs/:pid/ensure",
    "/safety/claims/verify",
    "/safety/grounding/add",
    "/safety/grounding/lookup",
    "/safety/grounding/verify",
    "/secrets/:id",
    "/secrets/:id/rotate",
    "/secrets/handle",
    "/secrets/resolve",
    "/secrets/store",
    "/system/verify/full",
    "/telemetry/playground",
    "/tools/bindings/scoped",
    "/tools/mcp/bridges/:bridge_id",
    "/tools/mcp/invoke",
    "/tools/mcp/invoke-scoped",
    "/v1/messages/count_tokens",
    "/webhooks/:id/test",
    "/webhooks/templates/render",
    "/workflows/catalog/sync",
];


fn strip_prefix(path: &str) -> &str {
    path.strip_prefix("/api/v1").unwrap_or(path)
}

fn segments_match(path: &str, pattern: &str) -> bool {
    let path = strip_prefix(path);
    let pattern = strip_prefix(pattern);
    let ps: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let ts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    if ps.len() != ts.len() {
        return false;
    }
    ps.iter().zip(ts).all(|(seg, tok)| tok.starts_with(':') || *seg == tok)
}

fn on_shell_list(path: &str) -> bool {
    SHELL_PATHS.iter().any(|pat| segments_match(path, pat))
}

fn declared_non_effect(path: &str) -> bool {
    let p = strip_prefix(path);
    // The lab banner flips this node's own posture. It is not an agent tool.
    if p.ends_with("/runtime/enable-hardening") {
        return true;
    }
    p.contains("/product/tasks")
        || p.contains("/character")
        || p.contains("/directives")
        || p.contains("/aliases")
        || p.contains("/situation")
        || p.contains("/eligible")
        || p.contains("/active")
        || p.contains("/tools/mcp/bridges/")
        || (p.contains("/webhooks/") && p.ends_with("/test"))
}

fn auth_bootstrap(path: &str) -> bool {
    const SKIP: &[&str] = &[
        "/auth/signup",
        "/auth/login",
        "/auth/token",
        "/auth/refresh",
        "/auth/logout",
        "/auth/sso",
        "/auth/sso/login",
        "/auth/sso/callback",
        "/auth/totp/verify",
        "/api/v1/auth/token",
    ];
    SKIP.iter().any(|pat| segments_match(path, pat))
}

/// These handlers, or the function they call, already open one PATE task.
/// A shell task here would block registration and chat, or spend twice.
fn already_mediated(path: &str) -> bool {
    const SKIP: &[&str] = &[
        "/tools/mcp/invoke",
        "/tools/mcp/invoke-scoped",
        "/agents/:pid/completions",
        "/agents/:pid/workbench/sessions/:sid/turn",
        "/agents/:pid/kill-switch",
        "/protocol/conp/message",
        "/cnp/messages",
        "/intelligence/apply",
        "/api/v2/agents",
        "/agents",
    ];
    SKIP.iter().any(|pat| segments_match(path, pat))
}

fn subject_for(path: &str) -> String {
    let p = strip_prefix(path);
    let ps: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    if let Some(i) = ps.iter().position(|s| *s == "agents") {
        if let Some(pid) = ps.get(i + 1) {
            if !pid.is_empty() && !pid.starts_with(':') {
                return (*pid).to_string();
            }
        }
    }
    for w in ps.windows(2) {
        if w[0] == "agents" {
            return w[1].to_string();
        }
    }
    "node".to_string()
}

pub fn shell_applies(method: &Method, path: &str) -> bool {
    should_shell(method, path, false)
}

fn should_shell(method: &Method, path: &str, v2: bool) -> bool {
    if !matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        return false;
    }
    if declared_non_effect(path) || auth_bootstrap(path) || already_mediated(path) {
        return false;
    }
    if v2 {
        return true;
    }
    on_shell_list(path)
}

async fn mediate(
    state: SharedState,
    req: Request<Body>,
    next: Next,
    v2: bool,
) -> axum::response::Response {
    if !should_shell(req.method(), req.uri().path(), v2) {
        return next.run(req).await;
    }
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let subject = subject_for(&path);
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &subject,
        "lifecycle",
        "route_mutate",
        &json!({"method": method, "path": path}),
    ) {
        Ok(atu) => atu,
        Err(body) => {
            return (StatusCode::OK, Json(body)).into_response();
        }
    };
    let mut open = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let resp = next.run(req).await;
    open.finish_observed(resp.status().is_success());
    resp
}

pub async fn middleware(
    State(state): State<SharedState>,
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    mediate(state, req, next, false).await
}

pub async fn v2_middleware(
    State(state): State<SharedState>,
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    mediate(state, req, next, true).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_skips_calls_that_already_admit() {
        assert!(!shell_applies(&Method::POST, "/api/v1/agents"));
        assert!(!shell_applies(&Method::POST, "/v1/chat/completions"));
        assert!(!shell_applies(&Method::POST, "/api/v1/agents/pid/completions"));
        assert!(!shell_applies(
            &Method::POST,
            "/api/v1/agents/pid/workbench/sessions/sid/turn"
        ));
        assert!(!shell_applies(&Method::POST, "/api/v1/product/tasks"));
        assert!(!shell_applies(&Method::POST, "/api/v1/auth/login"));
        assert!(!shell_applies(&Method::GET, "/api/v1/proof/certificate-sign"));
        assert!(!shell_applies(
            &Method::POST,
            "/api/v1/runtime/enable-hardening"
        ));
    }

    #[test]
    fn shell_covers_an_ungated_write() {
        assert!(shell_applies(&Method::POST, "/api/v1/proof/certificate-sign"));
        assert!(should_shell(&Method::POST, "/api/v2/agents/pid/start", true));
        assert!(!should_shell(&Method::POST, "/api/v2/agents", true));
        assert!(!should_shell(&Method::POST, "/agents", true));
    }
}
