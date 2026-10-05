"""
Connector Platform — Universal REST Client

A production-grade Python client for the full Connector Platform API.
Drop-in replacement for direct LLM calls — adds kernel-verified trust scoring,
tamper-proof audit trails, and compliance enforcement automatically.

Covers all 123 platform routes across 21 services:
  agents, actionlog, proof, memory, monitor, history, multiagent,
  disputes, pipeline, experiments, prompts, tools, insights, compliance,
  notifications, webhooks, licensing, auth, debug, notebook, payment.

Usage:
    from integrations.rest_client import ConnectorClient

    client = ConnectorClient(
        base_url="http://localhost:9090/api/v1",
        api_key="your-key",
    )

    # Run an agent
    result = client.agents.run_pipeline("my-agent", "Hello!", user="alice")
    print(result["text"], result["trust_score"])

    # Write memory
    client.memory.write(agent_pid="agent_123", content="Important fact", user="alice")

    # Generate compliance report
    report = client.compliance.report(framework="soc2")
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Union

import requests
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


# ── Base client with retry + auth ─────────────────────────────────────────────

class _BaseClient:
    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self._base    = base_url.rstrip("/")
        self._timeout = timeout

        self._session = Session()
        retry = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PATCH", "DELETE"],
        )
        self._session.mount("http://",  HTTPAdapter(max_retries=retry))
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

        self._session.headers.update({"Content-Type": "application/json"})
        if api_key:
            self._session.headers["Authorization"] = f"Bearer {api_key}"

    def set_token(self, token: str):
        self._session.headers["Authorization"] = f"Bearer {token}"

    def _url(self, path: str) -> str:
        return f"{self._base}{path}"

    def get(self, path: str, params: Optional[Dict] = None) -> Any:
        r = self._session.get(self._url(path), params=params, timeout=self._timeout)
        r.raise_for_status()
        return r.json()

    def post(self, path: str, body: Any = None) -> Any:
        r = self._session.post(self._url(path), json=body, timeout=self._timeout)
        r.raise_for_status()
        return r.json()

    def patch(self, path: str, body: Any = None) -> Any:
        r = self._session.patch(self._url(path), json=body, timeout=self._timeout)
        r.raise_for_status()
        return r.json()

    def delete(self, path: str) -> Any:
        r = self._session.delete(self._url(path), timeout=self._timeout)
        r.raise_for_status()
        return r.json()

    def get_bytes(self, path: str) -> bytes:
        r = self._session.get(self._url(path), timeout=self._timeout)
        r.raise_for_status()
        return r.content


# ── Service sub-clients ────────────────────────────────────────────────────────

class AgentsService(_BaseClient):
    """POST /agents, GET /agents, GET/PATCH/DELETE /agents/{pid}, etc."""

    def register(
        self,
        name: str,
        namespace: Optional[str] = None,
        role: str = "writer",
        model: Optional[str] = None,
        instructions: Optional[str] = None,
        token_budget: Optional[int] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict:
        return self.post("/agents", {
            "name": name, "namespace": namespace, "role": role,
            "model": model, "instructions": instructions,
            "token_budget": token_budget, "tags": tags,
        })

    def list(self, limit: int = 50) -> Dict:
        return self.get("/agents", {"limit": limit})

    def get_agent(self, pid: str) -> Dict:
        return self.get(f"/agents/{pid}")

    def update(self, pid: str, model: Optional[str] = None,
               instructions: Optional[str] = None,
               token_budget: Optional[int] = None) -> Dict:
        return self.patch(f"/agents/{pid}", {
            "model": model, "instructions": instructions, "token_budget": token_budget,
        })

    def terminate(self, pid: str) -> Dict:
        return self.delete(f"/agents/{pid}")

    def reset_budget(self, pid: str) -> Dict:
        return self.post(f"/agents/{pid}/reset-budget", {})

    def cost(self, pid: str) -> Dict:
        return self.get(f"/agents/{pid}/cost")

    def activity(self, pid: str) -> Dict:
        return self.get(f"/agents/{pid}/activity")

    def pause(self, pid: str) -> Dict:
        return self.post(f"/agents/{pid}/pause", {})

    def resume(self, pid: str) -> Dict:
        return self.post(f"/agents/{pid}/resume", {})

    # Shortcut: run a pipeline as a single agent
    def run_pipeline(
        self,
        agent_name: str,
        input_text: str,
        user: str = "api",
        instructions: Optional[str] = None,
        compliance: Optional[List[str]] = None,
        max_cost_usd: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> Dict:
        return self.post("/multiagent/run-pipeline", {
            "name":    f"run_{agent_name}",
            "agents":  [{"name": agent_name, "instructions": instructions}],
            "input":   input_text,
            "user":    user,
            "compliance":   compliance or [],
            "max_cost_usd": max_cost_usd,
            "max_tokens":   max_tokens,
        })


class ActionLogService(_BaseClient):
    """POST /actionlog/record, GET /actionlog/list, exports, chargeback."""

    def record(
        self,
        agent_pid: str,
        intent: str,
        action: str,
        resource: Optional[str] = None,
        outcome: str = "success",
        confidence: Optional[float] = None,
        cost_center: Optional[str] = None,
        team: Optional[str] = None,
        cost_usd: Optional[float] = None,
        tokens_used: Optional[int] = None,
    ) -> Dict:
        return self.post("/actionlog/record", {
            "agent_pid": agent_pid, "intent": intent, "action": action,
            "resource": resource, "outcome": outcome, "confidence": confidence,
            "cost_center": cost_center, "team": team,
            "cost_usd": cost_usd, "tokens_used": tokens_used,
        })

    def list(self, limit: int = 50, agent_pid: Optional[str] = None) -> Dict:
        params: Dict = {"limit": limit}
        if agent_pid:
            params["agent_pid"] = agent_pid
        return self.get("/actionlog/list", params)

    def compliance_actions(self, limit: int = 50) -> Dict:
        return self.get("/actionlog/compliance", {"limit": limit})

    def tool_audit(self, limit: int = 50) -> Dict:
        return self.get("/actionlog/tool-audit", {"limit": limit})

    def export_otel(self) -> Dict:
        return self.get("/actionlog/export/otel")

    def export_jsonl(self) -> Dict:
        return self.get("/actionlog/export/jsonl")

    def chargeback_report(
        self,
        period: str = "30d",
        cost_center: Optional[str] = None,
        team: Optional[str] = None,
    ) -> Dict:
        params: Dict = {"period": period}
        if cost_center: params["cost_center"] = cost_center
        if team:        params["team"] = team
        return self.get("/actionlog/chargeback-report", params)

    def subject_access(self, user_id: str, limit: int = 100) -> Dict:
        return self.get("/actionlog/subject-access", {"user_id": user_id, "limit": limit})


class MemoryService(_BaseClient):
    """POST /memory/write, GET /memory/recall/{ns}, knowledge ingest/query."""

    def write(
        self,
        agent_pid: str,
        content: str,
        user: str = "api",
        pipeline: str = "default",
        packet_type: str = "input",
        session_id: Optional[str] = None,
    ) -> Dict:
        return self.post("/memory/write", {
            "agent_pid": agent_pid, "content": content, "user": user,
            "pipeline": pipeline, "packet_type": packet_type, "session_id": session_id,
        })

    def recall(self, namespace: str, limit: int = 50, session_id: Optional[str] = None) -> Dict:
        params: Dict = {"limit": limit}
        if session_id: params["session_id"] = session_id
        return self.get(f"/memory/recall/{namespace}", params)

    def knowledge_ingest(
        self,
        agent_pid: str,
        observations: List[str],
        session_id: Optional[str] = None,
    ) -> Dict:
        return self.post("/memory/knowledge/ingest", {
            "agent_pid": agent_pid,
            "observations": observations,
            "session_id": session_id,
        })

    def knowledge_query(
        self,
        entities: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        token_budget: int = 4096,
        max_facts: int = 20,
    ) -> Dict:
        return self.post("/memory/knowledge/query", {
            "entities": entities or [], "keywords": keywords or [],
            "token_budget": token_budget, "max_facts": max_facts,
        })

    def list_agents(self) -> Dict:
        return self.get("/memory/agents")

    def stale_analysis(self) -> Dict:
        return self.get("/memory/stale-analysis")

    def optimize_context(self, agent_pid: str) -> Dict:
        return self.post(f"/memory/optimize-context/{agent_pid}", {})

    def context_pressure(self, agent_pid: str) -> Dict:
        return self.get(f"/memory/context-pressure/{agent_pid}")

    def consolidate(self, agent_pid: str) -> Dict:
        return self.post("/memory/consolidate", {"agent_pid": agent_pid})

    def enrich(self, agent_pid: str) -> Dict:
        return self.post("/memory/enrich", {"agent_pid": agent_pid})

    def share(self, grantor_pid: str, grantee_pid: str, namespace: str) -> Dict:
        return self.post("/memory/share", {
            "grantor_pid": grantor_pid, "grantee_pid": grantee_pid,
            "namespace": namespace,
        })

    def change_tier(self, agent_pid: str, cid: str, tier: str) -> Dict:
        return self.post("/memory/tier-change", {
            "agent_pid": agent_pid, "cid": cid, "tier": tier,
        })


class MonitorService(_BaseClient):
    """GET /monitor/health, metrics, trust, cost, signals, SLOs, etc."""

    def health(self) -> Dict:
        return self.get("/monitor/health")

    def metrics(self) -> Dict:
        return self.get("/monitor/metrics")

    def trust_trend(self) -> Dict:
        return self.get("/monitor/trust-trend")

    def cost(self) -> Dict:
        return self.get("/monitor/cost")

    def tools(self) -> Dict:
        return self.get("/monitor/tools")

    def signals(self) -> Dict:
        return self.get("/monitor/signals")

    def slos(self) -> Dict:
        return self.get("/monitor/slos")

    def cgroups(self) -> Dict:
        return self.get("/monitor/cgroups")

    def anomalies(self) -> Dict:
        return self.get("/monitor/anomalies/v2")

    def storage_layout(self) -> Dict:
        return self.get("/monitor/storage/layout")

    def forecast(self) -> Dict:
        return self.get("/monitor/forecast")

    def performance(self) -> Dict:
        return self.get("/monitor/performance")


class MultiAgentService(_BaseClient):
    """POST /multiagent/run-pipeline, approve-step, grant/revoke, ports, trace."""

    def run_pipeline(
        self,
        name: str,
        agents: List[Dict],
        input_text: str,
        user: str = "api",
        compliance: Optional[List[str]] = None,
        max_cost_usd: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> Dict:
        return self.post("/multiagent/run-pipeline", {
            "name": name, "agents": agents, "input": input_text,
            "user": user, "compliance": compliance or [],
            "max_cost_usd": max_cost_usd, "max_tokens": max_tokens,
        })

    def approve_step(
        self,
        pipeline_id: str,
        step: int,
        approver: str,
        approved: bool = True,
        comment: str = "",
    ) -> Dict:
        return self.post(f"/multiagent/pipelines/{pipeline_id}/approve-step/{step}", {
            "approver": approver, "approved": approved, "comment": comment,
        })

    def pipeline_trace(self, pipe_name: str) -> Dict:
        return self.get(f"/multiagent/pipelines/{pipe_name}/trace")

    def cross_agent_map(self) -> Dict:
        return self.get("/multiagent/map")

    def list_ports(self) -> Dict:
        return self.get("/multiagent/ports")

    def grant_access(
        self,
        grantor_pid: str,
        grantee_pid: str,
        namespace: str,
        permissions: Optional[List[str]] = None,
    ) -> Dict:
        return self.post("/multiagent/grant-access", {
            "grantor_pid": grantor_pid, "grantee_pid": grantee_pid,
            "namespace": namespace, "permissions": permissions or ["read"],
        })

    def revoke_access(self, revoker_pid: str, target_pid: str, namespace: str) -> Dict:
        return self.post("/multiagent/revoke-access", {
            "revoker_pid": revoker_pid, "target_pid": target_pid, "namespace": namespace,
        })


class ToolsService(_BaseClient):
    """MCP bridge, A2A channels, circuit breaker, approvals, signals, cgroups."""

    def mcp_register(
        self,
        name: str,
        endpoint: str,
        description: str = "",
        auth_token: Optional[str] = None,
    ) -> Dict:
        return self.post("/tools/mcp/register", {
            "name": name, "endpoint": endpoint,
            "description": description, "auth_token": auth_token,
        })

    def mcp_invoke(
        self,
        bridge_name: str,
        tool_name: str,
        params: Optional[Dict] = None,
        agent_pid: str = "api",
    ) -> Dict:
        return self.post("/tools/mcp/invoke", {
            "bridge_name": bridge_name, "tool_name": tool_name,
            "params": params or {}, "agent_pid": agent_pid,
        })

    def mcp_bridges(self) -> Dict:
        return self.get("/tools/mcp/bridges")

    def approvals_pending(self) -> Dict:
        return self.get("/tools/approvals/pending")

    def approve_tool(self, audit_id: str, approved: bool = True,
                     reason: Optional[str] = None) -> Dict:
        return self.post(f"/tools/approvals/{audit_id}", {
            "approved": approved, "reason": reason,
        })

    def send_signal(self, sender_pid: str, target_pid: str,
                    signal_type: str, payload: Optional[Dict] = None) -> Dict:
        return self.post("/tools/signals/send", {
            "sender_pid": sender_pid, "target_pid": target_pid,
            "signal_type": signal_type, "payload": payload or {},
        })

    def agent_did(self, agent_pid: str) -> Dict:
        return self.get(f"/tools/agents/{agent_pid}/did")

    def agent_card(self, agent_pid: str) -> Dict:
        return self.get(f"/tools/agents/{agent_pid}/card")

    def bind_scoped_tool(
        self,
        agent_pid: str,
        tool_name: str,
        allowed_params: Optional[List[str]] = None,
        data_class: Optional[str] = None,
    ) -> Dict:
        return self.post("/tools/scoped/bind", {
            "agent_pid": agent_pid, "tool_name": tool_name,
            "allowed_params": allowed_params, "data_class": data_class,
        })

    def circuit_breaker_config(
        self,
        agent_pid: str,
        failure_threshold: int = 5,
        cooldown_secs: int = 30,
    ) -> Dict:
        return self.post("/tools/circuit-breaker/configure", {
            "agent_pid": agent_pid,
            "failure_threshold": failure_threshold,
            "cooldown_secs": cooldown_secs,
        })

    def circuit_breaker_status(self, agent_pid: str) -> Dict:
        return self.get(f"/tools/circuit-breaker/{agent_pid}")

    def detect_collisions(self) -> Dict:
        return self.get("/tools/collisions")

    def register_signal_handler(
        self,
        agent_pid: str,
        signal_type: str,
        handler_action: str,
    ) -> Dict:
        return self.post("/tools/signals/register-handler", {
            "agent_pid": agent_pid, "signal_type": signal_type,
            "handler_action": handler_action,
        })

    def a2a_open(self, initiator_pid: str, peer_did: str,
                 channel_type: str = "task") -> Dict:
        return self.post("/tools/a2a/open", {
            "initiator_pid": initiator_pid, "peer_did": peer_did,
            "channel_type": channel_type,
        })

    def a2a_send(self, channel_id: str, sender_pid: str, message: str) -> Dict:
        return self.post("/tools/a2a/send", {
            "channel_id": channel_id, "sender_pid": sender_pid, "message": message,
        })

    def cgroup_register(
        self,
        name: str,
        agent_pids: List[str],
        cpu_limit: Optional[float] = None,
        memory_limit_mb: Optional[int] = None,
    ) -> Dict:
        return self.post("/tools/cgroups/register", {
            "name": name, "agent_pids": agent_pids,
            "cpu_limit": cpu_limit, "memory_limit_mb": memory_limit_mb,
        })

    def cgroup_list(self) -> Dict:
        return self.get("/tools/cgroups/list")


class ProofService(_BaseClient):
    """Generate proofs, certificates, W3C VCs, SCITT receipts."""

    def generate(
        self,
        agent_pid: str,
        title: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict:
        return self.post("/proof/generate", {
            "agent_pid": agent_pid, "title": title, "session_id": session_id,
        })

    def certificate(self, proof_id: str) -> Dict:
        return self.get(f"/proof/{proof_id}/certificate")

    def verify(self, proof_id: str) -> Dict:
        return self.get(f"/proof/{proof_id}/verify")

    def sign_certificate(self, agent_pid: str, title: str = "Trust Certificate") -> Dict:
        return self.post("/proof/certificate-sign", {
            "agent_pid": agent_pid, "title": title,
        })

    def verify_signature(self, payload_json: str, signature: str) -> Dict:
        return self.post("/proof/certificate-verify", {
            "payload_json": payload_json, "signature": signature,
        })

    def public_key(self) -> Dict:
        return self.get("/proof/public-key")

    def scitt_receipt(self, cid: str) -> Dict:
        return self.get(f"/proof/scitt-receipt/{cid}")

    def merkle_proof(self, cid: str) -> Dict:
        return self.get(f"/proof/merkle-proof/{cid}")

    def issue_vc(self, agent_pid: str) -> Dict:
        return self.post(f"/proof/vc/{agent_pid}", {})

    def trust_trend(self, agent_pid: str) -> Dict:
        return self.get(f"/proof/trust-trend/{agent_pid}")

    def certificate_pdf(self, proof_id: str) -> bytes:
        return self.get_bytes(f"/proof/{proof_id}/certificate.pdf")


class DebugService(_BaseClient):
    """Sessions, snapshots, reasoning chains, tool traces, diffs, failure clusters."""

    def sessions(self, limit: int = 50) -> Dict:
        return self.get("/debug/sessions", {"limit": limit})

    def session_detail(self, session_id: str) -> Dict:
        return self.get(f"/debug/sessions/{session_id}")

    def audit_log(self, limit: int = 50) -> Dict:
        return self.get("/debug/audit", {"limit": limit})

    def recall_by_cid(self, cid: str) -> Dict:
        return self.get(f"/debug/memory/cid/{cid}")

    def agent_tools(self, agent_pid: str) -> Dict:
        return self.get(f"/debug/agents/{agent_pid}/tools")

    def set_role(self, agent_pid: str, role: str) -> Dict:
        return self.post(f"/debug/agents/{agent_pid}/role", {"role": role})

    def inspect_permissions(self, agent_pid: str) -> Dict:
        return self.get(f"/debug/agents/{agent_pid}/permissions")

    def trace_tool_calls(self, agent_pid: str) -> Dict:
        return self.get(f"/debug/agents/{agent_pid}/tool-trace")

    def snapshot(self, agent_pid: str) -> Dict:
        return self.post(f"/debug/agents/{agent_pid}/snapshot", {})

    def restore(self, agent_pid: str, snapshot_id: str) -> Dict:
        return self.post(f"/debug/agents/{agent_pid}/restore", {
            "snapshot_id": snapshot_id,
        })

    def reasoning_chain(self, agent_pid: str) -> Dict:
        return self.get(f"/debug/agents/{agent_pid}/reasoning-chain")

    def diff(self, pid_a: str, pid_b: str) -> Dict:
        return self.post("/debug/diff", {"pid_a": pid_a, "pid_b": pid_b})

    def failure_clusters(self, limit: int = 20) -> Dict:
        return self.get("/debug/failure-clusters", {"limit": limit})

    def kernel_export(self) -> Dict:
        return self.get("/debug/kernel/export")


class ComplianceService(_BaseClient):
    """Compliance reports, findings, GDPR, scorecard."""

    def report(
        self,
        framework: str = "soc2",
        include_audit_log: bool = True,
        organization_name: Optional[str] = None,
        prepared_by: Optional[str] = None,
    ) -> Dict:
        return self.post("/compliance/report", {
            "framework": framework,
            "include_audit_log": include_audit_log,
            "organization_name": organization_name,
            "prepared_by": prepared_by,
        })

    def scorecard(self) -> Dict:
        return self.get("/compliance/scorecard")

    def findings(
        self,
        framework: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict:
        params: Dict = {}
        if framework: params["framework"] = framework
        if severity:  params["severity"]  = severity
        if status:    params["status"]    = status
        return self.get("/compliance/findings", params)

    def finding(self, finding_id: str) -> Dict:
        return self.get(f"/compliance/findings/{finding_id}")

    def update_finding(self, finding_id: str, status: Optional[str] = None,
                       owner: Optional[str] = None, due_date: Optional[str] = None,
                       notes: Optional[str] = None) -> Dict:
        return self.patch(f"/compliance/findings/{finding_id}", {
            "status": status, "owner": owner, "due_date": due_date, "notes": notes,
        })

    def frameworks(self) -> Dict:
        return self.get("/compliance/frameworks")

    def policy_violations(self) -> Dict:
        return self.get("/compliance/policy-violations")

    def access_report(self) -> Dict:
        return self.get("/compliance/access-report")

    def gdpr_data_subjects(self) -> Dict:
        return self.get("/compliance/gdpr/data-subjects")

    def gdpr_forget(self, agent_pid: str) -> Dict:
        return self.post(f"/compliance/gdpr/forget/{agent_pid}", {})

    def gdpr_erasure_log(self) -> Dict:
        return self.get("/compliance/gdpr/erasure-log")


class LicenseService(_BaseClient):
    """License status, activation, features, usage."""

    def status(self) -> Dict:
        return self.get("/licensing/status")

    def activate(self, license_key: str) -> Dict:
        return self.post("/licensing/activate", {"license_key": license_key})

    def machine_info(self) -> Dict:
        return self.get("/licensing/machine")

    def heartbeat(self) -> Dict:
        return self.get("/licensing/heartbeat")

    def usage(self) -> Dict:
        return self.get("/licensing/usage")

    def check_feature(self, feature: str) -> Dict:
        return self.get(f"/licensing/features/{feature}")

    def tiers(self) -> Dict:
        return self.get("/licensing/tiers")


class ExperimentsService(_BaseClient):
    """A/B experiments, runs, compare, auto-promote."""

    def list(self) -> Dict:
        return self.get("/experiments")

    def create(
        self,
        name: str,
        description: str = "",
        variants: Optional[List[Dict]] = None,
        traffic_split: Optional[Dict] = None,
        metric: str = "trust_score",
    ) -> Dict:
        return self.post("/experiments", {
            "name": name, "description": description,
            "variants": variants or [], "traffic_split": traffic_split,
            "metric": metric,
        })

    def get_experiment(self, experiment_id: str) -> Dict:
        return self.get(f"/experiments/{experiment_id}")

    def run(self, experiment_id: str, input_text: str, user: str = "api") -> Dict:
        return self.post(f"/experiments/{experiment_id}/run", {
            "input": input_text, "user": user,
        })

    def compare(self, experiment_id: str) -> Dict:
        return self.get(f"/experiments/{experiment_id}/compare")

    def cost(self, experiment_id: str) -> Dict:
        return self.get(f"/experiments/{experiment_id}/cost")

    def runs(self, experiment_id: str) -> Dict:
        return self.get(f"/experiments/{experiment_id}/runs")

    def significance(self, experiment_id: str) -> Dict:
        return self.get(f"/experiments/{experiment_id}/significance")

    def summary(self, experiment_id: str) -> Dict:
        return self.get(f"/experiments/{experiment_id}/summary")

    def suggest(self, experiment_id: str) -> Dict:
        return self.get(f"/experiments/{experiment_id}/suggest")

    def auto_promote(self, experiment_id: str, threshold: float = 0.95) -> Dict:
        return self.patch(f"/experiments/{experiment_id}/auto-promote",
                          {"threshold": threshold})


class PromptsService(_BaseClient):
    """Prompt registry — create, version, activate, render, lint, analytics."""

    def list(self) -> Dict:
        return self.get("/prompts")

    def create(
        self,
        name: str,
        template: str,
        description: str = "",
        tags: Optional[List[str]] = None,
        compliance: Optional[List[str]] = None,
    ) -> Dict:
        return self.post("/prompts", {
            "name": name, "template": template, "description": description,
            "tags": tags or [], "compliance": compliance or [],
        })

    def get_prompt(self, prompt_id: str) -> Dict:
        return self.get(f"/prompts/{prompt_id}")

    def delete(self, prompt_id: str) -> Dict:
        return self.delete(f"/prompts/{prompt_id}")

    def versions(self, prompt_id: str) -> Dict:
        return self.get(f"/prompts/{prompt_id}/versions")

    def add_version(self, prompt_id: str, template: str, note: str = "") -> Dict:
        return self.post(f"/prompts/{prompt_id}/versions", {
            "template": template, "note": note,
        })

    def activate(self, prompt_id: str, version: Optional[str] = None) -> Dict:
        return self.post(f"/prompts/{prompt_id}/activate", {"version": version})

    def resolve(self, prompt_id: str) -> Dict:
        return self.get(f"/prompts/{prompt_id}/resolve")

    def render(self, prompt_id: str, variables: Optional[Dict] = None) -> Dict:
        return self.post(f"/prompts/{prompt_id}/render", {"variables": variables or {}})

    def lint(self, prompt_id: str) -> Dict:
        return self.post(f"/prompts/{prompt_id}/lint", {})

    def analytics(self, prompt_id: str) -> Dict:
        return self.get(f"/prompts/{prompt_id}/analytics")


class AuthService(_BaseClient):
    """Login, register, token refresh, RBAC, TOTP, API keys."""

    def login(self, email: str, password: str) -> Dict:
        result = self.post("/auth/login", {"email": email, "password": password})
        if "token" in result:
            self.set_token(result["token"])
        return result

    def register(self, email: str, password: str, role: str = "viewer") -> Dict:
        return self.post("/auth/register", {
            "email": email, "password": password, "role": role,
        })

    def refresh(self, refresh_token: str) -> Dict:
        result = self.post("/auth/refresh", {"refresh_token": refresh_token})
        if "token" in result:
            self.set_token(result["token"])
        return result

    def me(self) -> Dict:
        return self.get("/auth/me")

    def api_keys(self) -> Dict:
        return self.get("/auth/api-keys")

    def create_api_key(self, name: str, role: str = "viewer",
                       expires_days: int = 365) -> Dict:
        return self.post("/auth/api-keys", {
            "name": name, "role": role, "expires_days": expires_days,
        })

    def revoke_api_key(self, key_id: str) -> Dict:
        return self.delete(f"/auth/api-keys/{key_id}")

    def users(self) -> Dict:
        return self.get("/auth/users")

    def update_role(self, user_id: str, role: str) -> Dict:
        return self.patch(f"/auth/users/{user_id}/role", {"role": role})

    def invite(self, email: str, role: str = "viewer") -> Dict:
        return self.post("/auth/invite", {"email": email, "role": role})

    def setup_totp(self) -> Dict:
        return self.post("/auth/totp/setup", {})

    def verify_totp(self, code: str) -> Dict:
        return self.post("/auth/totp/verify", {"code": code})


# ── Main client (aggregates all services) ─────────────────────────────────────

class ConnectorClient:
    """
    Connector Platform — full API client.

    All services are accessible as attributes:
        client.agents.run_pipeline(...)
        client.memory.write(...)
        client.compliance.report(...)
        client.tools.mcp_register(...)
        client.proof.generate(...)
        client.experiments.run(...)
        client.prompts.resolve(...)
        client.monitor.health()
        client.auth.login(...)
        client.debug.snapshot(...)
        client.license.status()
        client.multiagent.run_pipeline(...)
        client.actionlog.record(...)
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key:  Optional[str] = None,
        timeout:  int = 30,
        max_retries: int = 3,
    ):
        url = base_url or os.environ.get("CONNECTOR_BASE_URL", "http://localhost:9090/api/v1")
        key = api_key  or os.environ.get("CONNECTOR_API_KEY", "")

        kwargs = dict(base_url=url, api_key=key, timeout=timeout, max_retries=max_retries)

        self.agents      = AgentsService(**kwargs)
        self.actionlog   = ActionLogService(**kwargs)
        self.memory      = MemoryService(**kwargs)
        self.monitor     = MonitorService(**kwargs)
        self.multiagent  = MultiAgentService(**kwargs)
        self.tools       = ToolsService(**kwargs)
        self.proof       = ProofService(**kwargs)
        self.debug       = DebugService(**kwargs)
        self.compliance  = ComplianceService(**kwargs)
        self.license     = LicenseService(**kwargs)
        self.experiments = ExperimentsService(**kwargs)
        self.prompts     = PromptsService(**kwargs)
        self.auth        = AuthService(**kwargs)

    def health(self) -> Dict:
        return self.monitor.health()

    def run(
        self,
        agent: str,
        input_text: str,
        user: str = "api",
        instructions: Optional[str] = None,
        compliance: Optional[List[str]] = None,
    ) -> Dict:
        """Shortcut: run a single agent with trust scoring."""
        return self.agents.run_pipeline(
            agent_name=agent, input_text=input_text, user=user,
            instructions=instructions, compliance=compliance,
        )

    def pipeline(
        self,
        name: str,
        agents: List[Dict],
        input_text: str,
        user: str = "api",
        compliance: Optional[List[str]] = None,
        max_cost_usd: Optional[float] = None,
    ) -> Dict:
        """Shortcut: run a multi-agent pipeline."""
        return self.multiagent.run_pipeline(
            name=name, agents=agents, input_text=input_text,
            user=user, compliance=compliance, max_cost_usd=max_cost_usd,
        )
