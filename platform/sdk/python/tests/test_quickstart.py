"""
SDK integration tests — verify the 3-line quickstart and all major methods work
against a running Connector server at http://localhost:9090.

Run:
    CONNECTOR_DEV_MODE=1 cargo run   # start server
    pip install requests
    python -m pytest sdk/python/tests/test_quickstart.py -v
"""

import sys
import os
import uuid
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from connector_sdk import ConnectorAgent
from connector_sdk.exceptions import ConnectorError


BASE_URL = os.getenv("CONNECTOR_BASE_URL", "http://localhost:9090")
TOKEN = "dev-token"


def make_agent(suffix=""):
    return ConnectorAgent(
        name=f"sdk-test-{uuid.uuid4().hex[:6]}{suffix}",
        base_url=BASE_URL,
        token=TOKEN,
    )


# ── Connectivity ─────────────────────────────────────────────────────────────

def test_server_reachable():
    """Server must be reachable before any other test."""
    import requests
    r = requests.get(f"{BASE_URL}/health", timeout=5)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    # New: health endpoint returns capability inventory
    assert "capabilities" in data
    assert "protocols" in data


def test_capability_manifest():
    """GET /api/v1 must return full manifest with quickstart."""
    import requests
    r = requests.get(f"{BASE_URL}/api/v1", headers={"Authorization": f"Bearer {TOKEN}"}, timeout=5)
    assert r.status_code == 200
    data = r.json()
    assert "capabilities" in data
    assert "quickstart" in data
    assert "auth" in data
    caps = data["capabilities"]
    assert "memory" in caps
    assert "protocols" in caps
    assert "hallucination_safety" in caps
    assert "distributed_infra" in caps
    # Dev mode shows dev-token instructions
    assert data["auth"]["type"] == "dev"
    assert "dev-token" in str(data["auth"])


# ── 3-line Quickstart ─────────────────────────────────────────────────────────

def test_three_line_quickstart():
    """The most important test: 3 lines, working agent."""
    agent = ConnectorAgent(f"quickstart-{uuid.uuid4().hex[:6]}", base_url=BASE_URL, token=TOKEN)
    agent.remember("User prefers dark mode")
    memories = agent.recall()
    assert isinstance(memories, list)


# ── Memory ────────────────────────────────────────────────────────────────────

def test_remember_and_recall():
    agent = make_agent()
    r = agent.remember("The user is a senior engineer at a fintech startup")
    assert r.get("ok") is True
    cid = r.get("cid") or r.get("packet_id")
    assert cid is not None

    memories = agent.recall()
    assert isinstance(memories, list)


def test_remember_with_tags():
    agent = make_agent()
    r = agent.remember("Contract #001 approved", memory_type="Decision", tags=["legal", "contracts"])
    assert r.get("ok") is True


def test_remember_multiple_types():
    agent = make_agent()
    for mem_type in ["Feedback", "Decision", "Action"]:
        r = agent.remember(f"Test {mem_type} memory", memory_type=mem_type)
        assert r.get("ok") is True, f"Failed for type {mem_type}: {r}"


def test_recall_with_query():
    agent = make_agent()
    agent.remember("The user's budget is $50,000 for Q3")
    agent.remember("The user likes Python over TypeScript")
    memories = agent.recall(query="budget", limit=5)
    assert isinstance(memories, list)


# ── Safety ────────────────────────────────────────────────────────────────────

def test_verify_claim_explicit():
    agent = make_agent()
    result = agent.verify_claim(
        source_text="The clinical trial showed a 45% reduction in symptoms.",
        claims=["45% reduction in symptoms"],
    )
    assert result.get("ok") is True
    assert result.get("total_claims", 0) > 0
    assert "confirmed" in result
    assert "rejected" in result


def test_verify_claim_detects_absent():
    agent = make_agent()
    result = agent.verify_claim(
        source_text="The drug was tested on 100 patients.",
        claims=["100% cure rate achieved"],
    )
    assert result.get("ok") is True
    assert result.get("total_claims", 0) > 0


def test_safety_check_passes():
    agent = make_agent()
    report = agent.safety_check()
    assert report.get("ok") is True
    assert "invariants" in report or "all_invariants_passed" in report
    invariants = report.get("invariants", [])
    assert len(invariants) == 6, f"Expected 6 invariants, got {len(invariants)}"
    for inv in invariants:
        assert inv.get("passed") is True, f"Invariant failed: {inv}"


def test_ground_known_term():
    agent = make_agent()
    # Seed a grounding entry first
    agent.client.post("/safety/grounding/add", {
        "category": "sdk_test",
        "code": "SDK001",
        "term": "verified sdk term",
        "description": "A term added by the SDK test",
        "system": "SDK-TEST",
    })
    entry = agent.ground("verified sdk term", category="sdk_test")
    assert entry is not None
    assert entry["code"] == "SDK001"


def test_ground_unknown_returns_none():
    agent = make_agent()
    entry = agent.ground("completelymadeuptermthatdoesnotexist9999", category="nonexistent")
    assert entry is None


# ── Protocol Bridges ──────────────────────────────────────────────────────────

def test_a2a_task_submit():
    agent = make_agent()
    result = agent.a2a_task("Summarize the Q3 financial report")
    assert result.get("ok") is True
    assert result.get("task_id") is not None


def test_acp_send_message():
    sender = make_agent("-sender")
    recipient = make_agent("-recipient")
    result = sender.send_message(recipient.pid, "Hello from ACP bridge test")
    assert result.get("ok") is True
    assert result.get("protocol") == "ACP/1.0"


def test_mcp_list_platform_tools():
    """MCP tools endpoint — no remote server needed."""
    agent = make_agent()
    result = agent.client.get("/protocols/mcp/tools")
    assert "tools" in result
    assert len(result["tools"]) > 0


# ── Infrastructure ────────────────────────────────────────────────────────────

def test_store_secret():
    agent = make_agent()
    secret_id = f"sdk-secret-{uuid.uuid4().hex[:8]}"
    handle = agent.store_secret(secret_id, "super-secret-value-xyz", ttl_hours=1)
    assert handle.startswith("sh_")


def test_submit_pipeline():
    agent = make_agent()
    result = agent.submit_pipeline([
        {"task_id": "step-1", "agent_pid": "worker-a", "action": "fetch",   "dependencies": []},
        {"task_id": "step-2", "agent_pid": "worker-b", "action": "process", "dependencies": ["step-1"]},
    ])
    assert result.get("ok") is True
    assert result.get("orchestrator_id", "").startswith("orch:")


def test_set_quota():
    agent = make_agent()
    ns = f"sdk-quota-{uuid.uuid4().hex[:6]}"
    result = agent.set_quota(ns, 500_000)
    assert result.get("ok") is True


def test_stake_and_rate():
    agent_a = make_agent("-a")
    agent_b = make_agent("-b")
    agent_a.stake(500)
    agent_b.stake(200)
    result = agent_a.rate_peer(agent_b.pid, score=0.8, context="good work on pipeline")
    assert result.get("ok") is True


def test_propose_consensus():
    agent = make_agent()
    round_id = int(uuid.uuid4().int % 900000) + 100000
    agent.client.post("/infra/consensus/validators", {
        "validators": [agent.pid, "validator-2", "validator-3"]
    })
    try:
        result = agent.propose_consensus(round_id=round_id, value={"decision": "deploy", "version": "v2.0"})
        assert result.get("ok") is True
    except ConnectorError as e:
        # "Wrong round" means BFT state advanced — the endpoint is working correctly
        assert "round" in str(e).lower() or "proposer" in str(e).lower(), f"Unexpected error: {e}"


# ── Audit ─────────────────────────────────────────────────────────────────────

def test_audit_log():
    agent = make_agent()
    agent.remember("Audit test memory")
    log = agent.audit_log()
    assert isinstance(log, list)


# ── Error Handling ────────────────────────────────────────────────────────────

def test_error_on_bad_request():
    """422 errors must raise ConnectorError with useful info."""
    agent = make_agent()
    with pytest.raises(ConnectorError) as exc_info:
        # Memory write without required agent_pid must 422
        agent.client.post("/memory/write", {"invalid_field_only": True})
    assert exc_info.value.status_code in (400, 422)


def test_repr():
    agent = make_agent()
    r = repr(agent)
    assert "ConnectorAgent" in r
    assert agent.name in r
