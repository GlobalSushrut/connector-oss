import os
import requests
from urllib.parse import quote
from config import CONNECTOR_API_KEY, CONNECTOR_DEV_MODE, CONNECTOR_URL, DEEPSEEK_MODEL


class ConnectorPlatform:
    """Real Connector platform API client - all system data comes from running platform"""

    def __init__(self):
        token = os.getenv("CONNECTOR_API_KEY", CONNECTOR_API_KEY)
        dev_mode = os.getenv("CONNECTOR_DEV_MODE", CONNECTOR_DEV_MODE)
        base_url = os.getenv("CONNECTOR_URL", CONNECTOR_URL)
        if not token and dev_mode:
            token = "dev-token"
        if not token:
            raise RuntimeError("CONNECTOR_API_KEY must be set unless CONNECTOR_DEV_MODE is enabled")
        self.base = base_url
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }

    def _get(self, path):
        r = requests.get(f"{self.base}/api/v1{path}", headers=self.headers, timeout=10)
        r.raise_for_status()
        return r.json()

    def _post(self, path, body):
        r = requests.post(f"{self.base}/api/v1{path}", headers=self.headers, json=body, timeout=10)
        r.raise_for_status()
        return r.json()

    def _post_root(self, path, body):
        r = requests.post(f"{self.base}{path}", headers=self.headers, json=body, timeout=20)
        r.raise_for_status()
        return r.json()

    def _get_root(self, path):
        r = requests.get(f"{self.base}{path}", headers=self.headers, timeout=10)
        r.raise_for_status()
        return r.json()

    def _post_root_with_headers(self, path, body, extra_headers=None):
        headers = dict(self.headers)
        if extra_headers:
            headers.update(extra_headers)
        r = requests.post(f"{self.base}{path}", headers=headers, json=body, timeout=20)
        r.raise_for_status()
        return {
            "body": r.json(),
            "headers": dict(r.headers),
            "status_code": r.status_code,
        }

    def get_health(self):
        return self._get("/monitor/health")

    def get_cost_dashboard(self):
        return self._get("/monitor/cost-dashboard")

    def get_regulation_report(self, framework):
        return self._get(f"/actionlog/regulation-report/{framework}")

    def get_verify_report(self):
        return self._get("/safety/formal/report")

    def get_verify_violations(self):
        return self._get("/safety/formal/violations")

    def get_policy_violations(self):
        return self._get("/compliance/policy-violations")

    def get_graph_entities(self):
        return self._get("/memory/graph/entities")

    def get_interference(self, agent_pid):
        return self._get(f"/memory/interference2/{agent_pid}")

    def query_knowledge(self, entities=None, keywords=None, token_budget=4096, max_facts=10, min_relevance=0.0, ts_from=None, ts_to=None):
        body = {
            "entities": entities or [],
            "keywords": keywords or [],
            "token_budget": token_budget,
            "max_facts": max_facts,
            "min_relevance": min_relevance,
        }
        if ts_from is not None:
            body["ts_from"] = ts_from
        if ts_to is not None:
            body["ts_to"] = ts_to
        return self._post("/memory/knowledge/query2", body)

    def get_trace_stats(self):
        return self._get("/actionlog/traces/stats")

    def get_agent_traces(self, pid):
        return self._get(f"/agents/{pid}/traces")

    def get_receipt(self, seq_no):
        return self._get(f"/books/receipt/{seq_no}")

    def get_statement(self, account_id="platform"):
        return self._get(f"/books/statement/{account_id}")

    def invoke_chat(self, agent_pid, namespace, prompt, system=None, model=None):
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self._post_root("/v1/chat/completions", {
            "model": model or DEEPSEEK_MODEL,
            "messages": messages,
            "agent_pid": agent_pid,
            "namespace": namespace,
            "stream": False,
        })

    def invoke_chat_with_client(self, agent_pid, namespace, prompt, system=None, model=None, client_name=None, client_origin=None, user_agent=None):
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        extra_headers = {}
        if client_name:
            extra_headers["x-connector-client"] = client_name
        if client_origin:
            extra_headers["x-connector-origin"] = client_origin
        if user_agent:
            extra_headers["User-Agent"] = user_agent
        return self._post_root_with_headers("/v1/chat/completions", {
            "model": model or DEEPSEEK_MODEL,
            "messages": messages,
            "agent_pid": agent_pid,
            "namespace": namespace,
            "stream": False,
        }, extra_headers)

    def get_gateway_models(self):
        return self._get_root("/v1/models")

    # Agent lifecycle
    def register_agent(self, name, desc, clearance=3):
        return self._post("/agents", {"name": name, "description": desc, "clearance": clearance})

    def start_agent(self, pid):
        return self._post(f"/agents/{pid}/start", {})

    def kill_agent(self, pid):
        return self._post(f"/agents/{pid}/kill", {})

    def get_agent(self, pid):
        return self._get(f"/agents/{pid}")

    def list_agents(self):
        return self._get("/agents")

    def unquarantine_agent(self, pid):
        """Release agent from quarantine so it can resume operations."""
        try:
            return self._post(f"/agents/{pid}/unquarantine", {})
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def get_agent_memory_stats(self, pid):
        """Get memory statistics for agent."""
        try:
            return self._get(f"/agents/{pid}/memory/stats")
        except Exception:
            return {"error": "memory_stats_unavailable"}

    def get_interference(self, agent_pid):
        """Get interference/contradiction report for agent."""
        try:
            return self._get(f"/memory/interference/{agent_pid}")
        except Exception:
            return {"error": "interference_unavailable"}

    def knowledge_query(self, entities, keywords, agent_pid=None):
        """Query knowledge graph with entity + keyword retrieval."""
        body = {"entities": entities, "keywords": keywords}
        if agent_pid:
            body["agent_pid"] = agent_pid
        try:
            return self._post("/memory/knowledge/query", body)
        except Exception:
            return {"error": "knowledge_query_unavailable"}

    def context_snapshot(self, pid):
        """Snapshot agent context state."""
        try:
            return self._post(f"/context/{pid}/snapshot", {})
        except Exception:
            return {"error": "context_snapshot_unavailable"}

    def context_pressure(self, pid):
        """Get context pressure/budget for agent."""
        try:
            return self._get(f"/context/{pid}/pressure")
        except Exception:
            return {"error": "context_pressure_unavailable"}

    # Memory operations
    def write_memory(self, agent_pid, content, ptype=None, session_id=None, memory_type=None, tags=None, user=None, entity_kind=None):
        body = {"agent_pid": agent_pid, "content": content}
        if ptype:
            body["packet_type"] = ptype
        if session_id:
            body["session_id"] = session_id
        if memory_type:
            body["memory_type"] = memory_type
        if tags:
            body["tags"] = tags
        if user:
            body["user"] = user
        if entity_kind:
            body["entity_kind"] = entity_kind
        return self._post("/memory/write", body)

    def recall_memory(self, ns, limit=50, session_id=None, memory_type=None, min_abstraction=None, tier=None, ts_from=None, ts_to=None):
        params = {"limit": limit}
        if session_id:
            params["session_id"] = session_id
        if memory_type:
            params["memory_type"] = memory_type
        if min_abstraction is not None:
            params["min_abstraction"] = min_abstraction
        if tier:
            params["tier"] = tier
        if ts_from is not None:
            params["ts_from"] = ts_from
        if ts_to is not None:
            params["ts_to"] = ts_to
        r = requests.get(
            f"{self.base}/api/v1/memory/recall2/{quote(ns, safe='')}",
            headers=self.headers,
            params=params,
            timeout=12,
        )
        r.raise_for_status()
        return r.json()

    def search_memory(self, ns, query, top_k=5):
        # Use GET /memory/semantic-search with query params
        params = f"?q={query}&namespace={ns}&limit={top_k}"
        r = requests.get(f"{self.base}/api/v1/memory/semantic-search{params}", headers=self.headers, timeout=10)
        r.raise_for_status()
        return r.json()

    # System data (real kernel output)
    def get_books_position(self):
        return self._get("/books")

    def get_books_journal(self, limit=50):
        """Get books journal entries (replaces debug/audit which requires special auth)"""
        journal = self._get("/books/journal")
        if isinstance(journal, dict) and "entries" in journal:
            entries = journal["entries"]
            return {**journal, "entries": entries[-limit:] if limit else entries}
        if isinstance(journal, dict) and "data" in journal and isinstance(journal["data"], dict) and "entries" in journal["data"]:
            entries = journal["data"]["entries"]
            trimmed = entries[-limit:] if limit else entries
            return {
                **journal,
                "entries": trimmed,
                "total": journal["data"].get("total", len(entries)),
                "offset": journal["data"].get("offset", 0),
                "limit": journal["data"].get("limit", limit),
            }
        return journal

    def get_books_ledger(self, account="platform"):
        return self._get(f"/books/ledger/{account}")

    def get_system_metrics(self):
        try:
            return self._get("/metrics")
        except:
            return {"error": "metrics_endpoint_not_available"}

    # ── Glue: record every decision for provenance + signed ID ──────────────

    def record_decision(self, agent_pid, action, target, outcome,
                        model_name=None, rationale=None, confidence=None,
                        evidence_cids=None, regulations=None):
        body = {
            "agent_pid": agent_pid,
            "action": action,
            "target": target,
            "outcome": outcome,
        }
        if model_name:
            body["model_name"] = model_name
        if rationale:
            body["rationale"] = rationale
        if confidence is not None:
            body["confidence"] = confidence
        if evidence_cids:
            body["evidence_cids"] = evidence_cids
        if regulations:
            body["regulations"] = regulations
        return self._post("/disputes/record", body)

    # ── SOE: structured surface views ────────────────────────────────────────

    def get_dispute_report(self, decision_id):
        return self._get(f"/disputes/{decision_id}/report")

    def get_defense_package(self, decision_id):
        return self._get(f"/disputes/{decision_id}/defense-package")

    def generate_proof(self, agent_pid, title=None):
        body = {"agent_pid": agent_pid}
        if title:
            body["title"] = title
        return self._post("/proof/generate", body)

    def list_audit_receipts(self, agent_pid, limit=10):
        r = requests.get(
            f"{self.base}/api/v1/agents/{agent_pid}/audit/receipts",
            headers=self.headers,
            params={"limit": limit},
            timeout=10,
        )
        r.raise_for_status()
        return r.json()

    def get_agent_cost(self, agent_pid):
        return self._get(f"/agents/{agent_pid}/cost")

    def render_surface(self, surface, subject_id, view="summary"):
        """Render canonical SOE surface envelope from API."""
        r = requests.get(
            f"{self.base}/api/v1/surfaces/{surface}/{subject_id}",
            headers=self.headers,
            params={"view": view},
            timeout=12,
        )
        r.raise_for_status()
        return r.json()

    def compile_cls_contract(self, source):
        """Compile CLS/CCL source for live governance preflight."""
        return self._post("/cls/compile", {"source": source})

    def verify_grounding(self, text, categories=None):
        """Run grounding verification against loaded grounding table."""
        body = {"text": text}
        if categories:
            body["categories"] = categories
        try:
            return self._post("/safety/grounding/verify", body)
        except Exception:
            return {"error": "grounding_verify_unavailable"}

    def verify_claims(self, claims, source_text):
        """Run claims verification — checks quoted evidence against source text."""
        body = {"claims": claims, "source_text": source_text}
        try:
            return self._post("/safety/claims/verify", body)
        except Exception:
            return {"error": "claims_verify_unavailable"}

    def ground_output(self, text, categories=None):
        """Ground an LLM output text against the grounding table."""
        body = {"output": text}
        if categories:
            body["categories"] = categories
        try:
            return self._post("/grounding/ground-output", body)
        except Exception:
            return {"error": "ground_output_unavailable"}

    def mcp_register_bridge(self, bridge_id, url, tools):
        """Register an MCP tool bridge for governed dispatch."""
        try:
            return self._post("/tools/mcp/register", {
                "bridge_id": bridge_id,
                "url": url,
                "tools": tools,
            })
        except Exception:
            return {"error": "mcp_register_unavailable"}

    def mcp_invoke_tool(self, bridge_id, tool, agent_pid, tool_input=None):
        """Invoke a tool through the governed MCP dispatch pipeline."""
        body = {
            "bridge_id": bridge_id,
            "tool": tool,
            "agent_pid": agent_pid,
        }
        if tool_input is not None:
            body["input"] = tool_input
        try:
            return self._post("/tools/mcp/invoke", body)
        except Exception as e:
            return {"error": str(e)}

    def get_pending_approvals(self):
        """Get pending tool approval queue."""
        try:
            return self._get("/tools/approvals/pending")
        except Exception:
            return {"error": "approvals_unavailable", "pending_count": 0, "approvals": []}

    # Agent isolation testing
    def test_mac_enforcement(self, reader_pid, target_ns):
        """Test MAC enforcement via the real policy check engine (access(2) analog).
        Uses POST /agents/:reader_pid/policy/check so the verdict comes from
        the kernel policy layer, not a raw HTTP auth gate."""
        try:
            result = self._post(f"/agents/{reader_pid}/policy/check", {
                "operation": "mem_read",
                "resource": target_ns,
            })
            verdict = (
                result.get("verdict")
                or ("ALLOW" if result.get("allowed") else "DENY")
            )
            return {
                "verdict": verdict,
                "reason": result.get("reason", ""),
                "enforcement": "kernel_policy",
                "reader_pid": reader_pid,
                "target_ns": target_ns,
                "raw": result,
            }
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            if status in (403, 401):
                return {"verdict": "DENY", "reason": "mac_enforcement", "enforcement": "kernel_policy", "error": str(e)}
            return {"verdict": "ERROR", "enforcement": "kernel_policy", "error": str(e)}
        except Exception as e:
            return {"verdict": "ERROR", "enforcement": "kernel_policy", "error": str(e)}

    def get_agent_sessions(self, pid):
        """Get active sessions for an agent"""
        try:
            return self._get(f"/agents/{pid}/sessions")
        except:
            return {"error": "sessions_endpoint_not_available"}

    def get_cross_agent_map(self):
        """Get live cross-agent isolation/share topology"""
        try:
            return self._get("/multiagent/map")
        except:
            return {"error": "cross_agent_map_not_available", "agents": []}

    def policy_check(self, pid, operation, resource):
        """Run read-only policy preflight for an agent action"""
        try:
            return self._post(f"/agents/{pid}/policy/check", {
                "operation": operation,
                "resource": resource,
            })
        except:
            return {"error": "policy_check_not_available", "allowed": False}

    def get_mcp_bridges(self):
        """Get active MCP bridge inventory"""
        try:
            return self._get("/tools/mcp/bridges")
        except:
            return {"error": "mcp_bridges_not_available", "count": 0, "bridges": []}

    def get_pending_tool_approvals(self):
        """Get pending tool approvals"""
        try:
            return self._get("/tools/approvals/pending")
        except:
            return {"error": "pending_approvals_not_available", "pending_count": 0, "approvals": []}

    def get_agent_memory_tree(self, pid):
        """Get agent-scoped memory tree for explainability views"""
        try:
            return self._get(f"/agents/{pid}/memory/tree")
        except:
            return {"error": "agent_memory_tree_not_available", "tree": [], "total_packets": 0}

    def get_reasoning_chain(self, kernel_pid):
        """Get debug reasoning chain for a kernel agent pid"""
        try:
            return self._get(f"/debug/agents/{kernel_pid}/reasoning-chain")
        except:
            return {"error": "reasoning_chain_not_available", "audit_chain": []}

    def get_compliance_frameworks(self):
        """Probe compliance frameworks surface"""
        try:
            return self._get("/compliance/frameworks")
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            try:
                detail = e.response.json() if e.response is not None else {"error": str(e)}
            except:
                detail = {"error": str(e)}
            return {"error": "compliance_frameworks_unavailable", "status": status, "detail": detail}
        except:
            return {"error": "compliance_frameworks_unavailable", "status": None}

    # Guard pipeline inspection
    def get_guard_verdicts(self, limit=20):
        """Get recent guard pipeline verdicts from journal"""
        journal = self.get_books_journal(limit=limit)
        entries = journal.get("entries", []) if isinstance(journal, dict) else []
        if entries:
            verdicts = [e for e in entries if "guard" in e.get("action", "").lower()]
            return {"verdicts": verdicts, "count": len(verdicts)}
        return {"verdicts": [], "count": 0}

    def get_policy_decisions(self, limit=20):
        """Get recent policy engine decisions from journal"""
        journal = self.get_books_journal(limit=limit)
        entries = journal.get("entries", []) if isinstance(journal, dict) else []
        if entries:
            decisions = [e for e in entries if "policy" in e.get("action", "").lower()]
            return {"decisions": decisions, "count": len(decisions)}
        return {"decisions": [], "count": 0}

    # Cost tracking
    def get_cost_breakdown(self):
        """Get detailed cost breakdown from books ledger"""
        try:
            ledger = self.get_books_ledger("platform")
            # Parse ledger for cost entries
            return ledger
        except:
            return {"error": "ledger_not_available"}

    def get_agent_budget(self, pid):
        """Get budget status for specific agent"""
        try:
            return self._get(f"/agents/{pid}/budget")
        except:
            return {"error": "budget_endpoint_not_available"}

    # ── HITL Gate ────────────────────────────────────────────────────────────

    def list_hitl_pending(self, agent_pid):
        """Return pending HITL approval requests for an agent."""
        try:
            return self._get(f"/agents/{agent_pid}/hitl/pending")
        except Exception as e:
            return {"requests": [], "count": 0, "error": str(e)}

    def hitl_approve(self, agent_pid, request_id):
        """Approve a pending HITL gate request."""
        try:
            return self._post(f"/agents/{agent_pid}/hitl/{request_id}/approve", {})
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def hitl_deny(self, agent_pid, request_id):
        """Deny a pending HITL gate request."""
        try:
            return self._post(f"/agents/{agent_pid}/hitl/{request_id}/deny", {})
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # Knowledge base operations
    def ingest_knowledge(self, container_id, target_ns):
        return self._post("/assets/ingest", {"container_id": container_id, "target_ns": target_ns})

    def create_asset_container(self, name, allowed_types, quota_bytes=100*1024*1024):
        return self._post("/assets/containers", {
            "name": name,
            "allowed_types": allowed_types,
            "quota_bytes": quota_bytes
        })

    def upload_asset(self, container_id, filename, content):
        return self._post(f"/assets/containers/{container_id}/upload", {
            "filename": filename,
            "content": content
        })

    # ── Attack demo surfaces ─────────────────────────────────────────────────

    def firewall_inspect(self, agent_pid, content, namespace="default"):
        """POST /firewall/inspect — run content through all 5 guard pipeline layers.
        Returns blocked, final_decision, layers_evaluated."""
        try:
            return self._post("/firewall/inspect", {
                "agent_pid": agent_pid,
                "content": content,
                "namespace": namespace,
            })
        except Exception as e:
            return {"error": str(e)}

    def invoke_chat_raw(self, agent_pid, namespace, prompt, system=None, model=None):
        """Like invoke_chat but returns full HTTP response including status code and error body.
        Does NOT raise on 4xx — returns the structured error for display."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        try:
            r = requests.post(f"{self.base}/v1/chat/completions", headers=self.headers, json={
                "model": model or DEEPSEEK_MODEL,
                "messages": messages,
                "agent_pid": agent_pid,
                "namespace": namespace,
                "stream": False,
            }, timeout=30)
            try:
                body = r.json()
            except Exception:
                body = {"raw_text": r.text[:500]}
            return {
                "status_code": r.status_code,
                "headers": dict(r.headers),
                "body": body,
                "ok": r.status_code < 400,
            }
        except Exception as e:
            return {"status_code": 0, "body": {"error": str(e)}, "ok": False}
