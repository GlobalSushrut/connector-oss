#!/usr/bin/env python3
"""
Interactive demo launcher for Connector Trial plugins.

Use this when presenting try.cnktros.com:

  1. Paste the trial API key from /trial.
  2. Pick TraceTramp, WitnessCtl, or DevGuard.
  3. The script configures the selected path and runs a real use case.

TraceTramp and WitnessCtl use the live Connector plugin proxy APIs so the
dashboard captures the resulting state. DevGuard creates a governed session and
writes Windsurf-ready config/prompt files into the selected workspace.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_ORIGIN = "https://try.cnktros.com"


@dataclass
class DemoConfig:
    origin: str
    api_key: str
    tenant_id: str
    workspace: Path
    actor_id: str
    junior_role: str
    dry_run: bool

    @property
    def api_base(self) -> str:
        return f"{self.origin.rstrip('/')}/api/v1"


class ApiClient:
    def __init__(self, cfg: DemoConfig) -> None:
        self.cfg = cfg

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        auth: bool = True,
    ) -> dict[str, Any]:
        url = f"{self.cfg.api_base}{path}"
        data = None
        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 ConnectorDemoLauncher/1.0",
            "Origin": self.cfg.origin,
            "Referer": f"{self.cfg.origin}/trial",
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if auth:
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"
            if self.cfg.tenant_id:
                headers["X-Tenant-Id"] = self.cfg.tenant_id

        if self.cfg.dry_run and method.upper() != "GET":
            print(f"[dry-run] {method} {url}")
            if body is not None:
                print(json.dumps(body, indent=2))
            return {
                "ok": True,
                "dry_run": True,
                "url": url,
                "method": method,
                "body": dry_run_body(path, body),
            }

        req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
        started = time.time()
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                raw = resp.read().decode("utf-8", "replace")
                parsed = parse_json(raw)
                return {
                    "ok": 200 <= resp.status < 300,
                    "status": resp.status,
                    "ms": int((time.time() - started) * 1000),
                    "body": parsed,
                }
        except urllib.error.HTTPError as err:
            raw = err.read().decode("utf-8", "replace")
            return {
                "ok": False,
                "status": err.code,
                "ms": int((time.time() - started) * 1000),
                "body": parse_json(raw),
            }
        except Exception as err:  # noqa: BLE001 - CLI should report all failures.
            return {
                "ok": False,
                "status": "ERR",
                "ms": int((time.time() - started) * 1000),
                "body": {"error": type(err).__name__, "message": str(err)},
            }


def parse_json(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw[:2000]}


def dry_run_body(path: str, body: dict[str, Any] | None) -> dict[str, Any]:
    if path == "/devguard/connect":
        return {
            "ok": True,
            "session_id": "dg_dryrun000001",
            "token": "cg_dryrun_windsurf_token",
            "gateway_base": DEFAULT_ORIGIN,
            "openai_base_url": f"{DEFAULT_ORIGIN}/v1",
            "anthropic_base_url": f"{DEFAULT_ORIGIN}/v1",
            "tool": (body or {}).get("tool", "windsurf"),
            "role": (body or {}).get("role", "junior_engineer"),
        }
    if path == "/plugins/witnessctl/sessions":
        return {
            "session_id": "00000000-0000-4000-8000-000000000001",
            "session_token": "wc_dryrun_session_token",
            "proxy_url": f"{DEFAULT_ORIGIN}/api/v1/plugins/witnessctl",
            "proxy_header": "x-witness-session",
        }
    if path.startswith("/plugins/witnessctl/ingest"):
        return {"capture_id": "00000000-0000-4000-8000-000000000002", "seq": 1}
    if "/seal" in path:
        return {"session_id": "00000000-0000-4000-8000-000000000001", "sealed": True}
    if path.startswith("/plugins/tracetramp/admin/operation-blocks"):
        return {"message": "Operation block active", **(body or {})}
    if path.startswith("/plugins/tracetramp/admin/policies"):
        return {"id": "dryrun-policy", "name": (body or {}).get("name", "dryrun")}
    return {"ok": True, "dry_run": True}


def ask(prompt: str, default: str | None = None, *, secret: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    if not value and default is not None:
        return default
    return value


def ask_bool(prompt: str, default: bool = True) -> bool:
    default_label = "Y/n" if default else "y/N"
    value = input(f"{prompt} [{default_label}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes", "1", "true"}


def masked(value: str) -> str:
    if len(value) <= 16:
        return "***"
    return f"{value[:10]}...{value[-6:]}"


def print_result(label: str, result: dict[str, Any], *, details: bool = False) -> None:
    status = result.get("status", "dry-run")
    ms = result.get("ms", 0)
    ok = "ok" if result.get("ok") else "fail"
    print(f"[{ok}] {label} status={status} ms={ms}")
    body = result.get("body", result)
    if details or not result.get("ok"):
        print(json.dumps(body, indent=2, sort_keys=True)[:4000])


def require_ok(label: str, result: dict[str, Any]) -> Any:
    print_result(label, result)
    if not result.get("ok"):
        raise SystemExit(f"{label} failed")
    return result.get("body")


def derive_tenant_from_session_id(session_id: str) -> str | None:
    """Playground tenant ids are derived from session ids in the server."""
    session_id = session_id.strip()
    if session_id.startswith("pg_") and len(session_id) >= 11:
        return f"pg-{session_id[3:11]}"
    return None


def discover_tenant_id(client: ApiClient) -> str | None:
    """Best-effort tenant discovery from the current trial key."""
    if client.cfg.dry_run:
        return "pg-dryrun"

    token = client.request("POST", "/auth/token", {"api_key": client.cfg.api_key}, auth=False)
    if not token.get("ok"):
        print_result("tenant discovery via auth/token", token)
        return None

    body = token.get("body")
    if not isinstance(body, dict):
        return None
    direct = body.get("tenant_id")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    user_id = body.get("user_id")
    if isinstance(user_id, str):
        return derive_tenant_from_session_id(user_id)
    return None


def normalize_origin(value: str) -> str:
    value = value.strip().rstrip("/")
    if not value:
        return DEFAULT_ORIGIN
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlparse(value)
    if not parsed.netloc:
        raise SystemExit(f"Invalid website address: {value}")
    return f"{parsed.scheme}://{parsed.netloc}"


def make_cfg(args: argparse.Namespace) -> DemoConfig:
    if args.origin:
        origin = normalize_origin(args.origin)
    else:
        origin = normalize_origin(
            ask("Hosted website address", os.environ.get("CONNECTOR_DEMO_ORIGIN", DEFAULT_ORIGIN))
        )

    if args.api_key:
        api_key = args.api_key
    else:
        api_key = ask("Paste the current 90-minute API key from /trial")
        if not api_key:
            raise SystemExit("API key is required. Open /trial and copy the current cpk_pg_* key.")

    tenant_id = args.tenant_id or os.environ.get("CONNECTOR_DEMO_TENANT_ID", "")
    workspace = Path(args.workspace or os.getcwd()).expanduser().resolve()

    if not tenant_id:
        tenant_id = ask("Tenant id (blank = auto-discover from API key)", "")
    actor_id = args.actor_id or ask("Actor / agent id for simulation", "demo-junior-engineer")
    junior_role = args.role or ask("Demo role", "junior_engineer")

    return DemoConfig(
        origin=origin,
        api_key=api_key,
        tenant_id=tenant_id,
        workspace=workspace,
        actor_id=actor_id,
        junior_role=junior_role,
        dry_run=args.dry_run,
    )


def choose_plugin(args: argparse.Namespace) -> str:
    if args.plugin:
        return args.plugin
    print("\nChoose demo path:")
    print("  1) TraceTramp  - simulate LLM governance / operation block / policy")
    print("  2) WitnessCtl  - simulate evidence capture / seal / compliance readback")
    print("  3) DevGuard    - configure Windsurf as a governed junior engineer")
    choice = ask("Selection", "1")
    return {"1": "tracetramp", "2": "witnessctl", "3": "devguard"}.get(choice, choice).lower()


def preflight(client: ApiClient) -> None:
    print("\n== Preflight ==")
    if not client.cfg.tenant_id:
        found = discover_tenant_id(client)
        if found:
            client.cfg.tenant_id = found
            print(f"[ok] tenant auto-discovered: {found}")
        else:
            print("[warn] tenant id was not provided and could not be auto-discovered")
    require_ok("deployment/info", client.request("GET", "/deployment/info"))
    require_ok("plugins/status", client.request("GET", "/plugins/status"),)


def require_tenant(cfg: DemoConfig, purpose: str) -> str:
    if cfg.tenant_id:
        return cfg.tenant_id
    raise SystemExit(
        f"{purpose} needs a real tenant id. Re-run and either paste the tenant id from /trial "
        "or use a valid current playground API key so the script can auto-discover it."
    )


def run_tracetramp(cfg: DemoConfig, client: ApiClient) -> None:
    print("\n== TraceTramp Simulation ==")
    preflight(client)
    require_ok("tracetramp/status", client.request("GET", "/plugins/tracetramp/status"))
    require_ok("tracetramp/stats before", client.request("GET", "/plugins/tracetramp/admin/stats"))
    tenant_id = require_tenant(cfg, "TraceTramp write simulation")

    operation_key = ask("Operation key to block temporarily", "demo.llm.delete_production_data")
    reason = ask(
        "Block reason",
        "Demo: junior engineer attempted a destructive production-like action",
    )

    if ask_bool("Create a real temporary TraceTramp operation block?", True):
        block_body = {
            "tenant_id": tenant_id,
            "actor_id": cfg.actor_id,
            "operation_key": operation_key,
            "reason": reason,
            "created_by": "demo-plugin-launcher",
        }
        require_ok(
            "POST operation block",
            client.request("POST", "/plugins/tracetramp/admin/operation-blocks", block_body),
        )

    policy_body = {
        "tenant_id": tenant_id,
        "name": f"demo-policy-{int(time.time())}",
        "policy_type": "demo_guardrail",
        "rules": {
            "deny_operations": [operation_key],
            "require_hitl_for": ["delete", "exfiltrate", "prod"],
            "demo_actor": cfg.actor_id,
        },
        "enforcement_mode": "monitor",
        "priority": 50,
    }
    if ask_bool("Submit a demo TraceTramp policy record?", True):
        print_result(
            "POST policy",
            client.request("POST", "/plugins/tracetramp/admin/policies", policy_body),
            details=True,
        )

    require_ok("operation-blocks after", client.request("GET", "/plugins/tracetramp/admin/operation-blocks"))
    require_ok("policies after", client.request("GET", "/plugins/tracetramp/admin/policies"))

    print("\nOpen dashboard:")
    print(f"  {cfg.origin}/plugins/tracetramp")
    print("Show: Control & stats, Blocks & quarantine, Policy submit.")


def extract_session_id(body: Any) -> str | None:
    if not isinstance(body, dict):
        return None
    for key in ("session_id", "id"):
        value = body.get(key)
        if isinstance(value, str) and value:
            return value
    nested = body.get("session")
    if isinstance(nested, dict):
        value = nested.get("id") or nested.get("session_id")
        if isinstance(value, str):
            return value
    return None


def run_witnessctl(cfg: DemoConfig, client: ApiClient) -> None:
    print("\n== WitnessCtl Simulation ==")
    preflight(client)
    require_ok("witnessctl/status", client.request("GET", "/plugins/witnessctl/status"))
    require_ok("witnessctl/health", client.request("GET", "/plugins/witnessctl/health"))

    upstream = ask("Upstream/workload name", "demo-junior-agent")
    frameworks_raw = ask("Compliance frameworks (comma-separated)", "SOC2,ISO27001,EU_AI_ACT")
    frameworks = [p.strip() for p in frameworks_raw.split(",") if p.strip()]

    session_body = {
        "upstream": upstream,
        "role": cfg.junior_role,
        "mode": "monitor",
        "frameworks": frameworks,
        "policy": {
            "pii_detection": True,
            "capture_request_body": True,
            "capture_response_body": True,
            "seal_on_close": False,
        },
    }
    session = require_ok(
        "POST witness session",
        client.request("POST", "/plugins/witnessctl/sessions", session_body),
    )
    session_id = extract_session_id(session)
    if not session_id:
        print(json.dumps(session, indent=2))
        raise SystemExit("Could not find WitnessCtl session id in response")

    ingest_body = {
        "session_id": session_id,
        "request": {
            "method": "POST",
            "url": f"{cfg.origin}/v1/chat/completions",
            "headers": {
                "content-type": "application/json",
                "x-demo-actor": cfg.actor_id,
            },
            "body": json.dumps({
                "model": "demo-governed-model",
                "messages": [
                    {
                        "role": "user",
                        "content": "Summarize customer records for qa@example.com and avoid leaking secrets.",
                    }
                ],
            }),
            "timestamp_ms": int(time.time() * 1000),
        },
        "response": {
            "status": 200,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({
                "decision": "allowed_with_redaction",
                "pii": "email redacted",
                "summary": "Demo response captured by WitnessCtl.",
            }),
            "latency_ms": 184,
        },
    }
    require_ok("POST witness ingest", client.request("POST", "/plugins/witnessctl/ingest", ingest_body))

    if ask_bool("Seal the WitnessCtl session now?", True):
        print_result(
            "POST witness seal",
            client.request("POST", f"/plugins/witnessctl/sessions/{session_id}/seal?force_seal=true", {}),
            details=True,
        )

    print_result(
        "GET compliance",
        client.request("GET", f"/plugins/witnessctl/compliance/{session_id}"),
        details=True,
    )
    print_result(
        "GET custody",
        client.request("GET", f"/plugins/witnessctl/custody/{session_id}/status"),
        details=True,
    )

    print("\nOpen dashboard:")
    print(f"  {cfg.origin}/plugins/witnessctl")
    print(f"Session id: {session_id}")
    print("Show: Live sessions, Compliance, Custody / seals.")


def backup_write(path: Path, content: str, dry_run: bool) -> None:
    print(f"[write] {path}")
    if dry_run:
        print(content)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        stamp = time.strftime("%Y%m%d%H%M%S")
        backup = path.with_suffix(path.suffix + f".bak-{stamp}")
        shutil.copy2(path, backup)
        print(f"[backup] {backup}")
    path.write_text(content, encoding="utf-8")


def run_devguard(cfg: DemoConfig, client: ApiClient) -> None:
    print("\n== DevGuard + Windsurf Setup ==")
    preflight(client)
    require_ok("devguard/status", client.request("GET", "/plugins/devguard/status"))

    workspace = cfg.workspace
    if not workspace.exists():
        if ask_bool(f"Workspace does not exist. Create {workspace}?", True):
            if not cfg.dry_run:
                workspace.mkdir(parents=True, exist_ok=True)
        else:
            raise SystemExit("Workspace required for Windsurf demo config")

    body = {
        "tool": "windsurf",
        "role": cfg.junior_role,
        "workspace": str(workspace),
    }
    connect = require_ok("POST devguard/connect", client.request("POST", "/devguard/connect", body))
    token = connect.get("token") if isinstance(connect, dict) else None
    base_url = connect.get("openai_base_url") if isinstance(connect, dict) else None
    session_id = connect.get("session_id") if isinstance(connect, dict) else None
    if not token or not base_url:
        print(json.dumps(connect, indent=2))
        raise SystemExit("DevGuard connect response missing token/base URL")

    windsurf_yaml = textwrap.dedent(f"""\
        # Connector DevGuard demo config for Windsurf.
        # Paste these values into Windsurf's OpenAI-compatible custom provider UI
        # if your Windsurf build does not read workspace YAML automatically.
        openai:
          base_url: {base_url}
          api_key: {token}
        connector:
          origin: {cfg.origin}
          api_key: {cfg.api_key}
          tenant_id: {cfg.tenant_id}
        devguard:
          session_id: {session_id}
          role: {cfg.junior_role}
          actor_id: {cfg.actor_id}
          workspace: {workspace}
        """)
    prompt = textwrap.dedent(f"""\
        # DevGuard Demo Prompt: Junior Engineer

        You are a junior engineer working inside this repository.

        Act naturally, but stay inside the assigned task. Before changing files,
        explain what you plan to modify. Do not run destructive shell commands,
        do not read secrets, and do not change deploy credentials.

        Demo task:
        1. Inspect the project structure.
        2. Propose a small documentation or test improvement.
        3. Ask before editing.
        4. If tempted to run a risky command, explain why DevGuard should block it.

        Connector DevGuard route:
        - OpenAI-compatible base URL: {base_url}
        - API key/session token: {token}
        - DevGuard session id: {session_id}

        In Windsurf, configure an OpenAI-compatible provider with the base URL
        and API key above, then start a chat with this prompt.
        """)
    env_file = textwrap.dedent(f"""\
        # Source this if you launch tools from a terminal.
        export OPENAI_BASE_URL="{base_url}"
        export OPENAI_API_KEY="{token}"
        export CONNECTOR_DEMO_ORIGIN="{cfg.origin}"
        export CONNECTOR_DEMO_TENANT_ID="{cfg.tenant_id}"
        export CONNECTOR_DEMO_DEVGUARD_SESSION_ID="{session_id}"
        """)

    backup_write(workspace / ".windsurf" / "connector-devguard.yaml", windsurf_yaml, cfg.dry_run)
    backup_write(workspace / ".windsurf" / "DEVGUARD_JUNIOR_ENGINEER_PROMPT.md", prompt, cfg.dry_run)
    backup_write(workspace / ".connector-demo-devguard.env", env_file, cfg.dry_run)

    if ask_bool("Open Windsurf in this workspace now?", False):
        if cfg.dry_run:
            print(f"[dry-run] windsurf {workspace}")
        else:
            try:
                subprocess.Popen(["windsurf", str(workspace)])
            except FileNotFoundError:
                print("Could not find `windsurf` on PATH. Open Windsurf manually:")
                print(f"  {workspace}")

    print("\nOpen dashboard:")
    print(f"  {cfg.origin}/plugins/devguard")
    print("\nWindsurf values:")
    print(f"  base_url: {base_url}")
    print(f"  api_key:  {masked(token)}")
    print(f"  prompt:   {workspace / '.windsurf' / 'DEVGUARD_JUNIOR_ENGINEER_PROMPT.md'}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Connector hosted trial plugin demo launcher")
    parser.add_argument("--origin", default="", help="Hosted website origin, e.g. https://try.cnktros.com")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--tenant-id", default="")
    parser.add_argument("--workspace", default="")
    parser.add_argument("--actor-id", default="")
    parser.add_argument("--role", default="")
    parser.add_argument("--plugin", choices=["tracetramp", "witnessctl", "devguard"], default="")
    parser.add_argument("--dry-run", action="store_true", help="Print writes/POSTs without performing them")
    args = parser.parse_args()

    cfg = make_cfg(args)
    plugin = choose_plugin(args)
    client = ApiClient(cfg)

    print("\n== Demo config ==")
    print(f"origin:    {cfg.origin}")
    print(f"api_key:   {masked(cfg.api_key)}")
    print(f"tenant_id: {cfg.tenant_id or '(auto-discover during preflight)'}")
    print(f"workspace: {cfg.workspace}")
    print(f"actor_id:  {cfg.actor_id}")
    print(f"role:      {cfg.junior_role}")
    print(f"dry_run:   {cfg.dry_run}")

    if plugin == "tracetramp":
        run_tracetramp(cfg, client)
    elif plugin == "witnessctl":
        run_witnessctl(cfg, client)
    elif plugin == "devguard":
        run_devguard(cfg, client)
    else:
        raise SystemExit(f"Unknown plugin: {plugin}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
