"""
Patient Triage Agent — CLS Contract Executor Runtime.

This agent is a contract executor, NOT a script with business logic.
All behavior is defined in contract.yaml and enforced by the kernel.

Architecture:
    contract.yaml → ClsCompiler → SolutionContract → ContractExecutor → ExecutionReceipt
    agent.py = runtime shell (identity + kernel connection + contract loading)

10 Key Outcomes:
    1. Agent = contract executor, not script logic
    2. Clear separation: agent.py = runtime, contract = behavior, kernel = enforcement
    3. Deterministic + governed execution
    4. Built-in auditability and receipts
    5. Standardized agent structure (all agents follow this pattern)
    6. Plug-and-play: change contract → behavior changes
    7. Enterprise-grade control (budgets, policies, permissions)
    8. Multi-agent collaboration becomes native
    9. Debugging = traceable + replayable
    10. Agents become infrastructure, not experiments
"""

import json
import os
import time
import hashlib
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, field

import yaml
import httpx


# ═══════════════════════════════════════════════════════════════
# Agent Identity
# ═══════════════════════════════════════════════════════════════

AGENT_DIR = Path(__file__).parent
AGENT_NAME = "patient_triage"
AGENT_VERSION = "1.0.0"
AGENT_DOMAIN = "medical"


@dataclass
class AgentIdentity:
    """Immutable agent identity — who this agent is."""
    name: str = AGENT_NAME
    version: str = AGENT_VERSION
    domain: str = AGENT_DOMAIN
    agent_pid: str = ""
    session_id: str = ""
    roles: list[str] = field(default_factory=lambda: ["triage_nurse", "medical_staff"])

    def __post_init__(self):
        if not self.agent_pid:
            self.agent_pid = f"agent-{self.name}-{int(time.time() * 1000) & 0xFFFF:04x}"
        if not self.session_id:
            self.session_id = f"sess-{self.name}-{int(time.time() * 1000) & 0xFFFF:04x}"


# ═══════════════════════════════════════════════════════════════
# Kernel Connection
# ═══════════════════════════════════════════════════════════════

class KernelConnection:
    """
    Connects the agent to the Connector kernel (Rust backend).

    In production, this communicates with the kernel via the Connector API.
    The kernel handles: contract compilation, execution, governance enforcement,
    resource budgeting, tool dispatch, memory access, and receipt generation.
    """

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.client = httpx.Client(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "X-Agent-Protocol": "CLS/1.0",
            },
            timeout=60.0,
        )

    def compile_contract(self, contract_yaml: str) -> dict:
        """Send contract YAML to kernel for compilation → SolutionContract."""
        resp = self.client.post("/v1/cls/compile", json={"yaml": contract_yaml})
        resp.raise_for_status()
        return resp.json()

    def register_contract(self, contract: dict) -> str:
        """Register a compiled contract in the kernel registry."""
        resp = self.client.post("/v1/cls/registry/register", json=contract)
        resp.raise_for_status()
        return resp.json()["cid"]

    def execute_contract(
        self,
        contract_cid: str,
        agent_pid: str,
        session_id: str,
        inputs: dict,
        roles: list[str] | None = None,
    ) -> dict:
        """Execute a contract through the kernel, returning the ExecutionReceipt."""
        payload = {
            "contract_cid": contract_cid,
            "agent_pid": agent_pid,
            "session_id": session_id,
            "inputs": inputs,
        }
        if roles:
            payload["roles"] = roles
        resp = self.client.post("/v1/cls/execute", json=payload)
        resp.raise_for_status()
        return resp.json()

    def get_receipt(self, receipt_cid: str) -> dict:
        """Retrieve an execution receipt by CID."""
        resp = self.client.get(f"/v1/cls/receipts/{receipt_cid}")
        resp.raise_for_status()
        return resp.json()

    def close(self):
        self.client.close()


# ═══════════════════════════════════════════════════════════════
# Local Executor (standalone mode — no kernel connection)
# ═══════════════════════════════════════════════════════════════

class LocalExecutor:
    """
    Executes contracts locally using Python implementations of the
    tool/LLM/memory handlers. Used for development, testing, and
    environments where the Rust kernel is not available.

    This mirrors the Rust ContractExecutor but in Python.
    """

    def __init__(self, tools: dict, llm_handler=None, memory_store: dict | None = None):
        self.tools = tools  # tool_id → callable
        self.llm_handler = llm_handler
        self.memory: dict[str, list] = memory_store or {}
        self.receipt_chain: list[dict] = []

    def execute(self, contract: dict, identity: AgentIdentity, inputs: dict) -> dict:
        """Execute a contract locally, returning a receipt dict."""
        start_time = time.time()
        ctx = ExecutionContext(
            contract_id=contract.get("name", "unknown"),
            agent_pid=identity.agent_pid,
            session_id=identity.session_id,
            roles=identity.roles,
            variables=dict(inputs),
            resource_limits=contract.get("budget", {}),
        )

        # Walk steps sequentially (simplified — full DAG execution in Rust kernel)
        steps = contract.get("steps", [])
        outcome = "success"
        final_state = contract.get("states", {}).get("initial", "init")

        step_index = {s["id"]: i for i, s in enumerate(steps)}
        i = 0
        skip_to: str | None = None

        while i < len(steps):
            step = steps[i]

            # Handle skip (from branch)
            if skip_to is not None:
                if step["id"] != skip_to:
                    i += 1
                    continue
                skip_to = None

            ctx.trace.append({"node_id": step["id"], "timestamp": time.time()})

            # Budget check
            budget_check = ctx.check_budget()
            if budget_check:
                outcome = f"budget_exceeded:{budget_check}"
                break

            try:
                result = self._execute_step(step, ctx)
            except Exception as e:
                outcome = f"failed:{e}"
                break

            # Handle step result
            if result.get("type") == "transition":
                final_state = result["to_state"]
                terminals = contract.get("states", {}).get("terminal", [])
                if final_state in terminals:
                    i += 1
                    continue
            elif result.get("type") == "branch":
                skip_to = result.get("target")
            elif result.get("type") == "next":
                next_ids = result.get("next", [])
                if next_ids and next_ids[0] in step_index:
                    i = step_index[next_ids[0]]
                    continue

            i += 1

        duration_ms = int((time.time() - start_time) * 1000)

        # Build receipt
        receipt = self._build_receipt(contract, ctx, outcome, final_state, duration_ms)
        self.receipt_chain.append(receipt)
        return receipt

    def _execute_step(self, step: dict, ctx: "ExecutionContext") -> dict:
        step_type = step.get("type", "")

        if step_type == "tool_call":
            return self._exec_tool_call(step, ctx)
        elif step_type == "llm_infer":
            return self._exec_llm_infer(step, ctx)
        elif step_type == "mem_read":
            return self._exec_mem_read(step, ctx)
        elif step_type == "mem_write":
            return self._exec_mem_write(step, ctx)
        elif step_type == "branch":
            return self._exec_branch(step, ctx)
        elif step_type == "set_var":
            return self._exec_set_var(step, ctx)
        elif step_type == "transition":
            return self._exec_transition(step, ctx)
        elif step_type == "emit_event":
            return self._exec_emit_event(step, ctx)
        elif step_type == "checkpoint":
            return {"type": "continue"}
        else:
            return {"type": "continue"}

    def _exec_tool_call(self, step: dict, ctx: "ExecutionContext") -> dict:
        tool_id = step.get("tool", "")
        ctx.use_resource("tool_calls", 1)
        output_var = step.get("output", f"{step['id']}_result")

        # Resolve params
        params = {}
        skip_keys = {"id", "label", "type", "tool", "output", "next", "precondition", "postcondition"}
        for k, v in step.items():
            if k not in skip_keys:
                params[k] = ctx.resolve(v) if isinstance(v, str) else v

        if tool_id in self.tools:
            result = self.tools[tool_id](**params)
        else:
            result = {"tool": tool_id, "params": params, "status": "stub", "mock": True}

        ctx.variables[output_var] = result
        return {"type": "next", "next": step.get("next", [])}

    def _exec_llm_infer(self, step: dict, ctx: "ExecutionContext") -> dict:
        prompt_template = step.get("prompt", "")
        input_vars = step.get("inputs", [])
        output_var = step.get("output", f"{step['id']}_result")
        max_tokens = step.get("max_tokens", 1024)

        # Build prompt with context
        prompt_parts = [prompt_template]
        for var in input_vars:
            val = ctx.variables.get(var)
            if val is not None:
                prompt_parts.append(f"\n## {var}\n{json.dumps(val, default=str)}")
        full_prompt = "\n".join(prompt_parts)

        if self.llm_handler:
            response, tokens_used = self.llm_handler(full_prompt, max_tokens)
        else:
            tokens_used = min(len(full_prompt) // 4, max_tokens)
            response = f"[LLM assessment based on {len(input_vars)} inputs, {tokens_used} tokens]"

        ctx.use_resource("tokens", tokens_used)
        ctx.variables[output_var] = response
        return {"type": "next", "next": step.get("next", [])}

    def _exec_mem_read(self, step: dict, ctx: "ExecutionContext") -> dict:
        namespace = step.get("namespace", "")
        query = ctx.resolve(step.get("query", ""))
        output_var = step.get("output", f"{step['id']}_result")
        max_results = step.get("max_results", 10)

        records = self.memory.get(namespace, [])[:max_results]
        ctx.variables[output_var] = records
        return {"type": "continue"}

    def _exec_mem_write(self, step: dict, ctx: "ExecutionContext") -> dict:
        namespace = step.get("namespace", "")
        content_var = step.get("content", "")
        content = ctx.variables.get(content_var, {})
        tags = step.get("tags", [])

        self.memory.setdefault(namespace, []).append({
            "content": content,
            "tags": tags,
            "timestamp": time.time(),
        })
        return {"type": "continue"}

    def _exec_branch(self, step: dict, ctx: "ExecutionContext") -> dict:
        precondition = step.get("precondition", {})
        taken = ctx.evaluate_predicate(precondition)
        target = step.get("then") if taken else step.get("else")
        if target:
            return {"type": "branch", "target": target}
        return {"type": "continue"}

    def _exec_set_var(self, step: dict, ctx: "ExecutionContext") -> dict:
        var_name = step.get("var", "")
        value = step.get("value")
        if isinstance(value, str):
            value = ctx.resolve(value)
        ctx.variables[var_name] = value
        return {"type": "next", "next": step.get("next", [])}

    def _exec_transition(self, step: dict, ctx: "ExecutionContext") -> dict:
        return {"type": "transition", "to_state": step.get("to", "")}

    def _exec_emit_event(self, step: dict, ctx: "ExecutionContext") -> dict:
        event_type = step.get("event", "")
        data_vars = step.get("data", [])
        data = {v: ctx.variables.get(v) for v in data_vars}
        ctx.events.append({"type": event_type, "data": data, "timestamp": time.time()})
        return {"type": "continue"}

    def _build_receipt(self, contract: dict, ctx: "ExecutionContext", outcome: str, final_state: str, duration_ms: int) -> dict:
        # Collect outputs
        output_defs = contract.get("outputs", [])
        outputs = {o["name"]: ctx.variables.get(o["name"]) for o in output_defs if o["name"] in ctx.variables}

        receipt_data = {
            "contract": contract.get("name"),
            "version": contract.get("version"),
            "outcome": outcome,
            "final_state": final_state,
            "trace": ctx.trace,
            "agent_pid": ctx.agent_pid,
        }
        receipt_cid = "cls1-sha256-" + hashlib.sha256(json.dumps(receipt_data, default=str).encode()).hexdigest()

        previous_cid = self.receipt_chain[-1]["receipt_cid"] if self.receipt_chain else None

        return {
            "receipt_id": f"rcpt-{int(time.time() * 1000):016x}",
            "contract_id": contract.get("name"),
            "contract_version": contract.get("version"),
            "agent_pid": ctx.agent_pid,
            "session_id": ctx.session_id,
            "outcome": outcome,
            "final_state": final_state,
            "outputs": outputs,
            "resource_usage": dict(ctx.resource_usage),
            "trace": ctx.trace,
            "events": ctx.events,
            "duration_ms": duration_ms,
            "previous_receipt_cid": previous_cid,
            "receipt_cid": receipt_cid,
            "timestamp": time.time(),
        }


# ═══════════════════════════════════════════════════════════════
# Execution Context (Python mirror of Rust ExecutionContext)
# ═══════════════════════════════════════════════════════════════

class ExecutionContext:
    """Runtime state during contract execution."""

    def __init__(self, contract_id: str, agent_pid: str, session_id: str,
                 roles: list[str], variables: dict, resource_limits: dict):
        self.contract_id = contract_id
        self.agent_pid = agent_pid
        self.session_id = session_id
        self.roles = roles
        self.variables = variables
        self.resource_limits = resource_limits
        self.resource_usage: dict[str, float] = {}
        self.trace: list[dict] = []
        self.events: list[dict] = []
        self.started_at = time.time()

    def resolve(self, value: str) -> Any:
        """Resolve ${var_name} references in a string."""
        if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
            var_name = value[2:-1]
            return self.variables.get(var_name, value)
        return value

    def use_resource(self, resource: str, amount: float):
        self.resource_usage[resource] = self.resource_usage.get(resource, 0) + amount

    def check_budget(self) -> str | None:
        """Returns the violated resource name, or None if OK."""
        for resource, limit in self.resource_limits.items():
            used = self.resource_usage.get(resource, 0)
            if isinstance(limit, (int, float)) and used > limit:
                return resource
        return None

    def evaluate_predicate(self, predicate: dict) -> bool:
        """Evaluate a predicate against current context."""
        pred_type = predicate.get("type", "always")

        if pred_type == "always":
            return True
        elif pred_type == "never":
            return False
        elif pred_type == "field_present":
            field_name = predicate.get("field", "")
            return field_name in self.variables and self.variables[field_name] is not None
        elif pred_type == "field_equals":
            field_name = predicate.get("field", "")
            return self.variables.get(field_name) == predicate.get("value")
        elif pred_type == "field_gt":
            field_name = predicate.get("field", "")
            val = self.variables.get(field_name)
            threshold = predicate.get("value", 0)
            if isinstance(val, (int, float)):
                return val > threshold
            return False
        elif pred_type == "field_lt":
            field_name = predicate.get("field", "")
            val = self.variables.get(field_name)
            threshold = predicate.get("value", 0)
            if isinstance(val, (int, float)):
                return val < threshold
            return False
        elif pred_type == "has_role":
            return predicate.get("role", "") in self.roles
        elif pred_type == "and":
            return all(self.evaluate_predicate(p) for p in predicate.get("predicates", []))
        elif pred_type == "or":
            return any(self.evaluate_predicate(p) for p in predicate.get("predicates", []))
        elif pred_type == "not":
            return not self.evaluate_predicate(predicate.get("predicate", {}))
        else:
            return True  # Unknown predicates pass (domain kernel handles them)


# ═══════════════════════════════════════════════════════════════
# Agent — the main entry point
# ═══════════════════════════════════════════════════════════════

class PatientTriageAgent:
    """
    Patient Triage Agent — a contract executor.

    This agent does NOT contain business logic. It:
      1. Loads its contract (contract.yaml)
      2. Connects to the kernel (or uses local executor)
      3. Accepts inputs (patient_id, symptoms)
      4. Executes the contract through the kernel
      5. Returns the ExecutionReceipt (verifiable proof)

    To change behavior: edit contract.yaml, NOT this file.
    """

    def __init__(
        self,
        kernel_url: str | None = None,
        api_key: str | None = None,
        tools: dict | None = None,
        llm_handler=None,
    ):
        self.identity = AgentIdentity()
        self.contract = self._load_contract()
        self.receipts_dir = AGENT_DIR / "receipts"
        self.receipts_dir.mkdir(exist_ok=True)

        # Connect to kernel or use local executor
        if kernel_url and api_key:
            self.kernel = KernelConnection(kernel_url, api_key)
            self.local_executor = None
            self.mode = "kernel"
        else:
            self.kernel = None
            from . import tools as default_tools
            resolved_tools = tools or default_tools.get_tool_registry()
            self.local_executor = LocalExecutor(
                tools=resolved_tools,
                llm_handler=llm_handler,
            )
            self.mode = "local"

    def _load_contract(self) -> dict:
        """Load the contract.yaml that defines this agent's behavior."""
        contract_path = AGENT_DIR / "contract.yaml"
        with open(contract_path) as f:
            return yaml.safe_load(f)

    def run(self, patient_id: str, symptoms: str, vitals: dict | None = None) -> dict:
        """
        Execute the triage contract for a patient.

        This is the ONLY public method. All behavior comes from the contract.

        Args:
            patient_id: Patient identifier
            symptoms: Chief complaint / symptoms description
            vitals: Optional vital signs dict

        Returns:
            ExecutionReceipt — full audit trail of the execution
        """
        inputs = {
            "patient_id": patient_id,
            "symptoms": symptoms,
        }
        if vitals:
            inputs["vitals"] = vitals

        if self.mode == "kernel":
            receipt = self._execute_via_kernel(inputs)
        else:
            receipt = self._execute_locally(inputs)

        # Persist receipt
        self._save_receipt(receipt)
        return receipt

    def _execute_via_kernel(self, inputs: dict) -> dict:
        """Execute through the Rust kernel (production mode)."""
        # Compile and register contract (kernel caches by CID)
        contract_yaml = (AGENT_DIR / "contract.yaml").read_text()
        compiled = self.kernel.compile_contract(contract_yaml)
        cid = self.kernel.register_contract(compiled)

        # Execute
        receipt = self.kernel.execute_contract(
            contract_cid=cid,
            agent_pid=self.identity.agent_pid,
            session_id=self.identity.session_id,
            inputs=inputs,
            roles=self.identity.roles,
        )
        return receipt

    def _execute_locally(self, inputs: dict) -> dict:
        """Execute locally with Python handlers (dev/test mode)."""
        return self.local_executor.execute(self.contract, self.identity, inputs)

    def _save_receipt(self, receipt: dict):
        """Save receipt to receipts/ directory."""
        # Save as latest.json
        latest_path = self.receipts_dir / "latest.json"
        with open(latest_path, "w") as f:
            json.dump(receipt, f, indent=2, default=str)

        # Also save timestamped copy
        ts = int(time.time() * 1000)
        ts_path = self.receipts_dir / f"receipt_{ts}.json"
        with open(ts_path, "w") as f:
            json.dump(receipt, f, indent=2, default=str)

    def get_latest_receipt(self) -> dict | None:
        """Load the most recent execution receipt."""
        latest_path = self.receipts_dir / "latest.json"
        if latest_path.exists():
            with open(latest_path) as f:
                return json.load(f)
        return None

    @property
    def contract_name(self) -> str:
        return self.contract.get("name", "unknown")

    @property
    def contract_version(self) -> str:
        return self.contract.get("version", "0.0.0")

    def close(self):
        if self.kernel:
            self.kernel.close()


# ═══════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════

def main():
    """Run the agent from command line."""
    import argparse

    parser = argparse.ArgumentParser(description="Patient Triage Agent (CLS Contract Executor)")
    parser.add_argument("--patient-id", required=True, help="Patient identifier")
    parser.add_argument("--symptoms", required=True, help="Chief complaint / symptoms")
    parser.add_argument("--vitals", type=json.loads, default=None, help="Vitals as JSON")
    parser.add_argument("--kernel-url", default=os.environ.get("CONNECTOR_URL"), help="Kernel API URL")
    parser.add_argument("--api-key", default=os.environ.get("CONNECTOR_API_KEY"), help="API key")
    args = parser.parse_args()

    agent = PatientTriageAgent(
        kernel_url=args.kernel_url,
        api_key=args.api_key,
    )

    receipt = agent.run(
        patient_id=args.patient_id,
        symptoms=args.symptoms,
        vitals=args.vitals,
    )

    print(json.dumps(receipt, indent=2, default=str))
    print(f"\n✓ Outcome: {receipt['outcome']}")
    print(f"  State: {receipt['final_state']}")
    print(f"  Duration: {receipt['duration_ms']}ms")
    print(f"  Receipt CID: {receipt['receipt_cid']}")

    agent.close()


if __name__ == "__main__":
    main()
