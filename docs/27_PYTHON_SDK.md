# Python SDK

> vac-ffi PyO3 bindings, Connector/AgentHandle classes
> Source: `vac/crates/vac-ffi/src/lib.rs`, `sdks/python/connector/`

---

## Architecture

```
Python code
    ↓
from vac_ffi import Connector   (PyO3 thin bindings)
    ↓
connector-api (Rust)            (Ring 4 — developer API)
    ↓
connector-engine (Rust)         (Ring 3 — orchestration)
    ↓
vac-core MemoryKernel (Rust)    (Ring 1 — memory kernel)
```

The Python SDK is a **thin PyO3 wrapper** — no Python reimplementation of crypto, kernel logic, or compliance. Every call crosses the FFI boundary into Rust.

---

## Installation

```bash
# Build the Rust FFI bridge
cd vac/crates/vac-ffi && maturin develop --release && cd ../../..

# Install Python wrapper
cd sdks/python && pip install -e . && cd ../..
```

---

## Connector Class

```python
from vac_ffi import Connector

# Create connector
c = Connector("deepseek", "deepseek-chat", "sk-...")
# or with custom endpoint:
c = Connector("deepseek", "deepseek-chat", "sk-...", endpoint="https://api.deepseek.com")

# Introspection
c.packet_count()    # int — total packets in kernel
c.audit_count()     # int — total audit entries
c.integrity_check() # (bool, int) — (all_ok, error_count)

# Kernel export (JSON string)
snap_json = c.kernel_export(10)  # last 10 audit entries
import json
snap = json.loads(snap_json)
# snap["stats"]["total_agents"]
# snap["stats"]["total_packets"]
# snap["stats"]["total_audit_entries"]
# snap["stats"]["total_sessions"]
# snap["stats"]["namespaces"]
# snap["agents"]   — list of AgentInfo
# snap["audit_tail"] — last N audit entries

# Create agent
agent = c.agent("bot", "You are helpful")
```

---

## AgentHandle Class

```python
agent = c.agent(name, instructions)

# Run (calls LLM + stores in kernel)
result = agent.run("What are the patient's allergies?", "user:alice")

# Result fields
result.text          # str — LLM response
result.trust         # int — trust score 0–100
result.trust_grade   # str — "A+" | "A" | "B" | "C" | "D" | "F"
result.ok            # bool — True if no errors
result.cid           # str — CID of response packet
result.trace_id      # str — pipeline trace ID
result.verified      # bool — True if all events kernel-verified
result.duration_ms   # int — total duration in milliseconds

# Observability
result.warnings      # List[str]
result.errors        # List[str]
result.actors        # List[str] — agent PIDs involved
result.steps         # List[str] — pipeline steps executed
result.event_count   # int — total ObservationEvents
result.span_count    # int — total Trace spans

# Export
result.to_json()         # str — JSON with provenance tags
result.to_otel()         # str — OTLP-compatible resource_spans
result.to_llm()          # str — LLM-friendly structured JSON
result.provenance()      # dict — kernel_verified, llm_unverified, total, trust_percentage
result.is_verified()     # bool — all_observations_verified()
```

---

## Full Example

```python
import os
from vac_ffi import Connector

# 1. Create connector
c = Connector(
    "deepseek",
    "deepseek-chat",
    os.environ["DEEPSEEK_API_KEY"]
)

# 2. Create agents
triage = c.agent("triage", "Classify patients by urgency 1-5.")
doctor = c.agent("doctor", "Diagnose based on triage data.")

# 3. Run triage
t_result = triage.run(
    "Patient: 45M, chest pain 2h, BP 158/95, diaphoresis",
    "patient:P-001"
)
print(f"Triage: {t_result.text}")
print(f"Trust:  {t_result.trust}/100 ({t_result.trust_grade})")
print(f"CID:    {t_result.cid}")

# 4. Run doctor (reads triage memory via AccessGrant)
d_result = doctor.run(
    "What is the diagnosis for patient P-001?",
    "patient:P-001"
)
print(f"Diagnosis: {d_result.text}")

# 5. Kernel stats
print(f"Packets: {c.packet_count()}")
print(f"Audit:   {c.audit_count()}")

# 6. Integrity check
ok, errors = c.integrity_check()
print(f"Integrity: {'PASS' if ok else 'FAIL'} ({errors} errors)")

# 7. Export kernel state
import json
snap = json.loads(c.kernel_export(5))
print(f"Agents: {snap['stats']['total_agents']}")
for entry in snap['audit_tail']:
    print(f"  [{entry['outcome']:8}] {entry['operation']:20} {entry['duration_us']}µs")
```

---

## YAML Config Loading

```python
# Load from connector.yaml
c = Connector.from_config("connector.yaml")

# Load from YAML string
yaml_str = """
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}
"""
c = Connector.from_config_str(yaml_str)
```

---

## sdks/python/connector/ (thin wrapper)

```python
# sdks/python/connector/__init__.py
try:
    from vac_ffi import Connector, AgentHandle, PipelineOutput
except ImportError:
    raise ImportError(
        "vac_ffi not found. Build it with:\n"
        "  cd vac/crates/vac-ffi && maturin develop --release"
    )
```

The Python package (`connector-agent`) re-exports from `vac_ffi`. No Python reimplementation.

---

## Error Handling

```python
from vac_ffi import (
    KernelError,
    KernelDenied,
    MountViolation,
    RateLimited,
    BudgetExceeded,
    ToolDenied,
    PhaseViolation,
    CidError,
    CodecError,
    AgentNotFound,
    PacketNotFound,
)

try:
    result = agent.run("...", "user:alice")
except KernelDenied as e:
    print(f"Access denied: {e}")
except BudgetExceeded as e:
    print(f"Budget exceeded: {e}")
except KernelError as e:
    print(f"Kernel error: {e}")
```

---

## Demo Files

| File | Description |
|------|-------------|
| `demos/python/01_hello_world.py` | Basic agent + kernel memory + CID provenance |
| `demos/python/02_hospital_er.py` | Multi-agent ER pipeline with HIPAA compliance |
| `demos/python/03_multi_agent.py` | Namespace isolation + AccessGrant demo |
| `demos/python/04_trust_score.py` | Trust score + compliance report demo |
| `demos/python/05_audit_trail.py` | Audit chain + integrity check demo |
