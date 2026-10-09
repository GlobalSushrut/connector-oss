# 17 — Ring 6: Reasoning and LLM Interface

> Selective context, grounding verification, and the 11-layer cognitive pipeline.

---

## The Governed Chat Path

Every call to `/v1/chat/completions` through Connector differs from a raw LLM call in five ways:

| Raw LLM Call | Connector Governed Call |
|---|---|
| Your code sends everything to the LLM | Selective context construction — LLM sees only what it needs |
| No pre-call validation | 5-layer firewall on every message |
| LLM output is final | Grounding verification on every output |
| No audit trail | `audit_cid` + `decision_id` on every response |
| No cost governance | Budget enforced before call |

---

## Selective Context Construction

**The most important privacy mechanism in the system.**

The system holds the full agent state (including PHI in `/p/`). The LLM receives only a *selective* subset — what the specific task requires.

```
Full Agent Context (Ring 4 memory)        LLM Context Window
──────────────────────────────────        ──────────────────
/p/patients/p001/                         "Patient context:"
  name: John Doe                ✗         "  Diagnosis: Type 2 Diabetes"
  ssn: 123-45-6789              ✗         "  Medications: Metformin 500mg"
  dob: 1970-01-01               ✗         "  Recent HbA1c: 7.2%"
  address: 123 Main St          ✗
  diagnosis: Type 2 Diabetes    ✓    ──►
  medications: Metformin 500mg  ✓
  lab_hba1c: 7.2%               ✓
  emergency_contact: ...        ✗
```

The `✓` fields are selected by the CCL contract's `memory` block — everything else is fenced by Ring 4.

---

## LLM Router (`llm_router.rs`)

Routes requests to the appropriate model with fallback:

```yaml
llm:
  providers:
    openai:
      model: gpt-4o
      priority: 1
      max_tokens: 4096
    anthropic:
      model: claude-3-5-sonnet-20241022
      priority: 2
    ollama:
      model: llama3.2
      priority: 3     # local fallback
  routing:
    strategy: priority    # or: cost_optimized, latency_optimized
    circuit_breaker:
      failure_threshold: 3
      recovery_seconds: 60
    retry:
      max_attempts: 3
      backoff_ms: 500
```

---

## Grounding Verification (`grounding.rs`)

After the LLM responds, Ring 6 checks whether the output is **grounded** in memory:

```python
result = p.verify_grounding(
    text="The patient's HbA1c of 7.2% indicates well-controlled diabetes.",
    categories=["clinical_facts"]
)
# {
#   "grounded": true,
#   "grounding_score": 0.94,
#   "supporting_cids": ["mem1-sha256-abc..."],
#   "ungrounded_claims": []
# }
```

If the LLM makes a claim not supported by any memory packet:
- `grounded: false`
- `ungrounded_claims: ["The patient's HbA1c is 7.2%"]` (if no supporting memory)
- Output is **withheld** (not surfaced) if strict mode is enabled

---

## Claims Verification

```python
result = p.verify_claims(
    claims=["The patient has Type 2 Diabetes"],
    source_text="Patient record shows: dx: Type 2 Diabetes, onset 2018"
)
# {"verified": true, "verified_claims": [...], "failed_claims": []}
```

---

## The 11-Layer Cognitive Pipeline

The `cognitive/` module implements an 11-layer reasoning pipeline for complex agent decisions:

```
Layer 1:  Perception       — parse incoming signal / query
Layer 2:  Meaning          — extract semantic intent
Layer 3:  Tension          — identify competing pressures / goals
Layer 4:  Possibility      — enumerate possible responses
Layer 5:  Evaluation       — score options against policy and memory
Layer 6:  Commitment       — select and commit to a plan
Layer 7:  Plan             — sequence the steps
Layer 8:  Action           — execute the plan (triggers Ring 7)
Layer 9:  Reflection       — compare expected vs actual outcome
Layer 10: Learning         — update memory with new observations
Layer 11: Expression       — format output for Ring 9 surface
```

**Tension drives cognition:** Layer 3 (`tension.rs`) identifies competing pressures. Without tension (no competing goals), no reasoning happens — the system defaults to the safe path.

**Commitment persistence** (`commitment.rs`): Once committed to a plan, the agent continues even under mild contradiction — unless contradiction exceeds threshold, which triggers Layer 9 reflection.

---

## Dehallucination

When the LLM makes a claim that cannot be traced to a memory packet:

1. Grounding check fails (`grounded: false`)
2. Dehallucination chain node created: `ChainNodeType::Dehallucination`
3. Output marked as `ungrounded`
4. In strict mode: output is withheld, decision recorded as `deny_ungrounded`

```python
# Check if last LLM output was grounded
fw = p.get_verify_report()
# Look for: executive_summary.invariants_passed
# "Dehallucination chain: intact" = all claims were grounded
```

---

## `invoke_chat` vs `invoke_chat_raw`

```python
# invoke_chat — raises on 4xx, returns parsed body
response = p.invoke_chat(pid, ns, prompt)
content = response["choices"][0]["message"]["content"]

# invoke_chat_raw — never raises, returns full HTTP response
result = p.invoke_chat_raw(pid, ns, prompt)
if not result["ok"]:
    print(f"HTTP {result['status_code']}: {result['body']}")
```

---

## Response Fields

Every governed chat response includes standard OpenAI fields **plus**:

```json
{
  "choices": [{"message": {"role": "assistant", "content": "..."}}],
  "model": "gpt-4o",
  "usage": {"prompt_tokens": 120, "completion_tokens": 85},
  "audit_cid": "mem1-sha256-...",
  "decision_id": "dec_uuid...",
  "grounding_score": 0.94,
  "namespace": "m/my-agent"
}
```

---

## Next Steps

- **[18 — Ring 7: Tool Execution](18-ring-7-tool-execution.md)**
- **[World cage — LLM vendor cut and Landlock Talk](WORLD_CAGE_AND_BROWSER.md)**
- **[22 — Cognitive Substrate Theory](22-theory-cognitive-substrate.md)**
- **[46 — Builder: RAG Patterns](46-builder-rag-retrieval.md)**
