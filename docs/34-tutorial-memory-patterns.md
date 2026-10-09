# 34 — Tutorial: Memory Patterns

> Practical patterns for writing, recalling, and reasoning over memory.

---

## Memory Types in Practice

| Type | When to use | Retention |
|---|---|---|
| `working` | Session data, scratch space | Session lifetime |
| `evidence` | Audit-grade observations | Permanent |
| `episodic` | Events that happened | Permanent |
| `semantic` | Abstracted facts/knowledge | Permanent |

---

## Pattern 1: Session Working Memory

```python
session_id = "sess_patient_p001"

# Write session context at the start
p.write_memory(pid,
    json.dumps({"task": "patient_summary", "patient_id": "p001", "started_at": now_iso()}),
    ptype="session_start",
    memory_type="working",
    session_id=session_id,
    tags=["session_start"]
)

# Write intermediate steps
p.write_memory(pid,
    "Retrieved diagnosis: Type 2 Diabetes (onset 2018)",
    ptype="step_result",
    memory_type="working",
    session_id=session_id
)

# Recall everything from this session
session_mem = p.recall_memory(ns, limit=50, session_id=session_id)
packets = session_mem["packets"]
print(f"Session packets: {len(packets)}")
```

---

## Pattern 2: Evidence Chain for Audit

```python
def record_evidence_step(pid, ns, step_name, data, session_id, tags=None):
    """Write an audit-grade evidence packet."""
    cid = p.write_memory(pid,
        json.dumps({"step": step_name, "data": data, "timestamp": now_iso()}),
        ptype="evidence_step",
        memory_type="evidence",
        session_id=session_id,
        tags=(tags or []) + ["evidence_step", step_name]
    )["cid"]

    p.record_decision(pid, f"evidence.{step_name}",
                      session_id, "recorded",
                      confidence=1.0)
    return cid

# Example evidence chain
record_evidence_step(pid, ns, "data_retrieved",    {"source": "/p/patients/p001"}, session_id)
record_evidence_step(pid, ns, "pii_scanned",       {"pii_detected": False},         session_id)
record_evidence_step(pid, ns, "context_built",     {"fields_selected": 3},           session_id)
record_evidence_step(pid, ns, "llm_invoked",       {"model": "gpt-4o"},              session_id)
record_evidence_step(pid, ns, "output_surfaced",   {"grounding_score": 0.94},        session_id)
```

---

## Pattern 3: Selective Context for LLM

The key to PHI-safe RAG:

```python
def build_selective_context(patient_raw: dict) -> dict:
    """Extract only fields appropriate for LLM context."""
    ALLOWED_FIELDS = ["diagnosis", "medications", "lab_results",
                      "allergies", "relevant_history"]
    BLOCKED_FIELDS = ["name", "ssn", "dob", "address", "phone",
                      "email", "emergency_contact", "mrn"]

    selective = {}
    for field, value in patient_raw.items():
        if field in ALLOWED_FIELDS:
            selective[field] = value
        # BLOCKED_FIELDS are silently dropped — never reach LLM

    return selective

# Use in LLM call
patient = load_from_phi_namespace(patient_id)         # full record
context = build_selective_context(patient)             # stripped

fw = p.firewall_inspect(pid, json.dumps(context), ns)  # verify clean
assert not fw.get("pii_detected"), "PHI leaked into context"

response = p.invoke_chat(pid, ns,
    f"Summarize treatment for this patient: {json.dumps(context)}")
```

---

## Pattern 4: Knowledge Base Population

```python
MEDICAL_KNOWLEDGE = [
    ("Type 2 Diabetes is managed with diet, exercise, and medication such as Metformin.",
     ["diabetes", "treatment"]),
    ("HbA1c below 7% indicates good glycemic control.",
     ["diabetes", "lab_values", "hba1c"]),
    ("Metformin starting dose: 500mg twice daily with meals.",
     ["metformin", "dosage"]),
]

for fact, tags in MEDICAL_KNOWLEDGE:
    p.write_memory(pid, fact,
                   ptype="medical_fact",
                   memory_type="semantic",
                   tags=tags)

# Retrieve relevant knowledge
results = p.search_memory(ns, "Metformin dosage", top_k=3)
for pkt in results["packets"]:
    print(f"  {pkt['content']}")
```

---

## Pattern 5: Episodic Memory (Event Log)

```python
def log_event(pid, event_type: str, data: dict):
    """Write a timestamped event to episodic memory."""
    return p.write_memory(pid,
        json.dumps({"event": event_type, "data": data, "ts": now_iso()}),
        ptype="event",
        memory_type="episodic",
        tags=[f"event:{event_type}"]
    )

# Log key events
log_event(pid, "agent_started",    {"version": "1.0"})
log_event(pid, "task_received",    {"task": "patient_summary", "patient": "p001"})
log_event(pid, "task_completed",   {"duration_ms": 1450, "confidence": 0.95})
log_event(pid, "proof_generated",  {"proof_id": proof_id})

# Later: reconstruct the timeline
timeline = p.recall_memory(ns, limit=100, memory_type="episodic")
for pkt in sorted(timeline["packets"], key=lambda x: x["timestamp"]):
    evt = json.loads(pkt["content"])
    print(f"  [{evt['ts']}] {evt['event']}")
```

---

## Pattern 6: Contradiction Detection

```python
# Write two contradictory facts
p.write_memory(pid, "Patient is allergic to penicillin.")
p.write_memory(pid, "Patient takes amoxicillin (a penicillin-type antibiotic) daily.")

# Detect contradiction
interference = p.get_interference(pid)
if interference.get("count", 0) > 0:
    for conflict in interference["contradictions"]:
        print(f"⚠ Contradiction detected (score={conflict['conflict_score']:.2f}):")
        print(f"  A: {conflict['packet_a']['content']}")
        print(f"  B: {conflict['packet_b']['content']}")
        print(f"  Resolution: {conflict['resolution']}")
```

---

## Pattern 7: Memory-Grounded Responses

```python
def memory_grounded_answer(pid, ns, question: str) -> dict:
    # 1. Recall relevant memory
    relevant = p.search_memory(ns, question, top_k=5)
    context  = "\n".join(pkt["content"] for pkt in relevant["packets"])

    # 2. Build grounded prompt
    prompt = f"Given only this context:\n{context}\n\nAnswer: {question}"

    # 3. Firewall check
    fw = p.firewall_inspect(pid, prompt, ns)
    assert not fw["blocked"]

    # 4. Governed LLM call
    response = p.invoke_chat(pid, ns, prompt)
    content  = response["choices"][0]["message"]["content"]

    # 5. Verify grounding
    grounding = p.verify_grounding(text=content)
    if not grounding.get("grounded"):
        p.record_decision(pid, "answer.ungrounded", question[:60],
                          "flagged", rationale="Claim not in memory")

    return {
        "answer":          content,
        "grounding_score": grounding.get("grounding_score", 0),
        "source_cids":     grounding.get("supporting_cids", [])
    }
```

---

## Pattern 8: Namespace Cross-Referencing (Safe)

```python
# Agent can READ from /k/ (knowledge) and WRITE to /m/ (working)
# Never reads from /p/ (private)

knowledge = p.recall_memory("/k/medical/protocols", limit=10)
for pkt in knowledge["packets"]:
    # Process knowledge...
    p.write_memory(pid,
        f"Applied protocol: {pkt['content'][:100]}",
        memory_type="working")
```

---

## Memory Stats Check

```python
stats = p.get_agent_memory_stats(pid)
print(f"Total packets: {stats['total_packets']}")
print(f"By type: {stats['by_type']}")
print(f"Total bytes: {stats['total_bytes']:,}")
```

---

## Next Steps

- **[35 — Tutorial: Firewall Rules](35-tutorial-firewall-rules.md)**
- **[15 — Ring 4: Memory Kernel](15-ring-4-memory-kernel.md)**
- **[08 — Data Privacy Workflows](08-workflows-data-privacy.md)**
