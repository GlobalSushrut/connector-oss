# 46 — Builder: RAG Patterns and Retrieval Pipelines

> Governed retrieval-augmented generation — ground every answer in verified memory.

---

## Governed RAG vs Standard RAG

| Standard RAG | Governed RAG |
|---|---|
| Retrieval from any store | Retrieval only from authorized namespaces |
| No PII check on context | Firewall inspect before LLM |
| No audit trail | Every retrieval logged with CID |
| No grounding verification | Every output checked against source |
| No proof of data minimization | `generate_proof` produces evidence |

---

## Pattern 1: Basic Governed RAG

```python
def governed_rag(pid: str, ns: str, query: str) -> dict:
    # 1. Retrieve relevant context
    search_results = p.search_memory(ns, query, top_k=5)
    packets = search_results.get("packets", [])

    if not packets:
        return {"answer": "No relevant context found.", "grounded": False}

    # 2. Build context string
    context = "\n\n".join([
        f"[Source: {pkt['cid'][:20]}...]\n{pkt['content']}"
        for pkt in packets
    ])

    # 3. Firewall check the assembled context
    fw = p.firewall_inspect(pid, context, ns)
    if fw["blocked"] or fw.get("pii_detected"):
        p.record_decision(pid, "rag.context_blocked", query[:60],
                          "denied", rationale=fw["final_decision"])
        return {"answer": "Context failed safety check.", "grounded": False}

    # 4. Governed LLM call with grounded prompt
    prompt = (
        f"Answer the question using ONLY the provided context.\n"
        f"Context:\n{context}\n\n"
        f"Question: {query}\n\n"
        f"If the answer is not in the context, say 'Not found in context.'"
    )
    response = p.invoke_chat(pid, ns, prompt)
    answer   = response["choices"][0]["message"]["content"]

    # 5. Verify grounding
    grounding = p.verify_grounding(text=answer)

    return {
        "answer":          answer,
        "grounded":        grounding.get("grounded", True),
        "grounding_score": grounding.get("grounding_score", 0),
        "source_cids":     [pkt["cid"] for pkt in packets],
        "audit_cid":       response.get("audit_cid"),
        "decision_id":     response.get("decision_id")
    }
```

---

## Pattern 2: Multi-Namespace RAG

Retrieve from multiple namespaces, with different access levels:

```python
def multi_ns_rag(pid: str, query: str, patient_id: str) -> dict:
    """
    RAG across knowledge base (LLM-safe) and working memory.
    Never touches /p/ directly — uses pre-built selective context.
    """
    # Retrieve from knowledge base (safe for LLM)
    knowledge = p.recall_memory("/k/medical", limit=10, memory_type="semantic")
    k_packets = knowledge.get("packets", [])

    # Retrieve from agent working memory (selective — no PHI)
    working = p.recall_memory(f"m/{pid}/patient_context/{patient_id}", limit=5)
    w_packets = working.get("packets", [])

    # Combine (knowledge + selective patient context)
    all_packets = k_packets + w_packets
    context = "\n".join([pkt["content"] for pkt in all_packets])

    # Verify no PHI leaked into context
    fw = p.firewall_inspect(pid, context, f"m/{pid}")
    assert not fw.get("pii_detected"), "PHI in context — abort"

    # Govern the LLM call
    response = p.invoke_chat(pid, f"m/{pid}", query)
    return {
        "answer": response["choices"][0]["message"]["content"],
        "sources": [pkt["cid"] for pkt in all_packets]
    }
```

---

## Pattern 3: Streaming RAG with Evidence Collection

```python
def streaming_rag_with_evidence(pid: str, ns: str, query: str) -> None:
    """
    Stream RAG response while collecting evidence.
    """
    evidence_cids = []
    session_id    = f"rag_{int(time.time())}"

    # 1. Write query to memory
    query_cid = p.write_memory(pid, query,
        ptype="rag_query", memory_type="evidence",
        session_id=session_id)["cid"]
    evidence_cids.append(query_cid)

    # 2. Retrieve context
    results  = p.search_memory(ns, query, top_k=8)
    packets  = results.get("packets", [])
    src_cids = [pkt["cid"] for pkt in packets]
    evidence_cids.extend(src_cids)

    # 3. Write context assembly to evidence
    ctx_cid = p.write_memory(pid,
        json.dumps({"query": query, "source_cids": src_cids}),
        ptype="rag_context", memory_type="evidence",
        session_id=session_id)["cid"]
    evidence_cids.append(ctx_cid)

    # 4. Governed LLM call
    context = "\n".join(pkt["content"] for pkt in packets)
    prompt  = f"Context:\n{context}\n\nAnswer: {query}"
    resp    = p.invoke_chat_raw(pid, ns, prompt)

    # 5. Record decision with all evidence
    p.record_decision(pid, "rag.response", query[:60], "delivered",
                      evidence_cids=evidence_cids,
                      confidence=0.90)

    answer = resp.get("body", {}).get("choices", [{}])[0] \
                 .get("message", {}).get("content", "")
    print(answer)
```

---

## Pattern 4: Self-Correcting RAG

```python
def self_correcting_rag(pid: str, ns: str, query: str, max_attempts: int = 3) -> dict:
    """
    If output is not grounded, retrieve more context and retry.
    """
    for attempt in range(max_attempts):
        top_k = 5 + (attempt * 3)   # increase context each attempt

        results  = p.search_memory(ns, query, top_k=top_k)
        context  = "\n".join(pkt["content"] for pkt in results.get("packets", []))
        response = p.invoke_chat(pid, ns,
            f"Based only on:\n{context}\n\nAnswer: {query}")
        answer   = response["choices"][0]["message"]["content"]

        grounding = p.verify_grounding(text=answer)
        if grounding.get("grounded"):
            p.record_decision(pid, "rag.grounded", query[:60], "delivered",
                              confidence=0.95,
                              rationale=f"Grounded on attempt {attempt+1}")
            return {"answer": answer, "attempt": attempt + 1,
                    "grounding_score": grounding.get("grounding_score")}

        # Not grounded — log and try again with more context
        p.record_decision(pid, "rag.ungrounded", query[:60], "retry",
                          rationale=f"Attempt {attempt+1}: grounding_score="
                                    f"{grounding.get('grounding_score', 0):.2f}")

    # Final attempt: return with flag
    return {"answer": answer, "attempt": max_attempts,
            "grounded": False, "warning": "Could not fully ground after N attempts"}
```

---

## Pattern 5: PHI-Safe Clinical RAG

```python
def clinical_rag_safe(pid: str, patient_id: str, clinical_question: str) -> dict:
    """
    Clinical RAG: uses selective patient context + medical knowledge.
    PHI never reaches LLM.
    """
    # Get clinical fields only (strips PHI at source)
    patient_ctx = get_selective_patient_context(patient_id)  # strips PHI

    # Get medical knowledge
    knowledge = p.query_knowledge(
        entities=[patient_ctx.get("diagnosis", "")],
        keywords=clinical_question.split()[:5],
        token_budget=1500)

    # Assemble safe context
    safe_context = {
        "patient": patient_ctx,    # no PHI
        "knowledge": knowledge.get("facts", [])
    }

    # Verify clean
    fw = p.firewall_inspect(pid, json.dumps(safe_context), f"m/{pid}")
    assert not fw.get("pii_detected"), "PHI in context"

    # Governed call
    response = p.invoke_chat(pid, f"m/{pid}",
        f"Clinical context: {json.dumps(safe_context)}\n\n"
        f"Clinical question: {clinical_question}")

    p.record_decision(pid, "clinical_rag", clinical_question[:60],
                      "delivered", regulations=["hipaa"])

    return {"answer": response["choices"][0]["message"]["content"],
            "audit_cid": response.get("audit_cid")}
```

---

## RAG Quality Metrics

```python
def measure_rag_quality(results: list) -> dict:
    """Compute quality metrics for a batch of RAG results."""
    grounded       = [r for r in results if r.get("grounded")]
    grounding_scores = [r.get("grounding_score", 0) for r in results]

    return {
        "total":            len(results),
        "grounded":         len(grounded),
        "grounded_pct":     len(grounded) / len(results) if results else 0,
        "avg_grounding_score": sum(grounding_scores) / len(grounding_scores) if grounding_scores else 0,
        "avg_sources_used": sum(len(r.get("source_cids", [])) for r in results) / len(results)
    }
```

---

## Next Steps

- **[17 — Ring 6: Reasoning](17-ring-6-reasoning-llm.md)**
- **[47 — Builder: Real Execution Control](47-builder-real-execution-control.md)**
- **[57 — Knowledge System](57-knowledge-system.md)**
