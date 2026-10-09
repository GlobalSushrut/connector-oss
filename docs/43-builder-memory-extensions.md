# 43 — Builder: Memory Extensions

> Custom memory types, enrichment pipelines, and knowledge graph integration.

---

## Custom Memory Types

Any string is a valid `ptype` (packet type). Build domain-specific vocabularies:

```python
# Medical domain types
MEDICAL_TYPES = {
    "phi_record":          "Full PHI — /p/ namespace only",
    "clinical_observation": "Clinical fact — LLM accessible",
    "lab_result":          "Lab values — LLM accessible",
    "diagnosis":           "ICD-10 coded diagnosis",
    "medication":          "Active medication",
    "allergy":             "Documented allergy",
    "procedure":           "Clinical procedure record",
    "summary":             "Generated clinical summary",
}

# Legal domain types
LEGAL_TYPES = {
    "contract_clause":     "Contract clause — LLM accessible",
    "obligation":          "Identified obligation",
    "risk_flag":           "Risk or liability flag",
    "jurisdiction":        "Applicable jurisdiction",
    "precedent":           "Case law reference",
}

# Write with domain type
p.write_memory(pid,
    "Patient has documented allergy to penicillin (anaphylaxis, 2019)",
    ptype="allergy",
    memory_type="evidence",
    tags=["hipaa", "allergy", f"patient:{patient_id}"],
    entity_kind="clinical_allergy")
```

---

## Memory Enrichment Pipeline

Add automatic enrichment when writing memory:

```python
import json

def enriched_write(pid, content: str, ptype: str, **kwargs) -> dict:
    """Write memory with automatic enrichment metadata."""

    # 1. PII scan before writing
    fw = p.firewall_inspect(pid, content, f"m/{pid}")
    if fw.get("pii_detected") and kwargs.get("memory_type") == "evidence":
        # Auto-tag with PII type
        tags = kwargs.get("tags", [])
        for pii_type in fw.get("pii_types", []):
            tags.append(f"pii:{pii_type}")
        kwargs["tags"] = tags

    # 2. Add enrichment metadata
    enriched_content = json.dumps({
        "content":     content,
        "pii_scanned": True,
        "pii_found":   fw.get("pii_detected"),
        "pii_types":   fw.get("pii_types", []),
        "enriched_at": now_iso()
    })

    # 3. Write
    result = p.write_memory(pid, enriched_content, ptype=ptype, **kwargs)

    # 4. Record enrichment decision
    p.record_decision(pid,
        f"memory.enriched.{ptype}",
        result.get("cid", ""),
        "written_with_enrichment")

    return result
```

---

## Semantic Memory Index

Build a custom semantic index for domain-specific retrieval:

```python
class DomainMemoryIndex:
    """Domain-specific memory index with custom retrieval."""

    def __init__(self, pid, ns, domain):
        self.pid    = pid
        self.ns     = ns
        self.domain = domain

    def write(self, content: str, entity_type: str, tags: list = None):
        return p.write_memory(self.pid, content,
                               ptype=f"{self.domain}.{entity_type}",
                               memory_type="semantic",
                               tags=(tags or []) + [self.domain, entity_type])

    def search(self, query: str, entity_type: str = None, top_k: int = 5):
        results = p.search_memory(self.ns, query, top_k=top_k)
        packets = results.get("packets", [])
        if entity_type:
            packets = [p for p in packets
                       if p.get("packet_type", "").endswith(entity_type)]
        return packets

    def recall_by_tag(self, tag: str, limit: int = 20):
        all_mem = p.recall_memory(self.ns, limit=limit, memory_type="semantic")
        return [pkt for pkt in all_mem.get("packets", [])
                if tag in pkt.get("tags", [])]

# Usage
medical_index = DomainMemoryIndex(pid, ns, "medical")
medical_index.write("Type 2 Diabetes treated with Metformin 500mg", "medication")
medical_index.write("HbA1c target < 7% for well-controlled diabetes", "protocol")

results = medical_index.search("diabetes medication")
```

---

## Working Memory Lifecycle

```python
class SessionMemory:
    """Manage working memory for a session."""

    def __init__(self, pid, ns, session_id):
        self.pid        = pid
        self.ns         = ns
        self.session_id = session_id
        self._packets   = []

    def push(self, content: str, step: str):
        """Push a step result to working memory."""
        cid = p.write_memory(self.pid,
            json.dumps({"step": step, "content": content}),
            ptype=f"step_{step}",
            memory_type="working",
            session_id=self.session_id)["cid"]
        self._packets.append(cid)
        return cid

    def recall_all(self):
        """Recall all working memory for this session."""
        return p.recall_memory(self.ns, limit=100,
                                session_id=self.session_id,
                                memory_type="working")["packets"]

    def to_context(self) -> str:
        """Convert working memory to LLM context string."""
        packets = self.recall_all()
        return "\n".join(
            f"[{pkt.get('packet_type', 'step')}] {json.loads(pkt['content'])['content']}"
            for pkt in packets
        )

    def commit_to_evidence(self):
        """Commit working memory to evidence (audit-grade)."""
        packets = self.recall_all()
        for pkt in packets:
            p.write_memory(self.pid,
                pkt["content"],
                ptype="committed_evidence",
                memory_type="evidence",
                session_id=self.session_id)
```

---

## Knowledge Graph Integration

Use the knowledge query API to pull structured facts:

```python
def build_rag_context(pid, query: str, max_tokens: int = 2000) -> str:
    """Build a RAG context from the knowledge graph."""

    # 1. Extract entities from query using LLM
    entity_response = p.invoke_chat(pid, f"m/{pid}",
        f"Extract 2-3 key entities from: '{query}'. "
        f"Return as comma-separated list only.")
    entities = [e.strip() for e in
                entity_response["choices"][0]["message"]["content"].split(",")]

    # 2. Query knowledge graph
    knowledge = p.query_knowledge(
        entities=entities,
        keywords=query.split()[:5],
        token_budget=max_tokens,
        max_facts=10
    )

    # 3. Build context string
    facts = knowledge.get("facts", [])
    if not facts:
        return ""

    context_parts = [f"- {fact['content']}" for fact in facts[:8]]
    return "Relevant knowledge:\n" + "\n".join(context_parts)
```

---

## Memory Versioning

Track versions of evolving data:

```python
def versioned_write(pid, content: str, entity_id: str, version: int, **kwargs):
    """Write a versioned memory packet."""
    return p.write_memory(pid,
        json.dumps({
            "entity_id": entity_id,
            "version":   version,
            "content":   content,
            "supersedes": f"{entity_id}_v{version-1}" if version > 1 else None
        }),
        ptype="versioned_data",
        tags=[f"entity:{entity_id}", f"version:{version}"],
        **kwargs)

# Write versions
versioned_write(pid, "Patient weight: 85kg", "patient_weight", 1)
versioned_write(pid, "Patient weight: 83kg", "patient_weight", 2)  # updated

# Recall latest version
packets = p.recall_memory(ns, limit=10, memory_type="evidence")["packets"]
latest = max([p for p in packets if "entity:patient_weight" in p.get("tags", [])],
             key=lambda x: x.get("timestamp", ""))
```

---

## Next Steps

- **[44 — Builder: Custom Guard Layers](44-builder-firewall-layers.md)**
- **[15 — Ring 4: Memory Kernel](15-ring-4-memory-kernel.md)**
- **[57 — Knowledge System](57-knowledge-system.md)**
