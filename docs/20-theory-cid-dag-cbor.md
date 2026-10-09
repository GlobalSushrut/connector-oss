# 20 — CID, DAG, and CBOR

> Content-addressed identifiers, directed acyclic graph structure, and binary encoding.

---

## Content-Addressed Identifiers (CIDs)

A CID is the SHA-256 hash of the canonical serialization of a piece of data. Same content always produces the same CID. Changing one byte changes the CID entirely.

### CID Computation

```
1. Serialize content to canonical CBOR
2. SHA-256 hash the CBOR bytes
3. Base58 or hex encode
4. Prefix with namespace identifier
```

### CID Namespaces

| Prefix | Data Type | Example |
|---|---|---|
| `mem1-sha256-` | Memory packets | `mem1-sha256-3a4b5c6d7e8f...` |
| `cls1-sha256-` | Compiled CCL contracts | `cls1-sha256-abc123def456...` |
| `soe1-sha256-` | Surface output documents | `soe1-sha256-fedcba987654...` |

### Properties

- **Deterministic:** Same content → same CID, always, everywhere
- **Tamper-evident:** Any modification → different CID
- **Deduplication:** If a CID already exists in storage, the write is a no-op
- **Verifiable:** Anyone with the content can verify the CID independently

### Computing a CID (Python)

```python
import hashlib, cbor2, base64

def compute_cid(content: str) -> str:
    data = cbor2.dumps({"content": content}, canonical=True)
    hash_bytes = hashlib.sha256(data).digest()
    hex_hash   = hash_bytes.hex()
    return f"mem1-sha256-{hex_hash}"
```

---

## DAG (Directed Acyclic Graph) Structure

Memory packets and contracts form a DAG where each node can reference other nodes by CID:

```
Proof Bundle (prf_uuid)
    │
    ├── Decision Record (dec_uuid)
    │       └── Memory Packet (mem1-sha256-...)
    │
    ├── Journal Entries (seq 1–247)
    │       └── each entry: prev_hmac → this_hmac
    │
    └── Receipts (rec_uuid)
            └── prev_receipt → this_receipt
```

**Key property:** Following CID references always leads to the same content — there are no broken links (no "dangling pointers"). A CID that doesn't resolve means data was deleted or never existed.

### Partial Verification

Because the structure is a DAG, you can verify a subtree without reading the full graph:

```python
# Verify a specific decision record without loading the full proof
decision_cid = "mem1-sha256-abc..."
decision_data = fetch_by_cid(decision_cid)
computed_cid  = compute_cid(decision_data["content"])
assert computed_cid == decision_cid, "Tamper detected"
```

---

## CBOR Encoding

CBOR (Concise Binary Object Representation, RFC 7049) is used for all kernel data.

### Why CBOR Over JSON

| Property | JSON | CBOR |
|---|---|---|
| Encoding | Text | Binary |
| Size | Larger | ~30–60% smaller |
| Canonical | No (key order varies) | Yes (deterministic) |
| Types | Limited | Rich (bytes, integers, floats, maps) |
| Speed | Slower parse | Faster parse |

**Critical property:** CBOR has a *canonical* encoding mode where map keys are sorted deterministically. This ensures the same logical data always produces the same bytes, which is required for CID computation.

### CBOR in Practice

```python
import cbor2

# Encode
data = {"agent_pid": "agent_abc", "content": "Hello", "timestamp": 1713296400}
encoded = cbor2.dumps(data, canonical=True)   # canonical = sorted keys

# Decode
decoded = cbor2.loads(encoded)

# CID
cid = "mem1-sha256-" + hashlib.sha256(encoded).hexdigest()
```

---

## Prolly Tree Structure

For ordered memory ranges (e.g., time-series memory queries), Connector uses a **Prolly Tree** (probabilistic B-tree):

- Keys are content-addressed
- Leaf nodes contain actual memory packets
- Internal nodes contain CIDs of subtrees
- Splitting is probabilistic (based on hash of content)

**Properties:**
- Same content → same tree structure (deterministic)
- Range queries without full table scan
- Incremental verification: changed subtrees have different root CIDs

---

## CID Collision Properties

SHA-256 collision probability for practical data volumes:

| Documents | Collision Probability |
|---|---|
| 1 million | ~10⁻⁶³ |
| 1 billion | ~10⁻⁵⁷ |
| All internet data | ~10⁻⁴⁰ |

SHA-256 collisions are computationally infeasible with current hardware. The CID uniqueness guarantee is cryptographically sound.

---

## Inter-CID References

Memory packets can reference other packets:

```json
{
  "cid": "mem1-sha256-abc...",
  "content": "Summary of patient record",
  "source_cids": [
    "mem1-sha256-def...",    // references the original record
    "mem1-sha256-ghi..."     // references the diagnosis code lookup
  ],
  "namespace": "m/summarizer/output"
}
```

This creates a provenance chain: the summary can be traced back to its source data by following CID references.

---

## Next Steps

- **[21 — Cryptographic Proofs](21-theory-cryptographic-proofs.md)**
- **[15 — Ring 4: Memory Kernel](15-ring-4-memory-kernel.md)**
- **[60 — Chains 1–3](60-chains-audit-memory-dehall.md)**
