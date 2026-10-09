# 21 — Cryptographic Proofs: HMAC Chains, Merkle Trees, and Ed25519

> The full cryptographic stack that makes Connector's claims provable.

---

## HMAC-SHA256 Journal Chains

### Chain Construction

```
Entry N:
  prev_hmac = hmac(entry N-1)
  payload   = {seq, event_type, data, timestamp}
  hmac      = HMAC-SHA256(key=prev_hmac, msg=canonical_cbor(payload))
```

The HMAC key at each step is the HMAC of the previous step. This creates a **forward-chained** structure where:
- Entry N cannot be forged without knowing `hmac(N-1)`
- `hmac(N-1)` cannot be forged without knowing `hmac(N-2)`
- ...continuing back to the genesis entry (known only to the node keypair)

### Chain Verification (Python)

```python
import hmac, hashlib, cbor2

def verify_chain(entries: list) -> bool:
    prev_hmac = b"genesis"  # initial key
    for entry in entries:
        payload = cbor2.dumps({
            "seq":        entry["seq_no"],
            "event_type": entry["action"],
            "outcome":    entry["outcome"],
            "timestamp":  entry["timestamp"]
        }, canonical=True)
        expected = hmac.new(prev_hmac, payload, hashlib.sha256).digest().hex()
        if expected != entry["hmac"]:
            print(f"Chain break at seq {entry['seq_no']}")
            return False
        prev_hmac = expected.encode()
    return True

journal = p.get_books_journal(limit=1000)
print("Chain valid:", verify_chain(journal["entries"]))
```

### Chain Break Detection

If any entry is modified, deleted, or inserted, the HMAC chain breaks. This is immediately detectable:

```python
journal = p.get_books_journal()
print("Chain verified:", journal.get("t0_chain_verified"))
# False = tamper detected at some point in the chain
```

---

## Ed25519 Keypairs

### Node Identity Key

Generated at first boot, stored at `keypair_path` in `connector.yaml`:

```
Ed25519 private key (32 bytes, secret)
Ed25519 public key  (32 bytes, public — embedded in node_id)
```

**Used to sign:**
- Compiled CCL contracts → `cls1-sha256-*` + signature
- Surface output documents → `soe1-sha256-*` + signature
- Proof bundles → `prf_uuid` + signature
- Decision records → `decision_id` + signature

### Signature Verification

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import base64

def verify_decision(decision: dict, node_public_key_hex: str) -> bool:
    pub_key_bytes = bytes.fromhex(node_public_key_hex)
    pub_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)

    message   = decision["content_hash"].encode()
    signature = bytes.fromhex(decision["signature"].replace("ed25519:", ""))

    try:
        pub_key.verify(signature, message)
        return True
    except Exception:
        return False
```

---

## Merkle Trees Over Memory Namespaces

For each namespace, Connector maintains a Merkle tree where:
- Leaf nodes = individual memory packets (CIDs)
- Internal nodes = hash of children
- Root = namespace integrity hash

**Path proofs:** Prove a specific packet is in a namespace without revealing all packets:

```
Root (namespace hash)
├── H(left subtree)
│   ├── mem1-sha256-abc... ← target packet
│   └── mem1-sha256-def...
└── H(right subtree)
    ├── mem1-sha256-ghi...
    └── mem1-sha256-jkl...
```

The path proof for `mem1-sha256-abc...` is `[H(right subtree), mem1-sha256-def...]` — proving membership without exposing other packets.

---

## `fips_crypto.rs` — FIPS-Compliant Primitives

Connector uses FIPS 140-2 compliant cryptographic primitives:

| Operation | Algorithm | FIPS Standard |
|---|---|---|
| Hash | SHA-256 | FIPS 180-4 |
| MAC | HMAC-SHA256 | FIPS 198-1 |
| Signature | Ed25519 | FIPS 186-5 |
| KDF | HKDF-SHA256 | SP 800-56C |
| Random | CSPRNG | SP 800-90A |

---

## Post-Quantum Readiness (`post_quantum.rs`)

Current signatures (Ed25519) are vulnerable to Shor's algorithm on a sufficiently powerful quantum computer. `post_quantum.rs` provides:

- **CRYSTALS-Dilithium** — NIST-selected post-quantum signature scheme
- **Hybrid mode** — Ed25519 + Dilithium signatures simultaneously
- Migration path: nodes can be upgraded to PQ-only when required

Enable hybrid mode:
```yaml
node:
  crypto:
    post_quantum: hybrid   # or: classical | pq_only
```

---

## How `generate_proof` Assembles a Bundle

```
generate_proof(agent_pid, title)
    │
    ▼ 1. Load agent's journal entries (Ring 8)
    │
    ▼ 2. Verify HMAC chain
    │
    ▼ 3. Load execution receipts
    │
    ▼ 4. Verify receipt chain
    │
    ▼ 5. Load all decision records
    │
    ▼ 6. Build Merkle tree over all evidence
    │
    ▼ 7. Compute root hash
    │
    ▼ 8. Sign root hash with node keypair (Ed25519)
    │
    ▼ 9. Assemble proof bundle:
    │     {journal, receipts, decisions, merkle_root, signature}
    │
    ▼ 10. Write proof to Ring 9 surface
    │
    ▼ Return: proof_id, cid, signature
```

---

## Verifying a Proof Offline

The proof bundle is self-contained. Verification requires only:
1. The proof bundle (JSON)
2. The node's public key (retrievable from `GET /health`)

```python
def verify_proof_offline(bundle: dict, public_key_hex: str) -> bool:
    # 1. Verify journal HMAC chain
    if not verify_chain(bundle["journal_entries"]):
        return False

    # 2. Verify receipt chain
    prev = None
    for receipt in bundle["receipts"]:
        if prev and receipt.get("prev_receipt") != prev:
            return False
        prev = receipt["receipt_id"]

    # 3. Verify Merkle root signature
    root_hash = bundle["merkle_root"]
    signature = bundle["signature"]
    return verify_ed25519(root_hash, signature, public_key_hex)
```

---

## Next Steps

- **[22 — Cognitive Substrate](22-theory-cognitive-substrate.md)**
- **[37 — Tutorial: Audit Proof](37-tutorial-audit-proof.md)**
- **[62 — Chains 7–9: Trust, Isolation, Proof](62-chains-trust-isolation-proof.md)**
