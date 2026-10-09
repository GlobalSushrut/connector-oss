# AiPassport.sig — artifact provenance subsystem

Schema: `connector.aipsprt.sig.v1` · Header: `x-connector-aipsprt-sig`

## Thesis

AiPassport is **not** AI-content detection or watermarking.

> **AiPassport is the transition record where ephemeral agent execution becomes persistent external digital matter.**

Before it: Connector controls executing intelligence. After it: bytes may live for years outside the host. The passport is the bridge.

Related: [PACKET_DNA.md](./PACKET_DNA.md) (transit), [SPEND_CEASE.md](./SPEND_CEASE.md) (cost/stop), [AACR.md](./AACR.md) (epoch compliance).

## Claim separation

| Identity | Field | Meaning |
|----------|-------|---------|
| Content | `payload` DigestRef | Governed bytes at a **named** hash boundary |
| Instance | `artifact_instance_id` | This particular creation |
| Egress event | `egress_event_id` | This delivery/attempt |
| Transport | (outside) | gzip / MTA / proxy = external derivative |

Same text from two agents → same payload digest, different instance/subject/passport.  
Retries → same instance, different egress event.  
Delivery → **effect receipt**, not AiPassport.

## Mint boundary

Mint only after the **last Connector-controlled mutation** (redaction, projection, serialize). Never hash a JSON body then insert the passport into that same body.

Talk: mint over finalized projected text; attach as `connector_aipsprt` / `aipsprt` **sibling**.

## Public vs private

**Public passport:** `agent_subject_id`, `issuer_id`, `issuer_key_id`, Ed25519 signature.  
**Private tally:** maps subject → `agent_pid` / `principal_id` / internal node; digest indexes are **postings lists** (not single-value KV). No public digest existence oracle.

## Signing

External verify = **Ed25519** (platform node key). HMAC = local/dev only.

## Profiles

| Profile | Hash domain | Wire |
|---------|-------------|------|
| `buffered_json` | `buffered_json.payload.v1` | Envelope sibling |
| `streaming_closure` | sealed stream | Final SSE `event: aipsprt` |
| `file_bytes` | file commit bytes | `<path>.aipsprt.sig` |
| `email_parts` | logical body + attachments | Not final SMTP |

## Honesty

- Signature = issuer attestation, not environment truth, not court grade, not delivery proof.
- Aligns with EU AI Act Art.50 *machine-readable mark* tooling intent — not a compliance certificate.
- C2PA is an optional future export; AiPassport stays richer (agent/generation/role).
- See research notes in the design plan (C2PA 2.4 limits, SynthID ≠ who/why).

## C2PA export map (thin)

`connector_trust::c2pa_export_mapping` / `GET /api/v1/aipsprt/:id/c2pa-map` sketches:

| AiPassport | C2PA-ish target |
|------------|-----------------|
| `payload` DigestRef | hard binding (`alg` + hash + named domain) |
| `provenance_role` | `c2pa.actions` + IPTC `digitalSourceType` |
| `issuer_id` / `agent_subject_id` | `c2pa.ai-disclosure` generator fields |
| instance / egress / generation | **Connector extensions** (not C2PA core) |

This is an **export sketch only** — not an embedded Content Credentials manifest.

## Code

- Types: `connector_trust::aipsprt_sig`
- Runtime: `platform/server/src/substrate/aipsprt.rs`
- Talk mint: `governed_talk_core::finalize_talk`
- Private digest index (auth): `GET /api/v1/aipsprt/index/digest/:digest`
