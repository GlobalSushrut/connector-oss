# AACR — Augmented Agentic Compliance Record

Schema: `connector.aacr.v1` · Standard version: **1.1.0**

Kernel-maintained, append-only, content-digested evidence epochs for **augmented agentic** environments. Map once → SOC 2 / HIPAA / NIST CSF / NIST AI RMF Agentic / ISO 42001 / EU AI Act / OWASP Agentic / CSA AICM.

**Court-adoptable after** CD-1…CD-7 (+ CD-8 custody, CD-9 counsel). Never auto-green.

## Why this is the top-tier unit of evidence

Industry buyers and auditors in 2025–2026 no longer accept static “controls implemented” PDFs for agents that call tools. They expect:

| Expectation | AACR answer |
|-------------|-------------|
| Agent ≠ human JWT | S1 probabilistic identity + principal |
| Tool policy decisions | S4 + world grants |
| Continuous runtime evidence | S7 IIA + package digests; 30-day window |
| Human oversight digests | S6 HITL |
| Autonomy tiers | S3 Root/Cone/App |
| Tamper evidence | Per-section digests + content digest + optional Ed25519 |
| Multi-framework SoA | Built-in Statement of Applicability with section digests |

## Falsification classes

| Class | Meaning |
|-------|---------|
| `ed25519_court` | Node Ed25519 — stranger-verifiable |
| `hmac_custody` | WitnessCtl / audit shared-secret (CD-8 prerequisite) |
| `hash_chain` | Decision traces / rollups |
| `live_measure` | Unsigned snapshot — workpaper only |

## Record fields (v1.1)

- `sections[]` with `section_digest_sha256` + `industry_maps`
- `statement_of_applicability` (all frameworks)
- `bindings` (forensic package tier/digest, IIA head, node pubkey)
- `section_digest_rollup_sha256`, `content_digest_sha256`, `chain_head_digest`
- `observation_window` (30d)
- `honesty` (not CPA / not OCR / CD-8/9 pending)
- `signature` when court-eligible

## APIs

| Method | Path |
|--------|------|
| POST | `/api/v1/aacr/mint?agent_pid=` |
| GET | `/api/v1/aacr/latest?agent_pid=` |
| GET | `/api/v1/aacr/chain?agent_pid=` |
| GET | `/api/v1/aacr/report?agent_pid=&framework=` |
| GET | `/api/v1/aacr/report/pdf?agent_pid=` |
| POST | `/api/v1/aacr/verify` |

CLI: `connectorctl aacr verify --file <aacr.json>`

Forensic packages embed `aacr` binding. See [SOAS.md](./SOAS.md), [COURT_GRADE_CLAIMS.md](./COURT_GRADE_CLAIMS.md).
