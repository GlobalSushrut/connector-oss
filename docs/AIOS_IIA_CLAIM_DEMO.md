# AIOS IIA Claim Demo — Flagship §23 (14 steps)

**Prereq:** built platform (`make platform-build`).  
**Canon:** [intelligence-identity-architecture-v2.md](architecture/intelligence-identity-architecture-v2.md)  
**Engineering queue:** [IIA_CORE_UPGRADE_CHECKLIST.md](../IIA_CORE_UPGRADE_CHECKLIST.md)

## One command

```bash
make platform-build
make iia-flagship-demo
# evidence: platform/scripts/.iia-flagship-demo.ok
```

This runs `iia-court-gate` (T19–T28) then re-asserts all **14 flagship steps** live against the node.

| Step | Action | Automated by |
|------|--------|----------------|
| 1 | Register Agent A + B, same LLM | live + `iia-p0-gate` |
| 2 | `GET /runtime/self` — distinct AgentIDs + contracts | live |
| 3 | A: N4 cognize → QPR intent → quantum | live |
| 4 | Inject finance via A | live `qpr_denied` |
| 5 | Shell/SDK bypass without quantum | `.docklock-bypass-adversarial.ok` |
| 6 | Tamper runtime hash | live `continuity.state == broken` |
| 7 | `GET /runtime/hardware` | live ERM `attestation_tier` |
| 8 | B compliance / identity envelope | live |
| 9 | `GET /runtime/provenance` | live receipts |
| 10 | Export verify + tamper detect | `connectorctl iia verify-export` |
| 11 | Model substitution — AgentID stable | live |
| 12 | Untrusted context + privileged target | live (with step 4) |
| 13 | Failed N4 hello (empty model) | live `n4_handshake_denied` |
| 14 | Four-ID + forensic package | live provenance + `/forensics/package` |

## Court-only (faster)

```bash
make iia-court-gate
```

## Market claim

Engineering green ≠ market “court-grade.” Human **P10.9.4** sign-off on [IIA_CORE_UPGRADE_CHECKLIST.md](../IIA_CORE_UPGRADE_CHECKLIST.md) is still required before marketing language.
