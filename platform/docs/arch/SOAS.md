# SOAS — Standard Operation Agentic Standard

Schema: `connector.soas.report.v1`

Honest workpaper for “is this node ready?” — not CPA attestation, not CD-9 military counsel.

## Endpoints

| Method | Path | Role |
|--------|------|------|
| GET | `/api/v1/soas/report?agent_pid=` | JSON aggregator |
| GET | `/api/v1/soas/report/pdf?agent_pid=` | printpdf workpaper |

## Overall grades (never upgrade without evidence)

| Grade | Meaning |
|-------|---------|
| `playground_demo` | Hosted Fly trial — soft L7 broker, HMAC lab. **Always** the overall grade when `CONNECTOR_PLAYGROUND=1`. |
| `governance` | Self-host with live Talk/HITL/tools, no Landlock bar yet |
| `host_lab` | Lab node without wired LLM |
| `court_defensible_cd7` | Landlock + non-HMAC court package |
| `military_attach` | Reserved — requires host attach (not auto-assigned by SOAS) |

## Sections

Honesty envelope, Talk/LLM, broker/tokenization, vault, HITL, tools/CNP/CLS/AAPI, Landlock/OS, memory namespace, forensic spine, Seven Pillars pointers, playground session.

Compose only: court-readiness, isolation tiers, LLM status, broker status. See [COURT_GRADE_CLAIMS.md](./COURT_GRADE_CLAIMS.md).

Authoritative **augmented agentic** evidence is **[AACR](./AACR.md)** (`POST /api/v1/aacr/mint`). SOAS is the readiness honesty strip; AACR is the kernel digest chain courts can adopt after CD gates.
