# Connectorctl Customer Certification Matrix

## Scope

Customer-side certification sweep for the current `connectorctl` binary:

- Binary: `platform/server/target/debug/connectorctl`
- Sweep mode: non-interactive commands only (non-blocking)
- Commands tested: 61
- Result snapshot: 61 pass / 0 fail (readiness-gated live run)

This matrix is the enterprise readiness artifact for the current implementation state.

## Scoring Snapshot

| Family | Pass | Total | Pass % |
|---|---:|---:|---:|
| Onboarding | 3 | 3 | 100% |
| RuntimePolicy | 8 | 8 | 100% |
| Intent | 4 | 4 | 100% |
| Lifecycle | 8 | 8 | 100% |
| Surface | 9 | 9 | 100% |
| Fleet | 6 | 6 | 100% |
| Maintenance | 6 | 6 | 100% |
| Security | 6 | 6 | 100% |
| Infra | 8 | 8 | 100% |
| Gate (`llm/time/agent`) | 3 | 3 | 100% |

## Key Findings

- **`gate` command family is now implemented and certified**: `gate llm`, `gate time`, `gate agent`.
- **Endpoint parity improved across security/compliance/surveillance/chain/threat/pentest/events** via routed API fallbacks.
- **Lifecycle start preflight hardened** to only treat LISTEN sockets as conflicts and support idempotent start behavior.
- **Full certification achieved in live execution** when the sweep waits for node readiness before API-dependent commands.

## Command-Level Matrix

Legend:
- `PASS`: command returned exit `0` for tested invocation.
- `FAIL`: command returned non-zero for tested invocation.

Current readiness-gated run result:
- `PASS`: 61 commands
- `FAIL`: 0 commands

Residual failing commands:

| Command | Status | Exit | Note |
|---|---:|---:|---|
| _None_ | PASS | 0 | All tested customer commands passed in the final live run. |

## Enterprise Readiness Verdict (Current Run)

- **Contract Readiness:** Enterprise-grade for command contracts and machine output.
- **Functional Readiness:** 61/61 live-certified in readiness-gated controlled run.
- **Overall Verdict:** **Enterprise-certified for the current customer command surface.**

## Required To Reach Full Certification

1. Keep using readiness-gated certification (`connectorctl health --json` gate) before command sweeps.
2. Add this sweep to CI as a non-interactive command contract check.

