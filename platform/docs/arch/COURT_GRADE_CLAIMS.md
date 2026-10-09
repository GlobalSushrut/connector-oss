# Connector OS — Court / Military Grade Claim Discipline

**Rule:** A claim is only court-grade or military-grade when every listed evidence artifact is present, content-digested, and HMAC-signed. Marketing language without evidence is an overclaim and must be refused.

Live honesty aggregator for a running node: **[SOAS](./SOAS.md)** (`GET /api/v1/soas/report`). Authoritative **augmented agentic** evidence standard: **[AACR](./AACR.md)** (`connector.aacr.v1` — kernel mint + digest chain; court-adoptable after CD gates). Hosted playground always reports `playground_demo` — never auto-green to military court.

## Grades

| Grade | Meaning |
|-------|---------|
| `GOVERNANCE` | Authority model + partner HAL wire adapters + SIL safety interlock + TLS egress proxy coded |
| `HOST_LAB` | Linux tools + fail-closed paths + landlock apply + measured lab assets + TLS/SIL wiring proven |
| `MILITARY_COURT` | Live attach: eBPF **loaded**, kernel transparent egress (connect4 **or** nft) **applied**, Landlock **applied**, measured microVM hashes, TLS terminate proxy present, SIL interlock on, no break-glass |

## How to produce evidence

```bash
set -a && source platform/deploy/unbypassable.env && set +a
export CONNECTOR_AUDIT_HMAC_KEY="$(openssl rand -hex 32)"
export CONNECTOR_CONP_SIL_HMAC_KEY="$(openssl rand -hex 32)"
export CONNECTOR_EGRESS_CHANNEL_HMAC_KEY="$(openssl rand -hex 32)"
bash platform/scripts/seven-pillars-host-attach-proofs.sh   # prefers privileged docker for eBPF/nft
bash platform/scripts/court-grade-evidence-bind.sh
# Optional: run TLS hop
# cargo run --manifest-path platform/connector-egress-proxy/Cargo.toml
```

Outputs:
- `/tmp/connector-host-attach-proofs.json` — includes `military_court_ready`
- `/tmp/connector-court-evidence/` — signed binder

## Completed bars (coding + attach path)

| Topic | Completed |
|-------|-----------|
| T2 TLS terminate | `connector-egress-proxy` — CONNECT + Connector-CA MITM decrypt + upstream rustls; ticket required |
| T6 SIL body | `sil_interlock` — refuse physical CONP without partner attestation / heartbeat |
| Host attach | Landlock syscall apply · lab measured microVM · privileged docker eBPF/nft path |

## Overclaim refusal

`CLAIM_MILITARY_COURT=1` refused unless `military_court_ready=true` in the attach report. SIL certification of robots/PLCs remains partner-owned; Connector owns the **interlock gate**.
