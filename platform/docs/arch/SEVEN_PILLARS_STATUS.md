# Seven Engineering Solidification Pillars — Living Status

**Source:** Connector_OS_Seven_Engineering_Solidification_Pillars.pdf  
**Discipline:** each row is exactly one of `SHIPPED_VERIFIED` | `IMPLEMENTED_GATED` | `PLANNED` | `ASPIRATIONAL`.  
**Rule:** do not mark `SHIPPED_VERIFIED` unless a linked adversarial/acceptance test id exists and passes.

Status values match the PDF Current Status Discipline.

**PDF checklist completeness:** all implementation-checklist and release-gate rows are at least `IMPLEMENTED_GATED` (none remain `PLANNED`). Live Firecracker/cgroup attach and packet-level escape proofs stay host-gated until soak labs promote to `SHIPPED_VERIFIED`.

---

## Pillar 1 — Agent Identity and Cognitive Confinement

| Checklist item | Status | Test id |
|----------------|--------|---------|
| All model entry points require resolved Connector principal | IMPLEMENTED_GATED | P1-T01 |
| All model entry points require character/contract version hashes | IMPLEMENTED_GATED | P1-T02 |
| RAG/memory reads principal-scoped; cross-agent denial | IMPLEMENTED_GATED | P1-T03 |
| Cross-agent shares require grants + receipts | IMPLEMENTED_GATED | P1-T04 |
| Prompt/tool cannot override principal or character metadata | IMPLEMENTED_GATED | P1-T05 |
| Character/contract changes invalidate quanta and flow leases | IMPLEMENTED_GATED | P1-T06 |
| Bypass/drift → block/HITL/quarantine | IMPLEMENTED_GATED | P1-T07 |
| 100-agent concurrency identity isolation | SHIPPED_VERIFIED | P1-T08 |

## Pillar 2 — OS-Grade Enforcement + connector-kerneld

| Checklist item | Status | Test id |
|----------------|--------|---------|
| L1/L2/L3 mapped to Linux primitives in code | IMPLEMENTED_GATED | P2-T01 |
| Production fail-closed for missing Landlock/LSM | IMPLEMENTED_GATED | P2-T02 |
| Agent process tree bound to cgroup/namespace | IMPLEMENTED_GATED | P2-T03 |
| Kernel-observable principal attribution | IMPLEMENTED_GATED | P2-T04 |
| kerneld eBPF program loaded | IMPLEMENTED_GATED | P2-T05 |
| Desired-vs-applied reconciliation + drift alarm | IMPLEMENTED_GATED | P2-T06 |
| Adversarial syscall/raw socket/namespace escape tests | IMPLEMENTED_GATED | P2-T07 |
| 100-agent enforcement non-collision | SHIPPED_VERIFIED | P2-T08 |

## Pillar 3 — Cryptographic HITL / Exact-Action Admission

| Checklist item | Status | Test id |
|----------------|--------|---------|
| EffectAuthorization schema versioned | IMPLEMENTED_GATED | P3-T01 |
| Canonicalize signed parameters/destinations | IMPLEMENTED_GATED | P3-T02 |
| HITL binds exact effect digest (signed artifact) | IMPLEMENTED_GATED | P3-T03 |
| Grants reference agent × address | IMPLEMENTED_GATED | P3-T04 |
| Verify authz before credential materialization | IMPLEMENTED_GATED | P3-T05 |
| Verify authz at last trusted adapter | IMPLEMENTED_GATED | P3-T06 |
| Nonce/replay + expiry | IMPLEMENTED_GATED | P3-T07 |
| Invalidate on policy/character/grant change | IMPLEMENTED_GATED | P3-T08 |
| One-byte change after approval → deny | SHIPPED_VERIFIED | P3-T09 |

## Pillar 4 — Network Identity and Flow Admission

| Checklist item | Status | Test id |
|----------------|--------|---------|
| Flow Identity/Lease schema | IMPLEMENTED_GATED | P4-T01 |
| Socket bound to process/cgroup/ns identity | IMPLEMENTED_GATED | P4-T02 |
| Raw socket denied unless governed | IMPLEMENTED_GATED | P4-T03 |
| DNS/redirect policy checks | IMPLEMENTED_GATED | P4-T04 |
| Cut flows on quarantine/revocation/expiry | IMPLEMENTED_GATED | P4-T05 |
| Ordinary Internet gateway without leaking internals | IMPLEMENTED_GATED | P4-T06 |
| Connector-aware peer overlay | IMPLEMENTED_GATED | P4-T07 |
| ~100 concurrent flow isolation | SHIPPED_VERIFIED | P4-T08 |

## Pillar 5 — Invariant Effect Routing

| Checklist item | Status | Test id |
|----------------|--------|---------|
| EffectEnvelope versioned | IMPLEMENTED_GATED | P5-T01 |
| Canonical target/operation identities | IMPLEMENTED_GATED | P5-T02 |
| All tools/MCP through governed_effect + authz | IMPLEMENTED_GATED | P5-T03 |
| Secrets out of guest env | IMPLEMENTED_GATED | P5-T04 |
| Deny direct provider clients in hardened profile | IMPLEMENTED_GATED | P5-T05 |
| Alternate routes closed + exclusivity status API | IMPLEMENTED_GATED | P5-T06 |
| Adversarial header/URL/body/redirect tests | IMPLEMENTED_GATED | P5-T07 |
| Bypassing HTTP handler does not bypass authz | IMPLEMENTED_GATED | P5-T08 |

## Pillar 6 — Isolation Contract

| Checklist item | Status | Test id |
|----------------|--------|---------|
| ConnectorIsolationManifest versioned | IMPLEMENTED_GATED | P6-T01 |
| Tier promises map to measurable Linux/VM state | IMPLEMENTED_GATED | P6-T02 |
| DockLock/quantum bound to process/cgroup/VM id | IMPLEMENTED_GATED | P6-T03 |
| vsock channel authenticate/authorize | IMPLEMENTED_GATED | P6-T04 |
| Guest direct network denied in high tier | IMPLEMENTED_GATED | P6-T05 |
| MicroVM kernel/rootfs hash at launch | IMPLEMENTED_GATED | P6-T06 |
| Desired-vs-applied isolation drift detection | IMPLEMENTED_GATED | P6-T07 |
| Atomic revoke: quantum+flow+vsock+egress+workload | IMPLEMENTED_GATED | P6-T08 |
| Cross-agent isolation @ 100 agents | SHIPPED_VERIFIED | P6-T09 |
| Shared infra never merges principals | IMPLEMENTED_GATED | P6-T10 |

## Pillar 7 — cpkg / CLS / AAPI / CNP

| Checklist item | Status | Test id |
|----------------|--------|---------|
| cpkg as workload-security contract | IMPLEMENTED_GATED | P7-T01 |
| Signature/SBOM/deps before activation | IMPLEMENTED_GATED | P7-T02 |
| Enforce caps/egress/FS/device/secret/isolation | IMPLEMENTED_GATED | P7-T03 |
| CLS IR for states/transitions/effects/HITL/budgets | IMPLEMENTED_GATED | P7-T04 |
| Compile CLS → AAPI/effect policy + contract hash | IMPLEMENTED_GATED | P7-T05 |
| Narrow AAPI issue/delegate/revoke | IMPLEMENTED_GATED | P7-T06 |
| CNP packet schema + canonical signing | IMPLEMENTED_GATED | P7-T07 |
| Agent Packet DNA (7 genome params) | IMPLEMENTED_GATED | PACKET_DNA.md |
| Protocol adapters normalize into CNP | IMPLEMENTED_GATED | P7-T08 |
| CNP over TCP/TLS/HTTP/QUIC/IPv6 | IMPLEMENTED_GATED | P7-T09 |
| Malformed protocol cannot mint authority | IMPLEMENTED_GATED | P7-T10 |

## Release gates (PDF)

| Gate | Status | Test id |
|------|--------|---------|
| No model path without agent context | IMPLEMENTED_GATED | RG-01 |
| No regain denied FS/syscall/net via userspace bypass | IMPLEMENTED_GATED | RG-02 |
| No HITL replay for altered params | IMPLEMENTED_GATED | RG-03 |
| No anonymous agent socket | IMPLEMENTED_GATED | RG-04 |
| No external effect without governed authz | IMPLEMENTED_GATED | RG-05 |
| No prod workload with missing/drifted isolation | IMPLEMENTED_GATED | RG-06 |
| No undeclared cpkg/protocol capability | IMPLEMENTED_GATED | RG-07 |
| 100-agent soak identity/grant/flow separation | SHIPPED_VERIFIED | RG-08 |
| Restart does not duplicate effects | SHIPPED_VERIFIED | RG-09 |
| Atomic revocation across quantum/flow/vsock/isolation | IMPLEMENTED_GATED | RG-10 |
| Claims backed by CI adversarial evidence | IMPLEMENTED_GATED | RG-11 |

---

## Gate script

```bash
bash platform/scripts/seven-pillars-gate.sh
bash platform/scripts/seven-pillars-complete-adversarial.sh
```

Fails if any row is `SHIPPED_VERIFIED` without a non-empty Test id, or if status enum is invalid.  
Complete script fails if any PDF checklist row is still `PLANNED`.

## Code map (formerly PLANNED)

| Test id | Implementation |
|---------|----------------|
| P1-T08 / P2-T08 / P4-T08 / P6-T09 / RG-08 | `substrate/seven_pillars_soak.rs` (`soak_100_agent_isolation`) |
| RG-09 / T4 | `mission_journal::{begin_step_detailed,abandon_stale_pending}` + `seven-pillars-proofs` T4 soak |
| T2 | `substrate/transparent_egress.rs` + L7 channel hop |
| T6–T8 | CONP partner HAL fail-closed · MCP STRICT/OOPC · `/apps` + `/apps/parity` routes |
| T2 kernel | `platform/ebpf/connector_connect_redirect.bpf.c` + `kerneld egress-redirect-*` / `nft-redirect-apply` |
| T6 wire | `kernel/partner_hal.rs` ROS/Modbus/MQTT/TCP adapters |
| Host attach | `seven-pillars-host-attach-proofs.sh` → `/tmp/connector-host-attach-proofs.json` |
| P2-T03 / P2-T04 / P4-T02 / RG-04 | `kernel/agent_cgroup.rs` + flow lease `socket_binding` |
| P2-T05 | `platform/ebpf` + `connector-kerneld ebpf-*` |
| P2-T07 / RG-02 | `sandbox_unbypassable` + docklock/ebpf/exclusivity adversarial scripts |
| P4-T07 | `cnp/peer_overlay.rs` |
| P5-T08 | `seven_pillars_soak::assert_internal_path_cannot_bypass_authz` |
| P6-T04..T08 | vsock HMAC tickets, measured microVM, atomic revoke OS cut |

## P2-T05 eBPF notes

- Program: `platform/ebpf/connector_mark_deny.bpf.c` (`cgroup/skb` egress mark deny).
- Loader: `connector-kerneld ebpf-load|status|deny-mark|unload` (bpftool + bpffs pins).
- Honesty: `ebpf_loaded` only when `/sys/fs/bpf/connector/<agent>/prog` (and map) exist.
- Adversarial: `platform/scripts/seven-pillars-ebpf-adversarial.sh`.

## Sandbox unbypassable (VM / vsock / FS / net)

**Locked profile:** `platform/deploy/unbypassable.env`  
`export CONNECTOR_PRESET=defense-strict` (alias `unbypassable`) applies the same defaults at boot.

**Host lab (no full platform compile):**
```bash
bash platform/scripts/seven-pillars-host-adversarial-lab.sh
```

Promote further rows to `SHIPPED_VERIFIED` only when that lab report marks them PASS (and eBPF attach / Firecracker when CAP_BPF + assets exist).

## Court / military grade (claim discipline)

See [`COURT_GRADE_CLAIMS.md`](./COURT_GRADE_CLAIMS.md) and `security_claim_registry.json`.

```bash
bash platform/scripts/seven-pillars-host-adversarial-lab.sh   # includes evidence bind
# or: bash platform/scripts/court-grade-evidence-bind.sh
```

Verdict grades in `/tmp/connector-court-evidence/verdict.json`:
- `GOVERNANCE` — authority + crypto HITL/effect evidence
- `HOST_LAB` — fail-closed host lab
- `MILITARY_COURT` — **only** when eBPF loaded + Landlock visible + measured microVM + kerneld Active

**Overclaim refusal:** `CLAIM_MILITARY_COURT=1` is refused unless `MILITARY_COURT.met=true`.
