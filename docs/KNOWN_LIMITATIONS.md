# Known limitations (v1)

Honest open gaps for **Final** — aligned with [FINAL_REACH.md](../FINAL_REACH.md). Do **not** treat this list as marketing deferrals for features already shipped; do **not** claim L4/+2, L5/global mesh, or court-grade until the matching claim gates are signed.

| Area | Limitation | Final / Maturity |
|------|------------|------------------|
| CLS / workflow runtime | **Product ENABLE path = CLS engine + CNP dispatch tokens only** (`workflow_cnp` topics + scoped token; `dual_runtime: false`). No side executor for real runs. Full CNP topic-bus live dispatch / edge emission soak still open | P3.1 |
| CLS dry-run | Dry-run honesty stays `partial` \| `audit_tail`; **`product_mode: "cnp_correlated"`** when ENABLE CNP tokens exist (+ synthetic CNP-shaped `event_id`s from token scopes). Full CNP topic-bus would-fire/would-skip still open | P3.2 |
| Builder ⇄ CLS | Contract + **`GET /workflows/:id/builder-round-trip`**; UI save/re-open shows `partial — re-open OK` when fingerprint exists — full visual ↔ source ↔ package still open | P3.3, prod 3.4 |
| Hub workflow publish | Workflow **`.cpkg` Hub publish/install** not shipping; honesty stub `POST /api/v1/hub/workflows/publish` + Workflows drawer **Publish to Hub** shows `implemented:false` ([HUB_WORKFLOW_PUBLISH.md](HUB_WORKFLOW_PUBLISH.md)) | P4.2 |
| Hub certify | **2A.9 checklist + section headers** ship (`docs/PLUGIN_VERIFY_2A9.md`); idle/capability/UI-bundle checks still `skip`; install &lt;30s SLO unmeasured | P4.3 |
| CNP peer crypto | **`establish_mtls` fail-closed** without `CONNECTOR_CNP_ALLOW_MTLS_STUB=1` (empty-key success forbidden). Real mutual_auth / naming crypto not productized (`GET /cnp/overview` → `data.mtls`) | P3.4, P8.3 |
| Glue / SDK | Glue executor **stub-contained** in prod (fail-closed unless allow-stub); not a shipping integration surface | P5.2 |
| Object Fabric / moments | Put/get + budgeted **recall hydrate** + range seek exist; multipart complete → **thin moment** (part refs) when CAS chunks present; single assembled blob still open | P6.1–P6.2, I-10, I-22 |
| ArtifactLog | Segment append + **`rebuild_from_log` count stub** ship; full segment materialize / soak incomplete | P6.3, I-13 |
| Peer usage | **UsageReceipt** + Books `unmetered_peer` + Books UI panel exist; full A2A metered peer path still open | P6.5, I-08 |
| SGKE / placement | SGKE deny on MCP egress + Actionlog Denied-by-SGKE explainer; `HardwarePlacementV2` on `/runtime/cells` + Monitor mesh (single-node); multi-cell schedule open | P6.6–P6.7, I-19–I-20 |
| LLM cost-cap E2E | Gateway **hard_stop** vs Books month estimated USD ships; primary-down→fallback E2E + UsageEvent served-model path still open | P2.2 |
| Flow lease / kerneld | Status honesty exists; **prod unstamped-egress fail-closed** + full flow-lease map incomplete | P6.8, I-21 |
| Forensics / Moments UI | Partial panels; unified timeline + Moments/Vector Box play surface incomplete | P6.10, I-24–I-25 |
| Backup / upgrade | Trust-domain backup/restore + node-upgrade paths documented/UI’d; clean-VM migrate soak still operator/CI | P1.1–P1.2 |
| Signed release | Hash/signature path + verify script ship; full release automation / cosign CI incomplete | P1.3 |
| Isolation | Landlock child pores close in-process MCP/HAL/LLM dials when exclusivity/Ring-1/`CONNECTOR_LANDLOCK_CHILD=1`. Pore table is default DROP (owner grant required). **Session-connected vendor cut** DROPs host HTTPS to Anthropic/OpenAI/etc except the LLM-cage SO_MARK (`GET /runtime/llm-vendor-cut`). Dest pin is userspace + Landlock FS; nft/iptables needs CAP_NET_ADMIN. Not Firecracker. Provider `tool_calls` are not executed in the child. **Browser world** is document GET on a granted origin (`POST /world/browser/navigate`); Chromium click/type computer-use remains `unsupported_here`. Operator doc: [WORLD_CAGE_AND_BROWSER.md](WORLD_CAGE_AND_BROWSER.md). Swap-lab + Service Map polish open | P4.1, P4.4 |
| Institutions | `GET /runtime/policy-lineage` honesty partial (no durable policy revision); TT/WC light consoles show lineage snippet; FNI verify GET ships (WC/TT); full TT→WC→moment E2E soak still open; secondary plugins stay deferred | P5.1, I-17, P5.4 |
| L5 mesh | Product membership = **vac-cluster CRDT** ([mesh-membership.md](architecture/mesh-membership.md)); SWIM library-only. Fabric not wired as product SoT; honesty stays `product_sot=single_node`, `mesh_fabric: false`, `automatic_failover: false`. `GET /runtime/federation-policy` → `deny_overrides: local_only`, `aapi_federation_wired: false` | P8, T13–T18 |
| Court-grade custody | Issuer/local **HMAC ≠ court-grade**; N-of-M independent WitnessCtl quorum + export integrity from recompute not signed | P8.6, T17 |
| Scale / HA | 100-plugin condo targets and automatic failover are **not** product claims; operator HA only | Seg 9, P8.5 |
| TLS custom domain | Host routing + metadata in kernel; certificate termination is operator-managed | ops |
| Playground / docs site | Optional; see `CONNECTOR_OS_PLAYGROUND_AND_DOCS_SITE_PLAN.md` | vendor |
| wasm plugin backend | Experimental; not the default isolation path | P4 |

**Already true (do not re-list as gaps):** keyed audit HMAC + recompute; causal keyed `integrity_mac`; prod CFNI enforce preset; moment recall hydrate-by-budget; usage-first Books (unavailable ≠ $0); doctrine SoT (MemPackets / ArtifactLog / UsageEvent); ENABLE → CNP token mint + CLS activation record; CNP mTLS stub fail-closed without lab flag.

Automated gates: `make prod-readiness-gate` (engineering) vs Final GO/NO-GO (clean VM + QA stories). Claim marketing: **P7** for L4/+2, **P9** for L5/mesh/court-grade.
