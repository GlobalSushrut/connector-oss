# Connector Edge Plane (CEP)

**Vision:** One native control plane — like Cloudflare for DNS, TLS, and routing — but for **Connector's world**: LLM gateway paths, cage proxies, institution planes (TT/WC/DG), workflow bindings, agent isolation, and egress. Operators configure **how the outer world reaches isolated agents and workflows** without assembling Caddy + env vars + custom domain JSON by hand.

**Not:** Replacing Cloudflare/Fly on day one. **Is:** Making Connector the **source of truth** for routing intent; edge can still terminate TLS externally while CEP owns **records, bindings, health, and proof**.

**Parent UI:** [UI_MAKEOVER_PLAN.md](UI_MAKEOVER_PLAN.md) · SETUP mode + drawer topic **Edge**  
**Related substrate:** CFNI ([forensic network identity plan](.cursor/plans/forensic_network_identity_f8d4e546.plan.md)) · [CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md](CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md) §N1–N5

---

## 1. Problem today (honest backend map)

External traffic takes a **manual assembly** path:

```text
Internet
  → [Cloudflare DNS]  (operator manual — gray cloud for Fly)
  → [Caddy / Fly / nginx]  (TLS termination — operator manual)
  → connector-platform :9091
       ├─ /api/v1/*              kernel REST
       ├─ /v1/*                  LLM gateway (DevGuard connect lands here)
       ├─ /plugin/<slug>/*       cage proxy → internal_dns → plugin process
       ├─ Host: custom.domain    custom_domain middleware → same cage
       └─ :9092 /proto/*         protocol gateway (MCP/A2A/ACP…)

TraceTramp   data :9741  mgmt :9742   /cage/:sha for tenant SDK
WitnessCtl   mgmt + /witness/* capture proxy
DevGuard     hooks platform /v1 — no separate public dossier port
Workflows    in-kernel — share node HTTP surface, no per-WF listen port
connector-kerneld   host egress allowlists (systemd) — adjacent, not HTTP
```

| Layer | What exists | Config surface today | Gap |
|-------|-------------|----------------------|-----|
| **Public DNS** | Cloudflare manual | `CLOUDFLARE_DNS_FIX.md`, fly.toml | No DNS API in platform |
| **TLS** | Caddy/Fly | Caddyfile, operator certs | `tls_mode` in settings is **metadata only** |
| **Host → plugin** | `custom_domain_routing.rs` | Settings → Custom domains API | No workflow/agent dimension |
| **Cage internal** | `internal_dns` `*.cnktros` | env + plugin boot registration | Must not leak to public DNS |
| **LLM gateway** | `gateway.rs` `/v1/*` | Settings LLM routing rules | Not tied to workflow binding UI |
| **Plugin admin proxy** | `tracetramp_proxy`, `witnessctl_proxy`, `devguard_proxy` | env URLs + admin tokens | Scattered env, not one plane |
| **Protocol edge** | `protocol_gateway` :9092 | `CONNECTOR_PROTOCOL_PORT` | Separate listener, not unified UI |
| **Egress** | kerneld + plugin-runtime iptables | kernel profiles API | Not linked to edge records |
| **Forensics** | CFNI planned | — | No stamp at edge yet |

**Operator pain:** "Point Claude at `/v1`, put TT on `tracetramp.corp`, WC on another host, wire DevGuard connect, don't leak `*.cnktros`" — **five different mental models**.

---

## 2. CEP promise (Cloudflare analogy, Connector-native)

| Cloudflare concept | Connector Edge Plane equivalent |
|--------------------|--------------------------------|
| **DNS zone** | **Traffic zone** — one node (or cell) namespace |
| **A/AAAA/CNAME record** | **HOST_ALIAS** — public hostname → binding target |
| **MX** (route mail by domain) | **INSTITUTION_ROUTE** — hostname/path → TT / WC / gateway profile |
| **Worker route** | **WORKFLOW_ROUTE** — hostname/path → workflow + institution chain |
| **Spectrum / port proxy** | **PORT_BIND** — public port → cage upstream (advanced) |
| **SSL/TLS mode** | **TLS_POLICY** — terminate at edge / full / metadata + ACME hook (phased) |
| **Firewall rules** | **EDGE_POLICY** — allow/deny by tenant, agent, CFNI stamp |
| **Load balancer pool** | **UPSTREAM_POOL** — plugin instances, health-checked |
| **Analytics** | **EDGE_OBSERVABILITY** — requests, denials, latency by route |

**MX insight for Connector:** Different **institutions** on the same node are like different **mail handlers** on one domain — the edge must route by **host + path + SNI**, not one catch-all port.

---

## 3. Architecture (target)

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ CONNECTOR EDGE PLANE (CEP) — source of truth                            │
│  Records · Bindings · Policies · Health · Proof                         │
│  GET/POST /api/v1/operator/edge/*                                       │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ renders to
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ External edge │     │ Platform kernel │     │ connector-      │
│ Caddy/Fly/CF  │     │ cage proxy      │     │ kerneld egress  │
│ (optional)    │     │ gateway /v1     │     │ maps            │
└───────────────┘     │ protocol :9092  │     └─────────────────┘
                      │ internal_dns    │
                      └─────────────────┘
```

**CEP does not require** owning public DNS on v1 — it **emits** what operators (or future ACME worker) should apply, and **proves** routing works (`cage_proof` extended).

---

## 4. Record types (`edge_record.v1`)

Universal schema — workflows, plugins, agents **bind** to records; UI renders **one table**.

### 4.1 Record kinds

| Kind | Purpose | Example |
|------|---------|---------|
| **HOST_ALIAS** | Public `Host` → target | `tracetramp.acme.corp` → `plugin:tracetramp` |
| **PATH_ROUTE** | Path prefix → target | `/v1/*` → `gateway:default` |
| **CAGE_INTERNAL** | `slug.cnktros` → socket | `tracetramp.cnktros` → `127.0.0.1:9741` |
| **INSTITUTION_ROUTE** | Institution public entry | `witness.acme.corp` → `plugin:witnessctl` + `/witness` |
| **WORKFLOW_ROUTE** | WF-scoped edge (future) | `hitl.acme.corp` → `workflow:hitl-approve` → TT+WC chain |
| **AGENT_ROUTE** | Agent-scoped gateway token path | `agent-abc` → `/v1` + admission profile |
| **PROTO_ROUTE** | MCP/A2A listener | `mcp.acme.corp:9092` → `proto:mcp` |
| **EGRESS_RULE** | Outbound allow for bind target | `workflow:hitl` → `api.openai.com:443` |
| **TLS_POLICY** | Cert mode for HOST_ALIAS | `lets_encrypt` / `external` / `mtls` |

### 4.2 Record shape

```json
{
  "schema": "edge_record.v1",
  "id": "rec_tracetramp_acme",
  "kind": "HOST_ALIAS",
  "enabled": true,
  "match": {
    "host": "tracetramp.acme.corp",
    "path_prefix": "/"
  },
  "target": {
    "type": "plugin",
    "plugin_id": "tracetramp",
    "plane": "data",
    "internal_host": "tracetramp.cnktros"
  },
  "bind": {
    "tenant_id": "default",
    "workflow_id": null,
    "agent_pid": null
  },
  "tls": { "mode": "external", "cert_ref": null },
  "policy": {
    "require_cfni": false,
    "admission": "default",
    "rate_limit": null
  },
  "health": {
    "check_path": "/plugin/tracetramp/health",
    "last_ok_ms": 1730000000000
  },
  "status": "active|degraded|pending_dns|misconfigured"
}
```

### 4.3 Binding dimensions (isolation)

Every record can scope **who** it applies to:

| Dimension | Isolates |
|-----------|----------|
| `tenant_id` | multi-tenant cells |
| `workflow_id` | automation-specific hostname (future) |
| `agent_pid` | DevGuard connect / per-agent gateway profile |
| `institution_id` | TT vs WC vs DG plane |
| `session_id` | WC witness proxy path |

**Same UI row** — different `bind` — no separate TT page vs WC page.

---

## 5. How institutions map to edge (TT · WC · DG)

| Institution | Planes | Public entry pattern | CEP records |
|-------------|--------|----------------------|-------------|
| **TraceTramp** | data (:9741), mgmt (:9742) | `/plugin/tracetramp/v1/*` or HOST_ALIAS; `/cage/:sha/*` on TT | HOST_ALIAS + CAGE_INTERNAL + optional WORKFLOW_ROUTE |
| **WitnessCtl** | mgmt API, `/witness/*` capture | HOST_ALIAS → WC; cage `/plugin/witnessctl/witness/*` | INSTITUTION_ROUTE + TLS_POLICY |
| **DevGuard** | none separate — **uses platform `/v1`** | `CONNECTOR_PUBLIC_URL/v1` + `cg_*` token | AGENT_ROUTE + PATH_ROUTE(`gateway`) + EGRESS_RULE |
| **Workflow** | composes institutions | optional dedicated host per WF | WORKFLOW_ROUTE chains TT+WC+Dg bindings |
| **Protocol** | MCP/A2A on :9092 | `PROTO_ROUTE` | separate listener bind |

```text
                    ┌─ HOST_ALIAS: tracetramp.corp ──► TT data plane
Public DNS ────────►├─ HOST_ALIAS: witness.corp ─────► WC mgmt + /witness
                    ├─ PATH_ROUTE: /v1/* ────────────► gateway (DG + all LLM)
                    └─ WORKFLOW_ROUTE: hitl.corp ───► workflow → TT → WC chain
```

**DevGuard difference (universal UI):** CEP shows **AGENT_ROUTE** + connect snippet, not a WC-style HOST_ALIAS — capability-gated like [UI_UNIVERSAL_CAPABILITIES.md](UI_UNIVERSAL_CAPABILITIES.md).

---

## 6. What exists today → CEP migration

| Today | CEP record | API today |
|-------|------------|-----------|
| `custom_domains.aliases[]` | HOST_ALIAS / INSTITUTION_ROUTE | `GET/POST /settings/networking/custom-domains` |
| `internal_dns` table | CAGE_INTERNAL | `GET /internal/dns` (diag) |
| `CONNECTOR_PUBLIC_URL` | PATH_ROUTE default origin | env |
| `CONNECTOR_TRACETRAMP_*` env | INSTITUTION_ROUTE upstream metadata | env |
| `settings/llms/routing-rules` | PATH_ROUTE provider profile | settings API |
| `kernel/status` egress profiles | EGRESS_RULE | kernel API |
| `plugins/status` service map | health aggregation | plugins status |
| `cage_proof` | EDGE_PROOF CI | `GET /plugins/cage-proof` |

**CEP v1:** **read-merge** these into `GET /operator/edge/plane` — single operator view without breaking storage.

---

## 7. New APIs (phased)

| Endpoint | Phase | Purpose |
|----------|-------|---------|
| `GET /operator/edge/plane` | E1 | Merged records + health + DNS hints |
| `GET /operator/edge/records` | E1 | List `edge_record.v1` |
| `POST /operator/edge/records` | E2 | Create/update record (writes custom_domains + bindings) |
| `DELETE /operator/edge/records/:id` | E2 | Remove |
| `POST /operator/edge/records/:id/prove` | E2 | Run cage_proof / curl check |
| `GET /operator/edge/dns-hints` | E1 | "Create CNAME `tracetramp.acme.corp` → `<node>`" (no DNS API yet) |
| `GET /operator/edge/tls-status` | E3 | Cert expiry metadata if wired |
| `GET /workflows/:id/edge` | E3 | WORKFLOW_ROUTE bindings for WF drawer |
| `GET /agents/:pid/edge` | E3 | AGENT_ROUTE + DevGuard connect summary |

---

## 8. UI — universal Edge topic (SETUP + drawer)

CEP uses same **Op*** components as rest of shell — not a separate admin product.

### 8.1 SETUP → Edge (primary surface)

```text
┌─ Edge ─────────────────────────────────────────────────────────────────────┐
│ How the outer world reaches this node.                                      │
├──────────────────────────────────────────────────────────────────────────┤
│ STATUS                                                                    │
│  Public URL: https://node.acme.corp   ● gateway ok   ● cage ok   ⚠ DNS   │
│                                                                           │
│ RECORDS (universal table)                                    [+ Add]      │
│  Kind          Match                    Target              Status        │
│  HOST_ALIAS    tracetramp.acme.corp     plugin:tracetramp   ● active      │
│  HOST_ALIAS    witness.acme.corp        plugin:witnessctl   ● active      │
│  PATH_ROUTE    /v1/*                    gateway:default     ● active      │
│  AGENT_ROUTE   (tokens)                 gateway + admission ● active      │
│  CAGE_INTERNAL tracetramp.cnktros       127.0.0.1:9741      ● (private)   │
│  EGRESS_RULE   workflow:hitl-approve    openai.com:443      ○ pending     │
│                                                                           │
│ DNS HINTS (like Cloudflare "add this record")                             │
│  CNAME tracetramp.acme.corp → node.acme.corp   [Copy] [Verify]           │
│                                                                           │
│ [ Prove all routes ]  [ Export edge manifest ]  [ Developer ▾ JSON ]      │
└──────────────────────────────────────────────────────────────────────────┘
```

### 8.2 Workflow drawer → Edge tab

From RUN card — show only records where `bind.workflow_id` matches:

```text
Edge for: hitl-approve-audit
  WORKFLOW_ROUTE (planned) — hitl.acme.corp → TT + WC
  Inherited: PATH_ROUTE /v1/* (LLM gateway)
  Institutions: [TT●] tracetramp.acme.corp  [WC●] witness.acme.corp
  [ Edit in SETUP → Edge ]
```

### 8.3 Universal components

| Component | Renders |
|-----------|---------|
| `OpEdgeRecordRow` | one record — kind, match, target, status pill |
| `OpEdgeRecordForm` | add/edit — guided, not raw JSON default |
| `OpDnsHintCard` | CNAME/A instructions + verify button |
| `OpTlsBadge` | external / pending / expired |
| `OpUpstreamHealth` | plugin pool health from `plugins/status` |
| `OpEgressMap` | agent/WF → allowed destinations (kerneld) |
| `OpConnectSnippet` | DevGuard `ANTHROPIC_BASE_URL` copy block |
| `OpEdgeProofResult` | pass/fail from prove endpoint |

**Custom workflow:** adds WORKFLOW_ROUTE row via manifest — same table, no new page.

### 8.4 Capability gating (with institutions)

| Institution | Edge UI shows |
|-------------|---------------|
| TT | HOST_ALIAS, CAGE_INTERNAL, `/cage/:sha` hint, compliance path |
| WC | INSTITUTION_ROUTE, `/witness` path, export not edge |
| DG | AGENT_ROUTE, connect snippet, `/v1` PATH_ROUTE — **no** WC-style host |
| WF only | WORKFLOW_ROUTE compose picker (institutions checklist) |

---

## 9. Relationship to other planes

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  CEP        │     │  CFNI       │     │  Capabilities│
│  routing    │────►│  forensic   │◄────│  export/act  │
│  intent     │     │  stamp      │     │  registry    │
└─────────────┘     └─────────────┘     └─────────────┘
       │                                       │
       └───────────────┬───────────────────────┘
                       ▼
              WORKFLOW MANIFEST
              institutions + edge + evidence
```

- **CEP** = where traffic **should** go  
- **CFNI** = cryptographic proof of what **did** go (transit)  
- **Capabilities** = what operators **can do** (export PDF, connect IDE)  
- **Workflow manifest** = selects which rows matter for this automation  

`edge_record.policy.require_cfni` links CEP → CFNI when substrate matures.

---

## 10. Phased delivery

### E0 — Document + merge read API (no new storage)

- [ ] `edge_record.v1` schema
- [ ] `GET /operator/edge/plane` merges custom_domains + internal_dns + plugins/status + public URL
- [ ] UI: read-only Edge table in SETUP

### E1 — Universal Edge UI (SETUP)

- [ ] `OpEdgeRecordRow`, `OpDnsHintCard`, `OpConnectSnippet`
- [ ] DNS hints + prove button (wraps `cage_proof`)
- [ ] Workflow drawer Edge tab (filtered records)

### E2 — Write path + guided forms

- [ ] `POST /operator/edge/records` → writes `custom_domains` + future WORKFLOW bind store
- [ ] `OpEdgeRecordForm` — HOST_ALIAS wizard (host → plugin dropdown)
- [ ] Honest `pending_dns` / `misconfigured` status

### E3 — Workflow + agent bindings

- [ ] WORKFLOW_ROUTE in manifest (`edge.routes[]`)
- [ ] AGENT_ROUTE summary in agent drawer
- [ ] EGRESS_RULE view from kerneld (read-only first)

### E4 — TLS + DNS automation (optional)

- [ ] ACME integration or Cloudflare API worker (operator choice)
- [ ] TLS_POLICY not metadata-only
- [ ] PORT_BIND for advanced installs

### E5 — CFNI at edge

- [ ] `require_cfni` policy enforcement
- [ ] Edge observability: denials without stamp

---

## 11. Laws

| # | Law |
|---|-----|
| **E1** | One **Edge table** — not TT DNS page + WC DNS page + settings JSON |
| **E2** | `*.cnktros` never appears in public DNS hints |
| **E3** | DevGuard = **gateway route**, not fake institution host |
| **E4** | Workflow differences = **bind** on records, not new UI |
| **E5** | External TLS can stay on Caddy/Fly — CEP owns **intent + proof** |
| **E6** | Every record has **health + prove** — no green without check |
| **E7** | Egress rules visible next to ingress routes (same plane) |

---

## 12. Success tests

1. Operator adds `tracetramp.acme.corp` in **one form** — not custom_domains JSON + Caddy + env.
2. HITL workflow drawer shows TT+WC edge rows; PII workflow shows DG connect + gateway only.
3. `dig tracetramp.cnktros` failure still in prod gate; public alias proves OK.
4. Custom WF adds WORKFLOW_ROUTE via manifest — appears in Edge table, no UI PR.
5. Operator explains edge like Cloudflare: **"Records point the world at plugins, workflows, and agents."**

---

## 13. Key backend files (reference)

| Path | Role |
|------|------|
| `platform/server/src/services/custom_domain_routing.rs` | Host → cage middleware |
| `platform/server/src/services/plugin_cage_proxy.rs` | `/plugin/<slug>/*` |
| `platform/server/src/internal_dns/mod.rs` | `*.cnktros` registry |
| `platform/server/src/services/gateway.rs` | `/v1` LLM |
| `platform/server/src/protocol_gateway/mod.rs` | `:9092` protocols |
| `platform/server/src/services/tracetramp_proxy.rs` | TT admin forward |
| `platform/server/src/services/witnessctl_proxy.rs` | WC forward + export bytes |
| `platform/server/src/services/devguard.rs` | Connect + gateway hooks |
| `platform/server/src/services/cage_proof.rs` | Routing proof |
| `platform/connector-kerneld/src/main.rs` | Host egress |
| `platform/deploy/Caddyfile` | External edge template |
| `docs/TLS_CUSTOM_DOMAIN.md` | Operator TLS pattern |

---

*CEP is the networking control plane for the Universal Operator Shell. Configure outer world → isolated workflows and agents on one plane — simple like Cloudflare, native like Connector.*
