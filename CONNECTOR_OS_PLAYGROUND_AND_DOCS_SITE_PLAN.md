# Connector OS — hosted playground + docs website (plan)

> **Purpose:** Plan a **vendor-hosted** experience where prospects and developers **try Connector OS in the browser** (no install), read **all public docs and tutorials on the same site**, and only **book a calendar / commit** after they understand the product.  
> **Not in scope here:** Replacing the **customer-owned node** (`connector-platform` tarball) — the playground is a **shared demo substrate**, not production tenancy. See **`ARCHITECTURE.md`** (vendor control plane vs customer node).  
> **Related:** **`CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md`** (target stories), **`CONNECTOR_OS_PUBLIC_LAUNCH_CHECKLIST.md`** (launch gates), **`CONNECTOR_OS_ROADMAP.md`** §1.1 (operator vision).

---

## 1. Product intent

| Visitor need | What we provide |
|--------------|-----------------|
| “What is this?” | Marketing + architecture narrative on **one origin** |
| “Show me without installing” | **Playground**: live **operator dashboard** (or guided slices) against a **hosted Connector node** |
| “How do I wire my agents / TraceTramp / DevGuard?” | **Tutorials** that mirror Stories A–D in **`CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md`** |
| “I’m ready to talk / buy / self-host” | **Calendar / signup / download** CTAs only after try + read paths are clear |

**Principle:** The **website is the front door**; the **playground is the proof**; **docs are the manual**; **calendar is the conversion** — not the first click.

---

## 2. System topology (how it fits today’s repo)

```
                    ┌─────────────────────────────────────────┐
                    │  Public website (single origin)         │
                    │  e.g. https://connector.dev             │
                    │  ┌─────────────┐  ┌──────────────────┐  │
                    │  │ Marketing   │  │ Docs / tutorials │  │
                    │  │ + pricing   │  │ (MDX or static)  │  │
                    │  └─────────────┘  └──────────────────┘  │
                    │  ┌─────────────┐  ┌──────────────────┐  │
                    │  │ Playground  │  │ Calendar / signup│  │
                    │  │ (iframe or  │  │ (Cal.com / etc.) │  │
                    │  │  embedded)  │  └──────────────────┘  │
                    │  └──────┬──────┘                        │
                    └─────────┼───────────────────────────────┘
                              │ API + static (same site or BFF)
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌──────────────────────┐
│ connector-www   │ │ connector-      │ │ Playground node pool │
│ (portal UI)     │ │ license-server  │ │ (1..N connector-     │
│ platform/ui-    │ │ platform/       │ │  platform instances) │
│ leptos/www/     │ │ licensing/      │ │  HARD SANDBOX        │
└─────────────────┘ └─────────────────┘ └──────────────────────┘
```

| Layer | Repo / binary | Role in playground plan |
|-------|----------------|-------------------------|
| **Public shell** | Extend **`connector-www`** + new **docs site** section (or sibling app on same deploy) | Navigation: Home · Docs · Playground · Pricing · Book demo |
| **Identity & trials** | **`connector-license-server`** | Issue **short-lived playground tokens**, rate limits, optional email gate, link to portal account |
| **Live product** | **`connector-platform`** (dedicated **playground** fleet) | Real kernel + embedded **`connector-ui`** — not a mock UI |
| **Content** | **`docs/`** (+ curated public subset) | Source for tutorials; sync or build-time ingest into website |

---

## 3. Playground design (SaaS-like, one hosted node → pool)

### 3.1 What “one node” means for v1

- **v1:** Operate **one shared playground cluster** (single `connector-platform` process or small fixed pool behind a router) with **strong multi-tenant isolation at the product layer**:
  - **Ephemeral namespaces** per session (agents, workflows, memory prefixes).
  - **No cross-session data** readable from the UI or API.
  - **Reset** on session end or TTL (e.g. 45–90 minutes idle).
- **v1.5+:** **Pool of playground nodes** (N identical images) + queue when saturated; license server assigns `playground_session → node_id`.

### 3.2 Session model (website-only)

| Step | Behavior |
|------|----------|
| **Enter** | Visitor clicks **Try playground** (optional: email magic link or OAuth for abuse control). |
| **Provision** | Backend mints **`playground_session_id`**, scoped **API key** (read/write only inside sandbox policy), routes to playground origin. |
| **Experience** | Embedded **operator dashboard** (full or **guided mode** — see §3.3). |
| **Expire** | TTL + idle timeout; wipe session store; show “Session ended — start new” + CTA to docs or calendar. |
| **Abuse** | IP + fingerprint rate limits; no arbitrary outbound network from playground LLM keys (vendor keys only); cost caps per session/day. |

### 3.3 Guided vs full dashboard

Ship **guided mode** first for conversion clarity; add **full dashboard** when Stories A–D are stable on hosted nodes.

| Mode | User sees | Good for |
|------|-----------|----------|
| **Guided tours** | Fixed paths: Service Map → enable TraceTramp sample → run reference workflow → gateway snippet | First visit, marketing |
| **Sandbox dashboard** | Real **`connector-ui`** with restricted nav (no destructive admin, no raw vault export) | Power users evaluating before install |
| **API playground** | Optional tab: copy **gateway URL** + temp key + curl / Python snippet | Jordan persona (Story A) |

**Pre-filled catalog** on playground boot: TraceTramp, WitnessCtl, DevGuard **installed but not all enabled**; 3 reference workflows; sample agent — matches **`CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md`** §1.

### 3.4 What playground must *not* do (v1)

- No production data, customer BYOK for unrestricted providers, or host-level DevGuard install on visitor machines (DevGuard story = **docs + optional desktop helper download**, not full host takeover in browser).
- No promise of **100-plugin** scale on shared playground — cap installed plugins and concurrent sessions.
- No substitute for **self-hosted tarball** — playground CTA: **Download Connector OS** when ready.

---

## 4. Same website: documentation & tutorials (information architecture)

### 4.1 Top-level nav (one origin)

| Section | Contents |
|---------|----------|
| **Product** | What Connector OS is; vs Ollama / frameworks (short); **architecture diagram** (link **`ARCHITECTURE.md`** public summary). |
| **Playground** | Try live (§3). |
| **Docs** | Searchable library (see §4.2). |
| **Developers** | AGOS, `cargo connector new`, Hub, **`PLUGIN_CONTRACT.md`** public mirror. |
| **Pricing / Enterprise** | SKUs; link license portal. |
| **Book a call** | Calendar embed — **secondary** nav item, prominent only after playground or “Contact sales”. |

### 4.2 Docs library structure (map from in-repo `docs/`)

Publish a **curated public index** — not every internal arch doc on day one.

| Tier | Source (repo) | Public title (example) |
|------|---------------|-------------------------|
| **Start here** | `docs/01-quickstart.md`, `README.md`, **`CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md`** (edited for web) | Quickstart · How teams use Connector |
| **Operator** | `docs/32-connectorctl.md`, `docs/index.md` sections | CLI · Install · Upgrade |
| **Stories / tutorials** | New web-first guides derived from Stories A–D | Connect agents to gateway · TraceTramp tour · WitnessCtl audit path · Workflow catalog · DevGuard dev setup |
| **Architecture** | `docs/11-architecture-overview.md`, public slice of **`ARCHITECTURE.md`** | Nine rings · Node vs control plane |
| **Plugins & AGOS** | `docs/agos/plugin-authoring.md`, `docs/agos/abi-versioning.md` | Build a plugin · ABI policy |
| **Reference** | OpenAPI (`/openapi.json` from playground read-only or static export) | HTTP API reference |
| **Internal-only (not public v1)** | `CONNECTOR_OS_ROADMAP.md`, `MASTER_ISSUES.md`, raw arch assessments | — |

**Implementation options (pick one in Phase P1):**

1. **Static site generator** (mdBook, Docusaurus, Astro Starlight) in `platform/www-docs/` or `docs-site/` — build from `docs/` + `examples/`.
2. **In-app docs routes** inside expanded **`connector-www`** — faster single deploy, weaker search unless added.
3. **Hybrid:** marketing + playground in www; docs on `docs.connector.dev` subdomain with shared chrome (still “one website” via unified header).

### 4.3 Tutorial track (aligned with finish-line stories)

| Tutorial ID | Teaches | Playground exercise |
|-------------|---------|---------------------|
| **T1 — First 10 minutes** | Start node concept, catalog, health | Guided: open Service Map, read plugin row (PID/URI) |
| **T2 — Gateway** | Point SDK at gateway URL | Copy snippet; send test completion (playground validates) |
| **T3 — TraceTramp** | Traces from governed traffic | Enable sample plugin; view trace list |
| **T4 — WitnessCtl** | Receipt / policy concept | Run reference HITL workflow (dry-run OK on playground) |
| **T5 — Your workflow** | CLS + enable from catalog | Enable template; optional edit in read-only editor |
| **T6 — DevGuard** | Host dev tools (concept + download) | Docs-only + link to install helper; not full IDE in browser |
| **T7 — Self-host** | Tarball, `connectorctl start` | Exit playground → download page |

Each tutorial ends with: **Next tutorial** · **Open full playground** · **Book a call** (soft).

### 4.4 “Important info” hub (trust & ops)

Single **/trust** or **/docs/important** page aggregating:

- Security overview + disclosure process (`SECURITY.md`)
- Data handling for playground sessions (retention, no training on user content, region)
- License (OSS vs commercial)
- Status / known limitations (link v1 caveats from launch checklist)
- Changelog / release notes
- Support channels (community vs paid)

---

## 5. Calendar & conversion (after try, before commit)

| Funnel stage | Trigger | Action |
|--------------|---------|--------|
| **Aware** | Landing, SEO | Read product page |
| **Try** | Playground CTA | Session + optional account |
| **Learn** | Docs sidebar, tutorial completion | Depth on specific story |
| **Evaluate** | “Compare to stack” content | Download tarball or request pilot |
| **Commit** | Calendar widget | Sales / solutions engineering |
| **Retain** | Portal signup | License key, production node docs |

**Calendar rules:**

- Embed **Cal.com** (or equivalent) on `/demo` and tutorial completion screens — not on homepage hero (reduces low-intent bookings).
- Pass **UTM + playground_session_id** (hashed) to calendar for sales context.
- Offer **async path**: “Download quickstart PDF” for visitors who won’t book yet.

**Portal handoff:** After signup on **`connector-license-server`**, user gets production docs + install — playground account may upgrade to **pilot grant** (existing pilot APIs in `platform/licensing/`).

---

## 6. Phased delivery plan

### Phase P0 — Foundation (2–4 weeks, parallelizable)

- [ ] **Domain & deploy sketch:** `connector-www` + `connector-license-server` behind one ingress (Caddy/nginx per `platform/deploy/` patterns).
- [ ] **Public docs IA** (§4.1–4.2): nav + 5–10 pages from existing `docs/` (quickstart, architecture summary, connectorctl, AGOS intro).
- [ ] **Playground architecture doc** (this file) reviewed; threat model draft (session isolation, LLM spend caps).
- [ ] **Analytics:** page views, playground start, tutorial complete, calendar click (privacy-preserving).

### Phase P1 — Playground MVP (4–8 weeks)

- [ ] **Playground node** image: `connector-platform` with preset `CONNECTOR_PRESET=playground`, dev plugins pre-seeded, LLM via vendor keys only.
- [ ] **Session service** on license server (or small BFF): create / renew / destroy session; mint scoped API key.
- [ ] **Embed path:** iframe or reverse-proxy `/playground/` → playground node dashboard with session cookie / token.
- [ ] **Guided tour v1:** 3 steps (catalog, gateway copy, TraceTramp peek).
- [ ] **Rate limits + TTL + wipe** job tested under load.
- [ ] **Tutorials T1–T3** live on same site with “open in playground” deep links.

### Phase P2 — Docs depth + stories (4–6 weeks)

- [ ] **Search** across docs (Pagefind, Algolia, or built-in).
- [ ] **Tutorials T4–T7** + Story-aligned screenshots from playground.
- [ ] **OpenAPI** published (static from playground or release artifact).
- [ ] **Trust hub** (§4.4) + changelog from release process.
- [ ] **Sandbox dashboard** mode (restricted full UI) behind feature flag.

### Phase P3 — Scale & conversion polish (ongoing)

- [ ] **Node pool** + queue when session capacity exceeded.
- [ ] **Optional login** (GitHub/Google) to resume playground session 24h.
- [ ] **Calendar + CRM** integration; pilot grant automation from portal.
- [ ] **Hub teaser** in playground (install sample community plugin from public Hub only).
- [ ] **i18n** (if needed) — defer until English funnel proven.

---

## 7. Engineering checklist (add to public launch)

Merge into **`CONNECTOR_OS_PUBLIC_LAUNCH_CHECKLIST.md`** Part D when executing — summary here:

| # | Launch gate |
|---|-------------|
| G1 | Playground runs **real** `connector-platform` + `connector-ui`, not a mock |
| G2 | Session isolation verified (automated test: user A cannot read user B agent id) |
| G3 | Playground LLM spend capped; no visitor-supplied production API keys in v1 |
| G4 | Docs + playground + calendar on **one brand origin** (or documented subdomain set with shared nav) |
| G5 | Tutorials T1–T3 completable without installing software |
| G6 | Privacy policy covers playground session data |
| G7 | Playground SLO stated (e.g. business hours, best-effort vs 99.5%) |

---

## 8. Content ownership (who maintains what)

| Asset | Owner | Update trigger |
|-------|--------|----------------|
| Public docs pages | DevRel / Eng | Each release |
| Playground seed data | Platform eng | Plugin/workflow template changes |
| Tutorials | DevRel + PM | Story doc changes |
| Threat model / caps | Security | Quarterly or architecture change |
| Calendar copy & routing | GTM | Campaign |

---

## 9. Success metrics

| Metric | Target (first 90 days post-launch) |
|--------|-------------------------------------|
| Playground starts / week | Baseline then +20% MoM |
| Median session duration | >8 min |
| Tutorial completion (T1) | >40% of starts |
| Calendar bookings from playground/docs path | Track vs cold traffic |
| Tarball downloads after playground | Correlation >15% of engaged sessions |

---

## 10. Related documents

| Document | Relationship |
|----------|----------------|
| **`CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md`** | Playground must demonstrate these stories (subset in v1) |
| **`CONNECTOR_OS_PUBLIC_LAUNCH_CHECKLIST.md`** | Add Part **G** playground + docs gates before “public marketing launch” |
| **`CONNECTOR_OS_REMAINING_TO_REAL_SOFTWARE.md`** | Playground does not remove need for self-hosted finish line |
| **`ARCHITECTURE.md`** | Vendor plane hosts www + license; playground nodes are separate fleet |
| **`CONNECTOR_OS_ROADMAP.md`** §1.1 | Operator zero-terminal demo — playground is the web equivalent |

---

## 11. Open decisions (resolve in P0)

1. **Single repo app vs split:** extend `connector-www` only vs new `docs-site` crate.
2. **Playground tenancy:** one process with logical isolation vs one VM per session (cost vs safety).
3. **Email gate:** anonymous playground vs verified email for abuse/cost control.
4. **DevGuard in playground:** docs-only v1 vs limited browser extension demo.
5. **Calendar provider:** Cal.com vs HubSpot vs built-in scheduling.

Record decisions in this file’s header once locked.
