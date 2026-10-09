# cnktros.com — Landing Page Update Plan

> Current state: single-page marketing site with Hero, Video, Problem, Solution, Architecture, Services, Form.
> Target state: full product site with 9 plugin pages, enhanced navigation, buyer-outcome framing, tutorials, "Connector as the OS" narrative, and a smart intake form.

---

## What Exists Today (Audit)

| Component | Current content | Gap |
|---|---|---|
| `Nav.tsx` | 8 anchor links, flat single-page | No product dropdown, no pages |
| `HeroSection.tsx` | "Isolated agents. Governed decisions." | No product portfolio callout |
| `VideoSection.tsx` | Demo video embed | Fine — keep |
| `ProblemSection.tsx` | Shadow AI problem statement | Minor copy update |
| `SolutionSection.tsx` | Isolate / Govern / Verify pillars | Add "9 plugins, one OS" framing |
| `ArchSection.tsx` | Architecture diagram | Needs plugin portfolio block |
| `ServicesSection.tsx` | Use case bullets + diagrams | Replace with plugin card grid |
| `VisionFormSection.tsx` | CTA + pilot form | Keep structure, enhance |
| `PilotInterestForm.tsx` | Name, email, company, role, free-text | Add product interest, role enum, use case selector |

---

## Target Site Map

```
cnktros.com/                        ← Enhanced home (sections + smart nav)
cnktros.com/products/               ← All 9 plugins overview grid
cnktros.com/products/devguard       ← DevGuard product page
cnktros.com/products/tracetramp     ← TraceTramp product page
cnktros.com/products/conductor      ← Conductor product page
cnktros.com/products/agentloop      ← AgentLoop product page
cnktros.com/products/ledgerlens     ← LedgerLens product page
cnktros.com/products/witnessctl     ← WitnessCtl product page
cnktros.com/products/agentpassport  ← AgentPassport product page
cnktros.com/products/relay          ← Relay product page
cnktros.com/products/engram         ← Engram product page
cnktros.com/use-cases/              ← Use cases by buyer persona
cnktros.com/how-it-works/           ← "Connector as the OS" explainer
cnktros.com/get-started/            ← Tutorial: first agent in 5 minutes
```

---

## Build Order

### Phase 1 — Routing + Nav (Step 1)
- Install `react-router-dom`
- Add `BrowserRouter` + `Routes` to `App.tsx`
- Rewrite `Nav.tsx`: sticky header, Products megamenu dropdown (3-col grid of all 9 plugins), Use Cases, How it Works, Get Started links, "Request Access" CTA always visible, mobile hamburger drawer

### Phase 2 — Home Page Enhancements (Step 2)
- `HeroSection`: add plugin pill strip below subtitle, second CTA "Explore all 9 plugins →"
- `ServicesSection` → rename to `ProductsSection`: replace bullet list with 3×3 plugin card grid
- `SolutionSection`: add "Connector as the OS" narrative block after the 3 pillars
- `VisionFormSection`: keep CTA strip, update copy to reference the full portfolio

### Phase 3 — Enhanced Form (Step 3)
Full rewrite of `PilotInterestForm.tsx`:
- **Product interest** — multi-select chips for all 9 plugins + "Full OS"
- **Role** — dropdown: Developer / ML Engineer / Platform Engineer / CTO / CISO / Founder / Other
- **Company size** — dropdown: 1–10 / 11–50 / 51–200 / 201–1000 / 1000+
- **Primary use case** — dropdown: Agent governance / Cost & budget control / Compliance & audit / Memory management / Multi-agent orchestration / Developer tooling / Other
- **Timeline** — dropdown: Evaluating now / 1–3 months / 3–6 months / Just researching
- Keep: Name, Work email, Company, free-text "What are you building?"
- Submit button: shows selected product count dynamically ("Request access to 3 products")
- All new fields sent to existing `/api/submit-pilot` endpoint (extend payload)

### Phase 4 — Product Pages (Step 4)
One reusable `ProductPage.tsx` template, 9 data files:

**Template sections per product page:**
1. **ProductHero** — name, tagline, one-sentence outcome, CTA
2. **OutcomeGrid** — "What you get": 3 outcome cards (bold outcome + explanation)
3. **HowItWorks** — 3-step numbered flow with code/terminal snippet
4. **WhoItsFor** — buyer persona cards (Developer, Platform Eng, CISO, etc.)
5. **CompetitorTable** — feature comparison vs top 2-3 competitors
6. **Tutorial** — "Use it in 5 minutes": step-by-step with copy-paste commands
7. **ProductCTA** — form pre-filled with that product's interest checkbox checked

**9 product data files** (`src/data/products/`):

| File | Plugin | Tagline |
|---|---|---|
| `devguard.ts` | DevGuard | "Policy enforcement for every file, command, and secret your agent touches" |
| `tracetramp.ts` | TraceTramp | "Full execution graph for every agent call — language agnostic, zero instrumentation" |
| `conductor.ts` | Conductor | "Multi-agent orchestration without a framework — declarative pipelines, runtime enforcement" |
| `agentloop.ts` | AgentLoop | "Agent lifecycle management — spawn, monitor, suspend, recover, at scale" |
| `ledgerlens.ts` | LedgerLens | "Real-time cost attribution per agent, per team, per model — with hard budget gates" |
| `witnessctl.ts` | WitnessCtl | "Cryptographic audit receipts for every agent action — tamper-evident, SOC 2 ready" |
| `agentpassport.ts` | AgentPassport | "W3C DID identity for every agent — verifiable, portable, revocable" |
| `relay.ts` | Relay | "Zero-framework agent runtime — register any HTTP endpoint, get full Connector governance" |
| `engram.ts` | Engram | "Enterprise memory for agents — entropy-scored, dehallucination enforced, audit-chained" |

### Phase 5 — "How it Works" Page (Step 5)
`/how-it-works/` — "Connector as the OS":
- Opening: the problem with point solutions
- The kernel: what ConnectorOS provides at base
- 9 plugins diagram: kernel in center, 9 plugins orbiting, each with 1-line role
- "Use one plugin or all nine": progressive adoption narrative
- "How they work together": 3 example scenarios showing plugin combination
  1. Support AI: Relay + Engram + WitnessCtl
  2. Fintech compliance agent: DevGuard + LedgerLens + WitnessCtl + AgentPassport
  3. Multi-agent research: Conductor + AgentLoop + Engram + TraceTramp
- Bottom CTA → `/get-started/`

### Phase 6 — Use Cases Page (Step 6)
`/use-cases/` — by buyer persona:

| Persona | Pain | Plugins they need | Outcome they buy |
|---|---|---|---|
| **Developer** | Framework lock-in, no memory, no tooling | Relay, Engram | Ship faster, no rewrite |
| **ML Engineer** | Hallucinations, no grounding, entropy | Engram, WitnessCtl | Agents that don't lie |
| **Platform Engineer** | No visibility across agent fleet | TraceTramp, AgentLoop, Conductor | One pane of glass |
| **CTO** | $40K LLM bills, no breakdown | LedgerLens, Relay | Cost under control |
| **CISO** | No audit trail, shadow AI | WitnessCtl, DevGuard, AgentPassport | SOC 2 in 48 hours |
| **Healthcare CTO** | PHI leakage, hallucinated clinical facts | Engram + WitnessCtl | HIPAA compliant agents |

Each persona card links to: relevant product pages + a pre-filled form.

### Phase 7 — Get Started Page (Step 7)
`/get-started/` — "Your first governed agent in 5 minutes":

```
Step 1: Install Connector (one Docker command)
Step 2: Register your agent (relay register --name ... --uri ...)
Step 3: Change one env var (OPENAI_BASE_URL=http://relay:8087/v1)
Step 4: Make a call — see it in the audit log
Step 5: Set a budget gate (relay.yaml — 3 lines)
Step 6: Add memory (ENGRAM_URL=engram://key@host/namespace)
```

Each step has a copy-paste terminal block. Links to relevant product docs.

### Phase 8 — Deploy (Step 8)
```bash
cd platform/docs/landing-page/web
npm run build
vercel --prod
```

---

## New Dependencies to Add

```bash
npm install react-router-dom
npm install lucide-react          # icons for plugin cards and nav
```

No new CSS framework — extend existing `index.css` with new utility classes.

---

## File Structure After Update

```
src/
├── App.tsx                          ← Router + routes
├── index.css                        ← Extended with new styles
├── config.ts                        ← Unchanged
├── components/
│   ├── Nav.tsx                      ← REWRITE: megamenu, mobile drawer, sticky
│   ├── HeroSection.tsx              ← UPDATE: add pill strip + portfolio CTA
│   ├── ProductsSection.tsx          ← NEW (replaces ServicesSection): 3×3 plugin grid
│   ├── SolutionSection.tsx          ← UPDATE: add OS narrative block
│   ├── VideoSection.tsx             ← UNCHANGED
│   ├── ProblemSection.tsx           ← MINOR copy update
│   ├── ArchSection.tsx              ← UPDATE: add plugin portfolio diagram
│   ├── VisionFormSection.tsx        ← UPDATE: copy refresh
│   └── PilotInterestForm.tsx        ← REWRITE: smart multi-field form
├── pages/
│   ├── HomePage.tsx                 ← Extract home sections into this
│   ├── ProductsOverviewPage.tsx     ← /products/ grid of all 9
│   ├── ProductPage.tsx              ← Template: reused by all 9
│   ├── HowItWorksPage.tsx           ← /how-it-works/
│   ├── UseCasesPage.tsx             ← /use-cases/
│   └── GetStartedPage.tsx           ← /get-started/
└── data/
    └── products/
        ├── devguard.ts
        ├── tracetramp.ts
        ├── conductor.ts
        ├── agentloop.ts
        ├── ledgerlens.ts
        ├── witnessctl.ts
        ├── agentpassport.ts
        ├── relay.ts
        └── engram.ts
```

---

## Product Card Data Shape

```typescript
// src/data/products/types.ts
export interface ProductData {
  slug:        string
  name:        string
  tagline:     string
  description: string
  color:       string          // accent color for card border
  icon:        string          // lucide icon name
  outcomes:    Outcome[3]      // "What you get" — 3 items
  howItWorks:  Step[3]         // 3-step flow
  personas:    string[]        // buyer personas
  competitors: CompetitorRow[] // comparison table rows
  tutorial:    TutorialStep[]  // copy-paste steps
  competitors_headline: string // "vs LangChain" etc
}
```

---

## Form Payload (Extended)

```typescript
// New fields added to submit-pilot API payload
{
  name:          string
  email:         string
  company:       string
  companySize:   string   // new
  role:          string   // now dropdown not freetext
  products:      string[] // new — array of selected plugin slugs
  primaryUseCase: string  // new
  timeline:      string   // new
  useCase:       string   // free text — "What are you building?"
  _hp:           string   // honeypot unchanged
}
```

The `/api/submit-pilot` Vercel function needs to accept and store the new fields — update `api/submit-pilot.ts` to pass them through.

---

## Brand Preservation Rules (NON-NEGOTIABLE)

These must survive every change. Do not rewrite, soften, or replace:

- **Core tagline**: "Isolated agents. Governed decisions. Proven in production." — stays in Hero H1, verbatim
- **Brand name**: "Connector" on home, "ConnectorOS" in product context
- **Three pillars**: Isolate · Govern · Verify — appear on home and every product page footer
- **Visual identity**: dark background, monospace terminal blocks, existing SVG diagrams — all preserved
- **Existing SEO anchor text**: all existing section IDs (`#hero`, `#problem`, `#solution`, `#architecture`, `#services`, `#vision`, `#interest`) kept for backlink preservation — new pages are additive, not replacements
- **"Connector as infrastructure"** positioning: NOT a SaaS tool, NOT a framework. It is self-hosted governance infrastructure. This framing appears on home, every product page, and the how-it-works page.

## "Powered by ConnectorOS" — Applied to Every Product Page

Every plugin page must include, immediately below the product hero:

```
┌─────────────────────────────────────────────────────────┐
│  ⚡ Powered by Connector — Agentic Governance OS        │
│  DevGuard runs on the same kernel as all 9 plugins.    │
│  Add one. Add all. Same governance plane.              │
└─────────────────────────────────────────────────────────┘
```

- Rendered as a subtle banner/badge below the hero on every product page
- Links back to `/how-it-works/` (the OS explainer)
- Copy: "Powered by Connector — Agentic Governance OS · [View all 9 plugins →](/products/)"
- Every product page footer: "Isolate · Govern · Verify · [Back to Connector →](/)"

## Design Principles (carry through all new pages)

- **Dark background** — consistent with existing `index.css` dark theme
- **No new CSS framework** — extend existing CSS custom properties
- **Outcome-first copy** — every headline states what the buyer gets, not what the feature does
- **Progressive disclosure** — home teases, product page explains, get-started teaches
- **One primary CTA per page** — always "Request access" or "Get started", never two competing CTAs
- **Mobile-first** — nav drawer, single-column cards on mobile, readable terminal blocks
- **Fast** — no heavy JS libraries beyond react-router; product data is static JSON

---

## Copy Hierarchy (for each product page)

```
Page title (H1):    What outcome they buy
                    e.g. "Stop hallucinations before they reach users" (Engram)
                         "Every agent cost attributed in real time" (LedgerLens)
                         "SOC 2 audit trail for every agent action" (WitnessCtl)

Subheadline:        What the plugin is in one sentence
                    e.g. "Engram is enterprise memory for agents..."

Outcome grid:       Three concrete outcomes with evidence
                    e.g. "Entropy score on every write — know when memory goes bad"

How it works:       Three steps, each with a code snippet or terminal block

Competitor beat:    One table, sharp and honest
                    "vs Mem0", "vs LangChain", "vs Helicone" etc.

Tutorial:           Five steps, copy-paste ready, under 5 minutes

CTA:                "Request access to Engram →" → form with Engram pre-checked
```

---

## Execution Checklist

- [ ] Phase 1: Install react-router-dom, lucide-react; rewrite Nav; add routing to App.tsx
- [ ] Phase 2: Update HeroSection, ProductsSection, SolutionSection
- [ ] Phase 3: Rewrite PilotInterestForm with all new fields; update API endpoint
- [ ] Phase 4: Build ProductPage template + 9 product data files + 9 routes
- [ ] Phase 5: Build HowItWorksPage (OS narrative + scenarios)
- [ ] Phase 6: Build UseCasesPage (persona cards)
- [ ] Phase 7: Build GetStartedPage (5-minute tutorial)
- [ ] Phase 8: `npm run build` → verify no errors → `vercel --prod`
