# Brand and assets

**Audience:** anyone shipping Connector copy, landing (`cnktros.com`), or operator docs.  
**Honesty rule:** Connector is a generic intelligence OS. Institutions (DevGuard, TraceTramp, WitnessCtl) sit on the OS. They are not the OS.

---

## Marks

| Mark | Where it belongs | Where it does not |
|------|------------------|-------------------|
| Cyan knot + **cnktros** wordmark (`logo.png`) | `cnktros.com`, operator docs, OG publisher logo | OSS crate READMEs as a substitute for the OSS shield |
| Purple shield + “Connector OSS / Tamper-Proof Memory” (`oss/assets/`) | OSS crates only | `cnktros.com` |
| Teal letter-C favicon (old landing `favicon.svg`) | Parked | New tabs / nav |

Canonical lockup source: `platform/docs/important-images/` (ChatGPT `07_32_21`, identical to `07_36_20`).

Landing copies:

- `platform/docs/landing-page/web/public/logo.png` — full lockup
- `platform/docs/landing-page/web/public/favicon.png` — same lockup for the tab icon until a mark-only crop exists
- `docs/images/logo.png` — same file for markdown

Do not hotlink `cnktros.com` from operator docs. Copy PNGs into `docs/images/`.

---

## Diagrams (use these)

Stable names live in `platform/docs/landing-page/web/public/img/` and, for docs, `docs/images/`.

| File | Meaning | Landing | Docs |
|------|---------|---------|------|
| `os-stack.png` | Substrate → `connector-platform` → institutions on the OS | Home hero, About OS, Solution | This page, [truth story](CONNECTOR_TRUTH_STORY.md) |
| `world-cage.png` | Pore table default DROP, dest-pinned Landlock child | About OS, DevGuard product | [World cage](WORLD_CAGE_AND_BROWSER.md) |
| `nine-rings.png` | Nine rings; ring 7 is the world cage | About OS | optional architecture |
| `hmac-chain.png` | Issuer HMAC journal; tamper detectable | WitnessCtl, About OS Prove | not world-cage |
| `vendor-cut.png` | Direct vendor DROP vs `/v1` then marked child | Get started, About OS | [World cage](WORLD_CAGE_AND_BROWSER.md) vendor cut |

Parked (typos or older drafts): `06_26_34` (nine-rings alt), `06_30_24` (hmac alt), `06_33_34` (vendor-cut alt). Prefer `06_40_38`, `06_44_35`, `07_02_57`.

---

## Concept UI (not shipping screenshots)

`ui-agent-runtime.png`, `ui-fabric.png`, `ui-controlled-world.png` (`hero-og.png` is the last of these, used as OG).

They show Firecracker, “Isolation 100%”, microVM grids. **Alt and captions must say concept operator surface — not the shipping dashboard.** World dials today use dest-pinned Landlock children. MicroCell / Firecracker is a separate plane.

---

## Old SVGs

Keep in `platform/docs/landing-page/web/public/svg/` as archive. Do not put `oss-arch-four-rings.svg` (four rings, not nine) or `oss-ucan-capability.svg` (UCAN is not a shipping claim) on live pages. `connector-isolate-govern-verify.svg` is superseded by `os-stack.png`.

---

## Claims that must not ride the art

- Not Firecracker-by-default
- Stop is not undo
- Issuer HMAC ≠ court-grade / N-of-M quorum
- Memory and journals stay on the node; vendor LLM HTTP may leave when a model is granted
- Default listen is `:9091`, not `:8080`
- Binary is `connector-platform`, not `connector-server`
- No “air-gap ready” or “W3C DID” as a shipped SKU until AgentPassport exists
