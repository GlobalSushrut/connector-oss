# Connector Design System

> One Leptos primitive library, applied consistently across every
> route. The standard we hold against is what you'd expect from
> Linear, Vercel, Stripe, Notion — keyboard-first, accessible by
> default, no per-page reinvention of buttons, modals, tooltips,
> layout, headers, or empty states.

This document covers:

1. The design tokens (colour, type, motion, spacing, elevation, z-index) baked into the CSS layer.
2. The layout primitives that prevent component overlap.
3. The page primitives that give every route the same header / section rhythm.
4. The atoms (Button, TextField, Dialog, Tabs, …) that compose against the tokens.
5. The feedback primitives (Alert, Banner, EmptyState, Progress, Spinner, Toaster).
6. The cross-cutting UX infrastructure (error boundary, skeletons, route-change side effects).
7. The migration guide for pages still using ad-hoc HTML.

---

## 1 — Design tokens

All tokens live in `dashboard/input.css` under the `@theme` block.
Tailwind exposes them as utility classes (`text-brand`, `bg-success-10`,
`border-warn-30`, …). The five-token semantic palette is:

| Token     | Use                                  | Tailwind class examples                 |
| --------- | ------------------------------------ | --------------------------------------- |
| `brand`   | Primary CTAs, focus rings, links     | `bg-brand`, `text-brand`, `border-brand` |
| `success` | Healthy, online, completed           | `text-success`, `bg-success-10`         |
| `warn`    | Degraded, pending, attention         | `text-warn`, `bg-warn-10`               |
| `danger`  | Failed, destructive, over-cap        | `text-danger`, `bg-danger-10`           |
| `info`    | Neutral information                  | `text-info`, `bg-info/10`               |
| `muted`   | Secondary copy, helper text          | `text-muted`                            |

Every state has a 10%-opacity fill (`-10`) and a 30%-opacity stroke
(`-30`) variant pre-baked for chip / pill / badge backgrounds.

### Motion

The global `prefers-reduced-motion` rule in `input.css` neutralises
all animations, hover lifts, and 3D card tilts when the OS-level
preference is set. New components should never bypass this rule.

### Focus rings

A single `:focus-visible` rule applies a 2px brand ring with 2px
offset to every keyboard-reachable element. Components do not need
to manually wire their own focus styles — they get this for free.

### Touch targets

Anything tappable (`button`, `[role="button"]`, `a.nav-item`, `.tab-item`)
is forced to ≥40px tall on coarse pointers (mobile / tablet) via a
media query in `input.css`.

### Z-index stack

Named z-indices in 10-unit increments so layered surfaces never
collide. Anywhere you'd reach for `z-50` or `z-[60]`, use a named
class instead:

| Class          | Value | Use                                        |
| -------------- | ----- | ------------------------------------------ |
| `z-base`       | 0     | Default content                            |
| `z-raised`     | 10    | Slight lift (banner under topbar)          |
| `z-dropdown`   | 20    | Dropdown menus, command palette suggestions |
| `z-sticky`     | 30    | Sticky topbar / table headers              |
| `z-drawer`     | 40    | Sidebar / mobile drawer                    |
| `z-overlay`    | 50    | Overlay backdrop                           |
| `z-modal`      | 60    | Modal panel                                |
| `z-popover`    | 70    | Popovers above modals                      |
| `z-toast`      | 80    | Toast stack                                |
| `z-tooltip`    | 90    | Tooltips above toasts                      |
| `z-max`        | 100   | Last-resort top stop                       |

### Elevation scale

Five-step shadow scale tuned for the dark surface. Authors should
never roll their own `box-shadow` — use `shadow-elev-{0..5}` instead.

| Class           | Use                                       |
| --------------- | ----------------------------------------- |
| `shadow-elev-0` | Flat (inset border only)                  |
| `shadow-elev-1` | Default card                              |
| `shadow-elev-2` | Hover / focus lift                        |
| `shadow-elev-3` | Sticky surfaces (drawer, dropdown panel)  |
| `shadow-elev-4` | Modal panel                               |
| `shadow-elev-5` | Toast / tooltip                           |

### Motion tokens

Two durations × two easings — anything beyond that is noise. These
live as CSS custom properties (`--dur-fast`, `--dur-base`,
`--ease-snap`, `--ease-glide`, `--ease-spring`).

| Token          | When to use                                       |
| -------------- | ------------------------------------------------- |
| `--dur-fast`   | Hover / focus / colour transitions (120 ms)       |
| `--dur-base`   | Open / close / slide-in (180 ms)                  |
| `--dur-slow`   | Page-level transitions (280 ms — sparingly)       |
| `--ease-snap`  | Default — fast in, settled out                    |
| `--ease-glide` | Material standard — gentle                        |
| `--ease-spring`| Confirmation feedback (slight overshoot)          |

### Type scale

Nine-step scale with proper line-height + tracking pre-baked. The
heading sizes share an optical baseline so a `<PageHeader>` `text-h1`
sits at the same vertical offset on every route.

| Class          | Size / weight        | Use                                |
| -------------- | -------------------- | ---------------------------------- |
| `text-display` | 36 / 700, tight      | Hero / marketing                   |
| `text-h1`      | 30 / 700, tight      | PageHeader title                   |
| `text-h2`      | 24 / 600             | Section title                      |
| `text-h3`      | 20 / 600             | PageSection title, card titles     |
| `text-h4`      | 17 / 600             | Subsection title                   |
| `text-body`    | 14                   | Default body copy                  |
| `text-body-sm` | 13                   | Helper / description text          |
| `text-caption` | 12, slightly tracked | Captions, table cells              |
| `text-eyebrow` | 11 / 600, uppercase  | Category label above title         |
| `tabular-nums` | (any)                | Apply to metrics so digits align   |

### Spacing scale (8px grid)

Nine-tier stack spacing on the 8 px grid. The `<Stack>` and `<Inline>`
layout primitives consume these via the `Space` enum so the rhythm
matches across nested layouts.

| Tier  | Pixels |  Tier  | Pixels |
| ----- | ------ | ------ | ------ |
| `3xs` | 2      | `lg`   | 24     |
| `2xs` | 4      | `xl`   | 32     |
| `xs`  | 8      | `2xl`  | 48     |
| `sm`  | 12     | `3xl`  | 64     |
| `md`  | 16     |        |        |

---

## 2 — Layout primitives (`components::ui::layout::*`)

These prevent component overlap by enforcing a single layout
vocabulary across the app. All five primitives are typed; spacing
and alignment are enums, not strings.

| Primitive   | Direction      | Wraps? | Use case                                  |
| ----------- | -------------- | ------ | ----------------------------------------- |
| `Stack`     | Vertical       | n/a    | Default vertical flow                     |
| `Inline`    | Horizontal     | No     | Fixed-shape header rows, button bars      |
| `Cluster`   | Horizontal     | Yes    | Tag lists, badge groups, filter chips     |
| `Grid`      | 2-axis         | n/a    | Tile layouts (metrics, dashboards)        |
| `Center`    | Both           | n/a    | Empty states, login, 404                  |
| `Container` | Width-bounded  | n/a    | Page-level max-width + padding            |
| `Spacer`    | Flex filler    | n/a    | Push siblings apart                       |

### The overlap-safety trick

`<Stack>` applies `min-height: 0` so it can sit inside a flex parent
without collapsing. This is the canonical fix for the "my content
gets hidden under a sticky header" bug. Authors don't have to
remember it — every Stack does it.

### Example

```rust
use crate::components::ui::{Stack, Inline, Grid, Container, ContainerSize, Space};

view! {
    <Container size=ContainerSize::Page>
        <Stack space=Space::Lg>
            <PageHeader title="Agents".to_string() />
            <Grid cols=1 cols_md=2 cols_lg=3 space=Space::Md>
                <AgentCard />
                <AgentCard />
                <AgentCard />
            </Grid>
        </Stack>
    </Container>
}
```

The same `Space::Lg` tier flows through the whole page — section
breaks are visually consistent without manual `mt-6` / `mb-8` /
`space-y-4` tuning.

---

## 3 — Page primitives (`components::ui::page::*`)

Every route renders one `<PageHeader>` (the only `<h1>` on the page)
followed by `<PageSection>`s for sub-areas. The header lives at the
same scroll position relative to the topbar on every route, so
operators learn the shape once.

```rust
view! {
    <Container>
        <PageHeader
            eyebrow="Agents".to_string()
            title="Sales Bot".to_string()
            description="Production agent, owned by Sales Ops.".to_string()
            breadcrumbs=Some(vec![
                ("Home", "/"),
                ("Agents", "/agents"),
                ("Sales Bot", "/agents/sales-bot"),
            ])
            actions=Some(Children::new(move || view! {
                <Button variant=ButtonVariant::Secondary>"Duplicate"</Button>
                <Button variant=ButtonVariant::Primary>"Save"</Button>
            }.into_any()))
        />
        <PageSection title="Recent runs".to_string()>
            <RecentRunsTable />
        </PageSection>
    </Container>
}
```

### AppShell

`<AppShell>` is the single layout container that wraps the whole
app. It enforces the sidebar + topbar + content layout with the
`min-h-0 overflow-auto` recipe that keeps the content scrollable
without being hidden under the sticky topbar. `main.rs` mounts it
once around `<Outlet />` — pages don't construct it themselves.

---

## 4 — Atom primitives (`crate::components::ui::*`)

All primitives are accessible by default. They live in
`dashboard/src/components/ui/`. The full list and their use cases:

| Primitive    | Replaces                                 | Key behaviours                                                    |
| ------------ | ---------------------------------------- | ----------------------------------------------------------------- |
| `Button`     | `<button class="btn-…">`                 | 6 variants, 4 sizes, loading spinner, icon slots, ARIA-busy       |
| `TextField`  | `<input class="input">` + manual label   | Label + helper + error, `aria-invalid`, `aria-describedby`        |
| `Switch`     | Ad-hoc `<button>` toggles                | `role="switch"`, `aria-checked`, keyboard activation              |
| `Badge`      | `.badge-green` / `.badge-amber` / …      | Typed `BadgeVariant`, optional status dot                         |
| `Avatar`     | `<img class="avatar">` + initials hack   | Image + initials fallback, deterministic colour, sizes            |
| `Tooltip`    | `title="…"` (which doesn't announce)     | hover + focus, Escape dismiss, `role="tooltip"`                   |
| `Tabs`       | Ad-hoc tabs with `.tab-item`             | `role="tablist"/"tab"/"tabpanel"`, arrow-key nav                  |
| `Card` set   | `.card` div soup                         | shadcn-style `Card / Header / Title / Description / Content / Footer` |
| `Dialog`     | Hand-rolled modal `<div>`                | Focus trap, scroll lock, Escape, ARIA-modal, restore focus        |
| `Kbd`        | `<code>⌘K</code>`                        | Chip-shaped key with proper `<kbd>` element                       |
| `Separator`  | `<hr>` / `<div class="h-px bg-…">`       | Decorative vs semantic, horizontal / vertical                     |

### Variant types

Variants are enums, not strings. The compiler enforces consistency:

```rust
use crate::components::ui::{Button, ButtonVariant, ButtonSize};

view! {
    <Button variant=ButtonVariant::Danger size=ButtonSize::Sm>
        "Delete agent"
    </Button>
}
```

Adding a new variant means one match arm in `button.rs`, not a
codebase-wide string hunt.

### Handler conventions

Click / change handlers are typed as `Arc<dyn Fn(_) + Send + Sync>`.
Pages construct them once and pass them in:

```rust
use std::sync::Arc;

let on_save: Arc<dyn Fn(_) + Send + Sync> = Arc::new(move |_| {
    save_workflow();
});

view! { <Button on_click=on_save>"Save"</Button> }
```

`Arc` (not `Box`) is required because primitives that nest inside
`<Show>` / `ChildrenFn` boundaries need to re-render with the same
handler instance — `Arc` is `Clone`, `Box<dyn Fn>` is not.

---

## 5 — Feedback primitives

Every async operation in an enterprise app produces one of four
outcomes: success, failure, in-flight, or empty. The feedback
primitives map exactly to those:

| Primitive    | Channel               | Lifetime          | Use                                       |
| ------------ | --------------------- | ----------------- | ----------------------------------------- |
| `Alert`      | Inline, in-page       | Persistent        | Inline warnings, success acknowledgments  |
| `Banner`     | Pinned, top-of-page   | Persistent        | System state (maintenance, expired licence) |
| `Toast`      | Floating, bottom-right| Auto-dismiss 5 s  | Transient confirmations / errors          |
| `EmptyState` | In-place              | Until content     | List / panel / page has no data           |
| `Progress`   | Inline bar            | While running     | Determinate or indeterminate work         |
| `Spinner`    | Inline icon           | While running     | Tiny "this row is loading" indicator      |
| `Skeleton*`  | In-place placeholder  | While loading     | Content-shaped Suspense fallback          |

### Variant taxonomy

`AlertVariant` is reused across Alert / Banner: `Info`, `Success`,
`Warning`, `Danger`, `Neutral`. `Danger` and `Warning` carry
`role="alert"` so screen readers interrupt; others use `role="status"`
for polite announcement.

### EmptyState — the canonical shape

```rust
view! {
    <EmptyState
        title="No workflows yet".to_string()
        description="Workflows orchestrate your agents. Install a reference or build your own.".to_string()
        actions=Some(Children::new(move || view! {
            <Button variant=ButtonVariant::Primary>"Install reference"</Button>
            <Button variant=ButtonVariant::Ghost>"Read the guide"</Button>
        }.into_any()))
    >
        <WorkflowIcon />
    </EmptyState>
}
```

Every empty surface in the app should compose this shape. Never
land an operator at "No data." with no next action.

---

## 6 — Cross-cutting UX infrastructure

Beyond the primitives, four global subsystems live in `components/`:

### `toaster`

Single global `Toaster` mounted in `main.rs`. Push toasts from
anywhere:

```rust
use crate::components::toaster::toast;

toast::success("Workflow saved");
toast::error("Validation failed: missing 'inputs.body'");
```

Auto-dismiss after 5 seconds; manual dismiss via the close button.
ARIA `role="status"` so screen readers announce non-disruptively.

### `error_boundary`

`AppErrorBoundary` wraps the route tree in `main.rs`. Any panic
inside a routed view is caught, a recoverable "Something went wrong"
panel is rendered, and the error detail is shown behind the
developer-view toggle. Pages don't need to defend against their own
panics — the boundary catches them.

### `skeleton`

Content-shaped loading placeholders that prevent layout shift:
`SkeletonText`, `SkeletonHeading`, `SkeletonCircle`, `SkeletonCard`,
`SkeletonRow`, `SkeletonTable`, `SkeletonPage`. Use as Suspense
fallbacks:

```rust
view! {
    <Suspense fallback=|| view! { <SkeletonPage /> }>
        <UserDashboard />
    </Suspense>
}
```

### Route-change side effects

`main.rs` mounts a `RouteChangeSideEffects` sentinel inside `<Router>`
that, on every path change:

1. Resets keyboard focus to `<main id="main-content">` so screen
   readers re-announce the landmark.
2. Sets `document.title` from a path-derived fallback so every tab
   has a meaningful name (pages can still override via
   `use_page_title("…")`).

The fallback supports canonical overrides (`/cls-builder` →
"CLS Builder") with a titlecase converter for unknown paths. Unit
tests in `main.rs::tests` cover the helper.

---

## 7 — Migration guide

The new primitives don't break anything. The existing `.btn-primary`,
`.card`, `.badge-green` CSS classes still work; they're just the "raw"
layer below the primitives. Migrate at your own pace.

### Before / after

```rust
// BEFORE — pre-primitives, ad-hoc HTML + Tailwind:
view! {
    <button
        type="button"
        class="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium disabled:opacity-50"
        disabled=move || busy.get()
        on:click=on_save
    >
        {move || if busy.get() { "Saving…" } else { "Save" }}
    </button>
}
```

```rust
// AFTER — primitives:
use crate::components::ui::{Button, ButtonVariant};
use std::sync::Arc;

let on_save: Arc<dyn Fn(_) + Send + Sync> = Arc::new(move |_| save());

view! {
    <Button
        variant=ButtonVariant::Primary
        loading=busy
        on_click=on_save
    >
        "Save"
    </Button>
}
```

Wins:

- Focus ring is correct without thinking about it.
- Disabled state is `aria-disabled` + visual, not just visual.
- Loading state is `aria-busy` + a spinner with no extra layout work.
- The variant name is type-checked, not a string in a class attribute.

### Migration priority

The pages most worth migrating first (highest user-touch surface):

1. **Forms.** Every `<input>` should be `<TextField>` — that's
   where the `aria-invalid` / `aria-describedby` wins are biggest.
2. **Modals.** Replace any hand-rolled overlay with `<Dialog>` —
   one focus-trap + scroll-lock recipe across the app.
3. **Tabs.** Routes with multiple ad-hoc tabs (`/overview`,
   `/agents/:id`, `/plugins/:id`) should use `<Tabs>` for proper
   keyboard navigation.
4. **Lists with toggles.** Replace inline `<button>` switches with
   `<Switch>` so each row's toggle is announced correctly.

`SessionEndModal` is the reference port — read its source to see how
a non-trivial component composes against the primitives.

---

## 8 — Code-level rules

1. **No new inline `<button>` elements outside `components/ui/`.** Use
   `<Button>`.
2. **No new `<input type="text">` outside `components/ui/`.** Use
   `<TextField>` (or its kin: `TextFieldKind::Email` / `Password` /
   `Number` / `Search` / `Url` / `Tel`).
3. **No new `<hr>` for visual dividers.** Use `<Separator />`.
4. **No new `title="…"` for explanations.** Use `<Tooltip>`.
5. **No new bespoke modals.** Use `<Dialog>`.
6. **Variants are enums.** If you find yourself reaching for a string
   ("danger", "warning"), add a variant arm to the enum.

CI doesn't yet enforce these — they're code-review guardrails for
now. A `rg` guard in the existing `.github/workflows/ui-leptos.yml`
content-audit step could flag new `<button class=` and `<input class=`
usages outside `components/ui/` if we want to make the rules teeth-y.

---

## 9 — Roadmap

Shipped (Phase 8 + level-10 uplift):

- **Atoms** — Button, TextField, Switch, Badge, Avatar, Tooltip,
  Tabs, Card set, Dialog set, Kbd, Separator, Spinner.
- **Layout** — Stack, Inline, Cluster, Grid, Container, Center,
  Spacer.
- **Page chrome** — PageHeader (with eyebrow/breadcrumbs/actions),
  PageSection, Breadcrumbs, AppShell.
- **Feedback** — Alert, Banner, EmptyState, Progress, Spinner,
  global Toaster, AppErrorBoundary, typed Skeletons.
- **Tokens** — z-index stack, elevation scale, motion durations &
  easings, type scale, spacing scale, surface tiers.

Next phase, in priority order:

1. **DropdownMenu** — accessible menu with arrow-key nav, Escape
   close, type-ahead.
2. **Select** — proper `role="combobox"` / `listbox` with keyboard
   navigation.
3. **Popover** — generic positioned panel with collision detection.
4. **Confirm** — `confirm().await` helper for destructive flows.
5. **Toast actions** — undo button in toasts (Linear-style).
6. **DataTable** — sortable, paginated, selectable, sticky-headed
   table.
7. **Pagination** — accessible page-of-pages primitive.
8. **Combobox / Autocomplete** — typed search-and-pick.

---

## Appendix: file map

```
dashboard/src/components/
├── ui/
│   ├── mod.rs            # Re-exports
│   │
│   │ ── Atoms ─────────────────────────────────────────
│   ├── button.rs         # Button + OnClick type
│   ├── text_field.rs     # TextField + TextFieldKind
│   ├── switch.rs         # Switch (role="switch")
│   ├── badge.rs          # Badge + BadgeVariant
│   ├── avatar.rs         # Avatar + AvatarSize + initials fallback
│   ├── tooltip.rs        # Tooltip (hover + focus + escape)
│   ├── tabs.rs           # Tabs, TabList, TabTrigger, TabPanel
│   ├── card.rs           # Card, CardHeader, CardTitle, …
│   ├── dialog.rs         # Dialog, DialogHeader, DialogBody, DialogFooter
│   ├── kbd.rs            # Kbd
│   ├── separator.rs      # Separator
│   ├── spinner.rs        # Spinner + SpinnerSize
│   │
│   │ ── Layout & page chrome (level-10) ───────────────
│   ├── layout.rs         # Stack, Inline, Cluster, Grid, Container, Center, Spacer
│   ├── page.rs           # PageHeader, PageSection, Breadcrumbs
│   ├── app_shell.rs      # AppShell (sidebar + topbar + content)
│   │
│   │ ── Feedback ──────────────────────────────────────
│   ├── alert.rs          # Alert + Banner + AlertVariant
│   ├── empty_state.rs    # EmptyState
│   └── progress.rs       # Progress + ProgressSize
│
├── skeleton.rs           # SkeletonText/Heading/Circle/Card/Row/Table/Page
├── toaster.rs            # Global toast queue + toast::{success,error,…}
├── error_boundary.rs     # AppErrorBoundary
├── …                     # Pre-existing task-specific components
```

Date: 2026-05-25.
