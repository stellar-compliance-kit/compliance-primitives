# Accessibility audit — `web/`

An automated audit of `web/index.html` using [axe-core](https://github.com/dequelabs/axe-core)
(the same rule engine behind the Chrome DevTools Lighthouse accessibility
category and the `axe` browser extension), run headless via Puppeteer across
every viewport-width/color-scheme combination the page actually renders:

| Check | Viewport | Color scheme |
|---|---|---|
| desktop / light | 1280×800 | light (default) |
| desktop / dark | 1280×800 | dark (`prefers-color-scheme: dark`) |
| mobile / light | 375×800 | light |
| mobile / dark | 375×800 | dark |

All four combinations matter here: one finding below only reproduced in
dark mode, and another only reproduced at a narrow viewport width, so an
audit of only the default desktop/light rendering would have missed both.
See `scripts/check-accessibility.mjs` for the runnable version of this
audit — it now also runs as a CI job (`accessibility audit (web/)` in
`.github/workflows/ci.yml`), non-blocking for now per this issue's
acceptance criteria.

## Findings

All findings below were confirmed with a live axe-core run against the page
before this fix and re-verified at 0 violations across all four
viewport/color-scheme combinations after.

### 1. `<html>` missing a `lang` attribute — serious

**Rule**: [`html-has-lang`](https://dequeuniversity.com/rules/axe/4.13/html-has-lang) (WCAG 2.1 §3.1.1, Language of Page)

The page had no `<!DOCTYPE html>`, `<html>`, `<head>`, or `<body>` at all —
just a bare `<title>`, a couple of `<meta>` tags, and the visible content,
relying entirely on the browser's HTML5 tag-inference to construct an
implicit document. That inference never adds a `lang` attribute, so screen
readers have no declared language to select the correct pronunciation
engine/voice for, and it left the document without an explicit character
encoding (`<meta charset>`), which the HTML5 spec requires within the first
1024 bytes.

**Fix**: added an explicit `<!DOCTYPE html><html lang="en"><head>` with
`<meta charset="utf-8">` as its first child, moved the existing `<title>`
and `<meta>` tags inside `<head>`, and wrapped the visible content in
`<body>…</body>`.

### 2. Primary button fails contrast in dark mode — serious

**Rule**: [`color-contrast`](https://dequeuniversity.com/rules/axe/4.13/color-contrast) (WCAG 2.1 §1.4.3, Contrast (Minimum))

`.btn-primary` (the "View on GitHub" button) renders white text on
`var(--accent)`. In light mode `--accent` is `#0060df`, giving white text a
comfortable 5.6:1 contrast ratio. In dark mode `--accent` is redefined to
`#6ea8fe` — a much lighter blue, chosen so it reads well as *link/text*
color directly against the dark page background (7.8:1 there) — but reusing
it as a *button fill* under white text collapses to **2.41:1**, well under
the 4.5:1 AA minimum for normal-size text. Confirmed via axe-core:

```
[serious] color-contrast — foreground #ffffff, background #6ea8fe,
contrast 2.41 (expected 4.5:1) — .btn-primary
```

**Fix**: introduced a second CSS variable, `--accent-solid`, distinct from
`--accent`. `--accent` keeps its existing light/dark values (used for links,
the badge, and text-on-`--bg` contexts, none of which need to change).
`--accent-solid` is `#0060df` in light mode (same as `--accent` there) and
`#1f6feb` in dark mode — a darker, more saturated blue that gives white text
~4.63:1 while still reading clearly as "accent blue" against the dark
background (~4.08:1 against `--bg`, comfortably over the 3:1 UI-component
minimum). `.btn-primary` now uses `--accent-solid` for its background and
border.

### 3. Inline link distinguishable only by color — serious

**Rule**: [`link-in-text-block`](https://dequeuniversity.com/rules/axe/4.13/link-in-text-block) (WCAG 2.1 §1.4.1, Use of Color)

The sitewide `a { text-decoration: none; }` rule (underline only on
`:hover`) is a reasonable choice for navigation, footer, and button links,
which are set apart from surrounding content by position and chrome rather
than by sitting inside a paragraph of prose. But the "Architecture" section
has one link embedded directly in a sentence of body text (the
`/examples/denylist-gate-consumer` link), where color becomes the *only*
signal distinguishing it from the surrounding text — a real problem for
readers who can't perceive the color difference.

**Fix**: added a scoped rule, `section p a { text-decoration: underline; }`,
so any link inside a paragraph of section body copy is underlined by
default, without changing the nav/footer/button link style. This also
future-proofs any prose link added later in the page.

### 4. Horizontally-scrolling code/diagram blocks not keyboard-reachable — serious

**Rule**: [`scrollable-region-focusable`](https://dequeuniversity.com/rules/axe/4.13/scrollable-region-focusable) (keyboard operability)

`.flow` (the architecture call-flow diagram) and `pre.code` (the quick-start
shell commands) both use `overflow-x: auto` so their content scrolls
horizontally rather than wrapping or overflowing the layout. At desktop
width neither actually overflows, so this only reproduced at the mobile
(375px) viewport — where the diagram and the longer shell command lines do
overflow, and a keyboard-only user has no way to focus the region and
scroll it (no interactive descendant, and the container itself isn't
focusable).

**Fix**: added `tabindex="0"` plus `role="region"` and a descriptive
`aria-label` to both elements, and a visible `:focus-visible` outline in CSS
(the default outline can get visually clipped by `overflow: auto` in some
browsers).

### 5. No `<main>` landmark / page content not contained in a landmark — moderate

**Rules**: [`landmark-one-main`](https://dequeuniversity.com/rules/axe/4.13/landmark-one-main), [`region`](https://dequeuniversity.com/rules/axe/4.13/region) (best practice, screen-reader landmark navigation)

The page used `<nav>`, `<header>`, `<section>`, and `<footer>` — all
semantic, but with no `<main>` wrapping the actual page content, four of
the sections weren't contained by any landmark region, which makes
screen-reader landmark-jump navigation (a common way blind users skip
around a page) skip most of the page.

**Fix**: wrapped the hero `<header>` and all four `<section>` elements in a
single `<main>`, leaving `<nav>` and `<footer>` as their own top-level
landmarks (unchanged).

## Not run: color-blindness / low-vision simulation, screen-reader walkthrough

This audit is automated-tool coverage (axe-core), which the acceptance
criteria for this issue asks for as the baseline. Automated tools catch
programmatically-detectable issues (contrast math, missing attributes,
focusability) reliably, but they don't replace a manual screen-reader pass
or a real low-vision/color-blindness review — recommended as a manual
follow-up before this page is treated as fully accessible, not blocking for
this issue.
