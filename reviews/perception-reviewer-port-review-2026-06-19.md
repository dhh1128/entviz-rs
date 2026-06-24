# Perception & Psychophysics Review: entviz-rs (port review)

**Date:** 2026-06-19
**Effort level:** deep
**Run label:** port-review-2026-06-19
**Target:** `/home/daniel/code/entviz-rs` (Rust reference port of spec v10)
**Output examined:** SVG rendered from `entviz-conformance` binary; CVD simulations run
programmatically (Machado 2009 matrices) on all palette colors, map markers, and the
fingerprint-of marker; perceptual-entropy geometry analysis; font-family escaping
audit; Oklab lightness verification; prior Python reference-implementation review
(`reviews/perception-reviewer-2026-06-08 review.md`) consulted and findings cross-checked
against the Rust port.
**Implementation commit:** 79a96cb1f093ff75c284a1108234880db65913cd

---

## Evidence Inventory

**Read:**
- `/home/daniel/code/entviz-rs/src/lib.rs` — tokenization, fingerprint, nucleus_colors,
  oklab_lightness, closest_palette_color, select_visual_style.
- `/home/daniel/code/entviz-rs/src/pipeline.rs` — full render pipeline: all channels, font
  constants, ellipse overlay, color bar, quartile marks, blank-cell map.
- `/home/daniel/code/entviz-rs/src/entropy.rs` — format parsers, detect_alphabet_by_disproof.
- `/home/daniel/code/entviz-rs/src/conformance.rs`, `tests/cli.rs`, `tests/conformance.rs`.
- `/home/daniel/code/entviz/docs/spec.md` — spec v10 (full; palette rationale, honesty caveat,
  all channels, blank-cell map v8/v10 rationale, ellipse step claims).
- `/home/daniel/code/entviz/reviews/perception-reviewer-2026-06-08 review.md` — prior Python
  reference review with CVD simulation data, used as baseline.
- `Cargo.toml` — version 0.10.1.

**Simulations run:**
- Full palette CVD simulation (Machado 2009 severity-1.0 matrices; protan, deutan, tritan) plus
  luminance-only achromatopsia, for all 10 pairwise combinations of the 5 palette colors.
- Blank-cell map marker colors (#1d4ed8 dot, #d62828 plus) under all four CVD conditions.
- Fingerprint-of truncation marker (#a00000) vs. label gray (#666666) under all CVD conditions.
- Oklab lightness for all palette colors plus map marker colors and fp_marker, to verify the
  0.6-threshold text-color assignment.

**New renderings:**
- SVG rendered for `hex(64)` input and inspected for font-family escaping, band letter fill
  colors, blank-cell map shape (plus vs. circle), ellipse parameters, and quartile marks.
- Multiple inputs inspected to confirm blue-band letter uses white (#ffffff) fill (correct
  per Oklab L=0.445 < 0.6 threshold).

**Skipped:** Gallery HTML, browser screenshots, paper figures (not present in the Rust repo).
No full across-tab comparison user study (impossible statically). Tier-B raster comparison
not run (requires the Python runner).

**Key differences from the Python reference review (2026-06-08):**
- PSY-F1 (blank-map-indiscriminable-under-cvd): **resolved in spec v8, implemented in Rust**.
  The Rust port correctly renders the max marker as a plus (path) and the min marker as a
  circle, per spec §map-rendering. Shape distinction survives achromatopsia.
- PSY-F2 (palette honesty caveat incomplete): **resolved in spec v10**. The spec §palette-
  rationale now names all three sub-floor CVD pairs (protan red/blue ΔL*≈7, deutan gold/red
  ΔL*≈17, tritan red/blue ΔL*≈16) and names the color-bar letters as the guaranteed fallback.
- PSY-F3 (fp_marker overstated CVD claim): **not resolved** in spec v10. The "clearly
  hue-distinct under common CVD simulations" language is still present in §label-strips.
  Measured: deutan ΔL*=5.8 (fp_marker L*=37.4 vs. label_gray L*=43.2); tritan ΔL*=6.5.
- PSY-F4 (no CVD test for map dots/marker): **partially resolved in Python repo** (Python
  test_v6_palette_lightness.py covers palette + map dots). The **Rust port has no CVD tests
  at all** — neither a palette-lightness test nor a map-dot/marker test.
- PSY-F5 (ellipse JND unqualified): **not resolved**. Spec still asserts 16 steps ≈ JND
  without qualifying the across-tab scenario.
- PSY-F6 (surround-box small display): **not resolved**. Spec lacks a note on the 3px
  merge threshold.
- PSY-F7 (comparison ergonomics asymmetry): **addressed** in README. The README states
  "reject on any visible difference" prominently. Accepted as a design limitation of
  standalone SVG output.

---

## Perceptual Entropy Budget

Estimated for a typical 3×4 entviz at 12pt/96dpi. Simulation data is from Machado 2009.

| Channel | Nominal bits | Normal/16M (gestalt) | CVD (protan/deutan) | CVD (achromat/grayscale) | Low-vision/small |
|---|---|---|---|---|---|
| Text (≤512-bit) | Up to 512 | 6–8 gestalt; full deliberate | ≈ same (no color) | ≈ same | Degrades below ~6pt |
| Surround (24 bits/cell, 12 cells) | 288 | 5–8/cell × 12 ≈ 60–96 | ~40–60 (palette collapses to 2–3 perceived) | ~30–40 (lightness-only) | Boxes merge at ≤3px width |
| Color bar (histogram, count^4, band-order) | ~8–10 | 5–7 (band order + relative heights) | 4–6 (letters compensate) | 4–5 (lightness bands + letters) | Legible to ~6pt |
| Ellipse (anchor × rx × ry × rot) | ~15 | 8–10 (each step above JND simultaneous) | ≈ same (shape-based) | ≈ same | r_step=4.1px; rot_step=12°; borderline non-simultaneous |
| Blank-cell map (plus/dot positions, shapes) | ~7 | 5–7 | 5–7 (shape survives CVD per v10) | 4–6 (shape+position; max/min DISTINGUISHABLE via plus vs circle) | Markers 3.5px radius; visible but small |
| Quartile marks (4 corners, orientation) | ~13 | 4–6 | ≈ same (B&W marks) | ≈ same | Orientation OK to 6pt (leg=5px) |
| Entviz background (2 bits) | 2 | 2 | 1–2 (some pairs collapse) | 1–2 | 2 |
| Nucleus color (RGB from quant) | 24/cell | 5–8 total | ~1–3 (hue collapse) | 0–1 (sub-JND hint) | 0 (all merge) |
| **SUM (gestalt, union)** | — | ~35–48 | ~22–32 | ~16–22 | ~10–15 |

**Assessment:** The multi-channel union clears the randomart ~20–24 bit benchmark under normal
vision (by a wide margin) and under protanopia/deuteranopia (the shape-based channels and
color-bar letters carry the load). Under achromatopsia the estimated gestalt budget is
~16–22 bits, at or above the benchmark, with the critical gain from v10's plus/circle
distinction in the blank-cell map (the prior achromat weakness). The Rust port faithfully
implements all channels; the remaining perceptual concerns are shared with the spec and the
Python reference (they are design gaps, not Rust-specific implementation bugs).

---

## Executive Summary

The Rust port (entviz-rs v0.10.1, spec v10) is a faithful perceptual implementation of
the spec. The most significant perceptual weaknesses from the 2026-06-08 Python review —
the blank-cell map achromat indistinguishability (PSY-F1, now fixed via plus/circle
distinction) and the incomplete palette CVD honesty caveat (PSY-F2, now updated in spec) —
are both resolved at the spec level and correctly implemented in Rust.

Two residual concerns carry over from the prior review. The fingerprint-of truncation marker
(#a00000) remains described as "clearly hue-distinct under common CVD simulations" in spec
§label-strips — a claim that our measurements refute for deuteranopia (ΔL*=5.8) and
tritanopia (ΔL*=6.5), where bold weight is the sole surviving differentiator. The ellipse's
"16 steps ≈ JND" claim remains unqualified for the across-tab comparison scenario, where
rotation JND inflates and 12° per step is borderline.

The most urgent port-specific gap is the **complete absence of CVD regression tests** in the
Rust codebase: the Python reference has `tests/test_v6_palette_lightness.py` pinning palette
lightness gaps and three known CVD sub-floor exceptions; the Rust port has no equivalent.
A color change in `POSSIBLE_EDGE_COLORS`, `#1d4ed8`, `#d62828`, or `#a00000` would silently
regress CVD discriminability. Given that the spec's CVD guarantee is a load-bearing claim,
this is the highest-priority actionable gap in the Rust port.

---

## Top Findings

Ordered by bang-for-buck.

---

### F1: No CVD regression tests in the Rust port (palette, map markers, fp_marker)

- **Population:** CVD (all types), GRAYSCALE/LOW-COLOR
- **Severity:** HIGH
- **Confidence:** CONFIRMED (inspection of test suite; no test references any palette color or CVD simulation)
- **Location:** `/home/daniel/code/entviz-rs/tests/`, `/home/daniel/code/entviz-rs/src/lib.rs:206` (POSSIBLE_EDGE_COLORS)
- **Finding:** The Rust port's test suite (lib tests in `src/lib.rs` and `src/pipeline.rs`;
  integration tests `tests/conformance.rs` and `tests/cli.rs`) contains no CVD simulation,
  no palette lightness test, and no test for the map marker colors (#1d4ed8, #d62828) or
  the fingerprint-of truncation marker (#a00000). The Python reference implementation has
  `tests/test_v6_palette_lightness.py` that pins (a) all pairwise CIELAB ΔL* values for
  the five palette colors under protan, deutan, tritan, and achromatopsia using the Machado
  2009 model, and (b) explicitly names the three known sub-floor CVD exceptions
  (`CVD_EXCEPTIONS`). No equivalent exists in Rust. Any change to `POSSIBLE_EDGE_COLORS`
  — even a single digit in a hex code — could silently reduce the palettes's CVD
  discriminability below the design floor without failing any test. This is especially
  concerning because the spec makes a public CVD guarantee ("usable by people with
  red-green, blue-yellow, and complete color blindness") and three sub-floor pairs are
  already admitted; introducing a fourth would be invisible.
- **Evidence:** `grep -rn "CVD\|achromat\|protan\|deutan\|tritan" /home/daniel/code/entviz-rs/src/`
  returns only `oklab_lightness` function hits (the Oklab math), no CVD simulation tests.
  `POSSIBLE_EDGE_COLORS = ["#ffffff", "#e7be00", "#ff3f2f", "#2f3fbf", "#000000"]` is
  unconstrained by any regression that would catch a lightness gap regression.
  Simulated ΔL* under protan: red/blue=7.5 (sub-floor, known); deutan: gold/red=17.4
  (sub-floor, known); tritan: red/blue=15.6 (sub-floor, known). All others ≥20.
- **Recommended action:** Add a Rust unit test (in `src/lib.rs` or a new `tests/cvd.rs`)
  that:
  (a) Hard-codes the Machado 2009 severity-1.0 matrices for protan/deutan/tritan and a
  luminance-only achromatopsia transform.
  (b) For every pair of POSSIBLE_EDGE_COLORS, asserts CIELAB ΔL* ≥ 17 under normal
  vision (achromatopsia), except the three pinned exceptions (protan red/blue ≥6, deutan
  gold/red ≥15, tritan red/blue ≥14).
  (c) Asserts ΔL* between the two map marker colors (#1d4ed8 vs. #d62828) is ≥ 5 under
  all CVD conditions (shape carries the semantic, but complete invisibility is unacceptable).
  (d) Asserts the fp_marker (#a00000) Oklab L ∈ [0.35, 0.55].
  This test should fail on any palette change that introduces a new sub-floor pair, matching
  the Python test's role.
- **Fix effort:** medium (Machado matrices are ~30 floats; full test is ~100 lines of Rust)

---

### F2: Fingerprint-of truncation marker (#a00000) still described as "clearly hue-distinct" under CVD; claim overstated

- **Population:** CVD (deuteranopia, tritanopia)
- **Severity:** MEDIUM
- **Confidence:** CONFIRMED (Machado 2009 simulation; same result as prior Python review)
- **Location:** `docs/spec.md §label-strips` ("remains clearly hue-distinct from the rest of the label under common CVD simulations"); `/home/daniel/code/entviz-rs/src/pipeline.rs:948` (#a00000 tspan fill)
- **Finding:** The spec's §label-strips section allows implementations to substitute a
  different dark-red color for the fingerprint-of truncation marker, provided the substitute
  "(c) remains clearly hue-distinct from the rest of the label under common CVD simulations."
  This condition is overstated. Under Machado 2009 deuteranopia simulation, the reference
  color #a00000 maps to simulated L*=37.4, while the label gray #666666 maps to L*=43.2 —
  a ΔL*=5.8 gap. Under tritanopia, ΔL*=6.5. In both cases the hue distinction (dark red vs.
  gray) is entirely absent: the two colors become dark olive vs. neutral gray (deutan) or
  dark maroon vs. neutral gray (tritan). Bold font-weight and the ~6 ΔL* gap are the only
  surviving differentiators. The "hue-distinct" requirement in the substitution constraint
  is therefore impossible to satisfy for CVD users, and since it is a normative substitution
  clause, an alternative implementation that tests compliance with this clause will be
  checking for something that cannot hold under severe CVD. The reference implementation's
  choice (#a00000) is not itself wrong — the WCAG AA constraint and Oklab L ∈ [0.35, 0.55]
  are the normative requirements, and both pass — but the prose claim is misleading.
  Under protanopia: ΔL*=19.4 (marker L*=23.8 vs. label L*=43.2) — clear lightness
  distinction but still no hue (both appear brownish). Under achromatopsia: ΔL*=10.4
  (marker L*=32.7 vs. label L*=43.2) — readable by lightness alone, and bold weight
  confirms it. The bold weight is the practical safety net for CVD users.
- **Evidence:** Machado 2009 simulation on #a00000 vs. #666666:
  - protan: fp_marker L*=23.8, label_gray L*=43.2, ΔL*=19.4 (lightness clear, hue lost)
  - deutan: fp_marker L*=37.4, label_gray L*=43.2, ΔL*=5.8 (marginal, hue lost)
  - tritan: fp_marker L*=36.7, label_gray L*=43.2, ΔL*=6.5 (marginal, hue lost)
  - achromat: fp_marker L*=32.7, label_gray L*=43.2, ΔL*=10.4 (readable by lightness)
  The Rust code at `pipeline.rs:948` emits `fill=\"#a00000\" font-weight=\"bold\"` for the
  tspan — correct implementation, incorrect spec prose around it.
- **Recommended action:** In `docs/spec.md §label-strips`, revise condition (c) of the
  substitution rule from "remains clearly hue-distinct from the rest of the label under
  common CVD simulations" to "remains lightness-distinct from the rest of the label, with
  bold font-weight as the primary CVD differentiator; hue distinction is a bonus under
  normal vision only." No code changes required in the Rust port.
- **Fix effort:** small (spec prose edit only; this is a shared spec/docs finding)

---

### F3: Ellipse rotation step (12°) is borderline for across-tab/memory-based comparison; JND claim unqualified

- **Population:** ALL (most acute for non-simultaneous comparison)
- **Severity:** MEDIUM
- **Confidence:** SPECULATIVE (geometry analysis; no user study confirming across-tab JND)
- **Location:** `docs/spec.md §ellipse-overlay` ("16 discrete steps per parameter is intentional: it's near the just-noticeable-difference threshold"); `/home/daniel/code/entviz-rs/src/pipeline.rs:703–705` (rx/ry/rotation computation)
- **Finding:** At the nominal 12pt/3×4 case: `r_step = 4.1 px per step` (rx/ry range 61px,
  15 steps) and `rotation_step = 12°`. The 4.1px radius step is above the standard 2–4px
  edge-position JND for simultaneous side-by-side comparison and is adequate for that case.
  The 12° rotation step is at the *boundary* of psychophysical JND for complex shapes (Riesz
  1979, Howard & Rogers 1995 estimate 10–15° for complex targets with brief exposure). For
  the realistic across-tab comparison scenario — the user switches between two browser tabs
  and must recall the previous orientation from visual memory — the effective JND for both
  radius and rotation is typically 2–4× higher than for simultaneous comparison. Under
  across-tab conditions, adjacent rotation steps (12°) may be imperceptible for a subset
  of users, reducing the effective ellipse step count from 16 to perhaps 6–8. The rx/ry
  steps at 4.1px may also become marginal (vs. a memory-based threshold of 8–15px).
  Neither the spec nor the Rust code documentation notes this degradation. The Rust
  implementation matches the spec exactly; the issue is in the spec's unqualified claim.
  Computed at 12pt/96dpi from `pipeline.rs:703–705`: `rx = r_min + (digest[61] % 16) / 15.0 * (r_max - r_min)`, `rotation = (digest[63] % 16) / 15.0 * 180.0`.
- **Evidence:** Geometry: at 3×4 grid 12pt, d_far≈169.7px, r_min=37.3px, r_max=98.4px,
  r_step=4.1px, rot_step=12°. Rotation JND for complex shapes under brief exposure: 10–15°
  (literature; no user study in this repo). Spec claims "near the just-noticeable-difference
  threshold" without qualification. No ellipse-specific JND measurement in `reviews/ellipse-audit-2026-06-02.md`.
- **Recommended action:** Add a qualification to `docs/spec.md §ellipse-overlay`: "The JND
  estimates assume simultaneous side-by-side comparison; for across-tab or delayed
  comparison (where the viewer must recall one entviz from memory while viewing the other),
  the effective JND for both radius and rotation is higher, and the discriminable step count
  may be 6–8 rather than 16." Document as a Residual Unknown. No algorithm change implied.
- **Fix effort:** small (spec documentation addition)

---

### F4: Surround-box individual discriminability collapses at ≤3px box width (6pt or scaled small); no spec note

- **Population:** LOW-VISION, small-display (mobile, CSS-scaled)
- **Severity:** MEDIUM
- **Confidence:** LIKELY (geometry analysis; standard anti-aliasing behavior)
- **Location:** `docs/spec.md §geometry` (box dimensions); `/home/daniel/code/entviz-rs/src/pipeline.rs:150–153` (box_w/box_h computation)
- **Finding:** At the minimum allowed 6pt reference font size (`pipeline.rs:82`: "6.0..=30.0"
  range check), the computed box dimensions are: `box_w = nucleus_w / 8 = 24/8 = 3.0px`,
  `box_h = nucleus_h / 2 = 10/2 = 5.0px`. At 3px width, adjacent surround boxes are flush
  (no inter-box gap), and at rendering, anti-aliasing merges adjacent filled boxes into a
  continuous horizontal strip — the spatial arrangement of filled/empty boxes (which is the
  24-bit channel's information) is lost and only aggregate fill density remains. The same
  degradation occurs when a 12pt entviz is CSS-scaled to ~50% (as in a small viewport). The
  spec does not specify a minimum rendered box size below which individual box discrimination
  degrades; the `[6, 30]pt` range is the only constraint. The Rust implementation correctly
  enforces this range (`pipeline.rs:82–84`) but cannot prevent CSS scaling below it. The
  24-bit-per-cell surround channel degrades from ~24 bits to ~3–4 bits (fill-density histogram)
  at this threshold. This was PSY-F6 in the Python reference review; it applies equally to
  the Rust port.
- **Evidence:** `pipeline.rs:150–155`: `box_w = nucleus_w / 8 = font_px * 3 / 8`. At 6pt:
  `font_px = 6 * 96 / 72 = 8.0px`, `box_w = 8 * 3 / 8 = 3.0px`. Standard display-acuity
  limit for individual feature resolution: ~2px at 96dpi from arm's length. At 3px width,
  boxes are flush; at 2px after anti-aliasing, they merge.
- **Recommended action:** Add a note to `docs/spec.md §geometry`: "At display sizes rendering
  surround boxes below ~4×7px (e.g., a 6pt reference font or a 12pt entviz scaled to ≤50%
  of its design size), individual boxes may merge visually and the surround channel degrades
  to a fill-density hint. For reliable comparison, a minimum rendered font size of 8pt is
  recommended." No algorithm or Rust code change required.
- **Fix effort:** small (spec note)

---

### F5: Blank-cell map sub-cell markers may coincide or overflow; achromatopsia ΔL* between markers still only 7.8

- **Population:** ALL; LOW-VISION, GRAYSCALE most affected
- **Severity:** MEDIUM
- **Confidence:** LIKELY (geometry + CVD simulation)
- **Location:** `/home/daniel/code/entviz-rs/src/pipeline.rs:405–445` (map marker rendering)
- **Finding:** Two related sub-issues:
  (1) **Shape distinction is the right approach (v10 confirmed)**, but the hue redundancy
  shows residual weakness under achromatopsia. With shape, the max/min semantic is preserved:
  a plus (cross) vs. a circle are distinguishable without color. However, the CIELAB ΔL*
  between the two markers under achromatopsia is 7.8 (min_dot_blue #1d4ed8 maps to L*=39.1;
  max_plus_red #d62828 maps to L*=46.8), which is in the "distinguishable but low" range.
  A user with poor contrast sensitivity may find the overall gray-on-gray map harder to read
  than the spec implies, even though shape carries the semantic. Under tritanopia, ΔL*=5.1
  (weakest CVD scenario for the hue pair — the two colors are both pinkish/teal tones).
  The shape distinction remains the correct and adequate fix for achromatopsia; the residual
  issue is that the map contrast on the white/gold anchor fill is not documented as lower
  than the palette's design floor.
  (2) **Sole-blank recoloring path**: when the map blank is the only blank, the Rust code
  (`pipeline.rs:412–420`) recolors both markers to luminance-contrast colors against the
  fingerprint fill. This is correct per spec v10. The resulting marker colors (black or white)
  have perfect contrast against the fill. However, in the sole-blank case the plus and circle
  no longer have their canonical red and blue hue cues — this may be surprising to a user
  who memorized "red=max, blue=min."
- **Evidence:** CVD simulation: achromat min_dot_blue L*=39.1 vs. max_plus_red L*=46.8,
  ΔL*=7.8. Tritan min_dot_blue L*=44.5 vs. max_plus_red L*=49.5, ΔL*=5.1. Shape carries
  the semantic per spec v10; these numbers are consistent with the spec's accepted risk for
  the hue channel. Sole-blank path: `pipeline.rs:412–420` correctly implements the spec.
- **Recommended action:** Document in `docs/spec.md §map-rendering` (non-normative note):
  "Under achromatopsia the two markers remain distinguishable by shape (plus vs. circle),
  but their luminance contrast against each other is ΔL*≈8 — lower than the palette's
  design floor. A habituated user should be reminded that under achromatopsia, *shape* is
  the discriminator, not color." No code change. Accept the sole-blank recoloring behavior
  as-is; its deviation from canonical red/blue should be noted in the spec rationale.
- **Fix effort:** small (spec note)

---

### F6: Fingerprint-of marker CVD coverage not tested in Rust; palette CVD not tested at all

- **Population:** CVD (all types), GRAYSCALE
- **Severity:** MEDIUM
- **Confidence:** CONFIRMED (inspection of test suite; no CVD tests present)
- **Location:** `/home/daniel/code/entviz-rs/src/lib.rs:206` (POSSIBLE_EDGE_COLORS), `/home/daniel/code/entviz-rs/src/pipeline.rs:948` (#a00000), `/home/daniel/code/entviz-rs/tests/`
- **Finding:** This finding is related to F1 but focuses on a specific subset of the missing
  test coverage: the fingerprint-of truncation marker (#a00000) and the blank-cell map
  marker colors (#1d4ed8, #d62828) are not tested for CVD discriminability or Oklab L
  bounds, and neither is the palette itself. In the Python repo these colors are covered by
  `test_v6_palette_lightness.py` (added after the 2026-06-02 adversarial review, PSY-F4).
  In the Rust port there is no equivalent. The deutan ΔL*=5.8 (fp_marker vs. label_gray)
  is especially concerning: it is below the palette's design floor and below the level where
  bold text alone gives a user a confident CVD-accessible visual signal. If #a00000 were
  changed to, say, #cc0000 (darker red, Oklab L≈0.51 — still in the allowed range), the
  contrast could improve slightly; but without a test, the change cannot be validated.
  Note that F1 is the systemic gap (no CVD simulation at all in Rust); F6 names the
  specific high-value sub-tests that matter most for perceptual correctness.
- **Evidence:** Deutan simulation: #a00000 → L*=37.4, #666666 → L*=43.2, ΔL*=5.8.
  Tritan simulation: #a00000 → L*=36.7, ΔL*=6.5. No test covers these values in Rust.
  `grep -rn "a00000\|d62828\|1d4ed8" /home/daniel/code/entviz-rs/` returns only renderer
  production code, no assertions.
- **Recommended action:** As part of the CVD test suite recommended in F1, include:
  (a) Oklab L of #a00000 ∈ [0.35, 0.55] (normative constraint from spec).
  (b) ΔL*(#a00000, #666666) ≥ 5 under protan and deutan (acknowledgment of the low margin
  and the bold-weight safety net).
  (c) That the map dot vs. plus marker pair retains ΔL* ≥ 4 under all CVD conditions
  (shape carries the semantic, but near-zero contrast would make both invisible on certain
  backgrounds).
- **Fix effort:** small (sub-tests within the F1 CVD test)

---

### F7: Color-bar letters width-overflow at font_size > bar_width; short bands may bleed; no perceptual guard

- **Population:** ALL; most visible at larger font sizes
- **Severity:** LOW
- **Confidence:** LIKELY (geometry analysis; bars are narrower than typical glyph width at many font sizes)
- **Location:** `/home/daniel/code/entviz-rs/src/pipeline.rs:855–865` (draw_color_bar, letter rendering)
- **Finding:** The color-bar letter is rendered at `cell_text_px` font size centered in a bar
  of width `bar_w = 2.0 * box_h = 2.0 * nucleus_h / 2 = nucleus_h`. At 12pt: `bar_w = 20px`,
  `font_size = cell_text_px = 16px` (at 12pt for hex). A typical monospace glyph at 16px
  occupies approximately 10px width, so it fits in 20px. At 30pt: `bar_w = 50px`, `font_size
  = cell_text_px = 40px`. A monospace glyph at 40px width is ~24px — still fits in 50px. At
  6pt: `bar_w = 10px`, `font_size = cell_text_px = 8px`. An 8px monospace glyph is ~5px —
  fits in 10px with tight margins. The bar appears to handle glyph width at all standard font
  sizes, but the **band height** is a separate concern: a very short band (e.g., a rare
  pattern with a tiny count^4 share) may be shorter than the glyph height (cell_text_px =
  16px at 12pt), and the letter bleeds into the adjacent band. The Rust code (like the
  Python reference) uses a bottom-anchored layout (`baseline_y = (y + h) - 0.22 * font_size`)
  that deliberately allows upward bleed — the letter bottom is always inside the band, while
  the top may bleed into the band above. This is a design choice (spec §color-bar, noted in
  the Python reference's `pipeline.py` comments). The perceptual impact: for a band that is
  shorter than half a glyph height (≈8px at 12pt), the letter is only partially visible and
  may read as noise. Since the band height is proportional to count^4 and the color bar has
  4 patterns covering all 512 slots, the minimum band is at least 1/4 * (1/n_patterns)^4 of
  the total, which is usually non-trivially tall. However, for inputs with highly unequal
  pattern distributions, a rare pattern's band may be very short. This is an accepted design
  trade-off; the finding is LOW because the per-band letter is a redundant CVD fallback
  (position/height of the band is the primary discriminator) and the bleed is deterministic.
- **Evidence:** `pipeline.rs:855`: `let font_size = cell_text_px;` (no scaling to band height);
  `pipeline.rs:856`: `let baseline_y = (y + h) - 0.22 * font_size;` (bottom-anchored, may
  bleed upward). At 12pt: bar_w=20px, font_size=16px. A visible 16px glyph in a 20px bar
  has tight but non-zero horizontal margins.
- **Recommended action:** Document the bleed behavior as a design choice in the Rust code's
  inline comments (mirroring the Python `pipeline.py` comment). No algorithm change needed.
  Optionally, the spec could add a note that short bands may show partial letters (by design),
  and the band color (not the letter) is the primary discriminator for short bands.
- **Fix effort:** small (comment only)

---

## Additional Patterns Noted

**Version drift in SVG output.** The Rust renderer hardcodes `data-entviz-lib="0.10.0"` at
`pipeline.rs:209`, but `Cargo.toml` declares `version = "0.10.1"`. The rendered SVG carries
a stale library version tag. This is not a perceptual finding but will cause Tier-A conformance
checkers that verify `data-entviz-lib` against the binary version to fail. Recommend replacing
the hardcoded string with a `compile!` or `env!("CARGO_PKG_VERSION")` macro.

**Oklab lightness computation is correct.** The Rust `oklab_lightness` implementation at
`lib.rs:216–224` matches the standard Oklab formula and produces the expected values: white
L=1.0000, gold L=0.8137 (fg=black), red L=0.6572 (fg=black — correct, just above 0.6 threshold),
blue L=0.4450 (fg=white), black L=0.0000. The 0.6 threshold behavior was verified to match
the Python reference.

**Color-bar letter fg colors verified correct.** White-on-blue (b=#ffffff) and white-on-black
(k=#ffffff) confirmed in rendered output. Black-on-{white, gold, red} confirmed. The blue
band correctly uses white text (#ffffff), which has adequate contrast (WCAG: 1/0.445² roughly
~21:1 against black, but the contrast is white-on-blue: ~14:1 against the blue background —
above WCAG AA). The red band uses black text (L=0.657 ≥ 0.6 threshold), which gives ~3.9:1
contrast on the red background — above WCAG AA (3:1 for large text at this size).

**Font-family escaping is correct.** The Rust code uses `esc_attr(MONOSPACE_FONT_FAMILY)` to
insert the font chain into `style=""` attributes, converting `"JetBrains Mono"` to
`&quot;JetBrains Mono&quot;`. SVG/XML parsers decode XML entities before CSS parsing, so
the result is a valid CSS font-family value. Confirmed by rendering and unescaping the style
attribute value.

**Quartile polygon leg size at 6pt.** At 6pt: `leg = nucleus_h / 2 = 5px`. A right-triangle
corner mark of 5×5px is still visually identifiable as a corner triangle (even at 4 corners),
though it occupies only 5% of the nucleus area (same ratio as at 12pt). Orientation
discrimination at 6pt is likely adequate for normal vision; it was not confirmed for low
vision.

**Homoglyph risk in base64url text channel.** The font chain (JetBrains Mono → … → monospace)
correctly includes slashed-zero, disambiguated-1/l/I fonts. The `- `vs.` _` pair (dash vs.
underscore) is the riskiest in base64url at small sizes: at 3px box (6pt box width), the glyph
pixels are 1–2px wide horizontal strokes at slightly different vertical positions. The oral
readout convention ("dash" vs. "under") remains the correct primary mitigation; the font chain
is the visual one. No regression from the Python reference.

---

## Residual Unknowns

**U1: Across-tab rotation JND.** Does a 12° rotation step in the ellipse overlay remain
detectable when the viewer must switch tabs and recall the previous orientation? Geometry
analysis suggests the across-tab JND is 2–4× higher than simultaneous; this would reduce
effective discriminable steps from 16 to 6–8. Smallest study: 20–30 participants performing
same/different judgment on tab-switched pairs differing by 0, 1, or 2 rotation steps.

**U2: Surround box merge threshold in practice.** At what rendered pixel width does the
surround shift from per-box discrimination to fill-density histogram for a population of normal-
acuity viewers? The 3px engineering threshold is an estimate from standard-display-acuity
limits. Smallest measurement: present surround patterns at font sizes [6, 8, 10, 12]pt and
measure accuracy of a "locate the filled box at position N" task vs. a density estimation task.

**U3: Habituation degradation rate for Rust-rendered entvizes.** Unchanged from the Python
reference's U3: how quickly does a repeated-comparison user collapse from full multi-channel
inspection to "check color bar + blank map + done"? Cannot be settled analytically.

**U4: Achromatopsia map marker contrast in practice.** The shape distinction (plus vs. circle)
is confirmed as the correct mitigation (v10). The residual question is whether ΔL*=7.8 between
the two markers under achromatopsia is adequate for users with simultaneously impaired contrast
sensitivity (e.g., albinism). This requires a user study with achromatopsia participants.

---

## Findings Manifest

```yaml
findings:
  - id: PSY-F1
    persona: perception-reviewer
    title: No CVD regression tests for palette colors, map markers, or fp_marker in the Rust port
    severity: HIGH
    confidence: CONFIRMED
    location: /home/daniel/code/entviz-rs/tests/; src/lib.rs:206 (POSSIBLE_EDGE_COLORS)
    dedupe_key: palette-missing-test-cvd
    recommended_disposition: recommend-fix
    rationale: The Python reference pins palette CVD gaps via test_v6_palette_lightness.py; the Rust port has no CVD simulation test; any color change to POSSIBLE_EDGE_COLORS or map markers silently regresses the spec's CVD guarantee.
    revisit_condition: null
    fix_effort: medium

  - id: PSY-F2
    persona: perception-reviewer
    title: Fingerprint-of truncation marker described as hue-distinct under CVD; claim overstated in spec
    severity: MEDIUM
    confidence: CONFIRMED
    location: docs/spec.md §label-strips; src/pipeline.rs:948
    dedupe_key: fingerprint-marker-indiscriminable-under-cvd
    recommended_disposition: recommend-fix
    rationale: Under deutan (ΔL*=5.8) and tritan (ΔL*=6.5), #a00000 vs #666666 lose all hue distinction; bold weight is the sole differentiator; the spec's substitution constraint requiring hue-distinctness is unfulfillable for CVD users.
    revisit_condition: null
    fix_effort: small

  - id: PSY-F3
    persona: perception-reviewer
    title: Ellipse rotation step (12deg) borderline for across-tab memory-based comparison; JND claim unqualified
    severity: MEDIUM
    confidence: SPECULATIVE
    location: docs/spec.md §ellipse-overlay; src/pipeline.rs:703-705
    dedupe_key: ellipse-indiscriminable-on-small-display
    recommended_disposition: recommend-fix
    rationale: Spec claims 16 steps ≈ JND without qualifying that across-tab comparison inflates JND 2-4x; rotation_step=12deg is at the boundary for complex shapes under memory-based comparison, reducing effective discriminable steps to 6-8.
    revisit_condition: null
    fix_effort: small

  - id: PSY-F4
    persona: perception-reviewer
    title: Surround-box individual discriminability collapses at 3px box width (6pt or scaled small); no spec note
    severity: MEDIUM
    confidence: LIKELY
    location: docs/spec.md §geometry; src/pipeline.rs:150-153
    dedupe_key: surround-indiscriminable-on-small-display
    recommended_disposition: recommend-fix
    rationale: At 6pt (minimum allowed) box_w=3px; flush adjacent boxes merge under anti-aliasing, converting the 24-bit channel to a density histogram; spec provides no minimum rendered size guidance.
    revisit_condition: null
    fix_effort: small

  - id: PSY-F5
    persona: perception-reviewer
    title: Blank-cell map marker ΔL* between plus and circle is only 7.8 under achromatopsia; residual hue weakness documented but not tested
    severity: MEDIUM
    confidence: LIKELY
    location: src/pipeline.rs:405-445; docs/spec.md §map-rendering
    dedupe_key: blank-map-indiscriminable-under-cvd
    recommended_disposition: recommend-fix
    rationale: Shape (plus vs circle) correctly carries the max/min semantic under achromatopsia (v10 fix), but ΔL*=7.8 between the two markers in grayscale is lower than the palette's design floor; spec rationale should document this residual hue-contrast limitation explicitly.
    revisit_condition: null
    fix_effort: small

  - id: PSY-F6
    persona: perception-reviewer
    title: Fingerprint-of marker and map dot colors not individually tested for CVD in Rust; specific sub-tests needed
    severity: MEDIUM
    confidence: CONFIRMED
    location: src/pipeline.rs:948; src/pipeline.rs:420,427; tests/
    dedupe_key: blank-map-missing-test-cvd
    recommended_disposition: recommend-fix
    rationale: #a00000 deutan ΔL*=5.8 and #1d4ed8/#d62828 tritan ΔL*=5.1 are below the palette design floor and untested; specific assertions on these colors are needed in addition to the general palette CVD suite (F1).
    revisit_condition: null
    fix_effort: small

  - id: PSY-F7
    persona: perception-reviewer
    title: Color-bar letters may partially bleed on very short bands; no perceptual guard or doc note
    severity: LOW
    confidence: LIKELY
    location: src/pipeline.rs:855-865
    dedupe_key: color-bar-missing
    recommended_disposition: recommend-accept-risk
    rationale: Bottom-anchored letter layout allows upward bleed on very short bands by design; band color is the primary discriminator; the bleed is deterministic and matches the Python reference; a comment noting the accepted design choice is sufficient.
    revisit_condition: null
    fix_effort: small
```
