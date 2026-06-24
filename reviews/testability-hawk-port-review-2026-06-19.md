# Testability Review: entviz-rs (Rust port)

**Date:** 2026-06-19
**Effort level:** medium
**Run label:** port-review-2026-06-19
**Context sources used:** `AGENTS.md`, `Cargo.toml`, `src/lib.rs`, `src/main.rs`, `src/pipeline.rs`, `src/entropy.rs`, `src/keccak.rs`, `.github/workflows/ci.yml`, `tests/cli.rs`, `tests/conformance.rs`, `src/model.rs` (adversarial-gated). Corpus manifest and a representative `model.json` (`hex-256`) from `../entviz/compliance/corpus`. Spec (`../entviz/docs/spec.md`, Conformance section). Prior reviews read **after** forming independent assessment. Suite was **run**: `cargo test --locked` (110 tests, all green); `cargo test --locked --features adversarial` (123 tests, all green). Suite was NOT run with coverage (tool not available in this environment). A determinism re-render diff was **not** explicitly performed beyond what the existing `render_is_deterministic` test covers.

---

## Evidence Inventory

- **All source read:** `src/lib.rs`, `src/main.rs`, `src/pipeline.rs`, `src/entropy.rs`, `src/keccak.rs`, `src/model.rs`, `src/bin/render_model.rs` (existence confirmed; not audited as normative surface).
- **Tests read in full:** `tests/cli.rs` (4 integration tests), `tests/conformance.rs` (1 corpus smoke test). Inline `#[cfg(test)]` modules in every source file.
- **CI read in full:** `.github/workflows/ci.yml` (three jobs: `test`, `coverage`, `conformance`).
- **Corpus checked:** `../entviz/compliance/corpus/manifest.json` (52 vectors — 46 render, 6 error, 3 invariant pairs). One `model.json` examined in detail (`hex-256`). The Python conformance runner and `compliance/model.py` were skimmed to understand what Tier A actually compares.
- **Spec section read:** `docs/spec.md` §Conformance (three tiers, equivalence relation, error conditions, SVG profile).
- **Suite run:** `cargo test --locked` — 110 tests, 0 failed. `cargo test --locked --features adversarial` — 123 tests, 0 failed. The 13 extra tests are model.rs golden comparisons (adversarial-feature only).
- **What was skipped:** Coverage measurement (no tool), cross-platform determinism (single machine), property-based testing tools (none present), Tier-B raster run (requires cairosvg/Pillow).

---

## Executive Summary

The test suite for entviz-rs is broad, well-named, and clearly authored alongside the code rather than as an afterthought. The most serious structural gap is that the **cargo-test suite never compares the produced SVG against a golden render model at any level of field precision** — the render/reject smoke test in `tests/conformance.rs` only asserts the SVG is well-formed, not that it is *correct*. The model-field comparison that provides the real conformance proof lives in an out-of-tree Python runner; this is documented and deliberately separated, but it means a Rust-side regression that keeps producing valid-but-wrong SVGs would pass `cargo test` and require the human to remember to run the cross-repo command. A second gap is the determinism test's narrow footprint: it exercises exactly one input at one parameter set; the spec's mandate extends to every input and alphabet. Both gaps are bounded in practice by CI running Tier A via the Python runner, but the self-contained Rust test surface does not cover them.

---

## Top Findings

Ordered by bang-for-buck (most real bugs preventable per unit of fix effort, first).

### F1: Conformance test never compares render-model fields — correct-but-wrong SVG is invisible to `cargo test`

- **Severity:** HIGH
- **Confidence:** CONFIRMED
- **Location:** `tests/conformance.rs:62-68` (render check) and the entire file's doc comment (lines 5-8, which explicitly disclaims Tier-A and Tier-B comparison)
- **Finding:** `corpus_render_and_error_contract` checks that render vectors produce `<svg ... </svg>` and error vectors return `Err`. It reads `input.json` but never reads `model.json`. The golden model has ~11 top-level fields (bg_color, cols, rows, ellipse rx/ry/rotation/anchor, color_bar bands/markers, cell nucleus_bg, quartile placement, surround_bits, edge color) — none is verified. A regression that, say, silently miscomputes grid selection, swaps color channels, or breaks quartile placement would produce syntactically valid SVG, pass `cargo test`, and only be caught by the CI conformance job (which runs the Python runner with `--tiers A`).
- **Consequence:** Any render-model regression that keeps outputting a well-formed SVG ships undetected in `cargo test`. The CI gate exists (Tier-A Python runner), but it is not a Rust-side test — it is a cross-repo Python invocation that produces no test failure in `cargo test --locked` if it regresses.
- **Recommendation:** Vendor a small frozen subset of golden render-model assertions directly into the Rust test suite. The corpus `model.json` files are JSON; at minimum, for the existing corpus vectors already exercised by `corpus_render_and_error_contract`, parse the produced SVG's `data-*` attributes and assert them against the expected `model.json` fields (cols, rows, bg_color, ellipse anchor/rx/ry/rotation, color_bar marker slots and positions). This is achievable without the Python extractor — the attributes are readable directly in Rust. The existing 13 tests in `model.rs` (adversarial-feature) show this pattern and could be promoted to default-feature status for the most critical channels.
- **Fix effort:** medium

### F2: Determinism test covers one input at one parameter set — across-alphabet and large-input determinism are assumed, not asserted

- **Severity:** MEDIUM
- **Confidence:** CONFIRMED
- **Location:** `src/pipeline.rs:1326-1330` (`render_is_deterministic`)
- **Finding:** The single determinism test renders `"0123456789abcdef0123456789abcdef"` (a hex-256 input) at `(1.0, 12.0)` twice and asserts equality. The spec mandates that **identical input yields conformant-equivalent (byte-identical) SVG on every run and platform** for all alphabets, grid sizes, and input paths. The following paths have no coverage: UUID (dashed vs undashed, which must produce byte-identical SVG — the equivalence invariant), text-fallback (txt→b64url encode path), large-input truncation (the head/middle/tail path through `tokenize_entropy`), bech32/ETH/CESR/SSH parsers, non-default font sizes, and non-square aspect ratios. Any one of these could harbor a non-determinism source (e.g. if a new dependency introduced locale-sensitive formatting) that the current test would not catch.
- **Consequence:** A non-determinism bug introduced in the text-fallback or large-input path, or in any format-specific parser, would pass the determinism test and only be detected by accident or by a user who renders the same input twice and notices divergence.
- **Recommendation:** Add a parameterized determinism sweep: for each corpus vector (or a representative subset covering hex, UUID, ETH, SSH, base64, text-fallback, and a >512-bit input), render twice with `render()` and assert byte equality. This is four lines per vector and catches any non-determinism source across all code paths simultaneously. Group this as `test render_is_deterministic_across_formats`.
- **Fix effort:** small

### F3: Invariant pairs from the corpus are not tested in Rust — uuid-dashed==uuid-undashed can silently diverge

- **Severity:** MEDIUM
- **Confidence:** CONFIRMED
- **Location:** `tests/conformance.rs` (corpus test has no invariant-pair logic); `../entviz/compliance/corpus/manifest.json:50-60` (three invariant pairs defined)
- **Finding:** The corpus defines three invariant pairs: `uuid-dashed == uuid-undashed`, `ulid-canonical == ulid-lowercase`, and `avalanche-a == uuid-dashed`. These assert that semantically equivalent inputs produce byte-identical SVG. The Python conformance runner checks these (for in-process runs). The Rust `cargo test` suite never compares the SVG of any two equivalent inputs against each other. A regression in UUID normalization (the `stripped.to_lowercase()` at `entropy.rs:609`) that caused dashed UUIDs to produce a different core than undashed UUIDs would yield diverging SVGs but no failing Rust test — the smoke test would pass for both individually.
- **Consequence:** UUID/ULID normalization bugs could ship undetected as long as each variant individually produces a valid SVG. These are the spec's own "must produce equivalent output" examples; not testing them means the Rust port's equivalence-relation compliance is untested at the integration level.
- **Recommendation:** Add an integration test asserting that the three manifest invariant pairs produce byte-identical SVG: `render(uuid-dashed-entropy, ...) == render(uuid-undashed-entropy, ...)`, and similarly for ULID and avalanche. These inputs are already in the corpus; the test is a three-assertion addition to `tests/conformance.rs`.
- **Fix effort:** small

### F4: `data-entviz-lib` version stamp is hardcoded "0.10.0" while `Cargo.toml` is "0.10.1"; no test guards the relationship

- **Severity:** MEDIUM
- **Confidence:** CONFIRMED
- **Location:** `src/pipeline.rs:209` (`data-entviz-lib=\"0.10.0\"`); `Cargo.toml:3` (`version = "0.10.1"`)
- **Finding:** The SVG emits `data-entviz-lib="0.10.0"` as a literal string while the crate is already at 0.10.1 — the stamp is wrong today. The constant `SPEC_VERSION = "v10"` exists in `src/lib.rs` but is not referenced in `pipeline.rs`; `env!("CARGO_PKG_VERSION")` is not referenced anywhere in `src/`. Because no test compares the emitted attribute to `CARGO_PKG_VERSION`, every future version bump will silently leave the stamp stale. The `data-entviz-version` literal `"v10"` happens to match `SPEC_VERSION` today but is similarly disconnected (it is a literal in the format string, not `crate::SPEC_VERSION`).
- **Consequence:** Any consumer relying on `data-entviz-lib` to identify the producing build gets wrong provenance. The mismatch can persist silently through releases until someone grep-searches the SVG. (Note: `data-entviz-lib` is not compared by Tier-A, so conformance passes regardless. This was also found by the spec reviewer; the dedupe_key is `version-stamp-divergent`.)
- **Recommendation:** Two fixes: (1) replace literal `"v10"` with `crate::SPEC_VERSION` and `"0.10.0"` with `env!("CARGO_PKG_VERSION")` in the `format!` at `pipeline.rs:209`; (2) add a unit test asserting that a rendered SVG's `data-entviz-version` equals `SPEC_VERSION` and `data-entviz-lib` equals `env!("CARGO_PKG_VERSION")`. The test is a five-line parse+assert.
- **Fix effort:** small

### F5: Tier B (visual raster comparison) is not run in CI — only Tier A is gated

- **Severity:** MEDIUM
- **Confidence:** CONFIRMED
- **Location:** `.github/workflows/ci.yml:116` (`--tiers A`); the `conformance` CI job comment (lines 105-107)
- **Finding:** The CI conformance job explicitly runs only `--tiers A` (render-model semantic correctness). Tier B (canonical raster pixel comparison against `golden.png`) is deliberately excluded — the job installs only `lxml`, not `cairosvg`/`Pillow`. The SPEC reviewer ran Tier B manually (52/52 passed), but it is not a CI gate. Channels that Tier A recovers from `data-*` attributes (cell positions, ellipse parameters, color-bar bands/markers) are covered. Channels that require pixel comparison (the ellipse's actual painted opacity/fill/stroke, the nucleus fill's visual radius, exact edge-box geometry, the blank-cell rounded-rect shape, the border stroke alignment) are not gated.
- **Consequence:** A rendering regression in a channel not captured by `data-*` attributes (e.g. a broken fill-opacity on the ellipse, a geometry constant off by one pixel, or a color-bar band height computation error) could pass CI's Tier A and only be caught by the manual Tier B run. The conformance claim "certified at Tier A + Tier B" is currently supported by the manual run but not by a CI gate.
- **Recommendation:** Add Tier B to the CI conformance job. Install `cairosvg` and `Pillow` in the same venv step (they are already listed in the Python reference's dev dependencies), and change `--tiers A` to `--tiers AB`. Alternatively, run a Tier-B check over a small fixed subset of vectors (e.g. `hex-256`, `text-hello`, `hex-1024`) to keep the CI job fast. The golden PNGs are already in the corpus.
- **Fix effort:** small

---

## Additional Patterns Noted

- **Spec worked examples as assertions.** The spec documents two quant-extension examples: `0xAB → 0xABABAB` (tested: `lib.rs:362`) and `0x5 → 0x555555` (NOT tested). The third example, `0xABC → 0xABCABC`, is also absent. The grid-selection worked example (11 tokens at 1:1 → 3×4) IS tested (`lib.rs:382`). Adding the two missing extension examples is a two-line addition to `lib.rs`.

- **`sanitize_note` logic: redundant empty check.** At `pipeline.rs:47`, `n.is_empty()` inside the `Some(n)` arm can only be reached if the `Some("")` arm at line 39 did not already return. A non-empty string that passes the first length guard then hits `n.is_empty() || !n.chars().all(|c| c.is_ascii_alphanumeric())`. The `n.is_empty()` there is unreachable (it was already handled). This is not a behavior bug but could mask a future test: a test that deliberately reaches the "not alphanumeric" arm by passing `Some("")` to `sanitize_note` directly would pass for the wrong reason.

- **`model.rs` tests gated behind `adversarial` feature.** The 13 tests in `src/model.rs` verify golden render-model field values (hex256 ellipse, color bar, blank map, cell quartiles, surround bits, etc.) but only run under `--features adversarial`. This is the richest model-level coverage in the codebase — and it is not run by the default `cargo test`. Promoting these to the default feature set (or copying the assertions into `tests/`) would close most of F1 without a new test file.

- **CLI exit-code contract gap.** `tests/cli.rs` verifies the three exit codes (0, 1, 2) and that exit-0 produces `<svg`. It does not assert that the produced SVG *matches any expected content*, and does not test the `stdin-read-failure` path (exit 2 from `read_to_string` failure) — simulating that path requires either a broken pipe or injecting a stdin-replacement. The latter is a small gap that is covered by construction (the code path is a two-liner at `main.rs:11-14`), but a test that passes a closed-fd stdin would make it explicit.

- **No property-based tests.** No `proptest` or `quickcheck` dependency is present. Given that the spec mandates determinism for all inputs and alphabets, a property-based test that renders any non-empty ASCII-printable string twice and asserts equality would be a cheap, high-coverage addition. Similarly, a property that every render of valid input produces well-formed SVG (starts/ends correctly, balanced angle brackets) would guard against future format bugs.

- **`tests/conformance.rs` silently skips.** When `../entviz/compliance/corpus/manifest.json` is absent (a fresh checkout with no sibling), the test prints a message and passes trivially. In a CI environment where the corpus is not checked out, the `cargo test` output shows "1 passed" for conformance, giving no indication that the corpus was not exercised. This was also found by the spec reviewer (SPEC-F4 / `conformance-suite-untested-in-ci`); the CI conformance job always checks out the corpus so this is not a CI gap, but it is misleading in local development.

---

## Residual Unknowns

- **Cross-platform determinism.** All testing was on a single Linux machine (WSL2). The spec mandates cross-platform byte-identical output; this was not verified across macOS/Windows or across Rust toolchain versions. Float formatting in Rust's `Display` for `f64` is stable across platforms per the standard library, but this was not independently confirmed.
- **Coverage measurement.** The `cargo llvm-cov` coverage tool is present in CI (floor: 98% lines, 90% per-file), but was not run in this review. The claim of ~99% line coverage is taken from the CI job comment. Unexercised branches within tested functions were not enumerable without running the tool.
- **The `adversarial` feature tests.** `src/model.rs` and `src/bin/render_model.rs` are excluded from the published crate and gated behind `--features adversarial`. Their tests were confirmed to pass but their internal logic was not audited for completeness as test surface.

---

## Decisions Needed

- **Promote `model.rs` tests to default feature or copy assertions to `tests/`?** The 13 golden-comparison tests in `model.rs` are the richest model-level coverage and they run only under `adversarial`. A decision about whether to make them part of the default test surface (closing F1 cheaply) or maintain the separation is needed.
- **Tier B in CI: full or subset?** Adding Tier B to the CI conformance job closes F5 but adds a Python dependency (cairosvg, Pillow, numpy) and extends CI runtime. Running Tier B over a 5-vector representative subset (rather than all 46 render vectors) may be a faster compromise.
- **Invariant-pair testing: Rust-native or via the Python runner?** Closing F3 can be done by adding three `assert_eq!(render(a, ...), render(b, ...))` calls in `tests/conformance.rs` (Rust-native, no external dependency) or by relying on the Python runner's invariant-pair check in CI (already present for in-process runs, but not for `--impl-cmd`). The Rust-native approach is self-contained.

---

## Findings Manifest

```yaml
findings:
  - id: TST-F1
    persona: testability-hawk
    title: Conformance test never compares render-model fields — correct-but-wrong SVG invisible to cargo test
    severity: HIGH
    confidence: CONFIRMED
    location: tests/conformance.rs:62-68
    dedupe_key: conformance-suite-model-untested
    recommended_disposition: recommend-fix
    rationale: >
      Rust cargo test only checks that render vectors produce well-formed SVG; it never reads model.json
      or compares any semantic field. A grid-selection, color-bar, or ellipse regression that keeps
      outputting valid SVG passes all Rust tests. CI Tier-A Python runner catches this, but it is
      a cross-repo manual invocation, not a self-contained cargo test.
    revisit_condition: null
    fix_effort: medium

  - id: TST-F2
    persona: testability-hawk
    title: Determinism tested for one hex-256 input only; across-alphabet and large-input paths unasserted
    severity: MEDIUM
    confidence: CONFIRMED
    location: src/pipeline.rs:1326-1330
    dedupe_key: render-determinism-undertested
    recommended_disposition: recommend-fix
    rationale: >
      Single call render(hex-256, 1.0, 12.0, None) renders twice and asserts equality. Text-fallback,
      large-input truncation, UUID, ETH, SSH, bech32, non-default params all have zero determinism
      coverage. A non-determinism regression in any of these paths passes the existing test.
    revisit_condition: null
    fix_effort: small

  - id: TST-F3
    persona: testability-hawk
    title: Corpus invariant pairs not tested in Rust — uuid-dashed==uuid-undashed never asserted
    severity: MEDIUM
    confidence: CONFIRMED
    location: tests/conformance.rs
    dedupe_key: render-invariant-pairs-untested
    recommended_disposition: recommend-fix
    rationale: >
      Manifest defines three equivalence pairs (uuid-dashed==uuid-undashed, ulid-canonical==ulid-lowercase,
      avalanche-a==uuid-dashed). Rust corpus test never compares two inputs against each other. A UUID
      normalization bug that produces different cores for dashed vs undashed UUIDs passes cargo test.
    revisit_condition: null
    fix_effort: small

  - id: TST-F4
    persona: testability-hawk
    title: data-entviz-lib hardcoded "0.10.0" (Cargo.toml is 0.10.1); no test guards the relationship
    severity: MEDIUM
    confidence: CONFIRMED
    location: src/pipeline.rs:209
    dedupe_key: version-stamp-divergent
    recommended_disposition: recommend-fix
    rationale: >
      SVG emits data-entviz-lib="0.10.0" literal while crate is 0.10.1; SPEC_VERSION/CARGO_PKG_VERSION
      not referenced in pipeline.rs. No test asserts the emitted attribute equals the declared constant.
      Every future version bump silently leaves the stamp stale; the mismatch is already present.
    revisit_condition: null
    fix_effort: small

  - id: TST-F5
    persona: testability-hawk
    title: Tier B (visual raster comparison) not gated in CI — only Tier A runs on every push
    severity: MEDIUM
    confidence: CONFIRMED
    location: .github/workflows/ci.yml:116
    dedupe_key: conformance-tier-b-missing-from-ci
    recommended_disposition: recommend-fix
    rationale: >
      CI conformance job runs --tiers A only; Tier B (pixel comparison against golden.png) requires
      manual cross-repo invocation. Rendering bugs in channels not captured by data-* attributes
      (ellipse opacity, exact nucleus-fill geometry, border alignment) pass CI undetected.
    revisit_condition: null
    fix_effort: small
```
