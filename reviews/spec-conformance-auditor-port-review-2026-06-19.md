# Spec-Conformance & Determinism Review: entviz-rs (Rust port)

**Date:** 2026-06-19
**Effort level:** deep (renderer built and run; Tier A/B corpus executed; Rust↔Python SVG/model diffs performed)
**Conformance frame:** code `SPEC_VERSION` (`src/lib.rs`) = `"v10"`; the stamped `data-entviz-version` in `src/pipeline.rs` = `"v10"`; the authoritative `docs/spec.md` header (in the sibling `../entviz` repo) = **Version 10** — they agree. A golden corpus **exists** (`../entviz/compliance/corpus`, 52 vectors, manifest `spec_version` v10 / `lib_version` 0.10.0) and the Tier-A render-model + Tier-B canonical-raster checker **runs and passes** for this binary.
**Implementation commit:** 79a96cb1f093ff75c284a1108234880db65913cd (branch `main`)
**Context sources used:** Full `docs/spec.md` (588 lines, all sections including Conformance, Casual avalanche v10, Cell Rendering). All Rust source (`lib.rs`, `pipeline.rs`, `entropy.rs`, `keccak.rs`, `main.rs`, tests). Cross-read against the Python reference (`../entviz/src/entviz/*.py`, `../entviz/compliance/*.py`). The renderer **was built** (`cargo build --release`) and **run**: 52/52 corpus vectors pass Tier A+B; render output is byte-identical across repeated runs (large input and txt fallback); Tier-A render models match Python byte-for-byte on four non-corpus inputs (LEI, Stellar base32, txt fallback, >512-bit truncated). `this.i` was **not** present in this repo (the intent layer lives in the Python repo); I reconciled against the spec's `this.i:` references instead.

---

## Evidence Inventory

- Read in full: `docs/spec.md` (sibling repo), `src/lib.rs`, `src/pipeline.rs`, `src/entropy.rs`, `src/keccak.rs`, `src/main.rs`, `tests/conformance.rs`, `tests/cli.rs`, `Cargo.toml`.
- Cross-read: `../entviz/src/entviz/pipeline.py`, `entropy.py` (tokenize, median/quartile, parsers, EIP-55), `fingerprint.py`, `__init__.py`, `compliance/model.py`, `compliance/runner.py`, `compliance/generate.py`, the corpus manifest + a golden SVG.
- Ran: `cargo build --release --bin entviz-conformance` (clean), `cargo test --release` (115 tests, all green), the Python conformance runner against the Rust binary (`52/52 vectors passed`, Tier A **and** Tier B — the rasterizer was present, so Tier B genuinely executed), repeated-render determinism diffs, and Rust-vs-Python Tier-A model diffs on non-corpus inputs.
- `src/model.rs` / `src/bin/render_model.rs` are gated behind the off-by-default `adversarial` feature and excluded from the published crate; they are **not** on the normative render path and were not audited as conformance surface.
- Skipped: Tier-C browser smoke (out of scope for static review; non-blocking by spec). Cross-platform determinism (macOS/Windows) — see Residual Unknowns.

---

## Executive Summary

This is a faithful, high-fidelity port. The deterministic core (SHA-512 fingerprint, the domain-separated second digest with the verbatim `entviz/fingerprint-middle/v6\0` tag, base64url tokenization, the quant bit-extension doubling, median/quartile ASCII sorts, Oklab L threshold 0.6, weighted-RGB edge distance, grid selection, v10 fingerprint-edge cells and hybrid blank fill) matches the Python reference line-for-line, and the implementation **passes the entire 52-vector corpus at Tier A and Tier B** and rejects every error vector. Determinism is sound: no `time`/`rand`/`env`/locale reachable from `render()`, float formatting is locale-independent, and every `HashMap`/`HashSet` is accessed by key or `.contains()` — never iterated to emit output — so there is no hash-order leak. I found **no CRITICAL** correctness, fingerprint, or determinism defect. The most material finding is a **spec MUST gap in error reporting**: a failed EIP-55 checksum is correctly *rejected*, but the first-mismatched-digit position the spec requires the error to identify is computed and then **discarded** at the render boundary (`From<ParseError> for RenderError`), so the diagnostic MUST is not met (the corpus only checks rejection, so it passes anyway). The most urgent housekeeping action is the **version-stamp drift**: `data-entviz-lib` and `data-entviz-version` are hardcoded string literals disconnected from `CARGO_PKG_VERSION` / `SPEC_VERSION`, and the lib stamp is already wrong (`0.10.0` stamped vs `0.10.1` crate).

---

## Top Findings
Ordered by bang-for-buck.

### F1: EIP-55 rejection discards the first-mismatched-digit position the spec requires the error to identify

- **Class:** CODE (impl diverges from a normative MUST)
- **Severity:** MEDIUM
- **Confidence:** CONFIRMED
- **Location:** `src/pipeline.rs:30-34` (`impl From<ParseError> for RenderError`); the value originates at `src/entropy.rs:471` (`ParseError::Eip55 { position: i }`) and is surfaced by the CLI at `src/main.rs:34`. Spec: `docs/spec.md` §Error conditions ("the error MUST identify the first mismatched-case digit") and §Normalization (EIP-55).
- **Finding:** `validate_eip55` correctly computes the first mismatched digit and returns `ParseError::Eip55 { position }`. But `From<ParseError> for RenderError` matches `_` and maps **every** parse error to a field-less `RenderError::Eip55`, throwing the position away. The CLI then prints `entviz-rs: rejected: Eip55` with no digit index. The Python reference raises `EIP55ChecksumError` whose message reads `... position 2 is 'a', canonical case is 'A'` — it satisfies the MUST. The input *is* rejected with a non-zero exit (the security-critical behavior is correct, and the corpus error-vector check — which only asserts rejection — passes), but the normative obligation to *identify* the offending digit is not met.
- **Evidence / example:** Bad address `0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed`: Python emits `position 2 is 'a', canonical case is 'A'`; the Rust CLI emits only `rejected: Eip55`.
- **Recommended action:** Fix in code (small): carry the position through `RenderError` (e.g. `RenderError::Eip55 { position: usize }` via `From` that preserves the field) and include it in the `Display`/CLI message. Consider adding a Tier-A-adjacent conformance assertion on the error *message* for EIP-55 vectors (currently nothing verifies message content cross-impl).

### F2: Version stamps are hardcoded literals, disconnected from their declared sources of truth — and the lib stamp is already drifted

- **Class:** CODE / DETERMINISM-adjacent (cross-impl provenance) / maintainability
- **Severity:** MEDIUM
- **Confidence:** CONFIRMED
- **Location:** `src/pipeline.rs:209` (`data-entviz-version="v10" data-entviz-lib="0.10.0"`), vs. `src/lib.rs:26` (`SPEC_VERSION = "v10"`) and `Cargo.toml` (`version = "0.10.1"`).
- **Finding:** Both SVG version stamps are string literals baked into the `format!`, not derived from `SPEC_VERSION` (which exists, equals `"v10"`, and is the documented single source of truth) nor from `env!("CARGO_PKG_VERSION")`. The lib stamp is **already wrong**: the crate is `0.10.1` but every SVG advertises `data-entviz-lib="0.10.0"`. A consumer using `data-entviz-lib` to identify the producing build (the attribute's stated purpose) gets a false answer, and the next `SPEC_VERSION`/crate bump will silently leave one or both stamps stale because no test compares the literal to its source. This currently passes the corpus only because `data-entviz-lib` is **not** part of the compared Tier-A render model (`compliance/model.py` reads `data-entviz-version` and `data-input-bytes`, not `-lib`) and the corpus's own `lib_version` happens to be `0.10.0`.
- **Evidence / example:** `grep data-entviz-lib src/pipeline.rs` → literal `0.10.0`; `grep ^version Cargo.toml` → `0.10.1`. No `CARGO_PKG_VERSION` reference anywhere in `src/`.
- **Recommended action:** Fix in code (small): stamp `data-entviz-version` from `crate::SPEC_VERSION` and `data-entviz-lib` from `env!("CARGO_PKG_VERSION")`; add a unit test asserting the emitted attributes equal those constants so a future bump can't drift. Note: changing the lib stamp to `0.10.1` is a render-model-neutral change (lib stamp is outside the compared model), so it is **not** comparison-breaking.

### F3: `data-entviz-version` is not driven by the `SPEC_VERSION` constant (latent divergence on the next spec bump)

- **Class:** CODE / DIVERGENT (code vs. its own declared SoT)
- **Severity:** LOW
- **Confidence:** CONFIRMED
- **Location:** `src/pipeline.rs:209` vs `src/lib.rs:26`.
- **Finding:** A sub-case of F2 worth pinning separately because its blast radius is larger: `data-entviz-version` **is** part of the compared Tier-A model (`compliance/model.py:91` reads it as `spec_version`). It is correct today (`"v10"` literal == `SPEC_VERSION`), but because it is a literal rather than `SPEC_VERSION`, a future maintainer who bumps the const will produce SVGs whose stamped spec version lies, and Tier-A will then mis-compare against the new corpus in a confusing way (or pass against a stale corpus). The fix is the same one-liner as F2.
- **Evidence / example:** The two `"v10"` strings live in different files with no compile-time link.
- **Recommended action:** Fix in code (small), folded into F2's fix.

### F4: The crate's only corpus-driven test silently no-ops when the sibling corpus is absent — Tier-A/B parity is not guaranteed by `cargo test` alone

- **Class:** SPEC-conformance-suite readiness (testability-adjacent)
- **Severity:** LOW
- **Confidence:** CONFIRMED
- **Location:** `tests/conformance.rs:46-53` (skips and passes trivially when `../entviz/compliance/corpus/manifest.json` is absent); and the test, even when present, only checks the **render/reject contract** (well-formed SVG vs. rejection), explicitly **not** Tier-A model equality or Tier-B raster (see its own doc comment, lines 5-8).
- **Finding:** The actual conformance proof (Tier A model diff + Tier B raster) requires the out-of-tree Python runner (`python -m compliance.runner --impl-cmd ...`). From a clean `entviz-rs` checkout with no sibling `../entviz`, `cargo test` proves only that the renderer emits *a* well-formed SVG and rejects error vectors — it does **not** prove the SVG is conformant-equivalent to the golden. This is acceptable for a port that documents the external certification step (which it does, in `src/lib.rs`), but it means the multi-impl certification rests entirely on a manual, cross-repo invocation with no in-CI guard against a regression that keeps producing valid-but-wrong SVGs. I confirmed the external runner passes today (52/52, Tier A+B), so this is a process-robustness gap, not a current defect.
- **Evidence / example:** `tests/conformance.rs` `corpus_dir()` returns `None` → `eprintln!("skip: ...")` → test passes.
- **Recommended action:** Add a conformance test (CI): either vendor a small frozen subset of golden render *models* into the repo for an in-Rust Tier-A diff, or wire the Python runner into CI against a pinned `../entviz` checkout so a render-model regression fails the build without a human remembering to run the cross-repo command.

### F5: Cross-impl float-formatting of geometry is unverified outside the corpus (Tier-B landmine for the *next* implementation, not this port)

- **Class:** SPEC (under-specification) / cross-impl
- **Severity:** LOW
- **Confidence:** LIKELY
- **Location:** `src/pipeline.rs:67-69` (`fn n(x) = format!("{}", x)`); spec equivalence relation (`docs/spec.md` §Equivalence relation: "numeric formatting that denotes the same value ... e.g. 60 vs 60.0").
- **Finding:** The spec forgives numeric *formatting* differences only when they "denote the same value within the geometry-rounding rules." But the spec never pins a canonical float→string for geometry, and the renderer emits raw IEEE-754 artifacts like `1.9250000000000003` and `131.32394215885992` (ellipse/marker coordinates) straight from `format!("{}", f64)`. Rust's `{}` and Python's `repr`/`str` agree on these for the corpus (Tier B passed), but JS's `Number.prototype.toString` and other languages can emit a different shortest-round-trip string for the same `f64`, and at sufficiently extreme magnitudes the *value* (after the rasterizer parses it) is identical but the string is not. This is **not** a defect in *this* port (it matches Python where the corpus exercises it), but it is exactly the kind of under-specified cross-impl seam the spec's third certified implementation (entviz-js) could trip on, and the equivalence relation's "denotes the same value" clause papers over it only if every impl's parser round-trips identically. Flagging it here because the port review is the right place to surface it before entviz-js is certified.
- **Evidence / example:** `grep -oE '[0-9]+\.[0-9]{6,}'` over fresh Rust output yields `1.9250000000000003`, `109.5192987559727`, etc.
- **Recommended action:** Fix in spec (small): have `docs/spec.md` pin a canonical coordinate serialization (e.g. "round all emitted coordinates to N decimal places; format with `.` decimal separator, no exponent, no trailing-zero padding") so Tier-B equivalence does not depend on each language's default float printer. No code change needed for entviz-rs↔Python parity, which holds.

### F6: Non-determinism audit — clean (recorded so it is not re-litigated)

- **Class:** DETERMINISM
- **Severity:** LOW (informational; no defect)
- **Confidence:** CONFIRMED
- **Location:** whole render path.
- **Finding:** No `std::time`, `rand`, `std::env`, locale, or salted-`hash()` source is reachable from `render()`. The clip-path id salt is `primary[..8]` hex + grid dims (`src/pipeline.rs:220-221`) — fingerprint-derived, not random, exactly as the spec requires, and it is the only value the equivalence relation is allowed to ignore. Float formatting is locale-independent in Rust (`format!` always uses `.`), eliminating the catastrophic `,`-decimal-separator class of bug. Every `HashMap`/`HashSet` (`used_cells`, `blank_fill_color`, `quartile_of_cell`, `fingerprint_cells`, `token_by_index`, the color-bar `order_pos`/`color_order`) is consumed by key lookup or `.contains()`; output is emitted by `for ci in 0..cell_count` and by total-ordered `sort_by_key`, never by hash-iteration order. Repeated renders are byte-identical (verified for a >512-bit input and the txt fallback).
- **Evidence / example:** `diff` of two renders of the same large input → identical; code inspection of every collection's usage.
- **Recommended action:** None. Recorded so a later panel does not re-open the determinism question without new evidence.

### F7: Cryptographic / fingerprint construction — verified correct (recorded; no defect)

- **Class:** CRYPTO
- **Severity:** LOW (informational; no defect)
- **Confidence:** CONFIRMED
- **Location:** `src/lib.rs:137-168` (primary + second digest), `src/entropy.rs:1131-1187` (middle cells), `src/keccak.rs` (EIP-55 Keccak-256).
- **Finding:** (a) Primary fingerprint = `SHA-512` over the UTF-8 bytes of the canonical normalized **core text** (`compute_fingerprint` hashes `core.as_bytes()`), and the prefix-fold case hashes `prefix ‖ core` exactly when `prefix_semantic` is set (`src/pipeline.rs:131-134`) — the spec's text-not-bytes rule (`this.i:h4shtext`) is honored. (b) The domain tag is the verbatim byte string `b"entviz/fingerprint-middle/v6\x00"` including the trailing NUL and the literal `v6` (NOT tracking the spec version) — `src/lib.rs:155`. (c) The second digest drives the two color-bar markers on every input (`second[12]`/`second[13]`) and the four middle cells on large inputs, exactly as the v9/v10 spec defines. (d) Middle cells render `second[3i..3i+2]` as 5 lowercase Crockford base32 chars over `0123456789abcdefghjkmnpqrstvwxyz` (`crockford5`), the injective 24-bit readout. (e) The bit-extension doubling reproduces the spec's worked examples (`0xAB→0xABABAB`, `0x5→0x555555`, `0xABC→0xABCABC` — covered by `quant_extension` and `tokenize_*` tests). (f) Keccak-256 (original padding `0x01…0x80`, NOT NIST SHA3) matches FIPS/known-answer vectors for `""`, `"abc"`, and multi-block inputs (`src/keccak.rs` tests), and is used only on the EIP-55 path. A one-byte slip in any of these would be silent and total; none is present.
- **Evidence / example:** Byte-for-byte Rust↔Python Tier-A model match on a >512-bit truncated input confirms the middle-cell `second`-digest readout agrees end to end.
- **Recommended action:** None. Recorded to anchor the cryptographic-rigor conclusion.

---

## Additional Patterns Noted

- **`src/entropy.rs:1011` — doubled predicate in the EOS char-class:** `c.is_ascii_lowercase() && c.is_ascii_lowercase() || ...`. The `a && a` is a copy-paste artifact; it evaluates to `a`, so behavior is correct (and matches the Python `[a-z1-5.]` regex), but it reads as a bug. Trivial cleanup (maintainability).
- **Unknown-char→0 coercion is shared, not divergent:** `char_value` coerces an unrecognized char to `0` (`src/lib.rs:106-108`); Python does the identical `if char_val == -1: char_val = 0` (`entropy.py:1245`). Unreachable after parse/disproof (the core only holds valid alphabet chars), and identical across impls — not a divergence, but it is an under-specified spot the spec never names (see ledger).
- **`MAX_INPUT_CHARS = 65536` cap (`src/pipeline.rs:17`)** rejects inputs > 65536 chars with `InputTooLong`. The spec's normative error set does not include an input-length cap; this is an implementation-defined DoS guard. It is a *superset* rejection beyond the spec's mandated set. Confirm the Python reference shares the same cap (it appears to, given the corpus passes) so the two impls reject the same inputs — otherwise it is an over-rejection divergence. (Looks aligned; flagged for completeness.)
- **`data-bar-marker` (`left`/`right`) on each circle vs `data-bar-marker-left`/`-right` (slot index) on the group:** both are emitted; the group attributes carry the slot indices the spec requires, and the corpus passes, so the redundant per-circle attribute is harmless advisory metadata (allowed by the equivalence relation).
- **`parse_hex_multihash`, `parse_did`, `parse_cardano_address` omitted from `PARSERS`** (commented at `src/entropy.rs:1038-1053`) because the corpus does not exercise them. This is fine for *corpus* conformance but means inputs those parsers would have typed (e.g. a Cardano `addr1…`, a DID, a bare hex multihash) get a different type label / possibly a different alphabet than Python, which *could* change the fingerprint (different normalized core) and thus the whole entviz. Not corpus-visible, but a real cross-impl divergence for those input families — worth either porting the parsers or documenting them as an accepted, corpus-bounded limitation.

---

## Under-Specification Ledger

Places where `docs/spec.md` (not this port) leaves a choice two honest implementations could resolve differently and the equivalence relation does not list as ignorable:

1. **Canonical coordinate float serialization (F5).** The spec forgives "numeric formatting that denotes the same value" but never defines the value→string function for geometry, so Tier-B parity silently depends on each language's default float printer round-tripping identically. entviz-rs and Python agree; entviz-js is the risk. Pin a canonical format.
2. **Unknown-character handling in `tokenize`.** Both impls coerce an unrecognized char to quant-bits `0`; the spec never states this (it is unreachable after a successful parse, but a re-implementer could legitimately choose to *error* instead). Harmless today, but undocumented shared behavior is a latent divergence if a future parser ever lets an out-of-alphabet char reach `tokenize`.
3. **Error-message content for rejected inputs.** The spec mandates the EIP-55 error *identify the first mismatched digit* (F1) but the conformance corpus only checks that error vectors are *rejected* (exit code), never the message. There is no Tier-A field for "the error names the right digit," so this MUST is effectively unenforceable by the corpus — an impl can satisfy the checker while violating the spec (as this port currently does).
4. **`data-entviz-lib` is outside the compared render model.** `compliance/model.py` deliberately ignores it, so an impl can stamp any lib version (including a wrong one, as here) and still pass Tier A. If the lib stamp is meant to be trustworthy provenance, the spec/corpus should either compare it or explicitly declare it advisory-only.

---

## Residual Unknowns

- **Cross-platform determinism (macOS/Windows).** Static review + a Linux run show byte-identical repeats, and Rust's `f64`→string and SHA-512/Keccak are platform-independent by construction, so I have **high** confidence determinism holds cross-platform — but it is not *proven*. Smallest experiment: a CI matrix (Linux/macOS/Windows) rendering a fixed input set and diffing the SVG byte-for-byte.
- **Tier-C browser smoke.** Out of scope here; non-blocking per spec. Smallest experiment: the existing headless-browser subset, once entviz-rs output is embedded in a page.
- **The omitted parsers (Cardano/DID/hex-multihash).** Whether their absence causes a real fingerprint divergence vs. Python for those input families is untested (the corpus does not cover them). Smallest experiment: feed one representative input of each omitted family to both impls and diff the Tier-A model.

---

```yaml
findings:
  - id: SPEC-F1
    persona: spec-conformance-auditor
    title: EIP-55 rejection discards the first-mismatched-digit position the spec MUST identify
    severity: MEDIUM
    confidence: CONFIRMED
    location: src/pipeline.rs:30-34
    dedupe_key: eip55-noncompliant-error-identification
    recommended_disposition: recommend-fix
    rationale: validate_eip55 computes the position but From<ParseError> drops it; input is rejected (security-safe) yet the spec's "identify the first mismatched-case digit" MUST is unmet. Corpus only checks rejection, so it passes regardless.
    revisit_condition: null
    fix_effort: small
  - id: SPEC-F2
    persona: spec-conformance-auditor
    title: Version stamps are hardcoded literals disconnected from SoT; data-entviz-lib already drifted (0.10.0 vs crate 0.10.1)
    severity: MEDIUM
    confidence: CONFIRMED
    location: src/pipeline.rs:209
    dedupe_key: version-stamp-divergent
    recommended_disposition: recommend-fix
    rationale: data-entviz-lib literal 0.10.0 != Cargo 0.10.1; both stamps bypass SPEC_VERSION/CARGO_PKG_VERSION with no guard test. Provenance attribute lies; next bump drifts silently. Not comparison-breaking (lib stamp is outside the compared model).
    revisit_condition: null
    fix_effort: small
  - id: SPEC-F3
    persona: spec-conformance-auditor
    title: data-entviz-version literal not driven by SPEC_VERSION constant (latent Tier-A divergence on next bump)
    severity: LOW
    confidence: CONFIRMED
    location: src/pipeline.rs:209
    dedupe_key: spec-version-stamp-divergent
    recommended_disposition: recommend-fix
    rationale: data-entviz-version IS a compared Tier-A field; correct today but a literal, so a SPEC_VERSION bump would emit a lying stamp. Same one-line fix as F2.
    revisit_condition: null
    fix_effort: small
  - id: SPEC-F4
    persona: spec-conformance-auditor
    title: Crate's corpus test no-ops without the sibling corpus and never checks Tier-A/B equality
    severity: LOW
    confidence: CONFIRMED
    location: tests/conformance.rs:46-53
    dedupe_key: conformance-suite-untested-in-ci
    recommended_disposition: recommend-defer
    rationale: cargo test alone proves only render/reject, not conformant-equivalence; the real Tier-A/B proof is a manual cross-repo Python runner invocation (which passes 52/52 today). Process-robustness gap, not a current defect.
    revisit_condition: Before entviz-rs is relied on as an independently-certified impl in CI, or before the next spec bump.
    fix_effort: medium
  - id: SPEC-F5
    persona: spec-conformance-auditor
    title: Coordinate float serialization is unpinned by the spec (cross-impl Tier-B landmine for entviz-js)
    severity: LOW
    confidence: LIKELY
    location: src/pipeline.rs:67-69
    dedupe_key: spec-missing-coordinate-serialization-cross-impl
    recommended_disposition: recommend-fix
    rationale: Renderer emits raw f64 strings (e.g. 1.9250000000000003); Rust↔Python agree on the corpus but the spec never pins a canonical float format, so a third impl (JS) could diverge in Tier-B. Fix is in docs/spec.md, not this port.
    revisit_condition: null
    fix_effort: small
</yaml>
```
