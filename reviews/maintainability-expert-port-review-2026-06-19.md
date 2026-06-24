# Maintainability Review: entviz-rs

**Date:** 2026-06-19
**Effort level:** medium
**Context sources used:** README.md, AGENTS.md, Cargo.toml, src/lib.rs, src/entropy.rs, src/pipeline.rs, src/model.rs, src/keccak.rs, src/main.rs, src/bin/render_model.rs, tests/conformance.rs, tests/cli.rs, scripts/release.py, .github/workflows/ci.yml, reviews/ (read after forming own assessment)

**Note:** This is a Rust port (entviz-rs) not the Python reference. The maintainability-expert persona prompt targets the Python reference codebase structure. This review adapts the lens to Rust idioms and the port's specific context, while applying the same intent-boundary and duplication analysis.

---

## Evidence Inventory

**Repository:** entviz-rs — a certified Rust port of the entviz spec v10 SVG renderer.

**Structure:** Six source files (`lib.rs` core math, `entropy.rs` format parsers, `pipeline.rs` SVG renderer, `model.rs` adversarial oracle layer, `keccak.rs` vendored Keccak-256, `main.rs` conformance CLI), plus `src/bin/render_model.rs` gated behind the `adversarial` feature. Integration tests in `tests/conformance.rs` and `tests/cli.rs`.

**This.i / intent layer:** There is no `this.i` in this repository; AGENTS.md references tick marks but is thin compared to the Python reference. The port leans on comments within source files to convey rationale. Several Python reference `this.i` nodes are paraphrased (e.g. `s3mpr3fx` cited in model.rs:402), but none are present as a structured intent layer here. The absence of `this.i` is expected for a port repo at this stage — the risk is that the Python reference's intent nodes are cited by id without being reachable from this repo's own artifacts.

**Key observation before reading prior reviews:** First impressions as a new developer:

1. README is clear and well-structured, oriented around the cert status. The version convention (`0.<spec-major>.x`) is documented.
2. AGENTS.md is minimal — tick-ledger instructions, TDD, CI gate, no methodology section comparable to the Python reference.
3. There is no `this.i`; all rationale lives in code comments.
4. The most confusing early discovery: alphabets `HEX` and `BASE64URL` appear twice (once in `lib.rs`, once in `entropy.rs`). A new developer reading `entropy.rs` imports wouldn't know `lib.rs` has its own copies.
5. Multiple helper functions are duplicated verbatim between `pipeline.rs` and `model.rs` (`crockford5`, `assign_cell_indices`, `two_bit_counts`, `first_appearance`/`first_appearance_order`, `band_letter`).
6. `data-entviz-lib` in `pipeline.rs` is a hardcoded string literal already mismatched from the actual crate version.

After reading prior reviews: The spec-conformance auditor independently identified the hardcoded version stamps (F2/F3) and the EOS doubled predicate as additional patterns. The DevOps engineer noted spec-sync is absent from the release gate. None previously enumerated the full duplicated-function catalog or assessed the domain-tag freeze comment adequacy. The maintainability finding about `compute_fingerprint` lacking an explicit "text not decoded bytes" comment is novel here.

---

## Executive Summary

entviz-rs is well-crafted Rust with good inline documentation for the load-bearing cryptographic decisions. The dominant maintainability risk is **duplication of core helper functions and alphabet constants across modules**: `crockford5`, `assign_cell_indices`, `two_bit_counts`, `first_appearance`, `band_letter`, `HEX`, and `BASE64URL` each exist in two separate files without either a comment explaining why they are not shared or a test confirming they agree. A future maintainer who fixes a bug in one copy will miss the other. The second priority is the **hardcoded `data-entviz-lib` version stamp** (`"0.10.0"`) in `pipeline.rs` that is already wrong relative to the crate version (`0.10.1`); this will accumulate further drift with each patch release. The `MIDDLE_DOMAIN_TAG` `v6` freeze has a comment (`"fixed, not the spec version"`) but lacks the explicit prohibition that would stop a well-meaning maintainer from "fixing" it — recommend strengthening that one sentence to a hard warning.

---

## Top Findings

Ordered by bang-for-buck (highest future-mistake-prevention per unit of fix effort, first).

### MNT-F1: Core helpers duplicated between `pipeline.rs` and `model.rs` without explanation

- **Severity:** HIGH
- **Confidence:** CONFIRMED
- **Location:** `src/pipeline.rs:743` (`two_bit_counts`), `src/pipeline.rs:752` (`first_appearance`), `src/pipeline.rs:605` (`assign_cell_indices`), `src/pipeline.rs:769` (`band_letter`) vs. `src/model.rs:319`, `src/model.rs:331`, `src/model.rs:279`, `src/model.rs:98`; also `src/entropy.rs:1132` (`crockford5`) vs. `src/model.rs:25`
- **Finding:** Five functions — `two_bit_counts`, `first_appearance`/`first_appearance_order`, `assign_cell_indices`, `band_letter`, and `crockford5` — are copy-pasted between `pipeline.rs` (the SVG renderer) and `model.rs` (the adversarial oracle). They are currently in sync, but there is no comment explaining why they are not shared and no test confirming they agree. A bug fixed in one copy — say, a future spec change to the cell-index assignment algorithm — will silently survive in the other. The `model.rs` copies serve a different consumer (the adversarial grinder) so some separation may be intentional, but the intent is undocumented. `crockford5` additionally exists in `entropy.rs` (public, line 1132) while `model.rs` (line 25) defines a private copy instead of importing the public one.
- **Recommendation:** Either consolidate into shared private helpers in `lib.rs` (or a `shared.rs` module) and re-export/import them, or add an explicit comment above each duplicate in `model.rs` naming the reason for the separation (e.g., "deliberately not imported from `pipeline` to avoid coupling the adversarial oracle layer to the renderer"). For `crockford5` specifically, `model.rs` should `use crate::entropy::crockford5` rather than redefining it. Add a `#[test]` comparing the two `assign_cell_indices` implementations on a fixed input if the divergence is intentional.
- **Fix effort:** medium

---

### MNT-F2: `data-entviz-lib` hardcoded and already wrong; `data-entviz-version` uncoupled from `SPEC_VERSION`

- **Severity:** HIGH
- **Confidence:** CONFIRMED
- **Location:** `src/pipeline.rs:209`
- **Finding:** The SVG `data-entviz-lib` attribute is the string literal `"0.10.0"` but the crate is already at version `0.10.1` (`Cargo.toml:3`). This divergence will compound with every patch release. More broadly, `data-entviz-version` is the literal `"v10"` rather than a reference to `crate::SPEC_VERSION`, and `data-entviz-lib` is a literal rather than `env!("CARGO_PKG_VERSION")`. No test catches this drift. A consumer using `data-entviz-lib` for build provenance currently gets a false answer. If both stamps are meant to be trustworthy (they appear to be, given the attribute names and spec-version sync logic elsewhere), this is a HIGH: it erodes confidence in attribution and makes debugging impossible when two versions behave differently.
- **Recommendation:** Replace both literals:
  ```rust
  data-entviz-version=\"{}\" data-entviz-lib=\"{}\"
  ```
  with `crate::SPEC_VERSION` and `env!("CARGO_PKG_VERSION")` respectively. Add a unit test asserting the emitted SVG contains the correct runtime values.
- **Fix effort:** small

---

### MNT-F3: `HEX` and `BASE64URL` alphabet constants duplicated between `lib.rs` and `entropy.rs`

- **Severity:** MEDIUM
- **Confidence:** CONFIRMED
- **Location:** `src/lib.rs:50-58` vs. `src/entropy.rs:15-19` (`HEX`); `src/lib.rs:55-59` vs. `src/entropy.rs:55-59` (`BASE64URL`)
- **Finding:** Both `HEX` and `BASE64URL` are defined in `lib.rs` (used by `pipeline.rs` and the core math) and independently re-defined in `entropy.rs` (used by the parsers). Today the definitions are identical. A future maintainer who changes `entropy.rs::HEX::chars` to fix a parser quirk — e.g., adding a lowercase alias — will leave `lib.rs::HEX` unchanged, silently creating a case where the fingerprint tokenizer and the parsers disagree on what hex is. This mirrors exactly the `BASE64_ALPHABET` double-definition defect that the Python reference (`MNT-F2` from prior reviews on entviz) had. The fact that Rust's type system would not prevent two `Alphabet` values with the same `name` but different `chars` from coexisting makes this especially dangerous.
- **Recommendation:** Define `HEX` and `BASE64URL` once in `lib.rs` (they already exist there as the canonical home for shared types) and have `entropy.rs` import them via `use crate::{HEX, BASE64URL}`. The other alphabet constants (`BASE58`, `BASE64`, `BASE32`, etc.) that are entropy-only can stay in `entropy.rs`.
- **Fix effort:** small

---

### MNT-F4: `MIDDLE_DOMAIN_TAG` freeze comment is present but not strong enough to prevent the damaging "fix"

- **Severity:** MEDIUM
- **Confidence:** LIKELY
- **Location:** `src/lib.rs:153-155`
- **Finding:** The current comment reads: `"v6" is the *construction* version (fixed), not the spec version.` This is correct and better than nothing, but it does not explicitly say **what happens if you change it**: re-keying the domain separation would invalidate every large-input entviz ever rendered, silently, with no diagnostic. A future maintainer seeing `v6` in a codebase on spec v10 will feel a strong pull to "fix" this stale-looking literal, especially if they do not yet understand domain separation. The comment says "fixed" without saying "MUST NOT change even when `SPEC_VERSION` bumps." The risk is low for a security-trained developer but high for a general maintainer doing a spec-upgrade sweep.
- **Recommendation:** Strengthen the comment to make the consequence explicit:
  ```rust
  /// Domain tag for the second, domain-separated digest. The trailing NUL is
  /// included. `v6` is the *construction* version — **DO NOT update this literal
  /// when `SPEC_VERSION` changes.** Changing it re-keys the domain separation and
  /// invalidates every large-input entviz ever rendered (silently; no diagnostic).
  /// See Python reference this.i:s3mpr3fx.
  pub const MIDDLE_DOMAIN_TAG: &[u8] = b"entviz/fingerprint-middle/v6\x00";
  ```
- **Fix effort:** small

---

### MNT-F5: `compute_fingerprint` hashes the normalized text string, not decoded bytes — no callsite comment

- **Severity:** MEDIUM
- **Confidence:** CONFIRMED
- **Location:** `src/lib.rs:137-144`
- **Finding:** `compute_fingerprint` takes `&str` and hashes its UTF-8 bytes via `.as_bytes()`. This is correct per spec (`this.i:h4shtext` in the Python reference): the fingerprint must be computed over the canonical text representation of the core, not over any decoded byte sequence. However, there is no comment at the function definition or its call sites in `pipeline.rs` explaining *why* this is the right thing to do. A performance-minded Rust developer, seeing that many inputs are hex strings, would be tempted to decode to binary (`hex::decode`) and hash the compact form — halving the hash input — without realizing this would break the security property. The Python reference `this.i` node `h4shtext` captures this rationale, but it is not referenced or paraphrased anywhere in this Rust port.
- **Recommendation:** Add a doc comment to `compute_fingerprint` stating the invariant explicitly:
  ```rust
  /// Compute the entviz primary fingerprint over the canonical text core.
  ///
  /// **The spec mandates hashing the normalized text representation, not any
  /// decoded byte sequence.** For a hex core `"deadbeef"`, this hashes the
  /// 8-byte ASCII string, not the 4 decoded bytes. "Optimizing" to hash decoded
  /// bytes would break cross-implementation determinism and the spec's security
  /// model. See Python reference `this.i:h4shtext`.
  pub fn compute_fingerprint(core: &str) -> [u8; 64] {
  ```
- **Fix effort:** small

---

## Additional Patterns Noted

- **`eos_regex` doubled predicate (line 1011):** `c.is_ascii_lowercase() && c.is_ascii_lowercase()` is a copy-paste artifact — `a && a` evaluates to `a`, so behavior is correct (and the corpus passes), but it reads as a bug to anyone unfamiliar with EOS address syntax. The spec-conformance auditor also flagged this. Trivially cleaned up as `c.is_ascii_lowercase()`. Severity: LOW.

- **`patch_color_bar_attrs` retroactive string mutation pattern (`pipeline.rs:902-910`):** This function finds a sentinel string in the already-built SVG output and substitutes a larger string back, because the color-bar's `data-bar-slots`/`data-bar-marker-*` attributes are only available after the bar is drawn. This is a maintainability smell — it depends on the sentinel being unique in the output, which is currently true but not enforced. A future refactor that draws a second color bar (or renames the group) could silently defeat it. The fix would be to compute marker slot count before drawing (it depends only on `bounding_h` which is known early) and pass it as an argument to `draw_color_bar`. Severity: LOW.

- **`Alphabet` struct uses `&'static str` fields, requiring `Box::leak` in `render_model.rs`:** `src/bin/render_model.rs:69-73` leaks heap-allocated strings to satisfy the `'static` lifetime requirement on `Alphabet::name` and `Alphabet::chars`. The comment acknowledges this is intentional for a short-lived binary. However, if `Alphabet` were changed to own its strings (or use `Cow<'static, str>`), the workaround would disappear. No immediate action needed, but the `&'static str` constraint is a latent design choice with visibility cost. Severity: LOW.

- **`PARSERS` ordering comment is minimal:** The module doc says "order is semantics" (line 3) but the `const PARSERS` array comment only says "order matches entropy.py's parse_funcs." There is no in-code explanation of *which* orderings matter for disambiguation (e.g., UUID must precede general hex because 32-hex is a valid UUID; hex must precede bech32 in disproof detection). A maintainer who reorders to group related parsers could create silent misclassification. Low risk since the corpus will catch most regressions, but the intent boundary exists. Severity: LOW.

- **`sanitize_note` double-checks for empty string:** Lines 38-46 check `Some("")` → `Ok(None)` early, then re-check `n.is_empty()` in the validation branch (which can never be true because the `Some("")` case already returned). The dead branch is harmless but may confuse a reader. Severity: LOW.

- **No `this.i` analogue in this repo:** The Python reference's extensive `this.i` intent layer has no counterpart here. Decisions like "why `round_ties_even` for banker rounding" (model.rs:463-465) are well-commented inline, but there is no single searchable artifact collecting the rationale inventory. For a port repo, this may be acceptable — the Python `this.i` is the source of truth. But references to Python `this.i` nodes (e.g., `s3mpr3fx` in model.rs) are not useful to a developer who doesn't have the sister repo checked out, so the model.rs comment that says "See pipeline.py:195 and this.i:s3mpr3fx" requires navigating to another repo. Consider adding a cross-reference note in AGENTS.md pointing readers at the Python reference `this.i`.

- **`model.rs` has a separate `SPEC_VERSION_V10` constant (line 20)** instead of re-using `crate::SPEC_VERSION`. These are currently in sync (`"v10"`), but a future maintainer bumping `SPEC_VERSION` in `lib.rs` may forget to update `SPEC_VERSION_V10`. The fix is one import: `use crate::SPEC_VERSION;` and use it in `to_golden_json`. Severity: LOW.

- **Test for `sanitize_note` has a bug in the test description:** `render_model.rs` tests that font_pt=6 uses banker rounding (the `fs6_text_size_uses_banker_rounding` test) — excellent. But this test only exists in `model.rs`, not in `pipeline.rs`, even though `pipeline.rs` also uses `round_ties_even` at line 175-177. A regression in `pipeline.rs`'s rounding formula would not be caught by the model test. Add a parallel test in `pipeline.rs`'s test module that checks the emitted `font-size` attribute. Severity: LOW.

---

## Future Developer FAQ

1. **Why does `compute_fingerprint` hash the text string rather than decoding hex/base64 to bytes first?**  
   The spec mandates text-not-bytes (`this.i:h4shtext` in the Python reference). Hashing decoded bytes would break cross-implementation determinism — the Python reference also hashes text, and both must agree.

2. **Why is `MIDDLE_DOMAIN_TAG` literally `v6` when the spec is at v10?**  
   The `v6` is a *construction version* (fixed forever), not the spec version. It cannot be changed without re-keying all large-input fingerprints. The Python `this.i` documents this as frozen.

3. **Why are `crockford5`, `assign_cell_indices`, `two_bit_counts`, etc. in both `pipeline.rs` and `model.rs`?**  
   Currently unclear — there is no comment explaining the duplication. The likely intent is module independence (the adversarial oracle layer should not import from the renderer), but this is not stated.

4. **Why does the dispatch in `entropy.rs` use a `const PARSERS` array rather than a trait or enum?**  
   Order is semantics: parsers must run in a specific sequence because some inputs (e.g., a 32-hex string) match multiple parsers, and the first match wins. A const array with an explicit order is the most transparent encoding of this constraint. The module doc says "order is semantics."

5. **What is `model.rs` and why is it gated behind `--features adversarial`?**  
   It implements the Tier-A render-model oracle for the private adversarial grinder (`entviz-adversarial`). It is not part of the public implementation, not needed for conformance certification, and is excluded from the published crate on crates.io to keep the public API minimal.

---

## Residual Unknowns

- Whether the duplication of helpers between `pipeline.rs` and `model.rs` was an intentional design decision (avoid coupling layers) or accumulated coincidentally. The fix recommendation (consolidate or explain) holds either way, but the right location differs.
- Whether the EOS alphabet choice (`BASE64` assigned in `parse_eos_address`) is correct per the spec — EOS account names use `[a-z1-5.]` which is not any standard alphabet. The current assignment of `BASE64` appears to be a token-coercion choice rather than a correct alphabet claim. This is more a spec question than a maintainability one.

---

## Decisions Needed

1. **Duplication architecture:** Should `model.rs` import helpers from `pipeline.rs` (or a shared module), or should the two layers remain fully independent? This is a design decision that affects the entire helper-duplication family (F1). The answer should be recorded in AGENTS.md or as an inline comment once decided.

2. **Cross-repo intent references:** When `model.rs` cites `this.i:s3mpr3fx` from the Python reference, should `entviz-rs` AGENTS.md include a pointer to the Python reference `this.i` as a required context source? This would help agents and maintainers who work only in this repo.

---

## Findings Manifest

```yaml
findings:
  - id: MNT-F1
    persona: maintainability-expert
    title: Core helpers (crockford5, assign_cell_indices, two_bit_counts, band_letter) duplicated verbatim between pipeline.rs and model.rs
    severity: HIGH
    confidence: CONFIRMED
    location: src/pipeline.rs:605,743,752,769 vs src/model.rs:25,279,319,331,98 and src/entropy.rs:1132
    dedupe_key: pipeline-duplicated
    recommended_disposition: recommend-fix
    rationale: A bug fixed in the pipeline copy survives in the model copy (and vice versa); no test enforces parity; no comment explains the intentional separation.
    revisit_condition: null
    fix_effort: medium

  - id: MNT-F2
    persona: maintainability-expert
    title: data-entviz-lib hardcoded as "0.10.0" (crate is 0.10.1); data-entviz-version uncoupled from SPEC_VERSION
    severity: HIGH
    confidence: CONFIRMED
    location: src/pipeline.rs:209
    dedupe_key: pipeline-stale
    recommended_disposition: recommend-fix
    rationale: The lib stamp is already wrong and will diverge further with every release; no test catches it; data-entviz-version is equally fragile.
    revisit_condition: null
    fix_effort: small

  - id: MNT-F3
    persona: maintainability-expert
    title: HEX and BASE64URL alphabet constants defined twice (lib.rs and entropy.rs)
    severity: MEDIUM
    confidence: CONFIRMED
    location: src/lib.rs:50-59 vs src/entropy.rs:15-59
    dedupe_key: alphabet-duplicated
    recommended_disposition: recommend-fix
    rationale: Mirrors the BASE64_ALPHABET double-definition defect the Python reference carried; a change to one copy diverges silently.
    revisit_condition: null
    fix_effort: small

  - id: MNT-F4
    persona: maintainability-expert
    title: MIDDLE_DOMAIN_TAG freeze comment present but lacks explicit prohibition against bumping with SPEC_VERSION
    severity: MEDIUM
    confidence: LIKELY
    location: src/lib.rs:153-155
    dedupe_key: fingerprint-missing
    recommended_disposition: recommend-fix
    rationale: A maintainer doing a spec-upgrade sweep will see "v6" in a v10 codebase and feel compelled to fix it; the consequence (re-keys all large-input fingerprints) is absent from the comment.
    revisit_condition: null
    fix_effort: small

  - id: MNT-F5
    persona: maintainability-expert
    title: compute_fingerprint hashes text not decoded bytes — no callsite comment or doc on WHY
    severity: MEDIUM
    confidence: CONFIRMED
    location: src/lib.rs:137-144
    dedupe_key: fingerprint-missing
    recommended_disposition: recommend-fix
    rationale: A Rust developer would naturally optimize by decoding hex/base64 to bytes before hashing; the spec-mandated text-not-bytes invariant is not explained at the function definition or its call sites.
    revisit_condition: null
    fix_effort: small
```
