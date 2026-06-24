# Security Review: entviz-rs

**Date:** 2026-06-19
**Effort level:** medium
**Run label:** port-review-2026-06-19
**Context sources used:** `AGENTS.md`, `Cargo.toml`, `Cargo.lock`, `src/main.rs`, `src/lib.rs`, `src/pipeline.rs`, `src/entropy.rs`, `src/keccak.rs`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/workflows/copilot-review-gate.yml`, prior reviews `reviews/spec-conformance-auditor-port-review-2026-06-19.md`; `this.i` is absent from this repo; `docs/` is absent.

---

## Evidence Inventory

**Files read (complete):** All five source files under `src/` (`main.rs`, `lib.rs`, `pipeline.rs`, `entropy.rs`, `keccak.rs`), `Cargo.toml`, `Cargo.lock`, all three workflow YAML files, `AGENTS.md`.

**What was skipped and why:** There is no `this.i`, no `docs/spec.md`, no `docs/threat-model.md`, and no `README.md` in this repo. `AGENTS.md` explains that `entviz-rs` is a port of the Python reference implementation (`dhh1128/entviz`) and normative documentation lives there. The prior reviews were read after forming an independent model.

**Shell scans performed:**
- Grep for dangerous Rust primitives: `std::process::Command`, `unsafe`, shell execution — none found.
- Grep for concealed/bidi Unicode (U+200B through U+202E, Private Use Area) — none found.
- Dependency checksum cross-check against crates.io for all direct and notable transitive dependencies: all checksums matched.

**Renderer run:** Not run (medium effort). No adversarial input was fed to `entviz-conformance` at this tier.

---

## Executive Summary

The entviz-rs Rust port has a narrow, well-contained security surface: a JSON-in/SVG-out binary with no network listener, no filesystem writes beyond stdout, and no dynamic code evaluation. The single most important finding is a missing threat-model document. The hand-rolled SVG builder applies `esc_attr`/`esc_text` consistently across every user-influenced channel; no injection bypass was found. The CI/CD supply chain is strong: all GitHub Actions are SHA-pinned to node24/composite runtimes, `Cargo.lock` is committed, and every dependency checksum was verified against crates.io. Two low-severity items are actionable: a structural fragility in `copilot-review-gate.yml` (PR number interpolated into URL without a numeric guard), and the missing threat-model documentation.

---

## Top Findings

Ordered by bang-for-buck (highest risk reduction per unit fix effort, first).

### F1: No threat-model document — trust boundaries and accepted risks undocumented

- **Severity:** LOW
- **Confidence:** CONFIRMED
- **Location:** repo root (file absent)
- **Finding:** There is no `docs/threat-model.md` or `SECURITY.md` in this repo. The crate publishes to crates.io and its SVG output is embedded in web pages. Downstream library consumers have no documented record of: which inputs the library must-reject (note outside `[A-Za-z0-9]{1,8}`, input > 65536 chars, bad EIP-55 checksum); what it does NOT guard against (host-page CSS override); or what escaping model it relies on.
- **Exploit path:** Not directly exploitable. A consumer who re-renders the SVG string through an XML template engine without understanding the escaping model could inadvertently double-escape or strip protection. A developer consulting only the crate docs would not know the note sanitizer is a spec MUST-reject, not just a UX choice.
- **Recommendation:** Add a lightweight `SECURITY.md` at repo root naming: (1) trust boundary (entropy string is untrusted; note and parameters are caller-supplied); (2) defenses in place (`sanitize_note` MUST-reject gate, `esc_attr`/`esc_text` throughout); (3) accepted risks (CSS override from host page, no network/DB surface). One page suffices.

---

### F2: CSS override from host page can neutralize visual channels — accepted-risk observation

- **Severity:** LOW
- **Confidence:** CONFIRMED
- **Location:** `src/pipeline.rs:239-504` (SVG channel construction)
- **Finding:** entviz-rs emits color values using presentation attributes (`fill=`, `stroke=`, `style=`) with no shadow-DOM isolation. A page embedding many entvizes can override them with `[data-channel="color-bar"] rect { fill: gray !important }`, erasing the discriminating color-bar channel. This is an inherent limitation of non-isolated embedded SVG, not a defect. The inline-attribute approach (no `<style>` block, no class hooks that would make mass-targeting trivially easy) is already the best available defense for embedded SVG.
- **Exploit path:** An adversarial page operator embeds an entviz gallery and applies targeted CSS overrides to make two distinct values render indistinguishably on their own page. The attacker controls only their own page; this is perceptual sabotage on the attacker's own site, not injection or credential theft.
- **Recommendation:** Document as an accepted risk in `SECURITY.md`. No code change is warranted. Cross-reference to the perception reviewer (PSY) for the discriminability impact.

---

### F3: Workflow structural concern — `PR_NUMBER` interpolated into API URL path without numeric guard

- **Severity:** LOW
- **Confidence:** LIKELY
- **Location:** `.github/workflows/copilot-review-gate.yml:49,63`
- **Finding:** `${{ github.event.pull_request.number }}` is passed via `env:` (the correct safe pattern, not direct template-substitution into a `run:` block) and then used as `$PR_NUMBER` in a `gh api` URL path. No explicit numeric-sanity check guards it. In practice this is not exploitable — GitHub guarantees `pull_request.number` is always a positive integer. The `PR_TITLE` glob test (`[[ "$PR_TITLE" == *"[no-ccr]"* ]]`) is correctly safe because untrusted data appears on the left side of `[[` with proper quoting. `pull_request` (not `pull_request_target`) is used throughout; forked code is never checked out and run.
- **Exploit path:** Currently none — GitHub platform enforces the integer type. A future regression, event spoofing through `workflow_dispatch`, or copy-paste of this workflow to a privileged trigger context could expose the structural gap.
- **Recommendation:** Add `if ! [[ "$PR_NUMBER" =~ ^[0-9]+$ ]]; then echo "::error::unexpected PR_NUMBER"; exit 1; fi` before the API calls. Small fix, eliminates fragility.

---

### F4: Unfamiliar transitive dependencies (`serde_core`, `zmij`) — verified clean

- **Severity:** LOW
- **Confidence:** CONFIRMED
- **Location:** `Cargo.lock:122-162`
- **Finding:** The `serde_json = "1"` constraint resolves to version 1.0.150, which pulls in two crates unfamiliar to readers with pre-2025 training data: `serde_core` (serde-rs organization, a split of the trait-only layer; repository `serde-rs/serde`) and `zmij` (dtolnay, a float-to-string algorithm; repository `dtolnay/zmij`, 132M downloads). Both are legitimate serde-ecosystem crates. Checksums verified: `serde_core` `41d385c7d4...` matches crates.io; `zmij` `b8848ee67e...` matches crates.io; `serde_json` itself `e8014e44b4...` matches crates.io. This finding closes the supply-chain audit loop — no risk was confirmed.
- **Exploit path:** None identified.
- **Recommendation:** No action required. Optionally document these as recognized serde-ecosystem crates in `SECURITY.md` so a future auditor doesn't have to re-derive this. A `cargo audit` at publish time is recommended as part of the release checklist (not currently in `release.yml`).

---

### F5: No `unsafe` code — confirmed clean; large-input DoS resolved in port

- **Severity:** LOW (note, not a defect)
- **Confidence:** CONFIRMED
- **Location:** `src/` (all files); `src/pipeline.rs:17`, `src/entropy.rs:1144-1187`
- **Finding:** Zero `unsafe` blocks across all five source files. Memory safety is type-system-enforced. The large-input DoS concern from the Python reference (`SEC-F1` in prior Python reviews — `render()` had no length cap and `tokenize_entropy` tokenized the full multi-megabyte core before discarding most of it) is resolved in this Rust port: `MAX_INPUT_CHARS = 65536` (`pipeline.rs:17`) rejects inputs beyond 65536 chars before any tokenization; `tokenize_entropy` checks `token_count <= MAX_TOKENS && n_bytes <= 64` before calling `tokenize` on the full core, and the large-input path tokenizes only head (48 chars) + tail (48 chars), never the full core. The `choose_grid` loop iterates at most `token_count` times, bounded at 22.
- **Exploit path:** N/A — this is an absence of a risk and a confirmed fix.
- **Recommendation:** None. The `unsafe`-free codebase and the presence of the input cap and bounded tokenization path are security strengths.

---

## Additional Patterns Noted

- **All GitHub Actions SHA-pinned to node24/composite runtimes:** `actions/checkout@9c091bb` (node24 confirmed), `dtolnay/rust-toolchain@29eef33` (composite confirmed), `Swatinem/rust-cache@c19371` (node24 confirmed), `taiki-e/install-action@b8cecb8` (composite confirmed). `persist-credentials: false` is set consistently. No `pull_request_target` triggers anywhere. Exemplary CI hygiene.

- **SVG text-channel escaping coverage — complete:** Every user-influenced value reaching the SVG was traced: `token.text` via `esc_text` (line 489); `prefix`/`suffix` via `esc_text` (lines 936, 976, 984); `note` via `esc_attr` and `esc_text` (lines 979-980, 989-990); `type_name` is built exclusively from static label tables with decimal integer counts appended — never from raw user text; color strings via `esc_attr` (harmless, hardcoded hex); `MONOSPACE_FONT_FAMILY` contains embedded double-quotes that are correctly escaped via `esc_attr` when used inside `style="..."` attributes — `&quot;` in CSS attribute values is valid XML and browsers parse it correctly.

- **No secrets in source or CI:** `CARGO_REGISTRY_TOKEN` is sourced only from `${{ secrets.CARGO_REGISTRY_TOKEN }}` in `release.yml`; never hardcoded. No PEM blocks or high-entropy strings outside of test vectors.

- **`src/model.rs` and `src/bin/render_model.rs` excluded from published crate:** These adversarial oracle files are gated behind the off-by-default `adversarial` feature flag and listed in `Cargo.toml`'s `exclude = [...]`. A `cargo publish` does not ship them. Confirmed.

- **`data-input-bytes` reflects UTF-8 byte count, not char count:** `raw_input.len()` is a byte count (Rust `str::len()`). This differs from `.chars().count()` for non-ASCII entropy strings. Not an injection risk; worth noting for cross-impl consumers parsing the SVG's data attributes.

---

## Residual Unknowns

1. **Advisory database scan not performed:** At `effort: medium`, `cargo audit` or `osv-scanner` was not run. The dependency graph is small and all crates are from reputable authors, but a CVE scan at milestone release is recommended (not currently in `release.yml`).

2. **Renderer not exercised on adversarial inputs:** The deep path (run `entviz-conformance` on `<script>`, `]]>`, `&xxe;`, a 50 MB string, a note violating `[A-Za-z0-9]{1,8}`) was not taken at this effort level. Static code analysis found no injection bypass; a dynamic run on pathological inputs would raise confidence.

3. **Cross-impl fuzz surface not analyzed:** The conformance binary reads arbitrary JSON on stdin. A fuzzer targeting the JSON-parse-to-render path could surface panics. Rust's bounds checking prevents memory corruption, but a panic-exit is a DoS in a library context. Not analyzed at medium effort.

---

## Decisions Needed

1. **Add `SECURITY.md` or `docs/threat-model.md`?** Recommended. The crate publishes to crates.io; downstream consumers and future auditors benefit from explicit documentation of the trust model.

2. **Add `cargo audit` to `release.yml` before `cargo publish`?** Recommended. Small addition, closes the "known-CVE in transitive dep" gap. Should be gated to abort on HIGH/CRITICAL advisories only.

3. **Add PR_NUMBER numeric guard in `copilot-review-gate.yml`?** Recommended. Two-line bash check, eliminates a structural fragility.

---

## Findings Manifest

```yaml
findings:
  - id: SEC-F1
    persona: security-hawk
    title: No threat-model document — trust boundaries and accepted risks undocumented
    severity: LOW
    confidence: CONFIRMED
    location: "repo root (file absent)"
    dedupe_key: threat-model-missing
    recommended_disposition: recommend-fix
    rationale: >
      The crate publishes to crates.io and emits embeddable SVG; downstream
      consumers have no documented record of the sanitize_note MUST-reject gate,
      the esc_attr/esc_text defense model, or the CSS-override accepted risk.
    revisit_condition: null
    fix_effort: small

  - id: SEC-F2
    persona: security-hawk
    title: CSS override from host page can neutralize visual channels (accepted-risk observation)
    severity: LOW
    confidence: CONFIRMED
    location: "src/pipeline.rs:239-504"
    dedupe_key: svg-channel-exposed
    recommended_disposition: recommend-accept-risk
    rationale: >
      Inline fill/stroke attributes are as defensible as embedded SVG can be.
      Hostile host-page CSS can still override them with important. This is
      an inherent limitation of non-isolated SVG. Document as accepted risk.
    revisit_condition: null
    fix_effort: large

  - id: SEC-F3
    persona: security-hawk
    title: PR_NUMBER interpolated into API URL path without numeric guard
    severity: LOW
    confidence: LIKELY
    location: ".github/workflows/copilot-review-gate.yml:49,63"
    dedupe_key: github-actions-unpinned
    recommended_disposition: recommend-fix
    rationale: >
      PR_NUMBER is passed via env: (safe pattern) but the shell script does
      not validate it is numeric before using it in the gh api URL path.
      Not currently exploitable; a two-line bash guard eliminates the fragility.
    revisit_condition: null
    fix_effort: small

  - id: SEC-F4
    persona: security-hawk
    title: Unfamiliar transitive deps (serde_core, zmij) — checksums verified clean
    severity: LOW
    confidence: CONFIRMED
    location: "Cargo.lock:122-162"
    dedupe_key: uv-lock-unpinned
    recommended_disposition: recommend-accept-risk
    rationale: >
      serde_core and zmij are legitimate serde-ecosystem crates from serde-rs
      and dtolnay respectively; all checksums match crates.io exactly.
      No risk confirmed; listed to close the supply-chain audit loop.
    revisit_condition: "Reopen if cargo-audit or osv-scanner finds an advisory."
    fix_effort: small

  - id: SEC-F5
    persona: security-hawk
    title: No unsafe code; large-input DoS resolved in Rust port
    severity: LOW
    confidence: CONFIRMED
    location: "src/ (all files); src/pipeline.rs:17; src/entropy.rs:1144-1187"
    dedupe_key: cli-unbounded
    recommended_disposition: recommend-accept-risk
    rationale: >
      Zero unsafe blocks; MAX_INPUT_CHARS cap before tokenization; tokenize_entropy
      only touches head+tail on large inputs. The prior Python SEC-F1 unbounded-
      tokenize DoS does not apply here. Clean.
    revisit_condition: null
    fix_effort: small
```
