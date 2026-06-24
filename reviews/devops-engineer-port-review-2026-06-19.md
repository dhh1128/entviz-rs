# DevOps / CI/CD Review: entviz-rs

**Date:** 2026-06-19
**Effort level:** medium
**Context sources used:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/workflows/copilot-review-gate.yml`, `.github/dependabot.yml`, `scripts/release.py`, `scripts/setup-branch-protection.sh`, `Cargo.toml`, `Cargo.lock`, `README.md`, `AGENTS.md`, `tests/conformance.rs`, `tests/cli.rs`, `.gitignore`

---

## Evidence Inventory

Files read: all three workflow files in `.github/workflows/`, the `dependabot.yml`, both scripts in `scripts/`, `Cargo.toml`, `Cargo.lock`, `README.md`, `AGENTS.md`, and both test files in `tests/`. No prior `OPS-*` reviews were present in `reviews/` (the spec-conformance and perception reviews from this same run were noted but not consulted before forming this assessment).

Action SHAs resolved online using `curl` against the raw GitHub URLs:
- `actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0` → `using: node24` (v7.0.0) — CONFIRMED
- `dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8` → `using: composite` — CONFIRMED
- `Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4` → `using: "node24"` (v2.9.1) — CONFIRMED
- `taiki-e/install-action@b8cecb83565409bcc297b2df6e77f030b2a468d5` → `using: composite` (v2.82.0) — CONFIRMED

All actions: node24 or composite; none node20. SHA-pinning with human-readable `# vN.N.N` comments is present on every reference.

The Cargo.lock was confirmed tracked (correct for a binary/CLI crate). No tracked files in `target/`, `.venv/`, or other ignored-but-possibly-committed paths. Test suite structure: `tests/cli.rs` exercises the stdin/stdout/exit-code contract; `tests/conformance.rs` exercises the render/reject contract against the corpus when `../entviz` is present. No drift-check test (this is a Rust crate, not the Python reference — no committed generated assets). No `this.i` file exists.

The test suite itself was not run locally (as instructed, heavy shell work runs under `nice -n 19 ionice -c 3`; the test suite compiles Rust which would be heavy — the CI gate structure was audited from the workflow files directly, not by re-running).

---

## Executive Summary

The entviz-rs CI pipeline is well-structured for a young Rust port: actions are all SHA-pinned to node24 runtimes with Dependabot keeping them current, the release script runs a local gate before tagging, and the lockfile is enforced via `--locked` throughout. Two gaps stand out. First, `release.yml` grants `contents: write` at the **workflow level** rather than scoping it to the single step that needs it, which violates the principle of least privilege. Second — and more operationally material — the release gate inlines only `fmt + clippy + test`, omitting the **coverage floor** and **conformance** jobs that ci.yml runs; since the maintainer can push directly to main (admin bypass) and then push a tag, a commit that failed coverage or conformance in a PR can ship a release without either gate blocking it.

---

## Top Findings

Ordered by bang-for-buck (highest operational-risk reduction per unit of fix effort, first).

### F1: Release gate omits coverage floor and conformance — a direct-push tag can ship a noncompliant or undertested crate

- **Severity:** HIGH
- **Confidence:** CONFIRMED
- **Location:** `.github/workflows/release.yml` — `publish` job, "Gate (fmt + clippy + test)" step (line 32–37); also `scripts/setup-branch-protection.sh` line 22
- **Finding:** The inline gate in `release.yml` runs only `cargo fmt`, `cargo clippy`, and `cargo test`. It does not run `cargo llvm-cov` (the coverage floor job from ci.yml) and does not run the conformance suite. Since `scripts/setup-branch-protection.sh` configures branch protection with `enforce_admins: false`, the maintainer can push directly to `main` without a PR, then push a tag. A tag pushed at a commit that previously failed coverage or conformance in ci.yml will trigger the release workflow's gate — which will not re-run those checks — and the publish step will proceed.
- **Operational consequence:** A release of `entviz` on crates.io can ship with code below the 98%/90% coverage floor, or with a Tier-A conformance failure against the reference corpus. Because the spec-version sync logic in the conformance job is also absent from the release gate, spec drift (the crate behind the reference spec) can go unwarned at release time.
- **Recommendation:** Add a second job `gate-release` (or extend the inline gate) to run the coverage check and the conformance suite before the `publish` step. The simplest pattern is: make `publish` declare `needs: [test, coverage, conformance]` as separate jobs in `release.yml`, replicating the ci.yml structure. Alternatively, add `cargo llvm-cov --locked --fail-under-lines 98` and the conformance runner inline in the gate step. The spec-version sync warning from ci.yml should also be reproduced so the maintainer sees it at release time, not just on PRs.

---

### F2: `contents: write` granted at workflow level, not job level

- **Severity:** MEDIUM
- **Confidence:** CONFIRMED
- **Location:** `.github/workflows/release.yml` line 14–15 (`permissions: contents: write` at the top-level workflow block, with no job-level override)
- **Finding:** The `contents: write` permission is declared at the workflow level, meaning every job — and every step within those jobs — runs with write access to the repository contents. The actual need is narrow: only the final "Create the GitHub release" step (`gh release create`) requires `contents: write`, and `GH_TOKEN` is already scoped to that step via `env:`. The gate steps (fmt, clippy, test, tag verification) and the `cargo publish` step need no write access to contents.
- **Operational consequence:** If any third-party action or script in the job were compromised (supply-chain), it would have `contents: write` available for the entire job duration. The risk is lower here than for a multi-job workflow because there is only one job, but the deviation from least-privilege is unnecessary given that `GH_TOKEN` is passed per-step.
- **Recommendation:** Move the permissions block inside the `publish:` job (under `jobs: publish: permissions:`) and scope it tightly: `contents: write` (for the release creation), `packages: none`, all others inherited from the workflow default of `contents: read`. Even more targeted: the Gate and Verify steps could run in a separate job with `contents: read`, and only the create-release step's job needs `write`.

---

### F3: Coverage floor job is not a required branch-protection check

- **Severity:** MEDIUM
- **Confidence:** CONFIRMED
- **Location:** `scripts/setup-branch-protection.sh` line 21–24 (`"contexts": ["fmt + clippy + test", "spec-sync + Tier-A conformance"]`)
- **Finding:** The branch protection ruleset requires only two contexts: `fmt + clippy + test` and `spec-sync + Tier-A conformance`. The third ci.yml job — `coverage floor` (job `name: coverage floor`) — is not listed. A PR that drops line coverage below 98% or file-level coverage below 90% will fail the `coverage floor` job, but that failure will not block the PR from merging because it is not a required status check. The job runs, fails, and is ignored by the protection gate.
- **Operational consequence:** Coverage regressions can merge unblocked. The first signal that coverage dropped is when `cargo llvm-cov` fails in a future CI run — by which point the regressing commit is already on `main`.
- **Recommendation:** Add `"coverage floor"` to the `"contexts"` array in `setup-branch-protection.sh` and re-run the script against the repo. Alternatively, if the coverage floor is treated as informational (warn-only), annotate this explicitly in `AGENTS.md` so contributors don't expect it to block merges.

---

### F4: No `rust-version` (MSRV) declared in `Cargo.toml`

- **Severity:** MEDIUM
- **Confidence:** CONFIRMED
- **Location:** `Cargo.toml` — `[package]` section (no `rust-version` key present); `.github/workflows/ci.yml` — both `test` and `coverage` jobs pin to `toolchain: stable` only
- **Finding:** `Cargo.toml` does not declare a `rust-version` (minimum supported Rust version, MSRV). The CI matrix pins to `toolchain: stable` in all jobs. There is no `rust-toolchain.toml` in the repo root. This means: (1) the minimum rustc version this crate requires is implicit (currently edition = 2021, which implies rustc ≥ 1.56 for the edition itself, but individual APIs may require a higher floor); (2) the published crate on crates.io shows no MSRV badge; (3) a user on an older stable toolchain gets an opaque compiler error rather than a clear "please upgrade to rustc X.Y"; (4) CI will silently start requiring a newer rustc if any dependency bumps its own MSRV, with no diff to `rust-version` to catch it.
- **Operational consequence:** Downstream crate users on older toolchains get confusing errors. Crates.io tooling and `cargo msrv` cannot automate MSRV checks without the field. Future accidental MSRV bumps via transitive dependency upgrades are invisible.
- **Recommendation:** Set `rust-version = "1.70"` (or the actual minimum determined by running `cargo msrv`) in the `[package]` section of `Cargo.toml`. Consider also adding a `rust-toolchain.toml` pinning to `channel = "stable"` to make the exact toolchain reproducible for contributors and CI. If a specific minimum is important to advertise (e.g. MSRV ≥ 1.65 for let-else), determine it explicitly and record it.

---

### F5: README lacks a Release workflow badge

- **Severity:** LOW
- **Confidence:** CONFIRMED
- **Location:** `README.md` lines 3–6 (badge block); `.github/workflows/release.yml`
- **Finding:** The README badge block has four badges: CI, crates.io, docs.rs, and License. There is no badge for the Release workflow (`release.yml`). The CI badge covers `ci.yml` runs on `push`/`pull_request` against `main` — it does not reflect the state of the `release.yml` workflow that runs on tag pushes and is responsible for publishing to crates.io. If the release workflow breaks (e.g. CARGO_REGISTRY_TOKEN expires, a step regresses), the README gives no at-a-glance signal.
- **Operational consequence:** A broken release pipeline is invisible to a casual visitor looking at the README. The CI badge stays green while the publish path is broken.
- **Recommendation:** Add a Release badge:
  ```markdown
  [![Release](https://github.com/dhh1128/entviz-rs/actions/workflows/release.yml/badge.svg)](https://github.com/dhh1128/entviz-rs/actions/workflows/release.yml)
  ```
  Note: this badge will show the state of the *last tag-push run*, not the state of `main`; that is the correct signal for a release workflow.

---

## Additional Patterns Noted

- **No `this.i` file.** The entviz reference repo uses `this.i` as the intent layer for recorded decisions and deferred findings. entviz-rs has no equivalent. Decisions about the release process (e.g. "PyPI/crates.io Trusted Publishing when supported", "coverage not a required check intentionally") are not recorded anywhere durable. If this repo participates in the multi-implementation initiative tracked in the entviz MEMORY, it would benefit from a `this.i`.

- **Branch protection is not committed infrastructure.** `setup-branch-protection.sh` is a runonce script, not a GitHub-native committed ruleset (repo Settings → Rules → Rulesets, which can be committed as JSON). For a single-author repo this is a reasonable deferral (mirroring `OPS-F3` in the reference repo), but the protection is invisible to reviewers who cannot see repo settings and can be silently changed or bypassed. The script itself covers the core rules (strict status checks, required review, no force-push, no delete), which partially compensates.

- **`setup-branch-protection.sh` required contexts are stale relative to AGENTS.md.** The script's contexts list `"fmt + clippy + test"` and `"spec-sync + Tier-A conformance"` — the names match the ci.yml job `name:` values, which is correct. However `"coverage floor"` (see F3) is missing. Additionally, the `enforce_admins: false` setting intentionally allows the maintainer to bypass the protection for direct pushes, which, combined with F1, means the release gate is the only safety net for direct-push releases.

- **`.gitignore` is lean.** The current `.gitignore` covers `target/`, `*.log`, `.DS_Store`, and `.tick*`. It does not cover editor temporaries (`*.orig`, `*.swp`), JetBrains (`.idea/`), or `*.pdb` (Windows debug symbols that could appear if building on Windows). These are not currently present in the tracked file set, so this is not a live tracking defect — but the gitignore would benefit from the standard Rust project template entries.

- **Conformance harness in ci.yml uses bare `pip` for `lxml`.** The `conformance` job installs `lxml` into a venv via a bare `pip install --quiet lxml` without version pinning. This is not a lockfile concern for this Rust crate (the Python harness is a transient dev tool, not shipped), but it means CI silently resolves the latest `lxml`, which could introduce a breaking change on a future lxml major release. A `lxml==5.x` pin in the step comment, or a `requirements-harness.txt`, would protect against this. LOW severity — the harness only needs `lxml` for XML parsing and is unlikely to break on patch upgrades.

- **`model.rs` and `render_model.rs` are tracked in the repo but excluded from the published crate.** The `Cargo.toml` `exclude` list correctly omits `src/model.rs` and `src/bin/render_model.rs` from the published crate. This is correct and intentional (adversarial feature). No finding.

---

## Residual Unknowns

- **Whether branch protection rulesets are actually active on the remote repo.** `setup-branch-protection.sh` is committed but there is no way to verify from the tree whether it has been run against the live repo. The protection it configures may or may not be in effect.

- **CARGO_REGISTRY_TOKEN expiry.** The token is a static crates.io API token stored as a repo secret. Whether it is still valid (not expired or revoked) cannot be determined from the tree. A broken token would make the release workflow fail silently at the publish step after all gates pass. crates.io does not yet support OIDC Trusted Publishing (as of the knowledge cutoff), so a static token is the only option — but the maintainer should confirm the token is valid and consider adding a canary check (e.g. `cargo login --dry-run` or a scheduled ping).

- **Whether branch protection `enforce_admins: false` is the live setting.** The script sets it, but admin pushes to main are a known bypass path for the release gate gap (F1). If `enforce_admins` was later set to `true`, F1's practical severity drops.

---

## Decisions Needed

1. **Should the release gate run coverage floor and conformance?** The simplest fix for F1 is to add both inline in the gate step. The tradeoff is release time (conformance checks out the reference repo and runs Python). If the maintainer accepts the risk (only a human runs the release script, which also runs `cargo test --locked`), a lighter approach is a comment in `release.yml` acknowledging the gap and a procedure to run conformance manually before tagging.

2. **Should `contents: write` be scoped to the job level?** This is a straightforward improvement with no functional downside; the only question is whether to also split the workflow into a two-job structure (gate/publish) to enable tighter per-job permissions.

3. **Should the coverage floor become a required PR check?** If the 98%/90% floor is the project's actual policy (it runs as a CI job), it should block merges. If it is aspirational-but-advisory, document that explicitly.

4. **Should a `rust-version` MSRV be declared?** Running `cargo msrv` is a one-time operation that identifies the actual minimum. The effort is small; the benefit (clear crates.io MSRV metadata, future-proofing against accidental MSRV bumps) is real.

---

## Findings Manifest

```yaml
findings:
  - id: OPS-F1
    persona: devops-engineer
    title: Release gate omits coverage floor and conformance — direct-push tag can ship a noncompliant crate
    severity: HIGH
    confidence: CONFIRMED
    location: .github/workflows/release.yml:32-37 (Gate step)
    dedupe_key: release-yml-ungated
    recommended_disposition: recommend-fix
    rationale: Release gate runs only fmt+clippy+test; coverage floor and conformance are not checked; admin can tag a commit that failed those in ci.yml and publish.
    revisit_condition: null
    fix_effort: small

  - id: OPS-F2
    persona: devops-engineer
    title: contents:write granted at workflow level rather than job level
    severity: MEDIUM
    confidence: CONFIRMED
    location: .github/workflows/release.yml:14-15 (top-level permissions block)
    dedupe_key: release-yml-overpermissioned
    recommended_disposition: recommend-fix
    rationale: Workflow-level contents:write grants write access to all steps; only the create-release step needs it; violates least-privilege.
    revisit_condition: null
    fix_effort: small

  - id: OPS-F3
    persona: devops-engineer
    title: Coverage floor job is not a required branch-protection check
    severity: MEDIUM
    confidence: CONFIRMED
    location: scripts/setup-branch-protection.sh:21-24 (contexts array)
    dedupe_key: branch-protection-missing
    recommended_disposition: recommend-fix
    rationale: "coverage floor" CI job not in required contexts; a PR dropping coverage below 98%/90% can merge unblocked.
    revisit_condition: null
    fix_effort: small

  - id: OPS-F4
    persona: devops-engineer
    title: No rust-version (MSRV) declared in Cargo.toml
    severity: MEDIUM
    confidence: CONFIRMED
    location: Cargo.toml:[package] section
    dedupe_key: cargo-toml-missing-msrv
    recommended_disposition: recommend-fix
    rationale: No rust-version field means crates.io shows no MSRV and future transitive MSRV bumps are invisible; downstream users get opaque errors on older toolchains.
    revisit_condition: null
    fix_effort: small

  - id: OPS-F5
    persona: devops-engineer
    title: README lacks a Release workflow status badge
    severity: LOW
    confidence: CONFIRMED
    location: README.md:3-6 (badge block)
    dedupe_key: readme-missing-release-badge
    recommended_disposition: recommend-fix
    rationale: No badge for release.yml; a broken publish pipeline (expired token, step regression) is invisible to visitors.
    revisit_condition: null
    fix_effort: small
```
