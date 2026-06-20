# entviz-rs

[![CI](https://github.com/dhh1128/entviz-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/dhh1128/entviz-rs/actions/workflows/ci.yml)
[![Release](https://github.com/dhh1128/entviz-rs/actions/workflows/release.yml/badge.svg)](https://github.com/dhh1128/entviz-rs/actions/workflows/release.yml)
[![crates.io](https://img.shields.io/crates/v/entviz.svg)](https://crates.io/crates/entviz)
[![docs.rs](https://docs.rs/entviz/badge.svg)](https://docs.rs/entviz)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Rust implementation of [entviz](https://github.com/dhh1128/entviz) (spec **v10**)
— visualize high-entropy values as comparable SVG diagrams.

## Status: certified against the v10 conformance corpus ✅

A full, self-contained implementation that passes the shared conformance corpus
at **Tier A** (render model) **+ Tier B** (canonical raster) for every render
vector, rejects every error vector, and satisfies every invariant pair
(**52/52**). What's here:

- **`src/lib.rs`** — the deterministic shared core: alphabets, tokenization +
  24-bit quant extension, the SHA-512 fingerprint (via `sha2`), ftok
  median/quartile selection, the Oklab color rules + weighted-RGB edge
  selection, and grid selection.
- **`src/entropy.rs`** — the format-specific parsers (hex, UUID, Ethereum w/
  EIP-55, ULID, base58 / bech32 / base32 chains, CESR, LEI, snowflake, SWHID /
  gitoid semantic-prefix fold, IPFS CID, SSH, …) + the disproof-based alphabet
  detection and large-input (head / fingerprint-middle / tail) tokenization.
- **`src/keccak.rs`** — vendored Keccak-256 for EIP-55 checksum validation.
- **`src/pipeline.rs`** — the SVG renderer: geometry, 24-box surround,
  fingerprint-edge cells, ellipse overlay, color bar + markers, blank-cell map,
  quartile marks, labels, borders — emitting the normative `data-*` profile.
- **`src/main.rs`** — the `entviz-conformance` CLI (the stdin→stdout contract in
  the entviz repo's `compliance/README.md`).

## Build + certify

```sh
cargo test                                  # unit + corpus render/reject contract
cargo build --release --bin entviz-conformance

# from a checkout of the entviz reference repo (sibling ../entviz):
PYTHONPATH=src:. python -m compliance.runner \
  --impl-cmd '/path/to/entviz-rs/target/release/entviz-conformance'
# -> 52/52 vectors passed
```

`cargo test` also runs a corpus-driven smoke test (`tests/conformance.rs`) that
drives every vector through the renderer when `../entviz` is checked out; the
full Tier-A/Tier-B golden comparison is the Python runner above.

Dependencies are intentionally minimal (`sha2`, `base64`, `hex`, `serde_json`).

## Spec compliance & versioning

The crate version encodes the entviz **spec** level it is compliant with:

> **`0.<spec-major>.x`** — e.g. `0.10.x` ⇒ compliant with entviz spec **v10**
> (the same convention the Python reference uses, where spec v10 ↔ `0.10.0`).

A spec bump (v10 → v11) is a **minor** release here (`0.10.x` → `0.11.0`); a
**patch** is a crate-only change within a spec version. The canonical spec
level is the `SPEC_VERSION` constant in `src/lib.rs`.

CI **surfaces spec drift**: the `conformance` job checks out the public
[entviz reference](https://github.com/dhh1128/entviz), compares its
`SPEC_VERSION` to this crate's, and runs the Tier-A conformance suite. When the
reference spec is *ahead* of this crate it warns loudly (without blocking
unrelated PRs); when the versions match (or this crate is ahead) conformance is
a hard gate. `scripts/release.py` performs the same drift check before tagging.

## Releasing

Releases are **human-run** (agents must not push tags). From a clean, in-sync
`main`:

```sh
python scripts/release.py                  # patch bump
python scripts/release.py --minor -m "..." # minor bump (e.g. a spec bump)
```

It runs the gate (fmt + clippy + test), bumps `Cargo.toml` + `Cargo.lock`,
commits, pushes, and tags `vX.Y.Z`. The tag triggers
[`.github/workflows/release.yml`](.github/workflows/release.yml), which re-runs
the gate, verifies the tag matches `Cargo.toml`, and `cargo publish`es to
crates.io (needs the `CARGO_REGISTRY_TOKEN` repo secret).

Branch protection (require PR + CI + 1 review for contributors; maintainers
bypass via direct push) is configured by
[`scripts/setup-branch-protection.sh`](scripts/setup-branch-protection.sh).

## License

[Apache License 2.0](LICENSE). See also [`NOTICE`](NOTICE).
