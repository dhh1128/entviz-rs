# entviz-rs

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

## License

[Apache License 2.0](LICENSE). See also [`NOTICE`](NOTICE).
