# entviz-rs

Rust implementation of [entviz](https://github.com/dhh1128/entviz) (spec **v6**)
— visualize high-entropy values as comparable SVG diagrams.

## ⚠️ Status: unverified scaffold (blocked on toolchain)

This crate was scaffolded on a host **without a Rust toolchain** (`rustc` /
`cargo` are not installed), so it has **not been compiled, tested, or
certified**. What's here:

- **`src/lib.rs`** — the deterministic shared core, ported to mirror the
  *certified* `entviz-js` TypeScript core (which passes the shared conformance
  corpus at Tier A + Tier B): alphabets, tokenization + 24-bit quant extension,
  the SHA-512 fingerprint (via `sha2`), ftok median/quartile selection, the
  Oklab color rules + weighted-RGB edge selection, and grid selection. Includes
  `#[cfg(test)]` unit tests mirroring the certified TS tests.
- **`src/main.rs`** — the conformance-CLI stub (stdin→stdout contract); rejects
  everything until the renderer lands, rather than emit a wrong SVG.

## To finish + certify (once a toolchain is available)

```sh
rustup default stable          # install a toolchain
cargo test                     # the ported core's unit tests should pass

# then port the SVG renderer (mirror entviz-js/packages/core/src/entviz.ts —
# geometry, surround, ellipse, color bar, blank-cell map, quartile marks,
# labels) + the parsers, wire src/main.rs to call entviz::render(), and certify:
python -m compliance.runner \
  --impl-cmd 'cargo run -q --bin entviz-conformance' \
  --only '<supported subset>'
```

The renderer is a mechanical port of the certified TS renderer; the hard,
load-bearing core (the part most likely to differ subtly between languages) is
already ported here.

Dependencies are intentionally allowed (`sha2`, `base64`, `hex`).

## License

MIT.
