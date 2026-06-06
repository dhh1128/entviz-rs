//! Conformance CLI (stub).
//!
//! The conformance contract (see the entviz repo's compliance/README.md) is:
//! read one vector's `input.json` on stdin, write the entviz SVG to stdout
//! (exit 0) or exit non-zero to reject. The shared core is implemented in
//! `lib.rs`; the SVG renderer is the remaining port (it mirrors the certified
//! `entviz-js` renderer), so this binary currently rejects everything with a
//! clear message rather than emit a wrong SVG.
//!
//! Once the renderer lands, this reads the JSON request, calls
//! `entviz::render(...)`, and prints the SVG.

use std::io::Read;

fn main() {
    let mut input = String::new();
    let _ = std::io::stdin().read_to_string(&mut input);
    eprintln!(
        "entviz-rs: SVG renderer not yet ported (shared core is in lib.rs; \
         run `cargo test`). Certification pending a Rust toolchain on this host."
    );
    std::process::exit(2);
}
