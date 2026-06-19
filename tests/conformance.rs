//! Corpus-driven conformance smoke test.
//!
//! When the sibling reference repo (`../entviz`) is checked out, this drives
//! every corpus vector through [`entviz::pipeline::render`]: render vectors MUST
//! produce an SVG; error vectors MUST be rejected. It does NOT do the Tier-A /
//! Tier-B golden comparison (that needs the Python extractor + rasterizer — run
//! `python -m compliance.runner --impl-cmd ...` for the full proof); it guards
//! the render/reject contract from pure Rust so a regression fails `cargo test`.
//!
//! The test is skipped (passes trivially) when the corpus is not present.

use std::path::PathBuf;

use entviz::pipeline::render;
use serde_json::Value;

fn corpus_dir() -> Option<PathBuf> {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = here.parent()?.join("entviz").join("compliance").join("corpus");
    if dir.join("manifest.json").is_file() {
        Some(dir)
    } else {
        None
    }
}

fn render_vector(dir: &std::path::Path, vid: &str) -> Result<String, String> {
    let input: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join(vid).join("input.json")).unwrap())
            .unwrap();
    let p = &input["params"];
    render(
        input["entropy"].as_str().unwrap(),
        p["target_ar"].as_f64().unwrap_or(1.0),
        p["font_size_pt"].as_f64().unwrap_or(12.0),
        p["note"].as_str(),
    )
    .map_err(|e| format!("{e:?}"))
}

#[test]
fn corpus_render_and_error_contract() {
    let dir = match corpus_dir() {
        Some(d) => d,
        None => {
            eprintln!("skip: ../entviz corpus not present");
            return;
        }
    };
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();

    let mut failures = Vec::new();

    for vid in manifest["render_vectors"].as_array().unwrap() {
        let vid = vid.as_str().unwrap();
        match render_vector(&dir, vid) {
            Ok(svg) => {
                if !svg.starts_with("<svg ") || !svg.ends_with("</svg>") {
                    failures.push(format!("{vid}: malformed SVG"));
                }
            }
            Err(e) => failures.push(format!("{vid}: expected render, got rejection {e}")),
        }
    }

    for vid in manifest["error_vectors"].as_array().unwrap() {
        let vid = vid.as_str().unwrap();
        if render_vector(&dir, vid).is_ok() {
            failures.push(format!("{vid}: expected rejection, got an SVG"));
        }
    }

    assert!(failures.is_empty(), "conformance contract failures:\n{}", failures.join("\n"));
}
