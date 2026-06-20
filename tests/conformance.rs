//! Corpus-driven conformance test.
//!
//! When the sibling reference repo (`../entviz`) is checked out, this drives
//! every corpus vector through [`entviz::pipeline::render`]:
//!
//! * render vectors MUST produce an SVG whose semantic `data-*` attributes
//!   match the golden `model.json` (TST-F1 — a correct-but-wrong SVG that keeps
//!   emitting valid markup but with the wrong grid / cells / color-bar / ellipse
//!   now fails `cargo test`, not just the cross-repo Python runner);
//! * error vectors MUST be rejected;
//! * invariant pairs MUST render the same visualization — identical SVG once
//!   the legitimately-differing `data-input-bytes` is normalized out (TST-F3).
//!
//! It still does NOT do the full Tier-A extractor / Tier-B raster golden
//! comparison (that needs the Python extractor + rasterizer — run
//! `python -m compliance.runner --impl-cmd ...` for the complete proof). The
//! test is skipped (passes trivially) when the corpus is not present.

use std::path::PathBuf;

use entviz::pipeline::render;
use serde_json::Value;

fn corpus_dir() -> Option<PathBuf> {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = here
        .parent()?
        .join("entviz")
        .join("compliance")
        .join("corpus");
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

// ---- minimal data-* attribute extraction (no XML/regex dependency) ----

/// Value of the FIRST `name="..."` attribute occurrence in `svg`, if any.
fn attr_first<'a>(svg: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let start = svg.find(&needle)? + needle.len();
    let end = svg[start..].find('"')? + start;
    Some(&svg[start..end])
}

/// For every element carrying `data-cell-index="N"`, capture the value of
/// `attr` on that same element (attributes are emitted contiguously, so we read
/// forward only to the element's closing `>`). Returns a map index -> value.
fn cell_attr_map(svg: &str, attr: &str) -> std::collections::BTreeMap<usize, String> {
    let mut out = std::collections::BTreeMap::new();
    let idx_needle = "data-cell-index=\"";
    let attr_needle = format!("{attr}=\"");
    let mut pos = 0;
    while let Some(rel) = svg[pos..].find(idx_needle) {
        let istart = pos + rel + idx_needle.len();
        let iend = istart + svg[istart..].find('"').unwrap();
        let index: usize = svg[istart..iend].parse().unwrap();
        // Scope the attribute search to this element (up to the next '>').
        let elem_end = iend + svg[iend..].find('>').unwrap();
        let elem = &svg[iend..elem_end];
        if let Some(ar) = elem.find(&attr_needle) {
            let vstart = ar + attr_needle.len();
            let vend = vstart + elem[vstart..].find('"').unwrap();
            out.insert(index, elem[vstart..vend].to_string());
        }
        pos = elem_end;
    }
    out
}

/// Map of color-bar rank -> band letter as emitted in the SVG.
fn color_bar_map(svg: &str) -> std::collections::BTreeMap<usize, String> {
    let mut out = std::collections::BTreeMap::new();
    let rank_needle = "data-color-bar-rank=\"";
    let band_needle = "data-color-bar-band=\"";
    let mut pos = 0;
    while let Some(rel) = svg[pos..].find(rank_needle) {
        let rstart = pos + rel + rank_needle.len();
        let rend = rstart + svg[rstart..].find('"').unwrap();
        let rank: usize = svg[rstart..rend].parse().unwrap();
        let elem_end = rend + svg[rend..].find('>').unwrap();
        let elem = &svg[rend..elem_end];
        if let Some(br) = elem.find(band_needle) {
            let vstart = br + band_needle.len();
            let vend = vstart + elem[vstart..].find('"').unwrap();
            out.insert(rank, elem[vstart..vend].to_string());
        }
        pos = elem_end;
    }
    out
}

/// Compare the SVG's semantic fields against the golden model.json. Pushes one
/// human-readable line per mismatch into `failures`.
fn assert_model_match(vid: &str, svg: &str, model: &Value, failures: &mut Vec<String>) {
    let mut bad = |msg: String| failures.push(format!("{vid}: {msg}"));

    // --- grid dims ---
    for (attr, key) in [
        ("data-cols", "cols"),
        ("data-rows", "rows"),
        ("data-input-bytes", "input_bytes"),
    ] {
        let got = attr_first(svg, attr).unwrap_or("<missing>");
        let want = model[key].as_u64().map(|v| v.to_string()).unwrap();
        if got != want {
            bad(format!("{attr}={got:?} but model {key}={want:?}"));
        }
    }

    // --- per-cell col / row / quartile / blank / blank_map ---
    let cells = model["cells"].as_object().unwrap();
    let svg_col = cell_attr_map(svg, "data-cell-col");
    let svg_row = cell_attr_map(svg, "data-cell-row");
    let svg_quart = cell_attr_map(svg, "data-cell-quartile");
    let svg_blank = cell_attr_map(svg, "data-cell-blank");
    let svg_blank_map = cell_attr_map(svg, "data-cell-blank-map");
    for (k, cell) in cells {
        let idx: usize = k.parse().unwrap();
        let want_col = cell["col"].as_u64().unwrap().to_string();
        let want_row = cell["row"].as_u64().unwrap().to_string();
        if svg_col.get(&idx).map(String::as_str) != Some(&want_col) {
            bad(format!(
                "cell {idx} col {:?} != model {want_col}",
                svg_col.get(&idx)
            ));
        }
        if svg_row.get(&idx).map(String::as_str) != Some(&want_row) {
            bad(format!(
                "cell {idx} row {:?} != model {want_row}",
                svg_row.get(&idx)
            ));
        }
        // quartile: model holds 1..4 or null; the SVG emits the same value, and
        // only when present (null => the attribute is absent).
        match cell["quartile"].as_u64() {
            Some(q) => {
                let want_q = q.to_string();
                if svg_quart.get(&idx).map(String::as_str) != Some(&want_q) {
                    bad(format!(
                        "cell {idx} quartile {:?} != model {want_q}",
                        svg_quart.get(&idx)
                    ));
                }
            }
            None => {
                if svg_quart.contains_key(&idx) {
                    bad(format!(
                        "cell {idx} has SVG quartile {:?} but model is null",
                        svg_quart.get(&idx)
                    ));
                }
            }
        }
        // blank / blank_map: the SVG only stamps the attr when true.
        let want_blank = cell["blank"].as_bool().unwrap_or(false);
        if svg_blank.contains_key(&idx) != want_blank {
            bad(format!("cell {idx} blank mismatch (model={want_blank})"));
        }
        let want_blank_map = cell["blank_map"].as_bool().unwrap_or(false);
        if svg_blank_map.contains_key(&idx) != want_blank_map {
            bad(format!(
                "cell {idx} blank_map mismatch (model={want_blank_map})"
            ));
        }
    }

    // --- color bar (rank -> band letter) ---
    let svg_bar = color_bar_map(svg);
    for entry in model["color_bar"].as_array().unwrap() {
        let rank = entry["rank"].as_u64().unwrap() as usize;
        let band = entry["band"].as_str().unwrap();
        if svg_bar.get(&rank).map(String::as_str) != Some(band) {
            bad(format!(
                "color-bar rank {rank} band {:?} != model {band}",
                svg_bar.get(&rank)
            ));
        }
    }
    // color-bar markers + slots
    let markers = &model["color_bar_markers"];
    for (attr, key) in [
        ("data-bar-marker-left", "left"),
        ("data-bar-marker-right", "right"),
        ("data-bar-slots", "slots"),
    ] {
        let got = attr_first(svg, attr).unwrap_or("<missing>");
        let want = markers[key].as_u64().unwrap().to_string();
        if got != want {
            bad(format!("{attr}={got:?} but model {key}={want:?}"));
        }
    }

    // --- ellipse (when the model emits one) ---
    if model["ellipse"].is_object() {
        let e = &model["ellipse"];
        let want_anchor_x = e["anchor"][0].as_f64().unwrap();
        let want_anchor_y = e["anchor"][1].as_f64().unwrap();
        let want_rot = e["rotation"].as_f64().unwrap();
        let want_rx = e["rx"].as_f64().unwrap();
        let want_ry = e["ry"].as_f64().unwrap();
        let got_x: f64 = attr_first(svg, "data-ellipse-anchor-x")
            .unwrap()
            .parse()
            .unwrap();
        let got_y: f64 = attr_first(svg, "data-ellipse-anchor-y")
            .unwrap()
            .parse()
            .unwrap();
        let got_rot: f64 = attr_first(svg, "data-ellipse-rotation-deg")
            .unwrap()
            .parse()
            .unwrap();
        let got_rx: f64 = attr_first(svg, "data-ellipse-rx").unwrap().parse().unwrap();
        let got_ry: f64 = attr_first(svg, "data-ellipse-ry").unwrap().parse().unwrap();
        let close = |a: f64, b: f64| (a - b).abs() < 1e-3;
        if !close(got_x, want_anchor_x) || !close(got_y, want_anchor_y) {
            bad(format!(
                "ellipse anchor ({got_x},{got_y}) != model ({want_anchor_x},{want_anchor_y})"
            ));
        }
        if !close(got_rot, want_rot) {
            bad(format!("ellipse rotation {got_rot} != model {want_rot}"));
        }
        if !close(got_rx, want_rx) || !close(got_ry, want_ry) {
            bad(format!(
                "ellipse radii ({got_rx},{got_ry}) != model ({want_rx},{want_ry})"
            ));
        }
    }
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
                    continue;
                }
                // TST-F1: compare semantic fields against the golden model.json.
                let model_path = dir.join(vid).join("model.json");
                if model_path.is_file() {
                    let model: Value =
                        serde_json::from_str(&std::fs::read_to_string(&model_path).unwrap())
                            .unwrap();
                    assert_model_match(vid, &svg, &model, &mut failures);
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

    assert!(
        failures.is_empty(),
        "conformance contract failures:\n{}",
        failures.join("\n")
    );
}

/// Erase the one attribute that legitimately differs between members of an
/// invariant pair: `data-input-bytes` reflects the raw input length (e.g. a
/// dashed UUID is 36 chars, undashed 32), while everything else — the entire
/// visualization — must be identical. Mirrors the Python runner, which diffs
/// the render models with `input_bytes` excluded.
fn strip_input_bytes(svg: &str) -> String {
    let needle = "data-input-bytes=\"";
    if let Some(start) = svg.find(needle) {
        let vstart = start + needle.len();
        let vend = vstart + svg[vstart..].find('"').unwrap() + 1;
        return format!("{}{}", &svg[..start], &svg[vend..]);
    }
    svg.to_string()
}

#[test]
fn corpus_invariant_pairs_render_identically() {
    // TST-F3: the manifest's equivalence pairs (e.g. uuid-dashed == uuid-undashed,
    // ulid-canonical == ulid-lowercase, avalanche-a == uuid-dashed) MUST render
    // the same visualization. We compare the SVG with `data-input-bytes` removed
    // (the sole legitimately-differing field); everything else must be identical.
    // A normalization regression that produces different cores for the two
    // members of a pair fails here.
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
    for pair in manifest["invariant_pairs"].as_array().unwrap() {
        let a = pair[0].as_str().unwrap();
        let b = pair[1].as_str().unwrap();
        match (render_vector(&dir, a), render_vector(&dir, b)) {
            (Ok(sa), Ok(sb)) => {
                if strip_input_bytes(&sa) != strip_input_bytes(&sb) {
                    failures.push(format!("{a} != {b}: invariant pair rendered differently"));
                }
            }
            (ra, rb) => {
                failures.push(format!("{a}/{b}: render failed ({ra:?} / {rb:?})"));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "invariant-pair failures:\n{}",
        failures.join("\n")
    );
}
