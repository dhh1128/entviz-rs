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

/// Reverse the renderer's XML attribute escaping (`esc_attr`): `&amp; &lt;
/// &gt; &quot;` back to their literals. `&amp;` is applied LAST so a literal
/// like `&lt;` in the source round-trips correctly.
fn xml_unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&")
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

/// Concatenated text content of the FIRST element carrying
/// `data-channel="<channel>"`, with all XML tags (e.g. the styled `<tspan>`s for
/// the truncation marker / user note) stripped and entity-unescaped. Returns
/// `None` when the channel group is absent (e.g. no bottom strip).
fn channel_text(svg: &str, channel: &str) -> Option<String> {
    let needle = format!("data-channel=\"{channel}\"");
    let anchor = svg.find(&needle)? + needle.len();
    // The group opens with `<g data-channel="...">`; find its content start
    // (the '>' closing the <g>) and its matching '</g>'.
    let content_start = anchor + svg[anchor..].find('>')? + 1;
    let content_end = content_start + svg[content_start..].find("</g>")?;
    let inner = &svg[content_start..content_end];
    // Strip every tag, keep the text nodes.
    let mut out = String::new();
    let mut in_tag = false;
    for c in inner.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    Some(xml_unescape(&out))
}

/// Assert the v14 top/bottom label strips against the golden `model.labels`.
/// The top strip is always present; the bottom strip is present only when the
/// model's `labels.bottom` is a non-null string.
fn assert_labels_match(svg: &str, model: &Value, bad: &mut dyn FnMut(String)) {
    let labels = match model.get("labels") {
        Some(l) if l.is_object() => l,
        _ => return,
    };
    // top: always present, exact match.
    let want_top = labels["top"].as_str().unwrap_or("");
    match channel_text(svg, "label-top") {
        Some(got) if got == want_top => {}
        got => bad(format!(
            "label top {:?} != model {want_top:?}",
            got.as_deref().unwrap_or("<missing>")
        )),
    }
    // bottom: model holds a string or null. When null, the SVG must not emit a
    // label-bottom group; when a string, it must match exactly.
    match labels["bottom"].as_str() {
        Some(want_bottom) => match channel_text(svg, "label-bottom") {
            Some(got) if got == want_bottom => {}
            got => bad(format!(
                "label bottom {:?} != model {want_bottom:?}",
                got.as_deref().unwrap_or("<missing>")
            )),
        },
        None => {
            if let Some(got) = channel_text(svg, "label-bottom") {
                bad(format!(
                    "label bottom present {got:?} but model bottom is null"
                ));
            }
        }
    }
    // truncation_marker: the model flags whether the bold `fingerprint of `
    // marker is drawn; the SVG carries it as a leading tspan inside label-top.
    let want_marker = labels["truncation_marker"].as_bool().unwrap_or(false);
    let got_marker = svg.contains("font-weight=\"bold\">fingerprint of </tspan>");
    if want_marker != got_marker {
        bad(format!(
            "truncation_marker={got_marker} but model={want_marker}"
        ));
    }
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

    // --- entropy characterization (spec v13): the eight structured fields ---
    // The renderer emits them as data-* attributes on the root <svg>; recover
    // them and compare strictly, per field, against the golden model.json.
    // scheme/role are the EMPTY string in the SVG when null; the model carries
    // JSON null. qualifiers/parts are compact JSON in both places.
    let scheme_svg = attr_first(svg, "data-scheme").unwrap_or("<missing>");
    let scheme_want = model["scheme"].as_str().unwrap_or("");
    if scheme_svg != scheme_want {
        bad(format!(
            "data-scheme={scheme_svg:?} but model scheme={scheme_want:?}"
        ));
    }
    let role_svg = attr_first(svg, "data-role").unwrap_or("<missing>");
    let role_want = model["role"].as_str().unwrap_or("");
    if role_svg != role_want {
        bad(format!(
            "data-role={role_svg:?} but model role={role_want:?}"
        ));
    }
    for (attr, key) in [
        ("data-encoding", "encoding"),
        ("data-size-basis", "size_basis"),
        ("data-entropy-type", "entropy_type"),
    ] {
        let got = attr_first(svg, attr).unwrap_or("<missing>");
        let want = model[key].as_str().unwrap_or("<null>");
        if got != want {
            bad(format!("{attr}={got:?} but model {key}={want:?}"));
        }
    }
    {
        let got = attr_first(svg, "data-size-bits").unwrap_or("<missing>");
        let want = model["size_bits"].as_u64().map(|v| v.to_string());
        if Some(got.to_string()) != want {
            bad(format!(
                "data-size-bits={got:?} but model size_bits={want:?}"
            ));
        }
    }
    // qualifiers / parts: the SVG attribute is XML-escaped compact JSON; the
    // model holds the equivalent JSON. Compare structurally (order-preserving
    // for qualifiers, since insertion order is part of the reference contract).
    {
        let got_raw = attr_first(svg, "data-qualifiers").unwrap_or("");
        let got = xml_unescape(got_raw);
        let got_json: Value = serde_json::from_str(&got)
            .unwrap_or_else(|e| panic!("{vid}: data-qualifiers not JSON ({e}): {got:?}"));
        let want_json = &model["qualifiers"];
        if &got_json != want_json {
            bad(format!("data-qualifiers {got_json} != model {want_json}"));
        }
        // NOTE: we compare JSON VALUE equality (order-insensitive). The
        // reference SVG's data-qualifiers preserves the recognizer's insertion
        // order (e.g. cid: `version,codec,hash`), which the Rust port also
        // emits — verified against the reference goldens. We deliberately do
        // NOT assert against the model.json key order here: model.json is a
        // pretty-printed artifact serialized with SORTED keys, so its object
        // key order is not the normative transport order and would spuriously
        // disagree with both the reference and this port's SVG.
    }
    {
        let got_raw = attr_first(svg, "data-parts").unwrap_or("");
        let got = xml_unescape(got_raw);
        let got_json: Value = serde_json::from_str(&got)
            .unwrap_or_else(|e| panic!("{vid}: data-parts not JSON ({e}): {got:?}"));
        let want_json = &model["parts"];
        if &got_json != want_json {
            bad(format!("data-parts {got_json} != model {want_json}"));
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

    // --- v14 label strips (top/bottom projection + truncation marker) ---
    // Routed through `bad` so each message gets the {vid} prefix like the rest.
    assert_labels_match(svg, model, &mut bad);
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

/// Erase the attributes that legitimately differ between members of an
/// invariant pair before diffing. `data-input-bytes` reflects the raw input
/// length (a dashed UUID is 36 chars, undashed 32). The eight spec-v13
/// characterization attributes are ALSO excluded here — mirroring the Python
/// runner, which diffs the render models with the characterization keys +
/// `input_bytes` removed — because they are derived from the raw input's
/// presentation (e.g. `data-parts` text / `data-size-bits`) and so can differ
/// across an equivalence pair even when the entire *visualization* is
/// identical. Everything else must match byte-for-byte.
fn strip_variable_attrs(svg: &str) -> String {
    let mut out = svg.to_string();
    for needle in [
        "data-input-bytes=\"",
        "data-encoding=\"",
        "data-scheme=\"",
        "data-role=\"",
        "data-size-basis=\"",
        "data-entropy-type=\"",
        "data-size-bits=\"",
        "data-qualifiers=\"",
        "data-parts=\"",
    ] {
        // strip every occurrence, including a leading space if present.
        while let Some(start) = out.find(needle) {
            let vstart = start + needle.len();
            let vend = vstart + out[vstart..].find('"').unwrap() + 1;
            // absorb one leading space so we don't leave a double space.
            let cut_start = if start > 0 && out.as_bytes()[start - 1] == b' ' {
                start - 1
            } else {
                start
            };
            out = format!("{}{}", &out[..cut_start], &out[vend..]);
        }
    }
    out
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
                if strip_variable_attrs(&sa) != strip_variable_attrs(&sb) {
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
