//! Render-model computation (spec v9) — the abstract Tier-A structure an
//! implementation must compute prior to SVG serialization. This mirrors the
//! Python reference's `model.json` (golden conformance corpus) field-for-field
//! for **short inputs** (normalized core ≤ 64 bytes / ≤ 512 bits).
//!
//! This is the half of entviz the adversarial grinder cares about: every
//! fingerprint-driven channel a human can check is a discrete field here, and
//! each is `f(SHA-512(core))`. Large-input (>512-bit) head/middle/tail handling
//! is **not yet ported** — `compute_render_model` returns `Err` for it.
//!
//! Ground truth: `/home/daniel/code/entviz/compliance/corpus/<name>/model.json`.

use sha2::{Digest, Sha512};

use crate::{
    choose_grid, closest_palette_color, compute_fingerprint, median_token, nucleus_colors,
    quartile_tokens, select_visual_style, tokenize, tokenize_fingerprint, Alphabet, Grid, Token,
};

pub const SPEC_VERSION_V9: &str = "v9";

/// Domain tag for the second, domain-separated digest. The trailing NUL is
/// included. `v6` is the *construction* version (fixed), not the spec version.
pub const MIDDLE_DOMAIN_TAG: &[u8] = b"entviz/fingerprint-middle/v6\x00";

/// `second = SHA-512(DOMAIN_TAG ‖ core)`. Computed for every input (v9): drives
/// the two color-bar markers on all inputs (and the middle cells on large ones).
pub fn second_digest(core: &str) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(MIDDLE_DOMAIN_TAG);
    h.update(core.as_bytes());
    let out = h.finalize();
    let mut d = [0u8; 64];
    d.copy_from_slice(&out);
    d
}

fn band_letter(color: &str) -> Option<&'static str> {
    match color {
        "#ffffff" => Some("W"),
        "#e7be00" => Some("G"),
        "#ff3f2f" => Some("R"),
        "#2f3fbf" => Some("B"),
        "#000000" => Some("K"),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CellModel {
    pub index: usize,
    pub col: usize,
    pub row: usize,
    pub blank: bool,
    pub blank_map: bool,
    pub fingerprint: bool,
    // Filled-cell fields (None on blank cells):
    pub text: Option<String>,
    pub nucleus_bg: Option<String>,
    pub fg: Option<String>,
    pub edge_color: Option<String>,
    pub surround_bits: Option<u32>,
    pub text_size_px: Option<f64>,
    pub quartile: Option<u8>, // 1..=4, the corner-encoded quartile mark
    // Map fields (only on the single blank_map cell):
    pub map_min: Option<(usize, usize)>, // (row, col) of minftok cell (blue dot)
    pub map_max: Option<(usize, usize)>, // (row, col) of maxftok cell (red plus)
}

#[derive(Debug, Clone, PartialEq)]
pub struct BandModel {
    pub band: String,   // uppercase W|G|R|B|K
    pub letter: String, // lowercase
    pub rank: usize,    // position in decoupled first-appearance order (0 = top)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Markers {
    pub left: usize,
    pub right: usize,
    pub slots: usize, // K
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ellipse {
    pub anchor: (f64, f64),
    pub rx: f64,
    pub ry: f64,
    pub rotation: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RenderModel {
    pub spec_version: String,
    pub cols: usize,
    pub rows: usize,
    pub bg_color: String,
    pub input_bytes: usize,
    pub truncated: bool,
    pub cells: Vec<CellModel>, // indexed 0..cols*rows, in cell-index order
    pub color_bar: Vec<BandModel>,
    pub color_bar_markers: Markers,
    pub ellipse: Option<Ellipse>,
}

impl RenderModel {
    /// Serialize to a `serde_json::Value` matching the Python golden
    /// `compliance/corpus/<name>/model.json` schema, restricted to the fields
    /// this render-model layer computes (everything except the label channel —
    /// `labels` / `user_note`, which depend on the parser and are out of scope
    /// for the grinder's feature vector). The differential harness loads the
    /// golden, drops those two keys, and diffs field-for-field. Continuous
    /// ellipse params are rounded to 3 digits to match the golden's
    /// `ELLIPSE_NDIGITS` equivalence.
    pub fn to_golden_json(&self) -> serde_json::Value {
        use serde_json::{json, Map, Value};

        let round3 = |x: f64| (x * 1000.0).round() / 1000.0;

        let mut cells = Map::new();
        for c in &self.cells {
            let v = if c.blank {
                let mut m = json!({
                    "blank": true,
                    "blank_map": c.blank_map,
                    "col": c.col,
                    "row": c.row,
                    "fingerprint": c.fingerprint,
                    "quartile": Value::Null,
                });
                if c.blank_map {
                    let (mnr, mnc) = c.map_min.unwrap();
                    let (mxr, mxc) = c.map_max.unwrap();
                    m["map_min"] = json!([mnr, mnc]);
                    m["map_max"] = json!([mxr, mxc]);
                }
                m
            } else {
                json!({
                    "blank": false,
                    "blank_map": false,
                    "col": c.col,
                    "row": c.row,
                    "fingerprint": c.fingerprint,
                    "edge_color": c.edge_color,
                    "fg": c.fg,
                    "nucleus_bg": c.nucleus_bg,
                    "quartile": c.quartile,
                    "surround_bits": c.surround_bits,
                    "text": c.text,
                    "text_size_px": c.text_size_px.map(round3),
                })
            };
            cells.insert(c.index.to_string(), v);
        }

        let color_bar: Vec<Value> = self
            .color_bar
            .iter()
            .map(|b| json!({"band": b.band, "letter": b.letter, "rank": b.rank}))
            .collect();

        let ellipse = match &self.ellipse {
            Some(e) => json!({
                "anchor": [round3(e.anchor.0), round3(e.anchor.1)],
                "rotation": round3(e.rotation),
                "rx": round3(e.rx),
                "ry": round3(e.ry),
            }),
            None => Value::Null,
        };

        json!({
            "spec_version": self.spec_version,
            "cols": self.cols,
            "rows": self.rows,
            "bg_color": self.bg_color,
            "input_bytes": self.input_bytes,
            "truncated": self.truncated,
            "cells": Value::Object(cells),
            "color_bar": color_bar,
            "color_bar_markers": {
                "left": self.color_bar_markers.left,
                "right": self.color_bar_markers.right,
                "slots": self.color_bar_markers.slots,
            },
            "ellipse": ellipse,
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum ModelError {
    /// Normalized core exceeds 512 bits — the large-input path is not yet ported.
    LargeInputUnsupported,
    Empty,
}

/// Normalized-core byte length for the >512-bit truncation trigger. Faithful
/// for the power-of-two alphabets we grind in; approximate elsewhere (good
/// enough to detect the short/long boundary, which is all it gates).
fn core_byte_length(core: &str, alphabet: &Alphabet) -> usize {
    let n = core.chars().count();
    match alphabet.bits_per_char {
        4 => n / 2,                  // hex
        5 => n * 5 / 8,              // base32 / bech32 / crockford32
        6 => n * 6 / 8,              // base64 / base64url / base58 / base36 (approx)
        _ => n,
    }
}

/// Port of `layout.assign_cell_indices` (median + ASCII-last + ASCII-first
/// shifts, ≤ 3). Returns a vec mapping token_index -> cell_index.
fn assign_cell_indices(
    tokens: &[Token],
    grid: &Grid,
    median: &Option<Token>,
    sort_keys: &[Token],
) -> Vec<usize> {
    let token_count = tokens.len();
    let cell_count = grid.cols * grid.rows;
    let mut cell_idx: Vec<usize> = (0..token_count).collect(); // token_index -> cell_index

    if token_count >= cell_count || tokens.is_empty() {
        return cell_idx;
    }

    // Shift: every token whose token_index >= start gets +1 cell index.
    let shift_from = |cell_idx: &mut Vec<usize>, start: usize| {
        for (t_idx, ci) in cell_idx.iter_mut().enumerate() {
            if t_idx >= start {
                *ci += 1;
            }
        }
    };

    if let Some(m) = median {
        shift_from(&mut cell_idx, m.index);
    }

    // ASCII sort of the sort_keys by (text, index).
    let mut sorted: Vec<&Token> = sort_keys.iter().collect();
    sorted.sort_by(|a, b| a.text.cmp(&b.text).then(a.index.cmp(&b.index)));

    if token_count + 1 < cell_count {
        shift_from(&mut cell_idx, sorted[sorted.len() - 1].index);
    }
    if token_count + 2 < cell_count {
        shift_from(&mut cell_idx, sorted[0].index);
    }
    cell_idx
}

fn two_bit_counts(digest: &[u8; 64]) -> [usize; 4] {
    let mut counts = [0usize; 4];
    for &byte in digest.iter() {
        for shift in [0u32, 2, 4, 6] {
            counts[((byte >> shift) & 0x03) as usize] += 1;
        }
    }
    counts
}

/// v9 first-appearance order of the 4 patterns across the 256 slices.
/// Returns pattern values (0..3) ordered by (first-appearance index, value).
fn first_appearance_order(digest: &[u8; 64]) -> [usize; 4] {
    let mut first = [usize::MAX; 4];
    let mut idx = 0usize;
    for &byte in digest.iter() {
        for shift in [0u32, 2, 4, 6] {
            let pat = ((byte >> shift) & 0x03) as usize;
            if first[pat] == usize::MAX {
                first[pat] = idx;
            }
            idx += 1;
        }
    }
    let mut order = [0usize, 1, 2, 3];
    order.sort_by_key(|&p| (first[p], p));
    order
}

fn interior_corners(grid: &Grid, left: f64, top: f64, cw: f64, ch: f64) -> Vec<(f64, f64)> {
    let mut pts = Vec::new();
    for r in 1..grid.rows {
        for c in 1..grid.cols {
            pts.push((left + c as f64 * cw, top + r as f64 * ch));
        }
    }
    pts
}

fn external_corners(grid: &Grid, left: f64, top: f64, cw: f64, ch: f64) -> Vec<(f64, f64)> {
    let mut pts = Vec::new();
    for c in 0..=grid.cols {
        pts.push((left + c as f64 * cw, top));
    }
    for r in 1..grid.rows {
        pts.push((left, top + r as f64 * ch));
        pts.push((left + grid.cols as f64 * cw, top + r as f64 * ch));
    }
    for c in 0..=grid.cols {
        pts.push((left + c as f64 * cw, top + grid.rows as f64 * ch));
    }
    pts
}

/// Compute the v9 render model for a normalized core string and its declared
/// alphabet. `bottom_strip` = whether a suffix or user note adds a bottom label
/// band (affects bounding height → marker slot count `K`). For a bare hex/b64
/// input it is `false`.
pub fn compute_render_model(
    core: &str,
    alphabet: &Alphabet,
    target_ar: f64,
    font_pt: f64,
    bottom_strip: bool,
    raw_bytes: usize,
) -> Result<RenderModel, ModelError> {
    compute_render_model_fp(core, core, alphabet, target_ar, font_pt, bottom_strip, raw_bytes)
}

/// Like [`compute_render_model`] but with a distinct `fingerprint_core` — the
/// string the PRIMARY fingerprint is computed over. For most inputs it equals
/// `core`; for a SEMANTIC-prefix type (SWHID, gitoid) the Python pipeline folds
/// the prefix in (`fingerprint_core = prefix ‖ core`) so two values differing
/// only in their type code avalanche apart across every fingerprint-driven
/// channel. The cell text still tokenizes `core`, and the `second`/marker digest
/// stays over plain `core`. See pipeline.py:195 and this.i:s3mpr3fx.
pub fn compute_render_model_fp(
    core: &str,
    fingerprint_core: &str,
    alphabet: &Alphabet,
    target_ar: f64,
    font_pt: f64,
    bottom_strip: bool,
    raw_bytes: usize,
) -> Result<RenderModel, ModelError> {
    if core.is_empty() {
        return Err(ModelError::Empty);
    }
    let token_len = (24 / alphabet.bits_per_char) as usize;
    let token_count = (core.chars().count() + token_len - 1) / token_len; // ceil
    if token_count > 22 || core_byte_length(core, alphabet) > 64 {
        return Err(ModelError::LargeInputUnsupported);
    }

    let tokens = tokenize(core, alphabet);
    let token_count = tokens.len();

    let primary = compute_fingerprint(fingerprint_core);
    let ftoks_all = tokenize_fingerprint(&primary);
    let used_ftoks: Vec<Token> = ftoks_all.into_iter().take(token_count).collect();
    let second = second_digest(core);

    let grid = choose_grid(token_count, target_ar);
    let median = median_token(&used_ftoks);
    let quartiles = quartile_tokens(&used_ftoks);
    let style = select_visual_style(median.as_ref().expect("non-empty"));

    let cell_of_token = assign_cell_indices(&tokens, &grid, &median, &used_ftoks);

    // --- Geometry (font_pt → px, all derived) ---
    let font_px = font_pt * 96.0 / 72.0;
    let nucleus_w = font_px * 3.0;
    let nucleus_h = font_px * 1.25;
    let box_h = nucleus_h / 2.0;
    let box_w = nucleus_w / 8.0;
    let cell_w = nucleus_w + 2.0 * box_w;
    let cell_h = nucleus_h + 2.0 * box_h;
    let gm = box_h / 2.0;
    let bar_w = 2.0 * box_h;
    let grid_w = cell_w * grid.cols as f64;
    let grid_h = cell_h * grid.rows as f64;
    let bottom_region = if bottom_strip { nucleus_h + gm } else { gm };
    let bounding_h = 1.0 + gm + nucleus_h + grid_h + bottom_region + 1.0;
    let grid_left = 1.0 + bar_w + 1.0 + gm;
    let grid_top = 1.0 + gm + nucleus_h;

    // --- Per-cell text size (per alphabet for short inputs) ---
    // 4-bit alphabets (hex/decimal) render 6-char tokens at 0.75×, rounded to a
    // whole point. Python's `round()` is round-half-to-even, so `font_pt=6`
    // gives `round(4.5)=4`, NOT 5 — use `round_ties_even` to match the
    // reference (a plain `.round()` half-away-from-zero diverges on fs-6).
    let text_pt = if alphabet.bits_per_char == 4 {
        (font_pt * 0.75).round_ties_even()
    } else {
        font_pt
    };
    let text_size_px = text_pt * 96.0 / 72.0;

    // --- min/max ftok cells (for the blank-cell map) ---
    // min: smallest quant, tie-break highest cell index; max: largest quant, tie highest cell idx.
    let mut min_cell = (u32::MAX, 0usize, 0usize); // (quant, cell_idx, _)
    let mut max_cell = (0u32, 0usize, 0usize);
    for t in &tokens {
        let q = used_ftoks[t.index].quant;
        let ci = cell_of_token[t.index];
        // min by (quant asc, cell_idx desc)
        if q < min_cell.0 || (q == min_cell.0 && ci > min_cell.1) {
            min_cell = (q, ci, 0);
        }
        // max by (quant asc, cell_idx asc) -> pick largest quant, tie highest idx
        if q > max_cell.0 || (q == max_cell.0 && ci > max_cell.1) {
            max_cell = (q, ci, 0);
        }
    }
    let min_cell_idx = min_cell.1;
    let max_cell_idx = max_cell.1;

    // --- quartile mark per cell (q_idx 0..3 -> corner 1..4) ---
    let mut quartile_of_cell: std::collections::HashMap<usize, u8> = std::collections::HashMap::new();
    for (q_idx, qt) in quartiles.iter().enumerate() {
        if let Some(qt) = qt {
            let ci = cell_of_token[qt.index];
            quartile_of_cell.insert(ci, (q_idx + 1) as u8);
        }
    }

    // --- assemble cells ---
    let cell_count = grid.cols * grid.rows;
    let used_cells: std::collections::HashSet<usize> = cell_of_token.iter().copied().collect();
    let blank_indices: Vec<usize> = (0..cell_count).filter(|ci| !used_cells.contains(ci)).collect();
    let map_cell = blank_indices.iter().copied().min();

    // token_index for each cell index (reverse of cell_of_token)
    let mut token_of_cell: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for (t_idx, &ci) in cell_of_token.iter().enumerate() {
        token_of_cell.insert(ci, t_idx);
    }

    let edge_palette: Vec<&str> = style.edge_colors.iter().map(|s| s.as_str()).collect();

    let mut cells = Vec::with_capacity(cell_count);
    for ci in 0..cell_count {
        let col = ci % grid.cols;
        let row = ci / grid.cols;
        if let Some(&t_idx) = token_of_cell.get(&ci) {
            let token = &tokens[t_idx];
            let (bg, fg) = nucleus_colors(token.quant);
            let edge = closest_palette_color(&bg, &edge_palette).to_string();
            cells.push(CellModel {
                index: ci,
                col,
                row,
                blank: false,
                blank_map: false,
                fingerprint: false,
                text: Some(token.text.clone()),
                nucleus_bg: Some(bg),
                fg: Some(fg),
                edge_color: Some(edge),
                surround_bits: Some(used_ftoks[t_idx].quant),
                text_size_px: Some(text_size_px),
                quartile: quartile_of_cell.get(&ci).copied(),
                map_min: None,
                map_max: None,
            });
        } else {
            let is_map = Some(ci) == map_cell;
            cells.push(CellModel {
                index: ci,
                col,
                row,
                blank: true,
                blank_map: is_map,
                fingerprint: false,
                text: None,
                nucleus_bg: None,
                fg: None,
                edge_color: None,
                surround_bits: None,
                text_size_px: None,
                quartile: None,
                map_min: if is_map {
                    Some((min_cell_idx / grid.cols, min_cell_idx % grid.cols))
                } else {
                    None
                },
                map_max: if is_map {
                    Some((max_cell_idx / grid.cols, max_cell_idx % grid.cols))
                } else {
                    None
                },
            });
        }
    }

    // --- color bar (first-appearance order, count^4 heights only affect ranks order) ---
    let counts = two_bit_counts(&primary);
    let order = first_appearance_order(&primary);
    let order_pos: std::collections::HashMap<usize, usize> =
        order.iter().enumerate().map(|(i, &p)| (p, i)).collect();
    // edge_palette[i] is the color for pattern i.
    let mut used_bands: Vec<usize> = (0..4).filter(|&p| counts[p] > 0).collect();
    used_bands.sort_by_key(|&p| (order_pos[&p], p));
    let color_bar: Vec<BandModel> = used_bands
        .iter()
        .enumerate()
        .map(|(rank, &p)| {
            let color = edge_palette[p];
            BandModel {
                band: band_letter(color).unwrap_or("?").to_string(),
                letter: band_letter(color).unwrap_or("?").to_lowercase(),
                rank,
            }
        })
        .collect();

    // --- color-bar markers (v9) ---
    let bar_height = bounding_h - 2.0;
    let k = ((bar_height / 12.0).floor() as i64).clamp(4, 16) as usize;
    let markers = Markers {
        left: (second[12] as usize) % k,
        right: (second[13] as usize) % k,
        slots: k,
    };

    // --- ellipse ---
    let interior_count = (grid.cols - 1) * (grid.rows - 1);
    let pts = if interior_count >= 6 {
        interior_corners(&grid, grid_left, grid_top, cell_w, cell_h)
    } else {
        external_corners(&grid, grid_left, grid_top, cell_w, cell_h)
    };
    let ellipse = if pts.is_empty() {
        None
    } else {
        let anchor = pts[(primary[60] as usize) % pts.len()];
        let grid_right = grid_left + grid_w;
        let grid_bottom = grid_top + grid_h;
        let corners = [
            (grid_left, grid_top),
            (grid_right, grid_top),
            (grid_left, grid_bottom),
            (grid_right, grid_bottom),
        ];
        let d_far = corners
            .iter()
            .map(|c| ((c.0 - anchor.0).powi(2) + (c.1 - anchor.1).powi(2)).sqrt())
            .fold(0.0_f64, f64::max);
        let r_min = 0.22 * d_far;
        let r_max = 0.58 * d_far;
        if r_max <= r_min {
            None
        } else {
            let rx = r_min + ((primary[61] % 16) as f64 / 15.0) * (r_max - r_min);
            let ry = r_min + ((primary[62] % 16) as f64 / 15.0) * (r_max - r_min);
            let rotation = ((primary[63] % 16) as f64 / 15.0) * 180.0;
            Some(Ellipse { anchor, rx, ry, rotation })
        }
    };

    // input_bytes is the RAW input byte length (parser-supplied). It differs
    // from the core for stripped-prefix / re-encoded-fallback inputs (e.g.
    // "hello world" → core "aGVsbG8gd29ybGQ"), so it cannot be derived here.
    let input_bytes = raw_bytes;

    Ok(RenderModel {
        spec_version: SPEC_VERSION_V9.to_string(),
        cols: grid.cols,
        rows: grid.rows,
        bg_color: style.bg_color,
        input_bytes,
        truncated: false,
        cells,
        color_bar,
        color_bar_markers: markers,
        ellipse,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HEX;

    /// The exact input behind compliance/corpus/hex-256: "0123456789abcdef" ×4.
    fn hex256_core() -> String {
        "0123456789abcdef".repeat(4)
    }

    #[test]
    fn hex256_grid_bg_and_truncation() {
        let m = compute_render_model(&hex256_core(), &HEX, 1.0, 12.0, false, 64).unwrap();
        assert_eq!((m.cols, m.rows), (3, 4));
        assert_eq!(m.bg_color, "#2f3fbf"); // blue
        assert_eq!(m.input_bytes, 64);
        assert!(!m.truncated);
        assert_eq!(m.spec_version, "v9");
    }

    #[test]
    fn hex256_cell0_and_cell1() {
        let m = compute_render_model(&hex256_core(), &HEX, 1.0, 12.0, false, 64).unwrap();
        let c0 = &m.cells[0];
        assert_eq!(c0.text.as_deref(), Some("012345"));
        assert_eq!(c0.nucleus_bg.as_deref(), Some("#452301"));
        assert_eq!(c0.fg.as_deref(), Some("#ffffff"));
        assert_eq!(c0.edge_color.as_deref(), Some("#000000"));
        assert_eq!(c0.surround_bits, Some(11348353));
        assert_eq!(c0.quartile, Some(2));
        assert_eq!(c0.text_size_px, Some(12.0));

        let c1 = &m.cells[1];
        assert_eq!(c1.nucleus_bg.as_deref(), Some("#ab8967"));
        assert_eq!(c1.edge_color.as_deref(), Some("#ff3f2f"));
        assert_eq!(c1.quartile, Some(1));
    }

    #[test]
    fn hex256_blank_map() {
        let m = compute_render_model(&hex256_core(), &HEX, 1.0, 12.0, false, 64).unwrap();
        let c7 = &m.cells[7];
        assert!(c7.blank);
        assert!(c7.blank_map);
        assert_eq!(c7.map_max, Some((3, 1)));
        assert_eq!(c7.map_min, Some((3, 0)));
    }

    #[test]
    fn hex256_color_bar_order() {
        let m = compute_render_model(&hex256_core(), &HEX, 1.0, 12.0, false, 64).unwrap();
        let bands: Vec<&str> = m.color_bar.iter().map(|b| b.band.as_str()).collect();
        assert_eq!(bands, vec!["G", "K", "R", "W"]);
        for (i, b) in m.color_bar.iter().enumerate() {
            assert_eq!(b.rank, i);
        }
    }

    #[test]
    fn hex256_markers() {
        let m = compute_render_model(&hex256_core(), &HEX, 1.0, 12.0, false, 64).unwrap();
        assert_eq!(m.color_bar_markers.slots, 15);
        assert_eq!(m.color_bar_markers.left, 2);
        assert_eq!(m.color_bar_markers.right, 5);
    }

    #[test]
    fn hex256_ellipse() {
        let m = compute_render_model(&hex256_core(), &HEX, 1.0, 12.0, false, 64).unwrap();
        let e = m.ellipse.expect("ellipse present");
        assert!((e.anchor.0 - 87.0).abs() < 1e-6);
        assert!((e.anchor.1 - 66.0).abs() < 1e-6);
        assert!((e.rx - 37.335).abs() < 0.01, "rx={}", e.rx);
        assert!((e.ry - 57.7).abs() < 0.05, "ry={}", e.ry);
        assert!((e.rotation - 12.0).abs() < 1e-6, "rot={}", e.rotation);
    }

    #[test]
    fn fs6_text_size_uses_banker_rounding() {
        // font_pt=6, hex (4-bit) → text_pt = round(6*0.75) = round(4.5). Python's
        // round-half-to-even yields 4 (→ 4*96/72 = 5.333px), NOT 5. Pins the
        // round_ties_even fix the differential harness caught on the fs-6 vector.
        let m = compute_render_model(&hex256_core(), &HEX, 1.0, 6.0, false, 64).unwrap();
        let px = m.cells[0].text_size_px.unwrap();
        assert!((px - 4.0 * 96.0 / 72.0).abs() < 1e-9, "text_size_px={px}");
    }

    #[test]
    fn large_input_rejected() {
        let big = "ab".repeat(200); // 400 hex chars = 200 bytes > 64
        assert_eq!(
            compute_render_model(&big, &HEX, 1.0, 12.0, false, 400),
            Err(ModelError::LargeInputUnsupported)
        );
    }

    // Second golden vector: compliance/corpus/text-hello, input "hello world"
    // → fallback re-encoded to base64url core "aGVsbG8gd29ybGQ" (4 tokens, 2×2
    // grid, no blanks, external-corner ellipse path, raw bytes 11 ≠ core 15).
    use crate::BASE64URL;
    fn texthello_core() -> &'static str {
        "aGVsbG8gd29ybGQ"
    }

    #[test]
    fn texthello_grid_cells_bg() {
        let m = compute_render_model(texthello_core(), &BASE64URL, 1.0, 12.0, false, 11).unwrap();
        assert_eq!((m.cols, m.rows), (2, 2));
        assert_eq!(m.bg_color, "#2f3fbf");
        assert_eq!(m.input_bytes, 11); // raw, not the 15-char core
        let c0 = &m.cells[0];
        assert_eq!(c0.text.as_deref(), Some("aGVs"));
        assert_eq!(c0.nucleus_bg.as_deref(), Some("#6c6568"));
        assert_eq!(c0.edge_color.as_deref(), Some("#ff3f2f"));
        assert_eq!(c0.surround_bits, Some(3731819));
        assert_eq!(c0.quartile, Some(3));
        assert_eq!(c0.text_size_px, Some(16.0)); // 4-char b64url → full size
        // No blanks on a 2×2 grid filled by 4 tokens → no map cell.
        assert!(m.cells.iter().all(|c| !c.blank && !c.blank_map));
    }

    #[test]
    fn texthello_color_bar_markers_ellipse() {
        let m = compute_render_model(texthello_core(), &BASE64URL, 1.0, 12.0, false, 11).unwrap();
        let bands: Vec<&str> = m.color_bar.iter().map(|b| b.band.as_str()).collect();
        assert_eq!(bands, vec!["W", "R", "K", "G"]);
        assert_eq!(m.color_bar_markers.slots, 9);
        assert_eq!(m.color_bar_markers.left, 1);
        assert_eq!(m.color_bar_markers.right, 3);
        let e = m.ellipse.expect("ellipse present (external-corner path)");
        assert!((e.anchor.0 - 27.0).abs() < 1e-6 && (e.anchor.1 - 26.0).abs() < 1e-6);
        assert!((e.rx - 31.729).abs() < 0.01, "rx={}", e.rx);
        assert!((e.ry - 73.265).abs() < 0.01, "ry={}", e.ry);
        assert!((e.rotation - 60.0).abs() < 1e-6, "rot={}", e.rotation);
    }
}
