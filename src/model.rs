//! Render-model computation (spec v10) — the abstract Tier-A structure an
//! implementation must compute prior to SVG serialization. This mirrors the
//! Python reference's `model.json` (golden conformance corpus) field-for-field
//! for **short inputs** (normalized core ≤ 64 bytes / ≤ 512 bits).
//!
//! This is the half of entviz the adversarial grinder cares about: every
//! fingerprint-driven channel a human can check is a discrete field here, and
//! each is `f(SHA-512(core))`. Both the short and the large-input (>512-bit)
//! head + fingerprint-middle + tail paths are ported and verified against the
//! Python golden corpus by entviz-adversarial/oracle/diff_harness.py.
//!
//! Ground truth: `/home/daniel/code/entviz/compliance/corpus/<name>/model.json`.

use sha2::{Digest, Sha512};

use crate::{
    choose_grid, closest_palette_color, compute_fingerprint, median_token, nucleus_colors,
    quartile_tokens, select_visual_style, tokenize, tokenize_fingerprint, Alphabet, Grid, Token,
};

pub const SPEC_VERSION_V10: &str = "v10";

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

/// Encode a 24-bit value as 5 lowercase Crockford base32 chars (v9 middle-cell
/// readout). Mirrors `entropy._crockford5`: high-order first, single-case,
/// homoglyph-clean (Crockford omits i/l/o/u). Injective since 32^5 ≥ 2^24.
fn crockford5(quant: u32) -> String {
    const C: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = [0u8; 5];
    let mut v = quant;
    for i in 0..5 {
        out[4 - i] = C[(v & 0x1F) as usize];
        v >>= 5;
    }
    String::from_utf8(out.to_vec()).unwrap().to_lowercase()
}

/// Build the 20 renumbered tokens for a large (>512-bit) input: 8 head tokens
/// (first `8·token_len` chars of `core`), 4 middle tokens (each a Crockford-5
/// readout of 24 bits of the domain-separated `second` digest — neutral bg,
/// painted by the pipeline), and 8 tail tokens (last `8·token_len` chars).
/// Mirrors `entropy.tokenize_entropy`'s large path + `_build_fingerprint_middle_tokens`.
fn build_large_tokens(core: &str, alphabet: &Alphabet, token_len: usize) -> Vec<Token> {
    let chars: Vec<char> = core.chars().collect();
    let window = 8 * token_len;
    let head: String = chars[..window.min(chars.len())].iter().collect();
    let tail_start = chars.len().saturating_sub(window);
    let tail: String = chars[tail_start..].iter().collect();
    let head_tokens = tokenize(&head, alphabet);
    let tail_tokens = tokenize(&tail, alphabet);

    let second = second_digest(core);
    let mut combined: Vec<Token> = Vec::with_capacity(20);
    combined.extend(head_tokens);
    for i in 0..4 {
        let quant = ((second[3 * i] as u32) << 16)
            | ((second[3 * i + 1] as u32) << 8)
            | (second[3 * i + 2] as u32);
        combined.push(Token { text: crockford5(quant), index: i, quant });
    }
    combined.extend(tail_tokens);
    // Renumber 0..19 (head 0..7, middle 8..11, tail 12..19).
    combined
        .into_iter()
        .enumerate()
        .map(|(i, t)| Token { text: t.text, index: i, quant: t.quant })
        .collect()
}

/// Foreground (text) color for a cell painted with the neutral entviz-bg color
/// (the fingerprint-middle cells). Re-derives via the Oklab contrast rule on
/// the bg color's own quant, exactly as `Renderer.render_nucleus` does under a
/// `bg_override`.
fn fg_for_bg(bg_hex: &str) -> String {
    let r = u32::from_str_radix(&bg_hex[1..3], 16).unwrap();
    let g = u32::from_str_radix(&bg_hex[3..5], 16).unwrap();
    let b = u32::from_str_radix(&bg_hex[5..7], 16).unwrap();
    nucleus_colors(r | (g << 8) | (b << 16)).1
}

/// Index of a palette hex color in [`POSSIBLE_EDGE_COLORS`] (0..=4), or 255 if
/// it is not a palette color. Used to store the v10 color-singleton channels
/// (fingerprint-edge + blank-fill colors) compactly.
fn palette_idx(hex: &str) -> u8 {
    crate::POSSIBLE_EDGE_COLORS
        .iter()
        .position(|&c| c == hex)
        .map(|i| i as u8)
        .unwrap_or(255)
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
    // v10 casual-salience channels (NOT part of the Tier-A model.json / oracle —
    // excluded from `to_golden_json` — but load-bearing for the color-field
    // attack persona). `fp_edge`: this filled cell is a fingerprint-edge cell
    // (its `edge_color` is fingerprint-driven, not the nucleus echo).
    // `blank_fill`: POSSIBLE_EDGE_COLORS index of this blank cell's v10 pill fill.
    pub fp_edge: bool,
    pub blank_fill: Option<u8>,
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
    let est_token_count = (core.chars().count() + token_len - 1) / token_len; // ceil
    // v6 large-input trigger: >512 bits (>64 bytes) OR >22 tokens. The large
    // path renders 8 head + 4 fingerprint-middle + 8 tail tokens (20 total).
    let is_truncated = est_token_count > 22 || core_byte_length(core, alphabet) > 64;

    let tokens = if is_truncated {
        build_large_tokens(core, alphabet, token_len)
    } else {
        tokenize(core, alphabet)
    };
    let token_count = tokens.len();

    let primary = compute_fingerprint(fingerprint_core);
    let ftoks_all = tokenize_fingerprint(&primary);
    let used_ftoks: Vec<Token> = ftoks_all.into_iter().take(token_count).collect();
    let second = second_digest(core);

    // Large inputs choose the grid as if for 22 tokens (4×6 at AR 1.0) so the
    // blank-shift has slack, even though only 20 cells carry tokens.
    let grid = choose_grid(if is_truncated { 22 } else { token_count }, target_ar);
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
    // The v9 fingerprint-middle cells always render 5 Crockford chars, so they
    // use the 5-char (0.80×) size regardless of the input alphabet (round-to-even
    // to match Python's `round`). Only consulted on large inputs.
    let fp_middle_text_px = (font_pt * 0.80).round_ties_even() * 96.0 / 72.0;

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

    // v10 fingerprint-edge cells: the top-left cell (grid position 0, when used)
    // and the cells of the 1st & 2nd quartile ftoks take their surround edge
    // color from the fingerprint (2 low-order ftok-quant bits → edge palette)
    // instead of the nearest-palette nucleus echo, so the surround color
    // avalanches to a casual glance. See pipeline.py (v10 casual-avalanche).
    let mut fp_edge_cells: std::collections::HashSet<usize> = std::collections::HashSet::new();
    if used_cells.contains(&0) {
        fp_edge_cells.insert(0);
    }
    for qt in quartiles.iter().take(2).flatten() {
        fp_edge_cells.insert(cell_of_token[qt.index]);
    }

    // v10 hybrid blank fill (render-only in the Python ref; ported here for the
    // color-field persona). Every non-map blank is fingerprint-filled; the map
    // blank is fingerprint-filled ONLY when it is the sole blank, else it keeps
    // the white/gold anchor. Filled blanks are enumerated in cell-index order;
    // the j-th takes edge_palette[primary[32 + j] & 0b11]. See pipeline.py v10.
    let sole_blank = blank_indices.len() == 1;
    let anchor_idx = if style.bg_color == "#ffffff" { 1u8 } else { 0u8 }; // gold on white else white
    let mut blank_fill_of_cell: std::collections::HashMap<usize, u8> =
        std::collections::HashMap::new();
    let mut filled_j = 0usize;
    for &bi in &blank_indices {
        let is_map = Some(bi) == map_cell;
        if is_map && !sole_blank {
            blank_fill_of_cell.insert(bi, anchor_idx);
        } else {
            let pal = (primary[32 + filled_j] & 0b11) as usize;
            blank_fill_of_cell.insert(bi, palette_idx(edge_palette[pal]));
            filled_j += 1;
        }
    }

    let mut cells = Vec::with_capacity(cell_count);
    for ci in 0..cell_count {
        let col = ci % grid.cols;
        let row = ci / grid.cols;
        if let Some(&t_idx) = token_of_cell.get(&ci) {
            let token = &tokens[t_idx];
            // v6 fingerprint-middle cells (large inputs, token indices 8..=11):
            // neutral entviz-bg nucleus (no entropy in the bg), gold/white frame,
            // 0.80× Crockford text — surround stays ftok-driven.
            let is_fp_middle = is_truncated && (8..=11).contains(&token.index);
            let (bg, fg, tsize) = if is_fp_middle {
                let bg = style.bg_color.clone();
                let fg = fg_for_bg(&bg);
                (bg, fg, fp_middle_text_px)
            } else {
                let (bg, fg) = nucleus_colors(token.quant);
                (bg, fg, text_size_px)
            };
            // v10: a fingerprint-edge cell overrides the nucleus echo with the
            // ftok-driven palette color; otherwise the edge is the nearest
            // palette color to the (possibly neutralized) nucleus bg.
            let edge = if fp_edge_cells.contains(&ci) {
                edge_palette[(used_ftoks[t_idx].quant & 0b11) as usize].to_string()
            } else {
                closest_palette_color(&bg, &edge_palette).to_string()
            };
            cells.push(CellModel {
                index: ci,
                col,
                row,
                blank: false,
                blank_map: false,
                fingerprint: is_fp_middle,
                text: Some(token.text.clone()),
                nucleus_bg: Some(bg),
                fg: Some(fg),
                edge_color: Some(edge),
                surround_bits: Some(used_ftoks[t_idx].quant),
                text_size_px: Some(tsize),
                quartile: quartile_of_cell.get(&ci).copied(),
                map_min: None,
                map_max: None,
                fp_edge: fp_edge_cells.contains(&ci),
                blank_fill: None,
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
                fp_edge: false,
                blank_fill: blank_fill_of_cell.get(&ci).copied(),
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
        spec_version: SPEC_VERSION_V10.to_string(),
        cols: grid.cols,
        rows: grid.rows,
        bg_color: style.bg_color,
        input_bytes,
        truncated: is_truncated,
        cells,
        color_bar,
        color_bar_markers: markers,
        ellipse,
    })
}

// --------------------------------------------------------------------------
// Channels — the lean casual-gestalt feature vector (the grinder's hot path)
// --------------------------------------------------------------------------

/// The "casual gestalt" feature vector: the channels a habituated glance checks,
/// computed WITHOUT the per-cell `Vec` or JSON serialization. This is the
/// adversarial grinder's hot path — two SHA-512s + an ftok median + a few dozen
/// integer ops per candidate. Every field is a small integer so the match
/// predicate is branch-free comparison. Pinned consistent with
/// [`compute_render_model`] by the `channels_agree_with_model` test.
///
/// NOT yet modeled here (deliberately, until a persona needs them): the per-cell
/// nucleus/edge field and the v10 blank-cell fills. The fingerprint-edge cells'
/// colors and the blank fills are casually salient (that is the whole point of
/// v10), so a persona that checks "the field of cell colors" will need them
/// added — see entviz-adversarial/STATE.md.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channels {
    /// Index into [`POSSIBLE_EDGE_COLORS`] of the entviz background (0..=3).
    pub bg: u8,
    /// Count of each 2-bit pattern (0..3) across the 256 digest slices. Band
    /// heights are `count^4`; the tallest band is `argmax` of this.
    pub bar_counts: [u32; 4],
    /// First-appearance order of the 4 patterns (rank 0 = top band).
    pub bar_order: [u8; 4],
    /// Color-bar markers: left slot, right slot, and slot count K.
    pub marker_left: u8,
    pub marker_right: u8,
    pub marker_k: u8,
    /// Ellipse silhouette as the discrete params that fully determine it given a
    /// fixed grid+geometry: anchor index in the corner pool, and the rx/ry/rot
    /// 0..15 steps. Two candidates with equal tuples have identical silhouettes.
    pub ell_anchor: u16,
    pub ell_rx: u8,
    pub ell_ry: u8,
    pub ell_rot: u8,
}

impl Channels {
    /// Pattern id (0..3) of the dominant (tallest) color-bar band — the casual
    /// "biggest stripe". argmax of `bar_counts`, tie-break to the lower pattern.
    pub fn dominant_band(&self) -> u8 {
        let mut best = 0usize;
        for p in 1..4 {
            if self.bar_counts[p] > self.bar_counts[best] {
                best = p;
            }
        }
        best as u8
    }
}

/// Compute the lean [`Channels`] gestalt for a core. Mirrors the fingerprint-
/// driven channels of [`compute_render_model`] (bg, color bar, markers, ellipse)
/// but skips cell tokenization, per-cell assembly, and serialization. For a
/// semantic-prefix grind, pass `fingerprint_core = prefix‖core`; else it equals
/// `core`. `bottom_strip` only affects the marker slot count K.
pub fn channels(
    core: &str,
    fingerprint_core: &str,
    alphabet: &Alphabet,
    target_ar: f64,
    font_pt: f64,
    bottom_strip: bool,
) -> Channels {
    let token_len = (24 / alphabet.bits_per_char) as usize;
    let est_token_count = (core.chars().count() + token_len - 1) / token_len;
    let is_truncated = est_token_count > 22 || core_byte_length(core, alphabet) > 64;
    // Short: token_count == ceil(len/token_len). Large: always 20 (8+4+8). We
    // never need the cell text here, only the count (for ftoks + grid).
    let token_count = if is_truncated { 20 } else { est_token_count };

    let primary = compute_fingerprint(fingerprint_core);
    let ftoks_all = tokenize_fingerprint(&primary);
    let used_ftoks: Vec<Token> = ftoks_all.into_iter().take(token_count).collect();
    let median = median_token(&used_ftoks).expect("non-empty");
    let bg = (median.quant & 0x03) as u8;

    // Color bar.
    let counts = two_bit_counts(&primary);
    let mut bar_counts = [0u32; 4];
    for p in 0..4 {
        bar_counts[p] = counts[p] as u32;
    }
    let order = first_appearance_order(&primary);
    let mut bar_order = [0u8; 4];
    for (i, &p) in order.iter().enumerate() {
        bar_order[i] = p as u8;
    }

    // Geometry for the marker slot count K (= clamp(floor(bar_height/12), 4, 16)).
    let grid = choose_grid(if is_truncated { 22 } else { token_count }, target_ar);
    let font_px = font_pt * 96.0 / 72.0;
    let nucleus_h = font_px * 1.25;
    let box_h = nucleus_h / 2.0;
    let cell_h = nucleus_h + 2.0 * box_h;
    let gm = box_h / 2.0;
    let grid_h = cell_h * grid.rows as f64;
    let bottom_region = if bottom_strip { nucleus_h + gm } else { gm };
    let bounding_h = 1.0 + gm + nucleus_h + grid_h + bottom_region + 1.0;
    let bar_height = bounding_h - 2.0;
    let k = ((bar_height / 12.0).floor() as i64).clamp(4, 16) as usize;
    let second = second_digest(core);
    let marker_left = ((second[12] as usize) % k) as u8;
    let marker_right = ((second[13] as usize) % k) as u8;

    // Ellipse silhouette (discrete). pool_len mirrors interior/external corner
    // enumeration without materializing the points.
    let interior_count = (grid.cols.saturating_sub(1)) * (grid.rows.saturating_sub(1));
    let pool_len = if interior_count >= 6 {
        interior_count
    } else {
        2 * (grid.cols + grid.rows)
    };
    let ell_anchor = if pool_len == 0 {
        0
    } else {
        ((primary[60] as usize) % pool_len) as u16
    };

    Channels {
        bg,
        bar_counts,
        bar_order,
        marker_left,
        marker_right,
        marker_k: k as u8,
        ell_anchor,
        ell_rx: primary[61] % 16,
        ell_ry: primary[62] % 16,
        ell_rot: primary[63] % 16,
    }
}

/// The v10 casual-salience COLOR singletons — the channels v10 added so a one-
/// character change pops to a glance. The fingerprint-edge cell colors are also
/// in the Tier-A model (hence oracle-certified via `edge_color`); the blank-cell
/// fills are render-only there, so this is the only place they are computed (the
/// harness cross-checks them against the golden SVGs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColorField {
    /// [`POSSIBLE_EDGE_COLORS`] index of the entviz background (0..=3).
    pub bg: u8,
    /// (cell_index, palette index) of each fingerprint-edge cell, ascending.
    pub fp_edge: Vec<(usize, u8)>,
    /// (cell_index, palette index) of each blank cell's pill fill, ascending.
    pub blank_fill: Vec<(usize, u8)>,
}

/// Compute the v10 color-singleton field for a core (see [`ColorField`]). Built
/// from the full render model, so it carries the cell LAYOUT (positions) the
/// gestalt [`channels`] omits — a color-field forgery must reproduce both the
/// colors and where they sit. Panics only on an empty core.
pub fn color_field(
    core: &str,
    fingerprint_core: &str,
    alphabet: &Alphabet,
    target_ar: f64,
    font_pt: f64,
    bottom_strip: bool,
) -> ColorField {
    let m = compute_render_model_fp(
        core, fingerprint_core, alphabet, target_ar, font_pt, bottom_strip, 0,
    )
    .expect("non-empty core");
    let bg = palette_idx(&m.bg_color);
    let mut fp_edge = Vec::new();
    let mut blank_fill = Vec::new();
    for c in &m.cells {
        if c.blank {
            if let Some(f) = c.blank_fill {
                blank_fill.push((c.index, f));
            }
        } else if c.fp_edge {
            fp_edge.push((c.index, palette_idx(c.edge_color.as_deref().unwrap_or(""))));
        }
    }
    ColorField { bg, fp_edge, blank_fill }
}

/// The per-cell FRAME color, in cell-index order (cell 0 = top-left, the first-
/// fixation point). For a filled cell this is its surround/edge palette color —
/// the nucleus color quantized to the palette (and fingerprint-driven on the
/// v10 fingerprint-edge cells); for a blank cell it is the v10 pill-fill color.
/// Values are [`POSSIBLE_EDGE_COLORS`] indices (0..=4). This is the discrete
/// proxy for "the broad field of cell colors" a casual glance reads — the
/// attacker-side channel for the anchored color-field persona.
pub fn frame_colors(
    core: &str,
    fingerprint_core: &str,
    alphabet: &Alphabet,
    target_ar: f64,
    font_pt: f64,
    bottom_strip: bool,
) -> Vec<u8> {
    let m = compute_render_model_fp(
        core, fingerprint_core, alphabet, target_ar, font_pt, bottom_strip, 0,
    )
    .expect("non-empty core");
    m.cells
        .iter()
        .map(|c| {
            if c.blank {
                c.blank_fill.unwrap_or(255)
            } else {
                palette_idx(c.edge_color.as_deref().unwrap_or(""))
            }
        })
        .collect()
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
        assert_eq!(m.spec_version, "v10");
    }

    #[test]
    fn hex256_cell0_and_cell1() {
        let m = compute_render_model(&hex256_core(), &HEX, 1.0, 12.0, false, 64).unwrap();
        let c0 = &m.cells[0];
        assert_eq!(c0.text.as_deref(), Some("012345"));
        assert_eq!(c0.nucleus_bg.as_deref(), Some("#452301"));
        assert_eq!(c0.fg.as_deref(), Some("#ffffff"));
        // v10: cell 0 is the top-left fingerprint-edge cell, so its edge is the
        // ftok-driven palette color (#e7be00), not the v9 nucleus echo (#000000).
        assert_eq!(c0.edge_color.as_deref(), Some("#e7be00"));
        assert_eq!(c0.surround_bits, Some(11348353));
        assert_eq!(c0.quartile, Some(2));
        assert_eq!(c0.text_size_px, Some(12.0));

        let c1 = &m.cells[1];
        assert_eq!(c1.nucleus_bg.as_deref(), Some("#ab8967"));
        // cell 1 is the 1st-quartile fingerprint-edge cell (v10); its ftok-driven
        // palette color coincides with the v9 nucleus echo here.
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
    fn color_field_hex256() {
        // hex-256, blue bg. fp-edge cells = top-left (0) + 1st/2nd quartile cells
        // (1 and 0), so {0, 1}; their v10 edge colors are gold(#e7be00 → idx1)
        // on cell 0 and red(#ff3f2f → idx2) on cell 1. One blank (cell 7) which
        // is the sole blank → fingerprint-filled; its color is from the blue
        // edge palette {white0, gold1, red2, black4} (never blue=3).
        let core = hex256_core();
        let cf = color_field(&core, &core, &HEX, 1.0, 12.0, false);
        assert_eq!(cf.bg, 3); // blue
        assert_eq!(cf.fp_edge, vec![(0, 1), (1, 2)]);
        assert_eq!(cf.blank_fill.len(), 1);
        assert_eq!(cf.blank_fill[0].0, 7);
        let fill = cf.blank_fill[0].1;
        assert!(fill < 5 && fill != 3, "blank fill idx {fill} must be a non-blue palette color");
        // Consistency: fp_edge colors equal the model's edge_color on those cells.
        let m = compute_render_model(&core, &HEX, 1.0, 12.0, false, 64).unwrap();
        for &(ci, idx) in &cf.fp_edge {
            assert_eq!(
                crate::POSSIBLE_EDGE_COLORS[idx as usize],
                m.cells[ci].edge_color.as_deref().unwrap()
            );
        }
    }

    #[test]
    fn frame_colors_hex256() {
        // 12-cell 3×4 grid. cell 0 (top-left) = fp-edge gold (idx 1), cell 1 =
        // fp-edge red (idx 2). Every entry is a valid palette color (0..=4).
        let core = hex256_core();
        let fc = frame_colors(&core, &core, &HEX, 1.0, 12.0, false);
        assert_eq!(fc.len(), 12);
        assert_eq!(fc[0], 1); // top-left anchor = gold
        assert_eq!(fc[1], 2); // 1st-quartile fp-edge = red
        assert!(fc.iter().all(|&c| c <= 4));
    }

    #[test]
    fn channels_agree_with_model() {
        // The lean channels() gestalt must agree with the certified model on the
        // fingerprint-driven channels it projects (hex-256, 3×4, blue bg).
        let core = hex256_core();
        let m = compute_render_model(&core, &HEX, 1.0, 12.0, false, 64).unwrap();
        let ch = channels(&core, &core, &HEX, 1.0, 12.0, false);

        assert_eq!(crate::POSSIBLE_EDGE_COLORS[ch.bg as usize], m.bg_color);
        assert_eq!(ch.marker_left as usize, m.color_bar_markers.left);
        assert_eq!(ch.marker_right as usize, m.color_bar_markers.right);
        assert_eq!(ch.marker_k as usize, m.color_bar_markers.slots);
        // Known golden values for hex-256.
        assert_eq!(ch.bg, 3); // blue
        assert_eq!((ch.marker_left, ch.marker_right, ch.marker_k), (2, 5, 15));
        assert_eq!(ch.bar_order, [1, 3, 2, 0]); // gold, black, red, white (first-appearance)
        // Ellipse rotation: step/15·180 must equal the model's 12°.
        let e = m.ellipse.unwrap();
        assert!((ch.ell_rot as f64 / 15.0 * 180.0 - e.rotation).abs() < 1e-9);
        assert_eq!(ch.ell_rot, 1);
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
    fn large_input_truncates() {
        let big = "ab".repeat(200); // 400 hex chars = 200 bytes > 64 → large path
        let m = compute_render_model(&big, &HEX, 1.0, 12.0, false, 200).unwrap();
        assert!(m.truncated);
        assert_eq!((m.cols, m.rows), (4, 6));
        // Exactly 4 fingerprint-middle cells, each a 5-char Crockford readout.
        let fp: Vec<&CellModel> = m.cells.iter().filter(|c| c.fingerprint).collect();
        assert_eq!(fp.len(), 4);
        for c in fp {
            assert_eq!(c.text.as_ref().unwrap().chars().count(), 5);
            assert_eq!(c.nucleus_bg.as_deref(), Some(m.bg_color.as_str()));
        }
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
        // v10: top-left fingerprint-edge cell → ftok-driven palette color.
        assert_eq!(c0.edge_color.as_deref(), Some("#000000"));
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
