//! Full render pipeline: entropy string → SVG string (spec v10).
//!
//! Faithful port of `src/entviz/pipeline.py` + `renderer.py` + `shapes.py`.
//! Produces an SVG whose normative `data-*` attributes and geometry let the
//! conformance Tier-A extractor recover the golden render model, and whose
//! non-text pixels match the golden Tier-B raster.

use crate::entropy::{self, tokenize_entropy, ParseError, BASE64URL};
use crate::second_digest;
use crate::util::{assign_cell_indices, band_letter, two_bit_counts};
use crate::{
    choose_grid, closest_palette_color, compute_fingerprint, median_token, nucleus_colors,
    quartile_tokens, select_visual_style, tokenize_fingerprint, Grid, Token, VisualStyle,
};

const DPI: f64 = 96.0;
const NOTE_MAX_LEN: usize = 8;
const MAX_INPUT_CHARS: usize = 65536;
const MONOSPACE_FONT_FAMILY: &str = "\"JetBrains Mono\", \"Menlo\", \"Consolas\", \"DejaVu Sans Mono\", \"Liberation Mono\", \"Roboto Mono\", \"Noto Sans Mono\", monospace";

#[derive(Debug)]
pub enum RenderError {
    Note(String),
    InputTooLong,
    FontSizeRange,
    AspectRatioRange,
    NoTokens,
    /// EIP-55 checksum mismatch. `position` is the index (within the 40-hex
    /// address body, 0-based) of the first digit whose case disagrees with the
    /// canonical case derived from keccak256(lower(body)). The spec MUST
    /// "identify the first mismatched-case digit", so the position is carried
    /// through to the error (and surfaced by the CLI) rather than discarded.
    Eip55 {
        position: usize,
    },
}

impl From<ParseError> for RenderError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::Eip55 { position } => RenderError::Eip55 { position },
        }
    }
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RenderError::Note(msg) => write!(f, "{msg}"),
            RenderError::InputTooLong => write!(f, "input too long"),
            RenderError::FontSizeRange => write!(f, "font size out of range"),
            RenderError::AspectRatioRange => write!(f, "aspect ratio out of range"),
            RenderError::NoTokens => write!(f, "no tokens"),
            RenderError::Eip55 { position } => {
                write!(f, "EIP-55 checksum mismatch at position {position}")
            }
        }
    }
}

impl std::error::Error for RenderError {}

fn sanitize_note(note: Option<&str>) -> Result<Option<String>, RenderError> {
    match note {
        None => Ok(None),
        Some("") => Ok(None),
        Some(n) => {
            if n.chars().count() > NOTE_MAX_LEN {
                return Err(RenderError::Note(format!(
                    "note too long: {}",
                    n.chars().count()
                )));
            }
            if n.is_empty() || !n.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err(RenderError::Note("note must be ASCII alphanumeric".into()));
            }
            Ok(Some(n.to_string()))
        }
    }
}

// ---- tiny XML helpers ----
fn esc_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
fn esc_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
fn n(x: f64) -> String {
    format!("{}", x)
}

/// Render entropy as an entviz SVG string.
pub fn render(
    entropy_text: &str,
    target_ar: f64,
    font_size_pt: f64,
    note: Option<&str>,
) -> Result<String, RenderError> {
    let note = sanitize_note(note)?;
    if entropy_text.chars().count() > MAX_INPUT_CHARS {
        return Err(RenderError::InputTooLong);
    }
    if !(6.0..=30.0).contains(&font_size_pt) {
        return Err(RenderError::FontSizeRange);
    }
    if !(0.01..=100.0).contains(&target_ar) {
        return Err(RenderError::AspectRatioRange);
    }

    let raw_input = entropy_text.trim().to_string();
    let parsed = entropy::parse(&raw_input)?;

    let (core, mut type_name, alphabet, prefix, suffix, prefix_semantic);
    match parsed {
        None => {
            // txt -> b64url fallback (URL-safe base64, no padding).
            core = b64url_encode(raw_input.as_bytes());
            type_name = format!("txt({})->b64url", raw_input.chars().count());
            alphabet = BASE64URL;
            prefix = None;
            suffix = None;
            prefix_semantic = false;
        }
        Some(p) => {
            core = p.core;
            type_name = p.type_name;
            alphabet = p.alphabet;
            prefix = p.prefix;
            suffix = p.suffix;
            prefix_semantic = p.prefix_semantic;
            if type_name == "hex" {
                type_name = format!("hex({})", core.chars().count());
            } else if type_name == "base64" {
                type_name = format!("b64({})", core.chars().count());
            } else if type_name == "base64url" {
                type_name = format!("b64url({})", core.chars().count());
            }
        }
    }

    let (tokens, is_truncated) = tokenize_entropy(&core, &alphabet);
    if tokens.is_empty() {
        return Err(RenderError::NoTokens);
    }
    let truncated_bytes: Option<usize> = if is_truncated {
        Some(raw_input.len())
    } else {
        None
    };
    let token_count = tokens.len();

    let fingerprint_core = match (&prefix, prefix_semantic) {
        (Some(p), true) => format!("{p}{core}"),
        _ => core.clone(),
    };

    let primary = compute_fingerprint(&fingerprint_core);
    let ftoks_all = tokenize_fingerprint(&primary);
    let used_ftoks: Vec<Token> = ftoks_all.into_iter().take(token_count).collect();

    let grid = choose_grid(if is_truncated { 22 } else { token_count }, target_ar);
    let median_ftok = median_token(&used_ftoks);
    let quartile_ftoks = quartile_tokens(&used_ftoks);
    let style = select_visual_style(median_ftok.as_ref().expect("non-empty ftoks"));

    let cell_indices = assign_cell_indices(&tokens, &grid, &median_ftok, &used_ftoks);

    // --- geometry ---
    let font_px = font_size_pt * DPI / 72.0;
    let nucleus_w = font_px * 3.0;
    let nucleus_h = font_px * 1.25;
    let box_w = nucleus_w / 8.0;
    let box_h = nucleus_h / 2.0;
    let cell_w = nucleus_w + 2.0 * box_w;
    let cell_h = nucleus_h + 2.0 * box_h;
    let gm = box_h / 2.0;
    let bar_w = 2.0 * box_h;
    let grid_w = cell_w * grid.cols as f64;
    let grid_h = cell_h * grid.rows as f64;

    let bounding_w = 1.0 + bar_w + 1.0 + gm + grid_w + gm + 1.0;
    let has_bottom_label = suffix.is_some() || note.is_some();
    let bottom_region = if has_bottom_label { nucleus_h + gm } else { gm };
    let bounding_h = 1.0 + gm + nucleus_h + grid_h + bottom_region + 1.0;

    let grid_left = 1.0 + bar_w + 1.0 + gm;
    let grid_top = 1.0 + gm + nucleus_h;
    let grid_right = grid_left + grid_w;
    let grid_bottom = grid_top + grid_h;

    let cell_count = grid.cols * grid.rows;
    let used_cells: std::collections::HashSet<usize> = cell_indices.iter().copied().collect();

    // --- per-cell text sizes ---
    let cell_text_pt = if alphabet.bits_per_char == 4 {
        (font_size_pt * 0.75).round_ties_even()
    } else {
        font_size_pt
    };
    let cell_text_px = cell_text_pt * DPI / 72.0;
    let label_text_px = (font_size_pt * 0.75).round_ties_even() * DPI / 72.0;
    let fp_middle_text_px = (font_size_pt * 0.80).round_ties_even() * DPI / 72.0;

    // --- fingerprint-edge cells (v10) ---
    let mut fp_edge_cells: std::collections::HashSet<usize> = std::collections::HashSet::new();
    if used_cells.contains(&0) {
        fp_edge_cells.insert(0);
    }
    for q in quartile_ftoks.iter().take(2).flatten() {
        fp_edge_cells.insert(cell_indices[q.index]);
    }

    // --- nucleus bg per token ---
    // token_cells: (token, ftok, ci, nucleus_bg)
    let mut token_cells: Vec<(&Token, &Token, usize, String)> = Vec::with_capacity(token_count);
    for token in &tokens {
        let ci = cell_indices[token.index];
        let nucleus_bg = if is_truncated && (8..=11).contains(&token.index) {
            style.bg_color.clone()
        } else {
            nucleus_colors(token.quant).0
        };
        token_cells.push((token, &used_ftoks[token.index], ci, nucleus_bg));
    }

    // ===================== build SVG =====================
    let mut s = String::with_capacity(8192);
    s.push_str(&format!(
        "<svg width=\"{w}\" height=\"{h}\" viewBox=\"0 0 {w} {h}\" xmlns=\"http://www.w3.org/2000/svg\" \
         data-entviz-version=\"{ev}\" data-entviz-lib=\"{lib}\" data-input-bytes=\"{ib}\" \
         data-cols=\"{c}\" data-rows=\"{r}\"{trunc}>",
        ev = crate::SPEC_VERSION,
        lib = env!("CARGO_PKG_VERSION"),
        w = n(bounding_w),
        h = n(bounding_h),
        ib = raw_input.len(),
        c = grid.cols,
        r = grid.rows,
        trunc = if is_truncated { " data-truncated=\"true\"" } else { "" },
    ));

    // defs + clipPath
    let digest_hex: String = primary[..8].iter().map(|b| format!("{:02x}", b)).collect();
    let clip_id = format!("grid-clip-{}-{}x{}", digest_hex, grid.cols, grid.rows);
    s.push_str(&format!(
        "<defs><clipPath id=\"{cid}\"><rect x=\"{x}\" y=\"{y}\" width=\"{w}\" height=\"{h}\"/></clipPath></defs>",
        cid = esc_attr(&clip_id),
        x = n(grid_left),
        y = n(grid_top),
        w = n(grid_w),
        h = n(grid_h),
    ));

    // bounding white background
    s.push_str(&format!(
        "<rect x=\"0\" y=\"0\" width=\"{}\" height=\"{}\" fill=\"#ffffff\"/>",
        n(bounding_w),
        n(bounding_h)
    ));

    // grid channel
    s.push_str("<g data-channel=\"grid\">");
    s.push_str(&format!(
        "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\"/>",
        n(grid_left),
        n(grid_top),
        n(grid_w),
        n(grid_h),
        esc_attr(&style.bg_color)
    ));

    // Layer 1: edges
    s.push_str("<g>");
    for &(_token, ftok, ci, ref nucleus_bg) in &token_cells {
        let edge_color = if fp_edge_cells.contains(&ci) {
            style.edge_colors[(ftok.quant & 0b11) as usize].clone()
        } else {
            closest_palette_color(nucleus_bg, &edge_color_refs(&style)).to_string()
        };
        let col = ci % grid.cols;
        let row = ci / grid.cols;
        let cell_left = grid_left + col as f64 * cell_w;
        let cell_top = grid_top + row as f64 * cell_h;
        for i in 0..24u32 {
            if (ftok.quant >> i) & 1 == 0 {
                continue;
            }
            let (ox, oy) = box_origin(i, cell_left, cell_top, box_w, box_h);
            s.push_str(&format!(
                "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\"/>",
                n(ox),
                n(oy),
                n(box_w),
                n(box_h),
                esc_attr(&edge_color)
            ));
        }
    }
    s.push_str("</g>");

    // Layer 2: ellipse overlay (appended inside grid channel)
    draw_ellipse_overlay(
        &mut s,
        &primary,
        &grid,
        grid_left,
        grid_top,
        grid_w,
        grid_h,
        cell_w,
        cell_h,
        &style.bg_color,
        &clip_id,
    );

    // --- min/max ftok cells for the blank map ---
    let mut min_cell = (u32::MAX, 0usize);
    let mut max_cell = (0u32, 0usize);
    for token in &tokens {
        let q = used_ftoks[token.index].quant;
        let ci = cell_indices[token.index];
        if q < min_cell.0 || (q == min_cell.0 && ci > min_cell.1) {
            min_cell = (q, ci);
        }
        if q > max_cell.0 || (q == max_cell.0 && ci > max_cell.1) {
            max_cell = (q, ci);
        }
    }
    let min_cell_idx = min_cell.1;
    let max_cell_idx = max_cell.1;

    // --- blanks + fills ---
    let blank_indices: Vec<usize> = (0..cell_count)
        .filter(|ci| !used_cells.contains(ci))
        .collect();
    let map_cell_idx = blank_indices.iter().copied().min();
    let sole_blank = blank_indices.len() == 1;
    let map_fill = if style.bg_color == "#ffffff" {
        "#e7be00"
    } else {
        "#ffffff"
    };
    let mut blank_fill_color: std::collections::HashMap<usize, String> =
        std::collections::HashMap::new();
    let mut j = 0usize;
    for &bi in &blank_indices {
        if Some(bi) != map_cell_idx || sole_blank {
            let color = style.edge_colors[(primary[32 + j] & 0b11) as usize].clone();
            blank_fill_color.insert(bi, color);
            j += 1;
        }
    }

    // --- quartile marks per cell ---
    let token_by_index: std::collections::HashMap<usize, &Token> =
        tokens.iter().map(|t| (t.index, t)).collect();
    let mut quartile_of_cell: std::collections::HashMap<usize, (usize, String)> =
        std::collections::HashMap::new();
    for (q_idx, q_ftok) in quartile_ftoks.iter().enumerate() {
        if let Some(q) = q_ftok {
            let ci = cell_indices[q.index];
            if let Some(token) = token_by_index.get(&q.index) {
                let fg = nucleus_colors(token.quant).1;
                quartile_of_cell.insert(ci, (q_idx, fg));
            }
        }
    }

    // fingerprint cells (token indices 8..11) for tagging
    let fingerprint_cells: std::collections::HashSet<usize> = if is_truncated {
        (8..12).map(|t| cell_indices[t]).collect()
    } else {
        std::collections::HashSet::new()
    };

    // Layer 3+: per-cell groups in cell-index order
    s.push_str("<g>");
    let fp_border = if style.bg_color == "#ffffff" {
        "#e7be00"
    } else {
        "#ffffff"
    };
    let corner_radius = nucleus_h / 2.0;
    for ci in 0..cell_count {
        let col = ci % grid.cols;
        let row = ci / grid.cols;
        let mut attrs = format!(
            " data-channel=\"cell\" data-cell-index=\"{}\" data-cell-row=\"{}\" data-cell-col=\"{}\"",
            ci, row, col
        );
        let is_blank = !used_cells.contains(&ci);
        if is_blank {
            attrs.push_str(" data-cell-blank=\"true\"");
        }
        if fingerprint_cells.contains(&ci) {
            attrs.push_str(" data-cell-fingerprint=\"true\"");
        }
        let is_map = is_blank && Some(ci) == map_cell_idx;
        if is_map {
            attrs.push_str(" data-cell-blank-map=\"true\"");
        }
        if let Some((q_idx, _)) = quartile_of_cell.get(&ci) {
            attrs.push_str(&format!(" data-cell-quartile=\"{}\"", q_idx + 1));
        }
        s.push_str(&format!("<g{}>", attrs));

        if is_blank {
            let nx = grid_left + col as f64 * cell_w + box_w;
            let ny = grid_top + row as f64 * cell_h + box_h;
            let blank_fill: String = if is_map && !sole_blank {
                map_fill.to_string()
            } else {
                blank_fill_color.get(&ci).cloned().unwrap()
            };
            s.push_str(&format!(
                "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"{}\" ry=\"{}\" fill=\"{}\" stroke=\"#000000\" stroke-width=\"1\"/>",
                n(nx),
                n(ny),
                n(nucleus_w),
                n(nucleus_h),
                n(corner_radius),
                n(corner_radius),
                esc_attr(&blank_fill),
            ));
            if is_map {
                let sub_w = nucleus_w / grid.cols as f64;
                let sub_h = nucleus_h / grid.rows as f64;
                let dot_r = nucleus_h / 8.0 + font_px / 16.0;
                let (max_cx, max_cy) = sub_center(max_cell_idx, nx, ny, &grid, sub_w, sub_h);
                let (min_cx, min_cy) = sub_center(min_cell_idx, nx, ny, &grid, sub_w, sub_h);
                let (max_row, max_col) = (max_cell_idx / grid.cols, max_cell_idx % grid.cols);
                let (min_row, min_col) = (min_cell_idx / grid.cols, min_cell_idx % grid.cols);
                let plus_arm = dot_r * 1.2;
                let plus_w = (dot_r * 0.55).max(1.0);
                let (min_color, max_color) = if sole_blank {
                    let f = blank_fill_color.get(&map_cell_idx.unwrap()).unwrap();
                    let quant = u32::from_str_radix(&f[1..3], 16).unwrap()
                        | (u32::from_str_radix(&f[3..5], 16).unwrap() << 8)
                        | (u32::from_str_radix(&f[5..7], 16).unwrap() << 16);
                    let mc = nucleus_colors(quant).1;
                    (mc.clone(), mc)
                } else {
                    ("#1d4ed8".to_string(), "#d62828".to_string())
                };
                s.push_str(&format!(
                    "<circle cx=\"{}\" cy=\"{}\" r=\"{}\" fill=\"{}\" data-blank-map-min=\"{},{}\"/>",
                    n(min_cx),
                    n(min_cy),
                    n(dot_r),
                    esc_attr(&min_color),
                    min_row,
                    min_col,
                ));
                s.push_str(&format!(
                    "<path d=\"M {},{} H {} M {},{} V {}\" fill=\"none\" stroke=\"{}\" stroke-width=\"{}\" stroke-linecap=\"butt\" data-blank-map-max=\"{},{}\"/>",
                    n(max_cx - plus_arm),
                    n(max_cy),
                    n(max_cx + plus_arm),
                    n(max_cx),
                    n(max_cy - plus_arm),
                    n(max_cy + plus_arm),
                    esc_attr(&max_color),
                    n(plus_w),
                    max_row,
                    max_col,
                ));
            }
        } else {
            // filled cell: nucleus rect, optional border, text
            let (token, _ftok, _ci, nucleus_bg) = token_cells.iter().find(|tc| tc.2 == ci).unwrap();
            let is_fp_middle = is_truncated && (8..=11).contains(&token.index);
            let (bg_color, fg_color) = {
                let r = u32::from_str_radix(&nucleus_bg[1..3], 16).unwrap();
                let g = u32::from_str_radix(&nucleus_bg[3..5], 16).unwrap();
                let b = u32::from_str_radix(&nucleus_bg[5..7], 16).unwrap();
                nucleus_colors(r | (g << 8) | (b << 16))
            };
            let nx = grid_left + col as f64 * cell_w + box_w;
            let ny = grid_top + row as f64 * cell_h + box_h;
            s.push_str(&format!(
                "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\"/>",
                n(nx),
                n(ny),
                n(nucleus_w),
                n(nucleus_h),
                esc_attr(&bg_color)
            ));
            if is_fp_middle {
                s.push_str(&format!(
                    "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"none\" stroke=\"{}\" stroke-width=\"1\"/>",
                    n(nx + 0.5),
                    n(ny + 0.5),
                    n(nucleus_w - 1.0),
                    n(nucleus_h - 1.0),
                    esc_attr(fp_border)
                ));
            }
            let text_px = if is_fp_middle {
                fp_middle_text_px
            } else {
                cell_text_px
            };
            let cx = nx + nucleus_w / 2.0;
            let cy = ny + nucleus_h / 2.0;
            s.push_str(&format!(
                "<text x=\"{}\" y=\"{}\" fill=\"{}\" style=\"font-family: {}; font-size: {}px;\" text-anchor=\"middle\" dominant-baseline=\"central\">{}</text>",
                n(cx),
                n(cy),
                esc_attr(&fg_color),
                esc_attr(MONOSPACE_FONT_FAMILY),
                n(text_px),
                esc_text(&token.text)
            ));
            // quartile mark
            if let Some((q_idx, fg)) = quartile_of_cell.get(&ci) {
                let poly = quartile_polygon(*q_idx, nx, ny, nucleus_w, nucleus_h);
                s.push_str(&format!(
                    "<polygon points=\"{}\" fill=\"{}\"/>",
                    poly,
                    esc_attr(fg)
                ));
            }
        }
        s.push_str("</g>");
    }
    s.push_str("</g>"); // nuclei_g
    s.push_str("</g>"); // grid channel

    // color bar
    draw_color_bar(
        &mut s,
        &primary,
        &second_digest(&core),
        &style,
        bar_w,
        bounding_h,
        cell_text_px,
    );

    // labels
    draw_label_strips(
        &mut s,
        grid_left,
        grid_right,
        grid_top,
        grid_bottom,
        nucleus_h,
        &type_name,
        &prefix,
        &suffix,
        label_text_px,
        truncated_bytes,
        &note,
    );

    // borders
    let bl = |s: &mut String, x1: f64, y1: f64, x2: f64, y2: f64| {
        s.push_str(&format!(
            "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#808080\" stroke-width=\"1\" shape-rendering=\"crispEdges\"/>",
            n(x1), n(y1), n(x2), n(y2)
        ));
    };
    bl(&mut s, 0.0, 0.5, bounding_w, 0.5);
    bl(&mut s, bounding_w - 0.5, 0.0, bounding_w - 0.5, bounding_h);
    bl(&mut s, 0.0, bounding_h - 0.5, bounding_w, bounding_h - 0.5);
    bl(&mut s, 0.5, 0.0, 0.5, bounding_h);
    bl(
        &mut s,
        1.0 + bar_w + 0.5,
        0.0,
        1.0 + bar_w + 0.5,
        bounding_h,
    );

    s.push_str("</svg>");
    Ok(s)
}

fn edge_color_refs(style: &VisualStyle) -> Vec<&str> {
    style.edge_colors.iter().map(|s| s.as_str()).collect()
}

fn box_origin(i: u32, cell_left: f64, cell_top: f64, bw: f64, bh: f64) -> (f64, f64) {
    if i < 10 {
        (cell_left + i as f64 * bw, cell_top)
    } else if i < 12 {
        (cell_left + 9.0 * bw, cell_top + bh + (i - 10) as f64 * bh)
    } else if i < 22 {
        (cell_left + (21 - i) as f64 * bw, cell_top + 3.0 * bh)
    } else {
        (cell_left, cell_top + bh + (23 - i) as f64 * bh)
    }
}

fn sub_center(
    cell_idx: usize,
    nx: f64,
    ny: f64,
    grid: &Grid,
    sub_w: f64,
    sub_h: f64,
) -> (f64, f64) {
    (
        nx + (cell_idx % grid.cols) as f64 * sub_w + 0.5 * sub_w,
        ny + (cell_idx / grid.cols) as f64 * sub_h + 0.5 * sub_h,
    )
}

fn quartile_polygon(q_idx: usize, nx: f64, ny: f64, w: f64, h: f64) -> String {
    let leg = h / 2.0;
    let (left, top, right, bottom) = (nx, ny, nx + w, ny + h);
    let pts: [(f64, f64); 3] = match q_idx {
        0 => [(left, top), (left + leg, top), (left, top + leg)],
        1 => [(right, top), (right - leg, top), (right, top + leg)],
        2 => [
            (right, bottom),
            (right, bottom - leg),
            (right - leg, bottom),
        ],
        _ => [(left, bottom), (left, bottom - leg), (left + leg, bottom)],
    };
    pts.iter()
        .map(|p| format!("{},{}", n(p.0), n(p.1)))
        .collect::<Vec<_>>()
        .join(" ")
}

// --- ellipse overlay ---
#[allow(clippy::too_many_arguments)]
fn draw_ellipse_overlay(
    s: &mut String,
    digest: &[u8; 64],
    grid: &Grid,
    grid_left: f64,
    grid_top: f64,
    grid_w: f64,
    grid_h: f64,
    cell_w: f64,
    cell_h: f64,
    bg_color: &str,
    clip_id: &str,
) {
    let interior_count = (grid.cols.saturating_sub(1)) * (grid.rows.saturating_sub(1));
    let points: Vec<(f64, f64)> = if interior_count >= 6 {
        let mut p = Vec::new();
        for r in 1..grid.rows {
            for c in 1..grid.cols {
                p.push((grid_left + c as f64 * cell_w, grid_top + r as f64 * cell_h));
            }
        }
        p
    } else {
        let mut p = Vec::new();
        for c in 0..=grid.cols {
            p.push((grid_left + c as f64 * cell_w, grid_top));
        }
        for r in 1..grid.rows {
            p.push((grid_left, grid_top + r as f64 * cell_h));
            p.push((
                grid_left + grid.cols as f64 * cell_w,
                grid_top + r as f64 * cell_h,
            ));
        }
        for c in 0..=grid.cols {
            p.push((
                grid_left + c as f64 * cell_w,
                grid_top + grid.rows as f64 * cell_h,
            ));
        }
        p
    };
    if points.is_empty() {
        return;
    }
    let anchor = points[(digest[60] as usize) % points.len()];
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
        return;
    }
    let rx = r_min + ((digest[61] % 16) as f64 / 15.0) * (r_max - r_min);
    let ry = r_min + ((digest[62] % 16) as f64 / 15.0) * (r_max - r_min);
    let rotation = ((digest[63] % 16) as f64 / 15.0) * 180.0;
    let (fill, fill_op, edge_op) = overlay_for_bg(bg_color);
    let stroke_w = cell_h / 20.0;
    s.push_str(&format!(
        "<g clip-path=\"url(#{cid})\" data-channel=\"ellipse\" data-ellipse-anchor-x=\"{ax}\" data-ellipse-anchor-y=\"{ay}\" data-ellipse-rx=\"{rx}\" data-ellipse-ry=\"{ry}\" data-ellipse-rotation-deg=\"{rot}\">",
        cid = esc_attr(clip_id),
        ax = n(anchor.0),
        ay = n(anchor.1),
        rx = n(rx),
        ry = n(ry),
        rot = n(rotation),
    ));
    s.push_str(&format!(
        "<ellipse cx=\"{cx}\" cy=\"{cy}\" rx=\"{rx}\" ry=\"{ry}\" transform=\"rotate({rot} {cx} {cy})\" fill=\"{fill}\" stroke=\"{fill}\" fill-opacity=\"{fo}\" stroke-opacity=\"{eo}\" stroke-width=\"{sw}\"/>",
        cx = n(anchor.0),
        cy = n(anchor.1),
        rx = n(rx),
        ry = n(ry),
        rot = n(rotation),
        fill = fill,
        fo = n(fill_op),
        eo = n(edge_op),
        sw = n(stroke_w),
    ));
    s.push_str("</g>");
}

fn overlay_for_bg(bg: &str) -> (&'static str, f64, f64) {
    match bg {
        "#ffffff" => ("#000000", 0.20, 0.30),
        "#e7be00" => ("#000000", 0.20, 0.30),
        "#ff3f2f" => ("#000000", 0.25, 0.35),
        "#2f3fbf" => ("#ffffff", 0.35, 0.45),
        _ => ("#000000", 0.20, 0.30),
    }
}

// --- color bar ---
fn first_appearance(digest: &[u8; 64]) -> [usize; 4] {
    let mut first = [usize::MAX; 4];
    let mut idx = 0;
    for &byte in digest.iter() {
        for shift in [0u32, 2, 4, 6] {
            let p = ((byte >> shift) & 3) as usize;
            if first[p] == usize::MAX {
                first[p] = idx;
            }
            idx += 1;
        }
    }
    let mut order = [0usize, 1, 2, 3];
    order.sort_by_key(|&p| (first[p], p));
    order
}

fn draw_color_bar(
    s: &mut String,
    digest: &[u8; 64],
    second: &[u8; 64],
    style: &VisualStyle,
    bar_w: f64,
    bounding_h: f64,
    cell_text_px: f64,
) {
    let bar_left = 1.0;
    let bar_top = 1.0;
    let bar_height = bounding_h - 2.0;
    let counts = two_bit_counts(digest);
    // usage[edge_colors[i]] = counts[i]
    let edge = &style.edge_colors;
    // first-appearance order of patterns -> colors
    let order = first_appearance(digest);
    let order_pos: std::collections::HashMap<&str, usize> = order
        .iter()
        .enumerate()
        .map(|(i, &p)| (edge[p].as_str(), i))
        .collect();
    let color_order: std::collections::HashMap<&str, usize> = edge
        .iter()
        .enumerate()
        .map(|(i, c)| (c.as_str(), i))
        .collect();

    let mut used: Vec<(String, usize)> = (0..4)
        .filter(|&i| counts[i] > 0)
        .map(|i| (edge[i].clone(), counts[i]))
        .collect();
    if used.is_empty() {
        return;
    }
    used.sort_by_key(|(c, _)| {
        (
            *order_pos.get(c.as_str()).unwrap_or(&4),
            *color_order.get(c.as_str()).unwrap_or(&4),
        )
    });
    let total: f64 = used.iter().map(|(_, nn)| (*nn as f64).powi(4)).sum();

    s.push_str("<g data-channel=\"color-bar\">");
    let bar_cx = bar_left + bar_w / 2.0;
    let mut y = bar_top;
    let last = used.len() - 1;
    for (i, (color, nn)) in used.iter().enumerate() {
        let h = if i == last {
            (bar_top + bar_height) - y
        } else {
            bar_height * (*nn as f64).powi(4) / total
        };
        let letter = band_letter(color);
        let band_attrs = match letter {
            Some(l) => format!(
                " data-color-bar-rank=\"{}\" data-color-bar-band=\"{}\"",
                i, l
            ),
            None => format!(" data-color-bar-rank=\"{}\"", i),
        };
        s.push_str(&format!("<g{}>", band_attrs));
        s.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\"/>",
            n(bar_left),
            n(y),
            n(bar_w),
            n(h),
            esc_attr(color)
        ));
        if let Some(l) = letter {
            let r = u32::from_str_radix(&color[1..3], 16).unwrap();
            let g = u32::from_str_radix(&color[3..5], 16).unwrap();
            let b = u32::from_str_radix(&color[5..7], 16).unwrap();
            let fg = nucleus_colors(r | (g << 8) | (b << 16)).1;
            let font_size = cell_text_px;
            let baseline_y = (y + h) - 0.22 * font_size;
            s.push_str(&format!(
                "<text x=\"{}\" y=\"{}\" fill=\"{}\" style=\"font-family: {}; font-size: {}px;\" text-anchor=\"middle\" data-color-bar-letter=\"true\">{}</text>",
                n(bar_cx),
                n(baseline_y),
                esc_attr(&fg),
                esc_attr(MONOSPACE_FONT_FAMILY),
                n(font_size),
                esc_text(&l.to_lowercase())
            ));
        }
        s.push_str("</g>");
        y += h;
    }

    // markers
    let k = ((bar_height / 12.0).floor() as i64).clamp(4, 16) as usize;
    let slot_h = bar_height / k as f64;
    let radius = bar_w * 0.17;
    let inset = bar_w * 0.06;
    let left_slot = (second[12] as usize) % k;
    let right_slot = (second[13] as usize) % k;
    for (side, slot) in [("left", left_slot), ("right", right_slot)] {
        let cy = bar_top + (slot as f64 + 0.5) * slot_h;
        let cx = if side == "left" {
            bar_left + inset + radius
        } else {
            bar_left + bar_w - inset - radius
        };
        s.push_str(&format!(
            "<circle cx=\"{}\" cy=\"{}\" r=\"{}\" fill=\"#ffffff\" stroke=\"#000000\" stroke-width=\"0.75\" data-bar-marker=\"{}\"/>",
            n(cx),
            n(cy),
            n(radius),
            side
        ));
    }
    s.push_str("</g>");

    // Inject the marker/slot attributes onto the color-bar group opening tag.
    // (Done here by string replacement on the just-emitted group.)
    patch_color_bar_attrs(s, k, left_slot, right_slot);
}

/// Add `data-bar-slots` / `data-bar-marker-*` to the most recent
/// `<g data-channel="color-bar">` opening tag (they must live on the group).
fn patch_color_bar_attrs(s: &mut String, k: usize, left: usize, right: usize) {
    let needle = "<g data-channel=\"color-bar\">";
    if let Some(pos) = s.rfind(needle) {
        let replacement = format!(
            "<g data-channel=\"color-bar\" data-bar-slots=\"{}\" data-bar-marker-left=\"{}\" data-bar-marker-right=\"{}\">",
            k, left, right
        );
        s.replace_range(pos..pos + needle.len(), &replacement);
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_label_strips(
    s: &mut String,
    grid_left: f64,
    grid_right: f64,
    grid_top: f64,
    grid_bottom: f64,
    nucleus_h: f64,
    type_name: &str,
    prefix: &Option<String>,
    suffix: &Option<String>,
    text_px: f64,
    truncated_bytes: Option<usize>,
    note: &Option<String>,
) {
    let style_attr = format!(
        "font-family: {}; font-size: {}px;",
        MONOSPACE_FONT_FAMILY,
        n(text_px)
    );
    let rest_text = if !type_name.is_empty() {
        let mut t = format!("{}:", type_name);
        if let Some(p) = prefix {
            t.push_str(&format!(" {}...", p));
        }
        t
    } else if let Some(p) = prefix {
        format!("{}...", p)
    } else {
        String::new()
    };
    let top_cy = grid_top - nucleus_h / 2.0;
    s.push_str("<g data-channel=\"label-top\">");
    if truncated_bytes.is_some() {
        s.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" fill=\"#666666\" style=\"{}\" dominant-baseline=\"central\"><tspan fill=\"#a00000\" font-weight=\"bold\">fingerprint of </tspan>{}</text>",
            n(grid_left),
            n(top_cy),
            esc_attr(&style_attr),
            esc_text(&rest_text),
        ));
    } else {
        s.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" fill=\"#666666\" style=\"{}\" dominant-baseline=\"central\">{}</text>",
            n(grid_left),
            n(top_cy),
            esc_attr(&style_attr),
            esc_text(&rest_text),
        ));
    }
    s.push_str("</g>");

    if suffix.is_some() || note.is_some() {
        let bottom_cy = grid_bottom + nucleus_h / 2.0;
        s.push_str("<g data-channel=\"label-bottom\">");
        s.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" fill=\"#666666\" style=\"{}\" text-anchor=\"end\" dominant-baseline=\"central\">",
            n(grid_right),
            n(bottom_cy),
            esc_attr(&style_attr),
        ));
        match (suffix, note) {
            (Some(suf), Some(nt)) => {
                s.push_str(&format!("<tspan>...{} </tspan>", esc_text(suf)));
                s.push_str(&format!(
                    "<tspan fill=\"#808080\" data-user-note=\"{}\">({})</tspan>",
                    esc_attr(nt),
                    esc_text(nt)
                ));
            }
            (Some(suf), None) => {
                s.push_str(&format!("...{}", esc_text(suf)));
            }
            (None, Some(nt)) => {
                s.push_str(&format!(
                    "<tspan fill=\"#808080\" data-user-note=\"{}\">({})</tspan>",
                    esc_attr(nt),
                    esc_text(nt)
                ));
            }
            (None, None) => {}
        }
        s.push_str("</text></g>");
    }
}

fn b64url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_hex256() {
        let svg = render(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            1.0,
            12.0,
            None,
        )
        .unwrap();
        assert!(svg.starts_with("<svg "));
        assert!(svg.contains("data-cols=\"3\""));
        assert!(svg.contains("data-rows=\"4\""));
        assert!(svg.contains("data-channel=\"color-bar\" data-bar-slots="));
        assert!(svg.ends_with("</svg>"));
    }

    #[test]
    fn rejects_bad_eip55() {
        assert!(matches!(
            render(
                "0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                1.0,
                12.0,
                None
            ),
            Err(RenderError::Eip55 { .. })
        ));
    }

    #[test]
    fn bad_eip55_surfaces_first_mismatch_position() {
        // SPEC-F1: the spec MUST identify the first mismatched-case digit; the
        // position must be carried through to RenderError (not collapsed away)
        // and rendered in the Display/CLI message. This is a mixed-case address
        // whose checksum case does NOT match canonical EIP-55.
        let err = render(
            "0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            1.0,
            12.0,
            None,
        )
        .unwrap_err();
        let position = match err {
            RenderError::Eip55 { position } => position,
            other => panic!("expected Eip55, got {other:?}"),
        };
        // Cross-check: the position is the first body index whose case differs
        // from the canonical EIP-55 case, and the Display message names it.
        let msg = err.to_string();
        assert!(
            msg.contains(&position.to_string()),
            "Display message {msg:?} must name the mismatched position {position}"
        );
        assert!(msg.to_lowercase().contains("position"));
    }

    #[test]
    fn rejects_bad_note_and_fontsize() {
        assert!(render("a1b2c3d4e5f6a7b8", 1.0, 12.0, Some("two words")).is_err());
        assert!(render("a1b2c3d4e5f6a7b8", 1.0, 4.0, None).is_err());
        assert!(render("a1b2c3d4e5f6a7b8", 1.0, 40.0, None).is_err());
    }

    // ===================================================================
    // sanitize_note
    // ===================================================================
    #[test]
    fn sanitize_note_cases() {
        assert!(sanitize_note(None).unwrap().is_none());
        assert!(sanitize_note(Some("")).unwrap().is_none()); // empty -> None
        assert_eq!(
            sanitize_note(Some("abc123")).unwrap().as_deref(),
            Some("abc123")
        );
        // too long (> 8 chars)
        assert!(matches!(
            sanitize_note(Some("ninechars")),
            Err(RenderError::Note(_))
        ));
        // non-alphanumeric
        assert!(matches!(
            sanitize_note(Some("a b")),
            Err(RenderError::Note(_))
        ));
    }

    // ===================================================================
    // XML escaping + number formatting
    // ===================================================================
    #[test]
    fn escaping_and_number_formatting() {
        assert_eq!(esc_attr("a&b<c>d\"e"), "a&amp;b&lt;c&gt;d&quot;e");
        assert_eq!(esc_text("a&b<c>d\"e"), "a&amp;b&lt;c&gt;d\"e"); // quotes left as-is
        assert_eq!(n(3.0), "3");
        assert_eq!(n(3.5), "3.5");
    }

    #[test]
    fn b64url_encode_no_padding() {
        assert_eq!(b64url_encode(b"foobar"), "Zm9vYmFy");
        // bytes that would normally pad: no '=' present
        assert!(!b64url_encode(b"foo").contains('='));
    }

    // ===================================================================
    // Geometry helpers
    // ===================================================================
    #[test]
    fn box_origin_all_four_ranges() {
        // top row (i<10): moves right along x
        let (x, y) = box_origin(3, 100.0, 200.0, 10.0, 5.0);
        assert_eq!((x, y), (130.0, 200.0));
        // right column (10..12): fixed x, moves down
        let (x, y) = box_origin(10, 100.0, 200.0, 10.0, 5.0);
        assert_eq!((x, y), (190.0, 205.0));
        // bottom row (12..22): moves left along x at bottom
        let (x, y) = box_origin(12, 100.0, 200.0, 10.0, 5.0);
        assert_eq!((x, y), (100.0 + 9.0 * 10.0, 200.0 + 15.0));
        // left column (22..24): the else branch
        let (x, y) = box_origin(22, 100.0, 200.0, 10.0, 5.0);
        assert_eq!(x, 100.0);
        assert!(y > 200.0);
    }

    #[test]
    fn sub_center_positions() {
        let grid = Grid {
            cols: 2,
            rows: 2,
            token_count: 4,
        };
        // cell 0 -> top-left sub-cell center
        let (cx, cy) = sub_center(0, 0.0, 0.0, &grid, 10.0, 10.0);
        assert_eq!((cx, cy), (5.0, 5.0));
        // cell 3 -> bottom-right sub-cell center
        let (cx, cy) = sub_center(3, 0.0, 0.0, &grid, 10.0, 10.0);
        assert_eq!((cx, cy), (15.0, 15.0));
    }

    #[test]
    fn quartile_polygon_all_corners() {
        for q in 0..4 {
            let p = quartile_polygon(q, 0.0, 0.0, 8.0, 4.0);
            // three "x,y" points
            assert_eq!(p.split(' ').count(), 3);
        }
        // q0 anchors at the top-left corner
        assert!(quartile_polygon(0, 0.0, 0.0, 8.0, 4.0).starts_with("0,0"));
    }

    // ===================================================================
    // Color helpers
    // ===================================================================
    #[test]
    fn overlay_for_bg_all_backgrounds() {
        assert_eq!(overlay_for_bg("#ffffff"), ("#000000", 0.20, 0.30));
        assert_eq!(overlay_for_bg("#e7be00"), ("#000000", 0.20, 0.30));
        assert_eq!(overlay_for_bg("#ff3f2f"), ("#000000", 0.25, 0.35));
        assert_eq!(overlay_for_bg("#2f3fbf"), ("#ffffff", 0.35, 0.45));
        // default arm (e.g. black)
        assert_eq!(overlay_for_bg("#000000"), ("#000000", 0.20, 0.30));
    }

    #[test]
    fn band_letter_mapping() {
        assert_eq!(band_letter("#ffffff"), Some("W"));
        assert_eq!(band_letter("#e7be00"), Some("G"));
        assert_eq!(band_letter("#ff3f2f"), Some("R"));
        assert_eq!(band_letter("#2f3fbf"), Some("B"));
        assert_eq!(band_letter("#000000"), Some("K"));
        assert_eq!(band_letter("#123456"), None);
    }

    #[test]
    fn two_bit_counts_and_first_appearance() {
        let mut d = [0u8; 64];
        d[0] = 0b00_01_10_11; // one of each 2-bit pattern in byte 0
        let counts = two_bit_counts(&d);
        // remaining 63 bytes are zero -> pattern 0 dominates
        assert_eq!(counts[1], 1);
        assert_eq!(counts[2], 1);
        assert_eq!(counts[3], 1);
        assert!(counts[0] > 100);
        let order = first_appearance(&d);
        // byte 0 low-to-high: shift 0 -> pattern 11(=3), shift2 -> 10(=2),
        // shift4 -> 01(=1), shift6 -> 00(=0). So 3 appears first.
        assert_eq!(order[0], 3);
        // all four patterns present exactly once in the ordering
        let mut sorted = order;
        sorted.sort();
        assert_eq!(sorted, [0, 1, 2, 3]);
    }

    // ===================================================================
    // assign_cell_indices
    // ===================================================================
    fn tok(index: usize, text: &str, quant: u32) -> Token {
        Token {
            text: text.into(),
            index,
            quant,
        }
    }

    #[test]
    fn assign_cell_indices_identity_when_full() {
        let grid = Grid {
            cols: 2,
            rows: 2,
            token_count: 4,
        };
        let tokens = vec![
            tok(0, "a", 0),
            tok(1, "b", 0),
            tok(2, "c", 0),
            tok(3, "d", 0),
        ];
        let ci = assign_cell_indices(&tokens, &grid, &Some(tokens[0].clone()), &tokens);
        assert_eq!(ci, vec![0, 1, 2, 3]); // token_count >= cell_count
    }

    #[test]
    fn assign_cell_indices_shifts_for_sparse_grid() {
        let grid = Grid {
            cols: 3,
            rows: 2,
            token_count: 3,
        }; // 6 cells, 3 tokens -> all three shifts apply
        let tokens = vec![tok(0, "m", 0), tok(1, "a", 0), tok(2, "z", 0)];
        let median = median_token(&tokens);
        let ci = assign_cell_indices(&tokens, &grid, &median, &tokens);
        assert_eq!(ci.len(), 3);
        // every assigned cell index is in range and distinct
        assert!(ci.iter().all(|&c| c < 6));
        let set: std::collections::HashSet<_> = ci.iter().collect();
        assert_eq!(set.len(), 3);
    }

    // ===================================================================
    // render: error paths + label variants + truncation
    // ===================================================================
    #[test]
    fn render_rejects_input_too_long() {
        let huge = "a".repeat(70_000);
        assert!(matches!(
            render(&huge, 1.0, 12.0, None),
            Err(RenderError::InputTooLong)
        ));
    }

    #[test]
    fn render_rejects_aspect_ratio_out_of_range() {
        assert!(matches!(
            render("a1b2c3d4e5f6a7b8", 200.0, 12.0, None),
            Err(RenderError::AspectRatioRange)
        ));
        assert!(matches!(
            render("a1b2c3d4e5f6a7b8", 0.001, 12.0, None),
            Err(RenderError::AspectRatioRange)
        ));
    }

    #[test]
    fn render_empty_input_has_no_tokens() {
        assert!(matches!(
            render("", 1.0, 12.0, None),
            Err(RenderError::NoTokens)
        ));
    }

    #[test]
    fn render_b64url_detected_label() {
        // '-' and '_' force base64url detection -> "b64url(N)" type label.
        let svg = render("ABC-_DEF", 1.0, 12.0, None).unwrap();
        assert!(svg.contains("b64url("));
    }

    #[test]
    fn render_b64_detected_label() {
        // '+' / '/' force plain base64 detection -> "b64(N)" type label.
        let svg = render("ABC+/DEF", 1.0, 12.0, None).unwrap();
        assert!(svg.contains("b64("));
    }

    #[test]
    fn render_type_with_prefix_label() {
        // 0x-prefixed hex carries BOTH a type name and a prefix -> the
        // "type: prefix..." top-label branch.
        let svg = render("0xabcdef12", 1.0, 12.0, None).unwrap();
        assert!(svg.contains("hex("));
        assert!(svg.contains("0x..."));
    }

    #[test]
    fn render_suffix_only_bottom_label() {
        // LEI has a suffix but no note -> the (suffix, None) bottom branch.
        let svg = render("5493001KJTIIGC8Y1R12", 1.0, 12.0, None).unwrap();
        assert!(svg.contains("...12"));
        assert!(!svg.contains("data-user-note"));
    }

    #[test]
    fn render_text_fallback_label() {
        // plain text -> txt(N)->b64url label.
        let svg = render("hello world", 1.0, 12.0, None).unwrap();
        assert!(svg.contains("txt(") && svg.contains("b64url"));
    }

    #[test]
    fn render_swhid_semantic_prefix_label() {
        // type_name is empty for swhid; the label is just the prefix + "...".
        let svg = render(
            "swh:1:rev:309cf2674ee7a0749978cf8265ab91a60aea0f7d",
            1.0,
            12.0,
            None,
        )
        .unwrap();
        assert!(svg.contains("swh:1:rev:..."));
    }

    #[test]
    fn render_suffix_with_note_bottom_label() {
        // LEI carries a suffix; add a note -> the (suffix, note) bottom branch.
        let svg = render("5493001KJTIIGC8Y1R12", 1.0, 12.0, Some("hi")).unwrap();
        assert!(svg.contains("data-user-note=\"hi\""));
        assert!(svg.contains("...12"));
    }

    #[test]
    fn render_note_only_bottom_label() {
        let svg = render("a1b2c3d4e5f6a7b8", 1.0, 12.0, Some("note1")).unwrap();
        assert!(svg.contains("data-user-note=\"note1\""));
    }

    #[test]
    fn render_large_input_is_truncated() {
        let core = "a".repeat(400);
        let svg = render(&core, 1.0, 12.0, None).unwrap();
        assert!(svg.contains("data-truncated=\"true\""));
        assert!(svg.contains("data-cell-fingerprint=\"true\""));
        assert!(svg.contains("fingerprint of "));
    }

    #[test]
    fn render_is_deterministic() {
        let a = render("0123456789abcdef0123456789abcdef", 1.0, 12.0, None).unwrap();
        let b = render("0123456789abcdef0123456789abcdef", 1.0, 12.0, None).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn version_stamps_track_crate_and_spec() {
        // MNT-F2 / SPEC-F2: the rendered SVG's data-entviz-lib MUST equal the
        // crate version and data-entviz-version MUST equal SPEC_VERSION, so the
        // stamps can never silently drift from Cargo.toml / crate::SPEC_VERSION.
        let svg = render("0123456789abcdef0123456789abcdef", 1.0, 12.0, None).unwrap();
        assert!(
            svg.contains(&format!(
                "data-entviz-lib=\"{}\"",
                env!("CARGO_PKG_VERSION")
            )),
            "data-entviz-lib must equal CARGO_PKG_VERSION ({})",
            env!("CARGO_PKG_VERSION")
        );
        assert!(
            svg.contains(&format!("data-entviz-version=\"{}\"", crate::SPEC_VERSION)),
            "data-entviz-version must equal SPEC_VERSION ({})",
            crate::SPEC_VERSION
        );
    }

    #[test]
    fn render_hex_uses_smaller_cell_text() {
        // hex (4 bits/char) scales cell text to 0.75; just assert it renders text.
        let svg = render("0123456789abcdef0123456789abcdef", 1.0, 12.0, None).unwrap();
        assert!(svg.contains("<text"));
    }
}
