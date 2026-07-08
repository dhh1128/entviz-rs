//! entviz — Rust reference port (spec v13).
//!
//! **STATUS: CERTIFIED v13.** This crate is a full, self-contained entviz
//! implementation: the deterministic shared core (tokenization + quant
//! extension, the SHA-512 fingerprint, ftok median/quartile selection, the
//! Oklab color rules, grid selection), the format-specific parsers
//! ([`entropy`]), and the SVG renderer ([`pipeline::render`]). It passes the
//! shared conformance corpus at **Tier A (render model) + Tier B (canonical
//! raster)** for every render vector, rejects every error vector, and satisfies
//! every invariant pair. Certify with:
//!
//! ```sh
//! cargo build --release --bin entviz-conformance
//! # from the entviz repo:
//! PYTHONPATH=src:. python -m compliance.runner \
//!     --impl-cmd '/path/to/entviz-rs/target/release/entviz-conformance'
//! ```
//!
//! The `entviz-conformance` binary (`src/main.rs`) implements the stdin/stdout
//! contract in the entviz repo's `compliance/README.md`.

use base64::Engine;
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;

pub const SPEC_VERSION: &str = "v13";

pub mod characterize;
pub mod entropy;
pub mod keccak;
pub mod pipeline;
mod util;

// The render-model / feature-vector layer exists only to serve the private
// adversarial grinder (entviz-adversarial), which path-depends on this crate.
// It is NOT part of the public reference implementation: gated behind the
// off-by-default `adversarial` feature and excluded from the published crate
// (see Cargo.toml). Building the grinder enables `--features adversarial`.
#[cfg(feature = "adversarial")]
pub mod model;

// --------------------------------------------------------------------------
// Alphabets
// --------------------------------------------------------------------------
#[derive(Clone, Copy, Debug)]
pub struct Alphabet {
    pub name: &'static str,
    pub chars: &'static str,
    pub bits_per_char: u32,
}

pub const HEX: Alphabet = Alphabet {
    name: "hex",
    chars: "0123456789ABCDEF",
    bits_per_char: 4,
};
pub const BASE64URL: Alphabet = Alphabet {
    name: "base64url",
    chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    bits_per_char: 6,
};

// --------------------------------------------------------------------------
// Tokens + quant extension
// --------------------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct Token {
    pub text: String,
    pub index: usize,
    pub quant: u32,
}

fn char_value(chars: &str, ch: char, bits_per_char: u32) -> i32 {
    if let Some(i) = chars.find(ch) {
        return i as i32;
    }
    let lower = chars.to_lowercase();
    if let Some(i) = lower.find(ch.to_ascii_lowercase()) {
        return i as i32;
    }
    if bits_per_char == 6 {
        match ch {
            '-' | '+' => return 62,
            '_' | '/' => return 63,
            _ => {}
        }
    }
    -1
}

pub fn tokenize(text: &str, alphabet: &Alphabet) -> Vec<Token> {
    let bits = alphabet.bits_per_char;
    let token_len = (24 / bits) as usize;
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let end = (i + token_len).min(chars.len());
        let chunk: String = chars[i..end].iter().collect();
        i = end;
        if chunk.is_empty() {
            continue;
        }
        let mut val: u32 = 0;
        let mut actual_bits: u32 = 0;
        for ch in chunk.chars() {
            let mut cv = char_value(alphabet.chars, ch, bits);
            if cv == -1 {
                cv = 0;
            }
            val = (val << bits) | (cv as u32);
            actual_bits += bits;
        }
        let mut quant = val;
        if actual_bits > 0 && actual_bits < 24 {
            while actual_bits < 24 {
                let shift = actual_bits.min(24 - actual_bits);
                let mask = (1u32 << shift) - 1;
                let add = quant & mask;
                quant = (quant << shift) | add;
                actual_bits += shift;
            }
        } else if actual_bits > 24 {
            quant = val & 0xFFFFFF;
        }
        let index = tokens.len();
        tokens.push(Token {
            text: chunk,
            index,
            quant: quant & 0xFFFFFF,
        });
    }
    tokens
}

// --------------------------------------------------------------------------
// Fingerprint
// --------------------------------------------------------------------------
pub fn compute_fingerprint(core: &str) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(core.as_bytes());
    let out = hasher.finalize();
    let mut digest = [0u8; 64];
    digest.copy_from_slice(&out);
    digest
}

pub fn tokenize_fingerprint(digest: &[u8; 64]) -> Vec<Token> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    let toks = tokenize(&b64, &BASE64URL);
    assert_eq!(toks.len(), 22, "expected 22 ftoks");
    toks
}

/// Domain tag for the second, domain-separated digest. The trailing NUL is
/// included. `v6` is the *construction* version (fixed), NOT the spec version.
///
/// FREEZE: this byte string is part of the on-the-wire fingerprint construction.
/// It MUST NOT be bumped during a spec-version upgrade (e.g. v10 -> v11). The
/// `v6` here is decoupled from `SPEC_VERSION` on purpose: changing a single byte
/// re-keys `second_digest` and therefore silently changes the color-bar markers
/// on every input AND the middle cells of every large (>512-bit) input — every
/// previously-rendered large-input fingerprint would change. Do not "tidy" it to
/// match the spec version; treat it as a frozen magic constant.
pub const MIDDLE_DOMAIN_TAG: &[u8] = b"entviz/fingerprint-middle/v6\x00";

/// `second = SHA-512(DOMAIN_TAG ‖ core)`. Computed for every input (v9): drives
/// the two color-bar markers on all inputs (and the middle cells on large ones).
/// A legitimate part of the renderer — not adversarial tooling.
pub fn second_digest(core: &str) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(MIDDLE_DOMAIN_TAG);
    h.update(core.as_bytes());
    let out = h.finalize();
    let mut d = [0u8; 64];
    d.copy_from_slice(&out);
    d
}

// --------------------------------------------------------------------------
// Median / quartile selection (ASCII bytewise sort)
// --------------------------------------------------------------------------
pub fn median_token(tokens: &[Token]) -> Option<Token> {
    if tokens.is_empty() {
        return None;
    }
    let mut s: Vec<&Token> = tokens.iter().collect();
    s.sort_by(|a, b| a.text.cmp(&b.text).then(a.index.cmp(&b.index)));
    let mid = (s.len() - 1) / 2;
    Some(s[mid].clone())
}

pub fn quartile_tokens(tokens: &[Token]) -> Vec<Option<Token>> {
    if tokens.is_empty() {
        return vec![None, None, None, None];
    }
    let rev = |t: &Token| -> String { t.text.chars().rev().collect() };
    let mut s: Vec<&Token> = tokens.iter().collect();
    s.sort_by(|a, b| rev(a).cmp(&rev(b)).then(a.index.cmp(&b.index)));
    let q_size = s.len().div_ceil(4); // ceil(n/4)
    (0..4)
        .map(|i| {
            let idx = i * q_size;
            if idx < s.len() {
                Some(s[idx].clone())
            } else {
                None
            }
        })
        .collect()
}

// --------------------------------------------------------------------------
// Colors (Oklab)
// --------------------------------------------------------------------------
pub const POSSIBLE_EDGE_COLORS: [&str; 5] = ["#ffffff", "#e7be00", "#ff3f2f", "#2f3fbf", "#000000"];

fn srgb_to_linear(c: f64) -> f64 {
    if c <= 0.04045 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

pub fn oklab_lightness(r: u8, g: u8, b: u8) -> f64 {
    let rl = srgb_to_linear(r as f64 / 255.0);
    let gl = srgb_to_linear(g as f64 / 255.0);
    let bl = srgb_to_linear(b as f64 / 255.0);
    let l = 0.4122214708 * rl + 0.5363325363 * gl + 0.0514459929 * bl;
    let m = 0.2119034982 * rl + 0.6806995451 * gl + 0.1073969566 * bl;
    let s = 0.0883024619 * rl + 0.2817188376 * gl + 0.6299787005 * bl;
    0.2104542553 * l.cbrt() + 0.793617785 * m.cbrt() - 0.0040720468 * s.cbrt()
}

const OKLAB_THRESHOLD: f64 = 0.6;

/// Returns (bg_hex, fg_hex). Red is the low byte of the quant (CSS order).
pub fn nucleus_colors(quant: u32) -> (String, String) {
    let r = (quant & 0xFF) as u8;
    let g = ((quant >> 8) & 0xFF) as u8;
    let b = ((quant >> 16) & 0xFF) as u8;
    let bg = format!("#{:02x}{:02x}{:02x}", r, g, b);
    let fg = if oklab_lightness(r, g, b) < OKLAB_THRESHOLD {
        "#ffffff"
    } else {
        "#000000"
    };
    (bg, fg.to_string())
}

fn hex_to_rgb(h: &str) -> (i64, i64, i64) {
    let r = i64::from_str_radix(&h[1..3], 16).unwrap();
    let g = i64::from_str_radix(&h[3..5], 16).unwrap();
    let b = i64::from_str_radix(&h[5..7], 16).unwrap();
    (r, g, b)
}

pub fn weighted_rgb_distance(c1: &str, c2: &str) -> f64 {
    let (r1, g1, b1) = hex_to_rgb(c1);
    let (r2, g2, b2) = hex_to_rgb(c2);
    ((2 * (r1 - r2).pow(2) + 4 * (g1 - g2).pow(2) + 3 * (b1 - b2).pow(2)) as f64).sqrt()
}

pub fn closest_palette_color<'a>(target: &str, palette: &[&'a str]) -> &'a str {
    let mut best = palette[0];
    let mut best_d = f64::INFINITY;
    for &c in palette {
        let d = weighted_rgb_distance(c, target);
        if d < best_d {
            best_d = d;
            best = c;
        }
    }
    best
}

pub struct VisualStyle {
    pub bg_color: String,
    pub edge_colors: Vec<String>,
}

pub fn select_visual_style(median_ftok: &Token) -> VisualStyle {
    let idx = (median_ftok.quant & 0x03) as usize;
    let bg_color = POSSIBLE_EDGE_COLORS[idx].to_string();
    let edge_colors = POSSIBLE_EDGE_COLORS
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != idx)
        .map(|(_, c)| c.to_string())
        .collect();
    VisualStyle {
        bg_color,
        edge_colors,
    }
}

// --------------------------------------------------------------------------
// Grid selection
// --------------------------------------------------------------------------
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Grid {
    pub cols: usize,
    pub rows: usize,
    pub token_count: usize,
}

pub fn choose_grid(token_count: usize, target_ar: f64) -> Grid {
    let mut tightest: BTreeMap<usize, usize> = BTreeMap::new();
    let mut cols = 2;
    while cols <= token_count {
        let rows = token_count.div_ceil(cols); // ceil
        if rows >= 2 {
            tightest
                .entry(rows)
                .and_modify(|c| {
                    if cols < *c {
                        *c = cols;
                    }
                })
                .or_insert(cols);
        }
        cols += 1;
    }
    let candidates: Vec<(usize, usize, f64)> = tightest
        .iter()
        .map(|(&rows, &cols)| (cols, rows, (cols as f64 * 3.0) / (rows as f64 * 2.0)))
        .collect();
    if candidates.is_empty() {
        return Grid {
            cols: 2,
            rows: 2,
            token_count,
        };
    }
    let above: Vec<&(usize, usize, f64)> = candidates.iter().filter(|c| c.2 >= target_ar).collect();
    let chosen = if !above.is_empty() {
        above
            .iter()
            .min_by(|a, b| (a.2 - target_ar).partial_cmp(&(b.2 - target_ar)).unwrap())
            .unwrap()
    } else {
        candidates
            .iter()
            .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap())
            .unwrap()
    };
    Grid {
        cols: chosen.0,
        rows: chosen.1,
        token_count,
    }
}

// --------------------------------------------------------------------------
// Tests — mirror the certified entviz-js unit tests.
// --------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_hex() {
        let t = tokenize("0123456789abcdef", &HEX);
        assert_eq!(t.len(), 3);
        assert_eq!(t[0].text, "012345");
        assert_eq!(t[0].quant, 0x012345);
    }

    #[test]
    fn quant_extension() {
        let t = tokenize("ab", &HEX); // 0xAB -> 0xABABAB
        assert_eq!(t[0].quant, 0xABABAB);
    }

    #[test]
    fn fingerprint_22_ftoks() {
        let d = compute_fingerprint("hello");
        assert_eq!(tokenize_fingerprint(&d).len(), 22);
    }

    #[test]
    fn nucleus_colors_order_and_fg() {
        let (bg, fg) = nucleus_colors(0x452301);
        assert_eq!(bg, "#012345");
        assert_eq!(fg, "#ffffff");
        assert!(oklab_lightness(255, 255, 255) > 0.99);
        assert!(oklab_lightness(0, 0, 0) < 0.01);
    }

    #[test]
    fn grid_11_at_1to1_is_3x4() {
        let g = choose_grid(11, 1.0);
        assert_eq!(g.cols, 3);
        assert_eq!(g.rows, 4);
    }

    // ---- char_value ----
    #[test]
    fn char_value_direct_and_case_fold() {
        // direct hit
        assert_eq!(char_value(HEX.chars, 'A', 4), 10);
        // lowercase folds to uppercase alphabet position
        assert_eq!(char_value(HEX.chars, 'a', 4), 10);
        // base64 special-char aliases (the `-`/`+` -> 62, `_`/`/` -> 63 branch)
        assert_eq!(char_value(BASE64URL.chars, '-', 6), 62);
        assert_eq!(char_value(BASE64URL.chars, '_', 6), 63);
        assert_eq!(char_value(BASE64URL.chars, '+', 6), 62);
        assert_eq!(char_value(BASE64URL.chars, '/', 6), 63);
        // unknown char in a 6-bit alphabet -> -1 (falls through the alias block)
        assert_eq!(char_value(BASE64URL.chars, '!', 6), -1);
        // unknown char in a 4-bit alphabet -> -1
        assert_eq!(char_value(HEX.chars, 'z', 4), -1);
    }

    // ---- tokenize ----
    #[test]
    fn tokenize_empty_is_empty() {
        assert!(tokenize("", &HEX).is_empty());
    }

    #[test]
    fn tokenize_indices_are_sequential() {
        let t = tokenize("0123456789abcdef", &HEX);
        for (i, tok) in t.iter().enumerate() {
            assert_eq!(tok.index, i);
        }
    }

    #[test]
    fn tokenize_unknown_char_treated_as_zero() {
        // '!' is not in HEX; char_value -> -1 -> coerced to 0. The token still
        // forms; the unknown nibble contributes 0.
        let t = tokenize("!!!!!!", &HEX);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].quant, 0);
    }

    #[test]
    fn tokenize_short_chunk_quant_extends_to_24_bits() {
        // single hex char 'f' (4 bits) extends to fill 24 bits.
        let t = tokenize("f", &HEX);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].quant & 0xFFFFFF, t[0].quant); // within 24 bits
        assert_ne!(t[0].quant, 0);
    }

    #[test]
    fn tokenize_base64url_special_chars() {
        let t = tokenize("ab-_", &BASE64URL);
        assert_eq!(t.len(), 1);
        // a=26? no: BASE64URL 'a' is at index 26, 'b' 27, '-' 62, '_' 63.
        let expected = (26u32 << 18) | (27u32 << 12) | (62u32 << 6) | 63u32;
        assert_eq!(t[0].quant, expected & 0xFFFFFF);
    }

    // ---- fingerprint ----
    #[test]
    fn fingerprint_is_deterministic_and_distinct() {
        assert_eq!(compute_fingerprint("hello"), compute_fingerprint("hello"));
        assert_ne!(compute_fingerprint("hello"), compute_fingerprint("hellp"));
        assert_eq!(compute_fingerprint("hello").len(), 64);
    }

    #[test]
    fn second_digest_is_domain_separated() {
        // The middle digest must differ from the primary fingerprint for the
        // same input (domain tag prepended).
        assert_ne!(
            second_digest("hello").to_vec(),
            compute_fingerprint("hello").to_vec()
        );
        assert_eq!(second_digest("x"), second_digest("x"));
    }

    #[test]
    fn tokenize_fingerprint_count() {
        let d = compute_fingerprint("anything");
        let toks = tokenize_fingerprint(&d);
        assert_eq!(toks.len(), 22);
    }

    // ---- median / quartile ----
    #[test]
    fn median_empty_is_none() {
        assert!(median_token(&[]).is_none());
    }

    #[test]
    fn median_picks_lower_middle_by_text() {
        let toks = tokenize("0123456789abcdef0123", &HEX); // 4 tokens? 20/6 ceil
        let m = median_token(&toks).unwrap();
        // median index is (len-1)/2 of the text-sorted list.
        let mut sorted: Vec<&Token> = toks.iter().collect();
        sorted.sort_by(|a, b| a.text.cmp(&b.text).then(a.index.cmp(&b.index)));
        assert_eq!(m.text, sorted[(sorted.len() - 1) / 2].text);
    }

    #[test]
    fn quartile_empty_is_four_nones() {
        let q = quartile_tokens(&[]);
        assert_eq!(q.len(), 4);
        assert!(q.iter().all(|x| x.is_none()));
    }

    #[test]
    fn quartile_returns_four_slots() {
        let toks = tokenize("0123456789abcdef0123456789abcdef", &HEX);
        let q = quartile_tokens(&toks);
        assert_eq!(q.len(), 4);
        // first quartile is index 0 of the reversed-text sort
        assert!(q[0].is_some());
    }

    // ---- colors ----
    #[test]
    fn srgb_to_linear_and_oklab_extremes() {
        assert!(oklab_lightness(255, 255, 255) > 0.99);
        assert!(oklab_lightness(0, 0, 0) < 0.01);
        // mid grey lands between
        let mid = oklab_lightness(128, 128, 128);
        assert!(mid > 0.3 && mid < 0.8);
    }

    #[test]
    fn nucleus_colors_byte_order_and_threshold() {
        // red is the low byte, blue the high byte (CSS #RRGGBB order).
        let (bg, fg) = nucleus_colors(0x452301);
        assert_eq!(bg, "#012345");
        assert_eq!(fg, "#ffffff"); // dark bg -> white fg
                                   // bright yellow -> black fg
        let (bg2, fg2) = nucleus_colors(0x00ffff); // r=0xff g=0xff b=0x00 -> #ffff00
        assert_eq!(bg2, "#ffff00");
        assert_eq!(fg2, "#000000");
    }

    #[test]
    fn weighted_rgb_distance_zero_for_equal() {
        assert_eq!(weighted_rgb_distance("#123456", "#123456"), 0.0);
        assert!(weighted_rgb_distance("#000000", "#ffffff") > 0.0);
    }

    #[test]
    fn closest_palette_color_picks_nearest() {
        let palette = ["#ffffff", "#000000", "#ff0000"];
        assert_eq!(closest_palette_color("#fefefe", &palette), "#ffffff");
        assert_eq!(closest_palette_color("#010101", &palette), "#000000");
        assert_eq!(closest_palette_color("#fe0000", &palette), "#ff0000");
    }

    // ---- visual style ----
    #[test]
    fn select_visual_style_all_four_bg_indices() {
        for idx in 0u32..4 {
            // craft an ftok whose low two quant bits == idx
            let ftok = Token {
                text: "x".into(),
                index: 0,
                quant: idx,
            };
            let style = select_visual_style(&ftok);
            assert_eq!(style.bg_color, POSSIBLE_EDGE_COLORS[idx as usize]);
            // edge colors are the other four, in order, excluding bg
            assert_eq!(style.edge_colors.len(), 4);
            assert!(!style.edge_colors.contains(&style.bg_color));
        }
    }

    // ---- grid ----
    #[test]
    fn choose_grid_degenerate_token_counts_fall_back_to_2x2() {
        // token_count < 2 -> no candidates -> default 2x2.
        for tc in [0usize, 1] {
            let g = choose_grid(tc, 1.0);
            assert_eq!((g.cols, g.rows), (2, 2));
            assert_eq!(g.token_count, tc);
        }
    }

    #[test]
    fn choose_grid_no_candidate_above_target_picks_widest() {
        // A target aspect ratio nothing can reach forces the
        // "max by aspect" fallback branch.
        let g = choose_grid(11, 100.0);
        // widest layout maximizes cols*3 / rows*2.
        assert!(g.cols as f64 / g.rows as f64 >= 1.0);
        assert_eq!(g.token_count, 11);
    }

    #[test]
    fn choose_grid_tall_target_prefers_tall() {
        let wide = choose_grid(12, 5.0);
        let tall = choose_grid(12, 0.2);
        assert!(wide.cols >= tall.cols);
    }
}
