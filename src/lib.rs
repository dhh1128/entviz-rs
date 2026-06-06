//! entviz — Rust reference port (spec v6).
//!
//! **STATUS: UNVERIFIED SCAFFOLD.** This crate ports the deterministic shared
//! core of entviz (tokenization + quant extension, the SHA-512 fingerprint,
//! ftok median/quartile selection, the Oklab color rules, and grid selection),
//! mirroring the *certified* TypeScript implementation (`entviz-js`, which
//! passes the shared conformance corpus at Tier A + Tier B). It has **not been
//! compiled or tested** here because this machine has no Rust toolchain
//! (`rustc`/`cargo` absent). Once a toolchain is installed:
//!
//! ```sh
//! cargo test                  # the unit tests below mirror the certified TS
//! # then port the SVG renderer (see README) and certify via:
//! #   python -m compliance.runner --impl-cmd 'cargo run -q' --only '<subset>'
//! ```
//!
//! The SVG renderer (`render()`) and the format-specific parsers are the
//! remaining work; the core ported here is the load-bearing, hardest-to-get-
//! right part and is the same algorithm the TS core proved correct.

use base64::Engine;
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;

pub const SPEC_VERSION: &str = "v6";

// --------------------------------------------------------------------------
// Alphabets
// --------------------------------------------------------------------------
#[derive(Clone, Copy)]
pub struct Alphabet {
    pub name: &'static str,
    pub chars: &'static str,
    pub bits_per_char: u32,
}

pub const HEX: Alphabet = Alphabet { name: "hex", chars: "0123456789ABCDEF", bits_per_char: 4 };
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
        tokens.push(Token { text: chunk, index, quant: quant & 0xFFFFFF });
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
    let q_size = (s.len() + 3) / 4; // ceil(n/4)
    (0..4)
        .map(|i| {
            let idx = i * q_size;
            if idx < s.len() { Some(s[idx].clone()) } else { None }
        })
        .collect()
}

// --------------------------------------------------------------------------
// Colors (Oklab)
// --------------------------------------------------------------------------
pub const POSSIBLE_EDGE_COLORS: [&str; 5] =
    ["#ffffff", "#e7be00", "#ff3f2f", "#2f3fbf", "#000000"];

fn srgb_to_linear(c: f64) -> f64 {
    if c <= 0.04045 { c / 12.92 } else { ((c + 0.055) / 1.055).powf(2.4) }
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
    let fg = if oklab_lightness(r, g, b) < OKLAB_THRESHOLD { "#ffffff" } else { "#000000" };
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
    VisualStyle { bg_color, edge_colors }
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
        let rows = (token_count + cols - 1) / cols; // ceil
        if rows >= 2 {
            tightest
                .entry(rows)
                .and_modify(|c| { if cols < *c { *c = cols; } })
                .or_insert(cols);
        }
        cols += 1;
    }
    let candidates: Vec<(usize, usize, f64)> = tightest
        .iter()
        .map(|(&rows, &cols)| (cols, rows, (cols as f64 * 3.0) / (rows as f64 * 2.0)))
        .collect();
    if candidates.is_empty() {
        return Grid { cols: 2, rows: 2, token_count };
    }
    let above: Vec<&(usize, usize, f64)> =
        candidates.iter().filter(|c| c.2 >= target_ar).collect();
    let chosen = if !above.is_empty() {
        above.iter().min_by(|a, b| (a.2 - target_ar).partial_cmp(&(b.2 - target_ar)).unwrap()).unwrap()
    } else {
        candidates.iter().max_by(|a, b| a.2.partial_cmp(&b.2).unwrap()).unwrap()
    };
    Grid { cols: chosen.0, rows: chosen.1, token_count }
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
}
