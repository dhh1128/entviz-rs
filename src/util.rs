//! Small deterministic helpers shared by the SVG pipeline ([`crate::pipeline`])
//! and the render-model layer ([`crate::model`], `adversarial` feature only).
//!
//! These functions were previously duplicated verbatim between `pipeline.rs`
//! and `model.rs` (MNT-F1). They are hoisted here so a fix in one cannot drift
//! from the other; both call sites use these definitions. The module is always
//! compiled (not feature-gated) and is `pub(crate)` — not part of the public
//! API surface of the crate.

use crate::{Grid, Token};

/// Map each token's `token_index` to a `cell_index` on the grid.
///
/// When the grid has more cells than tokens, blank cells are introduced by
/// shifting: the median-fingerprint token's cell, then the largest and
/// smallest fingerprint-token cells (by ASCII `(text, index)` order), each
/// reserve a preceding blank, in that order, only while spare cells remain.
/// Identity mapping when the grid is exactly full (or tokens is empty).
pub(crate) fn assign_cell_indices(
    tokens: &[Token],
    grid: &Grid,
    median: &Option<Token>,
    sort_keys: &[Token],
) -> Vec<usize> {
    let token_count = tokens.len();
    let cell_count = grid.cols * grid.rows;
    let mut ci: Vec<usize> = (0..token_count).collect(); // token_index -> cell_index
    if token_count >= cell_count || tokens.is_empty() {
        return ci;
    }

    // Shift: every token whose token_index >= start gets +1 cell index.
    let shift = |ci: &mut Vec<usize>, start: usize| {
        for (t, c) in ci.iter_mut().enumerate() {
            if t >= start {
                *c += 1;
            }
        }
    };

    if let Some(m) = median {
        shift(&mut ci, m.index);
    }

    // ASCII sort of the sort_keys by (text, index).
    let mut sorted: Vec<&Token> = sort_keys.iter().collect();
    sorted.sort_by(|a, b| a.text.cmp(&b.text).then(a.index.cmp(&b.index)));

    if token_count + 1 < cell_count {
        shift(&mut ci, sorted[sorted.len() - 1].index);
    }
    if token_count + 2 < cell_count {
        shift(&mut ci, sorted[0].index);
    }
    ci
}

/// Count occurrences of each of the four 2-bit patterns across all 256 2-bit
/// slices of the 64-byte digest. `counts[p]` is the number of slices equal to
/// pattern `p` (0..=3).
pub(crate) fn two_bit_counts(digest: &[u8; 64]) -> [usize; 4] {
    let mut counts = [0usize; 4];
    for &byte in digest.iter() {
        for shift in [0u32, 2, 4, 6] {
            counts[((byte >> shift) & 0x03) as usize] += 1;
        }
    }
    counts
}

/// Single-letter mnemonic for a palette color used by the color-bar readout,
/// or `None` if the color is not one of the five palette colors.
pub(crate) fn band_letter(color: &str) -> Option<&'static str> {
    match color {
        "#ffffff" => Some("W"),
        "#e7be00" => Some("G"),
        "#ff3f2f" => Some("R"),
        "#2f3fbf" => Some("B"),
        "#000000" => Some("K"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_letter_palette_and_unknown() {
        assert_eq!(band_letter("#ffffff"), Some("W"));
        assert_eq!(band_letter("#e7be00"), Some("G"));
        assert_eq!(band_letter("#ff3f2f"), Some("R"));
        assert_eq!(band_letter("#2f3fbf"), Some("B"));
        assert_eq!(band_letter("#000000"), Some("K"));
        assert_eq!(band_letter("#123456"), None);
    }

    #[test]
    fn two_bit_counts_sum_to_256_and_uniform_inputs() {
        // All-zero digest: every 2-bit slice is pattern 0.
        let z = two_bit_counts(&[0u8; 64]);
        assert_eq!(z, [256, 0, 0, 0]);
        // All-0xFF digest: every 2-bit slice is pattern 3.
        let f = two_bit_counts(&[0xFFu8; 64]);
        assert_eq!(f, [0, 0, 0, 256]);
        // Mixed digest: counts always sum to 256 (64 bytes * 4 slices).
        let mut d = [0u8; 64];
        for (i, b) in d.iter_mut().enumerate() {
            *b = i as u8;
        }
        let c = two_bit_counts(&d);
        assert_eq!(c.iter().sum::<usize>(), 256);
    }
}
