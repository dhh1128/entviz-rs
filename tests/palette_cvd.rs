//! PSY-F1: color-vision-deficiency (CVD) palette regression guard.
//!
//! The Python reference pins the palette's perceptual gaps via
//! `test_v6_palette_lightness.py`; this port previously had no equivalent, so
//! any change to the edge-color palette or the map markers would silently
//! regress the spec's CVD guarantee. This file is the value-pinning floor: it
//! locks the exact hex values of `POSSIBLE_EDGE_COLORS` and the three map
//! markers (`#d62828`, `#1d4ed8`, `#a00000`) so a future palette edit trips a
//! test, and additionally checks the CIELAB lightness (L*) ordering +
//! separations of the palette (a value change that preserves the literals but
//! is perceptually different would have to also preserve L* order to slip
//! through, which the pinned literals already prevent).

use entviz::pipeline::render;
use entviz::POSSIBLE_EDGE_COLORS;

/// CIELAB L* (perceptual lightness, 0..100) of an sRGB `#rrggbb` hex color,
/// under the D65 white point. Used only to lock the palette's lightness
/// structure; not part of the render path.
fn lstar(hex: &str) -> f64 {
    let comp = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).unwrap() as f64 / 255.0;
    let lin = |c: f64| {
        if c <= 0.04045 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    let r = lin(comp(1));
    let g = lin(comp(3));
    let b = lin(comp(5));
    // Relative luminance Y (D65), then the CIELAB lightness transfer function.
    let y = 0.2126 * r + 0.7152 * g + 0.0722 * b;
    if y > 0.008856 {
        116.0 * y.cbrt() - 16.0
    } else {
        903.3 * y
    }
}

#[test]
fn possible_edge_colors_are_pinned() {
    // The v10 5-color edge palette. Any change here re-keys the visual identity
    // of every diagram AND can break the CVD lightness separations the spec
    // relies on — so it must be a deliberate, test-updating change.
    assert_eq!(
        POSSIBLE_EDGE_COLORS,
        ["#ffffff", "#e7be00", "#ff3f2f", "#2f3fbf", "#000000"],
        "POSSIBLE_EDGE_COLORS changed — review CVD lightness separations before updating this test"
    );
}

#[test]
fn map_markers_are_pinned() {
    // The blank-cell map markers (min=blue circle, max=red plus) and the
    // fingerprint-of truncation marker (#a00000). These carry max/min and
    // truncation semantics; pin them so a palette edit is caught.

    // `aaaa` renders a grid with a multi-blank map -> both the blue (#1d4ed8)
    // min circle (filled) and red (#d62828) max plus (stroked) markers.
    let mapped = render("aaaa", 1.0, 12.0, None).unwrap();
    assert!(
        mapped.contains("fill=\"#1d4ed8\""),
        "expected the blue (#1d4ed8) blank-map min marker (filled circle)"
    );
    assert!(
        mapped.contains("stroke=\"#d62828\""),
        "expected the red (#d62828) blank-map max marker (stroked plus)"
    );

    // A >512-bit input takes the truncation path and emits the bold #a00000
    // "+hash " marker (v15; was "fingerprint of ").
    let big_hex: String = "0123456789abcdef".repeat(16);
    let truncated = render(&big_hex, 1.0, 12.0, None).unwrap();
    assert!(
        truncated.contains("data-truncated=\"true\""),
        "sanity: the large input must take the truncation path"
    );
    assert!(
        truncated.contains("fill=\"#a00000\""),
        "expected the bold #a00000 fingerprint-of truncation marker"
    );
}

#[test]
fn palette_lightness_structure_is_locked() {
    // Lock the L* ordering and the headline separations so a palette change that
    // (somehow) kept the literals but shifted lightness still trips. Values are
    // computed from the pinned hex above; ordering is white > gold > red > blue
    // > black, and the two structurally-important gaps (gold/red, red/blue) are
    // pinned with tolerance.
    let l: Vec<f64> = POSSIBLE_EDGE_COLORS.iter().map(|c| lstar(c)).collect();
    let [white, gold, red, blue, black] = [l[0], l[1], l[2], l[3], l[4]];

    assert!(white > gold, "white must be lighter than gold");
    assert!(gold > red, "gold must be lighter than red");
    assert!(red > blue, "red must be lighter than blue");
    assert!(blue > black, "blue must be lighter than black");

    // White and black are the extremes.
    assert!((white - 100.0).abs() < 0.5, "white L* ~= 100, got {white}");
    assert!(black.abs() < 0.5, "black L* ~= 0, got {black}");

    // Headline CVD-relevant separations (lightness carries discriminability when
    // hue collapses under CVD). These are wide gaps by design; pin with slack.
    // gold/red ~= 21.2, red/blue ~= 23.3 at the pinned palette; pin with slack.
    assert!(
        (gold - red) > 15.0,
        "gold/red L* separation collapsed: {gold} vs {red}"
    );
    assert!(
        (red - blue) > 15.0,
        "red/blue L* separation collapsed: {red} vs {blue}"
    );
}
