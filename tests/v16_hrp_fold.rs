//! v16: the bech32 HRP is identity-bearing and binds the fingerprint.
//!
//! Before v16 a bech32 human-readable part was classified as presentation
//! framing — validated by the polymod, then dropped. Two values sharing a data
//! payload under different HRPs therefore rendered byte-identically in every
//! channel a human compares, and differed only in the 12px grey label: a Cosmos
//! address and its Osmosis spelling, mainnet and testnet Bitcoin or Cardano,
//! and — the case that motivated the change — a nostr `npub1…` public key and
//! the `nsec1…` secret key over the same payload.
//!
//! v16 folds `<hrp>1` into the fingerprint (`prefix ‖ core`), the mechanism
//! DIDs, URNs, SWHIDs and gitoids already use. See the entviz spec, *How
//! identity material is bound*.

use entviz::pipeline::render;

/// Each pair shares a data payload and differs only in the HRP. The checksums
/// differ because the polymod covers the HRP; they are the bound suffix and are
/// not part of the core, which is exactly why the fold is needed.
const HRP_PAIRS: &[(&str, &str)] = &[
    (
        "cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363e",
        "osmo1qqqsyqcyq5rqwzqfpg9scrgwpugpzysntdz28t",
    ),
    (
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    ),
    (
        concat!(
            "addr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xmyv4nxw6rfdf4kc",
            "mtwdac8zunnw36hvamc09a8klra0elsr0jfpr"
        ),
        concat!(
            "addr_test1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xmyv4nxw6rfdf4kc",
            "mtwdac8zunnw36hvamc09a8klra0els30xwlp"
        ),
    ),
    (
        "npub1802mpadp48s09v7y6hn0wzqe9ga5chtw07qfz23mf3wkuluqjy3swt0n8f",
        "nsec1802mpadp48s09v7y6hn0wzqe9ga5chtw07qfz23mf3wkuluqjy3szayjpu",
    ),
];

fn svg_of(entropy: &str) -> String {
    render(entropy, 1.0, 12.0, None).unwrap_or_else(|e| panic!("{entropy}: {e:?}"))
}

/// Every fingerprint-derived attribute on the rendered SVG. All of them move
/// when the hash input changes, so collecting the whole set keeps the test
/// honest if a channel is added or renamed later.
fn gestalt(svg: &str) -> Vec<String> {
    const ATTRS: &[&str] = &[
        "data-surround-bits=",
        "data-edge-color=",
        "data-cell-quartile=",
        "data-cell-blank=",
        "data-cell-blank-map=",
        "data-ellipse-rx=",
        "data-ellipse-ry=",
        "data-ellipse-rotation-deg=",
        "data-ellipse-anchor-x=",
        "data-ellipse-anchor-y=",
        "data-bar-marker=",
        "data-bar-marker-left=",
        "data-bar-marker-right=",
    ];
    let mut out = Vec::new();
    for attr in ATTRS {
        let mut rest = svg;
        while let Some(i) = rest.find(attr) {
            let after = &rest[i + attr.len() + 1..]; // skip the opening quote
            let end = after.find('"').expect("unterminated attribute");
            out.push(format!("{attr}{}", &after[..end]));
            rest = &after[end..];
        }
    }
    assert!(!out.is_empty(), "no fingerprint-derived attributes found");
    out
}

fn attrs(svg: &str, attr: &str) -> Vec<String> {
    gestalt(svg)
        .into_iter()
        .filter(|s| s.starts_with(attr))
        .collect()
}

#[test]
fn same_payload_different_hrp_renders_differently() {
    for (a, b) in HRP_PAIRS {
        assert_ne!(gestalt(&svg_of(a)), gestalt(&svg_of(b)), "{a} vs {b}");
    }
}

#[test]
fn the_two_renders_are_not_merely_label_deep() {
    // A reader who never looks at the label must still see a difference, so the
    // divergence has to reach the cells' own painted attributes — not just the
    // ellipse or the colour bar at the edges of the picture.
    for (a, b) in HRP_PAIRS {
        let ca = attrs(&svg_of(a), "data-surround-bits=");
        let cb = attrs(&svg_of(b), "data-surround-bits=");
        assert!(!ca.is_empty(), "{a}");
        assert_ne!(ca, cb, "{a} vs {b}");
    }
}

#[test]
fn the_hrp_is_still_readable_in_the_label() {
    // The fold puts the HRP in the fingerprint, not in the cells, so the label
    // is the only text carrier left. Losing it there would leave a read-aloud
    // comparison with no way to tell these values apart at all.
    for (entropy, expected) in [
        ("cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363e", "cosmos1"),
        ("osmo1qqqsyqcyq5rqwzqfpg9scrgwpugpzysntdz28t", "osmo1"),
        ("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "tb1"),
    ] {
        let svg = svg_of(entropy);
        assert!(svg.contains(expected), "{entropy} label lost the HRP");
    }
}

#[test]
fn cashaddr_is_the_documented_exception() {
    // CashAddr is deliberately NOT folded: its prefix is optional, so a bare
    // body and its prefixed spelling are the same address and must not diverge.
    // It is safe unfolded because its checksum stays in the core and covers the
    // prefix.
    let bare = svg_of("qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a");
    let prefixed = svg_of("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a");
    assert_eq!(gestalt(&bare), gestalt(&prefixed));
}
