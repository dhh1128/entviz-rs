//! v17: the network qualifier is read from the prefix, not assumed.
//!
//! Through v16 `characterize()` hardcoded `network: "mainnet"` for every BTC
//! address and emitted no network at all for Cardano Shelley. Because the MODS
//! slot surfaces the network only when it *departs* from mainnet (the v14 rule
//! — "testnet loud, mainnet silent"), a testnet address rendered a label
//! indistinguishable from its mainnet twin: `BTC, tb1` where `BTC, testnet,
//! tb1` was required. The port was non-conformant to the spec, in the same
//! mainnet-versus-testnet confusability family that v16 closed for the HRP.
//!
//! The Shelley matcher also had a length hole: its body floor of 50 characters
//! excluded every 29-byte Shelley address — all reward (`stake1…`) and
//! enterprise addresses, which are 47 characters ahead of the 6-character
//! checksum. See `this.i:n3twrkq` and `this.i:sh3lley29` in the reference.

use entviz::characterize::{characterize, render_label, QVal};
use entviz::entropy::parse;

fn network_of(value: &str) -> Option<String> {
    let ch = characterize(value).unwrap();
    ch.qualifiers
        .0
        .iter()
        .find_map(|(k, v)| match (k.as_str(), v) {
            ("network", QVal::Str(s)) => Some(s.clone()),
            _ => None,
        })
}

fn label_of(value: &str) -> String {
    render_label(&characterize(value).unwrap(), false, None, None, None).0
}

/// (value, expected network, expected label). Mirrors the reference's
/// `tests/test_v17_network_qualifier.py::NETWORK_CASES`.
const NETWORK_CASES: &[(&str, &str, &str)] = &[
    (
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "mainnet",
        "BTC, bc1",
    ),
    (
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        "testnet",
        "BTC, testnet, tb1",
    ),
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "mainnet", "BTC, 1"),
    (
        "mfWyW5fc9NUj75YAnFgoRLrjxgLDn2MMth",
        "testnet",
        "BTC, testnet, m",
    ),
    (
        "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9",
        "mainnet",
        "LTC, ltc1",
    ),
    (
        "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
        "mainnet",
        "BCH, bitcoincash:",
    ),
    (
        "bchtest:qpm2qsznhks23z7629mms6s4cwef74vcwvqcw003ap",
        "testnet",
        "BCH, testnet, bchtest:",
    ),
    (
        "stake1uyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcwfvml6",
        "mainnet",
        "ADA, stake1",
    ),
    (
        "stake_test1uqqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcfrxem8",
        "testnet",
        "ADA, testnet, stake_test1",
    ),
];

#[test]
fn network_is_read_from_the_prefix() {
    for (value, network, label) in NETWORK_CASES {
        assert_eq!(network_of(value).as_deref(), Some(*network), "{value}");
        assert_eq!(label_of(value), *label, "{value}");
    }
}

#[test]
fn testnet_is_loud_and_mainnet_is_silent() {
    // The v14 label rule, restated as a property so it cannot rot: the word
    // appears in the label exactly when the network departs from mainnet.
    for (value, network, label) in NETWORK_CASES {
        assert_eq!(label.contains("testnet"), *network == "testnet", "{value}");
    }
}

#[test]
fn a_testnet_address_never_labels_like_its_mainnet_twin() {
    // The defect, stated directly. These two share a payload and differ only in
    // the network; before v17 both read "BTC, …", separable only by the small
    // prefix slot, and their characterizations were byte-identical.
    let main = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let test = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    assert_eq!(
        parse(main).unwrap().unwrap().core,
        parse(test).unwrap().unwrap().core,
        "premise: one payload"
    );
    assert_ne!(
        characterize(main).unwrap().qualifiers.to_json(),
        characterize(test).unwrap().qualifiers.to_json()
    );
    assert_ne!(label_of(main), label_of(test));
}

#[test]
fn byron_claims_no_network() {
    // Deliberate: a Byron address's network magic is inside the CBOR payload,
    // which this parser does not decode — the same reason its CRC-32 goes
    // unverified. Asserting mainnet would be a guess dressed as a fact.
    for value in [
        "Ae2tdPwUPEZ7SZaSCeU8sGZXGZ7YrVc96FnzYdZcLkbry4CqUKax9dNeEoe",
        "DdzFFzCqrht1D2Tv5F9HLtZHEd4P9Tddf9DFv3d4KXa2RxudcL4uHKWtc2HfiDopch5UHyZkXQx7",
    ] {
        let ch = characterize(value).unwrap();
        assert_eq!(ch.scheme.as_deref(), Some("ada"));
        assert_eq!(ch.qualifiers.to_json(), "{\"variant\":\"byron\"}");
        assert!(!render_label(&ch, false, None, None, None)
            .0
            .contains("testnet"));
    }
}

// --- the Shelley 29-byte hole ------------------------------------------------

#[test]
fn twenty_nine_byte_shelley_addresses_reach_the_cardano_parser() {
    // Before v17 the mainnet form fell through to the generic bech32 parser
    // (scheme "bech32"), and the testnet form did not parse as bech32 at all —
    // `stake_test` contains `_`, outside the generic parser's [a-z] HRP
    // charset, so it landed on the base64url fallback with no scheme and no
    // checksum verification. Both are 47 body characters, under the old floor
    // of 50.
    for value in [
        "stake1uyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcwfvml6",
        "stake_test1uqqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcfrxem8",
    ] {
        let p = parse(value).unwrap().expect("must parse");
        assert_eq!(p.type_name, "ADA Shelley", "{value}");
        assert!(p.prefix_semantic, "{value}");
        assert_eq!(characterize(value).unwrap().scheme.as_deref(), Some("ada"));
    }
}

#[test]
fn the_57_byte_base_address_still_parses() {
    // The floor moved from 50 to 45; the long form must be unaffected.
    let value = concat!(
        "addr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xmyv4nxw6rfdf4kc",
        "mtwdac8zunnw36hvamc09a8klra0elsr0jfpr"
    );
    assert_eq!(parse(value).unwrap().unwrap().type_name, "ADA Shelley");
}
