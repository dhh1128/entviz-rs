//! v17 correction 2: reject only on an explicit marker.
//!
//! A failing checksum may reject **only** when the input carries an explicit,
//! multi-character scheme marker — `bc1`/`tb1`, `ltc1`,
//! `addr1`/`stake1`/`addr_test1`, a *typed* `bitcoincash:`/`bchtest:`, or `0x`
//! plus exactly 40 hex characters for EIP-55. There a failure means "this IS
//! that scheme, and it is corrupt". Where the only signal is a leading
//! character, a length band, or a reserved digit pair — the generic
//! `<hrp>1<data>` form, Bitcoin and Litecoin legacy base58check, a **bare**
//! `q…`/`p…` CashAddr body, and LEI's reserved `00` — a failure means only "not
//! that scheme", so the parser declines and the input continues to the next
//! recognizer and the alphabet ladder.
//!
//! Two things need pinning, and they pull in opposite directions. The
//! correction must actually buy the property it claims (no ordinary value is
//! refused outright), and it must not over-reach into "never reject anything".
//! Both are asserted below.
//!
//! See `this.i:w3aksig` and docs/spec.md "Checksum verification" in the entviz
//! reference repo.

use entviz::entropy::parse;

/// Inputs whose ONLY scheme signal is a leading character, a length band, or a
/// reserved digit pair, each carrying a deliberately corrupted checksum. Every
/// one must still render as SOMETHING, and never as the scheme it resembles.
const WEAK_SIGNAL_BAD_CHECKSUM: &[(&str, &str, &str)] = &[
    // One leading char from [123mn] plus a length band.
    (
        "btc-legacy",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",
        "BTC legacy",
    ),
    // `L`/`tL` plus a fixed length.
    (
        "ltc-legacy",
        "LKDyUEtTR1HXamkiEphisSiBJu6o3ZPE3a",
        "LTC legacy",
    ),
    // A reserved "00" at positions 4-5, which lands by chance in 1 of 1296
    // random 20-char base36 strings.
    ("lei", "5493001KJTIIGC8Y1R13", "LEI"),
    // A leading `q` plus a length, with NO typed prefix.
    (
        "cashaddr-bare",
        "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6q",
        "BCH",
    ),
    // The generic `<hrp>1<data>` form — no registry of valid HRPs exists, by
    // design. Corrected one pass earlier (`this.i:b3ch32fl`); pinned here so
    // the whole family lives in one table.
    (
        "generic-bech32",
        "cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363f",
        "bech32",
    ),
];

/// Inputs carrying an unmistakable multi-character marker, each with a
/// corrupted checksum. A failure here really does mean a corrupt instance of
/// that scheme, so rejection stands.
const EXPLICIT_MARKER_BAD_CHECKSUM: &[(&str, &str)] = &[
    ("bc1", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"),
    ("tb1", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsy"),
    ("ltc1", "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n8"),
    (
        "addr1",
        "addr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xmyv4nxw6rfdf4kc\
         mtwdac8zunnw36hvamc09a8klra0elsr0jfpq",
    ),
    (
        "bitcoincash:",
        "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6q",
    ),
    (
        "bchtest:",
        "bchtest:qpur7lcrzhq247gvqs5n79hj0tz4edmdqg09nfandq",
    ),
    ("eip55", "0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
];

#[test]
fn a_weak_signal_declines_and_never_claims_the_scheme() {
    for (name, value, scheme) in WEAK_SIGNAL_BAD_CHECKSUM {
        let parsed = parse(value)
            .unwrap_or_else(|e| panic!("{name} was REFUSED outright ({e:?}); it must decline"))
            .unwrap_or_else(|| panic!("{name} must still render as SOMETHING"));
        assert_ne!(
            &parsed.type_name, scheme,
            "{name} rendered AS {scheme} with a failing checksum — the label \
             must report the encoding actually recognized"
        );
    }
}

#[test]
fn an_explicit_marker_still_rejects() {
    // Guards the correction from over-reaching: it must not turn into "never
    // reject anything". Every entry here is the same corruption the weak-signal
    // table applies, differing only in whether the input names its scheme.
    for (name, value) in EXPLICIT_MARKER_BAD_CHECKSUM {
        assert!(
            parse(value).is_err(),
            "{name} carries an explicit marker with a corrupt checksum and MUST \
             reject; got {:?}",
            parse(value).map(|p| p.map(|p| p.type_name))
        );
    }
}

/// The same CashAddr body, twice: the verdict follows the INPUT, not the parser.
#[test]
fn cashaddr_splits_on_the_input_not_the_parser() {
    let body = "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6q";
    assert!(
        parse(&format!("bitcoincash:{body}")).is_err(),
        "a typed prefix is an explicit marker — reject"
    );
    let bare = parse(body)
        .expect("a bare body carries no marker — decline, do not refuse")
        .expect("and it still renders as a bare encoding");
    assert_ne!(bare.type_name, "BCH");
}

// --------------------------------------------------------------------------
// The property the whole correction exists to establish.
// --------------------------------------------------------------------------

/// SplitMix64. A deterministic generator is used deliberately: the reference's
/// equivalent test draws from `secrets`, but a port that fails this must fail
/// it reproducibly rather than once in a hundred CI runs.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn pick(&mut self, alphabet: &[char]) -> char {
        alphabet[(self.next_u64() % alphabet.len() as u64) as usize]
    }
}

#[test]
fn no_random_value_is_refused_outright() {
    // Before this correction, ~2% of these were refused — Bitcoin and Litecoin
    // legacy base58check dominating, plus LEI and bare CashAddr. Ordinary
    // values entviz would simply not render.
    let alphabets = [
        ("hex", "0123456789abcdef"),
        (
            "base58",
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
        ),
        ("base36", "0123456789abcdefghijklmnopqrstuvwxyz"),
    ];
    let mut rng = SplitMix64(0x656E_7476_697A_1702); // "entviz" + 0.17.2
    let mut refused: Vec<(String, String)> = Vec::new();
    for (name, alpha) in alphabets {
        let alpha: Vec<char> = alpha.chars().collect();
        for n in [12usize, 16, 20, 24, 26, 32, 34, 40, 42] {
            for _ in 0..120 {
                let s: String = (0..n).map(|_| rng.pick(&alpha)).collect();
                if let Err(e) = parse(&s) {
                    refused.push((format!("{name}/{n}: {s}"), format!("{e:?}")));
                }
            }
        }
    }
    assert!(
        refused.is_empty(),
        "values refused outright: {:?}",
        &refused[..refused.len().min(5)]
    );
}
