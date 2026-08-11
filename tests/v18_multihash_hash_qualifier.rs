//! v18: the multihash hash function is surfaced, and its table is observable.
//!
//! Through v17 `characterize()` recognized the hash-function name (the parser
//! has always put it in `Parsed::type_name`, e.g. "hex multihash sha3-256") and
//! then discarded it, so `qualifiers["hash"]` was never set for a multihash and
//! the MOD slot the v14 rule has required since v14 — "a multihash hash on
//! departure" — could never fire. A sha3-256 multihash labeled exactly like a
//! sha2-256 one.
//!
//! The consequence larger than a missing word: the 48-entry hash-function table
//! was UNOBSERVABLE. Its lookup ran and its result reached nothing a conformance
//! checker could see, so an implementation could get every entry wrong and still
//! pass Tier A. This file is the fix for that, not just for the qualifier: it
//! drives EVERY entry of the table through the rendered label, which is the only
//! artifact a checker reads. See `this.i:mh4shnam` in the reference — "a lookup
//! table is only as certified as its most observable consumer."
//!
//! The 45 single-byte codes are reachable as a hex multihash (its header is one
//! code byte plus one length byte). The three two-byte codes (0xb201..0xb203)
//! are reachable only through the table's OTHER consumer, CIDv1's uvarint
//! multicodec decode, so they are exercised there. 45 + 3 = 48, the whole table.

use entviz::characterize::{characterize, render_label, QVal};

fn label_of(value: &str) -> String {
    render_label(&characterize(value).unwrap(), false, None, None, None).0
}

fn hash_qualifier_of(value: &str) -> Option<String> {
    characterize(value)
        .unwrap()
        .qualifiers
        .0
        .iter()
        .find_map(|(k, v)| match (k.as_str(), v) {
            ("hash", QVal::Str(s)) => Some(s.clone()),
            _ => None,
        })
}

/// A hex multihash carrying `code` over a 32-byte digest: one code byte, one
/// length byte (0x20), then the digest. The declared length must match the
/// payload or the parser declines, so the digest size is fixed rather than
/// derived from the nominal hash width — this exercises the TABLE, not the
/// hash.
fn hex_multihash(code: u8) -> String {
    format!("{code:02x}20{}", "ab".repeat(32))
}

/// Every single-byte entry of the hash-function table, with the label the
/// reference renders for it. Generated against entviz v0.18.0's
/// `MULTIHASH_HASH_FUNCS` and checked entry by entry, not by remembered size.
/// (code, name, expected top label)
const ONE_BYTE_TABLE: &[(u8, &str, &str)] = &[
    (0x11, "sha1", "multihash, sha1, 256-bit, 1120"),
    (0x12, "sha2-256", "multihash, 256-bit, 1220"),
    (0x13, "sha2-512", "multihash, sha2-512, 256-bit, 1320"),
    (0x14, "sha3-224", "multihash, sha3-224, 256-bit, 1420"),
    (0x15, "sha3-256", "multihash, sha3-256, 256-bit, 1520"),
    (0x16, "sha3-384", "multihash, sha3-384, 256-bit, 1620"),
    (0x17, "sha3-512", "multihash, sha3-512, 256-bit, 1720"),
    (0x18, "shake-128", "multihash, shake-128, 256-bit, 1820"),
    (0x19, "shake-256", "multihash, shake-256, 256-bit, 1920"),
    (0x1a, "keccak-224", "multihash, keccak-224, 256-bit, 1a20"),
    (0x1b, "keccak-256", "multihash, keccak-256, 256-bit, 1b20"),
    (0x1c, "keccak-384", "multihash, keccak-384, 256-bit, 1c20"),
    (0x1d, "keccak-512", "multihash, keccak-512, 256-bit, 1d20"),
    (0x22, "blake2b-8", "multihash, blake2b-8, 256-bit, 2220"),
    (0x23, "blake2b-16", "multihash, blake2b-16, 256-bit, 2320"),
    (0x24, "blake2b-24", "multihash, blake2b-24, 256-bit, 2420"),
    (0x25, "blake2b-32", "multihash, blake2b-32, 256-bit, 2520"),
    (0x26, "blake2b-40", "multihash, blake2b-40, 256-bit, 2620"),
    (0x27, "blake2b-48", "multihash, blake2b-48, 256-bit, 2720"),
    (0x28, "blake2b-56", "multihash, blake2b-56, 256-bit, 2820"),
    (0x29, "blake2b-64", "multihash, blake2b-64, 256-bit, 2920"),
    (0x2a, "blake2b-72", "multihash, blake2b-72, 256-bit, 2a20"),
    (0x2b, "blake2b-80", "multihash, blake2b-80, 256-bit, 2b20"),
    (0x2c, "blake2b-88", "multihash, blake2b-88, 256-bit, 2c20"),
    (0x2d, "blake2b-96", "multihash, blake2b-96, 256-bit, 2d20"),
    (0x2e, "blake2b-104", "multihash, blake2b-104, 256-bit, 2e20"),
    (0x2f, "blake2b-112", "multihash, blake2b-112, 256-bit, 2f20"),
    (0x30, "blake2b-120", "multihash, blake2b-120, 256-bit, 3020"),
    (0x31, "blake2b-128", "multihash, blake2b-128, 256-bit, 3120"),
    (0x32, "blake2b-136", "multihash, blake2b-136, 256-bit, 3220"),
    (0x33, "blake2b-144", "multihash, blake2b-144, 256-bit, 3320"),
    (0x34, "blake2b-152", "multihash, blake2b-152, 256-bit, 3420"),
    (0x35, "blake2b-160", "multihash, blake2b-160, 256-bit, 3520"),
    (0x36, "blake2b-168", "multihash, blake2b-168, 256-bit, 3620"),
    (0x37, "blake2b-176", "multihash, blake2b-176, 256-bit, 3720"),
    (0x38, "blake2b-184", "multihash, blake2b-184, 256-bit, 3820"),
    (0x39, "blake2b-192", "multihash, blake2b-192, 256-bit, 3920"),
    (0x3a, "blake2b-200", "multihash, blake2b-200, 256-bit, 3a20"),
    (0x3b, "blake2b-208", "multihash, blake2b-208, 256-bit, 3b20"),
    (0x3c, "blake2b-216", "multihash, blake2b-216, 256-bit, 3c20"),
    (0x3d, "blake2b-224", "multihash, blake2b-224, 256-bit, 3d20"),
    (0x3e, "blake2b-232", "multihash, blake2b-232, 256-bit, 3e20"),
    (0x3f, "blake2b-240", "multihash, blake2b-240, 256-bit, 3f20"),
    (0x40, "blake2b-248", "multihash, blake2b-248, 256-bit, 4020"),
    (0x41, "blake2b-256", "multihash, blake2b-256, 256-bit, 4120"),
];

/// The three two-byte codes, unreachable through the one-byte hex-multihash
/// header, driven through CIDv1's uvarint multicodec decode instead.
/// (CIDv1 string, name, expected top label)
const TWO_BYTE_TABLE: &[(&str, &str, &str)] = &[
    (
        "bafkydzacecv2xk5lvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2w",
        "dbl-sha2-256",
        "CIDv1, raw, dbl-sha2-256, b",
    ),
    (
        "bafkyfzacecv2xk5lvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2w",
        "murmur3-128",
        "CIDv1, raw, murmur3-128, b",
    ),
    (
        "bafkyhzacecv2xk5lvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2w",
        "murmur3-32",
        "CIDv1, raw, murmur3-32, b",
    ),
];

#[test]
fn every_single_byte_hash_function_renders_its_name() {
    for (code, name, expected) in ONE_BYTE_TABLE {
        let value = hex_multihash(*code);
        assert_eq!(label_of(&value), *expected, "code {code:#04x} ({name})");
    }
    assert_eq!(ONE_BYTE_TABLE.len(), 45);
}

#[test]
fn every_two_byte_hash_function_renders_through_the_cid_consumer() {
    for (cid, name, expected) in TWO_BYTE_TABLE {
        assert_eq!(label_of(cid), *expected, "{name}");
        assert_eq!(hash_qualifier_of(cid).as_deref(), Some(*name));
    }
    assert_eq!(TWO_BYTE_TABLE.len(), 3);
}

#[test]
fn the_whole_table_is_covered() {
    // 48 entries, and this file reaches all of them through a rendered label.
    // If the table grows, this fails until the new entry is driven through the
    // label too — which is the entire point of v18.
    assert_eq!(ONE_BYTE_TABLE.len() + TWO_BYTE_TABLE.len(), 48);
}

#[test]
fn sha2_256_is_silent_and_every_departure_is_loud() {
    // The v14 MOD rule, restated as a property. sha2-256 is the near-universal
    // default, so the parser does not append it and the qualifier stays absent;
    // every other function is named in both the qualifier and the label.
    for (code, name, _) in ONE_BYTE_TABLE {
        let value = hex_multihash(*code);
        let is_default = *name == "sha2-256";
        assert_eq!(hash_qualifier_of(&value).is_none(), is_default, "{name}");
        assert_eq!(!label_of(&value).contains(name), is_default, "{name}");
    }
}

#[test]
fn a_sha3_multihash_never_labels_like_its_sha2_twin() {
    // The defect, stated directly. These share a digest and differ only in the
    // hash-function byte; through v17 both read "multihash, 256-bit, …" and
    // their characterizations carried identical (empty) qualifiers.
    let sha2 = hex_multihash(0x12);
    let sha3 = hex_multihash(0x15);
    assert_eq!(
        characterize(&sha2).unwrap().qualifiers.to_json(),
        "{}",
        "premise: the default is silent"
    );
    assert_eq!(
        characterize(&sha3).unwrap().qualifiers.to_json(),
        "{\"hash\":\"sha3-256\"}"
    );
    assert_ne!(label_of(&sha2), label_of(&sha3));
}

/// The four v18 corpus vectors, each DEPARTING from a default (a
/// default-valued vector proves nothing here), plus the two pre-v18 vectors
/// that must be unchanged. (input, expected top label)
const V18_CORPUS_LABELS: &[(&str, &str)] = &[
    (
        "1520abababababababababababababababababababababababababababababababab",
        "multihash, sha3-256, 256-bit, 1520",
    ),
    (
        concat!(
            "1340",
            "abababababababababababababababababababababababababababababababab",
            "abababababababababababababababababababababababababababababababab"
        ),
        "multihash, sha2-512, 512-bit, 1340",
    ),
    (
        "1114abababababababababababababababababababab",
        "multihash, sha1, 160-bit, 1114",
    ),
    (
        "bafkrkiaaaebagbafaydqqcikbmga2dqpcaireeyuculbogazdinryhi6d4",
        "CIDv1, raw, sha3-256, b",
    ),
    // Unchanged by v18: both sit on the silent default.
    (
        "1220b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553",
        "multihash, 256-bit, 1220",
    ),
    (
        "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        "CIDv1, dag-pb, b",
    ),
];

#[test]
fn the_v18_corpus_vectors_label_as_the_reference_does() {
    for (value, expected) in V18_CORPUS_LABELS {
        assert_eq!(label_of(value), *expected, "{value}");
    }
}
