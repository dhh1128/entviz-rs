//! Entropy characterization model (spec v13) — port of
//! `src/entviz/characterize.py`.
//!
//! The parser ([`crate::entropy`]) produces a [`Parsed`] display record whose
//! `type_name` string fuses several orthogonal facts (scheme, semantic role,
//! network/variant, size). [`characterize`] re-expresses that same recognition
//! along independent axes so downstream consumers read structured fields
//! instead of string-parsing the label.
//!
//! The characterization is REPORTING-ONLY. It changes no rendered pixel, no
//! fingerprint input, and no label string. The renderer emits the eight fields
//! onto the root `<svg>` as `data-*` attributes; the conformance model
//! extractor recovers them from *those attributes*. The attributes add no ink
//! (the closed profile permits extra `data-*`), so the golden raster is
//! unaffected. In particular `size_bits` is REPORTING-ONLY and is NOT wired
//! into the >512-bit truncation trigger (that stays keyed off the tokenizer's
//! byte-length test in [`crate::entropy::tokenize_entropy`]).

use crate::entropy::{self, Parsed};
use crate::Alphabet;

// Closed role enum (spec v13). Nothing outside this set may appear.
pub const ROLE_KEY: &str = "key";
pub const ROLE_SIGNATURE: &str = "signature";
pub const ROLE_DIGEST: &str = "digest";
pub const ROLE_ADDRESS: &str = "address";
pub const ROLE_IDENTIFIER: &str = "identifier";

/// A qualifier value: a string or a bare JSON integer (e.g. CID `version`).
#[derive(Clone, Debug, PartialEq)]
pub enum QVal {
    Str(String),
    Int(i64),
}

/// Insertion-ordered qualifier facets. The compact-JSON serialization MUST
/// preserve insertion order to match the reference (`{"version":1,"codec":...}`
/// for CID; `{"method":"ethr","network":"0x5"}` for did:ethr), so this is a
/// simple ordered vec, never a sorted/hashed map.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Qualifiers(pub Vec<(String, QVal)>);

impl Qualifiers {
    fn push_str(&mut self, k: &str, v: &str) {
        self.0.push((k.to_string(), QVal::Str(v.to_string())));
    }
    fn push_int(&mut self, k: &str, v: i64) {
        self.0.push((k.to_string(), QVal::Int(v)));
    }
    /// Compact JSON object: `{"k":"v",...}` / `{"k":1}`, no spaces, insertion
    /// order. Empty -> `{}`.
    pub fn to_json(&self) -> String {
        let mut s = String::from("{");
        for (i, (k, v)) in self.0.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&json_string(k));
            s.push(':');
            match v {
                QVal::Str(x) => s.push_str(&json_string(x)),
                QVal::Int(x) => s.push_str(&x.to_string()),
            }
        }
        s.push('}');
        s
    }
}

/// A reading-order part: text + bind ∈ {none, fold, core}.
#[derive(Clone, Debug, PartialEq)]
pub struct Part {
    pub text: String,
    pub bind: &'static str,
}

/// The eight-field structured characterization (spec v13).
#[derive(Clone, Debug, PartialEq)]
pub struct Characterization {
    pub encoding: String,
    pub scheme: Option<String>,
    pub role: Option<&'static str>,
    pub qualifiers: Qualifiers,
    pub size_basis: &'static str, // "decoded" | "utf8"
    pub size_bits: usize,
    pub parts: Vec<Part>,
    pub entropy_type: String,
}

impl Characterization {
    /// Compact JSON array for `data-parts`: `[{"text":"...","bind":"..."}]`,
    /// no spaces, key order text then bind (matches the reference).
    pub fn parts_json(&self) -> String {
        let mut s = String::from("[");
        for (i, p) in self.parts.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"text\":");
            s.push_str(&json_string(&p.text));
            s.push_str(",\"bind\":");
            s.push_str(&json_string(p.bind));
            s.push('}');
        }
        s.push(']');
        s
    }
}

/// Minimal JSON string encoder (compact; the only escapes the corpus can hit
/// are `"` and `\`, plus the C0 controls JSON requires). Mirrors Python's
/// `json.dumps` for the value domain the characterization produces.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// Non-power-of-2 alphabets whose true density is below the token-packing
// bits_per_char convention. For these, size_bits decodes the core as a big
// integer and takes its minimal byte length (Resolution A).
fn is_integer_decode_alphabet(name: &str) -> bool {
    matches!(name, "base58" | "base36" | "decimal")
}

/// Minimal byte length of `core` decoded as a big integer in its base. Used for
/// base58/base36/decimal. Character lookup mirrors the tokenizer's case
/// tolerance. An empty core (or a value of zero) is one byte.
fn decoded_bytes_integer(core: &str, alphabet: &Alphabet) -> usize {
    let chars = alphabet.chars;
    let lower = chars.to_lowercase();
    let base = chars.chars().count() as u128;
    // The value can exceed u128 for long cores; accumulate a byte big-integer.
    // We only need bit_length -> byte length, so track a Vec<u8> big-endian.
    let mut digits: Vec<u8> = vec![0]; // big-endian base-256 accumulator
    for c in core.chars() {
        let v = match chars.find(c) {
            Some(i) => i as u128,
            None => match lower.find(c.to_ascii_lowercase()) {
                Some(i) => i as u128,
                None => 0,
            },
        };
        mul_add_bigint(&mut digits, base, v); // digits = digits * base + v
    }
    // Byte length is the accumulator with leading zero bytes stripped; a zero
    // value (or empty core) is one byte, matching a single zero digit.
    match digits.iter().position(|&b| b != 0) {
        None => 1,
        Some(i) => digits.len() - i,
    }
}

/// `acc = acc * base + add`, acc big-endian base-256.
fn mul_add_bigint(acc: &mut Vec<u8>, base: u128, add: u128) {
    let mut carry: u128 = add;
    for byte in acc.iter_mut().rev() {
        let cur = (*byte as u128) * base + carry;
        *byte = (cur & 0xff) as u8;
        carry = cur >> 8;
    }
    while carry > 0 {
        acc.insert(0, (carry & 0xff) as u8);
        carry >>= 8;
    }
}

/// Value size in bits from the CORE only (Resolution A). Always a multiple of 8.
fn size_bits(core: &str, alphabet: &Alphabet, size_basis: &str) -> usize {
    if size_basis == "utf8" {
        return core.len() * 8;
    }
    if is_integer_decode_alphabet(alphabet.name) {
        return decoded_bytes_integer(core, alphabet) * 8;
    }
    ((core.chars().count() * alphabet.bits_per_char as usize) / 8) * 8
}

// CESR derivation-code role classification, keyed off the decoded primitive
// name the parser puts in `type` ("CESR <name>").
fn cesr_role(name: &str) -> &'static str {
    let low = name.to_lowercase();
    if low.contains("sig") {
        return ROLE_SIGNATURE;
    }
    for m in ["blake3", "blake2b", "blake2s", "sha3", "sha2", "sha"] {
        if low.contains(m) {
            return ROLE_DIGEST;
        }
    }
    ROLE_KEY
}

/// Return (scheme, role, qualifiers, size_basis) for a Parsed record. Mirrors
/// `_describe_from_parsed`.
fn describe_from_parsed(
    parsed: &Parsed,
) -> (
    Option<String>,
    Option<&'static str>,
    Qualifiers,
    &'static str,
) {
    let type_name = parsed.type_name.as_str();
    let prefix = parsed.prefix.as_deref();
    let mut q = Qualifiers::default();

    // --- Folded identity prefixes: did / urn / gitoid / swhid ---
    if let (Some(prefix), true) = (prefix, parsed.prefix_semantic) {
        if let Some(rest) = prefix.strip_prefix("did:") {
            let method = rest.trim_end_matches(':');
            q.push_str("method", method);
            // did:ethr:<network>:<addr> — recover the head network segment
            // (label-only; role stays identifier).
            if method == "ethr" {
                let head = parsed.core.split(':').next().unwrap_or("");
                q.push_str("network", head);
            }
            return (Some("did".into()), Some(ROLE_IDENTIFIER), q, "utf8");
        }
        if let Some(rest) = prefix.strip_prefix("urn:") {
            let nid = rest.trim_end_matches(':');
            q.push_str("nid", nid);
            return (Some("urn".into()), Some(ROLE_IDENTIFIER), q, "utf8");
        }
        if prefix.starts_with("gitoid:") {
            let segs: Vec<&str> = prefix.trim_matches(':').split(':').collect();
            if segs.len() >= 3 {
                q.push_str("object", segs[1]);
                q.push_str("algorithm", segs[2]);
            }
            return (Some("gitoid".into()), Some(ROLE_DIGEST), q, "decoded");
        }
        if prefix.starts_with("swh:") {
            let segs: Vec<&str> = prefix.trim_matches(':').split(':').collect();
            if segs.len() >= 3 {
                q.push_str("object", segs[2]);
            }
            q.push_str("algorithm", "sha1");
            return (Some("swhid".into()), Some(ROLE_DIGEST), q, "decoded");
        }
    }

    // --- CESR primitives: "CESR <decoded-name>" ---
    if let Some(name) = type_name.strip_prefix("CESR ") {
        q.push_str("algorithm", name);
        return (Some("cesr".into()), Some(cesr_role(name)), q, "decoded");
    }

    // --- SSH public keys: "SSH <algorithm>" or "SSH key" ---
    if let Some(rest0) = type_name.strip_prefix("SSH") {
        let rest = rest0.trim();
        if !rest.is_empty() && rest != "key" {
            q.push_str("algorithm", rest);
        }
        return (Some("ssh".into()), Some(ROLE_KEY), q, "decoded");
    }

    // --- Blockchain addresses ---
    if type_name.starts_with("BTC") {
        q.push_str("network", "mainnet");
        let low = type_name.to_lowercase();
        if low.contains("legacy") {
            q.push_str("variant", "legacy");
        } else if low.contains("segwit") {
            q.push_str("variant", "segwit");
        }
        return (Some("btc".into()), Some(ROLE_ADDRESS), q, "decoded");
    }
    if type_name == "BCH" {
        let is_testnet = prefix
            .map(|p| p.to_lowercase().starts_with("bchtest"))
            .unwrap_or(false);
        q.push_str("network", if is_testnet { "testnet" } else { "mainnet" });
        return (Some("bch".into()), Some(ROLE_ADDRESS), q, "decoded");
    }
    if type_name.starts_with("LTC") {
        q.push_str("network", "mainnet");
        if type_name.to_lowercase().contains("legacy") {
            q.push_str("variant", "legacy");
        }
        return (Some("ltc".into()), Some(ROLE_ADDRESS), q, "decoded");
    }
    if type_name.starts_with("ADA") {
        if type_name.contains("Byron") {
            q.push_str("variant", "byron");
        } else if type_name.contains("Shelley") {
            q.push_str("variant", "shelley");
        }
        return (Some("ada".into()), Some(ROLE_ADDRESS), q, "decoded");
    }
    if type_name == "ETH" {
        return (Some("eth".into()), Some(ROLE_ADDRESS), q, "decoded");
    }
    if type_name.starts_with("XLM") {
        if type_name.contains("muxed") {
            q.push_str("variant", "muxed");
        }
        return (Some("stellar".into()), Some(ROLE_ADDRESS), q, "decoded");
    }
    if type_name == "XRP" {
        return (Some("xrp".into()), Some(ROLE_ADDRESS), q, "decoded");
    }
    if type_name == "EOS" {
        return (Some("eos".into()), Some(ROLE_ADDRESS), q, "decoded");
    }
    if type_name == "bech32" {
        if let Some(p) = prefix {
            if let Some(hrp) = p.strip_suffix('1') {
                q.push_str("hrp", hrp);
            }
        }
        return (Some("bech32".into()), Some(ROLE_ADDRESS), q, "decoded");
    }

    // --- Content identifiers (IPFS CID) ---
    if type_name.starts_with("CIDv") {
        if type_name.starts_with("CIDv0") {
            q.push_int("version", 0);
            q.push_str("codec", "dag-pb");
            q.push_str("hash", "sha2-256");
        } else {
            q.push_int("version", 1);
            let rest = type_name["CIDv1".len()..].trim();
            if !rest.is_empty() {
                if let Some((codec, hash_name)) = rest.split_once('/') {
                    q.push_str("codec", codec);
                    q.push_str("hash", hash_name);
                } else {
                    q.push_str("codec", rest);
                    q.push_str("hash", "sha2-256");
                }
            }
        }
        return (Some("cid".into()), Some(ROLE_IDENTIFIER), q, "decoded");
    }

    // --- Structured identifiers ---
    if type_name == "UUID" {
        return (Some("uuid".into()), Some(ROLE_IDENTIFIER), q, "decoded");
    }
    if type_name == "ULID" {
        return (Some("ulid".into()), Some(ROLE_IDENTIFIER), q, "decoded");
    }
    if type_name == "LEI" {
        return (Some("lei".into()), Some(ROLE_IDENTIFIER), q, "decoded");
    }
    if type_name == "snowflake" {
        return (
            Some("snowflake".into()),
            Some(ROLE_IDENTIFIER),
            q,
            "decoded",
        );
    }
    if type_name.contains("multihash") {
        return (Some("multihash".into()), Some(ROLE_DIGEST), q, "decoded");
    }

    // --- Bare encodings (hex / base64 / base64url / disproof fallbacks) ---
    (None, None, q, "decoded")
}

/// Reading-order [{text, bind}] parts (Wrinkle 4). Mirrors `_parts_from_parsed`.
fn parts_from_parsed(parsed: &Parsed) -> Vec<Part> {
    let mut parts = Vec::new();
    if let Some(prefix) = &parsed.prefix {
        let bind = if parsed.prefix_semantic {
            "fold"
        } else {
            "none"
        };
        parts.push(Part {
            text: prefix.clone(),
            bind,
        });
    }
    parts.push(Part {
        text: parsed.core.clone(),
        bind: "core",
    });
    if let Some(suffix) = &parsed.suffix {
        parts.push(Part {
            text: suffix.clone(),
            bind: "none",
        });
    }
    parts
}

/// Characterize an entropy string into the structured model (spec v13). Never
/// errors for an in-range input: an unrecognized input falls back to the
/// UTF-8 -> base64url path (scheme=None, role=None, size_basis="utf8", size
/// measured over the ORIGINAL input bytes). A hard parse error (EIP-55) is
/// propagated so the whole render aborts, matching the reference contract.
pub fn characterize(entropy: &str) -> Result<Characterization, entropy::ParseError> {
    let raw = entropy.trim();
    let parsed = entropy::parse(raw)?;

    match parsed {
        None => {
            use base64::Engine;
            let core = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes());
            Ok(Characterization {
                encoding: crate::BASE64URL.name.to_string(),
                scheme: None,
                role: None,
                qualifiers: Qualifiers::default(),
                size_basis: "utf8",
                size_bits: raw.len() * 8,
                parts: vec![Part {
                    text: core,
                    bind: "core",
                }],
                entropy_type: crate::BASE64URL.name.to_string(),
            })
        }
        Some(parsed) => {
            let (scheme, role, qualifiers, basis) = describe_from_parsed(&parsed);
            let bits = size_bits(&parsed.core, &parsed.alphabet, basis);
            let encoding = parsed.alphabet.name.to_string();
            let entropy_type = scheme.clone().unwrap_or_else(|| encoding.clone());
            Ok(Characterization {
                encoding,
                scheme,
                role,
                qualifiers,
                size_basis: basis,
                size_bits: bits,
                parts: parts_from_parsed(&parsed),
                entropy_type,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(s: &str) -> Characterization {
        characterize(s).unwrap()
    }

    #[test]
    fn cesr_said_blake3_is_digest_264() {
        let c = ch("EBfdlu8R27Fbx_ehrqwImnK_8Cm79sqbAQ4caaZG_LFv");
        assert_eq!(c.scheme.as_deref(), Some("cesr"));
        assert_eq!(c.role, Some(ROLE_DIGEST));
        assert_eq!(c.size_basis, "decoded");
        assert_eq!(c.size_bits, 264);
        assert_eq!(c.entropy_type, "cesr");
        assert_eq!(c.qualifiers.to_json(), "{\"algorithm\":\"Blake3-256\"}");
        assert_eq!(
            c.parts_json(),
            "[{\"text\":\"EBfdlu8R27Fbx_ehrqwImnK_8Cm79sqbAQ4caaZG_LFv\",\"bind\":\"core\"}]"
        );
    }

    #[test]
    fn cesr_pubkey_is_key() {
        let c = ch("DKxy2sgzfplyr_tgwIxS19f2OchFHtLwPWD3v4oYimBx");
        assert_eq!(c.role, Some(ROLE_KEY));
    }

    #[test]
    fn text_fallback_is_utf8_over_raw_input() {
        let c = ch("hello world");
        assert!(c.scheme.is_none());
        assert!(c.role.is_none());
        assert_eq!(c.size_basis, "utf8");
        assert_eq!(c.size_bits, 88); // 11 bytes * 8
        assert_eq!(c.encoding, "base64url");
        assert_eq!(c.entropy_type, "base64url");
        assert_eq!(c.parts.len(), 1);
        assert_eq!(c.parts[0].bind, "core");
    }

    #[test]
    fn did_key_is_identifier_not_key() {
        let c = ch("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assert_eq!(c.scheme.as_deref(), Some("did"));
        assert_eq!(c.role, Some(ROLE_IDENTIFIER));
        assert_eq!(c.size_basis, "utf8");
        assert_eq!(c.qualifiers.to_json(), "{\"method\":\"key\"}");
        assert_eq!(c.parts.len(), 2);
        assert_eq!(c.parts[0].bind, "fold");
    }

    #[test]
    fn did_ethr_recovers_network() {
        let c = ch("did:ethr:0x5:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74");
        assert_eq!(
            c.qualifiers.to_json(),
            "{\"method\":\"ethr\",\"network\":\"0x5\"}"
        );
        assert_eq!(c.size_bits, 368); // 46 utf8 bytes * 8
    }

    #[test]
    fn urn_isbn_is_identifier_utf8() {
        let c = ch("urn:isbn:0451450523");
        assert_eq!(c.scheme.as_deref(), Some("urn"));
        assert_eq!(c.role, Some(ROLE_IDENTIFIER));
        assert_eq!(c.size_basis, "utf8");
        assert_eq!(c.size_bits, 80); // 10 bytes * 8
        assert_eq!(c.qualifiers.to_json(), "{\"nid\":\"isbn\"}");
    }

    #[test]
    fn snowflake_is_decimal_integer_decoded_64() {
        let c = ch("1234567890987654321");
        assert_eq!(c.encoding, "decimal");
        assert_eq!(c.scheme.as_deref(), Some("snowflake"));
        assert_eq!(c.size_basis, "decoded");
        assert_eq!(c.size_bits, 64); // 1234567890987654321 fits in 8 bytes
    }

    #[test]
    fn cid_v1_qualifier_order_version_codec_hash() {
        let c = ch("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi");
        assert_eq!(c.scheme.as_deref(), Some("cid"));
        assert_eq!(c.role, Some(ROLE_IDENTIFIER));
        assert_eq!(c.size_bits, 288);
        assert_eq!(
            c.qualifiers.to_json(),
            "{\"version\":1,\"codec\":\"dag-pb\",\"hash\":\"sha2-256\"}"
        );
    }

    #[test]
    fn ssh_ed25519_is_key_with_prefix_none_part() {
        let c =
            ch("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDtJVH9hM+2DyhmgRZBfeIDoVqCTbXY+0nKlS5pTkkXY");
        assert_eq!(c.scheme.as_deref(), Some("ssh"));
        assert_eq!(c.role, Some(ROLE_KEY));
        assert_eq!(c.qualifiers.to_json(), "{\"algorithm\":\"ed25519\"}");
        assert_eq!(c.parts[0].bind, "none");
        assert_eq!(c.parts[1].bind, "core");
    }

    #[test]
    fn empty_qualifiers_serialize_as_object() {
        assert_eq!(Qualifiers::default().to_json(), "{}");
    }
}
