//! Entropy characterization model (spec v13) + label projection (spec v14) —
//! port of `src/entviz/characterize.py`.
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

// ---------------------------------------------------------------------------
// Label projection (spec v14).
//
// The visible top/bottom label strips are a PURE PROJECTION of the eight
// characterization fields through one grammar — no per-parser string fusing.
// Every implementation renders the same strips by running this same function
// over the shared fields. Port of `entviz.characterize.render_label`; see
// docs/spec.md -> "Label strips" and reviews/v14-label-redesign.md.
//
//   top    = [fingerprint of ]PRIMARY[, MOD]...[, SIZE]
//   bottom = ...<suffix>[ (<note>)]
//
// Slot separator is ", " (comma-space); no trailing ':' or '...'.
// ---------------------------------------------------------------------------

/// The `fingerprint of ` marker prepended to the top strip for >512-bit
/// truncated inputs. The renderer splits it back out to style it bold dark-red.
pub const TRUNC_MARKER: &str = "fingerprint of ";

fn qval_str<'a>(q: &'a Qualifiers, key: &str) -> Option<&'a str> {
    q.0.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            QVal::Str(s) => Some(s.as_str()),
            QVal::Int(_) => None,
        })
}

fn qval_int(q: &Qualifiers, key: &str) -> Option<i64> {
    q.0.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            QVal::Int(i) => Some(*i),
            QVal::Str(_) => None,
        })
}

/// Bare-encoding display shortening for the PRIMARY slot when scheme is null
/// and the basis is decoded (base64 -> b64, base64url -> b64url; others verbatim).
fn encoding_primary(enc: &str) -> &str {
    match enc {
        "base64" => "b64",
        "base64url" => "b64url",
        other => other,
    }
}

/// scheme -> visible PRIMARY short-name for the non-self-describing schemes.
fn scheme_primary(scheme: &str) -> Option<&'static str> {
    Some(match scheme {
        "eth" => "ETH",
        "btc" => "BTC",
        "ltc" => "LTC",
        "bch" => "BCH",
        "ada" => "ADA",
        "xrp" => "XRP",
        "stellar" => "XLM",
        "eos" => "EOS",
        "uuid" => "UUID",
        "ulid" => "ULID",
        "lei" => "LEI",
        "snowflake" => "snowflake",
        "ssh" => "SSH",
        "cesr" => "CESR",
        "bech32" => "bech32",
        "multihash" => "multihash",
        _ => return None,
    })
}

fn is_blockchain_scheme(scheme: &str) -> bool {
    matches!(
        scheme,
        "btc" | "ltc" | "bch" | "ada" | "eth" | "xrp" | "stellar" | "eos" | "bech32"
    )
}

/// The PRIMARY slot: the always-present head of the top label.
fn primary(ch: &Characterization) -> String {
    let q = &ch.qualifiers;
    match ch.scheme.as_deref() {
        None => {
            if ch.size_basis == "utf8" {
                "text".to_string()
            } else {
                encoding_primary(&ch.encoding).to_string()
            }
        }
        Some("did") => format!("did:{}", qval_str(q, "method").unwrap_or("")),
        Some("urn") => format!("urn:{}", qval_str(q, "nid").unwrap_or("")),
        Some("gitoid") => format!(
            "gitoid:{}:{}",
            qval_str(q, "object").unwrap_or(""),
            qval_str(q, "algorithm").unwrap_or("")
        ),
        Some("swhid") => format!("swh:1:{}", qval_str(q, "object").unwrap_or("")),
        Some("cid") => {
            if qval_int(q, "version") == Some(0) {
                "CIDv0".to_string()
            } else {
                "CIDv1".to_string()
            }
        }
        Some(scheme) => scheme_primary(scheme).unwrap_or(scheme).to_string(),
    }
}

/// The MOD slots (zero or more): silent-default / loud-departure facets.
fn mods(ch: &Characterization) -> Vec<String> {
    let q = &ch.qualifiers;
    let mut out = Vec::new();
    match ch.scheme.as_deref() {
        Some("cesr") => {
            // The primitive with the redundant role word dropped: strip a
            // trailing " pubkey" (role=key/digest is implied by the primitive).
            if let Some(algo) = qval_str(q, "algorithm") {
                let algo = algo.strip_suffix(" pubkey").unwrap_or(algo);
                if !algo.is_empty() {
                    out.push(algo.to_string());
                }
            }
        }
        Some("ssh") => {
            if let Some(algo) = qval_str(q, "algorithm") {
                out.push(algo.to_string());
            }
        }
        Some("cid") => {
            // CIDv0 is dag-pb/sha2-256 by definition -> no MOD. CIDv1: codec
            // always; hash only on departure from sha2-256.
            if qval_int(q, "version") != Some(0) {
                if let Some(codec) = qval_str(q, "codec") {
                    out.push(codec.to_string());
                }
                if let Some(hash) = qval_str(q, "hash") {
                    if hash != "sha2-256" {
                        out.push(hash.to_string());
                    }
                }
            }
        }
        Some("multihash") => {
            if let Some(hash) = qval_str(q, "hash") {
                if hash != "sha2-256" {
                    out.push(hash.to_string());
                }
            }
        }
        Some(scheme) if is_blockchain_scheme(scheme) => {
            // Network only on departure (testnet); mainnet silent. Variant dropped.
            if let Some(network) = qval_str(q, "network") {
                if network != "mainnet" {
                    out.push(network.to_string());
                }
            }
        }
        _ => {}
    }
    out
}

/// The SIZE slot (zero or one), or None when omitted.
fn size(ch: &Characterization) -> Option<String> {
    match ch.scheme.as_deref() {
        None => {
            if ch.size_basis == "utf8" {
                Some(format!("{}-byte", ch.size_bits / 8))
            } else {
                Some(format!("{}-bit", ch.size_bits))
            }
        }
        Some("ssh") | Some("multihash") => Some(format!("{}-bit", ch.size_bits)),
        _ => None,
    }
}

/// Project a characterization into the (top, bottom) label strips (v14).
///
/// * `top`    = `[fingerprint of ]PRIMARY[, MOD]...[, SIZE]` — ", " joined,
///   no trailing `:` or `...`. The `fingerprint of ` marker is prepended when
///   `truncated`; the renderer splits it back out to style it.
/// * `bottom` = `...<suffix>` then ` (<note>)` — the bound (now-verified)
///   checksum and the user caption. Empty string when neither is present.
pub fn render_label(
    ch: &Characterization,
    truncated: bool,
    suffix: Option<&str>,
    note: Option<&str>,
) -> (String, String) {
    let mut slots = vec![primary(ch)];
    slots.extend(mods(ch));
    if let Some(sz) = size(ch) {
        slots.push(sz);
    }
    let mut top = slots.join(", ");
    if truncated {
        top = format!("{TRUNC_MARKER}{top}");
    }

    let mut bottom = String::new();
    if let Some(suf) = suffix {
        if !suf.is_empty() {
            bottom = format!("...{suf}");
        }
    }
    if let Some(nt) = note {
        if !nt.is_empty() {
            bottom = if bottom.is_empty() {
                format!("({nt})")
            } else {
                format!("{bottom} ({nt})")
            };
        }
    }
    (top, bottom)
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

    // ==================================================================
    // Coverage completion (spec v13): exercise every reachable scheme arm,
    // both size_basis branches, both integer-decode paths, all bind modes,
    // and the JSON escape ladder — WITHOUT the reference corpus (these run
    // in CI's coverage job where ../entviz is intentionally absent).
    // ==================================================================

    // ---- json_string escape ladder (chars.rs 118-122) ----
    #[test]
    fn json_string_escapes_quote_backslash_and_controls() {
        // A qualifier value carrying every escape class the encoder handles.
        let mut q = Qualifiers::default();
        q.push_str("k", "a\"b\\c\nd\re\tf\u{0001}g");
        // \u{0001} is a C0 control -> ; the named escapes cover the rest.
        assert_eq!(q.to_json(), "{\"k\":\"a\\\"b\\\\c\\nd\\re\\tf\\u0001g\"}");
    }

    // ---- CESR signature role (line 196) ----
    #[test]
    fn cesr_signature_code_is_signature_role() {
        // "0B" (Ed25519 sig, 88 chars) -> type_name "CESR Ed25519 sig",
        // whose lowercase contains "sig" -> ROLE_SIGNATURE.
        let input = format!("0B{}", "A".repeat(86));
        let c = ch(&input);
        assert_eq!(c.scheme.as_deref(), Some("cesr"));
        assert_eq!(c.role, Some(ROLE_SIGNATURE));
        assert_eq!(c.qualifiers.to_json(), "{\"algorithm\":\"Ed25519 sig\"}");
    }

    // ---- SSH bare key (SSH key -> role key, no algorithm qualifier) ----
    #[test]
    fn ssh_bare_key_is_key_without_algorithm_qualifier() {
        // "AAAA..."-prefixed base64 blob with no recognized key-type header
        // parses as "SSH key" (length dodges every CESR code): the type_name
        // strips to "key", so the `rest == "key"` branch pushes no algorithm.
        let c = ch("AAAAXabcd1234");
        assert_eq!(c.scheme.as_deref(), Some("ssh"));
        assert_eq!(c.role, Some(ROLE_KEY));
        assert_eq!(c.qualifiers.to_json(), "{}");
    }

    // ---- gitoid (fold prefix, digest, decoded, qualifiers, size_bits 256) ----
    #[test]
    fn gitoid_blob_sha256_is_digest_decoded_256() {
        let c = ch(
            "gitoid:blob:sha256:473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813",
        );
        assert_eq!(c.scheme.as_deref(), Some("gitoid"));
        assert_eq!(c.role, Some(ROLE_DIGEST));
        assert_eq!(c.size_basis, "decoded");
        assert_eq!(c.size_bits, 256); // 64 hex chars * 4 bits / 8 * 8
        assert_eq!(
            c.qualifiers.to_json(),
            "{\"object\":\"blob\",\"algorithm\":\"sha256\"}"
        );
        assert_eq!(c.parts[0].bind, "fold");
        assert_eq!(c.parts[1].bind, "core");
    }

    // ---- swhid (fold prefix, digest, sha1 qualifier) (line 253) ----
    #[test]
    fn swhid_is_digest_with_object_and_sha1() {
        let c = ch("swh:1:rev:309cf2674ee7a0749978cf8265ab91a60aea0f7d");
        assert_eq!(c.scheme.as_deref(), Some("swhid"));
        assert_eq!(c.role, Some(ROLE_DIGEST));
        assert_eq!(c.size_basis, "decoded");
        assert_eq!(
            c.qualifiers.to_json(),
            "{\"object\":\"rev\",\"algorithm\":\"sha1\"}"
        );
        assert_eq!(c.parts[0].bind, "fold");
    }

    // ---- BTC legacy address (network + variant, base58 integer-decode) ----
    #[test]
    fn btc_legacy_is_address_mainnet_legacy() {
        // v14: a real base58check-valid legacy address (synthetic ones now
        // reject on the checksum).
        let c = ch("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert_eq!(c.scheme.as_deref(), Some("btc"));
        assert_eq!(c.role, Some(ROLE_ADDRESS));
        assert_eq!(c.encoding, "base58");
        assert_eq!(c.size_basis, "decoded");
        assert_eq!(
            c.qualifiers.to_json(),
            "{\"network\":\"mainnet\",\"variant\":\"legacy\"}"
        );
    }

    // ---- BTC segwit variant branch ----
    #[test]
    fn btc_segwit_is_address_segwit() {
        let c = ch("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(c.scheme.as_deref(), Some("btc"));
        assert_eq!(
            c.qualifiers.to_json(),
            "{\"network\":\"mainnet\",\"variant\":\"segwit\"}"
        );
    }

    // ---- BCH mainnet + testnet branches (lines 282-288) ----
    #[test]
    fn bch_mainnet_and_testnet() {
        let m = ch("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a");
        assert_eq!(m.scheme.as_deref(), Some("bch"));
        assert_eq!(m.role, Some(ROLE_ADDRESS));
        assert_eq!(m.qualifiers.to_json(), "{\"network\":\"mainnet\"}");

        // v14: a real bchtest CashAddr (checksum computed under the bchtest hrp).
        let t = ch("bchtest:qpur7lcrzhq247gvqs5n79hj0tz4edmdqg09nfandy");
        assert_eq!(t.scheme.as_deref(), Some("bch"));
        assert_eq!(t.qualifiers.to_json(), "{\"network\":\"testnet\"}");
    }

    // ---- LTC legacy variant branch (lines 289-294) ----
    #[test]
    fn ltc_legacy_is_address_with_legacy_variant() {
        // v14: a real base58check-valid Litecoin legacy address.
        let c = ch("LKDyUEtTR1HXamkiEphisSiBJu6o3ZPE34");
        assert_eq!(c.scheme.as_deref(), Some("ltc"));
        assert_eq!(c.role, Some(ROLE_ADDRESS));
        assert_eq!(
            c.qualifiers.to_json(),
            "{\"network\":\"mainnet\",\"variant\":\"legacy\"}"
        );
    }

    // ---- LTC bech32 (no legacy variant; network only) ----
    #[test]
    fn ltc_bech32_is_address_no_variant() {
        let c = ch("ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9");
        assert_eq!(c.scheme.as_deref(), Some("ltc"));
        assert_eq!(c.qualifiers.to_json(), "{\"network\":\"mainnet\"}");
    }

    // ---- ETH (line 304-305): no qualifiers, address, decoded ----
    #[test]
    fn eth_is_address_no_qualifiers() {
        let c = ch("0x742d35cc6634c0532925a3b844bc454e4438f44e");
        assert_eq!(c.scheme.as_deref(), Some("eth"));
        assert_eq!(c.role, Some(ROLE_ADDRESS));
        assert_eq!(c.qualifiers.to_json(), "{}");
        assert_eq!(c.entropy_type, "eth");
    }

    // ---- XLM plain + muxed variant (lines 307-312) ----
    #[test]
    fn stellar_plain_and_muxed() {
        let g = ch("GCKFBEIYTKP5RDBQMUTAPDCDHF2TR4LPNRGW4JBQQTQUYZP4LDKP3SGM");
        assert_eq!(g.scheme.as_deref(), Some("stellar"));
        assert_eq!(g.role, Some(ROLE_ADDRESS));
        assert_eq!(g.qualifiers.to_json(), "{}");

        let m = ch("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK");
        assert_eq!(m.scheme.as_deref(), Some("stellar"));
        assert_eq!(m.qualifiers.to_json(), "{\"variant\":\"muxed\"}");
    }

    // ---- XRP (line 313-314) ----
    #[test]
    fn xrp_is_address() {
        let c = ch("rUocf1ixKzTuEe34kmVhRvGqNCofY1NJzV");
        assert_eq!(c.scheme.as_deref(), Some("xrp"));
        assert_eq!(c.role, Some(ROLE_ADDRESS));
        assert_eq!(c.qualifiers.to_json(), "{}");
    }

    // ---- EOS (line 316-317) ----
    #[test]
    fn eos_is_address() {
        let c = ch("eosaccount1");
        assert_eq!(c.scheme.as_deref(), Some("eos"));
        assert_eq!(c.role, Some(ROLE_ADDRESS));
        assert_eq!(c.qualifiers.to_json(), "{}");
    }

    // ---- generic bech32 with hrp qualifier (lines 319-325) ----
    #[test]
    fn generic_bech32_recovers_hrp() {
        let c = ch("cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363e");
        assert_eq!(c.scheme.as_deref(), Some("bech32"));
        assert_eq!(c.role, Some(ROLE_ADDRESS));
        assert_eq!(c.qualifiers.to_json(), "{\"hrp\":\"cosmos\"}");
    }

    // ---- CIDv0 branch (lines 330-333): version 0, dag-pb, sha2-256 ----
    #[test]
    fn cid_v0_is_identifier_with_fixed_qualifiers() {
        let c = ch("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG");
        assert_eq!(c.scheme.as_deref(), Some("cid"));
        assert_eq!(c.role, Some(ROLE_IDENTIFIER));
        assert_eq!(
            c.qualifiers.to_json(),
            "{\"version\":0,\"codec\":\"dag-pb\",\"hash\":\"sha2-256\"}"
        );
    }

    // ---- CIDv1 with an explicit codec/hash split (lines 338-340) ----
    #[test]
    fn cid_v1_codec_slash_hash_split() {
        // "bafkrei..." decodes to codec=raw, hash=sha2-256 -> label "CIDv1 raw"
        // (single token, no '/'), exercising the else branch (codec-only,
        // default hash sha2-256) at lines 341-343.
        let c = ch("bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy");
        assert_eq!(c.scheme.as_deref(), Some("cid"));
        assert_eq!(
            c.qualifiers.to_json(),
            "{\"version\":1,\"codec\":\"raw\",\"hash\":\"sha2-256\"}"
        );
    }

    // ---- ULID (line 354-355) ----
    #[test]
    fn ulid_is_identifier() {
        let c = ch("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(c.scheme.as_deref(), Some("ulid"));
        assert_eq!(c.role, Some(ROLE_IDENTIFIER));
    }

    // ---- UUID (line 351-352) ----
    #[test]
    fn uuid_is_identifier_decoded() {
        let c = ch("550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(c.scheme.as_deref(), Some("uuid"));
        assert_eq!(c.role, Some(ROLE_IDENTIFIER));
        assert_eq!(c.size_basis, "decoded");
    }

    // ---- LEI (line 357-358) ----
    #[test]
    fn lei_is_identifier() {
        let c = ch("5493001KJTIIGC8Y1R12");
        assert_eq!(c.scheme.as_deref(), Some("lei"));
        assert_eq!(c.role, Some(ROLE_IDENTIFIER));
    }

    // ---- base36 integer-decode path + char-not-found fallback (151-153) ----
    // A base36 core containing a character outside its alphabet's index that
    // still reaches decoded_bytes_integer via the case-tolerant lookup, plus
    // the all-zero core returning a single byte (line 161).
    #[test]
    fn integer_decode_zero_core_is_one_byte() {
        // decimal "0" -> value 0 -> minimal byte length 1 -> 8 bits.
        // Snowflake requires 17-19 digits, so use the parser-agnostic helper
        // directly for the zero/empty edge; and a real decimal id for the path.
        assert_eq!(decoded_bytes_integer("0", &entropy::DECIMAL), 1);
        assert_eq!(decoded_bytes_integer("", &entropy::DECIMAL), 1);
        // base36's alphabet is UPPERCASE ("0-9A-Z"); a lowercase letter misses
        // the primary `chars.find` and resolves through the lowercase fallback
        // (line 152 Some branch). "1a" -> 1*36 + 10 = 46 -> 1 byte.
        assert_eq!(decoded_bytes_integer("1a", &entropy::BASE36), 1);
        // A character in NEITHER case maps to 0 (line 153): "#" is treated as
        // digit 0, so "10" and "#0" decode identically (36 -> 1 byte).
        assert_eq!(decoded_bytes_integer("#0", &entropy::BASE36), 1);
    }

    // ---- bare-encoding fallback (line 373): scheme None, entropy_type == encoding ----
    #[test]
    fn bare_hex_falls_through_to_none_scheme() {
        // 64 hex chars: recognized as hex encoding but no scheme fires.
        let c = ch("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0");
        assert!(c.scheme.is_none());
        assert!(c.role.is_none());
        assert_eq!(c.size_basis, "decoded");
        assert_eq!(c.encoding, "hex");
        assert_eq!(c.entropy_type, c.encoding); // scheme ?? encoding
    }

    // ---- did with a plain method (did:web) exercises the non-ethr branch ----
    #[test]
    fn did_web_method_no_network_qualifier() {
        let c = ch("did:web:example.com:user:Alice");
        assert_eq!(c.scheme.as_deref(), Some("did"));
        assert_eq!(c.role, Some(ROLE_IDENTIFIER));
        assert_eq!(c.qualifiers.to_json(), "{\"method\":\"web\"}");
        assert_eq!(c.size_basis, "utf8");
    }

    // ---- CIDv1 with a non-default hash: the codec/hash "/"-split arm (339-340) ----
    #[test]
    fn cid_v1_non_default_hash_splits_codec_and_hash() {
        // A hand-built CIDv1 (version=1, codec=dag-pb=0x70, hashfn=sha2-512=0x13)
        // labels as "CIDv1 dag-pb/sha2-512", exercising the split_once('/') arm.
        let c = ch("bafybgqflvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2xk5lvov2w");
        assert_eq!(c.scheme.as_deref(), Some("cid"));
        assert_eq!(
            c.qualifiers.to_json(),
            "{\"version\":1,\"codec\":\"dag-pb\",\"hash\":\"sha2-512\"}"
        );
    }

    // ---- bare CIDv1 (undecodable multicodec): the `rest.is_empty()` arm (345) ----
    #[test]
    fn cid_v1_undecodable_has_only_version_qualifier() {
        // A valid-length/charset 'b...' CID whose leading uvarint version != 1,
        // so `b32_decode_multicodec` fails and the parser label stays bare
        // "CIDv1" -> `rest` is empty -> only the version qualifier is emitted.
        let c = ch("bajkrftonzxg43tonzxg43tonzxg43tonzxg43tonzxg43tonzxg43tonzxg43ti");
        assert_eq!(c.scheme.as_deref(), Some("cid"));
        assert_eq!(c.role, Some(ROLE_IDENTIFIER));
        assert_eq!(c.qualifiers.to_json(), "{\"version\":1}");
    }

    // ==================================================================
    // v14 label projection (render_label) — corpus-independent unit tests
    // covering every grammar arm (PRIMARY / MOD / SIZE, bottom strip, marker),
    // so the projection is exercised in the coverage job (no ../entviz corpus).
    // Values match the reviews/v14-label-redesign.md before->after table.
    // ==================================================================

    fn top_of(s: &str) -> String {
        let c = ch(s);
        render_label(&c, false, None, None).0
    }

    #[test]
    fn label_bare_encodings_show_encoding_and_size() {
        // hex, 256-bit / text, 56-byte / b64 & b64url short-names.
        assert_eq!(
            top_of("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0"),
            "hex, 256-bit"
        );
        // 56-byte lorem text -> utf8 byte SIZE (spaces/punctuation force the
        // UTF-8 fallback rather than a bare encoding).
        assert_eq!(
            top_of("Lorem ipsum dolor sit amet, consectetur adipiscing elit."),
            "text, 56-byte"
        );
        assert_eq!(top_of("ABC+/DEF"), "b64, 48-bit");
        assert_eq!(top_of("ABC-_DEF"), "b64url, 48-bit");
    }

    #[test]
    fn label_scheme_short_names_omit_size() {
        assert_eq!(top_of("0x742d35cc6634c0532925a3b844bc454e4438f44e"), "ETH");
        assert_eq!(top_of("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), "BTC");
        assert_eq!(top_of("550e8400-e29b-41d4-a716-446655440000"), "UUID");
        assert_eq!(top_of("5493001KJTIIGC8Y1R12"), "LEI");
        assert_eq!(top_of("80351110224678912"), "snowflake");
        assert_eq!(top_of("rUocf1ixKzTuEe34kmVhRvGqNCofY1NJzV"), "XRP");
    }

    #[test]
    fn label_cesr_drops_redundant_pubkey_word() {
        // "Ed25519 nt pubkey" -> "CESR, Ed25519 nt"; "Ed25519 pubkey" ->
        // "CESR, Ed25519"; a digest primitive stays verbatim.
        assert_eq!(
            top_of("BGKOqfCS08j0Spr6NfZQt4jXQMbAWo2ynBFjBg5Eib9v"),
            "CESR, Ed25519 nt"
        );
        assert_eq!(
            top_of("DKxy2sgzfplyr_tgwIxS19f2OchFHtLwPWD3v4oYimBx"),
            "CESR, Ed25519"
        );
        assert_eq!(
            top_of("EBfdlu8R27Fbx_ehrqwImnK_8Cm79sqbAQ4caaZG_LFv"),
            "CESR, Blake3-256"
        );
    }

    #[test]
    fn label_self_describing_prefixes() {
        assert_eq!(
            top_of("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
            "did:key"
        );
        assert_eq!(top_of("urn:isbn:0451450523"), "urn:isbn");
        assert_eq!(
            top_of("swh:1:rev:309cf2674ee7a0749978cf8265ab91a60aea0f7d"),
            "swh:1:rev"
        );
        assert_eq!(
            top_of(
                "gitoid:blob:sha256:473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813"
            ),
            "gitoid:blob:sha256"
        );
    }

    #[test]
    fn label_cid_and_ssh_and_multihash_mods_and_size() {
        // CIDv0 -> no MOD; CIDv1 -> codec MOD; SSH -> algorithm MOD + bit SIZE.
        assert_eq!(
            top_of("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"),
            "CIDv0"
        );
        assert_eq!(
            top_of("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"),
            "CIDv1, dag-pb"
        );
        assert_eq!(
            top_of(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDtJVH9hM+2DyhmgRZBfeIDoVqCTbXY+0nKlS5pTkkXY"
            ),
            "SSH, ed25519, 264-bit"
        );
    }

    #[test]
    fn label_blockchain_network_departure_and_variant_drop() {
        // A testnet BCH shows the loud "testnet" MOD; the legacy/segwit variant
        // is dropped, and mainnet stays silent (btc above shows bare "BTC").
        let c = ch("bchtest:qpur7lcrzhq247gvqs5n79hj0tz4edmdqg09nfandy");
        assert_eq!(render_label(&c, false, None, None).0, "BCH, testnet");
    }

    #[test]
    fn label_truncation_marker_and_bottom_strip() {
        // Truncated (>512-bit) prepends the loud marker; the renderer splits it.
        let big = ch(&"a".repeat(400));
        let (top, bottom) = render_label(&big, true, None, None);
        assert!(top.starts_with(TRUNC_MARKER));
        assert_eq!(bottom, "");
        // Bottom strip: suffix only, note only, and both.
        let c = ch("0123456789abcdef0123456789abcdef");
        assert_eq!(render_label(&c, false, Some("vfNa"), None).1, "...vfNa");
        assert_eq!(render_label(&c, false, None, Some("git")).1, "(git)");
        assert_eq!(
            render_label(&c, false, Some("12"), Some("hi")).1,
            "...12 (hi)"
        );
        // Empty suffix / empty note collapse to nothing.
        assert_eq!(render_label(&c, false, Some(""), Some("")).1, "");
    }
}
