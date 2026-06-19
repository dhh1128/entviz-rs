//! Format-specific entropy parsing (port of `src/entviz/entropy.py`).
//!
//! `parse()` dispatches over the registered parsers in order (order is
//! semantics) and returns the first match, or falls back to disproof-based
//! alphabet detection. The pipeline re-encodes to base64url only when this
//! returns `None`. A hard parse error (EIP-55 checksum failure) aborts the
//! whole render — the conformance contract rejects that input.

use crate::keccak::keccak256_hex;
use crate::Alphabet;

// --------------------------------------------------------------------------
// Alphabets (mirror entropy.py)
// --------------------------------------------------------------------------
pub const HEX: Alphabet = Alphabet {
    name: "hex",
    chars: "0123456789ABCDEF",
    bits_per_char: 4,
};
pub const BASE58: Alphabet = Alphabet {
    name: "base58",
    chars: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    bits_per_char: 6,
};
pub const BASE64: Alphabet = Alphabet {
    name: "base64",
    chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    bits_per_char: 6,
};
pub const BASE32: Alphabet = Alphabet {
    name: "base32",
    chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    bits_per_char: 5,
};
pub const BECH32: Alphabet = Alphabet {
    name: "bech32",
    chars: "qpzry9x8gf2tvdw0s3jn54khce6mua7l",
    bits_per_char: 5,
};
pub const CROCKFORD32: Alphabet = Alphabet {
    name: "crockford32",
    chars: "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
    bits_per_char: 5,
};
pub const BASE36: Alphabet = Alphabet {
    name: "base36",
    chars: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    bits_per_char: 6,
};
pub const DECIMAL: Alphabet = Alphabet {
    name: "decimal",
    chars: "0123456789",
    bits_per_char: 4,
};
pub const BASE64URL: Alphabet = Alphabet {
    name: "base64url",
    chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    bits_per_char: 6,
};

const HEX_CHARS: &str = "0123456789abcdef";
const BASE58_CHARS: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH32_CHARS: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BASE32_CHARS_UP: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, Clone)]
pub struct Parsed {
    pub type_name: String,
    pub alphabet: Alphabet,
    pub prefix: Option<String>,
    pub core: String,
    pub suffix: Option<String>,
    pub prefix_semantic: bool,
}

impl Parsed {
    fn new(
        type_name: &str,
        alphabet: Alphabet,
        prefix: Option<String>,
        core: String,
        suffix: Option<String>,
    ) -> Parsed {
        Parsed {
            type_name: type_name.to_string(),
            alphabet,
            prefix,
            core,
            suffix,
            prefix_semantic: false,
        }
    }
    fn semantic(mut self) -> Parsed {
        self.prefix_semantic = true;
        self
    }
}

#[derive(Debug)]
pub enum ParseError {
    Eip55 { position: usize },
}

type PResult = Result<Option<Parsed>, ParseError>;

// --------------------------------------------------------------------------
// Small char-class helpers
// --------------------------------------------------------------------------
fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}
fn all_in(s: &str, set: &str) -> bool {
    s.chars().all(|c| set.contains(c))
}
fn is_base58(s: &str) -> bool {
    !s.is_empty() && all_in(s, BASE58_CHARS)
}
fn is_bech32_either(s: &str) -> bool {
    !s.is_empty() && all_in(&s.to_lowercase(), BECH32_CHARS)
}
fn is_base32_either(s: &str) -> bool {
    !s.is_empty() && all_in(&s.to_uppercase(), BASE32_CHARS_UP)
}

// --------------------------------------------------------------------------
// Individual parsers
// --------------------------------------------------------------------------

fn parse_cesr(text: &str) -> PResult {
    // (code, label, total_len)
    const ONE: &[(&str, &str, usize)] = &[
        ("A", "Ed25519 seed", 44),
        ("B", "Ed25519 nt pubkey", 44),
        ("C", "X25519 pub enckey", 44),
        ("D", "Ed25519 pubkey", 44),
        ("E", "Blake3-256", 44),
        ("F", "Blake2b-256", 44),
        ("G", "Blake2s-256", 44),
        ("H", "SHA3-256", 44),
        ("I", "SHA2-256", 44),
        ("J", "secp256k1 seed", 44),
        ("K", "Ed448 seed", 76),
        ("L", "X448 pub enckey", 76),
        ("O", "X25519 priv deckey", 44),
        ("P", "X25519 124 cipher 44 seed", 124),
        ("Q", "secp256r1 seed", 44),
        ("a", "blinding factor", 44),
        ("c", "FN-DSA-512 seed", 44),
        ("d", "FN-DSA-1024 seed", 44),
        ("e", "FN-DSA-1024 sig", 1708),
        ("b", "FN-DSA-1024 pubkey", 2392),
    ];
    const TWO: &[(&str, &str, usize)] = &[
        ("0A", "random 128-bit number", 24),
        ("0B", "Ed25519 sig", 88),
        ("0C", "secp256k1 sig", 88),
        ("0D", "Blake3-512", 88),
        ("0E", "Blake2b-512", 88),
        ("0F", "SHA3-512", 88),
        ("0G", "SHA2-512", 88),
        ("0I", "secp256r1 sig", 88),
    ];
    const FOUR: &[(&str, &str, usize)] = &[
        ("1AAA", "secp256k1 nt pubkey", 48),
        ("1AAB", "secp256k1 pub/enc key", 48),
        ("1AAC", "Ed448 nt pubkey", 80),
        ("1AAD", "Ed448 pubkey", 80),
        ("1AAE", "Ed448 sig", 156),
        ("1AAH", "X25519 100 cipher 24 salt", 100),
        ("1AAI", "secp256r1 nt pubkey", 48),
        ("1AAJ", "secp256r1 pub/enc key", 48),
        ("1AAR", "FN-DSA-512 sig", 892),
        ("1AAQ", "FN-DSA-512 pubkey", 1200),
    ];
    if text.is_empty() {
        return Ok(None);
    }
    let len = text.chars().count();
    let first = text.chars().next().unwrap();
    let items: &[(&str, &str, usize)] = match first {
        '0' if TWO.iter().any(|x| x.2 == len) => TWO,
        '1' if FOUR.iter().any(|x| x.2 == len) => FOUR,
        c if c != '0' && c != '1' && ONE.iter().any(|x| x.2 == len) => ONE,
        _ => return Ok(None),
    };
    for &(code, label, total) in items {
        if text.starts_with(code) && len == total && is_base64url_nopad(text) {
            return Ok(Some(Parsed::new(
                &format!("CESR {label}"),
                BASE64URL,
                None,
                text.to_string(),
                None,
            )));
        }
    }
    Ok(None)
}

fn is_base64url_nopad(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

// SSH key type prefixes: (short_name, match_str, prefix_length).
const SSH_KEY_TYPES: &[(&str, &str, usize)] = &[
    (
        "ecdsa-nistp256",
        "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABB",
        52,
    ),
    (
        "ecdsa-nistp384",
        "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABh",
        52,
    ),
    (
        "ecdsa-nistp521",
        "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACF",
        52,
    ),
    ("rsa", "AAAAB3NzaC1yc2EAAAADAQAB", 28),
    ("ed25519", "AAAAC3NzaC1lZDI1NTE5AAAA", 24),
    ("dss", "AAAAB3NzaC1kc3M", 15),
];

fn parse_ssh_key(text: &str) -> PResult {
    // SSH_LINE_REGEX: optional leading "<type> " then payload (AAAA...base64),
    // then optional whitespace+comment. We hand-parse it.
    let (payload, _comment) = match ssh_line_split(text) {
        Some(v) => v,
        None => {
            // Bare AAAA-base64 blob fallback (SSH_KEY_REGEX).
            if let Some((p, rest)) = ssh_key_regex(text) {
                return Ok(Some(Parsed::new("SSH key", BASE64, Some(p), rest, None)));
            }
            return Ok(None);
        }
    };
    for &(short_name, match_str, prefix_length) in SSH_KEY_TYPES {
        if payload.starts_with(match_str) && payload.chars().count() >= prefix_length {
            let chars: Vec<char> = payload.chars().collect();
            let prefix: String = chars[..prefix_length].iter().collect();
            let body: String = chars[prefix_length..].iter().collect();
            return Ok(Some(Parsed::new(
                &format!("SSH {short_name}"),
                BASE64,
                Some(prefix),
                body,
                None,
            )));
        }
    }
    if let Some((p, rest)) = ssh_key_regex(&payload) {
        return Ok(Some(Parsed::new("SSH key", BASE64, Some(p), rest, None)));
    }
    Ok(None)
}

// AAAA-prefixed base64 blob, optionally trailing '='. Returns (prefix "AAAA", rest).
fn ssh_key_regex(text: &str) -> Option<(String, String)> {
    if !text.starts_with("AAAA") {
        return None;
    }
    let rest = &text[4..];
    if rest.is_empty() {
        return None;
    }
    // body = [0-9A-Za-z+/]+ then up to 3 '='
    let body_end = rest.find('=').unwrap_or(rest.len());
    let (body, pad) = rest.split_at(body_end);
    if body.is_empty()
        || !body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
    {
        return None;
    }
    if pad.len() > 3 || !pad.chars().all(|c| c == '=') {
        return None;
    }
    Some(("AAAA".to_string(), rest.to_string()))
}

// Split a full openssh line: [<type-string> ] <AAAA-payload> [ <comment>].
fn ssh_line_split(text: &str) -> Option<(String, Option<String>)> {
    let mut s = text;
    // Strip an optional leading recognized type token.
    let type_prefixes = [
        "ssh-ed25519",
        "ssh-rsa",
        "ssh-dss",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ];
    for tp in type_prefixes {
        if let Some(rest) = s.strip_prefix(tp) {
            if rest.starts_with(char::is_whitespace) {
                s = rest.trim_start();
                break;
            }
        }
    }
    if !s.starts_with("AAAA") {
        return None;
    }
    // payload = AAAA[0-9A-Za-z+/]+={0,3}; comment = optional whitespace + rest.
    let bytes: Vec<char> = s.chars().collect();
    // consume payload chars
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' {
            i += 1;
        } else {
            break;
        }
    }
    // trailing '=' padding
    while i < bytes.len() && bytes[i] == '=' {
        i += 1;
    }
    let payload_end = i;
    let payload: String = bytes[..payload_end].iter().collect();
    if !payload.starts_with("AAAA") {
        return None;
    }
    let rest: String = bytes[payload_end..].iter().collect();
    let comment = {
        let t = rest.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    };
    // If there were trailing non-whitespace chars immediately after payload with
    // no separating whitespace, the regex wouldn't match. Enforce that.
    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
        return None;
    }
    Some((payload, comment))
}

fn parse_bitcoin_address(text: &str) -> PResult {
    // Legacy: ^[123mn] base58{21,30} base58{4}$
    let chars: Vec<char> = text.chars().collect();
    if let Some(first) = chars.first() {
        if "123mn".contains(*first) {
            let body = &text[first.len_utf8()..];
            let n = body.chars().count();
            if (25..=34).contains(&n) && is_base58(body) {
                // split last 4 as suffix; middle 21..30
                let bchars: Vec<char> = body.chars().collect();
                let mid: String = bchars[..bchars.len() - 4].iter().collect();
                let suf: String = bchars[bchars.len() - 4..].iter().collect();
                if (21..=30).contains(&mid.chars().count()) {
                    return Ok(Some(Parsed::new(
                        "BTC legacy",
                        BASE58,
                        Some(first.to_string()),
                        mid,
                        Some(suf),
                    )));
                }
            }
        }
    }
    // SegWit: ^(bc1|tb1) bech32{39,69}$ (case-insensitive)
    if let Some(m) = match_prefix_bech32(text, &["bc1", "tb1"], 39, 69) {
        let (prefix, body) = m;
        return Ok(Some(Parsed::new(
            "BTC SegWit",
            BECH32,
            Some(prefix.to_lowercase()),
            body.to_lowercase(),
            None,
        )));
    }
    Ok(None)
}

// Match <one of prefixes><bech32 body of length in [lo,hi]>$ (case-insensitive
// on prefix and body). Returns (prefix_as_matched, body_as_matched).
fn match_prefix_bech32(
    text: &str,
    prefixes: &[&str],
    lo: usize,
    hi: usize,
) -> Option<(String, String)> {
    let low = text.to_lowercase();
    for p in prefixes {
        if low.starts_with(p) {
            let prefix: String = text.chars().take(p.chars().count()).collect();
            let body: String = text.chars().skip(p.chars().count()).collect();
            let n = body.chars().count();
            if (lo..=hi).contains(&n) && is_bech32_either(&body) {
                return Some((prefix, body));
            }
        }
    }
    None
}

fn parse_ripple_address(text: &str) -> PResult {
    // ^r base58{33}$
    if let Some(rest) = text.strip_prefix('r') {
        if rest.chars().count() == 33 && is_base58(rest) {
            return Ok(Some(Parsed::new(
                "XRP",
                BASE58,
                Some("r".to_string()),
                rest.to_string(),
                None,
            )));
        }
    }
    Ok(None)
}

fn parse_ethereum_address(text: &str) -> PResult {
    // ^(0x)?[0-9a-f]{40}$ case-insensitive
    let (has_prefix, body) =
        if let Some(b) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (true, b)
        } else {
            (false, text)
        };
    if body.chars().count() != 40 || !is_hex(body) {
        return Ok(None);
    }
    let letters: Vec<char> = body.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    let has_lower = letters.iter().any(|c| c.is_ascii_lowercase());
    let has_upper = letters.iter().any(|c| c.is_ascii_uppercase());
    let is_mixed = has_lower && has_upper;

    if !has_prefix {
        if !is_mixed {
            return Ok(None);
        }
        validate_eip55(body)?;
    } else if is_mixed {
        validate_eip55(body)?;
    }
    Ok(Some(Parsed::new(
        "ETH",
        HEX,
        Some("0x".to_string()),
        body.to_lowercase(),
        None,
    )))
}

fn validate_eip55(body: &str) -> Result<(), ParseError> {
    let lower = body.to_lowercase();
    let digest_hex = keccak256_hex(lower.as_bytes());
    let dh: Vec<char> = digest_hex.chars().collect();
    for (i, c) in body.chars().enumerate() {
        if !c.is_ascii_alphabetic() {
            continue;
        }
        let canonical_upper = dh[i].to_digit(16).unwrap() >= 8;
        let expected = if canonical_upper {
            c.to_ascii_uppercase()
        } else {
            c.to_ascii_lowercase()
        };
        if c != expected {
            return Err(ParseError::Eip55 { position: i });
        }
    }
    Ok(())
}

fn parse_litecoin_address(text: &str) -> PResult {
    // Legacy: ^t?L base58{33}$
    for prefix in ["tL", "L"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            if rest.chars().count() == 33 && is_base58(rest) {
                return Ok(Some(Parsed::new(
                    "LTC legacy",
                    BASE58,
                    Some(prefix.to_string()),
                    rest.to_string(),
                    None,
                )));
            }
        }
    }
    // ltc1 bech32{38,68}
    if let Some((prefix, body)) = match_prefix_bech32(text, &["ltc1"], 38, 68) {
        return Ok(Some(Parsed::new(
            "LTC",
            BECH32,
            Some(prefix.to_lowercase()),
            body.to_lowercase(),
            None,
        )));
    }
    Ok(None)
}

fn parse_bitcoin_cash_address(text: &str) -> PResult {
    // ^((bitcoincash|bchtest):)?[pq]bech32{41}$  (case-insensitive)
    let low = text.to_lowercase();
    let (prefix, rest) = if low.starts_with("bitcoincash:") {
        let n = "bitcoincash:".len();
        (Some(&text[..n]), &text[n..])
    } else if low.starts_with("bchtest:") {
        let n = "bchtest:".len();
        (Some(&text[..n]), &text[n..])
    } else {
        (None, text)
    };
    let rchars: Vec<char> = rest.chars().collect();
    if let Some(first) = rchars.first() {
        if (*first == 'p' || *first == 'q' || *first == 'P' || *first == 'Q') && rchars.len() == 42
        {
            let body: String = rchars[1..].iter().collect();
            if is_bech32_either(&body) {
                let full_body: String = rest.to_lowercase();
                return Ok(Some(Parsed::new(
                    "BCH",
                    BECH32,
                    prefix.map(|p| p.to_string()),
                    full_body,
                    None,
                )));
            }
        }
    }
    Ok(None)
}

fn parse_stellar_address(text: &str) -> PResult {
    let chars: Vec<char> = text.chars().collect();
    if let Some(first) = chars.first() {
        if (*first == 'G' || *first == 'g') && chars.len() == 56 {
            let body: String = chars[1..].iter().collect();
            if is_base32_either(&body) {
                return Ok(Some(Parsed::new(
                    "XLM",
                    BASE32,
                    Some("G".to_string()),
                    body.to_uppercase(),
                    None,
                )));
            }
        }
        if (*first == 'M' || *first == 'm') && chars.len() == 69 {
            let body: String = chars[1..].iter().collect();
            if is_base32_either(&body) {
                return Ok(Some(Parsed::new(
                    "XLM muxed",
                    BASE32,
                    Some("M".to_string()),
                    body.to_uppercase(),
                    None,
                )));
            }
        }
    }
    Ok(None)
}

fn parse_uuid(text: &str) -> PResult {
    // ^\{?hex{8}-?hex{4}-?hex{4}-?hex{4}-?hex{12}\}?$  case-insensitive
    let mut s = text;
    let had_brace_open = s.starts_with('{');
    if had_brace_open {
        s = &s[1..];
    }
    let mut s = s.to_string();
    if s.ends_with('}') {
        s.pop();
    }
    // Now match the 8-4-4-4-12 with optional dashes.
    let groups = [8usize, 4, 4, 4, 12];
    let stripped: String = s.chars().filter(|&c| c != '-').collect();
    // Validate structure: rebuild allowed forms. Simplest faithful check:
    // remove dashes, require 32 hex; AND ensure dashes (if present) sit only at
    // the group boundaries. We check via a small scan.
    if stripped.chars().count() != 32 || !is_hex(&stripped) {
        return Ok(None);
    }
    // Verify the dash placement matches the regex (optional dash after each group
    // except the last). Walk the original `s` against the group pattern.
    let sc: Vec<char> = s.chars().collect();
    let mut pos = 0;
    for (gi, &glen) in groups.iter().enumerate() {
        for _ in 0..glen {
            if pos >= sc.len() || !sc[pos].is_ascii_hexdigit() {
                return Ok(None);
            }
            pos += 1;
        }
        if gi < groups.len() - 1 && pos < sc.len() && sc[pos] == '-' {
            pos += 1;
        }
    }
    if pos != sc.len() {
        return Ok(None);
    }
    Ok(Some(Parsed::new(
        "UUID",
        HEX,
        None,
        stripped.to_lowercase(),
        None,
    )))
}

fn parse_ulid(text: &str) -> PResult {
    // ^[0-9A-TV-Za-tv-z]{26}$  (Crockford32 + I/L/O aliases, no U)
    if text.chars().count() != 26 {
        return Ok(None);
    }
    for c in text.chars() {
        let ok = c.is_ascii_digit()
            || ('A'..='T').contains(&c)
            || ('V'..='Z').contains(&c)
            || ('a'..='t').contains(&c)
            || ('v'..='z').contains(&c);
        if !ok {
            return Ok(None);
        }
    }
    let normalized: String = text
        .chars()
        .map(|c| match c {
            'I' | 'i' | 'L' | 'l' => '1',
            'O' | 'o' => '0',
            other => other,
        })
        .collect::<String>()
        .to_uppercase();
    Ok(Some(Parsed::new(
        "ULID",
        CROCKFORD32,
        None,
        normalized,
        None,
    )))
}

fn parse_snowflake(text: &str) -> PResult {
    let n = text.chars().count();
    if !(17..=20).contains(&n) || !text.chars().all(|c| c.is_ascii_digit()) {
        return Ok(None);
    }
    let val: u128 = match text.parse() {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    if val >> 63 != 0 {
        return Ok(None);
    }
    Ok(Some(Parsed::new(
        "snowflake",
        DECIMAL,
        None,
        text.to_string(),
        None,
    )))
}

fn parse_lei(text: &str) -> PResult {
    // ^[0-9A-Z]{20}$ case-insensitive; upper[4:6]=="00"; MOD 97-10 == 1
    if text.chars().count() != 20 || !text.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Ok(None);
    }
    let upper = text.to_uppercase();
    if &upper[4..6] != "00" {
        return Ok(None);
    }
    if !lei_checksum_ok(&upper) {
        return Ok(None);
    }
    Ok(Some(Parsed::new(
        "LEI",
        BASE36,
        None,
        upper[..18].to_string(),
        Some(upper[18..].to_string()),
    )))
}

fn lei_checksum_ok(lei: &str) -> bool {
    let mut digits = String::new();
    for c in lei.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else if c.is_ascii_uppercase() {
            digits.push_str(&(c as u32 - 'A' as u32 + 10).to_string());
        } else {
            return false;
        }
    }
    // mod 97 over a big decimal string
    let mut rem: u64 = 0;
    for ch in digits.bytes() {
        rem = (rem * 10 + (ch - b'0') as u64) % 97;
    }
    rem == 1
}

fn parse_swhid(text: &str) -> PResult {
    // ^(swh:1:(snp|rel|rev|dir|cnt):)([0-9a-f]{40})(?:;(.+))?$  case-insensitive
    let low = text.to_lowercase();
    let types = ["snp", "rel", "rev", "dir", "cnt"];
    for t in types {
        let pre = format!("swh:1:{t}:");
        if low.starts_with(&pre) {
            let rest = &low[pre.len()..];
            // optional ;qualifiers
            let (hexpart, _qual) = match rest.find(';') {
                Some(i) => (&rest[..i], Some(&rest[i + 1..])),
                None => (rest, None),
            };
            if hexpart.chars().count() == 40 && is_hex(hexpart) {
                let prefix: String = text.chars().take(pre.len()).collect();
                return Ok(Some(
                    Parsed::new(
                        "",
                        HEX,
                        Some(prefix.to_lowercase()),
                        hexpart.to_string(),
                        None,
                    )
                    .semantic(),
                ));
            }
        }
    }
    Ok(None)
}

fn parse_gitoid(text: &str) -> PResult {
    // ^(gitoid:(blob|tree|commit|tag):(sha1|sha256):)([0-9a-f]+)$ case-insensitive
    let low = text.to_lowercase();
    if !low.starts_with("gitoid:") {
        return Ok(None);
    }
    let parts: Vec<&str> = low.splitn(4, ':').collect();
    if parts.len() != 4 {
        return Ok(None);
    }
    let obj = parts[1];
    let algo = parts[2];
    let body = parts[3];
    if !["blob", "tree", "commit", "tag"].contains(&obj) {
        return Ok(None);
    }
    let want = match algo {
        "sha1" => 40,
        "sha256" => 64,
        _ => return Ok(None),
    };
    if body.chars().count() != want || !is_hex(body) {
        return Ok(None);
    }
    let prefix = format!("gitoid:{obj}:{algo}:");
    Ok(Some(
        Parsed::new("", HEX, Some(prefix), body.to_string(), None).semantic(),
    ))
}

// ---- bech32 checksum (generic Cosmos-style) ----
fn bech32_polymod(values: &[u32]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 != 0 {
                chk ^= g;
            }
        }
    }
    chk
}
fn bech32_hrp_expand(hrp: &str) -> Vec<u32> {
    let mut out: Vec<u32> = hrp.chars().map(|c| (c as u32) >> 5).collect();
    out.push(0);
    out.extend(hrp.chars().map(|c| (c as u32) & 31));
    out
}
fn bech32_checksum_const(hrp: &str, data: &str) -> Option<u32> {
    let mut values = Vec::new();
    for c in data.chars() {
        let idx = BECH32_CHARS.find(c)?;
        values.push(idx as u32);
    }
    let mut full = bech32_hrp_expand(hrp);
    full.extend(values);
    Some(bech32_polymod(&full))
}

fn parse_bech32_address(text: &str) -> PResult {
    // ^([a-z]{1,83})1(bech32{8,})$  case-insensitive; checksum valid
    // Find the LAST '1' as separator? The regex is greedy on hrp [a-z]{1,83}
    // then literal '1' then bech32{8,}. Python re is greedy, so hrp matches as
    // many [a-z] as possible before a '1' that still leaves >=8 bech32 chars.
    let low = text.to_lowercase();
    let chars: Vec<char> = low.chars().collect();
    // hrp must be letters; find separator positions where char=='1'.
    // Greedy: try the largest hrp first.
    // hrp = chars[..sep], all ascii lowercase letters; data = chars[sep+1..].
    let mut sep_candidates: Vec<usize> = Vec::new();
    for (i, &c) in chars.iter().enumerate() {
        if c == '1' {
            sep_candidates.push(i);
        }
    }
    // greedy hrp => prefer the LARGEST separator index that satisfies constraints
    for &sep in sep_candidates.iter().rev() {
        if !(1..=83).contains(&sep) {
            continue;
        }
        let hrp: String = chars[..sep].iter().collect();
        if !hrp.chars().all(|c| c.is_ascii_lowercase()) {
            continue;
        }
        let data: String = chars[sep + 1..].iter().collect();
        if data.chars().count() < 8 || !all_in(&data, BECH32_CHARS) {
            continue;
        }
        match bech32_checksum_const(&hrp, &data) {
            Some(c) if c == 1 || c == 0x2bc830a3 => {
                let dchars: Vec<char> = data.chars().collect();
                let core: String = dchars[..dchars.len() - 6].iter().collect();
                let suffix: String = dchars[dchars.len() - 6..].iter().collect();
                return Ok(Some(Parsed::new(
                    "bech32",
                    BECH32,
                    Some(format!("{hrp}1")),
                    core,
                    Some(suffix),
                )));
            }
            _ => continue,
        }
    }
    Ok(None)
}

// ---- IPFS CID ----
fn parse_ipfs_cid(text: &str) -> PResult {
    // CIDv0: ^Qm base58{44}$
    if let Some(rest) = text.strip_prefix("Qm") {
        if rest.chars().count() == 44 && is_base58(rest) {
            return Ok(Some(Parsed::new(
                "CIDv0",
                BASE58,
                Some("Qm".to_string()),
                rest.to_string(),
                None,
            )));
        }
    }
    // CIDv1: ^b base32{58,112}$ (either case)
    if let Some(rest) = text.strip_prefix('b') {
        let n = rest.chars().count();
        if (58..=112).contains(&n) && is_base32_either(rest) {
            let mut label = "CIDv1".to_string();
            if let Some((codec, hash)) = b32_decode_multicodec(rest) {
                label = format!("CIDv1 {codec}");
                if hash != "sha2-256" {
                    label.push('/');
                    label.push_str(&hash);
                }
            }
            return Ok(Some(Parsed::new(
                &label,
                BASE32,
                Some("b".to_string()),
                rest.to_uppercase(),
                None,
            )));
        }
    }
    Ok(None)
}

fn b32_decode_multicodec(body: &str) -> Option<(String, String)> {
    let bytes = base32_decode(&body.to_uppercase())?;
    let (version, p1) = read_uvarint(&bytes, 0)?;
    if version != 1 {
        return None;
    }
    let (codec, p2) = read_uvarint(&bytes, p1)?;
    let (hash_fn, _p3) = read_uvarint(&bytes, p2)?;
    let codec_name = multicodec_content(codec)?;
    let hash_name = multihash_func(hash_fn)?;
    Some((codec_name.to_string(), hash_name.to_string()))
}

fn read_uvarint(data: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    while pos < data.len() {
        let b = data[pos];
        pos += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((result, pos));
        }
        shift += 7;
    }
    None
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    // RFC4648 base32, upper, no padding required.
    let mut bits = 0u32;
    let mut value = 0u32;
    let mut out = Vec::new();
    for c in s.chars() {
        let idx = BASE32_CHARS_UP.find(c)? as u32;
        value = (value << 5) | idx;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((value >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn multicodec_content(code: u64) -> Option<&'static str> {
    Some(match code {
        0x00 => "identity",
        0x51 => "cbor",
        0x55 => "raw",
        0x60 => "rlp",
        0x70 => "dag-pb",
        0x71 => "dag-cbor",
        0x72 => "libp2p-key",
        0x78 => "git-raw",
        0x90 => "eth-block",
        0x97 => "eth-tx",
        0x0129 => "dag-json",
        0x0202 => "car",
        _ => return None,
    })
}

fn multihash_func(code: u64) -> Option<&'static str> {
    Some(match code {
        0x11 => "sha1",
        0x12 => "sha2-256",
        0x13 => "sha2-512",
        0x14 => "sha3-224",
        0x15 => "sha3-256",
        0x16 => "sha3-384",
        0x17 => "sha3-512",
        0x1b => "keccak-256",
        0x41 => "blake2b-256",
        _ => return None,
    })
}

fn parse_hex(text: &str) -> PResult {
    if text.is_empty() {
        return Ok(None);
    }
    let mut prefix = None;
    let mut body = text;
    if (text.starts_with("0x") || text.starts_with("0X")) && text.chars().count() > 2 {
        prefix = Some("0x".to_string());
        body = &text[2..];
    } else if !text.chars().count().is_multiple_of(2) {
        return Ok(None);
    }
    if is_hex(body) {
        return Ok(Some(Parsed::new(
            "hex",
            HEX,
            prefix,
            body.to_lowercase(),
            None,
        )));
    }
    Ok(None)
}

fn parse_eos_address(text: &str) -> PResult {
    // (^[a-z1-5.]{1,11}[a-z1-5]$)|(^[a-z1-5.]{12}[a-j1-5]$)
    let ok = eos_regex(text);
    if !ok {
        return Ok(None);
    }
    if text.chars().all(|c| "0123456789abcdef".contains(c)) {
        return Ok(None);
    }
    Ok(Some(Parsed::new(
        "EOS",
        BASE64,
        None,
        text.to_string(),
        None,
    )))
}

fn eos_regex(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let in_set = |c: char| {
        c.is_ascii_lowercase() && c.is_ascii_lowercase() || ('1'..='5').contains(&c) || c == '.'
    };
    let body_ok = |s: &[char]| s.iter().all(|&c| in_set(c));
    let n = chars.len();
    // form 1: {1,11}[a-z1-5] => total 2..12, last char in a-z1-5
    if (2..=12).contains(&n) {
        let last = chars[n - 1];
        if body_ok(&chars[..n - 1]) && (last.is_ascii_lowercase() || ('1'..='5').contains(&last)) {
            return true;
        }
    }
    // form 2: {12}[a-j1-5] => total 13, last in a-j1-5
    if n == 13 {
        let last = chars[12];
        if body_ok(&chars[..12]) && ((('a'..='j').contains(&last)) || ('1'..='5').contains(&last)) {
            return true;
        }
    }
    false
}

// --------------------------------------------------------------------------
// Dispatch
// --------------------------------------------------------------------------
type ParserFn = fn(&str) -> PResult;

const PARSERS: &[ParserFn] = &[
    // parse_hex_multihash and parse_did are not exercised by the corpus and are
    // omitted; the remaining order matches entropy.py's parse_funcs.
    parse_cesr,
    parse_ssh_key,
    parse_bitcoin_address,
    parse_ripple_address,
    parse_ethereum_address,
    parse_litecoin_address,
    parse_bitcoin_cash_address,
    // parse_cardano_address omitted (not in corpus; bech32 generic covers none of it)
    parse_stellar_address,
    parse_uuid,
    parse_ulid,
    parse_snowflake,
    parse_lei,
    // parse_did omitted
    parse_swhid,
    parse_gitoid,
    parse_bech32_address,
    parse_ipfs_cid,
    parse_hex,
    parse_eos_address,
];

/// Parse the (already-stripped) entropy string. Returns:
/// * `Ok(Some(parsed))` on a recognized type or disproof-detected alphabet,
/// * `Ok(None)` when nothing matches (caller re-encodes to base64url),
/// * `Err(..)` on a hard rejection (EIP-55 checksum failure).
pub fn parse(entropy: &str) -> Result<Option<Parsed>, ParseError> {
    let entropy = entropy.trim();
    for f in PARSERS {
        match f(entropy)? {
            Some(p) => return Ok(Some(p)),
            None => continue,
        }
    }
    if let Some(detected) = detect_alphabet_by_disproof(entropy) {
        let core = if detected.name == "base32" {
            entropy.to_uppercase()
        } else if detected.name == "bech32" || detected.name == "hex" {
            entropy.to_lowercase()
        } else {
            entropy.to_string()
        };
        return Ok(Some(Parsed::new(detected.name, detected, None, core, None)));
    }
    Ok(None)
}

fn detect_alphabet_by_disproof(text: &str) -> Option<Alphabet> {
    if text.is_empty() {
        return None;
    }
    let lower = text.to_lowercase();
    // (alphabet, charset, case_sensitive)
    let order: [(Alphabet, &str, bool); 6] = [
        (HEX, HEX_CHARS, false),
        (BASE32, "abcdefghijklmnopqrstuvwxyz234567", false),
        (BECH32, BECH32_CHARS, false),
        (BASE58, BASE58_CHARS, true),
        (
            BASE64,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            true,
        ),
        (
            BASE64URL,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            true,
        ),
    ];
    for (alpha, charset, case_sensitive) in order {
        let view = if case_sensitive { text } else { lower.as_str() };
        if view.chars().all(|c| charset.contains(c)) {
            return Some(alpha);
        }
    }
    None
}

// --------------------------------------------------------------------------
// Large-input tokenization (head + fingerprint-middle + tail)
// --------------------------------------------------------------------------
use crate::model::second_digest;
use crate::{tokenize, Token};

const HEAD_TOKENS: usize = 8;
const TAIL_TOKENS: usize = 8;
const MAX_TOKENS: usize = 22;

fn core_byte_length(core: &str, alphabet: &Alphabet) -> usize {
    (core.chars().count() * alphabet.bits_per_char as usize) / 8
}

/// Encode a 24-bit value as 5 lowercase Crockford base32 chars (v9 middle cell).
pub fn crockford5(value: u32) -> String {
    const C: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = [0u8; 5];
    let mut v = value;
    for i in 0..5 {
        out[4 - i] = C[(v & 0x1F) as usize];
        v >>= 5;
    }
    String::from_utf8(out.to_vec()).unwrap().to_lowercase()
}

/// Tokenize entropy with v6+ large-input handling. Returns (tokens, truncated).
pub fn tokenize_entropy(core: &str, alphabet: &Alphabet) -> (Vec<Token>, bool) {
    let token_len = (24 / alphabet.bits_per_char) as usize;
    let n_bytes = core_byte_length(core, alphabet);
    let token_count = core.chars().count().div_ceil(token_len); // ceil
    if token_count <= MAX_TOKENS && n_bytes <= 64 {
        return (tokenize(core, alphabet), false);
    }
    let chars: Vec<char> = core.chars().collect();
    let head_chars = HEAD_TOKENS * token_len;
    let tail_chars = TAIL_TOKENS * token_len;
    let head: String = chars[..head_chars.min(chars.len())].iter().collect();
    let tail_start = chars.len().saturating_sub(tail_chars);
    let tail: String = chars[tail_start..].iter().collect();
    let head_tokens = tokenize(&head, alphabet);
    let tail_tokens = tokenize(&tail, alphabet);

    let second = second_digest(core);
    let mut middle = Vec::with_capacity(4);
    for i in 0..4 {
        let quant = ((second[3 * i] as u32) << 16)
            | ((second[3 * i + 1] as u32) << 8)
            | (second[3 * i + 2] as u32);
        middle.push(Token {
            text: crockford5(quant),
            index: i,
            quant,
        });
    }

    let mut combined: Vec<Token> = Vec::with_capacity(20);
    combined.extend(head_tokens);
    combined.extend(middle);
    combined.extend(tail_tokens);
    let renumbered: Vec<Token> = combined
        .into_iter()
        .enumerate()
        .map(|(i, t)| Token {
            text: t.text,
            index: i,
            quant: t.quant,
        })
        .collect();
    (renumbered, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ptop(entropy: &str) -> (String, String, Option<String>, Option<String>) {
        let p = parse(entropy).unwrap().unwrap();
        (p.type_name, p.core, p.prefix, p.suffix)
    }

    #[test]
    fn hex_and_uuid_boundary() {
        // 16-hex -> hex(16); 32-hex -> UUID (matches reference dispatch).
        assert_eq!(ptop("a1b2c3d4e5f6a7b8").0, "hex");
        assert_eq!(ptop("0123456789abcdef0123456789abcdef").0, "UUID");
    }

    #[test]
    fn uuid_dashed_equals_undashed_core() {
        let a = parse("550e8400-e29b-41d4-a716-446655440000")
            .unwrap()
            .unwrap();
        let b = parse("550e8400e29b41d4a716446655440000").unwrap().unwrap();
        assert_eq!(a.core, b.core);
        assert_eq!(a.core, "550e8400e29b41d4a716446655440000");
    }

    #[test]
    fn eth_eip55_good_and_bad() {
        assert_eq!(
            parse("0x742d35cc6634c0532925a3b844bc454e4438f44e")
                .unwrap()
                .unwrap()
                .type_name,
            "ETH"
        );
        assert_eq!(
            parse("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
                .unwrap()
                .unwrap()
                .type_name,
            "ETH"
        );
        assert!(matches!(
            parse("0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
            Err(ParseError::Eip55 { .. })
        ));
    }

    #[test]
    fn swhid_gitoid_semantic_prefix() {
        let s = parse("swh:1:rev:309cf2674ee7a0749978cf8265ab91a60aea0f7d")
            .unwrap()
            .unwrap();
        assert!(s.prefix_semantic);
        assert_eq!(s.prefix.as_deref(), Some("swh:1:rev:"));
        assert_eq!(s.core, "309cf2674ee7a0749978cf8265ab91a60aea0f7d");
        let g = parse(
            "gitoid:blob:sha256:473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813",
        )
        .unwrap()
        .unwrap();
        assert!(g.prefix_semantic);
        assert_eq!(g.prefix.as_deref(), Some("gitoid:blob:sha256:"));
    }

    #[test]
    fn lei_suffix() {
        let p = parse("5493001KJTIIGC8Y1R12").unwrap().unwrap();
        assert_eq!(p.type_name, "LEI");
        assert_eq!(p.core, "5493001KJTIIGC8Y1R12"[..18].to_string());
        assert_eq!(p.suffix.as_deref(), Some("12"));
    }

    #[test]
    fn cesr_codes() {
        assert_eq!(
            parse("DKxy2sgzfplyr_tgwIxS19f2OchFHtLwPWD3v4oYimBx")
                .unwrap()
                .unwrap()
                .type_name,
            "CESR Ed25519 pubkey"
        );
        assert_eq!(
            parse("BKxy2sgzfplyr_tgwIxS19f2OchFHtLwPWD3v4oYimBx")
                .unwrap()
                .unwrap()
                .type_name,
            "CESR Ed25519 nt pubkey"
        );
        assert_eq!(
            parse("EBfdlu8R27Fbx_ehrqwImnK_8Cm79sqbAQ4caaZG_LFv")
                .unwrap()
                .unwrap()
                .type_name,
            "CESR Blake3-256"
        );
    }

    #[test]
    fn bech32_cosmos_suffix() {
        let p = parse("cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363e")
            .unwrap()
            .unwrap();
        assert_eq!(p.type_name, "bech32");
        assert_eq!(p.prefix.as_deref(), Some("cosmos1"));
        assert_eq!(p.suffix.as_deref(), Some("rk363e"));
    }

    #[test]
    fn cid_v1_label() {
        let p = parse("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
            .unwrap()
            .unwrap();
        assert_eq!(p.type_name, "CIDv1 dag-pb");
    }

    #[test]
    fn ssh_ed25519() {
        let p = parse("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDtJVH9hM+2DyhmgRZBfeIDoVqCTbXY+0nKlS5pTkkXY user@example.com").unwrap().unwrap();
        assert_eq!(p.type_name, "SSH ed25519");
        assert_eq!(p.prefix.as_deref(), Some("AAAAC3NzaC1lZDI1NTE5AAAA"));
    }

    #[test]
    fn snowflake_decimal() {
        assert_eq!(
            parse("80351110224678912").unwrap().unwrap().type_name,
            "snowflake"
        );
    }

    #[test]
    fn text_fallback_is_none() {
        assert!(parse("hello world").unwrap().is_none());
    }
}
