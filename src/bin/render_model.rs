//! `entviz-render-model` — the differential oracle's Rust side.
//!
//! Reads one JSON request on stdin and prints the computed render model as JSON
//! (the Python golden `compliance/corpus/<name>/model.json` schema, minus the
//! label channel) on stdout. The entviz-rs core has no parsers, so the caller
//! (the Python differential harness in entviz-adversarial) supplies everything
//! the parser would have produced:
//!
//! ```json
//! {
//!   "core": "0123456789abcdef…",      // normalized core (cell text source)
//!   "fingerprint_core": "0123…",       // = prefix‖core for semantic-prefix
//!                                       //   types (SWHID/gitoid); else = core
//!   "alphabet": {"name": "hex", "chars": "0123456789ABCDEF", "bits_per_char": 4},
//!   "target_ar": 1.0,
//!   "font_pt": 12.0,
//!   "bottom_strip": false,             // suffix or user-note adds a bottom band
//!   "raw_bytes": 64                    // len(raw_input.encode("utf-8"))
//! }
//! ```
//!
//! Both the short and large (>512-bit head/middle/tail) paths are supported.
//! An empty/unmodelable core exits 2.

use std::io::Read;

use entviz::model::{color_field, compute_render_model_fp, ModelError};
use entviz::{Alphabet, POSSIBLE_EDGE_COLORS};

fn fail(code: i32, msg: &str) -> ! {
    eprintln!("entviz-render-model: {msg}");
    std::process::exit(code);
}

fn main() {
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        fail(2, "failed to read stdin");
    }
    let req: serde_json::Value = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(e) => fail(2, &format!("invalid request JSON: {e}")),
    };

    let core = req["core"].as_str().unwrap_or_else(|| fail(2, "missing `core`"));
    // fingerprint_core defaults to core when absent.
    let fp_core = req["fingerprint_core"].as_str().unwrap_or(core);
    let target_ar = req["target_ar"].as_f64().unwrap_or(1.0);
    let font_pt = req["font_pt"].as_f64().unwrap_or(12.0);
    let bottom_strip = req["bottom_strip"].as_bool().unwrap_or(false);
    let raw_bytes = req["raw_bytes"].as_u64().unwrap_or(0) as usize;

    let alph = &req["alphabet"];
    let name = alph["name"].as_str().unwrap_or_else(|| fail(2, "missing alphabet.name"));
    let chars = alph["chars"].as_str().unwrap_or_else(|| fail(2, "missing alphabet.chars"));
    let bits = alph["bits_per_char"]
        .as_u64()
        .unwrap_or_else(|| fail(2, "missing alphabet.bits_per_char")) as u32;

    // The lib's `Alphabet` holds &'static str. This binary is short-lived and
    // builds exactly one alphabet, so leaking the two request strings to obtain
    // 'static lifetimes is the simplest faithful bridge (no lib change).
    let alphabet = Alphabet {
        name: Box::leak(name.to_string().into_boxed_str()),
        chars: Box::leak(chars.to_string().into_boxed_str()),
        bits_per_char: bits,
    };

    // `--colorfield`: print the v10 color-singleton field (bg + fingerprint-edge
    // + blank-fill colors, as hex) instead of the full model, for golden-SVG
    // validation of the blank-fill formula (the only color channel the Tier-A
    // oracle does not cover).
    if std::env::args().any(|a| a == "--colorfield") {
        let cf = color_field(core, fp_core, &alphabet, target_ar, font_pt, bottom_strip);
        let hex = |i: u8| POSSIBLE_EDGE_COLORS.get(i as usize).copied().unwrap_or("?");
        let pairs = |v: &[(usize, u8)]| {
            v.iter()
                .map(|&(ci, c)| format!("[{ci},\"{}\"]", hex(c)))
                .collect::<Vec<_>>()
                .join(",")
        };
        println!(
            "{{\"bg\":\"{}\",\"fp_edge\":[{}],\"blank_fill\":[{}]}}",
            hex(cf.bg),
            pairs(&cf.fp_edge),
            pairs(&cf.blank_fill),
        );
        return;
    }

    match compute_render_model_fp(core, fp_core, &alphabet, target_ar, font_pt, bottom_strip, raw_bytes)
    {
        Ok(model) => {
            println!("{}", model.to_golden_json());
        }
        Err(ModelError::Empty) => fail(2, "empty core"),
    }
}
