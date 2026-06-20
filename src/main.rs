//! Conformance CLI: read one vector's `input.json` on stdin, write the entviz
//! SVG to stdout (exit 0) or exit non-zero to reject (the contract in the
//! entviz repo's `compliance/README.md`).

use std::io::Read;

use entviz::pipeline::render;

fn main() {
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        eprintln!("entviz-rs: failed to read stdin");
        std::process::exit(2);
    }
    let req: serde_json::Value = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("entviz-rs: invalid request JSON: {e}");
            std::process::exit(2);
        }
    };

    let entropy = req["entropy"].as_str().unwrap_or("");
    let params = &req["params"];
    let target_ar = params["target_ar"].as_f64().unwrap_or(1.0);
    let font_size_pt = params["font_size_pt"].as_f64().unwrap_or(12.0);
    let note = params["note"].as_str();

    match render(entropy, target_ar, font_size_pt, note) {
        Ok(svg) => {
            print!("{svg}");
        }
        Err(e) => {
            eprintln!("entviz-rs: rejected: {e}");
            std::process::exit(1);
        }
    }
}
