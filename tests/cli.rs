//! Integration tests for the `entviz-conformance` CLI binary (`src/main.rs`).
//!
//! Exercises the stdin/stdout/exit-code contract from the entviz repo's
//! `compliance/README.md` against the real built executable: render → SVG on
//! stdout with exit 0, hard rejection with exit 1, and malformed input with
//! exit 2.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(stdin: &str) -> (i32, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_entviz-conformance"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn entviz-conformance");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn cli_renders_valid_request() {
    let req = r#"{"entropy":"0123456789abcdef0123456789abcdef","params":{"target_ar":1.0,"font_size_pt":12.0}}"#;
    let (code, stdout) = run(req);
    assert_eq!(code, 0);
    assert!(stdout.starts_with("<svg "));
    assert!(stdout.trim_end().ends_with("</svg>"));
}

#[test]
fn cli_renders_with_defaults_when_params_absent() {
    // Missing params -> the as_f64().unwrap_or(..) defaults kick in.
    let req = r#"{"entropy":"a1b2c3d4e5f6a7b8"}"#;
    let (code, stdout) = run(req);
    assert_eq!(code, 0);
    assert!(stdout.starts_with("<svg "));
}

#[test]
fn cli_rejects_bad_eip55_with_exit_1() {
    let req = r#"{"entropy":"0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed","params":{}}"#;
    let (code, stdout) = run(req);
    assert_eq!(code, 1);
    assert!(stdout.is_empty());
}

#[test]
fn cli_rejects_invalid_json_with_exit_2() {
    let (code, _stdout) = run("not json at all");
    assert_eq!(code, 2);
}
