//! `opaque-sidecar` CLI: JSON on stdin, JSON on stdout.
//!
//! Request:  {"op": "<setup_new|register_start|register_finish|login_start|login_finish>", ...fields}
//! Success:  {"ok": {...}}                                    (exit 0)
//! Failure:  {"error": "<message>"}                           (exit 0 — protocol failure, not a crash)
//! Crash (panic/IO): stderr text, nonzero exit — the ONLY case Python must
//! treat as an infrastructure fault rather than an auth outcome.

use std::io::Read;

fn main() {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("stdin: {e}");
        std::process::exit(2);
    }
    let req: serde_json::Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => {
            println!("{}", serde_json::json!({ "error": format!("invalid json: {e}") }));
            return;
        }
    };
    let op = req.get("op").and_then(|o| o.as_str()).unwrap_or("");
    match opaque_sidecar::handle(op, &req) {
        Ok(v) => println!("{}", serde_json::json!({ "ok": v })),
        Err(e) => println!("{}", serde_json::json!({ "error": e.to_string() })),
    }
}
