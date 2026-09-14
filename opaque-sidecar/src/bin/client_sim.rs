//! client-sim: generates REAL client OPAQUE messages (core-crypto) for live
//! FastAPI tests. JSON on stdin, JSON on stdout. Mirrors sidecar framing.
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::io::Read;

fn b64(b: &[u8]) -> String {
    B64.encode(b)
}
fn ub64(s: &str) -> Vec<u8> {
    B64.decode(s).unwrap()
}

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let req: serde_json::Value = serde_json::from_str(&input).unwrap();
    let op = req.get("op").and_then(|o| o.as_str()).unwrap_or("");
    let out = match op {
        "reg_start" => {
            let pw = ub64(req["password_b64"].as_str().unwrap());
            let r = core_crypto::opaque::register_start(&pw).unwrap();
            serde_json::json!({"request": b64(&r.request), "state": b64(&r.state)})
        }
        "reg_finish" => {
            let pw = ub64(req["password_b64"].as_str().unwrap());
            let resp = ub64(req["response_b64"].as_str().unwrap());
            let st = ub64(req["state_b64"].as_str().unwrap());
            let r = core_crypto::opaque::register_finish(&pw, &resp, &st).unwrap();
            serde_json::json!({
                "upload": b64(&r.upload),
                "export_key": b64(&r.export_key),
                "server_public_key": b64(&r.server_public_key),
            })
        }
        "login_start" => {
            let pw = ub64(req["password_b64"].as_str().unwrap());
            let r = core_crypto::opaque::login_start(&pw).unwrap();
            serde_json::json!({"request": b64(&r.request), "state": b64(&r.state)})
        }
        "login_finish" => {
            let pw = ub64(req["password_b64"].as_str().unwrap());
            let resp = ub64(req["response_b64"].as_str().unwrap());
            let st = ub64(req["state_b64"].as_str().unwrap());
            match core_crypto::opaque::login_finish(&pw, &resp, &st) {
                Ok(r) => serde_json::json!({
                    "finalization": b64(&r.finalization),
                    "session_key": b64(&r.session_key),
                    "export_key": b64(&r.export_key),
                }),
                Err(e) => {
                    println!("{}", serde_json::json!({"error": e.to_string()}));
                    return;
                }
            }
        }
        _ => {
            println!("{}", serde_json::json!({"error": "unknown op"}));
            return;
        }
    };
    println!("{}", serde_json::json!({"ok": out}));
}
