//! Client<->sidecar interop: the exact dance FastAPI will orchestrate.
//! Client = `core-crypto` (what ships in the APK), server = sidecar ops.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use opaque_sidecar::handle;
use serde_json::json;

fn b64(b: &[u8]) -> String {
    B64.encode(b)
}

fn field(v: &serde_json::Value, f: &str) -> Vec<u8> {
    B64.decode(v.get(f).and_then(|x| x.as_str()).unwrap()).unwrap()
}

#[test]
fn interop_register_and_login() {
    let pw = b"correct horse staple";
    let user = "alice";

    // ---- setup (once per deployment) ----
    let setup = handle("setup_new", &json!({})).unwrap()["setup"].as_str().unwrap().to_string();

    // ---- registration ----
    let c0 = core_crypto::opaque::register_start(pw).unwrap();
    let s0 = handle(
        "register_start",
        &json!({"setup": setup, "request": b64(&c0.request), "user_id": user}),
    )
    .unwrap();
    let c1 = core_crypto::opaque::register_finish(
        pw,
        &field(&s0, "response"),
        &c0.state,
    )
    .unwrap();
    let s1 = handle("register_finish", &json!({"upload": b64(&c1.upload)})).unwrap();
    let pf = s1["password_file"].as_str().unwrap().to_string();

    // export key continuity will be checked after login
    assert!(!c1.export_key.is_empty());

    // ---- login ----
    let l0 = core_crypto::opaque::login_start(pw).unwrap();
    let t0 = handle(
        "login_start",
        &json!({"setup": setup, "request": b64(&l0.request),
                "user_id": user, "password_file": pf}),
    )
    .unwrap();
    let l1 = core_crypto::opaque::login_finish(pw, &field(&t0, "response"), &l0.state).unwrap();
    let t1 = handle(
        "login_finish",
        &json!({"login_state": t0["login_state"].as_str().unwrap(),
                "finalization": b64(&l1.finalization)}),
    )
    .unwrap();

    // session keys match -> WS token material; export keys match registration
    assert_eq!(l1.session_key, field(&t1, "session_key"));
    assert_eq!(c1.export_key, l1.export_key);
    assert!(!l1.server_public_key.is_empty());
}

#[test]
fn interop_wrong_password_fails_at_finish() {
    let setup = handle("setup_new", &json!({})).unwrap()["setup"].as_str().unwrap().to_string();
    let c0 = core_crypto::opaque::register_start(b"right").unwrap();
    let s0 = handle(
        "register_start",
        &json!({"setup": setup, "request": b64(&c0.request), "user_id": "bob"}),
    )
    .unwrap();
    let c1 = core_crypto::opaque::register_finish(b"right", &field(&s0, "response"), &c0.state).unwrap();
    let s1 = handle("register_finish", &json!({"upload": b64(&c1.upload)})).unwrap();
    let pf = s1["password_file"].as_str().unwrap().to_string();

    let l0 = core_crypto::opaque::login_start(b"WRONG").unwrap();
    let t0 = handle(
        "login_start",
        &json!({"setup": setup, "request": b64(&l0.request),
                "user_id": "bob", "password_file": pf}),
    )
    .unwrap();
    // server happily responds (it cannot tell); the CLIENT rejects, or the
    // server finish rejects — either way no session key is issued.
    let client = core_crypto::opaque::login_finish(b"WRONG", &field(&t0, "response"), &l0.state);
    if let Ok(l1) = client {
        let server = handle(
            "login_finish",
            &json!({"login_state": t0["login_state"].as_str().unwrap(),
                    "finalization": b64(&l1.finalization)}),
        );
        assert!(server.is_err(), "server must reject wrong-password finalization");
    }
}

#[test]
fn interop_dummy_login_for_unknown_user() {
    let setup = handle("setup_new", &json!({})).unwrap()["setup"].as_str().unwrap().to_string();
    let l0 = core_crypto::opaque::login_start(b"whatever").unwrap();
    // password_file omitted entirely
    let t0 = handle(
        "login_start",
        &json!({"setup": setup, "request": b64(&l0.request), "user_id": "ghost"}),
    )
    .unwrap();
    assert!(t0.get("response").and_then(|x| x.as_str()).is_some());
    assert!(t0.get("login_state").and_then(|x| x.as_str()).is_some());
}

#[test]
fn unknown_op_is_a_clean_error() {
    assert!(handle("nope", &json!({})).is_err());
}
