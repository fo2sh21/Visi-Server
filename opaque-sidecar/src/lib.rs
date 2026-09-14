//! OPAQUE server-side operations for the Visi relay server.
//!
//! Same crate + same cipher suite as the Android client (`VisiSuite` from
//! `core-crypto`), so suite match is by construction, not by careful reading.
//! The FastAPI server treats this binary as a black box: JSON in on stdin,
//! JSON out on stdout, blobs stored in Postgres, never inspected.
//!
//! Suite (locked): OPRF Ristretto255-SHA512, KEX TripleDH-SHA512,
//! KSF Argon2id(m=65536 KiB, t=3, p=1), envelope mode `VisiApp`.
//! (Mode/identifiers use opaque-ke defaults; client+server share this crate.)

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use core_crypto::opaque::VisiSuite;
use opaque_ke::{
    RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginParameters,
    ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SidecarError {
    #[error("bad request: {0}")]
    Request(String),
    #[error("protocol failure: {0}")]
    Protocol(String),
}

fn b64_get(v: &Value, field: &str) -> Result<Vec<u8>, SidecarError> {
    v.get(field)
        .and_then(|x| x.as_str())
        .ok_or_else(|| SidecarError::Request(format!("missing field `{field}`")))
        .and_then(|s| B64.decode(s).map_err(|e| SidecarError::Request(format!("{field}: {e}"))))
}

fn str_get(v: &Value, field: &str) -> Result<String, SidecarError> {
    v.get(field)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| SidecarError::Request(format!("missing field `{field}`")))
}

fn b64(b: &[u8]) -> String {
    B64.encode(b)
}

fn setup_from(v: &Value) -> Result<ServerSetup<VisiSuite>, SidecarError> {
    let raw = b64_get(v, "setup")?;
    ServerSetup::deserialize(&raw).map_err(|e| SidecarError::Request(format!("setup: {e:?}")))
}

// ---------- ops (pure logic, unit-tested) ----------

/// Create a fresh `ServerSetup`. Run ONCE per deployment; store the blob.
pub fn op_setup_new() -> Value {
    let mut rng = OsRng;
    let setup = ServerSetup::<VisiSuite>::new(&mut rng);
    json!({ "setup": b64(&setup.serialize()) })
}

/// Registration step 2 (server): RegistrationRequest -> RegistrationResponse.
pub fn op_register_start(input: &Value) -> Result<Value, SidecarError> {
    let setup = setup_from(input)?;
    let req_raw = b64_get(input, "request")?;
    let user_id = str_get(input, "user_id")?;
    let req = RegistrationRequest::deserialize(&req_raw)
        .map_err(|e| SidecarError::Request(format!("request: {e:?}")))?;
    let res = ServerRegistration::<VisiSuite>::start(&setup, req, user_id.as_bytes())
        .map_err(|e| SidecarError::Protocol(format!("{e:?}")))?;
    Ok(json!({ "response": b64(&res.message.serialize()) }))
}

/// Registration step 4 (server): RegistrationUpload -> password file blob.
pub fn op_register_finish(input: &Value) -> Result<Value, SidecarError> {
    let up_raw = b64_get(input, "upload")?;
    let up = RegistrationUpload::deserialize(&up_raw)
        .map_err(|e| SidecarError::Request(format!("upload: {e:?}")))?;
    let pf = ServerRegistration::<VisiSuite>::finish(up);
    Ok(json!({ "password_file": b64(&pf.serialize()) }))
}

/// Login step 2 (server). `password_file: null` for unknown users produces a
/// dummy response indistinguishable from a real one (no enumeration oracle).
/// Returns the CredentialResponse PLUS an opaque `login_state` blob the caller
/// must hand back to `login_finish` (subprocess is stateless).
pub fn op_login_start(input: &Value) -> Result<Value, SidecarError> {
    let setup = setup_from(input)?;
    let req_raw = b64_get(input, "request")?;
    let user_id = str_get(input, "user_id")?;
    let req = opaque_ke::CredentialRequest::deserialize(&req_raw)
        .map_err(|e| SidecarError::Request(format!("request: {e:?}")))?;
    let pf = match input.get("password_file").and_then(|x| x.as_str()) {
        Some(s) => {
            let raw = B64
                .decode(s)
                .map_err(|e| SidecarError::Request(format!("password_file: {e}")))?;
            Some(
                ServerRegistration::<VisiSuite>::deserialize(&raw)
                    .map_err(|e| SidecarError::Request(format!("password_file: {e:?}")))?,
            )
        }
        None => None,
    };
    let mut rng = OsRng;
    let res = ServerLogin::start(
        &mut rng,
        &setup,
        pf,
        req,
        user_id.as_bytes(),
        ServerLoginParameters::default(),
    )
    .map_err(|e| SidecarError::Protocol(format!("{e:?}")))?;
    Ok(json!({
        "response": b64(&res.message.serialize()),
        "login_state": b64(&res.state.serialize()),
    }))
}

/// Login step 4 (server): CredentialFinalization -> session key (matches the
/// client's session key; use it to mint the WS token, then forget it).
pub fn op_login_finish(input: &Value) -> Result<Value, SidecarError> {
    let st_raw = b64_get(input, "login_state")?;
    let fin_raw = b64_get(input, "finalization")?;
    let state = ServerLogin::<VisiSuite>::deserialize(&st_raw)
        .map_err(|e| SidecarError::Request(format!("login_state: {e:?}")))?;
    let fin = opaque_ke::CredentialFinalization::deserialize(&fin_raw)
        .map_err(|e| SidecarError::Request(format!("finalization: {e:?}")))?;
    let res = state
        .finish(fin, ServerLoginParameters::default())
        .map_err(|e| SidecarError::Protocol(format!("{e:?}")))?;
    Ok(json!({ "session_key": b64(res.session_key.as_ref()) }))
}

/// Dispatch one JSON request object. Used by main() and by tests.
pub fn handle(op: &str, input: &Value) -> Result<Value, SidecarError> {
    match op {
        "setup_new" => Ok(op_setup_new()),
        "register_start" => op_register_start(input),
        "register_finish" => op_register_finish(input),
        "login_start" => op_login_start(input),
        "login_finish" => op_login_finish(input),
        _ => Err(SidecarError::Request(format!("unknown op `{op}`"))),
    }
}
