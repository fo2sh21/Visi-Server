//! OPAQUE client-side blinding (zero-trust: server never sees password/hash).
//!
//! Wraps `opaque-ke` v4 client API:
//! - `register_start(password) -> (request_bytes, client_state_bytes)`
//! - `register_finish(password, response_bytes, state_bytes) -> (upload, export_key, server_pk)`
//! - `login_start(password) -> (request_bytes, client_state_bytes)`
//! - `login_finish(password, response_bytes, state_bytes) -> (finalization, session_key, export_key, server_pk)`
//!
//! State is serialized to bytes so Kotlin holds it opaquely (survives process
//! death, no Rust-side session map, safe with `isolatedProcess`).
//! KSF is Argon2id m=64MiB,t=3,p=1 via per-call override (see kdf.rs).

use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
    TripleDh,
};
use sha2::Sha512;
use thiserror::Error;

use crate::kdf;

pub struct VisiSuite;
impl CipherSuite for VisiSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = TripleDh<opaque_ke::Ristretto255, Sha512>;
    // Argon2id KSF; every finish call passes our m=64MiB,t=3,p=1 instance.
    type Ksf = argon2::Argon2<'static>;
}

#[derive(Debug, Error)]
pub enum OpaqueError {
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("invalid message encoding: {0}")]
    Encoding(String),
    #[error("kdf error: {0}")]
    Kdf(String),
}

impl From<kdf::KdfError> for OpaqueError {
    fn from(e: kdf::KdfError) -> Self {
        OpaqueError::Kdf(e.to_string())
    }
}

fn ksf() -> Result<argon2::Argon2<'static>, OpaqueError> {
    kdf::opaque_ksf_argon2().map_err(OpaqueError::from)
}

// ---- registration ----

pub struct RegisterStart {
    pub request: Vec<u8>,
    pub state: Vec<u8>,
}

pub fn register_start(password: &[u8]) -> Result<RegisterStart, OpaqueError> {
    let mut rng = rand::rngs::OsRng;
    let res = ClientRegistration::<VisiSuite>::start(&mut rng, password)
        .map_err(|e| OpaqueError::Protocol(format!("{e:?}")))?;
    Ok(RegisterStart {
        request: res.message.serialize().to_vec(),
        state: res.state.serialize().to_vec(),
    })
}

pub struct RegisterFinish {
    pub upload: Vec<u8>,
    pub export_key: Vec<u8>,
    pub server_public_key: Vec<u8>,
}

pub fn register_finish(
    password: &[u8],
    response_bytes: &[u8],
    state_bytes: &[u8],
) -> Result<RegisterFinish, OpaqueError> {
    let response = RegistrationResponse::deserialize(response_bytes)
        .map_err(|e| OpaqueError::Encoding(format!("{e:?}")))?;
    let state = ClientRegistration::<VisiSuite>::deserialize(state_bytes)
        .map_err(|e| OpaqueError::Encoding(format!("{e:?}")))?;
    let k = ksf()?;
    let params = ClientRegistrationFinishParameters {
        ksf: Some(&k),
        ..Default::default()
    };
    let mut rng = rand::rngs::OsRng;
    let res = state
        .finish(&mut rng, password, response, params)
        .map_err(|e| OpaqueError::Protocol(format!("{e:?}")))?;
    Ok(RegisterFinish {
        upload: res.message.serialize().to_vec(),
        export_key: res.export_key.to_vec(),
        server_public_key: res.server_s_pk.serialize().to_vec(),
    })
}

// ---- login ----

pub struct LoginStart {
    pub request: Vec<u8>,
    pub state: Vec<u8>,
}

pub fn login_start(password: &[u8]) -> Result<LoginStart, OpaqueError> {
    let mut rng = rand::rngs::OsRng;
    let res = ClientLogin::<VisiSuite>::start(&mut rng, password)
        .map_err(|e| OpaqueError::Protocol(format!("{e:?}")))?;
    Ok(LoginStart {
        request: res.message.serialize().to_vec(),
        state: res.state.serialize().to_vec(),
    })
}

pub struct LoginFinish {
    pub finalization: Vec<u8>,
    pub session_key: Vec<u8>,
    pub export_key: Vec<u8>,
    pub server_public_key: Vec<u8>,
}

pub fn login_finish(
    password: &[u8],
    response_bytes: &[u8],
    state_bytes: &[u8],
) -> Result<LoginFinish, OpaqueError> {
    let response = CredentialResponse::deserialize(response_bytes)
        .map_err(|e| OpaqueError::Encoding(format!("{e:?}")))?;
    let state = ClientLogin::<VisiSuite>::deserialize(state_bytes)
        .map_err(|e| OpaqueError::Encoding(format!("{e:?}")))?;
    let k = ksf()?;
    let params = ClientLoginFinishParameters {
        ksf: Some(&k),
        ..Default::default()
    };
    let mut rng = rand::rngs::OsRng;
    let res = state
        .finish(&mut rng, password, response, params)
        .map_err(|e| OpaqueError::Protocol(format!("{e:?}")))?;
    Ok(LoginFinish {
        finalization: res.message.serialize().to_vec(),
        session_key: res.session_key.to_vec(),
        export_key: res.export_key.to_vec(),
        server_public_key: res.server_s_pk.serialize().to_vec(),
    })
}

// Re-export message serialize helpers for tests (server-side emulation).
#[cfg(test)]
pub mod test_support {
    use super::*;
    use opaque_ke::{
        CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
        ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
    };
    use rand::rngs::OsRng;

    pub fn full_register_login_roundtrip(password: &[u8]) {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<VisiSuite>::new(&mut rng);

        // registration
        let c0 = register_start(password).unwrap();
        let req = RegistrationRequest::deserialize(&c0.request).unwrap();
        let s0 = ServerRegistration::<VisiSuite>::start(
            &server_setup,
            req,
            b"test-user",
        )
        .unwrap();
        let c1 = register_finish(
            password,
            &s0.message.serialize().to_vec(),
            &c0.state,
        )
        .unwrap();
        let upload = RegistrationUpload::deserialize(&c1.upload).unwrap();
        let password_file = ServerRegistration::<VisiSuite>::finish(upload);

        // login
        let l0 = login_start(password).unwrap();
        let cred_req = CredentialRequest::deserialize(&l0.request).unwrap();
        let s1 = ServerLogin::start(
            &mut rng,
            &server_setup,
            Some(password_file),
            cred_req,
            b"test-user",
            ServerLoginParameters::default(),
        )
        .unwrap();
        let l1 = login_finish(
            password,
            &s1.message.serialize().to_vec(),
            &l0.state,
        )
        .unwrap();
        let fin = CredentialFinalization::deserialize(&l1.finalization).unwrap();
        let s2 = s1
            .state
            .finish(fin, ServerLoginParameters::default())
            .unwrap();
        assert_eq!(l1.session_key, s2.session_key.to_vec());
        // export key continuity registration -> login
        assert_eq!(c1.export_key, l1.export_key);
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::full_register_login_roundtrip;

    #[test]
    fn opaque_register_login_roundtrip() {
        full_register_login_roundtrip(b"correct horse staple");
    }

    #[test]
    fn opaque_wrong_password_fails_login() {
    use super::*;
    use opaque_ke::{
        CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin,
        ServerLoginParameters, ServerRegistration, ServerSetup,
    };
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let server_setup = ServerSetup::<VisiSuite>::new(&mut rng);
        let c0 = register_start(b"right").unwrap();
        let req = RegistrationRequest::deserialize(&c0.request).unwrap();
        let s0 =
            ServerRegistration::<VisiSuite>::start(&server_setup, req, b"u").unwrap();
        let c1 = register_finish(b"right", &s0.message.serialize().to_vec(), &c0.state)
            .unwrap();
        let pf = ServerRegistration::<VisiSuite>::finish(
            RegistrationUpload::deserialize(&c1.upload).unwrap(),
        );
        let l0 = login_start(b"WRONG").unwrap();
        let s1 = ServerLogin::start(
            &mut rng,
            &server_setup,
            Some(pf),
            CredentialRequest::deserialize(&l0.request).unwrap(),
            b"u",
            ServerLoginParameters::default(),
        )
        .unwrap();
        let bad =
            login_finish(b"WRONG", &s1.message.serialize().to_vec(), &l0.state);
        assert!(bad.is_err());
    }
}
