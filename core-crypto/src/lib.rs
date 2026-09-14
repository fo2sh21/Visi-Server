//! `core-crypto` — Rust crypto sandbox for the Visi app.
//!
//! Kotlin is UI + transport + OS integration only. Every function here is
//! exposed to Kotlin via UniFFI **proc-macros** (no `.udl` file, per decision).
//! Generate Kotlin bindings with:
//! `uniffi-bindgen generate --library <libcore_crypto.so> --language kotlin --out-dir <app/src/main/java>`

uniffi::setup_scaffolding!();

pub mod kdf;
pub mod media;
pub mod opaque;
pub mod signal;

// ---------- UniFFI surface ----------

/// Single error type crossing the JNI bridge (string payloads only — no
/// key material ever appears in errors or logs).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CryptoError {
    #[error("kdf failed: {0}")]
    Kdf(String),
    #[error("opaque failed: {0}")]
    Opaque(String),
    #[error("signal failed: {0}")]
    Signal(String),
    #[error("media failed: {0}")]
    Media(String),
}

fn e_kdf(e: kdf::KdfError) -> CryptoError {
    CryptoError::Kdf(e.to_string())
}
fn e_op(e: opaque::OpaqueError) -> CryptoError {
    CryptoError::Opaque(e.to_string())
}
fn e_sig(e: signal::SignalError) -> CryptoError {
    CryptoError::Signal(e.to_string())
}
fn e_med(e: media::MediaError) -> CryptoError {
    CryptoError::Media(e.to_string())
}

// KDF

/// Argon2id(m=64MiB,t=3,p=1). password_input=PIN/pass, salt=random>=16B,
/// keystore_secret=32B TEE/StrongBox secret. Returns 32B SQLCipher key.
#[uniffi::export]
pub fn kdf_derive_key(
    password_input: Vec<u8>,
    salt: Vec<u8>,
    keystore_secret: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    let k = kdf::derive_key(&password_input, &salt, &keystore_secret).map_err(e_kdf)?;
    Ok(k.to_vec())
}

// OPAQUE

#[derive(uniffi::Record)]
pub struct OpaqueRegisterStart {
    pub request: Vec<u8>,
    pub state: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct OpaqueRegisterFinish {
    pub upload: Vec<u8>,
    pub export_key: Vec<u8>,
    pub server_public_key: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct OpaqueLoginStart {
    pub request: Vec<u8>,
    pub state: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct OpaqueLoginFinish {
    pub finalization: Vec<u8>,
    pub session_key: Vec<u8>,
    pub export_key: Vec<u8>,
    pub server_public_key: Vec<u8>,
}

#[uniffi::export]
pub fn opaque_register_start(password: Vec<u8>) -> Result<OpaqueRegisterStart, CryptoError> {
    let r = opaque::register_start(&password).map_err(e_op)?;
    Ok(OpaqueRegisterStart { request: r.request, state: r.state })
}

#[uniffi::export]
pub fn opaque_register_finish(
    password: Vec<u8>,
    response: Vec<u8>,
    state: Vec<u8>,
) -> Result<OpaqueRegisterFinish, CryptoError> {
    let r = opaque::register_finish(&password, &response, &state).map_err(e_op)?;
    Ok(OpaqueRegisterFinish {
        upload: r.upload,
        export_key: r.export_key,
        server_public_key: r.server_public_key,
    })
}

#[uniffi::export]
pub fn opaque_login_start(password: Vec<u8>) -> Result<OpaqueLoginStart, CryptoError> {
    let r = opaque::login_start(&password).map_err(e_op)?;
    Ok(OpaqueLoginStart { request: r.request, state: r.state })
}

#[uniffi::export]
pub fn opaque_login_finish(
    password: Vec<u8>,
    response: Vec<u8>,
    state: Vec<u8>,
) -> Result<OpaqueLoginFinish, CryptoError> {
    let r = opaque::login_finish(&password, &response, &state).map_err(e_op)?;
    Ok(OpaqueLoginFinish {
        finalization: r.finalization,
        session_key: r.session_key,
        export_key: r.export_key,
        server_public_key: r.server_public_key,
    })
}

// Signal

#[derive(uniffi::Record)]
pub struct IdentityKeypairRec {
    pub seed: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct PreKeyRec {
    pub id: u32,
    pub secret: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct SignedPreKeyRec {
    pub id: u32,
    pub secret: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct PreKeyBundle {
    pub identity_pub_ed: Vec<u8>,
    pub signed_pre_pub_x: Vec<u8>,
    pub signed_pre_sig: Vec<u8>,
    pub onetime_pub_x: Option<Vec<u8>>,
}

fn bundle_from_rec(b: PreKeyBundle) -> Result<signal::Bundle, CryptoError> {
    let cv = |v: Vec<u8>, n: usize| -> Result<Vec<u8>, CryptoError> {
        if v.len() == n {
            Ok(v)
        } else {
            Err(CryptoError::Signal("bad bundle field length".into()))
        }
    };
    let i = cv(b.identity_pub_ed, 32)?;
    let s = cv(b.signed_pre_pub_x, 32)?;
    let g = cv(b.signed_pre_sig, 64)?;
    let o = match b.onetime_pub_x {
        Some(v) => Some(cv(v, 32)?.try_into().map_err(|_| CryptoError::Signal("bad ot".into()))?),
        None => None,
    };
    Ok(signal::Bundle {
        identity_pub_ed: i.try_into().map_err(|_| CryptoError::Signal("bad id".into()))?,
        signed_pre_pub_x: s.try_into().map_err(|_| CryptoError::Signal("bad sp".into()))?,
        signed_pre_sig: g.try_into().map_err(|_| CryptoError::Signal("bad sig".into()))?,
        onetime_pub_x: o,
    })
}

#[uniffi::export]
pub fn signal_identity_generate() -> Result<IdentityKeypairRec, CryptoError> {
    let k = signal::identity_generate();
    Ok(IdentityKeypairRec { seed: k.seed.to_vec(), public_key: k.public_ed.to_vec() })
}

#[uniffi::export]
pub fn signal_prekey_generate(id: u32) -> Result<PreKeyRec, CryptoError> {
    let k = signal::prekey_generate(id);
    Ok(PreKeyRec { id: k.id, secret: k.secret.to_vec(), public_key: k.public.to_vec() })
}

#[uniffi::export]
pub fn signal_signed_prekey_generate(identity_seed: Vec<u8>, id: u32) -> Result<SignedPreKeyRec, CryptoError> {
    let k = signal::signed_prekey_generate(&identity_seed, id).map_err(e_sig)?;
    Ok(SignedPreKeyRec {
        id: k.id,
        secret: k.secret.to_vec(),
        public_key: k.public.to_vec(),
        signature: k.signature.to_vec(),
    })
}

#[derive(uniffi::Record)]
pub struct SessionInitAlice {
    pub session: Vec<u8>,
    pub ephemeral_pub: Vec<u8>,
}

#[uniffi::export]
pub fn signal_session_init_alice(
    alice_identity_seed: Vec<u8>,
    bundle: PreKeyBundle,
) -> Result<SessionInitAlice, CryptoError> {
    let b = bundle_from_rec(bundle)?;
    let (s, e) = signal::session_init_alice(&alice_identity_seed, &b).map_err(e_sig)?;
    Ok(SessionInitAlice { session: s, ephemeral_pub: e.to_vec() })
}

#[uniffi::export]
pub fn signal_session_init_bob(
    bob_identity_seed: Vec<u8>,
    bob_signed_secret: Vec<u8>,
    bob_onetime_secret: Option<Vec<u8>>,
    alice_identity_pub_ed: Vec<u8>,
    alice_ephemeral_pub_x: Vec<u8>,
    bundle_signed_pub_x: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    signal::session_init_bob(
        &bob_identity_seed,
        &bob_signed_secret,
        bob_onetime_secret.as_deref(),
        &alice_identity_pub_ed,
        &alice_ephemeral_pub_x,
        &bundle_signed_pub_x,
    )
    .map_err(e_sig)
}

#[derive(uniffi::Record)]
pub struct EncryptOut {
    pub session: Vec<u8>,
    pub envelope: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct DecryptOut {
    pub session: Vec<u8>,
    pub plaintext: Vec<u8>,
}

#[uniffi::export]
pub fn signal_encrypt(session: Vec<u8>, plaintext: Vec<u8>) -> Result<EncryptOut, CryptoError> {
    let (s, e) = signal::session_encrypt(&session, &plaintext).map_err(e_sig)?;
    Ok(EncryptOut { session: s, envelope: e })
}

#[uniffi::export]
pub fn signal_decrypt(session: Vec<u8>, envelope: Vec<u8>) -> Result<DecryptOut, CryptoError> {
    let (s, p) = signal::session_decrypt(&session, &envelope).map_err(e_sig)?;
    Ok(DecryptOut { session: s, plaintext: p })
}

// Media + integrity

#[uniffi::export]
pub fn media_decrypt(envelope: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let pt = media::decrypt_to_buffer(&envelope, &key).map_err(e_med)?;
    Ok(pt.to_vec())
}

#[uniffi::export]
pub fn media_encrypt(plaintext: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    media::encrypt_buffer(&plaintext, &key).map_err(e_med)
}

/// Explicit shred call for audit (returns zeros). Rust-side buffers already
/// wipe on drop via `Zeroizing`; Kotlin must overwrite its own copies too.
#[uniffi::export]
pub fn media_shred_len(len: u64) -> Vec<u8> {
    media::shred_len(len)
}

/// SHA-256 hex for OTA APK integrity (STEP 6).
#[uniffi::export]
pub fn sha256_hex(data: Vec<u8>) -> String {
    media::sha256_hex(&data)
}
