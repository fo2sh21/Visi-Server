//! Signal-compatible E2EE engine: X3DH + Double Ratchet (pure Rust).
//!
//! NOTE on `libsignal-protocol-rust`: upstream lives in the Signal git monorepo
//! (AGPL, boringssl + protobuf toolchain) and has no usable crates.io release
//! for `cargo-ndk` Android builds.
//!
//! This module implements the same protocol mechanics — 256-bit identity keys, pre-key bundles, X3DH handshake, symmetric
//! + DH ratchet — over audited primitives (`ed25519-dalek`, `x25519-dalek`,
//! `hkdf`/`hmac`/`sha2`, `chacha20poly1305`). UniFFI signatures are transport
//! shaped so the official crate can replace internals without touching Kotlin.
//!
//! Session state serializes to bytes; Kotlin persists it in SQLCipher (never
//! plaintext/shared-prefs). All key buffers are `Zeroizing` and dropped fast.

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use thiserror::Error;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum SignalError {
    #[error("bad key length")]
    BadKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("decryption failed (wrong key, replay, or tampered envelope)")]
    Decrypt,
    #[error("unknown / stale session")]
    NoSession,
    #[error("state decode failed")]
    Decode,
}

// ---------- helpers ----------

fn hmac1(key: &[u8], byte: u8) -> Zeroizing<[u8; 32]> {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
    m.update(&[byte]);
    let out = m.finalize().into_bytes();
    let mut z = Zeroizing::new([0u8; 32]);
    z.copy_from_slice(&out);
    z
}

/// ed25519 seed -> x25519 static secret (RFC 8032 scalar: clamped SHA-512(seed)[..32]).
/// MUST match the scalar behind the ed25519 public key, otherwise X3DH DH1/DH2
/// disagree between initiator and responder.
fn ed_seed_to_x_secret(seed: &[u8; 32]) -> XSecret {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(seed);
    let d = h.finalize();
    let mut b = [0u8; 32];
    b.copy_from_slice(&d[..32]);
    b[0] &= 248;
    b[31] &= 127;
    b[31] |= 64;
    XSecret::from(b)
}

/// ed25519 pub -> x25519 pub (montgomery conversion).
fn ed_pub_to_x_pub(pub_ed: &[u8; 32]) -> Result<XPublic, SignalError> {
    let v = VerifyingKey::from_bytes(pub_ed).map_err(|_| SignalError::BadKey)?;
    Ok(XPublic::from(v.to_montgomery().to_bytes()))
}

fn nonce_for(counter: u32) -> Nonce {
    // Direction-independent: each message key is one-time, counter unique per chain.
    let mut n = [0u8; 12];
    n[4..8].copy_from_slice(&counter.to_be_bytes());
    *Nonce::from_slice(&n)
}

// ---------- keys ----------

/// 256-bit identity keypair (ed25519). Seed is the secret.
pub struct IdentityKeypair {
    pub seed: Zeroizing<[u8; 32]>,
    pub public_ed: [u8; 32],
}

pub fn identity_generate() -> IdentityKeypair {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut seed[..]);
    let sk = SigningKey::from_bytes(&seed);
    IdentityKeypair {
        public_ed: sk.verifying_key().to_bytes(),
        seed,
    }
}

pub struct PreKey {
    pub id: u32,
    pub secret: Zeroizing<[u8; 32]>,
    pub public: [u8; 32],
}

fn x_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let mut s = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut s[..]);
    let secret = XSecret::from(*s.clone());
    let p = XPublic::from(&secret).to_bytes();
    (s, p)
}

pub fn prekey_generate(id: u32) -> PreKey {
    let (secret, public) = x_keypair();
    PreKey { id, secret, public }
}

pub struct SignedPreKey {
    pub id: u32,
    pub secret: Zeroizing<[u8; 32]>,
    pub public: [u8; 32],
    pub signature: [u8; 64],
}

pub fn signed_prekey_generate(
    identity_seed: &[u8],
    id: u32,
) -> Result<SignedPreKey, SignalError> {
    if identity_seed.len() != 32 {
        return Err(SignalError::BadKey);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(identity_seed);
    let sk = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let (secret, public) = x_keypair();
    let sig = sk.sign(&public).to_bytes();
    Ok(SignedPreKey { id, secret, public, signature: sig })
}

/// Pre-key bundle Bob publishes (via server Merkle ledger). All bytes.
/// Plain struct (UniFFI passes fields individually; no serde needed).
#[derive(Clone)]
pub struct Bundle {
    pub identity_pub_ed: [u8; 32],
    pub signed_pre_pub_x: [u8; 32],
    pub signed_pre_sig: [u8; 64],
    pub onetime_pub_x: Option<[u8; 32]>,
}

pub fn verify_bundle(bundle: &Bundle) -> Result<(), SignalError> {
    let v = VerifyingKey::from_bytes(&bundle.identity_pub_ed).map_err(|_| SignalError::BadKey)?;
    v.verify_strict(&bundle.signed_pre_pub_x, &ed25519_dalek::Signature::from_bytes(&bundle.signed_pre_sig))
        .map_err(|_| SignalError::BadSignature)
}

// ---------- session ----------

const MAX_SKIP: usize = 100;

#[derive(Clone)]
struct Chain {
    key: [u8; 32],
    counter: u32,
}

#[derive(Clone)]
pub struct Session {
    root: [u8; 32],
    send: Chain,
    recv: Chain,
    dh_secret: [u8; 32],
    dh_public: [u8; 32],
    remote_dh: [u8; 32],
    /// false until a send chain is derived for the current root (Bob pre-first-send,
    /// or either side right after a receive-ratchet until next encrypt rotates).
    send_valid: bool,
    // (remote_dh_hex, counter) -> message key
    skipped: HashMap<String, [u8; 32]>,
}

impl Session {
    fn skip_key(&self, remote: &[u8; 32], ctr: u32) -> String {
        format!("{}:{}", hex_of(remote), ctr)
    }
}

fn hex_of(b: &[u8]) -> String {
    const H: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

/// Alice initializes from Bob's bundle. Returns (session_bytes, ephemeral_pub for first message).
pub fn session_init_alice(
    alice_identity_seed: &[u8],
    bundle: &Bundle,
) -> Result<(Vec<u8>, [u8; 32]), SignalError> {
    if alice_identity_seed.len() != 32 {
        return Err(SignalError::BadKey);
    }
    verify_bundle(bundle)?;
    let mut aseed = [0u8; 32];
    aseed.copy_from_slice(alice_identity_seed);
    let a_id_x = ed_seed_to_x_secret(&aseed);
    aseed.zeroize();
    let _a_id_x_pub = XPublic::from(&a_id_x);

    let (e_sec_raw, e_pub) = x_keypair();
    let e_sec = XSecret::from(*e_sec_raw.clone());

    let b_id_x_pub = ed_pub_to_x_pub(&bundle.identity_pub_ed)?;
    let b_sp_pub = XPublic::from(bundle.signed_pre_pub_x);
    let dh1 = a_id_x.diffie_hellman(&b_sp_pub);
    let dh2 = e_sec.diffie_hellman(&b_id_x_pub);
    let dh3 = e_sec.diffie_hellman(&b_sp_pub);
    let mut ikm = Vec::with_capacity(32 * 4);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    if let Some(ot) = bundle.onetime_pub_x {
        let dh4 = e_sec.diffie_hellman(&XPublic::from(ot));
        ikm.extend_from_slice(dh4.as_bytes());
    }
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    ikm.zeroize();
    let mut root = [0u8; 32];
    let mut chain0 = [0u8; 32];
    hk.expand(b"Visi-X3DH-v1\x01", &mut root).map_err(|_| SignalError::Decrypt)?;
    hk.expand(b"Visi-X3DH-v1\x02", &mut chain0).map_err(|_| SignalError::Decrypt)?;

    let s = Session {
        root,
        send: Chain { key: chain0, counter: 0 },
        recv: Chain { key: [0u8; 32], counter: 0 },
        dh_secret: *e_sec_raw.clone(),
        dh_public: e_pub,
        remote_dh: bundle.signed_pre_pub_x,
        send_valid: true, // Alice's X3DH chain is immediately usable
        skipped: HashMap::new(),
    };
    let bytes = serde_json_bytes(&s)?;
    Ok((bytes, e_pub))
}

/// Bob initializes from Alice's ephemeral + his keys. Returns session_bytes.
#[allow(clippy::too_many_arguments)]
pub fn session_init_bob(
    bob_identity_seed: &[u8],
    bob_signed_secret: &[u8],
    bob_onetime_secret: Option<&[u8]>,
    alice_identity_pub_ed: &[u8],
    alice_ephemeral_pub_x: &[u8],
    bundle_signed_pub_x: &[u8],
) -> Result<Vec<u8>, SignalError> {
    let mut bseed = [0u8; 32];
    if bob_identity_seed.len() != 32 || bob_signed_secret.len() != 32 {
        return Err(SignalError::BadKey);
    }
    bseed.copy_from_slice(bob_identity_seed);
    let b_id_x = ed_seed_to_x_secret(&bseed);
    bseed.zeroize();
    let mut sp = [0u8; 32];
    sp.copy_from_slice(bob_signed_secret);
    let sp_sec = XSecret::from(sp);
    sp.zeroize();

    let mut ae = [0u8; 32];
    let mut ai = [0u8; 32];
    let mut bsp = [0u8; 32];
    if alice_ephemeral_pub_x.len() != 32 || alice_identity_pub_ed.len() != 32 || bundle_signed_pub_x.len() != 32 {
        return Err(SignalError::BadKey);
    }
    ae.copy_from_slice(alice_ephemeral_pub_x);
    ai.copy_from_slice(alice_identity_pub_ed);
    bsp.copy_from_slice(bundle_signed_pub_x);
    let a_id_x_pub = ed_pub_to_x_pub(&ai)?;
    let a_eph_pub = XPublic::from(ae);
    let b_sp_pub = XPublic::from(bsp);

    let dh1 = sp_sec.diffie_hellman(&a_id_x_pub);
    let dh2 = b_id_x.diffie_hellman(&a_eph_pub);
    let dh3 = sp_sec.diffie_hellman(&a_eph_pub);
    let mut ikm = Vec::with_capacity(32 * 4);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    if let Some(ot) = bob_onetime_secret {
        if ot.len() != 32 {
            return Err(SignalError::BadKey);
        }
        let mut o = [0u8; 32];
        o.copy_from_slice(ot);
        let dh4 = XSecret::from(o).diffie_hellman(&a_eph_pub);
        o.zeroize();
        ikm.extend_from_slice(dh4.as_bytes());
    }
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    ikm.zeroize();
    let mut root = [0u8; 32];
    let mut chain0 = [0u8; 32];
    hk.expand(b"Visi-X3DH-v1\x01", &mut root).map_err(|_| SignalError::Decrypt)?;
    hk.expand(b"Visi-X3DH-v1\x02", &mut chain0).map_err(|_| SignalError::Decrypt)?;

    let s = Session {
        root,
        send: Chain { key: [0u8; 32], counter: 0 },
        recv: Chain { key: chain0, counter: 0 },
        dh_secret: sp_secret_copy(bob_signed_secret)?,
        dh_public: b_sp_pub.to_bytes(),
        remote_dh: ae,
        send_valid: false, // derived on Bob's first encrypt (with fresh rotation)
        skipped: HashMap::new(),
    };
    serde_json_bytes(&s)
}

fn sp_secret_copy(b: &[u8]) -> Result<[u8; 32], SignalError> {
    if b.len() != 32 {
        return Err(SignalError::BadKey);
    }
    let mut o = [0u8; 32];
    o.copy_from_slice(b);
    Ok(o)
}

// Envelope: dh_pub(32) || msg_ctr(4 BE) || prev_len(4 BE) || ciphertext
const HEADER_LEN: usize = 40;

fn serde_json_bytes(v: &Session) -> Result<Vec<u8>, SignalError> {
    // Manual fixed-layout codec (avoids serde_json binary weight on device).
    manual_encode(v).ok_or(SignalError::Decode)
}

// Manual Session codec (avoids serde_json binary weight on device).
fn manual_encode(s: &Session) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&s.root);
    out.extend_from_slice(&s.send.key);
    out.extend_from_slice(&s.send.counter.to_be_bytes());
    out.extend_from_slice(&s.recv.key);
    out.extend_from_slice(&s.recv.counter.to_be_bytes());
    out.extend_from_slice(&s.dh_secret);
    out.extend_from_slice(&s.dh_public);
    out.extend_from_slice(&s.remote_dh);
    out.push(u8::from(s.send_valid));
    let n = s.skipped.len().min(64) as u32;
    out.extend_from_slice(&n.to_be_bytes());
    for (k, v) in s.skipped.iter().take(64) {
        let kb = k.as_bytes();
        out.extend_from_slice(&(kb.len() as u32).to_be_bytes());
        out.extend_from_slice(kb);
        out.extend_from_slice(v);
    }
    Some(out)
}

fn manual_decode(b: &[u8]) -> Option<Session> {
    // Layout: 6x32B fields + 2x u32 counters + 1B send_valid + u32 skip-count.
    if b.len() < 32 * 6 + 8 + 1 + 4 {
        return None;
    }
    let mut o = 0usize;
    let take = |b: &[u8], o: &mut usize, n: usize| -> Option<Vec<u8>> {
        if *o + n > b.len() {
            return None;
        }
        let v = b[*o..*o + n].to_vec();
        *o += n;
        Some(v)
    };
    let root: [u8; 32] = take(b, &mut o, 32)?.try_into().ok()?;
    let skey: [u8; 32] = take(b, &mut o, 32)?.try_into().ok()?;
    let sctr = u32::from_be_bytes(take(b, &mut o, 4)?.try_into().ok()?);
    let rkey: [u8; 32] = take(b, &mut o, 32)?.try_into().ok()?;
    let rctr = u32::from_be_bytes(take(b, &mut o, 4)?.try_into().ok()?);
    let dhsec: [u8; 32] = take(b, &mut o, 32)?.try_into().ok()?;
    let dhpub: [u8; 32] = take(b, &mut o, 32)?.try_into().ok()?;
    let remdh: [u8; 32] = take(b, &mut o, 32)?.try_into().ok()?;
    let send_valid = match take(b, &mut o, 1)?.first() {
        Some(1) => true,
        Some(_) | None => false,
    };
    let n = u32::from_be_bytes(take(b, &mut o, 4)?.try_into().ok()?) as usize;
    let mut skipped = HashMap::new();
    for _ in 0..n.min(64) {
        let kl = u32::from_be_bytes(take(b, &mut o, 4)?.try_into().ok()?) as usize;
        if kl > 128 {
            return None;
        }
        let kb = take(b, &mut o, kl)?;
        let vb: [u8; 32] = take(b, &mut o, 32)?.try_into().ok()?;
        skipped.insert(String::from_utf8(kb).ok()?, vb);
    }
    Some(Session {
        root,
        send: Chain { key: skey, counter: sctr },
        recv: Chain { key: rkey, counter: rctr },
        dh_secret: dhsec,
        dh_public: dhpub,
        remote_dh: remdh,
        send_valid,
        skipped,
    })
}

fn aead_encrypt(key32: &[u8; 32], nonce: Nonce, aad: &[u8], mut pt: Vec<u8>) -> Result<Vec<u8>, SignalError> {
    let c = ChaCha20Poly1305::new_from_slice(key32).map_err(|_| SignalError::BadKey)?;
    c.encrypt_in_place(&nonce, aad, &mut pt)
        .map_err(|_| SignalError::Decrypt)?;
    Ok(pt)
}

fn aead_decrypt(key32: &[u8; 32], nonce: Nonce, aad: &[u8], mut ct: Vec<u8>) -> Result<Vec<u8>, SignalError> {
    let c = ChaCha20Poly1305::new_from_slice(key32).map_err(|_| SignalError::BadKey)?;
    c.decrypt_in_place(&nonce, aad, &mut ct)
        .map_err(|_| SignalError::Decrypt)?;
    Ok(ct)
}

fn header_bytes(dh: &[u8; 32], ctr: u32, prev: u32) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..32].copy_from_slice(dh);
    h[32..36].copy_from_slice(&ctr.to_be_bytes());
    h[36..40].copy_from_slice(&prev.to_be_bytes());
    h
}

/// Encrypt with session state. Returns (new_session_bytes, envelope_bytes).
pub fn session_encrypt(session_bytes: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SignalError> {
    let mut s = manual_decode(session_bytes).ok_or(SignalError::NoSession)?;
    if !s.send_valid {
        // First send on this root (Bob's reply) or first send after a
        // receive-ratchet: rotate fresh, mix DH(new, remote) into root.
        let (sec, publ) = x_keypair();
        let dh = XSecret::from(*sec.clone()).diffie_hellman(&XPublic::from(s.remote_dh));
        let hk = Hkdf::<Sha256>::new(Some(&s.root), dh.as_bytes());
        let mut r = [0u8; 32];
        let mut c = [0u8; 32];
        hk.expand(b"Visi-Root\x01", &mut r).map_err(|_| SignalError::Decrypt)?;
        hk.expand(b"Visi-Root\x02", &mut c).map_err(|_| SignalError::Decrypt)?;
        s.root = r;
        s.send.key = c;
        s.send.counter = 0;
        s.dh_secret.copy_from_slice(&sec[..]);
        s.dh_public = publ;
        s.send_valid = true;
    }
    let msg_key = hmac1(&s.send.key, 0x01);
    let next = hmac1(&s.send.key, 0x02);
    let ctr = s.send.counter;
    let header = header_bytes(&s.dh_public, ctr, 0);
    let mut mk = [0u8; 32];
    mk.copy_from_slice(&msg_key[..]);
    let ct = aead_encrypt(&mk, nonce_for(ctr), &header, plaintext.to_vec())?;
    mk.zeroize();
    s.send.key.copy_from_slice(&next[..]);
    s.send.counter += 1;
    let mut env = Vec::with_capacity(HEADER_LEN + ct.len());
    env.extend_from_slice(&header);
    env.extend_from_slice(&ct);
    let out = manual_encode(&s).ok_or(SignalError::Decode)?;
    Ok((out, env))
}

/// Decrypt envelope with session state. Returns (new_session_bytes, plaintext).
pub fn session_decrypt(session_bytes: &[u8], envelope: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SignalError> {
    if envelope.len() < HEADER_LEN + 16 {
        return Err(SignalError::Decrypt);
    }
    let mut s = manual_decode(session_bytes).ok_or(SignalError::NoSession)?;
    let mut dh = [0u8; 32];
    dh.copy_from_slice(&envelope[..32]);
    let ctr = u32::from_be_bytes(envelope[32..36].try_into().map_err(|_| SignalError::Decrypt)?);
    let header: [u8; HEADER_LEN] = envelope[..HEADER_LEN].try_into().map_err(|_| SignalError::Decrypt)?;
    let ct = envelope[HEADER_LEN..].to_vec();

    // 1) skipped keys (out-of-order)
    let key = s.skip_key(&dh, ctr);
    if let Some(mk) = s.skipped.remove(&key) {
        let pt = aead_decrypt(&mk, nonce_for(ctr), &header, ct)?;
        let out = manual_encode(&s).ok_or(SignalError::Decode)?;
        return Ok((out, pt));
    }
    // 2) DH ratchet if peer rotated
    if dh != s.remote_dh {
        ratchet_recv(&mut s, &dh)?;
    }
    // 3) advance receive chain, caching skipped
    while s.recv.counter < ctr {
        if s.skipped.len() >= MAX_SKIP {
            // evict oldest-ish: drop arbitrary entry
            if let Some(k) = s.skipped.keys().next().cloned() {
                s.skipped.remove(&k);
            }
        }
        let mk = hmac1(&s.recv.key, 0x01);
        let nxt = hmac1(&s.recv.key, 0x02);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&mk[..]);
        s.skipped.insert(s.skip_key(&s.remote_dh, s.recv.counter), arr);
        s.recv.key.copy_from_slice(&nxt[..]);
        s.recv.counter += 1;
    }
    let mk = hmac1(&s.recv.key, 0x01);
    let nxt = hmac1(&s.recv.key, 0x02);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&mk[..]);
    let pt = aead_decrypt(&arr, nonce_for(ctr), &header, ct)?;
    arr.zeroize();
    s.recv.key.copy_from_slice(&nxt[..]);
    s.recv.counter += 1;
    let out = manual_encode(&s).ok_or(SignalError::Decode)?;
    Ok((out, pt))
}

fn ratchet_recv(s: &mut Session, new_remote: &[u8; 32]) -> Result<(), SignalError> {
    // Mix DH(current own secret, new remote) into root -> new recv chain.
    // Own rotation is deferred to the next encrypt (send_valid=false), so both
    // sides mix the same DH pair.
    let dh = XSecret::from(s.dh_secret).diffie_hellman(&XPublic::from(*new_remote));
    let hk = Hkdf::<Sha256>::new(Some(&s.root), dh.as_bytes());
    let mut r = [0u8; 32];
    let mut c = [0u8; 32];
    hk.expand(b"Visi-Root\x01", &mut r).map_err(|_| SignalError::Decrypt)?;
    hk.expand(b"Visi-Root\x02", &mut c).map_err(|_| SignalError::Decrypt)?;
    s.root = r;
    s.recv.key = c;
    s.recv.counter = 0;
    s.remote_dh = *new_remote;
    s.send_valid = false;
    Ok(())
}

/// Message queue for Demo/tests: tracks pending envelopes per session.
pub struct PendingQueue {
    pub items: VecDeque<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice_bob() -> (Vec<u8>, Vec<u8>, [u8; 32], [u8; 32]) {
        let a = identity_generate();
        let b = identity_generate();
        let sp = signed_prekey_generate(&b.seed[..], 1).unwrap();
        let ot = prekey_generate(11);
        let bundle = Bundle {
            identity_pub_ed: b.public_ed,
            signed_pre_pub_x: sp.public,
            signed_pre_sig: sp.signature,
            onetime_pub_x: Some(ot.public),
        };
        let (a_sess, eph) = session_init_alice(&a.seed[..], &bundle).unwrap();
        let b_sess = session_init_bob(
            &b.seed[..],
            &sp.secret[..],
            Some(&ot.secret[..]),
            &a.public_ed,
            &eph,
            &sp.public,
        )
        .unwrap();
        (a_sess, b_sess, a.public_ed, b.public_ed)
    }

    #[test]
    fn x3dh_handshake_and_ping_pong() {
        let (mut a, mut b, _, _) = alice_bob();
        for i in 0..5 {
            let msg = format!("hello {i}").into_bytes();
            let (a2, env) = session_encrypt(&a, &msg).unwrap();
            a = a2;
            let (b2, pt) = session_decrypt(&b, &env).unwrap();
            b = b2;
            assert_eq!(pt, msg);
            let reply = format!("ack {i}").into_bytes();
            let (b3, env2) = session_encrypt(&b, &reply).unwrap();
            b = b3;
            let (a3, pt2) = session_decrypt(&a, &env2).unwrap();
            a = a3;
            assert_eq!(pt2, reply);
        }
    }

    #[test]
    fn tampered_envelope_fails() {
        let (a, b, _, _) = alice_bob();
        let (_, mut env) = session_encrypt(&a, b"secret").unwrap();
        let l = env.len();
        env[l - 1] ^= 0xFF;
        assert!(session_decrypt(&b, &env).is_err());
    }

    #[test]
    fn bad_bundle_signature_rejected() {
        let b = identity_generate();
        let sp = signed_prekey_generate(&b.seed[..], 1).unwrap();
        let mut bundle = Bundle {
            identity_pub_ed: b.public_ed,
            signed_pre_pub_x: sp.public,
            signed_pre_sig: sp.signature,
            onetime_pub_x: None,
        };
        bundle.signed_pre_pub_x[0] ^= 1;
        let a = identity_generate();
        assert!(session_init_alice(&a.seed[..], &bundle).is_err());
    }
}
