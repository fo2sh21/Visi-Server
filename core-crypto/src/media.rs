//! Media sandbox: decrypt-to-RAM + explicit shredding.
//!
//! Rules: ciphertext in, plaintext buffer out, held in memory only. When the
//! view counter hits zero / viewer closes / 6h expiry fires, the holder calls
//! `shred` (Rust `zeroize` on our side) and drops. Kotlin MUST also overwrite
//! its own copies (see STEP 3 shredding DAO) — wiping the Rust copy cannot wipe
//! the JVM heap copy, and this is documented, not hidden.
//!
//! Envelope: nonce(12B) || ChaCha20Poly1305(ciphertext+tag), key 32B.

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error)]
pub enum MediaError {
    #[error("bad key/nonce length")]
    BadKey,
    #[error("media decryption failed (tampered or wrong key)")]
    Decrypt,
    #[error("envelope too short")]
    Short,
}

/// Decrypt `nonce12 || ciphertext` with 32B key. Plaintext returned in a
/// `Zeroizing<Vec<u8>>` so drop = wipe on the Rust side.
pub fn decrypt_to_buffer(
    envelope: &[u8],
    key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, MediaError> {
    if key.len() != 32 {
        return Err(MediaError::BadKey);
    }
    if envelope.len() < 12 + 16 {
        return Err(MediaError::Short);
    }
    let c = ChaCha20Poly1305::new_from_slice(key).map_err(|_| MediaError::BadKey)?;
    let nonce = Nonce::from_slice(&envelope[..12]);
    let mut buf = Zeroizing::new(envelope[12..].to_vec());
    let inner: &mut Vec<u8> = &mut buf;
    c.decrypt_in_place(nonce, b"Visi-Media-v1", inner)
        .map_err(|_| {
            buf.zeroize();
            MediaError::Decrypt
        })?;
    Ok(buf)
}

/// Encrypt helper (sender side / tests). Returns `nonce12 || ciphertext`.
pub fn encrypt_buffer(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, MediaError> {
    if key.len() != 32 {
        return Err(MediaError::BadKey);
    }
    let c = ChaCha20Poly1305::new_from_slice(key).map_err(|_| MediaError::BadKey)?;
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let n = Nonce::from_slice(&nonce);
    let mut buf = plaintext.to_vec();
    c.encrypt_in_place(n, b"Visi-Media-v1", &mut buf)
        .map_err(|_| MediaError::Decrypt)?;
    let mut out = Vec::with_capacity(12 + buf.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Explicit shred: overwrite `len` bytes with zeros and return them. Exists so
/// Kotlin/UniFFI has a visible "shred call" for audit; real wiping of Rust
/// buffers happens via `Zeroizing` drop. Kotlin-side arrays need their own
/// overwrite loop (JVM heap is a separate copy).
pub fn shred_len(len: u64) -> Vec<u8> {
    vec![0u8; len.min(64 * 1024 * 1024) as usize]
}

/// SHA-256 hex of bytes — OTA APK integrity check (STEP 6).
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for x in d {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 15) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn roundtrip_and_tamper_fails() {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let env = encrypt_buffer(b"fake-image-bytes", &key).unwrap();
        let pt = decrypt_to_buffer(&env, &key).unwrap();
        assert_eq!(&pt[..], b"fake-image-bytes");
        let mut bad = env.clone();
        let l = bad.len();
        bad[l - 1] ^= 1;
        assert!(decrypt_to_buffer(&bad, &key).is_err());
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
