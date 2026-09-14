//! Argon2id key derivation.
//!
//! Contract (locked in plan):
//! - Algorithm: Argon2id, memory 64 MiB (65536 KiB), iterations 3, parallelism 1.
//! - `password_input` = stealth PIN / user passphrase bytes (UTF-8, zeroized by caller).
//! - `salt` = random >= 16 bytes per user (NOT the 4-digit PIN).
//! - `keystore_secret` = 32-byte hardware-bound secret from Android Keystore.
//!   Domain-separated and mixed into the Argon2 password input so a stolen DB
//!   alone is insufficient (thief needs TEE/StrongBox too).
//! - Output: 32-byte key for SQLCipher. Backed buffer is `Zeroizing`.

use argon2::{Algorithm, Argon2, Params, Version};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Argon2id cost parameters. 64 MiB = 65536 KiB.
pub const ARGON2_M_KIB: u32 = 65536;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;
pub const DERIVED_KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum KdfError {
    #[error("argon2 parameter error: {0}")]
    Params(String),
    #[error("argon2 hashing failed: {0}")]
    Hash(String),
    #[error("salt must be at least 16 bytes, got {0}")]
    ShortSalt(usize),
}

fn argon2id() -> Result<Argon2<'static>, KdfError> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T_COST, ARGON2_P_COST, None)
        .map_err(|e| KdfError::Params(e.to_string()))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Derive a 32-byte key. `password_input || 0x00 || keystore_secret` is the
/// Argon2 password; `salt` is the Argon2 salt. All intermediates zeroized.
pub fn derive_key(
    password_input: &[u8],
    salt: &[u8],
    keystore_secret: &[u8],
) -> Result<Zeroizing<[u8; DERIVED_KEY_LEN]>, KdfError> {
    if salt.len() < 16 {
        return Err(KdfError::ShortSalt(salt.len()));
    }
    // Domain-separated mixing: PIN/pass || 0x00 || keystore_secret.
    let mut mixed = Zeroizing::new(Vec::with_capacity(
        password_input.len() + 1 + keystore_secret.len(),
    ));
    mixed.extend_from_slice(password_input);
    mixed.push(0x00);
    mixed.extend_from_slice(keystore_secret);

    let mut out = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    argon2id()?
        .hash_password_into(&mixed, salt, &mut out[..])
        .map_err(|e| KdfError::Hash(e.to_string()))?;
    mixed.zeroize();
    Ok(out)
}

/// Build the shared Argon2 instance for OPAQUE KSF overrides (same params).
pub fn opaque_ksf_argon2() -> Result<Argon2<'static>, KdfError> {
    argon2id()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_stable_32b_key() {
        let k1 = derive_key(b"8008", &[7u8; 16], &[9u8; 32]).unwrap();
        let k2 = derive_key(b"8008", &[7u8; 16], &[9u8; 32]).unwrap();
        assert_eq!(&k1[..], &k2[..]);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn rejects_short_salt() {
        assert!(derive_key(b"8008", &[1u8; 8], &[9u8; 32]).is_err());
    }

    #[test]
    fn wrong_pin_gives_different_key() {
        let k1 = derive_key(b"8008", &[7u8; 16], &[9u8; 32]).unwrap();
        let k2 = derive_key(b"8009", &[7u8; 16], &[9u8; 32]).unwrap();
        assert_ne!(&k1[..], &k2[..]);
    }
}
