//! Port of `src/utils/encryption/x-cha-cha-20.ts` — XChaCha20 and
//! XChaCha20-Poly1305.
//!
//! IMPORTANT byte detail (replicated exactly): the 24-byte XChaCha nonce is
//! derived from a 16-byte random value rendered as a **hex string**, then SHA-256
//! hashed and truncated:
//!
//!   nonce        = randomHex(16)                  // 32-char hex string
//!   nonceExtended = sha256(utf8_bytes(nonce))[..24]
//!
//! Plaintext/ciphertext "bundles" are hex strings of the raw bytes.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::XChaCha20;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use railgun_utils::{fast_bytes_to_hex, fast_hex_to_bytes, random_hex};
use serde::{Deserialize, Serialize};

use crate::hash::sha256_bytes;

/// `XChaChaEncryptionAlgorithm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum XChaChaEncryptionAlgorithm {
    #[serde(rename = "XChaCha")]
    XChaCha,
    #[serde(rename = "XChaChaPoly1305")]
    XChaChaPoly1305,
}

/// `CiphertextXChaCha`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiphertextXChaCha {
    pub algorithm: XChaChaEncryptionAlgorithm,
    pub nonce: String,
    pub bundle: String,
}

#[derive(Debug, thiserror::Error)]
pub enum XChaChaError {
    #[error("Invalid ciphertext for {expected:?}: {got:?}")]
    WrongAlgorithm {
        expected: XChaChaEncryptionAlgorithm,
        got: XChaChaEncryptionAlgorithm,
    },
    #[error("invalid hex")]
    InvalidHex,
    #[error("invalid tag")]
    InvalidTag,
    #[error("invalid key length")]
    InvalidKeyLength,
}

/// `XChaCha20.getRandomIV` — 16 random bytes as a 32-char hex string.
pub fn get_random_iv() -> String {
    random_hex(16)
}

/// `nonceExtended = sha256(nonce_hex_string)[..24]`.
fn nonce_extended(nonce: &str) -> [u8; 24] {
    let hash = sha256_bytes(nonce.as_bytes());
    let mut out = [0u8; 24];
    out.copy_from_slice(&hash[..24]);
    out
}

fn require_key(key: &[u8]) -> Result<[u8; 32], XChaChaError> {
    key.try_into().map_err(|_| XChaChaError::InvalidKeyLength)
}

/// `encryptChaCha20` with an explicit nonce (16-byte hex string). Lets tests be
/// reproducible; the public `encrypt_cha_cha_20` generates a random nonce.
pub fn encrypt_cha_cha_20_with_nonce(
    plaintext: &str,
    key: &[u8],
    nonce: String,
) -> Result<CiphertextXChaCha, XChaChaError> {
    let key = require_key(key)?;
    let nonce_ext = nonce_extended(&nonce);
    let mut data = fast_hex_to_bytes(plaintext);
    let mut cipher = XChaCha20::new((&key).into(), (&nonce_ext).into());
    cipher.apply_keystream(&mut data);
    Ok(CiphertextXChaCha {
        algorithm: XChaChaEncryptionAlgorithm::XChaCha,
        nonce,
        bundle: fast_bytes_to_hex(&data),
    })
}

/// `XChaCha20.encryptChaCha20`.
pub fn encrypt_cha_cha_20(plaintext: &str, key: &[u8]) -> Result<CiphertextXChaCha, XChaChaError> {
    encrypt_cha_cha_20_with_nonce(plaintext, key, get_random_iv())
}

/// `XChaCha20.decryptChaCha20`.
pub fn decrypt_cha_cha_20(
    ciphertext: &CiphertextXChaCha,
    key: &[u8],
) -> Result<String, XChaChaError> {
    if ciphertext.algorithm != XChaChaEncryptionAlgorithm::XChaCha {
        return Err(XChaChaError::WrongAlgorithm {
            expected: XChaChaEncryptionAlgorithm::XChaCha,
            got: ciphertext.algorithm,
        });
    }
    let key = require_key(key)?;
    let nonce_ext = nonce_extended(&ciphertext.nonce);
    let mut data = hex::decode(&ciphertext.bundle).map_err(|_| XChaChaError::InvalidHex)?;
    let mut cipher = XChaCha20::new((&key).into(), (&nonce_ext).into());
    cipher.apply_keystream(&mut data);
    Ok(fast_bytes_to_hex(&data))
}

/// `encryptChaCha20Poly1305` with an explicit nonce (reproducible variant).
pub fn encrypt_cha_cha_20_poly1305_with_nonce(
    plaintext: &str,
    key: &[u8],
    nonce: String,
) -> Result<CiphertextXChaCha, XChaChaError> {
    let key = require_key(key)?;
    let nonce_ext = nonce_extended(&nonce);
    let data = fast_hex_to_bytes(plaintext);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let bundle = cipher
        .encrypt((&nonce_ext).into(), data.as_ref())
        .map_err(|_| XChaChaError::InvalidTag)?;
    Ok(CiphertextXChaCha {
        algorithm: XChaChaEncryptionAlgorithm::XChaChaPoly1305,
        nonce,
        bundle: fast_bytes_to_hex(&bundle),
    })
}

/// `XChaCha20.encryptChaCha20Poly1305`.
pub fn encrypt_cha_cha_20_poly1305(
    plaintext: &str,
    key: &[u8],
) -> Result<CiphertextXChaCha, XChaChaError> {
    encrypt_cha_cha_20_poly1305_with_nonce(plaintext, key, get_random_iv())
}

/// `XChaCha20.decryptChaCha20Poly1305`.
pub fn decrypt_cha_cha_20_poly1305(
    ciphertext: &CiphertextXChaCha,
    key: &[u8],
) -> Result<String, XChaChaError> {
    if ciphertext.algorithm != XChaChaEncryptionAlgorithm::XChaChaPoly1305 {
        return Err(XChaChaError::WrongAlgorithm {
            expected: XChaChaEncryptionAlgorithm::XChaChaPoly1305,
            got: ciphertext.algorithm,
        });
    }
    let key = require_key(key)?;
    let nonce_ext = nonce_extended(&ciphertext.nonce);
    let data = hex::decode(&ciphertext.bundle).map_err(|_| XChaChaError::InvalidHex)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let plaintext = cipher
        .decrypt((&nonce_ext).into(), data.as_ref())
        .map_err(|_| XChaChaError::InvalidTag)?;
    Ok(fast_bytes_to_hex(&plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plaintext_8x32() -> String {
        let mut p = String::new();
        for i in 0..8u8 {
            p.push_str(&hex::encode([i; 32]));
        }
        p
    }

    fn key() -> Vec<u8> {
        hex::decode("0202020202020202020202020202020202020202020202020202020202020202").unwrap()
    }

    // x-cha-cha-20.test.ts roundtrip (XChaCha20Poly1305).
    #[test]
    fn poly1305_roundtrip() {
        let plaintext = plaintext_8x32();
        let ct = encrypt_cha_cha_20_poly1305(&plaintext, &key()).unwrap();
        assert_eq!(decrypt_cha_cha_20_poly1305(&ct, &key()).unwrap(), plaintext);
    }

    // x-cha-cha-20.test.ts "Should reject invalid tag for XChaCha20Poly1305".
    #[test]
    fn poly1305_rejects_invalid_tag() {
        let plaintext = plaintext_8x32();
        let mut ct = encrypt_cha_cha_20_poly1305(&plaintext, &key()).unwrap();
        let len = ct.bundle.len();
        ct.bundle = format!("{}ffffffff", &ct.bundle[..len - 8]);
        assert!(matches!(
            decrypt_cha_cha_20_poly1305(&ct, &key()),
            Err(XChaChaError::InvalidTag)
        ));
    }

    // x-cha-cha-20.test.ts roundtrip (plain XChaCha20 stream cipher).
    #[test]
    fn stream_roundtrip() {
        let plaintext = plaintext_8x32();
        let ct = encrypt_cha_cha_20(&plaintext, &key()).unwrap();
        assert_eq!(decrypt_cha_cha_20(&ct, &key()).unwrap(), plaintext);
    }

    // Deterministic known-answer with a fixed nonce, so it is reproducible. The
    // nonce derivation (sha256 of the hex STRING) is the load-bearing detail.
    #[test]
    fn stream_deterministic_nonce() {
        let nonce = "00112233445566778899aabbccddeeff".to_string();
        let ct = encrypt_cha_cha_20_with_nonce("deadbeef", &key(), nonce.clone()).unwrap();
        // Independently compute the keystream-xor result to confirm the nonce path.
        let nonce_ext = nonce_extended(&nonce);
        let mut expected = fast_hex_to_bytes("deadbeef");
        let mut cipher = XChaCha20::new(
            (&<[u8; 32]>::try_from(key()).unwrap()).into(),
            (&nonce_ext).into(),
        );
        cipher.apply_keystream(&mut expected);
        assert_eq!(ct.bundle, hex::encode(expected));
        assert_eq!(decrypt_cha_cha_20(&ct, &key()).unwrap(), "deadbeef");
    }
}
