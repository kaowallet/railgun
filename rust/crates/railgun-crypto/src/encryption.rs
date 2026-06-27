//! Port of `src/utils/encryption/aes.ts` — AES-256-GCM and AES-256-CTR.
//!
//! RAILGUN encrypts in hex "chunks" but the cipher streams continuously across
//! them (GCM/CTR are stream constructions), so a chunked ciphertext is just the
//! full-message ciphertext re-split at the same byte boundaries. We compute the
//! full ciphertext once and re-chunk. Node uses a **16-byte** GCM IV (not 96-bit)
//! and a 128-bit big-endian CTR counter.

use aes::Aes256;
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::AesGcm;
use ctr::cipher::{KeyIvInit, StreamCipher};
use railgun_utils::{format_to_byte_length, hex_string_to_bytes, strip_0x, ByteLength, BytesData};
use serde::{Deserialize, Serialize};

type Aes256Gcm16 = AesGcm<Aes256, U16>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub iv: String,
    pub tag: String,
    pub data: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiphertextCtr {
    pub iv: String,
    pub data: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Invalid key length. Expected 32 bytes. Received {0} bytes.")]
    InvalidKeyLength(usize),
    #[error("Invalid iv length. Expected 16 bytes. Received {0} bytes.")]
    InvalidIvLength(usize),
    #[error("Invalid tag length. Expected 16 bytes. Received {0} bytes.")]
    InvalidTagLength(usize),
    #[error("Unable to decrypt ciphertext.")]
    DecryptFailed,
    #[error("invalid hex chunk")]
    InvalidHex,
}

fn require_key(key: &[u8]) -> Result<(), EncryptionError> {
    if key.len() != 32 {
        return Err(EncryptionError::InvalidKeyLength(key.len()));
    }
    Ok(())
}

/// Decode hex chunks (stripping 0x) into one buffer + their byte lengths.
fn decode_chunks(chunks: &[String]) -> Result<(Vec<u8>, Vec<usize>), EncryptionError> {
    let mut buf = Vec::new();
    let mut lens = Vec::with_capacity(chunks.len());
    for c in chunks {
        let bytes = hex_string_to_bytes(strip_0x(c)).map_err(|_| EncryptionError::InvalidHex)?;
        lens.push(bytes.len());
        buf.extend_from_slice(&bytes);
    }
    Ok((buf, lens))
}

/// Re-split a flat buffer into hex chunks by the given byte lengths.
fn rechunk(buf: &[u8], lens: &[usize]) -> Vec<String> {
    let mut out = Vec::with_capacity(lens.len());
    let mut offset = 0;
    for &len in lens {
        out.push(hex::encode(&buf[offset..offset + len]));
        offset += len;
    }
    out
}

fn random_iv16() -> [u8; 16] {
    let mut iv = [0u8; 16];
    getrandom_iv(&mut iv);
    iv
}

fn getrandom_iv(buf: &mut [u8]) {
    let hex = railgun_utils::random_hex(buf.len());
    let bytes = hex::decode(hex).expect("random hex");
    buf.copy_from_slice(&bytes);
}

/// `AES.encryptGCM`.
pub fn encrypt_gcm(plaintext: &[String], key: &[u8]) -> Result<Ciphertext, EncryptionError> {
    require_key(key)?;
    let iv = random_iv16();
    let (buf, lens) = decode_chunks(plaintext)?;

    let cipher = Aes256Gcm16::new(GenericArray::from_slice(key));
    let mut ct_and_tag = cipher
        .encrypt(GenericArray::from_slice(&iv), buf.as_ref())
        .map_err(|_| EncryptionError::DecryptFailed)?;
    let tag = ct_and_tag.split_off(ct_and_tag.len() - 16);

    Ok(Ciphertext {
        iv: format_to_byte_length(&BytesData::Bytes(iv.to_vec()), ByteLength::Uint128, false),
        tag: format_to_byte_length(&BytesData::Bytes(tag), ByteLength::Uint128, false),
        data: rechunk(&ct_and_tag, &lens),
    })
}

/// `AES.decryptGCM` — returns the per-chunk plaintext hex.
pub fn decrypt_gcm(ciphertext: &Ciphertext, key: &[u8]) -> Result<Vec<String>, EncryptionError> {
    require_key(key)?;
    let iv = hex_string_to_bytes(strip_0x(&ciphertext.iv)).map_err(|_| EncryptionError::InvalidHex)?;
    let tag = hex_string_to_bytes(strip_0x(&ciphertext.tag)).map_err(|_| EncryptionError::InvalidHex)?;
    let iv = &iv[iv.len().saturating_sub(16)..];
    let tag = &tag[tag.len().saturating_sub(16)..];
    if iv.len() != 16 {
        return Err(EncryptionError::InvalidIvLength(iv.len()));
    }
    if tag.len() != 16 {
        return Err(EncryptionError::InvalidTagLength(tag.len()));
    }

    let (mut buf, lens) = decode_chunks(&ciphertext.data)?;
    buf.extend_from_slice(tag);

    let cipher = Aes256Gcm16::new(GenericArray::from_slice(key));
    let plaintext = cipher
        .decrypt(GenericArray::from_slice(iv), buf.as_ref())
        .map_err(|_| EncryptionError::DecryptFailed)?;
    Ok(rechunk(&plaintext, &lens))
}

/// `AES.encryptCTR`.
pub fn encrypt_ctr(plaintext: &[String], key: &[u8]) -> Result<CiphertextCtr, EncryptionError> {
    require_key(key)?;
    let iv = random_iv16();
    let (mut buf, lens) = decode_chunks(plaintext)?;
    let mut cipher = Aes256Ctr::new(GenericArray::from_slice(key), GenericArray::from_slice(&iv));
    cipher.apply_keystream(&mut buf);
    Ok(CiphertextCtr {
        iv: format_to_byte_length(&BytesData::Bytes(iv.to_vec()), ByteLength::Uint128, false),
        data: rechunk(&buf, &lens),
    })
}

/// `AES.decryptCTR`.
pub fn decrypt_ctr(ciphertext: &CiphertextCtr, key: &[u8]) -> Result<Vec<String>, EncryptionError> {
    require_key(key)?;
    let iv = hex_string_to_bytes(strip_0x(&ciphertext.iv)).map_err(|_| EncryptionError::InvalidHex)?;
    if iv.len() != 16 {
        return Err(EncryptionError::InvalidIvLength(iv.len()));
    }
    let (mut buf, lens) = decode_chunks(&ciphertext.data)?;
    let mut cipher = Aes256Ctr::new(GenericArray::from_slice(key), GenericArray::from_slice(&iv));
    cipher.apply_keystream(&mut buf);
    Ok(rechunk(&buf, &lens))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()
    }

    #[test]
    fn gcm_roundtrip() {
        let plaintext = vec![
            "deadbeef".to_string(),
            "5d0afac6783502d701ebd089be93f497bd46ea52b0fb2a4304a952572899aadb".to_string(),
        ];
        let ct = encrypt_gcm(&plaintext, &key()).unwrap();
        assert_eq!(ct.iv.len(), 32);
        assert_eq!(ct.tag.len(), 32);
        assert_eq!(decrypt_gcm(&ct, &key()).unwrap(), plaintext);
    }

    #[test]
    fn gcm_wrong_key_fails() {
        let ct = encrypt_gcm(&["abcd".to_string()], &key()).unwrap();
        let bad = vec![2u8; 32];
        assert!(decrypt_gcm(&ct, &bad).is_err());
    }

    #[test]
    fn ctr_roundtrip() {
        let plaintext = vec!["deadbeef".to_string(), "00112233445566778899aabbccddeeff".to_string()];
        let ct = encrypt_ctr(&plaintext, &key()).unwrap();
        assert_eq!(decrypt_ctr(&ct, &key()).unwrap(), plaintext);
    }

    #[test]
    fn bad_key_length() {
        assert!(matches!(
            encrypt_gcm(&["00".to_string()], &[0u8; 16]),
            Err(EncryptionError::InvalidKeyLength(16))
        ));
    }
}
