//! Port of `src/utils/encryption/ciphertext.ts` and `src/utils/ecies.ts`.
//!
//! `EncryptedData` is the two-element `[ivTag, data]` hex tuple stored on chain /
//! in notes. ECIES wraps AES-256-GCM with a shared symmetric key to encrypt
//! arbitrary JSON.

use railgun_utils::{
    chunk, combine, format_to_byte_length, from_utf8_string, to_utf8_string, ByteLength, BytesData,
};

use crate::encryption::{decrypt_gcm, encrypt_gcm, Ciphertext, EncryptionError};

/// `EncryptedData` — `[ivTag, data]`.
pub type EncryptedData = [String; 2];

/// `ciphertextToEncryptedRandomData`.
pub fn ciphertext_to_encrypted_random_data(ciphertext: &Ciphertext) -> EncryptedData {
    let iv = format_to_byte_length(
        &BytesData::Hex(ciphertext.iv.clone()),
        ByteLength::Uint128,
        true,
    );
    let tag = format_to_byte_length(
        &BytesData::Hex(ciphertext.tag.clone()),
        ByteLength::Uint128,
        false,
    );
    let iv_tag = format!("{iv}{tag}");
    let data = format_to_byte_length(
        &BytesData::Hex(ciphertext.data[0].clone()),
        ByteLength::Uint128,
        true,
    );
    [iv_tag, data]
}

/// `ciphertextToEncryptedJSONData`.
pub fn ciphertext_to_encrypted_json_data(ciphertext: &Ciphertext) -> EncryptedData {
    let iv = format_to_byte_length(
        &BytesData::Hex(ciphertext.iv.clone()),
        ByteLength::Uint128,
        true,
    );
    let tag = format_to_byte_length(
        &BytesData::Hex(ciphertext.tag.clone()),
        ByteLength::Uint128,
        false,
    );
    let iv_tag = format!("{iv}{tag}");
    let data = combine(&ciphertext.data);
    [iv_tag, format!("0x{data}")]
}

/// `encryptedDataToCiphertext`.
pub fn encrypted_data_to_ciphertext(encrypted_data: &EncryptedData) -> Ciphertext {
    let hexlified_iv_tag = format_to_byte_length(
        &BytesData::Hex(encrypted_data[0].clone()),
        ByteLength::Uint256,
        false,
    );
    Ciphertext {
        iv: hexlified_iv_tag[..32].to_string(),
        tag: hexlified_iv_tag[32..].to_string(),
        data: chunk(
            &BytesData::Hex(encrypted_data[1].clone()),
            ByteLength::Uint256.bytes(),
        ),
    }
}

/// `encryptJSONDataWithSharedKey`.
pub fn encrypt_json_data_with_shared_key(
    data: &serde_json::Value,
    shared_key: &[u8],
) -> Result<EncryptedData, EncryptionError> {
    let data_string = serde_json::to_string(data).map_err(|_| EncryptionError::InvalidHex)?;
    let hex = from_utf8_string(&data_string).map_err(|_| EncryptionError::InvalidHex)?;
    let chunked = chunk(&BytesData::Hex(hex), ByteLength::Uint256.bytes());
    let ciphertext = encrypt_gcm(&chunked, shared_key)?;
    Ok(ciphertext_to_encrypted_json_data(&ciphertext))
}

/// `tryDecryptJSONDataWithSharedKey` — `None` if data is not addressed to this key.
pub fn try_decrypt_json_data_with_shared_key(
    encrypted_data: &EncryptedData,
    shared_key: &[u8],
) -> Option<serde_json::Value> {
    let ciphertext = encrypted_data_to_ciphertext(encrypted_data);
    let chunked = decrypt_gcm(&ciphertext, shared_key).ok()?;
    let data_string = to_utf8_string(&combine(&chunked)).ok()?;
    serde_json::from_str(&data_string).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key() -> Vec<u8> {
        hex::decode("0303030303030303030303030303030303030303030303030303030303030303").unwrap()
    }

    // ciphertext.test.ts "translate ciphertext to encrypted random and back".
    #[test]
    fn random_data_roundtrip() {
        let plaintext = vec![hex::encode([7u8; 16])];
        let ct = encrypt_gcm(&plaintext, &key()).unwrap();
        let encrypted = ciphertext_to_encrypted_random_data(&ct);
        let new_ct = encrypted_data_to_ciphertext(&encrypted);
        assert_eq!(new_ct, ct);
    }

    // ciphertext.test.ts "translate ciphertext to encrypted data and back".
    #[test]
    fn json_data_roundtrip() {
        let plaintext: Vec<String> = (0..40u8).map(|i| hex::encode([i; 32])).collect();
        let ct = encrypt_gcm(&plaintext, &key()).unwrap();
        let encrypted = ciphertext_to_encrypted_json_data(&ct);
        let new_ct = encrypted_data_to_ciphertext(&encrypted);
        assert_eq!(new_ct, ct);
    }

    // ecies.ts roundtrip.
    #[test]
    fn ecies_json_roundtrip() {
        let data = json!({ "data": "value", "more": { "data": "another_value" } });
        let encrypted = encrypt_json_data_with_shared_key(&data, &key()).unwrap();
        let decrypted = try_decrypt_json_data_with_shared_key(&encrypted, &key()).unwrap();
        assert_eq!(decrypted, data);

        // Wrong key -> None.
        let bad = vec![9u8; 32];
        assert!(try_decrypt_json_data_with_shared_key(&encrypted, &bad).is_none());
    }
}
