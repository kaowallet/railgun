//! Port of `src/note/memo.ts` — note annotation data (V2 AES-CTR / V3 XChaCha)
//! and UTF-8 memo text encode/decode.

use num_bigint::BigUint;
use railgun_crypto::{
    decrypt_cha_cha_20, decrypt_ctr, encrypt_cha_cha_20, encrypt_ctr, CiphertextCtr,
    CiphertextXChaCha, XChaChaEncryptionAlgorithm,
};
use railgun_models::formatted_types::{NoteAnnotationData, SenderAnnotationDecrypted};
use railgun_models::OutputType;
use railgun_utils::{fast_hex_to_bytes, hexlify, n_to_hex, strip_0x, ByteLength, BytesData};

use crate::wallet_info::{decode_wallet_source, get_encoded_wallet_source, WalletInfoError};

pub const MEMO_SENDER_RANDOM_NULL: &str = "000000000000000000000000000000";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MemoError {
    #[error("Metadata field 0 must be 16 bytes.")]
    MetadataField0Length,
    #[error("Invalid senderRandom length - expected 15 bytes (30 length)")]
    SenderRandomLength,
    #[error("wallet info error: {0}")]
    WalletInfo(#[from] WalletInfoError),
    #[error("encryption error")]
    Encryption,
}

fn try_decode_wallet_source(decrypted_bytes: &str) -> Option<String> {
    // The TS catches decode errors and returns undefined.
    let decoded = decode_wallet_source(decrypted_bytes);
    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

/// `Memo.decryptNoteAnnotationData` (V2).
pub fn decrypt_note_annotation_data(
    annotation_data: &str,
    viewing_private_key: &[u8],
) -> Option<NoteAnnotationData> {
    if annotation_data.is_empty() {
        return None;
    }

    let hexlified = hexlify(&BytesData::Hex(annotation_data.to_string()), false);
    let has_two_bytes = hexlified.len() > 64;

    // JS `String.prototype.substring` clamps out-of-range indices; replicate that
    // since the V2 annotation fields are 15 bytes (30 hex) each, so the full
    // string is 124 chars while the TS slices at 32-char boundaries up to 128.
    let sub = |start: usize, end: usize| -> String {
        let len = hexlified.len();
        let s = start.min(len);
        let e = end.min(len);
        hexlified[s..e].to_string()
    };

    let metadata_ciphertext = CiphertextCtr {
        iv: sub(0, 32),
        data: if has_two_bytes {
            vec![sub(32, 64), sub(64, 96), sub(96, 128)]
        } else {
            vec![sub(32, 64)]
        },
    };

    let decrypted = decrypt_ctr(&metadata_ciphertext, viewing_private_key).ok()?;

    let wallet_source = if has_two_bytes {
        try_decode_wallet_source(&decrypted[2])
    } else {
        None
    };

    let output_type_int = u8::from_str_radix(&decrypted[0][0..2], 16).ok()?;
    let output_type = OutputType::try_from(output_type_int).ok()?;
    let sender_random = decrypted[0][2..32].to_string();

    Some(NoteAnnotationData {
        output_type,
        sender_random,
        wallet_source,
    })
}

/// `Memo.decryptSenderCiphertextV3`.
pub fn decrypt_sender_ciphertext_v3(
    sender_ciphertext: &str,
    viewing_private_key: &[u8],
    transact_commitment_batch_index: usize,
) -> Option<SenderAnnotationDecrypted> {
    if sender_ciphertext.is_empty() {
        return None;
    }
    let stripped = strip_0x(sender_ciphertext);
    let metadata_ciphertext = CiphertextXChaCha {
        algorithm: XChaChaEncryptionAlgorithm::XChaCha,
        nonce: stripped[0..32].to_string(),
        bundle: stripped[32..].to_string(),
    };
    let decrypted = decrypt_cha_cha_20(&metadata_ciphertext, viewing_private_key).ok()?;

    let wallet_source = try_decode_wallet_source(&decrypted[0..32]);

    let output_type_byte_offset = 32 + transact_commitment_batch_index * 2;
    let output_type_int = u8::from_str_radix(
        decrypted.get(output_type_byte_offset..output_type_byte_offset + 2)?,
        16,
    )
    .ok()?;
    let output_type = OutputType::try_from(output_type_int).ok()?;

    Some(SenderAnnotationDecrypted {
        wallet_source,
        output_type,
    })
}

/// `Memo.decryptSenderRandom`.
pub fn decrypt_sender_random(annotation_data: &str, viewing_private_key: &[u8]) -> String {
    match decrypt_note_annotation_data(annotation_data, viewing_private_key) {
        Some(data) => data.sender_random,
        None => MEMO_SENDER_RANDOM_NULL.to_string(),
    }
}

/// `Memo.createEncryptedNoteAnnotationDataV2`. The AES-CTR IV is randomized by
/// `railgun-crypto`; decryption recovers the data regardless, matching the TS.
pub fn create_encrypted_note_annotation_data_v2(
    output_type: OutputType,
    sender_random: &str,
    wallet_source: &str,
    viewing_private_key: &[u8],
) -> Result<String, MemoError> {
    let output_type_formatted =
        n_to_hex(&BigUint::from(output_type as u8), ByteLength::Uint8, false); // 1 byte
    let metadata_field0 = format!("{output_type_formatted}{sender_random}");
    if metadata_field0.len() != 32 {
        return Err(MemoError::MetadataField0Length);
    }

    let metadata_field1 = "0".repeat(30); // 32 zeroes filled (matches TS Array(30).fill('0'))

    let mut metadata_field2 = get_encoded_wallet_source(wallet_source)?;
    while metadata_field2.len() < 30 {
        metadata_field2 = format!("0{metadata_field2}");
    }

    let to_encrypt = vec![metadata_field0, metadata_field1, metadata_field2];

    let metadata_ciphertext: CiphertextCtr =
        encrypt_ctr(&to_encrypt, viewing_private_key).map_err(|_| MemoError::Encryption)?;

    Ok(format!(
        "{}{}{}{}",
        metadata_ciphertext.iv,
        metadata_ciphertext.data[0],
        metadata_ciphertext.data[1],
        metadata_ciphertext.data[2],
    ))
}

/// `Memo.createSenderAnnotationEncryptedV3`. Nonce is randomized by `railgun-crypto`.
pub fn create_sender_annotation_encrypted_v3(
    wallet_source: &str,
    ordered_output_types: &[OutputType],
    viewing_private_key: &[u8],
) -> Result<String, MemoError> {
    let mut metadata_field0 = get_encoded_wallet_source(wallet_source)?;
    while metadata_field0.len() < 32 {
        metadata_field0 = format!("0{metadata_field0}");
    }
    let metadata_field1: String = ordered_output_types
        .iter()
        .map(|ot| n_to_hex(&BigUint::from(*ot as u8), ByteLength::Uint8, false))
        .collect();
    let to_encrypt = format!("{metadata_field0}{metadata_field1}");
    let ciphertext =
        encrypt_cha_cha_20(&to_encrypt, viewing_private_key).map_err(|_| MemoError::Encryption)?;
    Ok(railgun_utils::prefix_0x(&format!(
        "{}{}",
        ciphertext.nonce, ciphertext.bundle
    )))
}

/// `Memo.encodeMemoText`.
pub fn encode_memo_text(memo_text: Option<&str>) -> String {
    match memo_text {
        None => String::new(),
        Some(text) => hexlify(&BytesData::Bytes(text.as_bytes().to_vec()), false),
    }
}

/// `Memo.decodeMemoText`.
pub fn decode_memo_text(encoded: &str) -> Option<String> {
    if encoded.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&fast_hex_to_bytes(encoded)).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    // memo.test.ts "Should encrypt and decrypt note extra data".
    // Roundtrip (no hardcoded ciphertext); uses an arbitrary 32-byte viewing key.
    #[test]
    fn annotation_data_roundtrip_v2() {
        let viewing_private_key = [0x42u8; 32];
        let data = NoteAnnotationData {
            output_type: OutputType::BroadcasterFee,
            sender_random: "1234567890abcde1234567890abcde".into(), // 15 bytes
            wallet_source: Some("memo wallet".into()),
        };
        let encrypted = create_encrypted_note_annotation_data_v2(
            data.output_type,
            &data.sender_random,
            "memo wallet",
            &viewing_private_key,
        )
        .unwrap();
        let decrypted = decrypt_note_annotation_data(&encrypted, &viewing_private_key).unwrap();
        assert_eq!(decrypted, data);
    }

    // memo.test.ts "Should encode and decode empty memo text".
    #[test]
    fn empty_memo_text() {
        assert_eq!(encode_memo_text(None), "");
        assert_eq!(decode_memo_text(""), None);
    }

    // memo.test.ts "Should encode and decode long memo text" (emoji KAV).
    #[test]
    fn long_memo_text_with_emojis() {
        let memo_text = "A really long memo with emojis \u{1F610}\u{1F469}\u{1F3FE}\u{200D}\u{1F527}\u{1F60E} and other text !@#$%^&*() Private memo field \u{1F921}\u{1F640}\u{1F970}\u{1F469}\u{1F3FF}\u{200D}\u{1F692}\u{1F9DE} \u{1F921} \u{1F640} \u{1F970} \u{1F469}\u{1F3FF}\u{200D}\u{1F692} \u{1F9DE}, in order to test a major memo for a real live production use case.";
        let encoded = encode_memo_text(Some(memo_text));
        assert_eq!(
            encoded,
            "41207265616c6c79206c6f6e67206d656d6f207769746820656d6f6a697320f09f9890f09f91a9f09f8fbee2808df09f94a7f09f988e20616e64206f7468657220746578742021402324255e262a28292050726976617465206d656d6f206669656c6420f09fa4a1f09f9980f09fa5b0f09f91a9f09f8fbfe2808df09f9a92f09fa79e20f09fa4a120f09f998020f09fa5b020f09f91a9f09f8fbfe2808df09f9a9220f09fa79e2c20696e206f7264657220746f20746573742061206d616a6f72206d656d6f20666f722061207265616c206c6976652070726f64756374696f6e2075736520636173652e"
        );
        assert_eq!(decode_memo_text(&encoded), Some(memo_text.to_string()));
    }

    // memo.test.ts "Should encode and decode memo text - new line over an emoji".
    #[test]
    fn memo_text_emoji_kav() {
        let memo_text = "Private memo field \u{1F921}\u{1F640}\u{1F970}\u{1F469}\u{1F3FF}\u{200D}\u{1F692}\u{1F9DE} \u{1F921} \u{1F640} \u{1F970} \u{1F469}\u{1F3FF}\u{200D}\u{1F692} \u{1F9DE},";
        let encoded = encode_memo_text(Some(memo_text));
        assert_eq!(
            encoded,
            "50726976617465206d656d6f206669656c6420f09fa4a1f09f9980f09fa5b0f09f91a9f09f8fbfe2808df09f9a92f09fa79e20f09fa4a120f09f998020f09fa5b020f09f91a9f09f8fbfe2808df09f9a9220f09fa79e2c"
        );
        assert_eq!(decode_memo_text(&encoded), Some(memo_text.to_string()));
    }

    // memo.test.ts "Should encode and decode memo text without emojis".
    #[test]
    fn memo_text_no_emoji_roundtrip() {
        let memo_text =
            "A really long memo in order to test a major memo for a real live production use case.";
        let encoded = encode_memo_text(Some(memo_text));
        assert_eq!(decode_memo_text(&encoded), Some(memo_text.to_string()));
    }
}
