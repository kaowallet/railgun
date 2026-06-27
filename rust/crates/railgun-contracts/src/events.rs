//! Typed commitment / nullifier / unshield event decoding (V2 + V3 scope).
//!
//! Port of `src/contracts/railgun-smart-wallet/V2/V2-events.ts` (+ V3) commitment
//! ciphertext formatting. Full event-stream decoding from raw logs (the
//! `Shield` / `Transact` / `Nullified` / `Unshield` accumulation into
//! `CommitmentEvent`s) is RPC-bound and tracked as a TODO; the pure ciphertext
//! formatting used by the validation path is provided here and mirrored in
//! `railgun-engine`.

use railgun_models::formatted_types::CommitmentCiphertextV2;
use railgun_utils::{format_to_byte_length, ByteLength, BytesData};

use crate::abi::CommitmentCiphertextStruct;

/// `V2Events.formatCommitmentCiphertext` — turn the ABI `CommitmentCiphertext`
/// struct into the engine's [`CommitmentCiphertextV2`] model.
///
/// `ciphertext[0]` packs `iv(16B) || tag(16B)`; the remaining words are the
/// encrypted data. All words are normalised to 32-byte hex (no `0x`).
pub fn format_commitment_ciphertext_v2(cc: &CommitmentCiphertextStruct) -> CommitmentCiphertextV2 {
    use railgun_crypto::Ciphertext;

    let ciphertext: Vec<String> = cc
        .ciphertext
        .iter()
        .map(|el| {
            format_to_byte_length(
                &BytesData::Hex(hex::encode(el.0)),
                ByteLength::Uint256,
                false,
            )
        })
        .collect();
    let iv_tag = &ciphertext[0];

    CommitmentCiphertextV2 {
        ciphertext: Ciphertext {
            iv: iv_tag[..32].to_string(),
            tag: iv_tag[32..].to_string(),
            data: ciphertext[1..].to_vec(),
        },
        blinded_sender_viewing_key: format_to_byte_length(
            &BytesData::Hex(hex::encode(cc.blindedSenderViewingKey.0)),
            ByteLength::Uint256,
            false,
        ),
        blinded_receiver_viewing_key: format_to_byte_length(
            &BytesData::Hex(hex::encode(cc.blindedReceiverViewingKey.0)),
            ByteLength::Uint256,
            false,
        ),
        annotation_data: hex::encode(&cc.annotationData),
        memo: hex::encode(&cc.memo),
    }
}
