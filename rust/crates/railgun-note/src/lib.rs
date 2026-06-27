//! `railgun-note` — shield/unshield/transact notes, memo encoding, and token
//! hashing (port of `src/note/`).
//!
//! Scope: V2 (AES-256-GCM/CTR) and V3 (XChaCha20-Poly1305). Legacy V1 commitment
//! formats are out of scope, but the legacy *serialized note* form
//! (`LegacyNoteSerialized`, the encrypted-random DB layout) is supported because
//! the primary KAV oracle (`transact-note.test.ts`) deserializes from it.
//!
//! All cryptography is delegated to `railgun-crypto`; this crate only assembles
//! pre-images and ciphertext field layouts (the byte-exact part). Per-note
//! randomness is injectable so the stubbed-RNG TS vectors reproduce exactly.

pub mod memo;
pub mod note_util;
pub mod shield_note;
pub mod transact_note;
pub mod unshield_note;
pub mod wallet_info;

pub use memo::{
    create_encrypted_note_annotation_data_v2, create_sender_annotation_encrypted_v3,
    decode_memo_text, decrypt_note_annotation_data, decrypt_sender_ciphertext_v3,
    decrypt_sender_random, encode_memo_text, MemoError, MEMO_SENDER_RANDOM_NULL,
};
pub use note_util::{
    assert_valid_note_random, assert_valid_note_token, erc721_note_value, format_value,
    get_note_hash, get_token_data_erc20, get_token_data_hash, get_token_data_nft,
    serialize_pre_image, serialize_token_data, NoteUtilError, TOKEN_SUB_ID_NULL,
};
pub use shield_note::{ShieldNote, ShieldNoteError, ShieldPreImage};
pub use transact_note::{Erc20TokenDataGetter, TokenDataGetter, TransactNote, TransactNoteError};
pub use unshield_note::{UnshieldNote, ZERO_ADDRESS};
pub use wallet_info::{
    decode_wallet_source, get_encoded_wallet_source, validate_wallet_source, WalletInfoError,
};
