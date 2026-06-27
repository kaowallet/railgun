//! Port of `src/note/transact-note.ts`.
//!
//! Core transact-note crypto: note-public-key, note hash, nullifier, V2
//! (AES-256-GCM) and V3 (XChaCha20-Poly1305) encryption/decryption, memo,
//! sender-address visibility, serialization.
//!
//! Per-note randomness (`random`, `senderRandom`) is **injectable** so the
//! known-answer-vector tests (which stub `getNoteRandom` in the TS) are
//! reproducible. The AES IV / XChaCha nonce are randomized inside `railgun-crypto`
//! exactly as in the TS; the KAV tests are roundtrip-based and so independent of
//! them.

use num_bigint::BigUint;
use railgun_crypto::{
    decrypt_cha_cha_20_poly1305, decrypt_gcm, encrypt_cha_cha_20_poly1305, encrypt_gcm, poseidon,
    unblind_note_key, Ciphertext, CiphertextXChaCha,
};
use railgun_key_derivation::{decode_address, encode_address, AddressData};
use railgun_models::formatted_types::{DecryptedNote, LegacyNoteSerialized, NoteSerialized};
use railgun_models::{OutputType, TXIDVersion, TokenData, TokenType};
use railgun_utils::{
    combine, format_to_byte_length, hex_to_bigint, hexlify, n_to_hex, ByteLength, BytesData,
};

use crate::memo::{
    create_encrypted_note_annotation_data_v2, decode_memo_text, decrypt_note_annotation_data,
    decrypt_sender_ciphertext_v3, encode_memo_text, MemoError, MEMO_SENDER_RANDOM_NULL,
};
use crate::note_util::{
    assert_valid_note_random, erc721_note_value, get_token_data_erc20, get_token_data_hash,
    serialize_token_data, NoteUtilError,
};

const ERC20_TOKEN_HASH_PREFIX: &str = "000000000000000000000000";

/// Synchronous analogue of the TS `TokenDataGetter`. The ERC20 case is handled
/// in-process; NFT hashes require network/DB lookup and are delegated to the
/// caller-supplied implementation.
pub trait TokenDataGetter {
    fn get_token_data_from_hash(
        &self,
        txid_version: TXIDVersion,
        chain_id: u64,
        token_hash: &str,
    ) -> Option<TokenData>;
}

/// Default getter resolving only ERC20 hashes (the common path + every KAV
/// vector). Returns `None` for NFT hashes so callers know to supply their own.
pub struct Erc20TokenDataGetter;

impl TokenDataGetter for Erc20TokenDataGetter {
    fn get_token_data_from_hash(
        &self,
        _txid_version: TXIDVersion,
        _chain_id: u64,
        token_hash: &str,
    ) -> Option<TokenData> {
        let formatted = format_to_byte_length(
            &BytesData::Hex(token_hash.to_string()),
            ByteLength::Uint256,
            false,
        );
        if formatted.starts_with(ERC20_TOKEN_HASH_PREFIX) {
            Some(get_token_data_erc20(token_hash))
        } else {
            None
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransactNoteError {
    #[error("{0}")]
    NoteUtil(#[from] NoteUtilError),
    #[error("{0}")]
    Memo(#[from] MemoError),
    #[error("Invalid txidVersion for {0} encryption")]
    InvalidTxidVersion(&'static str),
    #[error("Invalid token type for {0} transfer: {1:?}")]
    InvalidTokenType(&'static str, TokenType),
    #[error("Output type must be set for encrypted note annotation data")]
    OutputTypeRequired,
    #[error("Sender random must be set for encrypted note annotation data")]
    SenderRandomRequired,
    #[error("Wallet source must be set for encrypted note annotation data")]
    WalletSourceRequired,
    #[error("Invalid senderRandom length - expected 15 bytes (30 length)")]
    SenderRandomLength,
    #[error("Invalid ciphertext for {0} decryption")]
    InvalidCiphertext(&'static str),
    #[error("transactCommitmentBatchIndex must be defined for V3 decryption")]
    BatchIndexRequired,
    #[error("token data not found for hash")]
    TokenDataNotFound,
    #[error("decryption failed")]
    DecryptFailed,
}

/// `TransactNote`.
#[derive(Clone, Debug)]
pub struct TransactNote {
    pub receiver_address_data: AddressData,
    pub sender_address_data: Option<AddressData>,
    pub token_hash: String,
    pub token_data: TokenData,
    pub random: String,
    pub value: BigUint,
    pub note_public_key: BigUint,
    pub hash: BigUint,
    pub output_type: Option<OutputType>,
    pub wallet_source: Option<String>,
    pub sender_random: Option<String>,
    pub memo_text: Option<String>,
    pub shield_fee: Option<String>,
    pub block_number: Option<u64>,
}

impl TransactNote {
    /// The private TS constructor.
    #[allow(clippy::too_many_arguments)]
    fn construct(
        receiver_address_data: AddressData,
        sender_address_data: Option<AddressData>,
        random: String,
        value: BigUint,
        token_data: TokenData,
        output_type: Option<OutputType>,
        wallet_source: Option<String>,
        sender_random: Option<String>,
        memo_text: Option<String>,
        shield_fee: Option<String>,
        block_number: Option<u64>,
    ) -> Result<Self, TransactNoteError> {
        assert_valid_note_random(&random)?;

        let token_data = serialize_token_data(
            &token_data.token_address,
            token_data.token_type,
            &hex_to_bigint(&token_data.token_sub_id),
        );
        let token_hash = get_token_data_hash(&token_data);
        let note_public_key =
            Self::get_note_public_key(&receiver_address_data.master_public_key, &random);
        let hash = Self::get_hash(&note_public_key, &token_hash, &value);

        Ok(TransactNote {
            receiver_address_data,
            sender_address_data,
            token_hash,
            token_data,
            random,
            value,
            note_public_key,
            hash,
            output_type,
            wallet_source,
            sender_random,
            memo_text,
            shield_fee,
            block_number,
        })
    }

    /// `createTransfer`. `note_random` (16 bytes hex) and `sender_random` (15
    /// bytes hex) are injectable for reproducibility; pass `None` to use the TS
    /// behaviour of `randomHex(16)` / `randomHex(15)`. `wallet_source` is the
    /// (lowercased) `WalletInfo.walletSource`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_transfer(
        receiver_address_data: AddressData,
        sender_address_data: Option<AddressData>,
        value: BigUint,
        token_data: TokenData,
        show_sender_address_to_recipient: bool,
        output_type: OutputType,
        memo_text: Option<String>,
        wallet_source: Option<String>,
        note_random: Option<String>,
        injected_sender_random: Option<String>,
    ) -> Result<Self, TransactNoteError> {
        let should_create_sender_random = !show_sender_address_to_recipient;
        let sender_random = if should_create_sender_random {
            injected_sender_random.unwrap_or_else(Self::get_sender_random)
        } else {
            MEMO_SENDER_RANDOM_NULL.to_string()
        };
        let random = note_random.unwrap_or_else(Self::get_note_random);

        Self::construct(
            receiver_address_data,
            sender_address_data,
            random,
            value,
            token_data,
            Some(output_type),
            wallet_source,
            Some(sender_random),
            memo_text,
            None,
            None,
        )
    }

    /// `createERC721Transfer`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_erc721_transfer(
        receiver_address_data: AddressData,
        sender_address_data: Option<AddressData>,
        token_data: TokenData,
        show_sender_address_to_recipient: bool,
        memo_text: Option<String>,
        wallet_source: Option<String>,
        note_random: Option<String>,
        sender_random: Option<String>,
    ) -> Result<Self, TransactNoteError> {
        if token_data.token_type != TokenType::Erc721 {
            return Err(TransactNoteError::InvalidTokenType(
                "ERC721",
                token_data.token_type,
            ));
        }
        Self::create_transfer(
            receiver_address_data,
            sender_address_data,
            erc721_note_value(),
            token_data,
            show_sender_address_to_recipient,
            OutputType::Transfer,
            memo_text,
            wallet_source,
            note_random,
            sender_random,
        )
    }

    /// `createERC1155Transfer`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_erc1155_transfer(
        receiver_address_data: AddressData,
        sender_address_data: Option<AddressData>,
        token_data: TokenData,
        amount: BigUint,
        show_sender_address_to_recipient: bool,
        memo_text: Option<String>,
        wallet_source: Option<String>,
        note_random: Option<String>,
        sender_random: Option<String>,
    ) -> Result<Self, TransactNoteError> {
        if token_data.token_type != TokenType::Erc1155 {
            return Err(TransactNoteError::InvalidTokenType(
                "ERC1155",
                token_data.token_type,
            ));
        }
        Self::create_transfer(
            receiver_address_data,
            sender_address_data,
            amount,
            token_data,
            show_sender_address_to_recipient,
            OutputType::Transfer,
            memo_text,
            wallet_source,
            note_random,
            sender_random,
        )
    }

    /// `getNoteRandom` — 16 random bytes hex.
    pub fn get_note_random() -> String {
        railgun_utils::random_hex(16)
    }

    /// `getSenderRandom` — 15 random bytes hex.
    pub fn get_sender_random() -> String {
        railgun_utils::random_hex(15)
    }

    /// `getNotePublicKey`.
    pub fn get_note_public_key(master_public_key: &BigUint, random: &str) -> BigUint {
        poseidon(&[master_public_key.clone(), hex_to_bigint(random)])
    }

    /// `getSenderAddress`.
    pub fn get_sender_address(&self) -> Option<String> {
        self.sender_address_data.as_ref().map(encode_address)
    }

    /// `getHash`.
    pub fn get_hash(note_public_key: &BigUint, token_hash: &str, value: &BigUint) -> BigUint {
        poseidon(&[
            note_public_key.clone(),
            hex_to_bigint(token_hash),
            value.clone(),
        ])
    }

    /// `getNullifier`.
    pub fn get_nullifier(nullifying_key: &BigUint, leaf_index: u64) -> BigUint {
        poseidon(&[nullifying_key.clone(), BigUint::from(leaf_index)])
    }

    /// `calculateTotalNoteValues`.
    pub fn calculate_total_note_values(notes: &[TransactNote]) -> BigUint {
        notes
            .iter()
            .fold(BigUint::from(0u8), |acc, n| acc + &n.value)
    }

    /// `getEncodedMasterPublicKey`.
    pub fn get_encoded_master_public_key(
        sender_random: Option<&str>,
        receiver_master_public_key: &BigUint,
        sender_master_public_key: &BigUint,
    ) -> BigUint {
        match sender_random {
            Some(sr) if sr != MEMO_SENDER_RANDOM_NULL => receiver_master_public_key.clone(),
            _ => receiver_master_public_key ^ sender_master_public_key,
        }
    }

    /// `getDecodedMasterPublicKey`.
    pub fn get_decoded_master_public_key(
        current_wallet_master_public_key: &BigUint,
        encoded_master_public_key: &BigUint,
        sender_random: Option<&str>,
        is_legacy_decryption: bool,
    ) -> BigUint {
        if is_legacy_decryption
            || matches!(sender_random, Some(sr) if sr != MEMO_SENDER_RANDOM_NULL)
        {
            encoded_master_public_key.clone()
        } else {
            encoded_master_public_key ^ current_wallet_master_public_key
        }
    }

    fn format_value(&self, prefix: bool) -> String {
        n_to_hex(&self.value, ByteLength::Uint128, prefix)
    }

    fn format_random(&self, prefix: bool) -> String {
        format_to_byte_length(
            &BytesData::Hex(self.random.clone()),
            ByteLength::Uint128,
            prefix,
        )
    }

    fn format_token_hash(&self, prefix: bool) -> String {
        format_to_byte_length(
            &BytesData::Hex(self.token_hash.clone()),
            ByteLength::Uint256,
            prefix,
        )
    }

    fn format_npk(&self, prefix: bool) -> String {
        n_to_hex(&self.note_public_key, ByteLength::Uint256, prefix)
    }

    /// `encryptV2` — AES-256-GCM. Returns `(noteCiphertext, noteMemo, annotationData)`.
    pub fn encrypt_v2(
        &self,
        txid_version: TXIDVersion,
        shared_key: &[u8],
        sender_master_public_key: &BigUint,
        sender_random: Option<&str>,
        viewing_private_key: &[u8],
    ) -> Result<(Ciphertext, String, String), TransactNoteError> {
        if txid_version != TXIDVersion::V2_PoseidonMerkle {
            return Err(TransactNoteError::InvalidTxidVersion("V2"));
        }

        let token_hash = self.format_token_hash(false);
        let value = self.format_value(false);
        let random = self.format_random(false);

        let receiver_mpk = &self.receiver_address_data.master_public_key;
        let encoded_mpk = Self::get_encoded_master_public_key(
            sender_random,
            receiver_mpk,
            sender_master_public_key,
        );

        let encoded_memo_text = encode_memo_text(self.memo_text.as_deref());

        let ciphertext = encrypt_gcm(
            &[
                n_to_hex(&encoded_mpk, ByteLength::Uint256, false),
                token_hash,
                format!("{random}{value}"),
                encoded_memo_text,
            ],
            shared_key,
        )
        .map_err(|_| TransactNoteError::DecryptFailed)?;

        let output_type = self
            .output_type
            .ok_or(TransactNoteError::OutputTypeRequired)?;
        let note_sender_random = self
            .sender_random
            .as_ref()
            .ok_or(TransactNoteError::SenderRandomRequired)?;
        let wallet_source = self
            .wallet_source
            .as_ref()
            .ok_or(TransactNoteError::WalletSourceRequired)?;

        let annotation_data = create_encrypted_note_annotation_data_v2(
            output_type,
            note_sender_random,
            wallet_source,
            viewing_private_key,
        )?;

        let note_memo = ciphertext.data[3].clone();
        let note_ciphertext = Ciphertext {
            iv: ciphertext.iv,
            tag: ciphertext.tag,
            data: ciphertext.data[..3].to_vec(),
        };

        Ok((note_ciphertext, note_memo, annotation_data))
    }

    /// `encryptV3` — XChaCha20-Poly1305.
    pub fn encrypt_v3(
        &self,
        txid_version: TXIDVersion,
        shared_key: &[u8],
        sender_master_public_key: &BigUint,
    ) -> Result<CiphertextXChaCha, TransactNoteError> {
        if txid_version != TXIDVersion::V3_PoseidonMerkle {
            return Err(TransactNoteError::InvalidTxidVersion("V3"));
        }

        let token_hash = self.format_token_hash(false);
        let value = self.format_value(false);
        let random = self.format_random(false);

        let receiver_mpk = &self.receiver_address_data.master_public_key;
        let encoded_mpk = Self::get_encoded_master_public_key(
            self.sender_random.as_deref(),
            receiver_mpk,
            sender_master_public_key,
        );

        let sender_random = self
            .sender_random
            .as_ref()
            .ok_or(TransactNoteError::SenderRandomRequired)?;
        if sender_random.len() != 30 {
            return Err(TransactNoteError::SenderRandomLength);
        }

        let encoded_memo_text = encode_memo_text(self.memo_text.as_deref());

        let plaintext = format!(
            "{}{}{}{}{}",
            n_to_hex(&encoded_mpk, ByteLength::Uint256, false), // 64
            format!("{random}{value}"),                         // 64
            token_hash,                                         // 64
            sender_random,                                      // 30
            encoded_memo_text,                                  // variable
        );

        encrypt_cha_cha_20_poly1305(&plaintext, shared_key)
            .map_err(|_| TransactNoteError::DecryptFailed)
    }

    fn unblind_viewing_public_key(
        random: &str,
        blinded_viewing_public_key: Option<&[u8; 32]>,
        sender_random: Option<&str>,
    ) -> Vec<u8> {
        if let (Some(blinded), Some(sr)) = (blinded_viewing_public_key, sender_random) {
            if let Some(unblinded) = unblind_note_key(blinded, random, sr) {
                return unblinded.to_vec();
            }
        }
        Vec::new()
    }

    /// `decrypt` — V2 (AES-GCM) or V3 (XChaCha). `is_legacy_decryption` mirrors
    /// the TS flag; NFT token resolution goes through `token_data_getter`.
    #[allow(clippy::too_many_arguments)]
    pub fn decrypt<G: TokenDataGetter>(
        txid_version: TXIDVersion,
        chain_id: u64,
        current_wallet_address_data: &AddressData,
        note_ciphertext_v2: Option<&Ciphertext>,
        note_ciphertext_v3: Option<&CiphertextXChaCha>,
        shared_key: &[u8],
        memo_v2: &str,
        annotation_data: &str,
        viewing_private_key: &[u8],
        blinded_receiver_viewing_key: Option<&[u8; 32]>,
        blinded_sender_viewing_key: Option<&[u8; 32]>,
        is_sent_note: bool,
        is_legacy_decryption: bool,
        token_data_getter: &G,
        block_number: Option<u64>,
        transact_commitment_batch_index_v3: Option<usize>,
    ) -> Result<TransactNote, TransactNoteError> {
        match txid_version {
            TXIDVersion::V2_PoseidonMerkle => {
                let note_ciphertext =
                    note_ciphertext_v2.ok_or(TransactNoteError::InvalidCiphertext("V2"))?;
                let mut data = note_ciphertext.data.clone();
                data.push(railgun_utils::strip_0x(memo_v2).to_string());
                let full_ciphertext = Ciphertext {
                    iv: note_ciphertext.iv.clone(),
                    tag: note_ciphertext.tag.clone(),
                    data,
                };
                let decrypted: Vec<String> = decrypt_gcm(&full_ciphertext, shared_key)
                    .map_err(|_| TransactNoteError::DecryptFailed)?
                    .iter()
                    .map(|v| hexlify(&BytesData::Hex(v.clone()), false))
                    .collect();

                let (random, value, memo_text, token_data, encoded_mpk) =
                    Self::decrypted_values_v2(
                        txid_version,
                        chain_id,
                        &decrypted,
                        token_data_getter,
                    )?;

                let note_annotation_data = if is_sent_note {
                    decrypt_note_annotation_data(annotation_data, viewing_private_key)
                } else {
                    None
                };
                let (output_type, wallet_source, sender_random) = match note_annotation_data {
                    Some(d) => (Some(d.output_type), d.wallet_source, Some(d.sender_random)),
                    None => (None, None, None),
                };

                Self::note_from_decrypted_values(
                    current_wallet_address_data,
                    output_type,
                    wallet_source,
                    blinded_receiver_viewing_key,
                    blinded_sender_viewing_key,
                    sender_random,
                    is_sent_note,
                    is_legacy_decryption,
                    block_number,
                    random,
                    value,
                    memo_text,
                    token_data,
                    encoded_mpk,
                )
            }
            TXIDVersion::V3_PoseidonMerkle => {
                let note_ciphertext =
                    note_ciphertext_v3.ok_or(TransactNoteError::InvalidCiphertext("V3"))?;
                let decrypted = decrypt_cha_cha_20_poly1305(note_ciphertext, shared_key)
                    .map_err(|_| TransactNoteError::DecryptFailed)?;

                let (random, value, memo_text, token_data, encoded_mpk, sender_random) =
                    Self::decrypted_values_v3(
                        txid_version,
                        chain_id,
                        &decrypted,
                        token_data_getter,
                    )?;

                let batch_index = transact_commitment_batch_index_v3
                    .ok_or(TransactNoteError::BatchIndexRequired)?;

                let sender_decrypted = if is_sent_note {
                    decrypt_sender_ciphertext_v3(annotation_data, viewing_private_key, batch_index)
                } else {
                    None
                };
                let (output_type, wallet_source) = match sender_decrypted {
                    Some(d) => (Some(d.output_type), d.wallet_source),
                    None => (None, None),
                };

                Self::note_from_decrypted_values(
                    current_wallet_address_data,
                    output_type,
                    wallet_source,
                    blinded_receiver_viewing_key,
                    blinded_sender_viewing_key,
                    Some(sender_random),
                    is_sent_note,
                    is_legacy_decryption,
                    block_number,
                    random,
                    value,
                    memo_text,
                    token_data,
                    encoded_mpk,
                )
            }
        }
    }

    fn decrypted_values_v2<G: TokenDataGetter>(
        txid_version: TXIDVersion,
        chain_id: u64,
        decrypted: &[String],
        token_data_getter: &G,
    ) -> Result<(String, BigUint, Option<String>, TokenData, BigUint), TransactNoteError> {
        let random = decrypted[2][0..32].to_string();
        let value = hex_to_bigint(&decrypted[2][32..64]);
        let token_hash = decrypted[1].clone();
        let memo_text = decode_memo_text(&combine(&decrypted[3..]));
        let token_data = token_data_getter
            .get_token_data_from_hash(txid_version, chain_id, &token_hash)
            .ok_or(TransactNoteError::TokenDataNotFound)?;
        let encoded_mpk = hex_to_bigint(&decrypted[0]);
        Ok((random, value, memo_text, token_data, encoded_mpk))
    }

    #[allow(clippy::type_complexity)]
    fn decrypted_values_v3<G: TokenDataGetter>(
        txid_version: TXIDVersion,
        chain_id: u64,
        decrypted: &str,
        token_data_getter: &G,
    ) -> Result<(String, BigUint, Option<String>, TokenData, BigUint, String), TransactNoteError>
    {
        let encoded_mpk = hex_to_bigint(&decrypted[0..64]);
        let random = decrypted[64..96].to_string();
        let value = hex_to_bigint(&decrypted[96..128]);
        let token_hash = decrypted[128..192].to_string();
        let token_data = token_data_getter
            .get_token_data_from_hash(txid_version, chain_id, &token_hash)
            .ok_or(TransactNoteError::TokenDataNotFound)?;
        let sender_random = decrypted[192..222].to_string();
        let memo_text = if decrypted.len() > 222 {
            decode_memo_text(&decrypted[222..])
        } else {
            None
        };
        Ok((
            random,
            value,
            memo_text,
            token_data,
            encoded_mpk,
            sender_random,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn note_from_decrypted_values(
        current_wallet_address_data: &AddressData,
        output_type: Option<OutputType>,
        wallet_source: Option<String>,
        blinded_receiver_viewing_key: Option<&[u8; 32]>,
        blinded_sender_viewing_key: Option<&[u8; 32]>,
        sender_random: Option<String>,
        is_sent_note: bool,
        is_legacy_decryption: bool,
        block_number: Option<u64>,
        random: String,
        value: BigUint,
        memo_text: Option<String>,
        token_data: TokenData,
        encoded_mpk: BigUint,
    ) -> Result<TransactNote, TransactNoteError> {
        if is_sent_note {
            let receiver_address_data = AddressData {
                master_public_key: Self::get_decoded_master_public_key(
                    &current_wallet_address_data.master_public_key,
                    &encoded_mpk,
                    sender_random.as_deref(),
                    is_legacy_decryption,
                ),
                viewing_public_key: Self::unblind_viewing_public_key(
                    &random,
                    blinded_receiver_viewing_key,
                    sender_random.as_deref(),
                ),
                chain: None,
                version: None,
            };
            return Self::construct(
                receiver_address_data,
                Some(current_wallet_address_data.clone()),
                random,
                value,
                token_data,
                output_type,
                wallet_source,
                sender_random,
                memo_text,
                None,
                block_number,
            );
        }

        // RECEIVE note.
        let sender_address_visible = encoded_mpk != current_wallet_address_data.master_public_key;

        let sender_address_data = if sender_address_visible {
            Some(AddressData {
                master_public_key: Self::get_decoded_master_public_key(
                    &current_wallet_address_data.master_public_key,
                    &encoded_mpk,
                    None,
                    is_legacy_decryption,
                ),
                viewing_public_key: Self::unblind_viewing_public_key(
                    &random,
                    blinded_sender_viewing_key,
                    Some(MEMO_SENDER_RANDOM_NULL),
                ),
                chain: None,
                version: None,
            })
        } else {
            None
        };

        Self::construct(
            current_wallet_address_data.clone(),
            sender_address_data,
            random,
            value,
            token_data,
            output_type,
            wallet_source,
            sender_random,
            memo_text,
            None,
            block_number,
        )
    }

    /// `serialize` — `NoteSerialized`.
    pub fn serialize(&self, prefix: bool) -> NoteSerialized {
        NoteSerialized {
            npk: self.format_npk(prefix),
            token_hash: self.format_token_hash(prefix),
            value: self.format_value(prefix),
            random: self.format_random(prefix),
            wallet_source: self.wallet_source.clone(),
            sender_random: self.sender_random.clone(),
            output_type: self.output_type,
            recipient_address: encode_address(&self.receiver_address_data),
            sender_address: self.sender_address_data.as_ref().map(encode_address),
            memo_text: self.memo_text.clone(),
            shield_fee: self.shield_fee.clone(),
            block_number: self.block_number,
        }
    }

    /// `serializeLegacy` — `LegacyNoteSerialized` (random AES-GCM encrypted with vpk).
    pub fn serialize_legacy(
        &self,
        viewing_private_key: &[u8],
        prefix: bool,
    ) -> Result<LegacyNoteSerialized, TransactNoteError> {
        let random = self.format_random(false);
        let random_ciphertext = encrypt_gcm(&[random], viewing_private_key)
            .map_err(|_| TransactNoteError::DecryptFailed)?;
        let [iv_tag, data] =
            railgun_crypto::ciphertext_to_encrypted_random_data(&random_ciphertext);
        Ok(LegacyNoteSerialized {
            npk: self.format_npk(prefix),
            token_hash: self.format_token_hash(prefix),
            value: self.format_value(prefix),
            encrypted_random: [
                hexlify(&BytesData::Hex(iv_tag), prefix),
                hexlify(&BytesData::Hex(data), prefix),
            ],
            memo_field: Vec::new(),
            recipient_address: encode_address(&self.receiver_address_data),
            memo_text: self.memo_text.clone(),
            block_number: self.block_number,
        })
    }

    /// `isLegacyTransactNote`.
    pub fn is_legacy_serialized(note: &DecryptedNote) -> bool {
        matches!(note, DecryptedNote::Legacy(_))
    }

    /// `deserialize` — `NoteSerialized | LegacyNoteSerialized`.
    pub fn deserialize<G: TokenDataGetter>(
        txid_version: TXIDVersion,
        chain_id: u64,
        note_data: &DecryptedNote,
        viewing_private_key: &[u8],
        token_data_getter: &G,
    ) -> Result<TransactNote, TransactNoteError> {
        match note_data {
            DecryptedNote::Legacy(legacy) => Self::deserialize_legacy(legacy, viewing_private_key),
            DecryptedNote::Note(note) => {
                let token_data = token_data_getter
                    .get_token_data_from_hash(txid_version, chain_id, &note.token_hash)
                    .ok_or(TransactNoteError::TokenDataNotFound)?;
                Self::construct(
                    decode_address(&note.recipient_address)
                        .map_err(|_| TransactNoteError::DecryptFailed)?,
                    match &note.sender_address {
                        Some(addr) => Some(
                            decode_address(addr).map_err(|_| TransactNoteError::DecryptFailed)?,
                        ),
                        None => None,
                    },
                    note.random.clone(),
                    hex_to_bigint(&note.value),
                    token_data,
                    note.output_type,
                    note.wallet_source.clone(),
                    note.sender_random.clone(),
                    note.memo_text.clone(),
                    note.shield_fee.clone(),
                    note.block_number,
                )
            }
        }
    }

    /// `deserializeLegacy` — random AES-GCM decrypted with the viewing key; ERC20 only.
    fn deserialize_legacy(
        note_data: &LegacyNoteSerialized,
        viewing_private_key: &[u8],
    ) -> Result<TransactNote, TransactNoteError> {
        let random_ciphertext =
            railgun_crypto::encrypted_data_to_ciphertext(&note_data.encrypted_random);
        let decrypted_random = decrypt_gcm(&random_ciphertext, viewing_private_key)
            .map_err(|_| TransactNoteError::DecryptFailed)?;
        let token_data = get_token_data_erc20(&note_data.token_hash);
        Self::construct(
            decode_address(&note_data.recipient_address)
                .map_err(|_| TransactNoteError::DecryptFailed)?,
            None,
            combine(&decrypted_random),
            hex_to_bigint(&note_data.value),
            token_data,
            None,
            None,
            None,
            note_data.memo_text.clone(),
            None,
            note_data.block_number,
        )
    }

    /// `newProcessingNoteWithValue`.
    pub fn new_processing_note_with_value(
        &self,
        value: BigUint,
    ) -> Result<TransactNote, TransactNoteError> {
        Self::construct(
            self.receiver_address_data.clone(),
            self.sender_address_data.clone(),
            Self::get_note_random(),
            value,
            self.token_data.clone(),
            self.output_type,
            self.wallet_source.clone(),
            self.sender_random.clone(),
            self.memo_text.clone(),
            self.shield_fee.clone(),
            None,
        )
    }

    /// `createNullUnshieldNote`.
    pub fn create_null_unshield_note(
        token_data: TokenData,
        value: BigUint,
    ) -> Result<TransactNote, TransactNoteError> {
        let null_address = AddressData {
            master_public_key: BigUint::from(0u8),
            viewing_public_key: vec![0u8; 32],
            chain: None,
            version: None,
        };
        Self::construct(
            null_address,
            None,
            Self::get_note_random(),
            value,
            token_data,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use railgun_crypto::get_public_viewing_key;
    use railgun_models::formatted_types::DecryptedNote;
    use railgun_models::OutputType;
    use railgun_utils::hex_string_to_bytes;

    const RECIPIENT_ADDRESS: &str = "0zk1qxvsy4jxshey7wtzv0ry7kp24x58fxtsg5yuvzrzjv93l8mayk8garv7j6fe3z53l7vsy4jxshey7wtzv0ry7kp24x58fxtsg5yuvzrzjv93l8mayk8guau6ef8";
    const BLOCK_NUMBER: u64 = 100;

    fn vpk(hex: &str) -> [u8; 32] {
        hex_string_to_bytes(hex).unwrap().try_into().unwrap()
    }

    // transact-note.test.ts "Should serialize and deserialize notes" (KAV: hashes).
    #[test]
    fn serialize_deserialize_notes() {
        struct V {
            npk: &'static str,
            token_hash: &'static str,
            value: &'static str,
            encrypted_random: [&'static str; 2],
            random: &'static str,
            vpk: &'static str,
            hash: &'static str,
        }
        let vectors = [
            V {
                npk: "23da85e72baa8d77f476a893de0964ce1ec2957d056b591a19d05bb4b9a549ed",
                token_hash: "0000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192",
                value: "0000000000000000086aa1ade61ccb53",
                encrypted_random: [
                    "0x5c4a783fd15546fbad149c673b7139790a9cf62ec849a5a8e6a167815ee2d08d",
                    "0x260693ec8dd38f5be7758b6786bc579e",
                ],
                random: "85b08a7cd73ee433072f1d410aeb4801",
                vpk: "0b252eea1d78ff7b2ad19ea161dfe380686a099f9713719d2eff85196a607685",
                hash: "29decce78b2f43c718ebb7c6825617ea6881836d88d9551dd2530c44f0d790c5",
            },
            V {
                npk: "21eacdfdbe32555ed1c08c4872e73da1e59cb47f7f9d886f702b0e0e6399474c",
                token_hash: "000000000000000000000000df0fa4124c8a5feec8efcb0e0142d3e04a9e0fbf",
                value: "000000000000000007cf6b5ae17ae75a",
                encrypted_random: [
                    "0xf401e001c520b9f40d37736c0ef2309fa9b2dc97bf1634ac1443fc2fe5359f69",
                    "0x093481f1f6ab744d9f937e6ec796e300",
                ],
                random: "f7c477afb5a3eb31dbb96295cdbcf165",
                vpk: "0a13664024e298e53bf01342e2111ae314f9595b12107e85cf0066e4b04cb3a3",
                hash: "2d78128d8bd632fa45e76906b6d58bbb7b581d28a040565b688adb498b8e37db",
            },
            V {
                npk: "24203d63bb50c2cfc256c405b81147058ded5ab422c97489dddef7a2486217d7",
                token_hash: "00000000000000000000000034e34b5d8e848f9d20d9bd8e1e48e24c3b87c396",
                value: "00000000000000000b9df0087cbbd709",
                encrypted_random: [
                    "0x4b0b63e8f573bf29cabc8e840c5db89892c0acc3f30bbdf6ad9d39ac9485fa49",
                    "0xcbfb4c84c0669aaf184a621c9d21e9ae",
                ],
                random: "6d8a7e26de6b0638cd092c2a2b524705",
                vpk: "099ba7ffc589df18402385d7c0d4771555dffd2a6514fc136c565ea1ee3bb520",
                hash: "0d046f7423d5e69726cf2d98d2c5c3fe089f3151f9ac968e2314696efa833f62",
            },
        ];

        let getter = Erc20TokenDataGetter;
        for v in vectors {
            let legacy = LegacyNoteSerialized {
                npk: v.npk.into(),
                token_hash: v.token_hash.into(),
                value: v.value.into(),
                encrypted_random: [v.encrypted_random[0].into(), v.encrypted_random[1].into()],
                memo_field: vec!["01".into()],
                recipient_address: RECIPIENT_ADDRESS.into(),
                memo_text: None,
                block_number: Some(BLOCK_NUMBER),
            };
            let note = TransactNote::deserialize(
                TXIDVersion::V2_PoseidonMerkle,
                1,
                &DecryptedNote::Legacy(legacy),
                &vpk(v.vpk),
                &getter,
            )
            .unwrap();

            assert_eq!(
                hexlify(&BytesData::Hex(note.random.clone()), false),
                v.random
            );
            assert_eq!(n_to_hex(&note.hash, ByteLength::Uint256, false), v.hash);

            // Re-serialize to NoteSerialized.
            let reserialized = note.serialize(false);
            assert_eq!(reserialized.npk, v.npk);
            assert_eq!(reserialized.value, v.value);
            assert_eq!(reserialized.token_hash, v.token_hash);
            assert_eq!(reserialized.recipient_address, RECIPIENT_ADDRESS);

            let reserialized_contract = note.serialize(true);
            assert_eq!(reserialized_contract.value, format!("0x{}", v.value));
            assert_eq!(
                reserialized_contract.token_hash,
                format!("0x{}", v.token_hash)
            );
            assert_eq!(reserialized_contract.recipient_address, RECIPIENT_ADDRESS);

            // serializeLegacy round-trips npk/value/tokenHash with empty memoField.
            let legacy_out = note.serialize_legacy(&vpk(v.vpk), false).unwrap();
            assert_eq!(legacy_out.npk, v.npk);
            assert_eq!(legacy_out.value, v.value);
            assert_eq!(legacy_out.token_hash, v.token_hash);
            assert!(legacy_out.memo_field.is_empty());
            assert_eq!(legacy_out.recipient_address, RECIPIENT_ADDRESS);
        }
    }

    // transact-note.test.ts "Should calculate nullifiers" (KAV).
    #[test]
    fn calculate_nullifiers() {
        let vectors = [
            (
                "08ad9143ae793cdfe94b77e4e52bc4e9f13666966cffa395e3d412ea4e20480f",
                0u64,
                "03f68801f3ee2ed10178c162b4f7f1bd466bc9718f4f98175fc04934c5caba6e",
            ),
            (
                "11299eb10424d82de500a440a2874d12f7c477afb5a3eb31dbb96295cdbcf165",
                12,
                "1aeadb64bf8faff93dfe26bcf0b2e2d0e9724293cc7a455f028b6accabee13b8",
            ),
            (
                "09b57736523cda7412ddfed0d2f1f4a86d8a7e26de6b0638cd092c2a2b524705",
                6500,
                "091961ce11c244db49a25668e57dfa2b5ffb1fe63055dd64a14af6f2be58b0e7",
            ),
        ];
        for (private_key, position, nullifier) in vectors {
            let n = TransactNote::get_nullifier(&hex_to_bigint(private_key), position);
            assert_eq!(n_to_hex(&n, ByteLength::Uint256, false), nullifier);
        }
    }

    // transact-note.test.ts "Should encrypt and decrypt notes" (V2 roundtrip).
    #[test]
    fn encrypt_decrypt_v2() {
        struct CV {
            pubkey: &'static str,
            random: &'static str,
            amount: &'static str,
            token: &'static str,
            shared_key: &'static str,
        }
        let vectors = [
            CV {
                pubkey: "6595f9a971c7471695948a445aedcbb9d624a325dbe68c228dea25eccf61919d",
                random: "85b08a7cd73ee433072f1d410aeb4801",
                amount: "000000000000000000000000000000000000000000000000086aa1ade61ccb53",
                token: "0000000000000000000000000000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192",
                shared_key: "b8b0ee90e05cec44880f1af4d20506265f44684eb3b6a4327bcf811244dc0a7f",
            },
            CV {
                pubkey: "ab017ebda8fae25c92ecfc38f219c0ed1f73538bc9dc8e5db8ae46f3b00d5a2f",
                random: "f7c477afb5a3eb31dbb96295cdbcf165",
                amount: "00000000000000000000000000000000000000000000000007cf6b5ae17ae75a",
                token: "000000000000000000000000000000000000000000000000df0fa4124c8a5feec8efcb0e0142d3e04a9e0fbf",
                shared_key: "c8c2a74bacf6ce3158069f81202d8c2d81fd25d226d7536f26442888c014a755",
            },
        ];

        let getter = Erc20TokenDataGetter;
        let viewing_private_key = [0x11u8; 32];
        let _ = get_public_viewing_key(&viewing_private_key);

        for v in vectors {
            let mpk = hex_to_bigint(v.pubkey);
            let viewing_public_key = hex_string_to_bytes(v.pubkey).unwrap();
            let address = AddressData {
                master_public_key: mpk.clone(),
                viewing_public_key,
                chain: None,
                version: None,
            };
            let token_data = get_token_data_erc20(v.token);
            let shared_key = hex_string_to_bytes(v.shared_key).unwrap();

            let note = TransactNote::create_transfer(
                address.clone(),
                Some(address.clone()),
                hex_to_bigint(v.amount),
                token_data,
                false, // showSenderAddressToRecipient
                OutputType::BroadcasterFee,
                Some("something".into()),
                Some("tester".into()),
                Some(v.random.into()),
                None, // injected_sender_random (random 15 bytes)
            )
            .unwrap();

            let (note_ciphertext, note_memo, annotation_data) = note
                .encrypt_v2(
                    TXIDVersion::V2_PoseidonMerkle,
                    &shared_key,
                    &address.master_public_key,
                    note.sender_random.as_deref(),
                    &viewing_private_key,
                )
                .unwrap();

            let decrypted = TransactNote::decrypt(
                TXIDVersion::V2_PoseidonMerkle,
                1,
                &address,
                Some(&note_ciphertext),
                None,
                &shared_key,
                &note_memo,
                &annotation_data,
                &viewing_private_key,
                None,
                None,
                true, // is_sent_note
                true, // is_legacy_decryption
                &getter,
                Some(BLOCK_NUMBER),
                None,
            )
            .unwrap();

            assert_eq!(decrypted.token_hash, note.token_hash);
            assert_eq!(decrypted.value, note.value);
            assert_eq!(decrypted.random, note.random);
            assert_eq!(decrypted.hash, note.hash);
            assert_eq!(decrypted.memo_text, note.memo_text);
        }
    }

    // V3 roundtrip (XChaCha20-Poly1305).
    #[test]
    fn encrypt_decrypt_v3() {
        let getter = Erc20TokenDataGetter;
        let viewing_private_key = [0x22u8; 32];
        let pubkey = "6595f9a971c7471695948a445aedcbb9d624a325dbe68c228dea25eccf61919d";
        let token = "0000000000000000000000000000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192";
        let shared_key =
            hex_string_to_bytes("b8b0ee90e05cec44880f1af4d20506265f44684eb3b6a4327bcf811244dc0a7f")
                .unwrap();

        let mpk = hex_to_bigint(pubkey);
        let address = AddressData {
            master_public_key: mpk.clone(),
            viewing_public_key: hex_string_to_bytes(pubkey).unwrap(),
            chain: None,
            version: None,
        };

        let note = TransactNote::create_transfer(
            address.clone(),
            Some(address.clone()),
            hex_to_bigint("086aa1ade61ccb53"),
            get_token_data_erc20(token),
            false,
            OutputType::BroadcasterFee,
            Some("hello world".into()),
            Some("tester".into()),
            Some("85b08a7cd73ee433072f1d410aeb4801".into()),
            Some("0a0b0c0d0e0f101112131415161718".into()), // 15-byte sender random
        )
        .unwrap();

        let note_ciphertext = note
            .encrypt_v3(
                TXIDVersion::V3_PoseidonMerkle,
                &shared_key,
                &address.master_public_key,
            )
            .unwrap();

        // V3 sender annotation, batch index 0.
        let annotation = crate::memo::create_sender_annotation_encrypted_v3(
            "tester",
            &[note.output_type.unwrap()],
            &viewing_private_key,
        )
        .unwrap();

        let decrypted = TransactNote::decrypt(
            TXIDVersion::V3_PoseidonMerkle,
            1,
            &address,
            None,
            Some(&note_ciphertext),
            &shared_key,
            "",
            &annotation,
            &viewing_private_key,
            None,
            None,
            true,
            false,
            &getter,
            Some(BLOCK_NUMBER),
            Some(0),
        )
        .unwrap();

        assert_eq!(decrypted.token_hash, note.token_hash);
        assert_eq!(decrypted.value, note.value);
        assert_eq!(decrypted.random, note.random);
        assert_eq!(decrypted.hash, note.hash);
        assert_eq!(decrypted.memo_text, note.memo_text);
    }
}
