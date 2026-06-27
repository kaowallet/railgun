//! Port of `src/note/shield-note.ts` and `src/note/erc20|nft/shield-note-*.ts`.

use num_bigint::BigUint;
use railgun_crypto::{
    encrypt_ctr, encrypt_gcm, get_public_viewing_key, get_shared_symmetric_key, poseidon,
};
use railgun_models::formatted_types::{NFTTokenData, ShieldCiphertext};
use railgun_models::TokenData;
use railgun_utils::{combine, hex_to_bigint, hexlify, n_to_hex, ByteLength, BytesData};

use crate::note_util::{
    assert_valid_note_random, assert_valid_note_token, get_token_data_erc20, get_token_data_hash,
    NoteUtilError,
};

#[derive(Debug, thiserror::Error)]
pub enum ShieldNoteError {
    #[error("{0}")]
    NoteUtil(#[from] NoteUtilError),
    #[error("Could not generated shared symmetric key for shielding.")]
    SharedKey,
    #[error("encryption error")]
    Encryption,
}

/// `ShieldNote` (abstract base). Concrete ERC20/NFT constructors are free functions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldNote {
    pub master_public_key: BigUint,
    pub random: String,
    pub value: BigUint,
    pub token_data: TokenData,
    pub token_hash: String,
    pub note_public_key: BigUint,
}

impl ShieldNote {
    /// Mirrors the TS base constructor (with validation).
    pub fn new(
        master_public_key: BigUint,
        random: String,
        value: BigUint,
        token_data: TokenData,
    ) -> Result<Self, ShieldNoteError> {
        assert_valid_note_random(&random)?;
        assert_valid_note_token(&token_data, &value)?;
        let token_hash = get_token_data_hash(&token_data);
        let note_public_key = Self::get_note_public_key(&master_public_key, &random);
        Ok(ShieldNote {
            master_public_key,
            random,
            value,
            token_data,
            token_hash,
            note_public_key,
        })
    }

    /// `ShieldNoteERC20`.
    pub fn erc20(
        master_public_key: BigUint,
        random: String,
        value: BigUint,
        token_address: &str,
    ) -> Result<Self, ShieldNoteError> {
        let token_data = get_token_data_erc20(token_address);
        Self::new(master_public_key, random, value, token_data)
    }

    /// `ShieldNoteNFT`.
    pub fn nft(
        master_public_key: BigUint,
        random: String,
        value: BigUint,
        token_data: NFTTokenData,
    ) -> Result<Self, ShieldNoteError> {
        Self::new(master_public_key, random, value, token_data)
    }

    /// `getShieldPrivateKeySignatureMessage` — DO NOT MODIFY.
    pub fn get_shield_private_key_signature_message() -> &'static str {
        "RAILGUN_SHIELD"
    }

    /// `getNotePublicKey`.
    pub fn get_note_public_key(master_public_key: &BigUint, random: &str) -> BigUint {
        poseidon(&[master_public_key.clone(), hex_to_bigint(random)])
    }

    /// `getShieldNoteHash`.
    pub fn get_shield_note_hash(
        note_public_key: &BigUint,
        token_hash: &str,
        value_after_fee: &BigUint,
    ) -> BigUint {
        poseidon(&[
            note_public_key.clone(),
            hex_to_bigint(token_hash),
            value_after_fee.clone(),
        ])
    }

    /// `serialize` — produces `(preimage, ciphertext)` for the `ShieldRequestStruct`.
    /// `shield_private_key` and `receiver_viewing_public_key` are 32-byte keys.
    pub fn serialize(
        &self,
        shield_private_key: &[u8; 32],
        receiver_viewing_public_key: &[u8; 32],
    ) -> Result<(ShieldPreImage, ShieldCiphertext), ShieldNoteError> {
        let shared_key = get_shared_symmetric_key(shield_private_key, receiver_viewing_public_key)
            .ok_or(ShieldNoteError::SharedKey)?;

        let encrypted_random = encrypt_gcm(&[self.random.clone()], &shared_key)
            .map_err(|_| ShieldNoteError::Encryption)?;

        let encrypted_receiver = encrypt_ctr(
            &[hex::encode(receiver_viewing_public_key)],
            shield_private_key,
        )
        .map_err(|_| ShieldNoteError::Encryption)?;

        let shield_key = hex::encode(get_public_viewing_key(shield_private_key));

        let mut bundle1_parts = encrypted_random.data.clone();
        bundle1_parts.push(encrypted_receiver.iv.clone());

        let ciphertext = ShieldCiphertext {
            encrypted_bundle: [
                hexlify(
                    &BytesData::Hex(format!("{}{}", encrypted_random.iv, encrypted_random.tag)),
                    true,
                ),
                hexlify(&BytesData::Hex(combine(&bundle1_parts)), true),
                hexlify(&BytesData::Hex(combine(&encrypted_receiver.data)), true),
            ],
            shield_key: hexlify(&BytesData::Hex(shield_key), true),
        };

        let preimage = ShieldPreImage {
            npk: n_to_hex(&self.note_public_key, ByteLength::Uint256, true),
            token: self.token_data.clone(),
            value: self.value.clone(),
        };

        Ok((preimage, ciphertext))
    }
}

/// The `preimage` field of a `ShieldRequestStruct` (value kept as `BigUint`, as in TS).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldPreImage {
    pub npk: String,
    pub token: TokenData,
    pub value: BigUint,
}

#[cfg(test)]
mod tests {
    use super::*;
    use railgun_models::TokenType;
    use railgun_utils::{format_to_byte_length, random_hex};

    fn token_address() -> String {
        // config.contracts.rail formatted to address length.
        format_to_byte_length(
            &BytesData::Hex("0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0".into()),
            ByteLength::Address,
            true,
        )
    }

    // shield-note.test.ts "Should get expected signature message".
    #[test]
    fn signature_message() {
        assert_eq!(
            ShieldNote::get_shield_private_key_signature_message(),
            "RAILGUN_SHIELD"
        );
    }

    // shield-note.test.ts "Should create shield note".
    #[test]
    fn create_shield_note() {
        let mpk = BigUint::from(123456789u64);
        let rand = random_hex(16);
        let shield = ShieldNote::erc20(
            mpk.clone(),
            rand.clone(),
            BigUint::from(1000u32),
            &token_address(),
        )
        .unwrap();
        assert_eq!(shield.token_data.token_address, token_address());
        assert_eq!(shield.token_data.token_type, TokenType::Erc20);
        assert_eq!(
            hex_to_bigint(&shield.token_data.token_sub_id),
            BigUint::from(0u8)
        );
        let npk = poseidon(&[mpk, hex_to_bigint(&rand)]);
        assert_eq!(shield.note_public_key, npk);
        assert_eq!(shield.value, BigUint::from(1000u32));
    }

    // shield-note.test.ts "Should validate length of random parameter".
    #[test]
    fn validates_random_length() {
        let mpk = BigUint::from(1u8);
        assert!(ShieldNote::erc20(
            mpk.clone(),
            random_hex(15),
            BigUint::from(1000u32),
            &token_address()
        )
        .is_err());
        assert!(ShieldNote::erc20(
            mpk.clone(),
            random_hex(17),
            BigUint::from(1000u32),
            &token_address()
        )
        .is_err());
        assert!(ShieldNote::erc20(
            mpk,
            random_hex(16),
            BigUint::from(1000u32),
            &token_address()
        )
        .is_ok());
    }

    // shield-note.test.ts "Should serialize ShieldNote to preimage and ciphertext".
    #[test]
    fn serialize_shield_note() {
        let mpk = BigUint::from(987654321u64);
        let vpk = [0x09u8; 32];
        let viewing_public_key = get_public_viewing_key(&vpk);
        let rand = random_hex(16);
        let shield =
            ShieldNote::erc20(mpk, rand, BigUint::from(1000u32), &token_address()).unwrap();
        let shield_private_key: [u8; 32] = railgun_utils::hex_string_to_bytes(&random_hex(32))
            .unwrap()
            .try_into()
            .unwrap();
        let (preimage, ciphertext) = shield
            .serialize(&shield_private_key, &viewing_public_key)
            .unwrap();
        assert_eq!(
            hexlify(&BytesData::Hex(preimage.npk.clone()), false).len(),
            64
        );
        assert_eq!(preimage.token.token_address, token_address());
        assert_eq!(preimage.value, BigUint::from(1000u32));
        assert_eq!(ciphertext.encrypted_bundle.len(), 3);
    }
}
