//! Port of `src/note/note-util.ts` — token data construction, token hashing,
//! note-hash and preimage helpers.

use num_bigint::BigUint;
use num_traits::Zero;
use railgun_crypto::{keccak256_bytes, poseidon};
use railgun_models::{TokenData, TokenType};
use railgun_utils::{
    combine, format_to_byte_length, hex_string_to_bytes, hex_to_bigint, hexlify, n_to_bytes,
    n_to_hex, ByteLength, BytesData,
};

pub const TOKEN_SUB_ID_NULL: &str = "0x00";

/// `ERC721_NOTE_VALUE`.
pub fn erc721_note_value() -> BigUint {
    BigUint::from(1u8)
}

/// RAILGUN's `SNARK_PRIME` (BN254 scalar field modulus).
fn snark_prime() -> BigUint {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("valid prime")
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NoteUtilError {
    #[error("{0}")]
    InvalidToken(String),
    #[error("{0}")]
    InvalidRandom(String),
    #[error("Unrecognized token type.")]
    UnrecognizedTokenType,
}

/// `assertValidNoteToken`.
pub fn assert_valid_note_token(
    token_data: &TokenData,
    value: &BigUint,
) -> Result<(), NoteUtilError> {
    let token_address_hex = hexlify(&BytesData::Hex(token_data.token_address.clone()), false);
    let token_address_length = token_address_hex.len();

    match token_data.token_type {
        TokenType::Erc20 => {
            if token_address_length != 40 && token_address_length != 64 {
                return Err(NoteUtilError::InvalidToken(format!(
                    "ERC20 address must be length 40 (20 bytes) or 64 (32 bytes). Got {token_address_hex}."
                )));
            }
            if !hex_to_bigint(&token_data.token_sub_id).is_zero() {
                return Err(NoteUtilError::InvalidToken(
                    "ERC20 note cannot have tokenSubID parameter.".into(),
                ));
            }
            Ok(())
        }
        TokenType::Erc721 => {
            if token_address_length != 40 {
                return Err(NoteUtilError::InvalidToken(format!(
                    "ERC721 address must be length 40 (20 bytes). Got {token_address_hex}."
                )));
            }
            if token_data.token_sub_id.is_empty() {
                return Err(NoteUtilError::InvalidToken(
                    "ERC721 note must have tokenSubID parameter.".into(),
                ));
            }
            if *value != BigUint::from(1u8) {
                return Err(NoteUtilError::InvalidToken(
                    "ERC721 note must have value of 1.".into(),
                ));
            }
            Ok(())
        }
        TokenType::Erc1155 => {
            if token_address_length != 40 {
                return Err(NoteUtilError::InvalidToken(format!(
                    "ERC1155 address must be length 40 (20 bytes). Got {token_address_hex}."
                )));
            }
            if token_data.token_sub_id.is_empty() {
                return Err(NoteUtilError::InvalidToken(
                    "ERC1155 note must have tokenSubID parameter.".into(),
                ));
            }
            Ok(())
        }
    }
}

/// `assertValidNoteRandom`.
pub fn assert_valid_note_random(random: &str) -> Result<(), NoteUtilError> {
    let h = hexlify(&BytesData::Hex(random.to_string()), false);
    if h.len() != 32 {
        return Err(NoteUtilError::InvalidRandom(format!(
            "Random must be length 32 (16 bytes). Got {h}."
        )));
    }
    Ok(())
}

/// `serializeTokenData`.
pub fn serialize_token_data(
    token_address: &str,
    token_type: TokenType,
    token_sub_id: &BigUint,
) -> TokenData {
    TokenData {
        token_address: format_to_byte_length(
            &BytesData::Hex(token_address.to_string()),
            ByteLength::Address,
            true,
        ),
        token_type,
        token_sub_id: n_to_hex(token_sub_id, ByteLength::Uint256, true),
    }
}

/// `getTokenDataERC20`.
pub fn get_token_data_erc20(token_address: &str) -> TokenData {
    TokenData {
        token_address: format_to_byte_length(
            &BytesData::Hex(token_address.to_string()),
            ByteLength::Address,
            true,
        ),
        token_type: TokenType::Erc20,
        token_sub_id: format_to_byte_length(
            &BytesData::Hex(TOKEN_SUB_ID_NULL.to_string()),
            ByteLength::Uint256,
            true,
        ),
    }
}

/// `getTokenDataNFT`.
pub fn get_token_data_nft(
    nft_address: &str,
    token_type: TokenType,
    token_sub_id: &str,
) -> TokenData {
    TokenData {
        token_address: format_to_byte_length(
            &BytesData::Hex(nft_address.to_string()),
            ByteLength::Address,
            true,
        ),
        token_type,
        token_sub_id: format_to_byte_length(
            &BytesData::Hex(token_sub_id.to_string()),
            ByteLength::Uint256,
            true,
        ),
    }
}

/// `getTokenDataHashERC20`.
fn get_token_data_hash_erc20(token_address: &str) -> String {
    let bytes = hex_string_to_bytes(railgun_utils::strip_0x(token_address)).unwrap_or_default();
    format_to_byte_length(&BytesData::Bytes(bytes), ByteLength::Uint256, false)
}

/// `getTokenDataHashNFT` — keccak256 of `[tokenType, tokenAddress, tokenSubID]`
/// (each 32 bytes), reduced mod the SNARK prime.
fn get_token_data_hash_nft(token_data: &TokenData) -> String {
    let token_type_bytes = n_to_bytes(
        &BigUint::from(token_data.token_type as u8),
        ByteLength::Uint256,
    );
    let address_padded = format_to_byte_length(
        &BytesData::Hex(token_data.token_address.clone()),
        ByteLength::Uint256,
        false,
    );
    let address_bytes = hex_string_to_bytes(&address_padded).unwrap_or_default();
    let sub_id_bytes = n_to_bytes(
        &hex_to_bigint(&token_data.token_sub_id),
        ByteLength::Uint256,
    );

    let combined = combine(&[
        hex::encode(token_type_bytes),
        hex::encode(address_bytes),
        hex::encode(sub_id_bytes),
    ]);
    let combined_bytes = hex_string_to_bytes(&combined).unwrap_or_default();
    let hashed = keccak256_bytes(&combined_bytes);
    let modulo = BigUint::from_bytes_be(&hashed) % snark_prime();
    n_to_hex(&modulo, ByteLength::Uint256, false)
}

/// `getTokenDataHash`.
pub fn get_token_data_hash(token_data: &TokenData) -> String {
    match token_data.token_type {
        TokenType::Erc20 => get_token_data_hash_erc20(&token_data.token_address),
        TokenType::Erc721 | TokenType::Erc1155 => get_token_data_hash_nft(token_data),
    }
}

/// `getNoteHash`.
pub fn get_note_hash(address: &str, token_data: &TokenData, value: &BigUint) -> BigUint {
    let token_hash = get_token_data_hash(token_data);
    poseidon(&[
        hex_to_bigint(address),
        hex_to_bigint(&token_hash),
        value.clone(),
    ])
}

/// `formatValue` — value as fixed UINT_128 hex.
pub fn format_value(value: &BigUint, prefix: bool) -> String {
    n_to_hex(value, ByteLength::Uint128, prefix)
}

/// `serializePreImage` — returns `(npk, token, value)`.
pub fn serialize_pre_image(
    address: &str,
    token_data: &TokenData,
    value: &BigUint,
    prefix: bool,
) -> (String, TokenData, String) {
    let npk = format_to_byte_length(
        &BytesData::Hex(address.to_string()),
        ByteLength::Uint256,
        prefix,
    );
    (npk, token_data.clone(), format_value(value, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    // note-util.test.ts "Should get token data hash for various token types".
    #[test]
    fn token_data_hash_vectors() {
        let erc20 = TokenData {
            token_address: "0x1234567890123456789012345678901234567890".into(),
            token_sub_id: BigUint::from(1u8).to_str_radix(10),
            token_type: TokenType::Erc20,
        };
        assert_eq!(
            get_token_data_hash(&erc20),
            format_to_byte_length(
                &BytesData::Hex(erc20.token_address.clone()),
                ByteLength::Uint256,
                false
            )
        );

        let erc721 = TokenData {
            token_type: TokenType::Erc721,
            ..erc20.clone()
        };
        assert_eq!(
            get_token_data_hash(&erc721),
            "075b737079de804169d5e006add4da4942063ab4fce32268c469c49460e52be0"
        );

        let erc1155 = TokenData {
            token_type: TokenType::Erc1155,
            ..erc20.clone()
        };
        assert_eq!(
            get_token_data_hash(&erc1155),
            "2d0c48e5b759b13bea21d65719c47747f857f47be541ddb0df54fa0a040a7bed"
        );
    }
}
