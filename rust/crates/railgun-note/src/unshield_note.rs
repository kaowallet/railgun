//! Port of `src/note/unshield-note.ts` and the erc20/nft unshield wrappers.

use num_bigint::BigUint;
use railgun_models::formatted_types::NFTTokenData;
use railgun_models::TokenData;
use railgun_utils::{n_to_hex, ByteLength};

use crate::note_util::{
    assert_valid_note_token, erc721_note_value, get_note_hash, get_token_data_erc20,
    serialize_pre_image, NoteUtilError,
};

pub const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// `UnshieldNote` (abstract base).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnshieldNote {
    pub to_address: String,
    pub value: BigUint,
    pub token_data: TokenData,
    pub hash: BigUint,
    pub allow_override: bool,
}

impl UnshieldNote {
    pub fn new(
        to_address: String,
        value: BigUint,
        token_data: TokenData,
        allow_override: bool,
    ) -> Result<Self, NoteUtilError> {
        assert_valid_note_token(&token_data, &value)?;
        let hash = get_note_hash(&to_address, &token_data, &value);
        Ok(UnshieldNote {
            to_address,
            value,
            token_data,
            hash,
            allow_override,
        })
    }

    /// `UnshieldNoteERC20`.
    pub fn erc20(
        to_address: String,
        value: BigUint,
        token_address: &str,
        allow_override: bool,
    ) -> Result<Self, NoteUtilError> {
        let token_data = get_token_data_erc20(token_address);
        Self::new(to_address, value, token_data, allow_override)
    }

    /// `UnshieldNoteERC20.empty()`.
    pub fn erc20_empty() -> Self {
        Self::erc20(
            ZERO_ADDRESS.to_string(),
            BigUint::from(0u8),
            ZERO_ADDRESS,
            false,
        )
        .expect("zero-value ERC20 unshield is valid")
    }

    /// `UnshieldNoteNFT`.
    pub fn nft(
        to_address: String,
        token_data: NFTTokenData,
        allow_override: bool,
    ) -> Result<Self, NoteUtilError> {
        Self::new(to_address, erc721_note_value(), token_data, allow_override)
    }

    /// `npk` getter — for unshields the npk *is* the destination address.
    pub fn npk(&self) -> &str {
        &self.to_address
    }

    /// `notePublicKey` getter.
    pub fn note_public_key(&self) -> BigUint {
        railgun_utils::hex_to_bigint(&self.to_address)
    }

    /// `hashHex` getter.
    pub fn hash_hex(&self) -> String {
        n_to_hex(&self.hash, ByteLength::Uint256, false)
    }

    /// `serialize` — `(npk, token, value)`.
    pub fn serialize(&self, prefix: bool) -> (String, TokenData, String) {
        serialize_pre_image(&self.to_address, &self.token_data, &self.value, prefix)
    }

    /// `getAmountFeeFromValue` — `(amount, fee)`.
    pub fn get_amount_fee_from_value(
        value: &BigUint,
        fee_basis_points: &BigUint,
    ) -> (BigUint, BigUint) {
        let basis_points = BigUint::from(10000u32);
        let fee = (value * fee_basis_points) / basis_points;
        let amount = value - &fee;
        (amount, fee)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // unshield-note.test.ts "Should get unshield fee and amount from value".
    #[test]
    fn amount_fee_from_value() {
        let bp = BigUint::from(25u8);
        let cases: [(u64, u64, u64); 5] = [
            (10000, 9975, 25),
            (10001, 9976, 25),
            (100, 100, 0),
            (399, 399, 0),
            (400, 399, 1),
        ];
        for (value, amount, fee) in cases {
            let (a, f) = UnshieldNote::get_amount_fee_from_value(&BigUint::from(value), &bp);
            assert_eq!(a, BigUint::from(amount), "amount for {value}");
            assert_eq!(f, BigUint::from(fee), "fee for {value}");
        }
    }
}
