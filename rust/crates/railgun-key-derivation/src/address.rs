//! Port of `src/key-derivation/bech32.ts` — `0zk` address encode/decode.

use bech32::primitives::decode::{CheckedHrpstring, CheckedHrpstringError};
use bech32::{Bech32m, Hrp};
use num_bigint::BigUint;
use railgun_utils::{
    format_to_byte_length, hex_string_to_bytes, hex_to_bigint, n_to_hex, ByteLength, BytesData,
};

use crate::chain::{get_chain_full_network_id, Chain};

pub const ADDRESS_LENGTH_LIMIT: usize = 127;
pub const ALL_CHAINS_NETWORK_ID: &str = "ffffffffffffffff";
const PREFIX: &str = "0zk";
const ADDRESS_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressData {
    pub master_public_key: BigUint,
    pub viewing_public_key: Vec<u8>,
    pub chain: Option<Chain>,
    pub version: Option<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("No address to decode")]
    Empty,
    #[error("Invalid address prefix")]
    InvalidPrefix,
    #[error("Invalid checksum")]
    InvalidChecksum,
    #[error("Incorrect address version")]
    IncorrectVersion,
    #[error("Failed to decode bech32 address")]
    Decode,
}

/// XOR the 8-byte network ID with "railgun" (positional, missing bytes => 0).
fn xor_network_id(chain_id_hex: &str) -> String {
    let chain_bytes = hex::decode(chain_id_hex).unwrap_or_default();
    let railgun = b"railgun";
    let len = chain_bytes.len().max(railgun.len());
    let mut out = vec![0u8; len];
    for (i, slot) in out.iter_mut().enumerate() {
        let a = chain_bytes.get(i).copied().unwrap_or(0);
        let b = railgun.get(i).copied().unwrap_or(0);
        *slot = a ^ b;
    }
    hex::encode(out)
}

fn chain_to_network_id(chain: Option<Chain>) -> String {
    match chain {
        None => ALL_CHAINS_NETWORK_ID.to_string(),
        Some(c) => get_chain_full_network_id(&c),
    }
}

fn network_id_to_chain(network_id: &str) -> Option<Chain> {
    if network_id == ALL_CHAINS_NETWORK_ID {
        return None;
    }
    Some(Chain {
        chain_type: u8::from_str_radix(&network_id[0..2], 16).unwrap_or(0),
        id: u64::from_str_radix(&network_id[2..16], 16).unwrap_or(0),
    })
}

/// `encodeAddress`.
pub fn encode_address(address_data: &AddressData) -> String {
    let master_public_key = n_to_hex(&address_data.master_public_key, ByteLength::Uint256, false);
    let viewing_public_key = format_to_byte_length(
        &BytesData::Bytes(address_data.viewing_public_key.clone()),
        ByteLength::Uint256,
        false,
    );
    let network_id = xor_network_id(&chain_to_network_id(address_data.chain));
    let version = "01";

    let address_string = format!("{version}{master_public_key}{network_id}{viewing_public_key}");
    let address_buffer = hex::decode(address_string).expect("valid hex payload");

    bech32::encode::<Bech32m>(Hrp::parse(PREFIX).expect("valid hrp"), &address_buffer)
        .expect("bech32m encode")
}

/// `decodeAddress`.
pub fn decode_address(address: &str) -> Result<AddressData, AddressError> {
    if address.is_empty() {
        return Err(AddressError::Decode);
    }
    // Decode strictly as bech32m (like @scure/base). The variant-agnostic
    // `bech32::decode` would accept a plain-bech32 string, masking a checksum
    // failure the TS treats as "Invalid checksum".
    let checked = CheckedHrpstring::new::<Bech32m>(address).map_err(|e| match e {
        CheckedHrpstringError::Checksum(_) => AddressError::InvalidChecksum,
        _ => AddressError::Decode,
    })?;

    if checked.hrp().as_str() != PREFIX {
        return Err(AddressError::Decode);
    }

    let data_bytes: Vec<u8> = checked.byte_iter().collect();
    let data = hex::encode(data_bytes);
    let version = u8::from_str_radix(&data[0..2], 16).map_err(|_| AddressError::Decode)?;
    let master_public_key = hex_to_bigint(&data[2..66]);
    let network_id = xor_network_id(&data[66..82]);
    let viewing_public_key =
        hex_string_to_bytes(&data[82..146]).map_err(|_| AddressError::Decode)?;
    let chain = network_id_to_chain(&network_id);

    if version != ADDRESS_VERSION {
        return Err(AddressError::IncorrectVersion);
    }

    Ok(AddressData {
        master_public_key,
        viewing_public_key,
        chain,
        version: Some(version),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainType;

    // src/key-derivation/__tests__/bech32-encode.test.ts
    fn addr_data(pubkey: &str, chain: Option<Chain>) -> AddressData {
        let mpk = hex_to_bigint(pubkey);
        let vpk_hex = format_to_byte_length(&BytesData::Hex(pubkey.into()), ByteLength::Uint256, false);
        AddressData {
            master_public_key: mpk,
            viewing_public_key: hex_string_to_bytes(&vpk_hex).unwrap(),
            chain,
            version: Some(1),
        }
    }

    #[test]
    fn encode_decode_addresses() {
        let vectors = [
            ("00000000", Some(Chain { chain_type: ChainType::Evm as u8, id: 1 }),
             "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca"),
            ("01bfd5681c0479be9a8ef8dd8baadd97115899a9af30b3d2455843afb41b", Some(Chain { chain_type: ChainType::Evm as u8, id: 56 }),
             "0zk1qyqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkunpd9kxwatw8qqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkcsu8tp"),
            ("01bfd5681c0479be9a8ef8dd8baadd97115899a9af30b3d2455843afb41b", Some(Chain { chain_type: 1, id: 56 }),
             "0zk1qyqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkumpd9kxwatw8qqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkwrfm4m"),
            ("ee6b4c702f8070c8ddea1cbb8b0f6a4a518b77fa8d3f9b68617b664550e75f64", None,
             "0zk1q8hxknrs97q8pjxaagwthzc0df99rzmhl2xnlxmgv9akv32sua0kfrv7j6fe3z53llhxknrs97q8pjxaagwthzc0df99rzmhl2xnlxmgv9akv32sua0kg0zpzts"),
        ];
        for (pubkey, chain, expected) in vectors {
            let data = addr_data(pubkey, chain);
            let encoded = encode_address(&data);
            assert_eq!(encoded, expected);
            assert_eq!(encoded.len(), ADDRESS_LENGTH_LIMIT);
            assert_eq!(decode_address(&encoded).unwrap(), data);
        }
    }

    #[test]
    fn invalid_checksum() {
        let r = decode_address(
            "rgany1pnj7u66vwqhcquxgmh4pewutpa4y55vtwlag60umdpshkej92rn47ey76ges3t3enn",
        );
        assert_eq!(r, Err(AddressError::InvalidChecksum));
    }

    #[test]
    fn invalid_prefix() {
        let r = decode_address(
            "rg1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsfhuuw",
        );
        assert_eq!(r, Err(AddressError::Decode));
    }
}
