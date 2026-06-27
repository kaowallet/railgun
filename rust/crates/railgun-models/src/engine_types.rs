//! Port of `src/models/engine-types.ts`.
//!
//! This is the **canonical home** of [`Chain`] / [`ChainType`] / [`KeyNode`] for
//! the whole workspace. `railgun-key-derivation` re-exports these instead of
//! keeping its own copy.

use serde::{Deserialize, Serialize};

/// `KeyNode` — a BIP32-style node (hex-encoded key + chain code).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyNode {
    #[serde(rename = "chainKey")]
    pub chain_key: String,
    #[serde(rename = "chainCode")]
    pub chain_code: String,
}

/// `ChainType` — keep integer value identical to the TS enum (`EVM = 0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(into = "u8", try_from = "u8")]
pub enum ChainType {
    Evm = 0,
}

impl From<ChainType> for u8 {
    fn from(c: ChainType) -> u8 {
        c as u8
    }
}

impl TryFrom<u8> for ChainType {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(ChainType::Evm),
            other => Err(format!("Invalid ChainType: {other}")),
        }
    }
}

/// `Chain { type, id }`.
///
/// The TS shape is `{ type: ChainType, id: number }`. We store `chain_type` as a
/// raw `u8` (not the `ChainType` enum) to mirror the existing key-derivation
/// usage, where chains with arbitrary type bytes are round-tripped through
/// addresses. `id` is a `u64` to cover all EVM chain ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Chain {
    #[serde(rename = "type")]
    pub chain_type: u8,
    pub id: u64,
}

/// `getChainFullNetworkID` — 1-byte type + 7-byte id, hex (16 chars).
///
/// Port of `src/chain/chain.ts`. Lives here so the canonical `Chain` carries its
/// own encoding; `railgun-key-derivation` re-exports it.
pub fn get_chain_full_network_id(chain: &Chain) -> String {
    use railgun_utils::{format_to_byte_length, ByteLength, BytesData};
    let formatted_type = format_to_byte_length(
        &BytesData::Num(chain.chain_type as u64),
        ByteLength::Uint8,
        false,
    );
    let formatted_id = format_to_byte_length(&BytesData::Num(chain.id), ByteLength::Uint56, false);
    format!("{formatted_type}{formatted_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_type_int_value() {
        assert_eq!(ChainType::Evm as u8, 0);
    }

    #[test]
    fn chain_serde_roundtrip() {
        let chain = Chain {
            chain_type: 0,
            id: 1,
        };
        let json = serde_json::to_string(&chain).unwrap();
        assert_eq!(json, r#"{"type":0,"id":1}"#);
        let back: Chain = serde_json::from_str(&json).unwrap();
        assert_eq!(back, chain);
    }

    #[test]
    fn full_network_id() {
        // 1-byte type (00) + 7-byte id (00..01 = 0e hex chars) => 16 hex chars.
        let chain = Chain {
            chain_type: 0,
            id: 1,
        };
        assert_eq!(get_chain_full_network_id(&chain), "0000000000000001");
        let chain56 = Chain {
            chain_type: 0,
            id: 56,
        };
        assert_eq!(get_chain_full_network_id(&chain56), "0000000000000038");
    }
}
