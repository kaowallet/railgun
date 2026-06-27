//! Minimal `Chain` model + network-ID encoding (port of the parts of
//! `src/models/engine-types.ts` and `src/chain/chain.ts` needed for addresses).
//!
//! NOTE: `Chain`/`ChainType` will move to the `railgun-models` crate in Phase 1;
//! they live here for now so Phase 0 is self-contained.

use railgun_utils::{format_to_byte_length, ByteLength, BytesData};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chain {
    pub chain_type: u8,
    pub id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChainType {
    Evm = 0,
}

/// `getChainFullNetworkID` — 1-byte type + 7-byte id, hex (16 chars).
pub fn get_chain_full_network_id(chain: &Chain) -> String {
    let formatted_type =
        format_to_byte_length(&BytesData::Num(chain.chain_type as u64), ByteLength::Uint8, false);
    let formatted_id =
        format_to_byte_length(&BytesData::Num(chain.id), ByteLength::Uint56, false);
    format!("{formatted_type}{formatted_id}")
}
