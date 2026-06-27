//! `railgun-models` — the pure data-type/enum layer shared by every higher
//! RAILGUN crate (port of `src/models/`, excluding `typechain-types.ts` which is
//! ethers ABI glue owned by `railgun-contracts`).
//!
//! Enum integer values, field-element encodings and serde key names mirror the
//! TypeScript exactly so DB schemas and hash pre-images stay byte-compatible.
//!
//! [`Chain`] / [`ChainType`] / [`KeyNode`] are defined here (canonical home);
//! `railgun-key-derivation` re-exports them.

pub mod engine_types;
pub mod event_types;
pub mod formatted_types;
pub mod merkletree_types;
pub mod poi_types;
pub mod prover_types;
pub mod transaction_constants;
pub mod transaction_types;
pub mod txo_types;
pub mod wallet_types;

// Re-export the canonical Chain model + the most-used types at the crate root.
pub use engine_types::{get_chain_full_network_id, Chain, ChainType, KeyNode};
pub use formatted_types::{
    Ciphertext, CiphertextCtr, Commitment, CommitmentType, OutputType, TokenData, TokenType,
};
pub use poi_types::{TXIDVersion, TXOPOIListStatus};

/// serde helper: (de)serialize a [`num_bigint::BigUint`] as a decimal string,
/// matching how the TS SDK stringifies `bigint` values in JSON.
pub(crate) mod serde_biguint {
    use num_bigint::BigUint;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(n: &BigUint, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&n.to_str_radix(10))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<BigUint, D::Error> {
        let s = String::deserialize(d)?;
        BigUint::parse_bytes(s.as_bytes(), 10)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid BigUint: {s}")))
    }
}
