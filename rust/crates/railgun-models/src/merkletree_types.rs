//! Port of `src/models/merkletree-types.ts`.

use std::collections::BTreeMap;

use num_bigint::BigUint;
use railgun_crypto::keccak256_bytes;
use railgun_utils::{n_to_hex, ByteLength};
use serde::{Deserialize, Serialize};

pub const TREE_DEPTH: usize = 16;
pub const TREE_MAX_ITEMS: usize = 65_536; // 2^16

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkletreeLeaf {
    pub hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidMerklerootDetails {
    pub position: u32,
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
}

/// `CommitmentProcessingGroupSize` — keep integer values identical to the TS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CommitmentProcessingGroupSize {
    XXXXLarge = 10000,
    XXXLarge = 8000,
    XXLarge = 1600,
    XLarge = 800,
    Large = 200,
    Medium = 40,
    Small = 10,
    Single = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeMetadata {
    #[serde(rename = "scannedHeight")]
    pub scanned_height: u32,
    #[serde(rename = "invalidMerklerootDetails")]
    pub invalid_merkleroot_details: Option<InvalidMerklerootDetails>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkletreesMetadata {
    pub trees: BTreeMap<u32, TreeMetadata>,
}

/// BN254 scalar field modulus == RAILGUN's `SNARK_PRIME`.
fn snark_prime() -> BigUint {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("valid SNARK_PRIME")
}

/// `MERKLE_ZERO_VALUE_BIGINT` = `keccak256('Railgun')` reduced mod `SNARK_PRIME`.
pub fn merkle_zero_value_bigint() -> BigUint {
    // `fromUTF8String('Railgun')` is just the UTF-8 bytes of the string, then
    // keccak256 hashes those bytes.
    let hash = keccak256_bytes(b"Railgun");
    let n = BigUint::from_bytes_be(&hash);
    n % snark_prime()
}

/// `MERKLE_ZERO_VALUE` — the zero value as a 32-byte (uint256) hex string.
pub fn merkle_zero_value() -> String {
    n_to_hex(&merkle_zero_value_bigint(), ByteLength::Uint256, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // KAV from src/models/merkletree-types.ts — keccak256('Railgun') % SNARK_PRIME.
    // Matches the TS engine's stored zero value used across the merkletree.
    const EXPECTED_MERKLE_ZERO_VALUE: &str =
        "0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc";

    #[test]
    fn merkle_zero_value_kav() {
        assert_eq!(merkle_zero_value(), EXPECTED_MERKLE_ZERO_VALUE);
        assert_eq!(merkle_zero_value().len(), 64);
    }

    #[test]
    fn merkle_zero_value_is_reduced() {
        // Must be strictly less than the field prime.
        assert!(merkle_zero_value_bigint() < snark_prime());
    }

    #[test]
    fn tree_depth_constants() {
        assert_eq!(TREE_DEPTH, 16);
        assert_eq!(TREE_MAX_ITEMS, 1 << TREE_DEPTH);
    }
}
