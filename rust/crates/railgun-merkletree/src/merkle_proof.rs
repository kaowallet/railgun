//! Port of `src/merkletree/merkle-proof.ts`.

use num_bigint::BigUint;
use railgun_models::formatted_types::MerkleProof;
use railgun_models::merkletree_types::TREE_DEPTH;
use railgun_utils::{hex_to_bigint, hexlify, n_to_hex, ByteLength, BytesData};

use crate::merkletree::hash_left_right;

/// `createDummyMerkleProof`.
pub fn create_dummy_merkle_proof(leaf: &str) -> MerkleProof {
    let indices = n_to_hex(&BigUint::from(0u8), ByteLength::Uint256, false);

    let elements: Vec<BigUint> = vec![BigUint::from(0u8); TREE_DEPTH];

    let mut latest_hash = hex_to_bigint(leaf);
    for element in &elements {
        // poseidon([latestHash, element]) on bigints.
        let h = hash_left_right(
            &n_to_hex(&latest_hash, ByteLength::Uint256, false),
            &n_to_hex(element, ByteLength::Uint256, false),
        );
        latest_hash = hex_to_bigint(&h);
    }

    MerkleProof {
        leaf: leaf.to_string(),
        indices,
        elements: elements
            .iter()
            .map(|el| n_to_hex(el, ByteLength::Uint256, false))
            .collect(),
        root: n_to_hex(&latest_hash, ByteLength::Uint256, false),
    }
}

/// `verifyMerkleProof`.
pub fn verify_merkle_proof(proof: &MerkleProof) -> bool {
    let indices = hex_to_bigint(&proof.indices);

    let mut current = proof.leaf.clone();
    for (index, element) in proof.elements.iter().enumerate() {
        // If bit `index` of `indices` is set, the element is on the right.
        let bit = (&indices >> index) & BigUint::from(1u8);
        if bit > BigUint::from(0u8) {
            current = hash_left_right(element, &current);
        } else {
            current = hash_left_right(&current, element);
        }
    }

    hexlify(&BytesData::Hex(proof.root.clone()), false) == hexlify(&BytesData::Hex(current), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use railgun_utils::random_hex;

    // src/merkletree/__tests__/merkle-proof.test.ts
    #[test]
    fn create_valid_dummy_merkle_proof() {
        let merkle_proof = create_dummy_merkle_proof(&random_hex(31));
        assert_eq!(merkle_proof.elements.len(), 16);
        assert!(verify_merkle_proof(&merkle_proof));
    }
}
