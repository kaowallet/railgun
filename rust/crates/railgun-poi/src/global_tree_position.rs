//! Port of `src/poi/global-tree-position.ts`.

use num_bigint::BigUint;
use railgun_models::merkletree_types::TREE_MAX_ITEMS;

// For reference (hardcoded sentinel values, mirrored from the TS):
pub const GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE: u64 = 99999;
pub const GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE: u64 = 99999;
pub const GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE: u64 = 199999;
pub const GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE: u64 = 199999;

/// `getGlobalTreePosition(tree, index)` — `tree * TREE_MAX_ITEMS + index`.
pub fn get_global_tree_position(tree: u64, index: u64) -> BigUint {
    BigUint::from(tree * (TREE_MAX_ITEMS as u64) + index)
}

/// `getGlobalTreePositionPreTransactionPOIProof()`.
pub fn get_global_tree_position_pre_transaction_poi_proof() -> BigUint {
    get_global_tree_position(
        GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
        GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // KAV from src/poi/__tests__/global-tree-position.test.ts.
    #[test]
    fn calculates_global_tree_position() {
        assert_eq!(get_global_tree_position(0, 0), BigUint::from(0u64));
        assert_eq!(
            get_global_tree_position(1, 0),
            BigUint::from(TREE_MAX_ITEMS as u64)
        );
        assert_eq!(
            get_global_tree_position(99999, 99999),
            BigUint::from(99999u64 * 65536 + 99999)
        );
    }

    #[test]
    fn pre_transaction_poi_proof_position() {
        assert_eq!(
            get_global_tree_position_pre_transaction_poi_proof(),
            BigUint::from(199999u64 * 65536 + 199999)
        );
    }
}
