//! Port of `src/solutions/simple-solutions.ts`.

use num_bigint::BigUint;
use railgun_models::wallet_types::TreeBalance;
use railgun_note::TransactNote;

use crate::nullifiers::is_valid_nullifier_count;
use crate::utxos::{calculate_total_spend, filter_zero_utxos, sort_utxos_by_ascending_value, Txo};

fn should_add_more_utxos(utxos: &[Txo], total_required: &BigUint) -> bool {
    &calculate_total_spend(utxos) < total_required
}

/// `findExactSolutionsOverTargetValue`.
///
/// Returns:
/// - `Some(vec![])` when this tree doesn't have enough to cover the transaction
///   (the TS returns `[]`).
/// - `Some(utxos)` when a valid solution is found.
/// - `None` when this tree cannot satisfy with a valid nullifier count
///   (the TS returns `undefined`), signalling fallback to the next tree.
pub fn find_exact_solutions_over_target_value(
    tree_balance: &TreeBalance<TransactNote>,
    total_required: &BigUint,
) -> Option<Vec<Txo>> {
    // If this tree doesn't have enough to cover this transaction, return empty.
    if &tree_balance.balance < total_required {
        return Some(vec![]);
    }

    // Remove utxos with 0 value.
    let filtered_utxos: Vec<Txo> = filter_zero_utxos(&tree_balance.utxos);

    // Use exact match if it exists.
    if let Some(exact_match) = filtered_utxos
        .iter()
        .find(|utxo| utxo.note.value == *total_required)
    {
        return Some(vec![exact_match.clone()]);
    }

    // Sort UTXOs by smallest size.
    let mut filtered_utxos = filtered_utxos;
    sort_utxos_by_ascending_value(&mut filtered_utxos);

    // Accumulate UTXOs until we hit the target value.
    let mut utxos: Vec<Txo> = Vec::new();
    while filtered_utxos.len() > utxos.len() && should_add_more_utxos(&utxos, total_required) {
        utxos.push(filtered_utxos[utxos.len()].clone());
    }

    if *total_required > calculate_total_spend(&utxos) {
        // Fallback to next tree, or complex transaction batch.
        return None;
    }

    if !is_valid_nullifier_count(utxos.len()) {
        // Fallback to next tree, or complex transaction batch.
        return None;
    }

    Some(utxos)
}
