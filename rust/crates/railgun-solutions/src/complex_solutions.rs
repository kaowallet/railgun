//! Port of `src/solutions/complex-solutions.ts`.

use num_bigint::BigUint;
use num_traits::Zero;
use railgun_models::formatted_types::CommitmentType;
use railgun_models::txo_types::{SpendingSolutionGroup, TXO};
use railgun_models::wallet_types::TreeBalance;
use railgun_note::{TransactNote, TransactNoteError};
use railgun_utils::{format_to_byte_length, ByteLength, BytesData};

use crate::nullifiers::{is_valid_nullifier_count, VALID_INPUT_COUNTS};
use crate::utxos::{calculate_total_spend, filter_zero_utxos, sort_utxos_by_ascending_value, Txo};

/// `ZERO_32_BYTE_VALUE` — 64-hex zero string (no `0x` prefix), matching
/// `src/utils/constants.ts`.
pub const ZERO_32_BYTE_VALUE: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error)]
pub enum SolutionsError {
    #[error("Balance too low: requires additional UTXOs to satisfy spending solution.")]
    BalanceTooLow,
    #[error(transparent)]
    Note(#[from] TransactNoteError),
}

fn min_bigint(a: BigUint, b: &BigUint) -> BigUint {
    if &a < b {
        a
    } else {
        b.clone()
    }
}

fn create_spending_solution_group(
    output: &TransactNote,
    tree: u32,
    solution_value: BigUint,
    utxos: Vec<Txo>,
    is_unshield: bool,
) -> Result<SpendingSolutionGroup<TransactNote>, SolutionsError> {
    if is_unshield {
        return Ok(SpendingSolutionGroup {
            spending_tree: tree,
            utxos,
            token_outputs: vec![],
            unshield_value: solution_value,
            token_data: output.token_data.clone(),
        });
    }

    let solution_output = output.new_processing_note_with_value(solution_value)?;
    Ok(SpendingSolutionGroup {
        spending_tree: tree,
        utxos,
        token_outputs: vec![solution_output],
        unshield_value: BigUint::zero(),
        token_data: output.token_data.clone(),
    })
}

/// UTXO with value 0n. All other fields are placeholders.
/// The circuit will ignore fields if value is 0.
fn create_null_utxo(null_note: TransactNote) -> Txo {
    let null_txid =
        format_to_byte_length(&BytesData::Hex("0x00".into()), ByteLength::Uint256, true);
    TXO {
        tree: 0,
        position: 100000, // out of bounds position - so we don't have collisions on nullifiers
        block_number: 100,
        timestamp: None,
        spendtxid: railgun_models::formatted_types::SpendTxid::Unspent(false),
        note: null_note,
        txid: null_txid,
        pois_per_list: None,
        blinded_commitment: None,
        transact_creation_railgun_txid: None,
        commitment_type: CommitmentType::TransactCommitmentV3,
        nullifier: ZERO_32_BYTE_VALUE.to_string(),
    }
}

fn get_utxoid_position(utxo: &Txo) -> String {
    format!("{}-{}", utxo.txid, utxo.position)
}

fn replace_or_remove_remaining_output(
    remaining_outputs: &mut Vec<TransactNote>,
    amount_to_fill: &BigUint,
) -> Result<(), SolutionsError> {
    // Remove the "used" output note.
    let deleted_output = remaining_outputs.remove(0);

    // Insert another remaining output note for any Amount Left.
    if amount_to_fill > &BigUint::zero() {
        remaining_outputs.insert(
            0,
            deleted_output.new_processing_note_with_value(amount_to_fill.clone())?,
        );
    }
    Ok(())
}

/// `createSpendingSolutionsForValue`.
///
/// Mutates `remaining_outputs` in place (matching the TS, which splices the
/// array) and returns the spending solution groups.
pub fn create_spending_solutions_for_value(
    tree_sorted_balances: &[TreeBalance<TransactNote>],
    remaining_outputs: &mut Vec<TransactNote>,
    excluded_utxoid_positions: &mut Vec<String>,
    is_unshield: bool,
) -> Result<Vec<SpendingSolutionGroup<TransactNote>>, SolutionsError> {
    // Primary output to find UTXOs for.
    let primary_output = remaining_outputs[0].clone();

    // Secondary output is used as the backup note for any change.
    let secondary_output: Option<TransactNote> = if remaining_outputs.len() > 1 {
        Some(remaining_outputs[1].clone())
    } else {
        None
    };

    let value = primary_output.value.clone();

    if value.is_zero() {
        replace_or_remove_remaining_output(remaining_outputs, &BigUint::zero())?;

        // Create a 0-value spending solution group.
        let null_note = primary_output.new_processing_note_with_value(BigUint::zero())?;
        let null_utxo = create_null_utxo(null_note.clone());
        let utxos = vec![null_utxo.clone()];
        let null_spending_solution_group = create_spending_solution_group(
            &null_note,
            null_utxo.tree,
            null_note.value.clone(),
            utxos,
            is_unshield,
        )?;
        return Ok(vec![null_spending_solution_group]);
    }

    let mut amount_to_fill = value;
    let mut spending_solution_groups: Vec<SpendingSolutionGroup<TransactNote>> = Vec::new();

    for (tree, tree_balance) in tree_sorted_balances.iter().enumerate() {
        let tree = tree as u32;
        while amount_to_fill > BigUint::zero() {
            let utxos = match find_next_solution_batch(
                tree_balance,
                &amount_to_fill,
                excluded_utxoid_positions,
            ) {
                Some(utxos) => utxos,
                None => break, // No more solutions in this tree.
            };

            // Don't allow these UTXOs to be used twice.
            excluded_utxoid_positions.extend(utxos.iter().map(get_utxoid_position));

            // Decrement amount left by total spend in UTXOs.
            let total_spend = calculate_total_spend(&utxos);

            // Solution Value is the smaller of Solution spend value, or required output value.
            let solution_value = min_bigint(total_spend.clone(), &amount_to_fill);

            // Generate spending solution group, which will be used to create a Transaction.
            let spending_solution_group = create_spending_solution_group(
                &primary_output,
                tree,
                solution_value,
                utxos,
                is_unshield,
            )?;
            spending_solution_groups.push(spending_solution_group);

            // amount_to_fill -= total_spend (can go negative => track as signed).
            let underflow = total_spend > amount_to_fill;
            let change = if underflow {
                &total_spend - &amount_to_fill
            } else {
                BigUint::zero()
            };
            let new_amount_to_fill = if underflow {
                BigUint::zero()
            } else {
                &amount_to_fill - &total_spend
            };
            amount_to_fill = new_amount_to_fill;

            replace_or_remove_remaining_output(remaining_outputs, &amount_to_fill)?;

            if amount_to_fill.is_zero() {
                // Use any remaining change to fill the secondary output.
                if change > BigUint::zero() && !is_unshield {
                    if let Some(ref secondary_output) = secondary_output {
                        let secondary_note_value: BigUint;
                        let final_amount_to_fill: BigUint;
                        if secondary_output.value < change {
                            secondary_note_value = secondary_output.value.clone();
                            final_amount_to_fill = BigUint::zero();
                        } else {
                            secondary_note_value = change.clone();
                            final_amount_to_fill = &secondary_output.value - &change;
                        }
                        let secondary_note = secondary_output
                            .new_processing_note_with_value(secondary_note_value)?;

                        let final_group = spending_solution_groups
                            .last_mut()
                            .expect("at least one spending solution group");
                        final_group.token_outputs.push(secondary_note);

                        // NOTE: Primary output is already removed from remaining_outputs.
                        replace_or_remove_remaining_output(
                            remaining_outputs,
                            &final_amount_to_fill,
                        )?;
                    }
                }
            }
        }
    }

    if amount_to_fill > BigUint::zero() {
        // Could not find enough solutions.
        return Err(SolutionsError::BalanceTooLow);
    }

    Ok(spending_solution_groups)
}

/// Finds next valid nullifier count above the current nullifier count.
pub fn next_nullifier_target(utxo_count: usize) -> Option<usize> {
    VALID_INPUT_COUNTS.iter().copied().find(|&n| n > utxo_count)
}

pub fn should_add_more_utxos_for_solution_batch(
    current_nullifier_count: usize,
    total_nullifier_count: usize,
    current_spend: &BigUint,
    total_required: &BigUint,
) -> bool {
    if current_spend >= total_required {
        // We've hit the target required.
        return false;
    }

    let nullifier_target = match next_nullifier_target(current_nullifier_count) {
        Some(t) => t,
        None => return false, // No next nullifier target.
    };

    if nullifier_target > total_nullifier_count {
        // Next target is not reachable. Don't add any more UTXOs.
        return false;
    }

    // Total spend < total required, and next nullifier target is reachable.
    true
}

/// `findNextSolutionBatch`.
///
/// 1. Filter out UTXOs with value 0.
/// 2. Use exact match UTXO for `total_required` value if it exists.
/// 3. Sort by smallest UTXO ascending.
/// 4. Add UTXOs to the batch until we hit `total_required`, or exceed the max.
pub fn find_next_solution_batch(
    tree_balance: &TreeBalance<TransactNote>,
    total_required: &BigUint,
    excluded_utxoid_positions: &[String],
) -> Option<Vec<Txo>> {
    let removed_zero_utxos = filter_zero_utxos(&tree_balance.utxos);
    let filtered_utxos: Vec<Txo> = removed_zero_utxos
        .into_iter()
        .filter(|utxo| !excluded_utxoid_positions.contains(&get_utxoid_position(utxo)))
        .collect();
    if filtered_utxos.is_empty() {
        // No more solutions in this tree.
        return None;
    }

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
    while should_add_more_utxos_for_solution_batch(
        utxos.len(),
        filtered_utxos.len(),
        &calculate_total_spend(&utxos),
        total_required,
    ) {
        utxos.push(filtered_utxos[utxos.len()].clone());
    }

    if !is_valid_nullifier_count(utxos.len()) {
        return None;
    }

    Some(utxos)
}
