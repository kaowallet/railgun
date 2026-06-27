//! Port of `src/solutions/` — pure in-memory coin selection / spending groups.
//!
//! Mirrors the TS modules: `nullifiers`, `utxos`, `simple-solutions`,
//! `complex-solutions`, `spending-group-extractor`. All logic is synchronous and
//! network-free.

pub mod complex_solutions;
pub mod nullifiers;
pub mod simple_solutions;
pub mod spending_group_extractor;
pub mod utxos;

pub use complex_solutions::{
    create_spending_solutions_for_value, find_next_solution_batch, next_nullifier_target,
    should_add_more_utxos_for_solution_batch, SolutionsError, ZERO_32_BYTE_VALUE,
};
pub use nullifiers::{
    is_valid_nullifier_count, MAX_INPUTS, VALID_INPUT_COUNTS, VALID_OUTPUT_COUNTS,
};
pub use simple_solutions::find_exact_solutions_over_target_value;
pub use spending_group_extractor::{
    extract_spending_solution_groups_data, serialize_extracted_spending_solution_groups_data,
    ExtractedSpendingSolutionGroupsData, SerializedSpendingSolutionGroupsData,
};
pub use utxos::{calculate_total_spend, filter_zero_utxos, sort_utxos_by_ascending_value, Txo};
