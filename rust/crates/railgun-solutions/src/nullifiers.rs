//! Port of `src/solutions/nullifiers.ts`.
//!
//! CIRCUITS (V2)
//!
//! Valid, currently used:
//! All circuits with 1 - 10 inputs and 1 - 5 outputs, less the 10x5 circuit.
//!
//! Valid, but currently unused: 11x1, 12x1, 13x1, 1x10, 1x13.

pub const VALID_INPUT_COUNTS: [usize; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
pub const VALID_OUTPUT_COUNTS: [usize; 5] = [1, 2, 3, 4, 5];

/// `MAX_INPUTS` — max of [`VALID_INPUT_COUNTS`].
pub const MAX_INPUTS: usize = 10;

pub fn is_valid_nullifier_count(utxo_count: usize) -> bool {
    VALID_INPUT_COUNTS.contains(&utxo_count)
}
