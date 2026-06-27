//! Port of `src/solutions/utxos.ts`.

use num_bigint::BigUint;
use num_traits::Zero;
use railgun_models::txo_types::TXO;
use railgun_note::TransactNote;

/// Type alias: a UTXO whose note is a [`TransactNote`].
pub type Txo = TXO<TransactNote>;

pub fn calculate_total_spend(utxos: &[Txo]) -> BigUint {
    utxos
        .iter()
        .fold(BigUint::zero(), |acc, utxo| acc + &utxo.note.value)
}

pub fn filter_zero_utxos(utxos: &[Txo]) -> Vec<Txo> {
    utxos
        .iter()
        .filter(|utxo| !utxo.note.value.is_zero())
        .cloned()
        .collect()
}

/// Stable sort by ascending note value (matches JS `Array.prototype.sort` which
/// is stable in V8 for the comparator used here).
pub fn sort_utxos_by_ascending_value(utxos: &mut [Txo]) {
    utxos.sort_by(|left, right| left.note.value.cmp(&right.note.value));
}
