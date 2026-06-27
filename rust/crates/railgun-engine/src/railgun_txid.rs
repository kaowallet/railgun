//! Port of the railgun-txid helpers from `src/transaction/railgun-txid.ts`.
//!
//! The `railgun-transaction` crate has not yet ported these (its module is still
//! a stub), so the pure Poseidon helpers the engine validation path needs are
//! reproduced here. They are byte-exact with the TS:
//! `getRailgunTransactionID`, `getRailgunTransactionIDHex`,
//! `getRailgunTxidLeafHash`, `calculateRailgunTransactionVerificationHash`.

use num_bigint::BigUint;
use railgun_crypto::{keccak256, poseidon};
use railgun_utils::{
    combine, format_to_byte_length, hex_string_to_bytes, hex_to_bigint, n_to_hex, ByteLength,
    BytesData,
};

/// `MERKLE_ZERO_VALUE_BIGINT` — keccak256("Railgun") mod p.
/// Mirrors `src/models/merkletree-types.ts`. Used as the padding zero value.
fn merkle_zero_value_bigint() -> BigUint {
    // keccak256("Railgun") % SNARK_PRIME
    // The TS computes this from the string "Railgun"; we reproduce it here.
    let snark_prime = BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("valid prime");
    let hashed = keccak256(b"Railgun");
    hex_to_bigint(&hashed) % snark_prime
}

fn pad_with_zeros_to_max(mut array: Vec<BigUint>, max: usize) -> Vec<BigUint> {
    let zero = merkle_zero_value_bigint();
    while array.len() < max {
        array.push(zero.clone());
    }
    array
}

/// `getRailgunTransactionIDFromBigInts`.
pub fn get_railgun_transaction_id_from_bigints(
    nullifiers: &[BigUint],
    commitments: &[BigUint],
    bound_params_hash: &BigUint,
) -> BigUint {
    let max_inputs = 13usize; // Always 13 — no matter the POI circuit.
    let nullifiers_padded = pad_with_zeros_to_max(nullifiers.to_vec(), max_inputs);
    let nullifiers_hash = poseidon(&nullifiers_padded);

    let max_outputs = 13usize;
    let commitments_padded = pad_with_zeros_to_max(commitments.to_vec(), max_outputs);
    let commitments_hash = poseidon(&commitments_padded);

    poseidon(&[nullifiers_hash, commitments_hash, bound_params_hash.clone()])
}

/// `getRailgunTransactionID`.
pub fn get_railgun_transaction_id(
    nullifiers: &[String],
    commitments: &[String],
    bound_params_hash: &str,
) -> BigUint {
    let nullifier_bigints: Vec<BigUint> = nullifiers.iter().map(|el| hex_to_bigint(el)).collect();
    let commitment_bigints: Vec<BigUint> = commitments.iter().map(|el| hex_to_bigint(el)).collect();
    let bound_params_hash_bigint = hex_to_bigint(bound_params_hash);
    get_railgun_transaction_id_from_bigints(
        &nullifier_bigints,
        &commitment_bigints,
        &bound_params_hash_bigint,
    )
}

/// `getRailgunTransactionIDHex`.
pub fn get_railgun_transaction_id_hex(
    nullifiers: &[String],
    commitments: &[String],
    bound_params_hash: &str,
) -> String {
    let railgun_txid = get_railgun_transaction_id(nullifiers, commitments, bound_params_hash);
    n_to_hex(&railgun_txid, ByteLength::Uint256, false)
}

/// `getRailgunTxidLeafHash`.
pub fn get_railgun_txid_leaf_hash(
    railgun_txid_bigint: &BigUint,
    utxo_tree_in: &BigUint,
    global_tree_position: &BigUint,
) -> String {
    n_to_hex(
        &poseidon(&[
            railgun_txid_bigint.clone(),
            utxo_tree_in.clone(),
            global_tree_position.clone(),
        ]),
        ByteLength::Uint256,
        false,
    )
}

/// `calculateRailgunTransactionVerificationHash` —
/// `hash[n] = keccak(hash[n-1] ?? 0, n_firstNullifier)`.
pub fn calculate_railgun_transaction_verification_hash(
    previous_verification_hash: Option<&str>,
    first_nullifier: &str,
) -> String {
    let prev = previous_verification_hash.unwrap_or("0x");
    let prev_bytes = hex_string_to_bytes(prev).unwrap_or_default();
    let first_bytes = hex_string_to_bytes(first_nullifier).unwrap_or_default();
    let combined = combine(&[hex::encode(prev_bytes), hex::encode(first_bytes)]);
    let combined_bytes = hex_string_to_bytes(&combined).unwrap_or_default();
    let hashed = keccak256(&combined_bytes);
    format_to_byte_length(&BytesData::Hex(hashed), ByteLength::Uint256, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    // KAV from merkletree/__tests__/txid-merkletree.test.ts:203 — an explicit
    // getRailgunTransactionID oracle. Exercises the real 13-input padded Poseidon
    // path (railgun-crypto's poseidon_wide): 2 nullifiers + 2 commitments each
    // padded to 13 inputs.
    #[test]
    fn railgun_txid_kav_v2() {
        let nullifiers = vec!["0x03".to_string(), "0x04".to_string()];
        let commitments = vec!["0x01".to_string(), "0x02".to_string()];
        let bound_params_hash = "0x05";
        let txid = get_railgun_transaction_id_hex(&nullifiers, &commitments, bound_params_hash);
        assert_eq!(
            txid,
            "1f9639a75d9aa09f959fb0f347da9a3afcbb09851c5cb398100d1721b5ed4be6"
        );
    }
}
