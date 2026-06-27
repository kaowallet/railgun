//! Port of `src/transaction/railgun-txid.ts`.
//!
//! RailgunTransactionID + TXID-merkletree leaf hash + verification-hash chain.
//! Pure functions, validated against `railgun-txid.test.ts`.

use num_bigint::BigUint;
use railgun_crypto::{keccak256_bytes, poseidon};
use railgun_models::formatted_types::{RailgunTransaction, RailgunTransactionWithHash};
use railgun_models::merkletree_types::merkle_zero_value_bigint;
use railgun_poi::get_global_tree_position;
use railgun_utils::{
    bytes_to_n, hex_string_to_bytes, hex_to_bigint, n_to_hex, ByteLength, BytesData,
};

/// `padWithZerosToMax` — pad a field-element array up to `max` with
/// `MERKLE_ZERO_VALUE_BIGINT`.
fn pad_with_zeros_to_max(array: &[BigUint], max: usize) -> Vec<BigUint> {
    let zero = merkle_zero_value_bigint();
    let mut padded: Vec<BigUint> = array.to_vec();
    while padded.len() < max {
        padded.push(zero.clone());
    }
    padded
}

/// `getRailgunTransactionIDFromBigInts(nullifiers, commitments, boundParamsHash)`.
///
/// Both nullifier and commitment arrays are padded to a fixed 13 elements
/// (regardless of POI circuit) and hashed; the two 13-input Poseidon hashes are
/// then combined with `boundParamsHash` via a final 3-input Poseidon.
pub fn get_railgun_transaction_id_from_bigints(
    nullifiers: &[BigUint],
    commitments: &[BigUint],
    bound_params_hash: &BigUint,
) -> BigUint {
    const MAX_INPUTS: usize = 13; // Always 13 - no matter the POI circuit.
    const MAX_OUTPUTS: usize = 13;

    let nullifiers_padded = pad_with_zeros_to_max(nullifiers, MAX_INPUTS);
    let nullifiers_hash = poseidon(&nullifiers_padded);

    let commitments_padded = pad_with_zeros_to_max(commitments, MAX_OUTPUTS);
    let commitments_hash = poseidon(&commitments_padded);

    poseidon(&[nullifiers_hash, commitments_hash, bound_params_hash.clone()])
}

/// `getRailgunTransactionID({ nullifiers, commitments, boundParamsHash })` —
/// hex-string inputs.
pub fn get_railgun_transaction_id(
    nullifiers: &[String],
    commitments: &[String],
    bound_params_hash: &str,
) -> BigUint {
    let nullifier_bigints: Vec<BigUint> = nullifiers.iter().map(|s| hex_to_bigint(s)).collect();
    let commitment_bigints: Vec<BigUint> = commitments.iter().map(|s| hex_to_bigint(s)).collect();
    let bound_params_hash_bigint = hex_to_bigint(bound_params_hash);
    get_railgun_transaction_id_from_bigints(
        &nullifier_bigints,
        &commitment_bigints,
        &bound_params_hash_bigint,
    )
}

/// `getRailgunTransactionIDHex(...)`.
pub fn get_railgun_transaction_id_hex(
    nullifiers: &[String],
    commitments: &[String],
    bound_params_hash: &str,
) -> String {
    let railgun_txid = get_railgun_transaction_id(nullifiers, commitments, bound_params_hash);
    n_to_hex(&railgun_txid, ByteLength::Uint256, false)
}

/// `getRailgunTxidLeafHash(railgunTxidBigInt, utxoTreeIn, globalTreePosition)`.
///
/// Leaf hash inserted into the TXID merkletree: a 3-input Poseidon over the
/// railgun txid, the input UTXO tree, and the global tree position.
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

/// Fields needed from a `RailgunTransaction` to compute its TXID + leaf hash,
/// abstracting over the V2/V3 enum variants.
struct TxidFields<'a> {
    nullifiers: &'a [String],
    commitments: &'a [String],
    bound_params_hash: &'a str,
    utxo_tree_in: u32,
    utxo_tree_out: u32,
    utxo_batch_start_position_out: u32,
}

fn txid_fields(tx: &RailgunTransaction) -> TxidFields<'_> {
    match tx {
        RailgunTransaction::V2(t) => TxidFields {
            nullifiers: &t.nullifiers,
            commitments: &t.commitments,
            bound_params_hash: &t.bound_params_hash,
            utxo_tree_in: t.utxo_tree_in,
            utxo_tree_out: t.utxo_tree_out,
            utxo_batch_start_position_out: t.utxo_batch_start_position_out,
        },
        RailgunTransaction::V3(t) => TxidFields {
            nullifiers: &t.nullifiers,
            commitments: &t.commitments,
            bound_params_hash: &t.bound_params_hash,
            utxo_tree_in: t.utxo_tree_in,
            utxo_tree_out: t.utxo_tree_out,
            utxo_batch_start_position_out: t.utxo_batch_start_position_out,
        },
    }
}

/// `createRailgunTransactionWithHash(railgunTransaction)`.
pub fn create_railgun_transaction_with_hash(
    railgun_transaction: RailgunTransaction,
) -> RailgunTransactionWithHash {
    let fields = txid_fields(&railgun_transaction);
    let railgun_txid_bigint = get_railgun_transaction_id(
        fields.nullifiers,
        fields.commitments,
        fields.bound_params_hash,
    );
    let global_tree_position = get_global_tree_position(
        fields.utxo_tree_out as u64,
        fields.utxo_batch_start_position_out as u64,
    );
    let hash = get_railgun_txid_leaf_hash(
        &railgun_txid_bigint,
        &BigUint::from(fields.utxo_tree_in),
        &global_tree_position,
    );
    let railgun_txid = n_to_hex(&railgun_txid_bigint, ByteLength::Uint256, false);

    RailgunTransactionWithHash {
        transaction: railgun_transaction,
        railgun_txid,
        hash,
    }
}

/// `calculateRailgunTransactionVerificationHash(previousVerificationHash, firstNullifier)`.
///
/// `hash[n] = keccak(hash[n-1] ?? 0x, n_firstNullifier)`, 0x-prefixed uint256.
pub fn calculate_railgun_transaction_verification_hash(
    previous_verification_hash: Option<&str>,
    first_nullifier: &str,
) -> String {
    // combine([hexToBytes(prev ?? '0x'), hexToBytes(firstNullifier)]) then keccak256.
    let mut combined: Vec<u8> = Vec::new();
    combined.extend_from_slice(
        &hex_string_to_bytes(previous_verification_hash.unwrap_or("0x")).expect("valid hex"),
    );
    combined.extend_from_slice(&hex_string_to_bytes(first_nullifier).expect("valid hex"));

    let hashed = keccak256_bytes(&combined);
    // formatToByteLength(keccak256(...), UINT_256, true): pad/trim to 32 bytes, 0x.
    let n = bytes_to_n(&hashed);
    railgun_utils::format_to_byte_length(
        &BytesData::Hex(n_to_hex(&n, ByteLength::Uint256, false)),
        ByteLength::Uint256,
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use railgun_models::formatted_types::RailgunTransactionVersion;

    fn big_dec(d: &str) -> BigUint {
        BigUint::parse_bytes(d.as_bytes(), 10).unwrap()
    }

    // railgun-txid.test.ts: 'Should get railgun transaction hash for txid merkletree'
    #[test]
    fn railgun_txid_leaf_hash_kav() {
        let railgun_txid = big_dec(
            "12157249116530410877712851712509084797672039320300907005218073634829938454808",
        );
        let global_tree_position = get_global_tree_position(99999, 99999);
        let result =
            get_railgun_txid_leaf_hash(&railgun_txid, &BigUint::from(0u8), &global_tree_position);
        let expected = n_to_hex(
            &big_dec(
                "20241071195545867095431884887423531306892427422293202401460555613931070025875",
            ),
            ByteLength::Uint256,
            false,
        );
        assert_eq!(result, expected);
    }

    // railgun-txid.test.ts: 'Should calculate verificationHash'
    #[test]
    fn verification_hash_kav() {
        assert_eq!(
            calculate_railgun_transaction_verification_hash(
                None,
                "0x1e52cee52f67c37a468458671cddde6b56390dcbdc4cf3b770badc0e78d66401",
            ),
            "0x099cd3ebcadaf6ff470d16bc0186fb5f26cd4103e9970effc9b6679478e11c72"
        );
        assert_eq!(
            calculate_railgun_transaction_verification_hash(
                Some("0x099cd3ebcadaf6ff470d16bc0186fb5f26cd4103e9970effc9b6679478e11c72"),
                "0x26d7d0d235dc1849e9794061ebc74e9ea211b8b5004081d26c7d086bdd3c0c35",
            ),
            "0x63b79987230ed89bcfbaf94c72c42515f116057e2c2f5d19c5b47d094858e874"
        );
        assert_eq!(
            calculate_railgun_transaction_verification_hash(
                Some("0x7497bd492633825701d6eefc644139d236f46ef961936f0aa69b6751af14497b"),
                "0x000727631f24f543408350df5883261cd5ab89d191c43da1436824ce637328c4",
            ),
            "0x31972b456d6d34a379e8576ed2a51d097f4046438456653914460d5e346f9dd4"
        );
    }

    // Full TXID path (13-input padded Poseidon, via the wide poseidon-ark
    // route) end-to-end. KAV generated from the TS `getRailgunTransactionIDHex`.
    #[test]
    fn railgun_transaction_id_kav() {
        let nullifiers =
            vec!["0x1e52cee52f67c37a468458671cddde6b56390dcbdc4cf3b770badc0e78d66401".to_string()];
        let commitments =
            vec!["0x26d7d0d235dc1849e9794061ebc74e9ea211b8b5004081d26c7d086bdd3c0c35".to_string()];
        let bound_params_hash =
            "0x099cd3ebcadaf6ff470d16bc0186fb5f26cd4103e9970effc9b6679478e11c72";
        let hex = get_railgun_transaction_id_hex(&nullifiers, &commitments, bound_params_hash);
        assert_eq!(
            hex,
            "2f499ee47c6a6688fa687530671bba04302843127ee9a465fd3b723e8c897923"
        );
    }

    // createRailgunTransactionWithHash over a V2 transaction: railgunTxid + leaf
    // hash are computed from the embedded fields.
    #[test]
    fn create_railgun_transaction_with_hash_v2() {
        use railgun_models::formatted_types::RailgunTransactionV2;
        let tx = RailgunTransaction::V2(RailgunTransactionV2 {
            version: RailgunTransactionVersion::V2,
            graph_id: "0x00".to_string(),
            nullifiers: vec![
                "0x1e52cee52f67c37a468458671cddde6b56390dcbdc4cf3b770badc0e78d66401".to_string(),
            ],
            commitments: vec![
                "0x26d7d0d235dc1849e9794061ebc74e9ea211b8b5004081d26c7d086bdd3c0c35".to_string(),
            ],
            bound_params_hash: "0x099cd3ebcadaf6ff470d16bc0186fb5f26cd4103e9970effc9b6679478e11c72"
                .to_string(),
            block_number: 0,
            txid: "0x00".to_string(),
            unshield: None,
            utxo_tree_in: 0,
            utxo_tree_out: 0,
            utxo_batch_start_position_out: 0,
            timestamp: 0,
            verification_hash: "0x00".to_string(),
        });
        let with_hash = create_railgun_transaction_with_hash(tx);
        // KAVs from the TS `createRailgunTransactionWithHash`.
        assert_eq!(
            with_hash.railgun_txid,
            "2f499ee47c6a6688fa687530671bba04302843127ee9a465fd3b723e8c897923"
        );
        assert_eq!(
            with_hash.hash,
            "10d13f2b6c12a8a889c06d9b6f2051a917724d192c5dd625fbeaca3aed41b6e9"
        );
    }
}
