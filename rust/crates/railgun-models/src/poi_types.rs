//! Port of `src/models/poi-types.ts`.

use std::collections::BTreeMap;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::prover_types::Proof;

/// `TXOPOIListStatus` — string-valued enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TXOPOIListStatus {
    Valid,
    ShieldBlocked,
    ProofSubmitted,
    Missing,
}

/// `POIsPerList` — `{ [listKey]: TXOPOIListStatus }`.
///
/// `BTreeMap` keeps key ordering deterministic for serde round-trips.
pub type POIsPerList = BTreeMap<String, TXOPOIListStatus>;

/// `BlindedCommitmentType` — string-valued enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlindedCommitmentType {
    Shield,
    Transact,
    Unshield,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedCommitmentData {
    #[serde(rename = "blindedCommitment")]
    pub blinded_commitment: String,
    #[serde(rename = "type")]
    pub commitment_type: BlindedCommitmentType,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyTransactProofData {
    #[serde(rename = "txidIndex")]
    pub txid_index: String,
    pub npk: String,
    pub value: String,
    #[serde(rename = "tokenHash")]
    pub token_hash: String,
    #[serde(rename = "blindedCommitment")]
    pub blinded_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreTransactionPOI {
    #[serde(rename = "snarkProof")]
    pub snark_proof: Proof,
    #[serde(rename = "txidMerkleroot")]
    pub txid_merkleroot: String,
    #[serde(rename = "poiMerkleroots")]
    pub poi_merkleroots: Vec<String>,
    #[serde(rename = "blindedCommitmentsOut")]
    pub blinded_commitments_out: Vec<String>,
    #[serde(rename = "railgunTxidIfHasUnshield")]
    pub railgun_txid_if_has_unshield: String,
}

/// `PreTransactionPOIsPerTxidLeafPerList` —
/// `Record<listKey, Record<txidLeafHash, PreTransactionPOI>>`.
pub type PreTransactionPOIsPerTxidLeafPerList =
    BTreeMap<String, BTreeMap<String, PreTransactionPOI>>;

/// `POIEngineProofInputs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct POIEngineProofInputs {
    // --- Public inputs ---
    pub any_railgun_txid_merkleroot_after_transaction: String,
    pub poi_merkleroots: Vec<String>,

    // --- Private inputs ---
    pub bound_params_hash: String,
    pub nullifiers: Vec<String>,
    pub commitments_out: Vec<String>,

    pub spending_public_key: [BigUint; 2],
    pub nullifying_key: BigUint,

    pub token: String,
    pub randoms_in: Vec<String>,
    pub values_in: Vec<BigUint>,
    pub utxo_positions_in: Vec<u32>,
    pub utxo_tree_in: u32,

    pub npks_out: Vec<BigUint>,
    pub values_out: Vec<BigUint>,
    pub utxo_batch_global_start_position_out: BigUint,

    pub railgun_txid_if_has_unshield: String,

    pub railgun_txid_merkle_proof_indices: String,
    pub railgun_txid_merkle_proof_path_elements: Vec<String>,

    pub poi_in_merkle_proof_indices: Vec<String>,
    pub poi_in_merkle_proof_path_elements: Vec<Vec<String>>,
}

/// `TXIDVersion` — string-valued enum. Variant names match the TS string values
/// (`"V2_PoseidonMerkle"` / `"V3_PoseidonMerkle"`) so serde emits them verbatim.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TXIDVersion {
    V2_PoseidonMerkle,
    V3_PoseidonMerkle,
}

pub const ACTIVE_UTXO_MERKLETREE_TXID_VERSIONS: [TXIDVersion; 2] = [
    TXIDVersion::V2_PoseidonMerkle,
    TXIDVersion::V3_PoseidonMerkle,
];

pub const ACTIVE_TXID_VERSIONS: [TXIDVersion; 2] = [
    TXIDVersion::V2_PoseidonMerkle,
    TXIDVersion::V3_PoseidonMerkle,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txid_version_serde_strings() {
        assert_eq!(
            serde_json::to_string(&TXIDVersion::V2_PoseidonMerkle).unwrap(),
            r#""V2_PoseidonMerkle""#
        );
        assert_eq!(
            serde_json::to_string(&TXIDVersion::V3_PoseidonMerkle).unwrap(),
            r#""V3_PoseidonMerkle""#
        );
    }

    #[test]
    fn poi_status_serde_strings() {
        assert_eq!(
            serde_json::to_string(&TXOPOIListStatus::Valid).unwrap(),
            r#""Valid""#
        );
        assert_eq!(
            serde_json::to_string(&TXOPOIListStatus::ShieldBlocked).unwrap(),
            r#""ShieldBlocked""#
        );
    }
}
