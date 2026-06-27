//! Port of `src/models/prover-types.ts`.
//!
//! `ArtifactGetter` is an *injected* dependency (it fetches Groth16 circuit
//! artifacts over HTTP or filesystem). We expose it as a trait; the caller
//! implements the I/O. The prover never fetches on its own.

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// `Circuits` — keep integer values identical (declaration order, 0-based).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Circuits {
    OneTwo = 0,
    OneThree = 1,
    TwoTwo = 2,
    TwoThree = 3,
    EightTwo = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct G1Point {
    pub x: BigUint,
    pub y: BigUint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct G2Point {
    pub x: [BigUint; 2],
    pub y: [BigUint; 2],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnarkProof {
    pub a: G1Point,
    pub b: G2Point,
    pub c: G1Point,
}

/// `Proof` — snarkjs-style stringified proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub pi_a: [String; 2],
    pub pi_b: [[String; 2]; 2],
    pub pi_c: [String; 2],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputsRailgun {
    pub merkle_root: BigUint,
    pub bound_params_hash: BigUint,
    pub nullifiers: Vec<BigUint>,
    pub commitments_out: Vec<BigUint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateInputsRailgun {
    pub token_address: BigUint,
    pub public_key: [BigUint; 2],
    pub random_in: Vec<BigUint>,
    pub value_in: Vec<BigUint>,
    pub path_elements: Vec<Vec<BigUint>>,
    pub leaves_indices: Vec<BigUint>,
    pub nullifying_key: BigUint,
    pub npk_out: Vec<BigUint>,
    pub value_out: Vec<BigUint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormattedCircuitInputsRailgun {
    pub merkle_root: BigUint,
    pub bound_params_hash: BigUint,
    pub nullifiers: Vec<BigUint>,
    pub commitments_out: Vec<BigUint>,
    pub token: BigUint,
    pub public_key: Vec<BigUint>,
    pub signature: Vec<BigUint>,
    pub random_in: Vec<BigUint>,
    pub value_in: Vec<BigUint>,
    pub path_elements: Vec<BigUint>,
    pub leaves_indices: Vec<BigUint>,
    pub nullifying_key: BigUint,
    pub npk_out: Vec<BigUint>,
    pub value_out: Vec<BigUint>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeProverFormattedJsonInputsRailgun {
    #[serde(rename = "merkleRoot")]
    pub merkle_root: String,
    #[serde(rename = "boundParamsHash")]
    pub bound_params_hash: String,
    pub nullifiers: Vec<String>,
    #[serde(rename = "commitmentsOut")]
    pub commitments_out: Vec<String>,
    pub token: String,
    #[serde(rename = "publicKey")]
    pub public_key: Vec<String>,
    pub signature: Vec<String>,
    #[serde(rename = "randomIn")]
    pub random_in: Vec<String>,
    #[serde(rename = "valueIn")]
    pub value_in: Vec<String>,
    #[serde(rename = "pathElements")]
    pub path_elements: Vec<String>,
    #[serde(rename = "leavesIndices")]
    pub leaves_indices: Vec<String>,
    #[serde(rename = "nullifyingKey")]
    pub nullifying_key: String,
    #[serde(rename = "npkOut")]
    pub npk_out: Vec<String>,
    #[serde(rename = "valueOut")]
    pub value_out: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputsPOI {
    pub any_railgun_txid_merkleroot_after_transaction: BigUint,
    pub blinded_commitments_out: Vec<BigUint>,
    pub poi_merkleroots: Vec<BigUint>,
    pub railgun_txid_if_has_unshield: BigUint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormattedCircuitInputsPOI {
    // Public inputs
    pub any_railgun_txid_merkleroot_after_transaction: BigUint,
    pub poi_merkleroots: Vec<BigUint>,

    // Private inputs
    pub bound_params_hash: BigUint,
    pub nullifiers: Vec<BigUint>,
    pub commitments_out: Vec<BigUint>,
    pub spending_public_key: [BigUint; 2],
    pub nullifying_key: BigUint,
    pub token: BigUint,
    pub randoms_in: Vec<BigUint>,
    pub values_in: Vec<BigUint>,
    pub utxo_positions_in: Vec<BigUint>,
    pub utxo_tree_in: BigUint,
    pub npks_out: Vec<BigUint>,
    pub values_out: Vec<BigUint>,
    pub utxo_batch_global_start_position_out: BigUint,
    pub railgun_txid_if_has_unshield: BigUint,
    pub railgun_txid_merkle_proof_indices: BigUint,
    pub railgun_txid_merkle_proof_path_elements: Vec<BigUint>,
    pub poi_in_merkle_proof_indices: Vec<BigUint>,
    pub poi_in_merkle_proof_path_elements: Vec<Vec<BigUint>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeProverFormattedJsonInputsPOI {
    // Public inputs
    #[serde(rename = "anyRailgunTxidMerklerootAfterTransaction")]
    pub any_railgun_txid_merkleroot_after_transaction: String,
    #[serde(rename = "poiMerkleroots")]
    pub poi_merkleroots: Vec<String>,

    // Private inputs
    #[serde(rename = "boundParamsHash")]
    pub bound_params_hash: String,
    pub nullifiers: Vec<String>,
    #[serde(rename = "commitmentsOut")]
    pub commitments_out: Vec<String>,
    #[serde(rename = "spendingPublicKey")]
    pub spending_public_key: [String; 2],
    #[serde(rename = "nullifyingKey")]
    pub nullifying_key: String,
    pub token: String,
    #[serde(rename = "randomsIn")]
    pub randoms_in: Vec<String>,
    #[serde(rename = "valuesIn")]
    pub values_in: Vec<String>,
    #[serde(rename = "utxoPositionsIn")]
    pub utxo_positions_in: Vec<String>,
    #[serde(rename = "utxoTreeIn")]
    pub utxo_tree_in: String,
    #[serde(rename = "npksOut")]
    pub npks_out: Vec<String>,
    #[serde(rename = "valuesOut")]
    pub values_out: Vec<String>,
    #[serde(rename = "utxoBatchGlobalStartPositionOut")]
    pub utxo_batch_global_start_position_out: String,
    #[serde(rename = "railgunTxidIfHasUnshield")]
    pub railgun_txid_if_has_unshield: String,
    #[serde(rename = "railgunTxidMerkleProofIndices")]
    pub railgun_txid_merkle_proof_indices: String,
    #[serde(rename = "railgunTxidMerkleProofPathElements")]
    pub railgun_txid_merkle_proof_path_elements: Vec<String>,
    #[serde(rename = "poiInMerkleProofIndices")]
    pub poi_in_merkle_proof_indices: Vec<String>,
    #[serde(rename = "poiInMerkleProofPathElements")]
    pub poi_in_merkle_proof_path_elements: Vec<Vec<String>>,
}

/// Placeholder for the Groth16 circuit artifact bundle.
///
/// The real shape (`.zkey`/`.wasm`/`.dat`/`.vkey` blobs) is defined by the
/// prover crate (Phase 4). Modeled here as opaque bytes so the
/// [`ArtifactGetter`] trait can compile; the prover refines it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Artifact {
    pub zkey: Vec<u8>,
    pub wasm: Option<Vec<u8>>,
    pub dat: Option<Vec<u8>>,
    pub vkey: Vec<u8>,
}

/// `ArtifactGetter` — injected dependency (HTTP/filesystem). The caller
/// implements I/O; the prover only calls these.
pub trait ArtifactGetter {
    fn assert_artifact_exists(&self, nullifiers: usize, commitments: usize) -> Result<(), String>;
    fn get_artifacts(&self, public_inputs: &PublicInputsRailgun) -> Result<Artifact, String>;
    fn get_artifacts_poi(&self, max_inputs: usize, max_outputs: usize) -> Result<Artifact, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuits_int_values() {
        assert_eq!(Circuits::OneTwo as u8, 0);
        assert_eq!(Circuits::OneThree as u8, 1);
        assert_eq!(Circuits::TwoTwo as u8, 2);
        assert_eq!(Circuits::TwoThree as u8, 3);
        assert_eq!(Circuits::EightTwo as u8, 4);
    }

    #[test]
    fn proof_serde_roundtrip() {
        let proof = Proof {
            pi_a: ["1".into(), "2".into()],
            pi_b: [["3".into(), "4".into()], ["5".into(), "6".into()]],
            pi_c: ["7".into(), "8".into()],
        };
        let json = serde_json::to_string(&proof).unwrap();
        let back: Proof = serde_json::from_str(&json).unwrap();
        assert_eq!(back, proof);
    }
}
