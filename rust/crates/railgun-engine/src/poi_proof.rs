//! Port of `src/validation/poi-proof.ts`.
//!
//! Verifies a POI transact proof against the prover, trying the 3x3 "mini"
//! circuit first and falling back to 13x13 "full".

use railgun_models::prover_types::Proof;
use railgun_prover::{ArtifactGetter, Prover};

use crate::debugger::EngineDebug;

/// `TransactProofData`.
#[derive(Clone, Debug)]
pub struct TransactProofData {
    pub snark_proof: Proof,
    pub poi_merkleroots: Vec<String>,
    pub txid_merkleroot: String,
    pub txid_merkleroot_index: usize,
    pub blinded_commitments_out: Vec<String>,
    pub railgun_txid_if_has_unshield: String,
}

/// `POIProof`.
pub struct PoiProof;

impl PoiProof {
    /// `verifyTransactProof` — mini (3x3) then full (13x13).
    pub async fn verify_transact_proof<A: ArtifactGetter>(
        prover: &Prover<A>,
        transact_proof_data: &TransactProofData,
    ) -> bool {
        if Self::try_verify_proof(prover, transact_proof_data, 3, 3).await {
            return true;
        }
        Self::try_verify_proof(prover, transact_proof_data, 13, 13).await
    }

    async fn try_verify_proof<A: ArtifactGetter>(
        prover: &Prover<A>,
        transact_proof_data: &TransactProofData,
        max_inputs: usize,
        max_outputs: usize,
    ) -> bool {
        let public_inputs = Prover::<A>::get_public_inputs_poi(
            &transact_proof_data.txid_merkleroot,
            &transact_proof_data.blinded_commitments_out,
            &transact_proof_data.poi_merkleroots,
            &transact_proof_data.railgun_txid_if_has_unshield,
            max_inputs,
            max_outputs,
        );
        match prover
            .verify_poi_proof(
                &public_inputs,
                &transact_proof_data.snark_proof,
                max_inputs,
                max_outputs,
            )
            .await
        {
            Ok(valid) => valid,
            Err(_) => {
                EngineDebug::error("Failed to verify POI proof");
                false
            }
        }
    }
}
