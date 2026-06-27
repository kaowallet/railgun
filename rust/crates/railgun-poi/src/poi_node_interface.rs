//! Port of `src/poi/poi-node-interface.ts`.
//!
//! `POINodeInterface` is an **injected** dependency: an HTTP/JSON-RPC client for
//! an external POI node. The SDK only defines the interface; it performs no I/O.
//! The caller implements this trait (e.g. with `reqwest`).

use std::collections::BTreeMap;

use async_trait::async_trait;
use railgun_models::engine_types::Chain;
use railgun_models::formatted_types::MerkleProof;
use railgun_models::poi_types::{
    BlindedCommitmentData, LegacyTransactProofData, POIsPerList, TXIDVersion,
};
use railgun_models::prover_types::Proof;

/// Error type returned by [`POINodeInterface`] methods. Implementors map their
/// transport/parse failures into this.
#[derive(Debug, thiserror::Error)]
pub enum POINodeError {
    #[error("POI node request failed: {0}")]
    Request(String),
}

/// `POINodeInterface` — async client trait for the external POI node.
#[async_trait]
pub trait POINodeInterface: Send + Sync {
    fn is_active(&self, chain: &Chain) -> bool;

    async fn is_required(&self, chain: &Chain) -> Result<bool, POINodeError>;

    async fn get_pois_per_list(
        &self,
        txid_version: TXIDVersion,
        chain: &Chain,
        list_keys: &[String],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<String, POIsPerList>, POINodeError>;

    async fn get_poi_merkle_proofs(
        &self,
        txid_version: TXIDVersion,
        chain: &Chain,
        list_key: &str,
        blinded_commitments: &[String],
    ) -> Result<Vec<MerkleProof>, POINodeError>;

    async fn validate_poi_merkleroots(
        &self,
        txid_version: TXIDVersion,
        chain: &Chain,
        list_key: &str,
        poi_merkleroots: &[String],
    ) -> Result<bool, POINodeError>;

    #[allow(clippy::too_many_arguments)]
    async fn submit_poi(
        &self,
        txid_version: TXIDVersion,
        chain: &Chain,
        list_key: &str,
        snark_proof: Proof,
        poi_merkleroots: &[String],
        txid_merkleroot: &str,
        txid_merkleroot_index: u32,
        blinded_commitments_out: &[String],
        railgun_txid_if_has_unshield: &str,
    ) -> Result<(), POINodeError>;

    async fn submit_legacy_transact_proofs(
        &self,
        txid_version: TXIDVersion,
        chain: &Chain,
        list_keys: &[String],
        legacy_transact_proof_datas: &[LegacyTransactProofData],
    ) -> Result<(), POINodeError>;
}
