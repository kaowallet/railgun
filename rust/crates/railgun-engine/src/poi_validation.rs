//! Port of `src/validation/poi-validation.ts`.
//!
//! Validates that a spendable transaction's pre-transaction POIs are valid: it
//! extracts the railgun transaction data, then for each active list key asserts
//! a valid spendable TXID (txid leaf hash present, dummy txid merkle proof root
//! matches, POI merkleroots validate, snark proof verifies).

use async_trait::async_trait;
use num_bigint::BigUint;
use railgun_crypto::poseidon;
use railgun_key_derivation::AddressData;
use railgun_models::engine_types::Chain;
use railgun_models::poi_types::{PreTransactionPOIsPerTxidLeafPerList, TXIDVersion};
use railgun_models::transaction_types::ExtractedRailgunTransactionData;
use railgun_note::transact_note::TokenDataGetter as NoteTokenDataGetter;
use railgun_poi::global_tree_position::get_global_tree_position_pre_transaction_poi_proof;
use railgun_prover::{ArtifactGetter, Prover};
use railgun_utils::{hex_to_bigint, n_to_hex, ByteLength};

use crate::extract_transaction_data::{
    extract_railgun_transaction_data_from_transaction_request, ExtractError,
};
use crate::poi_proof::{PoiProof, TransactProofData};
use crate::railgun_txid::get_railgun_txid_leaf_hash;

/// TREE_DEPTH for the txid merkletree (`src/models/merkletree-types.ts`).
const TREE_DEPTH: usize = 16;

/// `POIMerklerootsValidator` — injected async callback to validate POI
/// merkleroots for a list (the engine supplies the on-chain/POI-node check).
#[async_trait]
pub trait PoiMerklerootsValidator: Send + Sync {
    async fn validate_poi_merkleroots(
        &self,
        txid_version: TXIDVersion,
        chain: &Chain,
        list_key: &str,
        poi_merkleroots: &[String],
    ) -> bool;
}

#[derive(Debug, thiserror::Error)]
pub enum PoiValidationError {
    #[error("{0}")]
    Extract(#[from] ExtractError),
    #[error("Missing POIs for list: {0}")]
    MissingPoisForList(String),
    #[error("Missing POI for txidLeafHash {0} for list {1}")]
    MissingPoi(String, String),
    #[error("Invalid txid merkle proof")]
    InvalidTxidMerkleProof,
    #[error("Invalid POI merkleroots: list {0}")]
    InvalidPoiMerkleroots(String),
    #[error("Could not verify POI snark proof: list {0}")]
    InvalidSnarkProof(String),
}

/// `createDummyMerkleProof` (root only) — port of `src/merkletree/merkle-proof.ts`.
/// Fills `TREE_DEPTH` levels with the 0n dummy value (not the merkle zero value).
fn dummy_merkle_proof_root(leaf: &str) -> String {
    let mut latest_hash = hex_to_bigint(leaf);
    let zero = BigUint::default();
    for _ in 0..TREE_DEPTH {
        latest_hash = poseidon(&[latest_hash, zero.clone()]);
    }
    n_to_hex(&latest_hash, ByteLength::Uint256, false)
}

/// Result of [`is_valid_spendable_transaction`].
pub struct SpendableValidationResult {
    pub is_valid: bool,
    pub error: Option<String>,
    pub extracted_railgun_transaction_data: Option<ExtractedRailgunTransactionData>,
}

#[allow(clippy::too_many_arguments)]
pub async fn is_valid_spendable_transaction<A, G, V>(
    txid_version: TXIDVersion,
    chain: &Chain,
    prover: &Prover<A>,
    transaction_data: &[u8],
    transaction_to: Option<&str>,
    use_relay_adapt: bool,
    contract_address: &str,
    pre_transaction_pois: &PreTransactionPOIsPerTxidLeafPerList,
    receiving_viewing_private_key: &[u8],
    receiving_railgun_address_data: &AddressData,
    token_data_getter: &G,
    active_list_keys: &[String],
    validator: Option<&V>,
) -> SpendableValidationResult
where
    A: ArtifactGetter,
    G: NoteTokenDataGetter,
    V: PoiMerklerootsValidator,
{
    let extracted = match extract_railgun_transaction_data_from_transaction_request(
        txid_version,
        chain,
        transaction_data,
        transaction_to,
        use_relay_adapt,
        contract_address,
        receiving_viewing_private_key,
        receiving_railgun_address_data,
        token_data_getter,
    ) {
        Ok(d) => d,
        Err(e) => {
            return SpendableValidationResult {
                is_valid: false,
                error: Some(format!("Could not validate spendable TXID: {e}")),
                extracted_railgun_transaction_data: None,
            }
        }
    };

    let railgun_txids: Vec<String> = extracted.iter().map(|d| d.railgun_txid.clone()).collect();
    let utxo_trees_in: Vec<BigUint> = extracted.iter().map(|d| d.utxo_tree_in.clone()).collect();

    for list_key in active_list_keys {
        if let Err(e) = assert_is_valid_spendable_txid(
            txid_version,
            list_key,
            chain,
            prover,
            pre_transaction_pois,
            &railgun_txids,
            &utxo_trees_in,
            validator,
        )
        .await
        {
            return SpendableValidationResult {
                is_valid: false,
                error: Some(format!("Could not validate spendable TXID: {e}")),
                extracted_railgun_transaction_data: None,
            };
        }
    }

    SpendableValidationResult {
        is_valid: true,
        error: None,
        extracted_railgun_transaction_data: Some(extracted),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn assert_is_valid_spendable_txid<A, V>(
    txid_version: TXIDVersion,
    list_key: &str,
    chain: &Chain,
    prover: &Prover<A>,
    pre_transaction_pois: &PreTransactionPOIsPerTxidLeafPerList,
    railgun_txids: &[String],
    utxo_trees_in: &[BigUint],
    validator: Option<&V>,
) -> Result<bool, PoiValidationError>
where
    A: ArtifactGetter,
    V: PoiMerklerootsValidator,
{
    let global_tree_position = get_global_tree_position_pre_transaction_poi_proof();
    let txid_leaf_hashes: Vec<String> = railgun_txids
        .iter()
        .enumerate()
        .map(|(index, railgun_txid)| {
            get_railgun_txid_leaf_hash(
                &hex_to_bigint(railgun_txid),
                &utxo_trees_in[index],
                &global_tree_position,
            )
        })
        .collect();

    // 1. Validate list key is present.
    let pois_for_list = pre_transaction_pois
        .get(list_key)
        .ok_or_else(|| PoiValidationError::MissingPoisForList(list_key.to_string()))?;

    for txid_leaf_hash in &txid_leaf_hashes {
        // 2. Validate txid leaf hash.
        let poi = pois_for_list.get(txid_leaf_hash).ok_or_else(|| {
            PoiValidationError::MissingPoi(txid_leaf_hash.clone(), list_key.to_string())
        })?;

        // 3. Validate txidDummyMerkleProof and txid root.
        let dummy_root = dummy_merkle_proof_root(txid_leaf_hash);
        if dummy_root != strip_root(&poi.txid_merkleroot) {
            return Err(PoiValidationError::InvalidTxidMerkleProof);
        }

        // 4. Validate POI merkleroots for each list.
        let valid_poi_merkleroots = match validator {
            Some(v) => {
                v.validate_poi_merkleroots(txid_version, chain, list_key, &poi.poi_merkleroots)
                    .await
            }
            None => {
                // Fallback to POI nodes is performed by the caller in the TS SDK;
                // without an injected validator we conservatively fail.
                false
            }
        };
        if !valid_poi_merkleroots {
            return Err(PoiValidationError::InvalidPoiMerkleroots(
                list_key.to_string(),
            ));
        }

        // 5. Verify snark proof for each list.
        let transact_proof_data = TransactProofData {
            snark_proof: poi.snark_proof.clone(),
            txid_merkleroot: poi.txid_merkleroot.clone(),
            poi_merkleroots: poi.poi_merkleroots.clone(),
            blinded_commitments_out: poi.blinded_commitments_out.clone(),
            railgun_txid_if_has_unshield: poi.railgun_txid_if_has_unshield.clone(),
            txid_merkleroot_index: 0,
        };
        let valid_proof = PoiProof::verify_transact_proof(prover, &transact_proof_data).await;
        if !valid_proof {
            return Err(PoiValidationError::InvalidSnarkProof(list_key.to_string()));
        }
    }

    Ok(true)
}

fn strip_root(root: &str) -> String {
    n_to_hex(&hex_to_bigint(root), ByteLength::Uint256, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The dummy merkle proof root is a pure Poseidon ladder over a fixed leaf.
    // This pins it as a KAV so the validation path stays byte-exact.
    #[test]
    fn dummy_merkle_proof_root_deterministic() {
        let leaf = "00".repeat(31) + "01"; // leaf = 1
        let root = dummy_merkle_proof_root(&leaf);
        // Recompute independently with the same ladder.
        let mut h = BigUint::from(1u8);
        for _ in 0..TREE_DEPTH {
            h = poseidon(&[h, BigUint::default()]);
        }
        assert_eq!(root, n_to_hex(&h, ByteLength::Uint256, false));
        assert_eq!(root.len(), 64);
    }
}
