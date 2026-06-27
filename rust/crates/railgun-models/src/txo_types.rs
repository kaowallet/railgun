//! Port of `src/models/txo-types.ts`.
//!
//! [`TXO`], [`SentCommitment`] and [`SpendingSolutionGroup`] reference
//! `TransactNote`, which lives in the not-yet-ported `railgun-note` crate. To
//! avoid a circular/forward dependency they are generic over the note type `N`;
//! `railgun-note` will instantiate them with its `TransactNote`.

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::formatted_types::{CommitmentType, OutputType, SpendTxid, TokenData};
use crate::poi_types::POIsPerList;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TXO<N> {
    pub tree: u32,
    pub position: u32,
    pub txid: String,
    pub timestamp: Option<u64>,
    pub block_number: u64,
    pub spendtxid: SpendTxid,
    pub nullifier: String,
    pub note: N,
    /// POIs that created this TXO.
    pub pois_per_list: Option<POIsPerList>,
    pub blinded_commitment: Option<String>,
    pub commitment_type: CommitmentType,
    pub transact_creation_railgun_txid: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentCommitment<N> {
    pub tree: u32,
    pub position: u32,
    pub txid: String,
    pub timestamp: Option<u64>,
    pub note: N,
    pub wallet_source: Option<String>,
    pub output_type: Option<OutputType>,
    pub is_legacy_transact_note: bool,
    pub railgun_txid: Option<String>,
    pub pois_per_list: Option<POIsPerList>,
    pub blinded_commitment: Option<String>,
    pub commitment_type: CommitmentType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendingSolutionGroup<N> {
    pub utxos: Vec<TXO<N>>,
    pub spending_tree: u32,
    pub token_outputs: Vec<N>,
    pub unshield_value: BigUint,
    pub token_data: TokenData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnshieldData {
    pub to_address: String,
    pub value: BigUint,
    pub token_data: TokenData,
    pub allow_override: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TXOsReceivedPOIStatusInfoShared {
    pub tree: u32,
    pub position: u32,
    pub txid: String,
    pub commitment: String,
    #[serde(rename = "blindedCommitment")]
    pub blinded_commitment: String,
    #[serde(rename = "poisPerList", skip_serializing_if = "Option::is_none")]
    pub pois_per_list: Option<POIsPerList>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TXOsReceivedPOIStatusInfo {
    pub strings: TXOsReceivedPOIStatusInfoShared,
    pub emojis: TXOsReceivedPOIStatusInfoShared,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TXOsSpentPOIStatusInfoShared {
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
    pub txid: String,
    #[serde(rename = "railgunTxid")]
    pub railgun_txid: String,
    #[serde(rename = "railgunTransactionInfo")]
    pub railgun_transaction_info: String,
    #[serde(rename = "poiStatusesSpentTXOs")]
    pub poi_statuses_spent_txos: Vec<Option<POIsPerList>>,
    #[serde(rename = "sentCommitmentsBlinded")]
    pub sent_commitments_blinded: String,
    #[serde(rename = "poiStatusesSentCommitments")]
    pub poi_statuses_sent_commitments: Vec<Option<POIsPerList>>,
    #[serde(rename = "unshieldEventsBlinded")]
    pub unshield_events_blinded: String,
    #[serde(rename = "poiStatusesUnshieldEvents")]
    pub poi_statuses_unshield_events: Vec<Option<POIsPerList>>,
    #[serde(rename = "listKeysCanGenerateSpentPOIs")]
    pub list_keys_can_generate_spent_pois: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TXOsSpentPOIStatusInfo {
    pub strings: TXOsSpentPOIStatusInfoShared,
    pub emojis: TXOsSpentPOIStatusInfoShared,
}

/// `WalletBalanceBucket` — string-valued enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletBalanceBucket {
    Spendable,
    ShieldBlocked,
    ShieldPending,
    ProofSubmitted,
    MissingInternalPOI,
    MissingExternalPOI,
    Spent,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_balance_bucket_serde_strings() {
        assert_eq!(
            serde_json::to_string(&WalletBalanceBucket::Spendable).unwrap(),
            r#""Spendable""#
        );
        assert_eq!(
            serde_json::to_string(&WalletBalanceBucket::MissingInternalPOI).unwrap(),
            r#""MissingInternalPOI""#
        );
    }
}
