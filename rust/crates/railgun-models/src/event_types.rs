//! Port of `src/models/event-types.ts`.
//!
//! The TS callback type-aliases (`QuickSyncEvents`, `EventsCommitmentListener`,
//! `MerklerootValidator`, …) are *injected, network-facing* dependencies. Their
//! async trait forms belong to the higher (async) crates (engine/contracts/poi)
//! that own `tokio`/`async-trait`; this pure-sync types crate defines the data
//! shapes those callbacks carry. The async traits are recorded as TODOs.

use serde::{Deserialize, Serialize};

use crate::formatted_types::{Commitment, Nullifier, RailgunTransactionV3};
use crate::poi_types::POIsPerList;

/// `EngineEvent` — string-valued enum (event names). Keep string values exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineEvent {
    #[serde(rename = "decrypted-balances")]
    WalletDecryptBalancesComplete,
    #[serde(rename = "nullified")]
    ContractNullifierReceived,
    #[serde(rename = "utxo-merkletree-history-scan-update")]
    UTXOMerkletreeHistoryScanUpdate,
    #[serde(rename = "txid-merkletree-history-scan-update")]
    TXIDMerkletreeHistoryScanUpdate,
    #[serde(rename = "POIProofUpdate")]
    POIProofUpdate,
    #[serde(rename = "UTXOScanDecryptBalancesComplete")]
    UTXOScanDecryptBalancesComplete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentEvent {
    pub txid: String,
    #[serde(rename = "treeNumber")]
    pub tree_number: u32,
    #[serde(rename = "startPosition")]
    pub start_position: u32,
    pub commitments: Vec<Commitment>,
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnshieldStoredEvent {
    pub txid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    #[serde(rename = "toAddress")]
    pub to_address: String,
    #[serde(rename = "tokenType")]
    pub token_type: u8,
    #[serde(rename = "tokenAddress")]
    pub token_address: String,
    #[serde(rename = "tokenSubID")]
    pub token_sub_id: String,
    pub amount: String,
    pub fee: String,
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
    #[serde(rename = "eventLogIndex", skip_serializing_if = "Option::is_none")]
    pub event_log_index: Option<u32>,
    #[serde(rename = "railgunTxid", skip_serializing_if = "Option::is_none")]
    pub railgun_txid: Option<String>,
    #[serde(rename = "poisPerList", skip_serializing_if = "Option::is_none")]
    pub pois_per_list: Option<POIsPerList>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccumulatedEvents {
    #[serde(rename = "commitmentEvents")]
    pub commitment_events: Vec<CommitmentEvent>,
    #[serde(rename = "unshieldEvents")]
    pub unshield_events: Vec<UnshieldStoredEvent>,
    #[serde(rename = "nullifierEvents")]
    pub nullifier_events: Vec<Nullifier>,
    #[serde(
        rename = "railgunTransactionEvents",
        skip_serializing_if = "Option::is_none"
    )]
    pub railgun_transaction_events: Option<Vec<RailgunTransactionV3>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletScannedEventData {
    #[serde(rename = "txidVersion")]
    pub txid_version: crate::poi_types::TXIDVersion,
    pub chain: crate::engine_types::Chain,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UTXOScanDecryptBalancesCompleteEventData {
    #[serde(rename = "txidVersion")]
    pub txid_version: crate::poi_types::TXIDVersion,
    pub chain: crate::engine_types::Chain,
    #[serde(rename = "walletIdFilter", skip_serializing_if = "Option::is_none")]
    pub wallet_id_filter: Option<Vec<String>>,
}

/// `MerkletreeScanStatus` — string-valued enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MerkletreeScanStatus {
    Started,
    Updated,
    Complete,
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MerkletreeHistoryScanEventData {
    #[serde(rename = "txidVersion")]
    pub txid_version: crate::poi_types::TXIDVersion,
    pub chain: crate::engine_types::Chain,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<f64>,
    #[serde(rename = "scanStatus")]
    pub scan_status: MerkletreeScanStatus,
}

/// `POIProofEventStatus` — string-valued enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum POIProofEventStatus {
    LoadingNextBatch,
    InProgress,
    Error,
    AllProofsCompleted,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct POICurrentProofEventData {
    pub status: POIProofEventStatus,
    #[serde(rename = "txidVersion")]
    pub txid_version: crate::poi_types::TXIDVersion,
    pub chain: crate::engine_types::Chain,
    pub progress: f64,
    #[serde(rename = "listKey")]
    pub list_key: String,
    pub txid: String,
    #[serde(rename = "railgunTxid")]
    pub railgun_txid: String,
    pub index: u32,
    #[serde(rename = "totalCount")]
    pub total_count: u32,
    #[serde(rename = "errorMsg", skip_serializing_if = "Option::is_none")]
    pub error_msg: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_event_string_values() {
        assert_eq!(
            serde_json::to_string(&EngineEvent::WalletDecryptBalancesComplete).unwrap(),
            r#""decrypted-balances""#
        );
        assert_eq!(
            serde_json::to_string(&EngineEvent::ContractNullifierReceived).unwrap(),
            r#""nullified""#
        );
        assert_eq!(
            serde_json::to_string(&EngineEvent::POIProofUpdate).unwrap(),
            r#""POIProofUpdate""#
        );
    }
}
