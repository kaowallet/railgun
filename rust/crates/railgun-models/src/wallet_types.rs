//! Port of `src/models/wallet-types.ts`.
//!
//! [`TreeBalance`] references [`TXO`], which is generic over the note type `N`
//! (see [`crate::txo_types`]); the same generic is propagated here.

use std::collections::BTreeMap;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::event_types::UnshieldStoredEvent;
use crate::formatted_types::{OutputType, TokenData};
use crate::poi_types::TXIDVersion;
use crate::txo_types::{WalletBalanceBucket, TXO};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletDetails {
    #[serde(rename = "treeScannedHeights")]
    pub tree_scanned_heights: Vec<u32>,
    #[serde(rename = "creationTree", skip_serializing_if = "Option::is_none")]
    pub creation_tree: Option<u32>,
    #[serde(rename = "creationTreeHeight", skip_serializing_if = "Option::is_none")]
    pub creation_tree_height: Option<u32>,
}

/// `WalletDetailsMap` — `Partial<Record<TXIDVersion, WalletDetails>>`.
pub type WalletDetailsMap = BTreeMap<TXIDVersion, WalletDetails>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeBalance<N> {
    pub balance: BigUint,
    pub token_data: TokenData,
    pub utxos: Vec<TXO<N>>,
}

/// `TokenBalances` — `{ [tokenHash]: TreeBalance }`.
pub type TokenBalances<N> = BTreeMap<String, TreeBalance<N>>;

/// `TokenBalancesAllTxidVersions` — `{ [txidVersion]: TokenBalances }`.
pub type TokenBalancesAllTxidVersions<N> = BTreeMap<String, TokenBalances<N>>;

/// `TotalBalancesByTreeNumber` — `{ [tree]: TreeBalance[] }`.
pub type TotalBalancesByTreeNumber<N> = BTreeMap<String, Vec<TreeBalance<N>>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressKeys {
    pub master_public_key: BigUint,
    pub viewing_public_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletData {
    pub mnemonic: String,
    pub index: u32,
    #[serde(
        rename = "creationBlockNumbers",
        skip_serializing_if = "Option::is_none"
    )]
    pub creation_block_numbers: Option<Vec<Vec<u64>>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewOnlyWalletData {
    #[serde(rename = "shareableViewingKey")]
    pub shareable_viewing_key: String,
    #[serde(
        rename = "creationBlockNumbers",
        skip_serializing_if = "Option::is_none"
    )]
    pub creation_block_numbers: Option<Vec<Vec<u64>>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareableViewingKeyData {
    /// viewingPrivateKey
    pub vpriv: String,
    /// spendingPublicKey
    pub spub: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionHistoryTokenAmount {
    #[serde(rename = "tokenHash")]
    pub token_hash: String,
    #[serde(rename = "tokenData")]
    pub token_data: TokenData,
    #[serde(with = "crate::serde_biguint")]
    pub amount: BigUint,
    #[serde(rename = "outputType", skip_serializing_if = "Option::is_none")]
    pub output_type: Option<OutputType>,
    #[serde(rename = "walletSource", skip_serializing_if = "Option::is_none")]
    pub wallet_source: Option<String>,
    #[serde(rename = "memoText", skip_serializing_if = "Option::is_none")]
    pub memo_text: Option<String>,
    #[serde(rename = "hasValidPOIForActiveLists")]
    pub has_valid_poi_for_active_lists: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionHistoryTransferTokenAmount {
    #[serde(flatten)]
    pub base: TransactionHistoryTokenAmount,
    #[serde(rename = "recipientAddress")]
    pub recipient_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionHistoryUnshieldTokenAmount {
    #[serde(flatten)]
    pub base: TransactionHistoryTransferTokenAmount,
    #[serde(rename = "unshieldFee")]
    pub unshield_fee: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionHistoryReceiveTokenAmount {
    #[serde(flatten)]
    pub base: TransactionHistoryTokenAmount,
    #[serde(rename = "senderAddress", skip_serializing_if = "Option::is_none")]
    pub sender_address: Option<String>,
    #[serde(rename = "shieldFee", skip_serializing_if = "Option::is_none")]
    pub shield_fee: Option<String>,
    #[serde(rename = "balanceBucket")]
    pub balance_bucket: WalletBalanceBucket,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionHistoryEntryReceived {
    #[serde(rename = "txidVersion")]
    pub txid_version: TXIDVersion,
    pub txid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    #[serde(rename = "blockNumber", skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    #[serde(rename = "receiveTokenAmounts")]
    pub receive_token_amounts: Vec<TransactionHistoryReceiveTokenAmount>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionHistoryEntrySpent {
    #[serde(rename = "txidVersion")]
    pub txid_version: TXIDVersion,
    pub txid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    #[serde(rename = "blockNumber", skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    #[serde(rename = "transferTokenAmounts")]
    pub transfer_token_amounts: Vec<TransactionHistoryTransferTokenAmount>,
    #[serde(rename = "changeTokenAmounts")]
    pub change_token_amounts: Vec<TransactionHistoryTokenAmount>,
    #[serde(
        rename = "broadcasterFeeTokenAmount",
        skip_serializing_if = "Option::is_none"
    )]
    pub broadcaster_fee_token_amount: Option<TransactionHistoryTokenAmount>,
    #[serde(rename = "unshieldTokenAmounts")]
    pub unshield_token_amounts: Vec<TransactionHistoryUnshieldTokenAmount>,
    pub version: TransactionHistoryItemVersion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionHistoryEntryPreprocessSpent {
    pub txid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    #[serde(rename = "blockNumber", skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    #[serde(rename = "tokenAmounts")]
    pub token_amounts: Vec<TransactionHistoryTokenAmount>,
    pub version: TransactionHistoryItemVersion,
    #[serde(rename = "unshieldEvents")]
    pub unshield_events: Vec<UnshieldStoredEvent>,
}

/// `TransactionHistoryItemVersion` — keep integer values identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(into = "u8", try_from = "u8")]
pub enum TransactionHistoryItemVersion {
    Unknown = 0,
    Legacy = 1,
    UpdatedAug2022 = 2,
    UpdatedNov2022 = 3,
}

impl From<TransactionHistoryItemVersion> for u8 {
    fn from(v: TransactionHistoryItemVersion) -> u8 {
        v as u8
    }
}

impl TryFrom<u8> for TransactionHistoryItemVersion {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(TransactionHistoryItemVersion::Unknown),
            1 => Ok(TransactionHistoryItemVersion::Legacy),
            2 => Ok(TransactionHistoryItemVersion::UpdatedAug2022),
            3 => Ok(TransactionHistoryItemVersion::UpdatedNov2022),
            other => Err(format!("Invalid TransactionHistoryItemVersion: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_item_version_int_values() {
        assert_eq!(TransactionHistoryItemVersion::Unknown as u8, 0);
        assert_eq!(TransactionHistoryItemVersion::Legacy as u8, 1);
        assert_eq!(TransactionHistoryItemVersion::UpdatedAug2022 as u8, 2);
        assert_eq!(TransactionHistoryItemVersion::UpdatedNov2022 as u8, 3);
    }

    #[test]
    fn wallet_data_serde_keys() {
        let wd = WalletData {
            mnemonic: "test test".into(),
            index: 0,
            creation_block_numbers: None,
        };
        let json = serde_json::to_string(&wd).unwrap();
        assert_eq!(json, r#"{"mnemonic":"test test","index":0}"#);
        let back: WalletData = serde_json::from_str(&json).unwrap();
        assert_eq!(back, wd);
    }
}
