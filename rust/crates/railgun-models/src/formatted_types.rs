//! Port of `src/models/formatted-types.ts`.
//!
//! Re-uses [`railgun_crypto::Ciphertext`] / [`railgun_crypto::CiphertextCtr`] so
//! there is a single canonical AES ciphertext type across the workspace.

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

pub use railgun_crypto::{Ciphertext, CiphertextCtr};

use crate::poi_types::POIsPerList;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptID {
    pub contract: String,
    pub parameters: String,
}

/// `XChaChaEncryptionAlgorithm` — string-valued enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum XChaChaEncryptionAlgorithm {
    XChaCha,
    XChaChaPoly1305,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiphertextXChaCha {
    pub algorithm: XChaChaEncryptionAlgorithm,
    pub nonce: String,
    pub bundle: String,
}

/// `TokenType` — keep integer values identical to the TS enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(into = "u8", try_from = "u8")]
pub enum TokenType {
    Erc20 = 0,
    Erc721 = 1,
    Erc1155 = 2,
}

impl From<TokenType> for u8 {
    fn from(t: TokenType) -> u8 {
        t as u8
    }
}

impl TryFrom<u8> for TokenType {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(TokenType::Erc20),
            1 => Ok(TokenType::Erc721),
            2 => Ok(TokenType::Erc1155),
            other => Err(format!("Invalid TokenType: {other}")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReceiptLog {
    pub topics: Vec<String>,
    pub data: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenData {
    #[serde(rename = "tokenType")]
    pub token_type: TokenType,
    #[serde(rename = "tokenAddress")]
    pub token_address: String,
    #[serde(rename = "tokenSubID")]
    pub token_sub_id: String,
}

/// `NFTTokenData` is structurally identical to [`TokenData`]; in the TS it is a
/// refinement (`tokenType` is ERC721|ERC1155). We re-use [`TokenData`].
pub type NFTTokenData = TokenData;

/// `EncryptedData` — `[string, string]`.
pub type EncryptedData = [String; 2];

/// `CommitmentType` — string-valued enum (used as a serde tag for [`Commitment`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitmentType {
    // V1 (legacy)
    LegacyEncryptedCommitment,
    LegacyGeneratedCommitment,
    // V2
    ShieldCommitment,
    TransactCommitmentV2,
    // V3
    TransactCommitmentV3,
}

/// `OutputType` — keep integer values identical to the TS enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(into = "u8", try_from = "u8")]
pub enum OutputType {
    Transfer = 0,
    BroadcasterFee = 1,
    Change = 2,
}

impl From<OutputType> for u8 {
    fn from(t: OutputType) -> u8 {
        t as u8
    }
}

impl TryFrom<u8> for OutputType {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(OutputType::Transfer),
            1 => Ok(OutputType::BroadcasterFee),
            2 => Ok(OutputType::Change),
            other => Err(format!("Invalid OutputType: {other}")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteAnnotationData {
    pub output_type: OutputType,
    pub sender_random: String,
    pub wallet_source: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderAnnotationDecrypted {
    pub wallet_source: Option<String>,
    pub output_type: OutputType,
}

pub type EncryptedNoteAnnotationData = String;

/// `NoteSerialized`. !! Stored in the DB with these exact (camelCase) keys !!
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteSerialized {
    pub npk: String,
    pub value: String,
    #[serde(rename = "tokenHash")]
    pub token_hash: String,
    pub random: String,
    #[serde(rename = "recipientAddress")]
    pub recipient_address: String,
    #[serde(rename = "outputType", skip_serializing_if = "Option::is_none")]
    pub output_type: Option<OutputType>,
    #[serde(rename = "senderRandom", skip_serializing_if = "Option::is_none")]
    pub sender_random: Option<String>,
    #[serde(rename = "walletSource", skip_serializing_if = "Option::is_none")]
    pub wallet_source: Option<String>,
    #[serde(rename = "senderAddress", skip_serializing_if = "Option::is_none")]
    pub sender_address: Option<String>,
    #[serde(rename = "memoText", skip_serializing_if = "Option::is_none")]
    pub memo_text: Option<String>,
    #[serde(rename = "shieldFee", skip_serializing_if = "Option::is_none")]
    pub shield_fee: Option<String>,
    #[serde(rename = "blockNumber", skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
}

/// `LegacyNoteSerialized`. !! Stored in the DB with these exact keys !!
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyNoteSerialized {
    pub npk: String,
    pub value: String,
    #[serde(rename = "tokenHash")]
    pub token_hash: String,
    #[serde(rename = "encryptedRandom")]
    pub encrypted_random: [String; 2],
    #[serde(rename = "memoField")]
    pub memo_field: Vec<String>,
    #[serde(rename = "recipientAddress")]
    pub recipient_address: String,
    #[serde(rename = "memoText", skip_serializing_if = "Option::is_none")]
    pub memo_text: Option<String>,
    #[serde(rename = "blockNumber", skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
}

/// `DecryptedNote` — `NoteSerialized | LegacyNoteSerialized`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DecryptedNote {
    Note(NoteSerialized),
    Legacy(LegacyNoteSerialized),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf: String,
    pub elements: Vec<String>,
    pub indices: String,
    pub root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreImage {
    pub npk: String,
    pub token: TokenData,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldCiphertext {
    #[serde(rename = "encryptedBundle")]
    pub encrypted_bundle: [String; 3],
    #[serde(rename = "shieldKey")]
    pub shield_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentCiphertextV2 {
    pub ciphertext: Ciphertext,
    #[serde(rename = "blindedSenderViewingKey")]
    pub blinded_sender_viewing_key: String,
    #[serde(rename = "blindedReceiverViewingKey")]
    pub blinded_receiver_viewing_key: String,
    #[serde(rename = "annotationData")]
    pub annotation_data: String,
    pub memo: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentCiphertextV3 {
    pub ciphertext: CiphertextXChaCha,
    #[serde(rename = "blindedSenderViewingKey")]
    pub blinded_sender_viewing_key: String,
    #[serde(rename = "blindedReceiverViewingKey")]
    pub blinded_receiver_viewing_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyCommitmentCiphertext {
    pub ciphertext: Ciphertext,
    #[serde(rename = "ephemeralKeys")]
    pub ephemeral_keys: Vec<String>,
    pub memo: Vec<String>,
}

/// Fields shared by every commitment (the TS `CommitmentShared`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldCommitment {
    // `commitmentType` is provided by the `Commitment` enum tag (see below).
    pub hash: String,
    pub txid: String,
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    #[serde(rename = "utxoTree")]
    pub utxo_tree: u32,
    #[serde(rename = "utxoIndex")]
    pub utxo_index: u32,
    #[serde(rename = "preImage")]
    pub pre_image: PreImage,
    #[serde(rename = "encryptedBundle")]
    pub encrypted_bundle: [String; 3],
    #[serde(rename = "shieldKey")]
    pub shield_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactCommitmentV2 {
    // `commitmentType` is provided by the `Commitment` enum tag (see below).
    pub hash: String,
    pub txid: String,
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    #[serde(rename = "utxoTree")]
    pub utxo_tree: u32,
    #[serde(rename = "utxoIndex")]
    pub utxo_index: u32,
    pub ciphertext: CommitmentCiphertextV2,
    #[serde(rename = "railgunTxid", skip_serializing_if = "Option::is_none")]
    pub railgun_txid: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactCommitmentV3 {
    // `commitmentType` is provided by the `Commitment` enum tag (see below).
    pub hash: String,
    pub txid: String,
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    #[serde(rename = "utxoTree")]
    pub utxo_tree: u32,
    #[serde(rename = "utxoIndex")]
    pub utxo_index: u32,
    pub ciphertext: CommitmentCiphertextV3,
    #[serde(rename = "senderCiphertext")]
    pub sender_ciphertext: String,
    #[serde(rename = "railgunTxid", skip_serializing_if = "Option::is_none")]
    pub railgun_txid: Option<String>,
    #[serde(rename = "transactCommitmentBatchIndex")]
    pub transact_commitment_batch_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyGeneratedCommitment {
    // `commitmentType` is provided by the `Commitment` enum tag (see below).
    pub hash: String,
    pub txid: String,
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    #[serde(rename = "utxoTree")]
    pub utxo_tree: u32,
    #[serde(rename = "utxoIndex")]
    pub utxo_index: u32,
    #[serde(rename = "preImage")]
    pub pre_image: PreImage,
    #[serde(rename = "encryptedRandom")]
    pub encrypted_random: [String; 2],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyEncryptedCommitment {
    // `commitmentType` is provided by the `Commitment` enum tag (see below).
    pub hash: String,
    pub txid: String,
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    #[serde(rename = "utxoTree")]
    pub utxo_tree: u32,
    #[serde(rename = "utxoIndex")]
    pub utxo_index: u32,
    pub ciphertext: LegacyCommitmentCiphertext,
    #[serde(rename = "railgunTxid", skip_serializing_if = "Option::is_none")]
    pub railgun_txid: Option<String>,
}

/// `Commitment` union. Tagged by the `commitmentType` field (matches the TS
/// discriminant), so serde dispatches to the right variant on deserialize.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "commitmentType")]
pub enum Commitment {
    ShieldCommitment(ShieldCommitment),
    TransactCommitmentV2(TransactCommitmentV2),
    TransactCommitmentV3(TransactCommitmentV3),
    LegacyGeneratedCommitment(LegacyGeneratedCommitment),
    LegacyEncryptedCommitment(LegacyEncryptedCommitment),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nullifier {
    pub nullifier: String,
    #[serde(rename = "treeNumber")]
    pub tree_number: u32,
    pub txid: String,
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnshieldRailgunTransactionData {
    #[serde(rename = "tokenData")]
    pub token_data: TokenData,
    #[serde(rename = "toAddress")]
    pub to_address: String,
    pub value: String,
}

/// `RailgunTransactionVersion` — string-valued enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RailgunTransactionVersion {
    V2,
    V3,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailgunTransactionV2 {
    pub version: RailgunTransactionVersion,
    #[serde(rename = "graphID")]
    pub graph_id: String,
    pub commitments: Vec<String>,
    pub nullifiers: Vec<String>,
    #[serde(rename = "boundParamsHash")]
    pub bound_params_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
    pub txid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unshield: Option<UnshieldRailgunTransactionData>,
    #[serde(rename = "utxoTreeIn")]
    pub utxo_tree_in: u32,
    #[serde(rename = "utxoTreeOut")]
    pub utxo_tree_out: u32,
    #[serde(rename = "utxoBatchStartPositionOut")]
    pub utxo_batch_start_position_out: u32,
    pub timestamp: u64,
    #[serde(rename = "verificationHash")]
    pub verification_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailgunTransactionV3 {
    pub version: RailgunTransactionVersion,
    pub commitments: Vec<String>,
    pub nullifiers: Vec<String>,
    #[serde(rename = "boundParamsHash")]
    pub bound_params_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
    pub txid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unshield: Option<UnshieldRailgunTransactionData>,
    #[serde(rename = "utxoTreeIn")]
    pub utxo_tree_in: u32,
    #[serde(rename = "utxoTreeOut")]
    pub utxo_tree_out: u32,
    #[serde(rename = "utxoBatchStartPositionOut")]
    pub utxo_batch_start_position_out: u32,
    #[serde(rename = "verificationHash", skip_serializing_if = "Option::is_none")]
    pub verification_hash: Option<String>,
}

/// `RailgunTransaction` — `RailgunTransactionV2 | RailgunTransactionV3`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RailgunTransaction {
    V2(RailgunTransactionV2),
    V3(RailgunTransactionV3),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailgunTransactionWithHash {
    #[serde(flatten)]
    pub transaction: RailgunTransaction,
    #[serde(rename = "railgunTxid")]
    pub railgun_txid: String,
    pub hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TXIDMerkletreeData {
    #[serde(rename = "railgunTransaction")]
    pub railgun_transaction: RailgunTransactionWithHash,
    #[serde(rename = "currentMerkleProofForTree")]
    pub current_merkle_proof_for_tree: MerkleProof,
    #[serde(rename = "currentTxidIndexForTree")]
    pub current_txid_index_for_tree: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentSummary {
    #[serde(rename = "commitmentCiphertext")]
    pub commitment_ciphertext: CommitmentCiphertext,
    #[serde(rename = "commitmentHash")]
    pub commitment_hash: String,
}

/// `CommitmentCiphertextV2 | CommitmentCiphertextV3`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CommitmentCiphertext {
    V2(CommitmentCiphertextV2),
    V3(CommitmentCiphertextV3),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAdaptShieldERC20Recipient {
    #[serde(rename = "tokenAddress")]
    pub token_address: String,
    #[serde(rename = "recipientAddress")]
    pub recipient_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAdaptShieldNFTRecipient {
    #[serde(rename = "nftTokenData")]
    pub nft_token_data: NFTTokenData,
    #[serde(rename = "recipientAddress")]
    pub recipient_address: String,
}

/// `POICommitmentOutData`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct POICommitmentOutData {
    pub blinded_commitments_out: Vec<String>,
    pub npks_out: Vec<BigUint>,
    pub values_out: Vec<BigUint>,
    pub pois_per_list: Option<POIsPerList>,
}

/// `StoredReceiveCommitment`. !! Stored in the DB with these exact keys !!
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredReceiveCommitment {
    #[serde(rename = "txidVersion")]
    pub txid_version: crate::poi_types::TXIDVersion,
    pub spendtxid: SpendTxid,
    pub txid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    pub nullifier: String,
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
    pub decrypted: DecryptedNote,
    #[serde(rename = "senderAddress", skip_serializing_if = "Option::is_none")]
    pub sender_address: Option<String>,
    #[serde(rename = "commitmentType")]
    pub commitment_type: CommitmentType,
    #[serde(rename = "poisPerList", skip_serializing_if = "Option::is_none")]
    pub pois_per_list: Option<POIsPerList>,
    #[serde(rename = "blindedCommitment", skip_serializing_if = "Option::is_none")]
    pub blinded_commitment: Option<String>,
    #[serde(
        rename = "transactCreationRailgunTxid",
        skip_serializing_if = "Option::is_none"
    )]
    pub transact_creation_railgun_txid: Option<String>,
}

/// `spendtxid: string | false` — the txid that spent this commitment, or `false`
/// when unspent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SpendTxid {
    Txid(String),
    Unspent(bool), // always `false` in the TS
}

/// `StoredSendCommitment`. !! Stored in the DB with these exact keys !!
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSendCommitment {
    #[serde(rename = "txidVersion")]
    pub txid_version: crate::poi_types::TXIDVersion,
    pub txid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    pub decrypted: DecryptedNote,
    #[serde(rename = "commitmentType")]
    pub commitment_type: CommitmentType,
    #[serde(rename = "outputType", skip_serializing_if = "Option::is_none")]
    pub output_type: Option<OutputType>,
    #[serde(rename = "walletSource", skip_serializing_if = "Option::is_none")]
    pub wallet_source: Option<String>,
    #[serde(rename = "recipientAddress")]
    pub recipient_address: String,
    #[serde(rename = "railgunTxid", skip_serializing_if = "Option::is_none")]
    pub railgun_txid: Option<String>,
    #[serde(rename = "poisPerList", skip_serializing_if = "Option::is_none")]
    pub pois_per_list: Option<POIsPerList>,
    #[serde(rename = "blindedCommitment", skip_serializing_if = "Option::is_none")]
    pub blinded_commitment: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_type_int_values() {
        assert_eq!(TokenType::Erc20 as u8, 0);
        assert_eq!(TokenType::Erc721 as u8, 1);
        assert_eq!(TokenType::Erc1155 as u8, 2);
    }

    #[test]
    fn output_type_int_values() {
        assert_eq!(OutputType::Transfer as u8, 0);
        assert_eq!(OutputType::BroadcasterFee as u8, 1);
        assert_eq!(OutputType::Change as u8, 2);
    }

    #[test]
    fn token_data_serde_keys() {
        let td = TokenData {
            token_type: TokenType::Erc20,
            token_address: "0xabc".into(),
            token_sub_id: "0x00".into(),
        };
        let json = serde_json::to_string(&td).unwrap();
        assert_eq!(
            json,
            r#"{"tokenType":0,"tokenAddress":"0xabc","tokenSubID":"0x00"}"#
        );
        let back: TokenData = serde_json::from_str(&json).unwrap();
        assert_eq!(back, td);
    }

    #[test]
    fn note_serialized_omits_none() {
        let note = NoteSerialized {
            npk: "0x01".into(),
            value: "100".into(),
            token_hash: "0x02".into(),
            random: "0x03".into(),
            recipient_address: "0zk...".into(),
            output_type: None,
            sender_random: None,
            wallet_source: None,
            sender_address: None,
            memo_text: None,
            shield_fee: None,
            block_number: None,
        };
        let json = serde_json::to_string(&note).unwrap();
        // Optional fields skipped when None.
        assert!(!json.contains("outputType"));
        assert!(json.contains("\"tokenHash\":\"0x02\""));
        let back: NoteSerialized = serde_json::from_str(&json).unwrap();
        assert_eq!(back, note);
    }

    #[test]
    fn commitment_tagged_by_type() {
        let shield = Commitment::ShieldCommitment(ShieldCommitment {
            hash: "0xaa".into(),
            txid: "0xbb".into(),
            block_number: 10,
            timestamp: Some(123),
            utxo_tree: 0,
            utxo_index: 5,
            pre_image: PreImage {
                npk: "0x01".into(),
                token: TokenData {
                    token_type: TokenType::Erc20,
                    token_address: "0xtok".into(),
                    token_sub_id: "0x00".into(),
                },
                value: "1".into(),
            },
            encrypted_bundle: ["0x1".into(), "0x2".into(), "0x3".into()],
            shield_key: "0xkey".into(),
            fee: None,
            from: None,
        });
        let json = serde_json::to_string(&shield).unwrap();
        assert!(json.contains(r#""commitmentType":"ShieldCommitment""#));
        let back: Commitment = serde_json::from_str(&json).unwrap();
        assert_eq!(back, shield);
    }

    #[test]
    fn spendtxid_false_or_string() {
        assert_eq!(
            serde_json::to_string(&SpendTxid::Unspent(false)).unwrap(),
            "false"
        );
        assert_eq!(
            serde_json::to_string(&SpendTxid::Txid("0xff".into())).unwrap(),
            r#""0xff""#
        );
        let back: SpendTxid = serde_json::from_str("false").unwrap();
        assert_eq!(back, SpendTxid::Unspent(false));
    }
}
