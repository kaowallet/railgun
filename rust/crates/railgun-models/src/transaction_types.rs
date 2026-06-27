//! Port of `src/models/transaction-types.ts`.
//!
//! The TS `TransactionStructV2/V3` reference ethers/typechain ABI structs
//! (`SnarkProofStruct`, `BoundParamsStruct`, `CommitmentPreimageStruct`). The
//! typechain glue belongs to the `railgun-contracts` crate (per the port plan,
//! `typechain-types.ts` is excluded from models). To keep this crate
//! self-contained yet faithful, the on-chain-facing shapes are generic over the
//! bound-params type `B` that the contracts/transaction crate supplies.

use num_bigint::BigUint;

use crate::poi_types::TXIDVersion;

/// `SnarkProofStruct` — G1/G2 points as field-element pairs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnarkProofStruct {
    pub a: (BigUint, BigUint),
    pub b: ((BigUint, BigUint), (BigUint, BigUint)),
    pub c: (BigUint, BigUint),
}

/// `CommitmentPreimageStruct`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentPreimageStruct {
    pub npk: Vec<u8>,
    pub token: crate::formatted_types::TokenData,
    pub value: BigUint,
}

/// `TransactionStructV2` — generic over the V2 `BoundParamsStruct` type `B`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionStructV2<B> {
    pub txid_version: TXIDVersion, // always V2_PoseidonMerkle
    pub proof: SnarkProofStruct,
    pub merkle_root: Vec<u8>,
    pub nullifiers: Vec<Vec<u8>>,
    pub commitments: Vec<Vec<u8>>,
    pub bound_params: B,
    pub unshield_preimage: CommitmentPreimageStruct,
}

/// `TransactionStructV3` — generic over the V3 `BoundParamsStruct` type `B`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionStructV3<B> {
    pub txid_version: TXIDVersion, // always V3_PoseidonMerkle
    pub proof: SnarkProofStruct,
    pub merkle_root: Vec<u8>,
    pub nullifiers: Vec<Vec<u8>>,
    pub commitments: Vec<Vec<u8>>,
    pub bound_params: B,
    pub unshield_preimage: CommitmentPreimageStruct,
}

/// One element of `ExtractedRailgunTransactionData`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractedRailgunTransactionDataItem {
    pub railgun_txid: String,
    pub utxo_tree_in: BigUint,
    pub first_commitment: Option<String>,
    pub first_commitment_note_public_key: Option<BigUint>,
}

pub type ExtractedRailgunTransactionData = Vec<ExtractedRailgunTransactionDataItem>;
