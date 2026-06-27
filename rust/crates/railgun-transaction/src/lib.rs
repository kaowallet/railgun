//! `railgun-transaction` — transaction + batch assembly (port of `src/transaction/`).
//!
//! Provides:
//! - [`abi`] — the minimal Solidity ABI encoder for bound-params tuples.
//! - [`bound_params`] — V2/V3 bound-params hashing (`hashBoundParamsV2/V3`).
//! - [`railgun_txid`] — RailgunTransactionID, TXID-merkletree leaf hash, and the
//!   keccak verification-hash chain (`railgun-txid.ts`).
//! - [`transaction`] — circuit public-input assembly + EdDSA-Poseidon signing.
//!   Actual Groth16 proof generation is deferred behind the prover trait (TODO).

pub mod abi;
pub mod bound_params;
pub mod railgun_txid;
pub mod transaction;

pub use bound_params::{
    hash_bound_params_v2, hash_bound_params_v3, BoundParamsV2, BoundParamsV3,
    CommitmentCiphertextV2, CommitmentCiphertextV3, GlobalBoundParamsV3,
};
pub use railgun_txid::{
    calculate_railgun_transaction_verification_hash, create_railgun_transaction_with_hash,
    get_railgun_transaction_id, get_railgun_transaction_id_from_bigints,
    get_railgun_transaction_id_hex, get_railgun_txid_leaf_hash,
};
pub use transaction::{format_public_inputs_railgun, sign_public_inputs, PublicInputsRailgun};
