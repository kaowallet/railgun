//! `railgun-engine` — engine orchestrator + validation + token-data getter +
//! debugger (port of `src/railgun-engine.ts`, `src/validation/*`, `src/token/*`,
//! `src/debugger/debugger.ts`).
//!
//! Scope per the port plan: **V2 + V3, no legacy**.
//!
//! What is fully ported (pure logic, KAV-tested):
//! - [`debugger`] — thin `tracing` wrapper of `EngineDebug`.
//! - [`railgun_txid`] — Poseidon railgun-txid + leaf-hash helpers.
//! - [`extract_transaction_data`] — V2 `transact`/`relay` calldata ABI-decode +
//!   receiver-note decrypt + ERC20 amount map + railgun-txid extraction.
//! - [`token_data_getter`] — token-hash → [`TokenData`] (ERC20 in-process; NFT
//!   behind an injected async resolver + cache).
//! - [`poi_proof`] / [`poi_validation`] — POI transact-proof verification +
//!   spendable-TXID validation (dummy txid merkle proof + injected validator).
//!
//! What is exposed behind injected traits / `todo!()` (needs the not-yet-ported
//! merkletree + live contract-event crates):
//! - [`engine::RailgunEngine`] sync loop (`scan_contract_history`,
//!   `full_rescan_*`) and live merkletree application.
//!
//! [`TokenData`]: railgun_models::formatted_types::TokenData

pub mod debugger;
pub mod engine;
pub mod extract_transaction_data;
pub mod poi_proof;
pub mod poi_validation;
pub mod railgun_txid;
pub mod token_data_getter;

pub use debugger::{EngineDebug, EngineDebugger};
pub use engine::{
    EngineError, GetLatestValidatedRailgunTxid, LatestValidatedRailgunTxid, LoadedNetwork,
    MerklerootValidator, QuickSyncEvents, QuickSyncRailgunTransactionsV2, RailgunEngine,
};
pub use extract_transaction_data::{
    extract_first_note_erc20_amount_map_from_transaction_request,
    extract_railgun_transaction_data_from_transaction_request, ExtractError,
};
pub use poi_proof::{PoiProof, TransactProofData};
pub use poi_validation::{
    assert_is_valid_spendable_txid, is_valid_spendable_transaction, PoiMerklerootsValidator,
    PoiValidationError, SpendableValidationResult,
};
pub use railgun_txid::{
    calculate_railgun_transaction_verification_hash, get_railgun_transaction_id,
    get_railgun_transaction_id_hex, get_railgun_txid_leaf_hash,
};
pub use token_data_getter::{
    NftTokenDataCache, NftTokenDataResolver, NoopNftTokenDataCache, TokenDataGetter,
    TokenDataGetterError, UnsupportedNftResolver,
};
