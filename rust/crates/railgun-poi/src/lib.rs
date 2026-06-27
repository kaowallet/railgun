//! Port of `src/poi/` — proof-of-innocence support.
//!
//! Contains:
//! - [`blinded_commitment`] — Poseidon-based blinded commitments (KAV-tested).
//! - [`global_tree_position`] — global UTXO tree-position arithmetic (KAV-tested).
//! - [`poi`] — the `POI` status/balance-bucket logic (KAV-tested).
//! - [`poi_node_interface`] — the injected async POI-node client trait. The SDK
//!   only defines the interface; the caller implements the HTTP/JSON-RPC I/O.
//!
//! Out of scope for this crate (deferred): `poi-status-formatter.ts`, which
//! depends on the not-yet-ported `railgun-merkletree` (`Merkletree` /
//! `TXIDMerkletree`) and emoji-hash helpers; it is pure formatting and can be
//! ported once Phase 3 lands.

pub mod blinded_commitment;
pub mod global_tree_position;
pub mod poi;
pub mod poi_node_interface;

pub use blinded_commitment::BlindedCommitment;
pub use global_tree_position::{
    get_global_tree_position, get_global_tree_position_pre_transaction_poi_proof,
    GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
    GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE,
    GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
    GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE,
};
pub use poi::{
    is_shield_commitment_type, is_transact_commitment_type, remove_undefineds, POIList,
    POIListType, Poi, PoiNote,
};
pub use poi_node_interface::{POINodeError, POINodeInterface};
