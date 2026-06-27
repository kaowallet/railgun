//! `railgun-merkletree` — port of `src/merkletree/*.ts`.
//!
//! A depth-16 (65 536-leaf) binary Merkle tree hashed with
//! `poseidon([left, right])`, with hardcoded per-level zero values derived from
//! `MERKLE_ZERO_VALUE`. Two specializations are provided:
//!
//! * [`UTXOMerkletree`] — commitment leaves, plus nullifier / unshield-event
//!   storage.
//! * [`TXIDMerkletree`] — RAILGUN-txid leaves, plus historical-merkleroot and
//!   POI-launch-snapshot storage.
//!
//! The TypeScript engine wraps all of this in an async write-queue protected by
//! a refcounted lock (for concurrent chain scanning). Per the port plan the
//! lower crates are synchronous, so the queue/lock are collapsed into a plain
//! in-memory [`Vec`] write queue processed inline. Hash pre-image ordering,
//! field encodings and DB path keys are preserved byte-for-byte.

mod merkle_proof;
mod merkletree;
mod txid;
mod utxo;

pub use merkle_proof::{create_dummy_merkle_proof, verify_merkle_proof};
pub use merkletree::{MerkleKind, MerkletreeError, MerkletreeLeafData, TREE_DEPTH, TREE_MAX_ITEMS};
pub use txid::TXIDMerkletree;
pub use utxo::UTXOMerkletree;

// Re-export the static math helpers at the crate root so callers can use them
// without an instance (mirrors the TS `static` methods on `Merkletree`).
pub use merkletree::{
    get_global_position, get_tree_and_index_from_global_position, hash_left_right,
    num_nodes_per_level,
};
