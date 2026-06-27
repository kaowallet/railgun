//! # `railgun` — the ready-to-use RAILGUN wallet framework
//!
//! A unified front door over the `railgun-*` crates. It wires together storage,
//! the UTXO merkletree, and wallets so an app can: create/restore wallets,
//! derive addresses, **sync balances from chain**, and read per-token balances —
//! without hand-assembling a dozen crates.
//!
//! ## What it does / doesn't do
//! - **Network is caller-injected (trait-only).** You implement the
//!   [`engine::QuickSyncEvents`] trait (and friends) over your own RPC/indexer;
//!   the framework performs no outgoing requests itself.
//! - **Storage is your own [`db::KvStore`]** (e.g. redb). Wallet data is stored
//!   AES-256-GCM-encrypted; the merkletree is rebuilt on sync (fresh-resync model).
//! - **Spending is not included.** Proof generation needs a Groth16 backend
//!   (native rapidsnark + circuit artifacts) — see [`prover`]. This framework
//!   covers the read/sync/balance path; spending is a documented next step.
//!
//! ```no_run
//! use railgun::prelude::*;
//! # async fn demo<Q: QuickSyncEvents>(quick_sync: &Q) -> Result<(), FrameworkError> {
//! let mut db = Database::in_memory();          // or your redb-backed KvStore
//! let key = [0x11u8; 32];
//! let mnemonic = Mnemonic::generate(128);
//! let chain = Chain { chain_type: 0, id: 1 };
//!
//! let wallet = RailgunWallet::from_mnemonic(&mut db, &key, &mnemonic, 0, None)
//!     .map_err(|e| FrameworkError::Wallet(e.to_string()))?;
//!
//! let mut rg = Railgun::new(db, chain, TXIDVersion::V2_PoseidonMerkle);
//! rg.add_wallet(wallet);
//! rg.sync(quick_sync, 0).await?;               // events -> tree -> decrypt -> store
//! let balances = rg.token_balances(0)?;        // { tokenHash -> amount }, spent excluded
//! # let _ = balances; Ok(())
//! # }
//! ```

// ---- ecosystem re-exports -------------------------------------------------
pub use railgun_contracts as contracts;
pub use railgun_crypto as crypto;
pub use railgun_db as db;
pub use railgun_engine as engine;
pub use railgun_key_derivation as key_derivation;
pub use railgun_merkletree as merkletree;
pub use railgun_models as models;
pub use railgun_note as note;
pub use railgun_poi as poi;
pub use railgun_prover as prover;
pub use railgun_solutions as solutions;
pub use railgun_transaction as transaction;
pub use railgun_utils as utils;
pub use railgun_wallet as wallet;

/// Common imports for building a wallet app.
pub mod prelude {
    pub use crate::{FrameworkError, Railgun};
    pub use railgun_db::{Database, KvStore, MemStore};
    pub use railgun_engine::QuickSyncEvents;
    pub use railgun_key_derivation::{Chain, ChainType, Mnemonic};
    pub use railgun_models::poi_types::TXIDVersion;
    pub use railgun_wallet::{RailgunWallet, ViewOnlyWallet};
}

use std::collections::BTreeMap;

use num_bigint::BigUint;
use railgun_db::{Database, KvStore};
use railgun_engine::{EngineError, QuickSyncEvents};
use railgun_key_derivation::Chain;
use railgun_merkletree::UTXOMerkletree;
use railgun_models::formatted_types::{Commitment, DecryptedNote, StoredReceiveCommitment};
use railgun_models::poi_types::TXIDVersion;
use railgun_utils::hex_to_bigint;
use railgun_wallet::RailgunWallet;

#[derive(Debug, thiserror::Error)]
pub enum FrameworkError {
    #[error("sync error: {0}")]
    Engine(String),
    #[error("wallet error: {0}")]
    Wallet(String),
    #[error("{0}")]
    Other(String),
}

impl From<EngineError> for FrameworkError {
    fn from(e: EngineError) -> Self {
        FrameworkError::Engine(e.to_string())
    }
}

/// Per-token balance map: `tokenHash (64-hex) -> amount`.
pub type TokenBalances = BTreeMap<String, BigUint>;

/// The framework handle: owns your storage, the UTXO merkletree, and the
/// registered wallets for one chain + txid-version.
pub struct Railgun<S: KvStore> {
    /// Your encrypted key/value storage (wallet data lives here).
    pub db: Database<S>,
    chain: Chain,
    txid_version: TXIDVersion,
    /// Rebuilt from chain events on each [`sync`](Railgun::sync). Held in-memory.
    merkletree: UTXOMerkletree,
    wallets: Vec<RailgunWallet<S>>,
}

impl<S: KvStore> Railgun<S> {
    /// Create a framework instance for one chain. The UTXO merkletree is built
    /// in-memory and (re)populated by [`sync`](Railgun::sync).
    pub fn new(db: Database<S>, chain: Chain, txid_version: TXIDVersion) -> Self {
        let merkletree = UTXOMerkletree::create(
            Database::in_memory(),
            chain,
            txid_version,
            |_, _, _, _, _| true,
        );
        Self {
            db,
            chain,
            txid_version,
            merkletree,
            wallets: Vec::new(),
        }
    }

    /// Register a wallet to be scanned during sync.
    pub fn add_wallet(&mut self, wallet: RailgunWallet<S>) {
        self.wallets.push(wallet);
    }

    /// Access a registered wallet.
    pub fn wallet(&self, index: usize) -> Option<&RailgunWallet<S>> {
        self.wallets.get(index)
    }

    /// Sync from chain: fetch accumulated events via the caller-supplied
    /// [`QuickSyncEvents`], (re)build the UTXO merkletree, apply nullifiers, then
    /// decrypt+store every commitment addressed to a registered wallet.
    pub async fn sync<Q: QuickSyncEvents>(
        &mut self,
        quick_sync: &Q,
        start_block: u64,
    ) -> Result<(), FrameworkError> {
        let events = quick_sync
            .quick_sync_events(self.txid_version, &self.chain, start_block)
            .await?;

        // 1. Build the UTXO tree from commitment events.
        for ev in &events.commitment_events {
            self.merkletree.queue_leaves(
                ev.tree_number as usize,
                ev.start_position as usize,
                ev.commitments.clone(),
            );
        }
        self.merkletree.update_trees_from_write_queue();
        self.merkletree.nullify(&events.nullifier_events);
        self.merkletree
            .add_unshield_events(&events.unshield_events, false);

        // 2. Scan each registered wallet over the new commitments. (Split-borrow
        //    so the wallets + db can be used together.)
        let Self {
            db,
            wallets,
            txid_version,
            chain,
            ..
        } = self;
        for ev in &events.commitment_events {
            let leaves: Vec<Option<Commitment>> =
                ev.commitments.iter().cloned().map(Some).collect();
            for w in wallets.iter() {
                w.wallet
                    .scan_leaves(
                        db,
                        *txid_version,
                        &leaves,
                        ev.tree_number as u64,
                        chain,
                        ev.start_position as u64,
                    )
                    .map_err(|e| FrameworkError::Wallet(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Per-token spendable balances for a registered wallet: the sum of received
    /// commitments whose nullifier has not appeared on chain (i.e. unspent).
    pub fn token_balances(&mut self, wallet_index: usize) -> Result<TokenBalances, FrameworkError> {
        let Self {
            db,
            merkletree,
            wallets,
            chain,
            ..
        } = self;
        let wallet = wallets
            .get(wallet_index)
            .ok_or_else(|| FrameworkError::Other("wallet index out of range".into()))?;

        let mut balances = TokenBalances::new();
        let latest = merkletree.latest_tree();
        for tree in 0..=latest {
            let len = merkletree.get_tree_length(tree);
            for pos in 0..len {
                let key = wallet.wallet.get_wallet_receive_commitment_db_prefix(
                    chain,
                    tree as u64,
                    pos as u64,
                );
                let Ok(hex_value) = db.get(&key) else {
                    continue;
                };
                let Ok(bytes) = hex::decode(&hex_value) else {
                    continue;
                };
                let Ok(stored) = rmp_serde::from_slice::<StoredReceiveCommitment>(&bytes) else {
                    continue;
                };
                // Exclude spent notes (nullifier observed on chain).
                if merkletree
                    .get_nullifier_txid(&stored.nullifier, None, None)
                    .is_some()
                {
                    continue;
                }
                if let DecryptedNote::Note(ns) = &stored.decrypted {
                    *balances.entry(ns.token_hash.clone()).or_default() += hex_to_bigint(&ns.value);
                }
            }
        }
        Ok(balances)
    }
}
