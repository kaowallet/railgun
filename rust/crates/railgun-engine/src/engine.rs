//! Port of the public surface of `src/railgun-engine.ts`.
//!
//! The TS `RailgunEngine` orchestrates: UTXO + TXID merkletree sync, contract
//! event subscription, balance decryption, merkleroot validation and POI proof
//! validation. The full sync loop depends on the merkletree crate (not yet
//! ported) and live contract event subscription; those internals are exposed
//! behind the injected async traits defined here and marked `todo!()` where the
//! merkletree integration is required.
//!
//! What *is* fully wired here: the injected dependency traits (the caller's
//! network seams), the `RailgunEngine` struct + construction, address
//! encode/decode, debugger init, and references to the ported pure-logic
//! validation/token modules.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use railgun_key_derivation::{decode_address, encode_address, AddressData, AddressError};
use railgun_models::engine_types::Chain;
use railgun_models::event_types::AccumulatedEvents;
use railgun_models::formatted_types::RailgunTransactionV2;
use railgun_models::poi_types::TXIDVersion;
use railgun_prover::{ArtifactGetter, Prover};

use crate::debugger::{EngineDebug, EngineDebugger};

// ===== Injected async dependency traits (the caller's network seams) =====

/// `QuickSyncEvents` — fetch accumulated commitment/nullifier/unshield events
/// from `startingBlock` (e.g. via The Graph / RPC). Caller-injected; no I/O here.
#[async_trait]
pub trait QuickSyncEvents: Send + Sync {
    async fn quick_sync_events(
        &self,
        txid_version: TXIDVersion,
        chain: &Chain,
        starting_block: u64,
    ) -> Result<AccumulatedEvents, EngineError>;
}

/// `QuickSyncRailgunTransactionsV2` — fetch V2 railgun transactions (subgraph).
#[async_trait]
pub trait QuickSyncRailgunTransactionsV2: Send + Sync {
    async fn quick_sync_railgun_transactions_v2(
        &self,
        chain: &Chain,
        latest_graph_id: Option<&str>,
    ) -> Result<Vec<RailgunTransactionV2>, EngineError>;
}

/// `MerklerootValidator` — on-chain validation of a UTXO merkleroot.
#[async_trait]
pub trait MerklerootValidator: Send + Sync {
    async fn validate_merkleroot(
        &self,
        txid_version: TXIDVersion,
        chain: &Chain,
        tree: u64,
        index: u64,
        merkleroot: &str,
    ) -> Result<bool, EngineError>;
}

/// Result of [`GetLatestValidatedRailgunTxid::get_latest_validated_railgun_txid`].
#[derive(Clone, Debug, Default)]
pub struct LatestValidatedRailgunTxid {
    pub txid_index: Option<u64>,
    pub merkleroot: Option<String>,
}

/// `GetLatestValidatedRailgunTxid` — latest validated TXID merkleroot.
#[async_trait]
pub trait GetLatestValidatedRailgunTxid: Send + Sync {
    async fn get_latest_validated_railgun_txid(
        &self,
        txid_version: TXIDVersion,
        chain: &Chain,
    ) -> Result<LatestValidatedRailgunTxid, EngineError>;
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("{0}")]
    Address(#[from] AddressError),
    #[error("Merkletree integration not yet ported: {0}")]
    MerkletreeNotPorted(&'static str),
    #[error("Network layer not configured: {0}")]
    NetworkNotConfigured(&'static str),
    #[error("{0}")]
    Other(String),
}

/// Per-chain loaded-network state. The full TS version also holds the UTXO/TXID
/// merkletrees and contract subscribers; those are stubbed pending the
/// merkletree + contract-event crates.
#[derive(Clone, Debug)]
pub struct LoadedNetwork {
    pub proxy_contract: String,
    pub relay_adapt_contract: String,
    pub poseidon_merkle_accumulator_v3: Option<String>,
    pub poseidon_merkle_verifier_v3: Option<String>,
    pub token_vault_v3: Option<String>,
    pub supports_v3: bool,
    /// Starting scan block per txidVersion.
    pub deployment_blocks: BTreeMap<TXIDVersion, u64>,
}

/// `RailgunEngine`.
///
/// Generic over the injected dependencies. The TS singleton stores everything
/// mutably; here the caller owns the dependencies and the engine borrows them.
pub struct RailgunEngine<
    A: ArtifactGetter,
    QE: QuickSyncEvents,
    QT: QuickSyncRailgunTransactionsV2,
    MV: MerklerootValidator,
    LV: GetLatestValidatedRailgunTxid,
> {
    pub wallet_source: String,
    pub prover: Prover<A>,
    pub quick_sync_events: Arc<QE>,
    pub quick_sync_railgun_transactions_v2: Arc<QT>,
    pub validate_railgun_txid_merkleroot: Option<Arc<MV>>,
    pub get_latest_validated_railgun_txid: Option<Arc<LV>>,
    pub is_poi_node: bool,
    pub skip_merkletree_scans: bool,
    loaded_networks: BTreeMap<(u8, u64), LoadedNetwork>,
}

impl<A, QE, QT, MV, LV> RailgunEngine<A, QE, QT, MV, LV>
where
    A: ArtifactGetter,
    QE: QuickSyncEvents,
    QT: QuickSyncRailgunTransactionsV2,
    MV: MerklerootValidator,
    LV: GetLatestValidatedRailgunTxid,
{
    /// `RailgunEngine.initForWallet`.
    #[allow(clippy::too_many_arguments)]
    pub fn init_for_wallet(
        wallet_source: impl Into<String>,
        artifact_getter: A,
        quick_sync_events: Arc<QE>,
        quick_sync_railgun_transactions_v2: Arc<QT>,
        validate_railgun_txid_merkleroot: Option<Arc<MV>>,
        get_latest_validated_railgun_txid: Option<Arc<LV>>,
        engine_debugger: Option<Box<dyn EngineDebugger>>,
        skip_merkletree_scans: bool,
    ) -> Self {
        if let Some(d) = engine_debugger {
            EngineDebug::init(d);
        }
        Self {
            wallet_source: wallet_source.into(),
            prover: Prover::new(artifact_getter),
            quick_sync_events,
            quick_sync_railgun_transactions_v2,
            validate_railgun_txid_merkleroot,
            get_latest_validated_railgun_txid,
            is_poi_node: false,
            skip_merkletree_scans,
            loaded_networks: BTreeMap::new(),
        }
    }

    /// `RailgunEngine.initForPOINode`.
    pub fn init_for_poi_node(
        artifact_getter: A,
        quick_sync_events: Arc<QE>,
        quick_sync_railgun_transactions_v2: Arc<QT>,
        engine_debugger: Option<Box<dyn EngineDebugger>>,
    ) -> Self {
        if let Some(d) = engine_debugger {
            EngineDebug::init(d);
        }
        Self {
            wallet_source: "poinode".to_string(),
            prover: Prover::new(artifact_getter),
            quick_sync_events,
            quick_sync_railgun_transactions_v2,
            validate_railgun_txid_merkleroot: None,
            get_latest_validated_railgun_txid: None,
            is_poi_node: true,
            skip_merkletree_scans: false,
            loaded_networks: BTreeMap::new(),
        }
    }

    /// `RailgunEngine.setEngineDebugger`.
    pub fn set_engine_debugger(engine_debugger: Box<dyn EngineDebugger>) {
        EngineDebug::init(engine_debugger);
    }

    /// `RailgunEngine.loadNetwork` — register contract addresses + deployment
    /// blocks for a chain. The TS version also instantiates the merkletrees and
    /// starts contract event subscription; those are deferred to the merkletree +
    /// contract-event crates.
    #[allow(clippy::too_many_arguments)]
    pub fn load_network(
        &mut self,
        chain: Chain,
        proxy_contract: impl Into<String>,
        relay_adapt_contract: impl Into<String>,
        poseidon_merkle_accumulator_v3: Option<String>,
        poseidon_merkle_verifier_v3: Option<String>,
        token_vault_v3: Option<String>,
        deployment_blocks: BTreeMap<TXIDVersion, u64>,
        supports_v3: bool,
    ) {
        self.loaded_networks.insert(
            (chain.chain_type, chain.id),
            LoadedNetwork {
                proxy_contract: proxy_contract.into(),
                relay_adapt_contract: relay_adapt_contract.into(),
                poseidon_merkle_accumulator_v3,
                poseidon_merkle_verifier_v3,
                token_vault_v3,
                supports_v3,
                deployment_blocks,
            },
        );
    }

    /// `RailgunEngine.unloadNetwork`.
    pub fn unload_network(&mut self, chain: &Chain) {
        self.loaded_networks.remove(&(chain.chain_type, chain.id));
    }

    /// Loaded-network state lookup.
    pub fn loaded_network(&self, chain: &Chain) -> Option<&LoadedNetwork> {
        self.loaded_networks.get(&(chain.chain_type, chain.id))
    }

    /// `RailgunEngine.scanContractHistory` — full UTXO+TXID scan for a chain.
    ///
    /// Requires the merkletree crate (commitment listener + leaf insertion) which
    /// is not yet ported; the network fetch seam ([`QuickSyncEvents`]) is wired,
    /// but applying events into a merkletree is pending.
    pub async fn scan_contract_history(
        &self,
        _chain: &Chain,
        _wallet_id_filter: Option<&[String]>,
    ) -> Result<(), EngineError> {
        Err(EngineError::MerkletreeNotPorted("scan_contract_history"))
    }

    /// `RailgunEngine.syncRailgunTransactionsV2` — wires the injected V2 subgraph
    /// fetch. Applying the results to the TXID merkletree is pending the
    /// merkletree crate.
    pub async fn sync_railgun_transactions_v2(
        &self,
        chain: &Chain,
        _trigger: &str,
    ) -> Result<Vec<RailgunTransactionV2>, EngineError> {
        // The network fetch is fully wired; merkletree application is the TODO.
        self.quick_sync_railgun_transactions_v2
            .quick_sync_railgun_transactions_v2(chain, None)
            .await
    }

    /// `RailgunEngine.fullRescanUTXOMerkletreesAndWallets`.
    pub async fn full_rescan_utxo_merkletrees_and_wallets(
        &self,
        _chain: &Chain,
        _wallet_id_filter: Option<&[String]>,
    ) -> Result<(), EngineError> {
        Err(EngineError::MerkletreeNotPorted(
            "full_rescan_utxo_merkletrees_and_wallets",
        ))
    }

    /// `RailgunEngine.getLatestRailgunTxidData` — delegates to the injected
    /// validated-txid provider when available.
    pub async fn get_latest_railgun_txid_data(
        &self,
        txid_version: TXIDVersion,
        chain: &Chain,
    ) -> Result<LatestValidatedRailgunTxid, EngineError> {
        match &self.get_latest_validated_railgun_txid {
            Some(p) => {
                p.get_latest_validated_railgun_txid(txid_version, chain)
                    .await
            }
            None => Ok(LatestValidatedRailgunTxid::default()),
        }
    }

    /// `RailgunEngine.unload` — drop all loaded networks.
    pub fn unload(&mut self) {
        self.loaded_networks.clear();
    }

    /// `RailgunEngine.encodeAddress` (static).
    pub fn encode_address(data: &AddressData) -> String {
        encode_address(data)
    }

    /// `RailgunEngine.decodeAddress` (static).
    pub fn decode_address(address: &str) -> Result<AddressData, AddressError> {
        decode_address(address)
    }
}
