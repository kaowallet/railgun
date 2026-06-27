//! Injected RPC provider trait + `eth_getLogs` chunk/retry constants.
//!
//! Port of the provider seam from `src/provider/*` and the scan constants in
//! `src/contracts/railgun-smart-wallet/V2/railgun-smart-wallet.ts`.
//!
//! **No hard-coded HTTP.** The SDK only fetches via Ethereum JSON-RPC; the
//! caller supplies an [`EventProvider`] implementation (e.g. alloy + reqwest).
//! The engine/contracts layer issues calls through this trait.

use async_trait::async_trait;

use crate::ContractError;

/// `SCAN_CHUNKS` — `eth_getLogs` block-range chunk size.
pub const SCAN_CHUNKS: u64 = 499;
/// Maximum number of `eth_getLogs` retries before giving up.
pub const MAX_GET_LOGS_RETRIES: u32 = 30;
/// Maximum exponential-backoff delay between retries, in milliseconds.
pub const MAX_GET_LOGS_RETRY_BACKOFF_MS: u64 = 30_000;
/// Default polling interval for `eth_getBlockNumber`, in milliseconds.
pub const DEFAULT_POLLING_INTERVAL_MS: u64 = 10_000;

/// A raw EVM log: topic0..topicN + ABI-encoded data + block number.
#[derive(Clone, Debug)]
pub struct RawLog {
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
    pub block_number: u64,
    pub transaction_hash: String,
    pub log_index: u64,
}

/// An `eth_getLogs` filter for one address + topic0 over a block range.
#[derive(Clone, Debug)]
pub struct LogFilter {
    pub address: String,
    pub topic0: Option<[u8; 32]>,
    pub from_block: u64,
    pub to_block: u64,
}

/// `EventProvider` — injected JSON-RPC seam. The caller implements this.
#[async_trait]
pub trait EventProvider: Send + Sync {
    /// `eth_getBlockNumber`.
    async fn get_block_number(&self) -> Result<u64, ContractError>;

    /// `eth_getLogs` for a single filter (already chunked by the caller of the
    /// higher-level scan loop, or chunk internally using [`SCAN_CHUNKS`]).
    async fn get_logs(&self, filter: &LogFilter) -> Result<Vec<RawLog>, ContractError>;

    /// `eth_call` returning the raw ABI-encoded return bytes.
    async fn call(&self, to: &str, data: &[u8]) -> Result<Vec<u8>, ContractError>;
}
