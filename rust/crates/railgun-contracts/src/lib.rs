//! `railgun-contracts` — V2 + V3 RAILGUN smart-contract layer.
//!
//! Faithful port of `src/contracts/**`, `src/provider/*`, `src/chain/chain.ts`
//! and `src/abi/abi.ts`. Scope is **V2 + V3 only** (RailgunSmartWallet,
//! RelayAdapt, PoseidonMerkleAccumulator, PoseidonMerkleVerifier, TokenVault);
//! the V1/legacy commitment/event/ABI paths are intentionally skipped.
//!
//! ## Layout
//! - [`chain`] — `getChainFullNetworkID` (1-byte type + 7-byte id) KAV.
//! - [`abi`] — alloy `sol!` bindings for the V2/V3 contracts + RelayAdapt.
//! - [`relay_adapt`] — RelayAdapt helpers: adapt-params hashing (ABI-encode +
//!   keccak256), call/random formatting, and the custom error-prefix parsing
//!   (`0x5c0dee5d` / `0x08c379a0`) — all pure + unit-tested against the TS KAVs.
//! - [`events`] — typed commitment / nullifier / unshield event decoding (V2+V3).
//! - [`provider`] — the injected [`provider::EventProvider`] RPC trait and the
//!   `eth_getLogs` chunk/retry constants. **No hard-coded HTTP**: the caller
//!   supplies the provider implementation (per the port plan).

pub mod abi;
pub mod chain;
pub mod events;
pub mod provider;
pub mod relay_adapt;

pub use chain::{add_chain_supports_v3, assert_chain_supports_v3, get_chain_supports_v3};
pub use relay_adapt::{
    error::{
        extract_gas_estimate_call_failed_index_and_error_text, get_relay_adapt_call_error,
        parse_relay_adapt_return_value, RelayAdaptReturnValue, CALL_ERROR_TOPIC,
        RETURN_DATA_RELAY_ADAPT_STRING_PREFIX, RETURN_DATA_STRING_PREFIX,
    },
    helper::{format_calls, format_random, get_action_data, get_relay_adapt_params, ContractCall},
    MINIMUM_RELAY_ADAPT_CROSS_CONTRACT_CALLS_GAS_LIMIT_V2,
};

/// Crate-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("bytes error: {0}")]
    Bytes(#[from] railgun_utils::BytesError),
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("abi decode error: {0}")]
    AbiDecode(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("unsupported txid version")]
    UnsupportedTxidVersion,
    #[error("provider error: {0}")]
    Provider(String),
}
