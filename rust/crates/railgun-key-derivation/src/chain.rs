//! `Chain` / `ChainType` now live in `railgun-models` (their canonical home).
//! This module re-exports them for back-compat with the rest of this crate.

pub use railgun_models::engine_types::{get_chain_full_network_id, Chain, ChainType};
