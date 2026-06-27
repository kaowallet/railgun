//! `railgun-wallet` — full / view-only / multisig / hardware RAILGUN wallets.
//!
//! Port of `src/wallet/*.ts`. Scope (per PORT_PLAN.md phase 5):
//!
//! - `abstract_wallet` — shared core: key/address derivation, DB path
//!   construction, encrypted read/write, note decryption + commitment scanning
//!   (`scanLeaves`), wallet-details persistence, shareable-viewing-key codec.
//! - `railgun_wallet` — full wallet (mnemonic-backed), EdDSA-Poseidon signing.
//! - `view_only_wallet` — derived from a shareable viewing key.
//! - `hardware_wallet` — view-only wallet that delegates signing to an injected
//!   `ExternalSignerConnector` trait.
//! - `wallet_info` — base-37 wallet-source codec + stateful wrapper.
//!
//! Balance aggregation / POI / history that need a live merkletree + RPC are
//! kept behind injected traits and recorded as TODOs.

pub mod abstract_wallet;
pub mod hardware_wallet;
pub mod railgun_wallet;
pub mod view_only_wallet;
pub mod wallet_info;

pub use abstract_wallet::{
    public_inputs_message_hash, AbstractWallet, StoredWalletData, WalletError, WalletKeys,
    CURRENT_UTXO_MERKLETREE_HISTORY_VERSION,
};
pub use hardware_wallet::{
    ConnectorError, ExternalSignerConnector, HardwareWallet, PublicInputsRailgun,
};
pub use railgun_wallet::RailgunWallet;
pub use view_only_wallet::ViewOnlyWallet;
pub use wallet_info::WalletInfo;
