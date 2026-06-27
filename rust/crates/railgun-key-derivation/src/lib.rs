//! `railgun-key-derivation` — BIP39, the custom BabyJubJub BIP32 derivation,
//! wallet keys, and `0zk` bech32m addresses (port of `src/key-derivation/`).

pub mod address;
pub mod bip32;
pub mod bip39;
pub mod chain;
pub mod wallet_node;

pub use address::{decode_address, encode_address, AddressData, AddressError, ADDRESS_LENGTH_LIMIT};
pub use bip32::{
    child_key_derivation_hardened, get_master_key_from_seed, get_path_segments, KeyNode,
    HARDENED_OFFSET,
};
pub use bip39::{Mnemonic, MnemonicError};
pub use chain::{get_chain_full_network_id, Chain, ChainType};
pub use wallet_node::{
    derive_nodes, SpendingKeyPair, SpendingPublicKey, ViewingKeyPair, WalletNode, WalletNodes,
};
