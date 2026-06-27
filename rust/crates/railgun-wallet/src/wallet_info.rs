//! Port of `src/wallet/wallet-info.ts` — `WalletInfo`.
//!
//! The base-37 wallet-source codec already lives in `railgun-note::wallet_info`
//! (note annotation data needs it). This module adds the stateful `WalletInfo`
//! wrapper the TS SDK exposes: a process-global lowercased `walletSource` plus
//! the validate / encode / decode statics.

use std::sync::RwLock;

pub use railgun_note::wallet_info::{
    decode_wallet_source, get_encoded_wallet_source, validate_wallet_source, WalletInfoError,
};

static WALLET_SOURCE: RwLock<Option<String>> = RwLock::new(None);

/// `WalletInfo` — mirrors the TS class's static surface.
pub struct WalletInfo;

impl WalletInfo {
    /// `WalletInfo.setWalletSource` — validate then store the lowercased source.
    pub fn set_wallet_source(wallet_source: &str) -> Result<(), WalletInfoError> {
        let lowercase = wallet_source.to_lowercase();
        validate_wallet_source(&lowercase)?;
        *WALLET_SOURCE.write().unwrap() = Some(lowercase);
        Ok(())
    }

    /// `WalletInfo.walletSource` getter.
    pub fn wallet_source() -> Option<String> {
        WALLET_SOURCE.read().unwrap().clone()
    }

    /// `WalletInfo.getEncodedWalletSource`.
    pub fn get_encoded_wallet_source(wallet_source: &str) -> Result<String, WalletInfoError> {
        get_encoded_wallet_source(wallet_source)
    }

    /// `WalletInfo.decodeWalletSource`.
    pub fn decode_wallet_source(bytes: &str) -> String {
        decode_wallet_source(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // src/wallet/__tests__/wallet-info.test.ts
    #[test]
    fn encode_and_decode_wallet_source() {
        let wallet_source = "New Wallet";
        WalletInfo::set_wallet_source(wallet_source).unwrap();
        let encoded = WalletInfo::get_encoded_wallet_source(wallet_source).unwrap();
        assert_eq!(WalletInfo::wallet_source().as_deref(), Some("new wallet"));
        assert_eq!(WalletInfo::decode_wallet_source(&encoded), "new wallet");
    }

    #[test]
    fn fails_for_invalid_wallet_source() {
        assert!(WalletInfo::set_wallet_source("!@#$%").is_err());
    }
}
