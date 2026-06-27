//! Port of `src/wallet/view-only-wallet.ts` — `ViewOnlyWallet`.

use railgun_crypto::{get_public_viewing_key, sha256};
use railgun_db::{Database, KvStore};
use railgun_key_derivation::ViewingKeyPair;
use railgun_models::wallet_types::ViewOnlyWalletData;
use railgun_utils::hex_string_to_bytes;

use crate::abstract_wallet::{AbstractWallet, StoredWalletData, WalletError};

/// `ViewOnlyWallet` — derived from a shareable viewing key (no spending key).
pub struct ViewOnlyWallet<S: KvStore> {
    pub wallet: AbstractWallet<S>,
}

impl<S: KvStore> ViewOnlyWallet<S> {
    /// `ViewOnlyWallet.generateID` — `sha256(shareableViewingKey)` over the bytes
    /// of the hex string.
    pub fn generate_id(shareable_viewing_key: &str) -> String {
        // TS: sha256(shareableViewingKey) — bytesLikeify arrayifies the hex string.
        let bytes = railgun_utils::arrayify(&railgun_utils::BytesData::Hex(
            shareable_viewing_key.to_string(),
        ))
        .expect("valid hex");
        sha256(&bytes)
    }

    fn viewing_key_pair(viewing_private_key: &str) -> ViewingKeyPair {
        let vpk_bytes: [u8; 32] = hex_string_to_bytes(viewing_private_key)
            .expect("valid viewing private key")
            .try_into()
            .expect("32 bytes");
        ViewingKeyPair {
            private_key: vpk_bytes,
            pubkey: get_public_viewing_key(&vpk_bytes),
        }
    }

    pub(crate) fn create_wallet(
        id: &str,
        shareable_viewing_key: &str,
        creation_block_numbers: Option<Vec<Vec<u64>>>,
    ) -> Result<Self, WalletError> {
        let (viewing_private_key, spending_public_key) =
            AbstractWallet::<S>::get_keys_from_shareable_viewing_key(shareable_viewing_key)?;
        let viewing_key_pair = Self::viewing_key_pair(&viewing_private_key);
        Ok(ViewOnlyWallet {
            wallet: AbstractWallet::new(
                id,
                viewing_key_pair,
                spending_public_key,
                creation_block_numbers,
            ),
        })
    }

    /// `ViewOnlyWallet.fromShareableViewingKey`.
    pub fn from_shareable_viewing_key(
        db: &mut Database<S>,
        encryption_key: &[u8],
        shareable_viewing_key: &str,
        creation_block_numbers: Option<Vec<Vec<u64>>>,
    ) -> Result<Self, WalletError> {
        let id = Self::generate_id(shareable_viewing_key);
        AbstractWallet::write_wallet_data(
            db,
            &id,
            encryption_key,
            &StoredWalletData::ViewOnly(ViewOnlyWalletData {
                shareable_viewing_key: shareable_viewing_key.to_string(),
                creation_block_numbers: creation_block_numbers.clone(),
            }),
        )?;
        Self::create_wallet(&id, shareable_viewing_key, creation_block_numbers)
    }

    /// `ViewOnlyWallet.loadExisting`.
    pub fn load_existing(
        db: &Database<S>,
        encryption_key: &[u8],
        id: &str,
    ) -> Result<Self, WalletError> {
        let data = AbstractWallet::read_wallet_data(db, id, encryption_key)?;
        let StoredWalletData::ViewOnly(ViewOnlyWalletData {
            shareable_viewing_key,
            creation_block_numbers,
        }) = data
        else {
            return Err(WalletError::IncorrectWalletType);
        };
        Self::create_wallet(id, &shareable_viewing_key, creation_block_numbers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::railgun_wallet::RailgunWallet;
    use railgun_db::Database;
    use railgun_utils::{arrayify, BytesData};

    const MNEMONIC: &str = "test test test test test test test test test test test junk";
    const ENCRYPTION_KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    fn enc_key() -> Vec<u8> {
        arrayify(&BytesData::Hex(ENCRYPTION_KEY.to_string())).unwrap()
    }

    // railgun-wallet.test.ts: a view-only wallet from a full wallet's shareable
    // viewing key reproduces the same address keys, and loads round-trip.
    #[test]
    fn view_only_from_shareable_matches_full_wallet() {
        let mut db = Database::in_memory();
        let full = RailgunWallet::from_mnemonic(&mut db, &enc_key(), MNEMONIC, 0, None).unwrap();
        let shareable = full.wallet.generate_shareable_viewing_key().unwrap();

        let view_only =
            ViewOnlyWallet::from_shareable_viewing_key(&mut db, &enc_key(), &shareable, None)
                .unwrap();

        // Same address + masterPublicKey as the full wallet.
        assert_eq!(
            view_only.wallet.get_address(None),
            full.wallet.get_address(None)
        );
        assert_eq!(
            view_only.wallet.master_public_key(),
            full.wallet.master_public_key()
        );

        // Round-trips through the DB.
        let loaded = ViewOnlyWallet::load_existing(&db, &enc_key(), &view_only.wallet.id).unwrap();
        assert_eq!(loaded.wallet.id, view_only.wallet.id);
        assert_eq!(
            loaded.wallet.get_address(None),
            view_only.wallet.get_address(None)
        );
    }
}
