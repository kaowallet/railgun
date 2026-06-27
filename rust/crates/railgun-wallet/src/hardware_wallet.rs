//! Port of `src/wallet/hardware-wallet.ts` — `HardwareWallet`.
//!
//! A hardware wallet is a view-only wallet that delegates EdDSA signing to an
//! external signer (the `ExternalSignerConnector`). It stores only a shareable
//! viewing key; the spending private key never leaves the device.

use async_trait::async_trait;
use num_bigint::BigUint;

use railgun_crypto::{get_public_viewing_key, sha256, Signature};
use railgun_db::{Database, KvStore};
use railgun_key_derivation::{SpendingPublicKey, ViewingKeyPair};
use railgun_models::wallet_types::ViewOnlyWalletData;
use railgun_utils::hex_string_to_bytes;

use crate::abstract_wallet::{
    public_inputs_message_hash, AbstractWallet, StoredWalletData, WalletError,
};

/// Railgun public inputs passed to the external signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputsRailgun {
    pub merkle_root: BigUint,
    pub bound_params_hash: BigUint,
    pub nullifiers: Vec<BigUint>,
    pub commitments_out: Vec<BigUint>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error("External signer connector not initialized.")]
    NotInitialized,
    #[error("{0}")]
    Signer(String),
}

/// `ExternalSignerConnector` — the caller-implemented bridge to a hardware
/// signer. `sign` returns an EdDSA-Poseidon `(R8, S)` signature; the optional
/// `request_batch_approval` mirrors the TS optional method.
#[async_trait]
pub trait ExternalSignerConnector: Send + Sync {
    async fn sign(
        &self,
        expected_hash: BigUint,
        public_inputs: Option<PublicInputsRailgun>,
        sub_session: Option<String>,
    ) -> Result<Signature, ConnectorError>;

    async fn request_batch_approval(
        &self,
        _requests: &[serde_json::Value],
    ) -> Result<Option<String>, ConnectorError> {
        Ok(None)
    }
}

/// `HardwareWallet`.
pub struct HardwareWallet<S: KvStore> {
    pub wallet: AbstractWallet<S>,
    stored_spending_public_key: SpendingPublicKey,
    connector: Option<Box<dyn ExternalSignerConnector>>,
}

impl<S: KvStore> HardwareWallet<S> {
    fn generate_hardware_id(shareable_viewing_key: &str) -> String {
        // TS: sha256(shareableViewingKey) — the hex string is arrayified first.
        let bytes = railgun_utils::arrayify(&railgun_utils::BytesData::Hex(
            shareable_viewing_key.to_string(),
        ))
        .expect("valid hex");
        sha256(&bytes)
    }

    fn hardware_viewing_key_pair(viewing_private_key: &str) -> ViewingKeyPair {
        let vpk: [u8; 32] = hex_string_to_bytes(viewing_private_key)
            .expect("valid viewing private key")
            .try_into()
            .expect("32 bytes");
        ViewingKeyPair {
            private_key: vpk,
            pubkey: get_public_viewing_key(&vpk),
        }
    }

    fn create_hardware_wallet(
        id: &str,
        shareable_viewing_key: &str,
        creation_block_numbers: Option<Vec<Vec<u64>>>,
    ) -> Result<Self, WalletError> {
        let (viewing_private_key, spending_public_key) =
            AbstractWallet::<S>::get_keys_from_shareable_viewing_key(shareable_viewing_key)?;
        let viewing_key_pair = Self::hardware_viewing_key_pair(&viewing_private_key);
        Ok(HardwareWallet {
            wallet: AbstractWallet::new(
                id,
                viewing_key_pair,
                spending_public_key.clone(),
                creation_block_numbers,
            ),
            stored_spending_public_key: spending_public_key,
            connector: None,
        })
    }

    /// `HardwareWallet.fromShareableViewingKey`.
    pub fn from_shareable_viewing_key(
        db: &mut Database<S>,
        encryption_key: &[u8],
        shareable_viewing_key: &str,
        creation_block_numbers: Option<Vec<Vec<u64>>>,
    ) -> Result<Self, WalletError> {
        let id = Self::generate_hardware_id(shareable_viewing_key);
        AbstractWallet::write_wallet_data(
            db,
            &id,
            encryption_key,
            &StoredWalletData::ViewOnly(ViewOnlyWalletData {
                shareable_viewing_key: shareable_viewing_key.to_string(),
                creation_block_numbers: creation_block_numbers.clone(),
            }),
        )?;
        Self::create_hardware_wallet(&id, shareable_viewing_key, creation_block_numbers)
    }

    /// `HardwareWallet.loadExisting`.
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
        Self::create_hardware_wallet(id, &shareable_viewing_key, creation_block_numbers)
    }

    pub fn set_connector(&mut self, connector: Box<dyn ExternalSignerConnector>) {
        self.connector = Some(connector);
    }

    /// `getSpendingKeyPair` — the hardware wallet exposes only the public key;
    /// the private key is all-zero (held on the device).
    pub fn stored_spending_public_key(&self) -> &SpendingPublicKey {
        &self.stored_spending_public_key
    }

    /// `requestBatchApproval` — optional, delegated to the connector.
    pub async fn request_batch_approval(
        &self,
        requests: &[serde_json::Value],
    ) -> Result<Option<String>, ConnectorError> {
        match &self.connector {
            Some(c) => c.request_batch_approval(requests).await,
            None => Ok(None),
        }
    }

    /// `sign` — hash the public inputs, then delegate to the external connector.
    pub async fn sign(
        &self,
        public_inputs: PublicInputsRailgun,
        sub_session: &str,
    ) -> Result<Signature, ConnectorError> {
        let connector = self
            .connector
            .as_ref()
            .ok_or(ConnectorError::NotInitialized)?;
        let expected_hash = public_inputs_message_hash(
            &public_inputs.merkle_root,
            &public_inputs.bound_params_hash,
            &public_inputs.nullifiers,
            &public_inputs.commitments_out,
        );
        let sub = if sub_session.is_empty() {
            None
        } else {
            Some(sub_session.to_string())
        };
        connector
            .sign(expected_hash, Some(public_inputs), sub)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use railgun_crypto::Signature;
    use railgun_db::{Database, MemStore};
    use std::sync::Mutex;

    // hardware-wallet.test.ts: testEncryptionKey + testSharedViewingKey
    const ENCRYPTION_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SHARED_VIEWING_KEY: &str = "82a57670726976d94034326232623861643234306331323630396633623265363865656137613636373330306437373332633335346238373338343266373433313135313836303066a473707562d94061316166356531353935616330303736303734646465653034323737356230363365366434653666313966613632633333323935636336643363646635313165";

    fn enc_key() -> Vec<u8> {
        railgun_utils::arrayify(&railgun_utils::BytesData::Hex(ENCRYPTION_KEY.to_string())).unwrap()
    }

    fn sig(r0: u64, r1: u64, s: u64) -> Signature {
        Signature {
            r8: (BigUint::from(r0), BigUint::from(r1)),
            s: BigUint::from(s),
        }
    }

    /// Records what the connector received and returns a fixed signature.
    struct RecordingConnector {
        signature: Signature,
        received: Mutex<Option<(BigUint, Option<PublicInputsRailgun>, Option<String>)>>,
    }

    #[async_trait]
    impl ExternalSignerConnector for RecordingConnector {
        async fn sign(
            &self,
            expected_hash: BigUint,
            public_inputs: Option<PublicInputsRailgun>,
            sub_session: Option<String>,
        ) -> Result<Signature, ConnectorError> {
            *self.received.lock().unwrap() = Some((expected_hash, public_inputs, sub_session));
            Ok(self.signature.clone())
        }
    }

    fn new_hardware_wallet() -> (Database<MemStore>, HardwareWallet<MemStore>) {
        let mut db = Database::in_memory();
        let wallet = HardwareWallet::from_shareable_viewing_key(
            &mut db,
            &enc_key(),
            SHARED_VIEWING_KEY,
            None,
        )
        .unwrap();
        (db, wallet)
    }

    // hardware-wallet.test.ts: 'delegates signing to the external signer connector'
    #[tokio::test]
    async fn delegates_signing_to_connector() {
        let (_db, mut wallet) = new_hardware_wallet();
        let public_inputs = PublicInputsRailgun {
            merkle_root: BigUint::from(11u32),
            bound_params_hash: BigUint::from(12u32),
            nullifiers: vec![BigUint::from(13u32), BigUint::from(14u32)],
            commitments_out: vec![BigUint::from(15u32), BigUint::from(16u32)],
        };
        let signature = sig(21, 22, 23);
        let connector = RecordingConnector {
            signature: signature.clone(),
            received: Mutex::new(None),
        };
        // Wrap in Arc so we can inspect `received` after the call.
        let connector = std::sync::Arc::new(connector);
        wallet.set_connector(Box::new(ArcConnector(connector.clone())));

        let result = wallet
            .sign(public_inputs.clone(), "batch-sub-session")
            .await
            .unwrap();
        assert_eq!(result, signature);

        let received = connector.received.lock().unwrap().clone().unwrap();
        // expectedHash is the poseidon of the public inputs.
        let expected = public_inputs_message_hash(
            &public_inputs.merkle_root,
            &public_inputs.bound_params_hash,
            &public_inputs.nullifiers,
            &public_inputs.commitments_out,
        );
        assert_eq!(received.0, expected);
        assert_eq!(received.1.as_ref(), Some(&public_inputs));
        assert_eq!(received.2.as_deref(), Some("batch-sub-session"));
    }

    // Delegating wrapper so the test can keep a handle to the connector.
    struct ArcConnector(std::sync::Arc<RecordingConnector>);
    #[async_trait]
    impl ExternalSignerConnector for ArcConnector {
        async fn sign(
            &self,
            expected_hash: BigUint,
            public_inputs: Option<PublicInputsRailgun>,
            sub_session: Option<String>,
        ) -> Result<Signature, ConnectorError> {
            self.0.sign(expected_hash, public_inputs, sub_session).await
        }
    }

    // hardware-wallet.test.ts: 'treats batch approval as optional'
    #[tokio::test]
    async fn batch_approval_optional() {
        let (_db, mut wallet) = new_hardware_wallet();
        struct SignOnly;
        #[async_trait]
        impl ExternalSignerConnector for SignOnly {
            async fn sign(
                &self,
                _h: BigUint,
                _pi: Option<PublicInputsRailgun>,
                _ss: Option<String>,
            ) -> Result<Signature, ConnectorError> {
                Ok(Signature {
                    r8: (BigUint::from(1u32), BigUint::from(2u32)),
                    s: BigUint::from(3u32),
                })
            }
        }
        wallet.set_connector(Box::new(SignOnly));
        let result = wallet.request_batch_approval(&[]).await.unwrap();
        assert_eq!(result, None);
    }

    // hardware-wallet.test.ts: 'delegates batch approval when the connector provides it'
    #[tokio::test]
    async fn batch_approval_delegated() {
        let (_db, mut wallet) = new_hardware_wallet();
        struct WithApproval;
        #[async_trait]
        impl ExternalSignerConnector for WithApproval {
            async fn sign(
                &self,
                _h: BigUint,
                _pi: Option<PublicInputsRailgun>,
                _ss: Option<String>,
            ) -> Result<Signature, ConnectorError> {
                Ok(Signature {
                    r8: (BigUint::from(1u32), BigUint::from(2u32)),
                    s: BigUint::from(3u32),
                })
            }
            async fn request_batch_approval(
                &self,
                _requests: &[serde_json::Value],
            ) -> Result<Option<String>, ConnectorError> {
                Ok(Some("batch-sub-session".to_string()))
            }
        }
        wallet.set_connector(Box::new(WithApproval));
        let requests = vec![serde_json::json!({ "transaction": {} })];
        let result = wallet.request_batch_approval(&requests).await.unwrap();
        assert_eq!(result, Some("batch-sub-session".to_string()));
    }

    // hardware-wallet.test.ts: derived id matches sha256(shareableViewingKey)
    #[test]
    fn hardware_id_and_load() {
        let (db, wallet) = new_hardware_wallet();
        let expected = {
            let bytes = railgun_utils::arrayify(&railgun_utils::BytesData::Hex(
                SHARED_VIEWING_KEY.to_string(),
            ))
            .unwrap();
            railgun_crypto::sha256(&bytes)
        };
        assert_eq!(wallet.wallet.id, expected);

        let loaded = HardwareWallet::load_existing(&db, &enc_key(), &wallet.wallet.id).unwrap();
        assert_eq!(loaded.wallet.id, wallet.wallet.id);
        // The view-only-derived address matches.
        assert_eq!(
            loaded.wallet.get_address(None),
            wallet.wallet.get_address(None)
        );
    }

    // sign with no connector errors.
    #[tokio::test]
    async fn sign_without_connector_errors() {
        let (_db, wallet) = new_hardware_wallet();
        let public_inputs = PublicInputsRailgun {
            merkle_root: BigUint::from(1u32),
            bound_params_hash: BigUint::from(2u32),
            nullifiers: vec![BigUint::from(3u32)],
            commitments_out: vec![BigUint::from(4u32)],
        };
        assert!(matches!(
            wallet.sign(public_inputs, "").await,
            Err(ConnectorError::NotInitialized)
        ));
    }
}
