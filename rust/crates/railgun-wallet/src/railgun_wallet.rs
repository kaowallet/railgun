//! Port of `src/wallet/railgun-wallet.ts` — `RailgunWallet` (full wallet).

use num_bigint::BigUint;

use railgun_crypto::{sha256, sign_eddsa, Signature};
use railgun_db::{Database, KvStore};
use railgun_key_derivation::{derive_nodes, Mnemonic, SpendingKeyPair};
use railgun_models::wallet_types::WalletData;
use railgun_utils::{arrayify, combine, BytesData};

use crate::abstract_wallet::{
    public_inputs_message_hash, AbstractWallet, StoredWalletData, WalletError,
};

/// `RailgunWallet` — a full wallet backed by a stored mnemonic.
pub struct RailgunWallet<S: KvStore> {
    pub wallet: AbstractWallet<S>,
}

impl<S: KvStore> RailgunWallet<S> {
    /// `RailgunWallet.generateID` — `sha256(combine([seed, index.toString(16)]))`,
    /// where `combine` concatenates hex strings and `sha256` hashes the bytes.
    pub fn generate_id(mnemonic: &str, index: u32, mnemonic_password: &str) -> String {
        let seed = Mnemonic::to_seed(mnemonic, mnemonic_password).expect("valid mnemonic");
        let combined = combine(&[seed, format!("{index:x}")]);
        let bytes = arrayify(&BytesData::Hex(combined)).expect("valid hex");
        sha256(&bytes)
    }

    fn assert_mnemonic_password_matches_id(
        id: &str,
        mnemonic: &str,
        index: u32,
        mnemonic_password: &str,
    ) -> Result<(), WalletError> {
        if Self::generate_id(mnemonic, index, mnemonic_password) != id {
            return Err(WalletError::IncorrectMnemonicPassword);
        }
        Ok(())
    }

    fn create_wallet(
        id: &str,
        mnemonic: &str,
        mnemonic_password: &str,
        index: u32,
        creation_block_numbers: Option<Vec<Vec<u64>>>,
    ) -> Self {
        let nodes = derive_nodes(mnemonic, index, mnemonic_password);
        let viewing_key_pair = nodes.viewing.get_viewing_key_pair();
        let spending_public_key = nodes.spending.get_spending_key_pair().pubkey;
        RailgunWallet {
            wallet: AbstractWallet::new(
                id,
                viewing_key_pair,
                spending_public_key,
                creation_block_numbers,
            ),
        }
    }

    /// `RailgunWallet.fromMnemonic` (no BIP39 password).
    pub fn from_mnemonic(
        db: &mut Database<S>,
        encryption_key: &[u8],
        mnemonic: &str,
        index: u32,
        creation_block_numbers: Option<Vec<Vec<u64>>>,
    ) -> Result<Self, WalletError> {
        Self::from_mnemonic_with_password(
            db,
            encryption_key,
            mnemonic,
            "",
            index,
            creation_block_numbers,
        )
    }

    /// `RailgunWallet.fromMnemonicWithPassword`.
    pub fn from_mnemonic_with_password(
        db: &mut Database<S>,
        encryption_key: &[u8],
        mnemonic: &str,
        mnemonic_password: &str,
        index: u32,
        creation_block_numbers: Option<Vec<Vec<u64>>>,
    ) -> Result<Self, WalletError> {
        let id = Self::generate_id(mnemonic, index, mnemonic_password);
        // The BIP39 password is intentionally NOT persisted.
        AbstractWallet::write_wallet_data(
            db,
            &id,
            encryption_key,
            &StoredWalletData::Full(WalletData {
                mnemonic: mnemonic.to_string(),
                index,
                creation_block_numbers: creation_block_numbers.clone(),
            }),
        )?;
        Ok(Self::create_wallet(
            &id,
            mnemonic,
            mnemonic_password,
            index,
            creation_block_numbers,
        ))
    }

    /// `RailgunWallet.loadExisting`.
    pub fn load_existing(
        db: &Database<S>,
        encryption_key: &[u8],
        id: &str,
        mnemonic_password: Option<&str>,
    ) -> Result<Self, WalletError> {
        let data = AbstractWallet::read_wallet_data(db, id, encryption_key)?;
        let StoredWalletData::Full(WalletData {
            mnemonic,
            index,
            creation_block_numbers,
        }) = data
        else {
            return Err(WalletError::IncorrectWalletType);
        };
        let password = mnemonic_password.unwrap_or("");
        Self::assert_mnemonic_password_matches_id(id, &mnemonic, index, password)?;
        Ok(Self::create_wallet(
            id,
            &mnemonic,
            password,
            index,
            creation_block_numbers,
        ))
    }

    /// `getSpendingKeyPair` — re-derive the spending node from the stored
    /// mnemonic (verifying the supplied password reproduces the wallet ID).
    pub fn get_spending_key_pair(
        &self,
        db: &Database<S>,
        encryption_key: &[u8],
        mnemonic_password: Option<&str>,
    ) -> Result<SpendingKeyPair, WalletError> {
        let data = AbstractWallet::read_wallet_data(db, &self.wallet.id, encryption_key)?;
        let StoredWalletData::Full(WalletData {
            mnemonic, index, ..
        }) = data
        else {
            return Err(WalletError::IncorrectWalletType);
        };
        let password = mnemonic_password.unwrap_or("");
        Self::assert_mnemonic_password_matches_id(&self.wallet.id, &mnemonic, index, password)?;
        Ok(derive_nodes(&mnemonic, index, password)
            .spending
            .get_spending_key_pair())
    }

    /// `getChainAddress` — the EVM (0x) address for the wallet's account.
    pub fn get_chain_address(
        &self,
        db: &Database<S>,
        encryption_key: &[u8],
        mnemonic_password: Option<&str>,
    ) -> Result<String, WalletError> {
        let data = AbstractWallet::read_wallet_data(db, &self.wallet.id, encryption_key)?;
        let StoredWalletData::Full(WalletData {
            mnemonic, index, ..
        }) = data
        else {
            return Err(WalletError::IncorrectWalletType);
        };
        let password = mnemonic_password.unwrap_or("");
        Self::assert_mnemonic_password_matches_id(&self.wallet.id, &mnemonic, index, password)?;
        Mnemonic::to_0x_address(&mnemonic, Some(index), password)
            .map_err(|_| WalletError::IncorrectWalletType)
    }

    /// `sign` — EdDSA-Poseidon over the railgun public inputs.
    pub fn sign(
        &self,
        db: &Database<S>,
        merkle_root: &BigUint,
        bound_params_hash: &BigUint,
        nullifiers: &[BigUint],
        commitments_out: &[BigUint],
        encryption_key: &[u8],
        mnemonic_password: Option<&str>,
    ) -> Result<Signature, WalletError> {
        let spending_key_pair =
            self.get_spending_key_pair(db, encryption_key, mnemonic_password)?;
        let msg =
            public_inputs_message_hash(merkle_root, bound_params_hash, nullifiers, commitments_out);
        Ok(sign_eddsa(&spending_key_pair.private_key, &msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Num;
    use railgun_crypto::{verify_ed25519, verify_eddsa};
    use railgun_db::{Database, MemStore};
    use railgun_key_derivation::{Chain, ChainType};
    use railgun_utils::{arrayify, BytesData};

    // src/test/config.test.ts
    const MNEMONIC: &str = "test test test test test test test test test test test junk";
    const ENCRYPTION_KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    fn enc_key() -> Vec<u8> {
        arrayify(&BytesData::Hex(ENCRYPTION_KEY.to_string())).unwrap()
    }

    fn chain(id: u64) -> Chain {
        Chain {
            chain_type: ChainType::Evm as u8,
            id,
        }
    }

    fn new_wallet() -> (Database<MemStore>, RailgunWallet<MemStore>) {
        let mut db = Database::in_memory();
        let wallet = RailgunWallet::from_mnemonic(&mut db, &enc_key(), MNEMONIC, 0, None).unwrap();
        (db, wallet)
    }

    fn big(s: &str) -> BigUint {
        BigUint::from_str_radix(s, 10).unwrap()
    }

    // railgun-wallet.test.ts: 'Should get wallet prefix path'
    #[test]
    fn wallet_id_is_sha256_seed_index() {
        let (_db, wallet) = new_wallet();
        // path[1] === sha256(combine([toSeed(mnemonic), '00'])) === wallet.id
        let seed = Mnemonic::to_seed(MNEMONIC, "").unwrap();
        let combined = combine(&[seed, "00".to_string()]);
        let bytes = arrayify(&BytesData::Hex(combined)).unwrap();
        let expected = sha256(&bytes);
        assert_eq!(wallet.wallet.id, expected);
        assert_eq!(
            wallet.wallet.id,
            "bee63912e0e4cfa6830ebc8342d3efa9aa1336548c77bf4336c54c17409f2990"
        );
    }

    // railgun-wallet.test.ts: 'Should get wallet prefix path'
    #[test]
    fn wallet_db_prefix() {
        let (_db, wallet) = new_wallet();
        let path: Vec<String> = wallet
            .wallet
            .get_wallet_db_prefix(&chain(1), None, None)
            .iter()
            .map(|el| railgun_utils::hexlify(el, false))
            .collect();
        assert_eq!(
            path,
            vec![
                "000000000000000000000000000000000000000000000000000077616c6c6574",
                "bee63912e0e4cfa6830ebc8342d3efa9aa1336548c77bf4336c54c17409f2990",
                "0000000000000000000000000000000000000000000000000000000000000001",
            ]
        );
    }

    // railgun-wallet.test.ts: 'Should get wallet details path'
    #[test]
    fn wallet_details_path() {
        let (_db, wallet) = new_wallet();
        let path: Vec<String> = wallet
            .wallet
            .get_wallet_details_path(&chain(1))
            .iter()
            .map(|el| railgun_utils::hexlify(el, false))
            .collect();
        assert_eq!(
            path,
            vec![
                "000000000000000000000000000000000000000000000000000077616c6c6574",
                "bee63912e0e4cfa6830ebc8342d3efa9aa1336548c77bf4336c54c17409f2990",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "64657461696c73",
            ]
        );
    }

    // railgun-wallet.test.ts: 'Should get viewing keypair'
    #[test]
    fn viewing_keypair() {
        let (_db, wallet) = new_wallet();
        let kp = wallet.wallet.get_viewing_key_pair();
        assert_eq!(
            kp.private_key.to_vec(),
            vec![
                157, 164, 180, 240, 181, 73, 58, 107, 163, 247, 223, 6, 17, 195, 224, 132, 47, 126,
                43, 179, 214, 64, 243, 19, 178, 53, 241, 183, 92, 29, 128, 185,
            ]
        );
        assert_eq!(
            kp.pubkey.to_vec(),
            vec![
                119, 215, 170, 124, 91, 151, 128, 96, 190, 43, 167, 140, 188, 14, 249, 42, 79, 58,
                163, 252, 41, 128, 62, 175, 71, 132, 124, 245, 16, 185, 134, 234,
            ]
        );
    }

    // railgun-wallet.test.ts: 'Should sign and verify with viewing keypair'
    #[test]
    fn sign_verify_viewing_key() {
        let (_db, wallet) = new_wallet();
        let data = b"20388293809abc";
        let sig = wallet.wallet.sign_with_viewing_key(data);
        let sig64: [u8; 64] = sig.try_into().unwrap();
        let pubkey: [u8; 32] = wallet.wallet.get_viewing_key_pair().pubkey;
        assert!(verify_ed25519(data, &sig64, &pubkey));
    }

    // railgun-wallet.test.ts: 'Should get spending keypair'
    #[test]
    fn spending_keypair() {
        let (db, wallet) = new_wallet();
        let kp = wallet.get_spending_key_pair(&db, &enc_key(), None).unwrap();
        assert_eq!(
            kp.private_key.to_vec(),
            vec![
                176, 149, 143, 139, 194, 134, 174, 8, 50, 250, 131, 176, 27, 113, 154, 34, 90, 7,
                206, 123, 134, 31, 243, 17, 50, 63, 34, 22, 103, 179, 189, 80,
            ]
        );
        assert_eq!(
            kp.pubkey.0,
            big("15684838006997671713939066069845237677934334329285343229142447933587909549584")
        );
        assert_eq!(
            kp.pubkey.1,
            big("11878614856120328179849762231924033298788609151532558727282528569229552954628")
        );
    }

    // railgun-wallet.test.ts: 'Should get address keys'
    #[test]
    fn address_keys() {
        let (_db, wallet) = new_wallet();
        let keys = wallet.wallet.address_keys();
        assert_eq!(
            keys.master_public_key,
            big("20060431504059690749153982049210720252589378133547582826474262520121417617087")
        );
        assert_eq!(
            keys.viewing_public_key,
            vec![
                119, 215, 170, 124, 91, 151, 128, 96, 190, 43, 167, 140, 188, 14, 249, 42, 79, 58,
                163, 252, 41, 128, 62, 175, 71, 132, 124, 245, 16, 185, 134, 234,
            ]
        );
    }

    // railgun-wallet.test.ts: 'Should get addresses'
    #[test]
    fn addresses_per_chain() {
        let (_db, wallet) = new_wallet();
        assert_eq!(
            wallet.wallet.get_address(None),
            "0zk1qyk9nn28x0u3rwn5pknglda68wrn7gw6anjw8gg94mcj6eq5u48tlrv7j6fe3z53lama02nutwtcqc979wnce0qwly4y7w4rls5cq040g7z8eagshxrw5ajy990"
        );
        let cases = [
            (0u64, "0zk1qyk9nn28x0u3rwn5pknglda68wrn7gw6anjw8gg94mcj6eq5u48t7unpd9kxwatwqpma02nutwtcqc979wnce0qwly4y7w4rls5cq040g7z8eagshxrw5qq7f22"),
            (1, "0zk1qyk9nn28x0u3rwn5pknglda68wrn7gw6anjw8gg94mcj6eq5u48t7unpd9kxwatwq9ma02nutwtcqc979wnce0qwly4y7w4rls5cq040g7z8eagshxrw56ltkfa"),
            (2, "0zk1qyk9nn28x0u3rwn5pknglda68wrn7gw6anjw8gg94mcj6eq5u48t7unpd9kxwatwqfma02nutwtcqc979wnce0qwly4y7w4rls5cq040g7z8eagshxrw5aha7vd"),
            (3, "0zk1qyk9nn28x0u3rwn5pknglda68wrn7gw6anjw8gg94mcj6eq5u48t7unpd9kxwatwqdma02nutwtcqc979wnce0qwly4y7w4rls5cq040g7z8eagshxrw58ggp06"),
            (4, "0zk1qyk9nn28x0u3rwn5pknglda68wrn7gw6anjw8gg94mcj6eq5u48t7unpd9kxwatwq3ma02nutwtcqc979wnce0qwly4y7w4rls5cq040g7z8eagshxrw5n8cwxy"),
        ];
        for (id, expected) in cases {
            assert_eq!(
                wallet.wallet.get_address(Some(chain(id))),
                expected,
                "chain id {id}"
            );
        }
        // ChainType 1
        let other = |id: u64| Chain { chain_type: 1, id };
        assert_eq!(
            wallet.wallet.get_address(Some(other(0))),
            "0zk1qyk9nn28x0u3rwn5pknglda68wrn7gw6anjw8gg94mcj6eq5u48t7umpd9kxwatwqpma02nutwtcqc979wnce0qwly4y7w4rls5cq040g7z8eagshxrw5knt45s"
        );
        assert_eq!(
            wallet.wallet.get_address(Some(other(1))),
            "0zk1qyk9nn28x0u3rwn5pknglda68wrn7gw6anjw8gg94mcj6eq5u48t7umpd9kxwatwq9ma02nutwtcqc979wnce0qwly4y7w4rls5cq040g7z8eagshxrw5vv72h8"
        );
    }

    // railgun-wallet.test.ts: 'Should get chain address correctly'
    #[test]
    fn chain_address() {
        let (db, wallet) = new_wallet();
        let address = wallet.get_chain_address(&db, &enc_key(), None).unwrap();
        assert_eq!(address, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    }

    // railgun-wallet.test.ts: 'Should load existing wallet'
    #[test]
    fn load_existing() {
        let (db, wallet) = new_wallet();
        let loaded =
            RailgunWallet::load_existing(&db, &enc_key(), &wallet.wallet.id, None).unwrap();
        assert_eq!(loaded.wallet.id, wallet.wallet.id);
        assert_eq!(
            loaded.get_chain_address(&db, &enc_key(), None).unwrap(),
            wallet.get_chain_address(&db, &enc_key(), None).unwrap()
        );
    }

    // railgun-wallet.test.ts: mnemonic-password wallet flow
    #[test]
    fn mnemonic_password_distinct_and_load() {
        let mut db = Database::in_memory();
        let pw = "test mnemonic password";
        let pw_wallet =
            RailgunWallet::from_mnemonic_with_password(&mut db, &enc_key(), MNEMONIC, pw, 0, None)
                .unwrap();
        let no_pw = RailgunWallet::from_mnemonic(&mut db, &enc_key(), MNEMONIC, 0, None).unwrap();
        assert_ne!(pw_wallet.wallet.id, no_pw.wallet.id);

        // Load with correct password.
        let loaded =
            RailgunWallet::load_existing(&db, &enc_key(), &pw_wallet.wallet.id, Some(pw)).unwrap();
        assert_eq!(loaded.wallet.id, pw_wallet.wallet.id);

        // Missing password rejected.
        assert!(matches!(
            RailgunWallet::load_existing(&db, &enc_key(), &pw_wallet.wallet.id, None),
            Err(WalletError::IncorrectMnemonicPassword)
        ));
        // Wrong password rejected.
        assert!(matches!(
            RailgunWallet::load_existing(
                &db,
                &enc_key(),
                &pw_wallet.wallet.id,
                Some("wrong password")
            ),
            Err(WalletError::IncorrectMnemonicPassword)
        ));
    }

    // railgun-wallet.test.ts: nullifier derivation + EdDSA-Poseidon signing.
    #[test]
    fn sign_eddsa_public_inputs() {
        let (db, wallet) = new_wallet();
        let merkle_root = big("11");
        let bound_params_hash = big("12");
        let nullifiers = [big("13"), big("14")];
        let commitments_out = [big("15"), big("16")];
        let sig = wallet
            .sign(
                &db,
                &merkle_root,
                &bound_params_hash,
                &nullifiers,
                &commitments_out,
                &enc_key(),
                None,
            )
            .unwrap();
        let msg = public_inputs_message_hash(
            &merkle_root,
            &bound_params_hash,
            &nullifiers,
            &commitments_out,
        );
        let pubkey = wallet
            .get_spending_key_pair(&db, &enc_key(), None)
            .unwrap()
            .pubkey;
        assert!(verify_eddsa(&msg, &sig, &pubkey));
    }
}
