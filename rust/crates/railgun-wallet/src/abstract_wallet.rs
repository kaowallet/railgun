//! Port of `src/wallet/abstract-wallet.ts` — the shared wallet core.
//!
//! Scope: key/address derivation, DB path construction, note decryption +
//! commitment scanning (`scanLeaves`), wallet-details persistence, encrypted
//! read/write, and shareable-viewing-key (un)packing. Balance aggregation and
//! POI/history that need a live merkletree + RPC are scaffolded behind the
//! injected merkletree/POI traits and recorded as TODOs.

use std::collections::BTreeMap;
use std::marker::PhantomData;

use num_bigint::BigUint;

use railgun_crypto::{
    get_shared_symmetric_key, pack_point, poseidon, poseidon_hex, sign_ed25519, unpack_point,
};
use railgun_db::{Database, KvStore};
use railgun_key_derivation::{
    encode_address, get_chain_full_network_id, AddressData, Chain, SpendingPublicKey,
    ViewingKeyPair, WalletNode,
};
use railgun_models::formatted_types::{
    Commitment, CommitmentType, DecryptedNote, SpendTxid, StoredReceiveCommitment,
    StoredSendCommitment,
};
use railgun_models::poi_types::TXIDVersion;
use railgun_models::wallet_types::{
    AddressKeys, ShareableViewingKeyData, ViewOnlyWalletData, WalletData, WalletDetails,
    WalletDetailsMap,
};
use railgun_note::{Erc20TokenDataGetter, TransactNote};
use railgun_poi::{get_global_tree_position, BlindedCommitment};
use railgun_utils::{
    fast_bytes_to_hex, format_to_byte_length, from_utf8_string, hex_string_to_bytes, hex_to_bigint,
    hexlify, n_to_hex, to_utf8_string, ByteLength, BytesData,
};

/// `CURRENT_UTXO_MERKLETREE_HISTORY_VERSION` (engine constant).
pub const CURRENT_UTXO_MERKLETREE_HISTORY_VERSION: u32 = 7;

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("{0}")]
    Db(#[from] railgun_db::DbError),
    #[error("Invalid shareable private key.")]
    InvalidShareableKey,
    #[error("Incorrect wallet type.")]
    IncorrectWalletType,
    #[error("Incorrect mnemonic password for wallet.")]
    IncorrectMnemonicPassword,
    #[error("serialization failed")]
    Serialization,
    #[error("{0}")]
    Address(#[from] railgun_key_derivation::AddressError),
}

/// The decoded keys carried by every wallet (full / view-only / hardware).
#[derive(Clone)]
pub struct WalletKeys {
    pub viewing_key_pair: ViewingKeyPair,
    pub spending_public_key: SpendingPublicKey,
    pub nullifying_key: BigUint,
    pub master_public_key: BigUint,
}

/// `AbstractWallet` — the shared core, generic over the DB backend.
pub struct AbstractWallet<S: KvStore> {
    pub id: String,
    pub keys: WalletKeys,
    pub creation_block_numbers: Option<Vec<Vec<u64>>>,
    token_data_getter: Erc20TokenDataGetter,
    _store: PhantomData<fn() -> S>,
}

impl<S: KvStore> AbstractWallet<S> {
    /// The TS constructor: derives `nullifyingKey` + `masterPublicKey` from the
    /// supplied key material.
    pub fn new(
        id: &str,
        viewing_key_pair: ViewingKeyPair,
        spending_public_key: SpendingPublicKey,
        creation_block_numbers: Option<Vec<Vec<u64>>>,
    ) -> Self {
        let nullifying_key = hex_to_bigint(&poseidon_hex(&[&fast_bytes_to_hex(
            &viewing_key_pair.private_key,
        )]));
        let master_public_key =
            WalletNode::get_master_public_key(&spending_public_key, &nullifying_key);
        Self {
            id: hexlify(&BytesData::Hex(id.to_string()), false),
            keys: WalletKeys {
                viewing_key_pair,
                spending_public_key,
                nullifying_key,
                master_public_key,
            },
            creation_block_numbers,
            token_data_getter: Erc20TokenDataGetter,
            _store: PhantomData,
        }
    }

    // --- keys / addresses ------------------------------------------------

    pub fn get_viewing_key_pair(&self) -> &ViewingKeyPair {
        &self.keys.viewing_key_pair
    }

    pub fn viewing_public_key(&self) -> &[u8] {
        &self.keys.viewing_key_pair.pubkey
    }

    pub fn get_nullifying_key(&self) -> &BigUint {
        &self.keys.nullifying_key
    }

    pub fn master_public_key(&self) -> &BigUint {
        &self.keys.master_public_key
    }

    /// `signWithViewingKey` — Ed25519 signature over `message`.
    pub fn sign_with_viewing_key(&self, message: &[u8]) -> Vec<u8> {
        sign_ed25519(message, &self.keys.viewing_key_pair.private_key).to_vec()
    }

    /// `addressKeys` getter.
    pub fn address_keys(&self) -> AddressKeys {
        AddressKeys {
            master_public_key: self.keys.master_public_key.clone(),
            viewing_public_key: self.keys.viewing_key_pair.pubkey.to_vec(),
        }
    }

    fn address_data(&self, chain: Option<Chain>) -> AddressData {
        AddressData {
            master_public_key: self.keys.master_public_key.clone(),
            viewing_public_key: self.keys.viewing_key_pair.pubkey.to_vec(),
            chain,
            version: None,
        }
    }

    /// `getAddress` — bech32m `0zk` address (optionally chain-scoped).
    pub fn get_address(&self, chain: Option<Chain>) -> String {
        encode_address(&self.address_data(chain))
    }

    // --- DB path construction -------------------------------------------

    fn pad32(el: &str) -> BytesData {
        BytesData::Hex(format_to_byte_length(
            &BytesData::Hex(el.to_string()),
            ByteLength::Uint256,
            false,
        ))
    }

    fn pad_u64(v: u64) -> BytesData {
        // TS: ByteUtils.hexlify(ByteUtils.padToLength(value, 32)) — a number left-
        // pads to `value.toString(16).padStart(64, '0')`.
        BytesData::Hex(format!("{v:0>64x}"))
    }

    /// `getWalletDBPrefix` — `['wallet', id, chainNetworkID]` (+ tree/position).
    pub fn get_wallet_db_prefix(
        &self,
        chain: &Chain,
        tree: Option<u64>,
        position: Option<u64>,
    ) -> Vec<BytesData> {
        let wallet_hex = from_utf8_string("wallet").expect("utf8");
        let mut path = vec![
            Self::pad32(&wallet_hex),
            Self::pad32(&hexlify(&BytesData::Hex(self.id.clone()), false)),
            Self::pad32(&get_chain_full_network_id(chain)),
        ];
        if let Some(t) = tree {
            path.push(Self::pad_u64(t));
        }
        if let Some(p) = position {
            path.push(Self::pad_u64(p));
        }
        path
    }

    /// `getWalletReceiveCommitmentDBPrefix`.
    pub fn get_wallet_receive_commitment_db_prefix(
        &self,
        chain: &Chain,
        tree: u64,
        position: u64,
    ) -> Vec<BytesData> {
        self.get_wallet_db_prefix(chain, Some(tree), Some(position))
    }

    /// `getWalletSentCommitmentDBPrefix` — note the `<id>-spent` id segment.
    pub fn get_wallet_sent_commitment_db_prefix(
        &self,
        chain: &Chain,
        tree: Option<u64>,
        position: Option<u64>,
    ) -> Vec<BytesData> {
        let wallet_hex = from_utf8_string("wallet").expect("utf8");
        let id_spent = format!("{}-spent", hexlify(&BytesData::Hex(self.id.clone()), false));
        let mut path = vec![
            Self::pad32(&wallet_hex),
            // The TS pads the (now non-hex) `<id>-spent` string with formatToByteLength;
            // for a value already longer than 32 bytes this is the identity.
            BytesData::Hex(format_to_byte_length(
                &BytesData::Hex(id_spent),
                ByteLength::Uint256,
                false,
            )),
            Self::pad32(&get_chain_full_network_id(chain)),
        ];
        if let Some(t) = tree {
            path.push(Self::pad_u64(t));
        }
        if let Some(p) = position {
            path.push(Self::pad_u64(p));
        }
        path
    }

    /// `getWalletDetailsPath`.
    pub fn get_wallet_details_path(&self, chain: &Chain) -> Vec<BytesData> {
        let details = from_utf8_string("details").expect("utf8");
        let mut path = self.get_wallet_db_prefix(chain, None, None);
        path.push(BytesData::Hex(details));
        path
    }

    fn utxo_history_version_db_prefix(&self, chain: &Chain) -> Vec<BytesData> {
        let marker = from_utf8_string("merkleetree_history_version").expect("utf8");
        let mut path = self.get_wallet_db_prefix(chain, None, None);
        path.push(BytesData::Hex(marker));
        path.push(BytesData::Hex(get_chain_full_network_id(chain)));
        path
    }

    // --- merkletree history version (schema marker) ----------------------

    pub fn set_utxo_merkletree_history_version(
        &self,
        db: &mut Database<S>,
        chain: &Chain,
        version: u32,
    ) -> Result<(), WalletError> {
        // TS stores this with 'utf8' encoding: the raw decimal-string bytes.
        let utf8_hex = from_utf8_string(&version.to_string()).expect("utf8");
        db.put(
            &self.utxo_history_version_db_prefix(chain),
            &BytesData::Hex(utf8_hex),
        )?;
        Ok(())
    }

    pub fn get_utxo_merkletree_history_version(
        &self,
        db: &Database<S>,
        chain: &Chain,
    ) -> Option<u32> {
        let hex = db.get(&self.utxo_history_version_db_prefix(chain)).ok()?;
        let s = to_utf8_string(&hex).ok()?;
        s.trim().parse::<u32>().ok()
    }

    /// `loadUTXOMerkletree` history-version handling (the merkletree object
    /// itself is held by the caller / engine). Returns whether balances were
    /// cleared (i.e. a real schema migration ran).
    pub fn load_utxo_merkletree_history(
        &self,
        db: &mut Database<S>,
        chain: &Chain,
    ) -> Result<bool, WalletError> {
        match self.get_utxo_merkletree_history_version(db, chain) {
            None => {
                // Cold install or adjacent wipe: just stamp the marker, preserving
                // any walletDetails rebuilt after a wipe (no redundant rescan).
                self.set_utxo_merkletree_history_version(
                    db,
                    chain,
                    CURRENT_UTXO_MERKLETREE_HISTORY_VERSION,
                )?;
                Ok(false)
            }
            Some(v) if v < CURRENT_UTXO_MERKLETREE_HISTORY_VERSION => {
                self.clear_decrypted_balances_all_txid_versions(db, chain)?;
                self.set_utxo_merkletree_history_version(
                    db,
                    chain,
                    CURRENT_UTXO_MERKLETREE_HISTORY_VERSION,
                )?;
                Ok(true)
            }
            Some(_) => Ok(false),
        }
    }

    // --- wallet details --------------------------------------------------

    /// `getWalletDetailsMap` — msgpack-encoded map at the details path.
    pub fn get_wallet_details_map(&self, db: &Database<S>, chain: &Chain) -> WalletDetailsMap {
        let Ok(hex) = db.get(&self.get_wallet_details_path(chain)) else {
            return BTreeMap::new();
        };
        let Ok(bytes) = hex::decode(&hex) else {
            return BTreeMap::new();
        };
        rmp_serde::from_slice(&bytes).unwrap_or_default()
    }

    /// `getWalletDetails` for a single txid version (defaults when absent).
    pub fn get_wallet_details(
        &self,
        db: &Database<S>,
        txid_version: TXIDVersion,
        chain: &Chain,
    ) -> WalletDetails {
        self.get_wallet_details_map(db, chain)
            .get(&txid_version)
            .cloned()
            .unwrap_or(WalletDetails {
                tree_scanned_heights: vec![],
                creation_tree: None,
                creation_tree_height: None,
            })
    }

    pub fn put_wallet_details_map(
        &self,
        db: &mut Database<S>,
        chain: &Chain,
        map: &WalletDetailsMap,
    ) -> Result<(), WalletError> {
        let bytes = rmp_serde::to_vec_named(map).map_err(|_| WalletError::Serialization)?;
        db.put(
            &self.get_wallet_details_path(chain),
            &BytesData::Bytes(bytes),
        )?;
        Ok(())
    }

    /// `clearDecryptedBalancesAllTXIDVersions` — wipe the wallet namespace and
    /// reset the scanned heights in the (preserved) details map.
    pub fn clear_decrypted_balances_all_txid_versions(
        &self,
        db: &mut Database<S>,
        chain: &Chain,
    ) -> Result<(), WalletError> {
        let mut details_map = self.get_wallet_details_map(db, chain);
        db.clear_namespace(&self.get_wallet_db_prefix(chain, None, None));
        for details in details_map.values_mut() {
            details.tree_scanned_heights = vec![];
        }
        self.put_wallet_details_map(db, chain, &details_map)?;
        Ok(())
    }

    // --- scanning --------------------------------------------------------

    /// `scanLeaves` — decrypt each commitment addressed to this wallet and store
    /// the resulting receive/send commitment under the wallet namespace.
    pub fn scan_leaves(
        &self,
        db: &mut Database<S>,
        txid_version: TXIDVersion,
        leaves: &[Option<Commitment>],
        tree: u64,
        chain: &Chain,
        start_scan_height: u64,
    ) -> Result<(), WalletError> {
        for (i, leaf) in leaves.iter().enumerate() {
            let position = start_scan_height + i as u64;
            let Some(leaf) = leaf else { continue };
            self.create_scanned_db_commitments(db, txid_version, leaf, tree, chain, position)?;
        }
        Ok(())
    }

    fn create_scanned_db_commitments(
        &self,
        db: &mut Database<S>,
        txid_version: TXIDVersion,
        leaf: &Commitment,
        tree: u64,
        chain: &Chain,
        position: u64,
    ) -> Result<(), WalletError> {
        let vpk: [u8; 32] = self.keys.viewing_key_pair.private_key;

        let wallet_address = self.get_address(None);
        let address_data = self.address_data(None);

        let mut note_receive: Option<(TransactNote, String, u64, Option<u64>)> = None;
        let mut note_send: Option<(TransactNote, String, u64, Option<u64>)> = None;

        // SECURITY: a decrypted transact note must re-hash to the on-chain hash.
        let matches_commitment = |note: &TransactNote, leaf_hash: &str| -> bool {
            let note_hash = n_to_hex(&note.hash, ByteLength::Uint256, false);
            let commitment_hash = format_to_byte_length(
                &BytesData::Hex(leaf_hash.to_string()),
                ByteLength::Uint256,
                false,
            );
            note_hash == commitment_hash
        };

        match leaf {
            Commitment::TransactCommitmentV2(c) => {
                let blinded_sender = hex_string_to_bytes(&c.ciphertext.blinded_sender_viewing_key)
                    .ok()
                    .and_then(|v| <[u8; 32]>::try_from(v).ok());
                let blinded_receiver =
                    hex_string_to_bytes(&c.ciphertext.blinded_receiver_viewing_key)
                        .ok()
                        .and_then(|v| <[u8; 32]>::try_from(v).ok());
                let (Some(blinded_sender), Some(blinded_receiver)) =
                    (blinded_sender, blinded_receiver)
                else {
                    return Ok(());
                };

                let shared_key_receiver = get_shared_symmetric_key(&vpk, &blinded_sender);
                let shared_key_sender = get_shared_symmetric_key(&vpk, &blinded_receiver);

                if let Some(shared) = shared_key_receiver {
                    if let Ok(note) = TransactNote::decrypt(
                        txid_version,
                        chain.id,
                        &address_data,
                        Some(&c.ciphertext.ciphertext),
                        None,
                        &shared,
                        &c.ciphertext.memo,
                        &c.ciphertext.annotation_data,
                        &vpk,
                        Some(&blinded_receiver),
                        Some(&blinded_sender),
                        false, // isSentNote
                        false, // isLegacyDecryption
                        &self.token_data_getter,
                        Some(c.block_number),
                        None,
                    ) {
                        if matches_commitment(&note, &c.hash) {
                            note_receive =
                                Some((note, c.txid.clone(), c.block_number, c.timestamp));
                        }
                    }
                }
                if let Some(shared) = shared_key_sender {
                    if let Ok(note) = TransactNote::decrypt(
                        txid_version,
                        chain.id,
                        &address_data,
                        Some(&c.ciphertext.ciphertext),
                        None,
                        &shared,
                        &c.ciphertext.memo,
                        &c.ciphertext.annotation_data,
                        &vpk,
                        Some(&blinded_receiver),
                        Some(&blinded_sender),
                        true, // isSentNote
                        false,
                        &self.token_data_getter,
                        Some(c.block_number),
                        None,
                    ) {
                        if matches_commitment(&note, &c.hash) {
                            note_send = Some((note, c.txid.clone(), c.block_number, c.timestamp));
                        }
                    }
                }

                self.store_scanned(
                    db,
                    txid_version,
                    chain,
                    tree,
                    position,
                    leaf,
                    &c.hash,
                    c.utxo_tree as u64,
                    c.utxo_index as u64,
                    c.railgun_txid.clone(),
                    note_receive,
                    note_send,
                    &wallet_address,
                )?;
            }
            // Shield, V3 transact, and legacy commitments decrypt structurally the
            // same way (ECDH shared key -> note reconstruction / deserialize), but
            // need the shield random decryptor / V3 XChaCha path that are out of
            // the wallet KAV-test scope here. TODO: port the ShieldCommitment and
            // TransactCommitmentV3 branches once those decryptors are wired up.
            _ => {}
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn store_scanned(
        &self,
        db: &mut Database<S>,
        txid_version: TXIDVersion,
        chain: &Chain,
        tree: u64,
        position: u64,
        leaf: &Commitment,
        leaf_hash: &str,
        utxo_tree: u64,
        utxo_index: u64,
        railgun_txid: Option<String>,
        note_receive: Option<(TransactNote, String, u64, Option<u64>)>,
        note_send: Option<(TransactNote, String, u64, Option<u64>)>,
        wallet_address: &str,
    ) -> Result<(), WalletError> {
        let commitment_type = Self::commitment_type(leaf);
        let global_pos = get_global_tree_position(utxo_tree, utxo_index);

        if let Some((note, txid, block_number, timestamp)) = note_receive {
            let nullifier = TransactNote::get_nullifier(&self.keys.nullifying_key, position);
            let stored = StoredReceiveCommitment {
                txid_version,
                spendtxid: SpendTxid::Unspent(false),
                txid,
                timestamp,
                nullifier: n_to_hex(&nullifier, ByteLength::Uint256, false),
                block_number,
                decrypted: DecryptedNote::Note(note.serialize(false)),
                sender_address: note.sender_address_data.as_ref().map(encode_address),
                commitment_type,
                pois_per_list: None,
                blinded_commitment: Some(BlindedCommitment::get_for_shield_or_transact(
                    leaf_hash,
                    &note.note_public_key,
                    &global_pos,
                )),
                transact_creation_railgun_txid: railgun_txid.clone(),
            };
            let bytes = rmp_serde::to_vec_named(&stored).map_err(|_| WalletError::Serialization)?;
            db.put(
                &self.get_wallet_receive_commitment_db_prefix(chain, tree, position),
                &BytesData::Bytes(bytes),
            )?;
        }

        if let Some((note, txid, _block, timestamp)) = note_send {
            let stored = StoredSendCommitment {
                txid_version,
                txid,
                timestamp,
                decrypted: DecryptedNote::Note(note.serialize(false)),
                commitment_type,
                output_type: note.output_type,
                wallet_source: note.wallet_source.clone(),
                recipient_address: encode_address(&note.receiver_address_data),
                railgun_txid,
                pois_per_list: None,
                blinded_commitment: Some(BlindedCommitment::get_for_shield_or_transact(
                    leaf_hash,
                    &note.note_public_key,
                    &global_pos,
                )),
            };
            let bytes = rmp_serde::to_vec_named(&stored).map_err(|_| WalletError::Serialization)?;
            let _ = wallet_address;
            db.put(
                &self.get_wallet_sent_commitment_db_prefix(chain, Some(tree), Some(position)),
                &BytesData::Bytes(bytes),
            )?;
        }

        Ok(())
    }

    fn commitment_type(leaf: &Commitment) -> CommitmentType {
        match leaf {
            Commitment::ShieldCommitment(_) => CommitmentType::ShieldCommitment,
            Commitment::TransactCommitmentV2(_) => CommitmentType::TransactCommitmentV2,
            Commitment::TransactCommitmentV3(_) => CommitmentType::TransactCommitmentV3,
            Commitment::LegacyGeneratedCommitment(_) => CommitmentType::LegacyGeneratedCommitment,
            Commitment::LegacyEncryptedCommitment(_) => CommitmentType::LegacyEncryptedCommitment,
        }
    }

    // --- encrypted read / write -----------------------------------------

    fn db_path(id: &str) -> Vec<BytesData> {
        let wallet_hex = from_utf8_string("wallet").expect("utf8");
        vec![BytesData::Hex(wallet_hex), BytesData::Hex(id.to_string())]
    }

    /// `AbstractWallet.write` — msgpack-encode then AES-256-GCM store.
    pub fn write_wallet_data(
        db: &mut Database<S>,
        id: &str,
        encryption_key: &[u8],
        data: &StoredWalletData,
    ) -> Result<(), WalletError> {
        let bytes = data.to_msgpack()?;
        db.put_encrypted(&Self::db_path(id), encryption_key, &hex::encode(bytes))?;
        Ok(())
    }

    /// `AbstractWallet.read` — decrypt then msgpack-decode.
    pub fn read_wallet_data(
        db: &Database<S>,
        id: &str,
        encryption_key: &[u8],
    ) -> Result<StoredWalletData, WalletError> {
        let hex = db.get_encrypted(&Self::db_path(id), encryption_key)?;
        let bytes = hex::decode(&hex).map_err(|_| WalletError::Serialization)?;
        StoredWalletData::from_msgpack(&bytes)
    }

    // --- shareable viewing key ------------------------------------------

    /// `getKeysFromShareableViewingKey` — msgpack-decode + babyjub-unpack.
    pub fn get_keys_from_shareable_viewing_key(
        shareable_viewing_key: &str,
    ) -> Result<(String, SpendingPublicKey), WalletError> {
        let bytes =
            hex::decode(shareable_viewing_key).map_err(|_| WalletError::InvalidShareableKey)?;
        let data: ShareableViewingKeyData =
            rmp_serde::from_slice(&bytes).map_err(|_| WalletError::InvalidShareableKey)?;
        let packed: [u8; 32] = hex_string_to_bytes(&data.spub)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or(WalletError::InvalidShareableKey)?;
        let spending_public_key = unpack_point(&packed).ok_or(WalletError::InvalidShareableKey)?;
        Ok((data.vpriv, spending_public_key))
    }

    /// `generateShareableViewingKey` — pack the spending key + viewing private
    /// key into a msgpack hex blob.
    pub fn generate_shareable_viewing_key(&self) -> Result<String, WalletError> {
        let packed = pack_point(&self.keys.spending_public_key);
        let data = ShareableViewingKeyData {
            vpriv: format_to_byte_length(
                &BytesData::Bytes(self.keys.viewing_key_pair.private_key.to_vec()),
                ByteLength::Uint256,
                false,
            ),
            spub: hex::encode(packed),
        };
        let bytes = rmp_serde::to_vec_named(&data).map_err(|_| WalletError::Serialization)?;
        Ok(hex::encode(bytes))
    }
}

/// The data stored (encrypted) for a wallet — either a full wallet (`mnemonic`)
/// or a view-only / hardware wallet (`shareableViewingKey`). msgpack maps stay
/// string-keyed (matching `msgpack-lite`), so we (de)serialize via a JSON-ish
/// value rather than struct-as-array.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredWalletData {
    Full(WalletData),
    ViewOnly(ViewOnlyWalletData),
}

impl StoredWalletData {
    fn to_msgpack(&self) -> Result<Vec<u8>, WalletError> {
        match self {
            StoredWalletData::Full(d) => {
                rmp_serde::to_vec_named(d).map_err(|_| WalletError::Serialization)
            }
            StoredWalletData::ViewOnly(d) => {
                rmp_serde::to_vec_named(d).map_err(|_| WalletError::Serialization)
            }
        }
    }

    fn from_msgpack(bytes: &[u8]) -> Result<Self, WalletError> {
        // A full wallet has a `mnemonic` key; a view-only wallet has
        // `shareableViewingKey`. Try full first, then view-only.
        if let Ok(d) = rmp_serde::from_slice::<WalletData>(bytes) {
            return Ok(StoredWalletData::Full(d));
        }
        if let Ok(d) = rmp_serde::from_slice::<ViewOnlyWalletData>(bytes) {
            return Ok(StoredWalletData::ViewOnly(d));
        }
        Err(WalletError::IncorrectWalletType)
    }

    pub fn creation_block_numbers(&self) -> Option<Vec<Vec<u64>>> {
        match self {
            StoredWalletData::Full(d) => d.creation_block_numbers.clone(),
            StoredWalletData::ViewOnly(d) => d.creation_block_numbers.clone(),
        }
    }
}

/// `poseidon`-based message hash shared by `sign` implementations.
pub fn public_inputs_message_hash(
    merkle_root: &BigUint,
    bound_params_hash: &BigUint,
    nullifiers: &[BigUint],
    commitments_out: &[BigUint],
) -> BigUint {
    let mut inputs = vec![merkle_root.clone(), bound_params_hash.clone()];
    inputs.extend_from_slice(nullifiers);
    inputs.extend_from_slice(commitments_out);
    poseidon(&inputs)
}

#[cfg(test)]
mod tests {
    //! Port of railgun-wallet.test.ts `createScannedDBCommitments` security
    //! tests: a decrypted transact note must re-hash to the on-chain commitment
    //! hash, else it is discarded.
    use super::*;
    use num_traits::One;
    use railgun_crypto::get_note_blinding_keys;
    use railgun_db::{Database, MemStore};
    use railgun_key_derivation::{derive_nodes, AddressData, Chain, ChainType};
    use railgun_models::formatted_types::{
        Commitment, CommitmentCiphertextV2, OutputType, TransactCommitmentV2,
    };
    use railgun_note::note_util::get_token_data_erc20;
    use railgun_note::TransactNote;

    const MNEMONIC: &str = "test test test test test test test test test test test junk";

    fn chain() -> Chain {
        Chain {
            chain_type: ChainType::Evm as u8,
            id: 1,
        }
    }

    fn build_wallet() -> AbstractWallet<MemStore> {
        let nodes = derive_nodes(MNEMONIC, 0, "");
        let viewing = nodes.viewing.get_viewing_key_pair();
        let spending = nodes.spending.get_spending_key_pair().pubkey;
        AbstractWallet::new("test", viewing, spending, None)
    }

    /// Genuinely-encrypted self-transfer note that decrypts cleanly for `wallet`.
    fn encrypt_own_transact_note(
        wallet: &AbstractWallet<MemStore>,
    ) -> (TransactNote, CommitmentCiphertextV2) {
        let address_keys = wallet.address_keys();
        let addr = AddressData {
            master_public_key: address_keys.master_public_key.clone(),
            viewing_public_key: address_keys.viewing_public_key.clone(),
            chain: None,
            version: None,
        };
        let token_data = get_token_data_erc20("0x5fbdb2315678afecb367f032d93f642f64180aa3");
        let note = TransactNote::create_transfer(
            addr.clone(),
            Some(addr.clone()),
            BigUint::from(1000u32),
            token_data,
            false, // showSenderAddressToRecipient
            OutputType::Transfer,
            None,
            Some("test".to_string()),
            None,
            None,
        )
        .unwrap();
        let sender_random = note.sender_random.clone().expect("senderRandom");
        let vkp = wallet.get_viewing_key_pair();
        let (blinded_sender, blinded_receiver) = get_note_blinding_keys(
            &vkp.pubkey,
            &address_keys.viewing_public_key.clone().try_into().unwrap(),
            &note.random,
            &sender_random,
        )
        .unwrap();
        let shared_key = get_shared_symmetric_key(&vkp.private_key, &blinded_receiver).unwrap();
        let (note_ciphertext, note_memo, annotation_data) = note
            .encrypt_v2(
                TXIDVersion::V2_PoseidonMerkle,
                &shared_key,
                &address_keys.master_public_key,
                Some(&sender_random),
                &vkp.private_key,
            )
            .unwrap();
        let ciphertext = CommitmentCiphertextV2 {
            ciphertext: note_ciphertext,
            blinded_sender_viewing_key: hexlify(&BytesData::Bytes(blinded_sender.to_vec()), false),
            blinded_receiver_viewing_key: hexlify(
                &BytesData::Bytes(blinded_receiver.to_vec()),
                false,
            ),
            annotation_data,
            memo: note_memo,
        };
        (note, ciphertext)
    }

    fn make_v2_leaf(ciphertext: CommitmentCiphertextV2, hash: String) -> Commitment {
        Commitment::TransactCommitmentV2(TransactCommitmentV2 {
            hash,
            txid: format_to_byte_length(
                &BytesData::Hex("00".to_string()),
                ByteLength::Uint256,
                false,
            ),
            timestamp: None,
            block_number: 0,
            utxo_tree: 0,
            utxo_index: 0,
            railgun_txid: None,
            ciphertext,
        })
    }

    // 'Should store a receive commitment when the decrypted note hash matches'
    #[test]
    fn scan_stores_matching_receive_commitment() {
        let mut db = Database::in_memory();
        let wallet = build_wallet();
        let (note, ciphertext) = encrypt_own_transact_note(&wallet);
        let matching = n_to_hex(&note.hash, ByteLength::Uint256, false);
        wallet
            .scan_leaves(
                &mut db,
                TXIDVersion::V2_PoseidonMerkle,
                &[Some(make_v2_leaf(ciphertext, matching))],
                0,
                &chain(),
                0,
            )
            .unwrap();
        let key = wallet.get_wallet_receive_commitment_db_prefix(&chain(), 0, 0);
        assert!(db.get(&key).is_ok());
    }

    // 'Should discard a decrypted note whose hash does not match the commitment'
    #[test]
    fn scan_discards_tampered_hash() {
        let mut db = Database::in_memory();
        let wallet = build_wallet();
        let (note, ciphertext) = encrypt_own_transact_note(&wallet);
        let tampered = n_to_hex(&(&note.hash + BigUint::one()), ByteLength::Uint256, false);
        wallet
            .scan_leaves(
                &mut db,
                TXIDVersion::V2_PoseidonMerkle,
                &[Some(make_v2_leaf(ciphertext, tampered))],
                0,
                &chain(),
                0,
            )
            .unwrap();
        let key = wallet.get_wallet_receive_commitment_db_prefix(&chain(), 0, 0);
        assert!(db.get(&key).is_err());
    }
}
