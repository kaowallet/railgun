//! Port of `src/merkletree/utxo-merkletree.ts`.
//!
//! Commitment-leaf Merkle tree plus nullifier and unshield-event storage.

use railgun_db::{Database, MemStore};
use railgun_models::engine_types::Chain;
use railgun_models::event_types::UnshieldStoredEvent;
use railgun_models::formatted_types::{Commitment, MerkleProof, Nullifier};
use railgun_models::merkletree_types::CommitmentProcessingGroupSize;
use railgun_models::poi_types::TXIDVersion;
use railgun_utils::{format_to_byte_length, hexlify, ByteLength, BytesData};

use crate::merkletree::{MerkleCore, MerkleKind, MerkletreeError, MerkletreeLeafData};

impl MerkletreeLeafData for Commitment {
    fn hash(&self) -> &str {
        match self {
            Commitment::ShieldCommitment(c) => &c.hash,
            Commitment::TransactCommitmentV2(c) => &c.hash,
            Commitment::TransactCommitmentV3(c) => &c.hash,
            Commitment::LegacyGeneratedCommitment(c) => &c.hash,
            Commitment::LegacyEncryptedCommitment(c) => &c.hash,
        }
    }
}

/// `ByteUtils.FULL_32_BITS` == `2^32 - 1`.
const FULL_32_BITS: u64 = 0xffff_ffff;

pub struct UTXOMerkletree {
    pub core: MerkleCore<Commitment>,
}

impl UTXOMerkletree {
    /// `UTXOMerkletree.create`.
    pub fn create(
        db: Database<MemStore>,
        chain: Chain,
        txid_version: TXIDVersion,
        merkleroot_validator: impl FnMut(TXIDVersion, Chain, usize, usize, &str) -> bool + 'static,
    ) -> Self {
        let core = MerkleCore::new(
            db,
            chain,
            txid_version,
            MerkleKind::Utxo,
            CommitmentProcessingGroupSize::XXXXLarge as usize,
            Box::new(merkleroot_validator),
        );
        Self { core }
    }

    // ---- pass-throughs to the core ----

    pub fn zeros(&self) -> &[String] {
        &self.core.zeros
    }
    pub fn get_root(&mut self, tree: usize) -> String {
        self.core.get_root(tree)
    }
    pub fn get_tree_length(&mut self, tree: usize) -> usize {
        self.core.get_tree_length(tree)
    }
    pub fn latest_tree(&mut self) -> usize {
        self.core.latest_tree()
    }
    pub fn get_tree_db_prefix(&self, tree: usize) -> Vec<BytesData> {
        self.core.get_tree_db_prefix(tree)
    }
    pub fn get_node_hash_db_path(&self, tree: usize, level: usize, index: usize) -> Vec<BytesData> {
        self.core.get_node_hash_db_path(tree, level, index)
    }
    pub fn get_merkle_proof(&mut self, tree: usize, index: usize) -> MerkleProof {
        self.core.get_merkle_proof(tree, index)
    }
    pub fn queue_leaves(&mut self, tree: usize, starting_index: usize, leaves: Vec<Commitment>) {
        self.core.queue_leaves(tree, starting_index, leaves);
    }
    pub fn update_trees_from_write_queue(&mut self) {
        self.core.update_trees_from_write_queue(false);
    }
    pub fn get_merkletrees_metadata(
        &self,
    ) -> Option<railgun_models::merkletree_types::MerkletreesMetadata> {
        self.core.get_merkletrees_metadata()
    }
    pub fn store_merkletrees_metadata(
        &mut self,
        metadata: &railgun_models::merkletree_types::MerkletreesMetadata,
    ) {
        self.core.store_merkletrees_metadata(metadata);
    }
    pub fn update_invalid_merkleroot_details(
        &mut self,
        tree: usize,
        last_invalid_index: usize,
        block_number: u64,
    ) {
        self.core
            .update_invalid_merkleroot_details(tree, last_invalid_index, block_number);
    }
    pub fn remove_invalid_merkleroot_details_if_necessary(
        &mut self,
        tree: usize,
        last_valid_index: usize,
    ) {
        self.core
            .remove_invalid_merkleroot_details_if_necessary(tree, last_valid_index);
    }
    pub fn get_first_invalid_merkleroot_tree(&self) -> Option<usize> {
        self.core.get_first_invalid_merkleroot_tree()
    }
    pub fn invalid_merkleroot_details(
        &self,
        tree: usize,
    ) -> Option<railgun_models::merkletree_types::InvalidMerklerootDetails> {
        self.core
            .invalid_merkleroot_details_by_tree
            .get(&tree)
            .copied()
    }

    // ---- commitments ----

    pub fn get_commitment(&self, tree: usize, index: usize) -> Result<Commitment, MerkletreeError> {
        self.core.get_data(tree, index)
    }
    pub fn get_commitment_safe(&self, tree: usize, index: usize) -> Option<Commitment> {
        self.core.get_data(tree, index).ok()
    }

    // ---- nullifiers ----

    /// `getNullifierDBPath`.
    pub fn get_nullifier_db_path(&self, tree: usize, nullifier: &str) -> Vec<BytesData> {
        let mut parts = self.core.get_tree_db_prefix(tree);
        parts.push(BytesData::Hex(num_to_hex(FULL_32_BITS - 1))); // 2^32-2
        parts.push(BytesData::Hex(hexlify(
            &BytesData::Hex(nullifier.to_string()),
            false,
        )));
        parts
            .iter()
            .map(|el| BytesData::Hex(format_to_byte_length(el, ByteLength::Uint256, false)))
            .collect()
    }

    /// `nullify` — store nullifier→txid mappings.
    pub fn nullify(&mut self, nullifiers: &[Nullifier]) {
        for n in nullifiers {
            let path = self.get_nullifier_db_path(n.tree_number as usize, &n.nullifier);
            self.core
                .db
                .put(
                    &path,
                    &BytesData::Hex(hexlify(&BytesData::Hex(n.txid.clone()), false)),
                )
                .expect("nullifier put");
        }
    }

    /// `getNullifierTxid` — search a specific tree, or all trees latest-first.
    pub fn get_nullifier_txid(
        &mut self,
        nullifier: &str,
        tree_index: Option<usize>,
        latest_tree_override: Option<usize>,
    ) -> Option<String> {
        if let Some(tree) = tree_index {
            return self
                .core
                .db
                .get(&self.get_nullifier_db_path(tree, nullifier))
                .ok();
        }
        let latest_tree = latest_tree_override.unwrap_or_else(|| self.core.latest_tree());
        for tree in (0..=latest_tree).rev() {
            if let Ok(txid) = self
                .core
                .db
                .get(&self.get_nullifier_db_path(tree, nullifier))
            {
                return Some(txid);
            }
        }
        None
    }

    // ---- unshield events ----

    /// `getUnshieldEventsDBPath`.
    pub fn get_unshield_events_db_path(
        &self,
        txid: Option<&str>,
        event_log_index: Option<u32>,
        railgun_txid: Option<&str>,
    ) -> Vec<BytesData> {
        let mut path = self.core.get_merkletree_db_prefix();
        path.push(BytesData::Hex(num_to_hex(FULL_32_BITS - 2))); // 2^32-3
        if let Some(txid) = txid {
            path.push(BytesData::Hex(hexlify(
                &BytesData::Hex(txid.to_string()),
                false,
            )));
        }
        if let Some(eli) = event_log_index {
            path.push(BytesData::Hex(format!("{eli:x}")));
        } else if let Some(rt) = railgun_txid {
            path.push(BytesData::Hex(rt.to_string()));
        }
        path.iter()
            .map(|el| BytesData::Hex(format_to_byte_length(el, ByteLength::Uint256, false)))
            .collect()
    }

    pub fn has_existing_unshield_event(&self, unshield: &UnshieldStoredEvent) -> bool {
        self.get_all_unshield_events_for_txid(&unshield.txid)
            .iter()
            .any(|e| e.event_log_index == unshield.event_log_index)
    }

    /// `addUnshieldEvents`.
    pub fn add_unshield_events(
        &mut self,
        unshields: &[UnshieldStoredEvent],
        replace_existing: bool,
    ) {
        for unshield in unshields {
            if !replace_existing && self.has_existing_unshield_event(unshield) {
                continue;
            }
            let path = self.get_unshield_events_db_path(
                Some(&unshield.txid),
                unshield.event_log_index,
                unshield.railgun_txid.as_deref(),
            );
            let json = serde_json::to_vec(unshield).expect("unshield serializable");
            self.core
                .db
                .put(&path, &BytesData::Hex(hex::encode(json)))
                .expect("unshield put");
        }
    }

    pub fn update_unshield_event(&mut self, unshield_event: &UnshieldStoredEvent) {
        self.add_unshield_events(std::slice::from_ref(unshield_event), true);
    }

    /// `getAllUnshieldEventsForTxid`.
    pub fn get_all_unshield_events_for_txid(&self, txid: &str) -> Vec<UnshieldStoredEvent> {
        let stripped = format_to_byte_length(
            &BytesData::Hex(txid.to_string()),
            ByteLength::Uint256,
            false,
        );
        let namespace = self.get_unshield_events_db_path(Some(&stripped), None, None);
        let keys = self.core.db.get_namespace_keys(&namespace);
        let mut events = Vec::new();
        for key in keys {
            // TS filters to keySplit.length === 6 (full 6-segment paths).
            if key.split(':').count() != 6 {
                continue;
            }
            // Re-read the stored value by raw path key.
            let path: Vec<BytesData> = key
                .split(':')
                .map(|s| BytesData::Hex(s.to_string()))
                .collect();
            if let Ok(hex) = self.core.db.get(&path) {
                if let Ok(bytes) = hex::decode(&hex) {
                    if let Ok(mut event) = serde_json::from_slice::<UnshieldStoredEvent>(&bytes) {
                        event.timestamp = event.timestamp.or(None);
                        events.push(event);
                    }
                }
            }
        }
        events
    }
}

fn num_to_hex(n: u64) -> String {
    hexlify(&BytesData::Num(n), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_proof::verify_merkle_proof;
    use railgun_crypto::Ciphertext;
    use railgun_models::engine_types::{Chain, ChainType};
    use railgun_models::formatted_types::{LegacyCommitmentCiphertext, LegacyEncryptedCommitment};
    use railgun_models::merkletree_types::{MerkletreesMetadata, TreeMetadata};

    const TXID_VERSION: TXIDVersion = TXIDVersion::V2_PoseidonMerkle;
    const EMPTY_ROOT: &str = "14fceeac99eb8419a2796d1958fc2050d489bf5a3eb170ef16a667060344ba90";

    fn chain() -> Chain {
        Chain {
            chain_type: 0,
            id: 0,
        }
    }

    fn make_tree() -> UTXOMerkletree {
        UTXOMerkletree::create(
            Database::in_memory(),
            chain(),
            TXID_VERSION,
            |_, _, _, _, _| true,
        )
    }

    fn empty_ciphertext() -> LegacyCommitmentCiphertext {
        LegacyCommitmentCiphertext {
            ciphertext: Ciphertext {
                iv: String::new(),
                tag: String::new(),
                data: vec![],
            },
            ephemeral_keys: vec![String::new(), String::new()],
            memo: vec![String::new()],
        }
    }

    fn leaf(hash: &str) -> Commitment {
        Commitment::LegacyEncryptedCommitment(LegacyEncryptedCommitment {
            hash: hash.to_string(),
            txid: "0x1097c636f99f179de275635277e458820485039b0a37088a5d657b999f73b59b".into(),
            block_number: 0,
            timestamp: None,
            utxo_tree: 0,
            utxo_index: 0,
            ciphertext: empty_ciphertext(),
            railgun_txid: None,
        })
    }

    // src/merkletree/__tests__/utxo-merkletree.test.ts: 'Should hash left/right'
    #[test]
    fn hash_left_right_kav() {
        let vectors = [
            (
                "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a",
                "2a92a4c8d7c21d97d946951043d11954de794cd506093dbbb97ada64c14b203b",
                "106dc6dc79863b23dc1a63c7ca40e8c22bb830e449b75a2286c7f7b0b87ae6c3",
            ),
            (
                "0db945439b762ad08f144bcccc3746773b332e8a0045a11d87662dc227923df5",
                "09ce612d20912e20cde93cd2a03fcccdfdce5910242b555ff35b5373041bf329",
                "063c1c7dfb4b63255c492bb6b32d57eddddcb1c78cfb990e7b35416cf966ed79",
            ),
            (
                "09cf3efaeb0190e482c9f9cf1534f17fbf0ed1537c26db9faf26f3d55140804d",
                "2651021f2d224338f1c9f408db74111c98e7381072b9fcd640bd4f748584e769",
                "1576a4dd906cab90e381775c1c9bb1d713f7f02c7ec0911a8bc38a1c4b0bf69e",
            ),
        ];
        for (l, r, result) in vectors {
            assert_eq!(crate::hash_left_right(l, r), result);
        }
    }

    // 'Should calculate zero values'
    #[test]
    fn zero_values_kav() {
        let tree = make_tree();
        let expected = [
            "0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc",
            "01c405064436affeae1fc8e30b2e417b4243bbb819adca3b55bb32efc3e43a4f",
            "0888d37652d10d1781db54b70af87b42a2916e87118f507218f9a42a58e85ed2",
            "183f531ead7217ebc316b4c02a2aad5ad87a1d56d4fb9ed81bf84f644549eaf5",
            "093c48f1ecedf2baec231f0af848a57a76c6cf05b290a396707972e1defd17df",
            "1437bb465994e0453357c17a676b9fdba554e215795ebc17ea5012770dfb77c7",
            "12359ef9572912b49f44556b8bbbfa69318955352f54cfa35cb0f41309ed445a",
            "2dc656dadc82cf7a4707786f4d682b0f130b6515f7927bde48214d37ec25a46c",
            "2500bdfc1592791583acefd050bc439a87f1d8e8697eb773e8e69b44973e6fdc",
            "244ae3b19397e842778b254cd15c037ed49190141b288ff10eb1390b34dc2c31",
            "0ca2b107491c8ca6e5f7e22403ea8529c1e349a1057b8713e09ca9f5b9294d46",
            "18593c75a9e42af27b5e5b56b99c4c6a5d7e7d6e362f00c8e3f69aeebce52313",
            "17aca915b237b04f873518947a1f440f0c1477a6ac79299b3be46858137d4bfb",
            "2726c22ad3d9e23414887e8233ee83cc51603f58c48a9c9e33cb1f306d4365c0",
            "08c5bd0f85cef2f8c3c1412a2b69ee943c6925ecf79798bb2b84e1b76d26871f",
            "27f7c465045e0a4d8bec7c13e41d793734c50006ca08920732ce8c3096261435",
            "14fceeac99eb8419a2796d1958fc2050d489bf5a3eb170ef16a667060344ba90",
        ];
        assert_eq!(tree.zeros(), expected);
    }

    // 'Should get DB paths' (V2 vector)
    #[test]
    fn db_paths_kav() {
        let t0 = UTXOMerkletree::create(
            Database::in_memory(),
            Chain {
                chain_type: ChainType::Evm as u8,
                id: 0,
            },
            TXID_VERSION,
            |_, _, _, _, _| true,
        );
        let result0 = [
            "000000000000000000000000000000006d65726b6c65747265652d6572633230",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000005632",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000005",
        ];
        let prefix0: Vec<String> = t0
            .get_tree_db_prefix(0)
            .iter()
            .map(|b| hexlify(b, false))
            .collect();
        assert_eq!(prefix0, result0[0..4]);
        let path0: Vec<String> = t0
            .get_node_hash_db_path(0, 1, 5)
            .iter()
            .map(|b| hexlify(b, false))
            .collect();
        assert_eq!(path0, result0);

        let t1 = UTXOMerkletree::create(
            Database::in_memory(),
            Chain {
                chain_type: ChainType::Evm as u8,
                id: 4,
            },
            TXID_VERSION,
            |_, _, _, _, _| true,
        );
        let result1 = [
            "000000000000000000000000000000006d65726b6c65747265652d6572633230",
            "0000000000000000000000000000000000000000000000000000000000000004",
            "0000000000000000000000000000000000000000000000000000000000005632",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000007",
            "000000000000000000000000000000000000000000000000000000000000000a",
        ];
        let path1: Vec<String> = t1
            .get_node_hash_db_path(2, 7, 10)
            .iter()
            .map(|b| hexlify(b, false))
            .collect();
        assert_eq!(path1, result1);
    }

    // 'Should get empty merkle root'
    #[test]
    fn empty_merkle_root_kav() {
        let mut tree = make_tree();
        assert_eq!(
            railgun_models::merkletree_types::merkle_zero_value(),
            "0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc"
        );
        assert_eq!(tree.get_root(0), EMPTY_ROOT);
    }

    // 'Should update merkle tree correctly'
    #[test]
    fn update_merkle_tree_correctly() {
        let mut tree = make_tree();
        assert_eq!(tree.get_root(0), EMPTY_ROOT);

        // Queue at index 5 (gap) -> not inserted.
        let seven: Vec<Commitment> = [
            "ab2f9d1ebd74c3e1f1ccee452a80ae27a94f14a542a4fd8b0c9ad9a1b7f9ffe5",
            "8902638fe6fc05e4f1cd7c06940d6217591a0ccb003ed45198782fbff38e9f2d",
            "19889087c2ff4c4a164060a832a3ba11cce0c2e2dbd42da10c57101efb966fcd",
            "9f5e8310e384c6a0840699951d67810c6d90fd3f265bda66e9385fcb7142373d",
            "4c71361b89e9b6b55b094a0f0de4451d8306786b2626d67b3810c9b61fbf45b6",
            "b2eabd832f0bb9d8b42399a56821a565eec64669d7a55b828c8af2a541b044d6",
            "817e6732d170352ea6517c9640757570d4ea71c660603f9d7a060b2f2eb27be6",
        ]
        .iter()
        .map(|h| leaf(h))
        .collect();
        tree.queue_leaves(0, 5, seven);
        tree.update_trees_from_write_queue();
        assert_eq!(tree.get_tree_length(0), 0);
        assert_eq!(tree.get_root(0), EMPTY_ROOT);

        // Queue at index 3 (gap) -> not inserted.
        tree.queue_leaves(0, 3, vec![leaf("04")]);
        assert_eq!(tree.get_tree_length(0), 0);
        assert_eq!(tree.get_root(0), EMPTY_ROOT);

        // Queue 0..3 -> inserted (4 elements: 01,02,03 + earlier? no, 3 leaves).
        tree.queue_leaves(0, 0, vec![leaf("01"), leaf("02"), leaf("03")]);
        tree.update_trees_from_write_queue();
        assert_eq!(tree.get_tree_length(0), 4);
        assert_eq!(
            tree.get_root(0),
            "2f4c02f094b5c881b9a2d25539d50bc839652b96acb147b81181922064b25f29"
        );

        // Queue index 4 twice (dedup) then again -> length 12 after the gap fills.
        tree.queue_leaves(0, 4, vec![leaf("05")]);
        tree.queue_leaves(0, 4, vec![leaf("05")]);
        tree.update_trees_from_write_queue();
        tree.queue_leaves(0, 4, vec![leaf("05")]);
        tree.update_trees_from_write_queue();
        assert_eq!(tree.get_tree_length(0), 12);
        assert_eq!(
            tree.get_root(0),
            "1955726bb6619868e0435b3342b33644c8ecc9579bcbc31b41e0175d766a1e5c"
        );
    }

    // 'Should insert and retrieve commitment objects'
    #[test]
    fn insert_and_retrieve_commitments() {
        let mut tree = make_tree();
        let c0 = Commitment::LegacyEncryptedCommitment(LegacyEncryptedCommitment {
            hash: "02".into(),
            txid: "0x1097c636f99f179de275635277e458820485039b0a37088a5d657b999f73b59b".into(),
            block_number: 0,
            timestamp: None,
            utxo_tree: 0,
            utxo_index: 0,
            ciphertext: LegacyCommitmentCiphertext {
                ciphertext: Ciphertext {
                    iv: "02".into(),
                    tag: "05".into(),
                    data: vec!["03".into(), "04".into()],
                },
                ephemeral_keys: vec!["00".into(), "00".into()],
                memo: vec![String::new()],
            },
            railgun_txid: None,
        });
        tree.queue_leaves(0, 0, vec![c0.clone()]);
        tree.update_trees_from_write_queue();
        assert_eq!(tree.get_commitment(0, 0).unwrap(), c0);
    }

    // 'Should generate and validate merkle proofs'
    #[test]
    fn generate_and_validate_merkle_proofs() {
        let mut tree = make_tree();
        let leaves: Vec<Commitment> = ["02", "04", "08", "10", "20", "40"]
            .iter()
            .map(|h| leaf(h))
            .collect();
        tree.queue_leaves(0, 0, leaves);
        tree.update_trees_from_write_queue();

        let proof = tree.get_merkle_proof(0, 3);
        assert_eq!(proof.leaf, "10");
        assert_eq!(proof.elements.len(), 16);
        assert_eq!(proof.elements[0], "08");
        assert_eq!(
            proof.elements[1],
            "022678592fe7f282774b001df184b9448e46f7bc5b4d879f7f545a09f6e77feb"
        );
        assert_eq!(
            proof.indices,
            "0000000000000000000000000000000000000000000000000000000000000003"
        );
        assert_eq!(
            proof.root,
            "215b6e027da417c086db7e55d19c6d2cc270a0c2d54a2b2cd9ae8d40d0c250b3"
        );
        assert!(verify_merkle_proof(&proof));

        // Insert 600 leaves into tree 1.
        let leaves2: Vec<Commitment> = (0..600u32).map(|i| leaf(&format!("{i:x}"))).collect();
        tree.queue_leaves(1, 0, leaves2);
        tree.update_trees_from_write_queue();

        let mut proof2 = tree.get_merkle_proof(1, 34);
        assert_ne!(proof2.root, proof.root);
        assert_eq!(proof2.leaf, "22");
        assert_eq!(
            proof2.root,
            "1abfe84b40d5fbbebf8fce3a5838633f6f4de4d6a63c5a26c3eed8001e00e587"
        );
        assert!(verify_merkle_proof(&proof2));
        proof2.root = proof.root.clone();
        assert!(!verify_merkle_proof(&proof2));
        proof2.elements = proof.elements.clone();
        assert!(!verify_merkle_proof(&proof2));
    }

    // "Shouldn't write invalid batches"
    #[test]
    fn shouldnt_write_invalid_batches() {
        let mut tree = UTXOMerkletree::create(
            Database::in_memory(),
            chain(),
            TXID_VERSION,
            |_, _, _, _, _| false,
        );
        assert_eq!(tree.get_root(0), EMPTY_ROOT);
        let leaves: Vec<Commitment> = ["02", "04", "08", "10", "20", "40"]
            .iter()
            .map(|h| leaf(h))
            .collect();
        tree.queue_leaves(0, 0, leaves);
        tree.update_trees_from_write_queue();
        assert_eq!(tree.get_root(0), EMPTY_ROOT);
    }

    // 'Should store nullifiers'
    #[test]
    fn store_nullifiers() {
        let mut tree = make_tree();
        assert_eq!(tree.get_nullifier_txid("00", None, None), None);
        tree.nullify(&[Nullifier {
            nullifier: "00".into(),
            tree_number: 0,
            txid: "01".into(),
            block_number: 0,
        }]);
        assert_eq!(
            tree.get_nullifier_txid("00", None, None).as_deref(),
            Some("01")
        );
    }

    // 'Should store and retrieve unshield events'
    #[test]
    fn store_and_retrieve_unshield_events() {
        let mut tree = make_tree();
        assert_eq!(tree.get_all_unshield_events_for_txid("0"), vec![]);
        let mk = |txid: &str, token: &str, amount: &str, eli: u32| UnshieldStoredEvent {
            txid: txid.into(),
            timestamp: None,
            to_address: "123".into(),
            token_type: 1,
            token_address: token.into(),
            token_sub_id: "0x00".into(),
            amount: amount.into(),
            fee: "0x7890".into(),
            block_number: 0,
            event_log_index: Some(eli),
            railgun_txid: None,
            pois_per_list: None,
        };
        let a1 = mk("0", "0x4567", "0x1234567890", 0);
        let b1 = mk("1", "0x1234", "0x123456", 0);
        let b2 = mk("1", "0x1234", "0x123456", 1);
        tree.add_unshield_events(&[a1.clone(), b1.clone(), b2.clone()], false);

        assert_eq!(tree.get_all_unshield_events_for_txid("0"), vec![a1]);
        let mut for_1 = tree.get_all_unshield_events_for_txid("1");
        for_1.sort_by_key(|e| e.event_log_index);
        assert_eq!(for_1, vec![b1, b2]);
    }

    // 'Should return latest tree'
    #[test]
    fn return_latest_tree() {
        let mut tree = make_tree();
        assert_eq!(tree.latest_tree(), 0);
        tree.queue_leaves(0, 0, vec![leaf("02")]);
        tree.update_trees_from_write_queue();
        assert_eq!(tree.latest_tree(), 0);
        let mut expected1 = MerkletreesMetadata {
            trees: Default::default(),
        };
        expected1.trees.insert(
            0,
            TreeMetadata {
                scanned_height: 1,
                invalid_merkleroot_details: None,
            },
        );
        assert_eq!(tree.get_merkletrees_metadata(), Some(expected1));

        tree.queue_leaves(1, 0, vec![leaf("02")]);
        tree.update_trees_from_write_queue();
        assert_eq!(tree.latest_tree(), 1);
        assert_eq!(tree.get_tree_length(0), 1);
        assert_eq!(tree.get_tree_length(1), 1);
    }

    // 'Should store and retrieve trees metadata'
    #[test]
    fn store_and_retrieve_trees_metadata() {
        let mut tree = make_tree();
        assert_eq!(tree.get_merkletrees_metadata(), None);
        let mut new_metadata = MerkletreesMetadata {
            trees: Default::default(),
        };
        new_metadata.trees.insert(
            0,
            TreeMetadata {
                scanned_height: 127,
                invalid_merkleroot_details: None,
            },
        );
        new_metadata.trees.insert(
            1,
            TreeMetadata {
                scanned_height: 333,
                invalid_merkleroot_details: None,
            },
        );
        new_metadata.trees.insert(
            2,
            TreeMetadata {
                scanned_height: 0,
                invalid_merkleroot_details: None,
            },
        );
        tree.store_merkletrees_metadata(&new_metadata);
        assert_eq!(tree.get_merkletrees_metadata(), Some(new_metadata));
        assert_eq!(tree.latest_tree(), 1);
    }

    // 'Should store, update and remove invalid merkleroot details'
    #[test]
    fn invalid_merkleroot_details_lifecycle() {
        let mut tree = make_tree();
        let block_number = 10_000_000;
        tree.update_invalid_merkleroot_details(0, 100, block_number);
        assert_eq!(
            tree.invalid_merkleroot_details(0),
            Some(railgun_models::merkletree_types::InvalidMerklerootDetails {
                position: 100,
                block_number
            })
        );
        tree.update_invalid_merkleroot_details(0, 50, block_number);
        assert_eq!(
            tree.invalid_merkleroot_details(0),
            Some(railgun_models::merkletree_types::InvalidMerklerootDetails {
                position: 50,
                block_number
            })
        );
        tree.remove_invalid_merkleroot_details_if_necessary(0, 30);
        assert_eq!(
            tree.invalid_merkleroot_details(0).map(|d| d.position),
            Some(50)
        );
        tree.remove_invalid_merkleroot_details_if_necessary(1, 30);
        assert_eq!(
            tree.invalid_merkleroot_details(0).map(|d| d.position),
            Some(50)
        );

        let metadata = tree.get_merkletrees_metadata().unwrap();
        assert_eq!(
            metadata.trees[&0].invalid_merkleroot_details,
            Some(railgun_models::merkletree_types::InvalidMerklerootDetails {
                position: 50,
                block_number
            })
        );
        assert_eq!(tree.get_first_invalid_merkleroot_tree(), Some(0));
        tree.remove_invalid_merkleroot_details_if_necessary(0, 100);
        assert_eq!(tree.get_first_invalid_merkleroot_tree(), None);
    }
}

#[cfg(test)]
mod nullifier_collision_tests {
    use super::*;
    use railgun_models::engine_types::Chain;

    const TXID_VERSION: TXIDVersion = TXIDVersion::V2_PoseidonMerkle;

    fn make() -> UTXOMerkletree {
        UTXOMerkletree::create(
            Database::in_memory(),
            Chain {
                chain_type: 0,
                id: 0,
            },
            TXID_VERSION,
            |_, _, _, _, _| true,
        )
    }

    fn n(nullifier: &str, tree: u32, txid: &str) -> Nullifier {
        Nullifier {
            nullifier: nullifier.into(),
            tree_number: tree,
            txid: txid.into(),
            block_number: 0,
        }
    }

    // The TS test overrides `latestTree` to a fixed value; we pass it explicitly
    // via the `latest_tree_override` argument.
    #[test]
    fn retrieve_nullifier_txid_from_specific_tree() {
        let mut t = make();
        t.nullify(&[n("COLLISION", 0, "1000")]);
        t.nullify(&[n("COLLISION", 1, "1001")]);
        assert_eq!(
            t.get_nullifier_txid("COLLISION", Some(0), None).as_deref(),
            Some("1000")
        );
        assert_eq!(
            t.get_nullifier_txid("COLLISION", Some(1), None).as_deref(),
            Some("1001")
        );
    }

    #[test]
    fn latest_tree_priority() {
        let mut t = make();
        t.nullify(&[n("COLLISION", 0, "1000")]);
        t.nullify(&[n("COLLISION", 1, "1001")]);
        assert_eq!(
            t.get_nullifier_txid("COLLISION", None, Some(1)).as_deref(),
            Some("1001")
        );
    }

    #[test]
    fn find_in_older_trees() {
        let mut t = make();
        t.nullify(&[n("UNIQUE0", 0, "2000")]);
        assert_eq!(
            t.get_nullifier_txid("UNIQUE0", None, Some(1)).as_deref(),
            Some("2000")
        );
    }

    #[test]
    fn undefined_for_nonexistent() {
        let mut t = make();
        assert_eq!(t.get_nullifier_txid("NONEXISTENT", None, Some(1)), None);
        assert_eq!(t.get_nullifier_txid("NONEXISTENT", Some(0), None), None);
        assert_eq!(t.get_nullifier_txid("NONEXISTENT", Some(1), None), None);
    }

    #[test]
    fn batch_insertion() {
        let mut t = make();
        t.nullify(&[n("A", 0, "00A0"), n("B", 0, "00B0"), n("C", 1, "00C0")]);
        assert_eq!(
            t.get_nullifier_txid("A", Some(0), None).as_deref(),
            Some("00a0")
        );
        assert_eq!(
            t.get_nullifier_txid("B", Some(0), None).as_deref(),
            Some("00b0")
        );
        assert_eq!(
            t.get_nullifier_txid("C", Some(1), None).as_deref(),
            Some("00c0")
        );
        assert_eq!(
            t.get_nullifier_txid("A", None, Some(1)).as_deref(),
            Some("00a0")
        );
        assert_eq!(
            t.get_nullifier_txid("C", None, Some(1)).as_deref(),
            Some("00c0")
        );
    }

    #[test]
    fn overwrite_same_tree() {
        let mut t = make();
        t.nullify(&[n("OVERWRITE", 0, "1111")]);
        assert_eq!(
            t.get_nullifier_txid("OVERWRITE", Some(0), None).as_deref(),
            Some("1111")
        );
        t.nullify(&[n("OVERWRITE", 0, "2222")]);
        assert_eq!(
            t.get_nullifier_txid("OVERWRITE", Some(0), None).as_deref(),
            Some("2222")
        );
    }

    #[test]
    fn sparse_tree_usage() {
        let mut t = make();
        t.nullify(&[n("SPARSE", 0, "3000")]);
        t.nullify(&[n("SPARSE", 2, "3002")]);
        assert_eq!(
            t.get_nullifier_txid("SPARSE", None, Some(2)).as_deref(),
            Some("3002")
        );
        assert_eq!(
            t.get_nullifier_txid("SPARSE", Some(0), None).as_deref(),
            Some("3000")
        );
        assert_eq!(t.get_nullifier_txid("SPARSE", Some(1), None), None);
        assert_eq!(
            t.get_nullifier_txid("SPARSE", Some(2), None).as_deref(),
            Some("3002")
        );
    }
}
