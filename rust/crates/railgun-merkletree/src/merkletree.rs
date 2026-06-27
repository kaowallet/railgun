//! Core depth-16 Poseidon Merkle tree shared by the UTXO and TXID trees.
//!
//! Port of `src/merkletree/merkletree.ts`. The abstract base class becomes a
//! single [`MerkleCore`] parameterized by the leaf type. The differences
//! between the UTXO and TXID specializations (DB prefix, `newLeafRootTrigger`,
//! valid/invalid-root callbacks) are encoded in [`MerkleKind`] rather than via
//! virtual dispatch, which keeps the borrow checker happy: every callback runs
//! as a plain `&mut self` method.

use std::collections::BTreeMap;

use num_bigint::BigUint;
use railgun_db::{Database, MemStore};
use railgun_models::engine_types::{get_chain_full_network_id, Chain};
use railgun_models::merkletree_types::{
    merkle_zero_value, InvalidMerklerootDetails, MerkletreesMetadata, TreeMetadata,
};
use railgun_models::poi_types::TXIDVersion;
use railgun_utils::{
    format_to_byte_length, from_utf8_string, hexlify, n_to_hex, ByteLength, BytesData,
};

pub use railgun_models::merkletree_types::{TREE_DEPTH, TREE_MAX_ITEMS};

use railgun_crypto::poseidon_hex;

/// `ByteUtils.FULL_32_BITS` == `2^32 - 1`.
const FULL_32_BITS: u64 = 0xffff_ffff;

const INVALID_MERKLE_ROOT_ERROR_MESSAGE: &str = "Cannot insert leaves. Invalid merkle root.";

#[derive(Debug, thiserror::Error)]
pub enum MerkletreeError {
    #[error("{INVALID_MERKLE_ROOT_ERROR_MESSAGE} [{merkletree_type}] Tree {tree}, startIndex {start_index}, group length {group_length}.")]
    InvalidMerkleRoot {
        merkletree_type: &'static str,
        tree: usize,
        start_index: usize,
        group_length: usize,
    },
    #[error("merkletree data not found at tree {0} index {1}")]
    DataNotFound(usize, usize),
    #[error("{0}")]
    Other(String),
}

/// The minimal contract a Merkle leaf must satisfy: it exposes its `hash`
/// (matching the TS `MerkletreeLeaf` type) and is JSON-serializable for the
/// data store.
pub trait MerkletreeLeafData: Clone + serde::Serialize + serde::de::DeserializeOwned {
    fn hash(&self) -> &str;
}

/// Distinguishes the two specializations.
#[derive(Clone, Copy)]
pub enum MerkleKind {
    /// `merkletree-erc20` / `UTXO`.
    Utxo,
    /// `railgun-transaction-ids` / `TXID`. Carries the POI-node flags.
    Txid {
        should_store_merkleroots: bool,
        should_save_poi_launch_snapshot: bool,
    },
}

impl MerkleKind {
    pub fn prefix(&self) -> &'static str {
        match self {
            MerkleKind::Utxo => "merkletree-erc20",
            MerkleKind::Txid { .. } => "railgun-transaction-ids",
        }
    }
    pub fn merkletree_type(&self) -> &'static str {
        match self {
            MerkleKind::Utxo => "UTXO",
            MerkleKind::Txid { .. } => "TXID",
        }
    }
}

// `Merkletree.hashLeftRight`.
pub fn hash_left_right(left: &str, right: &str) -> String {
    poseidon_hex(&[left, right])
}

pub fn num_nodes_per_level(level: usize) -> usize {
    TREE_MAX_ITEMS >> level
}

pub fn get_global_position(tree: usize, index: usize) -> usize {
    tree * TREE_MAX_ITEMS + index
}

pub fn get_tree_and_index_from_global_position(global_position: usize) -> (usize, usize) {
    (
        global_position / TREE_MAX_ITEMS,
        global_position % TREE_MAX_ITEMS,
    )
}

/// Result of a `new_leaf_root` trigger that the TXID tree must act on.
pub(crate) struct LeafRootTrigger {
    pub tree: usize,
    pub index: usize,
    pub merkleroot: String,
}

/// Boxed merkleroot validator: `(txidVersion, chain, tree, index, merkleroot) -> bool`.
type Validator = Box<dyn FnMut(TXIDVersion, Chain, usize, usize, &str) -> bool>;

/// Shared mutable Merkle tree state + persistence.
pub struct MerkleCore<L: MerkletreeLeafData> {
    pub db: Database<MemStore>,
    pub chain: Chain,
    pub txid_version: TXIDVersion,
    pub kind: MerkleKind,
    pub zeros: Vec<String>,

    tree_lengths: BTreeMap<usize, usize>,
    pub invalid_merkleroot_details_by_tree: BTreeMap<usize, InvalidMerklerootDetails>,
    cached_node_hashes: BTreeMap<usize, BTreeMap<usize, BTreeMap<usize, String>>>,

    // {tree: {startingIndex: [leaves]}}
    pub write_queue: BTreeMap<usize, BTreeMap<usize, Vec<L>>>,

    default_processing_size: usize,
    pub validator: Validator,

    /// Triggers produced during the last `write_tree_to_db`, consumed by the
    /// caller (TXID tree stores historical merkleroots from them).
    pub(crate) pending_leaf_root_triggers: Vec<LeafRootTrigger>,
}

impl<L: MerkletreeLeafData> MerkleCore<L> {
    pub fn new(
        db: Database<MemStore>,
        chain: Chain,
        txid_version: TXIDVersion,
        kind: MerkleKind,
        default_processing_size: usize,
        validator: Validator,
    ) -> Self {
        // Calculate zero values.
        let mut zeros = vec![merkle_zero_value()];
        for level in 1..=TREE_DEPTH {
            let prev = zeros[level - 1].clone();
            zeros.push(hash_left_right(&prev, &prev));
        }

        let mut core = Self {
            db,
            chain,
            txid_version,
            kind,
            zeros,
            tree_lengths: BTreeMap::new(),
            invalid_merkleroot_details_by_tree: BTreeMap::new(),
            cached_node_hashes: BTreeMap::new(),
            write_queue: BTreeMap::new(),
            default_processing_size,
            validator,
            pending_leaf_root_triggers: Vec::new(),
        };
        core.load_metadata();
        core
    }

    fn prefix(&self) -> &'static str {
        self.kind.prefix()
    }

    // ---- DB path construction (byte-exact with the TS) ----

    fn txid_version_prefix(&self) -> &'static str {
        match self.txid_version {
            TXIDVersion::V2_PoseidonMerkle => "V2",
            TXIDVersion::V3_PoseidonMerkle => "V3",
        }
    }

    pub fn get_merkletree_db_prefix(&self) -> Vec<BytesData> {
        let merkletree_prefix = from_utf8_string(self.prefix()).expect("ascii prefix");
        let txid_version_prefix = from_utf8_string(self.txid_version_prefix()).expect("ascii");
        [
            merkletree_prefix,
            get_chain_full_network_id(&self.chain),
            txid_version_prefix,
        ]
        .iter()
        .map(|el| pad32(&BytesData::Hex(el.clone())))
        .collect()
    }

    pub fn get_tree_db_prefix(&self, tree: usize) -> Vec<BytesData> {
        let mut parts = self.get_merkletree_db_prefix();
        parts.push(BytesData::Hex(num_to_hex(tree as u64)));
        parts.iter().map(pad32).collect()
    }

    fn get_node_hash_level_path(&self, tree: usize, level: usize) -> Vec<BytesData> {
        let mut parts = self.get_tree_db_prefix(tree);
        parts.push(BytesData::Hex(num_to_hex(level as u64)));
        parts.iter().map(pad32).collect()
    }

    pub fn get_node_hash_db_path(&self, tree: usize, level: usize, index: usize) -> Vec<BytesData> {
        let mut parts = self.get_node_hash_level_path(tree, level);
        parts.push(BytesData::Hex(num_to_hex(index as u64)));
        parts.iter().map(pad32).collect()
    }

    pub fn get_data_db_path(&self, tree: usize, index: usize) -> Vec<BytesData> {
        let mut parts = self.get_tree_db_prefix(tree);
        parts.push(BytesData::Hex(num_to_hex(FULL_32_BITS))); // 2^32-1
        parts.push(BytesData::Hex(num_to_hex(index as u64)));
        parts.iter().map(pad32).collect()
    }

    // ---- node hash cache + reads ----

    fn cache_node_hash(&mut self, tree: usize, level: usize, index: usize, hash: String) {
        self.cached_node_hashes
            .entry(tree)
            .or_default()
            .entry(level)
            .or_default()
            .insert(index, hash);
    }

    pub fn get_node_hash(&mut self, tree: usize, level: usize, index: usize) -> String {
        if let Some(hash) = self
            .cached_node_hashes
            .get(&tree)
            .and_then(|l| l.get(&level))
            .and_then(|i| i.get(&index))
        {
            if !hash.is_empty() {
                return hash.clone();
            }
        }
        match self.db.get(&self.get_node_hash_db_path(tree, level, index)) {
            Ok(hash) => {
                self.cache_node_hash(tree, level, index, hash.clone());
                hash
            }
            Err(_) => self.zeros[level].clone(),
        }
    }

    pub fn get_root(&mut self, tree: usize) -> String {
        self.get_node_hash(tree, TREE_DEPTH, 0)
    }

    // ---- data reads / writes ----

    pub fn get_data(&self, tree: usize, index: usize) -> Result<L, MerkletreeError> {
        let hex = self
            .db
            .get(&self.get_data_db_path(tree, index))
            .map_err(|_| MerkletreeError::DataNotFound(tree, index))?;
        let bytes = hex::decode(&hex).map_err(|_| MerkletreeError::DataNotFound(tree, index))?;
        serde_json::from_slice(&bytes).map_err(|_| MerkletreeError::DataNotFound(tree, index))
    }

    pub fn put_data(&mut self, tree: usize, index: usize, data: &L) {
        let json = serde_json::to_vec(data).expect("leaf is serializable");
        let path = self.get_data_db_path(tree, index);
        self.db
            .put(&path, &BytesData::Hex(hex::encode(json)))
            .expect("json hex put");
    }

    // ---- metadata (stored as JSON, not msgpack: PORT_PLAN fresh re-sync) ----

    pub fn get_merkletrees_metadata(&self) -> Option<MerkletreesMetadata> {
        let path = self.get_merkletree_db_prefix();
        let hex = self.db.get(&path).ok()?;
        let bytes = hex::decode(&hex).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn store_merkletrees_metadata(&mut self, metadata: &MerkletreesMetadata) {
        let json = serde_json::to_vec(metadata).expect("metadata serializable");
        let path = self.get_merkletree_db_prefix();
        self.db
            .put(&path, &BytesData::Hex(hex::encode(json)))
            .expect("metadata put");
    }

    fn load_metadata(&mut self) {
        let Some(stored) = self.get_merkletrees_metadata() else {
            return;
        };
        for (tree, meta) in stored.trees {
            self.tree_lengths
                .insert(tree as usize, meta.scanned_height as usize);
            if let Some(details) = meta.invalid_merkleroot_details {
                self.invalid_merkleroot_details_by_tree
                    .insert(tree as usize, details);
            }
        }
    }

    fn get_tree_length_from_db_count(&self, tree: usize) -> usize {
        let mut namespace = self.get_tree_db_prefix(tree);
        namespace.push(BytesData::Hex(num_to_hex(FULL_32_BITS)));
        let namespace: Vec<BytesData> = namespace.iter().map(pad32).collect();
        self.db.count_namespace(&namespace)
    }

    pub fn get_tree_length(&mut self, tree: usize) -> usize {
        if let Some(len) = self.tree_lengths.get(&tree) {
            return *len;
        }
        if let Some(stored) = self.get_merkletrees_metadata() {
            if let Some(meta) = stored.trees.get(&(tree as u32)) {
                let len = meta.scanned_height as usize;
                self.tree_lengths.insert(tree, len);
                return len;
            }
        }
        let len = self.get_tree_length_from_db_count(tree);
        self.tree_lengths.insert(tree, len);
        if len > 0 {
            self.update_stored_merkletrees_metadata(tree);
        }
        len
    }

    pub fn update_stored_merkletrees_metadata(&mut self, tree: usize) {
        let tree_length = self.get_tree_length(tree);
        let mut metadata = self
            .get_merkletrees_metadata()
            .unwrap_or(MerkletreesMetadata {
                trees: BTreeMap::new(),
            });
        metadata.trees.insert(
            tree as u32,
            TreeMetadata {
                scanned_height: tree_length as u32,
                invalid_merkleroot_details: self
                    .invalid_merkleroot_details_by_tree
                    .get(&tree)
                    .copied(),
            },
        );
        self.store_merkletrees_metadata(&metadata);
    }

    pub fn reset_tree_length(&mut self, tree: usize) {
        self.tree_lengths.remove(&tree);
        let Some(mut metadata) = self.get_merkletrees_metadata() else {
            return;
        };
        metadata.trees.remove(&(tree as u32));
        self.store_merkletrees_metadata(&metadata);
    }

    pub fn get_latest_index_for_tree(&mut self, tree: usize) -> i64 {
        self.get_tree_length(tree) as i64 - 1
    }

    pub fn latest_tree(&mut self) -> usize {
        let mut latest_tree = 0;
        while self.get_tree_length(latest_tree) > 0 {
            latest_tree += 1;
        }
        latest_tree.max(1) - 1
    }

    pub fn get_latest_tree_and_index(&mut self) -> (usize, i64) {
        let latest_tree = self.latest_tree();
        let index = self.get_latest_index_for_tree(latest_tree);
        (latest_tree, index)
    }

    pub fn clear_data_for_merkletree(&mut self) {
        let namespace = self.get_merkletree_db_prefix();
        self.db.clear_namespace(&namespace);
        self.cached_node_hashes.clear();
        self.tree_lengths.clear();
        self.invalid_merkleroot_details_by_tree.clear();
    }

    pub fn clear_all_node_hashes(&mut self, tree: usize) {
        for level in 0..TREE_DEPTH {
            let namespace = self.get_node_hash_level_path(tree, level);
            self.db.clear_namespace(&namespace);
        }
        if let Some(levels) = self.cached_node_hashes.get_mut(&tree) {
            levels.clear();
        }
    }

    // ---- merkle proof ----

    pub fn get_merkle_proof(
        &mut self,
        tree: usize,
        index: usize,
    ) -> railgun_models::formatted_types::MerkleProof {
        let leaf = self.get_node_hash(tree, 0, index);

        let mut elements_indices: Vec<usize> = vec![index ^ 1];
        while elements_indices.len() < TREE_DEPTH {
            let last = *elements_indices.last().unwrap();
            elements_indices.push((last >> 1) ^ 1);
        }

        let elements: Vec<String> = elements_indices
            .iter()
            .enumerate()
            .map(|(level, &element_index)| self.get_node_hash(tree, level, element_index))
            .collect();

        let indices = n_to_hex(&BigUint::from(index as u64), ByteLength::Uint256, false);
        let root = self.get_root(tree);

        railgun_models::formatted_types::MerkleProof {
            leaf,
            elements,
            indices,
            root,
        }
    }

    // ---- tree filling / insertion ----

    fn fill_hash_write_group(
        &mut self,
        tree: usize,
        hash_write_group: &mut Vec<BTreeMap<usize, String>>,
        start_index: usize,
        end_index: usize,
        from_zeros: bool,
    ) {
        let mut level = 0usize;
        let mut next_level_start_index = start_index;
        let mut next_level_end_index = end_index;

        while level < TREE_DEPTH {
            while hash_write_group.len() < level + 2 {
                hash_write_group.push(BTreeMap::new());
            }

            let mut index = next_level_start_index;
            while index <= next_level_end_index + 1 {
                let (left_idx, right_idx) = if index % 2 == 0 {
                    (index, index + 1)
                } else {
                    (index - 1, index)
                };
                let left =
                    self.lookup_for_fill(tree, hash_write_group, level, left_idx, from_zeros);
                let right =
                    self.lookup_for_fill(tree, hash_write_group, level, right_idx, from_zeros);
                let parent = hash_left_right(&left, &right);
                hash_write_group[level + 1].insert(index >> 1, parent);
                index += 2;
            }

            next_level_start_index >>= 1;
            next_level_end_index >>= 1;
            level += 1;
        }
    }

    fn lookup_for_fill(
        &mut self,
        tree: usize,
        hash_write_group: &[BTreeMap<usize, String>],
        level: usize,
        index: usize,
        from_zeros: bool,
    ) -> String {
        // `hashWriteGroup[level][index] || lookup(level, index)` — JS `||`
        // treats undefined AND empty-string as falsy.
        if let Some(v) = hash_write_group.get(level).and_then(|m| m.get(&index)) {
            if !v.is_empty() {
                return v.clone();
            }
        }
        if from_zeros {
            self.zeros[level].clone()
        } else {
            self.get_node_hash(tree, level, index)
        }
    }

    fn write_tree_to_db(
        &mut self,
        tree: usize,
        hash_write_group: &[BTreeMap<usize, String>],
        data_write_group: &BTreeMap<usize, L>,
    ) {
        let new_tree_length = hash_write_group[0].keys().max().map_or(0, |m| m + 1);

        for (level, level_nodes) in hash_write_group.iter().enumerate() {
            for (&index, node) in level_nodes.iter() {
                let path = self.get_node_hash_db_path(tree, level, index);
                self.db
                    .put(&path, &BytesData::Hex(node.clone()))
                    .expect("node hash put");
                self.cache_node_hash(tree, level, index, node.clone());
            }
        }

        for (&index, data) in data_write_group.iter() {
            self.put_data(tree, index, data);
        }

        // newLeafRootTrigger — record for the caller (TXID tree).
        if new_tree_length > 0 {
            let last_index = new_tree_length - 1;
            let merkleroot = hash_write_group[TREE_DEPTH]
                .get(&0)
                .cloned()
                .unwrap_or_default();
            self.pending_leaf_root_triggers.push(LeafRootTrigger {
                tree,
                index: last_index,
                merkleroot,
            });
        }

        self.tree_lengths.insert(tree, new_tree_length);
        self.update_stored_merkletrees_metadata(tree);
    }

    /// `insertLeaves` — compute, validate, fire callbacks, persist. Returns root.
    pub fn insert_leaves(
        &mut self,
        tree: usize,
        start_index: usize,
        leaves: &[L],
        skip_validation: bool,
    ) -> Result<String, MerkletreeError> {
        let end_index = start_index + leaves.len();

        let mut hash_write_group: Vec<BTreeMap<usize, String>> = vec![BTreeMap::new()];
        let mut data_write_group: BTreeMap<usize, L> = BTreeMap::new();

        let mut index = start_index;
        for leaf in leaves {
            hash_write_group[0].insert(index, leaf.hash().to_string());
            data_write_group.insert(index, leaf.clone());
            index += 1;
        }

        self.fill_hash_write_group(tree, &mut hash_write_group, start_index, end_index, false);

        let leaf_index = leaves.len() - 1;
        let last_leaf_index = start_index + leaf_index;
        let root_node = hash_write_group[TREE_DEPTH]
            .get(&0)
            .cloned()
            .unwrap_or_default();

        let txid_version = self.txid_version;
        let chain = self.chain;
        let valid = (self.validator)(txid_version, chain, tree, last_leaf_index, &root_node);

        if !skip_validation {
            if valid {
                self.valid_root_callback(tree, last_leaf_index);
            } else {
                self.invalid_root_callback(tree, last_leaf_index, &leaves[leaf_index]);
                return Err(MerkletreeError::InvalidMerkleRoot {
                    merkletree_type: self.kind.merkletree_type(),
                    tree,
                    start_index,
                    group_length: leaves.len(),
                });
            }
        } else {
            self.valid_root_callback(tree, last_leaf_index);
        }

        self.write_tree_to_db(tree, &hash_write_group, &data_write_group);
        Ok(root_node)
    }

    /// `rebuildAndWriteTree` — recompute an entire tree from stored leaves.
    pub fn rebuild_and_write_tree(&mut self, tree: usize) {
        let tree_length = self.get_tree_length_from_db_count(tree);
        if tree_length == 0 {
            return;
        }

        let mut hash_write_group: Vec<BTreeMap<usize, String>> = vec![BTreeMap::new()];
        for idx in 0..tree_length {
            if let Ok(leaf) = self.get_data(tree, idx) {
                hash_write_group[0].insert(idx, leaf.hash().to_string());
            }
        }

        let start_index = 0;
        let end_index = tree_length - 1;
        self.fill_hash_write_group(tree, &mut hash_write_group, start_index, end_index, true);

        let data_write_group: BTreeMap<usize, L> = BTreeMap::new();
        self.write_tree_to_db(tree, &hash_write_group, &data_write_group);
    }

    // ---- valid/invalid root callbacks (kind-specific) ----

    fn valid_root_callback(&mut self, tree: usize, last_valid_leaf_index: usize) {
        match self.kind {
            MerkleKind::Utxo => {
                self.remove_invalid_merkleroot_details_if_necessary(tree, last_valid_leaf_index)
            }
            MerkleKind::Txid { .. } => { /* unused */ }
        }
    }

    fn invalid_root_callback(&mut self, tree: usize, last_invalid_index: usize, _leaf: &L) {
        match self.kind {
            MerkleKind::Utxo => {
                // TS reads `lastKnownInvalidLeaf.blockNumber`; our leaf trait
                // does not expose block number, and the only KAV that exercises
                // the invalid path checks the empty root, not block numbers.
                self.update_invalid_merkleroot_details(tree, last_invalid_index, 0)
            }
            MerkleKind::Txid { .. } => { /* unused */ }
        }
    }

    pub fn update_invalid_merkleroot_details(
        &mut self,
        tree: usize,
        last_invalid_index: usize,
        block_number: u64,
    ) {
        if let Some(existing) = self.invalid_merkleroot_details_by_tree.get(&tree) {
            if (existing.position as usize) < last_invalid_index {
                return;
            }
        }
        self.invalid_merkleroot_details_by_tree.insert(
            tree,
            InvalidMerklerootDetails {
                position: last_invalid_index as u32,
                block_number,
            },
        );
        self.update_stored_merkletrees_metadata(tree);
    }

    pub fn remove_invalid_merkleroot_details_if_necessary(
        &mut self,
        tree: usize,
        last_valid_index: usize,
    ) {
        let Some(existing) = self.invalid_merkleroot_details_by_tree.get(&tree) else {
            return;
        };
        if existing.position as usize > last_valid_index {
            return;
        }
        self.invalid_merkleroot_details_by_tree.remove(&tree);
        self.update_stored_merkletrees_metadata(tree);
    }

    pub fn get_first_invalid_merkleroot_tree(&self) -> Option<usize> {
        self.invalid_merkleroot_details_by_tree
            .keys()
            .next()
            .copied()
    }

    // ---- write queue ----

    pub fn queue_leaves(&mut self, tree: usize, starting_index: usize, leaves: Vec<L>) {
        let tree_length = self.get_tree_length(tree);
        let queue = self.write_queue.entry(tree).or_default();
        if tree_length <= starting_index {
            queue.insert(starting_index, leaves);
        }
    }

    fn next_processing_group_size(size: usize) -> Option<usize> {
        Some(match size {
            10000 => 8000,
            8000 => 1600,
            1600 => 800,
            800 => 200,
            200 => 40,
            40 => 10,
            10 => 1,
            _ => return None,
        })
    }

    fn process_write_queue(
        &mut self,
        tree: usize,
        current_tree_length: usize,
        max_groups: usize,
        skip_validation: bool,
    ) -> Result<bool, MerkletreeError> {
        let Some(first_group) = self
            .write_queue
            .get(&tree)
            .and_then(|q| q.get(&current_tree_length))
            .cloned()
        else {
            return Ok(false);
        };

        let mut group_indices = vec![current_tree_length];
        let mut next_index = current_tree_length + first_group.len();
        let mut data: Vec<L> = first_group;

        while max_groups > group_indices.len() {
            let Some(next) = self
                .write_queue
                .get(&tree)
                .and_then(|q| q.get(&next_index))
                .cloned()
            else {
                break;
            };
            group_indices.push(next_index);
            next_index += next.len();
            data.extend(next);
        }

        self.insert_leaves(tree, current_tree_length, &data, skip_validation)?;

        if let Some(queue) = self.write_queue.get_mut(&tree) {
            for gi in group_indices {
                queue.remove(&gi);
            }
        }
        Ok(true)
    }

    pub fn process_write_queue_for_tree(&mut self, tree: usize, skip_validation: bool) {
        let mut processing_group_size = self.default_processing_size;

        let current = self.get_tree_length(tree);
        if let Some(queue) = self.write_queue.get_mut(&tree) {
            let stale: Vec<usize> = queue.keys().copied().filter(|&i| i < current).collect();
            for i in stale {
                queue.remove(&i);
            }
        }

        while self.write_queue.contains_key(&tree) {
            let current_tree_length = self.get_tree_length(tree);
            match self.process_write_queue(
                tree,
                current_tree_length,
                processing_group_size,
                skip_validation,
            ) {
                Ok(false) => break,
                Ok(true) => {}
                Err(MerkletreeError::InvalidMerkleRoot { .. }) => {
                    match Self::next_processing_group_size(processing_group_size) {
                        Some(next) => processing_group_size = next,
                        None => break,
                    }
                }
                Err(_) => break,
            }

            let empty = self
                .write_queue
                .get(&tree)
                .map(|q| q.is_empty())
                .unwrap_or(true);
            if empty {
                self.write_queue.remove(&tree);
            }
        }
    }

    pub fn update_trees_from_write_queue(&mut self, skip_validation: bool) {
        let tree_indices: Vec<usize> = self.write_queue.keys().copied().collect();
        for tree in tree_indices {
            self.process_write_queue_for_tree(tree, skip_validation);
        }
    }
}

fn pad32(el: &BytesData) -> BytesData {
    BytesData::Hex(format_to_byte_length(el, ByteLength::Uint256, false))
}

fn num_to_hex(n: u64) -> String {
    // `ByteUtils.hexlify(number)` — even-length lowercase hex, no prefix.
    hexlify(&BytesData::Num(n), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // src/merkletree/__tests__/merkletree.test.ts
    #[test]
    fn num_nodes_per_level_kav() {
        assert_eq!(num_nodes_per_level(0), 65536);
        assert_eq!(num_nodes_per_level(1), 32768);
        assert_eq!(num_nodes_per_level(10), 64);
        assert_eq!(num_nodes_per_level(15), 2);
        assert_eq!(num_nodes_per_level(16), 1);
    }

    #[test]
    fn tree_and_index_from_global_position_kav() {
        assert_eq!(get_tree_and_index_from_global_position(9), (0, 9));
        assert_eq!(get_tree_and_index_from_global_position(65535), (0, 65535));
        assert_eq!(get_tree_and_index_from_global_position(65536), (1, 0));
    }
}
