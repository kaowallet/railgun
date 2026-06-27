//! Port of `src/merkletree/txid-merkletree.ts`.
//!
//! RAILGUN-txid-leaf Merkle tree plus historical-merkleroot storage, the
//! railgun-txid→index lookup, and the POI-launch snapshot machinery.
//!
//! The TS reads `POI.launchBlocks` (a network-injected registry) to decide when
//! to snapshot. To keep this crate network-free, the launch block is a plain
//! field set by the caller via [`TXIDMerkletree::set_poi_launch_block`].

use railgun_db::{Database, MemStore};
use railgun_models::engine_types::Chain;
use railgun_models::formatted_types::{
    MerkleProof, RailgunTransactionWithHash, TXIDMerkletreeData,
};
use railgun_models::merkletree_types::{CommitmentProcessingGroupSize, TREE_DEPTH, TREE_MAX_ITEMS};
use railgun_models::poi_types::TXIDVersion;
use railgun_utils::{
    format_to_byte_length, from_utf8_string, hexlify, n_to_hex, ByteLength, BytesData,
};

use crate::merkle_proof::verify_merkle_proof;
use crate::merkletree::{
    get_global_position, get_tree_and_index_from_global_position, MerkleCore, MerkleKind,
    MerkletreeError, MerkletreeLeafData,
};

impl MerkletreeLeafData for RailgunTransactionWithHash {
    fn hash(&self) -> &str {
        &self.hash
    }
}

/// `POILaunchSnapshotNode`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct POILaunchSnapshotNode {
    pub hash: String,
    pub index: usize,
}

pub struct TXIDMerkletree {
    pub core: MerkleCore<RailgunTransactionWithHash>,
    pub should_store_merkleroots: bool,
    pub should_save_poi_launch_snapshot: bool,
    pub saved_poi_launch_snapshot: Option<bool>,
    poi_launch_block: Option<u64>,
}

impl TXIDMerkletree {
    fn new(
        db: Database<MemStore>,
        chain: Chain,
        txid_version: TXIDVersion,
        is_poi_node: bool,
        validator: impl FnMut(TXIDVersion, Chain, usize, usize, &str) -> bool + 'static,
    ) -> Self {
        let processing_size = if is_poi_node {
            CommitmentProcessingGroupSize::Single as usize
        } else {
            CommitmentProcessingGroupSize::XXXXLarge as usize
        };
        let core = MerkleCore::new(
            db,
            chain,
            txid_version,
            MerkleKind::Txid {
                should_store_merkleroots: is_poi_node,
                should_save_poi_launch_snapshot: !is_poi_node,
            },
            processing_size,
            Box::new(validator),
        );
        Self {
            core,
            should_store_merkleroots: is_poi_node,
            should_save_poi_launch_snapshot: !is_poi_node,
            saved_poi_launch_snapshot: None,
            poi_launch_block: None,
        }
    }

    /// `TXIDMerkletree.createForWallet`.
    pub fn create_for_wallet(
        db: Database<MemStore>,
        chain: Chain,
        txid_version: TXIDVersion,
        validator: impl FnMut(TXIDVersion, Chain, usize, usize, &str) -> bool + 'static,
    ) -> Self {
        Self::new(db, chain, txid_version, false, validator)
    }

    /// `TXIDMerkletree.createForPOINode`.
    pub fn create_for_poi_node(
        db: Database<MemStore>,
        chain: Chain,
        txid_version: TXIDVersion,
    ) -> Self {
        Self::new(db, chain, txid_version, true, |_, _, _, _, _| true)
    }

    pub fn set_poi_launch_block(&mut self, block: u64) {
        self.poi_launch_block = Some(block);
    }

    // ---- static math (mirrors TS) ----

    pub fn next_tree_and_index(tree: usize, index: usize) -> (usize, usize) {
        if index + 1 >= TREE_MAX_ITEMS {
            (tree + 1, 0)
        } else {
            (tree, index + 1)
        }
    }

    pub fn is_out_of_bounds(tree: usize, index: usize, max_txid_index: Option<usize>) -> bool {
        match max_txid_index {
            None => false,
            Some(max) => get_global_position(tree, index) > max,
        }
    }

    // ---- pass-throughs ----

    pub fn zeros(&self) -> &[String] {
        &self.core.zeros
    }
    pub fn get_root(&mut self, tree: usize) -> String {
        self.core.get_root(tree)
    }
    pub fn get_tree_length(&mut self, tree: usize) -> usize {
        self.core.get_tree_length(tree)
    }
    pub fn get_node_hash(&mut self, tree: usize, level: usize, index: usize) -> String {
        self.core.get_node_hash(tree, level, index)
    }
    pub fn get_tree_db_prefix(&self, tree: usize) -> Vec<BytesData> {
        self.core.get_tree_db_prefix(tree)
    }
    pub fn get_node_hash_db_path(&self, tree: usize, level: usize, index: usize) -> Vec<BytesData> {
        self.core.get_node_hash_db_path(tree, level, index)
    }
    pub fn clear_data_for_merkletree(&mut self) {
        self.core.clear_data_for_merkletree();
        self.saved_poi_launch_snapshot = None;
    }
    pub fn get_merkle_proof(&mut self, tree: usize, index: usize) -> MerkleProof {
        self.core.get_merkle_proof(tree, index)
    }

    fn drain_leaf_root_triggers(&mut self) {
        if !self.should_store_merkleroots {
            self.core.pending_leaf_root_triggers.clear();
            return;
        }
        let triggers = std::mem::take(&mut self.core.pending_leaf_root_triggers);
        for t in triggers {
            let path = self.get_historical_merkleroot_db_path(t.tree, t.index);
            self.core
                .db
                .put(&path, &BytesData::Hex(t.merkleroot))
                .expect("historical merkleroot put");
        }
    }

    pub fn update_trees_from_write_queue(&mut self) {
        self.core.update_trees_from_write_queue(false);
        self.drain_leaf_root_triggers();
    }

    pub fn rebuild_and_write_tree(&mut self, tree: usize) {
        self.core.rebuild_and_write_tree(tree);
        self.drain_leaf_root_triggers();
    }

    // ---- railgun transaction reads ----

    pub fn get_railgun_transaction(
        &self,
        tree: i64,
        index: i64,
    ) -> Option<RailgunTransactionWithHash> {
        if tree < 0 || index < 0 {
            return None;
        }
        self.core.get_data(tree as usize, index as usize).ok()
    }

    pub fn get_global_utxo_tree_position_for_railgun_transaction_commitment(
        &self,
        tree: usize,
        index: usize,
        commitment_hash: &str,
    ) -> Result<usize, MerkletreeError> {
        let rt = self
            .get_railgun_transaction(tree as i64, index as i64)
            .ok_or_else(|| {
                MerkletreeError::Other("Railgun transaction for tree/index not found".into())
            })?;
        let target = format_to_byte_length(
            &BytesData::Hex(commitment_hash.to_string()),
            ByteLength::Uint256,
            false,
        );
        let commitments = rt.transaction_commitments();
        let commitment_index = commitments.iter().position(|c| {
            format_to_byte_length(&BytesData::Hex(c.clone()), ByteLength::Uint256, false) == target
        });
        let commitment_index = commitment_index.ok_or_else(|| {
            MerkletreeError::Other("Could not find commitmentHash for RailgunTransaction".into())
        })?;
        Ok(rt.transaction_utxo_batch_start_position_out() as usize + commitment_index)
    }

    pub fn railgun_txid_occurred_before_block_number(
        &self,
        tree: usize,
        index: usize,
        block_number: u64,
    ) -> Result<bool, MerkletreeError> {
        let rt = self
            .get_railgun_transaction(tree as i64, index as i64)
            .ok_or_else(|| MerkletreeError::Other("Railgun transaction not found".into()))?;
        Ok(rt.transaction_block_number() < block_number)
    }

    // ---- railgun-txid → index lookup ----

    fn get_railgun_txid_lookup_db_path(&self, railgun_txid: &str) -> Vec<BytesData> {
        let prefix = from_utf8_string("railgun-txid-lookup").expect("ascii");
        let mut parts = self.core.get_merkletree_db_prefix();
        parts.push(BytesData::Hex(prefix));
        parts.push(BytesData::Hex(railgun_txid.to_string()));
        parts
            .iter()
            .map(|el| BytesData::Hex(format_to_byte_length(el, ByteLength::Uint256, false)))
            .collect()
    }

    fn put_railgun_txid_lookup(&mut self, railgun_txid: &str, txid_index: usize) {
        let path = self.get_railgun_txid_lookup_db_path(railgun_txid);
        // stored 'utf8' in TS: the decimal string of the index.
        let value_hex = hex::encode(txid_index.to_string().as_bytes());
        self.core
            .db
            .put(&path, &BytesData::Hex(value_hex))
            .expect("railgun txid lookup put");
    }

    pub fn get_txid_index_by_railgun_txid(&self, railgun_txid: &str) -> Option<usize> {
        let hex = self
            .core
            .db
            .get(&self.get_railgun_txid_lookup_db_path(railgun_txid))
            .ok()?;
        let bytes = hex::decode(&hex).ok()?;
        let s = String::from_utf8(bytes).ok()?;
        s.parse::<usize>().ok()
    }

    pub fn get_railgun_transaction_by_txid(
        &self,
        railgun_txid: &str,
    ) -> Option<RailgunTransactionWithHash> {
        let txid_index = self.get_txid_index_by_railgun_txid(railgun_txid)?;
        let (tree, index) = get_tree_and_index_from_global_position(txid_index);
        self.core.get_data(tree, index).ok()
    }

    // ---- historical merkleroots ----

    fn get_historical_merkleroot_db_path(&self, tree: usize, index: usize) -> Vec<BytesData> {
        let prefix = from_utf8_string("merkleroots").expect("ascii");
        let mut parts = self.core.get_merkletree_db_prefix();
        parts.push(BytesData::Hex(prefix));
        parts.push(BytesData::Hex(num_to_hex(tree as u64)));
        parts.push(BytesData::Hex(num_to_hex(index as u64)));
        parts
            .iter()
            .map(|el| BytesData::Hex(format_to_byte_length(el, ByteLength::Uint256, false)))
            .collect()
    }

    pub fn get_historical_merkleroot(&self, tree: usize, index: usize) -> Option<String> {
        self.core
            .db
            .get(&self.get_historical_merkleroot_db_path(tree, index))
            .ok()
    }

    pub fn get_historical_merkleroot_for_txid_index(&self, txid_index: usize) -> Option<String> {
        let (tree, index) = get_tree_and_index_from_global_position(txid_index);
        self.get_historical_merkleroot(tree, index)
    }

    // ---- POI launch snapshot ----

    fn get_poi_launch_snapshot_node_db_path(&self, level: usize) -> Vec<BytesData> {
        let prefix = from_utf8_string("poi-launch-snapshot").expect("ascii");
        let mut parts = self.core.get_merkletree_db_prefix();
        parts.push(BytesData::Hex(prefix));
        parts.push(BytesData::Hex(num_to_hex(level as u64)));
        parts
            .iter()
            .map(|el| BytesData::Hex(format_to_byte_length(el, ByteLength::Uint256, false)))
            .collect()
    }

    pub fn get_poi_launch_snapshot_node(&self, level: usize) -> Option<POILaunchSnapshotNode> {
        let hex = self
            .core
            .db
            .get(&self.get_poi_launch_snapshot_node_db_path(level))
            .ok()?;
        let bytes = hex::decode(&hex).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn has_saved_poi_launch_snapshot(&self) -> bool {
        if self.saved_poi_launch_snapshot == Some(true) {
            return true;
        }
        self.get_poi_launch_snapshot_node(0).is_some()
    }

    fn rightmost_nonzero_indices(latest_leaf_index: usize) -> Vec<usize> {
        let mut indices = vec![latest_leaf_index];
        while indices.len() < TREE_DEPTH + 1 {
            indices.push(indices[indices.len() - 1] >> 1);
        }
        indices
    }

    fn save_poi_launch_snapshot(&mut self, latest_leaf_index: usize) {
        if !self.should_save_poi_launch_snapshot {
            return;
        }
        let indices_per_level = Self::rightmost_nonzero_indices(latest_leaf_index);
        for level in 0..(TREE_DEPTH + 1) {
            let index = indices_per_level[level];
            let hash = self.core.get_node_hash(0, level, index);
            let node = POILaunchSnapshotNode { hash, index };
            let path = self.get_poi_launch_snapshot_node_db_path(level);
            let json = serde_json::to_vec(&node).expect("snapshot serializable");
            self.core
                .db
                .put(&path, &BytesData::Hex(hex::encode(json)))
                .expect("snapshot put");
        }
        self.saved_poi_launch_snapshot = Some(true);
    }

    fn save_poi_launch_snapshot_if_necessary(
        &mut self,
        block_number: u64,
        latest_leaf_index: usize,
    ) {
        if !self.should_save_poi_launch_snapshot {
            return;
        }
        let Some(launch_block) = self.poi_launch_block else {
            return;
        };
        if block_number < launch_block {
            return;
        }
        if !self.has_saved_poi_launch_snapshot() {
            // Make sure trees have fully updated data.
            self.update_trees_from_write_queue();
            self.save_poi_launch_snapshot(latest_leaf_index);
        }
    }

    // ---- queue railgun transactions ----

    /// `queueRailgunTransactions`.
    pub fn queue_railgun_transactions(
        &mut self,
        railgun_transactions: &[RailgunTransactionWithHash],
        max_txid_index: Option<usize>,
    ) {
        if railgun_transactions.is_empty() {
            return;
        }

        let (latest_tree, latest_index) = self.core.get_latest_tree_and_index();
        let mut next_tree = latest_tree;
        let mut next_index: i64 = latest_index;

        let mut lookup_batch: Vec<(String, usize)> = Vec::new();

        let mut batch_tree: i64 = -1;
        let mut batch_start_index: i64 = -1;
        let mut batch_leaves: Vec<RailgunTransactionWithHash> = Vec::new();

        for rt in railgun_transactions {
            // nextTreeAndIndex(nextTree, nextIndex) — note index starts at -1.
            let (t, i) = if next_index < 0 {
                (next_tree, 0usize)
            } else {
                Self::next_tree_and_index(next_tree, next_index as usize)
            };
            next_tree = t;
            next_index = i as i64;

            if Self::is_out_of_bounds(next_tree, next_index as usize, max_txid_index) {
                break;
            }

            let txid_index = get_global_position(next_tree, next_index as usize);
            let railgun_txid = rt.railgun_txid.clone();

            // TS: const latestLeafIndex = nextIndex - 1;  (nextIndex already incremented)
            let ts_latest_leaf_index = (next_index - 1).max(0) as usize;

            // POI-launch flush of in-progress batch (wallet only).
            if self.should_save_poi_launch_snapshot
                && self.saved_poi_launch_snapshot != Some(true)
                && !batch_leaves.is_empty()
            {
                if let Some(launch_block) = self.poi_launch_block {
                    if rt.transaction_block_number() >= launch_block {
                        self.core.queue_leaves(
                            batch_tree as usize,
                            batch_start_index as usize,
                            std::mem::take(&mut batch_leaves),
                        );
                        batch_tree = -1;
                        batch_start_index = -1;
                    }
                }
            }

            self.save_poi_launch_snapshot_if_necessary(
                rt.transaction_block_number(),
                ts_latest_leaf_index,
            );

            if batch_tree == -1 {
                batch_tree = next_tree as i64;
                batch_start_index = next_index;
            }

            if next_tree as i64 != batch_tree {
                self.core.queue_leaves(
                    batch_tree as usize,
                    batch_start_index as usize,
                    std::mem::take(&mut batch_leaves),
                );
                batch_tree = next_tree as i64;
                batch_start_index = next_index;
            }

            batch_leaves.push(rt.clone());

            if self.should_store_merkleroots {
                self.core.queue_leaves(
                    batch_tree as usize,
                    batch_start_index as usize,
                    std::mem::take(&mut batch_leaves),
                );
                batch_tree = -1;
                batch_start_index = -1;
            }

            lookup_batch.push((railgun_txid, txid_index));
        }

        if !batch_leaves.is_empty() {
            self.core.queue_leaves(
                batch_tree as usize,
                batch_start_index as usize,
                batch_leaves,
            );
        }

        for (railgun_txid, txid_index) in lookup_batch {
            self.put_railgun_txid_lookup(&railgun_txid, txid_index);
        }
    }

    // ---- merkle proof with snapshot + current merkletree data ----

    fn get_merkle_proof_with_snapshot(
        &mut self,
        snapshot_leaf: &POILaunchSnapshotNode,
        tree: usize,
        index: usize,
    ) -> Result<MerkleProof, MerkletreeError> {
        let leaf = self.core.get_node_hash(tree, 0, index);
        let rightmost_indices = Self::rightmost_nonzero_indices(snapshot_leaf.index);

        let mut elements_indices: Vec<usize> = vec![index ^ 1];
        while elements_indices.len() < TREE_DEPTH {
            let last = *elements_indices.last().unwrap();
            elements_indices.push((last >> 1) ^ 1);
        }

        let mut elements = Vec::with_capacity(TREE_DEPTH);
        for (level, &element_index) in elements_indices.iter().enumerate() {
            let snapshot_index_at_level = rightmost_indices[level];
            if element_index > snapshot_index_at_level {
                elements.push(self.core.zeros[level].clone());
            } else if element_index == snapshot_index_at_level {
                let node = self.get_poi_launch_snapshot_node(level).ok_or_else(|| {
                    MerkletreeError::Other("POI Launch snapshot node not found".into())
                })?;
                elements.push(node.hash);
            } else {
                elements.push(self.core.get_node_hash(tree, level, element_index));
            }
        }

        let indices = n_to_hex(
            &num_bigint::BigUint::from(index as u64),
            ByteLength::Uint256,
            false,
        );
        let root_node = self
            .get_poi_launch_snapshot_node(TREE_DEPTH)
            .ok_or_else(|| MerkletreeError::Other("POI Launch snapshot root not found".into()))?;

        Ok(MerkleProof {
            leaf,
            elements,
            indices,
            root: root_node.hash,
        })
    }

    /// `getRailgunTxidCurrentMerkletreeData`.
    pub fn get_railgun_txid_current_merkletree_data(
        &mut self,
        railgun_txid: &str,
    ) -> Result<TXIDMerkletreeData, MerkletreeError> {
        let txid_index = self
            .get_txid_index_by_railgun_txid(railgun_txid)
            .ok_or_else(|| {
                MerkletreeError::Other(format!("tree/index not found: railgun txid {railgun_txid}"))
            })?;
        let (tree, index) = get_tree_and_index_from_global_position(txid_index);
        let railgun_transaction = self
            .core
            .get_data(tree, index)
            .map_err(|_| MerkletreeError::Other("railgun transaction not found".into()))?;

        let use_snapshot = self.poi_launch_block.is_some()
            && self.should_save_poi_launch_snapshot
            && railgun_transaction.transaction_block_number() < self.poi_launch_block.unwrap()
            && self.has_saved_poi_launch_snapshot();

        if use_snapshot {
            let snapshot_leaf = self
                .get_poi_launch_snapshot_node(0)
                .ok_or_else(|| MerkletreeError::Other("POI Launch snapshot not found".into()))?;
            let proof = self.get_merkle_proof_with_snapshot(&snapshot_leaf, tree, index)?;
            if !verify_merkle_proof(&proof) {
                return Err(MerkletreeError::Other(
                    "Invalid merkle proof for snapshot".into(),
                ));
            }
            return Ok(TXIDMerkletreeData {
                railgun_transaction,
                current_merkle_proof_for_tree: proof,
                current_txid_index_for_tree: snapshot_leaf.index as u32,
            });
        }

        let proof = self.core.get_merkle_proof(tree, index);
        if !verify_merkle_proof(&proof) {
            return Err(MerkletreeError::Other("Invalid merkle proof".into()));
        }
        let current_index = self.core.get_latest_index_for_tree(tree);
        let current_txid_index_for_tree = get_global_position(tree, current_index.max(0) as usize);
        Ok(TXIDMerkletreeData {
            railgun_transaction,
            current_merkle_proof_for_tree: proof,
            current_txid_index_for_tree: current_txid_index_for_tree as u32,
        })
    }

    // ---- clearing ----

    pub fn get_current_txid_index(&mut self) -> usize {
        let (tree, index) = self.core.get_latest_tree_and_index();
        get_global_position(tree, index.max(0) as usize)
    }

    /// `clearLeavesAfterTxidIndex`.
    pub fn clear_leaves_after_txid_index(&mut self, txid_index: usize) {
        self.core.write_queue.clear();

        let (tree, index) = get_tree_and_index_from_global_position(txid_index);
        let (latest_tree, latest_index) = self.core.get_latest_tree_and_index();
        let latest_index = latest_index.max(0) as usize;

        for current_tree in tree..=latest_tree {
            let start_index = if current_tree == tree { index + 1 } else { 0 };
            let max = if current_tree == latest_tree {
                latest_index
            } else {
                TREE_MAX_ITEMS - 1
            };
            for current_index in start_index..=max {
                self.core
                    .db
                    .del(&self.get_historical_merkleroot_db_path(current_tree, current_index));
                self.core
                    .db
                    .del(&self.core.get_data_db_path(current_tree, current_index));
            }
            self.core.clear_all_node_hashes(current_tree);
        }

        for current_tree in tree..=latest_tree {
            self.rebuild_and_write_tree(current_tree);
            self.core.reset_tree_length(current_tree);
            self.core.update_stored_merkletrees_metadata(current_tree);
        }
    }
}

fn num_to_hex(n: u64) -> String {
    hexlify(&BytesData::Num(n), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_proof::verify_merkle_proof;
    use num_bigint::BigUint;
    use railgun_crypto::poseidon;
    use railgun_models::engine_types::{Chain, ChainType};
    use railgun_models::formatted_types::{
        RailgunTransaction, RailgunTransactionV2, RailgunTransactionVersion,
    };
    use railgun_models::merkletree_types::merkle_zero_value_bigint;
    use railgun_utils::hex_to_bigint;

    const TXID_VERSION: TXIDVersion = TXIDVersion::V2_PoseidonMerkle;
    const EMPTY_ROOT: &str = "14fceeac99eb8419a2796d1958fc2050d489bf5a3eb170ef16a667060344ba90";
    const POI_LAUNCH_BLOCK: u64 = 3;

    fn chain() -> Chain {
        Chain {
            chain_type: 0,
            id: 0,
        }
    }

    // Port of getRailgunTransactionID / getRailgunTxidLeafHash / createRailgunTransactionWithHash.
    fn pad_to_max(mut v: Vec<BigUint>, max: usize) -> Vec<BigUint> {
        let zero = merkle_zero_value_bigint();
        while v.len() < max {
            v.push(zero.clone());
        }
        v
    }
    fn railgun_transaction_id(
        nullifiers: &[String],
        commitments: &[String],
        bound_params_hash: &str,
    ) -> BigUint {
        let nulls: Vec<BigUint> = nullifiers.iter().map(|s| hex_to_bigint(s)).collect();
        let comms: Vec<BigUint> = commitments.iter().map(|s| hex_to_bigint(s)).collect();
        let bph = hex_to_bigint(bound_params_hash);
        let nullifiers_hash = poseidon(&pad_to_max(nulls, 13));
        let commitments_hash = poseidon(&pad_to_max(comms, 13));
        poseidon(&[nullifiers_hash, commitments_hash, bph])
    }
    fn with_hash(t: RailgunTransactionV2) -> RailgunTransactionWithHash {
        let id = railgun_transaction_id(&t.nullifiers, &t.commitments, &t.bound_params_hash);
        let global_tree_position = BigUint::from(
            t.utxo_tree_out as u64 * TREE_MAX_ITEMS as u64 + t.utxo_batch_start_position_out as u64,
        );
        let hash = n_to_hex(
            &poseidon(&[
                id.clone(),
                BigUint::from(t.utxo_tree_in as u64),
                global_tree_position,
            ]),
            ByteLength::Uint256,
            false,
        );
        RailgunTransactionWithHash {
            railgun_txid: n_to_hex(&id, ByteLength::Uint256, false),
            hash,
            transaction: RailgunTransaction::V2(t),
        }
    }
    fn rt(
        graph_id: &str,
        commitments: &[&str],
        nullifiers: &[&str],
        bound_params_hash: &str,
        block_number: u64,
        utxo_batch_start_position_out: u32,
    ) -> RailgunTransactionV2 {
        RailgunTransactionV2 {
            version: RailgunTransactionVersion::V2,
            graph_id: graph_id.into(),
            commitments: commitments.iter().map(|s| s.to_string()).collect(),
            nullifiers: nullifiers.iter().map(|s| s.to_string()).collect(),
            bound_params_hash: bound_params_hash.into(),
            block_number,
            txid: "00".into(),
            unshield: None,
            utxo_tree_in: 0,
            utxo_tree_out: 0,
            utxo_batch_start_position_out,
            timestamp: 1_000_000,
            verification_hash: "test".into(),
        }
    }

    // src/merkletree/__tests__/txid-merkletree.test.ts: 'Should get next tree and index'
    #[test]
    fn next_tree_and_index_kav() {
        assert_eq!(TXIDMerkletree::next_tree_and_index(0, 0), (0, 1));
        assert_eq!(TXIDMerkletree::next_tree_and_index(1, 65535), (2, 0));
    }

    // 'Should get Txid merkletree DB paths' (V2)
    #[test]
    fn txid_db_paths_kav() {
        let t0 = TXIDMerkletree::create_for_poi_node(
            Database::in_memory(),
            Chain {
                chain_type: ChainType::Evm as u8,
                id: 0,
            },
            TXID_VERSION,
        );
        let result0 = [
            "0000000000000000007261696c67756e2d7472616e73616374696f6e2d696473",
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

        let t1 = TXIDMerkletree::create_for_poi_node(
            Database::in_memory(),
            Chain {
                chain_type: ChainType::Evm as u8,
                id: 4,
            },
            TXID_VERSION,
        );
        let result1 = [
            "0000000000000000007261696c67756e2d7472616e73616374696f6e2d696473",
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

    fn first_two_txs() -> Vec<RailgunTransactionWithHash> {
        vec![
            with_hash(rt(
                "0x00",
                &["0x01", "0x02"],
                &["0x03", "0x04"],
                "0x05",
                0,
                0,
            )),
            {
                let mut t = rt("0x10", &["0x11", "0x12"], &["0x13", "0x14"], "0x15", 0, 2);
                t.unshield = None;
                with_hash(t)
            },
        ]
    }

    fn more_txs() -> Vec<RailgunTransactionWithHash> {
        vec![
            with_hash(rt(
                "0x02",
                &["0x0101", "0x0102"],
                &["0x0103", "0x0104"],
                "0x0105",
                2,
                4,
            )),
            with_hash(rt(
                "0x13",
                &["0x0211", "0x0212"],
                &["0x0213", "0x0214"],
                "0x0215",
                3,
                6,
            )),
        ]
    }

    // 'Should update railgun txid merkle tree correctly' — POI Node variant.
    //
    // TODO(crypto-backend): the txid leaf hash derives from
    // `getRailgunTransactionID`, which pads nullifiers/commitments to 13 inputs
    // and Poseidon-hashes them. The current `railgun-crypto` backend
    // (`light-poseidon`) only supports up to 12 inputs (width 13), so building
    // these leaves panics. Re-enable once the crypto crate exposes a wider
    // (circomlibjs-compatible, up to 16-input) Poseidon. All merkletree-specific
    // math (DB paths, tree/position, snapshot indices, root hashing of 2 inputs)
    // is covered by the other tests and the UTXO root/proof KAVs.
    #[test]
    fn update_txid_tree_poi_node() {
        let mut tree =
            TXIDMerkletree::create_for_poi_node(Database::in_memory(), chain(), TXID_VERSION);
        tree.set_poi_launch_block(POI_LAUNCH_BLOCK);
        assert!(tree.should_store_merkleroots);
        run_update_txid_tree(&mut tree, true);
    }

    // 'Should update railgun txid merkle tree correctly' — Wallet variant.
    // Ignored for the same reason as `update_txid_tree_poi_node` (see TODO there).
    #[test]
    fn update_txid_tree_wallet() {
        let mut tree = TXIDMerkletree::create_for_wallet(
            Database::in_memory(),
            chain(),
            TXID_VERSION,
            |_, _, _, _, _| true,
        );
        tree.set_poi_launch_block(POI_LAUNCH_BLOCK);
        assert!(!tree.should_store_merkleroots);
        run_update_txid_tree(&mut tree, false);
    }

    fn run_update_txid_tree(tree: &mut TXIDMerkletree, is_poi_node: bool) {
        tree.clear_data_for_merkletree();
        assert_eq!(tree.get_root(0), EMPTY_ROOT);

        let txs = first_two_txs();
        tree.queue_railgun_transactions(&txs, Some(1));
        assert_eq!(tree.get_tree_length(0), 0);

        tree.update_trees_from_write_queue();
        assert_eq!(tree.get_tree_length(0), 2);
        assert_eq!(
            tree.get_root(0),
            "0a03b0bf8dc758a3d5dd7f6b8b1974a4b212a0080425740c92cbd0c860ebde33"
        );

        assert_eq!(
            tree.get_global_utxo_tree_position_for_railgun_transaction_commitment(0, 1, "0x12")
                .unwrap(),
            3
        );

        if is_poi_node {
            assert_eq!(
                tree.get_historical_merkleroot(0, 0).as_deref(),
                Some("2672380de5dc3f4078e8d5a5984fcd95e3e279be354665ba889a472b8cd27966")
            );
            assert_eq!(
                tree.get_historical_merkleroot(0, 1).as_deref(),
                Some("0a03b0bf8dc758a3d5dd7f6b8b1974a4b212a0080425740c92cbd0c860ebde33")
            );
        } else {
            assert_eq!(tree.get_historical_merkleroot(0, 0), None);
            assert_eq!(tree.get_historical_merkleroot(0, 1), None);
        }

        assert_eq!(
            tree.get_txid_index_by_railgun_txid(&txs[0].railgun_txid),
            Some(0)
        );
        assert_eq!(
            tree.get_txid_index_by_railgun_txid(&txs[1].railgun_txid),
            Some(1)
        );

        // Known railgun txid + leaf hash.
        let id = railgun_transaction_id(
            &txs[0].transaction_nullifiers(),
            &txs[0].transaction_commitments(),
            "0x05",
        );
        assert_eq!(
            id,
            BigUint::parse_bytes(
                b"14287123277508529327750979990773096097618894834009087566098724348137357265894",
                10
            )
            .unwrap()
        );
        assert_eq!(
            txs[0].railgun_txid,
            "1f9639a75d9aa09f959fb0f347da9a3afcbb09851c5cb398100d1721b5ed4be6"
        );
        assert_eq!(
            txs[0].hash,
            "1d20db6208e429e0bdfa9ceef6cdb33493a3a9134b4ec6d620d6d2e7c2de37f9"
        );

        // New tree inherits db values.
        let mut tree2 =
            TXIDMerkletree::create_for_poi_node(Database::in_memory(), chain(), TXID_VERSION);
        // (separate DB; just exercise construction)
        let _ = tree2.get_tree_length(0);

        let more = more_txs();
        tree.queue_railgun_transactions(&more, None);
        tree.update_trees_from_write_queue();

        if tree.should_save_poi_launch_snapshot {
            assert_eq!(
                tree.get_poi_launch_snapshot_node(0),
                Some(POILaunchSnapshotNode {
                    index: 2,
                    hash: "146d04257251ebab1d921f66145175d5a8c0b8c0f9298aac8e13f2477a7bc0d5".into(),
                })
            );
            assert_eq!(tree.saved_poi_launch_snapshot, Some(true));
        } else {
            assert_eq!(tree.get_poi_launch_snapshot_node(0), None);
            assert_eq!(tree.saved_poi_launch_snapshot, None);
        }

        assert_eq!(
            tree.railgun_txid_occurred_before_block_number(0, 0, 3)
                .unwrap(),
            true
        );
        assert_eq!(
            tree.railgun_txid_occurred_before_block_number(0, 3, 3)
                .unwrap(),
            false
        );

        if tree.should_save_poi_launch_snapshot {
            let data = tree
                .get_railgun_txid_current_merkletree_data(&txs[0].railgun_txid)
                .unwrap();
            assert_eq!(data.current_txid_index_for_tree, 2);
            assert_eq!(data.current_merkle_proof_for_tree.leaf, txs[0].hash);
            assert_eq!(
                data.current_merkle_proof_for_tree.elements[0],
                "12d0d49bb0803a2dea71223db3c45487909ef49600de461f9d8cc3a0daec012c"
            );
            assert_eq!(
                data.current_merkle_proof_for_tree.elements[1],
                "269093692b0655851303944dc9d416c78734119eb584b240f7176c98f929fd9e"
            );
            assert_eq!(
                data.current_merkle_proof_for_tree.root,
                "2f4f37ea40b00388e1415d7b4f762ef388024ea74cfc61845a2d44b2c82dd7db"
            );
            assert!(verify_merkle_proof(&data.current_merkle_proof_for_tree));
            let current_root = tree.get_root(0);
            assert_ne!(data.current_merkle_proof_for_tree.root, current_root);
            assert_eq!(
                Some(data.current_merkle_proof_for_tree.root.clone()),
                tree.get_poi_launch_snapshot_node(TREE_DEPTH)
                    .map(|n| n.hash)
            );
        } else {
            let data = tree
                .get_railgun_txid_current_merkletree_data(&txs[0].railgun_txid)
                .unwrap();
            assert_eq!(data.current_txid_index_for_tree, 3);
            assert_eq!(
                data.current_merkle_proof_for_tree.elements[1],
                "2097c0eb4015e8fea6dc5062a2e4979cd44852350b4f935387ea027737df91a4"
            );
            assert_eq!(
                data.current_merkle_proof_for_tree.root,
                "0a69c8788735b4a86b8bbe292ad5db83e8830fc27c9ed9dc216dd606cef347fe"
            );
            assert!(verify_merkle_proof(&data.current_merkle_proof_for_tree));
            assert_eq!(data.current_merkle_proof_for_tree.root, tree.get_root(0));
        }

        // Current root (4 elements).
        assert_eq!(
            tree.get_root(0),
            "0a69c8788735b4a86b8bbe292ad5db83e8830fc27c9ed9dc216dd606cef347fe"
        );

        // Rebuild entire tree -> same root.
        tree.rebuild_and_write_tree(0);
        assert_eq!(
            tree.get_root(0),
            "0a69c8788735b4a86b8bbe292ad5db83e8830fc27c9ed9dc216dd606cef347fe"
        );

        tree.clear_leaves_after_txid_index(0);
        assert_eq!(tree.get_node_hash(0, 0, 1), tree.zeros()[0]);
        // Current tree root (1 element).
        assert_eq!(
            tree.get_root(0),
            "2672380de5dc3f4078e8d5a5984fcd95e3e279be354665ba889a472b8cd27966"
        );

        if tree.should_store_merkleroots {
            assert_eq!(
                tree.get_historical_merkleroot_for_txid_index(0).as_deref(),
                Some("2672380de5dc3f4078e8d5a5984fcd95e3e279be354665ba889a472b8cd27966")
            );
            assert_eq!(tree.get_historical_merkleroot_for_txid_index(1), None);
            assert_eq!(tree.get_historical_merkleroot_for_txid_index(2), None);
        } else {
            assert_eq!(tree.get_historical_merkleroot_for_txid_index(0), None);
        }
    }
}

// Helpers on RailgunTransactionWithHash to reach into the untagged inner enum.
trait RtAccess {
    fn transaction_commitments(&self) -> Vec<String>;
    #[cfg(test)]
    fn transaction_nullifiers(&self) -> Vec<String>;
    fn transaction_utxo_batch_start_position_out(&self) -> u32;
    fn transaction_block_number(&self) -> u64;
}

impl RtAccess for RailgunTransactionWithHash {
    #[cfg(test)]
    fn transaction_nullifiers(&self) -> Vec<String> {
        use railgun_models::formatted_types::RailgunTransaction;
        match &self.transaction {
            RailgunTransaction::V2(t) => t.nullifiers.clone(),
            RailgunTransaction::V3(t) => t.nullifiers.clone(),
        }
    }
    fn transaction_commitments(&self) -> Vec<String> {
        use railgun_models::formatted_types::RailgunTransaction;
        match &self.transaction {
            RailgunTransaction::V2(t) => t.commitments.clone(),
            RailgunTransaction::V3(t) => t.commitments.clone(),
        }
    }
    fn transaction_utxo_batch_start_position_out(&self) -> u32 {
        use railgun_models::formatted_types::RailgunTransaction;
        match &self.transaction {
            RailgunTransaction::V2(t) => t.utxo_batch_start_position_out,
            RailgunTransaction::V3(t) => t.utxo_batch_start_position_out,
        }
    }
    fn transaction_block_number(&self) -> u64 {
        use railgun_models::formatted_types::RailgunTransaction;
        match &self.transaction {
            RailgunTransaction::V2(t) => t.block_number,
            RailgunTransaction::V3(t) => t.block_number,
        }
    }
}
