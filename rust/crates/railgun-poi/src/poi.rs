//! Port of `src/poi/poi.ts`.
//!
//! In the TS SDK `POI` is a static class with three pieces of injected state:
//! the configured `lists`, a `nodeInterface`, and a per-chain `launchBlocks`
//! registry. We model it as a [`Poi`] struct carrying that state; the pure
//! list-status logic (which is what the known-answer-vector tests exercise) is
//! implemented as methods plus a handful of free helpers.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use num_bigint::BigUint;
use num_traits::Zero;

use railgun_models::engine_types::Chain;
use railgun_models::event_types::UnshieldStoredEvent;
use railgun_models::formatted_types::{CommitmentType, OutputType, SpendTxid};
use railgun_models::poi_types::{POIsPerList, TXOPOIListStatus};
use railgun_models::txo_types::{SentCommitment, WalletBalanceBucket, TXO};

/// Minimal note interface the POI logic needs (mirrors the fields of
/// `TransactNote` the TS reads: `value` and `outputType`).
pub trait PoiNote {
    fn value(&self) -> &BigUint;
    fn output_type(&self) -> Option<OutputType>;
}

/// `POIListType` — string-valued enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum POIListType {
    Active,
    Gather,
}

/// `POIList`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct POIList {
    pub key: String,
    pub list_type: POIListType,
    pub name: String,
    pub description: String,
}

/// `isShieldCommitmentType` — port of `src/utils/commitment.ts`.
pub fn is_shield_commitment_type(commitment_type: CommitmentType) -> bool {
    matches!(
        commitment_type,
        CommitmentType::ShieldCommitment | CommitmentType::LegacyGeneratedCommitment
    )
}

/// `isTransactCommitmentType` — port of `src/utils/commitment.ts`.
pub fn is_transact_commitment_type(commitment_type: CommitmentType) -> bool {
    matches!(
        commitment_type,
        CommitmentType::TransactCommitmentV2
            | CommitmentType::TransactCommitmentV3
            | CommitmentType::LegacyEncryptedCommitment
    )
}

/// `POI` — port of the static class, holding the injected lists + launch blocks.
///
/// The async `nodeInterface` calls (`getPOIsPerList`, `submitPOI`, …) are not part
/// of this struct: they belong on the [`crate::POINodeInterface`] trait, which the
/// caller owns and invokes directly. This struct holds only the pure config the
/// status logic needs.
#[derive(Clone, Debug, Default)]
pub struct Poi {
    lists: Vec<POIList>,
    /// `launchBlocks` registry, keyed by chain.
    launch_blocks: BTreeMap<(u8, u64), u64>,
}

impl Poi {
    /// `POI.init(lists, ...)`.
    pub fn new(lists: Vec<POIList>) -> Self {
        Self {
            lists,
            launch_blocks: BTreeMap::new(),
        }
    }

    /// `POI.launchBlocks.set(null, chain, block)`.
    pub fn set_launch_block(&mut self, chain: &Chain, block: u64) {
        self.launch_blocks
            .insert((chain.chain_type, chain.id), block);
    }

    /// `POI.launchBlocks.get(null, chain)`.
    pub fn launch_block(&self, chain: &Chain) -> Option<u64> {
        self.launch_blocks
            .get(&(chain.chain_type, chain.id))
            .copied()
    }

    /// `POI.getAllListKeys()`.
    pub fn get_all_list_keys(&self) -> Vec<String> {
        self.lists.iter().map(|l| l.key.clone()).collect()
    }

    /// `POI.getActiveListKeys()`.
    pub fn get_active_list_keys(&self) -> Vec<String> {
        self.lists
            .iter()
            .filter(|l| l.list_type == POIListType::Active)
            .map(|l| l.key.clone())
            .collect()
    }

    fn has_all_keys(pois: &POIsPerList, keys: &[String]) -> bool {
        keys.iter().all(|k| pois.contains_key(k))
    }

    fn validate_poi_status_for_all_lists(
        pois: &POIsPerList,
        list_keys: &[String],
        statuses: &[TXOPOIListStatus],
    ) -> bool {
        if !Self::has_all_keys(pois, list_keys) {
            return false;
        }
        for list_key in list_keys {
            match pois.get(list_key) {
                Some(status) if statuses.contains(status) => {}
                _ => return false,
            }
        }
        true
    }

    fn has_valid_pois_all_lists(&self, pois: &POIsPerList) -> bool {
        let list_keys = self.get_all_list_keys();
        Self::validate_poi_status_for_all_lists(pois, &list_keys, &[TXOPOIListStatus::Valid])
    }

    /// `POI.hasValidPOIsActiveLists(pois)`.
    pub fn has_valid_pois_active_lists(&self, pois: Option<&POIsPerList>) -> bool {
        let pois = match pois {
            Some(p) => p,
            None => return false,
        };
        let list_keys = self.get_active_list_keys();
        Self::validate_poi_status_for_all_lists(pois, &list_keys, &[TXOPOIListStatus::Valid])
    }

    /// `POI.getBalanceBucket(txo)`.
    pub fn get_balance_bucket<N: PoiNote>(&self, txo: &TXO<N>) -> WalletBalanceBucket {
        if !matches!(txo.spendtxid, SpendTxid::Unspent(false)) {
            return WalletBalanceBucket::Spent;
        }

        let pois = txo.pois_per_list.as_ref();
        let is_change = txo.note.output_type() == Some(OutputType::Change);

        let active_list_keys = self.get_active_list_keys();

        let has_all = match pois {
            Some(p) => Self::has_all_keys(p, &active_list_keys),
            None => false,
        };
        if !has_all {
            if is_shield_commitment_type(txo.commitment_type) {
                return WalletBalanceBucket::ShieldPending;
            }
            return if is_change {
                WalletBalanceBucket::MissingInternalPOI
            } else {
                WalletBalanceBucket::MissingExternalPOI
            };
        }
        let pois = pois.unwrap();

        if self.has_valid_pois_active_lists(Some(pois)) {
            return WalletBalanceBucket::Spendable;
        }

        let any_shield_blocked = active_list_keys
            .iter()
            .any(|k| pois.get(k) == Some(&TXOPOIListStatus::ShieldBlocked));
        if any_shield_blocked {
            return WalletBalanceBucket::ShieldBlocked;
        }

        if is_shield_commitment_type(txo.commitment_type) {
            return WalletBalanceBucket::ShieldPending;
        }

        let any_proof_submitted = active_list_keys
            .iter()
            .any(|k| pois.get(k) == Some(&TXOPOIListStatus::ProofSubmitted));
        if any_proof_submitted {
            return WalletBalanceBucket::ProofSubmitted;
        }

        if is_change {
            WalletBalanceBucket::MissingInternalPOI
        } else {
            WalletBalanceBucket::MissingExternalPOI
        }
    }

    fn get_all_list_keys_with_valid_input_pois(
        &self,
        input_pois_per_list: &[&POIsPerList],
    ) -> Vec<String> {
        let list_keys = self.get_all_list_keys();
        let mut out = Vec::new();
        for list_key in list_keys {
            let every_input_valid = input_pois_per_list
                .iter()
                .all(|pois| pois.get(&list_key) == Some(&TXOPOIListStatus::Valid));
            if every_input_valid {
                out.push(list_key);
            }
        }
        out
    }

    fn find_lists_for_new_pois(&self, pois_per_list: Option<&POIsPerList>) -> Vec<String> {
        let list_keys = self.get_all_list_keys();
        let pois_per_list = match pois_per_list {
            Some(p) => p,
            None => return list_keys,
        };
        let submitted_statuses = [TXOPOIListStatus::ProofSubmitted, TXOPOIListStatus::Valid];
        let mut needs_spend_poi = Vec::new();
        for list_key in list_keys {
            let is_unsubmitted = match pois_per_list.get(&list_key) {
                None => true,
                Some(status) => !submitted_statuses.contains(status),
            };
            if is_unsubmitted {
                needs_spend_poi.push(list_key);
            }
        }
        needs_spend_poi
    }

    /// `POI.filterSpentTXOs(TXOs, nullifiers, utxoTreeIn)`.
    ///
    /// Filters by `0x`-prefixed nullifier membership **and** tree (the tree scope
    /// guards against cross-tree nullifier collisions). Order is preserved.
    pub fn filter_spent_txos<N: Clone>(
        txos: &[TXO<N>],
        nullifiers: &[String],
        utxo_tree_in: u32,
    ) -> Vec<TXO<N>> {
        txos.iter()
            .filter(|txo| {
                nullifiers.contains(&format!("0x{}", txo.nullifier)) && txo.tree == utxo_tree_in
            })
            .cloned()
            .collect()
    }

    /// `POI.getListKeysCanGenerateSpentPOIs(...)`.
    pub fn get_list_keys_can_generate_spent_pois<N: PoiNote>(
        &self,
        spent_txos: &[TXO<N>],
        sent_commitments: &[SentCommitment<N>],
        unshield_events: &[UnshieldStoredEvent],
        is_legacy_poi_proof: bool,
    ) -> Vec<String> {
        if sent_commitments.is_empty() && unshield_events.is_empty() {
            return Vec::new();
        }

        let input_pois_per_list: Vec<&POIsPerList> = spent_txos
            .iter()
            .filter_map(|txo| txo.pois_per_list.as_ref())
            .collect();

        let list_keys_with_valid_input_pois = if is_legacy_poi_proof {
            self.get_all_list_keys()
        } else {
            self.get_all_list_keys_with_valid_input_pois(&input_pois_per_list)
        };

        let valid_statuses = [TXOPOIListStatus::Valid, TXOPOIListStatus::ProofSubmitted];

        list_keys_with_valid_input_pois
            .into_iter()
            .filter(|list_key| {
                let all_sent_zero_or_valid = sent_commitments.iter().all(|sc| {
                    if sc.note.value().is_zero() {
                        return true;
                    }
                    match sc.pois_per_list.as_ref().and_then(|p| p.get(list_key)) {
                        Some(status) => valid_statuses.contains(status),
                        None => false,
                    }
                });
                let all_unshield_valid = unshield_events.iter().all(|ue| {
                    match ue.pois_per_list.as_ref().and_then(|p| p.get(list_key)) {
                        Some(status) => valid_statuses.contains(status),
                        None => false,
                    }
                });
                let all_pois_valid = all_sent_zero_or_valid && all_unshield_valid;
                !all_pois_valid
            })
            .collect()
    }

    /// `POI.getListKeysCanSubmitLegacyTransactEvents(TXOs)`.
    pub fn get_list_keys_can_submit_legacy_transact_events<N>(
        &self,
        txos: &[TXO<N>],
    ) -> Vec<String> {
        let list_keys = self.get_all_list_keys();
        list_keys
            .into_iter()
            .filter(|list_key| {
                !txos.iter().all(|txo| {
                    txo.pois_per_list.as_ref().and_then(|p| p.get(list_key))
                        == Some(&TXOPOIListStatus::Valid)
                })
            })
            .collect()
    }

    /// `POI.isLegacyTXO(chain, txo)`.
    pub fn is_legacy_txo<N>(&self, chain: &Chain, txo: &TXO<N>) -> bool {
        match self.launch_block(chain) {
            None => true,
            Some(launch_block) => txo.block_number < launch_block,
        }
    }

    /// `POI.shouldSubmitLegacyTransactEventsTXOs(chain, txo)`.
    pub fn should_submit_legacy_transact_events_txos<N>(
        &self,
        chain: &Chain,
        txo: &TXO<N>,
    ) -> bool {
        if txo.transact_creation_railgun_txid.is_none() {
            return false;
        }
        if txo.blinded_commitment.is_none() {
            return false;
        }
        if !self.is_legacy_txo(chain, txo) {
            return false;
        }
        let pois = match txo.pois_per_list.as_ref() {
            Some(p) => p,
            None => return false,
        };
        if !is_transact_commitment_type(txo.commitment_type) {
            return false;
        }
        !self.has_valid_pois_all_lists(pois)
    }

    /// `POI.shouldRetrieveTXOPOIs(txo)`.
    pub fn should_retrieve_txo_pois<N>(&self, txo: &TXO<N>) -> bool {
        if txo.blinded_commitment.is_none() {
            return false;
        }
        match txo.pois_per_list.as_ref() {
            None => true,
            Some(pois) => !self.has_valid_pois_all_lists(pois),
        }
    }

    /// `POI.shouldRetrieveSentCommitmentPOIs(sentCommitment)`.
    pub fn should_retrieve_sent_commitment_pois<N: PoiNote>(&self, sc: &SentCommitment<N>) -> bool {
        if sc.blinded_commitment.is_none() {
            return false;
        }
        if sc.note.value().is_zero() {
            return false;
        }
        match sc.pois_per_list.as_ref() {
            None => true,
            Some(pois) => !self.has_valid_pois_all_lists(pois),
        }
    }

    /// `POI.shouldRetrieveUnshieldEventPOIs(unshieldEvent)`.
    pub fn should_retrieve_unshield_event_pois(&self, ue: &UnshieldStoredEvent) -> bool {
        if ue.railgun_txid.is_none() {
            return false;
        }
        match ue.pois_per_list.as_ref() {
            None => true,
            Some(pois) => !self.has_valid_pois_all_lists(pois),
        }
    }

    /// `POI.shouldGenerateSpentPOIsSentCommitment(sentCommitment)`.
    pub fn should_generate_spent_pois_sent_commitment<N: PoiNote>(
        &self,
        sc: &SentCommitment<N>,
    ) -> bool {
        if sc.blinded_commitment.is_none() {
            return false;
        }
        if sc.note.value().is_zero() {
            return false;
        }
        if sc.pois_per_list.is_none() {
            return true;
        }
        !self
            .find_lists_for_new_pois(sc.pois_per_list.as_ref())
            .is_empty()
    }

    /// `POI.shouldGenerateSpentPOIsUnshieldEvent(unshieldEvent)`.
    pub fn should_generate_spent_pois_unshield_event(&self, ue: &UnshieldStoredEvent) -> bool {
        if ue.railgun_txid.is_none() {
            return false;
        }
        if ue.pois_per_list.is_none() {
            return true;
        }
        !self
            .find_lists_for_new_pois(ue.pois_per_list.as_ref())
            .is_empty()
    }
}

/// Helper mirroring the TS `removeUndefineds` over an iterator of `Option`s.
pub fn remove_undefineds<T>(items: impl IntoIterator<Item = Option<T>>) -> Vec<T> {
    items.into_iter().flatten().collect()
}

/// Dedup-preserving order helper (not in TS, but handy for callers). Unused by
/// the core logic; kept private-ish via crate visibility.
#[allow(dead_code)]
pub(crate) fn unique_preserving_order(items: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(key: &str, list_type: POIListType) -> POIList {
        POIList {
            key: key.to_string(),
            list_type,
            name: key.to_string(),
            description: key.to_string(),
        }
    }

    // --- mock note ---
    #[derive(Clone, Debug)]
    struct MockNote {
        value: BigUint,
        output_type: Option<OutputType>,
    }
    impl PoiNote for MockNote {
        fn value(&self) -> &BigUint {
            &self.value
        }
        fn output_type(&self) -> Option<OutputType> {
            self.output_type
        }
    }
    fn note(value: u64, output_type: Option<OutputType>) -> MockNote {
        MockNote {
            value: BigUint::from(value),
            output_type,
        }
    }

    fn pois(entries: &[(&str, TXOPOIListStatus)]) -> POIsPerList {
        entries.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    fn txo(
        pois_per_list: Option<POIsPerList>,
        commitment_type: CommitmentType,
        n: MockNote,
    ) -> TXO<MockNote> {
        TXO {
            tree: 0,
            position: 0,
            txid: String::new(),
            timestamp: None,
            block_number: 0,
            spendtxid: SpendTxid::Unspent(false),
            nullifier: String::new(),
            note: n,
            pois_per_list,
            blinded_commitment: None,
            commitment_type,
            transact_creation_railgun_txid: None,
        }
    }

    fn sent(
        pois_per_list: Option<POIsPerList>,
        commitment_type: CommitmentType,
        n: MockNote,
    ) -> SentCommitment<MockNote> {
        SentCommitment {
            tree: 0,
            position: 0,
            txid: String::new(),
            timestamp: None,
            note: n,
            wallet_source: None,
            output_type: None,
            is_legacy_transact_note: false,
            railgun_txid: None,
            pois_per_list,
            blinded_commitment: None,
            commitment_type,
        }
    }

    fn unshield(pois_per_list: Option<POIsPerList>) -> UnshieldStoredEvent {
        UnshieldStoredEvent {
            txid: String::new(),
            timestamp: None,
            to_address: String::new(),
            token_type: 0,
            token_address: String::new(),
            token_sub_id: String::new(),
            amount: String::new(),
            fee: String::new(),
            block_number: 0,
            event_log_index: None,
            railgun_txid: None,
            pois_per_list,
        }
    }

    const MOCK_LIST_KEY: &str = "mockListKey";
    const ACTIVE1: &str = "activeList1";
    const ACTIVE2: &str = "activeList2";

    fn test_poi() -> Poi {
        let mut p = Poi::new(vec![
            list(MOCK_LIST_KEY, POIListType::Gather),
            list(ACTIVE1, POIListType::Active),
            list(ACTIVE2, POIListType::Active),
        ]);
        p.set_launch_block(
            &Chain {
                chain_type: 0,
                id: 1,
            },
            0,
        );
        p
    }

    fn invalid_pois() -> POIsPerList {
        pois(&[
            (ACTIVE1, TXOPOIListStatus::Missing),
            (ACTIVE2, TXOPOIListStatus::Valid),
        ])
    }
    fn submitted_pois() -> POIsPerList {
        pois(&[
            (ACTIVE1, TXOPOIListStatus::ProofSubmitted),
            (ACTIVE2, TXOPOIListStatus::Valid),
        ])
    }
    fn valid_pois() -> POIsPerList {
        pois(&[
            (ACTIVE1, TXOPOIListStatus::Valid),
            (ACTIVE2, TXOPOIListStatus::Valid),
        ])
    }

    // KAV from src/poi/__tests__/poi.test.ts
    #[test]
    fn should_get_which_list_keys_can_generate_spent_pois() {
        let poi = test_poi();

        // legacy: input proofs all lists valid
        let keys = poi.get_list_keys_can_generate_spent_pois(
            &[txo(
                Some(invalid_pois()),
                CommitmentType::TransactCommitmentV2,
                note(1, None),
            )],
            &[sent(
                Some(submitted_pois()),
                CommitmentType::TransactCommitmentV2,
                note(1, None),
            )],
            &[unshield(Some(invalid_pois()))],
            true,
        );
        assert_eq!(keys, vec![MOCK_LIST_KEY.to_string(), ACTIVE1.to_string()]);

        // legacy, sentCommitment value 0
        let keys = poi.get_list_keys_can_generate_spent_pois(
            &[txo(
                Some(invalid_pois()),
                CommitmentType::TransactCommitmentV2,
                note(1, None),
            )],
            &[sent(
                Some(submitted_pois()),
                CommitmentType::TransactCommitmentV2,
                note(0, None),
            )],
            &[unshield(Some(submitted_pois()))],
            true,
        );
        assert_eq!(keys, vec![MOCK_LIST_KEY.to_string()]);

        // non-legacy, no input proofs valid -> []
        let keys = poi.get_list_keys_can_generate_spent_pois(
            &[txo(
                Some(invalid_pois()),
                CommitmentType::TransactCommitmentV2,
                note(1, None),
            )],
            &[sent(
                Some(submitted_pois()),
                CommitmentType::TransactCommitmentV2,
                note(1, None),
            )],
            &[unshield(Some(submitted_pois()))],
            false,
        );
        assert_eq!(keys, Vec::<String>::new());

        // non-legacy, all valid output proofs -> []
        let keys = poi.get_list_keys_can_generate_spent_pois(
            &[txo(
                Some(valid_pois()),
                CommitmentType::TransactCommitmentV2,
                note(1, None),
            )],
            &[sent(
                Some(submitted_pois()),
                CommitmentType::TransactCommitmentV2,
                note(1, None),
            )],
            &[unshield(Some(valid_pois()))],
            false,
        );
        assert_eq!(keys, Vec::<String>::new());

        // non-legacy, invalid unshield proof -> [activeList1]
        let keys = poi.get_list_keys_can_generate_spent_pois(
            &[txo(
                Some(valid_pois()),
                CommitmentType::TransactCommitmentV2,
                note(1, None),
            )],
            &[sent(
                Some(submitted_pois()),
                CommitmentType::TransactCommitmentV2,
                note(1, None),
            )],
            &[unshield(Some(invalid_pois()))],
            false,
        );
        assert_eq!(keys, vec![ACTIVE1.to_string()]);
    }

    #[test]
    fn should_get_list_keys_to_submit_legacy_transact_events() {
        let poi = test_poi();
        let keys = poi.get_list_keys_can_submit_legacy_transact_events(&[
            txo(
                Some(invalid_pois()),
                CommitmentType::TransactCommitmentV2,
                note(1, None),
            ),
            txo(
                Some(valid_pois()),
                CommitmentType::TransactCommitmentV2,
                note(1, None),
            ),
        ]);
        assert_eq!(keys, vec![MOCK_LIST_KEY.to_string(), ACTIVE1.to_string()]);
    }

    #[test]
    fn should_get_appropriate_balance_bucket() {
        let poi = test_poi();

        let bucket = poi.get_balance_bucket(&txo(
            None,
            CommitmentType::TransactCommitmentV2,
            note(0, Some(OutputType::Change)),
        ));
        assert_eq!(bucket, WalletBalanceBucket::MissingInternalPOI);

        let bucket = poi.get_balance_bucket(&txo(
            None,
            CommitmentType::TransactCommitmentV2,
            note(0, Some(OutputType::Transfer)),
        ));
        assert_eq!(bucket, WalletBalanceBucket::MissingExternalPOI);

        let bucket = poi.get_balance_bucket(&txo(
            Some(invalid_pois()),
            CommitmentType::TransactCommitmentV2,
            note(1, Some(OutputType::Change)),
        ));
        assert_eq!(bucket, WalletBalanceBucket::MissingInternalPOI);

        let bucket = poi.get_balance_bucket(&txo(
            Some(submitted_pois()),
            CommitmentType::TransactCommitmentV2,
            note(1, Some(OutputType::Change)),
        ));
        assert_eq!(bucket, WalletBalanceBucket::ProofSubmitted);

        let bucket = poi.get_balance_bucket(&txo(
            Some(valid_pois()),
            CommitmentType::TransactCommitmentV2,
            note(1, Some(OutputType::Change)),
        ));
        assert_eq!(bucket, WalletBalanceBucket::Spendable);

        let bucket = poi.get_balance_bucket(&txo(
            Some(pois(&[
                (ACTIVE1, TXOPOIListStatus::Missing),
                (ACTIVE2, TXOPOIListStatus::Valid),
            ])),
            CommitmentType::ShieldCommitment,
            note(1, Some(OutputType::Change)),
        ));
        assert_eq!(bucket, WalletBalanceBucket::ShieldPending);

        let bucket = poi.get_balance_bucket(&txo(
            Some(pois(&[
                (ACTIVE1, TXOPOIListStatus::ShieldBlocked),
                (ACTIVE2, TXOPOIListStatus::Valid),
            ])),
            CommitmentType::ShieldCommitment,
            note(1, Some(OutputType::Change)),
        ));
        assert_eq!(bucket, WalletBalanceBucket::ShieldBlocked);

        // spent
        let mut spent_txo = txo(
            Some(pois(&[
                (ACTIVE1, TXOPOIListStatus::ShieldBlocked),
                (ACTIVE2, TXOPOIListStatus::Valid),
            ])),
            CommitmentType::ShieldCommitment,
            note(1, Some(OutputType::Change)),
        );
        spent_txo.spendtxid = SpendTxid::Txid("123".to_string());
        assert_eq!(
            poi.get_balance_bucket(&spent_txo),
            WalletBalanceBucket::Spent
        );
    }

    // KAV from src/poi/__tests__/poi-nullifier-collision.test.ts
    fn collision_txo(tree: u32, position: u32, nullifier: &str, txid: &str) -> TXO<MockNote> {
        let mut t = txo(None, CommitmentType::TransactCommitmentV2, note(0, None));
        t.tree = tree;
        t.position = position;
        t.nullifier = nullifier.to_string();
        t.txid = txid.to_string();
        t
    }

    #[test]
    fn filter_spent_txos_by_tree_avoids_collision() {
        let txo_tree1 = collision_txo(1, 0, "COLLISION", "1000");
        let txo_tree2 = collision_txo(2, 0, "COLLISION", "2000");
        let txo_other = collision_txo(2, 1, "B", "2000");

        let result = Poi::filter_spent_txos(
            &[txo_tree1, txo_tree2.clone(), txo_other.clone()],
            &["0xCOLLISION".to_string(), "0xB".to_string()],
            2,
        );
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].txid, txo_tree2.txid);
        assert_eq!(result[0].tree, 2);
        assert_eq!(result[1].txid, txo_other.txid);
    }

    #[test]
    fn filter_spent_txos_ordering_with_collision() {
        let txo_tree1 = collision_txo(1, 0, "COLLISION", "1000");
        let txo_tree2 = collision_txo(2, 0, "COLLISION", "2000");
        let txo_b = collision_txo(2, 1, "B", "2000");
        let nullifiers = vec!["0xCOLLISION".to_string(), "0xB".to_string()];

        let spent = Poi::filter_spent_txos(&[txo_tree1, txo_tree2, txo_b], &nullifiers, 2);
        let ordered: Vec<TXO<MockNote>> = remove_undefineds(nullifiers.iter().map(|n| {
            spent
                .iter()
                .find(|t| format!("0x{}", t.nullifier) == *n)
                .cloned()
        }));
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].tree, 2);
        assert_eq!(ordered[0].txid, "2000");
        assert_eq!(ordered[1].nullifier, "B");
    }

    #[test]
    fn filter_spent_txos_no_collision() {
        let txo_a = collision_txo(2, 0, "A", "");
        let txo_b = collision_txo(2, 1, "B", "");
        let result =
            Poi::filter_spent_txos(&[txo_a, txo_b], &["0xA".to_string(), "0xB".to_string()], 2);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].nullifier, "A");
        assert_eq!(result[1].nullifier, "B");
    }
}
