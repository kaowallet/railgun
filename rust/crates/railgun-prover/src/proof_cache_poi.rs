//! Port of `src/prover/proof-cache-poi.ts`.
//!
//! Caches POI Groth16 proofs. The TS key is:
//! `stringifySafe([listKey, anyRailgunTxidMerklerootAfterTransaction,
//!  ...blindedCommitmentsOut, ...poiMerkleroots, railgunTxidIfHasUnshield])`.
//! We build the same JSON array key here so the cache hit/miss semantics match
//! the TS byte-for-byte.

use std::collections::HashMap;
use std::sync::Mutex;

use railgun_models::prover_types::Proof;

/// Cache of POI proofs keyed by the same fields the TS hashes.
#[derive(Default)]
pub struct ProofCachePOI {
    cache: Mutex<HashMap<String, Proof>>,
}

impl ProofCachePOI {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds the cache key, matching `stringifySafe([...])` in the TS. All the
    /// components are strings, so the JSON encoding is deterministic.
    pub fn cache_key(
        list_key: &str,
        any_railgun_txid_merkleroot_after_transaction: &str,
        blinded_commitments_out: &[String],
        poi_merkleroots: &[String],
        railgun_txid_if_has_unshield: &str,
    ) -> String {
        let mut arr: Vec<&str> =
            Vec::with_capacity(3 + blinded_commitments_out.len() + poi_merkleroots.len());
        arr.push(list_key);
        arr.push(any_railgun_txid_merkleroot_after_transaction);
        for s in blinded_commitments_out {
            arr.push(s);
        }
        for s in poi_merkleroots {
            arr.push(s);
        }
        arr.push(railgun_txid_if_has_unshield);
        serde_json::to_string(&arr).expect("string array serializes")
    }

    pub fn get(
        &self,
        list_key: &str,
        any_railgun_txid_merkleroot_after_transaction: &str,
        blinded_commitments_out: &[String],
        poi_merkleroots: &[String],
        railgun_txid_if_has_unshield: &str,
    ) -> Option<Proof> {
        let key = Self::cache_key(
            list_key,
            any_railgun_txid_merkleroot_after_transaction,
            blinded_commitments_out,
            poi_merkleroots,
            railgun_txid_if_has_unshield,
        );
        self.cache.lock().unwrap().get(&key).cloned()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn store(
        &self,
        list_key: &str,
        any_railgun_txid_merkleroot_after_transaction: &str,
        blinded_commitments_out: &[String],
        poi_merkleroots: &[String],
        railgun_txid_if_has_unshield: &str,
        proof: Proof,
    ) {
        let key = Self::cache_key(
            list_key,
            any_railgun_txid_merkleroot_after_transaction,
            blinded_commitments_out,
            poi_merkleroots,
            railgun_txid_if_has_unshield,
        );
        self.cache.lock().unwrap().insert(key, proof);
    }

    /// `clear_TEST_ONLY` in the TS.
    pub fn clear(&self) {
        self.cache.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_proof() -> Proof {
        Proof {
            pi_a: ["1".into(), "2".into()],
            pi_b: [["3".into(), "4".into()], ["5".into(), "6".into()]],
            pi_c: ["7".into(), "8".into()],
        }
    }

    #[test]
    fn cache_key_matches_ts_json() {
        let key = ProofCachePOI::cache_key(
            "abcde",
            "0xroot",
            &["bc0".into(), "bc1".into()],
            &["pm0".into()],
            "0xunshield",
        );
        assert_eq!(key, r#"["abcde","0xroot","bc0","bc1","pm0","0xunshield"]"#);
    }

    #[test]
    fn store_and_get_roundtrip() {
        let cache = ProofCachePOI::new();
        let bc = vec!["bc0".to_string()];
        let pm = vec!["pm0".to_string()];
        assert_eq!(cache.get("k", "r", &bc, &pm, "u"), None);
        cache.store("k", "r", &bc, &pm, "u", dummy_proof());
        assert_eq!(cache.get("k", "r", &bc, &pm, "u"), Some(dummy_proof()));
        // Differing list key misses.
        assert_eq!(cache.get("k2", "r", &bc, &pm, "u"), None);
        cache.clear();
        assert_eq!(cache.get("k", "r", &bc, &pm, "u"), None);
    }
}
