//! Port of `src/prover/proof-cache.ts`.
//!
//! Caches Railgun Groth16 proofs keyed by the (stringified) unproved
//! transaction inputs. The TS uses `stringifySafe(transactionRequest)` — a
//! JSON serialization with bigints rendered as decimal strings — as the map
//! key. We keep the same idea but key on a caller-provided string so the cache
//! stays decoupled from the exact `UnprovedTransactionInputs` shape (which
//! lives across other crates and varies V2/V3).

use std::collections::HashMap;
use std::sync::Mutex;

use railgun_models::prover_types::Proof;

/// Cache of Railgun proofs keyed by a stringified transaction-inputs key.
#[derive(Default)]
pub struct ProofCache {
    cache: Mutex<HashMap<String, Proof>>,
}

impl ProofCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a cached proof by its string key.
    pub fn get(&self, key: &str) -> Option<Proof> {
        self.cache.lock().unwrap().get(key).cloned()
    }

    /// Store a proof under the given string key.
    pub fn store(&self, key: String, proof: Proof) {
        self.cache.lock().unwrap().insert(key, proof);
    }

    pub fn clear(&self) {
        self.cache.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_proof(tag: &str) -> Proof {
        Proof {
            pi_a: [tag.into(), "2".into()],
            pi_b: [["3".into(), "4".into()], ["5".into(), "6".into()]],
            pi_c: [tag.into(), "8".into()],
        }
    }

    #[test]
    fn store_and_get() {
        let cache = ProofCache::new();
        assert_eq!(cache.get("a"), None);
        cache.store("a".into(), dummy_proof("a"));
        assert_eq!(cache.get("a"), Some(dummy_proof("a")));
        // Different key misses.
        assert_eq!(cache.get("b"), None);
    }
}
