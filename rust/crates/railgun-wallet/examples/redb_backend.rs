//! Plugging your own `redb` store into RAILGUN.
//!
//! `railgun-db` ships NO database engine — only the `KvStore` trait and an
//! in-memory `MemStore`. To persist a wallet in your app's own redb, implement
//! `KvStore` over a single redb table (RAILGUN's own key layout + AES-GCM value
//! sealing sit on top; your redb just stores opaque `String -> Vec<u8>`).
//!
//!   cargo run -p railgun-wallet --example redb_backend

use railgun_db::{Database, KvStore};
use railgun_key_derivation::Mnemonic;
use railgun_models::engine_types::Chain;
use railgun_wallet::RailgunWallet;
use redb::{Database as Redb, TableDefinition};
use std::sync::Arc;

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("railgun");

/// A `KvStore` adapter over a redb table. Clone-able so it can be shared; the
/// underlying `redb::Database` is internally synchronized.
#[derive(Clone)]
struct RedbStore {
    db: Arc<Redb>,
}

impl RedbStore {
    fn new(db: Redb) -> Self {
        // Ensure the table exists so read txns don't error on an empty db.
        let w = db.begin_write().unwrap();
        w.open_table(TABLE).unwrap();
        w.commit().unwrap();
        Self { db: Arc::new(db) }
    }
}

impl KvStore for RedbStore {
    fn put(&mut self, key: String, value: Vec<u8>) {
        let w = self.db.begin_write().unwrap();
        {
            let mut t = w.open_table(TABLE).unwrap();
            t.insert(key.as_str(), value.as_slice()).unwrap();
        }
        w.commit().unwrap();
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        let r = self.db.begin_read().unwrap();
        let t = r.open_table(TABLE).unwrap();
        t.get(key).unwrap().map(|v| v.value().to_vec())
    }

    fn del(&mut self, key: &str) {
        let w = self.db.begin_write().unwrap();
        {
            let mut t = w.open_table(TABLE).unwrap();
            t.remove(key).unwrap();
        }
        w.commit().unwrap();
    }

    fn range(&self, gte: &str, lte: &str) -> Vec<(String, Vec<u8>)> {
        let r = self.db.begin_read().unwrap();
        let t = r.open_table(TABLE).unwrap();
        t.range(gte..=lte)
            .unwrap()
            .map(|row| {
                let (k, v) = row.unwrap();
                (k.value().to_string(), v.value().to_vec())
            })
            .collect()
    }

    fn clear_range(&mut self, gte: &str, lte: &str) {
        let keys: Vec<String> = self.range(gte, lte).into_iter().map(|(k, _)| k).collect();
        let w = self.db.begin_write().unwrap();
        {
            let mut t = w.open_table(TABLE).unwrap();
            for k in keys {
                t.remove(k.as_str()).unwrap();
            }
        }
        w.commit().unwrap();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Your app's redb — in-memory here; use `Redb::create("wallet.redb")` on disk.
    let redb = Redb::builder().create_with_backend(redb::backends::InMemoryBackend::new())?;
    let mut db = Database::new(RedbStore::new(redb));

    let encryption_key = [0x11u8; 32];
    let mnemonic = Mnemonic::generate(128);

    // Identical to the MemStore flow — the wallet doesn't know or care which
    // KvStore backs it.
    let wallet = RailgunWallet::from_mnemonic(&mut db, &encryption_key, &mnemonic, 0, None)?;
    let ethereum = Chain {
        chain_type: 0,
        id: 1,
    };
    let zk_address = wallet.wallet.get_address(Some(ethereum));

    // Reload from the same redb-backed store.
    let id = wallet.wallet.id.clone();
    let restored = RailgunWallet::load_existing(&db, &encryption_key, &id, None)?;
    assert_eq!(restored.wallet.get_address(Some(ethereum)), zk_address);

    println!("wallet persisted in redb; 0zk address: {zk_address}");
    Ok(())
}
