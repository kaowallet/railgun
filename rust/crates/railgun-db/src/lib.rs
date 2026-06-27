//! `railgun-db` — port of `src/database/database.ts`.
//!
//! A small ordered key-value store with RAILGUN's path-to-key encoding and
//! AES-256-GCM encrypted values. The browser/levelup/IndexedDB specifics are
//! dropped (desktop, fresh re-sync) and replaced with a [`KvStore`] trait so a
//! persistent backend (e.g. `redb`) can slot in behind the same API. The default
//! [`MemStore`] is an in-memory `BTreeMap`, matching LevelDB's sorted-key
//! semantics for namespace streaming.

use std::collections::BTreeMap;

use railgun_crypto::{decrypt_gcm, encrypt_gcm, Ciphertext};
use railgun_utils::{arrayify, chunk, combine, hexlify, BytesData};

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("Key not found in database [{0}]")]
    KeyNotFound(String),
    #[error("Failed to decrypt database value")]
    Decrypt,
    #[error("invalid value")]
    InvalidValue,
}

/// Backend storage abstraction. Keys are the colon-delimited path keys; values
/// are opaque bytes. Range queries are inclusive and rely on lexicographic order.
pub trait KvStore {
    fn put(&mut self, key: String, value: Vec<u8>);
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn del(&mut self, key: &str);
    fn range(&self, gte: &str, lte: &str) -> Vec<(String, Vec<u8>)>;
    fn clear_range(&mut self, gte: &str, lte: &str);
}

#[derive(Default)]
pub struct MemStore(BTreeMap<String, Vec<u8>>);

impl MemStore {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
}

impl KvStore for MemStore {
    fn put(&mut self, key: String, value: Vec<u8>) {
        self.0.insert(key, value);
    }
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.0.get(key).cloned()
    }
    fn del(&mut self, key: &str) {
        self.0.remove(key);
    }
    fn range(&self, gte: &str, lte: &str) -> Vec<(String, Vec<u8>)> {
        self.0
            .range(gte.to_string()..=lte.to_string())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
    fn clear_range(&mut self, gte: &str, lte: &str) {
        let keys: Vec<String> = self
            .0
            .range(gte.to_string()..=lte.to_string())
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            self.0.remove(&k);
        }
    }
}

pub struct Database<S: KvStore> {
    store: S,
}

impl Database<MemStore> {
    /// In-memory database (used by tests and ephemeral contexts).
    pub fn in_memory() -> Self {
        Self {
            store: MemStore::new(),
        }
    }
}

impl<S: KvStore> Database<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// `Database.pathToKey` — hexlify each segment, left-pad to 32 bytes, join ':'.
    pub fn path_to_key(path: &[BytesData]) -> String {
        path.iter()
            .map(|el| format!("{:0>64}", hexlify(el, false)))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// `put` (hex encoding) — store a value coerced to raw bytes.
    pub fn put(&mut self, path: &[BytesData], value: &BytesData) -> Result<(), DbError> {
        let bytes = arrayify(value).map_err(|_| DbError::InvalidValue)?;
        self.store.put(Self::path_to_key(path), bytes);
        Ok(())
    }

    /// `get` (hex encoding) — returns the value as a hex string.
    pub fn get(&self, path: &[BytesData]) -> Result<String, DbError> {
        let key = Self::path_to_key(path);
        self.store
            .get(&key)
            .map(hex::encode)
            .ok_or(DbError::KeyNotFound(key))
    }

    /// `del`.
    pub fn del(&mut self, path: &[BytesData]) {
        self.store.del(&Self::path_to_key(path));
    }

    /// `putEncrypted` — AES-256-GCM, stored as JSON.
    pub fn put_encrypted(
        &mut self,
        path: &[BytesData],
        encryption_key: &[u8],
        value: &str,
    ) -> Result<(), DbError> {
        let chunks = chunk(&BytesData::Hex(value.to_string()), 32);
        let encrypted = encrypt_gcm(&chunks, encryption_key).map_err(|_| DbError::Decrypt)?;
        let json = serde_json::to_vec(&encrypted).map_err(|_| DbError::InvalidValue)?;
        self.store.put(Self::path_to_key(path), json);
        Ok(())
    }

    /// `getEncrypted`.
    pub fn get_encrypted(
        &self,
        path: &[BytesData],
        encryption_key: &[u8],
    ) -> Result<String, DbError> {
        let key = Self::path_to_key(path);
        let bytes = self.store.get(&key).ok_or(DbError::KeyNotFound(key))?;
        let ciphertext: Ciphertext =
            serde_json::from_slice(&bytes).map_err(|_| DbError::InvalidValue)?;
        let plaintext = decrypt_gcm(&ciphertext, encryption_key).map_err(|_| DbError::Decrypt)?;
        Ok(combine(&plaintext))
    }

    /// `countNamespace`.
    pub fn count_namespace(&self, namespace: &[BytesData]) -> usize {
        let pathkey = Self::path_to_key(namespace);
        self.store.range(&pathkey, &format!("{pathkey}~")).len()
    }

    /// `getNamespaceKeys`.
    pub fn get_namespace_keys(&self, namespace: &[BytesData]) -> Vec<String> {
        let pathkey = Self::path_to_key(namespace);
        self.store
            .range(&pathkey, &format!("{pathkey}~"))
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    }

    /// `streamRange` — values (hex) in an inclusive key range.
    pub fn stream_range(&self, start: &[BytesData], end: &[BytesData]) -> Vec<String> {
        let start_key = Self::path_to_key(start);
        let end_key = Self::path_to_key(end);
        self.store
            .range(&start_key, &end_key)
            .into_iter()
            .map(|(_, v)| hex::encode(v))
            .collect()
    }

    /// `clearNamespace`.
    pub fn clear_namespace(&mut self, namespace: &[BytesData]) {
        let pathkey = Self::path_to_key(namespace);
        self.store.clear_range(&pathkey, &format!("{pathkey}~"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    fn key() -> Vec<u8> {
        hex::decode(TEST_KEY_HEX).unwrap()
    }
    fn p(parts: &[&str]) -> Vec<BytesData> {
        parts
            .iter()
            .map(|s| BytesData::Hex((*s).to_string()))
            .collect()
    }

    // src/database/__tests__/database.test.ts
    #[test]
    fn create_and_get() {
        let mut db = Database::in_memory();
        db.put(&p(&["a"]), &BytesData::Hex("01".into())).unwrap();
        assert_eq!(db.get(&p(&["a"])).unwrap(), "01");
    }

    #[test]
    fn crud_operations() {
        let mut db = Database::in_memory();
        assert!(
            matches!(db.get(&p(&["a"])), Err(DbError::KeyNotFound(k)) if k == "000000000000000000000000000000000000000000000000000000000000000a")
        );
        db.put(&p(&["a"]), &BytesData::Hex("01".into())).unwrap();
        assert_eq!(db.get(&p(&["a"])).unwrap(), "01");
        db.del(&p(&["a"]));
        assert!(matches!(db.get(&p(&["a"])), Err(DbError::KeyNotFound(_))));
    }

    #[test]
    fn encrypted_values() {
        let mut db = Database::in_memory();
        db.put_encrypted(&p(&["a", "b"]), &key(), "01").unwrap();
        assert_eq!(db.get_encrypted(&p(&["a", "b"]), &key()).unwrap(), "01");
    }

    #[test]
    fn count_namespace() {
        let mut db = Database::in_memory();
        db.put(&p(&["a", "a"]), &BytesData::Hex("01".into()))
            .unwrap();
        db.put(&p(&["a", "b"]), &BytesData::Hex("02".into()))
            .unwrap();
        db.put(&p(&["a", "c"]), &BytesData::Hex("03".into()))
            .unwrap();
        assert_eq!(db.get(&p(&["a", "a"])).unwrap(), "01");
        assert_eq!(db.count_namespace(&p(&["a"])), 3);
    }

    #[test]
    fn stream_range() {
        let mut db = Database::in_memory();
        db.put(&p(&["a", "a"]), &BytesData::Hex("01".into()))
            .unwrap();
        db.put(&p(&["a", "b"]), &BytesData::Hex("02".into()))
            .unwrap();
        db.put(&p(&["a", "c"]), &BytesData::Hex("03".into()))
            .unwrap();
        let mut datas = db.stream_range(&p(&["a", "a"]), &p(&["a", "c"]));
        datas.sort();
        assert_eq!(datas, vec!["01", "02", "03"]);
    }

    #[test]
    fn clear_namespace() {
        let mut db = Database::in_memory();
        db.put(&p(&["a", "a"]), &BytesData::Hex("01".into()))
            .unwrap();
        db.put(&p(&["a", "b"]), &BytesData::Hex("02".into()))
            .unwrap();
        db.put(&p(&["a", "c"]), &BytesData::Hex("03".into()))
            .unwrap();
        db.clear_namespace(&p(&["a"]));
        assert!(
            matches!(db.get(&p(&["a", "a"])), Err(DbError::KeyNotFound(k))
            if k == "000000000000000000000000000000000000000000000000000000000000000a:000000000000000000000000000000000000000000000000000000000000000a")
        );
    }

    #[test]
    fn byte_array_to_hex() {
        let mut db = Database::in_memory();
        db.put(
            &[BytesData::Bytes(vec![0x1]), BytesData::Bytes(vec![0xa])],
            &BytesData::Bytes(vec![0xaa]),
        )
        .unwrap();
        db.put(
            &[BytesData::Bytes(vec![0x1]), BytesData::Bytes(vec![0xb])],
            &BytesData::Bytes(vec![0xab]),
        )
        .unwrap();
        assert_eq!(db.get(&p(&["01", "0a"])).unwrap(), "aa");
        assert_eq!(db.get(&p(&["01", "0b"])).unwrap(), "ab");
    }
}
