//! Differential fuzz against the Bun/TS oracle (rust/vectors/higher.json):
//! ERC20/NFT token-data hashing and note hashing.

use num_bigint::BigUint;
use railgun_models::formatted_types::TokenData;
use railgun_note::transact_note::TransactNote;
use railgun_note::{get_note_hash, get_token_data_hash};
use serde::Deserialize;

fn load(name: &str) -> serde_json::Value {
    let dir = std::env::var("RAILGUN_VECTORS_DIR")
        .unwrap_or_else(|_| format!("{}/../../vectors", env!("CARGO_MANIFEST_DIR")));
    let path = format!("{dir}/{name}");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|_| panic!("missing corpus {path}; run: bun run rust/oracle/gen.ts"));
    serde_json::from_slice(&bytes).unwrap()
}
fn from<T: for<'de> Deserialize<'de>>(v: &serde_json::Value, key: &str) -> Vec<T> {
    serde_json::from_value(v[key].clone()).unwrap()
}
fn dec(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).unwrap()
}

#[derive(Deserialize)]
struct TokenHashCase {
    #[serde(rename = "tokenData")]
    token_data: TokenData,
    out: String,
}
#[derive(Deserialize)]
struct NoteHashCase {
    address: String,
    #[serde(rename = "tokenData")]
    token_data: TokenData,
    value: String,
    out: String,
}
#[derive(Deserialize)]
struct NullifierCase {
    #[serde(rename = "nullifyingKey")]
    nullifying_key: String,
    #[serde(rename = "leafIndex")]
    leaf_index: u64,
    out: String,
}

#[test]
fn fuzz_note_against_ts_oracle() {
    let v = load("higher.json");

    for c in from::<TokenHashCase>(&v, "tokenHashErc20") {
        assert_eq!(get_token_data_hash(&c.token_data), c.out, "tokenHashErc20");
    }
    for c in from::<TokenHashCase>(&v, "tokenHashNft") {
        assert_eq!(get_token_data_hash(&c.token_data), c.out, "tokenHashNft");
    }
    for c in from::<NoteHashCase>(&v, "noteHash") {
        assert_eq!(
            get_note_hash(&c.address, &c.token_data, &dec(&c.value)),
            dec(&c.out),
            "noteHash"
        );
    }
    // Nullifier = poseidon([nullifyingKey, leafIndex]).
    for c in from::<NullifierCase>(&v, "nullifier") {
        assert_eq!(
            TransactNote::get_nullifier(&dec(&c.nullifying_key), c.leaf_index),
            dec(&c.out),
            "nullifier"
        );
    }
}
