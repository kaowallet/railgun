//! Differential fuzz against the Bun/TS oracle (rust/vectors/higher.json):
//! getRailgunTransactionID (random nullifier/commitment counts — exercises the
//! wide 13-input Poseidon path), the txid leaf hash, and the keccak verification
//! hash chain.

use num_bigint::BigUint;
use railgun_transaction::railgun_txid::{
    calculate_railgun_transaction_verification_hash, get_railgun_transaction_id_hex,
    get_railgun_txid_leaf_hash,
};
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
struct TxidCase {
    nullifiers: Vec<String>,
    commitments: Vec<String>,
    #[serde(rename = "boundParamsHash")]
    bound_params_hash: String,
    out: String,
}
#[derive(Deserialize)]
struct LeafCase {
    txid: String,
    #[serde(rename = "utxoTreeIn")]
    utxo_tree_in: String,
    #[serde(rename = "globalPos")]
    global_pos: String,
    out: String,
}
#[derive(Deserialize)]
struct VerifyCase {
    prev: Option<String>,
    #[serde(rename = "firstNullifier")]
    first_nullifier: String,
    out: String,
}

#[test]
fn fuzz_transaction_against_ts_oracle() {
    let v = load("higher.json");

    for c in from::<TxidCase>(&v, "railgunTxid") {
        assert_eq!(
            get_railgun_transaction_id_hex(&c.nullifiers, &c.commitments, &c.bound_params_hash),
            c.out,
            "railgunTxid ({} nullifiers, {} commitments)",
            c.nullifiers.len(),
            c.commitments.len()
        );
    }
    for c in from::<LeafCase>(&v, "txidLeafHash") {
        assert_eq!(
            get_railgun_txid_leaf_hash(&dec(&c.txid), &dec(&c.utxo_tree_in), &dec(&c.global_pos)),
            c.out,
            "txidLeafHash"
        );
    }
    for c in from::<VerifyCase>(&v, "verificationHash") {
        assert_eq!(
            calculate_railgun_transaction_verification_hash(c.prev.as_deref(), &c.first_nullifier),
            c.out,
            "verificationHash"
        );
    }
}
