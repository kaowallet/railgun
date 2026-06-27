//! Differential fuzz against the Bun/TS oracle (rust/vectors/higher.json):
//! blinded commitments (shield/transact + unshield) and global tree position.

use num_bigint::BigUint;
use railgun_poi::{get_global_tree_position, BlindedCommitment};
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
struct BlindedShieldTransactCase {
    #[serde(rename = "commitmentHash")]
    commitment_hash: String,
    npk: String,
    #[serde(rename = "globalTreePosition")]
    global_tree_position: String,
    out: String,
}
#[derive(Deserialize)]
struct BlindedUnshieldCase {
    #[serde(rename = "railgunTxid")]
    railgun_txid: String,
    out: String,
}
#[derive(Deserialize)]
struct GposCase {
    tree: u64,
    index: u64,
    out: String,
}

#[test]
fn fuzz_poi_against_ts_oracle() {
    let v = load("higher.json");

    for c in from::<BlindedShieldTransactCase>(&v, "blindedShieldTransact") {
        assert_eq!(
            BlindedCommitment::get_for_shield_or_transact(
                &c.commitment_hash,
                &dec(&c.npk),
                &dec(&c.global_tree_position)
            ),
            c.out,
            "blindedShieldTransact"
        );
    }
    for c in from::<BlindedUnshieldCase>(&v, "blindedUnshield") {
        assert_eq!(
            BlindedCommitment::get_for_unshield(&c.railgun_txid),
            c.out,
            "blindedUnshield"
        );
    }
    for c in from::<GposCase>(&v, "globalTreePosition") {
        assert_eq!(
            get_global_tree_position(c.tree, c.index),
            dec(&c.out),
            "globalTreePosition"
        );
    }
}
