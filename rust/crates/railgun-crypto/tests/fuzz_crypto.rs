//! Differential fuzz against the Bun/TS oracle (rust/vectors/crypto.json):
//! hashes, Poseidon, BabyJubJub spending keys, Ed25519 viewing keys, the private
//! scalar, and X25519 ECDH (incl. invalid-point => None parity).

use num_bigint::BigUint;
use railgun_crypto::*;
use serde::Deserialize;

fn load(name: &str) -> serde_json::Value {
    let path = format!("{}/../../vectors/{}", env!("CARGO_MANIFEST_DIR"), name);
    let bytes = std::fs::read(&path).unwrap_or_else(|_| panic!("missing corpus {path}; run the oracle generator"));
    serde_json::from_slice(&bytes).unwrap()
}
fn from<T: for<'de> Deserialize<'de>>(v: &serde_json::Value, key: &str) -> Vec<T> {
    serde_json::from_value(v[key].clone()).unwrap()
}
fn dec(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).unwrap()
}
fn b32(h: &str) -> [u8; 32] {
    hex::decode(h).unwrap().try_into().unwrap()
}

#[derive(Deserialize)]
struct Hashcase {
    #[serde(rename = "in")]
    input: String,
    out: String,
}
#[derive(Deserialize)]
struct Hmac {
    key: String,
    data: String,
    out: String,
}
#[derive(Deserialize)]
struct Poseidon {
    #[serde(rename = "in")]
    input: Vec<String>,
    out: String,
}
#[derive(Deserialize)]
struct SpendingKey {
    #[serde(rename = "in")]
    input: String,
    x: String,
    y: String,
}
#[derive(Deserialize)]
struct ViewingKey {
    #[serde(rename = "in")]
    input: String,
    out: String,
}
#[derive(Deserialize)]
struct Scalar {
    #[serde(rename = "in")]
    input: String,
    out: String,
}
#[derive(Deserialize)]
struct SharedKey {
    #[serde(rename = "privA")]
    priv_a: String,
    #[serde(rename = "pubB")]
    pub_b: String,
    out: Option<String>,
}

#[test]
fn fuzz_crypto_against_ts_oracle() {
    let v = load("crypto.json");

    for c in from::<Hashcase>(&v, "sha256") {
        assert_eq!(sha256(&hex::decode(&c.input).unwrap()), c.out, "sha256");
    }
    for c in from::<Hashcase>(&v, "sha512") {
        assert_eq!(sha512(&hex::decode(&c.input).unwrap()), c.out, "sha512");
    }
    for c in from::<Hashcase>(&v, "keccak256") {
        assert_eq!(keccak256(&hex::decode(&c.input).unwrap()), c.out, "keccak256");
    }
    for c in from::<Hmac>(&v, "sha512Hmac") {
        assert_eq!(
            sha512_hmac(&hex::decode(&c.key).unwrap(), &hex::decode(&c.data).unwrap()),
            c.out,
            "sha512HMAC"
        );
    }
    for c in from::<Poseidon>(&v, "poseidon") {
        let inputs: Vec<BigUint> = c.input.iter().map(|s| dec(s)).collect();
        assert_eq!(poseidon(&inputs), dec(&c.out), "poseidon({:?})", c.input);
    }
    for c in from::<Poseidon>(&v, "poseidonHex") {
        let refs: Vec<&str> = c.input.iter().map(|s| s.as_str()).collect();
        assert_eq!(poseidon_hex(&refs), c.out, "poseidonHex");
    }
    for c in from::<SpendingKey>(&v, "spendingKey") {
        assert_eq!(get_public_spending_key(&b32(&c.input)), (dec(&c.x), dec(&c.y)), "spendingKey({})", c.input);
    }
    for c in from::<ViewingKey>(&v, "viewingKey") {
        assert_eq!(hex::encode(get_public_viewing_key(&b32(&c.input))), c.out, "viewingKey({})", c.input);
    }
    for c in from::<Scalar>(&v, "privateScalar") {
        assert_eq!(get_private_scalar_from_private_key(&b32(&c.input)), dec(&c.out), "privateScalar({})", c.input);
    }
    for c in from::<SharedKey>(&v, "sharedKey") {
        let got = get_shared_symmetric_key(&b32(&c.priv_a), &b32(&c.pub_b)).map(hex::encode);
        assert_eq!(got, c.out, "sharedKey({}, {})", c.priv_a, c.pub_b);
    }
}
