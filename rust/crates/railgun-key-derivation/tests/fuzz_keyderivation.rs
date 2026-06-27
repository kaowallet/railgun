//! Differential fuzz against the Bun/TS oracle (rust/vectors/keyderivation.json):
//! BIP39 seed/entropy/0x-key, the custom BabyJubJub BIP32, wallet key pairs, and
//! 0zk address encode+decode roundtrips.

use num_bigint::BigUint;
use railgun_key_derivation::*;
use serde::Deserialize;

fn load(name: &str) -> serde_json::Value {
    let dir = std::env::var("RAILGUN_VECTORS_DIR")
        .unwrap_or_else(|_| format!("{}/../../vectors", env!("CARGO_MANIFEST_DIR")));
    let path = format!("{dir}/{name}");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|_| panic!("missing corpus {path}; run the oracle generator"));
    serde_json::from_slice(&bytes).unwrap()
}
fn from<T: for<'de> Deserialize<'de>>(v: &serde_json::Value, key: &str) -> Vec<T> {
    serde_json::from_value(v[key].clone()).unwrap()
}
fn dec(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).unwrap()
}

#[derive(Deserialize)]
struct ToSeed {
    mnemonic: String,
    password: String,
    out: String,
}
#[derive(Deserialize)]
struct Entropy {
    entropy: String,
    mnemonic: String,
}
#[derive(Deserialize)]
struct To0x {
    mnemonic: String,
    index: u32,
    out: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MasterKey {
    seed: String,
    chain_key: String,
    chain_code: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyNodeJson {
    chain_key: String,
    chain_code: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChildKey {
    parent: KeyNodeJson,
    index: u32,
    chain_key: String,
    chain_code: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpendingKeyPairCase {
    mnemonic: String,
    path: String,
    private_key: String,
    x: String,
    y: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ViewingKeyPairCase {
    mnemonic: String,
    path: String,
    private_key: String,
    pubkey: String,
}
#[derive(Deserialize)]
struct NullifyingKey {
    mnemonic: String,
    path: String,
    out: String,
}
#[derive(Deserialize)]
struct ChainJson {
    #[serde(rename = "type")]
    chain_type: u8,
    id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Address {
    master_public_key: String,
    viewing_public_key: String,
    chain: Option<ChainJson>,
    encoded: String,
}

#[test]
fn fuzz_key_derivation_against_ts_oracle() {
    let v = load("keyderivation.json");

    for c in from::<ToSeed>(&v, "toSeed") {
        assert_eq!(
            Mnemonic::to_seed(&c.mnemonic, &c.password).unwrap(),
            c.out,
            "toSeed"
        );
    }
    for c in from::<Entropy>(&v, "entropy") {
        assert_eq!(
            Mnemonic::to_entropy(&c.mnemonic).unwrap(),
            c.entropy,
            "toEntropy"
        );
        assert_eq!(
            Mnemonic::from_entropy(&c.entropy).unwrap(),
            c.mnemonic,
            "fromEntropy"
        );
    }
    for c in from::<To0x>(&v, "to0xPrivateKey") {
        assert_eq!(
            Mnemonic::to_0x_private_key(&c.mnemonic, Some(c.index), "").unwrap(),
            c.out,
            "to0xPrivateKey"
        );
    }
    for c in from::<MasterKey>(&v, "masterKey") {
        let node = get_master_key_from_seed(&c.seed);
        assert_eq!(
            node,
            KeyNode {
                chain_key: c.chain_key,
                chain_code: c.chain_code
            },
            "masterKey({})",
            c.seed
        );
    }
    for c in from::<ChildKey>(&v, "childKey") {
        let parent = KeyNode {
            chain_key: c.parent.chain_key,
            chain_code: c.parent.chain_code,
        };
        let child = child_key_derivation_hardened(&parent, c.index, HARDENED_OFFSET);
        assert_eq!(
            child,
            KeyNode {
                chain_key: c.chain_key,
                chain_code: c.chain_code
            },
            "childKey idx={}",
            c.index
        );
    }
    for c in from::<SpendingKeyPairCase>(&v, "spendingKeyPair") {
        let kp = WalletNode::from_mnemonic(&c.mnemonic, "")
            .derive(&c.path)
            .get_spending_key_pair();
        assert_eq!(
            hex::encode(kp.private_key),
            c.private_key,
            "spending priv {}",
            c.path
        );
        assert_eq!(kp.pubkey, (dec(&c.x), dec(&c.y)), "spending pub {}", c.path);
    }
    for c in from::<ViewingKeyPairCase>(&v, "viewingKeyPair") {
        let kp = WalletNode::from_mnemonic(&c.mnemonic, "")
            .derive(&c.path)
            .get_viewing_key_pair();
        assert_eq!(
            hex::encode(kp.private_key),
            c.private_key,
            "viewing priv {}",
            c.path
        );
        assert_eq!(hex::encode(kp.pubkey), c.pubkey, "viewing pub {}", c.path);
    }
    for c in from::<NullifyingKey>(&v, "nullifyingKey") {
        let nk = WalletNode::from_mnemonic(&c.mnemonic, "")
            .derive(&c.path)
            .get_nullifying_key();
        assert_eq!(nk, dec(&c.out), "nullifyingKey {}", c.path);
    }
    for c in from::<Address>(&v, "address") {
        let chain = c.chain.as_ref().map(|ch| Chain {
            chain_type: ch.chain_type,
            id: ch.id.parse().unwrap(),
        });
        let data = AddressData {
            master_public_key: dec(&c.master_public_key),
            viewing_public_key: hex::decode(&c.viewing_public_key).unwrap(),
            chain,
            version: Some(1),
        };
        assert_eq!(encode_address(&data), c.encoded, "encodeAddress");
        assert_eq!(decode_address(&c.encoded).unwrap(), data, "decodeAddress");
    }
}
