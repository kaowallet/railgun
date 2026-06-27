//! Differential fuzz against the Bun/TS oracle (rust/vectors/crypto.json):
//! hashes, Poseidon, BabyJubJub spending keys, Ed25519 viewing keys, the private
//! scalar, and X25519 ECDH (incl. invalid-point => None parity).

use num_bigint::BigUint;
use railgun_crypto::*;
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
#[derive(Deserialize)]
struct AesGcmCase {
    key: String,
    plaintext: String,
    ct: Ciphertext,
}
#[derive(Deserialize)]
struct AesCtrCase {
    key: String,
    plaintext: String,
    ct: CiphertextCtr,
}
#[derive(Deserialize)]
struct XChaChaCase {
    key: String,
    plaintext: String,
    ct: CiphertextXChaCha,
}
#[derive(Deserialize)]
struct EddsaCase {
    #[serde(rename = "priv")]
    priv_key: String,
    msg: String,
    r8x: String,
    r8y: String,
    s: String,
    #[serde(rename = "pubX")]
    pub_x: String,
    #[serde(rename = "pubY")]
    pub_y: String,
    verified: bool,
}
#[derive(Deserialize)]
struct BlindingKeysCase {
    #[serde(rename = "senderPub")]
    sender_pub: String,
    #[serde(rename = "receiverPub")]
    receiver_pub: String,
    #[serde(rename = "sharedRandom")]
    shared_random: String,
    #[serde(rename = "senderRandom")]
    sender_random: String,
    #[serde(rename = "blindedSender")]
    blinded_sender: String,
    #[serde(rename = "blindedReceiver")]
    blinded_receiver: String,
}
#[derive(Deserialize)]
struct EciesCase {
    key: String,
    json: serde_json::Value,
    encrypted: EncryptedData,
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
        assert_eq!(
            keccak256(&hex::decode(&c.input).unwrap()),
            c.out,
            "keccak256"
        );
    }
    for c in from::<Hmac>(&v, "sha512Hmac") {
        assert_eq!(
            sha512_hmac(
                &hex::decode(&c.key).unwrap(),
                &hex::decode(&c.data).unwrap()
            ),
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
    // Wide Poseidon (7..13 inputs) — the > 12-input path (poseidon-ark in Rust).
    for c in from::<Poseidon>(&v, "poseidonWide") {
        let inputs: Vec<BigUint> = c.input.iter().map(|s| dec(s)).collect();
        assert_eq!(
            poseidon(&inputs),
            dec(&c.out),
            "poseidonWide({} inputs)",
            c.input.len()
        );
    }
    // AES-256-GCM / -CTR: TS-encrypted bundle must decrypt to the original plaintext.
    for c in from::<AesGcmCase>(&v, "aesGcm") {
        let key = hex::decode(&c.key).unwrap();
        let pt = decrypt_gcm(&c.ct, &key).expect("gcm decrypt");
        assert_eq!(railgun_utils::combine(&pt), c.plaintext, "aesGcm");
    }
    for c in from::<AesCtrCase>(&v, "aesCtr") {
        let key = hex::decode(&c.key).unwrap();
        let pt = decrypt_ctr(&c.ct, &key).expect("ctr decrypt");
        assert_eq!(railgun_utils::combine(&pt), c.plaintext, "aesCtr");
    }
    // XChaCha20-Poly1305: TS-encrypted bundle must decrypt to the original plaintext.
    for c in from::<XChaChaCase>(&v, "xchacha") {
        let key = hex::decode(&c.key).unwrap();
        assert_eq!(
            decrypt_cha_cha_20_poly1305(&c.ct, &key).expect("xchacha decrypt"),
            c.plaintext,
            "xchacha"
        );
    }
    for c in from::<SpendingKey>(&v, "spendingKey") {
        assert_eq!(
            get_public_spending_key(&b32(&c.input)),
            (dec(&c.x), dec(&c.y)),
            "spendingKey({})",
            c.input
        );
    }
    for c in from::<ViewingKey>(&v, "viewingKey") {
        assert_eq!(
            hex::encode(get_public_viewing_key(&b32(&c.input))),
            c.out,
            "viewingKey({})",
            c.input
        );
    }
    for c in from::<Scalar>(&v, "privateScalar") {
        assert_eq!(
            get_private_scalar_from_private_key(&b32(&c.input)),
            dec(&c.out),
            "privateScalar({})",
            c.input
        );
    }
    for c in from::<SharedKey>(&v, "sharedKey") {
        let got = get_shared_symmetric_key(&b32(&c.priv_a), &b32(&c.pub_b)).map(hex::encode);
        assert_eq!(got, c.out, "sharedKey({}, {})", c.priv_a, c.pub_b);
    }
    // BabyJubJub Poseidon-EdDSA: signature is deterministic (must match byte-for-byte),
    // verify must accept the real signature and reject a tampered one.
    for c in from::<EddsaCase>(&v, "eddsa") {
        assert!(c.verified, "oracle says verifyEDDSA failed — bad vector");
        let priv32 = b32(&c.priv_key);
        let msg = dec(&c.msg);
        let pubkey = (dec(&c.pub_x), dec(&c.pub_y));
        assert_eq!(
            get_public_spending_key(&priv32),
            pubkey,
            "eddsa pubkey({})",
            c.priv_key
        );
        let sig = sign_eddsa(&priv32, &msg);
        assert_eq!(
            (sig.r8.0, sig.r8.1, sig.s),
            (dec(&c.r8x), dec(&c.r8y), dec(&c.s)),
            "signEDDSA({})",
            c.priv_key
        );
        let parsed = Signature {
            r8: (dec(&c.r8x), dec(&c.r8y)),
            s: dec(&c.s),
        };
        assert!(
            verify_eddsa(&msg, &parsed, &pubkey),
            "verifyEDDSA accept({})",
            c.priv_key
        );
        let tampered = Signature {
            r8: parsed.r8.clone(),
            s: parsed.s.clone() + 1u32,
        };
        assert!(
            !verify_eddsa(&msg, &tampered, &pubkey),
            "verifyEDDSA reject tampered({})",
            c.priv_key
        );
    }
    // Note blinding keys (X25519): blinded keys match TS, and unblinding recovers the originals.
    for c in from::<BlindingKeysCase>(&v, "blindingKeys") {
        let (bs, br) = get_note_blinding_keys(
            &b32(&c.sender_pub),
            &b32(&c.receiver_pub),
            &c.shared_random,
            &c.sender_random,
        )
        .expect("blinding keys");
        assert_eq!(hex::encode(bs), c.blinded_sender, "blindedSender");
        assert_eq!(hex::encode(br), c.blinded_receiver, "blindedReceiver");
        let us = unblind_note_key(&bs, &c.shared_random, &c.sender_random).expect("unblind sender");
        let ur =
            unblind_note_key(&br, &c.shared_random, &c.sender_random).expect("unblind receiver");
        assert_eq!(
            hex::encode(us),
            c.sender_pub,
            "unblind sender recovers original"
        );
        assert_eq!(
            hex::encode(ur),
            c.receiver_pub,
            "unblind receiver recovers original"
        );
    }
    // ECIES: TS-encrypted JSON must decrypt back to the identical object; wrong key => None.
    for c in from::<EciesCase>(&v, "ecies") {
        let key = hex::decode(&c.key).unwrap();
        let got = try_decrypt_json_data_with_shared_key(&c.encrypted, &key).expect("ecies decrypt");
        assert_eq!(got, c.json, "ecies decrypt matches original object");
        let mut bad = key.clone();
        bad[0] ^= 0xff;
        assert!(
            try_decrypt_json_data_with_shared_key(&c.encrypted, &bad).is_none(),
            "ecies wrong key => None"
        );
    }
}
