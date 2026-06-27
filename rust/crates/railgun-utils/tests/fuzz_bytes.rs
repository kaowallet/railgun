//! Differential fuzz: replay the Bun/TS oracle corpus (rust/vectors/bytes.json)
//! and assert our ByteUtils port matches byte-for-byte. Regenerate the corpus with
//! `NODE_ENV=test bun run rust/oracle/gen.ts`.

use num_bigint::BigUint;
use railgun_utils::*;
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
fn byte_length(n: usize) -> ByteLength {
    match n {
        1 => ByteLength::Uint8,
        7 => ByteLength::Uint56,
        15 => ByteLength::Uint120,
        16 => ByteLength::Uint128,
        20 => ByteLength::Address,
        24 => ByteLength::Uint192,
        31 => ByteLength::Uint248,
        32 => ByteLength::Uint256,
        _ => unreachable!("unexpected byte length {n}"),
    }
}
fn side(s: &str) -> Side {
    match s {
        "left" => Side::Left,
        "right" => Side::Right,
        _ => unreachable!(),
    }
}

#[derive(Deserialize)]
struct HexlifyBytes {
    #[serde(rename = "in")]
    input: String,
    prefix: bool,
    out: String,
}
#[derive(Deserialize)]
struct HexlifyBig {
    #[serde(rename = "in")]
    input: String,
    prefix: bool,
    out: String,
}
#[derive(Deserialize)]
struct Arrayify {
    #[serde(rename = "in")]
    input: String,
    out: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NToHex {
    #[serde(rename = "in")]
    input: String,
    byte_length: usize,
    prefix: bool,
    out: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FormatToByteLength {
    #[serde(rename = "in")]
    input: String,
    byte_length: usize,
    prefix: bool,
    out: String,
}
#[derive(Deserialize)]
struct PadToLength {
    #[serde(rename = "in")]
    input: String,
    length: usize,
    side: String,
    out: String,
}
#[derive(Deserialize)]
struct Trim {
    #[serde(rename = "in")]
    input: String,
    length: usize,
    side: String,
    out: String,
}
#[derive(Deserialize)]
struct ChunkCombine {
    #[serde(rename = "in")]
    input: String,
    size: usize,
    chunks: Vec<String>,
    combined: String,
}
#[derive(Deserialize)]
struct HexToBig {
    #[serde(rename = "in")]
    input: String,
    out: String,
}
#[derive(Deserialize)]
struct Utf8 {
    str: String,
    hex: String,
}

#[test]
fn fuzz_bytes_against_ts_oracle() {
    let v = load("bytes.json");

    for c in from::<HexlifyBytes>(&v, "hexlifyBytes") {
        let bytes = hex::decode(&c.input).unwrap();
        assert_eq!(hexlify(&BytesData::Bytes(bytes), c.prefix), c.out, "hexlify(bytes {})", c.input);
    }
    for c in from::<HexlifyBig>(&v, "hexlifyBigint") {
        assert_eq!(hexlify(&BytesData::Big(dec(&c.input)), c.prefix), c.out, "hexlify(bigint {})", c.input);
    }
    for c in from::<Arrayify>(&v, "arrayify") {
        let out = arrayify(&BytesData::Hex(c.input.clone())).unwrap();
        assert_eq!(hex::encode(out), c.out, "arrayify({})", c.input);
    }
    for c in from::<NToHex>(&v, "nToHex") {
        assert_eq!(n_to_hex(&dec(&c.input), byte_length(c.byte_length), c.prefix), c.out, "nToHex({}, {})", c.input, c.byte_length);
    }
    for c in from::<FormatToByteLength>(&v, "formatToByteLength") {
        assert_eq!(format_to_byte_length(&BytesData::Hex(c.input.clone()), byte_length(c.byte_length), c.prefix), c.out, "formatToByteLength({})", c.input);
    }
    for c in from::<PadToLength>(&v, "padToLength") {
        let Padded::Hex(out) = pad_to_length(&BytesData::Hex(c.input.clone()), c.length, side(&c.side)) else {
            panic!("expected hex padding");
        };
        assert_eq!(out, c.out, "padToLength({}, {}, {})", c.input, c.length, c.side);
    }
    for c in from::<Trim>(&v, "trim") {
        let Trimmed::Hex(out) = trim(&BytesData::Hex(c.input.clone()), c.length, side(&c.side)) else {
            panic!("expected hex trim");
        };
        assert_eq!(out, c.out, "trim({}, {}, {})", c.input, c.length, c.side);
    }
    for c in from::<ChunkCombine>(&v, "chunkCombine") {
        assert_eq!(chunk(&BytesData::Hex(c.input.clone()), c.size), c.chunks, "chunk({}, {})", c.input, c.size);
        assert_eq!(combine(&c.chunks), c.combined, "combine");
    }
    for c in from::<HexToBig>(&v, "hexToBigint") {
        assert_eq!(hex_to_bigint(&c.input), dec(&c.out), "hexToBigInt({})", c.input);
    }
    for c in from::<HexToBig>(&v, "bytesToN") {
        let bytes = hex::decode(&c.input).unwrap();
        assert_eq!(bytes_to_n(&bytes), dec(&c.out), "bytesToN({})", c.input);
    }
    for c in from::<Utf8>(&v, "utf8") {
        assert_eq!(to_utf8_string(&c.hex).unwrap(), c.str, "toUTF8String");
        assert_eq!(from_utf8_string(&c.str).unwrap(), c.hex, "fromUTF8String");
    }
}
