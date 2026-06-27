//! Faithful port of `src/utils/bytes.ts` (`ByteUtils`).
//!
//! RAILGUN's TS code treats "bytes data" polymorphically (`string | bigint |
//! number | ArrayLike<number>`). We model that with [`BytesData`] so the exact
//! coercion semantics — which downstream commitment/address encoding depends on
//! byte-for-byte — are preserved. Idiomatic typed helpers are layered on top.

use num_bigint::BigUint;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BytesError {
    #[error("Invalid BytesData")]
    InvalidBytesData,
    #[error("bigint must be positive")]
    NegativeBigInt,
    #[error("Invalid Unicode codepoint > 0xD800")]
    InvalidUnicode,
    #[error("invalid hex")]
    InvalidHex,
}

/// Mirror of the TS `BytesData` union.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BytesData {
    Hex(String),
    Big(BigUint),
    Num(u64),
    Bytes(Vec<u8>),
}

impl From<&str> for BytesData {
    fn from(s: &str) -> Self {
        BytesData::Hex(s.to_string())
    }
}
impl From<String> for BytesData {
    fn from(s: String) -> Self {
        BytesData::Hex(s)
    }
}
impl From<u64> for BytesData {
    fn from(n: u64) -> Self {
        BytesData::Num(n)
    }
}
impl From<BigUint> for BytesData {
    fn from(n: BigUint) -> Self {
        BytesData::Big(n)
    }
}
impl From<Vec<u8>> for BytesData {
    fn from(v: Vec<u8>) -> Self {
        BytesData::Bytes(v)
    }
}
impl From<&[u8]> for BytesData {
    fn from(v: &[u8]) -> Self {
        BytesData::Bytes(v.to_vec())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

/// Result of `pad_to_length` / `trim`: TS returns `string | number[]` (or a
/// bigint for trim), so the variant tracks the input flavour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Padded {
    Hex(String),
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trimmed {
    Hex(String),
    Big(BigUint),
    Bytes(Vec<u8>),
}

/// Byte counts used throughout the engine (matches the TS `ByteLength` enum).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum ByteLength {
    Uint8 = 1,
    Uint56 = 7,
    Uint120 = 15,
    Uint128 = 16,
    Address = 20,
    Uint192 = 24,
    Uint248 = 31,
    Uint256 = 32,
}

impl ByteLength {
    #[inline]
    pub const fn bytes(self) -> usize {
        self as usize
    }
}

#[inline]
pub fn is_prefixed(s: &str) -> bool {
    s.starts_with("0x")
}

#[inline]
pub fn prefix_0x(s: &str) -> String {
    if is_prefixed(s) {
        s.to_string()
    } else {
        format!("0x{s}")
    }
}

#[inline]
pub fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn pad_start(s: &str, width: usize, fill: char) -> String {
    if s.chars().count() >= width {
        s.to_string()
    } else {
        let pad = width - s.chars().count();
        format!("{}{}", fill.to_string().repeat(pad), s)
    }
}

fn pad_end(s: &str, width: usize, fill: char) -> String {
    if s.chars().count() >= width {
        s.to_string()
    } else {
        let pad = width - s.chars().count();
        format!("{}{}", s, fill.to_string().repeat(pad))
    }
}

/// `ByteUtils.hexlify` — coerce bytes data into a (optionally 0x-prefixed) hex string.
pub fn hexlify(data: &BytesData, prefix: bool) -> String {
    let hex_string = match data {
        BytesData::Hex(s) => strip_0x(s).to_string(),
        BytesData::Big(b) => {
            let mut h = format!("{b:x}");
            if h.len() % 2 == 1 {
                h = format!("0{h}");
            }
            h
        }
        BytesData::Num(n) => {
            let mut h = format!("{n:x}");
            if h.len() % 2 == 1 {
                h = format!("0{h}");
            }
            h
        }
        BytesData::Bytes(v) => v.iter().map(|b| format!("{b:02x}")).collect(),
    };
    let lower = hex_string.to_lowercase();
    if prefix {
        format!("0x{lower}")
    } else {
        lower
    }
}

/// `ByteUtils.arrayify` — coerce bytes data into a byte array.
pub fn arrayify(data: &BytesData) -> Result<Vec<u8>, BytesError> {
    if let BytesData::Bytes(v) = data {
        return Ok(v.clone());
    }
    let formatted = match data {
        BytesData::Big(_) | BytesData::Num(_) => hexlify(data, false),
        BytesData::Hex(s) => strip_0x(s).to_string(),
        BytesData::Bytes(_) => unreachable!(),
    };
    let chars: Vec<char> = formatted.chars().collect();
    let mut out = Vec::with_capacity(chars.len().div_ceil(2));
    let mut i = 0;
    while i < chars.len() {
        let end = (i + 2).min(chars.len());
        let chunk: String = chars[i..end].iter().collect();
        let byte = u8::from_str_radix(&chunk, 16).map_err(|_| BytesError::InvalidBytesData)?;
        out.push(byte);
        i += 2;
    }
    Ok(out)
}

/// `ByteUtils.padToLength`.
pub fn pad_to_length(data: &BytesData, length: usize, side: Side) -> Padded {
    match data {
        BytesData::Big(_) | BytesData::Num(_) => {
            let hex = match data {
                BytesData::Big(b) => format!("{b:x}"),
                BytesData::Num(n) => format!("{n:x}"),
                _ => unreachable!(),
            };
            let padded = match side {
                Side::Left => pad_start(&hex, length * 2, '0'),
                Side::Right => pad_end(&hex, length * 2, '0'),
            };
            Padded::Hex(padded)
        }
        BytesData::Hex(s) => {
            let stripped = strip_0x(s);
            let padded = match side {
                Side::Left => pad_start(stripped, length * 2, '0'),
                Side::Right => pad_end(stripped, length * 2, '0'),
            };
            if is_prefixed(s) {
                Padded::Hex(format!("0x{padded}"))
            } else {
                Padded::Hex(padded)
            }
        }
        BytesData::Bytes(v) => {
            let mut arr = v.clone();
            match side {
                Side::Left => {
                    while arr.len() < length {
                        arr.insert(0, 0);
                    }
                }
                Side::Right => {
                    while arr.len() < length {
                        arr.push(0);
                    }
                }
            }
            Padded::Bytes(arr)
        }
    }
}

/// `ByteUtils.chunk` — split hex into chunks of `size` bytes.
pub fn chunk(data: &BytesData, size: usize) -> Vec<String> {
    let formatted = hexlify(data, false);
    if formatted.is_empty() {
        return vec![];
    }
    let chars: Vec<char> = formatted.chars().collect();
    let width = size * 2;
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let end = (i + width).min(chars.len());
        out.push(chars[i..end].iter().collect());
        i += width;
    }
    out
}

/// `ByteUtils.combine`.
pub fn combine(data: &[String]) -> String {
    data.iter()
        .map(|s| hexlify(&BytesData::Hex(s.clone()), false))
        .collect()
}

/// `ByteUtils.trim`.
pub fn trim(data: &BytesData, length: usize, side: Side) -> Trimmed {
    match data {
        BytesData::Big(_) | BytesData::Num(_) => {
            let string_data = match data {
                BytesData::Big(b) => format!("{b:x}"),
                BytesData::Num(n) => format!("{n:x}"),
                _ => unreachable!(),
            };
            let Trimmed::Hex(trimmed) = trim(&BytesData::Hex(string_data), length, side) else {
                unreachable!()
            };
            Trimmed::Big(BigUint::parse_bytes(trimmed.as_bytes(), 16).unwrap_or_default())
        }
        BytesData::Hex(s) => {
            let stripped = strip_0x(s);
            let n = stripped.len();
            let trimmed = match side {
                Side::Left => &stripped[n.saturating_sub(length * 2)..],
                Side::Right => &stripped[..(length * 2).min(n)],
            };
            if is_prefixed(s) {
                Trimmed::Hex(format!("0x{trimmed}"))
            } else {
                Trimmed::Hex(trimmed.to_string())
            }
        }
        BytesData::Bytes(v) => {
            let trimmed = match side {
                Side::Left => v[v.len().saturating_sub(length)..].to_vec(),
                Side::Right => v[..length.min(v.len())].to_vec(),
            };
            Trimmed::Bytes(trimmed)
        }
    }
}

/// `ByteUtils.formatToByteLength`.
pub fn format_to_byte_length(data: &BytesData, length: ByteLength, prefix: bool) -> String {
    let len = length.bytes();
    let hex = hexlify(data, prefix);
    let Padded::Hex(padded) = pad_to_length(&BytesData::Hex(hex), len, Side::Left) else {
        unreachable!()
    };
    let Trimmed::Hex(trimmed) = trim(&BytesData::Hex(padded), len, Side::Left) else {
        unreachable!()
    };
    trimmed
}

/// `ByteUtils.nToHex` — bigint to fixed-length hex.
pub fn n_to_hex(n: &BigUint, byte_length: ByteLength, prefix: bool) -> String {
    let hex = format_to_byte_length(&BytesData::Hex(format!("{n:x}")), byte_length, prefix);
    if prefix {
        prefix_0x(&hex)
    } else {
        hex
    }
}

/// `ByteUtils.nToBytes`.
pub fn n_to_bytes(n: &BigUint, byte_length: ByteLength) -> Vec<u8> {
    let hex = n_to_hex(n, byte_length, false);
    hex::decode(hex).expect("n_to_hex produces valid even hex")
}

/// `ByteUtils.bytesToN`.
pub fn bytes_to_n(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// `ByteUtils.hexToBigInt`.
pub fn hex_to_bigint(s: &str) -> BigUint {
    BigUint::parse_bytes(strip_0x(s).as_bytes(), 16).unwrap_or_default()
}

/// `ByteUtils.u8ToBigInt`.
pub fn u8_to_bigint(u8: &[u8]) -> BigUint {
    BigUint::from_bytes_be(u8)
}

/// `ByteUtils.hexStringToBytes` — strip optional 0x then decode.
pub fn hex_string_to_bytes(s: &str) -> Result<Vec<u8>, BytesError> {
    hex::decode(strip_0x(s)).map_err(|_| BytesError::InvalidHex)
}

/// `ByteUtils.fastHexToBytes` — assumes even, unprefixed.
pub fn fast_hex_to_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).expect("fast_hex_to_bytes requires valid even hex")
}

/// `ByteUtils.fastBytesToHex`.
pub fn fast_bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// `ByteUtils.randomHex`.
pub fn random_hex(length: usize) -> String {
    let mut buf = vec![0u8; length];
    getrandom::getrandom(&mut buf).expect("OS RNG available");
    hex::encode(buf)
}

fn assert_bytes_within_range(s: &str) -> Result<(), BytesError> {
    // JS checks each UTF-16 code unit > 0xD800. A Rust `char`'s scalar value is
    // equivalent for this test: any unit/codepoint above 0xD800 (incl. anything
    // >= 0x10000, which JS sees as surrogates) trips the guard.
    if s.chars().any(|c| (c as u32) > 0xD800) {
        return Err(BytesError::InvalidUnicode);
    }
    Ok(())
}

/// `toUTF8String` — hex bytes to validated UTF-8 string.
pub fn to_utf8_string(hex_data: &str) -> Result<String, BytesError> {
    let bytes = fast_hex_to_bytes(hex_data);
    let s = String::from_utf8(bytes).map_err(|_| BytesError::InvalidUnicode)?;
    assert_bytes_within_range(&s)?;
    Ok(s)
}

/// `fromUTF8String` — validated UTF-8 string to hex.
pub fn from_utf8_string(s: &str) -> Result<String, BytesError> {
    assert_bytes_within_range(s)?;
    Ok(hexlify(&BytesData::Bytes(s.as_bytes().to_vec()), false))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big(hex: &str) -> BigUint {
        BigUint::parse_bytes(strip_0x(hex).as_bytes(), 16).unwrap()
    }
    fn big10(dec: &str) -> BigUint {
        BigUint::parse_bytes(dec.as_bytes(), 10).unwrap()
    }

    // Ported from src/utils/__tests__/bytes.test.ts
    struct ConvertVector {
        hex: &'static str,
        array: Vec<u8>,
        number: BigUint,
    }
    fn convert_vectors() -> Vec<ConvertVector> {
        vec![
            ConvertVector {
                hex: "0138bc",
                array: vec![1, 56, 188],
                number: big10("80060"),
            },
            ConvertVector {
                hex: "5241494c47554e",
                array: vec![82, 65, 73, 76, 71, 85, 78],
                number: big10("23152731158435150"),
            },
            ConvertVector {
                hex: "50524956414359202620414e4f4e594d495459",
                array: vec![
                    80, 82, 73, 86, 65, 67, 89, 32, 38, 32, 65, 78, 79, 78, 89, 77, 73, 84, 89,
                ],
                number: big10("1791227778594112336062762560780788585783186521"),
            },
        ]
    }

    #[test]
    fn should_return_random_values() {
        assert_eq!(random_hex(32).len(), 64);
        assert_eq!(random_hex(1).len(), 2);
        assert_eq!(random_hex(128).len(), 256);
    }

    #[test]
    fn should_hexlify() {
        for v in convert_vectors() {
            assert_eq!(hexlify(&format!("0x{}", v.hex).into(), false), v.hex);
            assert_eq!(hexlify(&v.hex.into(), false), v.hex);
            assert_eq!(hexlify(&v.hex.into(), true), format!("0x{}", v.hex));
            assert_eq!(hexlify(&BytesData::Bytes(v.array.clone()), false), v.hex);
            assert_eq!(
                hexlify(&BytesData::Bytes(v.array.clone()), true),
                format!("0x{}", v.hex)
            );
            assert_eq!(hexlify(&BytesData::Big(v.number.clone()), false), v.hex);
            assert_eq!(
                hexlify(&BytesData::Big(v.number.clone()), true),
                format!("0x{}", v.hex)
            );
        }
        assert_eq!(hexlify(&123u64.into(), false), "7b");
        assert_eq!(hexlify(&BytesData::Big(big10("123")), false), "7b");
        assert_eq!(hexlify(&1234u64.into(), false), "04d2");
        assert_eq!(hexlify(&BytesData::Big(big10("1234")), false), "04d2");
    }

    #[test]
    fn should_arrayify() {
        for v in convert_vectors() {
            assert_eq!(arrayify(&format!("0x{}", v.hex).into()).unwrap(), v.array);
            assert_eq!(arrayify(&v.hex.into()).unwrap(), v.array);
            assert_eq!(
                arrayify(&BytesData::Bytes(v.array.clone())).unwrap(),
                v.array
            );
            assert_eq!(
                arrayify(&BytesData::Big(v.number.clone())).unwrap(),
                v.array
            );
        }
    }

    #[test]
    fn should_not_arrayify_invalid() {
        assert_eq!(
            arrayify(&"zzzzza".into()),
            Err(BytesError::InvalidBytesData)
        );
    }

    #[test]
    fn should_pad_to_length() {
        // string / bigint inputs -> Hex; array inputs -> Bytes
        let p = |d: BytesData, l: usize, s: Side| pad_to_length(&d, l, s);
        // '4bd21a92a4c6e9f10164fe40'
        let s = "4bd21a92a4c6e9f10164fe40";
        assert_eq!(
            p(s.into(), 16, Side::Left),
            Padded::Hex("000000004bd21a92a4c6e9f10164fe40".into())
        );
        assert_eq!(
            p(s.into(), 32, Side::Left),
            Padded::Hex("00000000000000000000000000000000000000004bd21a92a4c6e9f10164fe40".into())
        );
        assert_eq!(
            p(s.into(), 16, Side::Right),
            Padded::Hex("4bd21a92a4c6e9f10164fe4000000000".into())
        );

        // array
        let arr = BytesData::Bytes(vec![32, 12, 18, 245]);
        assert_eq!(
            p(arr.clone(), 16, Side::Left),
            Padded::Bytes(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 12, 18, 245])
        );
        assert_eq!(
            p(arr.clone(), 16, Side::Right),
            Padded::Bytes(vec![32, 12, 18, 245, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );

        // bigint 16-byte value
        let n = BytesData::Big(big("0xf6fc84c9f21c24907d6bee6eec38caba"));
        assert_eq!(
            p(n.clone(), 16, Side::Left),
            Padded::Hex("f6fc84c9f21c24907d6bee6eec38caba".into())
        );
        assert_eq!(
            p(n.clone(), 32, Side::Left),
            Padded::Hex("00000000000000000000000000000000f6fc84c9f21c24907d6bee6eec38caba".into())
        );

        // prefixed string keeps 0x
        assert_eq!(
            p("0x00".into(), 4, Side::Left),
            Padded::Hex("0x00000000".into())
        );
    }

    #[test]
    fn should_trim_bytes() {
        assert_eq!(
            trim(&BytesData::Big(big10("861")), 1, Side::Left),
            Trimmed::Big(big10("93"))
        );
        assert_eq!(
            trim(&"17b3c8d9".into(), 2, Side::Left),
            Trimmed::Hex("c8d9".into())
        );
        assert_eq!(
            trim(&"17b3c8d9".into(), 2, Side::Right),
            Trimmed::Hex("17b3".into())
        );
        assert_eq!(
            trim(&"0x17b3c8d9".into(), 2, Side::Left),
            Trimmed::Hex("0xc8d9".into())
        );
        assert_eq!(
            trim(&"0x17b3c8d9".into(), 2, Side::Right),
            Trimmed::Hex("0x17b3".into())
        );
        assert_eq!(
            trim(&BytesData::Bytes(vec![12, 4, 250]), 2, Side::Left),
            Trimmed::Bytes(vec![4, 250])
        );
        assert_eq!(
            trim(&BytesData::Bytes(vec![12, 4, 250]), 2, Side::Right),
            Trimmed::Bytes(vec![12, 4])
        );
    }

    #[test]
    fn should_format_to_byte_length() {
        assert_eq!(
            format_to_byte_length(&"17b3c8d9".into(), ByteLength::Uint8, true),
            "0xd9"
        );
        assert_eq!(
            format_to_byte_length(&"17b3c8d9".into(), ByteLength::Address, true),
            "0x0000000000000000000000000000000017b3c8d9"
        );
        assert_eq!(
            format_to_byte_length(&"17b3c8d9".into(), ByteLength::Uint256, false),
            "0000000000000000000000000000000000000000000000000000000017b3c8d9"
        );
    }

    #[test]
    fn should_chunk_and_combine() {
        assert_eq!(chunk(&"5d0afa".into(), 32), vec!["5d0afa".to_string()]);
        let bytes = "5d0afac6783502d701ebd089be93f497bd46ea52b0fb2a4304a952572899aadb032b6a5bae56a1423ffb6bfeb3416b01748a6bbffc5ae430c572b00953dca448";
        let c32 = chunk(&bytes.into(), 32);
        assert_eq!(
            c32,
            vec![
                "5d0afac6783502d701ebd089be93f497bd46ea52b0fb2a4304a952572899aadb".to_string(),
                "032b6a5bae56a1423ffb6bfeb3416b01748a6bbffc5ae430c572b00953dca448".to_string(),
            ]
        );
        assert_eq!(combine(&c32), bytes);
        assert_eq!(chunk(&"".into(), 32), Vec::<String>::new());
        let c25 = chunk(&bytes.into(), 25);
        assert_eq!(
            c25,
            vec![
                "5d0afac6783502d701ebd089be93f497bd46ea52b0fb2a4304".to_string(),
                "a952572899aadb032b6a5bae56a1423ffb6bfeb3416b01748a".to_string(),
                "6bbffc5ae430c572b00953dca448".to_string(),
            ]
        );
        assert_eq!(combine(&c25), bytes);
    }

    #[test]
    fn should_convert_utf8() {
        assert_eq!(to_utf8_string("").unwrap(), "");
        assert_eq!(from_utf8_string("").unwrap(), "");
        assert_eq!(to_utf8_string("5261696c67756e").unwrap(), "Railgun");
        assert_eq!(from_utf8_string("Railgun").unwrap(), "5261696c67756e");

        // Brute-force codepoints 0..=0x800 (the safe range the TS test exercises).
        let mut test_string = String::new();
        for cp in 0u32..=0x0800 {
            if let Some(c) = char::from_u32(cp) {
                test_string.push(c);
            }
        }
        let full_bytes = hex::encode(test_string.as_bytes());
        assert_eq!(to_utf8_string(&full_bytes).unwrap(), test_string);
        assert_eq!(from_utf8_string(&test_string).unwrap(), full_bytes);
    }

    #[test]
    fn should_throw_on_invalid_utf8() {
        // 'PͶ𐀀Railgun' contains U+10000 (> 0xD800) => invalid
        assert_eq!(
            from_utf8_string("PͶ𐀀Railgun"),
            Err(BytesError::InvalidUnicode)
        );
        assert_eq!(
            to_utf8_string("50cdb6f09080805261696c67756e"),
            Err(BytesError::InvalidUnicode)
        );
    }
}
