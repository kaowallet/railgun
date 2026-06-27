//! `railgun-utils` — byte/hex/bigint primitives ported from `src/utils/`.
//!
//! This is the dependency-free floor of the RAILGUN Rust port. Everything here
//! is validated byte-for-byte against the TypeScript test vectors.

pub mod bigint;
pub mod bytes;

pub use bigint::{min_big_int, string_to_bigint};
pub use bytes::{
    arrayify, bytes_to_n, chunk, combine, fast_bytes_to_hex, fast_hex_to_bytes,
    format_to_byte_length, from_utf8_string, hex_string_to_bytes, hex_to_bigint, hexlify, n_to_bytes,
    n_to_hex, pad_to_length, prefix_0x, random_hex, strip_0x, to_utf8_string, trim, u8_to_bigint,
    ByteLength, BytesData, BytesError, Padded, Side, Trimmed,
};

/// `0x` followed by 64 zeros — the engine's `HashZero`.
pub fn hash_zero() -> String {
    format_to_byte_length(&BytesData::Hex("00".into()), ByteLength::Uint256, true)
}
