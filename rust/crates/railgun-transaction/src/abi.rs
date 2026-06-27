//! Minimal Solidity ABI (head/tail) encoder, sufficient to reproduce
//! `ethers.AbiCoder.defaultAbiCoder().encode(...)` for the exact bound-params
//! tuples used by [`crate::bound_params`].
//!
//! This is NOT a general ABI coder — it supports only the value kinds those two
//! tuples need:
//!   - static words: `uintN`/`address`/`bytesN` (all encoded as one 32-byte word)
//!   - dynamic `bytes`
//!   - dynamic arrays of (possibly dynamic) tuples
//!   - tuples (static or dynamic), nested
//!
//! Encoding follows the Solidity ABI spec: a tuple/array is "dynamic" if any
//! element is dynamic; dynamic elements are laid out as a head of 32-byte offsets
//! (relative to the start of the encoded block) followed by the tails.

use num_bigint::BigUint;
use railgun_utils::{n_to_bytes, ByteLength};

/// A single ABI value.
#[derive(Clone, Debug)]
pub enum AbiValue {
    /// A static value occupying exactly one 32-byte word (uintN, address, bytesN).
    Word([u8; 32]),
    /// Dynamic `bytes`.
    Bytes(Vec<u8>),
    /// A tuple of values (encoded inline if all-static, else dynamic).
    Tuple(Vec<AbiValue>),
    /// A dynamic-length array of values.
    Array(Vec<AbiValue>),
}

impl AbiValue {
    /// uintN / address — left-padded big-endian to 32 bytes.
    pub fn uint(n: &BigUint) -> Self {
        let mut word = [0u8; 32];
        let be = n_to_bytes(n, ByteLength::Uint256);
        word.copy_from_slice(&be);
        AbiValue::Word(word)
    }

    /// bytes32 — `bytes` already exactly 32 bytes long, encoded as one word
    /// (right-padded; for our inputs they are full 32-byte values).
    pub fn bytes32(bytes: &[u8]) -> Self {
        let mut word = [0u8; 32];
        // Solidity bytesN is left-aligned (right-padded). Our values are 32 bytes.
        let len = bytes.len().min(32);
        word[..len].copy_from_slice(&bytes[..len]);
        AbiValue::Word(word)
    }

    /// address — 20 bytes, encoded as a uint160 (left-padded to 32).
    pub fn address(bytes: &[u8]) -> Self {
        let mut word = [0u8; 32];
        let len = bytes.len().min(20);
        // right-align into the low 20 bytes
        word[32 - len..].copy_from_slice(&bytes[bytes.len() - len..]);
        AbiValue::Word(word)
    }

    /// Whether this value is dynamic per the ABI spec.
    fn is_dynamic(&self) -> bool {
        match self {
            AbiValue::Word(_) => false,
            AbiValue::Bytes(_) => true,
            AbiValue::Array(_) => true,
            AbiValue::Tuple(items) => items.iter().any(|v| v.is_dynamic()),
        }
    }

    /// Encode this value's "tail" (its full encoding when treated as a top-level
    /// or dynamic-tail element).
    fn encode(&self) -> Vec<u8> {
        match self {
            AbiValue::Word(w) => w.to_vec(),
            AbiValue::Bytes(b) => encode_bytes(b),
            AbiValue::Tuple(items) => encode_sequence(items),
            AbiValue::Array(items) => {
                let mut out = Vec::new();
                // length prefix
                out.extend_from_slice(&AbiValue::uint(&BigUint::from(items.len())).encode());
                out.extend_from_slice(&encode_sequence(items));
                out
            }
        }
    }
}

/// Encode dynamic `bytes`: 32-byte length, then right-padded data.
fn encode_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&AbiValue::uint(&BigUint::from(b.len())).encode());
    out.extend_from_slice(b);
    let rem = b.len() % 32;
    if rem != 0 {
        out.extend(std::iter::repeat(0u8).take(32 - rem));
    }
    out
}

/// Encode a sequence of values (the elements of a tuple, or of an array) using
/// the Solidity head/tail layout.
fn encode_sequence(items: &[AbiValue]) -> Vec<u8> {
    // Head size: each item contributes one 32-byte slot in the head (dynamic
    // items contribute an offset word; static items contribute their inline
    // encoding, which for our supported kinds is exactly one word — except
    // static tuples, which contribute their full inline encoding).
    let head_size: usize = items.iter().map(head_word_count).sum::<usize>() * 32;

    let mut head: Vec<u8> = Vec::new();
    let mut tail: Vec<u8> = Vec::new();

    for item in items {
        if item.is_dynamic() {
            let offset = head_size + tail.len();
            head.extend_from_slice(&AbiValue::uint(&BigUint::from(offset)).encode());
            tail.extend_from_slice(&item.encode());
        } else {
            // static: inline in the head
            head.extend_from_slice(&item.encode());
        }
    }

    let mut out = head;
    out.extend_from_slice(&tail);
    out
}

/// Number of 32-byte head words a value occupies inline when static, or 1 (the
/// offset word) when dynamic.
fn head_word_count(v: &AbiValue) -> usize {
    if v.is_dynamic() {
        return 1;
    }
    match v {
        AbiValue::Word(_) => 1,
        AbiValue::Tuple(items) => items.iter().map(head_word_count).sum(),
        // static arrays/bytes don't occur in our inputs
        _ => 1,
    }
}

/// Encode a list of top-level parameters (as `abiCoder.encode(types, values)`).
/// ethers wraps the parameter list in an implicit tuple, so this is exactly
/// `encode_sequence`.
pub fn encode(values: &[AbiValue]) -> Vec<u8> {
    encode_sequence(values)
}
