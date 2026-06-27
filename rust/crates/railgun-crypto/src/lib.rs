//! `railgun-crypto` — cryptographic primitives for the RAILGUN engine.
//!
//! Every primitive delegates to an existing, audited crate. Nothing here
//! re-implements a cipher, curve, or hash from scratch; the work is in matching
//! circomlibjs / RAILGUN byte conventions exactly (verified against TS vectors).

pub mod babyjubjub;
pub mod curve25519;
pub mod ed25519;
pub mod encryption;
pub mod hash;
pub mod poseidon;

pub use babyjubjub::get_public_spending_key;
pub use encryption::{
    decrypt_ctr, decrypt_gcm, encrypt_ctr, encrypt_gcm, Ciphertext, CiphertextCtr, EncryptionError,
};
pub use curve25519::{
    get_private_scalar_from_private_key, get_shared_symmetric_key, scalar_multiply,
};
pub use ed25519::{get_public_viewing_key, sign_ed25519, verify_ed25519};
pub use hash::{
    keccak256, keccak256_bytes, sha256, sha256_bytes, sha512, sha512_bytes, sha512_hmac,
    sha512_hmac_bytes,
};
pub use poseidon::{poseidon, poseidon_hex};
