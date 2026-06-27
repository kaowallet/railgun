//! Port of the Ed25519 (viewing-key) helpers in `src/utils/keys-utils.ts`.
//!
//! `@noble/ed25519` implements RFC 8032; `ed25519-dalek` does too, so public
//! keys and signatures are byte-identical.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

#[derive(Debug, thiserror::Error)]
pub enum Ed25519Error {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature length")]
    InvalidSignature,
}

/// `getPublicViewingKey` — 32-byte Ed25519 public key from a 32-byte secret.
pub fn get_public_viewing_key(private_key: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(private_key)
        .verifying_key()
        .to_bytes()
}

/// `signED25519`.
pub fn sign_ed25519(message: &[u8], private_key: &[u8; 32]) -> [u8; 64] {
    SigningKey::from_bytes(private_key).sign(message).to_bytes()
}

/// `verifyED25519`.
pub fn verify_ed25519(message: &[u8], signature: &[u8; 64], pubkey: &[u8; 32]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    vk.verify(message, &Signature::from_bytes(signature))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = [7u8; 32];
        let pk = get_public_viewing_key(&sk);
        let msg = br#"{"data":"value","more":{"data":"another_value"}}"#;
        let sig = sign_ed25519(msg, &sk);
        assert!(verify_ed25519(msg, &sig, &pk));
        assert!(!verify_ed25519(b"123", &sig, &pk));
    }
}
