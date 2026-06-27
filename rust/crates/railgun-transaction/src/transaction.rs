//! Port of the pure pieces of `src/transaction/transaction.ts` (and the wallet
//! `sign` message construction in `railgun-wallet.ts`).
//!
//! What lives here:
//! - [`PublicInputsRailgun`] — the circuit's public inputs.
//! - [`format_public_inputs_railgun`] — the Poseidon pre-image flattening
//!   `[merkleRoot, boundParamsHash, ...nullifiers, ...commitmentsOut]` and its
//!   single-field Poseidon hash, which is the EdDSA-Poseidon signing message.
//! - [`sign_public_inputs`] — EdDSA-Poseidon signature over that message, using
//!   `railgun_crypto::sign_eddsa`.
//!
//! Deferred (TODO): the full `Transaction` / `TransactionBatch` assembly
//! (`generateTransactionRequest`, note encryption, bound-params struct
//! population, spending-solution iteration) and Groth16 proof generation. Those
//! require the wallet (Phase 5), UTXO merkletree proofs, and the prover backend
//! + circuit artifacts (Phase 4) — all behind injected traits. The signing and
//! public-input hashing reproduced here are the cryptographic core those layers
//! call into, and are the parts pinned by known-answer vectors.

use num_bigint::BigUint;
use railgun_crypto::{poseidon, sign_eddsa, Signature};

/// `PublicInputsRailgun` (see `prover-types.ts`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputsRailgun {
    pub merkle_root: BigUint,
    pub bound_params_hash: BigUint,
    pub nullifiers: Vec<BigUint>,
    pub commitments_out: Vec<BigUint>,
}

impl PublicInputsRailgun {
    /// Flatten to the Poseidon pre-image array
    /// `[merkleRoot, boundParamsHash, ...nullifiers, ...commitmentsOut]`.
    pub fn to_poseidon_preimage(&self) -> Vec<BigUint> {
        let mut preimage =
            Vec::with_capacity(2 + self.nullifiers.len() + self.commitments_out.len());
        preimage.push(self.merkle_root.clone());
        preimage.push(self.bound_params_hash.clone());
        preimage.extend(self.nullifiers.iter().cloned());
        preimage.extend(self.commitments_out.iter().cloned());
        preimage
    }
}

/// `poseidon([merkleRoot, boundParamsHash, ...nullifiers, ...commitmentsOut])`
/// — the message that the spending key signs (`RailgunWallet.sign`).
pub fn format_public_inputs_railgun(public_inputs: &PublicInputsRailgun) -> BigUint {
    poseidon(&public_inputs.to_poseidon_preimage())
}

/// EdDSA-Poseidon signature over the public-inputs hash, mirroring
/// `RailgunWallet.sign`: `signEDDSA(spendingPrivateKey, poseidon(publicInputs))`.
pub fn sign_public_inputs(
    spending_private_key: &[u8; 32],
    public_inputs: &PublicInputsRailgun,
) -> Signature {
    let msg = format_public_inputs_railgun(public_inputs);
    sign_eddsa(spending_private_key, &msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use railgun_crypto::{get_public_spending_key, verify_eddsa};

    fn big_dec(d: &str) -> BigUint {
        BigUint::parse_bytes(d.as_bytes(), 10).unwrap()
    }

    #[test]
    fn public_inputs_preimage_ordering() {
        let pi = PublicInputsRailgun {
            merkle_root: BigUint::from(1u8),
            bound_params_hash: BigUint::from(2u8),
            nullifiers: vec![BigUint::from(3u8), BigUint::from(4u8)],
            commitments_out: vec![BigUint::from(5u8), BigUint::from(6u8)],
        };
        let preimage = pi.to_poseidon_preimage();
        assert_eq!(
            preimage,
            vec![
                BigUint::from(1u8),
                BigUint::from(2u8),
                BigUint::from(3u8),
                BigUint::from(4u8),
                BigUint::from(5u8),
                BigUint::from(6u8),
            ]
        );
        // Hash matches circomlibjs poseidon([1,2,3,4,5,6]).
        assert_eq!(
            format_public_inputs_railgun(&pi),
            big_dec(
                "20400040500897583745843009878988256314335038853985262692600694741116813247201"
            )
        );
    }

    #[test]
    fn sign_public_inputs_verifies() {
        // Deterministic 32-byte spending private key.
        let priv_key = [7u8; 32];
        let pubkey = get_public_spending_key(&priv_key);
        let pi = PublicInputsRailgun {
            merkle_root: big_dec("12345"),
            bound_params_hash: big_dec("67890"),
            nullifiers: vec![big_dec("111"), big_dec("222")],
            commitments_out: vec![big_dec("333")],
        };
        let sig = sign_public_inputs(&priv_key, &pi);
        let msg = format_public_inputs_railgun(&pi);
        assert!(verify_eddsa(&msg, &sig, &pubkey));
    }
}
