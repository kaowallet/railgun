//! Port of `getPublicSpendingKey` (circomlibjs `eddsa.prv2pub`) from
//! `src/utils/keys-utils.ts`.
//!
//! Algorithm (circomlibjs):
//!   1. h = BLAKE-512(privateKey)            (original BLAKE, not BLAKE2)
//!   2. prune h[0..32]: h[0]&=0xF8; h[31]&=0x7F; h[31]|=0x40
//!   3. s = little-endian integer of the pruned 32 bytes
//!   4. A = Base8 · (s >> 3)                  (scalar mult on BabyJubJub)
//!   5. return [A.x, A.y] as BN254 field elements
//!
//! BabyJubJub == arkworks' EdOnBN254 curve; its base field Fq is the BN254 scalar
//! field (RAILGUN's SNARK_PRIME). We delegate the curve math to `ark-ed-on-bn254`
//! and the BLAKE-512 to the reference `blake` crate.

use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_ff::Field;
use num_bigint::BigUint;

// circomlibjs BabyJubJub uses the twisted Edwards form with a = 168700, d = 168696.
// arkworks' `ed-on-bn254` uses the isomorphic reduced form a = 1, d = 168696/168700.
// The isomorphism is φ(x, y) = (x·√a, y). We map circomlibjs's Base8 onto the
// arkworks curve, do the scalar mult there, then map the result back. The round
// trip recovers circomlibjs coordinates exactly for either choice of √a.

fn coeff_a_sqrt() -> Fq {
    Fq::from(168700u64).sqrt().expect("168700 is a QR mod q")
}

fn base8_circom() -> (Fq, Fq) {
    let x = Fq::from(
        BigUint::parse_bytes(
            b"5299619240641551281634865583518297030282874472190772894086521144482721001553",
            10,
        )
        .unwrap(),
    );
    let y = Fq::from(
        BigUint::parse_bytes(
            b"16950150798460657717958625567821834550301663161624707787222815936182638968203",
            10,
        )
        .unwrap(),
    );
    (x, y)
}

fn blake512(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    blake::hash(512, data, &mut out).expect("blake512");
    out
}

/// `getPublicSpendingKey` — derive the BabyJubJub EdDSA public key `[x, y]`.
pub fn get_public_spending_key(private_key: &[u8; 32]) -> (BigUint, BigUint) {
    // 1-2. BLAKE-512 + prune (pruneBuffer)
    let mut h = blake512(private_key);
    h[0] &= 0b1111_1000;
    h[31] &= 0b0111_1111;
    h[31] |= 0b0100_0000;

    // 3. little-endian scalar from first 32 bytes
    let s = BigUint::from_bytes_le(&h[..32]);

    // 4. A = Base8 * (s >> 3), computed on the arkworks curve via the isomorphism
    let scalar = Fr::from(s >> 3u32);
    let sa = coeff_a_sqrt();
    let (b8x, b8y) = base8_circom();
    let base8_ark = EdwardsAffine::new_unchecked(b8x * sa, b8y);
    let a2 = (EdwardsProjective::from(base8_ark) * scalar).into_affine();

    // 5. map back to circomlibjs coordinates: x1 = x2 / √a, y1 = y2
    let x1 = a2.x().unwrap() * sa.inverse().expect("√a is nonzero");
    let y1 = a2.y().unwrap();
    (BigUint::from(x1), BigUint::from(y1))
}

#[cfg(test)]
mod tests {
    use super::*;

    // First spending-key vector from key-derivation.test.ts (private key bytes).
    #[test]
    fn spending_pubkey_vector() {
        let priv_key: [u8; 32] = [
            103, 215, 209, 157, 0, 230, 227, 179, 81, 127, 230, 138, 196, 101, 5, 221, 32, 125, 246,
            232, 254, 58, 160, 107, 163, 250, 206, 53, 46, 117, 153, 239,
        ];
        let (x, y) = get_public_spending_key(&priv_key);
        assert_eq!(
            x,
            BigUint::parse_bytes(
                b"1700559105542139805112168139351320601853033442476682590258553412078471731431",
                10
            )
            .unwrap()
        );
        assert_eq!(
            y,
            BigUint::parse_bytes(
                b"20772987336827599306927277921643441679141423747083423413320022373456048866305",
                10
            )
            .unwrap()
        );
    }
}
