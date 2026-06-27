//! Port of the Curve25519/ECDH helpers in `src/utils/keys-utils.ts` and
//! `src/utils/scalar-multiply.ts`.
//!
//! Note: the "scalar multiply" here operates on the **Edwards** form (the viewing
//! public keys are compressed Edwards points), matching `@noble/ed25519`'s
//! `Point.multiply`. We use `curve25519-dalek`'s `EdwardsPoint`.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use num_bigint::BigUint;

use crate::hash::{sha256_bytes, sha512_bytes};

/// Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493.
fn ed25519_order() -> BigUint {
    BigUint::parse_bytes(
        b"7237005577332262213973186563042994240857116359379907606001950938285454250989",
        10,
    )
    .expect("valid order")
}

fn biguint_to_le32(n: &BigUint) -> [u8; 32] {
    let mut le = n.to_bytes_le();
    le.resize(32, 0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&le[..32]);
    out
}

/// `getPrivateScalarFromPrivateKey` — derive the Ed25519 secret scalar (FIPS-186
/// style) from a 32-byte private key.
pub fn get_private_scalar_from_private_key(private_key: &[u8; 32]) -> BigUint {
    let hash = sha512_bytes(private_key);
    // adjustBytes25519(head, 'le')
    let mut head = [0u8; 32];
    head.copy_from_slice(&hash[..32]);
    head[0] &= 0b1111_1000;
    head[31] &= 0b0111_1111;
    head[31] |= 0b0100_0000;
    // BigInt('0x' + hex(head.reverse())) == little-endian integer of head.
    let scalar = BigUint::from_bytes_le(&head) % ed25519_order();
    if scalar > BigUint::from(0u8) {
        scalar
    } else {
        ed25519_order()
    }
}

/// `scalarMultiplyJavascript` — decompress an Edwards point, multiply by a scalar,
/// recompress. Returns `None` if the point is not a valid curve point.
pub fn scalar_multiply(point: &[u8; 32], scalar: &BigUint) -> Option<[u8; 32]> {
    let edwards = CompressedEdwardsY(*point).decompress()?;
    let s = Scalar::from_bytes_mod_order(biguint_to_le32(scalar));
    Some((edwards * s).compress().to_bytes())
}

/// `getSharedSymmetricKey` — ECDH shared key: scalar-mult then SHA-256.
pub fn get_shared_symmetric_key(
    private_key_a: &[u8; 32],
    blinded_public_key_b: &[u8; 32],
) -> Option<[u8; 32]> {
    let scalar = get_private_scalar_from_private_key(private_key_a);
    let key_preimage = scalar_multiply(blinded_public_key_b, &scalar)?;
    Some(sha256_bytes(&key_preimage))
}

#[cfg(test)]
mod tests {
    use super::*;

    // src/utils/__tests__/keys-utils.test.ts — WASM/JS shared-key known answer.
    #[test]
    fn shared_symmetric_key_vector() {
        let a: [u8; 32] = hex::decode("0123456789012345678901234567890123456789012345678901234567891234")
            .unwrap()
            .try_into()
            .unwrap();
        let b: [u8; 32] = hex::decode("0987654321098765432109876543210987654321098765432109876543210987")
            .unwrap()
            .try_into()
            .unwrap();
        let key = get_shared_symmetric_key(&a, &b).expect("valid point");
        assert_eq!(
            hex::encode(key),
            "fbb71adfede43b8a756939500c810d85b16cfbead66d126065639c0cec1fea56"
        );
    }
}
