//! Port of the Curve25519/ECDH helpers in `src/utils/keys-utils.ts` and
//! `src/utils/scalar-multiply.ts`.
//!
//! Note: the "scalar multiply" here operates on the **Edwards** form (the viewing
//! public keys are compressed Edwards points), matching `@noble/ed25519`'s
//! `Point.multiply`. We use `curve25519-dalek`'s `EdwardsPoint`.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;
use railgun_utils::{hex_to_bigint, n_to_bytes, ByteLength};

use crate::hash::{sha256_bytes, sha512, sha512_bytes};
use crate::poseidon::poseidon_hex;

/// Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493.
/// circomlibjs / @noble `CURVE.l` (== `CURVE.n`, the curve order used by RAILGUN).
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

/// `getRandomScalar` — `hexToBigInt(poseidonHex([fastBytesToHex(random32)]))`.
/// Randomness is injected (`random_32`) so it is reproducible in tests; callers
/// pass 32 random bytes.
pub fn get_random_scalar(random_32: &[u8; 32]) -> BigUint {
    hex_to_bigint(&poseidon_hex(&[&hex::encode(random_32)]))
}

/// `seedToScalar`, as 32 big-endian bytes. The TS source computes
/// `(hexToBigInt(seedHash) % CURVE.n) - 1n + 1n` — the `- 1n + 1n` cancels, so the
/// real reduction is `seedHash % n`. (The TS *comment* says `% (n - 1)`, which is
/// wrong; following the comment instead of the code produces blinding scalars that
/// disagree with every other RAILGUN client — caught by the blinding-key fuzz.)
fn seed_to_scalar(seed: &[u8]) -> [u8; 32] {
    let seed_hash = hex_to_bigint(&sha512(seed));
    let scalar = seed_hash % ed25519_order();
    let bytes = n_to_bytes(&scalar, ByteLength::Uint256);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// `getBlindingScalar` — XOR the shared and sender randoms then `seedToScalar`.
fn get_blinding_scalar(shared_random: &str, sender_random: &str) -> BigUint {
    let final_random = hex_to_bigint(shared_random) ^ hex_to_bigint(sender_random);
    let final_bytes = n_to_bytes(&final_random, ByteLength::Uint256);
    BigUint::from_bytes_be(&seed_to_scalar(&final_bytes))
}

/// `getNoteBlindingKeys` — blind sender/receiver viewing public keys.
/// Returns `(blindedSenderViewingKey, blindedReceiverViewingKey)`.
pub fn get_note_blinding_keys(
    sender_viewing_public_key: &[u8; 32],
    receiver_viewing_public_key: &[u8; 32],
    shared_random: &str,
    sender_random: &str,
) -> Option<([u8; 32], [u8; 32])> {
    let blinding_scalar = get_blinding_scalar(shared_random, sender_random);
    let blinded_sender = scalar_multiply(sender_viewing_public_key, &blinding_scalar)?;
    let blinded_receiver = scalar_multiply(receiver_viewing_public_key, &blinding_scalar)?;
    Some((blinded_sender, blinded_receiver))
}

/// Modular inverse of `a` mod `m` (extended Euclidean), matching `@noble`'s
/// `invert(scalar, CURVE.n)`.
fn invert_mod(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;
    let a = BigInt::from(a.clone());
    let m = BigInt::from(m.clone());
    let g = a.extended_gcd(&m);
    if g.gcd != BigInt::one() {
        return None;
    }
    let inv = ((g.x % &m) + &m) % &m;
    inv.to_biguint()
}

/// `unblindNoteKey` — invert the blinding multiplication to recover the key.
/// Returns `None` if the point is invalid (mirrors the TS `undefined`).
pub fn unblind_note_key(
    blinded_note_key: &[u8; 32],
    shared_random: &str,
    sender_random: &str,
) -> Option<[u8; 32]> {
    let blinding_scalar = get_blinding_scalar(shared_random, sender_random);
    let inverse = invert_mod(&blinding_scalar, &ed25519_order())?;
    scalar_multiply(blinded_note_key, &inverse)
}

#[cfg(test)]
mod tests {
    use super::*;

    // src/utils/__tests__/keys-utils.test.ts — WASM/JS shared-key known answer.
    #[test]
    fn shared_symmetric_key_vector() {
        let a: [u8; 32] =
            hex::decode("0123456789012345678901234567890123456789012345678901234567891234")
                .unwrap()
                .try_into()
                .unwrap();
        let b: [u8; 32] =
            hex::decode("0987654321098765432109876543210987654321098765432109876543210987")
                .unwrap()
                .try_into()
                .unwrap();
        let key = get_shared_symmetric_key(&a, &b).expect("valid point");
        assert_eq!(
            hex::encode(key),
            "fbb71adfede43b8a756939500c810d85b16cfbead66d126065639c0cec1fea56"
        );
    }

    use crate::ed25519::get_public_viewing_key;

    const MEMO_SENDER_RANDOM_NULL: &str = "000000000000000000000000000000";

    #[test]
    fn random_scalar_is_field_element() {
        let scalar = get_random_scalar(&[3u8; 32]);
        // 64-char fixed hex (UINT_256), matching keys-utils.test.ts.
        assert_eq!(
            railgun_utils::n_to_hex(&scalar, ByteLength::Uint256, false).len(),
            64
        );
    }

    // keys-utils.test.ts "Should get shared key from two note keys".
    #[test]
    fn shared_key_from_two_note_keys() {
        let sender = [11u8; 32];
        let sender_public = get_public_viewing_key(&sender);
        let receiver = [22u8; 32];
        let receiver_public = get_public_viewing_key(&receiver);

        let random = "0102030405060708090a0b0c0d0e0f10";
        let (blinded_sender, blinded_receiver) = get_note_blinding_keys(
            &sender_public,
            &receiver_public,
            random,
            MEMO_SENDER_RANDOM_NULL,
        )
        .unwrap();

        let k1 = get_shared_symmetric_key(&receiver, &blinded_sender);
        let k2 = get_shared_symmetric_key(&sender, &blinded_receiver);
        assert!(k1.is_some());
        assert_eq!(k1, k2);
    }

    // keys-utils.test.ts "...with sender blinding key".
    #[test]
    fn shared_key_with_sender_blinding() {
        let sender = [33u8; 32];
        let sender_public = get_public_viewing_key(&sender);
        let receiver = [44u8; 32];
        let receiver_public = get_public_viewing_key(&receiver);

        let random = "0102030405060708090a0b0c0d0e0f10";
        let sender_random = "0a0b0c0d0e0f101112131415161718"; // 15 bytes
        let (blinded_sender, blinded_receiver) =
            get_note_blinding_keys(&sender_public, &receiver_public, random, sender_random)
                .unwrap();

        let k1 = get_shared_symmetric_key(&receiver, &blinded_sender);
        let k2 = get_shared_symmetric_key(&sender, &blinded_receiver);
        assert_eq!(k1, k2);
    }

    // keys-utils.test.ts "Should unblind note keys".
    #[test]
    fn unblind_note_keys_roundtrip() {
        let sender = [55u8; 32];
        let sender_public = get_public_viewing_key(&sender);
        let receiver = [66u8; 32];
        let receiver_public = get_public_viewing_key(&receiver);

        let random = "0102030405060708090a0b0c0d0e0f10";
        let (blinded_sender, blinded_receiver) = get_note_blinding_keys(
            &sender_public,
            &receiver_public,
            random,
            MEMO_SENDER_RANDOM_NULL,
        )
        .unwrap();

        let sender_unblinded = unblind_note_key(&blinded_sender, random, MEMO_SENDER_RANDOM_NULL);
        let receiver_unblinded =
            unblind_note_key(&blinded_receiver, random, MEMO_SENDER_RANDOM_NULL);

        assert_eq!(sender_unblinded, Some(sender_public));
        assert_eq!(receiver_unblinded, Some(receiver_public));
    }

    // keys-utils.test.ts "Should unblind only receiver viewing key, with sender blinding key".
    #[test]
    fn unblind_requires_correct_blinding_key() {
        let sender = [77u8; 32];
        let sender_public = get_public_viewing_key(&sender);
        let receiver = [88u8; 32];
        let receiver_public = get_public_viewing_key(&receiver);

        let random = "0102030405060708090a0b0c0d0e0f10";
        let sender_random = "0a0b0c0d0e0f101112131415161718";
        let (blinded_sender, blinded_receiver) =
            get_note_blinding_keys(&sender_public, &receiver_public, random, sender_random)
                .unwrap();

        let sender_no_key = unblind_note_key(&blinded_sender, random, MEMO_SENDER_RANDOM_NULL);
        let sender_with_key = unblind_note_key(&blinded_sender, random, sender_random);
        let receiver_no_key = unblind_note_key(&blinded_receiver, random, MEMO_SENDER_RANDOM_NULL);
        let receiver_with_key = unblind_note_key(&blinded_receiver, random, sender_random);

        assert_ne!(sender_no_key, Some(sender_public));
        assert_eq!(sender_with_key, Some(sender_public));
        assert_ne!(receiver_no_key, Some(receiver_public));
        assert_eq!(receiver_with_key, Some(receiver_public));
    }
}
