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

use crate::poseidon::poseidon;

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

// --- EdDSA-Poseidon over BabyJubJub (circomlibjs `eddsa.signPoseidon`) ---

/// circomlibjs `babyJub.subOrder = order >> 3`, equal to `ark_ed_on_bn254::Fr`'s
/// modulus (the prime-order subgroup order used for `r` and `S`).
fn sub_order() -> BigUint {
    BigUint::parse_bytes(
        b"2736030358979909402780800718157159386076813972158567259200215660948447373041",
        10,
    )
    .expect("valid subOrder")
}

/// `{ R8: [x, y], S }` — circomlibjs Poseidon-EdDSA signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r8: (BigUint, BigUint),
    pub s: BigUint,
}

fn fq_from(n: &BigUint) -> Fq {
    Fq::from(n.clone())
}

/// Map a circomlibjs affine point (a = 168700 form) onto the arkworks reduced
/// curve (a = 1): φ(x, y) = (x·√a, y).
fn circom_to_ark(x: &Fq, y: &Fq) -> EdwardsAffine {
    let sa = coeff_a_sqrt();
    EdwardsAffine::new_unchecked(*x * sa, *y)
}

/// Inverse of `circom_to_ark`: map an arkworks affine point back to circomlibjs
/// coordinates: x1 = x2 / √a, y1 = y2.
fn ark_to_circom(p: &EdwardsAffine) -> (BigUint, BigUint) {
    let sa = coeff_a_sqrt();
    let x1 = p.x().unwrap() * sa.inverse().expect("√a is nonzero");
    let y1 = p.y().unwrap();
    (BigUint::from(x1), BigUint::from(y1))
}

fn base8_ark() -> EdwardsAffine {
    let (b8x, b8y) = base8_circom();
    circom_to_ark(&b8x, &b8y)
}

/// `babyJub.mulPointEscalar(Base8, scalar)` in circomlibjs coordinates.
fn base8_mul(scalar: &BigUint) -> (BigUint, BigUint) {
    let s = Fr::from(scalar.clone());
    let p = (EdwardsProjective::from(base8_ark()) * s).into_affine();
    ark_to_circom(&p)
}

/// `signPoseidon(privateKey, message)`.
pub fn sign_eddsa(private_key: &[u8; 32], message: &BigUint) -> Signature {
    let sub = sub_order();

    // h1 = BLAKE-512(prv); sBuff = prune(h1[0..32]); s = LE(sBuff)
    let h1 = blake512(private_key);
    let mut s_buff = [0u8; 32];
    s_buff.copy_from_slice(&h1[..32]);
    s_buff[0] &= 0xF8;
    s_buff[31] &= 0x7F;
    s_buff[31] |= 0x40;
    let s = BigUint::from_bytes_le(&s_buff);

    // A = Base8 * (s >> 3)
    let a = base8_mul(&(&s >> 3u32));

    // msgBuff = leInt2Buff(msg, 32); rBuff = BLAKE-512(h1[32..64] || msgBuff)
    let msg_buff = msg_to_le32(message);
    let mut r_pre = Vec::with_capacity(32 + 32);
    r_pre.extend_from_slice(&h1[32..64]);
    r_pre.extend_from_slice(&msg_buff);
    let r_buff = blake512(&r_pre);
    let r = BigUint::from_bytes_le(&r_buff) % &sub;

    // R8 = Base8 * r
    let r8 = base8_mul(&r);

    // hm = poseidon([R8.x, R8.y, A.x, A.y, msg])
    let hm = poseidon(&[
        r8.0.clone(),
        r8.1.clone(),
        a.0.clone(),
        a.1.clone(),
        message.clone(),
    ]);

    // S = (r + hm * s) mod subOrder
    let s_sig = (&r + (&hm % &sub) * (&s % &sub)) % &sub;

    Signature { r8, s: s_sig }
}

/// `leInt2Buff(msg, 32)` — 32-byte little-endian encoding of the message scalar.
fn msg_to_le32(message: &BigUint) -> [u8; 32] {
    let mut le = message.to_bytes_le();
    le.resize(32, 0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&le[..32]);
    out
}

/// `babyJub.inCurve(point)` for the circomlibjs (a = 168700) form, via the
/// arkworks isomorphism.
fn in_curve(x: &BigUint, y: &BigUint) -> bool {
    let p = circom_to_ark(&fq_from(x), &fq_from(y));
    p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()
}

/// `verifyPoseidon(message, signature, pubkey)`.
pub fn verify_eddsa(message: &BigUint, signature: &Signature, pubkey: &(BigUint, BigUint)) -> bool {
    let sub = sub_order();

    if !in_curve(&signature.r8.0, &signature.r8.1) {
        return false;
    }
    if !in_curve(&pubkey.0, &pubkey.1) {
        return false;
    }
    if signature.s >= sub {
        return false;
    }

    // hm = poseidon([R8.x, R8.y, A.x, A.y, msg])
    let hm = poseidon(&[
        signature.r8.0.clone(),
        signature.r8.1.clone(),
        pubkey.0.clone(),
        pubkey.1.clone(),
        message.clone(),
    ]);

    // Pleft = Base8 * S
    let p_left = base8_mul(&signature.s);

    // Pright = R8 + A * (hm * 8)
    let a_ark = circom_to_ark(&fq_from(&pubkey.0), &fq_from(&pubkey.1));
    let r8_ark = circom_to_ark(&fq_from(&signature.r8.0), &fq_from(&signature.r8.1));
    let hm8 = Fr::from(hm) * Fr::from(8u64);
    let p_right_ark =
        (EdwardsProjective::from(a_ark) * hm8 + EdwardsProjective::from(r8_ark)).into_affine();
    let p_right = ark_to_circom(&p_right_ark);

    p_left == p_right
}

// --- packPoint / unpackPoint (circomlibjs `babyjub`) ---
//
// circomlibjs packs a point as the little-endian 32-byte encoding of `y`, with
// the top bit of the last byte set when `x` is in the "upper half" of the field
// (`x > p >> 1`). unpackPoint recovers `x` from `y` via the twisted-Edwards
// curve equation in the a = 168700 form:
//     a·x² + y² = 1 + d·x²·y²   =>   x² = (1 − y²) / (a − d·y²)

fn coeff_a() -> Fq {
    Fq::from(168700u64)
}

fn coeff_d() -> Fq {
    Fq::from(168696u64)
}

/// BN254 scalar field prime (the base field `Fq` of BabyJubJub) as a `BigUint`.
fn fq_modulus() -> BigUint {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("valid Fq modulus")
}

fn is_upper_half(n: &BigUint) -> bool {
    *n > (fq_modulus() >> 1u32)
}

/// `babyjub.packPoint(point)` — 32-byte packed encoding of a circomlibjs point.
pub fn pack_point(point: &(BigUint, BigUint)) -> [u8; 32] {
    let mut buff = [0u8; 32];
    let y_le = point.1.to_bytes_le();
    buff[..y_le.len().min(32)].copy_from_slice(&y_le[..y_le.len().min(32)]);
    if is_upper_half(&point.0) {
        buff[31] |= 0x80;
    }
    buff
}

/// `babyjub.unpackPoint(buff)` — recover a circomlibjs point from its packed
/// 32-byte encoding. Returns `None` if the encoded `y` is not on the curve.
pub fn unpack_point(buff: &[u8; 32]) -> Option<(BigUint, BigUint)> {
    let mut bytes = *buff;
    let sign = bytes[31] & 0x80 != 0;
    bytes[31] &= 0x7F;

    let y = Fq::from(BigUint::from_bytes_le(&bytes));
    let y2 = y.square();
    let one = Fq::from(1u64);

    // x² = (1 − y²) / (a − d·y²)
    let numerator = one - y2;
    let denominator = coeff_a() - coeff_d() * y2;
    let denom_inv = denominator.inverse()?;
    let x2 = numerator * denom_inv;
    let mut x = x2.sqrt()?;

    // Pick the root whose "sign" (upper-half-ness) matches the packed sign bit.
    let x_big = BigUint::from(x);
    if is_upper_half(&x_big) != sign {
        x = -x;
    }

    Some((BigUint::from(x), BigUint::from(y)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let prv = [9u8; 32];
        let pubkey = get_public_spending_key(&prv);
        let packed = pack_point(&pubkey);
        let unpacked = unpack_point(&packed).unwrap();
        assert_eq!(unpacked, pubkey);
        assert!(in_curve(&unpacked.0, &unpacked.1));
    }

    // First spending-key vector from key-derivation.test.ts (private key bytes).
    #[test]
    fn spending_pubkey_vector() {
        let priv_key: [u8; 32] = [
            103, 215, 209, 157, 0, 230, 227, 179, 81, 127, 230, 138, 196, 101, 5, 221, 32, 125,
            246, 232, 254, 58, 160, 107, 163, 250, 206, 53, 46, 117, 153, 239,
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

    fn dec(s: &str) -> BigUint {
        BigUint::parse_bytes(s.as_bytes(), 10).unwrap()
    }

    // circomlibjs test/eddsa.js — "Sign (using Poseidon) a single 10 bytes 0..9".
    // msg = leBuff2int("00010203040506070809").
    #[test]
    fn sign_poseidon_known_answer_vector() {
        let prv: [u8; 32] =
            hex::decode("0001020304050607080900010203040506070809000102030405060708090001")
                .unwrap()
                .try_into()
                .unwrap();
        let pubkey = get_public_spending_key(&prv);
        assert_eq!(
            pubkey.0,
            dec("13277427435165878497778222415993513565335242147425444199013288855685581939618")
        );
        assert_eq!(
            pubkey.1,
            dec("13622229784656158136036771217484571176836296686641868549125388198837476602820")
        );

        // msg = little-endian int of bytes 00..09
        let msg = BigUint::from_bytes_le(&hex::decode("00010203040506070809").unwrap());

        let sig = sign_eddsa(&prv, &msg);
        assert_eq!(
            sig.r8.0,
            dec("11384336176656855268977457483345535180380036354188103142384839473266348197733")
        );
        assert_eq!(
            sig.r8.1,
            dec("15383486972088797283337779941324724402501462225528836549661220478783371668959")
        );
        assert_eq!(
            sig.s,
            dec("1672775540645840396591609181675628451599263765380031905495115170613215233181")
        );

        assert!(verify_eddsa(&msg, &sig, &pubkey));
    }

    // Mirrors keys-utils.test.ts "Should create and verify EDDSA signatures".
    #[test]
    fn sign_verify_eddsa_roundtrip() {
        let prv = [9u8; 32];
        let pubkey = get_public_spending_key(&prv);
        let message = poseidon(&[BigUint::from(1u8), BigUint::from(2u8)]);

        let sig = sign_eddsa(&prv, &message);
        assert!(verify_eddsa(&message, &sig, &pubkey));

        let fake_message = poseidon(&[BigUint::from(2u8), BigUint::from(3u8)]);
        assert!(!verify_eddsa(&fake_message, &sig, &pubkey));
        assert!(!verify_eddsa(
            &message,
            &sig,
            &(BigUint::from(0u8), BigUint::from(1u8))
        ));
    }
}
