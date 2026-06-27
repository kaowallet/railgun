//! Port of `src/utils/poseidon.ts`.
//!
//! RAILGUN uses circomlibjs Poseidon over the BN254 scalar field. We delegate to
//! `light-poseidon` (circom-compatible, audited by Veridise) and bridge via
//! canonical 32-byte big-endian field encodings, so this stays decoupled from the
//! arkworks version used elsewhere in the crate.

use light_poseidon::{Poseidon, PoseidonBytesHasher};
use num_bigint::BigUint;
use railgun_utils::{hex_to_bigint, n_to_hex, ByteLength};

/// BN254 scalar field modulus == RAILGUN's `SNARK_PRIME`.
fn field_modulus() -> BigUint {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("valid modulus")
}

fn to_be_32(n: &BigUint) -> [u8; 32] {
    let bytes = n.to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
}

/// `poseidon(args)` — hash an array of field elements, returning a field element.
///
/// circomlibjs coerces every input through `F.e(x)` (i.e. reduces mod the field
/// prime); we replicate that before handing off to light-poseidon, which rejects
/// inputs >= the modulus.
pub fn poseidon(inputs: &[BigUint]) -> BigUint {
    let modulus = field_modulus();
    let mut hasher = Poseidon::<ark_bn254::Fr>::new_circom(inputs.len())
        .expect("poseidon supports widths 1..=12");
    let arrays: Vec<[u8; 32]> = inputs.iter().map(|n| to_be_32(&(n % &modulus))).collect();
    let refs: Vec<&[u8]> = arrays.iter().map(|a| a.as_slice()).collect();
    let hash = hasher
        .hash_bytes_be(&refs)
        .expect("inputs are reduced field elements");
    BigUint::from_bytes_be(&hash)
}

/// `poseidonHex(args)` — hash hex strings (0x-prefixed or not), 64-char hex out.
pub fn poseidon_hex(inputs: &[&str]) -> String {
    let nums: Vec<BigUint> = inputs.iter().map(|s| hex_to_bigint(s)).collect();
    n_to_hex(&poseidon(&nums), ByteLength::Uint256, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big_hex(h: &str) -> BigUint {
        BigUint::parse_bytes(h.trim_start_matches("0x").as_bytes(), 16).unwrap()
    }
    fn big_dec(d: &str) -> BigUint {
        BigUint::parse_bytes(d.as_bytes(), 10).unwrap()
    }

    // src/utils/__tests__/poseidon.test.ts
    #[test]
    fn poseidon_bigint_inputs() {
        assert_eq!(
            poseidon(&[BigUint::from(0u8), BigUint::from(1u8)]),
            big_dec("12583541437132735734108669866114103169564651237895298778035846191048104863326")
        );
    }

    #[test]
    fn poseidon_hex_inputs() {
        let expected = "1bd20834f5de9830c643778a2e88a3a1363c8b9ac083d36d75bf87c49953e65e";
        assert_eq!(poseidon_hex(&["0", "1"]), expected);
        assert_eq!(poseidon_hex(&["00", "01"]), expected);
        assert_eq!(poseidon_hex(&["0x0", "0x1"]), expected);
    }

    // src/utils/__tests__/hash.test.ts poseidon vectors
    #[test]
    fn poseidon_hash_test_vectors() {
        assert_eq!(
            poseidon(&[BigUint::from(1u8), BigUint::from(2u8)]),
            big_hex("0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a")
        );
        assert_eq!(
            poseidon(&[
                BigUint::from(1u8),
                BigUint::from(2u8),
                BigUint::from(3u8),
                BigUint::from(4u8)
            ]),
            big_hex("0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465")
        );
        assert_eq!(
            poseidon(&[big_hex(
                "0x6b021e0d06d0b2d161cf0ea494e3fc1cbff12cc1b29281f7412170351b708fad"
            )]),
            big_hex("0x0b77a7c8dcbf2c84e75b6ff1dd558365532956cb7c1f328a67220a3a47a3ab43")
        );
    }
}
