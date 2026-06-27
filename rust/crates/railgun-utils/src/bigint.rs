//! Port of `src/utils/bigint.ts`.

use crate::bytes::hex_to_bigint;
use num_bigint::BigUint;

pub fn min_big_int(a: BigUint, b: BigUint) -> BigUint {
    if a < b {
        a
    } else {
        b
    }
}

/// `stringToBigInt` — decimal strings parse as base-10, everything else as hex.
pub fn string_to_bigint(s: &str) -> BigUint {
    let is_decimal = !s.is_empty()
        && s.trim_start_matches(['-', '+'])
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.');
    if is_decimal {
        // JS `BigInt("12.0")` would throw; the engine only feeds integer-looking
        // decimals here, so parse the integer part.
        let cleaned = s.trim_start_matches(['-', '+']);
        let int_part = cleaned.split('.').next().unwrap_or("0");
        BigUint::parse_bytes(int_part.as_bytes(), 10).unwrap_or_default()
    } else {
        hex_to_bigint(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_works() {
        assert_eq!(
            min_big_int(BigUint::from(3u8), BigUint::from(5u8)),
            BigUint::from(3u8)
        );
    }

    #[test]
    fn string_to_bigint_decimal_and_hex() {
        assert_eq!(string_to_bigint("255"), BigUint::from(255u32));
        assert_eq!(string_to_bigint("ff"), BigUint::from(255u32));
        assert_eq!(string_to_bigint("0xff"), BigUint::from(255u32));
    }
}
