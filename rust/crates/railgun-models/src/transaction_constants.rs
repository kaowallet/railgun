//! Port of `src/models/transaction-constants.ts`.

use num_bigint::BigUint;

pub const TOKEN_SUB_ID_NULL: &str = "0x00";

/// 15 bytes of `00` (hex).
pub const MEMO_SENDER_RANDOM_NULL: &str = "000000000000000000000000000000";

/// `UnshieldFlag`.
pub mod unshield_flag {
    use num_bigint::BigUint;

    pub fn no_unshield() -> BigUint {
        BigUint::from(0u8)
    }
    pub fn unshield() -> BigUint {
        BigUint::from(1u8)
    }
    pub fn r#override() -> BigUint {
        BigUint::from(2u8)
    }
}

/// Convenience integer view of [`unshield_flag`].
pub const UNSHIELD_FLAG_NO_UNSHIELD: u8 = 0;
pub const UNSHIELD_FLAG_UNSHIELD: u8 = 1;
pub const UNSHIELD_FLAG_OVERRIDE: u8 = 2;

#[allow(dead_code)]
fn _assert_consts() -> BigUint {
    unshield_flag::unshield()
}
