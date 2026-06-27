//! Port of the wallet-source base-37 codec used by note annotation data
//! (`src/wallet/wallet-info.ts`).
//!
//! Only the encode/decode helpers needed for memo/annotation are ported here;
//! the full `WalletInfo` (with the global mutable `walletSource`) lives in the
//! wallet crate. Note encryption takes the wallet source explicitly instead of
//! reading a global.

use num_bigint::BigUint;
use num_traits::Zero;

const MAX_LENGTH: usize = 16;
const WALLET_SOURCE_CHARSET: &str = " 0123456789abcdefghijklmnopqrstuvwxyz";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WalletInfoError {
    #[error("Wallet source must be less than {MAX_LENGTH} characters.")]
    TooLong,
    #[error("Please add a valid wallet source.")]
    Empty,
    #[error("Invalid character for wallet source: {0}")]
    InvalidChar(char),
}

fn charset() -> Vec<char> {
    WALLET_SOURCE_CHARSET.chars().collect()
}

/// `WalletInfo.encodeWalletSource` (private) — base-37 hex.
///
/// NOTE: the TS pads to an **odd** length string: it prepends `0` only when the
/// hex length is *even* (`outputHex.length % 2 ? outputHex : '0'+outputHex`).
/// Replicated verbatim — it is load-bearing for ciphertext byte layout.
fn encode_wallet_source(wallet_source: &str) -> Result<String, WalletInfoError> {
    let cs = charset();
    let base = BigUint::from(cs.len());
    let chars: Vec<char> = wallet_source.chars().collect();
    let mut output = BigUint::zero();
    for (i, ch) in chars.iter().enumerate() {
        let idx = cs
            .iter()
            .position(|c| c == ch)
            .ok_or(WalletInfoError::InvalidChar(*ch))?;
        let positional = base.pow((chars.len() - i - 1) as u32);
        output += BigUint::from(idx) * positional;
    }
    let output_hex = format!("{output:x}");
    Ok(if output_hex.len() % 2 == 1 {
        output_hex
    } else {
        format!("0{output_hex}")
    })
}

/// `WalletInfo.getEncodedWalletSource`.
pub fn get_encoded_wallet_source(wallet_source: &str) -> Result<String, WalletInfoError> {
    if wallet_source.is_empty() {
        return Ok(String::new());
    }
    encode_wallet_source(&wallet_source.to_lowercase())
}

/// `WalletInfo.setWalletSource` validation (used to reject invalid sources).
pub fn validate_wallet_source(wallet_source: &str) -> Result<(), WalletInfoError> {
    let lower = wallet_source.to_lowercase();
    if lower.len() > MAX_LENGTH {
        return Err(WalletInfoError::TooLong);
    }
    if lower.is_empty() {
        return Err(WalletInfoError::Empty);
    }
    encode_wallet_source(&lower).map(|_| ())
}

/// `WalletInfo.decodeWalletSource` — `bytes` is a hex string (no 0x prefix).
pub fn decode_wallet_source(bytes: &str) -> String {
    let cs = charset();
    let base = BigUint::from(cs.len());
    let mut input = BigUint::parse_bytes(bytes.as_bytes(), 16).unwrap_or_else(BigUint::zero);
    let mut output = String::new();
    while input > BigUint::zero() {
        let remainder = &input % &base;
        let idx: usize = (&remainder)
            .try_into()
            .expect("remainder < base fits usize");
        output.insert(0, cs[idx]);
        input = (input - remainder) / &base;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        for src in ["tester", "memo wallet", "a", "railgun"] {
            let encoded = get_encoded_wallet_source(src).unwrap();
            let decoded = decode_wallet_source(&encoded);
            assert_eq!(decoded, src);
        }
    }
}
