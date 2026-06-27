//! Port of the RelayAdapt error/revert parsing from
//! `src/contracts/relay-adapt/V2/relay-adapt-v2.ts` (V2 scope).
//!
//! Pure decoding of RelayAdapt `CallError` reverts: the custom
//! `0x5c0dee5d`-prefixed `(uint256 callIndex, bytes revertReason)` payload and
//! the standard `0x08c379a0`-prefixed `Error(string)` payload, plus the
//! ethers-style estimate-gas error-text extraction.

use alloy::dyn_abi::{DynSolType, DynSolValue};
use alloy::sol_types::SolEvent;

use crate::abi::CallError;

/// `RETURN_DATA_RELAY_ADAPT_STRING_PREFIX`.
pub const RETURN_DATA_RELAY_ADAPT_STRING_PREFIX: &str = "0x5c0dee5d";
/// `RETURN_DATA_STRING_PREFIX` — the standard Solidity `Error(string)` selector.
pub const RETURN_DATA_STRING_PREFIX: &str = "0x08c379a0";

/// The `CallError(uint256,bytes)` event topic0.
pub const CALL_ERROR_TOPIC: [u8; 32] = CallError::SIGNATURE_HASH.0;

/// Parsed RelayAdapt return value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayAdaptReturnValue {
    pub call_index: Option<u64>,
    pub error: String,
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

/// `parseRelayAdaptReturnValue`.
pub fn parse_relay_adapt_return_value(return_value: &str) -> Option<RelayAdaptReturnValue> {
    let lower = return_value.to_lowercase();
    if lower.contains(strip_0x(RETURN_DATA_RELAY_ADAPT_STRING_PREFIX)) {
        let stripped = lower.replacen(strip_0x(RETURN_DATA_RELAY_ADAPT_STRING_PREFIX), "", 1);
        let stripped = format!("0x{}", strip_0x(&stripped));
        return custom_relay_adapt_error_parse(&stripped);
    }
    if lower.contains(strip_0x(RETURN_DATA_STRING_PREFIX)) {
        return Some(RelayAdaptReturnValue {
            call_index: None,
            error: parse_relay_adapt_string_error(&lower),
        });
    }
    Some(RelayAdaptReturnValue {
        call_index: None,
        error: format!(
            "Not a RelayAdapt return value: must be prefixed with {RETURN_DATA_RELAY_ADAPT_STRING_PREFIX} or {RETURN_DATA_STRING_PREFIX}"
        ),
    })
}

fn custom_relay_adapt_error_parse(data: &str) -> Option<RelayAdaptReturnValue> {
    let bytes = hex::decode(strip_0x(data)).ok()?;
    let ty = DynSolType::Tuple(vec![DynSolType::Uint(256), DynSolType::Bytes]);
    let decoded = ty.abi_decode(&bytes).ok()?;
    let DynSolValue::Tuple(items) = decoded else {
        return None;
    };
    let call_index = match &items[0] {
        DynSolValue::Uint(u, _) => u.try_into().ok(),
        _ => None,
    };
    let revert_reason_bytes = match &items[1] {
        DynSolValue::Bytes(b) => format!("0x{}", hex::encode(b)),
        _ => "0x".to_string(),
    };
    let error = parse_relay_adapt_string_error(&revert_reason_bytes);
    Some(RelayAdaptReturnValue { call_index, error })
}

fn parse_relay_adapt_string_error(revert_reason: &str) -> String {
    let lower = revert_reason.to_lowercase();
    if lower.contains(strip_0x(RETURN_DATA_STRING_PREFIX)) {
        let stripped = lower.replacen(strip_0x(RETURN_DATA_STRING_PREFIX), "", 1);
        if let Ok(bytes) = hex::decode(strip_0x(&stripped)) {
            if let Ok(decoded) = DynSolType::String.abi_decode(&bytes) {
                if let DynSolValue::String(s) = decoded {
                    return s;
                }
            }
        }
    }
    // Try to parse the raw bytes as UTF-8.
    if let Ok(bytes) = hex::decode(strip_0x(revert_reason)) {
        if let Ok(s) = String::from_utf8(bytes) {
            let trimmed = s.trim_end_matches('\0');
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    "Unknown Relay Adapt error".to_string()
}

/// `getRelayAdaptCallError` — given the receipt logs (topic0 + data hex pairs),
/// find a `CallError` log and decode its `(callIndex, revertReason)`.
pub fn get_relay_adapt_call_error(logs: &[(Vec<u8>, String)]) -> Option<RelayAdaptReturnValue> {
    for (topic0, data) in logs {
        if topic0.as_slice() == CALL_ERROR_TOPIC {
            // The CallError event payload is the non-indexed `(uint256 callIndex,
            // bytes revertReason)`, which is exactly the custom-error body.
            return custom_relay_adapt_error_parse(&format!("0x{}", strip_0x(data)));
        }
    }
    None
}

/// `extractGasEstimateCallFailedIndexAndError` — pull the `data="0x..."` blob out
/// of an ethers-style estimate-gas error string and parse it.
pub fn extract_gas_estimate_call_failed_index_and_error_text(
    error_message: &str,
) -> Option<RelayAdaptReturnValue> {
    // Sample: ... data="0x5c0dee5d...", reason=null ...
    let marker = "data=\"";
    let start = error_message.find(marker)? + marker.len();
    let rest = &error_message[start..];
    let end = rest.find('"')?;
    let data = &rest[..end];
    parse_relay_adapt_return_value(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_relay_adapt_prefix() {
        let result = parse_relay_adapt_return_value("0xdeadbeef").unwrap();
        assert!(result.error.starts_with("Not a RelayAdapt return value"));
        assert_eq!(result.call_index, None);
    }
}
