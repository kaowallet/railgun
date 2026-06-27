//! Port of `RelayAdaptHelper` (`src/contracts/relay-adapt/relay-adapt-helper.ts`).
//!
//! The load-bearing KAV is [`get_relay_adapt_params`]: it ABI-encodes the
//! transaction nullifiers + length + action data exactly as
//! `AbiCoder.defaultAbiCoder().encode(...)` does in ethers, then keccak256s the
//! result. Reproduced with alloy's static `sol!` ABI encoder.

use alloy::primitives::{keccak256, Address, FixedBytes, U256};
use alloy::sol_types::SolValue;
use num_bigint::BigUint;

use crate::abi::{ActionDataStruct, CallStruct};
use crate::ContractError;

/// Minimal mirror of an ethers `ContractTransaction` for call formatting — only
/// the fields RelayAdapt needs (`to`, `data`, `value`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContractCall {
    /// 0x-prefixed (or bare) hex address; empty string => zero/empty (TS `''`).
    pub to: String,
    /// 0x-prefixed (or bare) hex calldata; empty string => empty bytes.
    pub data: String,
    /// Wei value.
    pub value: BigUint,
}

fn parse_address(s: &str) -> Result<Address, ContractError> {
    if s.is_empty() {
        return Ok(Address::ZERO);
    }
    s.parse::<Address>()
        .map_err(|e| ContractError::InvalidArgument(format!("invalid address {s}: {e}")))
}

fn parse_bytes(s: &str) -> Result<Vec<u8>, ContractError> {
    if s.is_empty() {
        return Ok(vec![]);
    }
    Ok(railgun_utils::hex_string_to_bytes(s)?)
}

fn biguint_to_u256(n: &BigUint) -> U256 {
    U256::from_be_slice(&n.to_bytes_be())
}

/// `RelayAdaptHelper.formatCalls` — strip populated transactions to `{to, data,
/// value}`, defaulting missing fields (`to`→'', `value`→0n) as the TS does.
pub fn format_calls(calls: &[ContractCall]) -> Result<Vec<CallStruct>, ContractError> {
    calls
        .iter()
        .map(|c| {
            Ok(CallStruct {
                to: parse_address(&c.to)?,
                data: parse_bytes(&c.data)?.into(),
                value: biguint_to_u256(&c.value),
            })
        })
        .collect()
}

/// `RelayAdaptHelper.formatRandom` — require a 31-byte (62-hex-char) value.
pub fn format_random(random: &str) -> Result<Vec<u8>, ContractError> {
    let stripped = railgun_utils::strip_0x(random);
    if stripped.len() != 62 {
        return Err(ContractError::InvalidArgument(
            "Relay Adapt random parameter must be a hex string of length 62 (31 bytes).".into(),
        ));
    }
    Ok(railgun_utils::hex_string_to_bytes(stripped)?)
}

/// `RelayAdaptHelper.getActionData`.
pub fn get_action_data(
    random: &str,
    require_success: bool,
    calls: &[ContractCall],
    min_gas_limit: &BigUint,
) -> Result<ActionDataStruct, ContractError> {
    let formatted_random = format_random(random)?;
    Ok(ActionDataStruct {
        random: FixedBytes::<31>::from_slice(&formatted_random),
        requireSuccess: require_success,
        minGasLimit: biguint_to_u256(min_gas_limit),
        calls: format_calls(calls)?,
    })
}

/// `RelayAdaptHelper.getRelayAdaptParams` — keccak256 of the ABI-encoded
/// `(bytes32[][] nullifiers, uint256 transactionsLength, ActionData actionData)`.
///
/// `nullifiers` is the per-transaction list of nullifier byte32 arrays.
pub fn get_relay_adapt_params(
    nullifiers: &[Vec<Vec<u8>>],
    transactions_length: usize,
    random: &str,
    require_success: bool,
    calls: &[ContractCall],
    min_gas_limit: &BigUint,
) -> Result<String, ContractError> {
    let action_data = get_action_data(random, require_success, calls, min_gas_limit)?;

    let nullifiers_abi: Vec<Vec<FixedBytes<32>>> = nullifiers
        .iter()
        .map(|tx_nullifiers| {
            tx_nullifiers
                .iter()
                .map(|n| {
                    // Pad/format each nullifier to 32 bytes (ethers `bytes32`).
                    let mut buf = [0u8; 32];
                    let bytes = if n.len() > 32 {
                        &n[n.len() - 32..]
                    } else {
                        &n[..]
                    };
                    buf[32 - bytes.len()..].copy_from_slice(bytes);
                    FixedBytes::<32>::from(buf)
                })
                .collect()
        })
        .collect();

    let tx_len = U256::from(transactions_length);

    // `AbiCoder.defaultAbiCoder().encode([...], [...])` == ABI tuple/params
    // encoding of the three values in order.
    let encoded = (nullifiers_abi, tx_len, action_data).abi_encode_params();

    let hash = keccak256(&encoded);
    Ok(format!("0x{}", hex::encode(hash)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Num;

    fn big_dec(s: &str) -> BigUint {
        BigUint::from_str_radix(s, 10).unwrap()
    }

    // Ported from relay-adapt.test.ts: "Should calculate relay adapt params".
    #[test]
    fn should_calculate_relay_adapt_params() {
        let nullifiers: Vec<Vec<u8>> = vec![
            vec![
                42, 178, 205, 78, 49, 222, 35, 76, 140, 83, 19, 50, 218, 74, 38, 161, 4, 32, 213,
                247, 186, 238, 81, 137, 50, 61, 32, 21, 178, 16, 168, 32,
            ],
            vec![
                5, 228, 162, 212, 44, 195, 165, 245, 46, 252, 85, 67, 78, 165, 80, 86, 216, 220,
                217, 118, 198, 92, 41, 84, 51, 159, 175, 75, 194, 103, 163, 115,
            ],
        ];

        let random = hex::encode([
            134u8, 114, 120, 89, 227, 254, 124, 13, 129, 226, 125, 250, 250, 240, 217, 194, 183,
            180, 136, 153, 29, 44, 89, 196, 146, 178, 37, 250, 159, 195, 7,
        ]);

        let data = hex::encode([
            210u8, 140, 37, 212, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 104, 105, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        let calls = vec![ContractCall {
            to: "0x8f86403A4DE0BB5791fa46B8e795C547942fE4Cf".into(),
            data,
            value: BigUint::from(0u8),
        }];

        // A single transaction carrying both nullifiers.
        let params = get_relay_adapt_params(
            &[nullifiers],
            1,
            &random,
            false,
            &calls,
            &big_dec("10000000"),
        )
        .unwrap();

        let expected = format!(
            "0x{}",
            hex::encode([
                53u8, 54, 66, 65, 188, 134, 60, 165, 0, 101, 8, 125, 85, 49, 151, 206, 203, 156,
                192, 199, 6, 178, 94, 150, 14, 31, 101, 68, 83, 251, 241, 35,
            ])
        );

        assert_eq!(params, expected);
    }

    #[test]
    fn format_random_rejects_wrong_length() {
        assert!(format_random("00").is_err());
        // 62 hex chars == 31 bytes is accepted.
        let ok = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd";
        assert_eq!(ok.len(), 62);
        assert!(format_random(ok).is_ok());
    }
}
