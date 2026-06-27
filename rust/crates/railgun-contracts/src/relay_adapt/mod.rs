//! Port of `src/contracts/relay-adapt/**` (V2 + V3 scope).
//!
//! - [`helper`] — `RelayAdaptHelper`: adapt-params hashing, call/random
//!   formatting, action-data assembly. Pure + KAV-tested.
//! - [`error`] — the custom RelayAdapt revert/error parsing (`0x5c0dee5d` /
//!   `0x08c379a0`), `CallError` log decoding, and the ethers-style
//!   estimate-gas error-text extraction. Pure + KAV-tested.
//!
//! The transaction-building methods on `RelayAdaptV2Contract`
//! (`populateShieldBaseToken`, `populateCrossContractCalls`, …) and live gas
//! estimation are RPC-bound; their populated-transaction shapes are produced
//! via the alloy bindings + [`helper`], and the actual RPC send/estimate is the
//! caller's responsibility through [`crate::provider::EventProvider`]. V3
//! transaction building is `Not implemented` in the TS source too, so it is left
//! as a TODO here.

pub mod error;
pub mod helper;

/// `MINIMUM_RELAY_ADAPT_CROSS_CONTRACT_CALLS_GAS_LIMIT_V2`
/// (`src/contracts/relay-adapt/constants.ts`).
pub const MINIMUM_RELAY_ADAPT_CROSS_CONTRACT_CALLS_GAS_LIMIT_V2: u64 = 3_200_000;

/// `RelayAdaptV2Contract.getMinimumGasLimitForContract` — contract needs
/// ~50k–150k less gas than the gasLimit setting.
pub fn get_minimum_gas_limit_for_contract_v2(minimum_gas_limit: u64) -> u64 {
    minimum_gas_limit - 150_000
}

/// `shouldRequireSuccessForCrossContractCalls` (V2).
pub fn should_require_success_for_cross_contract_calls(
    is_gas_estimate: bool,
    is_broadcaster_transaction: bool,
) -> bool {
    // Only !requireSuccess for production broadcaster transactions (not estimates).
    let continue_after_multicall_failure = is_broadcaster_transaction && !is_gas_estimate;
    !continue_after_multicall_failure
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_gas_limit_for_contract() {
        assert_eq!(
            get_minimum_gas_limit_for_contract_v2(
                MINIMUM_RELAY_ADAPT_CROSS_CONTRACT_CALLS_GAS_LIMIT_V2
            ),
            3_050_000
        );
    }

    #[test]
    fn require_success_logic() {
        // gas estimate => always requireSuccess
        assert!(should_require_success_for_cross_contract_calls(true, true));
        assert!(should_require_success_for_cross_contract_calls(true, false));
        // production broadcaster tx => !requireSuccess
        assert!(!should_require_success_for_cross_contract_calls(
            false, true
        ));
        // non-broadcaster => requireSuccess
        assert!(should_require_success_for_cross_contract_calls(
            false, false
        ));
    }
}
