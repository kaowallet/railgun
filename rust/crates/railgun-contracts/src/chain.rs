//! Port of `src/chain/chain.ts`.
//!
//! `getChainFullNetworkID` (1-byte chainType + 7-byte chainID) is a known-answer
//! vector. The canonical implementation lives in `railgun-models`
//! ([`railgun_models::get_chain_full_network_id`]); we re-export it here so the
//! contracts crate matches the TS module layout, and re-test the KAV.

use std::sync::Mutex;

use railgun_models::Chain;

pub use railgun_models::get_chain_full_network_id;

// Mirror of the TS module-level mutable `chainsSupportingV3` array.
static CHAINS_SUPPORTING_V3: Mutex<Vec<Chain>> = Mutex::new(Vec::new());

/// `getChainSupportsV3`.
pub fn get_chain_supports_v3(chain: &Chain) -> bool {
    let guard = CHAINS_SUPPORTING_V3.lock().expect("lock poisoned");
    guard
        .iter()
        .any(|c| c.id == chain.id && c.chain_type == chain.chain_type)
}

/// `assertChainSupportsV3`.
pub fn assert_chain_supports_v3(chain: &Chain) -> Result<(), String> {
    if get_chain_supports_v3(chain) {
        Ok(())
    } else {
        Err(format!(
            "Chain does not support V3: {}:{}. Set supportsV3 'true' in loadNetwork.",
            chain.chain_type, chain.id
        ))
    }
}

/// `addChainSupportsV3`.
pub fn add_chain_supports_v3(chain: Chain) {
    CHAINS_SUPPORTING_V3
        .lock()
        .expect("lock poisoned")
        .push(chain);
}

#[cfg(test)]
mod tests {
    use super::*;
    use railgun_models::ChainType;

    fn chain(chain_type: u8, id: u64) -> Chain {
        Chain { chain_type, id }
    }

    // Ported from getChainFullNetworkID behaviour (chain.ts) + models KAV.
    #[test]
    fn should_get_chain_full_network_id() {
        // 1-byte type + 7-byte id, hex (no 0x prefix).
        assert_eq!(
            get_chain_full_network_id(&chain(ChainType::Evm as u8, 1)),
            "0000000000000001"
        );
        // chainType 0, chainID 56 (0x38)
        assert_eq!(get_chain_full_network_id(&chain(0, 56)), "0000000000000038");
        // chainType 1, chainID 0x0123456789abcd (max-ish 7-byte id)
        assert_eq!(
            get_chain_full_network_id(&chain(1, 0x0123_4567_89ab_cd)),
            "010123456789abcd"
        );
        // Length is always 16 hex chars (8 bytes).
        assert_eq!(
            get_chain_full_network_id(&chain(ChainType::Evm as u8, 137)).len(),
            16
        );
    }

    #[test]
    fn should_track_v3_support() {
        let c = chain(ChainType::Evm as u8, 424242);
        assert!(!get_chain_supports_v3(&c));
        assert!(assert_chain_supports_v3(&c).is_err());
        add_chain_supports_v3(c);
        assert!(get_chain_supports_v3(&c));
        assert!(assert_chain_supports_v3(&c).is_ok());
    }
}
