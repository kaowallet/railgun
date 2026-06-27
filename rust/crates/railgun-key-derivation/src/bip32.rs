//! Port of `src/key-derivation/bip32.ts` — the custom BabyJubJub hardened
//! derivation (HMAC-SHA512 seeded with "babyjubjub seed"). This is NOT standard
//! BIP32 (secp256k1); only the hardened HMAC structure is shared.

use railgun_crypto::sha512_hmac_bytes;
use railgun_utils::BytesData;

const CURVE_SEED: &[u8] = b"babyjubjub seed";

/// A derived key node: 32-byte `chain_key` + 32-byte `chain_code`, hex-encoded
/// (matching the TS `KeyNode`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyNode {
    pub chain_key: String,
    pub chain_code: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DerivationError {
    #[error("Invalid derivation path")]
    InvalidPath,
}

fn is_valid_path(path: &str) -> bool {
    // ^m(/[0-9]+')+$
    let Some(rest) = path.strip_prefix('m') else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    let mut any = false;
    for seg in rest.split('/').skip(1) {
        any = true;
        let Some(num) = seg.strip_suffix('\'') else {
            return false;
        };
        if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    any
}

/// `getPathSegments`.
pub fn get_path_segments(path: &str) -> Result<Vec<u32>, DerivationError> {
    if !is_valid_path(path) {
        return Err(DerivationError::InvalidPath);
    }
    Ok(path
        .split('/')
        .skip(1)
        .map(|seg| seg.trim_end_matches('\'').parse::<u32>().unwrap())
        .collect())
}

/// `getMasterKeyFromSeed` — I = HMAC-SHA512("babyjubjub seed", seed).
pub fn get_master_key_from_seed(seed_hex: &str) -> KeyNode {
    let seed = railgun_utils::hex_string_to_bytes(seed_hex).expect("valid seed hex");
    let i = sha512_hmac_bytes(CURVE_SEED, &seed);
    KeyNode {
        chain_key: hex::encode(&i[..32]),
        chain_code: hex::encode(&i[32..]),
    }
}

/// `childKeyDerivationHardened`.
pub fn child_key_derivation_hardened(node: &KeyNode, index: u32, offset: u64) -> KeyNode {
    // padToLength(index + offset, 4) -> 8-hex (4-byte big-endian)
    let index_formatted = match railgun_utils::pad_to_length(
        &BytesData::Big((index as u64 + offset).into()),
        4,
        railgun_utils::Side::Left,
    ) {
        railgun_utils::Padded::Hex(s) => s,
        _ => unreachable!(),
    };
    // preImage = "00" + chainKey + indexFormatted  (hex string)
    let pre_image_hex = format!("00{}{}", node.chain_key, index_formatted);
    let key = railgun_utils::hex_string_to_bytes(&node.chain_code).expect("valid chain code");
    let data = railgun_utils::hex_string_to_bytes(&pre_image_hex).expect("valid preimage");
    let i = sha512_hmac_bytes(&key, &data);
    KeyNode {
        chain_key: hex::encode(&i[..32]),
        chain_code: hex::encode(&i[32..]),
    }
}

/// Default hardened offset used by `WalletNode`.
pub const HARDENED_OFFSET: u64 = 0x8000_0000;

#[cfg(test)]
mod tests {
    use super::*;

    // src/key-derivation/__tests__/bip32-babyjubjub.test.ts
    #[test]
    fn derive_master_key() {
        let vectors = [
            ("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4", "30d550bc2f61a7c206a1eba3704502da77f366fe69721265b3b7e2c7f05eeabc", "1fafc64161d1807e294cc9fded180ca2009aaaedf4cbd7359d4aaa3bb462f411"),
            ("d8c228addf9a9cfe5b7934223737815e2f709b3ac12b0c1b2aaec921e5d3a2e8aeea1df817af8159f981798dacd5a930a1fcd8570ba4845078c1b1d09fa060cb", "b37268d31994f4bbe422feffb3e1dcb35b61b76c0c1ebea2ded5fb0e37aa0809", "c544e07e1007d25b6a3a7ddba8f1e20c2c23c9baec8e9a6200dd6c3b2f8df6a5"),
            ("243c1266228fc9ff370d567ba4f805dfacc516375aecf4657cf870a4b551020d92d9b45a8181154f531c1358f742f42078a1620fca6251b1c4ec5fa6e1cf5c3a", "8bf4df70930efcf3ce0e8501464891837fa591b3b0924d9110b18152b8a85d37", "73eb04585b9ecc409c76a2949f099193be82198eb6abab1594be4138070f19d6"),
            ("87ec3e2ae9294cb5500698e6e6ee8357aa56222badae0e6b4150492c95ede7ddfca27c952afafb388453def93fac72f5d7e099debd79e85c2088f9b3e7a65df6", "5a7496d62dab5d3bef668bcff39eef421ea6b9544dba30805858989dc6611e36", "5c8f71501f449b499feddb89d865f15d35d24586b6447b7c9b7385d0bf217fd4"),
        ];
        for (seed, chain_code, chain_key) in vectors {
            let node = get_master_key_from_seed(seed);
            assert_eq!(node.chain_code, chain_code);
            assert_eq!(node.chain_key, chain_key);
        }
    }

    #[test]
    fn derive_child_keys() {
        let parent1 = KeyNode {
            chain_code: "30d550bc2f61a7c206a1eba3704502da77f366fe69721265b3b7e2c7f05eeabc".into(),
            chain_key: "1fafc64161d1807e294cc9fded180ca2009aaaedf4cbd7359d4aaa3bb462f411".into(),
        };
        assert_eq!(
            child_key_derivation_hardened(&parent1, 0, HARDENED_OFFSET),
            KeyNode {
                chain_code: "e8e6a1bbce8bab145fe8225435dc98d20d53bd32318ce3ede560b8feef3394a5"
                    .into(),
                chain_key: "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef"
                    .into(),
            }
        );
        assert_eq!(
            child_key_derivation_hardened(&parent1, 12, HARDENED_OFFSET),
            KeyNode {
                chain_code: "ff90a1dcb6531d437dc959b6e03f308dd4d9db7e489bdb30d8b4b1894a9e1344"
                    .into(),
                chain_key: "9606ae0c844601e0af4d518dce577983ad756dea08726d92c080ed2ca3f5f31d"
                    .into(),
            }
        );
        let parent2 = KeyNode {
            chain_code: "b37268d31994f4bbe422feffb3e1dcb35b61b76c0c1ebea2ded5fb0e37aa0809".into(),
            chain_key: "c544e07e1007d25b6a3a7ddba8f1e20c2c23c9baec8e9a6200dd6c3b2f8df6a5".into(),
        };
        assert_eq!(
            child_key_derivation_hardened(&parent2, 1, HARDENED_OFFSET),
            KeyNode {
                chain_code: "30c3769638ef70c9179a7b18a507318d2353831c2d7990056334cbf14ed4a2cf"
                    .into(),
                chain_key: "0b20d68e515add21c2686d88b8ae02d82912741ed66cb776b6a2eec628ce5fef"
                    .into(),
            }
        );
    }

    #[test]
    fn parse_path_segments() {
        assert_eq!(get_path_segments("m/0'/1'/1'").unwrap(), vec![0, 1, 1]);
        assert_eq!(get_path_segments("m/12'/0'/15'").unwrap(), vec![12, 0, 15]);
        assert_eq!(get_path_segments("m/1'/91'/12'").unwrap(), vec![1, 91, 12]);
        for invalid in ["m/0/0", "railgun", "m/0'/0'/x"] {
            assert_eq!(
                get_path_segments(invalid),
                Err(DerivationError::InvalidPath)
            );
        }
    }
}
