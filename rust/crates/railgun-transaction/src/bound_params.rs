//! Port of `src/transaction/bound-params.ts`.
//!
//! Bound-params hashing: ABI-encode the bound-params tuple exactly as ethers'
//! `defaultAbiCoder` does, keccak256 it, then reduce mod the SNARK prime.

use num_bigint::BigUint;
use railgun_crypto::keccak256_bytes;
use railgun_utils::hex_string_to_bytes;

use crate::abi::{encode, AbiValue};

/// BN254 scalar field modulus == RAILGUN's `SNARK_PRIME`.
fn snark_prime() -> BigUint {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("valid SNARK_PRIME")
}

/// One V2 commitment-ciphertext entry.
///
/// `ciphertext` is `bytes32[4]`; the four `String`s are hex (with or without 0x).
/// `blinded_*_viewing_key` are `bytes32` hex. `annotation_data` / `memo` are
/// arbitrary-length `bytes` hex.
#[derive(Clone, Debug)]
pub struct CommitmentCiphertextV2 {
    pub ciphertext: [String; 4],
    pub blinded_sender_viewing_key: String,
    pub blinded_receiver_viewing_key: String,
    pub annotation_data: String,
    pub memo: String,
}

/// V2 bound params (matches `BoundParamsStruct`).
#[derive(Clone, Debug)]
pub struct BoundParamsV2 {
    pub tree_number: u16,
    pub min_gas_price: BigUint,
    pub unshield: u8,
    pub chain_id: BigUint,
    /// 20-byte address hex.
    pub adapt_contract: String,
    /// 32-byte hex.
    pub adapt_params: String,
    pub commitment_ciphertext: Vec<CommitmentCiphertextV2>,
}

fn bytes32_value(hex: &str) -> AbiValue {
    let bytes = hex_string_to_bytes(hex).expect("valid hex");
    AbiValue::bytes32(&bytes)
}

fn dynamic_bytes_value(hex: &str) -> AbiValue {
    let bytes = hex_string_to_bytes(hex).expect("valid hex");
    AbiValue::Bytes(bytes)
}

fn address_value(hex: &str) -> AbiValue {
    let bytes = hex_string_to_bytes(hex).expect("valid hex");
    AbiValue::address(&bytes)
}

impl CommitmentCiphertextV2 {
    fn to_abi(&self) -> AbiValue {
        // tuple(bytes32[4] ciphertext, bytes32 blindedSenderViewingKey,
        //       bytes32 blindedReceiverViewingKey, bytes annotationData, bytes memo)
        // bytes32[4] is a static array of 4 words, encoded inline as a tuple of 4 words.
        let ciphertext =
            AbiValue::Tuple(self.ciphertext.iter().map(|h| bytes32_value(h)).collect());
        AbiValue::Tuple(vec![
            ciphertext,
            bytes32_value(&self.blinded_sender_viewing_key),
            bytes32_value(&self.blinded_receiver_viewing_key),
            dynamic_bytes_value(&self.annotation_data),
            dynamic_bytes_value(&self.memo),
        ])
    }
}

/// `hashBoundParamsV2`.
pub fn hash_bound_params_v2(bp: &BoundParamsV2) -> BigUint {
    let commitment_ciphertext = AbiValue::Array(
        bp.commitment_ciphertext
            .iter()
            .map(|c| c.to_abi())
            .collect(),
    );

    // tuple(uint16 treeNumber, uint48 minGasPrice, uint8 unshield, uint64 chainID,
    //       address adaptContract, bytes32 adaptParams,
    //       tuple(...)[] commitmentCiphertext)
    let bound_params = AbiValue::Tuple(vec![
        AbiValue::uint(&BigUint::from(bp.tree_number)),
        AbiValue::uint(&bp.min_gas_price),
        AbiValue::uint(&BigUint::from(bp.unshield)),
        AbiValue::uint(&bp.chain_id),
        address_value(&bp.adapt_contract),
        bytes32_value(&bp.adapt_params),
        commitment_ciphertext,
    ]);

    let encoded = encode(&[bound_params]);
    let hashed = keccak256_bytes(&encoded);
    BigUint::from_bytes_be(&hashed) % snark_prime()
}

// ---- V3 ----

/// One V3 commitment-ciphertext entry.
#[derive(Clone, Debug)]
pub struct CommitmentCiphertextV3 {
    /// arbitrary-length `bytes` hex.
    pub ciphertext: String,
    /// 32-byte hex.
    pub blinded_sender_viewing_key: String,
    /// 32-byte hex.
    pub blinded_receiver_viewing_key: String,
}

/// V3 "global" bound params.
#[derive(Clone, Debug)]
pub struct GlobalBoundParamsV3 {
    pub min_gas_price: BigUint,
    pub chain_id: BigUint,
    /// `bytes` hex.
    pub sender_ciphertext: String,
    /// 20-byte address hex.
    pub to: String,
    /// `bytes` hex.
    pub data: String,
}

/// V3 bound params (matches `PoseidonMerkleVerifier.BoundParamsStruct`).
#[derive(Clone, Debug)]
pub struct BoundParamsV3 {
    pub tree_number: u32,
    pub commitment_ciphertext: Vec<CommitmentCiphertextV3>,
    pub global: GlobalBoundParamsV3,
}

impl CommitmentCiphertextV3 {
    fn to_abi(&self) -> AbiValue {
        // tuple(bytes ciphertext, bytes32 blindedSenderViewingKey,
        //       bytes32 blindedReceiverViewingKey)
        AbiValue::Tuple(vec![
            dynamic_bytes_value(&self.ciphertext),
            bytes32_value(&self.blinded_sender_viewing_key),
            bytes32_value(&self.blinded_receiver_viewing_key),
        ])
    }
}

/// `hashBoundParamsV3`.
pub fn hash_bound_params_v3(bp: &BoundParamsV3) -> BigUint {
    // local = tuple(uint32 treeNumber, tuple(...)[] commitmentCiphertext)
    let commitment_ciphertext = AbiValue::Array(
        bp.commitment_ciphertext
            .iter()
            .map(|c| c.to_abi())
            .collect(),
    );
    let local = AbiValue::Tuple(vec![
        AbiValue::uint(&BigUint::from(bp.tree_number)),
        commitment_ciphertext,
    ]);

    // global = tuple(uint128 minGasPrice, uint128 chainID, bytes senderCiphertext,
    //                address to, bytes data)
    let global = AbiValue::Tuple(vec![
        AbiValue::uint(&bp.global.min_gas_price),
        AbiValue::uint(&bp.global.chain_id),
        dynamic_bytes_value(&bp.global.sender_ciphertext),
        address_value(&bp.global.to),
        dynamic_bytes_value(&bp.global.data),
    ]);

    // outermost: tuple(local, global)
    let bound_params = AbiValue::Tuple(vec![local, global]);

    let encoded = encode(&[bound_params]);
    let hashed = keccak256_bytes(&encoded);
    BigUint::from_bytes_be(&hashed) % snark_prime()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper mirroring TS `ByteUtils.formatToByteLength('00', UINT_256)` etc.
    fn zero_word() -> String {
        "0".repeat(64)
    }

    // KAV from transaction-erc20.test.ts: 'Should hash bound parameters for V2'
    #[test]
    fn hash_bound_params_v2_kav() {
        let bp = BoundParamsV2 {
            tree_number: 0,
            min_gas_price: BigUint::from(3000u32),
            unshield: 0,
            // chain.id in the TS test is 1 (HARDHAT chain id used as `chain.id`).
            chain_id: BigUint::from(1u32),
            adapt_contract: "00".repeat(20),
            adapt_params: zero_word(),
            commitment_ciphertext: vec![CommitmentCiphertextV2 {
                ciphertext: [zero_word(), zero_word(), zero_word(), zero_word()],
                blinded_sender_viewing_key: zero_word(),
                blinded_receiver_viewing_key: zero_word(),
                // hexlify('00') => "00"
                annotation_data: "00".to_string(),
                memo: "00".to_string(),
            }],
        };
        let hashed = hash_bound_params_v2(&bp);
        let expected = BigUint::parse_bytes(
            b"7297316625290769368067090402207718021912518614094704642142032948132837136470",
            10,
        )
        .unwrap();
        assert_eq!(hashed, expected);
    }

    // KAV from transaction-erc20.test.ts: 'Should hash bound parameters for V3'
    #[test]
    fn hash_bound_params_v3_kav() {
        let bp = BoundParamsV3 {
            tree_number: 0,
            commitment_ciphertext: vec![CommitmentCiphertextV3 {
                // 4 * 32-byte zero words joined => 128 zero bytes of `bytes`.
                ciphertext: "00".repeat(128),
                blinded_receiver_viewing_key: zero_word(),
                blinded_sender_viewing_key: zero_word(),
            }],
            global: GlobalBoundParamsV3 {
                min_gas_price: BigUint::from(1u32),
                chain_id: BigUint::from(1u32),
                // '0x' => empty bytes
                sender_ciphertext: String::new(),
                // ZERO_ADDRESS
                to: "00".repeat(20),
                data: String::new(),
            },
        };
        let hashed = hash_bound_params_v3(&bp);
        let expected = BigUint::parse_bytes(
            b"1042853354636355096886642476862765074115784833677897463840889848516202023630",
            10,
        )
        .unwrap();
        assert_eq!(hashed, expected);
    }
}
