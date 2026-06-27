//! Integration KAV ported from
//! `src/validation/__tests__/extract-transaction-data.test.ts`
//! ("[V2] Should extract railgun transaction data").
//!
//! The TS expectation is:
//!   railgunTxid: 18759632f78e7ce85cbd04769b98c8a5436d5144ff9f96f9743eeab43864f98a
//!   firstCommitment: 0x2d19ecebdbe7eaf95d5e36841de3df4fa84f4d978f00aea308f0edb3deb19586
//!   firstCommitmentNotePublicKey: 5359614152058359376498286929274915634684900503457035822149709199778311325149
//!
//! This test exercises the fully-ported path: ABI-decode the `transact`
//! calldata into `TransactionStruct[]`, format the V2 commitment ciphertext,
//! ECDH shared key + AES-GCM decrypt the receiver note, and derive its
//! note-public-key + the first commitment.
//!
//! The `railgunTxid` field itself is NOT asserted here: it requires a 13-input
//! Poseidon hash which the `light-poseidon` 0.3 backend cannot compute (caps at
//! 12 inputs). See `railgun_txid::tests::railgun_txid_kav_v2` (ignored) and the
//! crate-status blockers.

use alloy::sol_types::SolCall;
use num_bigint::BigUint;
use railgun_contracts::abi::transactCall;
use railgun_contracts::events::format_commitment_ciphertext_v2;
use railgun_engine::extract_transaction_data::extract_npk_from_commitment_ciphertext_v2;
use railgun_key_derivation::{derive_nodes, AddressData};
use railgun_models::engine_types::Chain;
use railgun_note::transact_note::Erc20TokenDataGetter;

const MNEMONIC: &str = "test test test test test test test test test test test junk";

// The full `transact` calldata from the TS KAV.
const CALLDATA_HEX: &str = "0xd8ae136a0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014fceeac99eb8419a2796d1958fc2050d489bf5a3eb170ef16a667060344ba900000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000002c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000105802951a46d9e999151eb0eb9e4c7c1260b7ee88539011c207dc169c4dd17ee00000000000000000000000000000000000000000000000000000000000000022d19ecebdbe7eaf95d5e36841de3df4fa84f4d978f00aea308f0edb3deb1958600b6efe9fcfa0057732d69ea826bb0b4249ed1f921e139eaa3aa6ea2ff0196fa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001c0f5c40b3a54da7510b4d04c25c3995ed107543dfa63c7e69f544b7a7f83e39cd9a1fc243639f8d9fbac6ac7f7744dc2b1fc49c9fce02cb93ce60536668e905bdd47813f3b05b8b5f29c4c7dfaf0bd2a3d9f143442dfed60bd8d63705031f12c68acd866af2b2f986a6468fd46b76730faebed97a29e654a96f2d1d18c964553150d1f957d2d57c0410a8d34c12433b67453c04d0edf89a437366ecee156e2da290d1f957d2d57c0410a8d34c12433b67453c04d0edf89a437366ecee156e2da2900000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000003ef2b9485d38127f76d7955f4c216bf8acf0c54ca8b05c6a90d051fa782a677d719a5cdb5269b184d038d3c6b238575efc42253c5b360b8e361f08b0b08798000000000000000000000000000000000000000000000000000000000000000000000744f5b8a005f417a594cdd783852c1e0979cc5010704f13c52de3377d0cad242957f9331392b03a10ec6354e1bb7f952b6056a0d071c839acf6c845bd8e248908c4cbe7c0d1884f0d5a7a5cad42a7fcdbddb25acbc5f9d444c625d2b0c63cc48945739b05749ef8c430e0c5bbd0c02056b0e2f106c9fcba307a291e4ba41a907bc910387ac5698108ef609bb441f44e25dcfcf2def6c174ae4c7108441cae9d7bc910387ac5698108ef609bb441f44e25dcfcf2def6c174ae4c7108441cae9d00000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000003e7f6aaaa49235ea17f5f90c73e2a0cf615bc392a8a52a29d262923059c165cd528f922b2b00c33a1e667a5ecee2086cf014a40705578552ab55413a9d4cc500000000000000000000000000000000000000000000000000000000000000000000";

fn wallet_address_data() -> (AddressData, [u8; 32]) {
    let nodes = derive_nodes(MNEMONIC, 0, "");
    let viewing = nodes.viewing.get_viewing_key_pair();
    let spending_public_key = nodes.spending.get_spending_key_pair().pubkey;

    // master_public_key = poseidon(spending_pubkey.x, spending_pubkey.y, nullifying_key)
    let nullifying_key = railgun_crypto::poseidon_hex(&[&hex::encode(viewing.private_key)]);
    let nullifying_key = railgun_utils::hex_to_bigint(&nullifying_key);
    let master_public_key = railgun_key_derivation::WalletNode::get_master_public_key(
        &spending_public_key,
        &nullifying_key,
    );

    let address_data = AddressData {
        master_public_key,
        viewing_public_key: viewing.pubkey.to_vec(),
        chain: None,
        version: None,
    };
    (address_data, viewing.private_key)
}

/// KAV: ABI-decode the calldata, format the V2 commitment ciphertext, ECDH +
/// AES-GCM decrypt the first receiver note, and assert its note-public-key + the
/// first commitment hash match the TS expectation.
///
/// This validates the entire fully-ported extract path *except* the 13-input
/// Poseidon railgun-txid (see module docs + crate blockers).
#[test]
fn extract_v2_first_commitment_npk_and_commitment() {
    let chain = Chain {
        chain_type: 0,
        id: 31337,
    };
    let (address_data, viewing_private_key) = wallet_address_data();
    let getter = Erc20TokenDataGetter;

    let calldata = railgun_utils::hex_string_to_bytes(CALLDATA_HEX).expect("valid calldata");

    // 1. ABI-decode `transact(TransactionStruct[])`.
    let decoded = transactCall::abi_decode(&calldata).expect("decode transact calldata");
    assert_eq!(decoded._transactions.len(), 1, "expected one railgun tx");
    let tx = &decoded._transactions[0];

    // 2. First commitment hash.
    let first_commitment = railgun_utils::prefix_0x(&hex::encode(tx.commitments[0].0));
    assert_eq!(
        first_commitment, "0x2d19ecebdbe7eaf95d5e36841de3df4fa84f4d978f00aea308f0edb3deb19586",
        "first commitment mismatch",
    );

    // 3. Format ciphertext + decrypt receiver note → note-public-key.
    let cc = format_commitment_ciphertext_v2(&tx.boundParams.commitmentCiphertext[0]);
    let npk = extract_npk_from_commitment_ciphertext_v2(
        &chain,
        &cc,
        &viewing_private_key,
        &address_data,
        &getter,
    );

    let expected_npk = BigUint::parse_bytes(
        b"5359614152058359376498286929274915634684900503457035822149709199778311325149",
        10,
    )
    .unwrap();
    assert_eq!(
        npk,
        Some(expected_npk),
        "first commitment note public key mismatch"
    );
}
