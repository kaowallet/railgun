//! End-to-end: register a wallet, sync a self-transfer commitment from a fixture
//! event source, read the balance, then spend (nullify) and watch it drop to zero.
//! No network — `QuickSyncEvents` is an in-memory fixture (exactly how a real app
//! would inject its own RPC/indexer).

use async_trait::async_trait;
use num_bigint::BigUint;
use railgun::crypto::{get_note_blinding_keys, get_shared_symmetric_key};
use railgun::engine::EngineError;
use railgun::key_derivation::AddressData;
use railgun::models::event_types::{AccumulatedEvents, CommitmentEvent};
use railgun::models::formatted_types::{
    Commitment, CommitmentCiphertextV2, Nullifier, OutputType, TransactCommitmentV2,
};
use railgun::note::{get_token_data_erc20, get_token_data_hash, TransactNote};
use railgun::prelude::*;
use railgun::utils::{format_to_byte_length, hexlify, n_to_hex, ByteLength, BytesData};

const TOKEN: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";

/// In-memory event source — what a real app would back with its own RPC/indexer.
struct FixtureEvents(AccumulatedEvents);

#[async_trait]
impl QuickSyncEvents for FixtureEvents {
    async fn quick_sync_events(
        &self,
        _txid_version: TXIDVersion,
        _chain: &Chain,
        _starting_block: u64,
    ) -> Result<AccumulatedEvents, EngineError> {
        Ok(self.0.clone())
    }
}

fn u256_hex(byte: &str) -> String {
    format_to_byte_length(
        &BytesData::Hex(byte.to_string()),
        ByteLength::Uint256,
        false,
    )
}

/// Build a genuinely-encrypted self-transfer commitment that `wallet` can decrypt.
fn self_transfer_commitment(wallet: &RailgunWallet<MemStore>, value: u32) -> Commitment {
    let address_keys = wallet.wallet.address_keys();
    let addr = AddressData {
        master_public_key: address_keys.master_public_key.clone(),
        viewing_public_key: address_keys.viewing_public_key.clone(),
        chain: None,
        version: None,
    };
    let note = TransactNote::create_transfer(
        addr.clone(),
        Some(addr.clone()),
        BigUint::from(value),
        get_token_data_erc20(TOKEN),
        false,
        OutputType::Transfer,
        None,
        Some("framework".to_string()),
        None,
        None,
    )
    .unwrap();
    let sender_random = note.sender_random.clone().unwrap();
    let vkp = wallet.wallet.get_viewing_key_pair();
    let recv_vpk: [u8; 32] = address_keys.viewing_public_key.clone().try_into().unwrap();
    let (blinded_sender, blinded_receiver) =
        get_note_blinding_keys(&vkp.pubkey, &recv_vpk, &note.random, &sender_random).unwrap();
    let shared_key = get_shared_symmetric_key(&vkp.private_key, &blinded_receiver).unwrap();
    let (ciphertext, memo, annotation_data) = note
        .encrypt_v2(
            TXIDVersion::V2_PoseidonMerkle,
            &shared_key,
            &address_keys.master_public_key,
            Some(&sender_random),
            &vkp.private_key,
        )
        .unwrap();

    Commitment::TransactCommitmentV2(TransactCommitmentV2 {
        hash: n_to_hex(&note.hash, ByteLength::Uint256, false),
        txid: u256_hex("00"),
        timestamp: None,
        block_number: 0,
        utxo_tree: 0,
        utxo_index: 0,
        railgun_txid: None,
        ciphertext: CommitmentCiphertextV2 {
            ciphertext,
            blinded_sender_viewing_key: hexlify(&BytesData::Bytes(blinded_sender.to_vec()), false),
            blinded_receiver_viewing_key: hexlify(
                &BytesData::Bytes(blinded_receiver.to_vec()),
                false,
            ),
            annotation_data,
            memo,
        },
    })
}

fn commitment_only_events(commitment: Commitment) -> AccumulatedEvents {
    AccumulatedEvents {
        commitment_events: vec![CommitmentEvent {
            txid: u256_hex("00"),
            tree_number: 0,
            start_position: 0,
            commitments: vec![commitment],
            block_number: 0,
        }],
        unshield_events: vec![],
        nullifier_events: vec![],
        railgun_transaction_events: None,
    }
}

#[tokio::test]
async fn sync_then_spend_updates_balance() {
    let mut db = Database::in_memory();
    let key = [0x11u8; 32];
    let mnemonic = Mnemonic::generate(128);
    let chain = Chain {
        chain_type: 0,
        id: 1,
    };
    let token_hash = get_token_data_hash(&get_token_data_erc20(TOKEN));

    let wallet = RailgunWallet::from_mnemonic(&mut db, &key, &mnemonic, 0, None).unwrap();
    let commitment = self_transfer_commitment(&wallet, 1000);

    let mut rg = Railgun::new(db, chain, TXIDVersion::V2_PoseidonMerkle);
    rg.add_wallet(wallet);

    // 1. Sync the received commitment -> balance reflects it.
    rg.sync(&FixtureEvents(commitment_only_events(commitment)), 0)
        .await
        .unwrap();
    let balances = rg.token_balances(0).unwrap();
    assert_eq!(balances.get(&token_hash), Some(&BigUint::from(1000u32)));

    // 2. Spend it: the note's nullifier appears on chain -> excluded from balance.
    let nullifying_key = rg.wallet(0).unwrap().wallet.get_nullifying_key().clone();
    let nullifier = n_to_hex(
        &TransactNote::get_nullifier(&nullifying_key, 0),
        ByteLength::Uint256,
        false,
    );
    let spend_events = AccumulatedEvents {
        commitment_events: vec![],
        unshield_events: vec![],
        nullifier_events: vec![Nullifier {
            nullifier,
            tree_number: 0,
            txid: u256_hex("00"),
            block_number: 0,
        }],
        railgun_transaction_events: None,
    };
    rg.sync(&FixtureEvents(spend_events), 0).await.unwrap();

    let balances_after = rg.token_balances(0).unwrap();
    assert_eq!(
        balances_after.get(&token_hash),
        None,
        "spent note must be excluded"
    );
}
