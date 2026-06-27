//! Ported known-answer-vector tests from
//! `src/solutions/__tests__/complex-solutions.test.ts` and `simple-solutions.test.ts`.

use num_bigint::BigUint;
use railgun_key_derivation::{decode_address, AddressData};
use railgun_models::formatted_types::{CommitmentType, OutputType, SpendTxid, TokenData};
use railgun_models::txo_types::TXO;
use railgun_models::wallet_types::TreeBalance;
use railgun_note::{get_token_data_erc20, TransactNote};
use railgun_solutions::complex_solutions::{
    create_spending_solutions_for_value, find_next_solution_batch, next_nullifier_target,
    should_add_more_utxos_for_solution_batch, SolutionsError,
};
use railgun_solutions::nullifiers::{
    is_valid_nullifier_count, VALID_INPUT_COUNTS, VALID_OUTPUT_COUNTS,
};
use railgun_solutions::spending_group_extractor::extract_spending_solution_groups_data;
use railgun_solutions::utxos::{filter_zero_utxos, sort_utxos_by_ascending_value, Txo};

const ADDR1: &str = "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca";
const ADDR2: &str = "0zk1qyqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkunpd9kxwatw8qqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkcsu8tp";
const ADDR3: &str = "0zk1q8hxknrs97q8pjxaagwthzc0df99rzmhl2xnlxmgv9akv32sua0kfrv7j6fe3z53llhxknrs97q8pjxaagwthzc0df99rzmhl2xnlxmgv9akv32sua0kg0zpzts";

const MOCK_POSITION: u32 = 2;
const TOKEN_ADDRESS: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

fn token_data() -> TokenData {
    get_token_data_erc20(TOKEN_ADDRESS)
}

fn address1() -> AddressData {
    decode_address(ADDR1).unwrap()
}
fn address2() -> AddressData {
    decode_address(ADDR2).unwrap()
}
fn address3() -> AddressData {
    decode_address(ADDR3).unwrap()
}

fn create_mock_note(address_data: AddressData, value: u64) -> TransactNote {
    TransactNote::create_transfer(
        address_data,
        None,
        BigUint::from(value),
        token_data(),
        false, // show_sender_address_to_recipient
        OutputType::Transfer,
        None, // memo_text
        None, // wallet_source
        None, // note_random (random)
        None, // injected_sender_random
    )
    .unwrap()
}

fn create_mock_txo(txid: &str, value: u64) -> Txo {
    let note = create_mock_note(address1(), value);
    TXO {
        txid: txid.to_string(),
        note,
        timestamp: None,
        position: MOCK_POSITION,
        tree: 0,
        spendtxid: SpendTxid::Unspent(false),
        pois_per_list: None,
        blinded_commitment: None,
        transact_creation_railgun_txid: None,
        commitment_type: CommitmentType::TransactCommitmentV3,
        nullifier: "00".repeat(32),
        block_number: 100,
    }
}

fn txids(utxos: &[Txo]) -> Vec<String> {
    utxos.iter().map(|u| u.txid.clone()).collect()
}

fn big(v: u64) -> BigUint {
    BigUint::from(v)
}

#[test]
fn should_get_valid_next_nullifier_targets() {
    assert_eq!(next_nullifier_target(0), Some(1));
    assert_eq!(next_nullifier_target(1), Some(2));
    assert_eq!(next_nullifier_target(2), Some(3));
    assert_eq!(next_nullifier_target(3), Some(4));
    assert_eq!(next_nullifier_target(4), Some(5));
    assert_eq!(next_nullifier_target(5), Some(6));
    assert_eq!(next_nullifier_target(6), Some(7));
    assert_eq!(next_nullifier_target(7), Some(8));
    assert_eq!(next_nullifier_target(8), Some(9));
    assert_eq!(next_nullifier_target(9), Some(10));
    assert_eq!(next_nullifier_target(10), None);
}

#[test]
fn should_determine_whether_to_add_utxos_to_solution_batch() {
    let low = big(999);
    let exact = big(1000);
    let high = big(1001);
    let total_required = big(1000);

    // Hit exact total amount. Valid. [ALL SET]
    assert!(!should_add_more_utxos_for_solution_batch(
        1,
        5,
        &exact,
        &total_required
    ));
    // Higher than total amount. Valid. [ALL SET]
    assert!(!should_add_more_utxos_for_solution_batch(
        3,
        5,
        &high,
        &total_required
    ));
    // Lower than total amount. Valid nullifier amount. [NEED MORE]
    assert!(should_add_more_utxos_for_solution_batch(
        3,
        8,
        &low,
        &total_required
    ));
    // Lower than total amount. Invalid nullifier amount. Next is not reachable. [ALL SET]
    assert!(!should_add_more_utxos_for_solution_batch(
        10,
        11,
        &low,
        &total_required
    ));
}

#[test]
fn should_create_next_solution_batch_from_utxos_6() {
    let tree_balance = TreeBalance {
        balance: big(150),
        token_data: token_data(),
        utxos: vec![
            create_mock_txo("a", 30),
            create_mock_txo("b", 40),
            create_mock_txo("c", 50),
            create_mock_txo("d", 10),
            create_mock_txo("e", 20),
            create_mock_txo("f", 0),
        ],
    };

    let mut utxos_for_sort = tree_balance.utxos.clone();
    assert_eq!(txids(&utxos_for_sort), vec!["a", "b", "c", "d", "e", "f"]);

    let filtered_zeroes = filter_zero_utxos(&utxos_for_sort);
    assert_eq!(txids(&filtered_zeroes), vec!["a", "b", "c", "d", "e"]);

    sort_utxos_by_ascending_value(&mut utxos_for_sort);
    assert_eq!(txids(&utxos_for_sort), vec!["f", "d", "e", "a", "b", "c"]);

    // More than balance. No excluded txids.
    let batch1 = find_next_solution_batch(&tree_balance, &big(180), &[]).unwrap();
    assert_eq!(txids(&batch1), vec!["d", "e", "a", "b", "c"]);

    // More than balance. Exclude txids.
    let excl = vec!["a-2".to_string(), "b-2".to_string()];
    let batch2 = find_next_solution_batch(&tree_balance, &big(180), &excl).unwrap();
    assert_eq!(txids(&batch2), vec!["d", "e", "c"]);

    // Less than balance. Exclude txids.
    let batch3 = find_next_solution_batch(&tree_balance, &big(9), &excl).unwrap();
    assert_eq!(txids(&batch3), vec!["d"]);

    // Less than balance. Most optimal is 4 UTXOs to consolidate balances.
    let batch4 = find_next_solution_batch(&tree_balance, &big(90), &[]).unwrap();
    assert_eq!(txids(&batch4), vec!["d", "e", "a", "b"]);

    // No utxos available.
    let excl5 = vec![
        "a-2".to_string(),
        "b-2".to_string(),
        "c-2".to_string(),
        "d-2".to_string(),
        "e-2".to_string(),
        "f-2".to_string(),
    ];
    let batch5 = find_next_solution_batch(&tree_balance, &big(120), &excl5);
    assert!(batch5.is_none());

    // Only a 0 txo available.
    let excl6 = vec![
        "a-2".to_string(),
        "b-2".to_string(),
        "c-2".to_string(),
        "d-2".to_string(),
        "e-2".to_string(),
    ];
    let batch6 = find_next_solution_batch(&tree_balance, &big(120), &excl6);
    assert!(batch6.is_none());
}

#[test]
fn should_create_next_solution_batch_from_utxos_11() {
    let tree_balance = TreeBalance {
        balance: big(660),
        token_data: token_data(),
        utxos: vec![
            create_mock_txo("a", 30),
            create_mock_txo("b", 40),
            create_mock_txo("c", 50),
            create_mock_txo("d", 10),
            create_mock_txo("e", 20),
            create_mock_txo("f", 60),
            create_mock_txo("g", 70),
            create_mock_txo("h", 80),
            create_mock_txo("i", 90),
            create_mock_txo("j", 100),
            create_mock_txo("k", 110),
        ],
    };

    // Case 1: More than balance. No excluded txids. Only 10 UTXOs per batch (no "k").
    let batch1 = find_next_solution_batch(&tree_balance, &big(500), &[]).unwrap();
    assert_eq!(
        txids(&batch1),
        vec!["d", "e", "a", "b", "c", "f", "g", "h", "i", "j"]
    );

    // Case 2: Less than balance. Exclude smallest utxo.
    let excl = vec!["d-2".to_string()];
    let batch2 = find_next_solution_batch(&tree_balance, &big(58), &excl).unwrap();
    assert_eq!(txids(&batch2), vec!["e", "a", "b"]);
}

#[test]
fn should_create_spending_solution_groups_for_various_outputs() {
    let tree_balance0 = TreeBalance {
        balance: big(20),
        token_data: token_data(),
        utxos: vec![
            create_mock_txo("aa", 20),
            create_mock_txo("ab", 0),
            create_mock_txo("ac", 0),
        ],
    };
    let tree_balance1 = TreeBalance {
        balance: big(450),
        token_data: token_data(),
        utxos: vec![
            create_mock_txo("a", 30),
            create_mock_txo("b", 40),
            create_mock_txo("c", 50),
            create_mock_txo("d", 10),
            create_mock_txo("e", 20),
            create_mock_txo("f", 60),
            create_mock_txo("g", 70),
            create_mock_txo("h", 80),
            create_mock_txo("i", 90),
            create_mock_txo("j", 0),
        ],
    };
    let sorted_tree_balances = vec![tree_balance0, tree_balance1];

    // Case 0.
    let mut remaining_outputs0 = vec![create_mock_note(address1(), 0)];
    let groups0 = create_spending_solutions_for_value(
        &sorted_tree_balances,
        &mut remaining_outputs0,
        &mut vec![],
        false,
    )
    .unwrap();
    // Ensure the 0n output was removed.
    assert!(remaining_outputs0.is_empty());
    let extracted0 = extract_spending_solution_groups_data(&groups0);
    assert_eq!(extracted0.len(), 1);
    assert_eq!(
        extracted0[0].utxo_txids,
        vec!["0x0000000000000000000000000000000000000000000000000000000000000000"]
    );
    assert_eq!(extracted0[0].utxo_values, vec![big(0)]);
    assert_eq!(extracted0[0].output_values, vec![big(0)]);
    assert_eq!(extracted0[0].output_address_datas.len(), 1);
    assert_eq!(
        extracted0[0].output_address_datas[0].master_public_key,
        big(0)
    );
    assert_eq!(
        extracted0[0].output_address_datas[0].viewing_public_key,
        vec![0u8; 32]
    );
    assert_eq!(extracted0[0].output_address_datas[0].version, Some(1));
    assert_eq!(extracted0[0].token_data, token_data());

    // Case 1.
    let mut remaining_outputs1 = vec![
        create_mock_note(address1(), 79),
        create_mock_note(address2(), 70),
        create_mock_note(address3(), 60),
    ];
    let groups1 = create_spending_solutions_for_value(
        &sorted_tree_balances,
        &mut remaining_outputs1,
        &mut vec![],
        false,
    )
    .unwrap();
    // 79n output removed; 69n = 70n - 1n change from secondary output.
    let rem1: Vec<BigUint> = remaining_outputs1.iter().map(|n| n.value.clone()).collect();
    assert_eq!(rem1, vec![big(69), big(60)]);
    let extracted1 = extract_spending_solution_groups_data(&groups1);
    assert_eq!(extracted1.len(), 2);

    assert_eq!(extracted1[0].utxo_txids, vec!["aa"]);
    assert_eq!(extracted1[0].utxo_values, vec![big(20)]);
    assert_eq!(extracted1[0].output_values, vec![big(20)]);
    assert_eq!(extracted1[0].output_address_datas, vec![address1()]);

    assert_eq!(extracted1[1].utxo_txids, vec!["d", "e", "a"]);
    assert_eq!(extracted1[1].utxo_values, vec![big(10), big(20), big(30)]);
    assert_eq!(extracted1[1].output_values, vec![big(59), big(1)]);
    assert_eq!(
        extracted1[1].output_address_datas,
        vec![address1(), address2()]
    );

    // Case 2.
    let mut remaining_outputs2 = vec![
        create_mock_note(address1(), 150),
        create_mock_note(address2(), 70),
        create_mock_note(address3(), 60),
    ];
    let groups2 = create_spending_solutions_for_value(
        &sorted_tree_balances,
        &mut remaining_outputs2,
        &mut vec![],
        false,
    )
    .unwrap();
    let rem2: Vec<BigUint> = remaining_outputs2.iter().map(|n| n.value.clone()).collect();
    assert_eq!(rem2, vec![big(50), big(60)]);
    let extracted2 = extract_spending_solution_groups_data(&groups2);
    assert_eq!(extracted2.len(), 2);

    assert_eq!(extracted2[0].utxo_txids, vec!["aa"]);
    assert_eq!(extracted2[0].utxo_values, vec![big(20)]);
    assert_eq!(extracted2[0].output_values, vec![big(20)]);
    assert_eq!(extracted2[0].output_address_datas, vec![address1()]);

    assert_eq!(extracted2[1].utxo_txids, vec!["d", "e", "a", "b", "c"]);
    assert_eq!(
        extracted2[1].utxo_values,
        vec![big(10), big(20), big(30), big(40), big(50)]
    );
    assert_eq!(extracted2[1].output_values, vec![big(130), big(20)]);
    assert_eq!(
        extracted2[1].output_address_datas,
        vec![address1(), address2()]
    );

    // Case 3. totalRequired exceeds tree balance => Balance Too Low.
    let mut remaining_outputs3 = vec![create_mock_note(address1(), 500)];
    let err = create_spending_solutions_for_value(
        &sorted_tree_balances,
        &mut remaining_outputs3,
        &mut vec![],
        false,
    )
    .unwrap_err();
    assert!(matches!(err, SolutionsError::BalanceTooLow));
}

#[test]
fn valid_input_output_counts_kav() {
    assert_eq!(VALID_INPUT_COUNTS, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    assert_eq!(VALID_OUTPUT_COUNTS, [1, 2, 3, 4, 5]);
    assert!(is_valid_nullifier_count(1));
    assert!(is_valid_nullifier_count(10));
    assert!(!is_valid_nullifier_count(0));
    assert!(!is_valid_nullifier_count(11));
}
