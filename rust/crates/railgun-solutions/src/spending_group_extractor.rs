//! Port of `src/solutions/spending-group-extractor.ts`.

use num_bigint::BigUint;
use railgun_key_derivation::{encode_address, AddressData};
use railgun_models::formatted_types::{TokenData, TokenType};
use railgun_models::txo_types::SpendingSolutionGroup;
use railgun_note::{get_token_data_hash, TransactNote};

/// `ExtractedSpendingSolutionGroupsData`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractedSpendingSolutionGroupsData {
    pub utxo_txids: Vec<String>,
    pub utxo_values: Vec<BigUint>,
    pub output_values: Vec<BigUint>,
    pub output_address_datas: Vec<AddressData>,
    pub token_data: TokenData,
}

/// `SerializedSpendingSolutionGroupsData`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerializedSpendingSolutionGroupsData {
    pub utxo_txids: Vec<String>,
    pub utxo_values: Vec<String>,
    pub output_values: Vec<String>,
    pub output_addresses: Vec<String>,
    pub token_address: String,
    pub token_type: TokenType,
    pub token_sub_id: String,
    pub token_hash: String,
}

pub fn serialize_extracted_spending_solution_groups_data(
    datas: &[ExtractedSpendingSolutionGroupsData],
) -> Vec<SerializedSpendingSolutionGroupsData> {
    datas
        .iter()
        .map(|data| SerializedSpendingSolutionGroupsData {
            utxo_txids: data.utxo_txids.clone(),
            utxo_values: data
                .utxo_values
                .iter()
                .map(|v| v.to_str_radix(10))
                .collect(),
            output_values: data
                .output_values
                .iter()
                .map(|v| v.to_str_radix(10))
                .collect(),
            output_addresses: data
                .output_address_datas
                .iter()
                .map(encode_address)
                .collect(),
            token_address: data.token_data.token_address.clone(),
            token_type: data.token_data.token_type,
            token_sub_id: data.token_data.token_sub_id.clone(),
            token_hash: get_token_data_hash(&data.token_data),
        })
        .collect()
}

pub fn extract_spending_solution_groups_data(
    spending_solution_groups: &[SpendingSolutionGroup<TransactNote>],
) -> Vec<ExtractedSpendingSolutionGroupsData> {
    spending_solution_groups
        .iter()
        .map(|group| ExtractedSpendingSolutionGroupsData {
            utxo_txids: group.utxos.iter().map(|utxo| utxo.txid.clone()).collect(),
            utxo_values: group
                .utxos
                .iter()
                .map(|utxo| utxo.note.value.clone())
                .collect(),
            output_values: group
                .token_outputs
                .iter()
                .map(|note| note.value.clone())
                .collect(),
            output_address_datas: group
                .token_outputs
                .iter()
                .map(|note| note.receiver_address_data.clone())
                .collect(),
            token_data: group.token_data.clone(),
        })
        .collect()
}
