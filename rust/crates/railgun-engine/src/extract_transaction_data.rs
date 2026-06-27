//! Port of `src/validation/extract-transaction-data.ts` +
//! `extract-transaction-data-v2.ts` (+ V3 dispatch).
//!
//! Decodes a `transact` / `relay` contract calldata into `TransactionStruct[]`,
//! decrypts the first commitment's receiver note, and derives the railgun txid +
//! ERC20 amount map. V2 is fully ported (the KAV path); V3 dispatch is provided
//! but its decode is tracked as a TODO (V3 batched ciphertext decode needs the
//! V3 event accumulator, not yet ported).

use std::collections::BTreeMap;

use alloy::primitives::Address;
use alloy::sol_types::SolCall;
use num_bigint::BigUint;
use railgun_contracts::abi::{relayCall, transactCall, BoundParamsStruct, TransactionStruct};
use railgun_crypto::{get_shared_symmetric_key, Ciphertext};
use railgun_key_derivation::AddressData;
use railgun_models::engine_types::Chain;
use railgun_models::formatted_types::{CommitmentCiphertextV2, TokenType};
use railgun_models::poi_types::TXIDVersion;
use railgun_models::transaction_types::{
    ExtractedRailgunTransactionData, ExtractedRailgunTransactionDataItem,
};
use railgun_note::transact_note::{TokenDataGetter as NoteTokenDataGetter, TransactNote};
use railgun_transaction::bound_params::{
    hash_bound_params_v2, BoundParamsV2, CommitmentCiphertextV2 as BPCommitmentCiphertextV2,
};
use railgun_utils::{
    format_to_byte_length, hex_string_to_bytes, hex_to_bigint, n_to_hex, prefix_0x, ByteLength,
    BytesData,
};

use crate::debugger::EngineDebug;
use crate::railgun_txid::get_railgun_transaction_id_hex;

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("Invalid contract address: got {got}, expected {expected} for network {chain_type}:{chain_id}")]
    InvalidContractAddress {
        got: String,
        expected: String,
        chain_type: u8,
        chain_id: u64,
    },
    #[error("No transaction parsable from request")]
    Unparsable,
    #[error("No ciphertext found for commitment at index 0")]
    NoCiphertext,
    #[error("Unsupported txidVersion")]
    UnsupportedTxidVersion,
    #[error("V3 extraction not yet ported")]
    V3NotPorted,
}

/// `extractFirstNoteERC20AmountMapFromTransactionRequest` — dispatch by version.
pub fn extract_first_note_erc20_amount_map_from_transaction_request<G: NoteTokenDataGetter>(
    txid_version: TXIDVersion,
    chain: &Chain,
    transaction_data: &[u8],
    transaction_to: Option<&str>,
    use_relay_adapt: bool,
    contract_address: &str,
    receiving_viewing_private_key: &[u8],
    receiving_railgun_address_data: &AddressData,
    token_data_getter: &G,
) -> Result<BTreeMap<String, BigUint>, ExtractError> {
    match txid_version {
        TXIDVersion::V2_PoseidonMerkle => extract_first_note_erc20_amount_map_v2(
            chain,
            transaction_data,
            transaction_to,
            use_relay_adapt,
            contract_address,
            receiving_viewing_private_key,
            receiving_railgun_address_data,
            token_data_getter,
        ),
        TXIDVersion::V3_PoseidonMerkle => Err(ExtractError::V3NotPorted),
    }
}

/// `extractRailgunTransactionDataFromTransactionRequest` — dispatch by version.
pub fn extract_railgun_transaction_data_from_transaction_request<G: NoteTokenDataGetter>(
    txid_version: TXIDVersion,
    chain: &Chain,
    transaction_data: &[u8],
    transaction_to: Option<&str>,
    use_relay_adapt: bool,
    contract_address: &str,
    receiving_viewing_private_key: &[u8],
    receiving_railgun_address_data: &AddressData,
    token_data_getter: &G,
) -> Result<ExtractedRailgunTransactionData, ExtractError> {
    match txid_version {
        TXIDVersion::V2_PoseidonMerkle => extract_railgun_transaction_data_v2(
            chain,
            transaction_data,
            transaction_to,
            use_relay_adapt,
            contract_address,
            receiving_viewing_private_key,
            receiving_railgun_address_data,
            token_data_getter,
        ),
        TXIDVersion::V3_PoseidonMerkle => Err(ExtractError::V3NotPorted),
    }
}

/// `getRailgunTransactionRequestsV2` — validate `to` and ABI-decode the calldata
/// into the list of `TransactionStruct`.
fn get_railgun_transaction_requests_v2(
    chain: &Chain,
    transaction_data: &[u8],
    transaction_to: Option<&str>,
    use_relay_adapt: bool,
    contract_address: &str,
) -> Result<Vec<TransactionStruct>, ExtractError> {
    let to = transaction_to.unwrap_or("");
    if to.is_empty() || to.to_lowercase() != contract_address.to_lowercase() {
        return Err(ExtractError::InvalidContractAddress {
            got: transaction_to.unwrap_or("(none)").to_string(),
            expected: contract_address.to_string(),
            chain_type: chain.chain_type,
            chain_id: chain.id,
        });
    }

    if use_relay_adapt {
        let decoded =
            relayCall::abi_decode(transaction_data).map_err(|_| ExtractError::Unparsable)?;
        Ok(decoded._transactions)
    } else {
        let decoded =
            transactCall::abi_decode(transaction_data).map_err(|_| ExtractError::Unparsable)?;
        Ok(decoded._transactions)
    }
}

/// `V2Events.formatCommitmentCiphertext` — turn the ABI struct into the
/// engine's [`CommitmentCiphertextV2`] model.
fn format_commitment_ciphertext_v2(
    bp: &BoundParamsStruct,
    index: usize,
) -> Option<CommitmentCiphertextV2> {
    let cc = bp.commitmentCiphertext.get(index)?;
    let ciphertext: Vec<String> = cc
        .ciphertext
        .iter()
        .map(|el| {
            format_to_byte_length(
                &BytesData::Hex(hex::encode(el.0)),
                ByteLength::Uint256,
                false,
            )
        })
        .collect();
    let iv_tag = &ciphertext[0];
    Some(CommitmentCiphertextV2 {
        ciphertext: Ciphertext {
            iv: iv_tag[..32].to_string(),
            tag: iv_tag[32..].to_string(),
            data: ciphertext[1..].to_vec(),
        },
        blinded_sender_viewing_key: format_to_byte_length(
            &BytesData::Hex(hex::encode(cc.blindedSenderViewingKey.0)),
            ByteLength::Uint256,
            false,
        ),
        blinded_receiver_viewing_key: format_to_byte_length(
            &BytesData::Hex(hex::encode(cc.blindedReceiverViewingKey.0)),
            ByteLength::Uint256,
            false,
        ),
        annotation_data: hex::encode(&cc.annotationData),
        memo: hex::encode(&cc.memo),
    })
}

/// Convert the ABI `BoundParamsStruct` into the txid-hashing `BoundParamsV2`.
fn bound_params_struct_to_model(bp: &BoundParamsStruct) -> BoundParamsV2 {
    let commitment_ciphertext: Vec<BPCommitmentCiphertextV2> = bp
        .commitmentCiphertext
        .iter()
        .map(|cc| BPCommitmentCiphertextV2 {
            ciphertext: cc
                .ciphertext
                .iter()
                .map(|el| {
                    n_to_hex(
                        &hex_to_bigint(&hex::encode(el.0)),
                        ByteLength::Uint256,
                        true,
                    )
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap_or_default(),
            blinded_sender_viewing_key: prefix_0x(&hex::encode(cc.blindedSenderViewingKey.0)),
            blinded_receiver_viewing_key: prefix_0x(&hex::encode(cc.blindedReceiverViewingKey.0)),
            annotation_data: prefix_0x(&hex::encode(&cc.annotationData)),
            memo: prefix_0x(&hex::encode(&cc.memo)),
        })
        .collect();

    BoundParamsV2 {
        tree_number: bp.treeNumber,
        min_gas_price: BigUint::from_bytes_be(&bp.minGasPrice.to_be_bytes_vec()),
        unshield: bp.unshield,
        chain_id: BigUint::from(bp.chainID),
        adapt_contract: prefix_0x(&hex::encode(bp.adaptContract.0)),
        adapt_params: prefix_0x(&hex::encode(bp.adaptParams.0)),
        commitment_ciphertext,
    }
}

fn commitment_hex(tx: &TransactionStruct, index: usize) -> Option<String> {
    tx.commitments
        .get(index)
        .map(|c| prefix_0x(&hex::encode(c.0)))
}

fn extract_railgun_transaction_data_v2<G: NoteTokenDataGetter>(
    chain: &Chain,
    transaction_data: &[u8],
    transaction_to: Option<&str>,
    use_relay_adapt: bool,
    contract_address: &str,
    receiving_viewing_private_key: &[u8],
    receiving_railgun_address_data: &AddressData,
    token_data_getter: &G,
) -> Result<ExtractedRailgunTransactionData, ExtractError> {
    let railgun_txs = get_railgun_transaction_requests_v2(
        chain,
        transaction_data,
        transaction_to,
        use_relay_adapt,
        contract_address,
    )?;

    let mut out = Vec::with_capacity(railgun_txs.len());
    for (railgun_tx_index, railgun_tx) in railgun_txs.iter().enumerate() {
        let nullifiers: Vec<String> = railgun_tx
            .nullifiers
            .iter()
            .map(|n| prefix_0x(&hex::encode(n.0)))
            .collect();
        let commitments: Vec<String> = railgun_tx
            .commitments
            .iter()
            .map(|c| prefix_0x(&hex::encode(c.0)))
            .collect();

        let bp_model = bound_params_struct_to_model(&railgun_tx.boundParams);
        let bound_params_hash =
            n_to_hex(&hash_bound_params_v2(&bp_model), ByteLength::Uint256, true);
        let railgun_txid =
            get_railgun_transaction_id_hex(&nullifiers, &commitments, &bound_params_hash);

        let utxo_tree_in = BigUint::from(railgun_tx.boundParams.treeNumber);

        if railgun_tx_index > 0 {
            out.push(ExtractedRailgunTransactionDataItem {
                railgun_txid,
                utxo_tree_in,
                first_commitment_note_public_key: None,
                first_commitment: commitment_hex(railgun_tx, 0),
            });
            continue;
        }

        let commitment_ciphertext = format_commitment_ciphertext_v2(&railgun_tx.boundParams, 0)
            .ok_or(ExtractError::NoCiphertext)?;

        let first_commitment_note_public_key = extract_npk_from_commitment_ciphertext_v2(
            chain,
            &commitment_ciphertext,
            receiving_viewing_private_key,
            receiving_railgun_address_data,
            token_data_getter,
        );

        out.push(ExtractedRailgunTransactionDataItem {
            railgun_txid,
            utxo_tree_in,
            first_commitment_note_public_key,
            first_commitment: commitment_hex(railgun_tx, 0),
        });
    }
    Ok(out)
}

fn extract_first_note_erc20_amount_map_v2<G: NoteTokenDataGetter>(
    chain: &Chain,
    transaction_data: &[u8],
    transaction_to: Option<&str>,
    use_relay_adapt: bool,
    contract_address: &str,
    receiving_viewing_private_key: &[u8],
    receiving_railgun_address_data: &AddressData,
    token_data_getter: &G,
) -> Result<BTreeMap<String, BigUint>, ExtractError> {
    let railgun_txs = get_railgun_transaction_requests_v2(
        chain,
        transaction_data,
        transaction_to,
        use_relay_adapt,
        contract_address,
    )?;

    let mut amounts: BTreeMap<String, BigUint> = BTreeMap::new();
    for railgun_tx in &railgun_txs {
        let commitment_ciphertext =
            match format_commitment_ciphertext_v2(&railgun_tx.boundParams, 0) {
                Some(cc) => cc,
                None => {
                    EngineDebug::log("no ciphertext found for commitment at index 0");
                    continue;
                }
            };
        let commitment_hash = match commitment_hex(railgun_tx, 0) {
            Some(c) => c,
            None => continue,
        };

        let decrypted_receiver_note = decrypt_receiver_note_safe_v2(
            chain,
            &commitment_ciphertext,
            receiving_viewing_private_key,
            receiving_railgun_address_data,
            token_data_getter,
        );

        if let Some((token_address, amount)) = extract_erc20_amount_from_transact_note(
            decrypted_receiver_note.as_ref(),
            &commitment_hash,
            receiving_railgun_address_data,
        ) {
            let entry = amounts
                .entry(token_address)
                .or_insert_with(BigUint::default);
            *entry += amount;
        }
    }
    Ok(amounts)
}

fn decrypt_receiver_note_safe_v2<G: NoteTokenDataGetter>(
    chain: &Chain,
    commitment_ciphertext: &CommitmentCiphertextV2,
    receiving_viewing_private_key: &[u8],
    receiving_railgun_address_data: &AddressData,
    token_data_getter: &G,
) -> Option<TransactNote> {
    let blinded_sender_viewing_key =
        hex_string_to_bytes(&commitment_ciphertext.blinded_sender_viewing_key).ok()?;
    let blinded_receiver_viewing_key =
        hex_string_to_bytes(&commitment_ciphertext.blinded_receiver_viewing_key).ok()?;

    let priv_key: [u8; 32] = receiving_viewing_private_key.try_into().ok()?;
    let sender_key: [u8; 32] = blinded_sender_viewing_key.as_slice().try_into().ok()?;
    let shared_key = match get_shared_symmetric_key(&priv_key, &sender_key) {
        Some(k) => k,
        None => {
            EngineDebug::log("invalid sharedKey");
            return None;
        }
    };

    let recv_key: Option<[u8; 32]> = blinded_receiver_viewing_key.as_slice().try_into().ok();
    let send_key: Option<[u8; 32]> = blinded_sender_viewing_key.as_slice().try_into().ok();

    TransactNote::decrypt(
        TXIDVersion::V2_PoseidonMerkle,
        chain.id,
        receiving_railgun_address_data,
        Some(&commitment_ciphertext.ciphertext),
        None,
        &shared_key,
        &commitment_ciphertext.memo,
        &commitment_ciphertext.annotation_data,
        receiving_viewing_private_key,
        recv_key.as_ref(),
        send_key.as_ref(),
        false, // is_sent_note
        false, // is_legacy_decryption
        token_data_getter,
        None,
        None,
    )
    .ok()
}

/// `extractNPKFromCommitmentCiphertextV2`.
pub fn extract_npk_from_commitment_ciphertext_v2<G: NoteTokenDataGetter>(
    chain: &Chain,
    commitment_ciphertext: &CommitmentCiphertextV2,
    receiving_viewing_private_key: &[u8],
    receiving_railgun_address_data: &AddressData,
    token_data_getter: &G,
) -> Option<BigUint> {
    decrypt_receiver_note_safe_v2(
        chain,
        commitment_ciphertext,
        receiving_viewing_private_key,
        receiving_railgun_address_data,
        token_data_getter,
    )
    .map(|n| n.note_public_key)
}

/// `extractERC20AmountFromTransactNote`.
pub fn extract_erc20_amount_from_transact_note(
    decrypted_receiver_note: Option<&TransactNote>,
    commitment_hash: &str,
    receiving_railgun_address_data: &AddressData,
) -> Option<(String, BigUint)> {
    let note = match decrypted_receiver_note {
        Some(n) => n,
        None => {
            EngineDebug::log("invalid decryptedReceiverNote");
            return None;
        }
    };

    if note.receiver_address_data.master_public_key
        != receiving_railgun_address_data.master_public_key
    {
        EngineDebug::log("invalid masterPublicKey");
        return None;
    }

    let note_hash = n_to_hex(&note.hash, ByteLength::Uint256, false);
    let commit_hash = format_to_byte_length(
        &BytesData::Hex(commitment_hash.to_string()),
        ByteLength::Uint256,
        false,
    );
    if note_hash != commit_hash {
        EngineDebug::log("invalid commitHash");
        return None;
    }

    if note.token_data.token_type != TokenType::Erc20 {
        EngineDebug::log("not an erc20");
        return None;
    }

    let token_address = format_to_byte_length(
        &BytesData::Hex(note.token_data.token_address.clone()),
        ByteLength::Address,
        true,
    )
    .to_lowercase();

    Some((token_address, note.value.clone()))
}

/// Helper: lowercase an EVM address for the `to`-field comparison.
pub fn to_checked_address(addr: &str) -> Option<Address> {
    addr.parse::<Address>().ok()
}
