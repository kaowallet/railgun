//! Port of `src/poi/blinded-commitment.ts`.

use num_bigint::BigUint;
use railgun_crypto::poseidon;
use railgun_utils::{format_to_byte_length, hex_to_bigint, n_to_hex, ByteLength, BytesData};

/// `0x`-prefixed 32-byte hex of a field element. Matches the TS `formatHash`.
fn format_hash(hash: &BigUint) -> String {
    format!("0x{}", n_to_hex(hash, ByteLength::Uint256, false))
}

/// `BlindedCommitment` — namespace for the two blinded-commitment derivations.
pub struct BlindedCommitment;

impl BlindedCommitment {
    /// `BlindedCommitment.getForUnshield(railgunTxid)` — just the txid, formatted
    /// to a 32-byte `0x`-prefixed hex string.
    pub fn get_for_unshield(railgun_txid: &str) -> String {
        format_to_byte_length(
            &BytesData::Hex(railgun_txid.to_string()),
            ByteLength::Uint256,
            true,
        )
    }

    /// `BlindedCommitment.getForShieldOrTransact(commitmentHash, npk, globalTreePosition)`
    /// — `poseidon([hexToBigInt(commitmentHash), npk, globalTreePosition])`, returned
    /// as a `0x`-prefixed 32-byte hex string.
    pub fn get_for_shield_or_transact(
        commitment_hash: &str,
        npk: &BigUint,
        global_tree_position: &BigUint,
    ) -> String {
        let hash = poseidon(&[
            hex_to_bigint(commitment_hash),
            npk.clone(),
            global_tree_position.clone(),
        ]);
        format_hash(&hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global_tree_position::get_global_tree_position;
    use num_traits::Num;

    fn bn(s: &str) -> BigUint {
        BigUint::from_str_radix(s, 10).unwrap()
    }

    // KAV from src/prover/__tests__/prover.test.ts: blinded commitment for a shield.
    #[test]
    fn blinded_commitment_for_shield_kav() {
        let shield_commitment =
            bn("6442080113031815261226726790601252395803415545769290265212232865825296902085");
        // notePublicKey for the prover test vector.
        let note_public_key =
            bn("6401386539363233023821237080626891507664131047949709897410333742190241828916");
        let commitment_hash = n_to_hex(&shield_commitment, ByteLength::Uint256, false);
        let blinded = BlindedCommitment::get_for_shield_or_transact(
            &commitment_hash,
            &note_public_key,
            &get_global_tree_position(0, 0),
        );
        let blinded_n = hex_to_bigint(&blinded);
        assert_eq!(
            blinded_n,
            bn("12151255948031648278500231754672666576376002857793985290167262750766640136930")
        );
    }

    #[test]
    fn get_for_unshield_formats_txid() {
        let txid = "abcd";
        let out = BlindedCommitment::get_for_unshield(txid);
        assert_eq!(
            out,
            "0x000000000000000000000000000000000000000000000000000000000000abcd"
        );
        assert_eq!(out.len(), 66);
    }
}
