//! Port of `src/key-derivation/wallet-node.ts` — `WalletNode`.

use num_bigint::BigUint;
use railgun_crypto::{get_public_spending_key, get_public_viewing_key, poseidon};

use crate::bip32::{
    child_key_derivation_hardened, get_master_key_from_seed, get_path_segments, KeyNode,
    HARDENED_OFFSET,
};
use crate::bip39::Mnemonic;

const SPENDING_PREFIX: &str = "m/44'/1984'/0'/0'/";
const VIEWING_PREFIX: &str = "m/420'/1984'/0'/0'/";

pub type SpendingPublicKey = (BigUint, BigUint);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendingKeyPair {
    pub private_key: [u8; 32],
    pub pubkey: SpendingPublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewingKeyPair {
    pub private_key: [u8; 32],
    pub pubkey: [u8; 32],
}

pub struct WalletNodes {
    pub spending: WalletNode,
    pub viewing: WalletNode,
}

#[derive(Clone, Debug)]
pub struct WalletNode {
    chain_key: String,
    chain_code: String,
}

impl WalletNode {
    pub fn new(node: KeyNode) -> Self {
        Self {
            chain_key: node.chain_key,
            chain_code: node.chain_code,
        }
    }

    /// `WalletNode.fromMnemonic`.
    pub fn from_mnemonic(mnemonic: &str, password: &str) -> Self {
        let seed = Mnemonic::to_seed(mnemonic, password).expect("valid mnemonic");
        Self::new(get_master_key_from_seed(&seed))
    }

    /// `WalletNode.derive` — hardened derivation along a path.
    pub fn derive(&self, path: &str) -> Self {
        let segments = get_path_segments(path).expect("valid path");
        let node = segments.iter().fold(
            KeyNode {
                chain_key: self.chain_key.clone(),
                chain_code: self.chain_code.clone(),
            },
            |parent, &segment| child_key_derivation_hardened(&parent, segment, HARDENED_OFFSET),
        );
        Self::new(node)
    }

    fn private_key_bytes(&self) -> [u8; 32] {
        railgun_utils::hex_string_to_bytes(&self.chain_key)
            .expect("32-byte chain key")
            .try_into()
            .expect("32 bytes")
    }

    /// `getSpendingKeyPair`.
    pub fn get_spending_key_pair(&self) -> SpendingKeyPair {
        let private_key = self.private_key_bytes();
        SpendingKeyPair {
            pubkey: get_public_spending_key(&private_key),
            private_key,
        }
    }

    /// `getViewingKeyPair`.
    pub fn get_viewing_key_pair(&self) -> ViewingKeyPair {
        let private_key = self.private_key_bytes();
        ViewingKeyPair {
            pubkey: get_public_viewing_key(&private_key),
            private_key,
        }
    }

    /// `getNullifyingKey` — poseidon of the viewing private key (as a field elem).
    pub fn get_nullifying_key(&self) -> BigUint {
        let private_key = self.private_key_bytes();
        poseidon(&[BigUint::from_bytes_be(&private_key)])
    }

    /// `WalletNode.getMasterPublicKey` — poseidon([spendX, spendY, nullifyingKey]).
    pub fn get_master_public_key(
        spending_public_key: &SpendingPublicKey,
        nullifying_key: &BigUint,
    ) -> BigUint {
        poseidon(&[
            spending_public_key.0.clone(),
            spending_public_key.1.clone(),
            nullifying_key.clone(),
        ])
    }
}

/// `deriveNodes`.
pub fn derive_nodes(mnemonic: &str, index: u32, password: &str) -> WalletNodes {
    WalletNodes {
        spending: WalletNode::from_mnemonic(mnemonic, password)
            .derive(&format!("{SPENDING_PREFIX}{index}'")),
        viewing: WalletNode::from_mnemonic(mnemonic, password)
            .derive(&format!("{VIEWING_PREFIX}{index}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Vector {
        mnemonic: &'static str,
        path: &'static str,
        spending_priv: [u8; 32],
        spending_pub: (&'static str, &'static str),
        viewing_pub: [u8; 32],
        nullifying_key: &'static str,
    }

    fn vectors() -> Vec<Vector> {
        vec![
            Vector {
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                path: "m/0'",
                spending_priv: [103, 215, 209, 157, 0, 230, 227, 179, 81, 127, 230, 138, 196, 101, 5, 221, 32, 125, 246, 232, 254, 58, 160, 107, 163, 250, 206, 53, 46, 117, 153, 239],
                spending_pub: ("1700559105542139805112168139351320601853033442476682590258553412078471731431", "20772987336827599306927277921643441679141423747083423413320022373456048866305"),
                viewing_pub: [13, 235, 247, 125, 142, 148, 54, 252, 7, 160, 220, 63, 232, 189, 144, 194, 245, 146, 160, 140, 171, 141, 190, 95, 151, 42, 71, 131, 70, 92, 214, 212],
                nullifying_key: "12835268173099116305231859677177501123414588269721547120001227054861606950622",
            },
            Vector {
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                path: "m/0'/1'",
                spending_priv: [52, 40, 207, 201, 57, 50, 3, 40, 80, 17, 116, 164, 231, 110, 134, 145, 151, 255, 200, 148, 181, 141, 191, 77, 14, 149, 60, 72, 77, 102, 203, 94],
                spending_pub: ("16684668252477829187059584092631702151145377657154285130424212860540363370357", "12981690610069374219327647242965768905998412239681315744257339323456415609107"),
                viewing_pub: [188, 10, 133, 20, 54, 28, 82, 39, 129, 118, 54, 192, 105, 143, 30, 183, 217, 77, 82, 240, 122, 203, 88, 224, 107, 241, 219, 145, 159, 230, 69, 20],
                nullifying_key: "12433581129726328896745774227574786958991377531034322249715552469191536529193",
            },
            Vector {
                mnemonic: "culture flower sunny seat maximum begin design magnet side permit coin dial alter insect whisper series desk power cream afford regular strike poem ostrich",
                path: "m/1984'/0'/1'/1'",
                spending_priv: [174, 161, 99, 229, 87, 84, 149, 94, 180, 249, 130, 131, 138, 60, 244, 236, 172, 83, 232, 9, 167, 168, 25, 67, 167, 236, 115, 134, 66, 111, 157, 93],
                spending_pub: ("14701770942636881946891894801429513727414463095087240498212571459549371788442", "6562351643365832094839703629534233618348049923815027910705830997906348902485"),
                viewing_pub: [28, 112, 24, 121, 34, 161, 22, 10, 20, 98, 221, 72, 216, 131, 91, 146, 55, 237, 168, 255, 121, 6, 217, 124, 152, 150, 232, 196, 138, 161, 179, 243],
                nullifying_key: "16602386444438786679333393766394518037774007889700655746209679443354561523707",
            },
        ]
    }

    fn big(d: &str) -> BigUint {
        BigUint::parse_bytes(d.as_bytes(), 10).unwrap()
    }

    // src/key-derivation/__tests__/key-derivation.test.ts
    #[test]
    fn derive_spending_keys() {
        for v in vectors() {
            let node = WalletNode::from_mnemonic(v.mnemonic, "").derive(v.path);
            let kp = node.get_spending_key_pair();
            assert_eq!(kp.private_key, v.spending_priv);
            assert_eq!(kp.pubkey, (big(v.spending_pub.0), big(v.spending_pub.1)));
        }
    }

    #[test]
    fn derive_viewing_keys() {
        for v in vectors() {
            let node = WalletNode::from_mnemonic(v.mnemonic, "").derive(v.path);
            let kp = node.get_viewing_key_pair();
            assert_eq!(kp.private_key, v.spending_priv);
            assert_eq!(kp.pubkey, v.viewing_pub);
        }
    }

    #[test]
    fn derive_nullifying_keys() {
        for v in vectors() {
            let node = WalletNode::from_mnemonic(v.mnemonic, "").derive(v.path);
            assert_eq!(node.get_nullifying_key(), big(v.nullifying_key));
        }
    }
}
