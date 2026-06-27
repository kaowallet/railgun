//! Port of `src/key-derivation/bip39.ts` — `Mnemonic`.

use bip39::Mnemonic as Bip39Mnemonic;

#[derive(Debug, thiserror::Error)]
pub enum MnemonicError {
    #[error("invalid mnemonic")]
    Invalid,
    #[error("invalid entropy")]
    InvalidEntropy,
    #[error("derivation failed")]
    Derivation,
}

pub struct Mnemonic;

impl Mnemonic {
    /// `Mnemonic.generate` — strength in bits (128/192/256 -> 12/18/24 words).
    pub fn generate(strength: usize) -> String {
        let word_count = strength / 32 * 3;
        Bip39Mnemonic::generate(word_count)
            .expect("valid word count")
            .to_string()
    }

    /// `Mnemonic.validate`.
    pub fn validate(mnemonic: &str) -> bool {
        Bip39Mnemonic::parse_normalized(mnemonic).is_ok()
    }

    /// `Mnemonic.toSeed` — BIP39 seed as hex (no checksum dependency in TS, but
    /// all real inputs are valid mnemonics).
    pub fn to_seed(mnemonic: &str, password: &str) -> Result<String, MnemonicError> {
        let m = Bip39Mnemonic::parse_normalized(mnemonic).map_err(|_| MnemonicError::Invalid)?;
        Ok(hex::encode(m.to_seed(password)))
    }

    /// `Mnemonic.toEntropy`.
    pub fn to_entropy(mnemonic: &str) -> Result<String, MnemonicError> {
        let m = Bip39Mnemonic::parse_normalized(mnemonic).map_err(|_| MnemonicError::Invalid)?;
        Ok(hex::encode(m.to_entropy()))
    }

    /// `Mnemonic.fromEntropy`.
    pub fn from_entropy(entropy_hex: &str) -> Result<String, MnemonicError> {
        let bytes = railgun_utils::hex_string_to_bytes(entropy_hex)
            .map_err(|_| MnemonicError::InvalidEntropy)?;
        Ok(Bip39Mnemonic::from_entropy(&bytes)
            .map_err(|_| MnemonicError::InvalidEntropy)?
            .to_string())
    }

    /// `Mnemonic.to0xPrivateKey` — standard secp256k1 BIP32 at m/44'/60'/0'/0/index.
    pub fn to_0x_private_key(
        mnemonic: &str,
        derivation_index: Option<u32>,
        password: &str,
    ) -> Result<String, MnemonicError> {
        let m = Bip39Mnemonic::parse_normalized(mnemonic).map_err(|_| MnemonicError::Invalid)?;
        let seed = m.to_seed(password);
        let path = format!("m/44'/60'/0'/0/{}", derivation_index.unwrap_or(0));
        let dp: bip32_secp::DerivationPath = path.parse().map_err(|_| MnemonicError::Derivation)?;
        let xprv =
            bip32_secp::XPrv::derive_from_path(seed, &dp).map_err(|_| MnemonicError::Derivation)?;
        Ok(hex::encode(xprv.private_key().to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // src/key-derivation/__tests__/bip39.test.ts
    #[test]
    fn generate_word_counts() {
        assert_eq!(Mnemonic::generate(128).split(' ').count(), 12);
        assert_eq!(Mnemonic::generate(192).split(' ').count(), 18);
        assert_eq!(Mnemonic::generate(256).split(' ').count(), 24);
        assert!(Mnemonic::generate(128).chars().all(|c| c.is_ascii_lowercase() || c == ' '));
    }

    #[test]
    fn entropy_roundtrip() {
        let vectors = [
            ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "00000000000000000000000000000000"),
            ("mammal step public march absorb critic visa rent miss color erase exhaust south lift ordinary ceiling stay physical", "86baaeb443e00c67bd2db28dc5b531a7bd0302e71127d4f4"),
            ("culture flower sunny seat maximum begin design magnet side permit coin dial alter insect whisper series desk power cream afford regular strike poem ostrich", "358b3365e12896288ef42fc7f464b59e8076ea3ea6203bf528cb823b4dae29c4"),
        ];
        for (mnemonic, entropy) in vectors {
            assert_eq!(Mnemonic::to_entropy(mnemonic).unwrap(), entropy);
            assert_eq!(Mnemonic::from_entropy(entropy).unwrap(), mnemonic);
        }
    }

    #[test]
    fn validate_mnemonics() {
        let valid = [
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "mammal step public march absorb critic visa rent miss color erase exhaust south lift ordinary ceiling stay physical",
            "culture flower sunny seat maximum begin design magnet side permit coin dial alter insect whisper series desk power cream afford regular strike poem ostrich",
        ];
        for m in valid {
            assert!(Mnemonic::validate(m));
        }
        let invalid = [
            "Why, sometimes I've believed as many as six impossible things before breakfast.",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
            "chicken",
        ];
        for m in invalid {
            assert!(!Mnemonic::validate(m));
        }
    }

    #[test]
    fn to_seed_vectors() {
        let vectors = [
            ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"),
            ("mammal step public march absorb critic visa rent miss color erase exhaust south lift ordinary ceiling stay physical", "", "d8c228addf9a9cfe5b7934223737815e2f709b3ac12b0c1b2aaec921e5d3a2e8aeea1df817af8159f981798dacd5a930a1fcd8570ba4845078c1b1d09fa060cb"),
            ("culture flower sunny seat maximum begin design magnet side permit coin dial alter insect whisper series desk power cream afford regular strike poem ostrich", "", "243c1266228fc9ff370d567ba4f805dfacc516375aecf4657cf870a4b551020d92d9b45a8181154f531c1358f742f42078a1620fca6251b1c4ec5fa6e1cf5c3a"),
            ("culture flower sunny seat maximum begin design magnet side permit coin dial alter insect whisper series desk power cream afford regular strike poem ostrich", "test", "87ec3e2ae9294cb5500698e6e6ee8357aa56222badae0e6b4150492c95ede7ddfca27c952afafb388453def93fac72f5d7e099debd79e85c2088f9b3e7a65df6"),
        ];
        for (mnemonic, password, seed) in vectors {
            assert_eq!(Mnemonic::to_seed(mnemonic, password).unwrap(), seed);
        }
    }

    // src/key-derivation/__tests__/mnemonic.test.ts
    #[test]
    fn to_0x_private_key_vectors() {
        let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(
            Mnemonic::to_0x_private_key(m, None, "").unwrap(),
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
        );
        assert_eq!(
            Mnemonic::to_0x_private_key(m, Some(100), "").unwrap(),
            "413cbeb8f83ecbd3c1e64f2ed89faac0ae89b5986fb4b010422e3056bbc61174"
        );
    }
}
