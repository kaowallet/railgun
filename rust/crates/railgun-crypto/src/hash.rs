//! Port of `src/utils/hash.ts` — SHA-256, SHA-512, HMAC-SHA-512, Keccak-256.
//!
//! Delegates to RustCrypto. The TS functions return lowercase hex without `0x`;
//! we keep both a hex API (for parity with vectors) and a raw-bytes API.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;

pub fn sha256_bytes(pre_image: &[u8]) -> [u8; 32] {
    Sha256::digest(pre_image).into()
}

pub fn sha256(pre_image: &[u8]) -> String {
    hex::encode(sha256_bytes(pre_image))
}

pub fn sha512_bytes(pre_image: &[u8]) -> [u8; 64] {
    Sha512::digest(pre_image).into()
}

pub fn sha512(pre_image: &[u8]) -> String {
    hex::encode(sha512_bytes(pre_image))
}

pub fn keccak256_bytes(pre_image: &[u8]) -> [u8; 32] {
    Keccak256::digest(pre_image).into()
}

pub fn keccak256(pre_image: &[u8]) -> String {
    hex::encode(keccak256_bytes(pre_image))
}

pub fn sha512_hmac_bytes(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn sha512_hmac(key: &[u8], data: &[u8]) -> String {
    hex::encode(sha512_hmac_bytes(key, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from src/utils/__tests__/hash.test.ts
    #[test]
    fn sha256_vectors() {
        let vectors: [(&[u8], &str); 3] = [
            (&[], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (
                &[82, 65, 73, 76, 71, 85, 78],
                "b25e4f3027088a658fa918eb93fd905969be8f455adb942987aa866013c9f836",
            ),
            (
                &[80, 82, 73, 86, 65, 67, 89, 32, 38, 32, 65, 78, 79, 78, 89, 77, 73, 84, 89],
                "947fa99dc47b17d91b3aceec798dcee836744c68423e9b41b9d1b7ffba8fdc8c",
            ),
        ];
        for (input, expected) in vectors {
            assert_eq!(sha256(input), expected);
        }
    }

    #[test]
    fn keccak256_vectors() {
        let vectors: [(&[u8], &str); 3] = [
            (&[], "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
            (
                &[82, 65, 73, 76, 71, 85, 78],
                "ef0394c8ea7550db58adcb1b8ffb98f76fca939554a4084889b6bffa01aac296",
            ),
            (
                &[80, 82, 73, 86, 65, 67, 89, 32, 38, 32, 65, 78, 79, 78, 89, 77, 73, 84, 89],
                "5c7d261b35e3b58c6ca6663e44b736a7fbbc0e2265cd050959f4976f8667d306",
            ),
        ];
        for (input, expected) in vectors {
            assert_eq!(keccak256(input), expected);
        }
    }

    #[test]
    fn sha512_hmac_vectors() {
        let vectors: [(&[u8], &[u8], &str); 3] = [
            (&[170], &[], "4e9f386d58475d4e030c55c47f54ab3e2e5790d2aaaedc2f4465b5665a5307da3416778a481a09a2f18e1db63c26d741aa0a82af5a38a893bf9793fb7dea031e"),
            (&[187], &[82, 65, 73, 76, 71, 85, 78], "206aca0dd9a7d87873692ff48a91f0c495ab896c488c4af5e7062774e8841298ddc9eee9699a6930b545aebf6dd3504bcef331231368318da26bb3783fdcc086"),
            (&[204], &[80, 82, 73, 86, 65, 67, 89, 32, 38, 32, 65, 78, 79, 78, 89, 77, 73, 84, 89], "b3513bb5230d933d8dc2cf28eddfa566bb76f49aa9bdf6f2475df0405feaaab4782d9d7a177ee9e32aa1e0af0ca0bb93a3c0312aa18788c7944a24f761bdcc1a"),
        ];
        for (key, data, expected) in vectors {
            assert_eq!(sha512_hmac(key, data), expected);
        }
    }
}
