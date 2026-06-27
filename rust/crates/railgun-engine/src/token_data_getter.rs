//! Port of `src/token/token-data-getter.ts`.
//!
//! Resolves a token hash to [`TokenData`]. ERC20 hashes resolve in-process; NFT
//! hashes need an `eth_call` (cache miss) which is delegated to an injected async
//! [`NftTokenDataResolver`] trait. A DB-backed cache mirrors the TS
//! `nft-token-data-map` namespace.

use async_trait::async_trait;
use railgun_models::engine_types::Chain;
use railgun_models::formatted_types::TokenData;
use railgun_models::poi_types::TXIDVersion;
use railgun_note::note_util::get_token_data_erc20;
use railgun_utils::{format_to_byte_length, from_utf8_string, ByteLength, BytesData};

/// 12 empty bytes — the ERC20 token-hash prefix.
const ERC20_TOKEN_HASH_PREFIX: &str = "000000000000000000000000";

/// `RailgunVersionedSmartContracts.getNFTTokenData` — injected async resolver
/// performing the on-chain `eth_call` on a cache miss. The SDK supplies no I/O;
/// the caller implements this (e.g. via `railgun-contracts` + an alloy provider).
#[async_trait]
pub trait NftTokenDataResolver: Send + Sync {
    async fn get_nft_token_data(
        &self,
        txid_version: TXIDVersion,
        chain: &Chain,
        formatted_token_hash: &str,
    ) -> Result<TokenData, TokenDataGetterError>;
}

/// Persistence backend for the NFT token-data cache. Mirrors the TS `db.put` /
/// `db.get` of `nft-token-data-map`. The caller wires this to `railgun-db`.
pub trait NftTokenDataCache: Send + Sync {
    fn get_cached(&self, path: &[String]) -> Option<TokenData>;
    fn put_cached(&self, path: &[String], token_data: &TokenData);
}

#[derive(Debug, thiserror::Error)]
pub enum TokenDataGetterError {
    #[error("NFT token-data resolution failed: {0}")]
    Resolve(String),
}

/// `TokenDataGetter`.
pub struct TokenDataGetter<C: NftTokenDataCache, R: NftTokenDataResolver> {
    cache: C,
    resolver: R,
}

impl<C: NftTokenDataCache, R: NftTokenDataResolver> TokenDataGetter<C, R> {
    pub fn new(cache: C, resolver: R) -> Self {
        Self { cache, resolver }
    }

    /// `getTokenDataFromHash`.
    pub async fn get_token_data_from_hash(
        &self,
        txid_version: TXIDVersion,
        chain: &Chain,
        token_hash: &str,
    ) -> Result<TokenData, TokenDataGetterError> {
        let formatted = format_to_byte_length(
            &BytesData::Hex(token_hash.to_string()),
            ByteLength::Uint256,
            false,
        );
        let is_erc20 = formatted.starts_with(ERC20_TOKEN_HASH_PREFIX);
        if is_erc20 {
            return Ok(get_token_data_erc20(token_hash));
        }
        self.get_nft_token_data(txid_version, chain, token_hash)
            .await
    }

    /// `getNFTTokenData`.
    pub async fn get_nft_token_data(
        &self,
        txid_version: TXIDVersion,
        chain: &Chain,
        token_hash: &str,
    ) -> Result<TokenData, TokenDataGetterError> {
        let formatted_token_hash = format_to_byte_length(
            &BytesData::Hex(token_hash.to_string()),
            ByteLength::Uint256,
            false,
        );

        if let Some(cached) = self.get_cached_nft_token_data(&formatted_token_hash) {
            return Ok(cached);
        }

        let token_data = self
            .resolver
            .get_nft_token_data(txid_version, chain, &formatted_token_hash)
            .await?;
        self.cache_nft_token_data(token_hash, &token_data);
        Ok(token_data)
    }

    fn get_nft_token_data_prefix() -> Vec<String> {
        let prefix = from_utf8_string("nft-token-data-map").unwrap_or_default();
        vec![prefix]
    }

    fn get_nft_token_data_path(token_hash: &str) -> Vec<String> {
        let mut parts = Self::get_nft_token_data_prefix();
        parts.push(token_hash.to_string());
        parts
            .into_iter()
            .map(|el| format_to_byte_length(&BytesData::Hex(el), ByteLength::Uint256, false))
            .collect()
    }

    fn cache_nft_token_data(&self, token_hash: &str, token_data: &TokenData) {
        let path = Self::get_nft_token_data_path(token_hash);
        self.cache.put_cached(&path, token_data);
    }

    /// `getCachedNFTTokenData`.
    pub fn get_cached_nft_token_data(&self, token_hash: &str) -> Option<TokenData> {
        let path = Self::get_nft_token_data_path(token_hash);
        self.cache.get_cached(&path)
    }
}

/// A [`NftTokenDataCache`] that never caches (ERC20-only deployments / tests).
pub struct NoopNftTokenDataCache;

impl NftTokenDataCache for NoopNftTokenDataCache {
    fn get_cached(&self, _path: &[String]) -> Option<TokenData> {
        None
    }
    fn put_cached(&self, _path: &[String], _token_data: &TokenData) {}
}

/// A [`NftTokenDataResolver`] that fails — for ERC20-only contexts where NFT
/// resolution is never expected (e.g. the KAV path).
pub struct UnsupportedNftResolver;

#[async_trait]
impl NftTokenDataResolver for UnsupportedNftResolver {
    async fn get_nft_token_data(
        &self,
        _txid_version: TXIDVersion,
        _chain: &Chain,
        _formatted_token_hash: &str,
    ) -> Result<TokenData, TokenDataGetterError> {
        Err(TokenDataGetterError::Resolve(
            "NFT token-data resolver not configured".to_string(),
        ))
    }
}
