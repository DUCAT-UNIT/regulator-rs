//! Nostr relay client for fetching pre-baked quotes

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::cache::CachedQuote;

/// Nostr event structure (NIP-01)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: i32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

/// Price contract content in Nostr event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceContractContent {
    pub chain_network: String,
    pub oracle_pubkey: String,
    pub base_price: i64,
    pub base_stamp: i64,
    pub commit_hash: String,
    pub contract_id: String,
    pub oracle_sig: String,
    pub thold_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thold_key: Option<String>,
    pub thold_price: i64,
}

/// Nostr relay client
pub struct NostrClient {
    relay_url: String,
    http_client: reqwest::Client,
}

impl NostrClient {
    pub fn new(relay_url: String) -> Self {
        Self {
            relay_url,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    /// Fetch quote by d-tag (commit_hash)
    pub async fn fetch_quote_by_dtag(&self, commit_hash: &str) -> Result<Option<CachedQuote>> {
        let url = format!("{}/api/quotes?d={}", self.relay_url, commit_hash);

        let response = self.http_client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            anyhow::bail!("Nostr relay returned status: {}", response.status());
        }

        let event: NostrEvent = response.json().await?;
        let content: PriceContractContent = serde_json::from_str(&event.content)?;

        Ok(Some(CachedQuote {
            chain_network: content.chain_network,
            oracle_pubkey: content.oracle_pubkey,
            base_price: content.base_price,
            base_stamp: content.base_stamp,
            commit_hash: content.commit_hash,
            contract_id: content.contract_id,
            oracle_sig: content.oracle_sig,
            thold_hash: content.thold_hash,
            thold_key: content.thold_key,
            thold_price: content.thold_price,
            cached_at: chrono::Utc::now().timestamp(),
        }))
    }

    /// Fetch multiple quotes by d-tags (batch)
    pub async fn fetch_quotes_by_dtags(&self, commit_hashes: &[String]) -> Result<Vec<CachedQuote>> {
        let mut quotes = Vec::new();

        // Fetch in parallel using join_all
        let futures: Vec<_> = commit_hashes
            .iter()
            .map(|hash| self.fetch_quote_by_dtag(hash))
            .collect();

        let results = futures::future::join_all(futures).await;

        for result in results {
            if let Ok(Some(quote)) = result {
                quotes.push(quote);
            }
        }

        Ok(quotes)
    }

    /// Fetch latest quotes (e.g., from recent batch)
    pub async fn fetch_recent_quotes(&self, limit: usize) -> Result<Vec<CachedQuote>> {
        let url = format!("{}/api/quotes?limit={}", self.relay_url, limit);

        let response = self.http_client.get(&url).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("Nostr relay returned status: {}", response.status());
        }

        let events: Vec<NostrEvent> = response.json().await?;
        let now = chrono::Utc::now().timestamp();

        let quotes: Vec<CachedQuote> = events
            .into_iter()
            .filter_map(|event| {
                serde_json::from_str::<PriceContractContent>(&event.content)
                    .ok()
                    .map(|content| CachedQuote {
                        chain_network: content.chain_network,
                        oracle_pubkey: content.oracle_pubkey,
                        base_price: content.base_price,
                        base_stamp: content.base_stamp,
                        commit_hash: content.commit_hash,
                        contract_id: content.contract_id,
                        oracle_sig: content.oracle_sig,
                        thold_hash: content.thold_hash,
                        thold_key: content.thold_key,
                        thold_price: content.thold_price,
                        cached_at: now,
                    })
            })
            .collect();

        Ok(quotes)
    }
}

/// Calculate commit_hash (d-tag) locally using BIP-340 tagged hash
/// This allows looking up pre-baked quotes without calling CRE
pub fn calculate_commit_hash(
    oracle_pubkey: &str,
    chain_network: &str,
    base_price: u32,
    base_stamp: u32,
    thold_price: u32,
) -> Result<String> {
    use sha2::{Digest, Sha256};

    // Decode oracle pubkey (must be 32 bytes / 64 hex chars)
    let pubkey_bytes = hex::decode(oracle_pubkey)?;
    if pubkey_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid oracle pubkey length: expected 32 bytes, got {}",
            pubkey_bytes.len()
        );
    }

    // Build preimage: pubkey || network || base_price || base_stamp || thold_price
    let mut preimage = Vec::with_capacity(32 + chain_network.len() + 12);
    preimage.extend_from_slice(&pubkey_bytes);
    preimage.extend_from_slice(chain_network.as_bytes());
    preimage.extend_from_slice(&base_price.to_be_bytes());
    preimage.extend_from_slice(&base_stamp.to_be_bytes());
    preimage.extend_from_slice(&thold_price.to_be_bytes());

    // BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
    let tag = "ducat/price-commit";
    let tag_hash = Sha256::digest(tag.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(&preimage);

    Ok(hex::encode(hasher.finalize()))
}

/// Calculate thold_price from base_price and collateral_ratio
/// collateral_ratio is expressed as percentage (e.g., 135 for 135%)
pub fn calculate_thold_price(base_price: u32, collateral_ratio: f64) -> u32 {
    // thold_price = base_price * (collateral_ratio / 100)
    // This is the liquidation price threshold
    ((base_price as f64) * (collateral_ratio / 100.0)) as u32
}

/// Calculate collateral_ratio from base_price and thold_price
pub fn calculate_collateral_ratio(base_price: u32, thold_price: u32) -> f64 {
    if base_price == 0 {
        return 0.0;
    }
    (thold_price as f64 / base_price as f64) * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_commit_hash() {
        let oracle_pubkey = "6b5008a293291c14effeb0e8b7c56a80ecb5ca7b801768e17ec93092be6c0621";
        let chain_network = "mutinynet";
        let base_price = 100000u32;
        let base_stamp = 1700000000u32;
        let thold_price = 135000u32;

        let result = calculate_commit_hash(
            oracle_pubkey,
            chain_network,
            base_price,
            base_stamp,
            thold_price,
        );

        assert!(result.is_ok());
        let hash = result.unwrap();
        assert_eq!(hash.len(), 64); // 32 bytes hex-encoded
    }

    #[test]
    fn test_calculate_commit_hash_invalid_pubkey() {
        let result = calculate_commit_hash("invalid", "mutinynet", 100000, 1700000000, 135000);
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_commit_hash_short_pubkey() {
        let result = calculate_commit_hash("abcd", "mutinynet", 100000, 1700000000, 135000);
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_thold_price() {
        // 100000 * 135% = 135000
        assert_eq!(calculate_thold_price(100000, 135.0), 135000);

        // 100000 * 150% = 150000
        assert_eq!(calculate_thold_price(100000, 150.0), 150000);

        // 100000 * 200% = 200000
        assert_eq!(calculate_thold_price(100000, 200.0), 200000);
    }

    #[test]
    fn test_calculate_collateral_ratio() {
        // 135000 / 100000 = 135%
        assert!((calculate_collateral_ratio(100000, 135000) - 135.0).abs() < 0.001);

        // 150000 / 100000 = 150%
        assert!((calculate_collateral_ratio(100000, 150000) - 150.0).abs() < 0.001);

        // Edge case: zero base price
        assert_eq!(calculate_collateral_ratio(0, 100), 0.0);
    }

    #[test]
    fn test_commit_hash_deterministic() {
        let oracle_pubkey = "6b5008a293291c14effeb0e8b7c56a80ecb5ca7b801768e17ec93092be6c0621";

        let hash1 =
            calculate_commit_hash(oracle_pubkey, "mutinynet", 100000, 1700000000, 135000).unwrap();
        let hash2 =
            calculate_commit_hash(oracle_pubkey, "mutinynet", 100000, 1700000000, 135000).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_commit_hash_different_for_different_prices() {
        let oracle_pubkey = "6b5008a293291c14effeb0e8b7c56a80ecb5ca7b801768e17ec93092be6c0621";

        let hash1 =
            calculate_commit_hash(oracle_pubkey, "mutinynet", 100000, 1700000000, 135000).unwrap();
        let hash2 =
            calculate_commit_hash(oracle_pubkey, "mutinynet", 100000, 1700000000, 136000).unwrap();

        assert_ne!(hash1, hash2);
    }
}
