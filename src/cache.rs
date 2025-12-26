//! Price cache for storing latest price data from CRE webhooks
//! and pre-baked quote contracts from Nostr

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cached price observation from CRE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPrice {
    pub oracle_pubkey: String,
    pub chain_network: String,
    pub base_price: u32,
    pub base_stamp: u32,
    pub updated_at: i64,
}

/// Cached quote contract from Nostr
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedQuote {
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
    pub cached_at: i64,
}

impl CachedQuote {
    /// Convert to v2.5 client-sdk format
    pub fn to_v25_quote(&self) -> crate::types::PriceQuoteResponse {
        let is_expired = self.thold_key.is_some();
        let origin = "cre".to_string();
        crate::types::PriceQuoteResponse {
            // Server identity
            srv_network: self.chain_network.clone(),
            srv_pubkey: self.oracle_pubkey.clone(),
            // Quote price
            quote_origin: origin.clone(),
            quote_price: self.base_price as f64,
            quote_stamp: self.base_stamp,
            // Latest price (same as quote for cached responses)
            latest_origin: origin.clone(),
            latest_price: self.base_price as f64,
            latest_stamp: self.base_stamp,
            // Event price
            event_origin: if is_expired { Some(origin) } else { None },
            event_price: if is_expired { Some(self.base_price as f64) } else { None },
            event_stamp: if is_expired { Some(self.base_stamp) } else { None },
            event_type: if is_expired { "breach".to_string() } else { "active".to_string() },
            // Threshold commitment
            thold_hash: self.thold_hash.clone(),
            thold_key: self.thold_key.clone(),
            thold_price: self.thold_price as f64,
            // State & signatures
            is_expired,
            req_id: self.commit_hash.clone(),
            req_sig: self.oracle_sig.clone(),
        }
    }
}

/// Price and quote cache
pub struct QuoteCache {
    /// Latest price observation
    price: RwLock<Option<CachedPrice>>,
    /// Quotes indexed by commit_hash (d-tag)
    quotes: RwLock<HashMap<String, CachedQuote>>,
    /// Maximum quotes to cache (prevent memory exhaustion)
    max_quotes: usize,
}

impl QuoteCache {
    pub fn new(max_quotes: usize) -> Self {
        Self {
            price: RwLock::new(None),
            quotes: RwLock::new(HashMap::new()),
            max_quotes,
        }
    }

    /// Update cached price from webhook
    pub fn update_price(&self, price: CachedPrice) {
        let mut cache = self.price.write();
        *cache = Some(price);
    }

    /// Get current cached price
    pub fn get_price(&self) -> Option<CachedPrice> {
        self.price.read().clone()
    }

    /// Store a quote by commit_hash
    pub fn store_quote(&self, commit_hash: String, quote: CachedQuote) {
        let mut cache = self.quotes.write();

        // Evict oldest if at capacity
        if cache.len() >= self.max_quotes && !cache.contains_key(&commit_hash) {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, q)| q.cached_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            }
        }

        cache.insert(commit_hash, quote);
    }

    /// Get quote by commit_hash (d-tag)
    pub fn get_quote(&self, commit_hash: &str) -> Option<CachedQuote> {
        self.quotes.read().get(commit_hash).cloned()
    }

    /// Store multiple quotes (batch from Nostr)
    pub fn store_quotes(&self, quotes: Vec<CachedQuote>) {
        let mut cache = self.quotes.write();

        for quote in quotes {
            // Evict oldest if at capacity
            if cache.len() >= self.max_quotes && !cache.contains_key(&quote.commit_hash) {
                if let Some(oldest_key) = cache
                    .iter()
                    .min_by_key(|(_, q)| q.cached_at)
                    .map(|(k, _)| k.clone())
                {
                    cache.remove(&oldest_key);
                }
            }
            cache.insert(quote.commit_hash.clone(), quote);
        }
    }

    /// Clear all quotes (e.g., when new batch arrives)
    pub fn clear_quotes(&self) {
        self.quotes.write().clear();
    }

    /// Get cache stats
    pub fn stats(&self) -> (usize, bool) {
        let quotes_count = self.quotes.read().len();
        let has_price = self.price.read().is_some();
        (quotes_count, has_price)
    }

    /// Cleanup quotes older than max_age_secs
    pub fn cleanup_old_quotes(&self, max_age_secs: i64) {
        let now = chrono::Utc::now().timestamp();
        let mut cache = self.quotes.write();
        cache.retain(|_, q| now - q.cached_at < max_age_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_price() -> CachedPrice {
        CachedPrice {
            oracle_pubkey: "abcd".repeat(16),
            chain_network: "mutinynet".to_string(),
            base_price: 100000,
            base_stamp: 1700000000,
            updated_at: chrono::Utc::now().timestamp(),
        }
    }

    fn sample_quote(commit_hash: &str, cached_at: i64) -> CachedQuote {
        CachedQuote {
            chain_network: "mutinynet".to_string(),
            oracle_pubkey: "abcd".repeat(16),
            base_price: 100000,
            base_stamp: 1700000000,
            commit_hash: commit_hash.to_string(),
            contract_id: "contract123".to_string(),
            oracle_sig: "sig".to_string(),
            thold_hash: "thold".to_string(),
            thold_key: None,
            thold_price: 95000,
            cached_at,
        }
    }

    #[test]
    fn test_price_cache() {
        let cache = QuoteCache::new(100);

        assert!(cache.get_price().is_none());

        cache.update_price(sample_price());

        let price = cache.get_price().unwrap();
        assert_eq!(price.base_price, 100000);
    }

    #[test]
    fn test_quote_cache() {
        let cache = QuoteCache::new(100);

        assert!(cache.get_quote("commit1").is_none());

        cache.store_quote("commit1".to_string(), sample_quote("commit1", 1000));

        let quote = cache.get_quote("commit1").unwrap();
        assert_eq!(quote.thold_price, 95000);
    }

    #[test]
    fn test_quote_cache_eviction() {
        let cache = QuoteCache::new(3);

        cache.store_quote("commit1".to_string(), sample_quote("commit1", 1000));
        cache.store_quote("commit2".to_string(), sample_quote("commit2", 2000));
        cache.store_quote("commit3".to_string(), sample_quote("commit3", 3000));

        // Should evict oldest (commit1)
        cache.store_quote("commit4".to_string(), sample_quote("commit4", 4000));

        assert!(cache.get_quote("commit1").is_none());
        assert!(cache.get_quote("commit2").is_some());
        assert!(cache.get_quote("commit3").is_some());
        assert!(cache.get_quote("commit4").is_some());
    }

    #[test]
    fn test_batch_store() {
        let cache = QuoteCache::new(100);

        let quotes = vec![
            sample_quote("commit1", 1000),
            sample_quote("commit2", 2000),
            sample_quote("commit3", 3000),
        ];

        cache.store_quotes(quotes);

        assert!(cache.get_quote("commit1").is_some());
        assert!(cache.get_quote("commit2").is_some());
        assert!(cache.get_quote("commit3").is_some());
    }

    #[test]
    fn test_stats() {
        let cache = QuoteCache::new(100);

        let (count, has_price) = cache.stats();
        assert_eq!(count, 0);
        assert!(!has_price);

        cache.update_price(sample_price());
        cache.store_quote("commit1".to_string(), sample_quote("commit1", 1000));

        let (count, has_price) = cache.stats();
        assert_eq!(count, 1);
        assert!(has_price);
    }
}
