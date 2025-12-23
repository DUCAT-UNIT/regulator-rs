use anyhow::{anyhow, Result};
use std::time::Duration;

/// Gateway server configuration
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub workflow_id: String,
    pub gateway_url: String,
    pub authorized_key: String,
    pub callback_url: String,
    pub block_timeout: Duration,
    pub cleanup_interval: Duration,
    pub max_pending: usize,

    // Rate limiting
    pub ip_rate_limit: f64,
    pub ip_burst_limit: usize,

    // Webhook security
    pub expected_webhook_pubkey: String,

    // Liquidation service
    pub liquidation_url: String,
    pub liquidation_interval: Duration,
    pub liquidation_enabled: bool,

    // Private key (hex encoded)
    pub private_key_hex: String,

    // Nostr relay
    pub nostr_relay_url: String,

    // Oracle identity (for local commit_hash calculation)
    pub oracle_pubkey: String,
    pub chain_network: String,
}

impl GatewayConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let workflow_id = std::env::var("CRE_WORKFLOW_ID")
            .map_err(|_| anyhow!("CRE_WORKFLOW_ID environment variable not set"))?;

        let gateway_url = std::env::var("CRE_GATEWAY_URL")
            .unwrap_or_else(|_| "https://01.gateway.zone-a.cre.chain.link".to_string());

        let authorized_key = std::env::var("DUCAT_AUTHORIZED_KEY")
            .map_err(|_| anyhow!("DUCAT_AUTHORIZED_KEY environment variable not set"))?;

        let callback_url = std::env::var("GATEWAY_CALLBACK_URL")
            .map_err(|_| anyhow!("GATEWAY_CALLBACK_URL environment variable not set"))?;

        let private_key_hex = std::env::var("DUCAT_PRIVATE_KEY")
            .map_err(|_| anyhow!("DUCAT_PRIVATE_KEY environment variable not set"))?
            .trim_start_matches("0x")
            .to_string();

        // Validate private key
        if private_key_hex.len() != 64 {
            return Err(anyhow!(
                "Private key must be 64 hex chars, got {}",
                private_key_hex.len()
            ));
        }
        hex::decode(&private_key_hex)?;

        let block_timeout = std::env::var("BLOCK_TIMEOUT_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(60));

        let cleanup_interval = std::env::var("CLEANUP_INTERVAL_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(120));

        let max_pending = std::env::var("MAX_PENDING_REQUESTS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);

        let ip_rate_limit = std::env::var("IP_RATE_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10.0);

        let ip_burst_limit = std::env::var("IP_BURST_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);

        let expected_webhook_pubkey = match std::env::var("CRE_WEBHOOK_PUBKEY") {
            Ok(key) => key,
            Err(_) => {
                // Only allow test fallback in test/dev mode
                if std::env::var("RUST_ENV").unwrap_or_default() == "test" {
                    "6a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3".to_string()
                } else {
                    return Err(anyhow!("CRE_WEBHOOK_PUBKEY environment variable not set (required in production)"));
                }
            }
        };

        let liquidation_url = std::env::var("LIQUIDATION_SERVICE_URL")
            .unwrap_or_else(|_| "http://localhost:4001/liq/api/at-risk".to_string());

        let liquidation_interval = std::env::var("LIQUIDATION_INTERVAL_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(90));

        let liquidation_enabled = std::env::var("LIQUIDATION_ENABLED")
            .map(|s| s == "true" || s == "1")
            .unwrap_or(true);

        let nostr_relay_url = std::env::var("NOSTR_RELAY_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());

        let oracle_pubkey = std::env::var("ORACLE_PUBKEY")
            .map_err(|_| anyhow!("ORACLE_PUBKEY environment variable not set"))?;

        // Validate oracle pubkey is 64 hex chars (32 bytes)
        if oracle_pubkey.len() != 64 || hex::decode(&oracle_pubkey).is_err() {
            return Err(anyhow!("ORACLE_PUBKEY must be 64 hex characters"));
        }

        let chain_network = std::env::var("CHAIN_NETWORK")
            .unwrap_or_else(|_| "mutinynet".to_string());

        Ok(Self {
            workflow_id,
            gateway_url,
            authorized_key,
            callback_url,
            block_timeout,
            cleanup_interval,
            max_pending,
            ip_rate_limit,
            ip_burst_limit,
            expected_webhook_pubkey,
            liquidation_url,
            liquidation_interval,
            liquidation_enabled,
            private_key_hex,
            nostr_relay_url,
            oracle_pubkey,
            chain_network,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    // Helper to set required env vars for tests
    fn set_required_env_vars() {
        env::set_var("CRE_WORKFLOW_ID", "test-workflow");
        env::set_var("DUCAT_AUTHORIZED_KEY", "0x1234567890abcdef");
        env::set_var("GATEWAY_CALLBACK_URL", "http://localhost:8080/webhook");
        env::set_var("DUCAT_PRIVATE_KEY", "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c");
        env::set_var("ORACLE_PUBKEY", "6b5008a293291c14effeb0e8b7c56a80ecb5ca7b801768e17ec93092be6c0621");
        env::set_var("RUST_ENV", "test");
    }

    fn clear_env_vars() {
        env::remove_var("CRE_WORKFLOW_ID");
        env::remove_var("DUCAT_AUTHORIZED_KEY");
        env::remove_var("GATEWAY_CALLBACK_URL");
        env::remove_var("DUCAT_PRIVATE_KEY");
        env::remove_var("CRE_GATEWAY_URL");
        env::remove_var("BLOCK_TIMEOUT_SECONDS");
        env::remove_var("CLEANUP_INTERVAL_SECONDS");
        env::remove_var("MAX_PENDING_REQUESTS");
        env::remove_var("IP_RATE_LIMIT");
        env::remove_var("IP_BURST_LIMIT");
        env::remove_var("CRE_WEBHOOK_PUBKEY");
        env::remove_var("LIQUIDATION_SERVICE_URL");
        env::remove_var("LIQUIDATION_INTERVAL_SECONDS");
        env::remove_var("LIQUIDATION_ENABLED");
        env::remove_var("NOSTR_RELAY_URL");
        env::remove_var("ORACLE_PUBKEY");
        env::remove_var("CHAIN_NETWORK");
        env::remove_var("RUST_ENV");
    }

    #[test]
    #[serial]
    fn test_config_from_env_success() {
        clear_env_vars();
        set_required_env_vars();

        let config = GatewayConfig::from_env().expect("should parse config");

        assert_eq!(config.workflow_id, "test-workflow");
        assert_eq!(config.authorized_key, "0x1234567890abcdef");
        assert_eq!(config.callback_url, "http://localhost:8080/webhook");
        assert_eq!(config.private_key_hex.len(), 64);

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_config_missing_workflow_id() {
        clear_env_vars();
        env::set_var("DUCAT_AUTHORIZED_KEY", "0x1234");
        env::set_var("GATEWAY_CALLBACK_URL", "http://localhost");
        env::set_var("DUCAT_PRIVATE_KEY", "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c");
        env::set_var("RUST_ENV", "test");

        let result = GatewayConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CRE_WORKFLOW_ID"));

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_config_missing_authorized_key() {
        clear_env_vars();
        env::set_var("CRE_WORKFLOW_ID", "test");
        env::set_var("GATEWAY_CALLBACK_URL", "http://localhost");
        env::set_var("DUCAT_PRIVATE_KEY", "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c");
        env::set_var("RUST_ENV", "test");

        let result = GatewayConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DUCAT_AUTHORIZED_KEY"));

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_config_missing_callback_url() {
        clear_env_vars();
        env::set_var("CRE_WORKFLOW_ID", "test");
        env::set_var("DUCAT_AUTHORIZED_KEY", "0x1234");
        env::set_var("DUCAT_PRIVATE_KEY", "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c");
        env::set_var("RUST_ENV", "test");

        let result = GatewayConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("GATEWAY_CALLBACK_URL"));

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_config_missing_private_key() {
        clear_env_vars();
        env::set_var("CRE_WORKFLOW_ID", "test");
        env::set_var("DUCAT_AUTHORIZED_KEY", "0x1234");
        env::set_var("GATEWAY_CALLBACK_URL", "http://localhost");
        env::set_var("RUST_ENV", "test");

        let result = GatewayConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DUCAT_PRIVATE_KEY"));

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_config_invalid_private_key_length() {
        clear_env_vars();
        env::set_var("CRE_WORKFLOW_ID", "test");
        env::set_var("DUCAT_AUTHORIZED_KEY", "0x1234");
        env::set_var("GATEWAY_CALLBACK_URL", "http://localhost");
        env::set_var("DUCAT_PRIVATE_KEY", "abcd"); // too short
        env::set_var("RUST_ENV", "test");

        let result = GatewayConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("64 hex chars"));

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_config_invalid_private_key_hex() {
        clear_env_vars();
        env::set_var("CRE_WORKFLOW_ID", "test");
        env::set_var("DUCAT_AUTHORIZED_KEY", "0x1234");
        env::set_var("GATEWAY_CALLBACK_URL", "http://localhost");
        env::set_var("DUCAT_PRIVATE_KEY", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        env::set_var("RUST_ENV", "test");

        let result = GatewayConfig::from_env();
        assert!(result.is_err());

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_config_private_key_with_0x_prefix() {
        clear_env_vars();
        set_required_env_vars();
        env::set_var("DUCAT_PRIVATE_KEY", "0xe0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c");

        let config = GatewayConfig::from_env().expect("should parse config");
        assert_eq!(config.private_key_hex.len(), 64);
        assert!(!config.private_key_hex.starts_with("0x"));

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_config_default_values() {
        clear_env_vars();
        set_required_env_vars();

        let config = GatewayConfig::from_env().expect("should parse config");

        // Check defaults
        assert_eq!(config.gateway_url, "https://01.gateway.zone-a.cre.chain.link");
        assert_eq!(config.block_timeout, Duration::from_secs(60));
        assert_eq!(config.cleanup_interval, Duration::from_secs(120));
        assert_eq!(config.max_pending, 1000);
        assert_eq!(config.ip_rate_limit, 10.0);
        assert_eq!(config.ip_burst_limit, 20);
        assert_eq!(config.liquidation_interval, Duration::from_secs(90));
        assert!(config.liquidation_enabled);

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_config_custom_values() {
        clear_env_vars();
        set_required_env_vars();
        env::set_var("CRE_GATEWAY_URL", "https://custom.gateway.com");
        env::set_var("BLOCK_TIMEOUT_SECONDS", "30");
        env::set_var("CLEANUP_INTERVAL_SECONDS", "60");
        env::set_var("MAX_PENDING_REQUESTS", "500");
        env::set_var("IP_RATE_LIMIT", "5.0");
        env::set_var("IP_BURST_LIMIT", "10");
        env::set_var("LIQUIDATION_ENABLED", "false");

        let config = GatewayConfig::from_env().expect("should parse config");

        assert_eq!(config.gateway_url, "https://custom.gateway.com");
        assert_eq!(config.block_timeout, Duration::from_secs(30));
        assert_eq!(config.cleanup_interval, Duration::from_secs(60));
        assert_eq!(config.max_pending, 500);
        assert_eq!(config.ip_rate_limit, 5.0);
        assert_eq!(config.ip_burst_limit, 10);
        assert!(!config.liquidation_enabled);

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_config_liquidation_enabled_values() {
        clear_env_vars();
        set_required_env_vars();

        // Test "true"
        env::set_var("LIQUIDATION_ENABLED", "true");
        let config = GatewayConfig::from_env().expect("should parse config");
        assert!(config.liquidation_enabled);

        // Test "1"
        env::set_var("LIQUIDATION_ENABLED", "1");
        let config = GatewayConfig::from_env().expect("should parse config");
        assert!(config.liquidation_enabled);

        // Test "false"
        env::set_var("LIQUIDATION_ENABLED", "false");
        let config = GatewayConfig::from_env().expect("should parse config");
        assert!(!config.liquidation_enabled);

        // Test "0"
        env::set_var("LIQUIDATION_ENABLED", "0");
        let config = GatewayConfig::from_env().expect("should parse config");
        assert!(!config.liquidation_enabled);

        clear_env_vars();
    }
}
