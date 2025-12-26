use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

/// Request tracking for pending requests
pub struct PendingRequest {
    pub request_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub result_sender: Option<oneshot::Sender<WebhookPayload>>,
    pub status: RequestStatus,
    pub result: Option<WebhookPayload>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStatus {
    Pending,
    Completed,
    Timeout,
}

/// Webhook payload from CRE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event_type: String,
    pub event_id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: i32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
    #[serde(default)]
    pub nostr_event: Option<serde_json::Value>,
}

/// v2.5 Price quote response matching client-sdk main branch schema
/// NOTE: Prices are f64 to match cre-hmac which uses float64 for HMAC computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceQuoteResponse {
    // Server identity
    pub srv_network: String,   // "main" | "test"
    pub srv_pubkey: String,    // Oracle public key (hex)

    // Quote price (at commitment creation)
    pub quote_origin: String,  // "link" | "nostr" | "cre"
    pub quote_price: f64,      // BTC/USD price
    pub quote_stamp: i64,      // Unix timestamp

    // Latest price (most recent observation)
    pub latest_origin: String,
    pub latest_price: f64,
    pub latest_stamp: i64,

    // Event price (at breach, if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_price: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_stamp: Option<i64>,
    pub event_type: String,    // "active" | "breach"

    // Threshold commitment
    pub thold_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thold_key: Option<String>,
    pub thold_price: f64,

    // State & signatures
    pub is_expired: bool,
    pub req_id: String,
    pub req_sig: String,
}

/// Legacy price contract response for internal CRE communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceContractResponse {
    pub chain_network: String,
    pub oracle_pubkey: String,
    pub base_price: f64,
    pub base_stamp: i64,
    pub commit_hash: String,
    pub contract_id: String,
    pub oracle_sig: String,
    pub thold_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thold_key: Option<String>,
    pub thold_price: f64,
}

impl PriceContractResponse {
    /// Convert internal format to v2.5 client-sdk format
    pub fn to_v25_quote(&self) -> PriceQuoteResponse {
        let is_expired = self.thold_key.is_some();
        let origin = "cre".to_string();
        PriceQuoteResponse {
            // Server identity
            srv_network: self.chain_network.clone(),
            srv_pubkey: self.oracle_pubkey.clone(),
            // Quote price
            quote_origin: origin.clone(),
            quote_price: self.base_price,
            quote_stamp: self.base_stamp,
            // Latest price (same as quote for CRE responses)
            latest_origin: origin.clone(),
            latest_price: self.base_price,
            latest_stamp: self.base_stamp,
            // Event price
            event_origin: if is_expired { Some(origin) } else { None },
            event_price: if is_expired { Some(self.base_price) } else { None },
            event_stamp: if is_expired { Some(self.base_stamp) } else { None },
            event_type: if is_expired { "breach".to_string() } else { "active".to_string() },
            // Threshold commitment
            thold_hash: self.thold_hash.clone(),
            thold_key: self.thold_key.clone(),
            thold_price: self.thold_price,
            // State & signatures
            is_expired,
            req_id: self.commit_hash.clone(),
            req_sig: self.oracle_sig.clone(),
        }
    }
}

/// Quote response with collateral ratio (returned to frontend) - v2.5 format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteResponse {
    #[serde(flatten)]
    pub quote: PriceQuoteResponse,
    /// Collateral ratio as percentage (e.g., 135.0 for 135%)
    pub collateral_ratio: f64,
}

/// Create quote request (query params)
#[derive(Debug, Deserialize)]
pub struct CreateRequest {
    pub th: f64,
    #[serde(default)]
    pub domain: Option<String>,
}

/// Check request body
#[derive(Debug, Deserialize)]
pub struct CheckRequest {
    pub domain: String,
    pub thold_hash: String,
}

/// Sync response for timeout/pending states
#[derive(Debug, Serialize)]
pub struct SyncResponse {
    pub status: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<WebhookPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: String,
    pub uptime: String,
}

/// Readiness response with dependency status
#[derive(Debug, Serialize)]
pub struct ReadinessResponse {
    pub status: String,
    pub timestamp: String,
    pub version: String,
    pub uptime: String,
    pub dependencies: std::collections::HashMap<String, DependencyHealth>,
    pub metrics: HealthMetrics,
}

#[derive(Debug, Serialize)]
pub struct DependencyHealth {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub last_checked: String,
}

#[derive(Debug, Serialize)]
pub struct HealthMetrics {
    pub pending_requests: usize,
    pub max_pending: usize,
    pub capacity_used_percent: f64,
}

/// At-risk vault from liquidation service
#[derive(Debug, Clone, Deserialize)]
pub struct AtRiskVault {
    pub vault_id: String,
    pub thold_hash: String,
    pub thold_price: f64,
    pub current_ratio: f64,
    pub collateral_btc: f64,
    pub debt_dusd: f64,
}

/// Response from liquidation service
#[derive(Debug, Clone, Deserialize)]
pub struct AtRiskResponse {
    pub at_risk_vaults: Vec<AtRiskVault>,
    pub total_count: usize,
    pub current_price: f64,
    pub threshold: f64,
    pub timestamp: i64,
}

/// JWT header
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: String,
}

/// JWT payload
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtPayload {
    pub digest: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_status_equality() {
        assert_eq!(RequestStatus::Pending, RequestStatus::Pending);
        assert_eq!(RequestStatus::Completed, RequestStatus::Completed);
        assert_eq!(RequestStatus::Timeout, RequestStatus::Timeout);
        assert_ne!(RequestStatus::Pending, RequestStatus::Completed);
        assert_ne!(RequestStatus::Completed, RequestStatus::Timeout);
    }

    #[test]
    fn test_request_status_debug() {
        assert_eq!(format!("{:?}", RequestStatus::Pending), "Pending");
        assert_eq!(format!("{:?}", RequestStatus::Completed), "Completed");
        assert_eq!(format!("{:?}", RequestStatus::Timeout), "Timeout");
    }

    #[test]
    fn test_request_status_clone() {
        let status = RequestStatus::Pending;
        let cloned = status.clone();
        assert_eq!(status, cloned);
    }

    #[test]
    fn test_webhook_payload_serialization() {
        let payload = WebhookPayload {
            event_type: "quote_created".to_string(),
            event_id: "abc123".to_string(),
            pubkey: "deadbeef".to_string(),
            created_at: 1700000000,
            kind: 30078,
            tags: vec![vec!["d".to_string(), "thold_hash".to_string()]],
            content: "{}".to_string(),
            sig: "signature".to_string(),
            nostr_event: None,
        };

        let json = serde_json::to_string(&payload).expect("should serialize");
        assert!(json.contains("quote_created"));
        assert!(json.contains("abc123"));

        let parsed: WebhookPayload = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(parsed.event_type, "quote_created");
        assert_eq!(parsed.event_id, "abc123");
    }

    #[test]
    fn test_webhook_payload_with_nostr_event() {
        let json = r#"{
            "event_type": "breach",
            "event_id": "xyz",
            "pubkey": "pub",
            "created_at": 1700000000,
            "kind": 30078,
            "tags": [],
            "content": "{}",
            "sig": "sig",
            "nostr_event": {"id": "nested"}
        }"#;

        let payload: WebhookPayload = serde_json::from_str(json).expect("should parse");
        assert!(payload.nostr_event.is_some());
    }

    #[test]
    fn test_price_contract_response_serialization() {
        let response = PriceContractResponse {
            chain_network: "mutiny".to_string(),
            oracle_pubkey: "pubkey".to_string(),
            base_price: 100000,
            base_stamp: 1700000000,
            commit_hash: "commit".to_string(),
            contract_id: "contract".to_string(),
            oracle_sig: "sig".to_string(),
            thold_hash: "thold".to_string(),
            thold_key: None,
            thold_price: 95000,
        };

        let json = serde_json::to_string(&response).expect("should serialize");
        assert!(json.contains("mutiny"));
        assert!(!json.contains("thold_key")); // Should be skipped when None

        let with_key = PriceContractResponse {
            thold_key: Some("secret".to_string()),
            ..response
        };
        let json_with_key = serde_json::to_string(&with_key).expect("should serialize");
        assert!(json_with_key.contains("thold_key"));
        assert!(json_with_key.contains("secret"));
    }

    #[test]
    fn test_create_request_deserialization() {
        let json = r#"{"th": 95000.5, "domain": "test"}"#;
        let req: CreateRequest = serde_json::from_str(json).expect("should parse");
        assert_eq!(req.th, 95000.5);
        assert_eq!(req.domain, Some("test".to_string()));

        let json_no_domain = r#"{"th": 95000}"#;
        let req2: CreateRequest = serde_json::from_str(json_no_domain).expect("should parse");
        assert_eq!(req2.th, 95000.0);
        assert!(req2.domain.is_none());
    }

    #[test]
    fn test_check_request_deserialization() {
        let json = r#"{"domain": "test-domain", "thold_hash": "abc123"}"#;
        let req: CheckRequest = serde_json::from_str(json).expect("should parse");
        assert_eq!(req.domain, "test-domain");
        assert_eq!(req.thold_hash, "abc123");
    }

    #[test]
    fn test_sync_response_serialization() {
        let response = SyncResponse {
            status: "pending".to_string(),
            request_id: "req123".to_string(),
            data: None,
            result: None,
            message: None,
        };

        let json = serde_json::to_string(&response).expect("should serialize");
        assert!(json.contains("pending"));
        assert!(json.contains("req123"));
        assert!(!json.contains("data")); // Should be skipped when None
        assert!(!json.contains("result"));
        assert!(!json.contains("message"));
    }

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "healthy".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            uptime: "1h30m".to_string(),
        };

        let json = serde_json::to_string(&response).expect("should serialize");
        assert!(json.contains("healthy"));
        assert!(json.contains("2024-01-01"));
        assert!(json.contains("1h30m"));
    }

    #[test]
    fn test_at_risk_vault_deserialization() {
        let json = r#"{
            "vault_id": "vault1",
            "thold_hash": "hash1",
            "thold_price": 95000.0,
            "current_ratio": 1.2,
            "collateral_btc": 1.5,
            "debt_dusd": 100000.0
        }"#;

        let vault: AtRiskVault = serde_json::from_str(json).expect("should parse");
        assert_eq!(vault.vault_id, "vault1");
        assert_eq!(vault.thold_price, 95000.0);
        assert_eq!(vault.current_ratio, 1.2);
    }

    #[test]
    fn test_at_risk_response_deserialization() {
        let json = r#"{
            "at_risk_vaults": [],
            "total_count": 0,
            "current_price": 100000.0,
            "threshold": 95000.0,
            "timestamp": 1700000000
        }"#;

        let response: AtRiskResponse = serde_json::from_str(json).expect("should parse");
        assert_eq!(response.total_count, 0);
        assert!(response.at_risk_vaults.is_empty());
    }

    #[test]
    fn test_jwt_header_serialization() {
        let header = JwtHeader {
            alg: "ES256".to_string(),
            typ: "JWT".to_string(),
        };

        let json = serde_json::to_string(&header).expect("should serialize");
        assert!(json.contains("ES256"));
        assert!(json.contains("JWT"));
    }

    #[test]
    fn test_jwt_payload_serialization() {
        let payload = JwtPayload {
            digest: "abc123".to_string(),
            iss: "ducat-gateway".to_string(),
            iat: 1700000000,
            exp: 1700003600,
            jti: "unique-id".to_string(),
        };

        let json = serde_json::to_string(&payload).expect("should serialize");
        assert!(json.contains("abc123"));
        assert!(json.contains("ducat-gateway"));
        assert!(json.contains("unique-id"));
    }
}
