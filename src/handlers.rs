use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::oneshot;
use subtle::ConstantTimeEq;

use crate::metrics;
use crate::middleware::CircuitBreaker;

/// Webhook replay protection cache TTL (5 minutes)
const WEBHOOK_CACHE_TTL_SECS: i64 = 300;

use crate::cache::{CachedPrice, QuoteCache};
use crate::config::GatewayConfig;
use crate::crypto::{
    generate_jwt, generate_request_id, get_tag, sha256_hex, truncate_event_id,
    verify_webhook_signature,
};
use crate::nostr::{calculate_commit_hash, calculate_collateral_ratio, NostrClient};
use crate::types::*;

/// Constant-time string comparison to prevent timing attacks
fn secure_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Validate hex string format
fn is_valid_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Application state shared across handlers
pub struct AppState {
    pub config: GatewayConfig,
    pub pending_requests: DashMap<String, PendingRequest>,
    pub start_time: Instant,
    pub http_client: reqwest::Client,
    /// Webhook replay protection cache: event_id -> timestamp
    pub processed_webhooks: RwLock<HashMap<String, i64>>,
    /// Quote and price cache
    pub quote_cache: QuoteCache,
    /// Nostr relay client
    pub nostr_client: NostrClient,
    /// Circuit breaker for CRE gateway
    pub circuit_breaker: CircuitBreaker,
}

impl AppState {
    pub fn new(config: GatewayConfig) -> anyhow::Result<Self> {
        let nostr_client = NostrClient::new(config.nostr_relay_url.clone());
        Ok(Self {
            pending_requests: DashMap::new(),
            start_time: Instant::now(),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            processed_webhooks: RwLock::new(HashMap::new()),
            quote_cache: QuoteCache::new(1000), // Cache up to 1000 quotes
            nostr_client,
            config,
            // Circuit breaker: open after 5 failures, reset after 30 seconds
            circuit_breaker: CircuitBreaker::new(5, std::time::Duration::from_secs(30)),
        })
    }

    /// Check if webhook has been processed (replay attack prevention)
    pub fn is_webhook_replayed(&self, event_id: &str) -> bool {
        let cache = self.processed_webhooks.read();
        cache.contains_key(event_id)
    }

    /// Maximum webhook cache size to prevent memory exhaustion DoS
    const MAX_WEBHOOK_CACHE_SIZE: usize = 10000;

    /// Mark webhook as processed
    /// SECURITY: Enforces maximum cache size to prevent memory exhaustion DoS
    pub fn mark_webhook_processed(&self, event_id: &str) {
        let mut cache = self.processed_webhooks.write();

        // If at capacity, remove oldest entry first (simple eviction)
        if cache.len() >= Self::MAX_WEBHOOK_CACHE_SIZE {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, ts)| *ts)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            }
        }
        cache.insert(event_id.to_string(), Utc::now().timestamp());
    }

    /// Cleanup old webhook entries
    pub fn cleanup_webhook_cache(&self) {
        let now = Utc::now().timestamp();
        let mut cache = self.processed_webhooks.write();
        cache.retain(|_, ts| now - *ts < WEBHOOK_CACHE_TTL_SECS);
    }
}

/// GET /api/quote?th=PRICE - Get quote for threshold price
///
/// New flow:
/// 1. Check if we have cached price data
/// 2. Calculate commit_hash locally for the requested thold_price
/// 3. Try to fetch pre-baked quote from Nostr by d-tag (commit_hash)
/// 4. If not found, fall back to triggering CRE workflow
pub async fn handle_create(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CreateRequest>,
) -> impl IntoResponse {
    // Validate threshold price
    if params.th <= 0.0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid th (threshold price must be positive)"})),
        )
            .into_response();
    }

    let thold_price = params.th as u32;

    // Step 1: Get cached price data
    let cached_price = match state.quote_cache.get_price() {
        Some(price) => price,
        None => {
            tracing::warn!("No cached price available, falling back to CRE");
            return fallback_to_cre(&state, params.th).await;
        }
    };

    // Step 2: Calculate commit_hash locally
    let commit_hash = match calculate_commit_hash(
        &state.config.oracle_pubkey,
        &state.config.chain_network,
        cached_price.base_price,
        cached_price.base_stamp,
        thold_price,
    ) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!(error = %e, "Failed to calculate commit_hash");
            return fallback_to_cre(&state, params.th).await;
        }
    };

    tracing::info!(
        thold_price = thold_price,
        commit_hash = %commit_hash,
        base_price = cached_price.base_price,
        "Looking up pre-baked quote"
    );

    // Step 3: Try to get from local cache first
    if let Some(quote) = state.quote_cache.get_quote(&commit_hash) {
        let collateral_ratio = calculate_collateral_ratio(
            cached_price.base_price,
            quote.thold_price as u32,
        );

        tracing::info!(
            commit_hash = %commit_hash,
            collateral_ratio = collateral_ratio,
            "Quote found in local cache"
        );

        let price_quote = quote.to_v25_quote();

        let response = QuoteResponse {
            quote: price_quote,
            collateral_ratio,
        };

        return (StatusCode::OK, Json(serde_json::to_value(response).unwrap())).into_response();
    }

    // Step 4: Try to fetch from Nostr relay
    match state.nostr_client.fetch_quote_by_dtag(&commit_hash).await {
        Ok(Some(quote)) => {
            let collateral_ratio = calculate_collateral_ratio(
                cached_price.base_price,
                quote.thold_price as u32,
            );

            tracing::info!(
                commit_hash = %commit_hash,
                collateral_ratio = collateral_ratio,
                "Quote fetched from Nostr"
            );

            // Cache for future requests
            state.quote_cache.store_quote(commit_hash.clone(), quote.clone());

            let price_quote = quote.to_v25_quote();

            let response = QuoteResponse {
                quote: price_quote,
                collateral_ratio,
            };

            (StatusCode::OK, Json(serde_json::to_value(response).unwrap())).into_response()
        }
        Ok(None) => {
            tracing::info!(
                commit_hash = %commit_hash,
                "Quote not found in Nostr, falling back to CRE"
            );
            fallback_to_cre(&state, params.th).await
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to fetch from Nostr, falling back to CRE");
            fallback_to_cre(&state, params.th).await
        }
    }
}

/// Fallback to CRE workflow when pre-baked quote not available
async fn fallback_to_cre(state: &Arc<AppState>, thold_price: f64) -> axum::response::Response {
    // Check circuit breaker
    if !state.circuit_breaker.allow() {
        tracing::warn!(
            circuit_state = %state.circuit_breaker.state_str(),
            "Circuit breaker open, rejecting request"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Service temporarily unavailable"})),
        )
            .into_response();
    }

    // Check capacity
    if state.pending_requests.len() >= state.config.max_pending {
        tracing::warn!(
            current = state.pending_requests.len(),
            max = state.config.max_pending,
            "Max pending requests reached"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Server at capacity, please retry later"})),
        )
            .into_response();
    }

    // Generate domain with cryptographically random component
    let random_id = match generate_request_id() {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(error = %e, "Failed to generate random ID");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal server error"})),
            )
                .into_response();
        }
    };

    let domain = format!(
        "req-{}-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        &random_id[..16]
    );
    let tracking_key = domain.clone();

    // Create channel for receiving webhook result
    let (tx, rx) = oneshot::channel();

    // Register pending request
    let pending = PendingRequest {
        request_id: tracking_key.clone(),
        created_at: Utc::now(),
        result_sender: Some(tx),
        status: RequestStatus::Pending,
        result: None,
    };
    state.pending_requests.insert(tracking_key.clone(), pending);

    metrics::set_pending_requests(state.pending_requests.len());

    tracing::info!(
        domain = %domain,
        threshold_price = thold_price,
        "CRE fallback: CREATE request initiated"
    );

    // Trigger CRE workflow
    if let Err(e) = trigger_workflow(
        state,
        "create",
        &domain,
        Some(thold_price),
        None,
        &state.config.callback_url,
    )
    .await
    {
        tracing::error!(domain = %domain, error = %e, "Failed to trigger workflow");
        state.pending_requests.remove(&tracking_key);
        metrics::set_pending_requests(state.pending_requests.len());
        metrics::record_workflow_trigger("create", false);
        state.circuit_breaker.record_failure();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to trigger workflow"})),
        )
            .into_response();
    }

    metrics::record_workflow_trigger("create", true);

    // Wait for webhook or timeout
    let timeout = tokio::time::timeout(state.config.block_timeout, rx).await;

    match timeout {
        Ok(Ok(payload)) => {
            tracing::info!(
                domain = %domain,
                event_id = %truncate_event_id(&payload.event_id),
                "CRE CREATE request completed"
            );

            state.circuit_breaker.record_success();

            if let Some(mut req) = state.pending_requests.get_mut(&tracking_key) {
                req.status = RequestStatus::Completed;
                req.result = Some(payload.clone());
            }

            match serde_json::from_str::<PriceContractResponse>(&payload.content) {
                Ok(contract) => (StatusCode::OK, Json(serde_json::to_value(contract).unwrap()))
                    .into_response(),
                Err(_) => (
                    StatusCode::OK,
                    Json(serde_json::json!({"raw": payload.content})),
                )
                    .into_response(),
            }
        }
        _ => {
            tracing::warn!(domain = %domain, "CRE CREATE request timeout");

            state.circuit_breaker.record_failure();

            if let Some(mut req) = state.pending_requests.get_mut(&tracking_key) {
                req.status = RequestStatus::Timeout;
            }

            metrics::record_request_timeout("create");

            let response = SyncResponse {
                status: "timeout".to_string(),
                request_id: tracking_key.clone(),
                data: None,
                result: None,
                message: Some(format!(
                    "Request is still processing. Use GET /status/{} to check status.",
                    tracking_key
                )),
            };

            (StatusCode::ACCEPTED, Json(serde_json::to_value(response).unwrap())).into_response()
        }
    }
}

/// POST /webhook/ducat - CRE callback endpoint
pub async fn handle_webhook(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WebhookPayload>,
) -> impl IntoResponse {
    // Validate content is not empty
    if payload.content.is_empty() {
        tracing::warn!(event_id = %truncate_event_id(&payload.event_id), "Webhook has empty content");
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Webhook content cannot be empty"})),
        );
    }

    // Check for replay attack BEFORE signature verification (fail fast)
    if state.is_webhook_replayed(&payload.event_id) {
        tracing::warn!(
            event_id = %truncate_event_id(&payload.event_id),
            "Duplicate webhook detected (replay attack prevention)"
        );
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "Duplicate webhook"})),
        );
    }

    // Verify signature
    if let Err(e) = verify_webhook_signature(&payload) {
        tracing::error!(
            error = %e,
            event_id = %truncate_event_id(&payload.event_id),
            "Webhook signature verification failed"
        );
        metrics::record_webhook_signature_failure("invalid_signature");
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Signature verification failed"})),
        );
    }

    // Verify pubkey matches expected (constant-time comparison to prevent timing attacks)
    if !secure_compare(&payload.pubkey, &state.config.expected_webhook_pubkey) {
        tracing::warn!(
            event_id = %truncate_event_id(&payload.event_id),
            "Webhook signed by unauthorized key"
        );
        metrics::record_webhook_signature_failure("unauthorized_key");
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Webhook signed by unauthorized key"})),
        );
    }

    // SECURITY: Check timestamp freshness using direct comparison to avoid integer overflow
    // Webhooks older than 5 minutes are rejected to limit replay window
    // Allow 5 seconds of future drift to handle minor clock skew between servers
    let current_time = Utc::now().timestamp();
    const MAX_CLOCK_SKEW: i64 = 5; // 5 seconds
    const MAX_WEBHOOK_AGE: i64 = 300; // 5 minutes

    if payload.created_at > current_time + MAX_CLOCK_SKEW {
        tracing::warn!(
            created_at = payload.created_at,
            current_time = current_time,
            "Webhook has future timestamp"
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid timestamp"})),
        );
    }
    if payload.created_at < current_time - MAX_WEBHOOK_AGE {
        tracing::warn!(
            created_at = payload.created_at,
            current_time = current_time,
            "Webhook timestamp expired"
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Webhook expired"})),
        );
    }

    // Mark webhook as processed (after all validations pass)
    state.mark_webhook_processed(&payload.event_id);

    // Extract domain from tags
    let domain = match get_tag(&payload.tags, "domain") {
        Some(d) => d,
        None => {
            tracing::warn!(
                event_id = %truncate_event_id(&payload.event_id),
                "Webhook missing required domain tag"
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing required domain tag"})),
            );
        }
    };

    // Find pending request and send result
    let matched = if let Some(mut pending) = state.pending_requests.get_mut(&domain) {
        if let Some(sender) = pending.result_sender.take() {
            if sender.send(payload.clone()).is_ok() {
                tracing::info!(
                    event_type = %payload.event_type,
                    domain = %domain,
                    event_id = %truncate_event_id(&payload.event_id),
                    "Webhook received and matched"
                );
                true
            } else {
                false
            }
        } else {
            false
        }
    } else {
        tracing::debug!(
            domain = %domain,
            event_id = %truncate_event_id(&payload.event_id),
            "Webhook received but no pending request found"
        );
        false
    };

    metrics::record_webhook_received(&payload.event_type, matched);

    (StatusCode::OK, Json(serde_json::json!({"status": "OK"})))
}

/// POST /check - Check threshold breach
pub async fn handle_check(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckRequest>,
) -> impl IntoResponse {
    // Check circuit breaker
    if !state.circuit_breaker.allow() {
        tracing::warn!(
            circuit_state = %state.circuit_breaker.state_str(),
            "Circuit breaker open, rejecting request"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Service temporarily unavailable"})),
        )
            .into_response();
    }

    // Validate request - domain must be non-empty and not too long, thold_hash must be exactly 40 hex chars
    // Max domain length is 253 per DNS spec limit
    const MAX_DOMAIN_LENGTH: usize = 253;
    if req.domain.is_empty() || req.domain.len() > MAX_DOMAIN_LENGTH || !is_valid_hex(&req.thold_hash, 40) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid domain or thold_hash"})),
        )
            .into_response();
    }

    // Check capacity
    if state.pending_requests.len() >= state.config.max_pending {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Server at capacity, please retry later"})),
        )
            .into_response();
    }

    let tracking_key = req.domain.clone();

    // Create channel for receiving webhook result
    let (tx, rx) = oneshot::channel();

    // Register pending request
    let pending = PendingRequest {
        request_id: tracking_key.clone(),
        created_at: Utc::now(),
        result_sender: Some(tx),
        status: RequestStatus::Pending,
        result: None,
    };
    state.pending_requests.insert(tracking_key.clone(), pending);

    // Update pending requests gauge
    metrics::set_pending_requests(state.pending_requests.len());

    tracing::info!(
        domain = %req.domain,
        thold_hash = %req.thold_hash,
        "CHECK request initiated"
    );

    // Trigger CRE workflow
    if let Err(e) = trigger_workflow(
        &state,
        "check",
        &req.domain,
        None,
        Some(&req.thold_hash),
        &state.config.callback_url,
    )
    .await
    {
        tracing::error!(domain = %req.domain, error = %e, "Failed to trigger workflow");
        state.pending_requests.remove(&tracking_key);
        metrics::set_pending_requests(state.pending_requests.len());
        metrics::record_workflow_trigger("check", false);
        state.circuit_breaker.record_failure();
        // SECURITY: Don't expose internal error details to clients
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to trigger workflow"})),
        )
            .into_response();
    }

    metrics::record_workflow_trigger("check", true);

    // Wait for webhook or timeout
    let timeout = tokio::time::timeout(state.config.block_timeout, rx).await;

    match timeout {
        Ok(Ok(payload)) => {
            if payload.event_type == "breach" {
                tracing::info!(domain = %req.domain, "BREACH detected - secret revealed");
            } else {
                tracing::info!(domain = %req.domain, status = %payload.event_type, "CHECK completed");
            }

            state.circuit_breaker.record_success();

            if let Some(mut pending) = state.pending_requests.get_mut(&tracking_key) {
                pending.status = RequestStatus::Completed;
                pending.result = Some(payload.clone());
            }

            match serde_json::from_str::<PriceContractResponse>(&payload.content) {
                Ok(contract) => (StatusCode::OK, Json(serde_json::to_value(contract).unwrap()))
                    .into_response(),
                Err(_) => (
                    StatusCode::OK,
                    Json(serde_json::json!({"raw": payload.content})),
                )
                    .into_response(),
            }
        }
        _ => {
            tracing::warn!(domain = %req.domain, "CHECK request timeout");

            state.circuit_breaker.record_failure();

            if let Some(mut pending) = state.pending_requests.get_mut(&tracking_key) {
                pending.status = RequestStatus::Timeout;
            }

            metrics::record_request_timeout("check");

            let response = SyncResponse {
                status: "timeout".to_string(),
                request_id: tracking_key.clone(),
                data: None,
                result: None,
                message: Some(format!(
                    "Request is still processing. Use GET /status/{} to check status.",
                    tracking_key
                )),
            };

            (StatusCode::ACCEPTED, Json(serde_json::to_value(response).unwrap())).into_response()
        }
    }
}

/// GET /status/:request_id - Check request status
pub async fn handle_status(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<String>,
) -> impl IntoResponse {
    if request_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Missing request_id"})),
        );
    }

    match state.pending_requests.get(&request_id) {
        Some(pending) => {
            if pending.status == RequestStatus::Completed {
                if let Some(ref result) = pending.result {
                    if let Ok(contract) =
                        serde_json::from_str::<PriceContractResponse>(&result.content)
                    {
                        return (StatusCode::OK, Json(serde_json::to_value(contract).unwrap()));
                    }
                }
            }

            let status_str = match pending.status {
                RequestStatus::Pending => "pending",
                RequestStatus::Completed => "completed",
                RequestStatus::Timeout => "timeout",
            };

            let response = SyncResponse {
                status: status_str.to_string(),
                request_id: request_id.clone(),
                data: None,
                result: pending.result.clone(),
                message: if pending.status == RequestStatus::Pending {
                    Some("Request is still processing".to_string())
                } else {
                    None
                },
            };

            (StatusCode::OK, Json(serde_json::to_value(response).unwrap()))
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Request not found"})),
        ),
    }
}

/// GET /health - Liveness probe
pub async fn handle_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed();

    metrics::record_health_check("liveness", "healthy");

    let response = HealthResponse {
        status: "healthy".to_string(),
        timestamp: Utc::now().to_rfc3339(),
        uptime: format!("{:?}", uptime),
    };

    (StatusCode::OK, Json(serde_json::to_value(response).unwrap()))
}

/// GET /api/price - Return the latest cached price from oracle
pub async fn handle_price(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.quote_cache.get_price() {
        Some(cached) => {
            let response = serde_json::json!({
                "USD": cached.base_price as f64,
                "time": cached.base_stamp
            });
            (StatusCode::OK, Json(response))
        }
        None => {
            let response = serde_json::json!({
                "error": "no price available",
                "message": "price data is stale or not yet received"
            });
            (StatusCode::SERVICE_UNAVAILABLE, Json(response))
        }
    }
}

/// GET /readiness - Readiness probe
pub async fn handle_readiness(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut dependencies = std::collections::HashMap::new();
    let mut overall_status = "healthy";

    // Check CRE gateway
    let cre_health = check_cre_gateway(&state).await;
    if cre_health.status != "up" {
        overall_status = "degraded";
    }
    dependencies.insert("cre_gateway".to_string(), cre_health);

    // Check capacity
    let current_pending = state.pending_requests.len();
    let capacity_percent = (current_pending as f64 / state.config.max_pending as f64) * 100.0;

    let (capacity_status, capacity_message) = if capacity_percent >= 100.0 {
        overall_status = "unhealthy";
        ("down", "At capacity limit")
    } else if capacity_percent >= 90.0 {
        overall_status = "degraded";
        ("degraded", "Near capacity limit")
    } else {
        ("up", "Capacity available")
    };

    dependencies.insert(
        "capacity".to_string(),
        DependencyHealth {
            status: capacity_status.to_string(),
            latency: None,
            message: Some(capacity_message.to_string()),
            last_checked: Utc::now().to_rfc3339(),
        },
    );

    // Authentication check
    dependencies.insert(
        "authentication".to_string(),
        DependencyHealth {
            status: "up".to_string(),
            latency: None,
            message: Some("Private key loaded".to_string()),
            last_checked: Utc::now().to_rfc3339(),
        },
    );

    let uptime = state.start_time.elapsed();

    let response = ReadinessResponse {
        status: overall_status.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        version: "1.0.0".to_string(),
        uptime: format!("{:?}", uptime),
        dependencies,
        metrics: HealthMetrics {
            pending_requests: current_pending,
            max_pending: state.config.max_pending,
            capacity_used_percent: capacity_percent,
        },
    };

    let status_code = if overall_status == "unhealthy" {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };

    // Record health check and update dependency status metrics
    metrics::record_health_check("readiness", overall_status);

    // Update dependency status gauges (1.0 = up, 0.5 = degraded, 0.0 = down)
    for (name, health) in &response.dependencies {
        let status_value = match health.status.as_str() {
            "up" => 1.0,
            "degraded" => 0.5,
            _ => 0.0,
        };
        metrics::set_dependency_status(name, status_value);
    }

    (status_code, Json(serde_json::to_value(response).unwrap()))
}

/// GET /metrics - Prometheus metrics (deprecated - use prometheus exporter)
pub async fn handle_metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Simple text format metrics
    let pending = state.pending_requests.len();
    let uptime = state.start_time.elapsed().as_secs();

    let metrics = format!(
        r#"# HELP gateway_pending_requests Current number of pending requests
# TYPE gateway_pending_requests gauge
gateway_pending_requests {}

# HELP gateway_uptime_seconds Server uptime in seconds
# TYPE gateway_uptime_seconds counter
gateway_uptime_seconds {}

# HELP gateway_max_pending Maximum pending requests allowed
# TYPE gateway_max_pending gauge
gateway_max_pending {}
"#,
        pending, uptime, state.config.max_pending
    );

    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        metrics,
    )
}

/// Trigger CRE workflow
async fn trigger_workflow(
    state: &AppState,
    op: &str,
    domain: &str,
    thold_price: Option<f64>,
    thold_hash: Option<&str>,
    callback_url: &str,
) -> anyhow::Result<()> {
    // Build input
    let mut input = serde_json::json!({
        "domain": domain,
        "callback_url": callback_url,
    });

    if let Some(price) = thold_price {
        input["thold_price"] = serde_json::json!(price);
    }
    if let Some(hash) = thold_hash {
        input["thold_hash"] = serde_json::json!(hash);
    }

    // Create JSON-RPC request
    let req_id = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0).to_string();
    let rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "workflows.execute",
        "params": {
            "input": input,
            "workflow": {
                "workflowID": state.config.workflow_id,
            }
        }
    });

    let rpc_json = serde_json::to_vec(&rpc_request)?;

    // Compute digest
    let digest = sha256_hex(&rpc_json);

    // Generate JWT
    let jti = generate_request_id()?;
    let token = generate_jwt(
        &state.config.private_key_hex,
        &state.config.authorized_key,
        &digest,
        &jti,
    )?;

    // Send request
    let response = state
        .http_client
        .post(&state.config.gateway_url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", token))
        .body(rpc_json)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("non-success status {}: {}", status, body);
    }

    Ok(())
}

/// Check CRE gateway health
async fn check_cre_gateway(state: &AppState) -> DependencyHealth {
    let start = Instant::now();

    match state
        .http_client
        .head(&state.config.gateway_url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(_) => {
            let latency = start.elapsed();
            let (status, message) = if latency > std::time::Duration::from_secs(2) {
                ("degraded", "Slow response time")
            } else {
                ("up", "Reachable")
            };

            DependencyHealth {
                status: status.to_string(),
                latency: Some(format!("{:?}", latency)),
                message: Some(message.to_string()),
                last_checked: Utc::now().to_rfc3339(),
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "CRE gateway health check failed");
            DependencyHealth {
                status: "down".to_string(),
                latency: None,
                message: Some(format!("Unreachable: {}", e)),
                last_checked: Utc::now().to_rfc3339(),
            }
        }
    }
}

/// Background task to cleanup old requests
pub async fn cleanup_old_requests(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(state.config.cleanup_interval);

    loop {
        interval.tick().await;

        let now = Utc::now();
        let mut to_remove = Vec::new();

        for entry in state.pending_requests.iter() {
            let age = now.signed_duration_since(entry.created_at);

            let should_delete = match entry.status {
                RequestStatus::Completed | RequestStatus::Timeout => {
                    age > chrono::Duration::minutes(5)
                }
                RequestStatus::Pending => {
                    age > chrono::Duration::from_std(state.config.block_timeout * 2).unwrap()
                }
            };

            if should_delete {
                to_remove.push(entry.key().clone());
            }
        }

        let cleaned = to_remove.len();
        for key in to_remove {
            state.pending_requests.remove(&key);
        }

        // Also cleanup webhook replay cache
        state.cleanup_webhook_cache();

        // Update metrics
        if cleaned > 0 {
            metrics::record_requests_cleaned_up(cleaned);
            metrics::set_pending_requests(state.pending_requests.len());
            tracing::info!(
                removed = cleaned,
                pending = state.pending_requests.len(),
                "Cleanup completed"
            );
        }

        // Update uptime metric
        let uptime = state.start_time.elapsed().as_secs_f64();
        metrics::set_uptime_seconds(uptime);
    }
}

/// Background task to poll liquidation service
pub async fn poll_liquidation_service(state: Arc<AppState>) {
    tracing::info!(
        url = %state.config.liquidation_url,
        interval = ?state.config.liquidation_interval,
        "Starting liquidation service poller"
    );

    let mut interval = tokio::time::interval(state.config.liquidation_interval);

    loop {
        interval.tick().await;

        match state
            .http_client
            .get(&state.config.liquidation_url)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(at_risk) = response.json::<AtRiskResponse>().await {
                        if at_risk.total_count > 0 {
                            tracing::info!(
                                count = at_risk.total_count,
                                current_price = at_risk.current_price,
                                "At-risk vaults detected"
                            );

                            // Trigger batch evaluate for at-risk vaults
                            // Validate hex format to prevent injection
                            let thold_hashes: Vec<String> = at_risk
                                .at_risk_vaults
                                .iter()
                                .filter(|v| is_valid_hex(&v.thold_hash, 40))
                                .map(|v| v.thold_hash.clone())
                                .collect();

                            if !thold_hashes.is_empty() {
                                if let Err(e) =
                                    trigger_batch_evaluate(&state, thold_hashes).await
                                {
                                    tracing::error!(error = %e, "Failed to trigger batch evaluate");
                                }
                            }
                        } else {
                            tracing::debug!(
                                current_price = at_risk.current_price,
                                "No at-risk vaults"
                            );
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Liquidation service unreachable");
            }
        }
    }
}

/// CRE has a 30KB maximum request size limit (including headers and body).
/// Each thold_hash is ~45 bytes (40 hex chars + JSON overhead).
/// With JSON-RPC wrapper overhead (~500 bytes), we can fit ~650 vaults max.
/// Using 500 per batch for safety margin.
const CRE_BATCH_SIZE: usize = 500;

/// Delay between batches to avoid CRE rate limits (429 errors observed at 500ms)
const CRE_BATCH_DELAY: std::time::Duration = std::time::Duration::from_secs(10);

/// Trigger batch evaluate workflow with batching to respect CRE 30KB limit
async fn trigger_batch_evaluate(state: &AppState, thold_hashes: Vec<String>) -> anyhow::Result<()> {
    if thold_hashes.is_empty() {
        return Ok(());
    }

    let total_vaults = thold_hashes.len();
    let num_batches = (total_vaults + CRE_BATCH_SIZE - 1) / CRE_BATCH_SIZE;

    tracing::info!(
        total_vaults = total_vaults,
        batch_size = CRE_BATCH_SIZE,
        num_batches = num_batches,
        "Triggering CRE evaluate for at-risk vaults"
    );

    let mut success_count = 0;
    let mut error_count = 0;

    for (batch_idx, chunk) in thold_hashes.chunks(CRE_BATCH_SIZE).enumerate() {
        let batch_num = batch_idx + 1;
        let batch: Vec<String> = chunk.to_vec();

        // Generate a unique domain for this batch
        let domain = format!(
            "liq-{}-b{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            batch_num
        );

        match trigger_single_batch_evaluate(state, &domain, batch.clone()).await {
            Ok(()) => {
                tracing::info!(
                    batch = batch_num,
                    batch_size = batch.len(),
                    total_batches = num_batches,
                    domain = %domain,
                    "Triggered evaluate workflow batch"
                );
                success_count += 1;
            }
            Err(e) => {
                tracing::error!(
                    batch = batch_num,
                    batch_size = batch.len(),
                    total_batches = num_batches,
                    error = %e,
                    "Failed to trigger evaluate workflow batch"
                );
                error_count += 1;
            }
        }

        // Delay between batches to avoid CRE rate limits
        if batch_idx + 1 < num_batches {
            tokio::time::sleep(CRE_BATCH_DELAY).await;
        }
    }

    tracing::info!(
        successful_batches = success_count,
        failed_batches = error_count,
        total_vaults = total_vaults,
        "Completed triggering evaluate workflow batches"
    );

    Ok(())
}

/// Trigger a single batch evaluate workflow
async fn trigger_single_batch_evaluate(
    state: &AppState,
    domain: &str,
    thold_hashes: Vec<String>,
) -> anyhow::Result<()> {
    let input = serde_json::json!({
        "domain": domain,
        "thold_hashes": thold_hashes,
        "callback_url": state.config.callback_url,
    });

    let req_id = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0).to_string();
    let rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "workflows.execute",
        "params": {
            "input": input,
            "workflow": {
                "workflowID": state.config.workflow_id,
            }
        }
    });

    let rpc_json = serde_json::to_vec(&rpc_request)?;
    let digest = sha256_hex(&rpc_json);

    let jti = generate_request_id()?;
    let token = generate_jwt(
        &state.config.private_key_hex,
        &state.config.authorized_key,
        &digest,
        &jti,
    )?;

    let response = state
        .http_client
        .post(&state.config.gateway_url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", token))
        .body(rpc_json)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("non-success status {}: {}", status, body);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_compare_equal() {
        assert!(secure_compare("hello", "hello"));
        assert!(secure_compare("", ""));
        assert!(secure_compare("a", "a"));
    }

    #[test]
    fn test_secure_compare_not_equal() {
        assert!(!secure_compare("hello", "world"));
        assert!(!secure_compare("hello", "Hello"));
        assert!(!secure_compare("a", "b"));
    }

    #[test]
    fn test_secure_compare_different_lengths() {
        assert!(!secure_compare("hello", "hello!"));
        assert!(!secure_compare("hello!", "hello"));
        assert!(!secure_compare("", "a"));
        assert!(!secure_compare("a", ""));
    }

    #[test]
    fn test_is_valid_hex() {
        // Valid hex
        assert!(is_valid_hex("0123456789abcdef", 16));
        assert!(is_valid_hex("0123456789ABCDEF", 16));
        assert!(is_valid_hex("", 0));
        assert!(is_valid_hex("a".repeat(40).as_str(), 40));

        // Invalid: wrong length
        assert!(!is_valid_hex("0123456789abcdef", 15));
        assert!(!is_valid_hex("0123456789abcdef", 17));

        // Invalid: non-hex chars
        assert!(!is_valid_hex("0123456789abcdeg", 16));
        assert!(!is_valid_hex("zzzzzzzz", 8));
        assert!(!is_valid_hex("hello world", 11));
    }

    #[test]
    fn test_is_valid_hex_edge_cases() {
        // Mixed case is valid
        assert!(is_valid_hex("aAbBcCdDeEfF", 12));

        // Spaces are not valid hex
        assert!(!is_valid_hex("ab cd ef", 8));

        // Unicode is not valid hex
        assert!(!is_valid_hex("aaaaaaaa\u{1F600}", 9));
    }

    fn test_config() -> GatewayConfig {
        GatewayConfig {
            authorized_key: "0xtest".to_string(),
            private_key_hex: "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c".to_string(),
            gateway_url: "http://localhost".to_string(),
            callback_url: "http://localhost/callback".to_string(),
            workflow_id: "test".to_string(),
            expected_webhook_pubkey: "test".to_string(),
            max_pending: 100,
            block_timeout: std::time::Duration::from_secs(30),
            cleanup_interval: std::time::Duration::from_secs(60),
            ip_rate_limit: 10.0,
            ip_burst_limit: 20,
            liquidation_url: "http://localhost/liq".to_string(),
            liquidation_interval: std::time::Duration::from_secs(90),
            nostr_relay_url: "http://localhost:8080".to_string(),
            oracle_pubkey: "6b5008a293291c14effeb0e8b7c56a80ecb5ca7b801768e17ec93092be6c0621".to_string(),
            chain_network: "mutinynet".to_string(),
            liquidation_enabled: false,
        }
    }

    #[tokio::test]
    async fn test_app_state_webhook_replay_detection() {
        let config = test_config();

        let state = AppState::new(config).unwrap();

        // Initially not replayed
        assert!(!state.is_webhook_replayed("event1"));

        // Mark as processed
        state.mark_webhook_processed("event1");

        // Now should be detected as replayed
        assert!(state.is_webhook_replayed("event1"));

        // Different event not replayed
        assert!(!state.is_webhook_replayed("event2"));
    }

    #[tokio::test]
    async fn test_app_state_webhook_cache_max_size() {
        let config = test_config();

        let state = AppState::new(config).unwrap();

        // Fill cache to max size
        for i in 0..AppState::MAX_WEBHOOK_CACHE_SIZE {
            state.mark_webhook_processed(&format!("event{}", i));
        }

        // Add one more - should evict oldest
        state.mark_webhook_processed("new_event");

        // Cache should still be at max size
        let cache = state.processed_webhooks.read();
        assert_eq!(cache.len(), AppState::MAX_WEBHOOK_CACHE_SIZE);
    }

    #[tokio::test]
    async fn test_app_state_cleanup_webhook_cache() {
        let config = test_config();

        let state = AppState::new(config).unwrap();

        // Add some entries
        state.mark_webhook_processed("event1");
        state.mark_webhook_processed("event2");

        // Manually set one to be old (past TTL)
        {
            let mut cache = state.processed_webhooks.write();
            cache.insert("old_event".to_string(), Utc::now().timestamp() - 400); // > 300 TTL
        }

        // Cleanup should remove the old entry
        state.cleanup_webhook_cache();

        // Recent entries should remain
        assert!(state.is_webhook_replayed("event1"));
        assert!(state.is_webhook_replayed("event2"));

        // Old entry should be gone
        assert!(!state.is_webhook_replayed("old_event"));
    }
}
