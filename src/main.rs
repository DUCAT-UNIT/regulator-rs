mod cache;
mod config;
mod crypto;
mod handlers;
mod metrics;
mod middleware;
mod nostr;
mod types;

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
    routing::{get, post},
    Router,
};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::sync::Arc;
use std::time::Instant;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use http::{Method, header};

use crate::config::GatewayConfig;
use crate::handlers::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ducat_gateway=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Initialize Prometheus metrics exporter
    let prometheus_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus recorder");

    // Initialize metrics descriptions
    metrics::init_metrics();

    // Load configuration
    let config = GatewayConfig::from_env()?;
    tracing::info!(
        workflow_id = %config.workflow_id,
        callback_url = %config.callback_url,
        max_pending = config.max_pending,
        "Gateway server starting"
    );

    // Set max pending gauge
    metrics::set_max_pending(config.max_pending);

    // Initialize application state
    let state = Arc::new(AppState::new(config)?);

    // Start background cleanup task
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        handlers::cleanup_old_requests(cleanup_state).await;
    });

    // Start liquidation polling if enabled
    if state.config.liquidation_enabled {
        let liq_state = state.clone();
        tokio::spawn(async move {
            handlers::poll_liquidation_service(liq_state).await;
        });
    }

    // Store prometheus handle in state for metrics endpoint
    let prometheus_handle = Arc::new(prometheus_handle);
    let metrics_handle = prometheus_handle.clone();

    // Build router with metrics middleware
    let app = Router::new()
        .route("/api/quote", get(handlers::handle_create))
        .route("/webhook/ducat", post(handlers::handle_webhook))
        .route("/health", get(handlers::handle_health))
        .route("/readiness", get(handlers::handle_readiness))
        .route("/status/:request_id", get(handlers::handle_status))
        .route("/check", post(handlers::handle_check))
        .layer(axum::middleware::from_fn(metrics_middleware))
        // Restrictive CORS - only allow configured origins
        .layer(CorsLayer::new()
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]))
        // Request body size limit (1MB)
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .with_state(state);

    // Add metrics endpoint separately (no metrics middleware on metrics endpoint)
    let app = app.route(
        "/metrics",
        get(move || {
            let handle = metrics_handle.clone();
            async move { handle.render() }
        }),
    );

    // Get port from environment
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);

    tracing::info!(address = %addr, "Server listening");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Server shutdown complete");
    Ok(())
}

/// Metrics middleware that records request duration and status
async fn metrics_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().to_string();
    let path = request.uri().path().to_string();

    // Determine endpoint name for metrics
    let endpoint = if path.starts_with("/api/quote") {
        "create"
    } else if path.starts_with("/webhook/ducat") {
        "webhook"
    } else if path.starts_with("/health") {
        "health"
    } else if path.starts_with("/readiness") {
        "readiness"
    } else if path.starts_with("/status") {
        "status"
    } else if path.starts_with("/check") {
        "check"
    } else {
        "other"
    };

    let response = next.run(request).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16();

    // Record metrics
    metrics::record_http_request(endpoint, &method, status);
    metrics::record_http_duration(endpoint, &method, duration);

    response
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received");
}
