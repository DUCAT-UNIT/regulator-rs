use metrics::{counter, gauge, histogram, describe_counter, describe_gauge, describe_histogram};
use std::sync::Once;

static INIT: Once = Once::new();

/// Initialize all metrics with descriptions
pub fn init_metrics() {
    INIT.call_once(|| {
        // HTTP request metrics
        describe_counter!(
            "gateway_http_requests_total",
            "Total number of HTTP requests by endpoint and status"
        );
        describe_histogram!(
            "gateway_http_request_duration_seconds",
            "HTTP request latency in seconds"
        );

        // Pending requests
        describe_gauge!(
            "gateway_pending_requests",
            "Current number of pending requests"
        );
        describe_gauge!(
            "gateway_max_pending",
            "Maximum pending requests allowed"
        );

        // Webhook metrics
        describe_counter!(
            "gateway_webhooks_received_total",
            "Total number of webhooks received by event type"
        );
        describe_counter!(
            "gateway_webhook_signature_failures_total",
            "Total number of webhook signature verification failures"
        );

        // Workflow metrics
        describe_counter!(
            "gateway_workflow_triggers_total",
            "Total number of workflow triggers by operation and status"
        );

        // Cleanup metrics
        describe_counter!(
            "gateway_requests_cleaned_up_total",
            "Total number of old requests cleaned up"
        );

        // Timeout metrics
        describe_counter!(
            "gateway_request_timeouts_total",
            "Total number of request timeouts by endpoint"
        );

        // Health check metrics
        describe_counter!(
            "gateway_health_checks_total",
            "Total number of health/readiness checks by status"
        );
        describe_gauge!(
            "gateway_dependency_status",
            "Status of dependencies (1=up, 0.5=degraded, 0=down)"
        );

        // Rate limiting metrics
        describe_counter!(
            "gateway_rate_limit_rejected_total",
            "Total number of requests rejected due to rate limiting"
        );

        // Panic recovery metrics
        describe_counter!(
            "gateway_panics_recovered_total",
            "Total number of panics recovered by the server"
        );

        // Uptime metric
        describe_gauge!(
            "gateway_uptime_seconds",
            "Server uptime in seconds"
        );
    });
}

/// Record an HTTP request
pub fn record_http_request(endpoint: &str, method: &str, status: u16) {
    counter!(
        "gateway_http_requests_total",
        "endpoint" => endpoint.to_string(),
        "method" => method.to_string(),
        "status" => status.to_string()
    )
    .increment(1);
}

/// Record HTTP request duration
pub fn record_http_duration(endpoint: &str, method: &str, duration_secs: f64) {
    histogram!(
        "gateway_http_request_duration_seconds",
        "endpoint" => endpoint.to_string(),
        "method" => method.to_string()
    )
    .record(duration_secs);
}

/// Set pending requests gauge
pub fn set_pending_requests(count: usize) {
    gauge!("gateway_pending_requests").set(count as f64);
}

/// Set max pending gauge
pub fn set_max_pending(max: usize) {
    gauge!("gateway_max_pending").set(max as f64);
}

/// Record a webhook received
pub fn record_webhook_received(event_type: &str, matched: bool) {
    counter!(
        "gateway_webhooks_received_total",
        "event_type" => event_type.to_string(),
        "matched" => matched.to_string()
    )
    .increment(1);
}

/// Record webhook signature failure
pub fn record_webhook_signature_failure(reason: &str) {
    counter!(
        "gateway_webhook_signature_failures_total",
        "reason" => reason.to_string()
    )
    .increment(1);
}

/// Record workflow trigger
pub fn record_workflow_trigger(operation: &str, success: bool) {
    counter!(
        "gateway_workflow_triggers_total",
        "operation" => operation.to_string(),
        "status" => if success { "success" } else { "error" }.to_string()
    )
    .increment(1);
}

/// Record requests cleaned up
pub fn record_requests_cleaned_up(count: usize) {
    counter!("gateway_requests_cleaned_up_total").increment(count as u64);
}

/// Record request timeout
pub fn record_request_timeout(endpoint: &str) {
    counter!(
        "gateway_request_timeouts_total",
        "endpoint" => endpoint.to_string()
    )
    .increment(1);
}

/// Record health check
pub fn record_health_check(check_type: &str, status: &str) {
    counter!(
        "gateway_health_checks_total",
        "type" => check_type.to_string(),
        "status" => status.to_string()
    )
    .increment(1);
}

/// Set dependency status gauge
pub fn set_dependency_status(dependency: &str, status: f64) {
    gauge!(
        "gateway_dependency_status",
        "dependency" => dependency.to_string()
    )
    .set(status);
}

/// Record rate limit rejection
pub fn record_rate_limit_rejected(endpoint: &str) {
    counter!(
        "gateway_rate_limit_rejected_total",
        "endpoint" => endpoint.to_string()
    )
    .increment(1);
}

/// Record panic recovery
pub fn record_panic_recovered() {
    counter!("gateway_panics_recovered_total").increment(1);
}

/// Set uptime seconds
pub fn set_uptime_seconds(seconds: f64) {
    gauge!("gateway_uptime_seconds").set(seconds);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_metrics_idempotent() {
        // Should be safe to call multiple times
        init_metrics();
        init_metrics();
        init_metrics();
    }

    #[test]
    fn test_record_http_request() {
        init_metrics();
        record_http_request("create", "GET", 200);
        record_http_request("webhook", "POST", 400);
    }

    #[test]
    fn test_record_http_duration() {
        init_metrics();
        record_http_duration("create", "GET", 0.123);
        record_http_duration("webhook", "POST", 0.456);
    }

    #[test]
    fn test_set_pending_requests() {
        init_metrics();
        set_pending_requests(10);
        set_pending_requests(20);
    }

    #[test]
    fn test_record_webhook_received() {
        init_metrics();
        record_webhook_received("quote_created", true);
        record_webhook_received("breach", false);
    }

    #[test]
    fn test_record_workflow_trigger() {
        init_metrics();
        record_workflow_trigger("create", true);
        record_workflow_trigger("check", false);
    }

    #[test]
    fn test_record_requests_cleaned_up() {
        init_metrics();
        record_requests_cleaned_up(5);
    }

    #[test]
    fn test_record_request_timeout() {
        init_metrics();
        record_request_timeout("create");
        record_request_timeout("check");
    }

    #[test]
    fn test_record_health_check() {
        init_metrics();
        record_health_check("liveness", "healthy");
        record_health_check("readiness", "degraded");
    }

    #[test]
    fn test_set_dependency_status() {
        init_metrics();
        set_dependency_status("cre_gateway", 1.0);
        set_dependency_status("capacity", 0.5);
    }

    #[test]
    fn test_record_rate_limit_rejected() {
        init_metrics();
        record_rate_limit_rejected("/api/quote");
    }

    #[test]
    fn test_record_panic_recovered() {
        init_metrics();
        record_panic_recovered();
    }

    #[test]
    fn test_set_uptime_seconds() {
        init_metrics();
        set_uptime_seconds(3600.0);
    }
}
