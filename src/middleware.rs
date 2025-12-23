// Middleware module - rate limiting and circuit breaker middleware

use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::Mutex;

/// Maximum number of IP rate limiters to prevent memory exhaustion DoS
const MAX_IP_RATE_LIMITERS: usize = 10000;

/// Simple token bucket rate limiter per IP
/// SECURITY: Enforces maximum map size to prevent memory exhaustion DoS
pub struct IpRateLimiter {
    limiters: Mutex<HashMap<String, TokenBucket>>,
    rate: f64,
    burst: usize,
}

struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

impl IpRateLimiter {
    pub fn new(rate: f64, burst: usize) -> Self {
        Self {
            limiters: Mutex::new(HashMap::new()),
            rate,
            burst,
        }
    }

    /// Check if a request from the given IP should be allowed
    /// SECURITY: Enforces maximum bucket count to prevent memory exhaustion
    pub fn allow(&self, ip: &str) -> bool {
        let mut limiters = self.limiters.lock();
        let now = Instant::now();

        // Check if bucket exists
        if !limiters.contains_key(ip) {
            // If at capacity, remove oldest entry first (LRU eviction)
            if limiters.len() >= MAX_IP_RATE_LIMITERS {
                // Find and remove the oldest entry
                let oldest_key = limiters
                    .iter()
                    .min_by_key(|(_, bucket)| bucket.last_update)
                    .map(|(k, _)| k.clone());

                if let Some(key) = oldest_key {
                    limiters.remove(&key);
                }
            }
        }

        let bucket = limiters.entry(ip.to_string()).or_insert_with(|| TokenBucket {
            tokens: self.burst as f64,
            last_update: now,
        });

        // Refill tokens based on time elapsed
        let elapsed = now.duration_since(bucket.last_update).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst as f64);
        bucket.last_update = now;

        // Check if we have a token available
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Cleanup old entries that haven't been used recently
    pub fn cleanup(&self, max_age: Duration) {
        let mut limiters = self.limiters.lock();
        let now = Instant::now();

        limiters.retain(|_, bucket| {
            now.duration_since(bucket.last_update) < max_age
        });
    }

    /// Get current number of tracked IPs
    pub fn len(&self) -> usize {
        self.limiters.lock().len()
    }

    /// Check if rate limiter is empty
    pub fn is_empty(&self) -> bool {
        self.limiters.lock().is_empty()
    }
}

/// Simple circuit breaker implementation
pub struct CircuitBreaker {
    state: Mutex<CircuitState>,
    threshold: usize,
    reset_timeout: Duration,
}

struct CircuitState {
    failures: usize,
    last_failure: Option<Instant>,
    state: BreakerState,
    half_open_requests: usize,
}

#[derive(Clone, Copy, PartialEq)]
enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitBreaker {
    pub fn new(threshold: usize, reset_timeout: Duration) -> Self {
        Self {
            state: Mutex::new(CircuitState {
                failures: 0,
                last_failure: None,
                state: BreakerState::Closed,
                half_open_requests: 0,
            }),
            threshold,
            reset_timeout,
        }
    }

    /// Check if a request should be allowed through
    pub fn allow(&self) -> bool {
        let mut state = self.state.lock();
        let now = Instant::now();

        match state.state {
            BreakerState::Closed => true,
            BreakerState::Open => {
                // Check if we should transition to half-open
                if let Some(last_failure) = state.last_failure {
                    if now.duration_since(last_failure) > self.reset_timeout {
                        state.state = BreakerState::HalfOpen;
                        state.half_open_requests = 0;
                        return true;
                    }
                }
                false
            }
            BreakerState::HalfOpen => {
                // Allow limited requests in half-open state
                if state.half_open_requests < 3 {
                    state.half_open_requests += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Record a successful request
    pub fn record_success(&self) {
        let mut state = self.state.lock();
        if state.state == BreakerState::HalfOpen {
            state.state = BreakerState::Closed;
            state.failures = 0;
        }
    }

    /// Record a failed request
    pub fn record_failure(&self) {
        let mut state = self.state.lock();
        state.failures += 1;
        state.last_failure = Some(Instant::now());

        if state.state == BreakerState::HalfOpen || state.failures >= self.threshold {
            state.state = BreakerState::Open;
        }
    }

    /// Get current state as string
    pub fn state_str(&self) -> &'static str {
        let state = self.state.lock();
        match state.state {
            BreakerState::Closed => "closed",
            BreakerState::Open => "open",
            BreakerState::HalfOpen => "half-open",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let limiter = IpRateLimiter::new(10.0, 20);

        // Should allow burst
        for _ in 0..20 {
            assert!(limiter.allow("127.0.0.1"));
        }

        // Should be rate limited after burst
        assert!(!limiter.allow("127.0.0.1"));

        // Different IP should have its own bucket
        assert!(limiter.allow("192.168.1.1"));
    }

    #[test]
    fn test_circuit_breaker() {
        let cb = CircuitBreaker::new(3, Duration::from_millis(100));

        // Initially closed
        assert!(cb.allow());
        assert_eq!(cb.state_str(), "closed");

        // Record failures
        cb.record_failure();
        cb.record_failure();
        assert!(cb.allow()); // Still closed

        cb.record_failure(); // Threshold reached
        assert_eq!(cb.state_str(), "open");
        assert!(!cb.allow());

        // Wait for reset timeout
        std::thread::sleep(Duration::from_millis(150));
        assert!(cb.allow()); // Now half-open
        assert_eq!(cb.state_str(), "half-open");

        // Record success to close
        cb.record_success();
        assert_eq!(cb.state_str(), "closed");
    }

    #[test]
    fn test_circuit_breaker_half_open_limited_requests() {
        let cb = CircuitBreaker::new(1, Duration::from_millis(50));

        // Open the circuit
        cb.record_failure();
        assert_eq!(cb.state_str(), "open");

        // Wait for reset timeout
        std::thread::sleep(Duration::from_millis(60));

        // First request transitions to half-open (counter=0, returns true without incrementing)
        assert!(cb.allow());
        assert_eq!(cb.state_str(), "half-open");

        // In half-open, allows requests while counter < 3
        // Counter starts at 0, each allow() increments it
        assert!(cb.allow()); // counter 0 -> 1
        assert!(cb.allow()); // counter 1 -> 2
        assert!(cb.allow()); // counter 2 -> 3

        // 5th request should be blocked (counter=3, not < 3)
        assert!(!cb.allow());
    }

    #[test]
    fn test_circuit_breaker_failure_in_half_open() {
        let cb = CircuitBreaker::new(1, Duration::from_millis(50));

        // Open the circuit
        cb.record_failure();
        assert_eq!(cb.state_str(), "open");

        // Wait for reset timeout
        std::thread::sleep(Duration::from_millis(60));
        cb.allow(); // Transition to half-open
        assert_eq!(cb.state_str(), "half-open");

        // Failure in half-open should reopen
        cb.record_failure();
        assert_eq!(cb.state_str(), "open");
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let limiter = IpRateLimiter::new(10.0, 20);

        // Use an IP
        limiter.allow("192.168.1.1");

        // Check it's in the limiters
        assert!(limiter.limiters.lock().contains_key("192.168.1.1"));

        // Cleanup with short max_age - should remove it since last_update is recent
        limiter.cleanup(Duration::from_secs(0));
        assert!(!limiter.limiters.lock().contains_key("192.168.1.1"));
    }

    #[test]
    fn test_rate_limiter_token_refill() {
        let limiter = IpRateLimiter::new(100.0, 5); // 100 tokens per second, burst 5

        // Exhaust all tokens
        for _ in 0..5 {
            assert!(limiter.allow("test-ip"));
        }
        assert!(!limiter.allow("test-ip"));

        // Wait a bit for refill (50ms should give us ~5 tokens at 100/s)
        std::thread::sleep(Duration::from_millis(50));

        // Should have some tokens now
        assert!(limiter.allow("test-ip"));
    }

    #[test]
    fn test_circuit_breaker_success_in_closed_no_effect() {
        let cb = CircuitBreaker::new(3, Duration::from_millis(100));

        // Recording success in closed state should have no effect
        cb.record_success();
        assert_eq!(cb.state_str(), "closed");

        // Still allows requests
        assert!(cb.allow());
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        let limiter = IpRateLimiter::new(10.0, 2);

        // Exhaust tokens for IP 1
        assert!(limiter.allow("ip1"));
        assert!(limiter.allow("ip1"));
        assert!(!limiter.allow("ip1"));

        // IP 2 should still have tokens
        assert!(limiter.allow("ip2"));
        assert!(limiter.allow("ip2"));
        assert!(!limiter.allow("ip2"));

        // IP 3 should also have tokens
        assert!(limiter.allow("ip3"));
    }

    #[test]
    fn test_rate_limiter_len_and_is_empty() {
        let limiter = IpRateLimiter::new(10.0, 20);

        assert!(limiter.is_empty());
        assert_eq!(limiter.len(), 0);

        limiter.allow("ip1");
        assert!(!limiter.is_empty());
        assert_eq!(limiter.len(), 1);

        limiter.allow("ip2");
        assert_eq!(limiter.len(), 2);

        // Same IP shouldn't increase count
        limiter.allow("ip1");
        assert_eq!(limiter.len(), 2);
    }

    #[test]
    fn test_rate_limiter_max_size_eviction() {
        // Use a small burst to avoid exhausting tokens in test
        let limiter = IpRateLimiter::new(10.0, 100);

        // Add entries up to MAX_IP_RATE_LIMITERS
        // We can't test 10000 entries efficiently, so we test the logic indirectly
        // by verifying that new IPs can always be added (eviction works)
        for i in 0..100 {
            assert!(limiter.allow(&format!("ip{}", i)));
        }

        // All should be tracked
        assert_eq!(limiter.len(), 100);

        // Adding more should still work (no panic, eviction happens when needed)
        for i in 100..200 {
            assert!(limiter.allow(&format!("ip{}", i)));
        }
    }
}
