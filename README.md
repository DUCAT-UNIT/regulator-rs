# DUCAT Oracle Gateway Server (Rust)

A high-performance, memory-safe gateway server built with Axum that bridges clients with the Chainlink CRE for privacy-preserving threshold price commitments.

## Overview

Rust implementation of the DUCAT Gateway with:
- **Async/Await**: Full async I/O with Tokio runtime
- **Memory Safety**: Zero-cost abstractions with compile-time guarantees
- **Concurrent State**: Lock-free data structures with DashMap

## System Integration

The Regulator is the **orchestrator** - it runs the cron jobs that drive the liquidation system.

### Role in System

```
┌─────────────┐                      ┌─────────────┐
│   Client    │ ◄──────────────────► │  Regulator  │
│   (SDK)     │    REST API          │  (Gateway)  │
└─────────────┘                      └──────┬──────┘
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    │                       │                       │
                    ▼                       ▼                       ▼
            ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
            │     CRE     │         │ Nostr Relay │         │   Indexer   │
            │   (WASM)    │         │             │         │ (at-risk)   │
            └─────────────┘         └─────────────┘         └─────────────┘
```

### Background Jobs

| Job | Frequency | Action |
|-----|-----------|--------|
| **Liquidation Poller** | Every 90s | Poll indexer `/at-risk`, trigger CRE CHECK for each |
| **Cleanup Job** | Every 2min | Remove stale pending requests |

### Endpoints

| Endpoint | Method | Purpose | Called By |
|----------|--------|---------|-----------|
| `GET /api/quote?th=PRICE` | GET | Create threshold commitment | Client SDK |
| `GET /api/price` | GET | Get latest cached price | Client SDK |
| `POST /webhook/ducat` | POST | Receive CRE callback | CRE |
| `POST /check` | POST | Check if threshold breached | Internal (liquidation) |
| `GET /status/:id` | GET | Poll async request status | Client SDK |
| `GET /health` | GET | Liveness probe | Kubernetes |
| `GET /readiness` | GET | Readiness probe | Kubernetes |
| `GET /metrics` | GET | Prometheus metrics | Prometheus |

### Type Schema (v2.5 PriceQuote)

```rust
pub struct PriceQuote {
    // Server identity
    pub srv_network: String,        // "main" | "test"
    pub srv_pubkey: String,         // Oracle public key (hex)

    // Quote price (at commitment creation)
    pub quote_origin: String,       // "link" | "nostr" | "cre"
    pub quote_price: f64,           // BTC/USD price
    pub quote_stamp: i64,           // Unix timestamp

    // Latest price (most recent observation)
    pub latest_origin: String,
    pub latest_price: f64,
    pub latest_stamp: i64,

    // Event price (at breach, if any)
    pub event_origin: Option<String>,
    pub event_price: Option<f64>,
    pub event_stamp: Option<i64>,
    pub event_type: String,         // "active" | "breach"

    // Threshold commitment
    pub thold_hash: String,         // Hash160 (20 bytes hex)
    pub thold_key: Option<String>,  // Revealed on breach
    pub thold_price: f64,

    // State & signatures
    pub is_expired: bool,
    pub req_id: String,             // Request ID hash
    pub req_sig: String,            // Schnorr signature
}
```

**Note**: All prices are `f64` to match cre-hmac HMAC computation.

## CRE Integration

### Request Size Limits

CRE has a **30KB maximum request size** (including headers and body). The gateway automatically batches large liquidation requests:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Batch Size | 500 vaults | ~22KB per batch (safely under 30KB) |
| Batch Delay | 10 seconds | Avoid CRE rate limits (429 errors) |

### Batch Processing

When the liquidation poller detects at-risk vaults:

1. Vaults are split into batches of 500
2. Each batch triggers a separate CRE `evaluate` workflow
3. 10-second delay between batches prevents rate limiting
4. Success/failure logged per batch with running totals

### Circuit Breaker

The Rust implementation includes a circuit breaker to prevent cascading failures:

| Parameter | Value | Description |
|-----------|-------|-------------|
| Failure Threshold | 5 | Consecutive failures before opening |
| Recovery Timeout | 30 seconds | Time before attempting recovery |

## Security Features

- **BIP-340 Schnorr Signature Verification**: Uses `secp256k1` crate
- **Constant-Time Comparisons**: `subtle` crate for timing-attack prevention
- **Replay Attack Prevention**: RwLock-protected event ID cache
- **Timestamp Validation**: 5-minute window, 5-second clock skew tolerance
- **Restrictive CORS**: Configurable allowed origins (no wildcard by default)
- **Request Body Limits**: 1MB limit prevents memory exhaustion

## Environment Variables

### Required
| Variable | Description |
|----------|-------------|
| `CRE_WORKFLOW_ID` | CRE workflow identifier |
| `DUCAT_AUTHORIZED_KEY` | Ethereum address authorized for CRE |
| `GATEWAY_CALLBACK_URL` | URL where CRE sends webhook responses |
| `DUCAT_PRIVATE_KEY` | 64-char hex private key for signing |
| `CRE_WEBHOOK_PUBKEY` | Expected CRE public key (64-char hex) |

### Optional
| Variable | Default | Description |
|----------|---------|-------------|
| `CRE_GATEWAY_URL` | `https://01.gateway.zone-a.cre.chain.link` | CRE gateway |
| `PORT` | `8080` | Server port |
| `BLOCK_TIMEOUT_SECONDS` | `60` | Request timeout |
| `CLEANUP_INTERVAL_SECONDS` | `120` | Cleanup interval |
| `MAX_PENDING_REQUESTS` | `1000` | Max concurrent requests |
| `IP_RATE_LIMIT` | `10` | Requests/second per IP |
| `IP_BURST_LIMIT` | `20` | Burst capacity per IP |
| `LIQUIDATION_SERVICE_URL` | `http://localhost:4001/liq/api/at-risk` | Liquidation endpoint |
| `LIQUIDATION_INTERVAL_SECONDS` | `90` | Polling interval |
| `LIQUIDATION_ENABLED` | `true` | Enable liquidation polling |
| `RUST_ENV` | (none) | Set to `test` for test mode |

## API Endpoints

### `GET /api/quote?th=PRICE`
Create a threshold price commitment.

### `GET /api/price`
Get the latest cached BTC/USD price.

**Response** (200 OK):
```json
{
  "USD": 87202,
  "time": 1766771403
}
```

**Response** (503 Service Unavailable):
```json
{
  "error": "no price available",
  "message": "price data is stale or not yet received"
}
```

### `POST /webhook/ducat`
CRE callback endpoint for signed Nostr events.

### `POST /check`
Check if threshold breach occurred.

### `GET /status/:request_id`
Poll request status.

### `GET /health`
Liveness probe.

### `GET /readiness`
Readiness probe with dependency checks.

### `GET /metrics`
Prometheus-format metrics.

## Building

```bash
cd gateway-rs
cargo build --release
```

## Running

```bash
export CRE_WORKFLOW_ID="your-workflow-id"
export DUCAT_AUTHORIZED_KEY="0x..."
export GATEWAY_CALLBACK_URL="https://your-server/webhook/ducat"
export DUCAT_PRIVATE_KEY="..."
export CRE_WEBHOOK_PUBKEY="..."

./target/release/ducat-gateway
```

## Testing

```bash
RUST_ENV=test cargo test
```

## Dependencies

Key crates:
- `axum` - Web framework
- `tokio` - Async runtime
- `secp256k1` - Schnorr signatures
- `k256` - ECDSA/Ethereum signing
- `dashmap` - Concurrent hash map
- `parking_lot` - Fast synchronization primitives
- `subtle` - Constant-time operations

## Architecture

### Quote Flow

The gateway uses a tiered resolution strategy for quote requests:

```
GET /api/quote?th=95000
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                    Quote Resolution                      │
│                                                         │
│  1. Calculate commit_hash locally                       │
│     commit_hash = hash340("DUCAT/commit",               │
│       oracle_pubkey || chain_network ||                 │
│       base_price || base_stamp || thold_price)          │
│                                                         │
│  2. Check local cache (5-min TTL)                       │
│     └── If found → return with collateral_ratio         │
│                                                         │
│  3. Query Nostr relay by d-tag (commit_hash)            │
│     GET /api/quotes?d=<commit_hash>                     │
│     └── If found → cache + return with collateral_ratio │
│                                                         │
│  4. Fallback to CRE (trigger workflow)                  │
│     └── Wait for webhook → return response              │
└─────────────────────────────────────────────────────────┘
```

### Request Flow

```
Client Request
     │
     ▼
┌─────────────────┐
│  Rate Limiter   │ ← Per-IP token bucket
└────────┬────────┘
         │
         ▼
┌─────────────────┐         ┌─────────────────┐
│ Request Handler │────────▶│   Quote Cache   │
└────────┬────────┘         │  (5-min TTL)    │
         │                  └────────┬────────┘
         │                           │
         │ (cache miss)              │
         ▼                           │
┌─────────────────┐                  │
│  Nostr Client   │────────────────▶ │
│  (HTTP fetch)   │ (cache on hit)   │
└────────┬────────┘                  │
         │                           │
         │ (not found)               │
         ▼                           │
┌─────────────────┐                  │
│ Circuit Breaker │                  │
└────────┬────────┘                  │
         │                           │
         ▼                           │
┌─────────────────┐    ┌─────────────────┐
│  CRE Gateway    │───▶│ Pending Request │
└────────┬────────┘    │     Registry    │
         │             └────────┬────────┘
         ▼                      │
┌─────────────────┐             │
│ Webhook Handler │ ◄───────────┘
│ (Signature      │
│  Verification)  │
└─────────────────┘
```

### Response Format

Quote responses now include `collateral_ratio`:

```json
{
  "chain_network": "mutinynet",
  "oracle_pubkey": "...",
  "base_price": 100000,
  "base_stamp": 1703289600,
  "commit_hash": "...",
  "contract_id": "...",
  "oracle_sig": "...",
  "thold_hash": "...",
  "thold_key": null,
  "thold_price": 135000,
  "collateral_ratio": 135.0
}
```

## Project Structure

```
gateway-rs/
├── Cargo.toml
└── src/
    ├── main.rs       # Server setup, routes
    ├── config.rs     # Configuration loading
    ├── handlers.rs   # HTTP request handlers
    ├── cache.rs      # Quote and price caching
    ├── nostr.rs      # Nostr relay client
    ├── crypto.rs     # Cryptographic operations
    ├── middleware.rs # Rate limiting, circuit breaker
    └── types.rs      # Data structures
```

## Performance

The Rust implementation offers:
- Lower memory footprint than Go/TypeScript
- Zero garbage collection pauses
- Predictable latency under load
- Native async I/O without green threads overhead
