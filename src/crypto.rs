use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use k256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    schnorr::{signature::Verifier, Signature as SchnorrSignature, VerifyingKey},
};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::types::{JwtHeader, JwtPayload, WebhookPayload};

/// Generate a cryptographically random 32-character hex request ID
pub fn generate_request_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| anyhow!("Failed to generate random bytes: {}", e))?;
    Ok(hex::encode(bytes))
}

/// Sign a message using Ethereum's prefixed message format
/// Returns a 65-byte signature in the form r||s||v
pub fn sign_ethereum_message(private_key_hex: &str, message: &str) -> Result<Vec<u8>> {
    let private_key_bytes = hex::decode(private_key_hex)?;
    let signing_key = SigningKey::from_bytes((&private_key_bytes[..]).into())?;

    // Create Ethereum signed message prefix
    let prefix = format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message);

    // Hash with Keccak256
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    let message_hash = hasher.finalize();

    // Sign the message
    let (signature, recovery_id): (Signature, _) = signing_key.sign_recoverable(&message_hash)?;

    let sig_bytes = signature.to_bytes();
    let r = &sig_bytes[0..32];
    let s = &sig_bytes[32..64];

    // Format: r || s || v (Ethereum format: v = recovery_id + 27)
    let mut result = Vec::with_capacity(65);
    result.extend_from_slice(r);
    result.extend_from_slice(s);
    result.push(recovery_id.to_byte() + 27);

    Ok(result)
}

/// Derive Ethereum address from private key
pub fn private_key_to_address(private_key_hex: &str) -> Result<String> {
    let private_key_bytes = hex::decode(private_key_hex)?;
    let signing_key = SigningKey::from_bytes((&private_key_bytes[..]).into())?;
    let verifying_key = signing_key.verifying_key();

    // Get uncompressed public key bytes (without 0x04 prefix)
    let pubkey_bytes = verifying_key.to_encoded_point(false);
    let pubkey_uncompressed = &pubkey_bytes.as_bytes()[1..]; // Skip 0x04 prefix

    // Keccak256 hash
    let mut hasher = Keccak256::new();
    hasher.update(pubkey_uncompressed);
    let hash = hasher.finalize();

    // Take last 20 bytes for address
    Ok(format!("0x{}", hex::encode(&hash[12..])))
}

/// Generate a JWT token for CRE gateway authentication
pub fn generate_jwt(private_key_hex: &str, address: &str, digest: &str, jti: &str) -> Result<String> {
    let now = chrono::Utc::now().timestamp();

    // Create header
    let header = JwtHeader {
        alg: "ETH".to_string(),
        typ: "JWT".to_string(),
    };
    let header_json = serde_json::to_string(&header)?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());

    // Create payload
    let payload = JwtPayload {
        digest: digest.to_string(),
        iss: address.to_string(),
        iat: now,
        exp: now + 300, // 5 minutes
        jti: jti.to_string(),
    };
    let payload_json = serde_json::to_string(&payload)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    // Create message to sign
    let message = format!("{}.{}", header_b64, payload_b64);

    // Sign with Ethereum prefix
    let signature = sign_ethereum_message(private_key_hex, &message)?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    Ok(format!("{}.{}", message, signature_b64))
}

/// SECURITY: Tag array limits to prevent memory exhaustion DoS
const MAX_TAGS: usize = 100;
const MAX_TAG_ELEMENTS: usize = 10;
const MAX_TAG_ELEMENT_LEN: usize = 1024;

/// Verify webhook signature (BIP-340 Schnorr)
pub fn verify_webhook_signature(payload: &WebhookPayload) -> Result<()> {
    // Validate required fields
    if payload.event_id.is_empty() {
        return Err(anyhow!("missing event_id"));
    }
    if payload.pubkey.is_empty() {
        return Err(anyhow!("missing pubkey"));
    }
    if payload.sig.is_empty() {
        return Err(anyhow!("missing signature"));
    }

    // SECURITY: Validate tags array size to prevent memory exhaustion DoS
    if payload.tags.len() > MAX_TAGS {
        return Err(anyhow!(
            "too many tags: max {}, got {}",
            MAX_TAGS,
            payload.tags.len()
        ));
    }
    for tag in &payload.tags {
        if tag.len() > MAX_TAG_ELEMENTS {
            return Err(anyhow!(
                "too many tag elements: max {}, got {}",
                MAX_TAG_ELEMENTS,
                tag.len()
            ));
        }
        for element in tag {
            if element.len() > MAX_TAG_ELEMENT_LEN {
                return Err(anyhow!(
                    "tag element too long: max {}, got {}",
                    MAX_TAG_ELEMENT_LEN,
                    element.len()
                ));
            }
        }
    }

    // Validate field lengths
    if payload.event_id.len() != 64 {
        return Err(anyhow!(
            "invalid event_id length: expected 64 hex chars, got {}",
            payload.event_id.len()
        ));
    }
    if payload.pubkey.len() != 64 {
        return Err(anyhow!(
            "invalid pubkey length: expected 64 hex chars, got {}",
            payload.pubkey.len()
        ));
    }
    if payload.sig.len() != 128 {
        return Err(anyhow!(
            "invalid signature length: expected 128 hex chars, got {}",
            payload.sig.len()
        ));
    }

    // Recompute event ID to verify integrity
    // NIP-01 format: [0, <pubkey>, <created_at>, <kind>, <tags>, <content>]
    let tags_json = serde_json::to_string(&payload.tags)?;
    let serialized = format!(
        "[0,\"{}\",{},{},{},\"{}\"]",
        payload.pubkey,
        payload.created_at,
        payload.kind,
        tags_json,
        escape_json_string(&payload.content)
    );

    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    let computed_hash = hasher.finalize();
    let computed_id = hex::encode(computed_hash);

    if computed_id != payload.event_id {
        return Err(anyhow!(
            "event_id mismatch: computed {}, got {}",
            computed_id,
            payload.event_id
        ));
    }

    // Decode and verify Schnorr signature
    let sig_bytes = hex::decode(&payload.sig)?;

    // SECURITY: Reject all-zero signatures to prevent potential bypass attacks
    if sig_bytes.iter().all(|&b| b == 0) {
        return Err(anyhow!("invalid signature: all-zero signature rejected"));
    }

    let signature = SchnorrSignature::try_from(&sig_bytes[..])?;

    let pubkey_bytes = hex::decode(&payload.pubkey)?;

    // SECURITY: Reject all-zero pubkeys to prevent point-at-infinity attacks
    if pubkey_bytes.iter().all(|&b| b == 0) {
        return Err(anyhow!("invalid pubkey: all-zero pubkey rejected"));
    }

    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)?;

    let event_id_bytes = hex::decode(&payload.event_id)?;

    verifying_key
        .verify(&event_id_bytes, &signature)
        .map_err(|_| anyhow!("schnorr signature verification failed"))
}

/// Escape a string for JSON serialization (matching Go's json.Marshal behavior)
fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

/// Compute SHA256 hash and return as hex string prefixed with 0x
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    format!("0x{}", hex::encode(hash))
}

/// Extract domain tag from webhook tags
pub fn get_tag(tags: &[Vec<String>], key: &str) -> Option<String> {
    tags.iter()
        .find(|tag| tag.len() >= 2 && tag[0] == key)
        .map(|tag| tag[1].clone())
}

/// Truncate event ID for logging (prevents log injection)
pub fn truncate_event_id(event_id: &str) -> &str {
    if event_id.len() <= 16 {
        event_id
    } else {
        &event_id[..16]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_request_id() {
        let id1 = generate_request_id().unwrap();
        let id2 = generate_request_id().unwrap();

        assert_eq!(id1.len(), 32);
        assert_eq!(id2.len(), 32);
        assert_ne!(id1, id2);

        // Verify valid hex
        assert!(hex::decode(&id1).is_ok());
    }

    #[test]
    fn test_sign_ethereum_message() {
        let private_key = "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c";
        let message = "test message";

        let signature = sign_ethereum_message(private_key, message).unwrap();

        assert_eq!(signature.len(), 65);

        // Verify v is in Ethereum format (27-30)
        let v = signature[64];
        assert!(v >= 27 && v <= 30);
    }

    #[test]
    fn test_private_key_to_address() {
        let private_key = "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c";
        let address = private_key_to_address(private_key).unwrap();

        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_generate_jwt() {
        let private_key = "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c";
        let address = "0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82";
        let digest = "0x1234567890abcdef";
        let jti = generate_request_id().unwrap();

        let token = generate_jwt(private_key, address, digest, &jti).unwrap();

        // Verify JWT structure (header.payload.signature)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_get_tag() {
        let tags = vec![
            vec!["domain".to_string(), "test-domain".to_string()],
            vec!["other".to_string(), "value".to_string()],
        ];

        assert_eq!(get_tag(&tags, "domain"), Some("test-domain".to_string()));
        assert_eq!(get_tag(&tags, "other"), Some("value".to_string()));
        assert_eq!(get_tag(&tags, "missing"), None);
    }

    #[test]
    fn test_truncate_event_id() {
        assert_eq!(truncate_event_id("short"), "short");
        assert_eq!(
            truncate_event_id("1234567890123456789012345678901234567890"),
            "1234567890123456"
        );
    }

    #[test]
    fn test_truncate_event_id_edge_cases() {
        // Empty string
        assert_eq!(truncate_event_id(""), "");

        // Exactly 16 chars
        assert_eq!(truncate_event_id("1234567890123456"), "1234567890123456");

        // Exactly 17 chars (should truncate)
        assert_eq!(truncate_event_id("12345678901234567"), "1234567890123456");
    }

    #[test]
    fn test_sha256_hex() {
        let data = b"test data";
        let hash = sha256_hex(data);

        // Should start with 0x
        assert!(hash.starts_with("0x"));

        // Should be 66 chars (0x + 64 hex chars)
        assert_eq!(hash.len(), 66);

        // Should be deterministic
        let hash2 = sha256_hex(data);
        assert_eq!(hash, hash2);

        // Different data should produce different hash
        let hash3 = sha256_hex(b"different data");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_escape_json_string() {
        // Test basic escaping
        assert_eq!(escape_json_string("hello"), "hello");
        assert_eq!(escape_json_string("hello\"world"), "hello\\\"world");
        assert_eq!(escape_json_string("hello\\world"), "hello\\\\world");
        assert_eq!(escape_json_string("hello\nworld"), "hello\\nworld");
        assert_eq!(escape_json_string("hello\rworld"), "hello\\rworld");
        assert_eq!(escape_json_string("hello\tworld"), "hello\\tworld");

        // Test control characters
        let control_char = String::from_utf8(vec![0x01]).unwrap();
        assert_eq!(escape_json_string(&control_char), "\\u0001");

        // Test empty string
        assert_eq!(escape_json_string(""), "");

        // Test unicode (should pass through)
        assert_eq!(escape_json_string("hello\u{1F600}world"), "hello\u{1F600}world");
    }

    #[test]
    fn test_get_tag_edge_cases() {
        // Empty tags
        let empty_tags: Vec<Vec<String>> = vec![];
        assert_eq!(get_tag(&empty_tags, "domain"), None);

        // Tag with only one element (no value)
        let single_element_tag = vec![vec!["domain".to_string()]];
        assert_eq!(get_tag(&single_element_tag, "domain"), None);

        // Tag with empty value
        let empty_value_tag = vec![vec!["domain".to_string(), "".to_string()]];
        assert_eq!(get_tag(&empty_value_tag, "domain"), Some("".to_string()));

        // Multiple tags with same key (should return first)
        let duplicate_tags = vec![
            vec!["domain".to_string(), "first".to_string()],
            vec!["domain".to_string(), "second".to_string()],
        ];
        assert_eq!(get_tag(&duplicate_tags, "domain"), Some("first".to_string()));
    }

    #[test]
    fn test_sign_ethereum_message_empty() {
        let private_key = "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c";

        // Empty message should still work
        let signature = sign_ethereum_message(private_key, "").unwrap();
        assert_eq!(signature.len(), 65);
    }

    #[test]
    fn test_sign_ethereum_message_long() {
        let private_key = "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c";

        // Long message should work
        let long_message = "a".repeat(10000);
        let signature = sign_ethereum_message(private_key, &long_message).unwrap();
        assert_eq!(signature.len(), 65);
    }

    #[test]
    fn test_sign_ethereum_message_invalid_key() {
        // Invalid hex (non-hex chars)
        let result = sign_ethereum_message("zzzzzzzz", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_to_address_invalid() {
        // Invalid hex (non-hex chars)
        let result = private_key_to_address("zzzzzzzz");
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_jwt_structure() {
        let private_key = "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c";
        let address = "0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82";
        let digest = "0xdeadbeef";
        let jti = "test-jti-123";

        let token = generate_jwt(private_key, address, digest, jti).unwrap();
        let parts: Vec<&str> = token.split('.').collect();

        // Decode and verify header
        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: JwtHeader = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header.alg, "ETH");
        assert_eq!(header.typ, "JWT");

        // Decode and verify payload
        let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: JwtPayload = serde_json::from_slice(&payload_json).unwrap();
        assert_eq!(payload.digest, digest);
        assert_eq!(payload.iss, address);
        assert_eq!(payload.jti, jti);
        assert_eq!(payload.exp, payload.iat + 300);

        // Verify signature is 65 bytes (base64 decoded)
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(sig_bytes.len(), 65);
    }

    #[test]
    fn test_verify_webhook_signature_missing_fields() {
        // Missing event_id
        let payload = WebhookPayload {
            event_type: "test".to_string(),
            event_id: "".to_string(),
            pubkey: "a".repeat(64),
            created_at: 1234567890,
            kind: 1,
            tags: vec![],
            content: "test content".to_string(),
            sig: "b".repeat(128),
            nostr_event: None,
        };
        assert!(verify_webhook_signature(&payload).is_err());

        // Missing pubkey
        let payload = WebhookPayload {
            event_type: "test".to_string(),
            event_id: "a".repeat(64),
            pubkey: "".to_string(),
            created_at: 1234567890,
            kind: 1,
            tags: vec![],
            content: "test content".to_string(),
            sig: "b".repeat(128),
            nostr_event: None,
        };
        assert!(verify_webhook_signature(&payload).is_err());

        // Missing signature
        let payload = WebhookPayload {
            event_type: "test".to_string(),
            event_id: "a".repeat(64),
            pubkey: "a".repeat(64),
            created_at: 1234567890,
            kind: 1,
            tags: vec![],
            content: "test content".to_string(),
            sig: "".to_string(),
            nostr_event: None,
        };
        assert!(verify_webhook_signature(&payload).is_err());
    }

    #[test]
    fn test_verify_webhook_signature_invalid_lengths() {
        // Invalid event_id length
        let payload = WebhookPayload {
            event_type: "test".to_string(),
            event_id: "short".to_string(),
            pubkey: "a".repeat(64),
            created_at: 1234567890,
            kind: 1,
            tags: vec![],
            content: "test content".to_string(),
            sig: "b".repeat(128),
            nostr_event: None,
        };
        assert!(verify_webhook_signature(&payload).is_err());

        // Invalid pubkey length
        let payload = WebhookPayload {
            event_type: "test".to_string(),
            event_id: "a".repeat(64),
            pubkey: "short".to_string(),
            created_at: 1234567890,
            kind: 1,
            tags: vec![],
            content: "test content".to_string(),
            sig: "b".repeat(128),
            nostr_event: None,
        };
        assert!(verify_webhook_signature(&payload).is_err());

        // Invalid signature length
        let payload = WebhookPayload {
            event_type: "test".to_string(),
            event_id: "a".repeat(64),
            pubkey: "a".repeat(64),
            created_at: 1234567890,
            kind: 1,
            tags: vec![],
            content: "test content".to_string(),
            sig: "short".to_string(),
            nostr_event: None,
        };
        assert!(verify_webhook_signature(&payload).is_err());
    }

    #[test]
    fn test_verify_webhook_signature_too_many_tags() {
        let payload = WebhookPayload {
            event_type: "test".to_string(),
            event_id: "a".repeat(64),
            pubkey: "a".repeat(64),
            created_at: 1234567890,
            kind: 1,
            tags: (0..101).map(|_| vec!["tag".to_string()]).collect(),
            content: "test content".to_string(),
            sig: "b".repeat(128),
            nostr_event: None,
        };
        let result = verify_webhook_signature(&payload);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too many tags"));
    }

    #[test]
    fn test_verify_webhook_signature_too_many_tag_elements() {
        let payload = WebhookPayload {
            event_type: "test".to_string(),
            event_id: "a".repeat(64),
            pubkey: "a".repeat(64),
            created_at: 1234567890,
            kind: 1,
            tags: vec![(0..11).map(|i| format!("element{}", i)).collect()],
            content: "test content".to_string(),
            sig: "b".repeat(128),
            nostr_event: None,
        };
        let result = verify_webhook_signature(&payload);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too many tag elements"));
    }

    #[test]
    fn test_verify_webhook_signature_tag_element_too_long() {
        let payload = WebhookPayload {
            event_type: "test".to_string(),
            event_id: "a".repeat(64),
            pubkey: "a".repeat(64),
            created_at: 1234567890,
            kind: 1,
            tags: vec![vec!["x".repeat(1025)]],
            content: "test content".to_string(),
            sig: "b".repeat(128),
            nostr_event: None,
        };
        let result = verify_webhook_signature(&payload);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tag element too long"));
    }

    #[test]
    fn test_verify_webhook_signature_event_id_mismatch() {
        // Mismatched event_id should be rejected (checked before all-zero checks)
        let payload = WebhookPayload {
            event_type: "test".to_string(),
            event_id: "a".repeat(64),
            pubkey: "a".repeat(64),
            created_at: 1234567890,
            kind: 1,
            tags: vec![],
            content: "test content".to_string(),
            sig: "b".repeat(128),
            nostr_event: None,
        };
        let result = verify_webhook_signature(&payload);
        assert!(result.is_err());
        // Will fail at event_id mismatch since computed hash won't match
        assert!(result.unwrap_err().to_string().contains("event_id mismatch"));
    }

    #[test]
    fn test_verify_webhook_signature_invalid_signature_hex() {
        // Invalid hex in signature should fail
        let payload = WebhookPayload {
            event_type: "test".to_string(),
            event_id: "a".repeat(64),
            pubkey: "a".repeat(64),
            created_at: 1234567890,
            kind: 1,
            tags: vec![],
            content: "test content".to_string(),
            sig: "z".repeat(128), // Invalid hex
            nostr_event: None,
        };
        let result = verify_webhook_signature(&payload);
        assert!(result.is_err());
    }
}
