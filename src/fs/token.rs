//! Capability token for scoped file access.
//!
//! Minted after row authorization; verified on `PUT`/`GET` without
//! additional policy checks. Short-lived (5m) HMAC.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::fs::error::FsError;
use crate::policy::Action;

/// Claims embedded in a file capability token.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FsClaims {
    /// Subject that may use the token.
    pub sub: String,
    /// File this token grants access to.
    pub file_id: String,
    /// Action granted (`read`/`write`/`delete`).
    pub act: String,
    /// Expiry as unix seconds.
    pub exp: u64,
}

/// Default TTL for tokens.
const DEFAULT_TTL_SECS: u64 = 300;

/// Parses a capability secret from config/env: 64 hex chars (32 bytes).
///
/// Hex keeps secrets copy-pasteable through TOML and env vars without
/// quoting hazards; the length check rejects truncated UUIDs and
/// passphrases at startup instead of minting under weak material.
pub fn parse_secret_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "capability secret must be 64 hex chars (32 bytes), got {} chars",
            s.len()
        ));
    }
    (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Derives a stable `kid` from a secret: the first 4 SHA-256 bytes as
/// hex. Deterministic, so rotated deployments agree on kids without
/// extra config, and distinct per secret so verifiers can tell key
/// generations apart.
pub fn kid_for(secret: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let hash = Sha256::digest(secret);
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3]
    )
}

/// Mint a token for `sub` to perform `act` on `file_id`.
pub fn mint(
    sub: &str,
    file_id: &str,
    act: Action,
    kid: &str,
    secret: &[u8],
    ttl_secs: Option<u64>,
) -> Result<String, FsError> {
    let exp = chrono::Utc::now().timestamp() as u64 + ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
    let claims = FsClaims {
        sub: sub.to_string(),
        file_id: file_id.to_string(),
        act: act.to_string(),
        exp,
    };
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(kid.to_string());
    encode(&header, &claims, &EncodingKey::from_secret(secret))
        .map_err(|e| FsError::Internal(e.to_string()))
}

/// Verify token grants `act` on `file_id`, trying each known secret in
/// order (current first, previous during rotation). A signature that
/// verifies decides: matching claims accept, mismatched claims reject
/// without consulting older keys.
pub fn verify(
    token: &str,
    file_id: &str,
    act: Action,
    secrets: &[&[u8]],
) -> Result<FsClaims, FsError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = 0;
    for secret in secrets {
        let data = match decode::<FsClaims>(token, &DecodingKey::from_secret(secret), &validation)
        {
            Ok(data) => data,
            Err(_) => continue,
        };
        if data.claims.exp < chrono::Utc::now().timestamp() as u64 {
            return Err(FsError::Forbidden);
        }
        if data.claims.file_id != file_id || data.claims.act != act.to_string() {
            return Err(FsError::Forbidden);
        }
        return Ok(data.claims);
    }
    Err(FsError::Forbidden)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Action;

    #[test]
    fn round_trip() {
        let secret = b"test-secret-32-bytes-long-xxxxxx";
        let token = mint("alice", "file1", Action::Read, "k1", secret, Some(60)).unwrap();
        let claims = verify(&token, "file1", Action::Read, &[secret]).unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.file_id, "file1");
        assert_eq!(claims.act, "read");
    }

    #[test]
    fn rejects_wrong_file_or_act() {
        let secret = b"test-secret-32-bytes-long-xxxxxx";
        let token = mint("alice", "file1", Action::Read, "k1", secret, Some(60)).unwrap();
        assert!(verify(&token, "file2", Action::Read, &[secret]).is_err());
        assert!(verify(&token, "file1", Action::Write, &[secret]).is_err());
    }

    #[test]
    fn rejects_expired() {
        let secret = b"test-secret-32-bytes-long-xxxxxx";
        let past = FsClaims {
            sub: "alice".to_string(),
            file_id: "file1".to_string(),
            act: "read".to_string(),
            exp: (chrono::Utc::now().timestamp() as u64).saturating_sub(10),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &past,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        assert!(verify(&token, "file1", Action::Read, &[secret]).is_err());
    }

    #[test]
    fn rotation_accepts_previous_key() {
        let old = b"old-secret-32-bytes-long-xxxxxxxx";
        let new = b"new-secret-32-bytes-long-xxxxxxxx";
        let token = mint("alice", "file1", Action::Read, "k-old", old, Some(60)).unwrap();
        // Current tried first, previous still verifies during rotation.
        let claims = verify(&token, "file1", Action::Read, &[new, old]).unwrap();
        assert_eq!(claims.sub, "alice");
        // Unknown keys verify nothing.
        assert!(verify(&token, "file1", Action::Read, &[new]).is_err());
        assert!(verify(&token, "file1", Action::Read, &[]).is_err());
    }

    #[test]
    fn kid_derivation_is_stable_and_distinct() {
        let a = b"old-secret-32-bytes-long-xxxxxxxx";
        let b = b"new-secret-32-bytes-long-xxxxxxxx";
        assert_eq!(kid_for(a), kid_for(a));
        assert_ne!(kid_for(a), kid_for(b));
        assert_eq!(kid_for(a).len(), 8);
    }

    #[test]
    fn secret_hex_parsing_rejects_weak_material() {
        assert_eq!(parse_secret_hex(&"ab".repeat(32)).unwrap().len(), 32);
        assert!(parse_secret_hex(&"ab".repeat(31)).is_err());
        assert!(parse_secret_hex(&"zz".repeat(32)).is_err());
        assert!(parse_secret_hex("passphrase-as-secret").is_err());
    }
}
