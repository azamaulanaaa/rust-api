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

/// Mint a token for `sub` to perform `act` on `file_id`.
pub fn mint(
    sub: &str,
    file_id: &str,
    act: Action,
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
    header.kid = Some("fs".to_string());
    encode(&header, &claims, &EncodingKey::from_secret(secret))
        .map_err(|e| FsError::Internal(e.to_string()))
}

/// Verify token grants `act` on `file_id`.
pub fn verify(token: &str, file_id: &str, act: Action, secret: &[u8]) -> Result<FsClaims, FsError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = 0;
    let data = decode::<FsClaims>(token, &DecodingKey::from_secret(secret), &validation)
        .map_err(|_| FsError::Forbidden)?;
    if data.claims.exp < chrono::Utc::now().timestamp() as u64 {
        return Err(FsError::Forbidden);
    }
    if data.claims.file_id != file_id || data.claims.act != act.to_string() {
        return Err(FsError::Forbidden);
    }
    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Action;

    #[test]
    fn round_trip() {
        let secret = b"test-secret-32-bytes-long-xxxxxx";
        let token = mint("alice", "file1", Action::Read, secret, Some(60)).unwrap();
        let claims = verify(&token, "file1", Action::Read, secret).unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.file_id, "file1");
        assert_eq!(claims.act, "read");
    }

    #[test]
    fn rejects_wrong_file_or_act() {
        let secret = b"test-secret-32-bytes-long-xxxxxx";
        let token = mint("alice", "file1", Action::Read, secret, Some(60)).unwrap();
        assert!(verify(&token, "file2", Action::Read, secret).is_err());
        assert!(verify(&token, "file1", Action::Write, secret).is_err());
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
        assert!(verify(&token, "file1", Action::Read, secret).is_err());
    }
}
