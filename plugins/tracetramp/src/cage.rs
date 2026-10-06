//! Cage route validation (tenant address hardening).

use crate::error::AppError;

/// Cage tenant address must be hex (SHA-style) to reduce enumeration and path injection.
pub fn validate_cage_sha_address(sha_address: &str) -> Result<(), AppError> {
    let t = sha_address.trim();
    if t.len() < 8 || t.len() > 128 {
        return Err(AppError::Validation(
            "Invalid cage address: expected 8–128 hex characters".to_string(),
        ));
    }
    if !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AppError::Validation(
            "Invalid cage address: expected hexadecimal (SHA-style)".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_hex() {
        validate_cage_sha_address("deadbeef01234567").unwrap();
    }

    #[test]
    fn rejects_short() {
        assert!(validate_cage_sha_address("abc").is_err());
    }

    #[test]
    fn rejects_path_injection() {
        assert!(validate_cage_sha_address("deadbeef/../").is_err());
    }
}
