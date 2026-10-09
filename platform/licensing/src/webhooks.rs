/// Stripe webhook helpers — signature verification and event dispatch.
///
/// The primary Stripe handler lives in `routes::stripe_webhook`.
/// This module provides shared webhook utilities and will house
/// additional webhook processors (Paddle, Lemon Squeezy, etc.) in future.

/// Verify the `Stripe-Signature` header using HMAC-SHA256.
///
/// Stripe sends:  `Stripe-Signature: t=<timestamp>,v1=<hex_sig>`
///
/// Reconstructs the signed payload as `"<timestamp>.<raw_body>"` and
/// compares against the expected HMAC. Returns `false` if the timestamp
/// is more than 5 minutes old (replay protection).
pub fn verify_stripe_signature(body: &[u8], sig_header: &str, secret: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut timestamp = "";
    let mut v1_sig = "";
    for part in sig_header.split(',') {
        if let Some(ts) = part.strip_prefix("t=") {
            timestamp = ts;
        } else if let Some(sig) = part.strip_prefix("v1=") {
            v1_sig = sig;
        }
    }

    if timestamp.is_empty() || v1_sig.is_empty() {
        return false;
    }

    // Replay protection: reject events older than 5 minutes
    if let Ok(ts_secs) = timestamp.parse::<i64>() {
        let now = chrono::Utc::now().timestamp();
        if (now - ts_secs).abs() > 300 {
            eprintln!("[webhooks] Stripe timestamp too old (ts={} now={}) — replay?", ts_secs, now);
            return false;
        }
    }

    let signed_payload = format!("{}.{}", timestamp, std::str::from_utf8(body).unwrap_or(""));

    let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(signed_payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    expected == v1_sig
}
