//! Connector URI parsing (`connector://…`).

use crate::error::NativeContractError;
use crate::surface::TargetRef;

/// Parse a canonical connector URI into a [`TargetRef`].
///
/// Expected form:
/// `connector://<tenant>/<namespace>/<kind>/<name>?api=<contract>#<operation>`
///
/// Strict validation: scheme must be `connector`, and tenant / namespace / kind / name
/// must be non-empty path segments.
pub fn parse_connector_uri(uri: &str) -> Result<TargetRef, NativeContractError> {
    let uri = uri.trim();
    let rest = uri
        .strip_prefix("connector://")
        .ok_or_else(|| NativeContractError::InvalidUri("scheme must be connector".into()))?;

    if rest.is_empty() {
        return Err(NativeContractError::InvalidUri("empty authority/path".into()));
    }

    // Split fragment (#operation) first.
    let (before_frag, operation) = match rest.split_once('#') {
        Some((b, frag)) => (b, Some(frag.to_string())),
        None => (rest, None),
    };

    // Split query (?api=…).
    let (path_part, api) = match before_frag.split_once('?') {
        Some((path, query)) => {
            let mut api_val: Option<String> = None;
            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v) = match pair.split_once('=') {
                    Some((k, v)) => (k, v),
                    None => (pair, ""),
                };
                if k == "api" {
                    if v.is_empty() {
                        return Err(NativeContractError::InvalidUri(
                            "api query parameter must be non-empty".into(),
                        ));
                    }
                    api_val = Some(percent_decode(v)?);
                }
            }
            (path, api_val)
        }
        None => (before_frag, None),
    };

    // Path: tenant/namespace/kind/name (no leading slash required after //).
    let path = path_part.trim_start_matches('/');
    if path.is_empty() {
        return Err(NativeContractError::InvalidUri("missing path segments".into()));
    }

    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() != 4 {
        return Err(NativeContractError::InvalidUri(format!(
            "expected exactly 4 path segments (tenant/namespace/kind/name), got {}",
            segments.len()
        )));
    }

    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() {
            return Err(NativeContractError::InvalidUri(format!(
                "empty path segment at index {i}"
            )));
        }
        if seg.contains("..") {
            return Err(NativeContractError::InvalidUri(
                "path segment must not contain ..".into(),
            ));
        }
    }

    let tenant = percent_decode(segments[0])?;
    let namespace = percent_decode(segments[1])?;
    let kind = percent_decode(segments[2])?;
    let name = percent_decode(segments[3])?;

    let operation = match operation {
        Some(op) if op.is_empty() => {
            return Err(NativeContractError::InvalidUri(
                "fragment operation must be non-empty when present".into(),
            ));
        }
        Some(op) => Some(percent_decode(&op)?),
        None => None,
    };

    let canonical = TargetRef::canonical_uri(
        &tenant,
        &namespace,
        &kind,
        &name,
        api.as_deref(),
        operation.as_deref(),
    );

    Ok(TargetRef {
        tenant,
        namespace,
        kind,
        name,
        api,
        operation,
        uri: canonical,
    })
}

fn percent_decode(s: &str) -> Result<String, NativeContractError> {
    // Minimal decode: only + and %XX; reject invalid sequences.
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(NativeContractError::InvalidUri(
                        "truncated percent-encoding".into(),
                    ));
                }
                let h = from_hex(bytes[i + 1])?;
                let l = from_hex(bytes[i + 2])?;
                out.push((h << 4) | l);
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| NativeContractError::InvalidUri("invalid utf-8".into()))
}

fn from_hex(b: u8) -> Result<u8, NativeContractError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(NativeContractError::InvalidUri(
            "invalid percent-encoding hex".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        let uri = "connector://acme/prod/tool/search?api=search.v1#query";
        let t = parse_connector_uri(uri).expect("parse");
        assert_eq!(t.tenant, "acme");
        assert_eq!(t.namespace, "prod");
        assert_eq!(t.kind, "tool");
        assert_eq!(t.name, "search");
        assert_eq!(t.api.as_deref(), Some("search.v1"));
        assert_eq!(t.operation.as_deref(), Some("query"));
        assert_eq!(t.uri, uri);
        let again = parse_connector_uri(&t.uri).expect("reparse");
        assert_eq!(again, t);
    }

    #[test]
    fn parse_without_query_fragment() {
        let t = parse_connector_uri("connector://t/ns/k/n").expect("parse");
        assert!(t.api.is_none());
        assert!(t.operation.is_none());
        assert_eq!(t.uri, "connector://t/ns/k/n");
    }

    #[test]
    fn reject_bad_scheme() {
        let err = parse_connector_uri("https://t/ns/k/n").unwrap_err();
        assert!(matches!(err, NativeContractError::InvalidUri(_)));
    }

    #[test]
    fn reject_empty_segments() {
        assert!(parse_connector_uri("connector://t//k/n").is_err());
        assert!(parse_connector_uri("connector://t/ns/k/").is_err());
        assert!(parse_connector_uri("connector:///ns/k/n").is_err());
    }

    #[test]
    fn reject_wrong_segment_count() {
        assert!(parse_connector_uri("connector://t/ns/k").is_err());
        assert!(parse_connector_uri("connector://t/ns/k/n/extra").is_err());
    }
}
