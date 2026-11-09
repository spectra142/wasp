//! HTTP helpers shared by the web-facing modules.
//!
//! * [`read_body`] reads a response body with a hard size cap so a hostile or
//!   misconfigured server cannot exhaust memory.
//! * [`NotFoundBaseline`] detects "soft 404" behaviour: servers (often SPAs or
//!   catch-all routes) that answer `200 OK` for every path. Without this check,
//!   every probed path on such a host would be reported as an exposed file.

use reqwest::{Client, Response, StatusCode};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of body bytes WASP reads from any single HTTP response.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Read up to [`MAX_BODY_BYTES`] of a response body as (lossy) UTF-8.
pub async fn read_body(resp: Response) -> String {
    read_body_limited(resp, MAX_BODY_BYTES).await
}

/// Read up to `max` bytes of a response body as (lossy) UTF-8. Errors while
/// streaming return whatever was read so far.
pub async fn read_body_limited(mut resp: Response, max: usize) -> String {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = max.saturating_sub(buf.len());
                if chunk.len() >= remaining {
                    buf.extend_from_slice(&chunk[..remaining]);
                    break;
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                log::debug!("error while reading body from {}: {}", resp.url(), e);
                break;
            }
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// A short pseudo-random token for cache-busting / canary paths. It does not
/// need to be cryptographically secure, only unlikely to exist on the target.
pub fn random_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    // Mix in the address of a stack value so concurrent callers diverge.
    let marker = 0u8;
    let addr = &marker as *const u8 as usize as u128;
    format!("{:x}", (nanos ^ addr.rotate_left(64)) & 0xffff_ffff_ffff)
}

/// What a server returns for a path that certainly does not exist.
#[derive(Debug, Clone, Default)]
pub struct NotFoundBaseline {
    /// Successful responses observed for random, non-existent paths. Empty
    /// when the server correctly answers non-existent paths with an error.
    samples: Vec<Sample>,
}

#[derive(Debug, Clone)]
struct Sample {
    status: StatusCode,
    /// Body with the random canary token removed, so responses that echo the
    /// requested path still compare equal.
    body: String,
}

impl NotFoundBaseline {
    /// Probe `base_url` (which must end with `/`) with random paths and record
    /// how the server answers them.
    pub async fn probe(client: &Client, base_url: &str) -> Self {
        let mut samples = Vec::new();
        for suffix in ["", ".php", "/"] {
            let token = format!("wasp-{}", random_token());
            let url = format!("{}{}{}", base_url, token, suffix);
            let resp = match client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    log::debug!("soft-404 baseline request to {} failed: {}", url, e);
                    continue;
                }
            };
            let status = resp.status();
            if !status.is_success() {
                continue;
            }
            let body = read_body(resp).await.replace(&token, "");
            samples.push(Sample { status, body });
        }
        if !samples.is_empty() {
            log::debug!(
                "{} answers non-existent paths with success ({} sample(s)); enabling soft-404 filtering",
                base_url,
                samples.len()
            );
        }
        Self { samples }
    }

    /// Whether the server returns success for paths that do not exist.
    pub fn is_catch_all(&self) -> bool {
        !self.samples.is_empty()
    }

    /// Returns `true` when a successful response for `path` looks like the
    /// server's generic "not found" page rather than real content.
    pub fn is_soft_404(&self, status: StatusCode, path: &str, body: &str) -> bool {
        if !status.is_success() || self.samples.is_empty() {
            return false;
        }
        let path = path.trim_matches('/');
        let body = if path.is_empty() {
            body.to_string()
        } else {
            body.replace(path, "")
        };
        self.samples
            .iter()
            .any(|s| s.status == status && similar(&s.body, &body))
    }
}

/// Cheap similarity check: identical bodies, or bodies whose lengths differ by
/// less than 5% and that share the same leading content.
fn similar(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let (la, lb) = (a.len() as f64, b.len() as f64);
    let max = la.max(lb);
    if max == 0.0 {
        return true;
    }
    if (la - lb).abs() / max > 0.05 {
        return false;
    }
    let prefix = 256.min(a.len()).min(b.len());
    let a_prefix = a.get(..prefix).unwrap_or(a);
    let b_prefix = b.get(..prefix).unwrap_or(b);
    a_prefix == b_prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline(body: &str) -> NotFoundBaseline {
        NotFoundBaseline {
            samples: vec![Sample {
                status: StatusCode::OK,
                body: body.to_string(),
            }],
        }
    }

    #[test]
    fn empty_baseline_never_flags() {
        let b = NotFoundBaseline::default();
        assert!(!b.is_catch_all());
        assert!(!b.is_soft_404(StatusCode::OK, ".env", "<html>app</html>"));
    }

    #[test]
    fn identical_catch_all_page_is_soft_404() {
        let b = baseline("<html><div id=root></div></html>");
        assert!(b.is_soft_404(StatusCode::OK, ".env", "<html><div id=root></div></html>"));
    }

    #[test]
    fn page_echoing_the_path_is_soft_404() {
        let b = baseline("<html>Sorry,  was not found</html>");
        assert!(b.is_soft_404(
            StatusCode::OK,
            "/backup.zip",
            "<html>Sorry, backup.zip was not found</html>"
        ));
    }

    #[test]
    fn distinct_content_is_not_soft_404() {
        let b = baseline("<html><div id=root></div></html>");
        assert!(!b.is_soft_404(StatusCode::OK, ".env", "DB_PASSWORD=hunter2\nAPI_KEY=abc"));
    }

    #[test]
    fn error_status_is_never_soft_404() {
        let b = baseline("x");
        assert!(!b.is_soft_404(StatusCode::NOT_FOUND, ".env", "x"));
    }

    #[test]
    fn random_tokens_differ() {
        assert_ne!(random_token(), {
            std::thread::sleep(std::time::Duration::from_millis(1));
            random_token()
        });
    }
}
