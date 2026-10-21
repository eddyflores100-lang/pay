//! Reference remote spending authority over HTTP(S).
//!
//! PR #514 (`crate::authority`) defines the `SpendingAuthority` trait and the
//! call-path guarantees; it intentionally leaves concrete policy providers to
//! hosts. This module ships the production-shaped reference provider: it
//! consults an external trust service — the Universal Trust Adapter (UTA)
//! pattern discussed in #505 — by POSTing the exact `SpendRequest` JSON and
//! mapping the verdict fail-closed.
//!
//! # Wire contract (single round trip)
//!
//! ```text
//! POST {endpoint}
//! content-type: application/json
//!
//! body: serde_json::to_vec(&SpendRequest)
//!       (headers serialize as [name, value] pairs; request body as a byte array)
//!
//! 2xx + {"decision":"allow","unavailable":false}  -> Ok(AuthorityDecision::Allow)
//! 2xx + {"decision":"deny", "unavailable":false}  -> Ok(AuthorityDecision::Deny)
//! 2xx + {"unavailable":true, ...}                 -> Err(AuthorityUnavailable)
//! non-2xx, malformed body, unknown verdict,
//! transport error, timeout                        -> Err(AuthorityUnavailable)
//! ```
//!
//! Fail-closed by construction: the only path to `Allow` is a 2xx response
//! whose parsed verdict is exactly `decision:"allow"` with a false or absent
//! `unavailable` flag. The `unavailable` flag takes precedence over
//! `decision`, so a provider that failed while its fallback stance is deny
//! surfaces as unavailable — never as a silent policy denial and never as an
//! implicit allow. This mirrors the tested Node bridge semantics in
//! `universal-trust-adapter/pay-mcp-bridge/src/spend514.mjs`.
//!
//! # Security posture
//!
//! - `endpoint` is trusted host configuration, never a tool argument; it is
//!   resolved per call but supplied only by the host that constructs the
//!   `RemoteHttpAuthority`.
//! - No credentials are attached to the consultation, and redirects are not
//!   followed ([`reqwest::redirect::Policy::none`]): the frozen request and
//!   offer snapshot cannot leak to a different origin mid-flight.
//! - Verdict responses are opaque to the agent: they only ever surface as
//!   Allow/Deny/`UNAVAILABLE` through the `AuthorityAttempt` mapping. Hosts
//!   that want receipts (verdict ids, bands, Ed25519 attestations) should
//!   capture them in their own audit sink, e.g. by wrapping this authority.
//! - Deadlines belong to the `AuthorityBinding` (5s default, 60s maximum).
//!   The optional inner `request_timeout` can only narrow that window; it
//!   cannot extend it.
//!
//! # Example
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use pay_mcp::authority::AuthorityBinding;
//! # use pay_mcp::authority_remote::RemoteHttpAuthority;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let authority = Arc::new(RemoteHttpAuthority::new(
//!     "http://127.0.0.1:8642/v1/authority/authorize",
//! )?);
//! let binding = AuthorityBinding::new("trusted-agent-42", authority);
//! # Ok(())
//! # }
//! ```

use crate::authority::{AuthorityDecision, AuthorityUnavailable, SpendRequest, SpendingAuthority};
use serde_json::Value;
use std::{
    future::Future,
    pin::Pin,
    time::Duration,
};

/// Consults a trusted external trust service over HTTP(S) for every spend.
#[derive(Clone)]
pub struct RemoteHttpAuthority {
    endpoint: String,
    client: reqwest::Client,
    request_timeout: Option<Duration>,
}

impl RemoteHttpAuthority {
    /// `endpoint` is trusted configuration, for example
    /// `http://127.0.0.1:8642/v1/authority/authorize` for a local UTA bridge.
    pub fn new(endpoint: impl Into<String>) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            endpoint: endpoint.into(),
            client,
            request_timeout: None,
        })
    }

    /// Optional inner deadline for the consultation itself. It can only
    /// narrow the `AuthorityBinding` timeout that wraps every `authorize`
    /// call; it can never extend it.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }

    /// Maps a parsed verdict to a decision. Anything that is not an
    /// unambiguous, available allow/deny fails closed.
    fn map_verdict(verdict: &Value) -> Result<AuthorityDecision, AuthorityUnavailable> {
        if verdict
            .get("unavailable")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(AuthorityUnavailable);
        }
        match verdict.get("decision").and_then(Value::as_str) {
            Some("allow") => Ok(AuthorityDecision::Allow),
            Some("deny") => Ok(AuthorityDecision::Deny),
            _ => Err(AuthorityUnavailable),
        }
    }
}

impl SpendingAuthority for RemoteHttpAuthority {
    fn authorize(
        &self,
        request: SpendRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorityDecision, AuthorityUnavailable>> + Send + '_>>
    {
        Box::pin(async move {
            // `SpendRequest` is Serialize; a serialization failure is a host
            // bug but must still fail closed rather than panic mid-payment.
            let body = serde_json::to_vec(&request).map_err(|_| AuthorityUnavailable)?;
            let mut builder = self
                .client
                .post(&self.endpoint)
                .header("content-type", "application/json")
                .header("accept", "application/json")
                .body(body);
            if let Some(timeout) = self.request_timeout {
                builder = builder.timeout(timeout);
            }
            let response = builder.send().await.map_err(|_| AuthorityUnavailable)?;
            if !response.status().is_success() {
                return Err(AuthorityUnavailable);
            }
            let bytes = response.bytes().await.map_err(|_| AuthorityUnavailable)?;
            let verdict: Value = serde_json::from_slice(&bytes).map_err(|_| AuthorityUnavailable)?;
            Self::map_verdict(&verdict)
        })
    }
}
