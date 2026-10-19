//! One logical paid request and the idempotency material its retries share.
//!
//! When a paid retry gets no definitive answer (a transport error, a timeout,
//! a server error), the payment may or may not have settled. Retrying the same
//! request must then reuse the same idempotency material — the x402
//! `payment-identifier`, or the exact signed `upto` header — so the server can
//! recognise it instead of charging again. A definitive answer clears it.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::Result;

type Digest32 = [u8; 32];

/// Material kept for unresolved attempts, by attempt identity then by offer.
static PENDING: LazyLock<Mutex<HashMap<Digest32, HashMap<Digest32, Pending>>>> =
    LazyLock::new(Mutex::default);

struct Pending {
    value: String,
    expires: Instant,
}

/// The identity of one logical paid request: method, URL, and body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentAttempt {
    identity: Digest32,
}

impl PaymentAttempt {
    pub fn new(method: &str, url: &str, body: Option<&[u8]>) -> Self {
        let mut hasher = Sha256::new();
        for part in [method.as_bytes(), url.as_bytes()] {
            hasher.update((part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        match body {
            Some(body) => {
                hasher.update([1]);
                hasher.update(Sha256::digest(body));
            }
            None => hasher.update([0]),
        }
        Self {
            identity: hasher.finalize().into(),
        }
    }

    /// The material pending for this attempt and offer, or a new value from
    /// `make` that stays pending for `ttl` until [`Self::resolved`].
    pub(crate) fn reuse_or_insert(
        &self,
        kind: &str,
        terms: &[&str],
        ttl: Duration,
        make: impl FnOnce() -> Result<String>,
    ) -> Result<String> {
        let offer = offer_key(kind, terms);
        let now = Instant::now();
        if let Some(pending) = PENDING
            .lock()
            .unwrap()
            .get(&self.identity)
            .and_then(|offers| offers.get(&offer))
            .filter(|pending| pending.expires > now)
        {
            return Ok(pending.value.clone());
        }
        let value = make()?;
        let mut pending = PENDING.lock().unwrap();
        pending.retain(|_, offers| {
            offers.retain(|_, entry| entry.expires > now);
            !offers.is_empty()
        });
        pending.entry(self.identity).or_default().insert(
            offer,
            Pending {
                value: value.clone(),
                expires: now + ttl,
            },
        );
        Ok(value)
    }

    /// The server answered definitively: forget this attempt's material.
    pub fn resolved(&self) {
        PENDING.lock().unwrap().remove(&self.identity);
    }
}

fn offer_key(kind: &str, terms: &[&str]) -> Digest32 {
    let mut hasher = Sha256::new();
    for part in std::iter::once(kind).chain(terms.iter().copied()) {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter() -> impl FnMut() -> Result<String> {
        let mut next = 0;
        move || {
            next += 1;
            Ok(format!("value-{next}"))
        }
    }

    #[test]
    fn a_pending_attempt_reuses_its_material_until_resolved() {
        let attempt = PaymentAttempt::new("POST", "https://a.example/pending", Some(b"{}"));
        let ttl = Duration::from_secs(60);
        let mut make = counter();
        let first = attempt
            .reuse_or_insert("k", &["t"], ttl, &mut make)
            .unwrap();
        let retry = attempt
            .reuse_or_insert("k", &["t"], ttl, &mut make)
            .unwrap();
        assert_eq!(first, retry);

        attempt.resolved();
        let fresh = attempt
            .reuse_or_insert("k", &["t"], ttl, &mut make)
            .unwrap();
        assert_ne!(first, fresh);
        attempt.resolved();
    }

    #[test]
    fn material_is_scoped_to_request_identity_and_offer() {
        let ttl = Duration::from_secs(60);
        let mut make = counter();
        let attempt = PaymentAttempt::new("POST", "https://a.example/scoped", Some(b"a"));
        let base = attempt
            .reuse_or_insert("k", &["t"], ttl, &mut make)
            .unwrap();

        let other_body = PaymentAttempt::new("POST", "https://a.example/scoped", Some(b"b"));
        let no_body = PaymentAttempt::new("POST", "https://a.example/scoped", None);
        let other_method = PaymentAttempt::new("PUT", "https://a.example/scoped", Some(b"a"));
        for other in [&other_body, &no_body, &other_method] {
            assert_ne!(other, &attempt);
            assert_ne!(
                other.reuse_or_insert("k", &["t"], ttl, &mut make).unwrap(),
                base
            );
            other.resolved();
        }
        // Changed payment terms are a different offer.
        assert_ne!(
            attempt
                .reuse_or_insert("k", &["t2"], ttl, &mut make)
                .unwrap(),
            base
        );
        assert_ne!(
            attempt
                .reuse_or_insert("k2", &["t"], ttl, &mut make)
                .unwrap(),
            base
        );
        // Field boundaries are length-prefixed.
        assert_ne!(offer_key("k", &["ab", "c"]), offer_key("k", &["a", "bc"]));
        attempt.resolved();
    }

    #[test]
    fn expired_material_is_replaced() {
        let attempt = PaymentAttempt::new("GET", "https://a.example/expired", None);
        let mut make = counter();
        let first = attempt
            .reuse_or_insert("k", &["t"], Duration::ZERO, &mut make)
            .unwrap();
        let second = attempt
            .reuse_or_insert("k", &["t"], Duration::from_secs(60), &mut make)
            .unwrap();
        assert_ne!(first, second);
        attempt.resolved();
    }
}
