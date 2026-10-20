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

    /// The server answered definitively: forget this attempt's material.
    pub fn resolved(&self) {
        PENDING.lock().unwrap().remove(&self.identity);
    }
}

/// Where pending material is filed: one request, signed by one payer on one
/// network, for one offer. Signed material is never shared across wallets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PaymentCacheKey {
    identity: Digest32,
    offer: Digest32,
}

impl PaymentCacheKey {
    pub(crate) fn new(
        attempt: &PaymentAttempt,
        payer: &solana_pubkey::Pubkey,
        network: &str,
        kind: &str,
        terms: &[&str],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(payer.to_bytes());
        for part in [network, kind].into_iter().chain(terms.iter().copied()) {
            hasher.update((part.len() as u64).to_le_bytes());
            hasher.update(part.as_bytes());
        }
        Self {
            identity: attempt.identity,
            offer: hasher.finalize().into(),
        }
    }

    /// The material pending under this key, or a new value from `make` that
    /// stays pending for `ttl` until [`PaymentAttempt::resolved`].
    pub(crate) fn reuse_or_insert(
        &self,
        ttl: Duration,
        make: impl FnOnce() -> Result<String>,
    ) -> Result<String> {
        let now = Instant::now();
        if let Some(pending) = PENDING
            .lock()
            .unwrap()
            .get(&self.identity)
            .and_then(|offers| offers.get(&self.offer))
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
            self.offer,
            Pending {
                value: value.clone(),
                expires: now + ttl,
            },
        );
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYER: solana_pubkey::Pubkey = solana_pubkey::Pubkey::new_from_array([1; 32]);

    fn counter() -> impl FnMut() -> Result<String> {
        let mut next = 0;
        move || {
            next += 1;
            Ok(format!("value-{next}"))
        }
    }

    fn key(attempt: &PaymentAttempt, kind: &str, terms: &[&str]) -> PaymentCacheKey {
        PaymentCacheKey::new(attempt, &PAYER, "mainnet", kind, terms)
    }

    #[test]
    fn a_pending_attempt_reuses_its_material_until_resolved() {
        let attempt = PaymentAttempt::new("POST", "https://a.example/pending", Some(b"{}"));
        let ttl = Duration::from_secs(60);
        let mut make = counter();
        let key = key(&attempt, "k", &["t"]);
        let first = key.reuse_or_insert(ttl, &mut make).unwrap();
        let retry = key.reuse_or_insert(ttl, &mut make).unwrap();
        assert_eq!(first, retry);

        attempt.resolved();
        let fresh = key.reuse_or_insert(ttl, &mut make).unwrap();
        assert_ne!(first, fresh);
        attempt.resolved();
    }

    #[test]
    fn material_is_scoped_to_request_identity_and_offer() {
        let ttl = Duration::from_secs(60);
        let mut make = counter();
        let attempt = PaymentAttempt::new("POST", "https://a.example/scoped", Some(b"a"));
        let base = key(&attempt, "k", &["t"])
            .reuse_or_insert(ttl, &mut make)
            .unwrap();

        let other_body = PaymentAttempt::new("POST", "https://a.example/scoped", Some(b"b"));
        let no_body = PaymentAttempt::new("POST", "https://a.example/scoped", None);
        let other_method = PaymentAttempt::new("PUT", "https://a.example/scoped", Some(b"a"));
        for other in [&other_body, &no_body, &other_method] {
            assert_ne!(other, &attempt);
            assert_ne!(
                key(other, "k", &["t"])
                    .reuse_or_insert(ttl, &mut make)
                    .unwrap(),
                base
            );
            other.resolved();
        }
        // Changed payment terms are a different offer.
        for other in [key(&attempt, "k", &["t2"]), key(&attempt, "k2", &["t"])] {
            assert_ne!(other.reuse_or_insert(ttl, &mut make).unwrap(), base);
        }
        // Field boundaries are length-prefixed.
        assert_ne!(
            key(&attempt, "k", &["ab", "c"]),
            key(&attempt, "k", &["a", "bc"])
        );
        attempt.resolved();
    }

    #[test]
    fn material_is_scoped_to_payer_and_network() {
        let ttl = Duration::from_secs(60);
        let mut make = counter();
        let attempt = PaymentAttempt::new("POST", "https://a.example/payer", Some(b"a"));
        let base = key(&attempt, "k", &["t"])
            .reuse_or_insert(ttl, &mut make)
            .unwrap();
        let other_payer = solana_pubkey::Pubkey::new_from_array([2; 32]);
        for other in [
            PaymentCacheKey::new(&attempt, &other_payer, "mainnet", "k", &["t"]),
            PaymentCacheKey::new(&attempt, &PAYER, "devnet", "k", &["t"]),
        ] {
            assert_ne!(other.reuse_or_insert(ttl, &mut make).unwrap(), base);
        }
        // Positive control: the same payer and network still reuse it.
        assert_eq!(
            key(&attempt, "k", &["t"])
                .reuse_or_insert(ttl, &mut make)
                .unwrap(),
            base
        );
        attempt.resolved();
    }

    #[test]
    fn expired_material_is_replaced() {
        let attempt = PaymentAttempt::new("GET", "https://a.example/expired", None);
        let mut make = counter();
        let key = key(&attempt, "k", &["t"]);
        let first = key.reuse_or_insert(Duration::ZERO, &mut make).unwrap();
        let second = key
            .reuse_or_insert(Duration::from_secs(60), &mut make)
            .unwrap();
        assert_ne!(first, second);
        attempt.resolved();
    }
}
