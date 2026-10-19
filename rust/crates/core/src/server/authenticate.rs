//! Server-side bridge to the MPP `authenticate` intent.
//!
//! Builds a [`pay_kit::mpp::AuthenticateServer`] from pay's endpoint
//! config so the middleware can emit / verify SIWS-style identity
//! tokens that gate subscription endpoints between billing periods
//! without re-prompting the wallet.
//!
//! Composes with [`super::subscription`]: every subscription-gated
//! endpoint also accepts authenticate-intent credentials on
//! subsequent requests within the period.

use pay_kit::mpp::server::{AuthenticateConfig, AuthenticateServer};

use crate::{Error, Result};
use pay_types::metering::{SubscriptionEndpoint, SubscriptionPeriodUnit as TypesPeriodUnit};

use super::subscription::OperatorDefaults;

/// Build an [`AuthenticateServer`] for a subscription-gated endpoint.
///
/// Returns `Ok(None)` when the endpoint hasn't been published yet
/// (`plan_id` missing) — the middleware should still emit a
/// subscription challenge in that case, just not an authenticate
/// challenge.
///
/// `domain` is the HTTP host the server gates (typically the request
/// `Host` header). `uri` is the canonical origin URL.
pub fn build_handler(
    spec: &SubscriptionEndpoint,
    defaults: OperatorDefaults<'_>,
    domain: &str,
    uri: &str,
) -> Result<Option<AuthenticateServer>> {
    let Some(plan_id) = spec.plan_id.clone() else {
        return Ok(None);
    };
    let Some(plan_created_at) = spec.plan_created_at else {
        return Ok(None);
    };
    let (period_unit, period_count) = spec.parse_period().map_err(Error::Config)?;
    let period_hours = period_hours_from_spec(period_unit, period_count)?;

    // `challenge_binding_secret` and `realm` are required on the SDK side, no
    // SDK-internal env-var fallbacks. The pay server middleware
    // resolves both from `operator.{challenge_binding_secret,realm}`
    // in the server YAML (falling back to the subdomain for realm).
    let challenge_binding_secret = defaults
        .challenge_binding_secret
        .map(str::to_string)
        .ok_or_else(|| {
            Error::Config(
                "authenticate handler requires a challenge-binding secret — set \
             `operator.challenge_binding_secret` in the server YAML"
                    .into(),
            )
        })?;
    let realm = defaults
        .realm
        .map(str::to_string)
        .ok_or_else(|| Error::Config("authenticate handler requires a realm".into()))?;

    let config = AuthenticateConfig {
        domain: domain.to_string(),
        uri: uri.to_string(),
        plan_id,
        plan_created_at,
        period_hours,
        subscription_expires: spec.expires_at.clone(),
        network: defaults.network.to_string(),
        program_id: None,
        challenge_binding_secret,
        realm,
        statement: Some("Signed message to use active subscription.".to_string()),
        store: None,
    };

    AuthenticateServer::new(config)
        .map(Some)
        .map_err(|e| Error::Mpp(format!("Failed to initialise AuthenticateServer: {e}")))
}

/// Map pay's typed period unit + count to the SDK's `period_hours`.
fn period_hours_from_spec(unit: TypesPeriodUnit, count: u32) -> Result<u64> {
    if count == 0 {
        return Err(Error::Config(
            "subscription period count must be > 0".into(),
        ));
    }
    let hours = match unit {
        TypesPeriodUnit::Day => (count as u64).saturating_mul(24),
        TypesPeriodUnit::Week => (count as u64).saturating_mul(168),
    };
    if hours == 0 || hours > 8760 {
        return Err(Error::Config(format!(
            "subscription period_hours {hours} out of [1, 8760]"
        )));
    }
    Ok(hours)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_spec(plan_id: Option<&str>) -> SubscriptionEndpoint {
        SubscriptionEndpoint {
            plan_id: plan_id.map(str::to_string),
            plan_created_at: Some(1_780_000_000),
            plan_id_numeric: None,
            plan_bump: None,
            currency: "USDC".into(),
            price_usd: Some(9.99),
            amount_base_units: None,
            period: "30d".into(),
            recipient: None,
            puller: None,
            expires_at: None,
            free_trial_days: None,
        }
    }

    fn defaults<'a>() -> OperatorDefaults<'a> {
        OperatorDefaults {
            puller: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
            recipient: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
            network: "mainnet",
            rpc_url: "https://api.mainnet-beta.solana.com",
            challenge_binding_secret: Some("test-secret-key-do-not-use-32b-pad"),
            realm: Some("api.example.com"),
            fee_payer: false,
            fee_payer_signer: None,
            store: Some(std::sync::Arc::new(pay_kit::mpp::store::MemoryStore::new())),
        }
    }

    #[test]
    fn build_handler_returns_none_when_plan_id_missing() {
        let server = build_handler(
            &make_spec(None),
            defaults(),
            "api.example.com",
            "https://api.example.com/",
        )
        .expect("ok");
        assert!(server.is_none());
    }

    #[test]
    fn build_handler_returns_server_when_spec_complete() {
        let spec = make_spec(Some("Amp9FrnEX17tVeZ7QnHX1Hh4TynhH4sXLRSde797vdKR"));
        let server = build_handler(
            &spec,
            defaults(),
            "api.example.com",
            "https://api.example.com/",
        )
        .expect("ok");
        assert!(server.is_some());
    }

    async fn signed_credential(
        server: &AuthenticateServer,
        plan_id: &str,
    ) -> pay_kit::mpp::PaymentCredential {
        use pay_kit::mpp::program::subscriptions::{default_program_id, find_subscription_pda};
        use pay_kit::mpp::solana_keychain::SolanaSigner;
        let key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(&key.to_bytes());
        keypair[32..].copy_from_slice(key.verifying_key().as_bytes());
        let signer =
            pay_kit::mpp::solana_keychain::memory::MemorySigner::from_bytes(&keypair).unwrap();
        let plan = plan_id.parse().unwrap();
        let (pda, _) = find_subscription_pda(&plan, &signer.pubkey(), &default_program_id());
        let header = pay_kit::mpp::client::build_authenticate_credential_header(
            &signer,
            &server.challenge().unwrap(),
            &pda.to_string(),
        )
        .await
        .unwrap();
        pay_kit::mpp::parse_authorization(&header).unwrap()
    }

    fn rfc3339_from_now(seconds: i64) -> String {
        (chrono::Utc::now() + chrono::Duration::seconds(seconds))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    #[tokio::test]
    async fn legacy_tokens_stop_verifying_at_the_endpoint_expiry() {
        let plan_id = "Amp9FrnEX17tVeZ7QnHX1Hh4TynhH4sXLRSde797vdKR";
        let mut spec = make_spec(Some(plan_id));
        let server = |spec: &SubscriptionEndpoint| {
            build_handler(
                spec,
                defaults(),
                "api.example.com",
                "https://api.example.com/",
            )
            .unwrap()
            .unwrap()
        };
        // Issued before the cutoff, so it carries the plan-period expiration.
        let credential = signed_credential(&server(&spec), plan_id).await;
        server(&spec).verify(&credential).unwrap();

        spec.expires_at = Some(rfc3339_from_now(3600));
        server(&spec).verify(&credential).unwrap_err();
        spec.expires_at = Some(rfc3339_from_now(-1));
        server(&spec).verify(&credential).unwrap_err();
    }

    #[tokio::test]
    async fn tokens_issued_under_an_endpoint_expiry_verify_until_it() {
        let plan_id = "Amp9FrnEX17tVeZ7QnHX1Hh4TynhH4sXLRSde797vdKR";
        let mut spec = make_spec(Some(plan_id));
        spec.expires_at = Some(rfc3339_from_now(3600));
        let server = build_handler(
            &spec,
            defaults(),
            "api.example.com",
            "https://api.example.com/",
        )
        .unwrap()
        .unwrap();
        let credential = signed_credential(&server, plan_id).await;
        server.verify(&credential).unwrap();
    }

    #[test]
    fn malformed_endpoint_expiry_is_a_config_error() {
        let mut spec = make_spec(Some("Amp9FrnEX17tVeZ7QnHX1Hh4TynhH4sXLRSde797vdKR"));
        spec.expires_at = Some("next tuesday".into());
        assert!(
            build_handler(
                &spec,
                defaults(),
                "api.example.com",
                "https://api.example.com/"
            )
            .is_err()
        );
    }

    #[test]
    fn period_hours_rejects_zero_count() {
        assert!(period_hours_from_spec(TypesPeriodUnit::Day, 0).is_err());
    }

    #[test]
    fn period_hours_rejects_out_of_range() {
        assert!(period_hours_from_spec(TypesPeriodUnit::Day, 366).is_err());
    }

    #[test]
    fn period_hours_maps_day_and_week_units() {
        assert_eq!(
            period_hours_from_spec(TypesPeriodUnit::Day, 30).unwrap(),
            720
        );
        assert_eq!(
            period_hours_from_spec(TypesPeriodUnit::Week, 4).unwrap(),
            672
        );
    }
}
