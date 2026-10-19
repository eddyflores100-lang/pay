//! Payment-gate pricing: the amounts and splits the gate challenges for.
//!
//! Run: `cargo test -p pay-core --features server --test gate_pricing_tests`

#![cfg(feature = "server")]

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use pay_core::PaymentState;
use pay_core::server::gate::{GateDecision, GateRequest, PaymentGate};
use pay_kit::mpp::server::{Config, Mpp};
use pay_kit::mpp::{ChargeRequest, parse_www_authenticate};
use pay_types::metering::ApiSpec;

#[derive(Clone)]
struct State {
    apis: Arc<Vec<ApiSpec>>,
    mpp: Mpp,
}

impl PaymentState for State {
    fn apis(&self) -> &[ApiSpec] {
        &self.apis
    }

    fn mpp(&self) -> Option<&Mpp> {
        Some(&self.mpp)
    }
}

/// SOL at 9 decimals: $1 in the spec is 1_000_000_000 base units on the wire.
fn sol_mpp() -> Mpp {
    Mpp::new(Config {
        recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
        currency: "SOL".to_string(),
        decimals: 9,
        network: "localnet".to_string(),
        rpc_url: Some("http://127.0.0.1:8899".to_string()),
        challenge_binding_secret: Some("test-secret-key-do-not-use-32b-pad".to_string()),
        ..Default::default()
    })
    .expect("local MPP backend")
}

fn spec(yaml: &str) -> ApiSpec {
    let mut api: ApiSpec = serde_yml::from_str(yaml).expect("spec parses");
    api.apply_scheme_defaults();
    api
}

struct Challenge {
    status: StatusCode,
    charge: Option<ChargeRequest>,
    body: serde_json::Value,
}

async fn challenge(api: &ApiSpec, path: &str, content_length: Option<u64>) -> Challenge {
    let state = State {
        apis: Arc::new(vec![api.clone()]),
        mpp: sol_mpp(),
    };
    let host = format!("{}.localhost", api.subdomain);
    let decision = PaymentGate::new(state)
        .evaluate(&GateRequest {
            method: &Method::POST,
            path,
            host: Some(&host),
            accept: None,
            authorization: None,
            content_length,
            query: None,
            x402_payment: None,
        })
        .await;
    let GateDecision::Respond(response) = decision else {
        panic!("an unpaid metered request must not be forwarded");
    };
    let charge = response
        .headers
        .iter()
        .filter(|(name, _)| name == axum::http::header::WWW_AUTHENTICATE)
        .filter_map(|(_, value)| parse_www_authenticate(value.to_str().ok()?).ok())
        .find(|c| c.intent.as_str() == "charge")
        .map(|c| c.request.decode::<ChargeRequest>().expect("charge request"));
    Challenge {
        status: response.status,
        charge,
        body: serde_json::from_slice(&response.body).unwrap_or_default(),
    }
}

async fn charge_amount(api: &ApiSpec, path: &str, content_length: Option<u64>) -> String {
    let challenge = challenge(api, path, content_length).await;
    assert_eq!(
        challenge.status,
        StatusCode::PAYMENT_REQUIRED,
        "{}",
        challenge.body
    );
    challenge.charge.expect("MPP charge challenge").amount
}

// ── Body-selected variants (SOLA1-60) ───────────────────────────────────────

const BODY_VARIANTS: &str = r#"
name: body-variant
subdomain: body-variant
title: Body variant
description: Body-selected pricing variants
category: ai_ml
version: v1
routing:
  type: respond
endpoints:
  - method: POST
    path: v1/generate
    metering:
      variants:
        - param: model
          value: cheap
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers: [{price_usd: 0.01}]
        - param: model
          value: premium
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers: [{price_usd: 0.10}]
  - method: POST
    path: v1/models/{modelId}:generate
    metering:
      variants:
        - param: model
          value: cheap
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers: [{price_usd: 0.01}]
        - param: model
          value: premium
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers: [{price_usd: 0.10}]
        - param: model
          value: default
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers: [{price_usd: 0.05}]
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_selectable_variant_is_charged_at_the_most_expensive_candidate() {
    let api = spec(BODY_VARIANTS);
    assert!(pay_types::metering::validate_api_spec(&api).is_empty());
    // The body may select `premium`; a fixed charge cannot see it, so it must
    // not settle for the first (cheap) variant.
    assert_eq!(
        charge_amount(&api, "v1/generate", Some(64)).await,
        "100000000"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_selected_variant_keeps_its_own_price() {
    let api = spec(BODY_VARIANTS);
    assert_eq!(
        charge_amount(&api, "v1/models/cheap:generate", None).await,
        "10000000"
    );
    assert_eq!(
        charge_amount(&api, "v1/models/premium:generate", None).await,
        "100000000"
    );
    // An unlisted path model uses the explicit `default` variant.
    assert_eq!(
        charge_amount(&api, "v1/models/other:generate", None).await,
        "50000000"
    );
}

// ── Overlapping variant values (SOLA1-62) ──────────────────────────────────

const OVERLAPPING_VARIANTS: &str = r#"
name: collision
subdomain: collision
title: Collision
description: Overlapping model variants
category: ai_ml
version: v1
routing:
  type: respond
endpoints:
  - method: POST
    path: v1/models/{modelId}:generate
    metering:
      schemes: [mpp-charge]
      variants:
        - param: model
          value: gpt-4
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers: [{price_usd: 0.01}]
        - param: model
          value: gpt-4o
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers: [{price_usd: 1.00}]
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_variant_is_priced_by_the_forwarded_model() {
    let api = spec(OVERLAPPING_VARIANTS);
    assert!(pay_types::metering::validate_api_spec(&api).is_empty());
    assert_eq!(
        charge_amount(&api, "v1/models/gpt-4o:generate", None).await,
        "1000000000"
    );
    assert_eq!(
        charge_amount(&api, "v1/models/gpt-4:generate", None).await,
        "10000000"
    );
}
