//! Local MPP channel deployment and hook trust policy. Never applies to x402.

use crate::{Error, Result};
use pay_kit::core::payment_channels_v2::{ChannelHooks, resolve_deployment};
use solana_pubkey::Pubkey;

fn environment(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(Error::Config(format!("{name} must contain UTF-8 text"))),
    }
}

/// Server opt-in configuration. An explicit program never silently falls back.
pub fn server_profile() -> Result<(Pubkey, Option<u8>, Option<ChannelHooks>)> {
    parse_server_profile(
        environment("PAY_PAYMENT_CHANNELS_PROGRAM_ID")?.as_deref(),
        environment("PAY_MPP_CHANNEL_VERSION")?.as_deref(),
        environment("PAY_MPP_CHANNEL_HOOKS")?.as_deref(),
    )
}

fn parse_server_profile(
    program: Option<&str>,
    version: Option<&str>,
    hooks: Option<&str>,
) -> Result<(Pubkey, Option<u8>, Option<ChannelHooks>)> {
    let program = program
        .map(str::parse)
        .transpose()
        .map_err(|_| Error::Config("invalid PAY_PAYMENT_CHANNELS_PROGRAM_ID".into()))?
        .unwrap_or_else(pay_kit::mpp::program::payment_channels::default_program_id);
    let version = version
        .map(str::parse::<u8>)
        .transpose()
        .map_err(|_| Error::Config("invalid PAY_MPP_CHANNEL_VERSION".into()))?;
    resolve_deployment(program, version)
        .map_err(|error| Error::Config(format!("invalid MPP channel deployment: {error}")))?;
    let hooks: Option<ChannelHooks> = hooks
        .map(serde_json::from_str)
        .transpose()
        .map_err(|error| Error::Config(format!("invalid PAY_MPP_CHANNEL_HOOKS: {error}")))?;
    if let Some(hooks) = &hooks {
        if version != Some(2) {
            return Err(Error::Config("MPP channel hooks require version 2".into()));
        }
        hooks
            .validate()
            .map_err(|error| Error::Config(error.to_string()))?;
    }
    Ok((program, version, hooks))
}

/// Validate the remote profile before requesting wallet access. Hook execution
/// requires an exact descriptor match with local policy, not just a program ID.
pub fn validate_challenge(request: &pay_kit::mpp::SessionRequest) -> Result<()> {
    let details = &request.method_details;
    let program = details
        .channel_program
        .parse()
        .map_err(|_| Error::Mpp("invalid session channel program".into()))?;
    pay_kit::mpp::program::channel_deployment::resolve_for_network(
        program,
        details.channel_version,
        details.channel_hooks.as_ref(),
        &details.network,
    )
    .map_err(|error| Error::Mpp(format!("invalid session channel deployment: {error}")))?;
    if let Some(hooks) = &details.channel_hooks {
        if details.channel_version != Some(2) {
            return Err(Error::Mpp("session hooks require version 2".into()));
        }
        hooks
            .validate()
            .map_err(|error| Error::Mpp(error.to_string()))?;
        let trusted = environment("PAY_MPP_TRUSTED_CHANNEL_HOOKS")?
            .map(|value| serde_json::from_str::<ChannelHooks>(&value))
            .transpose()
            .map_err(|_| Error::Config("invalid PAY_MPP_TRUSTED_CHANNEL_HOOKS".into()))?;
        require_trusted_hooks(hooks, trusted.as_ref())?;
    }
    Ok(())
}

fn require_trusted_hooks(hooks: &ChannelHooks, trusted: Option<&ChannelHooks>) -> Result<()> {
    if trusted != Some(hooks) {
        return Err(Error::Mpp(
            "session channel hooks are not approved by local PAY_MPP_TRUSTED_CHANNEL_HOOKS policy"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_v1_and_invalid_explicit_program_fails_closed() {
        let (program, version, hooks) = parse_server_profile(None, None, None).unwrap();
        assert_eq!(
            program,
            pay_kit::mpp::program::payment_channels::default_program_id()
        );
        assert_eq!(version, None);
        assert_eq!(hooks, None);
        assert!(parse_server_profile(Some("invalid"), None, None).is_err());
    }

    #[test]
    fn deployment_and_hook_policy_require_explicit_opt_in() {
        let v2 = "CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ";
        assert!(parse_server_profile(Some(v2), None, None).is_err());
        assert!(parse_server_profile(None, Some("2"), None).is_err());
        assert!(parse_server_profile(Some(v2), Some("2"), None).is_ok());
        assert!(parse_server_profile(None, None, Some("{}")).is_err());
        let hooks: ChannelHooks = serde_json::from_str("{}").unwrap();
        assert!(require_trusted_hooks(&hooks, None).is_err());
        assert!(require_trusted_hooks(&hooks, Some(&hooks)).is_ok());
    }

    #[test]
    fn trusting_a_program_does_not_trust_changed_hook_arguments() {
        let descriptor = serde_json::json!({
            "postDistribute": {
                "programId": Pubkey::new_unique().to_string(),
                "entrypoint": [1, 2, 3, 4, 5, 6, 7, 8],
                "accounts": [{
                    "address": Pubkey::new_unique().to_string(),
                    "writable": false
                }],
                "staticData": [1]
            }
        });
        let trusted: ChannelHooks = serde_json::from_value(descriptor.clone()).unwrap();
        assert!(require_trusted_hooks(&trusted, Some(&trusted)).is_ok());
        let mut changed = descriptor.clone();
        changed["postDistribute"]["staticData"] = serde_json::json!([2]);
        let changed: ChannelHooks = serde_json::from_value(changed).unwrap();
        assert!(require_trusted_hooks(&changed, Some(&trusted)).is_err());
        let mut changed = descriptor;
        changed["postDistribute"]["accounts"][0]["writable"] = serde_json::json!(true);
        let changed: ChannelHooks = serde_json::from_value(changed).unwrap();
        assert!(require_trusted_hooks(&changed, Some(&trusted)).is_err());
    }
}
