//! RTSS decisions derived inside the plugin from generic launch/client facts.
use crate::lease::ProfileValues;
use crate::{FrameLimiterProvider, GlobalSettings, Platform};
use amaterasu_module_sdk::extension_api::ProviderContext;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const CAPABILITY: &str = crate::settings_descriptor::WINDOWS_CAPABILITY;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Provider {
    Auto,
    Rtss,
    Nvidia,
    None,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    pub provider: Provider,
    pub installation: String,
    pub profile: String,
    pub values: ProfileValues,
    pub driver_limit_millihz: Option<u32>,
    pub disable_vsync: bool,
    pub smooth_motion: bool,
}

pub(crate) fn resolve(
    settings: &Value,
    context: &ProviderContext,
) -> Result<Option<Policy>, &'static str> {
    let values = serde_json::from_value(settings.clone()).map_err(|_| "invalid_settings")?;
    crate::settings_descriptor::validate(Platform::Windows, &values)
        .map_err(|_| "invalid_settings")?;
    let settings = GlobalSettings::from_json(settings.clone())
        .map_err(|_| "invalid_settings")?
        .settings;
    let facts = crate::lifecycle_facts::resolve(context, Platform::Windows)?;
    let decision = crate::evaluate_policy(&crate::EffectiveSettings::from(&settings), facts);
    let smooth_motion =
        facts.frame_generation_provider == crate::FrameGenerationProvider::NvidiaSmoothMotion;
    let limiting =
        settings.provider != FrameLimiterProvider::None && decision.should_consider_apply;
    if !limiting && !settings.disable_vsync && !smooth_motion {
        return Ok(None);
    }
    if !matches!(
        settings.provider,
        FrameLimiterProvider::Auto
            | FrameLimiterProvider::Rtss
            | FrameLimiterProvider::NvidiaControlPanel
            | FrameLimiterProvider::None
    ) {
        return Err("provider_unavailable");
    }
    if limiting
        && settings.fps_limit.is_follow_stream()
        && facts.lossless_scaling_limit.is_none()
        && context.client.is_none()
    {
        return Err("client_context_unavailable");
    }
    let rate = decision.effective_limit.value.millihz();
    if limiting && rate == 0 {
        return Err("stream_rate_unavailable");
    }
    let profile_values = if limiting {
        crate::lease::desired_rtss_profile(
            decision.effective_limit.source,
            rate,
            decision.rtss_sync_limiter.value,
        )?
    } else {
        crate::lease::DEFAULT_PROFILE
    };
    Ok(Some(Policy {
        provider: match settings.provider {
            FrameLimiterProvider::Auto => Provider::Auto,
            FrameLimiterProvider::Rtss => Provider::Rtss,
            FrameLimiterProvider::NvidiaControlPanel => Provider::Nvidia,
            _ => Provider::None,
        },
        installation: settings.rtss_install_path,
        profile: crate::rtss::GLOBAL_PROFILE.into(),
        values: profile_values,
        driver_limit_millihz: limiting.then_some(
            (u64::from(profile_values.frame_limit as u32) * 1000
                / u64::from(profile_values.frame_limit_denominator as u32)) as u32,
        ),
        disable_vsync: settings.disable_vsync,
        smooth_motion,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use amaterasu_module_sdk::extension_api::{
        ClientContext, ClientDisplayMode, LifecycleTarget, VideoMode,
    };
    use serde_json::json;

    fn fixture() -> (Value, ProviderContext) {
        let mut settings = amaterasu_configuration_schema::defaults(
            &crate::settings_descriptor::definitions(Platform::Windows),
        )
        .unwrap();
        settings.insert("frame_limiter_enable".into(), json!(true));
        let context = ProviderContext {
            target: LifecycleTarget::Session {
                host_epoch: "epoch".into(),
                session_id: "session".into(),
                generation: 1,
            },
            application: json!({"kind":"application","executable_path":r"C:\Games\Game.exe"}),
            requested_video: Some(VideoMode {
                width: 1920,
                height: 1080,
                refresh_millihz: 120000,
                hdr: false,
            }),
            client: Some(ClientContext {
                properties: None,
                client_ref: Some("client".into()),
                display_mode: Some(ClientDisplayMode {
                    width: 1920,
                    height: 1080,
                    refresh_millihz: 59940,
                }),
            }),
        };
        (json!(settings), context)
    }

    #[test]
    fn exact_client_rate_and_explicit_settings_are_plugin_owned() {
        let (mut settings, context) = fixture();
        let policy = resolve(&settings, &context).unwrap().unwrap();
        assert_eq!(policy.profile, crate::rtss::GLOBAL_PROFILE);
        assert_eq!(
            (
                policy.values.frame_limit,
                policy.values.frame_limit_denominator
            ),
            (2997, 50)
        );
        settings["frame_limiter_fps_limit"] = json!(117.5);
        settings["rtss_frame_limit_type"] = json!("back edge sync");
        let policy = resolve(&settings, &context).unwrap().unwrap();
        assert_eq!(
            (
                policy.values.frame_limit,
                policy.values.frame_limit_denominator
            ),
            (235, 2)
        );
        assert_eq!(policy.values.sync_limiter, 2);
    }

    #[test]
    fn lossless_scaling_context_activates_and_derives_the_rtss_game_input_limit() {
        let (mut settings, mut context) = fixture();
        settings["frame_limiter_enable"] = json!(false);
        context.application["properties"] = json!({"lossless_scaling_framegen":true,
            "lossless_scaling_target_fps":90});
        let policy = resolve(&settings, &context).unwrap().unwrap();
        assert_eq!(policy.values.frame_limit, 45);
        assert_eq!(policy.values.frame_limit_denominator, 1);
        context.client.as_mut().unwrap().properties = Some(json!({"frame_generation_mode":"off"}));
        assert_eq!(resolve(&settings, &context), Ok(None));
    }

    #[test]
    fn disabled_default_is_inert_and_missing_or_unsupported_inputs_are_rejected() {
        let (mut settings, mut context) = fixture();
        settings["frame_limiter_enable"] = json!(false);
        context.application = Value::Null;
        assert_eq!(resolve(&settings, &context), Ok(None));
        settings["frame_limiter_enable"] = json!(true);
        assert_eq!(
            resolve(&settings, &context).unwrap().unwrap().profile,
            crate::rtss::GLOBAL_PROFILE
        );
        context.application = json!({"executable_path":r"C:\Games\Game.exe"});
        context.client = None;
        assert_eq!(
            resolve(&settings, &context),
            Err("client_context_unavailable")
        );
        settings["frame_limiter_fps_limit"] = json!(60);
        assert!(resolve(&settings, &context).unwrap().is_some());
        settings["frame_limiter_disable_vsync"] = json!(true);
        assert!(resolve(&settings, &context).unwrap().unwrap().disable_vsync);
    }

    #[test]
    fn driver_vsync_does_not_require_a_cap_or_client_rate() {
        let (mut settings, mut context) = fixture();
        settings["frame_limiter_enable"] = json!(false);
        settings["frame_limiter_provider"] = json!("none");
        settings["frame_limiter_disable_vsync"] = json!(true);
        context.client = None;
        context.requested_video = None;
        context.application = Value::Null;
        let policy = resolve(&settings, &context).unwrap().unwrap();
        assert_eq!(policy.provider, Provider::None);
        assert_eq!(policy.driver_limit_millihz, None);
        assert!(policy.disable_vsync);
        assert_eq!(policy.values, crate::lease::DEFAULT_PROFILE);
    }
}
