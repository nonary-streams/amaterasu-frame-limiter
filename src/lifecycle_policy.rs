//! Linux policy derived from plugin settings and generic lifecycle context.
use crate::{
    FrameLimiterProvider, GlobalSettings, MangoHudLimiterMethod, MangoHudPreset, Platform,
};
use amaterasu_module_sdk::extension_api::ProviderContext;
use serde_json::{Value, json};

/// Build an owned Proton-launch policy. `None` means no limiter is requested.
/// A missing client context is unknown, not proof that no display override exists.
pub(crate) fn proton_policy(
    settings: &Value,
    context: &ProviderContext,
    mangohud_available: bool,
) -> Result<Option<Value>, &'static str> {
    let values = serde_json::from_value(settings.clone()).map_err(|_| "invalid_settings")?;
    crate::settings_descriptor::validate(Platform::Linux, &values)
        .map_err(|_| "invalid_settings")?;
    let parsed = GlobalSettings::from_json(settings.clone()).map_err(|_| "invalid_settings")?;
    let settings = parsed.settings;
    if settings.provider == FrameLimiterProvider::None {
        return Ok(None);
    }
    let mut facts = crate::lifecycle_facts::resolve(context, Platform::Linux)?;
    facts.mangohud_available = mangohud_available;
    let decision = crate::evaluate_policy(&crate::EffectiveSettings::from(&settings), facts);
    if !decision.should_consider_apply {
        return Ok(None);
    }
    if settings.disable_vsync {
        return Err("vsync_control_unavailable");
    }
    let provider = match decision
        .providers
        .attempts
        .first()
        .map(|attempt| attempt.backend)
    {
        Some(crate::ProviderBackend::Proton) if !decision.providers.overlays.is_empty() => {
            "mangohud-proton"
        }
        Some(crate::ProviderBackend::Proton) => "proton",
        Some(crate::ProviderBackend::MangoHud) => "mangohud",
        _ => return Err("mangohud_unavailable"),
    };
    if settings.fps_limit.is_follow_stream()
        && facts.lossless_scaling_limit.is_none()
        && context.client.is_none()
    {
        return Err("client_context_unavailable");
    }
    let limit = decision.effective_limit.value.millihz();
    if !(1..=1_000_000).contains(&limit) {
        return Err("invalid_rate");
    }
    let preset = match settings.mangohud_preset {
        MangoHudPreset::Custom => "custom",
        MangoHudPreset::One => "1",
        MangoHudPreset::Two => "2",
        MangoHudPreset::Three => "3",
        MangoHudPreset::Four => "4",
    };
    let method = match settings.mangohud_limiter_method {
        MangoHudLimiterMethod::Early => "early",
        MangoHudLimiterMethod::Late => "late",
    };
    Ok(Some(
        json!({"app_id":null,"provider":provider,"limit_millihz":limit,
        "preset":preset,"method":method,"graph":settings.mangohud_always_show_graph}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use amaterasu_module_sdk::extension_api::{
        ClientContext, ClientDisplayMode, LifecycleTarget, VideoMode,
    };

    fn fixture() -> (Value, ProviderContext) {
        let mut values = amaterasu_configuration_schema::defaults(
            &crate::settings_descriptor::definitions(Platform::Linux),
        )
        .unwrap();
        values.insert("frame_limiter_enable".into(), json!(true));
        let context = ProviderContext {
            target: LifecycleTarget::Session {
                host_epoch: "epoch".into(),
                session_id: "session".into(),
                generation: 1,
            },
            application: json!({"kind":"desktop"}),
            requested_video: Some(VideoMode {
                width: 1920,
                height: 1080,
                refresh_millihz: 60000,
                hdr: false,
            }),
            client: Some(ClientContext {
                properties: None,
                client_ref: Some("client".into()),
                display_mode: None,
            }),
        };
        (serde_json::to_value(values).unwrap(), context)
    }

    #[test]
    fn client_mode_takes_precedence_over_stream_and_explicit_limit_wins() {
        let (mut settings, mut context) = fixture();
        assert_eq!(
            proton_policy(&settings, &context, true).unwrap().unwrap()["limit_millihz"],
            60000
        );
        context.client.as_mut().unwrap().display_mode = Some(ClientDisplayMode {
            width: 1920,
            height: 1080,
            refresh_millihz: 59940,
        });
        let projected = proton_policy(&settings, &context, true).unwrap().unwrap();
        assert_eq!(projected["provider"], "mangohud-proton");
        assert_eq!(projected["limit_millihz"], 59940);
        settings["frame_limiter_fps_limit"] = json!(117.5);
        assert_eq!(
            proton_policy(&settings, &context, true).unwrap().unwrap()["limit_millihz"],
            117500
        );
    }

    #[test]
    fn configured_frame_generation_activates_the_plugin_without_host_limiter_logic() {
        let (mut settings, mut context) = fixture();
        settings["frame_limiter_enable"] = json!(false);
        context.application["properties"] = json!({"lossless_scaling_framegen":true,
            "lossless_scaling_target_fps":90});
        assert_eq!(
            proton_policy(&settings, &context, true).unwrap().unwrap()["limit_millihz"],
            90000
        );
        context.client.as_mut().unwrap().properties = Some(json!({"frame_generation_mode":"off"}));
        assert_eq!(proton_policy(&settings, &context, true), Ok(None));
        context.client.as_mut().unwrap().properties =
            Some(json!({"frame_generation_mode":"game-provided"}));
        assert_eq!(
            proton_policy(&settings, &context, true).unwrap().unwrap()["limit_millihz"],
            60000
        );
    }

    #[test]
    fn optional_overlay_falls_back_to_proton_when_mangohud_is_unavailable() {
        let (mut settings, context) = fixture();
        settings["mangohud_always_show_graph"] = json!(true);
        for selected in ["auto", "mangohud-proton", "proton"] {
            settings["frame_limiter_provider"] = json!(selected);
            let policy = proton_policy(&settings, &context, false).unwrap().unwrap();
            assert_eq!(policy["provider"], "proton");
            let contribution = crate::linux_environment::contribution(&policy).unwrap();
            let environment = amaterasu_module_sdk::extension_api::merge_launch_environment(
                &Default::default(),
                &[contribution],
            )
            .unwrap();
            assert_eq!(environment["VKD3D_FRAME_RATE"], "60");
            assert!(!environment.contains_key("MANGOHUD"));
            assert!(!environment["LD_PRELOAD"].contains("MangoHud"));
        }
        settings["frame_limiter_provider"] = json!("mangohud");
        assert_eq!(
            proton_policy(&settings, &context, false),
            Err("mangohud_unavailable")
        );
    }

    #[test]
    fn unknown_context_and_unsupported_vsync_never_create_a_policy() {
        let (mut settings, mut context) = fixture();
        context.client = None;
        assert_eq!(
            proton_policy(&settings, &context, true),
            Err("client_context_unavailable")
        );
        settings["frame_limiter_fps_limit"] = json!(60);
        settings["frame_limiter_disable_vsync"] = json!(true);
        assert_eq!(
            proton_policy(&settings, &context, true),
            Err("vsync_control_unavailable")
        );
        settings["frame_limiter_enable"] = json!(false);
        assert_eq!(proton_policy(&settings, &context, true), Ok(None));
        settings["frame_limiter_auto_virtual_framegen"] = json!("disabled");
        assert_eq!(proton_policy(&settings, &context, true), Ok(None));
        settings["frame_limiter_provider"] = json!("none");
        assert_eq!(proton_policy(&settings, &context, true), Ok(None));
    }
}
