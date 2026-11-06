use serde_json::json;

use crate::{
    AutoVirtualFramegenMode, EffectiveSettings, FallbackCondition, FpsLimit,
    FrameGenerationProvider, FrameLimitSource, FrameLimiterOverrides, FrameLimiterProvider,
    GlobalSettings, MangoHudLimiterMethod, MangoHudPreset, Platform, PolicyContext,
    PolicyDiagnostic, ProviderAttempt, ProviderBackend, RtssFrameLimitType, RtssSyncLimiterReason,
    SettingsDiagnostic, SettingsError, plan_provider, resolve_effective_limit,
    resolve_rtss_sync_limiter, should_consider_apply,
};

#[test]
fn fps_limit_requires_exact_millihertz_precision_and_range() {
    assert_eq!(FpsLimit::parse_hz("0").unwrap().millihz(), 0);
    assert_eq!(FpsLimit::parse_hz("0.001").unwrap().millihz(), 1);
    assert_eq!(FpsLimit::parse_hz("59.94").unwrap().millihz(), 59_940);
    assert_eq!(FpsLimit::parse_hz("1000").unwrap().millihz(), 1_000_000);

    for invalid in [
        "-1", "+1", "1e2", "1.0000", "1000.001", "1001", ".5", "1.", " 1",
    ] {
        assert_eq!(
            FpsLimit::parse_hz(invalid),
            Err(SettingsError::InvalidFpsLimit),
            "accepted {invalid:?}"
        );
    }
}

#[test]
fn defaults_match_the_global_configuration_contract() {
    let settings = GlobalSettings::default();
    assert!(!settings.enable);
    assert_eq!(settings.provider, FrameLimiterProvider::Auto);
    assert_eq!(settings.fps_limit, FpsLimit::FOLLOW_STREAM);
    assert!(!settings.disable_vsync);
    assert_eq!(
        settings.auto_virtual_framegen,
        AutoVirtualFramegenMode::Enabled
    );
    assert_eq!(settings.rtss_frame_limit_type, RtssFrameLimitType::Async);
    assert!(settings.rtss_install_path.is_empty());
    assert!(!settings.rtss_allow_virtual_display_override);
    assert_eq!(settings.mangohud_preset, MangoHudPreset::Custom);
    assert!(!settings.mangohud_always_show_graph);
    assert_eq!(
        settings.mangohud_limiter_method,
        MangoHudLimiterMethod::Late
    );
}

#[test]
fn legacy_vsync_alias_is_folded_and_wins_if_both_keys_are_present() {
    let parsed = GlobalSettings::from_json(json!({
        "frame_limiter_disable_vsync": false,
        "rtss_disable_vsync_ullm": true
    }))
    .unwrap();
    assert!(parsed.settings.disable_vsync);
    let legacy_false = GlobalSettings::from_json(json!({
        "rtss_disable_vsync_ullm": false
    }))
    .unwrap();
    assert!(!legacy_false.settings.disable_vsync);
}

#[test]
fn virtual_frame_generation_modes_accept_canonical_values_and_legacy_aliases() {
    for (name, expected) in [
        ("enabled", AutoVirtualFramegenMode::Enabled),
        ("vrr", AutoVirtualFramegenMode::Vrr),
        ("legacy", AutoVirtualFramegenMode::Legacy),
        ("disabled", AutoVirtualFramegenMode::Disabled),
        ("true", AutoVirtualFramegenMode::Enabled),
        ("1000Hz", AutoVirtualFramegenMode::Vrr),
        ("2x", AutoVirtualFramegenMode::Legacy),
        ("off", AutoVirtualFramegenMode::Disabled),
    ] {
        assert_eq!(AutoVirtualFramegenMode::parse(name), Some(expected));
    }

    let parsed = GlobalSettings::from_json(json!({
        "frame_limiter_auto_virtual_framegen": "unknown-mode"
    }))
    .unwrap();
    assert_eq!(
        parsed.settings.auto_virtual_framegen,
        AutoVirtualFramegenMode::Enabled
    );
    assert_eq!(
        parsed.diagnostics,
        vec![SettingsDiagnostic::UnknownVirtualFramegenUsesEnabled]
    );
}

#[test]
fn rtss_reflex_sync_mode_accepts_short_alias() {
    assert_eq!(
        "reflex".parse::<RtssFrameLimitType>().unwrap(),
        RtssFrameLimitType::NvidiaReflex
    );
    assert_eq!(
        "NVIDIA Reflex".parse::<RtssFrameLimitType>().unwrap(),
        RtssFrameLimitType::NvidiaReflex
    );
}

#[test]
fn unknown_mangohud_options_recover_to_defaults_with_diagnostics() {
    let parsed = GlobalSettings::from_json(json!({
        "mangohud_preset": "future-preset",
        "mangohud_limiter_method": "middle"
    }))
    .unwrap();

    assert_eq!(parsed.settings.mangohud_preset, MangoHudPreset::Custom);
    assert_eq!(
        parsed.settings.mangohud_limiter_method,
        MangoHudLimiterMethod::Late
    );
    assert_eq!(
        parsed.diagnostics,
        vec![
            SettingsDiagnostic::UnknownMangoHudPresetUsesCustom,
            SettingsDiagnostic::UnknownMangoHudLimiterMethodUsesLate,
        ]
    );
}

#[test]
fn path_validation_is_target_specific_and_allows_windows_install_subfolders() {
    let mut settings = GlobalSettings::default();
    assert!(settings.validate(Platform::Windows).is_ok());
    settings.rtss_install_path = r"C:\Program Files\RTSS".into();
    assert!(settings.validate(Platform::Windows).is_ok());
    settings.rtss_install_path = r"\\server\share\RTSS".into();
    assert!(settings.validate(Platform::Windows).is_ok());
    settings.rtss_install_path = "relative\\RTSS".into();
    assert!(settings.validate(Platform::Windows).is_ok());
    settings.rtss_install_path = r"\rooted-but-not-qualified".into();
    assert_eq!(
        settings.validate(Platform::Windows),
        Err(SettingsError::InvalidRtssInstallPath)
    );
    settings.rtss_install_path = "C:drive-relative".into();
    assert_eq!(
        settings.validate(Platform::Windows),
        Err(SettingsError::InvalidRtssInstallPath)
    );

    settings.rtss_install_path = format!(r"C:\{}", "x".repeat(5_000));
    assert!(settings.validate(Platform::Windows).is_ok());

    settings.rtss_install_path = "/opt/rtss".into();
    assert_eq!(
        settings.validate(Platform::Windows),
        Err(SettingsError::InvalidRtssInstallPath)
    );
    assert_eq!(
        settings.validate(Platform::Linux),
        Err(SettingsError::InvalidRtssInstallPath)
    );
    assert_eq!(
        settings.validate(Platform::Macos),
        Err(SettingsError::InvalidRtssInstallPath)
    );
    settings.rtss_install_path.clear();
    assert!(settings.validate(Platform::Linux).is_ok());
    assert!(settings.validate(Platform::Macos).is_ok());
    settings.rtss_install_path = "opt/rtss".into();
    assert_eq!(
        settings.validate(Platform::Linux),
        Err(SettingsError::InvalidRtssInstallPath)
    );
}

#[test]
fn scoped_overrides_preserve_explicit_false_zero_and_client_precedence() {
    let global = GlobalSettings {
        enable: true,
        fps_limit: FpsLimit::parse_hz("60").unwrap(),
        ..GlobalSettings::default()
    };
    let application = FrameLimiterOverrides {
        enable: Some(true),
        fps_limit: Some(FpsLimit::parse_hz("90").unwrap()),
        disable_vsync: Some(true),
        ..FrameLimiterOverrides::default()
    };
    let client = FrameLimiterOverrides {
        enable: Some(false),
        fps_limit: Some(FpsLimit::FOLLOW_STREAM),
        disable_vsync: Some(false),
        ..FrameLimiterOverrides::default()
    };

    let resolved = EffectiveSettings::resolve(&global, &application, &client);
    assert!(!resolved.enable);
    assert_eq!(resolved.fps_limit, FpsLimit::FOLLOW_STREAM);
    assert!(!resolved.disable_vsync);
    assert_eq!(resolved.rtss_install_path, global.rtss_install_path);
}

#[test]
fn windows_auto_prefers_rtss_then_uses_nvcp_as_a_failure_fallback() {
    let context = PolicyContext {
        platform: Platform::Windows,
        nvidia_gpu_present: true,
        ..PolicyContext::default()
    };
    let plan = plan_provider(FrameLimiterProvider::Auto, context);
    assert_eq!(
        plan.attempts,
        vec![
            ProviderAttempt {
                backend: ProviderBackend::Rtss,
                fallback: FallbackCondition::FirstChoice,
            },
            ProviderAttempt {
                backend: ProviderBackend::NvidiaControlPanel,
                fallback: FallbackCondition::AfterFailure,
            },
        ]
    );

    let explicit_rtss = plan_provider(FrameLimiterProvider::Rtss, context);
    assert_eq!(
        explicit_rtss.attempts[1].fallback,
        FallbackCondition::OnlyAfterStall
    );
    assert_eq!(
        plan_provider(FrameLimiterProvider::NvidiaControlPanel, context)
            .attempts
            .len(),
        1
    );
}

#[test]
fn linux_auto_always_uses_proton_and_adds_optional_overlay() {
    for proton_environment in [false, true] {
        let plan = plan_provider(
            FrameLimiterProvider::Auto,
            PolicyContext {
                platform: Platform::Linux,
                proton_environment,
                mangohud_available: true,
                ..PolicyContext::default()
            },
        );
        assert_eq!(
            plan.attempts
                .iter()
                .map(|attempt| attempt.backend)
                .collect::<Vec<_>>(),
            vec![ProviderBackend::Proton]
        );
        assert_eq!(plan.overlays, vec![ProviderBackend::MangoHudProton]);
        assert_eq!(plan.attempts[0].fallback, FallbackCondition::FirstChoice);
    }

    let no_overlay = plan_provider(
        FrameLimiterProvider::Auto,
        PolicyContext {
            platform: Platform::Linux,
            proton_environment: false,
            mangohud_available: false,
            ..PolicyContext::default()
        },
    );
    assert_eq!(no_overlay.attempts[0].backend, ProviderBackend::Proton);
    assert!(no_overlay.overlays.is_empty());
    assert_eq!(
        no_overlay.diagnostics,
        vec![PolicyDiagnostic::MangoHudUnavailable]
    );

    let proton = plan_provider(
        FrameLimiterProvider::Proton,
        PolicyContext {
            platform: Platform::Linux,
            proton_environment: true,
            mangohud_available: true,
            ..PolicyContext::default()
        },
    );
    assert_eq!(proton.attempts.len(), 1);
    assert!(proton.overlays.is_empty());

    let proton_with_overlay = plan_provider(
        FrameLimiterProvider::MangoHudProton,
        PolicyContext {
            platform: Platform::Linux,
            mangohud_available: true,
            ..PolicyContext::default()
        },
    );
    assert_eq!(proton_with_overlay.attempts.len(), 1);
    assert_eq!(
        proton_with_overlay.overlays,
        vec![ProviderBackend::MangoHudProton]
    );

    let proton_without_overlay = plan_provider(
        FrameLimiterProvider::MangoHudProton,
        PolicyContext {
            platform: Platform::Linux,
            mangohud_available: false,
            ..PolicyContext::default()
        },
    );
    assert_eq!(proton_without_overlay.attempts.len(), 1);
    assert!(proton_without_overlay.overlays.is_empty());
    assert_eq!(
        proton_without_overlay.diagnostics,
        vec![PolicyDiagnostic::MangoHudUnavailable]
    );

    let unavailable = plan_provider(
        FrameLimiterProvider::MangoHud,
        PolicyContext {
            platform: Platform::Linux,
            ..PolicyContext::default()
        },
    );
    assert_eq!(
        unavailable.diagnostics,
        vec![PolicyDiagnostic::MangoHudUnavailable]
    );
}

#[test]
fn unsupported_explicit_provider_and_macos_auto_return_diagnostics() {
    let linux_rtss = plan_provider(
        FrameLimiterProvider::Rtss,
        PolicyContext {
            platform: Platform::Linux,
            ..PolicyContext::default()
        },
    );
    assert_eq!(
        linux_rtss.diagnostics,
        vec![PolicyDiagnostic::UnsupportedProviderForPlatform]
    );

    let macos = plan_provider(
        FrameLimiterProvider::Auto,
        PolicyContext {
            platform: Platform::Macos,
            ..PolicyContext::default()
        },
    );
    assert!(macos.attempts.is_empty());
    assert_eq!(
        macos.diagnostics,
        vec![PolicyDiagnostic::PlatformHasNoLimiterBackend]
    );
}

#[test]
fn configured_limit_wins_then_lossless_scaling_then_display_mode() {
    let context = PolicyContext {
        client_display_mode_rate: Some(FpsLimit::from_millihz(144_000).unwrap()),
        requested_stream_fps: Some(FpsLimit::from_millihz(120_000).unwrap()),
        lossless_scaling_limit: Some(FpsLimit::from_millihz(72_000).unwrap()),
        ..PolicyContext::default()
    };
    let limit = resolve_effective_limit(FpsLimit::FOLLOW_STREAM, context);
    assert_eq!(limit.value.millihz(), 72_000);
    assert_eq!(limit.source, FrameLimitSource::LosslessScaling);

    let configured = resolve_effective_limit(FpsLimit::parse_hz("60").unwrap(), context);
    assert_eq!(configured.value.millihz(), 60_000);
    assert_eq!(configured.source, FrameLimitSource::Configured);

    let pending_stream_rate =
        resolve_effective_limit(FpsLimit::FOLLOW_STREAM, PolicyContext::default());
    assert_eq!(pending_stream_rate.value, FpsLimit::FOLLOW_STREAM);
    assert_eq!(pending_stream_rate.source, FrameLimitSource::FollowStream);

    let display_only = resolve_effective_limit(
        FpsLimit::FOLLOW_STREAM,
        PolicyContext {
            lossless_scaling_limit: None,
            ..context
        },
    );
    assert_eq!(display_only.value.millihz(), 144_000);
    assert_eq!(display_only.source, FrameLimitSource::DisplayMode);

    let requested_stream = resolve_effective_limit(
        FpsLimit::FOLLOW_STREAM,
        PolicyContext {
            requested_stream_fps: Some(FpsLimit::from_millihz(120_000).unwrap()),
            ..PolicyContext::default()
        },
    );
    assert_eq!(requested_stream.value.millihz(), 120_000);
    assert_eq!(requested_stream.source, FrameLimitSource::RequestedStream);

    let zero_stream_rate = resolve_effective_limit(
        FpsLimit::FOLLOW_STREAM,
        PolicyContext {
            requested_stream_fps: Some(FpsLimit::FOLLOW_STREAM),
            ..PolicyContext::default()
        },
    );
    assert_eq!(zero_stream_rate.value, FpsLimit::FOLLOW_STREAM);
    assert_eq!(zero_stream_rate.source, FrameLimitSource::FollowStream);
}

#[test]
fn apply_decision_accounts_for_virtual_display_framegen_and_lossless_scaling() {
    let settings = EffectiveSettings::from(&GlobalSettings::default());
    assert!(!should_consider_apply(&settings, PolicyContext::default()));
    assert!(should_consider_apply(
        &settings,
        PolicyContext {
            virtual_display_active: true,
            ..PolicyContext::default()
        }
    ));

    let disabled_auto = EffectiveSettings {
        auto_virtual_framegen: AutoVirtualFramegenMode::Disabled,
        ..settings.clone()
    };
    assert!(!should_consider_apply(
        &disabled_auto,
        PolicyContext {
            virtual_display_active: true,
            ..PolicyContext::default()
        }
    ));
    assert!(should_consider_apply(
        &disabled_auto,
        PolicyContext {
            lossless_scaling_limit: Some(FpsLimit::from_millihz(60_000).unwrap()),
            ..PolicyContext::default()
        }
    ));
    assert!(should_consider_apply(
        &disabled_auto,
        PolicyContext {
            physical_framegen_capture: true,
            ..PolicyContext::default()
        }
    ));

    let lossless_scaling_framegen = PolicyContext {
        frame_generation_provider: FrameGenerationProvider::LosslessScaling,
        ..PolicyContext::default()
    };
    assert!(should_consider_apply(
        &disabled_auto,
        lossless_scaling_framegen
    ));
    let decision = resolve_rtss_sync_limiter(&disabled_auto, lossless_scaling_framegen);
    assert_eq!(decision.value, RtssFrameLimitType::FrontEdgeSync);
    assert_eq!(
        decision.reason,
        RtssSyncLimiterReason::FrameGenerationPolicy
    );
}

#[test]
fn virtual_display_rtss_defaults_to_reflex_with_scoped_escape_hatch() {
    let mut settings = EffectiveSettings::from(&GlobalSettings::default());
    settings.rtss_frame_limit_type = RtssFrameLimitType::Async;
    let context = PolicyContext {
        virtual_display_active: true,
        nvidia_gpu_present: true,
        ..PolicyContext::default()
    };
    let decision = resolve_rtss_sync_limiter(&settings, context);
    assert_eq!(decision.value, RtssFrameLimitType::NvidiaReflex);
    assert_eq!(decision.reason, RtssSyncLimiterReason::VirtualDisplaySafety);

    let allow_global = EffectiveSettings {
        rtss_allow_virtual_display_override: true,
        ..settings.clone()
    };
    assert_eq!(
        resolve_rtss_sync_limiter(&allow_global, context).value,
        RtssFrameLimitType::Async
    );

    let game_framegen = PolicyContext {
        frame_generation_provider: FrameGenerationProvider::GameProvided,
        ..context
    };
    let decision = resolve_rtss_sync_limiter(&allow_global, game_framegen);
    assert_eq!(decision.value, RtssFrameLimitType::NvidiaReflex);
    assert_eq!(
        decision.reason,
        RtssSyncLimiterReason::GameFrameGenerationSafety
    );

    let scoped_override = PolicyContext {
        scoped_rtss_type_override: true,
        frame_generation_provider: FrameGenerationProvider::GameProvided,
        ..context
    };
    let decision = resolve_rtss_sync_limiter(&settings, scoped_override);
    assert_eq!(decision.value, RtssFrameLimitType::Async);
    assert_eq!(decision.reason, RtssSyncLimiterReason::ScopedOverride);
}

#[test]
fn game_framegen_uses_reflex_only_on_supported_windows_and_yields_to_scoped_override() {
    let settings = EffectiveSettings {
        rtss_frame_limit_type: RtssFrameLimitType::Async,
        ..EffectiveSettings::from(&GlobalSettings::default())
    };
    let physical_game_framegen = PolicyContext {
        physical_framegen_capture: true,
        frame_generation_provider: FrameGenerationProvider::GameProvided,
        nvidia_gpu_present: true,
        ..PolicyContext::default()
    };
    let decision = resolve_rtss_sync_limiter(&settings, physical_game_framegen);
    assert_eq!(decision.value, RtssFrameLimitType::NvidiaReflex);
    assert_eq!(
        decision.reason,
        RtssSyncLimiterReason::GameFrameGenerationSafety
    );

    let inferred_physical_game_framegen = PolicyContext {
        frame_generation_provider: FrameGenerationProvider::GameProvided,
        nvidia_gpu_present: true,
        ..PolicyContext::default()
    };
    assert!(should_consider_apply(
        &settings,
        inferred_physical_game_framegen
    ));
    let decision = resolve_rtss_sync_limiter(&settings, inferred_physical_game_framegen);
    assert_eq!(decision.value, RtssFrameLimitType::NvidiaReflex);
    assert_eq!(
        decision.reason,
        RtssSyncLimiterReason::GameFrameGenerationSafety
    );

    let virtual_game_framegen = PolicyContext {
        virtual_display_active: true,
        frame_generation_provider: FrameGenerationProvider::GameProvided,
        nvidia_gpu_present: true,
        ..PolicyContext::default()
    };
    assert_eq!(
        resolve_rtss_sync_limiter(&settings, virtual_game_framegen).value,
        RtssFrameLimitType::NvidiaReflex
    );

    let scoped = PolicyContext {
        scoped_rtss_type_override: true,
        ..physical_game_framegen
    };
    assert_eq!(
        resolve_rtss_sync_limiter(&settings, scoped).value,
        RtssFrameLimitType::Async
    );

    for unsupported in [
        PolicyContext {
            physical_framegen_capture: true,
            frame_generation_provider: FrameGenerationProvider::GameProvided,
            ..PolicyContext::default()
        },
        PolicyContext {
            physical_framegen_capture: true,
            frame_generation_provider: FrameGenerationProvider::GameProvided,
            nvidia_gpu_present: true,
            amd_gpu_present: true,
            ..PolicyContext::default()
        },
    ] {
        let decision = resolve_rtss_sync_limiter(&settings, unsupported);
        assert_eq!(decision.value, RtssFrameLimitType::FrontEdgeSync);
        assert_eq!(decision.reason, RtssSyncLimiterReason::NonNvidiaAdapter);
    }
}

#[test]
fn automatic_virtual_reflex_requires_policy_mode_global_opt_in_and_supported_gpu() {
    let settings = EffectiveSettings {
        rtss_frame_limit_type: RtssFrameLimitType::BackEdgeSync,
        ..EffectiveSettings::from(&GlobalSettings::default())
    };
    let virtual_context = PolicyContext {
        virtual_display_active: true,
        nvidia_gpu_present: true,
        ..PolicyContext::default()
    };
    let decision = resolve_rtss_sync_limiter(&settings, virtual_context);
    assert_eq!(decision.value, RtssFrameLimitType::NvidiaReflex);
    assert_eq!(decision.reason, RtssSyncLimiterReason::VirtualDisplaySafety);

    let no_automatic_mode = EffectiveSettings {
        auto_virtual_framegen: AutoVirtualFramegenMode::Disabled,
        ..settings.clone()
    };
    assert_eq!(
        resolve_rtss_sync_limiter(&no_automatic_mode, virtual_context).value,
        RtssFrameLimitType::BackEdgeSync
    );
    let game_framegen_without_virtual_policy = PolicyContext {
        frame_generation_provider: FrameGenerationProvider::GameProvided,
        ..virtual_context
    };
    assert!(should_consider_apply(
        &no_automatic_mode,
        game_framegen_without_virtual_policy
    ));
    let game_framegen_decision =
        resolve_rtss_sync_limiter(&no_automatic_mode, game_framegen_without_virtual_policy);
    assert_eq!(
        game_framegen_decision.value,
        RtssFrameLimitType::NvidiaReflex
    );
    assert_eq!(
        game_framegen_decision.reason,
        RtssSyncLimiterReason::GameFrameGenerationSafety
    );

    let global_override = EffectiveSettings {
        rtss_allow_virtual_display_override: true,
        ..settings.clone()
    };
    assert_eq!(
        resolve_rtss_sync_limiter(&global_override, virtual_context).value,
        RtssFrameLimitType::BackEdgeSync
    );
    let game_framegen_with_global_override = EffectiveSettings {
        rtss_allow_virtual_display_override: true,
        ..no_automatic_mode
    };
    let decision = resolve_rtss_sync_limiter(
        &game_framegen_with_global_override,
        game_framegen_without_virtual_policy,
    );
    assert_eq!(decision.value, RtssFrameLimitType::NvidiaReflex);
    assert_eq!(
        decision.reason,
        RtssSyncLimiterReason::GameFrameGenerationSafety
    );

    for unsupported in [
        PolicyContext {
            virtual_display_active: true,
            ..PolicyContext::default()
        },
        PolicyContext {
            virtual_display_active: true,
            nvidia_gpu_present: true,
            amd_gpu_present: true,
            ..PolicyContext::default()
        },
    ] {
        assert_eq!(
            resolve_rtss_sync_limiter(&settings, unsupported).value,
            RtssFrameLimitType::FrontEdgeSync
        );
    }
}

#[test]
fn rtss_framegen_sync_policy_respects_smooth_motion_provider_and_platform() {
    let settings = EffectiveSettings {
        rtss_frame_limit_type: RtssFrameLimitType::BackEdgeSync,
        ..EffectiveSettings::from(&GlobalSettings::default())
    };
    let smooth_motion = PolicyContext {
        physical_framegen_capture: true,
        frame_generation_provider: FrameGenerationProvider::NvidiaSmoothMotion,
        nvidia_gpu_present: true,
        ..PolicyContext::default()
    };
    let decision = resolve_rtss_sync_limiter(&settings, smooth_motion);
    assert_eq!(decision.value, RtssFrameLimitType::FrontEdgeSync);
    assert_eq!(decision.reason, RtssSyncLimiterReason::NvidiaSmoothMotion);

    let inferred_smooth_motion = PolicyContext {
        frame_generation_provider: FrameGenerationProvider::NvidiaSmoothMotion,
        nvidia_gpu_present: true,
        ..PolicyContext::default()
    };
    assert!(should_consider_apply(&settings, inferred_smooth_motion));
    let decision = resolve_rtss_sync_limiter(&settings, inferred_smooth_motion);
    assert_eq!(decision.value, RtssFrameLimitType::FrontEdgeSync);
    assert_eq!(decision.reason, RtssSyncLimiterReason::NvidiaSmoothMotion);

    let virtual_smooth_motion = PolicyContext {
        virtual_display_active: true,
        frame_generation_provider: FrameGenerationProvider::NvidiaSmoothMotion,
        nvidia_gpu_present: true,
        ..PolicyContext::default()
    };
    let allow_virtual_override = EffectiveSettings {
        rtss_allow_virtual_display_override: true,
        ..settings.clone()
    };
    assert_eq!(
        resolve_rtss_sync_limiter(&allow_virtual_override, virtual_smooth_motion).value,
        RtssFrameLimitType::BackEdgeSync
    );

    let inactive = PolicyContext {
        frame_generation_provider: FrameGenerationProvider::Other,
        nvidia_gpu_present: false,
        ..PolicyContext::default()
    };
    assert_eq!(
        resolve_rtss_sync_limiter(&settings, inactive).value,
        RtssFrameLimitType::BackEdgeSync
    );

    let non_rtss_provider = EffectiveSettings {
        provider: FrameLimiterProvider::NvidiaControlPanel,
        ..settings.clone()
    };
    let scoped_sync_override = PolicyContext {
        scoped_rtss_type_override: true,
        ..smooth_motion
    };
    let decision = resolve_rtss_sync_limiter(&non_rtss_provider, scoped_sync_override);
    assert_eq!(decision.value, RtssFrameLimitType::BackEdgeSync);
    assert_eq!(decision.reason, RtssSyncLimiterReason::Configured);

    let linux = PolicyContext {
        platform: Platform::Linux,
        scoped_rtss_type_override: true,
        ..smooth_motion
    };
    let decision = resolve_rtss_sync_limiter(&settings, linux);
    assert_eq!(decision.value, RtssFrameLimitType::BackEdgeSync);
    assert_eq!(decision.reason, RtssSyncLimiterReason::Configured);
}
