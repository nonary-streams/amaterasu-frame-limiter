use crate::{
    AutoVirtualFramegenMode, EffectiveSettings, FpsLimit, FrameGenerationProvider,
    FrameLimiterProvider, Platform, RtssFrameLimitType,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderBackend {
    Rtss,
    NvidiaControlPanel,
    MangoHud,
    Proton,
    MangoHudProton,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FallbackCondition {
    FirstChoice,
    AfterFailure,
    OnlyAfterStall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderAttempt {
    pub backend: ProviderBackend,
    pub fallback: FallbackCondition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyDiagnostic {
    UnsupportedProviderForPlatform,
    NoProviderAvailable,
    MangoHudUnavailable,
    NvidiaFallbackUnavailable,
    PlatformHasNoLimiterBackend,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProviderPlan {
    /// Ordered candidates for a later runtime adapter. This policy layer does not apply them.
    pub attempts: Vec<ProviderAttempt>,
    /// Concurrent overlays associated with a limiter candidate, never sequential fallbacks.
    pub overlays: Vec<ProviderBackend>,
    pub diagnostics: Vec<PolicyDiagnostic>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameLimitSource {
    Configured,
    LosslessScaling,
    DisplayMode,
    RequestedStream,
    FollowStream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectiveFrameLimit {
    pub value: FpsLimit,
    pub source: FrameLimitSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtssSyncLimiterReason {
    Configured,
    ScopedOverride,
    VirtualDisplaySafety,
    GameFrameGenerationSafety,
    FrameGenerationPolicy,
    NvidiaSmoothMotion,
    NonNvidiaAdapter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtssSyncLimiterDecision {
    pub value: RtssFrameLimitType,
    pub reason: RtssSyncLimiterReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyContext {
    pub platform: Platform,
    pub virtual_display_active: bool,
    pub client_display_mode_rate: Option<FpsLimit>,
    /// Authoritative requested stream rate, when the launcher has resolved one.
    pub requested_stream_fps: Option<FpsLimit>,
    pub lossless_scaling_limit: Option<FpsLimit>,
    pub frame_generation_provider: FrameGenerationProvider,
    pub physical_framegen_capture: bool,
    pub nvidia_gpu_present: bool,
    pub amd_gpu_present: bool,
    /// Environment fact for launch projection; Linux Auto provider selection ignores it.
    pub proton_environment: bool,
    pub mangohud_available: bool,
    /// True when a per-application or per-client RTSS type was explicitly supplied.
    pub scoped_rtss_type_override: bool,
}

impl Default for PolicyContext {
    fn default() -> Self {
        Self {
            platform: Platform::Windows,
            virtual_display_active: false,
            client_display_mode_rate: None,
            requested_stream_fps: None,
            lossless_scaling_limit: None,
            frame_generation_provider: FrameGenerationProvider::None,
            physical_framegen_capture: false,
            nvidia_gpu_present: false,
            amd_gpu_present: false,
            proton_environment: false,
            mangohud_available: false,
            scoped_rtss_type_override: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameLimiterDecision {
    /// Whether an integration should consider applying a limiter. This is not an applied state.
    pub should_consider_apply: bool,
    pub effective_limit: EffectiveFrameLimit,
    pub providers: ProviderPlan,
    pub rtss_sync_limiter: RtssSyncLimiterDecision,
}

pub fn evaluate_policy(
    settings: &EffectiveSettings,
    context: PolicyContext,
) -> FrameLimiterDecision {
    FrameLimiterDecision {
        should_consider_apply: should_consider_apply(settings, context),
        effective_limit: resolve_effective_limit(settings.fps_limit, context),
        providers: plan_provider(settings.provider, context),
        rtss_sync_limiter: resolve_rtss_sync_limiter(settings, context),
    }
}

pub fn should_consider_apply(settings: &EffectiveSettings, context: PolicyContext) -> bool {
    settings.enable
        || (context.virtual_display_active
            && settings.auto_virtual_framegen != AutoVirtualFramegenMode::Disabled)
        || frame_generation_policy_is_active(context)
        || context
            .lossless_scaling_limit
            .is_some_and(|limit| !limit.is_follow_stream())
}

fn frame_generation_policy_is_active(context: PolicyContext) -> bool {
    context.physical_framegen_capture
        || matches!(
            context.frame_generation_provider,
            FrameGenerationProvider::LosslessScaling
                | FrameGenerationProvider::GameProvided
                | FrameGenerationProvider::NvidiaSmoothMotion
        )
}

pub fn resolve_effective_limit(
    configured: FpsLimit,
    context: PolicyContext,
) -> EffectiveFrameLimit {
    if !configured.is_follow_stream() {
        return EffectiveFrameLimit {
            value: configured,
            source: FrameLimitSource::Configured,
        };
    }

    if let Some(limit) = context
        .lossless_scaling_limit
        .filter(|limit| !limit.is_follow_stream())
    {
        return EffectiveFrameLimit {
            value: limit,
            source: FrameLimitSource::LosslessScaling,
        };
    }

    if let Some(refresh_rate) = context
        .client_display_mode_rate
        .filter(|refresh_rate| !refresh_rate.is_follow_stream())
    {
        return EffectiveFrameLimit {
            value: refresh_rate,
            source: FrameLimitSource::DisplayMode,
        };
    }

    if let Some(stream_fps) = context
        .requested_stream_fps
        .filter(|stream_fps| !stream_fps.is_follow_stream())
    {
        return EffectiveFrameLimit {
            value: stream_fps,
            source: FrameLimitSource::RequestedStream,
        };
    }

    EffectiveFrameLimit {
        value: FpsLimit::FOLLOW_STREAM,
        source: FrameLimitSource::FollowStream,
    }
}

pub fn plan_provider(provider: FrameLimiterProvider, context: PolicyContext) -> ProviderPlan {
    let mut plan = ProviderPlan::default();

    match context.platform {
        Platform::Windows => plan_windows_provider(provider, context, &mut plan),
        Platform::Linux => plan_linux_provider(provider, context, &mut plan),
        Platform::Macos => {
            if provider != FrameLimiterProvider::None {
                plan.diagnostics
                    .push(PolicyDiagnostic::PlatformHasNoLimiterBackend);
            }
        }
    }

    plan
}

fn plan_windows_provider(
    provider: FrameLimiterProvider,
    context: PolicyContext,
    plan: &mut ProviderPlan,
) {
    match provider {
        FrameLimiterProvider::Auto => {
            push_attempt(plan, ProviderBackend::Rtss, FallbackCondition::FirstChoice);
            if context.nvidia_gpu_present {
                push_attempt(
                    plan,
                    ProviderBackend::NvidiaControlPanel,
                    FallbackCondition::AfterFailure,
                );
            } else {
                plan.diagnostics
                    .push(PolicyDiagnostic::NvidiaFallbackUnavailable);
            }
        }
        FrameLimiterProvider::Rtss => {
            push_attempt(plan, ProviderBackend::Rtss, FallbackCondition::FirstChoice);
            if context.nvidia_gpu_present {
                push_attempt(
                    plan,
                    ProviderBackend::NvidiaControlPanel,
                    FallbackCondition::OnlyAfterStall,
                );
            }
        }
        FrameLimiterProvider::NvidiaControlPanel if context.nvidia_gpu_present => {
            push_attempt(
                plan,
                ProviderBackend::NvidiaControlPanel,
                FallbackCondition::FirstChoice,
            );
        }
        FrameLimiterProvider::NvidiaControlPanel => {
            plan.diagnostics.push(PolicyDiagnostic::NoProviderAvailable);
        }
        FrameLimiterProvider::None => {}
        FrameLimiterProvider::MangoHud
        | FrameLimiterProvider::Proton
        | FrameLimiterProvider::MangoHudProton => {
            plan.diagnostics
                .push(PolicyDiagnostic::UnsupportedProviderForPlatform);
        }
    }
}

fn plan_linux_provider(
    provider: FrameLimiterProvider,
    context: PolicyContext,
    plan: &mut ProviderPlan,
) {
    match provider {
        FrameLimiterProvider::Auto => {
            push_attempt(
                plan,
                ProviderBackend::Proton,
                FallbackCondition::FirstChoice,
            );
            add_mangohud_overlay(context, plan);
        }
        FrameLimiterProvider::Proton => {
            push_attempt(
                plan,
                ProviderBackend::Proton,
                FallbackCondition::FirstChoice,
            );
        }
        FrameLimiterProvider::MangoHud if context.mangohud_available => {
            push_attempt(
                plan,
                ProviderBackend::MangoHud,
                FallbackCondition::FirstChoice,
            );
        }
        FrameLimiterProvider::MangoHud => {
            plan.diagnostics.push(PolicyDiagnostic::MangoHudUnavailable);
        }
        FrameLimiterProvider::MangoHudProton => {
            push_attempt(
                plan,
                ProviderBackend::Proton,
                FallbackCondition::FirstChoice,
            );
            add_mangohud_overlay(context, plan);
        }
        FrameLimiterProvider::None => {}
        FrameLimiterProvider::Rtss | FrameLimiterProvider::NvidiaControlPanel => {
            plan.diagnostics
                .push(PolicyDiagnostic::UnsupportedProviderForPlatform);
        }
    }
}

fn add_mangohud_overlay(context: PolicyContext, plan: &mut ProviderPlan) {
    if context.mangohud_available {
        plan.overlays.push(ProviderBackend::MangoHudProton);
    } else {
        plan.diagnostics.push(PolicyDiagnostic::MangoHudUnavailable);
    }
}

fn push_attempt(plan: &mut ProviderPlan, backend: ProviderBackend, fallback: FallbackCondition) {
    plan.attempts.push(ProviderAttempt { backend, fallback });
}

pub fn resolve_rtss_sync_limiter(
    settings: &EffectiveSettings,
    context: PolicyContext,
) -> RtssSyncLimiterDecision {
    if context.platform != Platform::Windows
        || !matches!(
            settings.provider,
            FrameLimiterProvider::Auto | FrameLimiterProvider::Rtss
        )
    {
        return RtssSyncLimiterDecision {
            value: settings.rtss_frame_limit_type,
            reason: RtssSyncLimiterReason::Configured,
        };
    }

    if context.scoped_rtss_type_override {
        return RtssSyncLimiterDecision {
            value: settings.rtss_frame_limit_type,
            reason: RtssSyncLimiterReason::ScopedOverride,
        };
    }

    let virtual_display_policy_active = context.virtual_display_active
        && settings
            .auto_virtual_framegen
            .automatic_virtual_limiter_enabled();
    let frame_generation_policy_active =
        virtual_display_policy_active || frame_generation_policy_is_active(context);
    if !frame_generation_policy_active {
        return RtssSyncLimiterDecision {
            value: settings.rtss_frame_limit_type,
            reason: RtssSyncLimiterReason::Configured,
        };
    }

    let reflex_supported = context.nvidia_gpu_present && !context.amd_gpu_present;

    let game_provided = context.frame_generation_provider == FrameGenerationProvider::GameProvided;
    let virtual_display_reflex_required = virtual_display_policy_active
        && (game_provided || !settings.rtss_allow_virtual_display_override);
    let virtual_display_sync_overridden = context.virtual_display_active
        && settings.rtss_allow_virtual_display_override
        && !virtual_display_reflex_required
        && !game_provided;
    if virtual_display_sync_overridden {
        return RtssSyncLimiterDecision {
            value: settings.rtss_frame_limit_type,
            reason: RtssSyncLimiterReason::Configured,
        };
    }

    if context.frame_generation_provider == FrameGenerationProvider::NvidiaSmoothMotion {
        return RtssSyncLimiterDecision {
            value: RtssFrameLimitType::FrontEdgeSync,
            reason: RtssSyncLimiterReason::NvidiaSmoothMotion,
        };
    }

    if virtual_display_policy_active && reflex_supported {
        return RtssSyncLimiterDecision {
            value: RtssFrameLimitType::NvidiaReflex,
            reason: if game_provided {
                RtssSyncLimiterReason::GameFrameGenerationSafety
            } else {
                RtssSyncLimiterReason::VirtualDisplaySafety
            },
        };
    }

    if game_provided && reflex_supported {
        return RtssSyncLimiterDecision {
            value: RtssFrameLimitType::NvidiaReflex,
            reason: RtssSyncLimiterReason::GameFrameGenerationSafety,
        };
    }

    RtssSyncLimiterDecision {
        value: RtssFrameLimitType::FrontEdgeSync,
        reason: if !reflex_supported && (game_provided || virtual_display_policy_active) {
            RtssSyncLimiterReason::NonNvidiaAdapter
        } else {
            RtssSyncLimiterReason::FrameGenerationPolicy
        },
    }
}
