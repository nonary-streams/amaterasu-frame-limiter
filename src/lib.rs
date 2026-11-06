//! Validated frame-limiter settings and pure launch-policy decisions.
mod extension;
mod lease;
mod lifecycle;
#[cfg(any(target_os = "linux", windows, test))]
mod lifecycle_facts;
#[cfg(any(target_os = "linux", windows, test))]
mod lifecycle_plan;
#[cfg(target_os = "linux")]
mod lifecycle_policy;
#[cfg(target_os = "linux")]
mod linux_availability;
#[cfg(target_os = "linux")]
mod linux_environment;
#[cfg(target_os = "linux")]
mod linux_journal;
#[cfg(target_os = "linux")]
mod linux_lifecycle;
#[cfg(target_os = "linux")]
mod linux_ownership;
mod model;
#[cfg(any(windows, all(test, target_os = "linux")))]
mod native_worker_process;
#[cfg(any(windows, test))]
mod nvcp;
mod policy;
#[cfg(target_os = "linux")]
mod proton_worker;
mod rtss;
#[cfg(all(windows, target_pointer_width = "64"))]
mod rtss_installation;
#[cfg(any(all(windows, target_pointer_width = "64"), test))]
mod rtss_profile;
mod runtime;
mod service;
pub mod settings_descriptor;
#[cfg(any(windows, test))]
mod windows_lifecycle;
#[cfg(any(windows, test))]
mod windows_policy;
#[cfg(windows)]
mod windows_worker;

pub use model::{
    AutoVirtualFramegenMode, EffectiveSettings, FpsLimit, FrameGenerationProvider,
    FrameLimiterOverrides, FrameLimiterProvider, GlobalSettings, MangoHudLimiterMethod,
    MangoHudPreset, ParsedGlobalSettings, Platform, RtssFrameLimitType, SettingsDiagnostic,
    SettingsError,
};
pub use policy::{
    EffectiveFrameLimit, FallbackCondition, FrameLimitSource, FrameLimiterDecision, PolicyContext,
    PolicyDiagnostic, ProviderAttempt, ProviderBackend, ProviderPlan, RtssSyncLimiterDecision,
    RtssSyncLimiterReason, evaluate_policy, plan_provider, resolve_effective_limit,
    resolve_rtss_sync_limiter, should_consider_apply,
};
pub use runtime::FrameLimiterModule;
pub use service::{
    ApplyRequest, CONTRACT_VERSION, GameFrameGenerationMode, LeaseStatus, Operation,
    OperationResponse, PolicyOnlyPlan, Presence, ProviderAvailability, ProviderCandidate,
    ResponseState, RestoreRequest, ServiceError, SettingsInput, StatusRequest, build_response,
    handle_operation, handle_payload, parse_operation,
};

#[cfg(test)]
mod tests;

amaterasu_module_sdk::export_module!(FrameLimiterModule);
