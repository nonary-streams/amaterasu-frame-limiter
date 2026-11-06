//! Strict, side-effect-free request boundary for the frame-limiter service.
use crate::{
    AutoVirtualFramegenMode, EffectiveSettings, FrameGenerationProvider, FrameLimiterDecision,
    FrameLimiterProvider, GlobalSettings, MangoHudLimiterMethod, MangoHudPreset, Platform,
    PolicyContext, PolicyDiagnostic, RtssFrameLimitType, evaluate_policy,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::{Value, json};
use std::str::FromStr;

pub const CONTRACT_VERSION: u32 = 1;
const MAX_SESSION_ID_BYTES: usize = 128;
const MAX_EXECUTABLE_PATH_BYTES: usize = 4096;

/// Distinguishes an omitted nullable request field from an explicit JSON null.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Presence<T> {
    #[default]
    Missing,
    Null,
    Value(T),
}

impl<T> Presence<T> {
    pub fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }

    pub fn as_ref(&self) -> Option<&T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Missing | Self::Null => None,
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Presence<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match Option::<T>::deserialize(deserializer)? {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}

impl<T: Serialize> Serialize for Presence<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Missing | Self::Null => serializer.serialize_none(),
            Self::Value(value) => serializer.serialize_some(value),
        }
    }
}

/// Wire operation accepted by `amaterasu.frame-limiter/1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Apply(ApplyRequest),
    Status(StatusRequest),
    Restore(RestoreRequest),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplyRequest {
    pub version: u32,
    pub session_id: String,
    pub executable_path: String,
    pub settings: SettingsInput,
    /// Missing or null means unknown. Zero is a known follow-stream value.
    #[serde(default, skip_serializing_if = "Presence::is_missing")]
    pub requested_stream_fps_millihz: Presence<u32>,
    /// Refresh rate from an explicit client display-mode setting, never from
    /// stream dimensions. Missing or null means unknown; zero means no rate.
    #[serde(default, skip_serializing_if = "Presence::is_missing")]
    pub client_display_mode_override_millihz: Presence<u32>,
    /// Missing or null means unknown; zero means no Lossless Scaling limit.
    #[serde(default, skip_serializing_if = "Presence::is_missing")]
    pub lossless_scaling_limit_millihz: Presence<u32>,
    /// Missing or null means the virtual-display state is unknown.
    #[serde(default, skip_serializing_if = "Presence::is_missing")]
    pub virtual_display_active: Presence<bool>,
    /// Missing or null means the physical frame-generation state is unknown.
    #[serde(default, skip_serializing_if = "Presence::is_missing")]
    pub physical_framegen_capture: Presence<bool>,
    /// Missing or null means the active game's frame-generation mode is unknown.
    #[serde(default, skip_serializing_if = "Presence::is_missing")]
    pub game_frame_generation_mode: Presence<GameFrameGenerationMode>,
    /// True only when a scoped RTSS type is known to be explicitly supplied.
    /// Missing or null means the settings source did not establish provenance.
    #[serde(default, skip_serializing_if = "Presence::is_missing")]
    pub rtss_frame_limit_type_explicit_override: Presence<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Presence::is_missing")]
    pub session_id: Presence<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Presence::is_missing")]
    pub session_id: Presence<String>,
    #[serde(default, skip_serializing_if = "Presence::is_missing")]
    pub lease: Presence<String>,
}

/// Resolved limiter settings supplied by the launch adapter. Rates are exact
/// integer millihertz, never floating-point Hz values.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettingsInput {
    pub frame_limiter_enable: bool,
    pub frame_limiter_provider: String,
    pub frame_limiter_fps_limit_millihz: u32,
    pub frame_limiter_disable_vsync: bool,
    pub frame_limiter_auto_virtual_framegen: String,
    pub rtss_frame_limit_type: String,
    pub rtss_install_path: String,
    pub rtss_allow_virtual_display_override: bool,
    pub mangohud_preset: String,
    pub mangohud_always_show_graph: bool,
    pub mangohud_limiter_method: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GameFrameGenerationMode {
    None,
    #[serde(rename = "lossless-scaling")]
    LosslessScaling,
    #[serde(rename = "game-provided")]
    GameProvided,
    #[serde(rename = "nvidia-smooth-motion")]
    NvidiaSmoothMotion,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError {
    InvalidJson,
    InvalidOperation,
    UnsupportedVersion,
    InvalidIdentifier,
    InvalidExecutablePath,
    InvalidSettings,
    InvalidMillihertz,
    InvalidRestoreTarget,
}

impl ServiceError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid_json",
            Self::InvalidOperation => "invalid_operation",
            Self::UnsupportedVersion => "unsupported_version",
            Self::InvalidIdentifier => "invalid_identifier",
            Self::InvalidExecutablePath => "invalid_executable_path",
            Self::InvalidSettings => "invalid_settings",
            Self::InvalidMillihertz => "invalid_millihertz",
            Self::InvalidRestoreTarget => "invalid_restore_target",
        }
    }
}

/// Policy data for a response. Its providers are candidates only; this module
/// does not detect or invoke provider backends.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyOnlyPlan {
    /// Null means available context cannot determine whether to apply policy.
    pub should_consider_apply: Option<bool>,
    /// Null means an earlier-priority rate source is unknown.
    pub effective_limit_millihz: Option<u32>,
    pub effective_limit_source: Option<String>,
    pub provider_candidates: Vec<ProviderCandidate>,
    pub concurrent_overlays: Vec<String>,
    pub diagnostics: Vec<String>,
    pub rtss_sync_limiter_type: String,
    pub rtss_sync_limiter_reason: String,
    pub provider_availability: ProviderAvailability,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderCandidate {
    pub provider: String,
    pub fallback: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAvailability {
    Unknown,
    Available,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseState {
    PolicyOnly,
    Applied,
    AlreadyApplied,
    NotNeeded,
    RuntimeUnavailable,
    LeaseConflict,
    StaleLease,
    Restored,
    RestoreFailed,
    NotFound,
}

/// Caller-visible lease state. Stale entries retain their token so the owner
/// can request cleanup after a provider or module restart.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseStatus {
    pub lease: String,
    pub session_id: String,
    pub executable_path: String,
    pub provider: String,
    pub state: ResponseState,
    pub applied: bool,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationResponse {
    pub ok: bool,
    pub version: u32,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// True only when the selected provider effect is confirmed by readback.
    pub applied: bool,
    pub state: ResponseState,
    pub provider_availability: ProviderAvailability,
    /// Present on apply only after the exact provider state is verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease: Option<String>,
    /// Caller-owned active, stale, or restore-pending leases returned by status.
    pub leases: Vec<LeaseStatus>,
    pub diagnostics: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<PolicyOnlyPlan>,
}

impl<'de> Deserialize<'de> for Operation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut value = Value::deserialize(deserializer)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| D::Error::custom("operation must be an object"))?;
        let action = object
            .remove("action")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| D::Error::custom("operation action is missing or invalid"))?;
        match action.as_str() {
            "apply" => serde_json::from_value(value)
                .map(Self::Apply)
                .map_err(D::Error::custom),
            "status" => serde_json::from_value(value)
                .map(Self::Status)
                .map_err(D::Error::custom),
            "restore" => serde_json::from_value(value)
                .map(Self::Restore)
                .map_err(D::Error::custom),
            _ => Err(D::Error::custom("unsupported operation action")),
        }
    }
}

pub fn parse_operation(json: &str) -> Result<Operation, ServiceError> {
    let operation: Operation = serde_json::from_str(json).map_err(|_| ServiceError::InvalidJson)?;
    operation.validate()?;
    Ok(operation)
}

impl Operation {
    pub fn validate(&self) -> Result<(), ServiceError> {
        match self {
            Self::Apply(request) => request.validate(),
            Self::Status(request) => validate_status_request(request),
            Self::Restore(request) => validate_restore_request(request),
        }
    }

    pub fn build_response(&self) -> Result<OperationResponse, ServiceError> {
        build_response(self)
    }
}

impl ApplyRequest {
    pub fn validate(&self) -> Result<(), ServiceError> {
        validate_version(self.version)?;
        validate_session_id(&self.session_id)?;
        if self.executable_path.trim().is_empty()
            || self.executable_path.len() > MAX_EXECUTABLE_PATH_BYTES
            || self.executable_path.chars().any(char::is_control)
        {
            return Err(ServiceError::InvalidExecutablePath);
        }
        let platform = current_platform();
        if !is_resolved_executable_path(&self.executable_path, platform) {
            return Err(ServiceError::InvalidExecutablePath);
        }
        self.settings.to_model(platform)?;
        for rate in [
            &self.requested_stream_fps_millihz,
            &self.client_display_mode_override_millihz,
            &self.lossless_scaling_limit_millihz,
        ] {
            if let Presence::Value(rate) = rate {
                crate::FpsLimit::from_millihz(*rate)
                    .map_err(|_| ServiceError::InvalidMillihertz)?;
            }
        }
        Ok(())
    }

    pub fn policy_context(&self) -> Result<PolicyContext, ServiceError> {
        self.validate()?;
        let client_display_mode_rate = match &self.client_display_mode_override_millihz {
            Presence::Value(0) => None,
            Presence::Value(rate) => Some(
                crate::FpsLimit::from_millihz(*rate)
                    .map_err(|_| ServiceError::InvalidMillihertz)?,
            ),
            Presence::Missing | Presence::Null => None,
        };
        let lossless_scaling_limit = match &self.lossless_scaling_limit_millihz {
            Presence::Value(limit) => Some(
                crate::FpsLimit::from_millihz(*limit)
                    .map_err(|_| ServiceError::InvalidMillihertz)?,
            ),
            Presence::Missing | Presence::Null => None,
        };
        let frame_generation_provider = match &self.game_frame_generation_mode {
            Presence::Value(GameFrameGenerationMode::None) | Presence::Missing | Presence::Null => {
                FrameGenerationProvider::None
            }
            Presence::Value(GameFrameGenerationMode::LosslessScaling) => {
                FrameGenerationProvider::LosslessScaling
            }
            Presence::Value(GameFrameGenerationMode::GameProvided) => {
                FrameGenerationProvider::GameProvided
            }
            Presence::Value(GameFrameGenerationMode::NvidiaSmoothMotion) => {
                FrameGenerationProvider::NvidiaSmoothMotion
            }
            Presence::Value(GameFrameGenerationMode::Other) => FrameGenerationProvider::Other,
        };
        let context = PolicyContext {
            platform: current_platform(),
            virtual_display_active: matches!(self.virtual_display_active, Presence::Value(true)),
            client_display_mode_rate,
            requested_stream_fps: match &self.requested_stream_fps_millihz {
                Presence::Value(0) => None,
                Presence::Value(value) => Some(
                    crate::FpsLimit::from_millihz(*value)
                        .map_err(|_| ServiceError::InvalidMillihertz)?,
                ),
                Presence::Null | Presence::Missing => None,
            },
            lossless_scaling_limit,
            frame_generation_provider,
            physical_framegen_capture: matches!(
                self.physical_framegen_capture,
                Presence::Value(true)
            ),
            scoped_rtss_type_override: matches!(
                self.rtss_frame_limit_type_explicit_override,
                Presence::Value(true)
            ),
            ..PolicyContext::default()
        };
        // Missing provider context is mapped to conservative policy defaults
        // for calculation only. The response carries unknown/null outcomes.
        Ok(context)
    }

    fn should_consider_apply_is_known(&self, settings: &EffectiveSettings) -> Option<bool> {
        if settings.enable {
            return Some(true);
        }

        let lossless_limit_active = match self.lossless_scaling_limit_millihz {
            Presence::Value(limit) => Some(limit != 0),
            Presence::Missing | Presence::Null => None,
        };
        let virtual_display_policy_active = if settings
            .auto_virtual_framegen
            .automatic_virtual_limiter_enabled()
        {
            self.virtual_display_active.as_ref().copied()
        } else {
            Some(false)
        };
        let explicit_physical_capture = self.physical_framegen_capture.as_ref().copied();
        let inferred_frame_generation = match self.game_frame_generation_mode {
            Presence::Value(GameFrameGenerationMode::LosslessScaling)
            | Presence::Value(GameFrameGenerationMode::GameProvided)
            | Presence::Value(GameFrameGenerationMode::NvidiaSmoothMotion) => Some(true),
            Presence::Value(_) => Some(false),
            Presence::Missing | Presence::Null => None,
        };
        let frame_generation_policy_active =
            combine_known_boolean_or(explicit_physical_capture, inferred_frame_generation);

        combine_known_boolean_or(
            lossless_limit_active,
            combine_known_boolean_or(
                virtual_display_policy_active,
                frame_generation_policy_active,
            ),
        )
    }

    fn effective_limit_is_known(&self, settings: &EffectiveSettings) -> bool {
        if !settings.fps_limit.is_follow_stream() {
            return true;
        }

        match self.lossless_scaling_limit_millihz {
            Presence::Value(limit) if limit != 0 => true,
            Presence::Value(_) => match self.client_display_mode_override_millihz {
                Presence::Value(rate) if rate != 0 => true,
                Presence::Value(_) => {
                    matches!(self.requested_stream_fps_millihz, Presence::Value(_))
                }
                Presence::Missing | Presence::Null => false,
            },
            Presence::Missing | Presence::Null => false,
        }
    }
}

fn combine_known_boolean_or(left: Option<bool>, right: Option<bool>) -> Option<bool> {
    match (left, right) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    }
}

impl SettingsInput {
    pub fn to_model(&self, platform: Platform) -> Result<EffectiveSettings, ServiceError> {
        self.validate_wire_tokens()?;
        let settings = GlobalSettings {
            enable: self.frame_limiter_enable,
            provider: FrameLimiterProvider::from_str(&self.frame_limiter_provider)
                .map_err(|_| ServiceError::InvalidSettings)?,
            fps_limit: crate::FpsLimit::from_millihz(self.frame_limiter_fps_limit_millihz)
                .map_err(|_| ServiceError::InvalidMillihertz)?,
            disable_vsync: self.frame_limiter_disable_vsync,
            auto_virtual_framegen: AutoVirtualFramegenMode::parse(
                &self.frame_limiter_auto_virtual_framegen,
            )
            .ok_or(ServiceError::InvalidSettings)?,
            rtss_frame_limit_type: RtssFrameLimitType::from_str(&self.rtss_frame_limit_type)
                .map_err(|_| ServiceError::InvalidSettings)?,
            rtss_install_path: self.rtss_install_path.clone(),
            rtss_allow_virtual_display_override: self.rtss_allow_virtual_display_override,
            mangohud_preset: MangoHudPreset::from_str(&self.mangohud_preset)
                .map_err(|_| ServiceError::InvalidSettings)?,
            mangohud_always_show_graph: self.mangohud_always_show_graph,
            mangohud_limiter_method: MangoHudLimiterMethod::from_str(&self.mangohud_limiter_method)
                .map_err(|_| ServiceError::InvalidSettings)?,
        };
        settings
            .validate(platform)
            .map_err(|_| ServiceError::InvalidSettings)?;
        Ok(EffectiveSettings::from(&settings))
    }

    fn validate_wire_tokens(&self) -> Result<(), ServiceError> {
        let valid_provider = matches!(
            self.frame_limiter_provider.as_str(),
            "auto"
                | "mangohud"
                | "mangohud-proton"
                | "proton"
                | "rtss"
                | "nvidia-control-panel"
                | "none"
        );
        let valid_frame_generation = matches!(
            self.frame_limiter_auto_virtual_framegen.as_str(),
            "enabled" | "vrr" | "legacy" | "disabled"
        );
        let valid_rtss_type = matches!(
            self.rtss_frame_limit_type.as_str(),
            "async" | "front edge sync" | "back edge sync" | "nvidia reflex"
        );
        let valid_mangohud_preset = matches!(
            self.mangohud_preset.as_str(),
            "custom" | "1" | "2" | "3" | "4"
        );
        let valid_mangohud_limiter_method =
            matches!(self.mangohud_limiter_method.as_str(), "early" | "late");

        if valid_provider
            && valid_frame_generation
            && valid_rtss_type
            && valid_mangohud_preset
            && valid_mangohud_limiter_method
        {
            Ok(())
        } else {
            Err(ServiceError::InvalidSettings)
        }
    }
}

pub(crate) fn evaluate_apply(request: &ApplyRequest) -> Result<FrameLimiterDecision, ServiceError> {
    request.validate()?;
    let settings = request.settings.to_model(current_platform())?;
    Ok(evaluate_policy(&settings, request.policy_context()?))
}

pub fn build_response(operation: &Operation) -> Result<OperationResponse, ServiceError> {
    operation.validate()?;
    let (action, session_id, state, plan) = match operation {
        Operation::Apply(request) => {
            let settings = request.settings.to_model(current_platform())?;
            let decision = evaluate_apply(request)?;
            (
                "apply",
                Some(request.session_id.clone()),
                ResponseState::PolicyOnly,
                Some(policy_only_plan(request, &settings, decision)),
            )
        }
        Operation::Status(request) => (
            "status",
            request.session_id.as_ref().cloned(),
            ResponseState::RuntimeUnavailable,
            None,
        ),
        Operation::Restore(request) => (
            "restore",
            request.session_id.as_ref().cloned(),
            ResponseState::RuntimeUnavailable,
            None,
        ),
    };
    Ok(OperationResponse {
        ok: true,
        version: CONTRACT_VERSION,
        action: action.into(),
        session_id,
        applied: false,
        state,
        provider_availability: ProviderAvailability::Unknown,
        lease: None,
        leases: Vec::new(),
        diagnostics: Vec::new(),
        plan,
    })
}

/// Validates caller scope and returns a JSON response without applying settings
/// or creating a lease. Provider execution belongs to the runtime adapter.
pub fn handle_operation(caller: &str, operation: Operation) -> Value {
    if caller.trim().is_empty()
        || caller.len() > MAX_SESSION_ID_BYTES
        || caller.chars().any(char::is_control)
    {
        return error_response(ServiceError::InvalidIdentifier);
    }
    match build_response(&operation) {
        Ok(response) => serde_json::to_value(response)
            .unwrap_or_else(|_| error_response(ServiceError::InvalidOperation)),
        Err(error) => error_response(error),
    }
}

/// Parses a tagged operation payload and returns the same strict error shape
/// used by `handle_operation` when JSON fields or values are invalid.
pub fn handle_payload(caller: &str, payload: Value) -> Value {
    match serde_json::from_value::<Operation>(payload) {
        Ok(operation) => handle_operation(caller, operation),
        Err(_) => error_response(ServiceError::InvalidJson),
    }
}

fn policy_only_plan(
    request: &ApplyRequest,
    settings: &EffectiveSettings,
    decision: FrameLimiterDecision,
) -> PolicyOnlyPlan {
    let should_consider_apply = request.should_consider_apply_is_known(settings);
    let effective_limit_is_known = request.effective_limit_is_known(settings);
    let mut diagnostics = vec!["provider_hardware_facts_unknown".into()];
    if decision
        .providers
        .diagnostics
        .contains(&PolicyDiagnostic::UnsupportedProviderForPlatform)
    {
        diagnostics.push("unsupported_provider_for_platform".into());
    }
    if decision
        .providers
        .diagnostics
        .contains(&PolicyDiagnostic::PlatformHasNoLimiterBackend)
    {
        diagnostics.push("platform_has_no_limiter_backend".into());
    }
    if should_consider_apply.is_none() || !effective_limit_is_known {
        diagnostics.push("policy_context_incomplete".into());
    }

    PolicyOnlyPlan {
        should_consider_apply,
        effective_limit_millihz: effective_limit_is_known
            .then_some(decision.effective_limit.value.millihz()),
        effective_limit_source: effective_limit_is_known
            .then(|| limit_source_name(decision.effective_limit.source).into()),
        // Provider and GPU facts are not detected by this policy-only module.
        // Do not turn the policy context's default false values into absence claims.
        provider_candidates: Vec::new(),
        concurrent_overlays: Vec::new(),
        diagnostics,
        rtss_sync_limiter_type: "unknown".into(),
        rtss_sync_limiter_reason: "provider_hardware_facts_unknown".into(),
        provider_availability: ProviderAvailability::Unknown,
    }
}

fn is_resolved_executable_path(path: &str, platform: Platform) -> bool {
    let is_absolute = match platform {
        Platform::Windows => crate::model::is_absolute_windows_path(path),
        Platform::Linux | Platform::Macos => path.starts_with('/'),
    };
    if !is_absolute {
        return false;
    }

    let file_name = match platform {
        Platform::Windows => path.rsplit(['\\', '/']).next(),
        Platform::Linux | Platform::Macos => path.rsplit('/').next(),
    };
    file_name.is_some_and(|name| !name.is_empty() && name != "." && name != "..")
}

fn validate_status_request(request: &StatusRequest) -> Result<(), ServiceError> {
    validate_version(request.version)?;
    if let Presence::Value(session_id) = &request.session_id {
        validate_session_id(session_id)?;
    }
    Ok(())
}

fn validate_restore_request(request: &RestoreRequest) -> Result<(), ServiceError> {
    validate_version(request.version)?;
    match (&request.session_id, &request.lease) {
        (Presence::Value(session_id), Presence::Missing | Presence::Null) => {
            validate_session_id(session_id)
        }
        (Presence::Missing | Presence::Null, Presence::Value(lease)) => validate_session_id(lease),
        _ => Err(ServiceError::InvalidRestoreTarget),
    }
}

fn validate_version(version: u32) -> Result<(), ServiceError> {
    if version == CONTRACT_VERSION {
        Ok(())
    } else {
        Err(ServiceError::UnsupportedVersion)
    }
}

fn validate_session_id(session_id: &str) -> Result<(), ServiceError> {
    if session_id.trim().is_empty()
        || session_id.len() > MAX_SESSION_ID_BYTES
        || session_id.chars().any(char::is_control)
    {
        return Err(ServiceError::InvalidIdentifier);
    }
    Ok(())
}

fn current_platform() -> Platform {
    #[cfg(target_os = "windows")]
    {
        Platform::Windows
    }
    #[cfg(target_os = "linux")]
    {
        Platform::Linux
    }
    #[cfg(target_os = "macos")]
    {
        Platform::Macos
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Platform::Macos
    }
}

fn limit_source_name(source: crate::FrameLimitSource) -> &'static str {
    match source {
        crate::FrameLimitSource::Configured => "configured",
        crate::FrameLimitSource::LosslessScaling => "lossless_scaling",
        crate::FrameLimitSource::DisplayMode => "display_mode",
        crate::FrameLimitSource::RequestedStream => "requested_stream",
        crate::FrameLimitSource::FollowStream => "follow_stream",
    }
}

fn error_response(error: ServiceError) -> Value {
    let message = match error {
        ServiceError::InvalidJson => "request JSON is malformed or contains unknown fields",
        ServiceError::InvalidOperation => "operation is malformed",
        ServiceError::UnsupportedVersion => "operation version is unsupported",
        ServiceError::InvalidIdentifier => "caller or session identifier is invalid",
        ServiceError::InvalidExecutablePath => "executable path is empty or invalid",
        ServiceError::InvalidSettings => "effective settings are invalid",
        ServiceError::InvalidMillihertz => "millihertz value is outside the supported range",
        ServiceError::InvalidRestoreTarget => "restore requires exactly one session_id or lease",
    };
    json!({"ok": false, "applied": false, "error": {"code": error.code(), "message": message}})
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn executable_path() -> String {
        #[cfg(target_os = "windows")]
        {
            r"C:\Games\example\game.exe".into()
        }
        #[cfg(not(target_os = "windows"))]
        {
            "/games/example/game.exe".into()
        }
    }

    fn effective_settings() -> Value {
        json!({
            "frame_limiter_enable": true,
            "frame_limiter_provider": "auto",
            "frame_limiter_fps_limit_millihz": 0,
            "frame_limiter_disable_vsync": false,
            "frame_limiter_auto_virtual_framegen": "enabled",
            "rtss_frame_limit_type": "async",
            "rtss_install_path": "",
            "rtss_allow_virtual_display_override": false,
            "mangohud_preset": "custom",
            "mangohud_always_show_graph": false,
            "mangohud_limiter_method": "late"
        })
    }

    fn apply_json() -> Value {
        json!({
            "action": "apply",
            "version": 1,
            "session_id": "session-17",
            "executable_path": executable_path(),
            "settings": effective_settings(),
            "requested_stream_fps_millihz": 143_997,
            "client_display_mode_override_millihz": null,
            "lossless_scaling_limit_millihz": null,
            "virtual_display_active": null,
            "physical_framegen_capture": null,
            "game_frame_generation_mode": null,
            "rtss_frame_limit_type_explicit_override": null
        })
    }

    #[test]
    fn strict_apply_parser_preserves_null_and_absent_fields() {
        let mut value = apply_json();
        let parsed = parse_operation(&value.to_string()).unwrap();
        let Operation::Apply(request) = parsed else {
            panic!("expected apply operation");
        };
        assert_eq!(request.client_display_mode_override_millihz, Presence::Null);
        assert_eq!(request.lossless_scaling_limit_millihz, Presence::Null);
        assert_eq!(request.virtual_display_active, Presence::Null);
        assert_eq!(request.physical_framegen_capture, Presence::Null);
        assert_eq!(request.game_frame_generation_mode, Presence::Null);
        assert_eq!(
            request.rtss_frame_limit_type_explicit_override,
            Presence::Null
        );
        assert_eq!(
            request.requested_stream_fps_millihz,
            Presence::Value(143_997)
        );
        let serialized = serde_json::to_value(&request).unwrap();
        assert_eq!(
            serialized["client_display_mode_override_millihz"],
            Value::Null
        );

        value
            .as_object_mut()
            .unwrap()
            .remove("client_display_mode_override_millihz");
        value
            .as_object_mut()
            .unwrap()
            .remove("lossless_scaling_limit_millihz");
        value
            .as_object_mut()
            .unwrap()
            .remove("game_frame_generation_mode");
        value
            .as_object_mut()
            .unwrap()
            .remove("rtss_frame_limit_type_explicit_override");
        value
            .as_object_mut()
            .unwrap()
            .remove("requested_stream_fps_millihz");
        value
            .as_object_mut()
            .unwrap()
            .remove("virtual_display_active");
        value
            .as_object_mut()
            .unwrap()
            .remove("physical_framegen_capture");
        let parsed = parse_operation(&value.to_string()).unwrap();
        let Operation::Apply(request) = parsed else {
            panic!("expected apply operation");
        };
        assert_eq!(
            request.client_display_mode_override_millihz,
            Presence::Missing
        );
        assert_eq!(request.lossless_scaling_limit_millihz, Presence::Missing);
        assert_eq!(request.virtual_display_active, Presence::Missing);
        assert_eq!(request.physical_framegen_capture, Presence::Missing);
        assert_eq!(request.game_frame_generation_mode, Presence::Missing);
        assert_eq!(
            request.rtss_frame_limit_type_explicit_override,
            Presence::Missing
        );
        assert_eq!(request.requested_stream_fps_millihz, Presence::Missing);
        let serialized = serde_json::to_value(&request).unwrap();
        assert!(
            serialized
                .get("client_display_mode_override_millihz")
                .is_none()
        );
        assert!(serialized.get("requested_stream_fps_millihz").is_none());

        value["requested_stream_fps_millihz"] = Value::Null;
        let Operation::Apply(request) = parse_operation(&value.to_string()).unwrap() else {
            panic!("expected apply operation");
        };
        assert_eq!(request.requested_stream_fps_millihz, Presence::Null);
        assert_eq!(request.policy_context().unwrap().requested_stream_fps, None);
        value["requested_stream_fps_millihz"] = json!(0);
        let Operation::Apply(request) = parse_operation(&value.to_string()).unwrap() else {
            panic!("expected apply operation");
        };
        assert_eq!(request.requested_stream_fps_millihz, Presence::Value(0));
        assert_eq!(request.policy_context().unwrap().requested_stream_fps, None);
    }

    #[test]
    fn parser_rejects_unknown_fields_versions_identifiers_and_millihertz_errors() {
        let mut value = apply_json();
        value["unexpected"] = json!(true);
        assert_eq!(
            parse_operation(&value.to_string()).unwrap_err(),
            ServiceError::InvalidJson
        );

        let mut value = apply_json();
        value["version"] = json!(2);
        assert_eq!(
            parse_operation(&value.to_string()).unwrap_err(),
            ServiceError::UnsupportedVersion
        );

        let mut value = apply_json();
        value["session_id"] = json!(" \n ");
        assert_eq!(
            parse_operation(&value.to_string()).unwrap_err(),
            ServiceError::InvalidIdentifier
        );

        let mut value = apply_json();
        value["requested_stream_fps_millihz"] = json!(1_000_001);
        assert_eq!(
            parse_operation(&value.to_string()).unwrap_err(),
            ServiceError::InvalidMillihertz
        );

        let mut value = apply_json();
        value["lossless_scaling_limit_millihz"] = json!(12.5);
        assert_eq!(
            parse_operation(&value.to_string()).unwrap_err(),
            ServiceError::InvalidJson
        );

        let mut value = apply_json();
        value["settings"]["frame_limiter_fps_limit_millihz"] = json!(1_000_001);
        assert_eq!(
            parse_operation(&value.to_string()).unwrap_err(),
            ServiceError::InvalidMillihertz
        );

        let mut value = apply_json();
        value["executable_path"] = json!("game.exe");
        assert_eq!(
            parse_operation(&value.to_string()).unwrap_err(),
            ServiceError::InvalidExecutablePath
        );
    }

    #[test]
    fn wire_settings_accept_only_canonical_tokens() {
        for (field, value) in [
            ("frame_limiter_provider", "nvcp"),
            ("frame_limiter_auto_virtual_framegen", "smooth"),
            ("rtss_frame_limit_type", "front_edge_sync"),
        ] {
            let mut request = apply_json();
            request["settings"][field] = json!(value);
            assert_eq!(
                parse_operation(&request.to_string()).unwrap_err(),
                ServiceError::InvalidSettings,
                "{field} accepted a noncanonical wire token"
            );
        }
    }

    #[test]
    fn rtss_install_path_is_rejected_off_windows() {
        let mut input: SettingsInput = serde_json::from_value(effective_settings()).unwrap();
        input.rtss_install_path = "/opt/rtss".into();
        assert_eq!(
            input.to_model(Platform::Linux).unwrap_err(),
            ServiceError::InvalidSettings
        );
        input.rtss_install_path.clear();
        assert!(input.to_model(Platform::Linux).is_ok());
    }

    #[test]
    fn conversion_keeps_exact_rates_and_explicit_scoped_rtss_provenance() {
        let mut value = apply_json();
        value["settings"]["frame_limiter_fps_limit_millihz"] = json!(0);
        value["requested_stream_fps_millihz"] = json!(143_997);
        value["client_display_mode_override_millihz"] = json!(119_880);
        value["lossless_scaling_limit_millihz"] = json!(90_000);
        value["virtual_display_active"] = json!(true);
        value["physical_framegen_capture"] = json!(false);
        value["game_frame_generation_mode"] = json!("game-provided");
        value["settings"]["rtss_frame_limit_type"] = json!("front edge sync");
        value["rtss_frame_limit_type_explicit_override"] = json!(true);

        let Operation::Apply(request) = parse_operation(&value.to_string()).unwrap() else {
            panic!("expected apply operation");
        };
        let settings = request.settings.to_model(current_platform()).unwrap();
        let context = request.policy_context().unwrap();
        assert_eq!(settings.fps_limit.millihz(), 0);
        assert_eq!(context.requested_stream_fps.unwrap().millihz(), 143_997);
        assert_eq!(context.client_display_mode_rate.unwrap().millihz(), 119_880);
        assert_eq!(context.lossless_scaling_limit.unwrap().millihz(), 90_000);
        assert_eq!(
            context.frame_generation_provider,
            FrameGenerationProvider::GameProvided
        );
        assert!(context.virtual_display_active);
        assert!(context.scoped_rtss_type_override);

        let response = evaluate_apply(&request).unwrap();
        assert_eq!(response.effective_limit.value.millihz(), 90_000);
        assert_eq!(
            response.effective_limit.source,
            crate::FrameLimitSource::LosslessScaling
        );
    }

    #[test]
    fn malformed_settings_and_display_rates_are_rejected() {
        let mut value = apply_json();
        value["settings"]["frame_limiter_provider"] = json!("mystery");
        assert_eq!(
            parse_operation(&value.to_string()).unwrap_err(),
            ServiceError::InvalidSettings
        );

        let mut value = apply_json();
        value["client_display_mode_override_millihz"] = json!(1_000_001);
        assert_eq!(
            parse_operation(&value.to_string()).unwrap_err(),
            ServiceError::InvalidMillihertz
        );

        let mut value = apply_json();
        value["game_frame_generation_mode"] = json!("game_provided");
        assert_eq!(
            parse_operation(&value.to_string()).unwrap_err(),
            ServiceError::InvalidJson
        );
    }

    #[test]
    fn apply_status_and_restore_responses_never_claim_provider_effects() {
        let response = handle_payload("module-host", apply_json());
        assert_eq!(response["ok"], true);
        assert_eq!(response["applied"], false);
        assert_eq!(response["state"], "policy_only");
        assert_eq!(response["provider_availability"], "unknown");
        assert!(response["plan"].is_object());
        assert_eq!(response["plan"]["should_consider_apply"], true);
        assert_eq!(response["plan"]["effective_limit_millihz"], Value::Null);
        assert_eq!(response["plan"]["rtss_sync_limiter_type"], "unknown");
        assert_eq!(
            response["plan"]["diagnostics"][0],
            "provider_hardware_facts_unknown"
        );

        let mut unsupported_provider = apply_json();
        let expected_platform_diagnostic = match current_platform() {
            Platform::Windows => {
                unsupported_provider["settings"]["frame_limiter_provider"] = json!("mangohud");
                "unsupported_provider_for_platform"
            }
            Platform::Linux => {
                unsupported_provider["settings"]["frame_limiter_provider"] = json!("rtss");
                "unsupported_provider_for_platform"
            }
            Platform::Macos => "platform_has_no_limiter_backend",
        };
        let unsupported = handle_payload("module-host", unsupported_provider);
        assert!(
            unsupported["plan"]["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|diagnostic| diagnostic == expected_platform_diagnostic)
        );

        let mut incomplete_context = apply_json();
        incomplete_context["settings"]["frame_limiter_enable"] = json!(false);
        let incomplete = handle_payload("module-host", incomplete_context);
        assert_eq!(incomplete["plan"]["should_consider_apply"], Value::Null);
        assert_eq!(incomplete["plan"]["effective_limit_millihz"], Value::Null);
        assert_eq!(
            incomplete["plan"]["diagnostics"][1],
            "policy_context_incomplete"
        );

        let mut complete_context = apply_json();
        complete_context["settings"]["frame_limiter_enable"] = json!(false);
        complete_context["requested_stream_fps_millihz"] = json!(0);
        complete_context["client_display_mode_override_millihz"] = json!(0);
        complete_context["lossless_scaling_limit_millihz"] = json!(0);
        complete_context["virtual_display_active"] = json!(false);
        complete_context["physical_framegen_capture"] = json!(false);
        complete_context["game_frame_generation_mode"] = json!("none");
        let complete = handle_payload("module-host", complete_context);
        assert_eq!(complete["plan"]["should_consider_apply"], false);
        assert_eq!(complete["plan"]["effective_limit_millihz"], 0);
        assert_eq!(complete["plan"]["effective_limit_source"], "follow_stream");

        let mut inferred_game_generation = apply_json();
        inferred_game_generation["settings"]["frame_limiter_enable"] = json!(false);
        inferred_game_generation["requested_stream_fps_millihz"] = json!(60_000);
        inferred_game_generation["client_display_mode_override_millihz"] = json!(0);
        inferred_game_generation["lossless_scaling_limit_millihz"] = json!(0);
        inferred_game_generation["virtual_display_active"] = json!(false);
        inferred_game_generation["physical_framegen_capture"] = Value::Null;
        inferred_game_generation["game_frame_generation_mode"] = json!("game-provided");
        let inferred = handle_payload("module-host", inferred_game_generation);
        assert_eq!(inferred["plan"]["should_consider_apply"], true);

        let mut inferred_lossless_generation = apply_json();
        inferred_lossless_generation["settings"]["frame_limiter_enable"] = json!(false);
        inferred_lossless_generation["requested_stream_fps_millihz"] = json!(60_000);
        inferred_lossless_generation["client_display_mode_override_millihz"] = json!(0);
        inferred_lossless_generation["lossless_scaling_limit_millihz"] = json!(0);
        inferred_lossless_generation["virtual_display_active"] = json!(false);
        inferred_lossless_generation["physical_framegen_capture"] = json!(false);
        inferred_lossless_generation["game_frame_generation_mode"] = json!("lossless-scaling");
        let inferred = handle_payload("module-host", inferred_lossless_generation);
        assert_eq!(inferred["plan"]["should_consider_apply"], true);
        assert_eq!(inferred["plan"]["effective_limit_millihz"], 60_000);

        let invalid = handle_payload(
            "module-host",
            json!({"action":"apply","version":1,"extra":true}),
        );
        assert_eq!(invalid["ok"], false);
        assert_eq!(invalid["applied"], false);

        let operation = parse_operation(&apply_json().to_string()).unwrap();
        let response = build_response(&operation).unwrap();
        assert!(!response.applied);
        assert_eq!(response.state, ResponseState::PolicyOnly);
        assert_eq!(
            response.provider_availability,
            ProviderAvailability::Unknown
        );
        assert!(response.plan.is_some());

        for (action, json) in [
            ("status", json!({"action":"status","version":1})),
            (
                "restore",
                json!({"action":"restore","version":1,"session_id":"s"}),
            ),
            (
                "restore",
                json!({"action":"restore","version":1,"lease":"opaque-lease"}),
            ),
        ] {
            let operation = parse_operation(&json.to_string()).unwrap();
            let response = build_response(&operation).unwrap();
            assert_eq!(response.action, action);
            assert!(!response.applied);
            assert_eq!(response.state, ResponseState::RuntimeUnavailable);
            assert!(response.plan.is_none());
        }

        for invalid_restore in [
            json!({"action":"restore","version":1}),
            json!({"action":"restore","version":1,"session_id":"s","lease":"l"}),
        ] {
            assert_eq!(
                parse_operation(&invalid_restore.to_string()).unwrap_err(),
                ServiceError::InvalidRestoreTarget
            );
        }
    }

    #[test]
    fn lifecycle_response_schema_only_exposes_verified_apply_leases() {
        let lease = LeaseStatus {
            lease: "frame-lease-1".into(),
            session_id: "session-17".into(),
            executable_path: executable_path(),
            provider: "rtss".into(),
            state: ResponseState::Applied,
            applied: true,
            diagnostics: Vec::new(),
        };
        let applied = OperationResponse {
            ok: true,
            version: CONTRACT_VERSION,
            action: "apply".into(),
            session_id: Some("session-17".into()),
            applied: true,
            state: ResponseState::Applied,
            provider_availability: ProviderAvailability::Available,
            lease: Some(lease.lease.clone()),
            leases: vec![lease.clone()],
            diagnostics: Vec::new(),
            plan: None,
        };
        let value = serde_json::to_value(applied).unwrap();
        assert_eq!(value["state"], "applied");
        assert_eq!(value["provider_availability"], "available");
        assert_eq!(value["lease"], "frame-lease-1");
        assert_eq!(value["leases"][0]["lease"], "frame-lease-1");
        assert_eq!(value["leases"][0]["applied"], true);

        let stale = LeaseStatus {
            state: ResponseState::StaleLease,
            applied: false,
            diagnostics: vec!["provider_state_changed".into()],
            ..lease
        };
        let response = OperationResponse {
            ok: true,
            version: CONTRACT_VERSION,
            action: "status".into(),
            session_id: Some("session-17".into()),
            applied: false,
            state: ResponseState::StaleLease,
            provider_availability: ProviderAvailability::Unavailable,
            lease: None,
            leases: vec![stale],
            diagnostics: vec!["stale_lease_detected_after_restart".into()],
            plan: None,
        };
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["state"], "stale_lease");
        assert_eq!(value["applied"], false);
        assert!(value.get("lease").is_none());
        assert_eq!(value["leases"][0]["state"], "stale_lease");
        assert_eq!(value["leases"][0]["applied"], false);
    }
}
