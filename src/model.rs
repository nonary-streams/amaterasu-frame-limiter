use serde::Deserialize;
use serde_json::{Number, Value};
use std::str::FromStr;

pub const MAX_FPS_LIMIT_MILLIHZ: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Linux,
    Macos,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FpsLimit(u32);

impl FpsLimit {
    pub const FOLLOW_STREAM: Self = Self(0);

    pub fn from_millihz(value: u32) -> Result<Self, SettingsError> {
        if value <= MAX_FPS_LIMIT_MILLIHZ {
            Ok(Self(value))
        } else {
            Err(SettingsError::InvalidFpsLimit)
        }
    }

    /// Parses the reference configuration's decimal-Hz syntax without rounding.
    pub fn parse_hz(value: &str) -> Result<Self, SettingsError> {
        let (whole, fractional) = match value.split_once('.') {
            Some((whole, fractional))
                if !fractional.is_empty() && fractional.len() <= 3 && !fractional.contains('.') =>
            {
                (whole, fractional)
            }
            Some(_) => return Err(SettingsError::InvalidFpsLimit),
            None => (value, ""),
        };

        let whole = parse_decimal_component(whole).ok_or(SettingsError::InvalidFpsLimit)?;
        if whole > 1_000 {
            return Err(SettingsError::InvalidFpsLimit);
        }

        let fractional_value = if fractional.is_empty() {
            0
        } else {
            let parsed =
                parse_decimal_component(fractional).ok_or(SettingsError::InvalidFpsLimit)?;
            match fractional.len() {
                1 => parsed * 100,
                2 => parsed * 10,
                3 => parsed,
                _ => return Err(SettingsError::InvalidFpsLimit),
            }
        };
        let millihz = whole * 1_000 + fractional_value;
        Self::from_millihz(millihz)
    }

    pub fn millihz(self) -> u32 {
        self.0
    }

    pub fn is_follow_stream(self) -> bool {
        self.0 == 0
    }
}

fn parse_decimal_component(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FrameLimiterProvider {
    #[default]
    Auto,
    Rtss,
    NvidiaControlPanel,
    MangoHud,
    Proton,
    MangoHudProton,
    None,
}

impl FrameLimiterProvider {
    pub fn choices(platform: Platform) -> &'static [Self] {
        const WINDOWS: &[FrameLimiterProvider] = &[
            FrameLimiterProvider::Auto,
            FrameLimiterProvider::Rtss,
            FrameLimiterProvider::NvidiaControlPanel,
            FrameLimiterProvider::None,
        ];
        const LINUX: &[FrameLimiterProvider] = &[
            FrameLimiterProvider::Auto,
            FrameLimiterProvider::MangoHud,
            FrameLimiterProvider::Proton,
            FrameLimiterProvider::MangoHudProton,
            FrameLimiterProvider::None,
        ];
        const MACOS_UI_ONLY: &[FrameLimiterProvider] =
            &[FrameLimiterProvider::Auto, FrameLimiterProvider::None];

        match platform {
            Platform::Windows => WINDOWS,
            Platform::Linux => LINUX,
            Platform::Macos => MACOS_UI_ONLY,
        }
    }
}

impl FromStr for FrameLimiterProvider {
    type Err = SettingsError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = normalize_token(value);
        match normalized.as_str() {
            "" | "auto" => Ok(Self::Auto),
            "rtss" => Ok(Self::Rtss),
            "nvidiacontrolpanel" | "nvidia" | "nvcp" => Ok(Self::NvidiaControlPanel),
            "mangohud" => Ok(Self::MangoHud),
            "proton" => Ok(Self::Proton),
            "mangohudproton" | "protonmangohud" => Ok(Self::MangoHudProton),
            "none" | "disabled" => Ok(Self::None),
            _ => Err(SettingsError::InvalidProvider),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AutoVirtualFramegenMode {
    #[default]
    Enabled,
    Vrr,
    Legacy,
    Disabled,
}

impl AutoVirtualFramegenMode {
    pub fn parse(value: &str) -> Option<Self> {
        match normalize_token(value).as_str() {
            "enabled" | "enable" | "true" | "yes" | "on" | "1" | "smooth" | "smoother" => {
                Some(Self::Enabled)
            }
            "vrr" | "1000hz" | "1000" | "fixed1000hz" => Some(Self::Vrr),
            "legacy" | "2x" | "fixed2x" => Some(Self::Legacy),
            "false" | "no" | "disable" | "disabled" | "off" | "0" => Some(Self::Disabled),
            _ => None,
        }
    }

    pub fn automatic_virtual_limiter_enabled(self) -> bool {
        self != Self::Disabled
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RtssFrameLimitType {
    #[default]
    Async,
    FrontEdgeSync,
    BackEdgeSync,
    NvidiaReflex,
}

impl FromStr for RtssFrameLimitType {
    type Err = SettingsError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match normalize_token(value).as_str() {
            "async" => Ok(Self::Async),
            "frontedgesync" => Ok(Self::FrontEdgeSync),
            "backedgesync" => Ok(Self::BackEdgeSync),
            "nvidiareflex" | "reflex" => Ok(Self::NvidiaReflex),
            _ => Err(SettingsError::InvalidRtssFrameLimitType),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MangoHudPreset {
    #[default]
    Custom,
    One,
    Two,
    Three,
    Four,
}

impl FromStr for MangoHudPreset {
    type Err = SettingsError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "custom" => Ok(Self::Custom),
            "1" => Ok(Self::One),
            "2" => Ok(Self::Two),
            "3" => Ok(Self::Three),
            "4" => Ok(Self::Four),
            _ => Err(SettingsError::InvalidMangoHudPreset),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MangoHudLimiterMethod {
    Early,
    #[default]
    Late,
}

impl FromStr for MangoHudLimiterMethod {
    type Err = SettingsError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "early" => Ok(Self::Early),
            "late" => Ok(Self::Late),
            _ => Err(SettingsError::InvalidMangoHudLimiterMethod),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FrameGenerationProvider {
    #[default]
    None,
    LosslessScaling,
    GameProvided,
    NvidiaSmoothMotion,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalSettings {
    pub enable: bool,
    pub provider: FrameLimiterProvider,
    pub fps_limit: FpsLimit,
    pub disable_vsync: bool,
    pub auto_virtual_framegen: AutoVirtualFramegenMode,
    pub rtss_frame_limit_type: RtssFrameLimitType,
    pub rtss_install_path: String,
    pub rtss_allow_virtual_display_override: bool,
    pub mangohud_preset: MangoHudPreset,
    pub mangohud_always_show_graph: bool,
    pub mangohud_limiter_method: MangoHudLimiterMethod,
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            enable: false,
            provider: FrameLimiterProvider::Auto,
            fps_limit: FpsLimit::FOLLOW_STREAM,
            disable_vsync: false,
            auto_virtual_framegen: AutoVirtualFramegenMode::Enabled,
            rtss_frame_limit_type: RtssFrameLimitType::Async,
            rtss_install_path: String::new(),
            rtss_allow_virtual_display_override: false,
            mangohud_preset: MangoHudPreset::Custom,
            mangohud_always_show_graph: false,
            mangohud_limiter_method: MangoHudLimiterMethod::Late,
        }
    }
}

impl GlobalSettings {
    /// Parses canonical setting keys and folds the legacy VSync key into its canonical field.
    /// When both keys are present, the reference parser's later legacy parse takes precedence.
    pub fn from_json(mut value: Value) -> Result<ParsedGlobalSettings, SettingsError> {
        let object = value
            .as_object_mut()
            .ok_or(SettingsError::InvalidDocument)?;
        if let Some(legacy_value) = object.remove("rtss_disable_vsync_ullm") {
            object.insert("frame_limiter_disable_vsync".into(), legacy_value);
        }

        let wire: WireGlobalSettings =
            serde_json::from_value(value).map_err(|_| SettingsError::InvalidDocument)?;
        let mut diagnostics = Vec::new();
        let mut settings = Self::default();

        if let Some(enable) = wire.frame_limiter_enable {
            settings.enable = enable;
        }
        if let Some(provider) = wire.frame_limiter_provider {
            settings.provider = match FrameLimiterProvider::from_str(&provider) {
                Ok(provider) => provider,
                Err(_) => {
                    diagnostics.push(SettingsDiagnostic::UnknownProviderUsesAuto);
                    FrameLimiterProvider::Auto
                }
            };
        }
        if let Some(fps_limit) = wire.frame_limiter_fps_limit {
            settings.fps_limit = parse_fps_limit_value(&fps_limit)?;
        }
        if let Some(disable_vsync) = wire.frame_limiter_disable_vsync {
            settings.disable_vsync = disable_vsync;
        }
        if let Some(auto_virtual_framegen) = wire.frame_limiter_auto_virtual_framegen {
            settings.auto_virtual_framegen = AutoVirtualFramegenMode::parse(&auto_virtual_framegen)
                .unwrap_or_else(|| {
                    diagnostics.push(SettingsDiagnostic::UnknownVirtualFramegenUsesEnabled);
                    AutoVirtualFramegenMode::Enabled
                });
        }
        if let Some(rtss_frame_limit_type) = wire.rtss_frame_limit_type {
            settings.rtss_frame_limit_type = RtssFrameLimitType::from_str(&rtss_frame_limit_type)?;
        }
        if let Some(rtss_install_path) = wire.rtss_install_path {
            settings.rtss_install_path = rtss_install_path;
        }
        if let Some(allow_override) = wire.rtss_allow_virtual_display_override {
            settings.rtss_allow_virtual_display_override = allow_override;
        }
        if let Some(preset) = wire.mangohud_preset {
            settings.mangohud_preset = MangoHudPreset::from_str(&preset).unwrap_or_else(|_| {
                diagnostics.push(SettingsDiagnostic::UnknownMangoHudPresetUsesCustom);
                MangoHudPreset::Custom
            });
        }
        if let Some(always_show_graph) = wire.mangohud_always_show_graph {
            settings.mangohud_always_show_graph = always_show_graph;
        }
        if let Some(limiter_method) = wire.mangohud_limiter_method {
            settings.mangohud_limiter_method = MangoHudLimiterMethod::from_str(&limiter_method)
                .unwrap_or_else(|_| {
                    diagnostics.push(SettingsDiagnostic::UnknownMangoHudLimiterMethodUsesLate);
                    MangoHudLimiterMethod::Late
                });
        }

        Ok(ParsedGlobalSettings {
            settings,
            diagnostics,
        })
    }

    pub fn validate(&self, platform: Platform) -> Result<(), SettingsError> {
        let path = &self.rtss_install_path;
        let invalid_path = path.chars().any(char::is_control)
            || (!path.is_empty() && !is_valid_install_path(path, platform));
        if invalid_path {
            return Err(SettingsError::InvalidRtssInstallPath);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedGlobalSettings {
    pub settings: GlobalSettings,
    pub diagnostics: Vec<SettingsDiagnostic>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsDiagnostic {
    UnknownProviderUsesAuto,
    UnknownVirtualFramegenUsesEnabled,
    UnknownMangoHudPresetUsesCustom,
    UnknownMangoHudLimiterMethodUsesLate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsError {
    InvalidDocument,
    InvalidFpsLimit,
    InvalidProvider,
    InvalidRtssFrameLimitType,
    InvalidMangoHudPreset,
    InvalidMangoHudLimiterMethod,
    InvalidRtssInstallPath,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameLimiterOverrides {
    pub enable: Option<bool>,
    pub provider: Option<FrameLimiterProvider>,
    pub fps_limit: Option<FpsLimit>,
    pub auto_virtual_framegen: Option<AutoVirtualFramegenMode>,
    pub disable_vsync: Option<bool>,
    pub rtss_frame_limit_type: Option<RtssFrameLimitType>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveSettings {
    pub enable: bool,
    pub provider: FrameLimiterProvider,
    pub fps_limit: FpsLimit,
    pub disable_vsync: bool,
    pub auto_virtual_framegen: AutoVirtualFramegenMode,
    pub rtss_frame_limit_type: RtssFrameLimitType,
    pub rtss_install_path: String,
    pub rtss_allow_virtual_display_override: bool,
    pub mangohud_preset: MangoHudPreset,
    pub mangohud_always_show_graph: bool,
    pub mangohud_limiter_method: MangoHudLimiterMethod,
}

impl From<&GlobalSettings> for EffectiveSettings {
    fn from(settings: &GlobalSettings) -> Self {
        Self {
            enable: settings.enable,
            provider: settings.provider,
            fps_limit: settings.fps_limit,
            disable_vsync: settings.disable_vsync,
            auto_virtual_framegen: settings.auto_virtual_framegen,
            rtss_frame_limit_type: settings.rtss_frame_limit_type,
            rtss_install_path: settings.rtss_install_path.clone(),
            rtss_allow_virtual_display_override: settings.rtss_allow_virtual_display_override,
            mangohud_preset: settings.mangohud_preset,
            mangohud_always_show_graph: settings.mangohud_always_show_graph,
            mangohud_limiter_method: settings.mangohud_limiter_method,
        }
    }
}

impl EffectiveSettings {
    pub fn resolve(
        global: &GlobalSettings,
        application: &FrameLimiterOverrides,
        client: &FrameLimiterOverrides,
    ) -> Self {
        let mut resolved = Self::from(global);
        resolved.enable = client
            .enable
            .or(application.enable)
            .unwrap_or(global.enable);
        resolved.provider = client
            .provider
            .or(application.provider)
            .unwrap_or(global.provider);
        resolved.fps_limit = client
            .fps_limit
            .or(application.fps_limit)
            .unwrap_or(global.fps_limit);
        resolved.auto_virtual_framegen = client
            .auto_virtual_framegen
            .or(application.auto_virtual_framegen)
            .unwrap_or(global.auto_virtual_framegen);
        resolved.disable_vsync = client
            .disable_vsync
            .or(application.disable_vsync)
            .unwrap_or(global.disable_vsync);
        resolved.rtss_frame_limit_type = client
            .rtss_frame_limit_type
            .or(application.rtss_frame_limit_type)
            .unwrap_or(global.rtss_frame_limit_type);
        resolved
    }
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct WireGlobalSettings {
    frame_limiter_enable: Option<bool>,
    frame_limiter_provider: Option<String>,
    frame_limiter_fps_limit: Option<Value>,
    frame_limiter_disable_vsync: Option<bool>,
    frame_limiter_auto_virtual_framegen: Option<String>,
    rtss_frame_limit_type: Option<String>,
    rtss_install_path: Option<String>,
    rtss_allow_virtual_display_override: Option<bool>,
    mangohud_preset: Option<String>,
    mangohud_always_show_graph: Option<bool>,
    mangohud_limiter_method: Option<String>,
}

fn parse_fps_limit_value(value: &Value) -> Result<FpsLimit, SettingsError> {
    let Value::Number(number) = value else {
        return Err(SettingsError::InvalidFpsLimit);
    };
    parse_fps_limit_number(number)
}

fn parse_fps_limit_number(value: &Number) -> Result<FpsLimit, SettingsError> {
    FpsLimit::parse_hz(&value.to_string())
}

fn normalize_token(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_valid_install_path(value: &str, platform: Platform) -> bool {
    match platform {
        Platform::Windows => {
            is_absolute_windows_path(value) || is_relative_windows_install_path(value)
        }
        Platform::Linux | Platform::Macos => false,
    }
}

fn is_relative_windows_install_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    let starts_at_root = matches!(bytes.first().copied(), Some(b'\\' | b'/'));
    let has_drive_prefix = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    !starts_at_root && !has_drive_prefix
}

pub(crate) fn is_absolute_windows_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    let has_drive_root = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    let has_unc_root = value.starts_with("\\\\") || value.starts_with("//");
    has_drive_root
        || (has_unc_root
            && value[2..]
                .split(['\\', '/'])
                .filter(|part| !part.is_empty())
                .count()
                >= 2)
}
