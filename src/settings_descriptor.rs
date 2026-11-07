//! Plugin-owned settings metadata for the generic extension registry.
use crate::{GlobalSettings, Platform};
use amaterasu_configuration_schema::{Definition, Fields, Values};
use amaterasu_module_sdk::extension_api::{
    ApplyPolicy, ExtensionDescriptor, MethodRef, OptionDescriptor, SettingScope,
};

pub const PROVIDER: &str = "amaterasu.frame-limiter";
/// Typed extension methods are separate from the legacy lease service.
pub const SERVICE: &str = "nonary.frame-limiter/1";
pub(crate) const WINDOWS_CAPABILITY: &str = "nonary.frame-limiter.windows";

/// Packaging tools consume the same metadata shipped by the module. No host
/// consumer needs a Rust dependency on the frame-limiter implementation.
pub fn installation_metadata(platform: Platform) -> serde_json::Value {
    let methods: Vec<_> = std::iter::once(crate::extension::settings_registration())
        .chain(crate::lifecycle::registrations())
        .map(|command| match command {
            amaterasu_module_sdk::Command::RegisterApi { method } => method,
            _ => unreachable!("only API registrations are metadata"),
        })
        .collect();
    serde_json::json!({"descriptor":descriptor(platform),"methods":methods})
}

fn choices(default: &str, choices: &[&str]) -> Definition {
    Definition::Enum {
        default: default.into(),
        options: choices.iter().map(|choice| (*choice).into()).collect(),
    }
}

/// The platform's explicit choices; unsupported choices are never silently
/// rewritten by the editor or sent to a different backend.
pub fn definitions(platform: Platform) -> Fields {
    let providers: &[&str] = match platform {
        Platform::Linux => &["auto", "mangohud", "proton", "mangohud-proton", "none"],
        Platform::Windows => &["auto", "rtss", "nvidia-control-panel", "none"],
        Platform::Macos => &["auto", "none"],
    };
    let mut fields: Fields = [
        (
            "frame_limiter_enable",
            Definition::Boolean { default: false },
        ),
        ("frame_limiter_provider", choices("auto", providers)),
        (
            "frame_limiter_fps_limit",
            Definition::Decimal {
                default: 0.0,
                minimum: Some(0.0),
                maximum: Some(1000.0),
            },
        ),
        (
            "frame_limiter_disable_vsync",
            Definition::Boolean { default: false },
        ),
        (
            "frame_limiter_auto_virtual_framegen",
            choices("enabled", &["enabled", "vrr", "legacy", "disabled"]),
        ),
    ]
    .into_iter()
    .map(|(name, definition)| (name.into(), definition))
    .collect();
    match platform {
        Platform::Windows => fields.extend([
            (
                "rtss_frame_limit_type".into(),
                choices(
                    "async",
                    &[
                        "async",
                        "front edge sync",
                        "back edge sync",
                        "nvidia reflex",
                    ],
                ),
            ),
            (
                "rtss_install_path".into(),
                Definition::String {
                    default: String::new(),
                    min_length: Some(0),
                    max_length: Some(1024),
                },
            ),
            (
                "rtss_allow_virtual_display_override".into(),
                Definition::Boolean { default: false },
            ),
        ]),
        Platform::Linux => fields.extend([
            (
                "mangohud_preset".into(),
                choices("custom", &["custom", "1", "2", "3", "4"]),
            ),
            (
                "mangohud_always_show_graph".into(),
                Definition::Boolean { default: false },
            ),
            (
                "mangohud_limiter_method".into(),
                choices("late", &["early", "late"]),
            ),
        ]),
        Platform::Macos => (),
    }
    fields
}

pub fn validate(platform: Platform, values: &Values) -> Result<(), String> {
    let fields = definitions(platform);
    if values.len() != fields.len() || fields.keys().any(|name| !values.contains_key(name)) {
        return Err("incomplete_settings".into());
    }
    amaterasu_configuration_schema::validate_values(&fields, values)?;
    let document = serde_json::to_value(values).map_err(|_| "invalid_settings")?;
    let parsed = GlobalSettings::from_json(document).map_err(|_| "invalid_settings")?;
    parsed
        .settings
        .validate(platform)
        .map_err(|_| "invalid_settings")?;
    Ok(())
}

pub fn descriptor(platform: Platform) -> ExtensionDescriptor {
    let scoped = [
        "frame_limiter_enable",
        "frame_limiter_provider",
        "frame_limiter_fps_limit",
        "frame_limiter_disable_vsync",
        "frame_limiter_auto_virtual_framegen",
        "rtss_frame_limit_type",
    ];
    let field_order = [
        "frame_limiter_enable",
        "frame_limiter_provider",
        "frame_limiter_fps_limit",
        "mangohud_preset",
        "mangohud_always_show_graph",
        "mangohud_limiter_method",
        "rtss_frame_limit_type",
        "rtss_install_path",
        "rtss_allow_virtual_display_override",
        "frame_limiter_auto_virtual_framegen",
        "frame_limiter_disable_vsync",
    ];
    let fields = definitions(platform);
    let options = field_order.into_iter().filter_map(|id| fields.get(id).map(|definition| (id.to_owned(), definition.clone()))).map(|(id, definition)| {
        let allowed_scopes = if scoped.contains(&id.as_str()) {
            vec![SettingScope::Host, SettingScope::Application, SettingScope::PairedClient, SettingScope::Session]
        } else { vec![SettingScope::Host] };
        OptionDescriptor {
            label: match id.as_str() {
                "frame_limiter_enable" => "Enable frame limiting",
                "frame_limiter_provider" => "Limiter",
                "frame_limiter_fps_limit" => "Frame rate limit (FPS)",
                "mangohud_preset" => "MangoHUD appearance",
                "mangohud_always_show_graph" => "Show frame-time graph",
                "mangohud_limiter_method" => "MangoHUD timing",
                "frame_limiter_auto_virtual_framegen" => "Automatic frame-generation limiting",
                "frame_limiter_disable_vsync" => "Disable VSync",
                "rtss_frame_limit_type" => "RTSS timing",
                "rtss_install_path" => "RTSS installation folder",
                "rtss_allow_virtual_display_override" => "Override RTSS timing for virtual displays",
                _ => unreachable!("known limiter option"),
            }.into(),
            help: match id.as_str() {
                "frame_limiter_enable" => "Limit games launched during a streaming session. Start a new application session after saving.",
                "frame_limiter_provider" => "Automatic uses Proton for limiting and MangoHUD for the overlay when available.",
                "frame_limiter_fps_limit" => "Use 0 to follow the client display or stream rate. For example: 60 or 59.94.",
                "mangohud_preset" => "Use your existing MangoHUD configuration, or choose a built-in overlay preset.",
                "mangohud_always_show_graph" => "Show the frame-time graph in the MangoHUD overlay.",
                "mangohud_limiter_method" => "Early favors smooth pacing; late favors lower input latency. Used when MangoHUD limits the game.",
                "frame_limiter_auto_virtual_framegen" => "Apply frame limiting automatically when supported frame generation is configured.",
                "frame_limiter_disable_vsync" if platform == Platform::Linux => "MangoHUD and Proton cannot change VSync. Leave this off and configure VSync in the game.",
                "frame_limiter_disable_vsync" => "Turn off driver VSync while streaming, then restore it afterward.",
                "rtss_frame_limit_type" => "Choose how RTSS paces frames.",
                "rtss_install_path" => "Leave blank to find the installed RTSS copy automatically.",
                "rtss_allow_virtual_display_override" => "Allow automatic timing selection for virtual displays.",
                _ => unreachable!("known limiter option"),
            }.into(),
            choice_labels: match id.as_str() {
                "frame_limiter_provider" => [("auto","Automatic"),("mangohud","MangoHUD"),("proton","Proton"),("mangohud-proton","Proton + MangoHUD"),("rtss","RTSS"),("nvidia-control-panel","NVIDIA driver"),("none","Disabled")].as_slice(),
                "mangohud_preset" => [("custom","My MangoHUD configuration"),("1","Preset 1"),("2","Preset 2"),("3","Preset 3"),("4","Preset 4")].as_slice(),
                "mangohud_limiter_method" => [("early","Smooth pacing (early)"),("late","Lower latency (late)")].as_slice(),
                "frame_limiter_auto_virtual_framegen" => [("enabled","Enabled"),("vrr","Variable refresh rate"),("legacy","Legacy mode"),("disabled","Disabled")].as_slice(),
                _ => [].as_slice(),
            }.iter().filter(|(value,_)| matches!(&definition, Definition::Enum { options, .. } if options.iter().any(|option| option == value))).map(|(value,label)| ((*value).into(),(*label).into())).collect(),
            presentation: (id == "frame_limiter_fps_limit").then_some(amaterasu_module_sdk::extension_api::OptionPresentation::Slider),
            id, definition, allowed_scopes,
            apply_policy: ApplyPolicy::NextStream, required_capabilities: vec![],
        }
    }).collect();
    ExtensionDescriptor {
        provider: PROVIDER.into(),
        display_name: Some("Frame limiting".into()),
        default_expanded: false,
        revision: 1,
        options,
        actions: vec![],
        capabilities: match platform {
            Platform::Linux => {
                vec![
                    amaterasu_module_sdk::extension_api::LAUNCH_ENVIRONMENT_CAPABILITY.into(),
                    amaterasu_module_sdk::extension_api::STREAM_JOIN_CAPABILITY.into(),
                ]
            }
            Platform::Windows => vec![
                WINDOWS_CAPABILITY.into(),
                amaterasu_module_sdk::extension_api::STREAM_JOIN_CAPABILITY.into(),
            ],
            Platform::Macos => {
                vec![amaterasu_module_sdk::extension_api::STREAM_JOIN_CAPABILITY.into()]
            }
        },
        settings_validate: MethodRef {
            service: SERVICE.into(),
            method: "settings_validate".into(),
            interface_major: 1,
            interface_minor: 0,
            schema_revision: 1,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn descriptors_and_default_settings_are_valid_on_all_platforms() {
        for platform in [Platform::Linux, Platform::Windows, Platform::Macos] {
            let description = descriptor(platform);
            amaterasu_module_sdk::extension_api::validate_descriptor(&description).unwrap();
            assert_eq!(description.display_name.as_deref(), Some("Frame limiting"));
            assert_eq!(description.options[0].id, "frame_limiter_enable");
            assert_eq!(description.options[1].choice_labels["auto"], "Automatic");
            let values = amaterasu_configuration_schema::defaults(&definitions(platform)).unwrap();
            validate(platform, &values).unwrap();
        }
        assert!(definitions(Platform::Linux).contains_key("mangohud_preset"));
        assert!(!definitions(Platform::Linux).contains_key("rtss_install_path"));
        assert!(definitions(Platform::Windows).contains_key("rtss_install_path"));
        assert!(!definitions(Platform::Windows).contains_key("mangohud_preset"));
    }

    #[test]
    fn packaged_metadata_matches_plugin_registrations() {
        for (platform, document) in [
            (Platform::Linux, include_str!("../metadata/linux.json")),
            (Platform::Windows, include_str!("../metadata/windows.json")),
            (Platform::Macos, include_str!("../metadata/macos.json")),
        ] {
            let packaged: serde_json::Value = serde_json::from_str(document).unwrap();
            assert_eq!(packaged, installation_metadata(platform));
        }
    }

    #[test]
    fn exact_fractional_rate_and_platform_provider_are_validated() {
        let mut values =
            amaterasu_configuration_schema::defaults(&definitions(Platform::Linux)).unwrap();
        values.insert("frame_limiter_fps_limit".into(), json!(59.94));
        values.insert("frame_limiter_provider".into(), json!("mangohud-proton"));
        assert!(validate(Platform::Linux, &values).is_ok());
        values.insert("frame_limiter_fps_limit".into(), json!(59.9401));
        assert!(validate(Platform::Linux, &values).is_err());
        values.insert("frame_limiter_fps_limit".into(), json!(60));
        values.insert("frame_limiter_provider".into(), json!("rtss"));
        assert!(validate(Platform::Linux, &values).is_err());
    }
}
