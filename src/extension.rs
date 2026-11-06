//! Typed settings validation for the selected extension registry.
use amaterasu_module_sdk::{
    ApiFieldKind, ApiMethod, ApiPrivilege, ApiSchema, Command, ModuleResult,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(crate) fn registry_principal(settings: &Value) -> ModuleResult<Option<String>> {
    let Some(value) = settings.get("extension_registry_principal") else {
        return Ok(None);
    };
    let principal = value
        .as_str()
        .filter(|principal| {
            !principal.is_empty()
                && principal.len() <= 128
                && principal.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
        .ok_or("invalid extension registry principal")?;
    Ok(Some(principal.into()))
}

pub(crate) fn settings_registration() -> Command {
    Command::RegisterApi {
        method: ApiMethod {
            service: crate::settings_descriptor::SERVICE.into(),
            method: "settings_validate".into(),
            interface_major: 1,
            interface_minor: 0,
            request: ApiSchema {
                required: BTreeMap::from([("values".into(), ApiFieldKind::Object)]),
                optional: BTreeMap::new(),
                allow_extra: false,
            },
            response: ApiSchema {
                required: BTreeMap::from([
                    ("ok".into(), ApiFieldKind::Boolean),
                    ("valid".into(), ApiFieldKind::Boolean),
                ]),
                optional: BTreeMap::from([("message".into(), ApiFieldKind::String)]),
                allow_extra: false,
            },
            privilege: ApiPrivilege::User,
        },
    }
}

pub(crate) fn handle_settings(
    caller: &str,
    selected_registry: Option<&str>,
    payload: Value,
) -> Value {
    if selected_registry != Some(caller) {
        return json!({"ok":true,"valid":false,"message":"unauthorized caller"});
    }
    let Some(envelope) = payload.as_object().filter(|object| object.len() == 4) else {
        return json!({"ok":true,"valid":false,"message":"invalid request"});
    };
    if envelope.get("method") != Some(&json!("settings_validate"))
        || envelope.get("interface_major") != Some(&json!(1))
        || envelope.get("interface_minor") != Some(&json!(0))
    {
        return json!({"ok":true,"valid":false,"message":"invalid request"});
    }
    let Some(values) = envelope
        .get("arguments")
        .and_then(Value::as_object)
        .filter(|arguments| arguments.len() == 1)
        .and_then(|arguments| arguments.get("values"))
        .and_then(|values| serde_json::from_value(values.clone()).ok())
    else {
        return json!({"ok":true,"valid":false,"message":"invalid settings"});
    };
    let platform = if cfg!(target_os = "linux") {
        crate::Platform::Linux
    } else if cfg!(target_os = "windows") {
        crate::Platform::Windows
    } else {
        crate::Platform::Macos
    };
    match crate::settings_descriptor::validate(platform, &values) {
        Ok(()) => json!({"ok":true,"valid":true}),
        Err(_) => json!({"ok":true,"valid":false,"message":"invalid settings"}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_registry_alone_can_validate_its_complete_settings() {
        let platform = if cfg!(target_os = "linux") {
            crate::Platform::Linux
        } else if cfg!(target_os = "windows") {
            crate::Platform::Windows
        } else {
            crate::Platform::Macos
        };
        let values = amaterasu_configuration_schema::defaults(
            &crate::settings_descriptor::definitions(platform),
        )
        .unwrap();
        let request = json!({"method":"settings_validate","interface_major":1,"interface_minor":0,"arguments":{"values":values}});
        assert_eq!(
            handle_settings("custom.registry", Some("custom.registry"), request.clone())["valid"],
            true
        );
        assert_eq!(
            handle_settings("other.registry", Some("custom.registry"), request.clone())["valid"],
            false
        );
        assert_eq!(
            handle_settings("custom.registry", None, request)["valid"],
            false
        );
    }
}
