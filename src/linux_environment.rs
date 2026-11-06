//! Launch data produced by the Linux plugin; consumers only see the SDK schema.
use amaterasu_module_sdk::extension_api::{
    self as api, EnvironmentExtension, LaunchEnvironmentContribution,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

const SHIM: &str = "/usr/$LIB/mangohud/libMangoHud_shim.so";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    app_id: Option<String>,
    provider: String,
    limit_millihz: u32,
    preset: String,
    method: String,
    graph: bool,
}

pub(crate) fn contribution(policy: &Value) -> Result<LaunchEnvironmentContribution, &'static str> {
    let policy: Policy = serde_json::from_value(policy.clone()).map_err(|_| "invalid_policy")?;
    if !matches!(
        policy.provider.as_str(),
        "proton" | "mangohud" | "mangohud-proton"
    ) || !(1..=1_000_000).contains(&policy.limit_millihz)
        || !matches!(policy.preset.as_str(), "custom" | "1" | "2" | "3" | "4")
        || !matches!(policy.method.as_str(), "early" | "late")
        || policy.app_id.as_ref().is_some_and(|id| {
            id.is_empty() || id.len() > 10 || !id.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err("invalid_policy");
    }
    let rate = if policy.limit_millihz.is_multiple_of(1000) {
        (policy.limit_millihz / 1000).to_string()
    } else {
        format!(
            "{}.{:03}",
            policy.limit_millihz / 1000,
            policy.limit_millihz % 1000
        )
        .trim_end_matches('0')
        .to_owned()
    };
    let mut edits = BTreeMap::new();
    let mut extensions = BTreeMap::new();
    if policy.provider != "mangohud" {
        let whole_rate = ((policy.limit_millihz + 500) / 1000).to_string();
        edits.insert("DXVK_FRAME_RATE".into(), Some(whole_rate.clone()));
        edits.insert("VKD3D_FRAME_RATE".into(), Some(rate.clone()));
        extensions.insert(
            "DXVK_CONFIG".into(),
            EnvironmentExtension {
                separator: ';',
                prefix: vec![],
                suffix: [
                    "dxvk.maxFrameRate",
                    "dxgi.maxFrameRate",
                    "d3d9.maxFrameRate",
                ]
                .into_iter()
                .map(|key| format!("{key} = {whole_rate}"))
                .collect(),
                remove: vec![],
                deduplicate: false,
            },
        );
    }
    let overlay = policy.provider != "proton";
    if overlay {
        edits.insert("MANGOHUD".into(), Some("1".into()));
        let mut suffix = vec![];
        if policy.preset != "custom" {
            suffix.push(format!("preset={}", policy.preset));
        }
        if policy.provider == "mangohud-proton" || policy.preset != "custom" || policy.graph {
            suffix.push("no_display=0".into());
        }
        if policy.graph {
            suffix.push("frame_timing=1".into());
        }
        suffix.push(format!("fps_limit_method={}", policy.method));
        suffix.push(format!(
            "fps_limit={}",
            if policy.provider == "mangohud" {
                &rate
            } else {
                "0"
            }
        ));
        extensions.insert(
            "MANGOHUD_CONFIG".into(),
            EnvironmentExtension {
                separator: ',',
                prefix: vec!["read_cfg".into()],
                suffix,
                remove: vec![],
                deduplicate: false,
            },
        );
    } else {
        edits.insert("MANGOHUD".into(), None);
        edits.insert("MANGOHUD_CONFIG".into(), None);
    }
    edits.insert(
        "MANGOHUD_FPS_LIMIT".into(),
        if policy.provider == "mangohud" && policy.limit_millihz.is_multiple_of(1000) {
            Some(rate)
        } else {
            None
        },
    );
    extensions.insert(
        "LD_PRELOAD".into(),
        EnvironmentExtension {
            separator: ':',
            prefix: vec![],
            suffix: if overlay { vec![SHIM.into()] } else { vec![] },
            remove: if overlay { vec![] } else { vec![SHIM.into()] },
            deduplicate: true,
        },
    );
    let result = LaunchEnvironmentContribution { edits, extensions };
    api::merge_launch_environment(&BTreeMap::new(), std::slice::from_ref(&result))
        .map_err(|_| "invalid_environment")?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn native_launch_preserves_inherited_configuration_and_exact_fractional_cap() {
        let policy = json!({"app_id":null,"provider":"mangohud","limit_millihz":59940,"preset":"3","method":"early","graph":true});
        let base = BTreeMap::from([
            ("LD_PRELOAD".into(), "/other.so".into()),
            ("MANGOHUD_CONFIG".into(), "gpu_stats,fps_limit=120".into()),
            ("MANGOHUD_FPS_LIMIT".into(), "120".into()),
        ]);
        let result =
            api::merge_launch_environment(&base, &[contribution(&policy).unwrap()]).unwrap();
        assert_eq!(result["LD_PRELOAD"], format!("/other.so:{SHIM}"));
        assert_eq!(
            result["MANGOHUD_CONFIG"],
            "read_cfg,gpu_stats,fps_limit=120,preset=3,no_display=0,frame_timing=1,fps_limit_method=early,fps_limit=59.94"
        );
        assert!(!result.contains_key("MANGOHUD_FPS_LIMIT"));
        assert!(!result.contains_key("DXVK_FRAME_RATE"));
    }

    #[test]
    fn proton_keeps_unrelated_preloads_and_appends_renderer_caps_after_user_config() {
        let policy = json!({"app_id":null,"provider":"proton","limit_millihz":59940,"preset":"custom","method":"late","graph":false});
        let base = BTreeMap::from([
            ("LD_PRELOAD".into(), format!("/other.so:{SHIM}")),
            ("DXVK_CONFIG".into(), "dxvk.hud = fps".into()),
            ("MANGOHUD".into(), "1".into()),
        ]);
        let result =
            api::merge_launch_environment(&base, &[contribution(&policy).unwrap()]).unwrap();
        assert_eq!(result["LD_PRELOAD"], "/other.so");
        assert_eq!(result["DXVK_FRAME_RATE"], "60");
        assert_eq!(result["VKD3D_FRAME_RATE"], "59.94");
        assert!(result["DXVK_CONFIG"].starts_with("dxvk.hud = fps;dxvk.maxFrameRate = 60;"));
        assert!(!result.contains_key("MANGOHUD"));
    }
}
