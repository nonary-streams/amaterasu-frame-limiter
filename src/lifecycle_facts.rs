//! Plugin-owned interpretation of opaque application and client properties.
use crate::{FpsLimit, FrameGenerationProvider, Platform, PolicyContext};
use amaterasu_module_sdk::extension_api::ProviderContext;
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Default, Deserialize)]
struct SettingsFacts {
    frame_generation_mode: Option<String>,
    frame_generation_provider: Option<String>,
    lossless_scaling_framegen: Option<bool>,
    lossless_scaling_target_fps: Option<u32>,
}

impl SettingsFacts {
    fn mode(&self) -> Result<FrameGenerationProvider, &'static str> {
        let selected = self
            .frame_generation_mode
            .as_deref()
            .or(self.frame_generation_provider.as_deref());
        match selected {
            Some("off" | "none") => Ok(FrameGenerationProvider::None),
            Some("game-provided") => Ok(FrameGenerationProvider::GameProvided),
            Some("nvidia-smooth-motion") => Ok(FrameGenerationProvider::NvidiaSmoothMotion),
            Some("lossless-scaling")
                if self.frame_generation_mode.is_some()
                    || self.lossless_scaling_framegen == Some(true) =>
            {
                Ok(FrameGenerationProvider::LosslessScaling)
            }
            Some("lossless-scaling") => Ok(FrameGenerationProvider::None),
            None if self.lossless_scaling_framegen == Some(true) => {
                Ok(FrameGenerationProvider::LosslessScaling)
            }
            None => Ok(FrameGenerationProvider::None),
            _ => Err("invalid_frame_generation_context"),
        }
    }
}

fn overlay(target: &mut Map<String, Value>, source: Option<&Value>) -> Result<(), &'static str> {
    match source {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Object(values)) => {
            target.extend(
                values
                    .iter()
                    .filter(|(_, value)| !value.is_null())
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
            Ok(())
        }
        Some(_) => Err("invalid_application_context"),
    }
}

pub(crate) fn resolve(
    context: &ProviderContext,
    platform: Platform,
) -> Result<PolicyContext, &'static str> {
    let mut values = Map::new();
    overlay(&mut values, context.application.get("properties"))?;
    overlay(
        &mut values,
        context
            .client
            .as_ref()
            .and_then(|client| client.properties.as_ref()),
    )?;
    let facts: SettingsFacts = serde_json::from_value(Value::Object(values))
        .map_err(|_| "invalid_frame_generation_context")?;
    let mode = facts.mode()?;
    let rate = |value| FpsLimit::from_millihz(value).map_err(|_| "invalid_rate");
    let requested = context
        .requested_video
        .as_ref()
        .map(|video| rate(video.refresh_millihz))
        .transpose()?;
    let lossless_scaling_limit = if mode == FrameGenerationProvider::LosslessScaling {
        match facts.lossless_scaling_target_fps {
            Some(value @ 1..=1000) => Some(rate(value * 1000)?),
            Some(_) => return Err("invalid_lossless_scaling_target"),
            None => requested,
        }
    } else {
        None
    };
    Ok(PolicyContext {
        platform,
        frame_generation_provider: mode,
        lossless_scaling_limit,
        requested_stream_fps: requested,
        client_display_mode_rate: context
            .client
            .as_ref()
            .and_then(|client| client.display_mode.as_ref())
            .map(|mode| rate(mode.refresh_millihz))
            .transpose()?,
        // Display ownership, GPU discovery, and scoped setting provenance must
        // come from their respective providers; configuration is not evidence.
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use amaterasu_module_sdk::extension_api::{
        ClientContext, ClientDisplayMode, LifecycleTarget, VideoMode,
    };
    use serde_json::json;

    pub(super) fn context(properties: Value) -> ProviderContext {
        ProviderContext {
            target: LifecycleTarget::Session {
                host_epoch: "epoch".into(),
                session_id: "session".into(),
                generation: 1,
            },
            application: json!({"kind":"application","properties":properties}),
            client: Some(ClientContext {
                client_ref: Some("client".into()),
                properties: None,
                display_mode: Some(ClientDisplayMode {
                    width: 1920,
                    height: 1080,
                    refresh_millihz: 59940,
                }),
            }),
            requested_video: Some(VideoMode {
                width: 1920,
                height: 1080,
                refresh_millihz: 120000,
                hdr: false,
            }),
        }
    }

    #[test]
    fn lossless_scaling_uses_its_target_then_stream_with_client_overrides() {
        let mut source =
            context(json!({"lossless_scaling_framegen":true,"lossless_scaling_target_fps":90}));
        let facts = resolve(&source, Platform::Windows).unwrap();
        assert_eq!(facts.lossless_scaling_limit.unwrap().millihz(), 90000);
        source.client.as_mut().unwrap().properties =
            Some(json!({"lossless_scaling_target_fps":144}));
        assert_eq!(
            resolve(&source, Platform::Windows)
                .unwrap()
                .lossless_scaling_limit
                .unwrap()
                .millihz(),
            144000
        );
        source.application["properties"]
            .as_object_mut()
            .unwrap()
            .remove("lossless_scaling_target_fps");
        source.client.as_mut().unwrap().properties = None;
        assert_eq!(
            resolve(&source, Platform::Linux)
                .unwrap()
                .lossless_scaling_limit
                .unwrap()
                .millihz(),
            120000
        );
    }

    #[test]
    fn explicit_mode_and_disable_survive_sparse_client_values() {
        let mut source = context(json!({"lossless_scaling_framegen":true}));
        source.client.as_mut().unwrap().properties =
            Some(json!({"lossless_scaling_framegen":false}));
        assert_eq!(
            resolve(&source, Platform::Linux)
                .unwrap()
                .frame_generation_provider,
            FrameGenerationProvider::None
        );
        source.application["properties"]["frame_generation_mode"] = json!("game-provided");
        assert_eq!(
            resolve(&source, Platform::Windows)
                .unwrap()
                .frame_generation_provider,
            FrameGenerationProvider::GameProvided
        );
        source.client.as_mut().unwrap().properties = Some(json!({"frame_generation_mode":"off"}));
        assert_eq!(
            resolve(&source, Platform::Windows)
                .unwrap()
                .frame_generation_provider,
            FrameGenerationProvider::None
        );
        source.client.as_mut().unwrap().properties =
            Some(json!({"frame_generation_mode":"unknown"}));
        assert_eq!(
            resolve(&source, Platform::Windows),
            Err("invalid_frame_generation_context")
        );
    }
}
