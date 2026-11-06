//! Generic lifecycle participant admission and bounded context reads.
//!
//! The selected coordinator is trusted startup composition. Context requests
//! are read-only, asynchronous, and must settle before a participant response.
use amaterasu_module_sdk::{
    ApiFieldKind as Kind, ApiMethod, ApiPrivilege, ApiSchema, Command, ModuleResult, Response,
    RuntimeClient,
    extension_api::{
        self, LifecyclePhase, ProviderContextResponse, ProviderOperation, ProviderRequest,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

const MAX_PENDING: usize = 32;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    principal: String,
    service: String,
}

pub(crate) fn selection(settings: &Value) -> ModuleResult<Option<Selection>> {
    let Some(value) = settings.get("lifecycle_coordinator") else {
        return Ok(None);
    };
    let selected: Selection =
        serde_json::from_value(value.clone()).map_err(|_| "invalid lifecycle coordinator")?;
    let valid = |value: &str| {
        !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-' | b'/')
            })
    };
    if !valid(&selected.principal) || !valid(&selected.service) {
        return Err("invalid lifecycle coordinator".into());
    }
    Ok(Some(selected))
}

pub(crate) fn registrations() -> Vec<Command> {
    ["resource_plan", "lifecycle_callback", "lifecycle_status"]
        .into_iter()
        .map(|method| {
            let request = if method == "lifecycle_status" {
                schema(
                    &[
                        ("provider_sequence", Kind::Integer),
                        ("operation_id", Kind::String),
                        ("transition_id", Kind::String),
                        ("receipt_id", Kind::String),
                    ],
                    &[],
                )
            } else {
                schema(
                    &[
                        ("provider_sequence", Kind::Integer),
                        ("operation", Kind::String),
                        ("version", Kind::Integer),
                        ("transition_id", Kind::String),
                        ("operation_id", Kind::String),
                        ("target", Kind::Object),
                        ("phase", Kind::String),
                        ("settings_revision", Kind::String),
                        ("settings", Kind::Object),
                        ("intent", Kind::Any),
                        ("reason", Kind::Any),
                        ("requested_video", Kind::Any),
                        ("consumer_requirements", Kind::Object),
                        ("remaining_ms", Kind::Integer),
                        ("plan_revision", Kind::Any),
                        ("admission_id", Kind::Any),
                        ("approved_plan", Kind::Any),
                    ],
                    &[
                        ("resource_generation", Kind::Integer),
                        ("source_video_mode", Kind::Object),
                        ("join_context", Kind::Object),
                        ("dependency_inputs", Kind::Array),
                        ("control_results", Kind::Array),
                    ],
                )
            };
            Command::RegisterApi {
                method: ApiMethod {
                    service: crate::settings_descriptor::SERVICE.into(),
                    method: method.into(),
                    interface_major: 1,
                    interface_minor: 0,
                    request,
                    response: schema(
                        &[("status", Kind::String)],
                        &[
                            ("reason", Kind::String),
                            ("plan", Kind::Object),
                            ("candidate", Kind::Any),
                            ("obligations", Kind::Array),
                            ("outputs", Kind::Array),
                            ("outcomes", Kind::Array),
                            ("receipt_id", Kind::String),
                        ],
                    ),
                    privilege: ApiPrivilege::User,
                },
            }
        })
        .collect()
}

fn schema(required: &[(&str, Kind)], optional: &[(&str, Kind)]) -> ApiSchema {
    ApiSchema {
        required: required
            .iter()
            .cloned()
            .map(|(name, kind)| (name.into(), kind))
            .collect(),
        optional: optional
            .iter()
            .cloned()
            .map(|(name, kind)| (name.into(), kind))
            .collect::<BTreeMap<_, _>>(),
        allow_extra: false,
    }
}

enum Stage {
    Submit,
    Wait(u64),
    Release(u64, Value),
    Cancel(u64),
    CancelRelease(u64),
}
struct Pending {
    inbound: u64,
    request: ProviderRequest,
    operation_id: String,
    deadline: Instant,
    timeout_ms: u64,
    stage: Stage,
    abandoned: bool,
}

pub(crate) struct Bridge {
    selected: Selection,
    pending: VecDeque<Pending>,
    #[cfg(target_os = "linux")]
    backend: crate::linux_lifecycle::Backend,
    #[cfg(windows)]
    windows: Option<crate::runtime::NativeOwner>,
}

impl Bridge {
    pub(crate) fn configured(
        selected: Selection,
        settings: &Value,
        native: crate::runtime::NativeOwner,
    ) -> ModuleResult<Self> {
        let bridge = Self::new(selected);
        #[cfg(target_os = "linux")]
        let bridge = {
            let mut bridge = bridge;
            bridge.backend = crate::linux_lifecycle::Backend::configured(settings)?;
            bridge
        };
        #[cfg(not(target_os = "linux"))]
        let _ = settings;
        #[cfg(windows)]
        let bridge = {
            let mut bridge = bridge;
            bridge.windows = Some(native);
            bridge
        };
        #[cfg(not(windows))]
        let _ = native;
        Ok(bridge)
    }

    pub(crate) fn new(selected: Selection) -> Self {
        Self {
            selected,
            pending: VecDeque::new(),
            #[cfg(target_os = "linux")]
            backend: crate::linux_lifecycle::Backend::from_environment(),
            #[cfg(windows)]
            windows: None,
        }
    }

    /// `None` means a valid call was queued; an immediate reply is otherwise returned.
    pub(crate) fn accept(
        &mut self,
        inbound: u64,
        caller: &str,
        payload: Value,
        remaining_ms: u64,
    ) -> Option<Value> {
        let reject = |reason: &str| Some(json!({"status":"rejected","reason":reason}));
        if caller != self.selected.principal {
            return reject("unauthorized_caller");
        }
        let Some(envelope) = payload.as_object().filter(|object| object.len() == 4) else {
            return reject("invalid_request");
        };
        if envelope.get("interface_major") != Some(&json!(1))
            || envelope.get("interface_minor") != Some(&json!(0))
        {
            return reject("invalid_request");
        }
        let method = envelope.get("method").and_then(Value::as_str).unwrap_or("");
        if method == "lifecycle_status" {
            #[cfg(any(target_os = "linux", windows))]
            {
                let status = match serde_json::from_value::<extension_api::ProviderStatusRequest>(
                    envelope.get("arguments").cloned().unwrap_or(Value::Null),
                ) {
                    Ok(status) => status,
                    Err(_) => return reject("invalid_request"),
                };
                #[cfg(target_os = "linux")]
                let response = self.backend.status(&status);
                #[cfg(windows)]
                let response = self
                    .windows
                    .as_ref()
                    .map(|backend| backend.borrow().status(&status))
                    .unwrap_or(extension_api::ProviderResponse::RecoveryRequired {
                        reason: "backend_not_configured".into(),
                    });
                return Some(serde_json::to_value(response).expect("serializable response"));
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            return Some(json!({"status":"recovery_required","reason":"unknown_receipt"}));
        }
        let expected = match method {
            "resource_plan" => ProviderOperation::ResourcePlan,
            "lifecycle_callback" => ProviderOperation::LifecycleCallback,
            _ => return reject("unknown_method"),
        };
        let Some(arguments) = envelope.get("arguments") else {
            return reject("invalid_request");
        };
        let Ok(request) = serde_json::from_value::<ProviderRequest>(arguments.clone()) else {
            return reject("invalid_request");
        };
        if request.operation != expected
            || extension_api::validate_provider_request(&request).is_err()
            || remaining_ms == 0
        {
            return reject("invalid_request");
        }
        if self.pending.len() >= MAX_PENDING {
            return reject("provider_busy");
        }
        let mut nonce = [0_u8; 16];
        if getrandom::fill(&mut nonce).is_err() {
            return reject("entropy_unavailable");
        }
        let operation_id = format!(
            "limiter-context-{}",
            nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let timeout_ms = remaining_ms.min(request.remaining_ms).min(30_000);
        self.pending.push_back(Pending {
            inbound,
            request,
            operation_id,
            deadline: Instant::now() + Duration::from_millis(timeout_ms),
            timeout_ms,
            stage: Stage::Submit,
            abandoned: false,
        });
        None
    }

    pub(crate) fn advance(&mut self, runtime: &RuntimeClient) -> ModuleResult<()> {
        #[cfg(target_os = "linux")]
        self.backend.advance();
        let Some(mut pending) = self.pending.pop_front() else {
            return Ok(());
        };
        match runtime.send(Command::CheckRequest {
            request: pending.inbound,
        }) {
            Ok(Response::Ok) => (),
            Ok(Response::Error { code, .. }) if code == "request_ended" || code == "not_found" => {
                pending.abandoned = true
            }
            _ => {
                self.pending.push_back(pending);
                return Ok(());
            }
        }
        if Instant::now() >= pending.deadline {
            pending.abandoned = true;
        }
        if pending.abandoned {
            pending.stage = match pending.stage {
                Stage::Submit => return Ok(()),
                Stage::Wait(id) => Stage::Cancel(id),
                Stage::Release(id, _) => Stage::CancelRelease(id),
                other => other,
            };
        }
        let mut completion = None;
        match &mut pending.stage {
            Stage::Submit => {
                let payload = serde_json::to_value(extension_api::ProviderContextRequest {
                    operation: "read_provider_context".into(),
                    provider_request: pending.request.clone(),
                })
                .map_err(|error| error.to_string())?;
                match runtime.send(Command::Request {
                    service: self.selected.service.clone(),
                    payload,
                    timeout_ms: pending.timeout_ms,
                    operation_id: pending.operation_id.clone(),
                    parent: None,
                }) {
                    Ok(Response::Accepted { id }) => pending.stage = Stage::Wait(id),
                    Ok(Response::Error { code, .. }) => {
                        eprintln!("frame limiter context request rejected code={code}");
                        completion =
                            Some(json!({"status":"rejected","reason":"context_unavailable"}))
                    }
                    _ => (), // Retry the same read identity after uncertain admission.
                }
            }
            Stage::Wait(id) => match runtime.send(Command::TakeResult { request: *id }) {
                Ok(Response::Pending) => (),
                Ok(Response::Result { payload }) => pending.stage = Stage::Release(*id, payload),
                Ok(Response::Error { code, .. }) if code == "not_found" => {
                    completion = Some(json!({"status":"rejected","reason":"context_unavailable"}))
                }
                _ => (),
            },
            Stage::Release(id, payload) => {
                #[cfg(windows)]
                if self
                    .windows
                    .as_ref()
                    .is_some_and(|worker| worker.borrow_mut().initializing())
                {
                    self.pending.push_back(pending);
                    return Ok(());
                }
                #[cfg(target_os = "linux")]
                if self.backend.is_recovering() {
                    self.pending.push_back(pending);
                    return Ok(());
                }
                match runtime.send(Command::ReleaseResult { request: *id }) {
                    Ok(Response::Ok) => {
                        completion = Some(
                            self.evaluate_with_budget(
                                &pending.request,
                                payload.clone(),
                                pending
                                    .deadline
                                    .saturating_duration_since(Instant::now())
                                    .as_millis() as u64,
                            ),
                        )
                    }
                    Ok(Response::Error { code, .. }) if code == "not_found" => {
                        completion = Some(
                            self.evaluate_with_budget(
                                &pending.request,
                                payload.clone(),
                                pending
                                    .deadline
                                    .saturating_duration_since(Instant::now())
                                    .as_millis() as u64,
                            ),
                        )
                    }
                    _ => (),
                }
            }
            Stage::Cancel(id) => match runtime.send(Command::Cancel { request: *id }) {
                Ok(Response::Ok) => pending.stage = Stage::CancelRelease(*id),
                Ok(Response::Error { code, .. }) if code == "not_found" => return Ok(()),
                _ => (),
            },
            Stage::CancelRelease(id) => match runtime.send(Command::ReleaseResult { request: *id })
            {
                Ok(Response::Ok) => return Ok(()),
                Ok(Response::Error { code, .. }) if code == "not_found" => return Ok(()),
                _ => (),
            },
        }
        if let Some(payload) = completion {
            if !pending.abandoned {
                match runtime.send(Command::Complete {
                    request: pending.inbound,
                    payload,
                })? {
                    Response::Ok => (),
                    Response::Error { code, .. }
                        if code == "request_ended" || code == "not_found" => {}
                    response => return Err(format!("lifecycle completion failed: {response:?}")),
                }
            }
        } else {
            self.pending.push_back(pending);
        }
        Ok(())
    }

    #[cfg(all(test, target_os = "linux"))]
    fn evaluate(&mut self, request: &ProviderRequest, payload: Value) -> Value {
        self.evaluate_with_budget(request, payload, request.remaining_ms)
    }

    fn evaluate_with_budget(
        &mut self,
        request: &ProviderRequest,
        payload: Value,
        remaining_ms: u64,
    ) -> Value {
        #[cfg(not(any(target_os = "linux", windows)))]
        let _ = remaining_ms;
        let context = match serde_json::from_value::<ProviderContextResponse>(payload.clone()) {
            Ok(context) => context,
            Err(_) => {
                let reason = payload
                    .get("reason")
                    .or_else(|| payload.get("code"))
                    .and_then(Value::as_str)
                    .filter(|reason| {
                        reason.len() <= 64
                            && reason
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    })
                    .unwrap_or("invalid_context_response");
                eprintln!("frame limiter context response rejected reason={reason}");
                return json!({"status":"rejected","reason":"context_unavailable"});
            }
        };
        if context.status != "succeeded"
            || context.context.target != request.target
            || context.context.requested_video != request.requested_video
        {
            return json!({"status":"rejected","reason":"context_mismatch"});
        }
        if request.intent == Some(extension_api::StreamIntent::Join) {
            let response = match request.operation {
                ProviderOperation::ResourcePlan => {
                    extension_api::stream_join_plan(request, crate::settings_descriptor::PROVIDER)
                        .map(|plan| extension_api::ProviderResponse::Planned { plan })
                }
                ProviderOperation::LifecycleCallback => extension_api::stream_join_callback(
                    request,
                    crate::settings_descriptor::PROVIDER,
                ),
                _ => Err("unsupported join operation".into()),
            };
            return match response {
                Ok(response) => serde_json::to_value(response).expect("serializable join response"),
                Err(_) => json!({"status":"rejected","reason":"invalid_join_context"}),
            };
        }
        let releasing = matches!(
            request.phase,
            LifecyclePhase::SessionRelease | LifecyclePhase::StreamRelease
        );
        #[cfg(target_os = "linux")]
        if releasing {
            let response = if request.operation == ProviderOperation::ResourcePlan
                && (self.backend.owns_target(&request.target)
                    || (request
                        .settings
                        .get("frame_limiter_enable")
                        .and_then(Value::as_bool)
                        == Some(true)
                        && request
                            .settings
                            .get("frame_limiter_provider")
                            .and_then(Value::as_str)
                            != Some("none")))
            {
                self.backend
                    .plan(request, None)
                    .map(|plan| extension_api::ProviderResponse::Planned { plan })
            } else if request.operation == ProviderOperation::LifecycleCallback
                && request
                    .approved_plan
                    .as_ref()
                    .is_some_and(|plan| !plan.obligations.is_empty())
            {
                Ok(self.backend.begin_with_budget(request, None, remaining_ms))
            } else {
                return no_op_response(request);
            };
            return response_value(request, response);
        }
        #[cfg(windows)]
        if releasing {
            let Some(backend) = self.windows.as_mut() else {
                return json!({"status":"rejected","reason":"backend_not_configured"});
            };
            let response = if request.operation == ProviderOperation::ResourcePlan
                && (backend.borrow().owns_target(&request.target)
                    || (request
                        .settings
                        .get("frame_limiter_enable")
                        .and_then(Value::as_bool)
                        == Some(true)
                        && request
                            .settings
                            .get("frame_limiter_provider")
                            .and_then(Value::as_str)
                            != Some("none")))
            {
                backend
                    .borrow()
                    .plan(request, None)
                    .map(|plan| extension_api::ProviderResponse::Planned { plan })
            } else if request.operation == ProviderOperation::LifecycleCallback
                && request
                    .approved_plan
                    .as_ref()
                    .is_some_and(|plan| !plan.obligations.is_empty())
            {
                Ok(backend.borrow_mut().begin(request, None, remaining_ms))
            } else {
                return no_op_response(request);
            };
            return response_value(request, response);
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        if releasing {
            return no_op_response(request);
        }
        #[cfg(target_os = "linux")]
        let decision = crate::lifecycle_policy::proton_policy(
            &serde_json::to_value(&request.settings).unwrap_or(Value::Null),
            &context.context,
            self.backend.mangohud_available(),
        );
        #[cfg(windows)]
        let decision = crate::windows_policy::resolve(
            &serde_json::to_value(&request.settings).unwrap_or(Value::Null),
            &context.context,
        );
        #[cfg(not(any(target_os = "linux", windows)))]
        let decision = unavailable_backend_policy(
            &serde_json::to_value(&request.settings).unwrap_or(Value::Null),
        );
        match decision {
            Err(reason) => json!({"status":"rejected","reason":reason}),
            Ok(Some(policy)) => {
                #[cfg(target_os = "linux")]
                let response = match request.operation {
                    ProviderOperation::ResourcePlan => self
                        .backend
                        .plan(request, Some(&policy))
                        .map(|plan| extension_api::ProviderResponse::Planned { plan }),
                    ProviderOperation::LifecycleCallback => {
                        Ok(self
                            .backend
                            .begin_with_budget(request, Some(policy), remaining_ms))
                    }
                    _ => Err("invalid_operation"),
                };
                #[cfg(windows)]
                let response = if let Some(backend) = self.windows.as_mut() {
                    match request.operation {
                        ProviderOperation::ResourcePlan => backend
                            .borrow()
                            .plan(request, Some(&policy))
                            .map(|plan| extension_api::ProviderResponse::Planned { plan }),
                        ProviderOperation::LifecycleCallback => {
                            Ok(backend
                                .borrow_mut()
                                .begin(request, Some(policy), remaining_ms))
                        }
                        _ => Err("invalid_operation"),
                    }
                } else {
                    Err("backend_not_configured")
                };
                #[cfg(not(any(target_os = "linux", windows)))]
                let response = {
                    let _ = policy;
                    Err("platform_backend_unavailable")
                };
                response_value(request, response)
            }
            Ok(None) => no_op_response(request),
        }
    }
}

#[cfg(any(not(any(target_os = "linux", windows)), test))]
fn unavailable_backend_policy(settings: &Value) -> Result<Option<Value>, &'static str> {
    let values = serde_json::from_value(settings.clone()).map_err(|_| "invalid_settings")?;
    crate::settings_descriptor::validate(crate::Platform::Macos, &values)
        .map_err(|_| "invalid_settings")?;
    let settings = crate::GlobalSettings::from_json(settings.clone())
        .map_err(|_| "invalid_settings")?
        .settings;
    if !settings.enable || settings.provider == crate::FrameLimiterProvider::None {
        Ok(None)
    } else {
        Err("platform_backend_unavailable")
    }
}

fn response_value(
    request: &ProviderRequest,
    response: Result<extension_api::ProviderResponse, &'static str>,
) -> Value {
    match response {
        Ok(response) if extension_api::validate_provider_response(request, &response).is_ok() => {
            serde_json::to_value(response).expect("serializable response")
        }
        Ok(_) => json!({"status":"rejected","reason":"invalid_admission"}),
        Err(reason) => json!({"status":"rejected","reason":reason}),
    }
}

fn no_op_response(request: &ProviderRequest) -> Value {
    let response = match request.operation {
        ProviderOperation::ResourcePlan => {
            let plan = extension_api::ResourcePlan {
                plan_id: format!("limiter-noop-{}", request.provider_sequence),
                revision: request.provider_sequence,
                resources: vec![],
                mutation_domains: vec![],
                required_capabilities: vec![],
                constraints: json!({}),
                obligations: vec![],
                affected_consumers: vec![],
                consumer_change: extension_api::ConsumerChange::Live,
                candidate_constraint: None,
                allowed_degradation: vec![],
                control_proposals: vec![],
                resource_disposition: None,
            };
            extension_api::ProviderResponse::Planned { plan }
        }
        ProviderOperation::LifecycleCallback
            if matches!(
                request.phase,
                LifecyclePhase::SessionRelease | LifecyclePhase::StreamRelease
            ) =>
        {
            extension_api::ProviderResponse::Cleanup {
                outcomes: vec![],
                outputs: vec![],
            }
        }
        ProviderOperation::LifecycleCallback => extension_api::ProviderResponse::Prepared {
            candidate: None,
            obligations: vec![],
            outputs: vec![],
        },
        _ => return json!({"status":"rejected","reason":"invalid_operation"}),
    };
    if extension_api::validate_provider_response(request, &response).is_err() {
        return json!({"status":"rejected","reason":"invalid_admission"});
    }
    serde_json::to_value(response)
        .unwrap_or_else(|_| json!({"status":"rejected","reason":"invalid_response"}))
}

#[cfg(test)]
mod tests {
    #[test]
    fn unsupported_platform_keeps_disabled_settings_inert() {
        let values = amaterasu_configuration_schema::defaults(
            &crate::settings_descriptor::definitions(crate::Platform::Macos),
        )
        .unwrap();
        let mut settings = serde_json::to_value(values).unwrap();
        assert_eq!(super::unavailable_backend_policy(&settings), Ok(None));
        settings["frame_limiter_enable"] = serde_json::json!(true);
        assert_eq!(
            super::unavailable_backend_policy(&settings),
            Err("platform_backend_unavailable")
        );
        settings["frame_limiter_provider"] = serde_json::json!("none");
        assert_eq!(super::unavailable_backend_policy(&settings), Ok(None));
    }

    use super::*;

    fn request(provider: &str) -> ProviderRequest {
        let platform = if cfg!(target_os = "linux") {
            crate::Platform::Linux
        } else if cfg!(target_os = "windows") {
            crate::Platform::Windows
        } else {
            crate::Platform::Macos
        };
        let mut settings = amaterasu_configuration_schema::defaults(
            &crate::settings_descriptor::definitions(platform),
        )
        .unwrap();
        settings.insert("frame_limiter_provider".into(), json!(provider));
        serde_json::from_value(json!({"provider_sequence":1,"operation":"resource_plan","version":1,
            "transition_id":"transition","operation_id":"plan", "target":{"kind":"session",
            "host_epoch":"epoch","session_id":"session","generation":1},"phase":"session.prepare",
            "settings_revision":"revision","settings":settings,"intent":null,"reason":null,
            "requested_video":{"width":1920,"height":1080,"refresh_millihz":60000,"hdr":false},
            "consumer_requirements":{"execution_domain":"seat","capture_providers":["capture"],"selector_schemas":["selector/1"]},
            "remaining_ms":5000,"plan_revision":null,"admission_id":null,"approved_plan":null})).unwrap()
    }

    #[cfg(target_os = "linux")]
    fn context(request: &ProviderRequest) -> Value {
        json!({"status":"succeeded","context":{"target":request.target,
            "application":{"kind":"desktop"},"requested_video":request.requested_video,
            "client":{"client_ref":"client","display_mode":null}}})
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn plans_are_typed_and_enabled_backend_requires_matching_context() {
        let mut bridge = Bridge::new(Selection {
            principal: "coordinator".into(),
            service: "lifecycle/1".into(),
        });
        let disabled = request("none");
        let result = bridge.evaluate(&disabled, context(&disabled));
        let response: extension_api::ProviderResponse = serde_json::from_value(result).unwrap();
        extension_api::validate_provider_response(&disabled, &response).unwrap();
        let mut enabled = request("proton");
        enabled
            .settings
            .insert("frame_limiter_enable".into(), json!(true));
        assert_eq!(
            bridge.evaluate(&enabled, context(&enabled))["status"],
            "planned"
        );
        let mut forged = context(&enabled);
        forged["context"]["target"]["session_id"] = json!("other");
        assert_eq!(
            bridge.evaluate(&enabled, forged)["reason"],
            "context_mismatch"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn default_auto_provider_has_no_prepare_or_release_effect_when_disabled() {
        let mut bridge = Bridge::new(Selection {
            principal: "coordinator".into(),
            service: "lifecycle/1".into(),
        });
        let mut disabled = request("auto");
        for phase in [
            LifecyclePhase::SessionPrepare,
            LifecyclePhase::SessionRelease,
        ] {
            disabled.phase = phase;
            let result = bridge.evaluate(&disabled, context(&disabled));
            let response: extension_api::ProviderResponse =
                serde_json::from_value(result.clone()).unwrap();
            extension_api::validate_provider_response(&disabled, &response).unwrap();
            assert!(result["plan"]["resources"].as_array().unwrap().is_empty());
        }
    }

    #[test]
    fn lifecycle_methods_accept_a_distinct_source_video_mode() {
        for command in registrations() {
            let Command::RegisterApi { method } = command else {
                panic!("expected lifecycle method registration");
            };
            if method.method == "lifecycle_status" {
                assert!(!method.request.optional.contains_key("source_video_mode"));
                continue;
            }
            assert_eq!(
                method.request.optional.get("source_video_mode"),
                Some(&Kind::Object)
            );
        }

        let mut request = request("none");
        request.requested_video.as_mut().unwrap().hdr = true;
        let mut source = request.requested_video.clone().unwrap();
        source.hdr = false;
        request.source_video_mode = Some(source.clone());
        assert!(extension_api::validate_provider_request(&request).is_ok());
        let payload = json!({"method":"resource_plan","interface_major":1,"interface_minor":0,"arguments":request});
        let mut bridge = Bridge::new(Selection {
            principal: "coordinator".into(),
            service: "lifecycle/1".into(),
        });
        assert!(bridge.accept(1, "coordinator", payload, 5000).is_none());
        assert_eq!(bridge.pending[0].request.source_video_mode, Some(source));
        assert!(
            bridge.pending[0]
                .request
                .requested_video
                .as_ref()
                .unwrap()
                .hdr
        );
    }

    #[test]
    fn configured_coordinator_identity_is_required() {
        let selected = selection(&json!({"lifecycle_coordinator":{"principal":"custom.coordinator","service":"custom.lifecycle/1"}})).unwrap().unwrap();
        let mut bridge = Bridge::new(selected);
        let envelope = json!({"method":"resource_plan","interface_major":1,"interface_minor":0,"arguments":request("none")});
        assert_eq!(
            bridge.accept(1, "foreign", envelope.clone(), 5000).unwrap()["reason"],
            "unauthorized_caller"
        );
        assert!(
            bridge
                .accept(1, "custom.coordinator", envelope, 5000)
                .is_none()
        );
        assert_eq!(bridge.pending.len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn participant_reads_context_and_releases_broker_result_before_replying() {
        use amaterasu_module_sdk::abi;
        use std::ffi::c_void;

        struct Host {
            payload: Value,
            commands: Vec<Command>,
        }
        unsafe extern "C" fn invoke(
            context: *mut c_void,
            input: abi::BorrowedBytes,
            reply: abi::ReplySink,
        ) -> abi::Status {
            // SAFETY: the boxed Host outlives the client and calls are serialized in this test.
            let host = unsafe { &mut *context.cast::<Host>() };
            // SAFETY: the SDK lends bytes for the duration of this synchronous callback.
            let Ok(bytes) = (unsafe { input.read() }) else {
                return abi::STATUS_INVALID_ARGUMENT;
            };
            let Ok(command) = serde_json::from_slice::<Command>(bytes) else {
                return abi::STATUS_INVALID_ARGUMENT;
            };
            let response = match &command {
                Command::CheckRequest { .. } => Response::Ok,
                Command::Request { payload, .. }
                    if payload["operation"] == "read_provider_context" =>
                {
                    Response::Accepted { id: 42 }
                }
                Command::TakeResult { request: 42 } => Response::Result {
                    payload: host.payload.clone(),
                },
                Command::ReleaseResult { request: 42 } | Command::Complete { .. } => Response::Ok,
                _ => return abi::STATUS_INVALID_ARGUMENT,
            };
            host.commands.push(command);
            let Ok(output) = serde_json::to_vec(&response) else {
                return abi::STATUS_INTERNAL_ERROR;
            };
            // SAFETY: ReplySink copies these bytes before this function returns.
            unsafe { reply.send(&output) };
            abi::STATUS_OK
        }

        let request = request("none");
        let mut host = Box::new(Host {
            payload: context(&request),
            commands: vec![],
        });
        let endpoint = abi::HostApi {
            header: abi::AbiHeader::of::<abi::HostApi>(),
            context: (&mut *host as *mut Host).cast(),
            invoke,
        };
        // SAFETY: endpoint and boxed host remain alive until after the client is dropped.
        let runtime = unsafe { RuntimeClient::from_endpoint(endpoint) };
        let selected = selection(
            &json!({"lifecycle_coordinator":{"principal":"coordinator","service":"lifecycle/1"}}),
        )
        .unwrap()
        .unwrap();
        let mut bridge = Bridge::new(selected);
        let payload = json!({"method":"resource_plan","interface_major":1,"interface_minor":0,"arguments":request});
        assert!(bridge.accept(7, "coordinator", payload, 5000).is_none());
        for _ in 0..3 {
            bridge.advance(&runtime).unwrap();
        }
        assert!(bridge.pending.is_empty());
        let release = host
            .commands
            .iter()
            .position(|command| matches!(command, Command::ReleaseResult { request: 42 }))
            .unwrap();
        let complete = host
            .commands
            .iter()
            .position(|command| matches!(command, Command::Complete { request: 7, .. }))
            .unwrap();
        assert!(release < complete);
        assert!(
            matches!(&host.commands[complete],Command::Complete {payload,..} if payload["status"] == "planned")
        );
    }
}
