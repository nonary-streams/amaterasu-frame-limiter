#[cfg(not(windows))]
use crate::lease::{LeaseManager, handle_runtime_operation};
#[cfg(not(windows))]
use crate::rtss::RtssProvider;
use amaterasu_module_sdk::{Command, ManagedModule, ModuleResult, Response, RuntimeClient};
use serde_json::{Value, json};
use std::{cell::RefCell, path::PathBuf, rc::Rc};

const SERVICE: &str = "amaterasu.frame-limiter/1";

#[cfg(not(windows))]
pub(crate) type NativeOwner = Rc<RefCell<LeaseManager<RtssProvider>>>;
#[cfg(windows)]
pub(crate) type NativeOwner = Rc<RefCell<crate::windows_worker::Worker>>;

/// Registers the policy and verified runtime service for frame-limiter requests.
pub struct FrameLimiterModule {
    runtime: RuntimeClient,
    native: NativeOwner,
    #[cfg(windows)]
    pending_native: std::collections::BTreeMap<u64, u64>,
    registry_principal: Option<String>,
    lifecycle: Option<crate::lifecycle::Bridge>,
}

impl ManagedModule for FrameLimiterModule {
    fn start(runtime: RuntimeClient) -> ModuleResult<Self> {
        let journal_path = default_journal_path()?;
        #[cfg(not(windows))]
        let native = {
            let mut leases = LeaseManager::open(RtssProvider::new(), journal_path)
                .map_err(|error| format!("frame-limiter lease journal failed: {error}"))?;
            leases
                .recover()
                .map_err(|error| format!("frame-limiter lease recovery failed: {error}"))?;
            Rc::new(RefCell::new(leases))
        };
        #[cfg(windows)]
        let native = Rc::new(RefCell::new(crate::windows_worker::Worker::new(
            journal_path,
        )));
        runtime.require_success(Command::Register {
            service: SERVICE.into(),
        })?;
        let settings = match runtime.send(Command::GetSettings {})? {
            Response::Result { payload } => payload,
            response => return Err(format!("frame-limiter settings unavailable: {response:?}")),
        };
        let registry_principal = crate::extension::registry_principal(&settings)?;
        let selected_lifecycle = crate::lifecycle::selection(&settings)?;
        if registry_principal.is_some() {
            runtime.require_success(crate::extension::settings_registration())?;
        }
        if selected_lifecycle.is_some() {
            for registration in crate::lifecycle::registrations() {
                runtime.require_success(registration)?;
            }
        }
        Ok(Self {
            runtime,
            native: native.clone(),
            #[cfg(windows)]
            pending_native: Default::default(),
            registry_principal,
            lifecycle: selected_lifecycle
                .map(|selection| {
                    crate::lifecycle::Bridge::configured(selection, &settings, native.clone())
                })
                .transpose()?,
        })
    }

    fn tick(&mut self) -> ModuleResult<()> {
        #[cfg(windows)]
        {
            self.native.borrow_mut().advance();
            self.complete_native_requests()?;
        }
        if let Some(lifecycle) = &mut self.lifecycle {
            lifecycle.advance(&self.runtime)?;
        }
        match self.runtime.send(Command::Poll {})? {
            Response::Pending => Ok(()),
            Response::Request {
                id,
                caller,
                service,
                payload,
                remaining_ms,
                ..
            } => {
                if !self.request_is_active(id)? {
                    return Ok(());
                }

                let response = if service == crate::settings_descriptor::SERVICE {
                    if payload.get("method").and_then(Value::as_str) == Some("settings_validate") {
                        crate::extension::handle_settings(
                            &caller,
                            self.registry_principal.as_deref(),
                            payload,
                        )
                    } else if let Some(lifecycle) = &mut self.lifecycle {
                        let Some(reply) = lifecycle.accept(id, &caller, payload, remaining_ms)
                        else {
                            return Ok(());
                        };
                        reply
                    } else {
                        json!({"status":"rejected","reason":"lifecycle_not_selected"})
                    }
                } else if service != SERVICE {
                    json!({
                        "ok": false,
                        "applied": false,
                        "error": {
                            "code": "invalid_service",
                            "message": "unsupported frame-limiter service"
                        }
                    })
                } else {
                    #[cfg(not(windows))]
                    {
                        handle_runtime_operation(&caller, payload, &mut self.native.borrow_mut())
                    }
                    #[cfg(windows)]
                    {
                        let submitted =
                            self.native
                                .borrow_mut()
                                .legacy(&caller, payload, remaining_ms);
                        match submitted {
                            Ok(operation) => {
                                self.pending_native.insert(id, operation);
                                return Ok(());
                            }
                            Err(reason) => {
                                json!({"ok":false,"applied":false,"error":{"code":reason,"message":"Native limiter unavailable"}})
                            }
                        }
                    }
                };

                self.complete(id, response)
            }
            response => Err(format!("frame-limiter poll failed: {response:?}")),
        }
    }
}

impl FrameLimiterModule {
    #[cfg(windows)]
    fn complete_native_requests(&mut self) -> ModuleResult<()> {
        let pending: Vec<_> = self
            .pending_native
            .iter()
            .map(|(request, operation)| (*request, *operation))
            .collect();
        for (request, operation) in pending {
            if !self.request_is_active(request)? {
                self.native.borrow_mut().cancel(operation);
                self.pending_native.remove(&request);
            } else if let Some(response) = self.native.borrow().result(operation) {
                self.complete(request, response)?;
                self.pending_native.remove(&request);
            }
        }
        Ok(())
    }
    fn request_is_active(&self, id: u64) -> ModuleResult<bool> {
        match self.runtime.send(Command::CheckRequest { request: id })? {
            Response::Ok => Ok(true),
            Response::Error { code, .. } if code == "request_ended" || code == "not_found" => {
                Ok(false)
            }
            response => Err(format!("frame-limiter request check failed: {response:?}")),
        }
    }

    fn complete(&self, id: u64, payload: Value) -> ModuleResult<()> {
        match self.runtime.send(Command::Complete {
            request: id,
            payload,
        })? {
            Response::Ok => Ok(()),
            Response::Error { code, .. } if code == "request_ended" || code == "not_found" => {
                Ok(())
            }
            response => Err(format!("frame-limiter completion failed: {response:?}")),
        }
    }
}

pub(crate) fn default_journal_path() -> ModuleResult<PathBuf> {
    #[cfg(target_os = "windows")]
    let data_root = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .map(PathBuf::from)
        .ok_or_else(|| "user data directory is unavailable".to_owned())?;

    #[cfg(target_os = "macos")]
    let data_root = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "user data directory is unavailable".to_owned())?
        .join("Library")
        .join("Application Support");

    #[cfg(target_os = "linux")]
    let data_root = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".local").join("share"))
        })
        .ok_or_else(|| "user data directory is unavailable".to_owned())?;

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    return Err("user data directory is unsupported on this platform".into());

    if !data_root.is_absolute() {
        return Err("user data directory must be absolute".into());
    }
    Ok(data_root
        .join("Amaterasu")
        .join("frame-limiter")
        .join("leases.json"))
}
