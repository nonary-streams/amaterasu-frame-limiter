//! Plugin-private process boundary for Windows effects. Parent-side callbacks
//! remain asynchronous; only the child loads RTSS or NVIDIA's native APIs.
mod child;
mod launch;
#[cfg(test)]
mod tests;
pub(crate) use child::stage as child_stage;

use crate::{native_worker_process::Process, windows_policy::Policy};
use amaterasu_module_sdk::extension_api::{
    self as api, ProviderRequest, ProviderResponse, ProviderStatusRequest, ResourcePlan,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u32,
    rtss_journal: PathBuf,
    nvcp_journal: PathBuf,
    disable_stalled_rtss: bool,
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Lifecycle {
        request: Box<ProviderRequest>,
        policy: Option<Policy>,
    },
    Legacy {
        caller: String,
        payload: Value,
    },
    Ping,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Call {
    id: u64,
    operation: Operation,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    revision: u64,
    targets: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Reply {
    Ready {
        snapshot: Snapshot,
    },
    Result {
        id: u64,
        value: Value,
        snapshot: Snapshot,
    },
    Stage {
        id: u64,
        stage: String,
    },
    Fatal {
        reason: String,
    },
}

struct Job {
    operation: Operation,
    response: Option<Value>,
    deadline: Instant,
    last_progress: Instant,
    stage: String,
    retried: bool,
}

pub(crate) struct Worker {
    #[cfg(test)]
    fixture: Option<(PathBuf, String)>,
    config: Config,
    process: Option<Process>,
    snapshot: Option<Snapshot>,
    starting: Option<Instant>,
    wanted: bool,
    failure: Option<&'static str>,
    next_id: u64,
    jobs: BTreeMap<u64, Job>,
    receipts: BTreeMap<String, u64>,
    queue: VecDeque<u64>,
    completed: VecDeque<u64>,
    active: Option<u64>,
}

impl Worker {
    pub(crate) fn new(rtss_journal: PathBuf) -> Self {
        Self {
            #[cfg(test)]
            fixture: None,
            config: Config {
                version: 1,
                nvcp_journal: rtss_journal.with_file_name("nvcp-leases.json"),
                rtss_journal,
                disable_stalled_rtss: false,
            },
            process: None,
            snapshot: None,
            starting: None,
            wanted: false,
            failure: None,
            next_id: 1,
            jobs: BTreeMap::new(),
            receipts: BTreeMap::new(),
            queue: VecDeque::new(),
            completed: VecDeque::new(),
            active: None,
        }
    }

    /// Starts initialization on demand. A terminal initialization error must be
    /// returned to the caller, not turn into an endless context-read wait.
    pub(crate) fn initializing(&mut self) -> bool {
        self.wanted = true;
        self.snapshot.is_none() && self.failure.is_none()
    }

    pub(crate) fn owns_target(&self, target: &api::LifecycleTarget) -> bool {
        let Ok((_, id)) = crate::windows_lifecycle::target_identity(target) else {
            return false;
        };
        self.snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.targets.contains(&id))
    }

    pub(crate) fn plan(
        &self,
        request: &ProviderRequest,
        policy: Option<&Policy>,
    ) -> Result<ResourcePlan, &'static str> {
        if let Some(reason) = self.failure {
            return Err(reason);
        }
        let snapshot = self.snapshot.as_ref().ok_or("native_worker_not_ready")?;
        let policy = policy
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| "invalid_policy")?;
        crate::lifecycle_plan::build_native(request, policy.as_ref(), snapshot.revision)
    }

    pub(crate) fn begin(
        &mut self,
        request: &ProviderRequest,
        policy: Option<Policy>,
        remaining_ms: u64,
    ) -> ProviderResponse {
        if let Some(reason) = self.failure {
            return recovery(reason);
        }
        if api::validate_provider_request(request).is_err()
            || request.operation != api::ProviderOperation::LifecycleCallback
        {
            return ProviderResponse::Rejected {
                reason: "invalid_request".into(),
            };
        }
        let receipt = receipt_id(request);
        let operation = Operation::Lifecycle {
            request: Box::new(request.clone()),
            policy,
        };
        if let Some(id) = self.receipts.get(&receipt) {
            let Some(job) = self.jobs.get(id) else {
                return recovery("native_worker_receipt_evicted");
            };
            if job.operation != operation {
                return ProviderResponse::Rejected {
                    reason: "operation_identity_conflict".into(),
                };
            }
            return job
                .response
                .as_ref()
                .and_then(|value| serde_json::from_value(value.clone()).ok())
                .unwrap_or(ProviderResponse::Pending {
                    receipt_id: receipt,
                });
        }
        if let Some(reason) = self.failure {
            return recovery(reason);
        }
        match self.submit(operation, remaining_ms.min(request.remaining_ms)) {
            Ok(id) => {
                self.receipts.insert(receipt.clone(), id);
                ProviderResponse::Pending {
                    receipt_id: receipt,
                }
            }
            Err(reason) => ProviderResponse::Rejected {
                reason: reason.into(),
            },
        }
    }

    pub(crate) fn status(&self, request: &ProviderStatusRequest) -> ProviderResponse {
        if let Some(reason) = self.failure {
            return recovery(reason);
        }
        let Some(job) = self
            .receipts
            .get(&request.receipt_id)
            .and_then(|id| self.jobs.get(id))
        else {
            return recovery("native_worker_receipt_unknown");
        };
        let Operation::Lifecycle {
            request: original, ..
        } = &job.operation
        else {
            return recovery("native_worker_receipt_unknown");
        };
        if original.provider_sequence != request.provider_sequence
            || original.operation_id != request.operation_id
            || original.transition_id != request.transition_id
        {
            return recovery("native_worker_receipt_unknown");
        }
        job.response
            .as_ref()
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .unwrap_or(ProviderResponse::Pending {
                receipt_id: request.receipt_id.clone(),
            })
    }

    pub(crate) fn legacy(
        &mut self,
        caller: &str,
        payload: Value,
        remaining_ms: u64,
    ) -> Result<u64, &'static str> {
        if let Some(reason) = self.failure {
            return Err(reason);
        }
        self.submit(
            Operation::Legacy {
                caller: caller.into(),
                payload,
            },
            remaining_ms,
        )
    }

    fn submit(&mut self, operation: Operation, remaining_ms: u64) -> Result<u64, &'static str> {
        if serde_json::to_vec(&operation)
            .map_err(|_| "native_worker_invalid_request")?
            .len()
            + 128
            >= crate::native_worker_process::MAX_FRAME
        {
            return Err("native_worker_request_too_large");
        }
        if self.queue.len() + usize::from(self.active.is_some()) >= 32 {
            return Err("native_worker_busy");
        }
        if remaining_ms == 0 || self.next_id == u64::MAX {
            return Err("native_worker_invalid_request");
        }
        let id = self.next_id;
        self.next_id += 1;
        let now = Instant::now();
        self.jobs.insert(
            id,
            Job {
                operation,
                response: None,
                deadline: now + Duration::from_millis(remaining_ms.min(30_000)),
                last_progress: now,
                stage: String::new(),
                retried: false,
            },
        );
        self.queue.push_back(id);
        self.wanted = true;
        Ok(id)
    }

    pub(crate) fn result(&self, id: u64) -> Option<Value> {
        self.jobs.get(&id)?.response.clone()
    }
    pub(crate) fn cancel(&mut self, id: u64) {
        if let Some(job) = self.jobs.get_mut(&id) {
            job.deadline = Instant::now();
        }
    }

    pub(crate) fn advance(&mut self) {
        if self.failure.is_some() || !self.wanted {
            return;
        }
        if let Err(reason) = self.advance_inner() {
            self.fail(reason);
        }
    }

    fn advance_inner(&mut self) -> Result<(), &'static str> {
        let now = Instant::now();
        if self.process.is_none() {
            #[cfg(test)]
            let command = if let Some((program, mode)) = &self.fixture {
                let mut command = std::process::Command::new(program);
                command.env("AMATERASU_NATIVE_WORKER_FIXTURE_MODE", mode);
                command
            } else {
                launch::command()?
            };
            #[cfg(not(test))]
            let command = launch::command()?;
            let process = Process::spawn(command)?;
            process.submit(
                &serde_json::to_value(&self.config).map_err(|_| "native_worker_invalid_config")?,
            )?;
            self.process = Some(process);
            self.starting = Some(now);
        }
        for _ in 0..64 {
            let Some(value) = self.process.as_ref().unwrap().poll()? else {
                break;
            };
            match serde_json::from_value::<Reply>(value)
                .map_err(|_| "native_worker_invalid_reply")?
            {
                Reply::Ready { snapshot } if self.starting.is_some() => {
                    validate_snapshot(&snapshot)?;
                    self.snapshot = Some(snapshot);
                    self.starting = None;
                }
                Reply::Stage { id: 0, .. } if self.starting.is_some() => (),
                Reply::Stage { id, stage } if self.active == Some(id) => {
                    if !matches!(stage.as_str(), "rtss" | "rtss_startup" | "nvcp") {
                        return Err("native_worker_invalid_stage");
                    }
                    let job = self.jobs.get_mut(&id).unwrap();
                    job.last_progress = now;
                    job.stage = stage;
                }
                Reply::Result {
                    id,
                    value,
                    snapshot,
                } if self.active == Some(id) => {
                    validate_snapshot(&snapshot)?;
                    if let Operation::Lifecycle { request, .. } = &self.jobs[&id].operation {
                        let response: ProviderResponse = serde_json::from_value(value.clone())
                            .map_err(|_| "native_worker_invalid_reply")?;
                        api::validate_provider_response(request, &response)
                            .map_err(|_| "native_worker_invalid_reply")?;
                    }
                    self.snapshot = Some(snapshot);
                    self.active = None;
                    self.finish(id, value);
                }
                Reply::Fatal { .. } => return Err("native_worker_initialization_failed"),
                _ => return Err("native_worker_invalid_reply"),
            }
        }
        if self
            .starting
            .is_some_and(|started| now.duration_since(started) >= Duration::from_secs(5))
        {
            return Err("native_worker_startup_timeout");
        }
        if let Some(id) = self.active {
            let job = &self.jobs[&id];
            let stage_limit = if job.stage == "rtss_startup" {
                Duration::from_secs(4)
            } else {
                Duration::from_secs(1)
            };
            if now >= job.deadline || now.duration_since(job.last_progress) >= stage_limit {
                // Require the complete owned tree to exit before journal-based
                // fallback. Waiting only for the worker could leave RTSS alive.
                self.process.take().unwrap().retire()?;
                if self.retry_stalled_rtss(id, now) {
                    return Ok(());
                }
                return Err("native_worker_effect_unconfirmed");
            }
        }
        if !self.process.as_mut().unwrap().is_running()? {
            return Err("native_worker_stopped");
        }
        if self.starting.is_none() && self.active.is_none() {
            while let Some(id) = self.queue.pop_front() {
                if now >= self.jobs[&id].deadline {
                    let value = match &self.jobs[&id].operation {
                        Operation::Lifecycle { .. } => {
                            serde_json::to_value(ProviderResponse::Rejected {
                                reason: "native_worker_expired_before_effect".into(),
                            })
                            .unwrap()
                        }
                        other => error_value(other, "native_worker_expired_before_effect"),
                    };
                    self.finish(id, value);
                    continue;
                }
                let call = Call {
                    id,
                    operation: self.jobs[&id].operation.clone(),
                };
                self.process.as_ref().unwrap().submit(
                    &serde_json::to_value(call).map_err(|_| "native_worker_invalid_request")?,
                )?;
                self.jobs.get_mut(&id).unwrap().last_progress = now;
                self.active = Some(id);
                break;
            }
        }
        Ok(())
    }

    fn retry_stalled_rtss(&mut self, id: u64, now: Instant) -> bool {
        let job = self.jobs.get_mut(&id).unwrap();
        let Operation::Lifecycle {
            policy: Some(policy),
            ..
        } = &job.operation
        else {
            return false;
        };
        if job.retried
            || !matches!(job.stage.as_str(), "rtss" | "rtss_startup")
            || now >= job.deadline
            || !matches!(
                policy.provider,
                crate::windows_policy::Provider::Auto | crate::windows_policy::Provider::Rtss
            )
            || crate::lease::journal_has_effects(&self.config.rtss_journal) != Ok(false)
            || crate::nvcp::lease::journal_has_effects(&self.config.nvcp_journal) != Ok(false)
        {
            return false;
        }
        job.retried = true;
        self.config.disable_stalled_rtss = true;
        self.snapshot = None;
        self.starting = None;
        self.active = None;
        self.queue.push_front(id);
        true
    }

    fn finish(&mut self, id: u64, response: Value) {
        self.jobs.get_mut(&id).unwrap().response = Some(response);
        self.completed.push_back(id);
        while self.completed.len() > 256 {
            if let Some(id) = self.completed.pop_front() {
                self.jobs.remove(&id);
                self.receipts.retain(|_, owner| *owner != id);
            }
        }
    }
    fn fail(&mut self, reason: &'static str) {
        self.process = None;
        self.snapshot = None;
        self.starting = None;
        self.failure = Some(reason);
        let pending: Vec<_> = self
            .jobs
            .iter()
            .filter(|(_, job)| job.response.is_none())
            .map(|(id, _)| *id)
            .collect();
        for id in pending {
            self.finish(id, error_value(&self.jobs[&id].operation, reason));
        }
        self.active = None;
        self.queue.clear();
    }
}

fn recovery(reason: &str) -> ProviderResponse {
    ProviderResponse::RecoveryRequired {
        reason: reason.into(),
    }
}
fn error_value(operation: &Operation, reason: &str) -> Value {
    match operation {
        Operation::Lifecycle { .. } => serde_json::to_value(recovery(reason)).unwrap(),
        _ => {
            json!({"ok":false,"applied":false,"error":{"code":reason,"message":"Native frame limiter worker did not confirm the operation"}})
        }
    }
}
fn receipt_id(request: &ProviderRequest) -> String {
    format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&(
                &request.transition_id,
                &request.operation_id,
                request.provider_sequence
            ))
            .unwrap()
        )
    )
}
fn validate_snapshot(snapshot: &Snapshot) -> Result<(), &'static str> {
    if snapshot.revision == 0
        || snapshot.targets.len() > 1024
        || snapshot
            .targets
            .iter()
            .any(|target| target.is_empty() || target.len() > 128)
    {
        Err("native_worker_invalid_snapshot")
    } else {
        Ok(())
    }
}
