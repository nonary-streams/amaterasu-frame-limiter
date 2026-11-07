//! Asynchronous lifecycle effects owned entirely by the Linux plugin.
//!
//! Admission returns a receipt before work starts. Receipts retain their exact
//! request identity; neither a timed-out broker call nor a late cleanup can
//! replay a mutation. The worker and ownership ledger serialize policy changes.
use crate::{
    linux_journal::{Journal, Receipt, State, receipt_id},
    linux_ownership::Change,
    proton_worker::ProtonWorker,
};
use amaterasu_module_sdk::extension_api::{
    self as api, CleanupOutcome, CleanupState, LifecyclePhase, ProviderRequest, ProviderResponse,
    ProviderStatusRequest,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    time::{Duration, Instant},
};

const MAX_PENDING: usize = 32;

enum Step {
    Queued,
    Discover(u64),
    Install {
        id: u64,
        remaining: VecDeque<String>,
    },
    Effect {
        id: u64,
        change: Change,
    },
}

struct Record {
    request: ProviderRequest,
    policy: Option<Value>,
    response: Option<ProviderResponse>,
    step: Step,
    deadline: Instant,
}

pub(crate) struct Backend {
    mangohud: crate::linux_availability::MangoHudProbe,
    runtime_root: Option<PathBuf>,
    journal_root: Option<PathBuf>,
    steam_roots: Vec<PathBuf>,
    worker: Option<ProtonWorker>,
    ready: bool,
    failed: bool,
    next_id: u64,
    state: State,
    journal: Option<Journal>,
    recovering: bool,
    recovery_deadline: Option<Instant>,
    records: BTreeMap<String, Record>,
    queue: VecDeque<String>,
    shutdown: crate::shutdown::Shutdown,
    shutdown_complete: bool,
    retiring_worker: bool,
}

impl Backend {
    pub(crate) fn configured(settings: &Value) -> Result<Self, &'static str> {
        let mut backend = Self::from_environment();
        backend.mangohud = crate::linux_availability::MangoHudProbe::configured(settings)?;
        if let Some(root) = settings.get("proton_runtime_directory") {
            let path = PathBuf::from(root.as_str().ok_or("invalid_runtime_directory")?);
            if !path.is_absolute() {
                return Err("invalid_runtime_directory");
            }
            backend.runtime_root = Some(path);
        }
        if let Some(root) = settings.get("proton_state_directory") {
            let path = PathBuf::from(root.as_str().ok_or("invalid_state_directory")?);
            if !path.is_absolute() {
                return Err("invalid_state_directory");
            }
            backend.journal_root = Some(path);
        }
        if let Some(roots) = settings.get("proton_steam_roots") {
            let roots: Vec<PathBuf> =
                serde_json::from_value(roots.clone()).map_err(|_| "invalid_steam_roots")?;
            if roots.len() > 64 || roots.iter().any(|path| !path.is_absolute()) {
                return Err("invalid_steam_roots");
            }
            backend.steam_roots = roots;
        }
        if backend.runtime_root.is_some() {
            backend.initialize()?;
        }
        Ok(backend)
    }

    pub(crate) fn plan(
        &self,
        request: &ProviderRequest,
        policy: Option<&Value>,
    ) -> Result<api::ResourcePlan, &'static str> {
        if self.failed {
            return Err("worker_recovery_required");
        }
        let inherited = self.inherited_policy(&request.target);
        let policy = if preparing(request) {
            inherited.as_ref().or(policy)
        } else {
            policy
        };
        crate::lifecycle_plan::build(request, policy, self.state.revision)
    }

    pub(crate) fn inherited_policy(&self, target: &api::LifecycleTarget) -> Option<Value> {
        let key = crate::linux_ownership::session_key(target).ok()?;
        self.state.root_policies.get(&key).cloned()
    }

    pub(crate) fn mangohud_available(&self) -> bool {
        self.mangohud.available()
    }

    pub(crate) fn owns_target(&self, target: &api::LifecycleTarget) -> bool {
        self.state.ownership.knows_target(target)
    }

    pub(crate) fn from_environment() -> Self {
        let runtime_root = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        let steam_roots = std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| vec![home.join(".steam/steam"), home.join(".local/share/Steam")])
            .unwrap_or_default();
        let mut backend = Self::new(runtime_root, steam_roots);
        backend.journal_root = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state"))
            });
        backend
    }

    fn new(runtime_root: Option<PathBuf>, steam_roots: Vec<PathBuf>) -> Self {
        Self {
            mangohud: crate::linux_availability::MangoHudProbe::from_environment(),
            journal_root: runtime_root.clone(),
            runtime_root,
            steam_roots,
            worker: None,
            ready: false,
            failed: false,
            next_id: 1,
            state: State::uninitialized(),
            journal: None,
            recovering: false,
            recovery_deadline: None,
            records: BTreeMap::new(),
            queue: VecDeque::new(),
            shutdown: Default::default(),
            shutdown_complete: false,
            retiring_worker: false,
        }
    }

    pub(crate) fn prepare_shutdown(&mut self, deadline: Instant) {
        let deadline = self.shutdown.announce_until(deadline);
        if let Some(worker) = &mut self.worker {
            worker.prepare_shutdown(deadline);
        }
    }

    pub(crate) fn quiesce(&mut self) -> Result<bool, &'static str> {
        if self.shutdown_complete {
            return Ok(true);
        }
        let deadline = self.shutdown.begin();
        // A previous owner may still have a durable policy even when this
        // instance has not started its replacement worker. Its strict startup
        // check must retire that exact intent before shutdown can claim success.
        if self.worker.is_none()
            && (self.recovering
                || !self.state.worker_policies.is_empty()
                || self.state.pending_policies.is_some())
        {
            if Instant::now() >= deadline {
                return Err("worker_shutdown_deadline_exceeded");
            }
            if !self.ensure_worker_ready()? {
                return Ok(false);
            }
        }
        if let Some(worker) = &mut self.worker {
            worker.prepare_shutdown(deadline);
            if !worker.quiesce()? {
                return Ok(false);
            }
        }
        if let Some(journal) = &mut self.journal {
            // The worker's successful exit and owned-file absence are the
            // proof. Persist it before replacing the live receipt ledger.
            let mut retired = self.state.clone();
            retired.retire_after_worker_restart()?;
            journal.save(&retired)?;
            self.state = retired;
        }
        self.worker = None;
        self.queue.clear();
        self.records.clear();
        self.ready = false;
        self.recovering = false;
        self.retiring_worker = false;
        self.shutdown_complete = true;
        Ok(true)
    }

    fn initialize(&mut self) -> Result<(), &'static str> {
        if self.journal.is_none() {
            let root = self
                .journal_root
                .as_deref()
                .ok_or("state_directory_unavailable")?;
            let (journal, state, recovering) =
                Journal::open_persistent(root, self.runtime_root.as_deref())?;
            self.journal = Some(journal);
            self.state = state;
            self.recovering = recovering;
            self.recovery_deadline = recovering.then(|| Instant::now() + Duration::from_secs(5));
        }
        Ok(())
    }

    pub(crate) fn is_recovering(&self) -> bool {
        self.recovering
    }

    fn checkpoint(&mut self) -> Result<(), &'static str> {
        self.journal
            .as_mut()
            .ok_or("journal_unavailable")?
            .save(&self.state)
    }

    #[cfg(test)]
    pub(crate) fn begin(
        &mut self,
        request: &ProviderRequest,
        policy: Option<Value>,
    ) -> ProviderResponse {
        self.begin_with_budget(request, policy, request.remaining_ms)
    }

    pub(crate) fn begin_with_budget(
        &mut self,
        request: &ProviderRequest,
        policy: Option<Value>,
        remaining_ms: u64,
    ) -> ProviderResponse {
        let reject = |reason: &str| ProviderResponse::Rejected {
            reason: reason.into(),
        };
        if api::validate_provider_request(request).is_err()
            || request.operation != api::ProviderOperation::LifecycleCallback
        {
            return reject("invalid_request");
        }
        if let Err(reason) = self.initialize() {
            return reject(reason);
        }
        let receipt = receipt_id(request);
        let policy = if preparing(request) {
            if self.state.receipts.contains_key(&receipt) {
                // A retained receipt binds the whole admitted plan and policy
                // fingerprint. Its immutable projection survives a sibling
                // root release; current settings cannot reinterpret that retry.
                request
                    .approved_plan
                    .as_ref()
                    .and_then(|plan| plan.constraints.get("policy"))
                    .filter(|policy| !policy.is_null())
                    .cloned()
                    .or(policy)
            } else {
                self.inherited_policy(&request.target).or(policy)
            }
        } else {
            policy
        };
        if let Err(reason) = validate_admission(request, policy.as_ref()) {
            return reject(reason);
        }
        if remaining_ms == 0 {
            return reject("callback_expired_before_effect");
        }
        if self.failed && !self.recovering {
            return ProviderResponse::RecoveryRequired {
                reason: "worker_recovery_required".into(),
            };
        }
        if let Some(record) = self.state.receipts.get(&receipt) {
            if !record.matches(request, &policy) {
                return reject("operation_identity_conflict");
            }
            if self.recovering {
                return ProviderResponse::Pending {
                    receipt_id: receipt,
                };
            }
            return record
                .response
                .clone()
                .unwrap_or(ProviderResponse::Pending {
                    receipt_id: receipt,
                });
        }
        if self.shutdown.started() {
            return reject("provider_shutting_down");
        }
        if self.recovering {
            return reject("worker_recovery_pending");
        }
        if request
            .approved_plan
            .as_ref()
            .and_then(|plan| plan.mutation_domains.first())
            .is_none_or(|domain| domain.expected_revision != self.state.revision)
        {
            return reject("stale_provider_observation");
        }
        if self.queue.len() >= MAX_PENDING {
            return reject("provider_busy");
        }
        if self
            .runtime_root
            .as_ref()
            .is_none_or(|path| !path.is_absolute())
        {
            return reject("runtime_directory_unavailable");
        }
        self.state.receipts.insert(
            receipt.clone(),
            Receipt::new(request, &policy, success(request)),
        );
        if let Err(reason) = self.checkpoint() {
            self.failed = true;
            return reject(reason);
        }
        self.records.insert(
            receipt.clone(),
            Record {
                request: request.clone(),
                policy,
                response: None,
                step: Step::Queued,
                deadline: Instant::now()
                    + Duration::from_millis(request.remaining_ms.min(remaining_ms).min(30_000)),
            },
        );
        self.queue.push_back(receipt.clone());
        ProviderResponse::Pending {
            receipt_id: receipt,
        }
    }

    pub(crate) fn status(&self, request: &ProviderStatusRequest) -> ProviderResponse {
        if self.failed && !self.recovering {
            return ProviderResponse::RecoveryRequired {
                reason: "worker_recovery_required".into(),
            };
        }
        match self.state.receipts.get(&request.receipt_id) {
            Some(record)
                if record.provider_sequence == request.provider_sequence
                    && record.operation_id == request.operation_id
                    && record.transition_id == request.transition_id =>
            {
                if self.recovering {
                    return ProviderResponse::Pending {
                        receipt_id: request.receipt_id.clone(),
                    };
                }
                record
                    .response
                    .clone()
                    .unwrap_or_else(|| ProviderResponse::Pending {
                        receipt_id: request.receipt_id.clone(),
                    })
            }
            _ => ProviderResponse::RecoveryRequired {
                reason: "unknown_receipt".into(),
            },
        }
    }

    pub(crate) fn has_receipt(&self, request: &ProviderRequest) -> bool {
        self.state.receipts.contains_key(&receipt_id(request))
    }

    pub(crate) fn advance(&mut self) {
        if self.shutdown.started() {
            return;
        }
        if self.retiring_worker && !self.poll_failed_worker_retirement() {
            return;
        }
        if self.queue.is_empty()
            && self.ready
            && self
                .worker
                .as_mut()
                .is_some_and(|worker| worker.is_running() != Ok(true))
        {
            self.retiring_worker = true;
            self.ready = false;
            self.failed = true;
            self.start_recovery();
            return;
        }
        if self.recovering {
            if self.recover_worker().is_err() {
                self.retiring_worker = self.worker.is_some();
                self.ready = false;
                self.failed = true;
                self.recovering = false;
            }
            return;
        }
        let Some(receipt) = self.queue.front().cloned() else {
            return;
        };
        let mut record = self.records.remove(&receipt).expect("queued record");
        let outcome = self.advance_record(&mut record);
        let mut recover_worker = false;
        match outcome {
            Ok(Some(response)) => record.response = Some(response),
            Ok(None) => (),
            Err(reason) => {
                // A worker failure can follow a successful filesystem write. Retire
                // the worker to make its policy inert, and retain uncertainty.
                self.retiring_worker = self.worker.is_some();
                self.ready = false;
                self.failed = true;
                recover_worker = true;
                record.response = Some(ProviderResponse::RecoveryRequired {
                    reason: reason.into(),
                });
            }
        }
        if record.response.is_some() {
            self.queue.pop_front();
            self.state.finish(
                &receipt,
                record.response.clone().expect("completed response"),
            );
            if let Err(reason) = self.checkpoint() {
                self.retiring_worker = self.worker.is_some();
                self.ready = false;
                self.failed = true;
                record.response = Some(ProviderResponse::RecoveryRequired {
                    reason: reason.into(),
                });
                self.state
                    .receipts
                    .get_mut(&receipt)
                    .expect("retained receipt")
                    .response = record.response.clone();
            } else if recover_worker {
                self.start_recovery();
            }
            self.records
                .retain(|id, _| self.state.receipts.contains_key(id));
        }
        self.records.insert(receipt, record);
    }

    fn start_recovery(&mut self) {
        self.recovering = true;
        self.recovery_deadline = Some(Instant::now() + Duration::from_secs(5));
    }

    fn poll_failed_worker_retirement(&mut self) -> bool {
        let Some(worker) = &mut self.worker else {
            self.retiring_worker = false;
            return true;
        };
        let deadline = self
            .recovery_deadline
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(5));
        worker.prepare_shutdown(deadline);
        let retired = match worker.quiesce() {
            Ok(retired) => retired,
            // A failed worker may leave its exact policy file behind. Native
            // process exit allows a replacement to validate and remove that
            // intent; it is not itself policy retirement proof.
            Err(_) => worker.is_running() == Ok(false),
        };
        if retired {
            self.worker = None;
            self.retiring_worker = false;
        }
        retired
    }

    fn recover_worker(&mut self) -> Result<(), &'static str> {
        if self
            .recovery_deadline
            .is_none_or(|deadline| Instant::now() >= deadline)
        {
            return Err("worker_recovery_deadline_exceeded");
        }
        if !self.ensure_worker_ready()? {
            return Ok(());
        }
        self.state.retire_after_worker_restart()?;
        self.checkpoint()?;
        self.recovering = false;
        self.recovery_deadline = None;
        self.failed = false;
        self.queue.clear();
        self.records.clear();
        Ok(())
    }

    fn ensure_worker_ready(&mut self) -> Result<bool, &'static str> {
        if self.worker.is_none() {
            let mut expected = vec![
                self.state
                    .worker_policies
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ];
            if let Some(policies) = &self.state.pending_policies {
                expected.push(policies.values().cloned().collect());
            }
            self.worker = Some(ProtonWorker::start(
                self.runtime_root
                    .as_ref()
                    .ok_or("runtime_directory_unavailable")?,
                &self.state.owner_id,
                &expected,
            )?);
            if let Some(deadline) = self.shutdown.deadline() {
                self.worker
                    .as_mut()
                    .expect("started worker")
                    .prepare_shutdown(deadline);
            }
        }
        if !self.ready {
            let Some(reply) = self.worker.as_ref().expect("started worker").poll()? else {
                return Ok(false);
            };
            if reply != json!({"id":null,"ok":true,"state":"ready"}) {
                return Err("worker_not_ready");
            }
            self.ready = true;
        }
        Ok(true)
    }

    fn advance_record(
        &mut self,
        record: &mut Record,
    ) -> Result<Option<ProviderResponse>, &'static str> {
        if self.failed {
            return Err("worker_recovery_required");
        }
        if matches!(record.step, Step::Queued) {
            if Instant::now() >= record.deadline {
                return Ok(Some(rejected("callback_expired_before_effect")));
            }
            if record
                .request
                .approved_plan
                .as_ref()
                .and_then(|plan| plan.mutation_domains.first())
                .is_none_or(|domain| domain.expected_revision != self.state.revision)
            {
                return Ok(Some(rejected("stale_provider_observation")));
            }
        }
        if Instant::now() >= record.deadline {
            return Err("worker_deadline_exceeded");
        }
        if !self.ensure_worker_ready()? {
            return Ok(None);
        }
        match &mut record.step {
            Step::Queued if record.policy.is_some() => {
                let id = self.send(json!({"operation":"discover","roots":self.steam_roots}))?;
                record.step = Step::Discover(id);
            }
            Step::Queued => return self.start_effect(record),
            Step::Discover(id) => {
                let Some(reply) = self.receive(*id)? else {
                    return Ok(None);
                };
                let tools: Vec<String> = serde_json::from_value(
                    reply.get("tools").cloned().ok_or("invalid_worker_reply")?,
                )
                .map_err(|_| "invalid_worker_reply")?;
                if tools.is_empty() {
                    if record
                        .policy
                        .as_ref()
                        .and_then(|policy| policy["provider"].as_str())
                        == Some("mangohud")
                    {
                        return self.start_effect(record);
                    }
                    return Ok(Some(ProviderResponse::Rejected {
                        reason: "proton_tools_unavailable".into(),
                    }));
                }
                if tools.len() > 256 {
                    return Err("invalid_worker_reply");
                }
                let mut remaining: VecDeque<_> = tools.into();
                let tool = remaining.pop_front().expect("nonempty tools");
                let id = self.send(json!({"operation":"install","tool":tool}))?;
                record.step = Step::Install { id, remaining };
            }
            Step::Install { id, remaining } => {
                if self.receive(*id)?.is_none() {
                    return Ok(None);
                }
                if let Some(tool) = remaining.pop_front() {
                    *id = self.send(json!({"operation":"install","tool":tool}))?;
                } else {
                    return self.start_effect(record);
                }
            }
            Step::Effect { id, change } => {
                if self.receive(*id)?.is_none() {
                    return Ok(None);
                }
                self.state.ownership.commit(change.clone())?;
                self.state.worker_policies = self
                    .state
                    .pending_policies
                    .take()
                    .ok_or("missing_policy_intent")?;
                if matches!(record.request.target, api::LifecycleTarget::Session { .. }) {
                    if let Some(policy) = &record.policy {
                        self.state
                            .root_policies
                            .insert(change.session.clone(), policy.clone());
                    } else {
                        self.state.root_policies.remove(&change.session);
                    }
                }
                self.state.revision = self
                    .state
                    .revision
                    .checked_add(1)
                    .ok_or("provider_revision_exhausted")?;
                if !preparing(&record.request) {
                    self.state
                        .ownership
                        .finish_session_if_idle(&record.request.target)?;
                }
                self.checkpoint()?;
                return Ok(Some(success(&record.request)));
            }
        }
        Ok(None)
    }

    fn start_effect(
        &mut self,
        record: &mut Record,
    ) -> Result<Option<ProviderResponse>, &'static str> {
        let change = if let Some(policy) = &record.policy {
            let change = match self
                .state
                .ownership
                .prepare(&record.request.target, &record.request.transition_id)
            {
                Ok(change) => change,
                Err(reason) => return Ok(Some(rejected(reason))),
            };
            let command = json!({"operation":"set","session":change.policy_key()?,
                "expected_revision":change.expected_revision,"revision":change.new_revision,"policy":policy});
            (change, command)
        } else {
            let release = match self.state.ownership.release(&record.request.target) {
                Ok(change) => change,
                Err(reason) => return Ok(Some(rejected(reason))),
            };
            let Some(change) = release else {
                if let Err(reason) = self
                    .state
                    .ownership
                    .finish_session_if_idle(&record.request.target)
                {
                    return Ok(Some(rejected(reason)));
                }
                return Ok(Some(success(&record.request)));
            };
            let command = json!({"operation":"remove","session":change.policy_key()?,"expected_revision":change.expected_revision});
            (change, command)
        };
        let mut expected = self.state.worker_policies.clone();
        let policy_key = change.0.policy_key()?;
        if let Some(policy) = &record.policy {
            expected.insert(policy_key.clone(), policy.clone());
        } else {
            expected.remove(&policy_key);
        }
        if expected.len() > 32 {
            self.state.ownership.abort(&change.0)?;
            return Ok(Some(rejected("policy_capacity_exhausted")));
        }
        self.state.pending_policies = Some(expected);
        self.checkpoint()?;
        let id = match self.send(change.1) {
            Ok(id) => id,
            Err(error) => {
                self.state.ownership.abort(&change.0)?;
                self.state.pending_policies = None;
                self.checkpoint()?;
                return Ok(Some(rejected(error)));
            }
        };
        record.step = Step::Effect {
            id,
            change: change.0,
        };
        Ok(None)
    }

    fn send(&mut self, mut command: Value) -> Result<u64, &'static str> {
        let id = self.next_id;
        if id >= (1 << 53) {
            return Err("worker_sequence_exhausted");
        }
        command["id"] = json!(id);
        self.worker
            .as_ref()
            .ok_or("worker_stopped")?
            .submit(&command)?;
        self.next_id += 1;
        Ok(id)
    }

    fn receive(&self, id: u64) -> Result<Option<Value>, &'static str> {
        let Some(reply) = self.worker.as_ref().ok_or("worker_stopped")?.poll()? else {
            return Ok(None);
        };
        if reply.get("id").and_then(Value::as_u64) != Some(id) {
            return Err("worker_reply_mismatch");
        }
        if reply.get("ok") != Some(&Value::Bool(true)) {
            return Err("worker_effect_unconfirmed");
        }
        Ok(Some(reply))
    }
}

fn preparing(request: &ProviderRequest) -> bool {
    matches!(
        request.phase,
        LifecyclePhase::SessionPrepare | LifecyclePhase::StreamPrepare
    )
}

fn rejected(reason: &str) -> ProviderResponse {
    ProviderResponse::Rejected {
        reason: reason.into(),
    }
}

fn validate_admission(
    request: &ProviderRequest,
    policy: Option<&Value>,
) -> Result<(), &'static str> {
    api::validate_provider_request(request).map_err(|_| "invalid_request")?;
    if request.operation != api::ProviderOperation::LifecycleCallback {
        return Err("invalid_operation");
    }
    let admitted = request.approved_plan.as_ref().ok_or("missing_admission")?;
    let mut planning = request.clone();
    planning.operation = api::ProviderOperation::ResourcePlan;
    planning.provider_sequence = admitted.revision;
    planning.approved_plan = None;
    planning.admission_id = None;
    planning.plan_revision = None;
    let revision = admitted
        .mutation_domains
        .first()
        .ok_or("missing_mutation_domain")?
        .expected_revision;
    let expected = crate::lifecycle_plan::build(&planning, policy, revision)?;
    if *admitted != expected {
        return Err("admission_mismatch");
    }
    Ok(())
}

fn success(request: &ProviderRequest) -> ProviderResponse {
    let obligations = request
        .approved_plan
        .as_ref()
        .expect("validated admission")
        .obligations
        .clone();
    if matches!(
        request.phase,
        LifecyclePhase::SessionRelease | LifecyclePhase::StreamRelease
    ) {
        ProviderResponse::Cleanup {
            outcomes: obligations
                .into_iter()
                .map(|obligation| CleanupOutcome {
                    obligation_id: obligation.obligation_id,
                    state: CleanupState::Released,
                    reason: None,
                })
                .collect(),
            outputs: vec![],
        }
    } else {
        ProviderResponse::Prepared {
            candidate: None,
            obligations,
            outputs: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        root: PathBuf,
        backend: Backend,
    }
    impl Fixture {
        fn new() -> Self {
            let mut nonce = [0_u8; 16];
            getrandom::fill(&mut nonce).unwrap();
            let root = std::env::temp_dir().join(format!(
                "limiter-lifecycle-{:x}",
                u128::from_le_bytes(nonce)
            ));
            let steam = root.join("steam");
            let tool = steam.join("steamapps/common/ProtonFixture");
            std::fs::create_dir_all(&tool).unwrap();
            std::fs::write(tool.join("proton"), b"fixture").unwrap();
            std::fs::write(
                tool.join("user_settings.sample.py"),
                b"user_settings = {}\n",
            )
            .unwrap();
            let mut backend = Backend::new(Some(root.clone()), vec![steam]);
            backend.initialize().unwrap();
            Self { backend, root }
        }

        fn run(&mut self, request: &ProviderRequest, policy: Option<Value>) -> ProviderResponse {
            let ProviderResponse::Pending { receipt_id } = self.backend.begin(request, policy)
            else {
                panic!("callback not admitted")
            };
            let status = ProviderStatusRequest {
                provider_sequence: request.provider_sequence,
                operation_id: request.operation_id.clone(),
                transition_id: request.transition_id.clone(),
                receipt_id,
            };
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                self.backend.advance();
                let response = self.backend.status(&status);
                if !matches!(response, ProviderResponse::Pending { .. }) {
                    api::validate_provider_response(request, &response).unwrap();
                    return response;
                }
                assert!(Instant::now() < deadline, "worker did not settle");
                std::thread::sleep(Duration::from_millis(2));
            }
        }

        fn policies(&self) -> Vec<Value> {
            let bytes = match std::fs::read(self.root.join("amaterasu/frame-limiter/active.json")) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return vec![],
                Err(error) => panic!("cannot inspect policy: {error}"),
            };
            let state: Value = serde_json::from_slice(&bytes).unwrap();
            state["policies"].as_array().unwrap().clone()
        }

        fn restart(&mut self) {
            self.backend.worker = None;
            self.backend = Backend::new(None, vec![]);
            self.backend = Backend::configured(&json!({
                "proton_runtime_directory":self.root,
                "proton_state_directory":self.root,
                "proton_steam_roots":[self.root.join("steam")]
            }))
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.backend.is_recovering() {
                self.backend.advance();
                assert!(Instant::now() < deadline, "recovery did not settle");
                std::thread::sleep(Duration::from_millis(2));
            }
        }

        fn wait_for_effect(&mut self) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let receipt = self.backend.queue.front().expect("queued operation");
                if matches!(self.backend.records[receipt].step, Step::Effect { .. }) {
                    break;
                }
                self.backend.advance();
                assert!(Instant::now() < deadline, "effect not submitted");
                std::thread::sleep(Duration::from_millis(2));
            }
            // Stop advancing the Rust side: simulate death before it consumes
            // the worker's successful reply and commits the ownership change.
            loop {
                if self
                    .backend
                    .worker
                    .as_ref()
                    .unwrap()
                    .poll()
                    .unwrap()
                    .is_some()
                {
                    break;
                }
                assert!(Instant::now() < deadline, "worker effect did not settle");
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.backend.worker = None;
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn policy(rate: u32) -> Value {
        json!({"app_id":null,"provider":"mangohud-proton","limit_millihz":rate,
            "preset":"custom","method":"late","graph":false})
    }

    fn status_request(request: &ProviderRequest) -> ProviderStatusRequest {
        ProviderStatusRequest {
            provider_sequence: request.provider_sequence,
            operation_id: request.operation_id.clone(),
            transition_id: request.transition_id.clone(),
            receipt_id: receipt_id(request),
        }
    }

    #[test]
    fn idle_worker_crash_is_detected_and_recovered_without_replaying_preparation() {
        let mut fixture = Fixture::new();
        let policy = policy(60000);
        let prepare = request(&fixture.backend, 1, None, false, Some(&policy));
        fixture.run(&prepare, Some(policy));
        let revision = fixture.backend.state.revision;
        fixture.backend.worker.as_mut().unwrap().crash_for_test();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            fixture.backend.advance();
            if fixture.backend.state.revision > revision && !fixture.backend.is_recovering() {
                break;
            }
            assert!(Instant::now() < deadline, "worker did not recover");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(!fixture.backend.failed);
        assert!(fixture.policies().is_empty());
        assert!(matches!(
            fixture.backend.status(&status_request(&prepare)),
            ProviderResponse::RecoveryRequired { .. }
        ));
        let release = request(&fixture.backend, 2, None, true, None);
        assert!(matches!(
            fixture.run(&release, None),
            ProviderResponse::Cleanup { .. }
        ));
    }

    #[test]
    fn worker_crash_with_an_unconsumed_reply_retires_all_queued_receipts() {
        let mut fixture = Fixture::new();
        let policy = policy(60000);
        let prepare = request(&fixture.backend, 1, None, false, Some(&policy));
        let queued = request(&fixture.backend, 2, Some("queued"), false, Some(&policy));
        fixture.backend.begin(&prepare, Some(policy.clone()));
        fixture.backend.begin(&queued, Some(policy));
        fixture.wait_for_effect();
        fixture.backend.worker.as_mut().unwrap().crash_for_test();
        let revision = fixture.backend.state.revision;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            fixture.backend.advance();
            if fixture.backend.state.revision > revision && !fixture.backend.is_recovering() {
                break;
            }
            assert!(Instant::now() < deadline, "worker did not recover");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(!fixture.backend.failed);
        assert!(fixture.backend.queue.is_empty());
        assert!(fixture.policies().is_empty());
        for request in [prepare, queued] {
            assert!(matches!(
                fixture.backend.status(&status_request(&request)),
                ProviderResponse::RecoveryRequired { .. }
            ));
        }
    }

    #[test]
    fn restart_retires_owned_policy_and_preserves_cleanup_and_new_stream_generations() {
        let mut fixture = Fixture::new();
        let policy = policy(60000);
        let session = request(&fixture.backend, 1, None, false, Some(&policy));
        assert!(matches!(
            fixture.run(&session, Some(policy.clone())),
            ProviderResponse::Prepared { .. }
        ));
        let stream = request(&fixture.backend, 2, Some("first"), false, Some(&policy));
        fixture.run(&stream, Some(policy.clone()));
        let original_owner = fixture.backend.state.owner_id.clone();
        let old_revision = fixture.backend.state.revision;
        fixture.restart();
        assert!(!fixture.backend.failed);
        assert_eq!(fixture.backend.state.owner_id, original_owner);
        assert!(fixture.backend.state.revision > old_revision);
        assert!(fixture.policies().is_empty());
        assert!(fixture.backend.owns_target(&stream.target));
        assert!(matches!(
            fixture.backend.status(&status_request(&stream)),
            ProviderResponse::RecoveryRequired { .. }
        ));
        assert!(matches!(
            fixture.backend.begin(&stream, Some(policy.clone())),
            ProviderResponse::RecoveryRequired { .. }
        ));
        let stop = request(&fixture.backend, 3, Some("first"), true, None);
        assert!(matches!(
            fixture.run(&stop, None),
            ProviderResponse::Cleanup { .. }
        ));
        let resume = request(&fixture.backend, 4, Some("next"), false, Some(&policy));
        assert!(matches!(
            fixture.run(&resume, Some(policy.clone())),
            ProviderResponse::Prepared { .. }
        ));
        let stale = request(&fixture.backend, 5, Some("first"), true, None);
        assert!(matches!(
            fixture.run(&stale, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(fixture.policies(), vec![policy]);
    }

    #[test]
    fn restart_resolves_preparation_before_and_after_worker_effect_without_replaying_it() {
        for submit_effect in [false, true] {
            let mut fixture = Fixture::new();
            let policy = policy(59940);
            let prepare = request(&fixture.backend, 1, None, false, Some(&policy));
            assert!(matches!(
                fixture.backend.begin(&prepare, Some(policy)),
                ProviderResponse::Pending { .. }
            ));
            if submit_effect {
                fixture.wait_for_effect();
                assert!(!fixture.policies().is_empty());
            }
            fixture.restart();
            assert!(!fixture.backend.failed);
            assert!(fixture.policies().is_empty());
            assert!(matches!(
                fixture.backend.status(&status_request(&prepare)),
                ProviderResponse::RecoveryRequired { .. }
            ));
            let release = request(&fixture.backend, 2, None, true, None);
            assert!(matches!(
                fixture.run(&release, None),
                ProviderResponse::Cleanup { .. }
            ));
        }
    }

    #[test]
    fn restart_confirms_pending_cleanup_only_after_owned_policy_is_absent() {
        let mut fixture = Fixture::new();
        let original = policy(60000);
        let prepare = request(&fixture.backend, 1, None, false, Some(&original));
        fixture.run(&prepare, Some(original));
        let release = request(&fixture.backend, 2, None, true, None);
        fixture.backend.begin(&release, None);
        fixture.wait_for_effect();
        fixture.restart();
        assert!(!fixture.backend.failed);
        assert!(fixture.policies().is_empty());
        assert!(matches!(
            fixture.backend.status(&status_request(&release)),
            ProviderResponse::Cleanup { .. }
        ));
        assert!(matches!(
            fixture.backend.begin(&release, None),
            ProviderResponse::Cleanup { .. }
        ));
        let late_policy = policy(120000);
        let late = request(
            &fixture.backend,
            3,
            Some("after-end"),
            false,
            Some(&late_policy),
        );
        assert_eq!(
            fixture.run(&late, Some(late_policy)),
            rejected("retired_session")
        );
        assert!(fixture.policies().is_empty());
    }

    #[test]
    fn recovery_preserves_a_foreign_policy_and_does_not_claim_prior_preparation() {
        for foreign_owner in [false, true] {
            let mut fixture = Fixture::new();
            let policy = policy(60000);
            let prepare = request(&fixture.backend, 1, None, false, Some(&policy));
            fixture.run(&prepare, Some(policy));
            fixture.backend.worker = None;
            let path = fixture.root.join("amaterasu/frame-limiter/active.json");
            let mut foreign: Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            if foreign_owner {
                foreign["owner_id"] = json!("different-owner");
            } else {
                foreign["policies"][0]["limit_millihz"] = json!(144000);
            }
            let bytes = serde_json::to_vec(&foreign).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            fixture.restart();
            assert!(fixture.backend.failed);
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert!(matches!(
                fixture.backend.status(&status_request(&prepare)),
                ProviderResponse::RecoveryRequired { .. }
            ));
        }
    }

    #[test]
    fn externally_changed_journal_blocks_effects_and_second_owner_cannot_open_it() {
        let mut fixture = Fixture::new();
        assert!(Backend::configured(&json!({"proton_runtime_directory":fixture.root,"proton_state_directory":fixture.root})).is_err());
        let path = fixture.root.join("amaterasu/frame-limiter/lifecycle.json");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.push(b' ');
        std::fs::write(&path, &bytes).unwrap();
        let policy = policy(60000);
        let prepare = request(&fixture.backend, 1, None, false, Some(&policy));
        assert!(matches!(
            fixture.backend.begin(&prepare, Some(policy)),
            ProviderResponse::Rejected { .. }
        ));
        assert!(fixture.backend.worker.is_none());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    fn request(
        backend: &Backend,
        sequence: u64,
        stream: Option<&str>,
        release: bool,
        policy: Option<&Value>,
    ) -> ProviderRequest {
        let target = match stream {
            Some(id) => {
                json!({"kind":"stream","host_epoch":"epoch","session_id":"session","stream_id":id,"generation":1})
            }
            None => {
                json!({"kind":"session","host_epoch":"epoch","session_id":"session","generation":1})
            }
        };
        let phase = match (stream.is_some(), release) {
            (false, false) => "session.prepare",
            (false, true) => "session.release",
            (true, false) => "stream.prepare",
            (true, true) => "stream.release",
        };
        let mut request: ProviderRequest = serde_json::from_value(json!({"provider_sequence":sequence,"operation":"resource_plan","version":1,
            "transition_id":format!("transition-{sequence}"),"operation_id":format!("plan-{sequence}"),"target":target,"phase":phase,
            "settings_revision":"revision","settings":{},"intent":null,"reason":null,"requested_video":null,
            "consumer_requirements":{"execution_domain":"seat","capture_providers":["capture"],"selector_schemas":["selector/1"]},
            "remaining_ms":5000,"plan_revision":null,"admission_id":null,"approved_plan":null})).unwrap();
        let plan = backend.plan(&request, policy).unwrap();
        request.operation = api::ProviderOperation::LifecycleCallback;
        request.operation_id = format!("callback-{sequence}");
        request.plan_revision = Some(plan.revision);
        request.admission_id = Some(format!("admitted-{sequence}"));
        request.approved_plan = Some(plan);
        request
    }

    #[test]
    fn admitted_callbacks_install_apply_resume_and_retire_with_receipts() {
        let mut fixture = Fixture::new();
        let first = policy(59940);
        let prepare = request(&fixture.backend, 1, None, false, Some(&first));
        assert!(matches!(
            fixture.run(&prepare, Some(first.clone())),
            ProviderResponse::Prepared { .. }
        ));
        assert_eq!(fixture.policies(), vec![first.clone()]);
        let hook = fixture
            .root
            .join("steam/steamapps/common/ProtonFixture/user_settings.py");
        assert!(
            std::fs::read_to_string(hook)
                .unwrap()
                .contains("BEGIN Amaterasu frame limiter")
        );
        // Exact retries return the retained outcome without another worker effect.
        assert!(matches!(
            fixture.backend.begin(&prepare, Some(first.clone())),
            ProviderResponse::Prepared { .. }
        ));
        let stream = request(&fixture.backend, 2, Some("first"), false, Some(&first));
        assert!(matches!(
            fixture.run(&stream, Some(first.clone())),
            ProviderResponse::Prepared { .. }
        ));
        let stop = request(&fixture.backend, 3, Some("first"), true, None);
        assert!(matches!(
            fixture.run(&stop, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(fixture.policies(), vec![first.clone()]);
        let resumed = policy(120000);
        let resume = request(&fixture.backend, 4, Some("resumed"), false, Some(&resumed));
        assert!(matches!(
            fixture.run(&resume, Some(resumed.clone())),
            ProviderResponse::Prepared { .. }
        ));
        let late = request(&fixture.backend, 5, Some("first"), true, None);
        assert!(matches!(
            fixture.run(&late, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(fixture.policies(), vec![first.clone(), first]);
        let stop = request(&fixture.backend, 6, Some("resumed"), true, None);
        assert!(matches!(
            fixture.run(&stop, None),
            ProviderResponse::Cleanup { .. }
        ));
        let end = request(&fixture.backend, 7, None, true, None);
        assert!(matches!(
            fixture.run(&end, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert!(fixture.policies().is_empty());
    }

    #[test]
    fn paused_application_retains_original_policy_for_fresh_proton_launches() {
        for session_first in [false, true] {
            let mut fixture = Fixture::new();
            let mut root_policy = policy(59940);
            root_policy["provider"] = json!("proton");
            let prepare = request(&fixture.backend, 1, None, false, Some(&root_policy));
            assert!(matches!(
                fixture.run(&prepare, Some(root_policy.clone())),
                ProviderResponse::Prepared { .. }
            ));
            let stream = request(
                &fixture.backend,
                2,
                Some("first"),
                false,
                Some(&root_policy),
            );
            assert!(matches!(
                fixture.run(&stream, Some(root_policy.clone())),
                ProviderResponse::Prepared { .. }
            ));
            let mut pause = request(&fixture.backend, 3, Some("first"), true, None);
            pause.reason = Some(api::ReleaseReason::Pause);
            assert!(matches!(
                fixture.run(&pause, None),
                ProviderResponse::Cleanup { .. }
            ));
            let launch = crate::proton_worker::apply_hook_for_test(&fixture.root);
            assert_eq!(
                launch["applied"], true,
                "paused application lost its launch policy"
            );
            assert_eq!(launch["environment"]["DXVK_FRAME_RATE"], "60");
            assert_eq!(launch["environment"]["VKD3D_FRAME_RATE"], "59.94");

            let changed_client = policy(120000);
            let resume = request(
                &fixture.backend,
                4,
                Some("resumed"),
                false,
                Some(&changed_client),
            );
            assert_eq!(
                resume.approved_plan.as_ref().unwrap().constraints["policy"],
                root_policy
            );
            assert_eq!(
                resume.approved_plan.as_ref().unwrap().constraints["launch_environment"]["contribution"]
                    ["edits"]["VKD3D_FRAME_RATE"],
                "59.94"
            );
            assert!(matches!(
                fixture.run(&resume, Some(changed_client.clone())),
                ProviderResponse::Prepared { .. }
            ));
            let late = request(&fixture.backend, 5, Some("first"), true, None);
            assert!(matches!(
                fixture.run(&late, None),
                ProviderResponse::Cleanup { .. }
            ));
            let launch = crate::proton_worker::apply_hook_for_test(&fixture.root);
            assert_eq!(launch["environment"]["VKD3D_FRAME_RATE"], "59.94");

            let (first_target, last_target) = if session_first {
                (None, Some("resumed"))
            } else {
                (Some("resumed"), None)
            };
            let mut first_end = request(&fixture.backend, 6, first_target, true, None);
            first_end.reason = Some(api::ReleaseReason::End);
            assert!(matches!(
                fixture.run(&first_end, None),
                ProviderResponse::Cleanup { .. }
            ));
            if session_first {
                assert!(
                    matches!(
                        fixture.backend.begin(&resume, Some(changed_client.clone())),
                        ProviderResponse::Prepared { .. }
                    ),
                    "root release changed an exact stream preparation receipt"
                );
            }
            assert_eq!(
                crate::proton_worker::apply_hook_for_test(&fixture.root)["environment"]["VKD3D_FRAME_RATE"],
                "59.94",
                "one departing owner removed a peer's policy"
            );
            let mut last_end = request(&fixture.backend, 7, last_target, true, None);
            last_end.reason = Some(api::ReleaseReason::End);
            assert!(matches!(
                fixture.run(&last_end, None),
                ProviderResponse::Cleanup { .. }
            ));
            assert_eq!(
                crate::proton_worker::apply_hook_for_test(&fixture.root)["applied"],
                false
            );
            assert!(fixture.policies().is_empty());
        }
    }

    #[test]
    fn root_and_stream_entries_share_capacity_without_retiring_existing_policies() {
        fn group_request(
            backend: &Backend,
            sequence: u64,
            group: usize,
            stream: Option<&str>,
            release: bool,
            policy: Option<&Value>,
        ) -> ProviderRequest {
            let mut request = request(backend, sequence, stream, release, policy);
            match &mut request.target {
                api::LifecycleTarget::Session { session_id, .. }
                | api::LifecycleTarget::Stream { session_id, .. } => {
                    *session_id = format!("group-{group}");
                }
                _ => unreachable!(),
            }
            request.operation = api::ProviderOperation::ResourcePlan;
            request.operation_id = format!("plan-{sequence}");
            request.plan_revision = None;
            request.admission_id = None;
            request.approved_plan = None;
            let plan = backend.plan(&request, policy).unwrap();
            request.operation = api::ProviderOperation::LifecycleCallback;
            request.operation_id = format!("callback-{sequence}");
            request.plan_revision = Some(plan.revision);
            request.admission_id = Some(format!("admitted-{sequence}"));
            request.approved_plan = Some(plan);
            request
        }

        let mut fixture = Fixture::new();
        let first = policy(60000);
        for group in 0..32 {
            let prepare = group_request(
                &fixture.backend,
                group as u64 + 1,
                group,
                None,
                false,
                Some(&first),
            );
            assert!(matches!(
                fixture.run(&prepare, Some(first.clone())),
                ProviderResponse::Prepared { .. }
            ));
        }
        let existing = fixture.policies();
        assert_eq!(existing.len(), 32);
        let stream = group_request(&fixture.backend, 33, 0, Some("extra"), false, Some(&first));
        assert_eq!(
            fixture.run(&stream, Some(first)),
            rejected("policy_capacity_exhausted")
        );
        assert_eq!(fixture.policies(), existing);
        assert!(!fixture.backend.failed);
        let release = group_request(&fixture.backend, 34, 0, None, true, None);
        assert!(matches!(
            fixture.run(&release, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(fixture.policies().len(), 31);
    }

    #[test]
    fn shutdown_announcement_preserves_policy_and_serves_declared_consumers() {
        let mut fixture = Fixture::new();
        let first = policy(60000);
        let prepare = request(&fixture.backend, 1, None, false, Some(&first));
        assert!(matches!(
            fixture.run(&prepare, Some(first.clone())),
            ProviderResponse::Prepared { .. }
        ));
        let path = fixture.root.join("amaterasu/frame-limiter/active.json");
        let policy_bytes = std::fs::read(&path).unwrap();
        let state_path = fixture.root.join("amaterasu/frame-limiter/lifecycle.json");
        let state_bytes = std::fs::read(&state_path).unwrap();
        let expired = Instant::now() - Duration::from_millis(1);
        fixture.backend.prepare_shutdown(expired);
        fixture
            .backend
            .prepare_shutdown(Instant::now() + Duration::from_secs(300));
        for _ in 0..3 {
            fixture.backend.advance();
        }
        assert_eq!(fixture.backend.shutdown.deadline(), Some(expired));
        assert!(!fixture.backend.shutdown.started());
        assert_eq!(std::fs::read(&path).unwrap(), policy_bytes);
        assert_eq!(std::fs::read(&state_path).unwrap(), state_bytes);
        assert_eq!(
            fixture.backend.worker.as_mut().unwrap().is_running(),
            Ok(true)
        );

        // Announcing host shutdown does not cut off a declared consumer's
        // already-owned lifecycle operations before the dependency drain.
        let stream = request(&fixture.backend, 2, Some("first"), false, Some(&first));
        assert!(matches!(
            fixture.run(&stream, Some(first)),
            ProviderResponse::Prepared { .. }
        ));
        let release = request(&fixture.backend, 3, Some("first"), true, None);
        assert!(matches!(
            fixture.run(&release, None),
            ProviderResponse::Cleanup { .. }
        ));
    }

    #[test]
    fn provider_quiesce_waits_for_eof_policy_retirement_before_replacing_receipts() {
        let mut fixture = Fixture::new();
        let first = policy(60000);
        let prepare = request(&fixture.backend, 1, None, false, Some(&first));
        fixture.backend.begin(&prepare, Some(first));
        fixture.wait_for_effect();
        assert!(!fixture.policies().is_empty());
        fixture
            .backend
            .prepare_shutdown(Instant::now() + Duration::from_secs(5));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if fixture.backend.quiesce().unwrap() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "worker retirement did not settle"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(fixture.policies().is_empty());
        assert!(fixture.backend.worker.is_none());
        assert!(fixture.backend.state.worker_policies.is_empty());
        assert!(fixture.backend.state.pending_policies.is_none());
        assert!(matches!(
            fixture.backend.status(&status_request(&prepare)),
            ProviderResponse::RecoveryRequired { .. }
        ));
        assert_eq!(fixture.backend.quiesce(), Ok(true));
    }

    #[test]
    fn shutdown_retains_retirement_proof_across_a_failed_journal_write() {
        let mut fixture = Fixture::new();
        let first = policy(60000);
        let prepare = request(&fixture.backend, 1, None, false, Some(&first));
        fixture.run(&prepare, Some(first));
        let deadline = Instant::now() + Duration::from_secs(5);
        fixture.backend.prepare_shutdown(deadline);
        while !fixture.backend.worker.as_mut().unwrap().quiesce().unwrap() {
            assert!(Instant::now() < deadline, "worker did not retire");
            std::thread::sleep(Duration::from_millis(2));
        }
        fixture
            .backend
            .journal
            .as_mut()
            .unwrap()
            .fail_next_save_for_test();
        assert_eq!(
            fixture.backend.quiesce(),
            Err("injected_journal_write_failure")
        );
        assert!(
            fixture.backend.worker.is_some(),
            "exact exit proof was lost"
        );
        assert!(!fixture.backend.state.worker_policies.is_empty());
        // Saving proven retirement does not start new native work and remains
        // valid after the original host budget has expired.
        fixture
            .backend
            .prepare_shutdown(Instant::now() - Duration::from_millis(1));
        assert_eq!(fixture.backend.quiesce(), Ok(true));
        assert!(fixture.backend.worker.is_none());
        assert!(fixture.backend.state.worker_policies.is_empty());
    }

    #[test]
    fn a_late_worker_inherits_the_first_announced_shutdown_deadline() {
        let mut fixture = Fixture::new();
        let expired = Instant::now() - Duration::from_millis(1);
        fixture.backend.prepare_shutdown(expired);
        fixture
            .backend
            .prepare_shutdown(Instant::now() + Duration::from_secs(300));
        assert!(fixture.backend.worker.is_none());
        let first = policy(60000);
        let prepare = request(&fixture.backend, 1, None, false, Some(&first));
        assert!(matches!(
            fixture.run(&prepare, Some(first)),
            ProviderResponse::Prepared { .. }
        ));
        assert_eq!(
            fixture
                .backend
                .worker
                .as_ref()
                .unwrap()
                .shutdown_deadline_for_test(),
            Some(expired)
        );
        assert!(!fixture.policies().is_empty());
        assert!(!fixture.backend.shutdown.started());
    }

    #[test]
    fn shutdown_does_not_confirm_unexecuted_cleanup_for_an_unknown_target() {
        let mut fixture = Fixture::new();
        let release = request(&fixture.backend, 1, None, true, None);
        assert!(matches!(
            fixture.backend.begin(&release, None),
            ProviderResponse::Pending { .. }
        ));
        assert!(fixture.backend.worker.is_none());
        assert_eq!(fixture.backend.quiesce(), Ok(true));
        assert!(matches!(
            fixture.backend.status(&status_request(&release)),
            ProviderResponse::RecoveryRequired { .. } | ProviderResponse::Rejected { .. }
        ));
    }

    #[test]
    fn altered_admission_and_foreign_status_cannot_authorize_effects() {
        let mut fixture = Fixture::new();
        let first = policy(60000);
        let mut prepare = request(&fixture.backend, 1, None, false, Some(&first));
        prepare.approved_plan.as_mut().unwrap().constraints = json!({"policy":policy(144000)});
        assert_eq!(
            fixture.backend.begin(&prepare, Some(first)),
            ProviderResponse::Rejected {
                reason: "admission_mismatch".into()
            }
        );
        assert!(fixture.backend.worker.is_none());
        assert!(matches!(
            fixture.backend.status(&ProviderStatusRequest {
                provider_sequence: 1,
                operation_id: "foreign".into(),
                transition_id: "transition-1".into(),
                receipt_id: "missing".into()
            }),
            ProviderResponse::RecoveryRequired { .. }
        ));
    }

    #[test]
    fn elapsed_context_budget_cannot_start_a_worker_effect() {
        let mut fixture = Fixture::new();
        let policy = policy(60000);
        let prepare = request(&fixture.backend, 1, None, false, Some(&policy));
        assert_eq!(
            fixture.backend.begin_with_budget(&prepare, Some(policy), 0),
            rejected("callback_expired_before_effect")
        );
        assert!(fixture.backend.worker.is_none());
        assert!(fixture.policies().is_empty());
    }

    #[test]
    fn stale_queued_admission_does_not_replace_or_retire_the_current_policy() {
        let mut fixture = Fixture::new();
        let first = policy(60000);
        let prepare = request(&fixture.backend, 1, None, false, Some(&first));
        let replacement = policy(144000);
        let stale = request(
            &fixture.backend,
            2,
            Some("stale"),
            false,
            Some(&replacement),
        );
        assert!(matches!(
            fixture.backend.begin(&prepare, Some(first.clone())),
            ProviderResponse::Pending { .. }
        ));
        assert!(matches!(
            fixture.backend.begin(&stale, Some(replacement.clone())),
            ProviderResponse::Pending { .. }
        ));
        assert!(matches!(
            fixture.run(&prepare, Some(first.clone())),
            ProviderResponse::Prepared { .. }
        ));
        assert_eq!(
            fixture.run(&stale, Some(replacement)),
            rejected("stale_provider_observation")
        );
        assert_eq!(fixture.policies(), vec![first.clone()]);
        assert!(!fixture.backend.failed);

        let stream = request(&fixture.backend, 3, Some("active"), false, Some(&first));
        assert!(matches!(
            fixture.run(&stream, Some(first.clone())),
            ProviderResponse::Prepared { .. }
        ));
        let root_end = request(&fixture.backend, 4, None, true, None);
        assert!(matches!(
            fixture.run(&root_end, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(fixture.policies(), vec![first]);
        assert!(!fixture.backend.failed);
        let stream_end = request(&fixture.backend, 5, Some("active"), true, None);
        assert!(matches!(
            fixture.run(&stream_end, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert!(fixture.policies().is_empty());
    }

    #[test]
    fn native_mangohud_does_not_require_a_proton_installation() {
        let mut fixture = Fixture::new();
        std::fs::remove_dir_all(fixture.root.join("steam")).unwrap();
        let mut policy = policy(59940);
        policy["provider"] = json!("mangohud");
        let prepare = request(&fixture.backend, 1, None, false, Some(&policy));
        assert!(matches!(
            fixture.run(&prepare, Some(policy)),
            ProviderResponse::Prepared { .. }
        ));
        let release = request(&fixture.backend, 2, None, true, None);
        assert!(matches!(
            fixture.run(&release, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert!(fixture.policies().is_empty());
    }
}
