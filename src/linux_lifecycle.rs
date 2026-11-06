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
        crate::lifecycle_plan::build(request, policy, self.state.revision)
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
        }
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
        if let Err(reason) = validate_admission(request, policy.as_ref()) {
            return reject(reason);
        }
        if remaining_ms == 0 {
            return reject("callback_expired_before_effect");
        }
        if let Err(reason) = self.initialize() {
            return reject(reason);
        }
        if self.failed && !self.recovering {
            return ProviderResponse::RecoveryRequired {
                reason: "worker_recovery_required".into(),
            };
        }
        let receipt = receipt_id(request);
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

    pub(crate) fn advance(&mut self) {
        if self.queue.is_empty()
            && self.ready
            && self
                .worker
                .as_mut()
                .is_some_and(|worker| worker.is_running() != Ok(true))
        {
            self.worker = None;
            self.ready = false;
            self.failed = true;
            self.start_recovery();
        }
        if self.recovering {
            if self.recover_worker().is_err() {
                self.worker = None;
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
                self.worker = None;
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
                self.worker = None;
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
                self.state.revision = self
                    .state
                    .revision
                    .checked_add(1)
                    .ok_or("provider_revision_exhausted")?;
                if record.request.phase == LifecyclePhase::SessionRelease {
                    self.state
                        .ownership
                        .finish_session(&record.request.target)?;
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
            let command = json!({"operation":"set","session":change.session,
                "expected_revision":change.expected_revision,"revision":change.new_revision,"policy":policy});
            (change, command)
        } else {
            let release = match self.state.ownership.release(&record.request.target) {
                Ok(change) => change,
                Err(reason) => return Ok(Some(rejected(reason))),
            };
            let Some(change) = release else {
                if record.request.phase == LifecyclePhase::SessionRelease
                    && let Err(reason) = self.state.ownership.finish_session(&record.request.target)
                {
                    return Ok(Some(rejected(reason)));
                }
                return Ok(Some(success(&record.request)));
            };
            let command = json!({"operation":"remove","session":change.session,"expected_revision":change.expected_revision});
            (change, command)
        };
        let mut expected = self.state.worker_policies.clone();
        if let Some(policy) = &record.policy {
            expected.insert(change.0.session.clone(), policy.clone());
        } else {
            expected.remove(&change.0.session);
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
        let policy = policy(60000);
        let prepare = request(&fixture.backend, 1, None, false, Some(&policy));
        fixture.run(&prepare, Some(policy));
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
            fixture.run(&stream, Some(first)),
            ProviderResponse::Prepared { .. }
        ));
        let stop = request(&fixture.backend, 3, Some("first"), true, None);
        assert!(matches!(
            fixture.run(&stop, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert!(fixture.policies().is_empty());
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
        assert_eq!(fixture.policies(), vec![resumed]);
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
        let premature_end = request(&fixture.backend, 4, None, true, None);
        assert_eq!(
            fixture.run(&premature_end, None),
            rejected("session_not_retired")
        );
        assert_eq!(fixture.policies(), vec![first]);
        assert!(!fixture.backend.failed);
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
