//! Windows lifecycle effects. The plugin owns both native lease managers;
//! no launch or stream consumer selects or calls a native limiter backend.
pub(crate) mod ownership;
use crate::lease::{
    ApplyOutcome, ApplyPreflight, FrameLimitProvider, LeaseApplyRequest, LeaseManager,
    RestoreOutcome,
};
use crate::nvcp::{
    self, DriverSettings,
    lease::{Manager, Outcome},
};
use crate::windows_policy::Policy;
use amaterasu_module_sdk::extension_api::{
    self as api, CleanupOutcome, CleanupState, LifecyclePhase, LifecycleTarget, ProviderOperation,
    ProviderRequest, ProviderResponse,
};
#[cfg(test)]
use amaterasu_module_sdk::extension_api::{ProviderStatusRequest, ResourcePlan};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, VecDeque},
    rc::Rc,
};

// A broker principal cannot contain ':', so compatibility RPC callers cannot
// acquire this internal owner identity.
const OWNER: &str = ":lifecycle";
const MAX_COMPLETED: usize = 256;

/// The admitted plan freezes a resumed stream's inherited policy. Use it for
/// receipt identity even after its application root has subsequently retired.
pub(crate) fn callback_policy(
    request: &ProviderRequest,
    supplied: Option<Policy>,
) -> Result<Option<Policy>, &'static str> {
    if !matches!(
        request.phase,
        LifecyclePhase::SessionPrepare | LifecyclePhase::StreamPrepare
    ) || request.operation != ProviderOperation::LifecycleCallback
    {
        return Ok(supplied);
    }
    let value = request
        .approved_plan
        .as_ref()
        .and_then(|plan| plan.constraints.get("policy"))
        .ok_or("missing_admitted_policy")?;
    serde_json::from_value(value.clone())
        .map(Some)
        .map_err(|_| "invalid_admitted_policy")
}

pub(crate) struct Backend<P, N = nvcp::Driver> {
    leases: Rc<RefCell<LeaseManager<P>>>,
    driver: Manager<N>,
    completed: BTreeMap<String, (ProviderRequest, Option<Policy>, ProviderResponse)>,
    order: VecDeque<String>,
    retiring_sessions: BTreeSet<String>,
}

fn hash(value: &impl serde::Serialize) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("serializable identity"))
    )
}

pub(crate) fn target_identity(target: &LifecycleTarget) -> Result<(String, String), &'static str> {
    let (epoch, session, phase) = match target {
        LifecycleTarget::Session {
            host_epoch,
            session_id,
            ..
        } => (host_epoch, session_id, "s"),
        LifecycleTarget::Stream {
            host_epoch,
            session_id,
            ..
        } => (host_epoch, session_id, "t"),
        _ => return Err("invalid_target"),
    };
    let group = format!("lc.{}.", &hash(&(epoch, session))[..32]);
    let identity = format!("{group}{phase}.{}", &hash(target)[..48]);
    Ok((group, identity))
}

impl<P: FrameLimitProvider> Backend<P> {
    #[cfg(windows)]
    pub(crate) fn configured_at(
        leases: Rc<RefCell<LeaseManager<P>>>,
        journal: &std::path::Path,
    ) -> Result<Self, String> {
        let mut driver = Manager::open(nvcp::Driver::new(), journal)?;
        // Keep unresolved driver ownership in the manager; no later provider
        // choice may silently bypass it.
        driver.recover();
        Ok(Self {
            leases,
            driver,
            completed: BTreeMap::new(),
            order: VecDeque::new(),
            retiring_sessions: BTreeSet::new(),
        })
    }
    #[cfg(test)]
    pub(crate) fn new(
        leases: Rc<RefCell<LeaseManager<P>>>,
    ) -> Backend<P, nvcp::testing::Unavailable> {
        Backend::with_driver(leases, Manager::in_memory(nvcp::testing::Unavailable))
    }
}

impl<P: FrameLimitProvider, N: DriverSettings> Backend<P, N> {
    /// Restore exact journal-owned effects, including compatibility RPC leases.
    /// Native failures leave those records available to recovery/retry.
    pub(crate) fn shutdown(&mut self) -> Result<(), &'static str> {
        let mut roots = self.root_state()?;
        if let Some(root) = &mut roots.root {
            root.application = false;
            root.releasing.extend(std::mem::take(&mut root.streams));
            root.phase = ownership::Phase::Restoring;
            roots.save(&mut self.leases.borrow_mut())?;
            self.restore_root(&mut roots)?;
        }
        let mut failure = None;
        if let Some((owner, target)) = self
            .driver
            .active_target()
            .map(|(owner, target)| (owner.to_owned(), target.to_owned()))
            && !matches!(
                self.driver.restore(&owner, &target),
                Outcome::Restored | Outcome::NotFound
            )
        {
            failure = Some("native_worker_driver_cleanup_failed");
        }
        let records = self.leases.borrow().records();
        for record in records {
            if !matches!(
                self.leases
                    .borrow_mut()
                    .restore(&record.owner, None, Some(&record.lease_id)),
                RestoreOutcome::Restored(_) | RestoreOutcome::NotFound
            ) {
                failure.get_or_insert("native_worker_rtss_cleanup_failed");
            }
        }
        if let Err(error) = self.leases.borrow_mut().retire_provider_if_idle() {
            failure.get_or_insert(error.diagnostic());
        }
        failure.map_or(Ok(()), Err)
    }

    #[cfg(windows)]
    pub(crate) fn snapshot(&self) -> Result<(u64, Vec<String>), &'static str> {
        let leases = self.leases.borrow();
        let revision = leases
            .revision()
            .checked_add(self.driver.revision())
            .ok_or("provider_revision_exhausted")?;
        let mut targets: Vec<_> = leases
            .records()
            .iter()
            .filter(|lease| lease.owner == OWNER)
            .map(|lease| lease.session_id.clone())
            .chain(self.driver.targets(OWNER))
            .collect();
        if let Some(root) = self.root_state()?.root {
            targets.push(target_identity(&root.target)?.1);
            targets.extend(root.streams);
            targets.extend(root.releasing);
        }
        targets.sort();
        targets.dedup();
        Ok((revision, targets))
    }

    #[cfg(windows)]
    pub(crate) fn snapshot_root(&self) -> Result<Option<ownership::Root>, &'static str> {
        Ok(self.root_state()?.root)
    }
    #[cfg(test)]
    fn with_driver(leases: Rc<RefCell<LeaseManager<P>>>, driver: Manager<N>) -> Self {
        Self {
            leases,
            driver,
            completed: BTreeMap::new(),
            order: VecDeque::new(),
            retiring_sessions: BTreeSet::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn owns_target(&self, target: &LifecycleTarget) -> bool {
        if self.root_state().is_ok_and(|state| {
            state
                .root
                .as_ref()
                .is_some_and(|root| self.root_owns(root, target))
        }) {
            return true;
        }
        target_identity(target).is_ok_and(|(_, identity)| {
            self.leases
                .borrow()
                .records()
                .iter()
                .any(|lease| lease.owner == OWNER && lease.session_id == identity)
                || self.driver.owns(OWNER, &identity)
        })
    }

    #[cfg(test)]
    pub(crate) fn plan(
        &self,
        request: &ProviderRequest,
        policy: Option<&Policy>,
    ) -> Result<ResourcePlan, &'static str> {
        let retained = if request.phase == LifecyclePhase::StreamPrepare {
            self.retained_policy(&request.target)?
        } else {
            None
        };
        let policy = retained.as_ref().or(policy);
        let value = policy
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| "invalid_policy")?;
        crate::lifecycle_plan::build_native(
            request,
            value.as_ref(),
            self.leases
                .borrow()
                .revision()
                .checked_add(self.driver.revision())
                .ok_or("provider_revision_exhausted")?,
        )
    }

    pub(crate) fn begin(
        &mut self,
        request: &ProviderRequest,
        policy: Option<Policy>,
    ) -> ProviderResponse {
        let supplied = policy.clone();
        let policy = match callback_policy(request, policy) {
            Ok(policy) => policy,
            Err(reason) => {
                return ProviderResponse::RecoveryRequired {
                    reason: reason.into(),
                };
            }
        };
        let identity = hash(&(
            &request.transition_id,
            &request.operation_id,
            request.provider_sequence,
        ));
        if let Some((original, original_policy, response)) = self.completed.get(&identity) {
            return if original == request && original_policy == &policy {
                response.clone()
            } else {
                ProviderResponse::Rejected {
                    reason: "operation_identity_conflict".into(),
                }
            };
        }
        if supplied
            .as_ref()
            .is_some_and(|supplied| policy.as_ref() != Some(supplied))
            && !(request.phase == LifecyclePhase::StreamPrepare
                && self
                    .retained_policy(&request.target)
                    .ok()
                    .flatten()
                    .as_ref()
                    == policy.as_ref())
        {
            return ProviderResponse::RecoveryRequired {
                reason: "admission_mismatch".into(),
            };
        }
        if supplied.is_none()
            && policy.is_some()
            && self.root_state().is_ok_and(|state| state.root.is_none())
        {
            return ProviderResponse::RecoveryRequired {
                reason: "missing_policy".into(),
            };
        }
        let result = self.apply(request, policy.clone());
        let response = result.unwrap_or_else(|reason| ProviderResponse::RecoveryRequired {
            reason: reason.into(),
        });
        self.completed.insert(
            identity.clone(),
            (request.clone(), policy, response.clone()),
        );
        self.order.push_back(identity);
        while self.order.len() > MAX_COMPLETED {
            if let Some(oldest) = self.order.pop_front() {
                self.completed.remove(&oldest);
            }
        }
        response
    }

    fn apply_native(
        &mut self,
        request: &ProviderRequest,
        policy: Option<Policy>,
    ) -> Result<ProviderResponse, &'static str> {
        api::validate_provider_request(request).map_err(|_| "invalid_request")?;
        if request.operation != ProviderOperation::LifecycleCallback {
            return Err("invalid_operation");
        }
        let admitted = request.approved_plan.as_ref().ok_or("missing_admission")?;
        let mut planning = request.clone();
        planning.operation = ProviderOperation::ResourcePlan;
        planning.provider_sequence = admitted.revision;
        planning.approved_plan = None;
        planning.admission_id = None;
        planning.plan_revision = None;
        let observed = admitted
            .mutation_domains
            .first()
            .ok_or("missing_mutation_domain")?
            .expected_revision;
        let value = policy
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| "invalid_policy")?;
        if crate::lifecycle_plan::build_native(&planning, value.as_ref(), observed)? != *admitted {
            return Err("admission_mismatch");
        }
        let (group, target) = target_identity(&request.target)?;
        if let Some(policy) = &policy {
            let fingerprint = serde_json::to_string(policy).map_err(|_| "invalid_policy")?;
            let rtss = self
                .leases
                .borrow_mut()
                .preflight_apply(OWNER, &target, &fingerprint);
            let driver = self.driver.verify(OWNER, &target, &fingerprint);
            match rtss {
                ApplyPreflight::AlreadyApplied(_)
                    if driver == Outcome::AlreadyApplied
                        || (driver == Outcome::NotFound
                            && !policy.disable_vsync
                            && !policy.smooth_motion
                            && !self.driver.owns(OWNER, &target)) =>
                {
                    return Ok(success(request));
                }
                ApplyPreflight::Continue => {}
                _ => return Err("native_lease_requires_recovery"),
            }
            if driver == Outcome::AlreadyApplied {
                return Ok(success(request));
            }
            if driver == Outcome::Conflict
                && self
                    .driver
                    .active_target()
                    .is_some_and(|(_, active)| active == target)
            {
                return Err("native_lease_requires_recovery");
            }
            if !matches!(driver, Outcome::NotFound | Outcome::Conflict) {
                return Err("native_lease_requires_recovery");
            }
        }
        if Some(observed)
            != self
                .leases
                .borrow()
                .revision()
                .checked_add(self.driver.revision())
        {
            return Err("stale_provider_observation");
        }
        if let Some(policy) = policy {
            let active = self.leases.borrow().records();
            if active.iter().any(|lease| {
                lease.owner == OWNER
                    && lease.session_id.starts_with(&format!("{group}t."))
                    && lease.session_id != target
            }) {
                return Err("previous_stream_not_retired");
            }
            if self.driver.active_target().is_some_and(|(owner, active)| {
                owner != OWNER || (active != target && !active.starts_with(&format!("{group}s.")))
            }) {
                return Err("previous_driver_policy_not_retired");
            }
            if matches!(request.phase, LifecyclePhase::StreamPrepare) {
                for initial in active.iter().filter(|lease| {
                    lease.owner == OWNER && lease.session_id.starts_with(&format!("{group}s."))
                }) {
                    match self
                        .leases
                        .borrow_mut()
                        .restore(OWNER, None, Some(&initial.lease_id))
                    {
                        RestoreOutcome::Restored(_) => {}
                        _ => return Err("initial_policy_restore_unconfirmed"),
                    }
                }
                if let Some((_, initial)) = self
                    .driver
                    .active_target()
                    .filter(|(_, active)| active.starts_with(&format!("{group}s.")))
                {
                    let initial = initial.to_owned();
                    if self.driver.restore(OWNER, &initial) != Outcome::Restored {
                        return Err("initial_driver_restore_unconfirmed");
                    }
                }
            }
            let fingerprint = serde_json::to_string(&policy).map_err(|_| "invalid_policy")?;
            let try_rtss = policy.driver_limit_millihz.is_some()
                && matches!(
                    policy.provider,
                    crate::windows_policy::Provider::Auto | crate::windows_policy::Provider::Rtss
                );
            let mut rtss_applied = false;
            if try_rtss {
                match self.leases.borrow_mut().apply(LeaseApplyRequest {
                    enable_limiter: true,
                    initialize_profile: true,
                    owner: OWNER,
                    session_id: &target,
                    // The compatibility journal stores a target identity in this field.
                    executable_path: &policy.profile,
                    rtss_install_path: &policy.installation,
                    profile: &policy.profile,
                    request_fingerprint: &fingerprint,
                    desired_profile: policy.values,
                }) {
                    ApplyOutcome::Applied(_) | ApplyOutcome::AlreadyApplied(_) => {
                        rtss_applied = true;
                    }
                    ApplyOutcome::Unavailable(reason)
                        if policy.provider == crate::windows_policy::Provider::Auto
                            || reason == "rtss_disabled_after_stall" => {}
                    ApplyOutcome::Conflict(reason) | ApplyOutcome::Unavailable(reason) => {
                        return Err(reason);
                    }
                    _ => return Err("native_policy_apply_unconfirmed"),
                }
            }
            if !rtss_applied
                && self
                    .leases
                    .borrow()
                    .records()
                    .iter()
                    .any(|lease| lease.owner == OWNER)
            {
                return Err("rtss_ownership_requires_recovery");
            }
            let driver_changes = nvcp::changes(
                if rtss_applied {
                    None
                } else {
                    policy.driver_limit_millihz
                },
                rtss_applied,
                policy.disable_vsync,
                false,
                policy.smooth_motion,
            );
            if !driver_changes.is_empty() {
                match self
                    .driver
                    .apply(OWNER, &target, &fingerprint, &driver_changes)
                {
                    Outcome::Applied | Outcome::AlreadyApplied => (),
                    Outcome::Unavailable(_)
                        if rtss_applied && !policy.disable_vsync && !policy.smooth_motion => {}
                    Outcome::Unavailable(reason) => {
                        if rtss_applied
                            && !matches!(
                                self.leases.borrow_mut().restore(OWNER, Some(&target), None),
                                RestoreOutcome::Restored(_)
                            )
                        {
                            return Err("native_policy_rollback_unconfirmed");
                        }
                        return Err(reason);
                    }
                    _ => return Err("driver_policy_apply_unconfirmed"),
                }
            }
        } else {
            // Each release addresses its own target, including after a restart.
            // A delayed session or old stream cleanup cannot remove a resumed cap.
            let driver = self.driver.restore(OWNER, &target);
            let rtss = self.leases.borrow_mut().restore(OWNER, Some(&target), None);
            match rtss {
                RestoreOutcome::Restored(_) => {}
                RestoreOutcome::NotFound
                    if !self
                        .leases
                        .borrow()
                        .records()
                        .iter()
                        .any(|lease| lease.owner == OWNER && lease.session_id == target) => {}
                _ => return Err("native_policy_restore_unconfirmed"),
            }
            if !matches!(driver, Outcome::Restored | Outcome::NotFound) {
                return Err("driver_policy_restore_unconfirmed");
            }
            if request.phase == LifecyclePhase::SessionRelease {
                self.retiring_sessions.insert(group.clone());
            }
            if self.retiring_sessions.contains(&group) {
                self.leases
                    .borrow_mut()
                    .retire_provider_if_idle()
                    .map_err(|error| error.diagnostic())?;
                // Keep the request until the last stream in this session has
                // released its lease. This set is bounded by unresolved leases.
                if !self
                    .leases
                    .borrow()
                    .records()
                    .iter()
                    .any(|lease| lease.owner == OWNER && lease.session_id.starts_with(&group))
                {
                    self.retiring_sessions.remove(&group);
                }
            }
        }
        Ok(success(request))
    }

    #[cfg(test)]
    pub(crate) fn status(&self, request: &ProviderStatusRequest) -> ProviderResponse {
        if request.receipt_id
            != hash(&(
                &request.transition_id,
                &request.operation_id,
                request.provider_sequence,
            ))
        {
            return ProviderResponse::RecoveryRequired {
                reason: "receipt_not_retained".into(),
            };
        }
        self.completed
            .values()
            .find(|(original, _, _)| {
                original.provider_sequence == request.provider_sequence
                    && original.operation_id == request.operation_id
                    && original.transition_id == request.transition_id
            })
            .map(|(_, _, response)| response.clone())
            .unwrap_or(ProviderResponse::RecoveryRequired {
                reason: "receipt_not_retained".into(),
            })
    }
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
    use crate::lease::{ProfileValues, ProviderError};
    use serde_json::json;

    const ORIGINAL: ProfileValues = ProfileValues {
        frame_limit: 30,
        frame_limit_denominator: 1,
        sync_limiter: 0,
    };
    struct Memory {
        profile: ProfileValues,
        writes: Vec<ProfileValues>,
        disabled: bool,
        available: bool,
        stalled: bool,
        retired: usize,
        block_final_metadata: Option<std::path::PathBuf>,
    }
    struct FakeProvider(Rc<RefCell<Memory>>);
    impl FrameLimitProvider for FakeProvider {
        fn retire_idle(&mut self) -> Result<(), ProviderError> {
            self.0.borrow_mut().retired += 1;
            if let Some(path) = self.0.borrow_mut().block_final_metadata.take() {
                std::fs::rename(&path, path.with_extension("saved")).unwrap();
                std::fs::create_dir(path).unwrap();
            }
            Ok(())
        }
        fn select_installation(&mut self, _path: &str) -> Result<String, ProviderError> {
            if !self.0.borrow().available {
                return Err(ProviderError::Unavailable(if self.0.borrow().stalled {
                    "rtss_disabled_after_stall"
                } else {
                    "rtss_not_running"
                }));
            }
            Ok(r"C:\RTSS".into())
        }
        fn profile_exists(&mut self, profile: &str) -> Result<bool, ProviderError> {
            assert_eq!(profile, crate::rtss::GLOBAL_PROFILE);
            Ok(true)
        }
        fn read_profile(&mut self, profile: &str) -> Result<ProfileValues, ProviderError> {
            assert_eq!(profile, crate::rtss::GLOBAL_PROFILE);
            Ok(self.0.borrow().profile)
        }
        fn ensure_safe_writes_supported(&mut self) -> Result<(), ProviderError> {
            Ok(())
        }
        fn write_profile_verified(
            &mut self,
            profile: &str,
            expected: ProfileValues,
            values: ProfileValues,
        ) -> Result<(), ProviderError> {
            assert_eq!(profile, crate::rtss::GLOBAL_PROFILE);
            let mut state = self.0.borrow_mut();
            if state.profile != expected {
                return Err(ProviderError::ProfileMismatch {
                    code: "external_change",
                    observed: state.profile,
                });
            }
            state.profile = values;
            state.writes.push(values);
            Ok(())
        }
        fn limiter_disabled(&mut self) -> Result<bool, ProviderError> {
            Ok(self.0.borrow().disabled)
        }
        fn ensure_limiter_flag_writes_supported(&mut self) -> Result<(), ProviderError> {
            Ok(())
        }
        fn set_limiter_disabled_verified(
            &mut self,
            expected: bool,
            desired: bool,
        ) -> Result<(), ProviderError> {
            let mut state = self.0.borrow_mut();
            if state.disabled != expected {
                return Err(ProviderError::VerifyFailed("flag_changed"));
            }
            state.disabled = desired;
            Ok(())
        }
    }
    fn policy(rate: i32) -> Policy {
        Policy {
            provider: crate::windows_policy::Provider::Auto,
            installation: String::new(),
            profile: crate::rtss::GLOBAL_PROFILE.into(),
            values: ProfileValues {
                frame_limit: rate,
                frame_limit_denominator: 1,
                sync_limiter: 0,
            },
            driver_limit_millihz: Some(rate as u32 * 1000),
            disable_vsync: false,
            smooth_motion: false,
        }
    }
    fn memory() -> Rc<RefCell<Memory>> {
        Rc::new(RefCell::new(Memory {
            profile: ORIGINAL,
            writes: vec![],
            disabled: false,
            available: true,
            stalled: false,
            retired: 0,
            block_final_metadata: None,
        }))
    }
    fn request<N: DriverSettings>(
        backend: &Backend<FakeProvider, N>,
        stream: Option<&str>,
        sequence: u64,
        policy: Option<&Policy>,
    ) -> ProviderRequest {
        request_at_generation(backend, stream, sequence, policy, 1)
    }

    fn request_at_generation<N: DriverSettings>(
        backend: &Backend<FakeProvider, N>,
        stream: Option<&str>,
        sequence: u64,
        policy: Option<&Policy>,
        generation: u64,
    ) -> ProviderRequest {
        let target = if let Some(stream) = stream {
            json!({"kind":"stream","host_epoch":"epoch","session_id":"session","stream_id":stream,"generation":generation})
        } else {
            json!({"kind":"session","host_epoch":"epoch","session_id":"session","generation":generation})
        };
        let phase = match (stream.is_some(), policy.is_some()) {
            (false, true) => "session.prepare",
            (true, true) => "stream.prepare",
            (false, false) => "session.release",
            (true, false) => "stream.release",
        };
        let mut request: ProviderRequest = serde_json::from_value(json!({"version":1,"provider_sequence":sequence,"operation":"resource_plan",
            "transition_id":format!("transition-{sequence}"),"operation_id":format!("operation-{sequence}"),"target":target,"phase":phase,
            "settings_revision":"r","settings":{},"intent":null,"reason":null,"requested_video":null,
            "consumer_requirements":{"execution_domain":"desktop","capture_providers":["capture"],"selector_schemas":["selector/1"]},
            "remaining_ms":5000,"plan_revision":null,"admission_id":null,"approved_plan":null})).unwrap();
        let plan = backend.plan(&request, policy).unwrap();
        assert_eq!(
            plan.required_capabilities
                .contains(&crate::windows_policy::CAPABILITY.into()),
            policy.is_some()
        );
        assert!(plan.constraints.get("launch_environment").is_none());
        request.operation = ProviderOperation::LifecycleCallback;
        request.provider_sequence += 100;
        request.plan_revision = Some(plan.revision);
        request.admission_id = Some(format!("admission-{sequence}"));
        request.approved_plan = Some(plan);
        request
    }
    fn run<N: DriverSettings>(
        backend: &mut Backend<FakeProvider, N>,
        stream: Option<&str>,
        sequence: u64,
        policy: Option<Policy>,
    ) -> ProviderResponse {
        let request = request(backend, stream, sequence, policy.as_ref());
        let response = backend.begin(&request, policy);
        api::validate_provider_response(&request, &response).unwrap();
        response
    }

    #[test]
    fn native_shutdown_restores_owned_rtss_and_driver_and_retries_failed_cleanup() {
        let rtss = memory();
        let driver = nvcp::testing::Fake::new();
        let before = driver.0.borrow().values.clone();
        let leases = Rc::new(RefCell::new(LeaseManager::in_memory(FakeProvider(
            rtss.clone(),
        ))));
        let mut backend = Backend::with_driver(leases.clone(), Manager::in_memory(driver.clone()));
        let mut desired = policy(60);
        desired.disable_vsync = true;
        assert!(matches!(
            run(&mut backend, None, 1, Some(desired)),
            ProviderResponse::Prepared { .. }
        ));
        driver.0.borrow_mut().available = false;
        assert_eq!(
            backend.shutdown(),
            Err("application_driver_restore_unconfirmed")
        );
        assert!(
            backend.driver.active_target().is_some(),
            "failed native restore must keep exact ownership"
        );
        assert!(leases.borrow().records().is_empty());
        assert_eq!(rtss.borrow().profile, ORIGINAL);
        driver.0.borrow_mut().available = true;
        backend.shutdown().unwrap();
        assert!(backend.driver.active_target().is_none());
        assert_eq!(driver.0.borrow().values, before);
    }

    #[test]
    fn native_shutdown_preserves_external_changes_and_keeps_failed_ownership() {
        let rtss = memory();
        let leases = Rc::new(RefCell::new(LeaseManager::in_memory(FakeProvider(
            rtss.clone(),
        ))));
        let mut backend = Backend::new(leases.clone());
        assert!(matches!(
            run(&mut backend, None, 1, Some(policy(60))),
            ProviderResponse::Prepared { .. }
        ));
        // Compatibility and lifecycle leases share this exact-record drain;
        // an unrecognized external change cannot be overwritten to look clean.
        rtss.borrow_mut().profile.frame_limit = 77;
        assert_eq!(
            backend.shutdown(),
            Err("application_rtss_restore_unconfirmed")
        );
        assert_eq!(rtss.borrow().profile.frame_limit, 77);
        assert_eq!(leases.borrow().records().len(), 1);
        assert_eq!(rtss.borrow().retired, 0);
        rtss.borrow_mut().profile = policy(60).values;
        backend.shutdown().unwrap();
        assert_eq!(rtss.borrow().profile, ORIGINAL);
        assert!(leases.borrow().records().is_empty());
    }

    #[test]
    fn completed_application_group_rejects_fresh_stream_but_unrooted_stream_mode_stays_available() {
        let rtss = memory();
        let mut backend = Backend::new(Rc::new(RefCell::new(LeaseManager::in_memory(
            FakeProvider(rtss.clone()),
        ))));
        assert!(matches!(
            run(&mut backend, None, 1, Some(policy(60))),
            ProviderResponse::Prepared { .. }
        ));
        assert!(matches!(
            run(&mut backend, None, 2, None),
            ProviderResponse::Cleanup { .. }
        ));
        let writes = rtss.borrow().writes.len();
        let revision = backend.leases.borrow().revision();
        assert!(
            matches!(
                run(&mut backend, Some("late-new-stream"), 3, Some(policy(90))),
                ProviderResponse::RecoveryRequired { .. }
            ),
            "ended application admitted a fresh standalone stream policy"
        );
        assert_eq!(rtss.borrow().profile, ORIGINAL);
        assert_eq!(rtss.borrow().writes.len(), writes);
        assert_eq!(backend.leases.borrow().revision(), revision);
        let standalone_rtss = memory();
        let mut standalone = Backend::new(Rc::new(RefCell::new(LeaseManager::in_memory(
            FakeProvider(standalone_rtss.clone()),
        ))));
        assert!(matches!(
            run(&mut standalone, Some("standalone"), 1, Some(policy(90))),
            ProviderResponse::Prepared { .. }
        ));
        assert_eq!(standalone_rtss.borrow().profile.frame_limit, 90);
        assert!(matches!(
            run(&mut standalone, Some("standalone"), 2, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(standalone_rtss.borrow().profile, ORIGINAL);
    }

    #[test]
    fn active_root_reserves_retirement_capacity_before_admitting_another_stream() {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "windows-root-capacity-{:032x}",
            u128::from_le_bytes(nonce)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("rtss.json");
        let rtss = memory();
        let open = || {
            let mut leases = LeaseManager::open(FakeProvider(rtss.clone()), path.clone()).unwrap();
            leases.recover().unwrap();
            Backend::new(Rc::new(RefCell::new(leases)))
        };
        let mut backend = open();
        assert!(matches!(
            run(&mut backend, None, 1, Some(policy(60))),
            ProviderResponse::Prepared { .. }
        ));
        let mut state = backend.root_state().unwrap();
        let root = state.root.as_mut().unwrap();
        for index in 0..255 {
            let target = LifecycleTarget::Stream {
                host_epoch: "epoch".into(),
                session_id: "session".into(),
                stream_id: format!("retired-{index}"),
                generation: 1,
            };
            root.retired_streams
                .insert(target_identity(&target).unwrap().1);
        }
        state.save(&mut backend.leases.borrow_mut()).unwrap();
        assert!(matches!(
            run(&mut backend, Some("last-slot"), 2, Some(policy(90))),
            ProviderResponse::Prepared { .. }
        ));
        let revision = backend.leases.borrow().revision();
        let writes = rtss.borrow().writes.len();
        // Existing exact ownership remains retryable even when every future
        // retirement slot has been reserved.
        assert!(matches!(
            run(&mut backend, Some("last-slot"), 3, Some(policy(120))),
            ProviderResponse::Prepared { .. }
        ));
        assert_eq!(backend.leases.borrow().revision(), revision);
        assert!(
            matches!(
                run(&mut backend, Some("overflow"), 4, Some(policy(90))),
                ProviderResponse::RecoveryRequired { .. }
            ),
            "257th distinct claim was admitted without a retirement slot"
        );
        assert_eq!(backend.leases.borrow().revision(), revision);
        assert_eq!(rtss.borrow().writes.len(), writes);
        assert!(matches!(
            run(&mut backend, Some("last-slot"), 5, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(
            backend
                .root_state()
                .unwrap()
                .root
                .as_ref()
                .unwrap()
                .retired_streams
                .len(),
            256
        );
        drop(backend);
        let mut recovered = open();
        assert!(matches!(
            run(&mut recovered, Some("retired-0"), 6, Some(policy(90))),
            ProviderResponse::RecoveryRequired { .. }
        ));
        assert!(matches!(
            run(&mut recovered, Some("last-slot"), 7, Some(policy(90))),
            ProviderResponse::RecoveryRequired { .. }
        ));
        assert!(matches!(
            run(&mut recovered, Some("overflow"), 8, Some(policy(90))),
            ProviderResponse::RecoveryRequired { .. }
        ));
        assert_eq!(rtss.borrow().profile.frame_limit, 60);
        assert_eq!(rtss.borrow().writes.len(), writes);
        assert!(matches!(
            run(&mut recovered, None, 9, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(rtss.borrow().profile, ORIGINAL);
        drop(recovered);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn session_callback_replay_uses_its_admitted_policy_without_new_context() {
        let rtss = memory();
        let mut backend = Backend::new(Rc::new(RefCell::new(LeaseManager::in_memory(
            FakeProvider(rtss.clone()),
        ))));
        let callback = request(&backend, None, 1, Some(&policy(60)));
        assert!(matches!(
            backend.begin(&callback, Some(policy(60))),
            ProviderResponse::Prepared { .. }
        ));
        let writes = rtss.borrow().writes.len();
        assert!(
            matches!(
                backend.begin(&callback, None),
                ProviderResponse::Prepared { .. }
            ),
            "exact SessionPrepare replay lost its admitted policy"
        );
        assert_eq!(rtss.borrow().writes.len(), writes);
    }

    #[test]
    fn pause_preserves_the_exact_rtss_and_driver_policy_until_application_end() {
        for provider in [
            crate::windows_policy::Provider::Rtss,
            crate::windows_policy::Provider::Nvidia,
        ] {
            let rtss = memory();
            let driver = nvcp::testing::Fake::new();
            let before = driver.0.borrow().values.clone();
            let mut backend = Backend::with_driver(
                Rc::new(RefCell::new(LeaseManager::in_memory(FakeProvider(
                    rtss.clone(),
                )))),
                Manager::in_memory(driver.clone()),
            );
            let mut frozen = policy(60);
            frozen.provider = provider;
            frozen.disable_vsync = true;
            assert!(matches!(
                run(&mut backend, None, 1, Some(frozen.clone())),
                ProviderResponse::Prepared { .. }
            ));
            assert!(matches!(
                run(&mut backend, Some("first"), 2, Some(frozen)),
                ProviderResponse::Prepared { .. }
            ));
            let retained_rtss = rtss.borrow().profile;
            let retained_driver = driver.0.borrow().values.clone();
            let mut pause = request(&backend, Some("first"), 3, None);
            pause.reason = Some(api::ReleaseReason::Pause);
            assert!(matches!(
                backend.begin(&pause, None),
                ProviderResponse::Cleanup { .. }
            ));
            assert_eq!(
                rtss.borrow().profile,
                retained_rtss,
                "Pause restored the owned RTSS policy"
            );
            assert_eq!(
                driver.0.borrow().values,
                retained_driver,
                "Pause restored the owned NVCP policy"
            );
            let resumed = request(&backend, Some("resumed"), 4, Some(&policy(90)));
            assert!(matches!(
                backend.begin(&resumed, Some(policy(90))),
                ProviderResponse::Prepared { .. }
            ));
            assert_eq!(rtss.borrow().profile, retained_rtss);
            assert_eq!(driver.0.borrow().values, retained_driver);
            assert!(matches!(
                run(&mut backend, Some("resumed"), 5, None),
                ProviderResponse::Cleanup { .. }
            ));
            assert!(matches!(
                run(&mut backend, None, 6, None),
                ProviderResponse::Cleanup { .. }
            ));
            assert_eq!(rtss.borrow().profile, ORIGINAL);
            assert_eq!(driver.0.borrow().values, before);
            let writes = rtss.borrow().writes.len();
            assert!(
                matches!(
                    backend.begin(&resumed, Some(policy(90))),
                    ProviderResponse::Prepared { .. }
                ),
                "cached callback must use its admitted frozen policy after the root disappears"
            );
            assert_eq!(rtss.borrow().writes.len(), writes);
            assert_eq!(driver.0.borrow().values, before);
        }
    }

    #[test]
    fn durable_application_and_stream_claims_survive_reopen_and_both_release_orders() {
        for provider in [
            crate::windows_policy::Provider::Rtss,
            crate::windows_policy::Provider::Nvidia,
        ] {
            for session_first in [false, true] {
                let mut nonce = [0_u8; 16];
                getrandom::fill(&mut nonce).unwrap();
                let directory = std::env::temp_dir()
                    .join(format!("windows-root-{:032x}", u128::from_le_bytes(nonce)));
                std::fs::create_dir(&directory).unwrap();
                let rtss = memory();
                let driver = nvcp::testing::Fake::new();
                let original_driver = driver.0.borrow().values.clone();
                let open = || {
                    let mut leases =
                        LeaseManager::open(FakeProvider(rtss.clone()), directory.join("rtss.json"))
                            .unwrap();
                    leases.recover().unwrap();
                    let mut native =
                        Manager::open(driver.clone(), &directory.join("nvcp.json")).unwrap();
                    native.recover();
                    Backend::with_driver(Rc::new(RefCell::new(leases)), native)
                };
                let mut backend = open();
                let mut frozen = policy(60);
                frozen.provider = provider;
                frozen.disable_vsync = true;
                let session_callback = request(&backend, None, 1, Some(&frozen));
                assert!(matches!(
                    backend.begin(&session_callback, Some(frozen)),
                    ProviderResponse::Prepared { .. }
                ));
                assert!(matches!(
                    run(&mut backend, Some("first"), 2, Some(policy(90))),
                    ProviderResponse::Prepared { .. }
                ));
                let joined_callback = request(&backend, Some("joined"), 3, Some(&policy(120)));
                assert!(matches!(
                    backend.begin(&joined_callback, Some(policy(120))),
                    ProviderResponse::Prepared { .. }
                ));
                let retained_rtss = rtss.borrow().profile;
                let retained_driver = driver.0.borrow().values.clone();
                assert!(matches!(
                    run(&mut backend, Some("first"), 4, None),
                    ProviderResponse::Cleanup { .. }
                ));
                drop(backend);
                let mut backend = open();
                let recovered_revision = backend.leases.borrow().revision();
                assert!(
                    matches!(
                        backend.begin(&session_callback, None),
                        ProviderResponse::Prepared { .. }
                    ),
                    "reopen rejected an already-owned Session callback"
                );
                assert!(
                    matches!(
                        backend.begin(&joined_callback, None),
                        ProviderResponse::Prepared { .. }
                    ),
                    "reopen rejected an already-owned stream callback"
                );
                assert_eq!(
                    backend.leases.borrow().revision(),
                    recovered_revision,
                    "owned callback replay must not create another claim"
                );
                assert!(matches!(
                    run(&mut backend, Some("resumed"), 5, Some(policy(75))),
                    ProviderResponse::Prepared { .. }
                ));
                if session_first {
                    assert!(matches!(
                        run(&mut backend, None, 6, None),
                        ProviderResponse::Cleanup { .. }
                    ));
                    drop(backend);
                    backend = open(); // An ended application still owes its exact stream claims.
                    assert!(matches!(
                        backend.begin(&joined_callback, Some(policy(120))),
                        ProviderResponse::Prepared { .. }
                    ));
                }
                assert!(matches!(
                    run(&mut backend, Some("joined"), 7, None),
                    ProviderResponse::Cleanup { .. }
                ));
                assert_eq!(rtss.borrow().profile, retained_rtss);
                assert_eq!(driver.0.borrow().values, retained_driver);
                assert!(matches!(
                    run(&mut backend, Some("resumed"), 8, None),
                    ProviderResponse::Cleanup { .. }
                ));
                if !session_first {
                    assert_eq!(rtss.borrow().profile, retained_rtss);
                    assert_eq!(driver.0.borrow().values, retained_driver);
                    assert!(matches!(
                        run(&mut backend, None, 9, None),
                        ProviderResponse::Cleanup { .. }
                    ));
                }
                assert_eq!(rtss.borrow().profile, ORIGINAL);
                assert_eq!(driver.0.borrow().values, original_driver);
                assert!(backend.root_state().unwrap().root.is_none());
                let successor = request_at_generation(&backend, None, 10, Some(&policy(90)), 2);
                assert!(matches!(
                    backend.begin(&successor, Some(policy(90))),
                    ProviderResponse::Prepared { .. }
                ));
                assert!(matches!(
                    run(&mut backend, None, 11, None),
                    ProviderResponse::Cleanup { .. }
                ));
                assert!(matches!(
                    run(&mut backend, Some("resumed"), 12, None),
                    ProviderResponse::Cleanup { .. }
                ));
                assert_eq!(
                    rtss.borrow().profile.frame_limit,
                    90,
                    "old release changed a successor's policy"
                );
                let end = request_at_generation(&backend, None, 13, None, 2);
                assert!(matches!(
                    backend.begin(&end, None),
                    ProviderResponse::Cleanup { .. }
                ));
                assert_eq!(rtss.borrow().profile, ORIGINAL);
                assert_eq!(driver.0.borrow().values, original_driver);
                drop(backend);
                assert!(!crate::lease::journal_has_effects(&directory.join("rtss.json")).unwrap());
                std::fs::remove_dir_all(directory).unwrap();
            }
        }
    }

    #[test]
    fn missing_driver_journal_keeps_durable_application_cleanup_unconfirmed() {
        let rtss = memory();
        let driver = nvcp::testing::Fake::new();
        let leases = Rc::new(RefCell::new(LeaseManager::in_memory(FakeProvider(rtss))));
        let mut backend = Backend::with_driver(leases.clone(), Manager::in_memory(driver));
        let mut desired = policy(60);
        desired.provider = crate::windows_policy::Provider::Nvidia;
        assert!(matches!(
            run(&mut backend, None, 1, Some(desired)),
            ProviderResponse::Prepared { .. }
        ));
        drop(backend);
        // Losing the native before-state cannot be treated as NotFound proof.
        let mut recovered =
            Backend::with_driver(leases, Manager::in_memory(nvcp::testing::Fake::new()));
        assert!(matches!(
            run(&mut recovered, None, 2, None),
            ProviderResponse::RecoveryRequired { .. }
        ));
        let state = recovered.root_state().unwrap();
        assert_eq!(
            state.root.as_ref().unwrap().phase,
            ownership::Phase::Restoring
        );
        assert!(recovered.owns_target(&state.root.unwrap().target));
    }

    #[test]
    fn root_metadata_cannot_restore_a_lease_bound_to_another_session_generation() {
        let rtss = memory();
        let driver = nvcp::testing::Fake::new();
        let mut backend = Backend::with_driver(
            Rc::new(RefCell::new(LeaseManager::in_memory(FakeProvider(
                rtss.clone(),
            )))),
            Manager::in_memory(driver.clone()),
        );
        assert!(matches!(
            run(&mut backend, None, 1, Some(policy(60))),
            ProviderResponse::Prepared { .. }
        ));
        let retained = driver.0.borrow().values.clone();
        let mut metadata = backend.root_state().unwrap();
        let LifecycleTarget::Session { generation, .. } =
            &mut metadata.root.as_mut().unwrap().target
        else {
            unreachable!()
        };
        *generation = 2;
        metadata.save(&mut backend.leases.borrow_mut()).unwrap();
        let cleanup = request_at_generation(&backend, None, 2, None, 2);
        assert!(matches!(
            backend.begin(&cleanup, None),
            ProviderResponse::RecoveryRequired { .. }
        ));
        assert_eq!(rtss.borrow().profile.frame_limit, 60);
        assert_eq!(driver.0.borrow().values, retained);
        assert!(backend.root_state().unwrap().root.is_some());
    }

    #[test]
    fn disabled_policy_creates_no_application_root_or_native_changes() {
        let rtss = memory();
        let driver = nvcp::testing::Fake::new();
        let before = driver.0.borrow().values.clone();
        let mut backend = Backend::with_driver(
            Rc::new(RefCell::new(LeaseManager::in_memory(FakeProvider(
                rtss.clone(),
            )))),
            Manager::in_memory(driver.clone()),
        );
        let mut disabled = policy(60);
        disabled.provider = crate::windows_policy::Provider::None;
        disabled.driver_limit_millihz = None;
        assert!(matches!(
            run(&mut backend, None, 1, Some(disabled)),
            ProviderResponse::Prepared { .. }
        ));
        assert!(backend.root_state().unwrap().root.is_none());
        assert!(rtss.borrow().writes.is_empty());
        assert_eq!(driver.0.borrow().values, before);
    }

    #[test]
    fn failed_final_root_checkpoint_reopens_and_retries_exact_completed_native_proof() {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "windows-root-checkpoint-{:032x}",
            u128::from_le_bytes(nonce)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("rtss.json");
        let rtss = memory();
        let driver = nvcp::testing::Fake::new();
        let original_driver = driver.0.borrow().values.clone();
        let leases = Rc::new(RefCell::new(
            LeaseManager::open(FakeProvider(rtss.clone()), path.clone()).unwrap(),
        ));
        let mut backend = Backend::with_driver(
            leases,
            Manager::open(driver.clone(), &directory.join("nvcp.json")).unwrap(),
        );
        let mut desired = policy(60);
        desired.disable_vsync = true;
        assert!(matches!(
            run(&mut backend, None, 1, Some(desired)),
            ProviderResponse::Prepared { .. }
        ));
        rtss.borrow_mut().block_final_metadata = Some(path.clone());
        assert!(matches!(
            run(&mut backend, None, 2, None),
            ProviderResponse::RecoveryRequired { .. }
        ));
        assert_eq!(rtss.borrow().profile, ORIGINAL);
        assert_eq!(driver.0.borrow().values, original_driver);
        assert_eq!(
            backend.root_state().unwrap().root.as_ref().unwrap().phase,
            ownership::Phase::Restoring
        );
        drop(backend);
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(path.with_extension("saved"), &path).unwrap();
        let mut leases = LeaseManager::open(FakeProvider(rtss.clone()), path.clone()).unwrap();
        leases.recover().unwrap();
        let mut native = Manager::open(driver.clone(), &directory.join("nvcp.json")).unwrap();
        native.recover();
        let mut recovered = Backend::with_driver(Rc::new(RefCell::new(leases)), native);
        let writes = rtss.borrow().writes.len();
        let commits = driver.0.borrow().commits;
        assert!(matches!(
            run(&mut recovered, None, 3, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert!(recovered.root_state().unwrap().root.is_none());
        assert_eq!(
            rtss.borrow().writes.len(),
            writes,
            "retry must use completed proof, not rerun native writes"
        );
        assert_eq!(driver.0.borrow().commits, commits);
        drop(recovered);
        assert!(!crate::lease::journal_has_effects(&path).unwrap());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn auto_falls_back_to_the_driver_without_touching_rtss_and_resumes_safely() {
        let rtss = memory();
        rtss.borrow_mut().available = false;
        let driver = nvcp::testing::Fake::new();
        let before = driver.0.borrow().values.clone();
        let mut backend = Backend::with_driver(
            Rc::new(RefCell::new(LeaseManager::in_memory(FakeProvider(
                rtss.clone(),
            )))),
            Manager::in_memory(driver.clone()),
        );
        assert!(matches!(
            run(&mut backend, None, 1, Some(policy(60))),
            ProviderResponse::Prepared { .. }
        ));
        assert_eq!(
            driver.0.borrow().values[&nvcp::Setting::FrameLimit].explicit,
            Some(60)
        );
        assert!(rtss.borrow().writes.is_empty());
        assert!(matches!(
            run(&mut backend, Some("next"), 2, Some(policy(120))),
            ProviderResponse::Prepared { .. }
        ));
        assert_eq!(
            driver.0.borrow().values[&nvcp::Setting::FrameLimit].explicit,
            Some(60)
        );
        assert!(matches!(
            run(&mut backend, None, 3, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(
            driver.0.borrow().values[&nvcp::Setting::FrameLimit].explicit,
            Some(60)
        );
        assert!(matches!(
            run(&mut backend, Some("next"), 4, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(driver.0.borrow().values, before);
    }

    #[test]
    fn explicit_rtss_falls_back_only_after_a_confirmed_stall() {
        for stalled in [false, true] {
            let rtss = memory();
            rtss.borrow_mut().available = false;
            rtss.borrow_mut().stalled = stalled;
            let driver = nvcp::testing::Fake::new();
            let mut backend = Backend::with_driver(
                Rc::new(RefCell::new(LeaseManager::in_memory(FakeProvider(rtss)))),
                Manager::in_memory(driver.clone()),
            );
            let mut policy = policy(60);
            policy.provider = crate::windows_policy::Provider::Rtss;
            let response = run(&mut backend, None, 1, Some(policy));
            assert_eq!(
                matches!(response, ProviderResponse::Prepared { .. }),
                stalled
            );
            assert_eq!(
                driver.0.borrow().values[&nvcp::Setting::FrameLimit].explicit,
                stalled.then_some(60)
            );
        }
    }

    #[test]
    fn explicit_driver_selection_and_rtss_with_vsync_keep_separate_owned_effects() {
        for provider in [
            crate::windows_policy::Provider::Nvidia,
            crate::windows_policy::Provider::Rtss,
        ] {
            let rtss = memory();
            let driver = nvcp::testing::Fake::new();
            let before = driver.0.borrow().values.clone();
            let mut backend = Backend::with_driver(
                Rc::new(RefCell::new(LeaseManager::in_memory(FakeProvider(
                    rtss.clone(),
                )))),
                Manager::in_memory(driver.clone()),
            );
            let mut policy = policy(60);
            policy.provider = provider;
            policy.disable_vsync = true;
            assert!(matches!(
                run(&mut backend, None, 1, Some(policy)),
                ProviderResponse::Prepared { .. }
            ));
            let desired = if provider == crate::windows_policy::Provider::Rtss {
                0
            } else {
                60
            };
            assert_eq!(
                driver.0.borrow().values[&nvcp::Setting::FrameLimit].explicit,
                Some(desired)
            );
            assert_eq!(
                driver.0.borrow().values[&nvcp::Setting::Vsync].explicit,
                Some(0x0841_6747)
            );
            assert_eq!(
                rtss.borrow().writes.is_empty(),
                provider != crate::windows_policy::Provider::Rtss
            );
            assert!(matches!(
                run(&mut backend, None, 2, None),
                ProviderResponse::Cleanup { .. }
            ));
            assert_eq!(rtss.borrow().profile, ORIGINAL);
            assert_eq!(driver.0.borrow().values, before);
        }
    }

    #[test]
    fn required_driver_control_failure_rolls_back_rtss_and_uncertain_save_stays_owned() {
        for uncertain in [false, true] {
            let rtss = memory();
            let driver = nvcp::testing::Fake::new();
            if uncertain {
                driver.0.borrow_mut().fault = Some(nvcp::testing::Fault::PartialSave);
            } else {
                driver.0.borrow_mut().available = false;
            }
            let mut backend = Backend::with_driver(
                Rc::new(RefCell::new(LeaseManager::in_memory(FakeProvider(
                    rtss.clone(),
                )))),
                Manager::in_memory(driver.clone()),
            );
            let mut policy = policy(60);
            policy.disable_vsync = true;
            assert!(matches!(
                run(&mut backend, None, 1, Some(policy)),
                ProviderResponse::RecoveryRequired { .. }
            ));
            assert_eq!(
                rtss.borrow().profile.frame_limit,
                if uncertain { 60 } else { ORIGINAL.frame_limit }
            );
            if uncertain {
                assert!(backend.driver.active_target().is_some());
                assert!(matches!(
                    run(&mut backend, None, 2, None),
                    ProviderResponse::Cleanup { .. }
                ));
                assert_eq!(rtss.borrow().profile, ORIGINAL);
            }
        }
    }

    #[test]
    fn vsync_can_be_changed_without_a_frame_cap() {
        let rtss = memory();
        let driver = nvcp::testing::Fake::new();
        let mut backend = Backend::with_driver(
            Rc::new(RefCell::new(LeaseManager::in_memory(FakeProvider(
                rtss.clone(),
            )))),
            Manager::in_memory(driver.clone()),
        );
        let mut policy = policy(60);
        policy.provider = crate::windows_policy::Provider::None;
        policy.driver_limit_millihz = None;
        policy.disable_vsync = true;
        assert!(matches!(
            run(&mut backend, None, 1, Some(policy)),
            ProviderResponse::Prepared { .. }
        ));
        assert!(rtss.borrow().writes.is_empty());
        assert_eq!(
            driver.0.borrow().values[&nvcp::Setting::FrameLimit].explicit,
            None
        );
        assert_eq!(
            driver.0.borrow().values[&nvcp::Setting::Vsync].explicit,
            Some(0x0841_6747)
        );
        assert!(matches!(
            run(&mut backend, None, 2, None),
            ProviderResponse::Cleanup { .. }
        ));
    }

    #[test]
    fn global_lifecycle_lease_restores_a_previously_disabled_rtss_limiter() {
        let state = memory();
        state.borrow_mut().disabled = true;
        let leases = Rc::new(RefCell::new(LeaseManager::in_memory(FakeProvider(
            state.clone(),
        ))));
        let mut backend = Backend::new(leases);
        assert!(matches!(
            run(&mut backend, None, 1, Some(policy(60))),
            ProviderResponse::Prepared { .. }
        ));
        assert!(!state.borrow().disabled);
        assert!(matches!(
            run(&mut backend, None, 2, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert!(state.borrow().disabled);
        assert_eq!(state.borrow().profile, ORIGINAL);
    }

    #[test]
    fn warm_provider_is_kept_during_pause_and_retired_after_session_cleanup_in_either_order() {
        for session_first in [false, true] {
            let memory = memory();
            let mut backend = Backend::new(Rc::new(RefCell::new(LeaseManager::in_memory(
                FakeProvider(memory.clone()),
            ))));
            assert!(matches!(
                run(&mut backend, None, 1, Some(policy(60))),
                ProviderResponse::Prepared { .. }
            ));
            assert!(matches!(
                run(&mut backend, Some("stream"), 2, Some(policy(60))),
                ProviderResponse::Prepared { .. }
            ));
            if session_first {
                assert!(matches!(
                    run(&mut backend, None, 3, None),
                    ProviderResponse::Cleanup { .. }
                ));
                assert_eq!(memory.borrow().retired, 0);
                assert!(matches!(
                    run(&mut backend, Some("stream"), 4, None),
                    ProviderResponse::Cleanup { .. }
                ));
            } else {
                assert!(matches!(
                    run(&mut backend, Some("stream"), 3, None),
                    ProviderResponse::Cleanup { .. }
                ));
                assert_eq!(memory.borrow().retired, 0);
                assert!(matches!(
                    run(&mut backend, None, 4, None),
                    ProviderResponse::Cleanup { .. }
                ));
            }
            assert_eq!(memory.borrow().retired, 1);
            assert!(backend.retiring_sessions.is_empty());
        }
    }

    #[test]
    fn preparation_retries_and_delayed_cleanup_preserve_the_current_stream() {
        let memory = memory();
        let leases = Rc::new(RefCell::new(LeaseManager::in_memory(FakeProvider(
            memory.clone(),
        ))));
        let mut backend = Backend::new(leases.clone());
        let initial = request(&backend, None, 1, Some(&policy(60)));
        assert!(matches!(
            backend.begin(&initial, Some(policy(60))),
            ProviderResponse::Prepared { .. }
        ));
        let writes = memory.borrow().writes.len();
        assert!(matches!(
            backend.begin(&initial, Some(policy(60))),
            ProviderResponse::Prepared { .. }
        ));
        assert_eq!(memory.borrow().writes.len(), writes);
        assert!(backend.owns_target(&initial.target));
        assert!(matches!(
            run(&mut backend, Some("first"), 2, Some(policy(120))),
            ProviderResponse::Prepared { .. }
        ));
        assert_eq!(memory.borrow().profile.frame_limit, 60);
        assert!(matches!(
            run(&mut backend, None, 3, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(
            memory.borrow().profile.frame_limit,
            60,
            "late initial cleanup cannot change stream policy"
        );
        assert!(matches!(
            run(&mut backend, Some("second"), 4, Some(policy(90))),
            ProviderResponse::RecoveryRequired { .. }
        ));
        assert_eq!(memory.borrow().profile.frame_limit, 60);
        assert!(matches!(
            run(&mut backend, Some("first"), 5, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(memory.borrow().profile, ORIGINAL);
        let successor = request_at_generation(&backend, None, 6, Some(&policy(90)), 2);
        assert!(matches!(
            backend.begin(&successor, Some(policy(90))),
            ProviderResponse::Prepared { .. }
        ));
        assert!(matches!(
            run(&mut backend, Some("second"), 7, Some(policy(90))),
            ProviderResponse::Prepared { .. }
        ));
        assert!(matches!(
            run(&mut backend, Some("first"), 8, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(memory.borrow().profile.frame_limit, 90);
        let status = ProviderStatusRequest {
            provider_sequence: initial.provider_sequence,
            operation_id: initial.operation_id.clone(),
            transition_id: initial.transition_id.clone(),
            receipt_id: hash(&(
                &initial.transition_id,
                &initial.operation_id,
                initial.provider_sequence,
            )),
        };
        assert!(matches!(
            backend.status(&status),
            ProviderResponse::Prepared { .. }
        ));
        assert!(leases.borrow().revision() > 1);
    }

    #[test]
    fn changed_admission_or_external_profile_edits_never_overwrite_native_state() {
        let memory = memory();
        let mut backend = Backend::new(Rc::new(RefCell::new(LeaseManager::in_memory(
            FakeProvider(memory.clone()),
        ))));
        let mut altered = request(&backend, None, 1, Some(&policy(60)));
        altered.approved_plan.as_mut().unwrap().constraints["policy"]["values"]["frame_limit"] =
            json!(144);
        assert!(matches!(
            backend.begin(&altered, Some(policy(60))),
            ProviderResponse::RecoveryRequired { .. }
        ));
        assert!(memory.borrow().writes.is_empty());
        assert!(matches!(
            run(&mut backend, None, 2, Some(policy(60))),
            ProviderResponse::Prepared { .. }
        ));
        memory.borrow_mut().profile.frame_limit = 75;
        let count = memory.borrow().writes.len();
        assert!(matches!(
            run(&mut backend, None, 3, None),
            ProviderResponse::RecoveryRequired { .. }
        ));
        assert_eq!(memory.borrow().profile.frame_limit, 75);
        assert_eq!(memory.borrow().writes.len(), count);
    }

    #[test]
    fn restart_keeps_the_revision_and_restores_only_the_exact_owned_target() {
        let root = std::env::temp_dir().join(format!(
            "limiter-windows-{}",
            u128::from_le_bytes({
                let mut id = [0; 16];
                getrandom::fill(&mut id).unwrap();
                id
            })
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("leases.json");
        let memory = memory();
        let leases = Rc::new(RefCell::new(
            LeaseManager::open(FakeProvider(memory.clone()), path.clone()).unwrap(),
        ));
        let mut backend = Backend::new(leases.clone());
        let original = request(&backend, Some("stream"), 1, Some(&policy(60)));
        assert!(matches!(
            backend.begin(&original, Some(policy(60))),
            ProviderResponse::Prepared { .. }
        ));
        let revision = leases.borrow().revision();
        drop(backend);
        drop(leases);
        let mut manager = LeaseManager::open(FakeProvider(memory.clone()), path).unwrap();
        manager.recover().unwrap();
        assert_eq!(manager.revision(), revision);
        let mut recovered = Backend::new(Rc::new(RefCell::new(manager)));
        assert!(matches!(
            recovered.begin(&original, Some(policy(60))),
            ProviderResponse::Prepared { .. }
        ));
        assert!(matches!(
            run(&mut recovered, Some("different"), 2, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(memory.borrow().profile.frame_limit, 60);
        assert!(matches!(
            run(&mut recovered, Some("stream"), 3, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(memory.borrow().profile, ORIGINAL);
        drop(recovered);
        std::fs::remove_dir_all(root).unwrap();
    }
}
