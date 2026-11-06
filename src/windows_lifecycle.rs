//! Windows lifecycle effects. The plugin owns both native lease managers;
//! no launch or stream consumer selects or calls a native limiter backend.
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
        targets.sort();
        targets.dedup();
        Ok((revision, targets))
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

    fn apply(
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
    }
    struct FakeProvider(Rc<RefCell<Memory>>);
    impl FrameLimitProvider for FakeProvider {
        fn retire_idle(&mut self) -> Result<(), ProviderError> {
            self.0.borrow_mut().retired += 1;
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
        }))
    }
    fn request<N: DriverSettings>(
        backend: &Backend<FakeProvider, N>,
        stream: Option<&str>,
        sequence: u64,
        policy: Option<&Policy>,
    ) -> ProviderRequest {
        let target = if let Some(stream) = stream {
            json!({"kind":"stream","host_epoch":"epoch","session_id":"session","stream_id":stream,"generation":1})
        } else {
            json!({"kind":"session","host_epoch":"epoch","session_id":"session","generation":1})
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
            Some(120)
        );
        assert!(matches!(
            run(&mut backend, None, 3, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(
            driver.0.borrow().values[&nvcp::Setting::FrameLimit].explicit,
            Some(120)
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
        assert_eq!(memory.borrow().profile.frame_limit, 120);
        assert!(matches!(
            run(&mut backend, None, 3, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(
            memory.borrow().profile.frame_limit,
            120,
            "late initial cleanup cannot change stream policy"
        );
        assert!(matches!(
            run(&mut backend, Some("second"), 4, Some(policy(90))),
            ProviderResponse::RecoveryRequired { .. }
        ));
        assert_eq!(memory.borrow().profile.frame_limit, 120);
        assert!(matches!(
            run(&mut backend, Some("first"), 5, None),
            ProviderResponse::Cleanup { .. }
        ));
        assert_eq!(memory.borrow().profile, ORIGINAL);
        assert!(matches!(
            run(&mut backend, Some("second"), 6, Some(policy(90))),
            ProviderResponse::Prepared { .. }
        ));
        assert!(matches!(
            run(&mut backend, Some("first"), 7, None),
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
