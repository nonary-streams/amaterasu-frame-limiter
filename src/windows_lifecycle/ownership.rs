//! Durable logical ownership; native before/applied snapshots remain in the
//! existing RTSS and NVCP lease records, addressed by this exact Session root.
use super::*;
use serde::{Deserialize, Serialize};

const STREAM_IDENTITY_LIMIT: usize = 256;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Root {
    pub target: LifecycleTarget,
    pub policy: Policy,
    pub rtss_lease: Option<String>,
    pub driver: bool,
    pub application: bool,
    pub streams: BTreeSet<String>,
    pub releasing: BTreeSet<String>,
    pub retired_streams: BTreeSet<String>,
    pub phase: Phase,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Active,
    Restoring,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    version: u32,
    pub root: Option<Root>,
    completed: Vec<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            root: None,
            completed: vec![],
        }
    }
}

impl State {
    pub(crate) fn decode(value: Option<&serde_json::Value>) -> Result<Self, &'static str> {
        let state: Self = value
            .map(|value| {
                serde_json::from_value(value.clone()).map_err(|_| "windows_root_journal_invalid")
            })
            .transpose()?
            .unwrap_or_default();
        if state.version != 1
            || state.completed.len() > 256
            || state.completed.iter().any(|id| !valid_id(id))
        {
            return Err("windows_root_journal_invalid");
        }
        if let Some(root) = &state.root {
            validate_root(root)?;
        }
        Ok(state)
    }

    pub(super) fn save<P: FrameLimitProvider>(
        &self,
        leases: &mut LeaseManager<P>,
    ) -> Result<(), &'static str> {
        let value = serde_json::to_value(self).map_err(|_| "windows_root_journal_invalid")?;
        Self::decode(Some(&value))?;
        leases.save_windows_lifecycle(value)
    }

    pub(super) fn completed(&self, identity: &str) -> bool {
        self.completed.iter().any(|entry| entry == identity)
    }

    fn completed_session(&self, group: &str) -> bool {
        let prefix = format!("{group}s.");
        self.completed
            .iter()
            .any(|identity| identity.starts_with(&prefix))
    }

    pub(super) fn finish(&mut self) {
        if let Some(root) = self.root.take() {
            let session = target_identity(&root.target).expect("validated root").1;
            self.completed.extend(root.retired_streams);
            self.completed.extend(root.releasing);
            self.completed.extend(root.streams);
            self.completed.push(session);
            if self.completed.len() > 256 {
                self.completed.drain(..self.completed.len() - 256);
            }
        }
    }
}

impl<P: FrameLimitProvider, N: DriverSettings> Backend<P, N> {
    pub(super) fn root_state(&self) -> Result<State, &'static str> {
        State::decode(self.leases.borrow().windows_lifecycle())
    }

    pub(crate) fn retained_policy(
        &self,
        target: &LifecycleTarget,
    ) -> Result<Option<Policy>, &'static str> {
        let state = self.root_state()?;
        let Some(root) = state.root else {
            return Ok(None);
        };
        let (group, identity) = target_identity(target)?;
        let same_group = group == target_identity(&root.target)?.0;
        Ok((matches!(target, LifecycleTarget::Stream { .. })
            && same_group
            && (root.application || root.streams.contains(&identity))
            && root.phase == Phase::Active)
            .then_some(root.policy))
    }

    pub(super) fn root_owns(&self, root: &Root, target: &LifecycleTarget) -> bool {
        let Ok((_, id)) = target_identity(target) else {
            return false;
        };
        root.target == *target || root.streams.contains(&id) || root.releasing.contains(&id)
    }

    fn validate_claim(
        &self,
        request: &ProviderRequest,
        policy: Option<&Policy>,
    ) -> Result<u64, &'static str> {
        api::validate_provider_request(request).map_err(|_| "invalid_request")?;
        if request.operation != ProviderOperation::LifecycleCallback {
            return Err("invalid_operation");
        }
        let admitted = request.approved_plan.as_ref().ok_or("missing_admission")?;
        let observed = admitted
            .mutation_domains
            .first()
            .ok_or("missing_mutation_domain")?
            .expected_revision;
        let mut planning = request.clone();
        planning.operation = ProviderOperation::ResourcePlan;
        planning.provider_sequence = admitted.revision;
        planning.approved_plan = None;
        planning.admission_id = None;
        planning.plan_revision = None;
        let value = policy
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| "invalid_policy")?;
        if crate::lifecycle_plan::build_native(&planning, value.as_ref(), observed)? != *admitted {
            return Err("admission_mismatch");
        }
        Ok(observed)
    }

    fn ensure_observed_revision(&self, observed: u64) -> Result<(), &'static str> {
        if self
            .leases
            .borrow()
            .revision()
            .checked_add(self.driver.revision())
            != Some(observed)
        {
            return Err("stale_provider_observation");
        }
        Ok(())
    }

    fn verify_root(&mut self, root: &Root) -> Result<(), &'static str> {
        if root.phase != Phase::Active {
            return Err("application_policy_requires_recovery");
        }
        let id = target_identity(&root.target)?.1;
        let fingerprint = serde_json::to_string(&root.policy).map_err(|_| "invalid_policy")?;
        if let Some(lease) = &root.rtss_lease
            && !matches!(self.leases.borrow_mut().preflight_apply(OWNER, &id, &fingerprint), ApplyPreflight::AlreadyApplied(found) if found == *lease)
        {
            return Err("application_rtss_policy_unconfirmed");
        }
        if root.driver && self.driver.verify(OWNER, &id, &fingerprint) != Outcome::AlreadyApplied {
            return Err("application_driver_policy_unconfirmed");
        }
        Ok(())
    }

    pub(super) fn restore_root(&mut self, state: &mut State) -> Result<(), &'static str> {
        let root = state.root.as_ref().ok_or("application_root_missing")?;
        let id = target_identity(&root.target)?.1;
        let mut failure = None;
        if (root.driver
            || self
                .driver
                .active_target()
                .is_some_and(|(owner, target)| owner == OWNER && target == id))
            && self.driver.restore(OWNER, &id) != Outcome::Restored
        {
            failure = Some("application_driver_restore_unconfirmed");
        }
        let mut leases: BTreeSet<_> = self
            .leases
            .borrow()
            .records()
            .iter()
            .filter(|lease| lease.owner == OWNER && lease.session_id == id)
            .map(|lease| lease.lease_id.clone())
            .collect();
        leases.extend(root.rtss_lease.iter().cloned());
        for lease in leases {
            if !matches!(
                self.leases
                    .borrow_mut()
                    .restore_exact_lease(OWNER, &id, &lease),
                RestoreOutcome::Restored(_)
            ) {
                failure.get_or_insert("application_rtss_restore_unconfirmed");
            }
        }
        if let Some(reason) = failure {
            return Err(reason);
        }
        self.leases
            .borrow_mut()
            .retire_provider_if_idle()
            .map_err(|error| error.diagnostic())?;
        state.finish();
        state.save(&mut self.leases.borrow_mut())
    }

    pub(super) fn apply(
        &mut self,
        request: &ProviderRequest,
        policy: Option<Policy>,
    ) -> Result<ProviderResponse, &'static str> {
        let mut state = self.root_state()?;
        let (group, id) = target_identity(&request.target)?;
        let completed = state.completed(&id);
        if let Some(root) = state.root.as_mut() {
            let observed = self.validate_claim(request, policy.as_ref())?;
            let same_group = target_identity(&root.target)?.0 == group;
            match request.phase {
                LifecyclePhase::SessionPrepare if root.target == request.target => {
                    if !root.application {
                        return Err("application_root_ended");
                    }
                    if policy.as_ref() != Some(&root.policy) {
                        return Err("application_policy_is_frozen");
                    }
                    self.verify_root(root)?;
                    return Ok(success(request));
                }
                LifecyclePhase::StreamPrepare if same_group => {
                    if policy.as_ref() != Some(&root.policy) {
                        return Err("admission_mismatch");
                    }
                    self.verify_root(root)?;
                    if root.streams.contains(&id) {
                        return Ok(success(request));
                    }
                    if !root.application {
                        return Err("application_root_ended");
                    }
                    if root.retired_streams.contains(&id) || completed {
                        return Err("stream_claim_already_retired");
                    }
                    if root.streams.len() >= 32 && !root.streams.contains(&id) {
                        return Err("stream_claim_capacity");
                    }
                    // Every admitted identity must retain its tombstone until
                    // this application ends; release cannot discard old proof.
                    if root.streams.len() + root.retired_streams.len() >= STREAM_IDENTITY_LIMIT {
                        return Err("stream_retirement_capacity");
                    }
                    self.ensure_observed_revision(observed)?;
                    root.streams.insert(id);
                    state.save(&mut self.leases.borrow_mut())?;
                    return Ok(success(request));
                }
                LifecyclePhase::SessionPrepare | LifecyclePhase::StreamPrepare => {
                    return Err("previous_application_policy_not_retired");
                }
                LifecyclePhase::SessionRelease if root.target == request.target => {
                    if !root.application && root.phase == Phase::Active {
                        return Ok(success(request));
                    }
                    self.ensure_observed_revision(observed)?;
                    root.application = false;
                    if root.streams.is_empty() {
                        root.phase = Phase::Restoring;
                        root.releasing.insert(id);
                    }
                }
                LifecyclePhase::StreamRelease if same_group => {
                    if !root.streams.contains(&id) && !root.releasing.contains(&id) {
                        return Ok(success(request));
                    }
                    self.ensure_observed_revision(observed)?;
                    root.streams.remove(&id);
                    root.retired_streams.insert(id.clone());
                    if !root.application && root.streams.is_empty() {
                        root.phase = Phase::Restoring;
                        root.releasing.insert(id);
                    }
                }
                _ => return Ok(success(request)), // Exact old/foreign release owns no current claim.
            }
            let restoring = root.phase == Phase::Restoring;
            state.save(&mut self.leases.borrow_mut())?;
            if restoring {
                self.restore_root(&mut state)?;
            }
            return Ok(success(request));
        }
        if request.phase == LifecyclePhase::StreamPrepare && state.completed_session(&group) {
            return Err("application_root_ended");
        }
        if matches!(
            request.phase,
            LifecyclePhase::SessionPrepare | LifecyclePhase::StreamPrepare
        ) && state.completed(&id)
        {
            return Err("application_claim_already_retired");
        }
        let result = self.apply_native(request, policy.clone())?;
        if request.phase == LifecyclePhase::SessionPrepare
            && let Some(policy) = policy
        {
            let rtss_lease = self
                .leases
                .borrow()
                .records()
                .iter()
                .find(|lease| lease.owner == OWNER && lease.session_id == id)
                .map(|lease| lease.lease_id.clone());
            let driver = self
                .driver
                .active_target()
                .is_some_and(|(owner, target)| owner == OWNER && target == id);
            if rtss_lease.is_some() || driver {
                state.root = Some(Root {
                    target: request.target.clone(),
                    policy,
                    rtss_lease,
                    driver,
                    application: true,
                    streams: BTreeSet::new(),
                    releasing: BTreeSet::new(),
                    retired_streams: BTreeSet::new(),
                    phase: Phase::Active,
                });
                state.save(&mut self.leases.borrow_mut())?;
            }
        }
        Ok(result)
    }
}

pub(crate) fn validate_root(root: &Root) -> Result<(), &'static str> {
    let LifecycleTarget::Session {
        host_epoch,
        session_id,
        generation,
    } = &root.target
    else {
        return Err("windows_root_journal_invalid");
    };
    let valid_text = |value: &str| {
        !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
    };
    let stream_prefix = format!("{}t.", target_identity(&root.target)?.0);
    if !valid_text(host_epoch)
        || !valid_text(session_id)
        || *generation == 0
        || root.streams.len() > 32
        || root.releasing.len() > 32
        || root.retired_streams.len() > STREAM_IDENTITY_LIMIT
        || root.streams.len() + root.retired_streams.len() > STREAM_IDENTITY_LIMIT
        || root
            .streams
            .iter()
            .chain(&root.releasing)
            .chain(&root.retired_streams)
            .any(|id| !valid_id(id))
        || root
            .streams
            .iter()
            .chain(&root.retired_streams)
            .any(|id| !id.starts_with(&stream_prefix))
        || root
            .streams
            .iter()
            .any(|id| root.releasing.contains(id) || root.retired_streams.contains(id))
        || root.phase == Phase::Active && !root.application && root.streams.is_empty()
        || root.phase == Phase::Restoring && (root.application || !root.streams.is_empty())
        || serde_json::to_vec(&root.policy)
            .map_err(|_| "windows_root_journal_invalid")?
            .len()
            > 4096
        || root.policy.profile != crate::rtss::GLOBAL_PROFILE
        || root.policy.values.frame_limit < 0
        || root.policy.values.frame_limit_denominator <= 0
        || root.policy.driver_limit_millihz == Some(0)
        || root
            .rtss_lease
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 128)
        || root.rtss_lease.is_none() && !root.driver
    {
        return Err("windows_root_journal_invalid");
    }
    Ok(())
}

fn valid_id(id: &str) -> bool {
    id.len() == 86
        && id.starts_with("lc.")
        && id
            .as_bytes()
            .get(35..38)
            .is_some_and(|kind| kind == b".s." || kind == b".t.")
        && id.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 2 | 35 | 37)
                || index == 36 && matches!(byte, b's' | b't')
                || index < 2 && byte == b"lc"[index]
                || byte.is_ascii_hexdigit()
        })
}
