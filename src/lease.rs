//! Caller-owned RTSS leases and compare-before-restore lifecycle.
use crate::{
    FrameLimitSource, FrameLimiterProvider, Platform, RtssFrameLimitType,
    service::{
        ApplyRequest, Operation, OperationResponse, Presence, ProviderAvailability, ResponseState,
        RestoreRequest, StatusRequest, build_response, evaluate_apply, handle_operation,
        handle_payload, parse_operation,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const JOURNAL_FORMAT: u32 = 1;
const JOURNAL_LIMIT_BYTES: u64 = 1024 * 1024;
const COMPLETED_LEASE_LIMIT: usize = 256;
static NEXT_LEASE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ProfileValues {
    pub frame_limit: i32,
    pub frame_limit_denominator: i32,
    pub sync_limiter: i32,
}

pub(crate) const DEFAULT_PROFILE: ProfileValues = ProfileValues {
    frame_limit: 0,
    frame_limit_denominator: 1,
    sync_limiter: 0,
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ProviderSnapshot {
    pub profile: ProfileValues,
    pub profile_exists: bool,
    pub limiter_disabled: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LeasePhase {
    Pending,
    #[default]
    Active,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct LeaseRecord {
    pub lease_id: String,
    pub owner: String,
    pub session_id: String,
    pub request_fingerprint: String,
    pub rtss_install_path: String,
    pub executable_path: String,
    pub profile: String,
    pub before: ProviderSnapshot,
    pub applied: ProviderSnapshot,
    #[serde(default)]
    pub manage_limiter_enable: bool,
    /// A default profile created by this intent remains after cleanup, as an
    /// initialized RTSS configuration; cleanup removes its temporary cap.
    #[serde(default)]
    pub initialized_profile: bool,
    #[serde(default)]
    pub phase: LeasePhase,
}

pub(crate) struct LeaseApplyRequest<'a> {
    pub owner: &'a str,
    pub session_id: &'a str,
    pub executable_path: &'a str,
    pub rtss_install_path: &'a str,
    pub profile: &'a str,
    pub request_fingerprint: &'a str,
    pub desired_profile: ProfileValues,
    /// Global lifecycle policies may enable RTSS while holding the lease.
    /// Compatibility requests for an executable do not change this global bit.
    pub enable_limiter: bool,
    pub initialize_profile: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnedLeaseStatus {
    pub lease_id: String,
    pub session_id: String,
    pub executable_path: String,
    pub state: &'static str,
    pub diagnostic: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProviderError {
    Unavailable(&'static str),
    #[cfg(any(windows, test))]
    ReadFailed(&'static str),
    /// A locked profile-file comparison observed a different limiter snapshot.
    #[cfg(any(windows, test))]
    ProfileMismatch {
        code: &'static str,
        observed: ProfileValues,
    },
    VerifyFailed(&'static str),
    /// Create-new lost a race before changing any bytes.
    #[cfg(any(windows, test))]
    CreationConflict(&'static str),
}

impl ProviderError {
    pub(crate) fn diagnostic(&self) -> &'static str {
        match self {
            Self::Unavailable(code) | Self::VerifyFailed(code) => code,
            #[cfg(any(windows, test))]
            Self::CreationConflict(code) => code,
            #[cfg(any(windows, test))]
            Self::ReadFailed(code) => code,
            #[cfg(any(windows, test))]
            Self::ProfileMismatch { code, .. } => code,
        }
    }
}

/// Provider operations are split by profile values and the global limiter bit
/// so the lease manager can preserve unrelated global RTSS flags.
pub(crate) trait FrameLimitProvider {
    fn select_installation(&mut self, path: &str) -> Result<String, ProviderError>;
    /// Effectful preparation is separate from read-only provider probes.
    fn prepare_installation(&mut self, path: &str) -> Result<String, ProviderError> {
        self.select_installation(path)
    }
    #[cfg(any(windows, test))]
    fn retire_idle(&mut self) -> Result<(), ProviderError> {
        Ok(())
    }
    fn profile_exists(&mut self, profile: &str) -> Result<bool, ProviderError>;
    fn read_profile(&mut self, profile: &str) -> Result<ProfileValues, ProviderError>;
    fn ensure_safe_writes_supported(&mut self) -> Result<(), ProviderError>;
    fn missing_profile_baseline(&mut self, _profile: &str) -> Result<ProfileValues, ProviderError> {
        Err(ProviderError::Unavailable(
            "rtss_profile_missing_safe_create_unsupported",
        ))
    }
    fn create_profile_verified(
        &mut self,
        _profile: &str,
        _values: ProfileValues,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable(
            "rtss_profile_missing_safe_create_unsupported",
        ))
    }
    /// Writes only when the current values match `expected`. `ProfileMismatch`
    /// includes the exact values observed under the provider's write guard.
    fn write_profile_verified(
        &mut self,
        profile: &str,
        expected: ProfileValues,
        values: ProfileValues,
    ) -> Result<(), ProviderError>;
    fn limiter_disabled(&mut self) -> Result<bool, ProviderError>;
    fn ensure_limiter_flag_writes_supported(&mut self) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable(
            "rtss_limiter_flag_write_unsupported",
        ))
    }
    fn set_limiter_disabled_verified(
        &mut self,
        expected: bool,
        desired: bool,
    ) -> Result<(), ProviderError> {
        if self.limiter_disabled()? != expected {
            return Err(ProviderError::VerifyFailed("rtss_limiter_flag_changed"));
        }
        if expected == desired {
            Ok(())
        } else {
            Err(ProviderError::Unavailable(
                "rtss_limiter_flag_write_unsupported",
            ))
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    format_version: u32,
    #[serde(default = "initial_revision")]
    revision: u64,
    leases: Vec<LeaseRecord>,
    #[serde(default)]
    completed: Vec<CompletedLease>,
}

impl Default for Journal {
    fn default() -> Self {
        Self {
            format_version: JOURNAL_FORMAT,
            revision: initial_revision(),
            leases: Vec::new(),
            completed: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct CompletedLease {
    lease_id: String,
    owner: String,
    session_id: String,
}

pub(crate) struct LeaseManager<P> {
    provider: P,
    leases: BTreeMap<String, LeaseRecord>,
    completed: BTreeMap<String, CompletedLease>,
    journal_path: Option<PathBuf>,
    revision: u64,
}

fn initial_revision() -> u64 {
    1
}

impl<P: FrameLimitProvider> LeaseManager<P> {
    #[cfg(test)]
    pub(crate) fn in_memory(provider: P) -> Self {
        Self {
            provider,
            leases: BTreeMap::new(),
            completed: BTreeMap::new(),
            journal_path: None,
            revision: initial_revision(),
        }
    }

    pub(crate) fn open(provider: P, path: PathBuf) -> Result<Self, &'static str> {
        let journal = load_journal(&path)?;
        let leases = journal
            .leases
            .into_iter()
            .map(|lease| (lease.lease_id.clone(), lease))
            .collect();
        let completed = journal
            .completed
            .into_iter()
            .map(|lease| (lease.lease_id.clone(), lease))
            .collect();
        Ok(Self {
            provider,
            leases,
            completed,
            journal_path: Some(path),
            revision: journal.revision,
        })
    }

    pub(crate) fn apply(&mut self, request: LeaseApplyRequest<'_>) -> ApplyOutcome {
        let LeaseApplyRequest {
            owner,
            session_id,
            executable_path,
            rtss_install_path,
            profile,
            request_fingerprint,
            desired_profile,
            enable_limiter,
            initialize_profile,
        } = request;
        if let Some(existing) = self
            .leases
            .values()
            .find(|lease| lease.owner == owner && lease.session_id == session_id)
            .cloned()
        {
            if existing.executable_path == executable_path
                && existing.profile == profile
                && existing.request_fingerprint == request_fingerprint
                && existing.applied.profile == desired_profile
                && existing.manage_limiter_enable == enable_limiter
                && existing.applied.profile_exists
            {
                return match self.confirmed_active_state(&existing) {
                    Ok(true) => ApplyOutcome::AlreadyApplied(existing.clone()),
                    Ok(false) => ApplyOutcome::Stale(existing.lease_id.clone()),
                    Err(error) => ApplyOutcome::Unavailable(error.diagnostic()),
                };
            }
            return ApplyOutcome::Conflict("session_already_has_a_different_lease");
        }

        let normalized_install_path = match self.provider.prepare_installation(rtss_install_path) {
            Ok(path) => path,
            Err(error) => return ApplyOutcome::Unavailable(error.diagnostic()),
        };

        if self.leases.values().any(|lease| {
            lease
                .rtss_install_path
                .eq_ignore_ascii_case(&normalized_install_path)
                && lease.profile.eq_ignore_ascii_case(profile)
        }) {
            return ApplyOutcome::Conflict("rtss_profile_is_owned_by_another_session");
        }

        let before_exists = match self.provider.profile_exists(profile) {
            Ok(exists) => exists,
            Err(error) => return ApplyOutcome::Unavailable(error.diagnostic()),
        };
        let before_profile = match if before_exists {
            self.provider.read_profile(profile)
        } else if initialize_profile {
            self.provider.missing_profile_baseline(profile)
        } else {
            Err(ProviderError::Unavailable(
                "rtss_profile_missing_safe_create_unsupported",
            ))
        } {
            Ok(values) => values,
            Err(error) => return ApplyOutcome::Unavailable(error.diagnostic()),
        };
        let before_disabled = match self.provider.limiter_disabled() {
            Ok(disabled) => disabled,
            Err(error) => return ApplyOutcome::Unavailable(error.diagnostic()),
        };
        let before = ProviderSnapshot {
            profile: before_profile,
            profile_exists: before_exists,
            limiter_disabled: before_disabled,
        };
        if before_disabled && !enable_limiter {
            return ApplyOutcome::Unavailable("rtss_limiter_disabled_globally");
        }
        if before_disabled && let Err(error) = self.provider.ensure_limiter_flag_writes_supported()
        {
            return ApplyOutcome::Unavailable(error.diagnostic());
        }
        if let Err(error) = self.provider.ensure_safe_writes_supported() {
            return ApplyOutcome::Unavailable(error.diagnostic());
        }
        let applied = ProviderSnapshot {
            profile: desired_profile,
            profile_exists: true,
            limiter_disabled: if enable_limiter {
                false
            } else {
                before_disabled
            },
        };

        let mut record = LeaseRecord {
            lease_id: next_lease_id(),
            owner: owner.to_owned(),
            session_id: session_id.to_owned(),
            request_fingerprint: request_fingerprint.to_owned(),
            rtss_install_path: normalized_install_path,
            executable_path: executable_path.to_owned(),
            profile: profile.to_owned(),
            before,
            applied,
            manage_limiter_enable: enable_limiter,
            initialized_profile: !before_exists && initialize_profile,
            phase: LeasePhase::Pending,
        };
        self.leases.insert(record.lease_id.clone(), record.clone());
        if let Err(code) = self.persist() {
            self.leases.remove(&record.lease_id);
            return ApplyOutcome::Unavailable(code);
        }

        if record.initialized_profile
            && let Err(error) = self
                .provider
                .create_profile_verified(profile, before_profile)
        {
            return match error {
                #[cfg(any(windows, test))]
                ProviderError::CreationConflict(code) => {
                    self.discard_unmutated_pending_apply(record, code)
                }
                error => self.rollback_pending_apply(record, error.diagnostic()),
            };
        }

        if let Err(error) =
            self.provider
                .write_profile_verified(profile, before.profile, desired_profile)
        {
            return match error {
                #[cfg(any(windows, test))]
                ProviderError::ProfileMismatch { code, .. } => {
                    self.discard_unmutated_pending_apply(record, code)
                }
                error => self.rollback_pending_apply(record, error.diagnostic()),
            };
        }

        if before.limiter_disabled != applied.limiter_disabled
            && let Err(error) = self
                .provider
                .set_limiter_disabled_verified(before.limiter_disabled, applied.limiter_disabled)
        {
            return self.rollback_pending_apply(record, error.diagnostic());
        }

        match self.current_state(&record) {
            Ok(true) => {
                record.phase = LeasePhase::Active;
                self.leases.insert(record.lease_id.clone(), record.clone());
                if self.persist().is_err() {
                    // Keep the applied effect and verified lease visible in
                    // memory; startup will report stale if its exact snapshot
                    // was not durably recorded.
                    record.phase = LeasePhase::Pending;
                    self.leases.insert(record.lease_id.clone(), record.clone());
                    return ApplyOutcome::RestoreFailed {
                        code: "lease_journal_update_failed",
                        rollback_code: "lease_journal_update_failed",
                    };
                }
                ApplyOutcome::Applied(record)
            }
            Ok(false) => self.rollback_after_unverified_apply(record),
            Err(error) => {
                let code = error.diagnostic();
                self.rollback_after_unverified_apply_with_error(record, code)
            }
        }
    }

    pub(crate) fn status(
        &mut self,
        owner: &str,
        session_id: Option<&str>,
    ) -> Vec<OwnedLeaseStatus> {
        let owned: Vec<LeaseRecord> = self
            .leases
            .values()
            .filter(|lease| {
                lease.owner == owner && session_id.is_none_or(|session| lease.session_id == session)
            })
            .cloned()
            .collect();
        self.status_for_records(owned)
    }

    pub(crate) fn status_for_lease(
        &mut self,
        owner: &str,
        lease_id: &str,
    ) -> Vec<OwnedLeaseStatus> {
        let owned = self
            .leases
            .get(lease_id)
            .filter(|lease| lease.owner == owner)
            .cloned()
            .into_iter()
            .collect();
        self.status_for_records(owned)
    }

    fn status_for_records(&mut self, owned: Vec<LeaseRecord>) -> Vec<OwnedLeaseStatus> {
        let mut results = Vec::with_capacity(owned.len());
        for lease in owned {
            let provider_state = self.confirmed_active_state(&lease);
            let (state, diagnostic) = if lease.phase == LeasePhase::Pending {
                match provider_state {
                    Err(error) => ("stale_lease", Some(error.diagnostic())),
                    Ok(_) => ("stale_lease", Some("pending_apply_not_verified")),
                }
            } else {
                match provider_state {
                    Ok(true) => ("applied", None),
                    Ok(false) => ("stale_lease", Some("provider_state_changed")),
                    Err(error) => ("stale_lease", Some(error.diagnostic())),
                }
            };
            results.push(OwnedLeaseStatus {
                lease_id: lease.lease_id,
                session_id: lease.session_id,
                executable_path: lease.executable_path,
                state,
                diagnostic,
            });
        }
        results
    }

    pub(crate) fn preflight_apply(
        &mut self,
        owner: &str,
        session_id: &str,
        request_fingerprint: &str,
    ) -> ApplyPreflight {
        if let Some(lease) = self
            .leases
            .values()
            .find(|lease| lease.owner == owner && lease.session_id == session_id)
            .cloned()
        {
            if lease.request_fingerprint != request_fingerprint {
                return ApplyPreflight::Conflict("session_already_has_a_different_lease");
            }
            if lease.phase == LeasePhase::Pending {
                return ApplyPreflight::Stale(lease.lease_id);
            }
            return match self.confirmed_active_state(&lease) {
                Ok(true) => ApplyPreflight::AlreadyApplied(lease.lease_id),
                Ok(false) => ApplyPreflight::Stale(lease.lease_id),
                Err(error) => ApplyPreflight::Unavailable(error.diagnostic()),
            };
        }
        if self
            .completed
            .values()
            .any(|lease| lease.owner == owner && lease.session_id == session_id)
        {
            return ApplyPreflight::Conflict("session_lease_already_restored");
        }
        ApplyPreflight::Continue
    }

    pub(crate) fn probe_provider(&mut self) -> Result<(), ProviderError> {
        self.provider.select_installation("").map(|_| ())
    }

    #[cfg(any(windows, test))]
    pub(crate) fn retire_provider_if_idle(&mut self) -> Result<(), ProviderError> {
        if self.leases.is_empty() {
            self.provider.retire_idle()?;
        }
        Ok(())
    }

    pub(crate) fn restore(
        &mut self,
        owner: &str,
        session_id: Option<&str>,
        lease_id: Option<&str>,
    ) -> RestoreOutcome {
        let targets: Vec<String> = self
            .leases
            .values()
            .filter(|lease| {
                lease.owner == owner
                    && match (session_id, lease_id) {
                        (Some(session), None) => lease.session_id == session,
                        (None, Some(id)) => lease.lease_id == id,
                        _ => false,
                    }
            })
            .map(|lease| lease.lease_id.clone())
            .collect();
        if targets.is_empty() {
            let completed: Vec<String> = self
                .completed
                .values()
                .filter(|lease| {
                    lease.owner == owner
                        && match (session_id, lease_id) {
                            (Some(session), None) => lease.session_id == session,
                            (None, Some(id)) => lease.lease_id == id,
                            _ => false,
                        }
                })
                .map(|lease| lease.lease_id.clone())
                .collect();
            if !completed.is_empty() {
                return RestoreOutcome::Restored(completed);
            }
            return RestoreOutcome::NotFound;
        }

        let previous_leases = self.leases.clone();
        let previous_completed = self.completed.clone();

        let mut restored = Vec::new();
        for id in targets {
            let Some(lease) = self.leases.get(&id).cloned() else {
                continue;
            };
            match self.restore_one(&lease) {
                Ok(()) => {
                    self.leases.remove(&id);
                    self.completed.insert(
                        id.clone(),
                        CompletedLease {
                            lease_id: lease.lease_id.clone(),
                            owner: lease.owner.clone(),
                            session_id: lease.session_id.clone(),
                        },
                    );
                    restored.push(id);
                }
                Err(RestoreFailure::Stale) => return RestoreOutcome::Stale(lease.lease_id),
                Err(RestoreFailure::Provider(code)) => {
                    return RestoreOutcome::Failed {
                        lease_id: lease.lease_id,
                        code,
                    };
                }
            }
        }
        if let Err(code) = self.persist() {
            // Native restoration may already have succeeded. Retain its exact
            // ownership evidence until the durable journal also confirms it.
            self.leases = previous_leases;
            self.completed = previous_completed;
            return RestoreOutcome::Failed {
                lease_id: restored.first().cloned().unwrap_or_default(),
                code,
            };
        }
        RestoreOutcome::Restored(restored)
    }

    #[cfg(any(windows, test))]
    pub(crate) fn records(&self) -> Vec<LeaseRecord> {
        self.leases.values().cloned().collect()
    }

    #[cfg(any(windows, test))]
    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }

    /// Reconciles the durable journal with RTSS before accepting new requests.
    /// Pending intents at their applied state become active. Intents still at
    /// their before-state are finalized. A known partial profile/enable-flag
    /// transaction returns to its before-state; unrelated state stays stale.
    pub(crate) fn recover(&mut self) -> Result<(), &'static str> {
        let leases: Vec<LeaseRecord> = self.leases.values().cloned().collect();
        let mut changed = false;
        for lease in leases {
            let current = self
                .provider
                .prepare_installation(&lease.rtss_install_path)
                .and_then(|_| self.read_provider_snapshot(&lease.profile));
            let Ok(current) = current else {
                continue;
            };
            if self.snapshot_matches_before(&lease, current) {
                self.leases.remove(&lease.lease_id);
                self.completed.insert(
                    lease.lease_id.clone(),
                    CompletedLease {
                        lease_id: lease.lease_id.clone(),
                        owner: lease.owner,
                        session_id: lease.session_id,
                    },
                );
                changed = true;
            } else if self
                .snapshot_matches_applied(&lease, current)
                .unwrap_or(false)
                && lease.phase == LeasePhase::Pending
                && (lease.manage_limiter_enable
                    || lease.before.limiter_disabled == lease.applied.limiter_disabled)
                && self.provider.ensure_safe_writes_supported().is_ok()
                && (lease.before.limiter_disabled == lease.applied.limiter_disabled
                    || self.provider.ensure_limiter_flag_writes_supported().is_ok())
            {
                let mut active = lease;
                active.phase = LeasePhase::Active;
                self.leases.insert(active.lease_id.clone(), active);
                changed = true;
            } else if lease.phase == LeasePhase::Pending
                && lease.manage_limiter_enable
                && lease.before.limiter_disabled != lease.applied.limiter_disabled
                && (self.snapshot_matches_before_profile(&lease, current)
                    || self
                        .snapshot_matches_applied_profile(&lease, current)
                        .unwrap_or(false))
                && self.restore_one(&lease).is_ok()
            {
                self.leases.remove(&lease.lease_id);
                self.completed.insert(
                    lease.lease_id.clone(),
                    CompletedLease {
                        lease_id: lease.lease_id,
                        owner: lease.owner,
                        session_id: lease.session_id,
                    },
                );
                changed = true;
            }
        }
        if changed {
            self.persist()?;
        }
        Ok(())
    }

    fn current_state(&mut self, lease: &LeaseRecord) -> Result<bool, ProviderError> {
        self.provider
            .select_installation(&lease.rtss_install_path)?;
        let current = self.read_provider_snapshot(&lease.profile)?;
        self.snapshot_matches_applied(lease, current)
    }

    fn confirmed_active_state(&mut self, lease: &LeaseRecord) -> Result<bool, ProviderError> {
        if lease.phase == LeasePhase::Pending
            || (!lease.manage_limiter_enable
                && lease.before.limiter_disabled != lease.applied.limiter_disabled)
        {
            return Ok(false);
        }
        // A lease imported from an older journal may still match its applied
        // values even though this provider can no longer restore them safely.
        // Do not advertise that record as an active, retryable effect.
        self.provider.ensure_safe_writes_supported()?;
        if lease.before.limiter_disabled != lease.applied.limiter_disabled {
            self.provider.ensure_limiter_flag_writes_supported()?;
        }
        self.current_state(lease)
    }

    fn restore_one(&mut self, lease: &LeaseRecord) -> Result<(), RestoreFailure> {
        if !lease.manage_limiter_enable
            && lease.before.limiter_disabled != lease.applied.limiter_disabled
        {
            return Err(RestoreFailure::Stale);
        }
        self.provider
            .prepare_installation(&lease.rtss_install_path)
            .map_err(|error| RestoreFailure::Provider(error.diagnostic()))?;
        self.provider
            .ensure_safe_writes_supported()
            .map_err(|error| RestoreFailure::Provider(error.diagnostic()))?;
        if lease.before.limiter_disabled != lease.applied.limiter_disabled {
            self.provider
                .ensure_limiter_flag_writes_supported()
                .map_err(|error| RestoreFailure::Provider(error.diagnostic()))?;
        }
        let current_profile = self
            .read_provider_snapshot(&lease.profile)
            .map_err(|error| RestoreFailure::Provider(error.diagnostic()))?;
        let disabled = current_profile.limiter_disabled;
        let profile_at_applied = self
            .snapshot_matches_applied_profile(lease, current_profile)
            .map_err(|error| RestoreFailure::Provider(error.diagnostic()))?;
        let profile_at_before = self.snapshot_matches_before_profile(lease, current_profile);
        let flag_at_applied = disabled == lease.applied.limiter_disabled;
        let flag_at_before = disabled == lease.before.limiter_disabled;
        if !profile_at_applied && !profile_at_before {
            return Err(RestoreFailure::Stale);
        }
        if !flag_at_applied && !flag_at_before {
            return Err(RestoreFailure::Stale);
        }

        if profile_at_applied {
            if !lease.before.profile_exists && !lease.initialized_profile {
                return Err(RestoreFailure::Stale);
            }
            match self.provider.write_profile_verified(
                &lease.profile,
                lease.applied.profile,
                lease.before.profile,
            ) {
                Ok(()) => (),
                #[cfg(any(windows, test))]
                Err(ProviderError::ProfileMismatch { observed, .. }) => {
                    // Only a locked observation of the original values can
                    // prove that another writer already restored the profile.
                    if observed != lease.before.profile {
                        return Err(RestoreFailure::Stale);
                    }
                    self.confirm_profile_at_before(lease)?;
                }
                Err(error) => return Err(RestoreFailure::Provider(error.diagnostic())),
            }
        } else if current_profile.profile_exists {
            // Hooks can lag a direct file edit. Even when its snapshot already
            // equals the before state, confirm that state under the file guard.
            self.confirm_profile_at_before(lease)?;
        }
        if !flag_at_before {
            self.provider
                .set_limiter_disabled_verified(disabled, lease.before.limiter_disabled)
                .map_err(|error| RestoreFailure::Provider(error.diagnostic()))?;
        }
        if !self
            .exactly_at_before(lease)
            .map_err(|error| RestoreFailure::Provider(error.diagnostic()))?
        {
            return Err(RestoreFailure::Provider("restore_verification_failed"));
        }
        Ok(())
    }

    fn confirm_profile_at_before(&mut self, lease: &LeaseRecord) -> Result<(), RestoreFailure> {
        match self.provider.write_profile_verified(
            &lease.profile,
            lease.before.profile,
            lease.before.profile,
        ) {
            Ok(()) => Ok(()),
            #[cfg(any(windows, test))]
            Err(ProviderError::ProfileMismatch { .. }) => Err(RestoreFailure::Stale),
            Err(error) => Err(RestoreFailure::Provider(error.diagnostic())),
        }
    }

    fn exactly_at_before(&mut self, lease: &LeaseRecord) -> Result<bool, ProviderError> {
        self.provider
            .select_installation(&lease.rtss_install_path)?;
        let current = self.read_provider_snapshot(&lease.profile)?;
        Ok(self.snapshot_matches_before(lease, current))
    }

    fn snapshot_matches_before(&self, lease: &LeaseRecord, current: ProviderSnapshot) -> bool {
        self.snapshot_matches_before_profile(lease, current)
            && current.limiter_disabled == lease.before.limiter_disabled
    }

    fn snapshot_matches_before_profile(
        &self,
        lease: &LeaseRecord,
        current: ProviderSnapshot,
    ) -> bool {
        if lease.before.profile_exists {
            current.profile_exists && current.profile == lease.before.profile
        } else {
            !current.profile_exists
                || (lease.initialized_profile && current.profile == lease.before.profile)
        }
    }

    fn snapshot_matches_applied(
        &self,
        lease: &LeaseRecord,
        current: ProviderSnapshot,
    ) -> Result<bool, ProviderError> {
        Ok(self.snapshot_matches_applied_profile(lease, current)?
            && current.limiter_disabled == lease.applied.limiter_disabled)
    }

    fn snapshot_matches_applied_profile(
        &self,
        lease: &LeaseRecord,
        current: ProviderSnapshot,
    ) -> Result<bool, ProviderError> {
        if !current.profile_exists || current.profile != lease.applied.profile {
            return Ok(false);
        }
        Ok((lease.before.profile_exists || lease.initialized_profile)
            && lease.applied.profile_exists)
    }

    fn rollback_unleased(&mut self, lease: &LeaseRecord) -> Result<(), ProviderError> {
        self.provider
            .select_installation(&lease.rtss_install_path)?;
        let current = self.read_provider_snapshot(&lease.profile)?;
        if self.snapshot_matches_before(lease, current) {
            return Ok(());
        }
        self.restore_one(lease).map_err(|error| match error {
            RestoreFailure::Stale => {
                ProviderError::VerifyFailed("provider_state_changed_before_rollback")
            }
            RestoreFailure::Provider(code) => ProviderError::VerifyFailed(code),
        })
    }

    fn read_provider_snapshot(&mut self, profile: &str) -> Result<ProviderSnapshot, ProviderError> {
        let exists = self.provider.profile_exists(profile)?;
        Ok(ProviderSnapshot {
            profile: if exists {
                self.provider.read_profile(profile)?
            } else {
                DEFAULT_PROFILE
            },
            profile_exists: exists,
            limiter_disabled: self.provider.limiter_disabled()?,
        })
    }

    fn rollback_after_unverified_apply(&mut self, lease: LeaseRecord) -> ApplyOutcome {
        self.rollback_after_unverified_apply_with_error(lease, "provider_readback_mismatch")
    }

    fn rollback_after_unverified_apply_with_error(
        &mut self,
        lease: LeaseRecord,
        code: &'static str,
    ) -> ApplyOutcome {
        let result = self.rollback_unleased(&lease);
        match result {
            Err(error) => ApplyOutcome::RestoreFailed {
                code,
                rollback_code: error.diagnostic(),
            },
            Ok(()) => {
                self.leases.remove(&lease.lease_id);
                if let Err(journal_code) = self.persist() {
                    self.leases.insert(lease.lease_id.clone(), lease);
                    ApplyOutcome::RestoreFailed {
                        code,
                        rollback_code: journal_code,
                    }
                } else {
                    ApplyOutcome::Unavailable(code)
                }
            }
        }
    }

    fn rollback_pending_apply(&mut self, lease: LeaseRecord, code: &'static str) -> ApplyOutcome {
        match self.rollback_unleased(&lease) {
            Err(error) => ApplyOutcome::RestoreFailed {
                code,
                rollback_code: error.diagnostic(),
            },
            Ok(()) => {
                self.leases.remove(&lease.lease_id);
                if let Err(journal_code) = self.persist() {
                    self.leases.insert(lease.lease_id.clone(), lease);
                    ApplyOutcome::RestoreFailed {
                        code,
                        rollback_code: journal_code,
                    }
                } else {
                    ApplyOutcome::Unavailable(code)
                }
            }
        }
    }

    #[cfg(any(windows, test))]
    fn discard_unmutated_pending_apply(
        &mut self,
        lease: LeaseRecord,
        code: &'static str,
    ) -> ApplyOutcome {
        self.leases.remove(&lease.lease_id);
        if self.persist().is_err() {
            self.leases.insert(lease.lease_id.clone(), lease);
            return ApplyOutcome::RestoreFailed {
                code,
                rollback_code: "lease_journal_update_failed",
            };
        }
        ApplyOutcome::Unavailable(code)
    }

    fn persist(&mut self) -> Result<(), &'static str> {
        let next = self
            .revision
            .checked_add(1)
            .ok_or("lease_revision_exhausted")?;
        if let Some(path) = &self.journal_path {
            save_journal(
                path,
                next,
                self.leases.values().cloned().collect(),
                self.completed.values().cloned().collect(),
            )?;
        }
        self.revision = next;
        Ok(())
    }
}

/// Applies the `amaterasu.frame-limiter/1` operation against a real provider
/// while preserving the strict v1 parsing and pure policy response plan.
pub(crate) fn handle_runtime_operation<P: FrameLimitProvider>(
    caller: &str,
    payload: serde_json::Value,
    manager: &mut LeaseManager<P>,
) -> serde_json::Value {
    if caller.trim().is_empty() || caller.len() > 128 || caller.chars().any(char::is_control) {
        let valid_probe = Operation::Status(StatusRequest {
            version: crate::CONTRACT_VERSION,
            session_id: Presence::Missing,
        });
        return handle_operation(caller, valid_probe);
    }

    let operation_json = match serde_json::to_string(&payload) {
        Ok(json) => json,
        Err(_) => return handle_payload(caller, payload),
    };
    let operation = match parse_operation(&operation_json) {
        Ok(operation) => operation,
        Err(_) => return handle_payload(caller, payload),
    };
    let mut response = match build_response(&operation) {
        Ok(response) => response,
        Err(_) => return handle_operation(caller, operation),
    };

    match operation {
        Operation::Apply(request) => handle_apply(caller, request, manager, &mut response),
        Operation::Status(request) => handle_status(caller, request, manager, &mut response),
        Operation::Restore(request) => handle_restore(caller, request, manager, &mut response),
    }
    serde_json::to_value(response).unwrap_or_else(|_| {
        handle_payload(
            caller,
            serde_json::json!({"action":"status", "version":crate::CONTRACT_VERSION}),
        )
    })
}

fn handle_apply<P: FrameLimitProvider>(
    caller: &str,
    request: ApplyRequest,
    manager: &mut LeaseManager<P>,
    response: &mut OperationResponse,
) {
    let fingerprint = match serde_json::to_string(&request) {
        Ok(fingerprint) => fingerprint,
        Err(_) => {
            set_unavailable(response, "request_fingerprint_failed");
            return;
        }
    };
    match manager.preflight_apply(caller, &request.session_id, &fingerprint) {
        ApplyPreflight::Continue => (),
        ApplyPreflight::AlreadyApplied(lease) => {
            response.state = ResponseState::AlreadyApplied;
            response.applied = true;
            response.lease = Some(lease);
            response.provider_availability = ProviderAvailability::Available;
            response.diagnostics.clear();
            update_plan_availability(response);
            return;
        }
        ApplyPreflight::Conflict(code) => {
            set_conflict(response, code, ProviderAvailability::Unknown);
            attach_session_leases(response, manager, caller, &request.session_id);
            return;
        }
        ApplyPreflight::Stale(_) => {
            response.state = ResponseState::StaleLease;
            response.provider_availability = ProviderAvailability::Available;
            response
                .diagnostics
                .push("existing_session_lease_is_stale".into());
            attach_session_leases(response, manager, caller, &request.session_id);
            return;
        }
        ApplyPreflight::Unavailable(code) => {
            set_unavailable(response, code);
            attach_session_leases(response, manager, caller, &request.session_id);
            return;
        }
    }

    let settings = match request.settings.to_model(current_platform()) {
        Ok(settings) => settings,
        Err(_) => {
            set_unavailable(response, "invalid_settings");
            return;
        }
    };
    let decision = match evaluate_apply(&request) {
        Ok(decision) => decision,
        Err(_) => {
            set_unavailable(response, "policy_evaluation_failed");
            return;
        }
    };
    if !matches!(
        settings.provider,
        FrameLimiterProvider::Auto | FrameLimiterProvider::Rtss
    ) {
        set_unavailable(response, "selected_provider_not_implemented");
        return;
    }
    if current_platform() != Platform::Windows {
        set_unavailable(response, "rtss_supported_on_windows_only");
        return;
    }
    if settings.disable_vsync {
        set_unavailable(response, "rtss_cannot_apply_disable_vsync");
        return;
    }
    if !request.settings.rtss_install_path.trim().is_empty()
        && !Path::new(&request.settings.rtss_install_path).is_absolute()
    {
        set_unavailable(response, "rtss_install_path_not_absolute");
        return;
    }
    let Some(plan) = response.plan.as_ref() else {
        set_unavailable(response, "policy_plan_unavailable");
        return;
    };
    match plan.should_consider_apply {
        Some(false) => {
            response.state = ResponseState::NotNeeded;
            response.provider_availability = ProviderAvailability::Unknown;
            response
                .diagnostics
                .push("policy_does_not_require_a_limiter".into());
            return;
        }
        None => {
            set_unavailable(response, "policy_context_incomplete");
            return;
        }
        Some(true) => (),
    }
    let Some(limit_millihz) = plan.effective_limit_millihz else {
        set_unavailable(response, "effective_limit_unknown");
        return;
    };
    if limit_millihz == 0 {
        response.state = ResponseState::NotNeeded;
        response.provider_availability = ProviderAvailability::Unknown;
        response
            .diagnostics
            .push("follow_stream_has_no_resolved_rate".into());
        return;
    }

    let profile = match profile_name(&request.executable_path) {
        Some(profile) => profile,
        None => {
            set_unavailable(response, "rtss_profile_name_unsupported");
            return;
        }
    };
    let desired_profile = match desired_rtss_profile(
        decision.effective_limit.source,
        limit_millihz,
        decision.rtss_sync_limiter.value,
    ) {
        Ok(profile) => profile,
        Err(code) => {
            set_unavailable(response, code);
            return;
        }
    };
    match manager.apply(LeaseApplyRequest {
        enable_limiter: false,
        initialize_profile: false,
        owner: caller,
        session_id: &request.session_id,
        executable_path: &request.executable_path,
        rtss_install_path: &request.settings.rtss_install_path,
        profile: &profile,
        request_fingerprint: &fingerprint,
        desired_profile,
    }) {
        ApplyOutcome::Applied(lease) => {
            response.state = ResponseState::Applied;
            response.applied = true;
            response.lease = Some(lease.lease_id);
            response.provider_availability = ProviderAvailability::Available;
            response.diagnostics.clear();
        }
        ApplyOutcome::AlreadyApplied(lease) => {
            response.state = ResponseState::AlreadyApplied;
            response.applied = true;
            response.lease = Some(lease.lease_id);
            response.provider_availability = ProviderAvailability::Available;
            response.diagnostics.clear();
        }
        ApplyOutcome::Conflict(code) => {
            set_conflict(response, code, ProviderAvailability::Available);
        }
        ApplyOutcome::Stale(_) => {
            response.state = ResponseState::StaleLease;
            response.provider_availability = ProviderAvailability::Available;
            response
                .diagnostics
                .push("existing_session_lease_is_stale".into());
        }
        ApplyOutcome::Unavailable(code) => set_unavailable(response, code),
        ApplyOutcome::RestoreFailed {
            code,
            rollback_code,
        } => {
            response.state = ResponseState::RestoreFailed;
            response.provider_availability = ProviderAvailability::Unavailable;
            response.diagnostics.push(code.into());
            response.diagnostics.push(rollback_code.into());
            let statuses = manager.status(caller, Some(&request.session_id));
            response.applied = statuses.iter().any(|status| status.state == "applied");
            response.provider_availability = statuses_provider_availability(&statuses);
            response.leases = statuses.into_iter().map(to_wire_lease_status).collect();
            if response.applied {
                response.lease = response.leases.first().map(|lease| lease.lease.clone());
            }
        }
    }
    update_plan_availability(response);
}

fn handle_status<P: FrameLimitProvider>(
    caller: &str,
    request: StatusRequest,
    manager: &mut LeaseManager<P>,
    response: &mut OperationResponse,
) {
    let session_id = request.session_id.as_ref().map(String::as_str);
    let statuses = manager.status(caller, session_id);
    if statuses.is_empty() {
        response.state = if session_id.is_some() {
            ResponseState::NotFound
        } else {
            ResponseState::NotNeeded
        };
        response.diagnostics.push("no_owned_rtss_lease".into());
        match manager.probe_provider() {
            Ok(()) => response.provider_availability = ProviderAvailability::Available,
            Err(error) => {
                response.provider_availability = ProviderAvailability::Unavailable;
                response.diagnostics.push(error.diagnostic().into());
            }
        }
        return;
    }
    response.applied = statuses.iter().any(|status| status.state == "applied");
    response.state = if statuses.iter().any(|status| status.state == "stale_lease") {
        ResponseState::StaleLease
    } else {
        ResponseState::Applied
    };
    response.provider_availability = statuses_provider_availability(&statuses);
    response.leases = statuses.into_iter().map(to_wire_lease_status).collect();
    response.diagnostics = response
        .leases
        .iter()
        .flat_map(|lease| lease.diagnostics.iter().cloned())
        .collect();
}

fn handle_restore<P: FrameLimitProvider>(
    caller: &str,
    request: RestoreRequest,
    manager: &mut LeaseManager<P>,
    response: &mut OperationResponse,
) {
    let (session_id, lease_id) = match (&request.session_id, &request.lease) {
        (Presence::Value(session), Presence::Missing | Presence::Null) => {
            (Some(session.as_str()), None)
        }
        (Presence::Missing | Presence::Null, Presence::Value(lease)) => {
            (None, Some(lease.as_str()))
        }
        _ => {
            set_unavailable(response, "invalid_restore_target");
            return;
        }
    };
    match manager.restore(caller, session_id, lease_id) {
        RestoreOutcome::Restored(_) => {
            response.state = ResponseState::Restored;
            response.provider_availability = ProviderAvailability::Available;
        }
        RestoreOutcome::NotFound => {
            response.state = ResponseState::NotFound;
            response.diagnostics.push("owned_lease_not_found".into());
            match manager.probe_provider() {
                Ok(()) => response.provider_availability = ProviderAvailability::Available,
                Err(error) => {
                    response.provider_availability = ProviderAvailability::Unavailable;
                    response.diagnostics.push(error.diagnostic().into());
                }
            }
        }
        RestoreOutcome::Stale(_) => {
            response.state = ResponseState::StaleLease;
            response.provider_availability = ProviderAvailability::Available;
            response
                .diagnostics
                .push("provider_state_changed_before_restore".into());
        }
        RestoreOutcome::Failed { lease_id, code } => {
            response.state = ResponseState::RestoreFailed;
            response.diagnostics.push(code.into());
            let statuses = match (session_id, lease_id.as_str()) {
                (Some(session), _) => manager.status(caller, Some(session)),
                (None, lease) => manager.status_for_lease(caller, lease),
            };
            response.applied = statuses.iter().any(|status| status.state == "applied");
            response.provider_availability = statuses_provider_availability(&statuses);
            response.leases = statuses.into_iter().map(to_wire_lease_status).collect();
            if response.applied {
                response.lease = response.leases.first().map(|lease| lease.lease.clone());
            }
        }
    }
}

fn to_wire_lease_status(lease: OwnedLeaseStatus) -> crate::LeaseStatus {
    let stale = lease.state == "stale_lease";
    crate::LeaseStatus {
        lease: lease.lease_id,
        session_id: lease.session_id,
        executable_path: lease.executable_path,
        provider: "rtss".into(),
        state: if stale {
            ResponseState::StaleLease
        } else {
            ResponseState::Applied
        },
        applied: !stale,
        diagnostics: lease.diagnostic.into_iter().map(str::to_owned).collect(),
    }
}

fn set_unavailable(response: &mut OperationResponse, diagnostic: &str) {
    response.state = ResponseState::RuntimeUnavailable;
    response.applied = false;
    response.provider_availability = ProviderAvailability::Unavailable;
    response.diagnostics.push(diagnostic.into());
    update_plan_availability(response);
}

fn set_conflict(
    response: &mut OperationResponse,
    diagnostic: &str,
    availability: ProviderAvailability,
) {
    response.state = ResponseState::LeaseConflict;
    response.applied = false;
    response.provider_availability = availability;
    response.diagnostics.push(diagnostic.into());
    update_plan_availability(response);
}

fn update_plan_availability(response: &mut OperationResponse) {
    if let Some(plan) = response.plan.as_mut() {
        plan.provider_availability = response.provider_availability;
    }
}

fn statuses_provider_availability(statuses: &[OwnedLeaseStatus]) -> ProviderAvailability {
    if statuses.iter().any(|status| status.state == "applied")
        || statuses
            .iter()
            .any(|status| status.diagnostic == Some("provider_state_changed"))
    {
        ProviderAvailability::Available
    } else {
        ProviderAvailability::Unavailable
    }
}

fn attach_session_leases<P: FrameLimitProvider>(
    response: &mut OperationResponse,
    manager: &mut LeaseManager<P>,
    caller: &str,
    session_id: &str,
) {
    let statuses = manager.status(caller, Some(session_id));
    if !statuses.is_empty() {
        if response.provider_availability == ProviderAvailability::Unknown {
            response.provider_availability = statuses_provider_availability(&statuses);
        }
        response.leases = statuses.into_iter().map(to_wire_lease_status).collect();
    }
    update_plan_availability(response);
}

fn current_platform() -> Platform {
    #[cfg(target_os = "windows")]
    {
        Platform::Windows
    }
    #[cfg(target_os = "linux")]
    {
        Platform::Linux
    }
    #[cfg(target_os = "macos")]
    {
        Platform::Macos
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Platform::Macos
    }
}

pub(crate) fn profile_name(executable_path: &str) -> Option<String> {
    let name = executable_path.rsplit(['\\', '/']).next()?;
    if name.is_empty()
        || !name.ends_with(".exe")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return None;
    }
    Some(name.to_owned())
}

fn exact_rtss_ratio(millihz: u32) -> (i32, i32) {
    let divisor = gcd(millihz, 1000);
    ((millihz / divisor) as i32, (1000 / divisor) as i32)
}

pub(crate) fn desired_rtss_profile(
    source: FrameLimitSource,
    effective_limit_millihz: u32,
    sync_limiter: RtssFrameLimitType,
) -> Result<ProfileValues, &'static str> {
    let rtss_limit_millihz = if source == FrameLimitSource::LosslessScaling {
        // The reference caps the game's generated-frame input at half the LS
        // output target, rounding positive half-FPS ties away from zero.
        let rounded_half_rate_fps = (u64::from(effective_limit_millihz) + 1_000) / 2_000;
        let Some(limit) = rounded_half_rate_fps.checked_mul(1_000) else {
            return Err("lossless_scaling_rtss_limit_out_of_range");
        };
        let Ok(limit) = u32::try_from(limit) else {
            return Err("lossless_scaling_rtss_limit_out_of_range");
        };
        if limit == 0 {
            return Err("lossless_scaling_limit_below_rtss_resolution");
        }
        limit
    } else {
        effective_limit_millihz
    };
    let (frame_limit, frame_limit_denominator) = exact_rtss_ratio(rtss_limit_millihz);
    Ok(ProfileValues {
        frame_limit,
        frame_limit_denominator,
        sync_limiter: sync_limiter_value(sync_limiter),
    })
}

fn gcd(mut left: u32, mut right: u32) -> u32 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left.max(1)
}

fn sync_limiter_value(value: RtssFrameLimitType) -> i32 {
    match value {
        RtssFrameLimitType::Async => 0,
        RtssFrameLimitType::FrontEdgeSync => 1,
        RtssFrameLimitType::BackEdgeSync => 2,
        RtssFrameLimitType::NvidiaReflex => 3,
    }
}

enum RestoreFailure {
    Stale,
    Provider(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ApplyOutcome {
    Applied(LeaseRecord),
    AlreadyApplied(LeaseRecord),
    Conflict(&'static str),
    Stale(String),
    Unavailable(&'static str),
    RestoreFailed {
        code: &'static str,
        rollback_code: &'static str,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ApplyPreflight {
    Continue,
    AlreadyApplied(String),
    Conflict(&'static str),
    Stale(String),
    Unavailable(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RestoreOutcome {
    Restored(Vec<String>),
    NotFound,
    Stale(String),
    Failed {
        lease_id: String,
        code: &'static str,
    },
}

fn next_lease_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let sequence = NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed);
    format!("{timestamp:032x}-{sequence:016x}")
}

fn load_journal(path: &Path) -> Result<Journal, &'static str> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Journal::default());
        }
        Err(_) => return Err("lease_journal_unavailable"),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err("lease_journal_invalid_path");
        }
        Ok(_) => (),
    }
    let metadata = fs::metadata(path).map_err(|_| "lease_journal_unavailable")?;
    if metadata.len() > JOURNAL_LIMIT_BYTES {
        return Err("lease_journal_too_large");
    }
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| "lease_journal_unavailable")?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(JOURNAL_LIMIT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "lease_journal_unavailable")?;
    if bytes.len() as u64 > JOURNAL_LIMIT_BYTES {
        return Err("lease_journal_too_large");
    }
    let journal: Journal = serde_json::from_slice(&bytes).map_err(|_| "lease_journal_corrupt")?;
    if journal.format_version != JOURNAL_FORMAT || journal.revision == 0 {
        return Err("lease_journal_version_unsupported");
    }
    let mut identifiers = BTreeMap::new();
    for lease in &journal.leases {
        if lease.lease_id.is_empty()
            || lease.owner.is_empty()
            || lease.session_id.is_empty()
            || lease.profile.is_empty()
            || (lease.initialized_profile
                && (lease.before.profile_exists
                    || !lease.applied.profile_exists
                    || lease.before.profile != DEFAULT_PROFILE))
            || identifiers.insert(lease.lease_id.as_str(), ()).is_some()
        {
            return Err("lease_journal_corrupt");
        }
    }
    Ok(journal)
}

#[cfg(windows)]
pub(crate) fn journal_has_effects(path: &Path) -> Result<bool, &'static str> {
    Ok(!load_journal(path)?.leases.is_empty())
}

fn save_journal(
    path: &Path,
    revision: u64,
    leases: Vec<LeaseRecord>,
    completed: Vec<CompletedLease>,
) -> Result<(), &'static str> {
    let parent = path.parent().ok_or("lease_journal_invalid_path")?;
    fs::create_dir_all(parent).map_err(|_| "lease_journal_unavailable")?;
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => (),
        _ => return Err("lease_journal_invalid_path"),
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("lease_journal_invalid_path"),
    }
    let journal = Journal {
        format_version: JOURNAL_FORMAT,
        revision,
        leases,
        completed: completed
            .into_iter()
            .rev()
            .take(COMPLETED_LEASE_LIMIT)
            .collect(),
    };
    let bytes = serde_json::to_vec(&journal).map_err(|_| "lease_journal_unavailable")?;
    if bytes.len() as u64 > JOURNAL_LIMIT_BYTES {
        return Err("lease_journal_too_large");
    }
    let temp_path = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|_| "lease_journal_unavailable")?;
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|_| "lease_journal_unavailable")?;
        file.sync_all().map_err(|_| "lease_journal_unavailable")?;
        fs::rename(&temp_path, path).map_err(|_| "lease_journal_unavailable")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const START: ProfileValues = ProfileValues {
        frame_limit: 60,
        frame_limit_denominator: 1,
        sync_limiter: 0,
    };
    const TARGET: ProfileValues = ProfileValues {
        frame_limit: 59_500,
        frame_limit_denominator: 1_000,
        sync_limiter: 2,
    };

    fn global_provider() -> FakeProvider {
        let mut provider = FakeProvider::new();
        let global = crate::rtss::GLOBAL_PROFILE.to_owned();
        provider.profiles.insert(global.clone(), START);
        provider.profile_files.insert(global.clone(), START);
        provider.existent_profiles.insert(global, true);
        provider.limiter_disabled = true;
        provider
    }

    fn apply_global(manager: &mut LeaseManager<FakeProvider>) -> ApplyOutcome {
        manager.apply(LeaseApplyRequest {
            enable_limiter: true,
            initialize_profile: true,
            owner: "global-owner",
            session_id: "global-session",
            executable_path: crate::rtss::GLOBAL_PROFILE,
            rtss_install_path: r"C:\RTSS",
            profile: crate::rtss::GLOBAL_PROFILE,
            request_fingerprint: "global-request",
            desired_profile: TARGET,
        })
    }

    fn missing_global_provider() -> FakeProvider {
        let mut provider = global_provider();
        provider.profiles.remove(crate::rtss::GLOBAL_PROFILE);
        provider.profile_files.remove(crate::rtss::GLOBAL_PROFILE);
        provider
            .existent_profiles
            .insert(crate::rtss::GLOBAL_PROFILE.into(), false);
        provider
    }

    #[test]
    fn creation_is_journaled_and_cleanup_retains_the_initialized_default_profile() {
        let root = std::env::temp_dir().join(format!(
            "amaterasu-profile-create-{}-{}",
            std::process::id(),
            NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let journal = root.join("leases.json");
        let mut provider = missing_global_provider();
        provider.journal_path = Some(journal.clone());
        let mut manager = LeaseManager::open(provider, journal.clone()).unwrap();
        let ApplyOutcome::Applied(lease) = apply_global(&mut manager) else {
            panic!("create failed");
        };
        assert!(lease.initialized_profile);
        assert!(!lease.before.profile_exists);
        assert_eq!(lease.before.profile, DEFAULT_PROFILE);
        assert!(manager.provider.durable_creation_intent_seen);
        assert_eq!(manager.provider.created_profiles, 1);
        let provider = manager.provider.clone();
        drop(manager);
        let mut restarted = LeaseManager::open(provider, journal).unwrap();
        restarted.recover().unwrap();
        assert_eq!(
            restarted.restore("global-owner", Some("global-session"), None),
            RestoreOutcome::Restored(vec![lease.lease_id])
        );
        assert_eq!(
            restarted.provider.profiles[crate::rtss::GLOBAL_PROFILE],
            DEFAULT_PROFILE
        );
        assert!(restarted.provider.existent_profiles[crate::rtss::GLOBAL_PROFILE]);
        assert!(restarted.provider.limiter_disabled);
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_profile_initialization_proof_is_rejected_on_restart() {
        let root = std::env::temp_dir().join(format!(
            "amaterasu-profile-proof-{}-{}",
            std::process::id(),
            NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let journal = root.join("leases.json");
        let mut manager = LeaseManager::open(missing_global_provider(), journal.clone()).unwrap();
        let ApplyOutcome::Applied(mut lease) = apply_global(&mut manager) else {
            panic!("create failed");
        };
        lease.before.profile = TARGET;
        save_journal(&journal, manager.revision(), vec![lease], vec![]).unwrap();
        assert!(matches!(
            LeaseManager::open(manager.provider.clone(), journal),
            Err("lease_journal_corrupt")
        ));
        drop(manager);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn create_races_and_external_edits_never_overwrite_the_other_writer() {
        let foreign = ProfileValues {
            frame_limit: 77,
            ..DEFAULT_PROFILE
        };
        let mut provider = missing_global_provider();
        provider.race_before_create = Some(foreign);
        let mut manager = LeaseManager::in_memory(provider);
        assert_eq!(
            apply_global(&mut manager),
            ApplyOutcome::Unavailable("rtss_profile_already_exists")
        );
        assert_eq!(
            manager.provider.profiles[crate::rtss::GLOBAL_PROFILE],
            foreign
        );
        assert!(manager.provider.limiter_disabled);
        assert!(manager.leases.is_empty());
        assert_eq!(manager.provider.created_profiles, 0);
        let mut manager = LeaseManager::in_memory(missing_global_provider());
        let ApplyOutcome::Applied(lease) = apply_global(&mut manager) else {
            panic!("create failed");
        };
        manager
            .provider
            .profiles
            .insert(crate::rtss::GLOBAL_PROFILE.into(), foreign);
        manager
            .provider
            .profile_files
            .insert(crate::rtss::GLOBAL_PROFILE.into(), foreign);
        assert_eq!(
            manager.restore("global-owner", Some("global-session"), None),
            RestoreOutcome::Stale(lease.lease_id)
        );
        assert_eq!(
            manager.provider.profiles[crate::rtss::GLOBAL_PROFILE],
            foreign
        );
        assert!(!manager.provider.limiter_disabled);
    }

    #[test]
    fn abandoned_creation_recovers_a_default_profile_without_claiming_an_active_cap() {
        let mut manager = LeaseManager::in_memory(missing_global_provider());
        let ApplyOutcome::Applied(lease) = apply_global(&mut manager) else {
            panic!("create failed");
        };
        manager.leases.get_mut(&lease.lease_id).unwrap().phase = LeasePhase::Pending;
        manager
            .provider
            .profiles
            .insert(crate::rtss::GLOBAL_PROFILE.into(), DEFAULT_PROFILE);
        manager
            .provider
            .profile_files
            .insert(crate::rtss::GLOBAL_PROFILE.into(), DEFAULT_PROFILE);
        manager.provider.limiter_disabled = true;
        manager.recover().unwrap();
        assert!(manager.leases.is_empty());
        assert_eq!(
            manager.provider.profiles[crate::rtss::GLOBAL_PROFILE],
            DEFAULT_PROFILE
        );
        assert!(manager.provider.limiter_disabled);
    }

    #[test]
    fn global_enable_is_write_ahead_and_restores_the_original_flag_after_restart() {
        let root = std::env::temp_dir().join(format!(
            "amaterasu-global-flag-{}-{}",
            std::process::id(),
            NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let journal = root.join("leases.json");
        let mut provider = global_provider();
        provider.journal_path = Some(journal.clone());
        let mut first = LeaseManager::open(provider, journal.clone()).unwrap();
        let ApplyOutcome::Applied(lease) = apply_global(&mut first) else {
            panic!("global apply failed");
        };
        assert!(lease.before.limiter_disabled);
        assert!(!lease.applied.limiter_disabled);
        assert!(lease.manage_limiter_enable);
        assert!(first.provider.durable_flag_intent_seen);
        assert!(!first.provider.limiter_disabled);
        let provider = first.provider.clone();
        drop(first);
        let mut restarted = LeaseManager::open(provider, journal).unwrap();
        restarted.recover().unwrap();
        assert_eq!(
            restarted.restore("global-owner", Some("global-session"), None),
            RestoreOutcome::Restored(vec![lease.lease_id])
        );
        assert_eq!(
            restarted.provider.profiles[crate::rtss::GLOBAL_PROFILE],
            START
        );
        assert!(restarted.provider.limiter_disabled);
        assert_eq!(
            restarted.provider.flag_writes,
            [(true, false), (false, true)]
        );
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn flag_write_failure_restores_the_profile_without_losing_ownership_on_retry() {
        let mut provider = global_provider();
        provider.fail_flag_writes = true;
        let mut manager = LeaseManager::in_memory(provider);
        assert_eq!(
            apply_global(&mut manager),
            ApplyOutcome::Unavailable("fake_flag_write_failure")
        );
        assert!(manager.leases.is_empty());
        assert_eq!(
            manager.provider.profiles[crate::rtss::GLOBAL_PROFILE],
            START
        );
        assert!(manager.provider.limiter_disabled);
        manager.provider.fail_flag_writes = false;
        let ApplyOutcome::Applied(lease) = apply_global(&mut manager) else {
            panic!("retry failed");
        };
        manager.provider.fail_flag_writes = true;
        assert!(matches!(
            manager.restore("global-owner", Some("global-session"), None),
            RestoreOutcome::Failed {
                code: "fake_flag_write_failure",
                ..
            }
        ));
        assert!(manager.leases.contains_key(&lease.lease_id));
        assert!(!manager.provider.limiter_disabled);
        assert_eq!(
            manager.provider.profiles[crate::rtss::GLOBAL_PROFILE],
            START
        );
        manager.provider.fail_flag_writes = false;
        assert_eq!(
            manager.restore("global-owner", Some("global-session"), None),
            RestoreOutcome::Restored(vec![lease.lease_id])
        );
        assert!(manager.provider.limiter_disabled);
    }

    #[test]
    fn an_old_journal_cannot_claim_ownership_of_an_unattributed_global_flag() {
        let mut manager = LeaseManager::in_memory(global_provider());
        let ApplyOutcome::Applied(lease) = apply_global(&mut manager) else {
            panic!("apply failed");
        };
        let stored = manager.leases.get_mut(&lease.lease_id).unwrap();
        stored.manage_limiter_enable = false;
        stored.phase = LeasePhase::Pending;
        let writes = manager.provider.flag_writes.clone();
        manager.recover().unwrap();
        assert_eq!(manager.status("global-owner", None)[0].state, "stale_lease");
        assert_eq!(
            manager.restore("global-owner", Some("global-session"), None),
            RestoreOutcome::Stale(lease.lease_id)
        );
        assert_eq!(manager.provider.flag_writes, writes);
        assert!(!manager.provider.limiter_disabled);
    }

    #[test]
    fn pending_mixed_profile_and_flag_states_recover_but_foreign_profiles_remain_untouched() {
        for profile_at_before in [false, true] {
            let mut manager = LeaseManager::in_memory(global_provider());
            let ApplyOutcome::Applied(lease) = apply_global(&mut manager) else {
                panic!("apply failed");
            };
            manager.leases.get_mut(&lease.lease_id).unwrap().phase = LeasePhase::Pending;
            if profile_at_before {
                manager
                    .provider
                    .profiles
                    .insert(crate::rtss::GLOBAL_PROFILE.into(), START);
                manager
                    .provider
                    .profile_files
                    .insert(crate::rtss::GLOBAL_PROFILE.into(), START);
            } else {
                manager.provider.limiter_disabled = true;
            }
            manager.recover().unwrap();
            assert!(manager.leases.is_empty());
            assert!(manager.provider.limiter_disabled);
            assert_eq!(
                manager.provider.profiles[crate::rtss::GLOBAL_PROFILE],
                START
            );
        }
        let mut manager = LeaseManager::in_memory(global_provider());
        let ApplyOutcome::Applied(lease) = apply_global(&mut manager) else {
            panic!("apply failed");
        };
        let foreign = ProfileValues {
            frame_limit: 77,
            ..START
        };
        manager
            .provider
            .profiles
            .insert(crate::rtss::GLOBAL_PROFILE.into(), foreign);
        manager
            .provider
            .profile_files
            .insert(crate::rtss::GLOBAL_PROFILE.into(), foreign);
        assert_eq!(
            manager.restore("global-owner", Some("global-session"), None),
            RestoreOutcome::Stale(lease.lease_id)
        );
        assert!(!manager.provider.limiter_disabled);
        assert_eq!(
            manager.provider.profiles[crate::rtss::GLOBAL_PROFILE],
            foreign
        );
    }

    #[test]
    fn lossless_scaling_rtss_limit_uses_rounded_half_rate() {
        let profile = desired_rtss_profile(
            FrameLimitSource::LosslessScaling,
            60_000,
            RtssFrameLimitType::Async,
        )
        .unwrap();
        assert_eq!(profile.frame_limit, 30);
        assert_eq!(profile.frame_limit_denominator, 1);

        let odd_rate = desired_rtss_profile(
            FrameLimitSource::LosslessScaling,
            61_000,
            RtssFrameLimitType::Async,
        )
        .unwrap();
        assert_eq!(odd_rate.frame_limit, 31);
        assert_eq!(odd_rate.frame_limit_denominator, 1);

        let fractional_rate = desired_rtss_profile(
            FrameLimitSource::LosslessScaling,
            60_500,
            RtssFrameLimitType::Async,
        )
        .unwrap();
        assert_eq!(fractional_rate.frame_limit, 30);
        assert_eq!(fractional_rate.frame_limit_denominator, 1);
    }

    #[test]
    fn non_lossless_rates_are_exact_and_sub_resolution_lossless_rates_are_rejected() {
        let configured = desired_rtss_profile(
            FrameLimitSource::Configured,
            59_500,
            RtssFrameLimitType::BackEdgeSync,
        )
        .unwrap();
        assert_eq!(configured.frame_limit, 119);
        assert_eq!(configured.frame_limit_denominator, 2);
        assert_eq!(configured.sync_limiter, 2);

        assert_eq!(
            desired_rtss_profile(
                FrameLimitSource::LosslessScaling,
                500,
                RtssFrameLimitType::Async,
            ),
            Err("lossless_scaling_limit_below_rtss_resolution")
        );
        let one_fps_target = desired_rtss_profile(
            FrameLimitSource::LosslessScaling,
            1_000,
            RtssFrameLimitType::Async,
        )
        .unwrap();
        assert_eq!(one_fps_target.frame_limit, 1);
        assert_eq!(one_fps_target.frame_limit_denominator, 1);
    }

    #[derive(Clone)]
    struct FakeProvider {
        profiles: BTreeMap<String, ProfileValues>,
        existent_profiles: BTreeMap<String, bool>,
        available: bool,
        mutation_supported: bool,
        limiter_disabled: bool,
        fail_writes: bool,
        mismatch_writeback: bool,
        external_write_before_next_write: Option<ProfileValues>,
        profile_files: BTreeMap<String, ProfileValues>,
        journal_path: Option<PathBuf>,
        durable_pending_seen_before_write: bool,
        durable_flag_intent_seen: bool,
        fail_flag_writes: bool,
        flag_writes: Vec<(bool, bool)>,
        race_before_create: Option<ProfileValues>,
        durable_creation_intent_seen: bool,
        created_profiles: usize,
        installation_preparations: usize,
        idle_retirements: usize,
    }

    impl FakeProvider {
        fn new() -> Self {
            Self {
                profiles: [("game.exe".into(), START), ("other.exe".into(), START)].into(),
                existent_profiles: [("game.exe".into(), true), ("other.exe".into(), true)].into(),
                available: true,
                mutation_supported: true,
                limiter_disabled: false,
                fail_writes: false,
                mismatch_writeback: false,
                external_write_before_next_write: None,
                profile_files: [("game.exe".into(), START), ("other.exe".into(), START)].into(),
                journal_path: None,
                durable_pending_seen_before_write: false,
                durable_flag_intent_seen: false,
                fail_flag_writes: false,
                flag_writes: vec![],
                race_before_create: None,
                durable_creation_intent_seen: false,
                created_profiles: 0,
                installation_preparations: 0,
                idle_retirements: 0,
            }
        }
    }

    impl FrameLimitProvider for FakeProvider {
        fn prepare_installation(&mut self, path: &str) -> Result<String, ProviderError> {
            self.installation_preparations += 1;
            self.select_installation(path)
        }

        fn retire_idle(&mut self) -> Result<(), ProviderError> {
            self.idle_retirements += 1;
            Ok(())
        }

        fn select_installation(&mut self, path: &str) -> Result<String, ProviderError> {
            if self.available {
                Ok(path.to_owned())
            } else {
                Err(ProviderError::Unavailable("fake_provider_unavailable"))
            }
        }

        fn profile_exists(&mut self, profile: &str) -> Result<bool, ProviderError> {
            Ok(self
                .existent_profiles
                .get(profile)
                .copied()
                .unwrap_or(false))
        }

        fn read_profile(&mut self, profile: &str) -> Result<ProfileValues, ProviderError> {
            self.profiles
                .get(profile)
                .copied()
                .ok_or(ProviderError::ReadFailed("profile_not_found"))
        }

        fn ensure_safe_writes_supported(&mut self) -> Result<(), ProviderError> {
            if self.mutation_supported {
                Ok(())
            } else {
                Err(ProviderError::Unavailable("fake_safe_write_unsupported"))
            }
        }

        fn missing_profile_baseline(
            &mut self,
            profile: &str,
        ) -> Result<ProfileValues, ProviderError> {
            if profile != crate::rtss::GLOBAL_PROFILE {
                return Err(ProviderError::Unavailable(
                    "rtss_profile_missing_safe_create_unsupported",
                ));
            }
            Ok(DEFAULT_PROFILE)
        }

        fn create_profile_verified(
            &mut self,
            profile: &str,
            values: ProfileValues,
        ) -> Result<(), ProviderError> {
            if let Some(foreign) = self.race_before_create.take() {
                self.profiles.insert(profile.into(), foreign);
                self.profile_files.insert(profile.into(), foreign);
                self.existent_profiles.insert(profile.into(), true);
            }
            if self.profile_exists(profile)? {
                return Err(ProviderError::CreationConflict(
                    "rtss_profile_already_exists",
                ));
            }
            if let Some(path) = &self.journal_path {
                let journal = load_journal(path).unwrap();
                self.durable_creation_intent_seen = journal.leases.iter().any(|lease| {
                    lease.phase == LeasePhase::Pending
                        && lease.profile == profile
                        && lease.initialized_profile
                        && !lease.before.profile_exists
                });
                assert!(self.durable_creation_intent_seen);
            }
            self.created_profiles += 1;
            self.profiles.insert(profile.into(), values);
            self.profile_files.insert(profile.into(), values);
            self.existent_profiles.insert(profile.into(), true);
            Ok(())
        }

        fn write_profile_verified(
            &mut self,
            profile: &str,
            expected: ProfileValues,
            values: ProfileValues,
        ) -> Result<(), ProviderError> {
            if !self.mutation_supported {
                return Err(ProviderError::Unavailable("fake_safe_write_unsupported"));
            }
            if self.fail_writes {
                return Err(ProviderError::Unavailable("fake_write_failure"));
            }
            if let Some(external_values) = self.external_write_before_next_write.take() {
                self.profile_files
                    .insert(profile.to_owned(), external_values);
                self.profiles.insert(profile.to_owned(), external_values);
                return Err(ProviderError::ProfileMismatch {
                    code: "fake_profile_changed_before_write",
                    observed: external_values,
                });
            }
            let Some(observed) = self.profile_files.get(profile).copied() else {
                return Err(ProviderError::Unavailable("fake_profile_missing"));
            };
            if !self.profile_exists(profile)? || observed != expected {
                return Err(ProviderError::ProfileMismatch {
                    code: "fake_profile_changed_before_write",
                    observed,
                });
            }
            if let Some(path) = &self.journal_path {
                let journal = load_journal(path).expect(
                    "the write-ahead lease intent must be durable before provider mutation",
                );
                let applying = journal.leases.iter().any(|lease| {
                    lease.phase == LeasePhase::Pending
                        && lease.profile == profile
                        && lease.before.profile == expected
                        && lease.applied.profile == values
                });
                let restoring = journal.leases.iter().any(|lease| {
                    lease.profile == profile
                        && lease.before.profile == values
                        && (expected == lease.applied.profile || expected == lease.before.profile)
                });
                self.durable_pending_seen_before_write |= applying;
                assert!(
                    applying || restoring,
                    "write must match the durable apply or restore intent"
                );
            }
            let written = if self.mismatch_writeback {
                ProfileValues {
                    frame_limit: values.frame_limit - 1,
                    ..values
                }
            } else {
                values
            };
            self.profiles.insert(profile.to_owned(), written);
            self.profile_files.insert(profile.to_owned(), written);
            self.existent_profiles.insert(profile.to_owned(), true);
            Ok(())
        }

        fn limiter_disabled(&mut self) -> Result<bool, ProviderError> {
            Ok(self.limiter_disabled)
        }

        fn ensure_limiter_flag_writes_supported(&mut self) -> Result<(), ProviderError> {
            Ok(())
        }

        fn set_limiter_disabled_verified(
            &mut self,
            expected: bool,
            desired: bool,
        ) -> Result<(), ProviderError> {
            if self.limiter_disabled != expected {
                return Err(ProviderError::VerifyFailed("fake_limiter_flag_changed"));
            }
            if self.fail_flag_writes {
                return Err(ProviderError::Unavailable("fake_flag_write_failure"));
            }
            if let Some(path) = &self.journal_path {
                let journal: Journal = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                self.durable_flag_intent_seen = journal
                    .leases
                    .iter()
                    .any(|lease| lease.before.limiter_disabled != lease.applied.limiter_disabled);
            }
            self.limiter_disabled = desired;
            self.flag_writes.push((expected, desired));
            Ok(())
        }
    }

    fn apply(manager: &mut LeaseManager<FakeProvider>, owner: &str, session: &str) -> ApplyOutcome {
        manager.apply(LeaseApplyRequest {
            enable_limiter: false,
            initialize_profile: false,
            owner,
            session_id: session,
            executable_path: r"C:\Games\game.exe",
            rtss_install_path: r"C:\RTSS",
            profile: "game.exe",
            request_fingerprint: "same-request",
            desired_profile: TARGET,
        })
    }

    #[test]
    fn status_and_retries_do_not_start_a_provider_and_live_leases_prevent_retirement() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        manager.probe_provider().unwrap();
        assert!(manager.status("caller", None).is_empty());
        assert_eq!(manager.provider.installation_preparations, 0);

        assert!(matches!(
            apply(&mut manager, "caller", "session"),
            ApplyOutcome::Applied(_)
        ));
        assert_eq!(manager.provider.installation_preparations, 1);
        assert_eq!(manager.status("caller", None)[0].state, "applied");
        assert!(matches!(
            apply(&mut manager, "caller", "session"),
            ApplyOutcome::AlreadyApplied(_)
        ));
        assert_eq!(manager.provider.installation_preparations, 1);
        manager.retire_provider_if_idle().unwrap();
        assert_eq!(manager.provider.idle_retirements, 0);

        // An unresolved effect must retain its provider, including after failed cleanup.
        manager.provider.fail_writes = true;
        assert!(matches!(
            manager.restore("caller", Some("session"), None),
            RestoreOutcome::Failed { .. }
        ));
        manager.retire_provider_if_idle().unwrap();
        assert_eq!(manager.provider.idle_retirements, 0);
        manager.provider.fail_writes = false;
        assert!(matches!(
            manager.restore("caller", Some("session"), None),
            RestoreOutcome::Restored(_)
        ));
        manager.retire_provider_if_idle().unwrap();
        assert_eq!(manager.provider.idle_retirements, 1);
    }

    #[test]
    fn recovery_only_prepares_installations_with_owned_effects() {
        let root = std::env::temp_dir().join(format!(
            "limiter-preparation-{}-{}",
            std::process::id(),
            NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let journal = root.join("leases.json");
        let mut manager = LeaseManager::open(FakeProvider::new(), journal.clone()).unwrap();
        assert_eq!(manager.provider.installation_preparations, 0);
        assert!(matches!(
            apply(&mut manager, "caller", "session"),
            ApplyOutcome::Applied(_)
        ));
        let mut provider = manager.provider.clone();
        provider.installation_preparations = 0;
        drop(manager);
        let mut restarted = LeaseManager::open(provider, journal.clone()).unwrap();
        restarted.recover().unwrap();
        assert_eq!(restarted.provider.installation_preparations, 1);
        assert!(matches!(
            restarted.restore("caller", Some("session"), None),
            RestoreOutcome::Restored(_)
        ));
        assert_eq!(restarted.provider.installation_preparations, 2);
        let mut provider = restarted.provider.clone();
        provider.installation_preparations = 0;
        drop(restarted);
        let mut restarted = LeaseManager::open(provider, journal).unwrap();
        restarted.recover().unwrap();
        assert_eq!(restarted.provider.installation_preparations, 0);
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    fn apply_for_profile(
        manager: &mut LeaseManager<FakeProvider>,
        owner: &str,
        session: &str,
        profile: &str,
    ) -> ApplyOutcome {
        manager.apply(LeaseApplyRequest {
            enable_limiter: false,
            initialize_profile: false,
            owner,
            session_id: session,
            executable_path: if profile == "game.exe" {
                r"C:\Games\game.exe"
            } else {
                r"C:\Games\other.exe"
            },
            rtss_install_path: r"C:\RTSS",
            profile,
            request_fingerprint: "same-request",
            desired_profile: TARGET,
        })
    }

    #[cfg(windows)]
    fn runtime_apply_request() -> serde_json::Value {
        serde_json::json!({
            "action": "apply",
            "version": crate::CONTRACT_VERSION,
            "session_id": "runtime-session",
            "executable_path": r"C:\Games\game.exe",
            "settings": {
                "frame_limiter_enable": true,
                "frame_limiter_provider": "rtss",
                "frame_limiter_fps_limit_millihz": 60_000,
                "frame_limiter_disable_vsync": false,
                "frame_limiter_auto_virtual_framegen": "enabled",
                "rtss_frame_limit_type": "async",
                "rtss_install_path": "",
                "rtss_allow_virtual_display_override": false,
                "mangohud_preset": "custom",
                "mangohud_always_show_graph": false,
                "mangohud_limiter_method": "late"
            },
            "requested_stream_fps_millihz": 60_000,
            "client_display_mode_override_millihz": null,
            "lossless_scaling_limit_millihz": null,
            "virtual_display_active": null,
            "physical_framegen_capture": null,
            "game_frame_generation_mode": null,
            "rtss_frame_limit_type_explicit_override": null
        })
    }

    #[test]
    fn apply_reads_back_exact_values_and_duplicate_retry_returns_same_lease() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        let ApplyOutcome::Applied(lease) = apply(&mut manager, "caller.a", "session-1") else {
            panic!("first apply must create a verified lease");
        };
        assert_eq!(lease.before.profile, START);
        assert_eq!(lease.applied.profile, TARGET);
        assert!(!lease.before.limiter_disabled);
        assert!(!lease.applied.limiter_disabled);
        assert_eq!(
            apply(&mut manager, "caller.a", "session-1"),
            ApplyOutcome::AlreadyApplied(lease)
        );
        assert!(matches!(
            manager.preflight_apply("caller.a", "session-1", "same-request"),
            ApplyPreflight::AlreadyApplied(_)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn lossless_scaling_apply_records_half_rate_and_restores_through_fake_provider() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        let mut request = runtime_apply_request();
        request["settings"]["frame_limiter_enable"] = serde_json::json!(false);
        request["settings"]["frame_limiter_fps_limit_millihz"] = serde_json::json!(0);
        request["requested_stream_fps_millihz"] = serde_json::json!(61_000);
        request["lossless_scaling_limit_millihz"] = serde_json::json!(61_000);
        request["game_frame_generation_mode"] = serde_json::json!("lossless-scaling");

        let applied = handle_runtime_operation("caller.a", request, &mut manager);
        assert_eq!(applied["state"], "applied");
        assert_eq!(applied["plan"]["effective_limit_millihz"], 61_000);
        assert_eq!(manager.records()[0].applied.profile.frame_limit, 31);
        assert_eq!(
            manager.records()[0].applied.profile.frame_limit_denominator,
            1
        );

        let restored = handle_runtime_operation(
            "caller.a",
            serde_json::json!({
                "action": "restore",
                "version": crate::CONTRACT_VERSION,
                "lease": applied["lease"]
            }),
            &mut manager,
        );
        assert_eq!(restored["state"], "restored");
        assert_eq!(manager.provider.profiles["game.exe"], START);
    }

    #[test]
    fn different_owner_cannot_observe_or_restore_another_callers_lease() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        let ApplyOutcome::Applied(lease) = apply(&mut manager, "caller.a", "session-1") else {
            panic!("apply must succeed");
        };
        assert!(manager.status("caller.b", None).is_empty());
        assert_eq!(
            manager.restore("caller.b", None, Some(&lease.lease_id)),
            RestoreOutcome::NotFound
        );
        assert_eq!(
            manager.status("caller.a", Some("session-1"))[0].state,
            "applied"
        );
    }

    #[test]
    fn failed_restore_journal_keeps_ownership_until_retry_confirms_persistence() {
        let root = std::env::temp_dir().join(format!(
            "amaterasu-restore-journal-{}-{}",
            std::process::id(),
            NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let journal = root.join("leases.json");
        let backup = root.join("leases.before.json");
        let mut manager = LeaseManager::open(FakeProvider::new(), journal.clone()).unwrap();
        let ApplyOutcome::Applied(lease) = apply(&mut manager, "caller.a", "session") else {
            panic!("apply must succeed");
        };
        let revision = manager.revision();
        fs::rename(&journal, &backup).unwrap();
        fs::create_dir(&journal).unwrap();
        assert!(matches!(
            manager.restore("caller.a", None, Some(&lease.lease_id)),
            RestoreOutcome::Failed {
                code: "lease_journal_invalid_path",
                ..
            }
        ));
        assert_eq!(manager.revision(), revision);
        assert!(manager.leases.contains_key(&lease.lease_id));
        assert!(manager.completed.is_empty());
        assert_eq!(manager.provider.profiles["game.exe"], START);
        fs::remove_dir(&journal).unwrap();
        fs::rename(&backup, &journal).unwrap();
        assert_eq!(
            manager.restore("caller.a", None, Some(&lease.lease_id)),
            RestoreOutcome::Restored(vec![lease.lease_id.clone()])
        );
        assert!(!manager.leases.contains_key(&lease.lease_id));
        assert_eq!(manager.revision(), revision + 1);
        drop(manager);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restart_reloads_owned_lease_and_restores_exact_before_state() {
        let provider = FakeProvider::new();
        let temp_directory = std::env::temp_dir().join(format!(
            "amaterasu-frame-limiter-{}-{}",
            std::process::id(),
            NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let journal_path = temp_directory.join("leases.json");
        let mut first = LeaseManager::open(provider, journal_path.clone()).unwrap();
        let ApplyOutcome::Applied(lease) = apply(&mut first, "caller.a", "session-1") else {
            panic!("apply must succeed");
        };
        let provider = first.provider.clone();
        drop(first);
        let mut restarted = LeaseManager::open(provider, journal_path.clone()).unwrap();
        assert_eq!(restarted.status("caller.a", None)[0].state, "applied");
        assert_eq!(
            restarted.restore("caller.a", Some("session-1"), None),
            RestoreOutcome::Restored(vec![lease.lease_id.clone()])
        );
        assert_eq!(restarted.provider.profiles["game.exe"], START);
        assert!(!restarted.provider.limiter_disabled);
        assert_eq!(
            restarted.restore("caller.a", None, Some(&lease.lease_id)),
            RestoreOutcome::Restored(vec![lease.lease_id.clone()])
        );
        drop(restarted);
        fs::remove_dir_all(temp_directory).unwrap();
    }

    #[test]
    fn durable_pending_intent_precedes_provider_mutation() {
        let temp_directory = std::env::temp_dir().join(format!(
            "amaterasu-frame-limiter-write-ahead-{}-{}",
            std::process::id(),
            NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let journal_path = temp_directory.join("leases.json");
        let mut provider = FakeProvider::new();
        provider.journal_path = Some(journal_path.clone());
        let mut manager = LeaseManager::open(provider, journal_path.clone()).unwrap();
        assert!(matches!(
            apply(&mut manager, "caller.a", "session-1"),
            ApplyOutcome::Applied(_)
        ));
        assert!(manager.provider.durable_pending_seen_before_write);
        drop(manager);
        fs::remove_dir_all(temp_directory).unwrap();
    }

    #[test]
    fn restart_promotes_pending_intent_after_crash_between_write_and_activation() {
        let temp_directory = std::env::temp_dir().join(format!(
            "amaterasu-frame-limiter-pending-recovery-{}-{}",
            std::process::id(),
            NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let journal_path = temp_directory.join("leases.json");
        let mut first = LeaseManager::open(FakeProvider::new(), journal_path.clone()).unwrap();
        let ApplyOutcome::Applied(active_lease) = apply(&mut first, "caller.a", "session-1") else {
            panic!("apply must establish the fake provider state");
        };

        // Model a process crash after the provider write/readback, before the
        // journal could promote the durable intent to Active.
        let mut pending_lease = active_lease.clone();
        pending_lease.phase = LeasePhase::Pending;
        save_journal(&journal_path, 1, vec![pending_lease], Vec::new()).unwrap();
        let provider = first.provider.clone();
        drop(first);

        let mut restarted = LeaseManager::open(provider, journal_path.clone()).unwrap();
        assert_eq!(restarted.records()[0].phase, LeasePhase::Pending);
        restarted.recover().unwrap();
        assert_eq!(restarted.records()[0].phase, LeasePhase::Active);
        assert_eq!(restarted.status("caller.a", None)[0].state, "applied");
        assert_eq!(
            restarted.restore("caller.a", Some("session-1"), None),
            RestoreOutcome::Restored(vec![active_lease.lease_id])
        );
        drop(restarted);
        fs::remove_dir_all(temp_directory).unwrap();
    }

    #[test]
    fn restart_reports_legacy_created_profile_lease_as_stale() {
        let temp_directory = std::env::temp_dir().join(format!(
            "amaterasu-frame-limiter-legacy-profile-recovery-{}-{}",
            std::process::id(),
            NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let journal_path = temp_directory.join("leases.json");
        let mut first = LeaseManager::in_memory(FakeProvider::new());
        let ApplyOutcome::Applied(mut lease) = apply(&mut first, "caller.a", "session-1") else {
            panic!("apply must update the existing profile");
        };
        // Model a durable lease from an earlier implementation that allowed
        // creation. Recovery must never delete or overwrite that whole profile.
        lease.before.profile_exists = false;
        lease.phase = LeasePhase::Pending;
        save_journal(&journal_path, 1, vec![lease.clone()], Vec::new()).unwrap();
        let provider = first.provider.clone();
        drop(first);

        let mut restarted = LeaseManager::open(provider, journal_path.clone()).unwrap();
        restarted.recover().unwrap();
        assert_eq!(restarted.records()[0].phase, LeasePhase::Pending);
        let status = restarted.status("caller.a", None);
        assert_eq!(status[0].state, "stale_lease");
        assert_eq!(status[0].diagnostic, Some("pending_apply_not_verified"));
        assert_eq!(
            restarted.restore("caller.a", None, Some(&lease.lease_id)),
            RestoreOutcome::Stale(lease.lease_id)
        );
        assert_eq!(restarted.provider.profiles["game.exe"], TARGET);
        assert!(restarted.provider.existent_profiles["game.exe"]);
        drop(restarted);
        fs::remove_dir_all(temp_directory).unwrap();
    }

    #[test]
    fn restart_does_not_claim_pending_effect_when_writes_are_unsupported() {
        let temp_directory = std::env::temp_dir().join(format!(
            "amaterasu-frame-limiter-unsupported-write-recovery-{}-{}",
            std::process::id(),
            NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&temp_directory).unwrap();
        let journal_path = temp_directory.join("leases.json");
        let mut first = LeaseManager::in_memory(FakeProvider::new());
        let ApplyOutcome::Applied(mut lease) = apply(&mut first, "caller.a", "session-1") else {
            panic!("the initial fake provider supports writes");
        };
        lease.phase = LeasePhase::Pending;
        save_journal(&journal_path, 1, vec![lease.clone()], Vec::new()).unwrap();
        let mut provider = first.provider.clone();
        provider.mutation_supported = false;
        drop(first);

        let mut restarted = LeaseManager::open(provider, journal_path.clone()).unwrap();
        restarted.recover().unwrap();
        assert_eq!(restarted.records()[0].phase, LeasePhase::Pending);
        let status = restarted.status("caller.a", None);
        assert_eq!(status[0].state, "stale_lease");
        assert_eq!(status[0].diagnostic, Some("pending_apply_not_verified"));
        assert_eq!(
            restarted.restore("caller.a", None, Some(&lease.lease_id)),
            RestoreOutcome::Failed {
                lease_id: lease.lease_id,
                code: "fake_safe_write_unsupported",
            }
        );
        assert_eq!(restarted.provider.profiles["game.exe"], TARGET);
        drop(restarted);
        fs::remove_dir_all(temp_directory).unwrap();
    }

    #[test]
    fn restart_does_not_advertise_an_active_lease_without_safe_restore() {
        let temp_directory = std::env::temp_dir().join(format!(
            "amaterasu-frame-limiter-unsupported-active-recovery-{}-{}",
            std::process::id(),
            NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&temp_directory).unwrap();
        let journal_path = temp_directory.join("leases.json");
        let mut first = LeaseManager::open(FakeProvider::new(), journal_path.clone()).unwrap();
        let ApplyOutcome::Applied(lease) = apply(&mut first, "caller.a", "session-1") else {
            panic!("the old provider must create an active lease");
        };
        let mut provider = first.provider.clone();
        provider.mutation_supported = false;
        drop(first);

        let mut restarted = LeaseManager::open(provider, journal_path.clone()).unwrap();
        restarted.recover().unwrap();
        let status = restarted.status("caller.a", Some("session-1"));
        assert_eq!(status[0].state, "stale_lease");
        assert_eq!(status[0].diagnostic, Some("fake_safe_write_unsupported"));
        assert_eq!(
            restarted.preflight_apply("caller.a", "session-1", "same-request"),
            ApplyPreflight::Unavailable("fake_safe_write_unsupported")
        );
        assert_eq!(
            apply(&mut restarted, "caller.a", "session-1"),
            ApplyOutcome::Unavailable("fake_safe_write_unsupported")
        );
        assert_eq!(
            restarted.restore("caller.a", None, Some(&lease.lease_id)),
            RestoreOutcome::Failed {
                lease_id: lease.lease_id,
                code: "fake_safe_write_unsupported",
            }
        );
        assert_eq!(restarted.records().len(), 1);
        assert_eq!(restarted.provider.profiles["game.exe"], TARGET);
        drop(restarted);
        fs::remove_dir_all(temp_directory).unwrap();
    }

    #[test]
    fn restore_failure_retains_the_lease_for_retry() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        let ApplyOutcome::Applied(lease) = apply(&mut manager, "caller.a", "session-1") else {
            panic!("apply must succeed");
        };
        manager.provider.fail_writes = true;
        assert_eq!(
            manager.restore("caller.a", None, Some(&lease.lease_id)),
            RestoreOutcome::Failed {
                lease_id: lease.lease_id.clone(),
                code: "fake_write_failure",
            }
        );
        assert_eq!(manager.records().len(), 1);
        manager.provider.fail_writes = false;
        assert_eq!(
            manager.restore("caller.a", None, Some(&lease.lease_id)),
            RestoreOutcome::Restored(vec![lease.lease_id.clone()])
        );
        assert_eq!(
            manager.restore("caller.a", None, Some(&lease.lease_id)),
            RestoreOutcome::Restored(vec![lease.lease_id])
        );
        assert!(manager.records().is_empty());
    }

    #[test]
    fn a_different_owner_conflicts_only_on_the_owned_rtss_profile() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        let ApplyOutcome::Applied(_) = apply(&mut manager, "caller.a", "session-1") else {
            panic!("first apply must succeed");
        };
        assert_eq!(
            apply(&mut manager, "caller.b", "session-2"),
            ApplyOutcome::Conflict("rtss_profile_is_owned_by_another_session")
        );
        assert!(matches!(
            apply_for_profile(&mut manager, "caller.b", "session-2", "other.exe"),
            ApplyOutcome::Applied(_)
        ));
    }

    #[test]
    fn same_owner_session_rejects_changed_full_request_fingerprint() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        let ApplyOutcome::Applied(_) = apply(&mut manager, "caller.a", "session-1") else {
            panic!("first apply must succeed");
        };
        assert_eq!(
            manager.apply(LeaseApplyRequest {
                enable_limiter: false,
                initialize_profile: false,
                owner: "caller.a",
                session_id: "session-1",
                executable_path: r"C:\Games\game.exe",
                rtss_install_path: r"C:\RTSS",
                profile: "game.exe",
                request_fingerprint: "different-context-or-settings",
                desired_profile: TARGET,
            }),
            ApplyOutcome::Conflict("session_already_has_a_different_lease")
        );
        assert_eq!(
            manager.preflight_apply("caller.a", "session-1", "different-context-or-settings"),
            ApplyPreflight::Conflict("session_already_has_a_different_lease")
        );
    }

    #[test]
    fn unverified_provider_state_is_retained_for_safe_recovery_without_a_lease() {
        let mut provider = FakeProvider::new();
        provider.mismatch_writeback = true;
        let mut manager = LeaseManager::in_memory(provider);
        assert!(matches!(
            apply(&mut manager, "caller.a", "session-1"),
            ApplyOutcome::RestoreFailed { .. }
        ));
        assert_eq!(manager.records().len(), 1);
        assert_eq!(manager.records()[0].phase, LeasePhase::Pending);
        assert_eq!(
            manager.provider.profiles["game.exe"],
            ProfileValues {
                frame_limit: TARGET.frame_limit - 1,
                ..TARGET
            }
        );
    }

    #[test]
    fn globally_disabled_limiter_is_not_enabled_as_a_side_effect() {
        let mut provider = FakeProvider::new();
        provider.limiter_disabled = true;
        let mut manager = LeaseManager::in_memory(provider);
        assert_eq!(
            apply(&mut manager, "caller.a", "session-1"),
            ApplyOutcome::Unavailable("rtss_limiter_disabled_globally")
        );
        assert!(manager.provider.limiter_disabled);
        assert!(manager.records().is_empty());
    }

    #[test]
    fn restart_reports_external_provider_changes_as_stale_without_overwriting_them() {
        let temp_directory = std::env::temp_dir().join(format!(
            "amaterasu-frame-limiter-stale-{}-{}",
            std::process::id(),
            NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let journal_path = temp_directory.join("leases.json");
        let mut manager = LeaseManager::open(FakeProvider::new(), journal_path.clone()).unwrap();
        let ApplyOutcome::Applied(lease) = apply(&mut manager, "caller.a", "session-1") else {
            panic!("apply must succeed");
        };
        manager
            .provider
            .profiles
            .get_mut("game.exe")
            .unwrap()
            .frame_limit = 72;
        let provider = manager.provider.clone();
        drop(manager);

        let mut restarted = LeaseManager::open(provider, journal_path.clone()).unwrap();
        let status = restarted.status("caller.a", None);
        assert_eq!(status[0].state, "stale_lease");
        assert_eq!(status[0].diagnostic, Some("provider_state_changed"));
        assert_eq!(
            restarted.restore("caller.a", Some("session-1"), None),
            RestoreOutcome::Stale(lease.lease_id)
        );
        assert_eq!(restarted.provider.profiles["game.exe"].frame_limit, 72);
        drop(restarted);
        fs::remove_dir_all(temp_directory).unwrap();
    }

    #[test]
    fn absent_profile_is_not_created_and_returns_runtime_unavailable() {
        let mut provider = FakeProvider::new();
        provider.existent_profiles.insert("game.exe".into(), false);
        let mut manager = LeaseManager::in_memory(provider);
        assert_eq!(
            apply(&mut manager, "caller.a", "session-1"),
            ApplyOutcome::Unavailable("rtss_profile_missing_safe_create_unsupported")
        );
        assert!(!manager.provider.existent_profiles["game.exe"]);
        assert_eq!(manager.provider.profiles["game.exe"], START);
        assert!(manager.records().is_empty());
    }

    #[test]
    fn unsupported_mutation_is_rejected_before_persisting_intent() {
        let temp_directory = std::env::temp_dir().join(format!(
            "amaterasu-frame-limiter-unsupported-write-{}-{}",
            std::process::id(),
            NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&temp_directory).unwrap();
        let journal_path = temp_directory.join("leases.json");
        let mut provider = FakeProvider::new();
        provider.mutation_supported = false;
        provider.journal_path = Some(journal_path.clone());
        let mut manager = LeaseManager::open(provider, journal_path.clone()).unwrap();

        assert_eq!(
            apply(&mut manager, "caller.a", "session-1"),
            ApplyOutcome::Unavailable("fake_safe_write_unsupported")
        );
        assert!(manager.records().is_empty());
        assert!(!journal_path.exists());
        assert_eq!(manager.provider.profiles["game.exe"], START);
        drop(manager);
        fs::remove_dir_all(temp_directory).unwrap();
    }

    #[test]
    fn external_profile_change_to_requested_values_is_not_rolled_back() {
        let mut provider = FakeProvider::new();
        provider.external_write_before_next_write = Some(TARGET);
        let mut manager = LeaseManager::in_memory(provider);
        assert_eq!(
            apply(&mut manager, "caller.a", "session-1"),
            ApplyOutcome::Unavailable("fake_profile_changed_before_write")
        );
        assert_eq!(manager.provider.profiles["game.exe"], TARGET);
        assert!(manager.records().is_empty());
    }

    #[test]
    fn external_profile_change_during_restore_keeps_lease_stale_without_overwriting() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        let ApplyOutcome::Applied(lease) = apply(&mut manager, "caller.a", "session-1") else {
            panic!("apply must succeed");
        };
        let external_values = ProfileValues {
            frame_limit: 80_000,
            frame_limit_denominator: 1_000,
            sync_limiter: 1,
        };
        manager.provider.external_write_before_next_write = Some(external_values);

        assert_eq!(
            manager.restore("caller.a", None, Some(&lease.lease_id)),
            RestoreOutcome::Stale(lease.lease_id.clone())
        );
        assert_eq!(manager.provider.profiles["game.exe"], external_values);
        assert_eq!(manager.records().len(), 1);
        let status = manager.status_for_lease("caller.a", &lease.lease_id);
        assert_eq!(status[0].state, "stale_lease");
    }

    #[test]
    fn hooks_reporting_before_cannot_hide_locked_third_profile_values() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        let ApplyOutcome::Applied(lease) = apply(&mut manager, "caller.a", "session-1") else {
            panic!("apply must succeed");
        };
        let external_file_values = ProfileValues {
            frame_limit: 80_000,
            frame_limit_denominator: 1_000,
            sync_limiter: 1,
        };
        manager.provider.profiles.insert("game.exe".into(), START);
        manager
            .provider
            .profile_files
            .insert("game.exe".into(), external_file_values);

        assert_eq!(
            manager.restore("caller.a", None, Some(&lease.lease_id)),
            RestoreOutcome::Stale(lease.lease_id.clone())
        );
        assert_eq!(manager.provider.profiles["game.exe"], START);
        assert_eq!(
            manager.provider.profile_files["game.exe"],
            external_file_values
        );
        assert_eq!(manager.records().len(), 1);
    }

    #[test]
    fn external_restore_to_before_values_during_restore_needs_no_provider_write() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        let ApplyOutcome::Applied(lease) = apply(&mut manager, "caller.a", "session-1") else {
            panic!("apply must succeed");
        };
        manager.provider.external_write_before_next_write = Some(START);

        assert_eq!(
            manager.restore("caller.a", None, Some(&lease.lease_id)),
            RestoreOutcome::Restored(vec![lease.lease_id.clone()])
        );
        assert_eq!(manager.provider.profiles["game.exe"], START);
        assert!(manager.records().is_empty());
    }

    #[test]
    fn restored_owner_session_cannot_be_reapplied_while_tombstone_is_retained() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        let ApplyOutcome::Applied(lease) = apply(&mut manager, "caller.a", "session-1") else {
            panic!("apply must succeed");
        };
        assert_eq!(
            manager.restore("caller.a", None, Some(&lease.lease_id)),
            RestoreOutcome::Restored(vec![lease.lease_id.clone()])
        );
        assert_eq!(
            manager.preflight_apply("caller.a", "session-1", "same-request"),
            ApplyPreflight::Conflict("session_lease_already_restored")
        );
        assert_eq!(
            manager.restore("caller.a", None, Some(&lease.lease_id)),
            RestoreOutcome::Restored(vec![lease.lease_id])
        );
    }

    #[test]
    fn status_without_owned_leases_reports_provider_detection_result() {
        let operation = serde_json::json!({
            "action": "status",
            "version": crate::CONTRACT_VERSION,
            "session_id": "session-unknown"
        });
        let mut available = LeaseManager::in_memory(FakeProvider::new());
        let response = handle_runtime_operation("caller.a", operation.clone(), &mut available);
        assert_eq!(response["state"], "not_found");
        assert_eq!(response["provider_availability"], "available");

        let mut provider = FakeProvider::new();
        provider.available = false;
        let mut unavailable = LeaseManager::in_memory(provider);
        let response = handle_runtime_operation("caller.a", operation, &mut unavailable);
        assert_eq!(response["state"], "not_found");
        assert_eq!(response["provider_availability"], "unavailable");
        assert_eq!(response["diagnostics"][1], "fake_provider_unavailable");
    }

    #[test]
    fn journal_retains_the_most_recent_256_restore_tombstones() {
        let temp_directory = std::env::temp_dir().join(format!(
            "amaterasu-frame-limiter-tombstone-limit-{}-{}",
            std::process::id(),
            NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let journal_path = temp_directory.join("leases.json");
        let completed = (0..300)
            .map(|index| CompletedLease {
                lease_id: format!("lease-{index:03}"),
                owner: "caller.a".into(),
                session_id: format!("session-{index:03}"),
            })
            .collect();
        save_journal(&journal_path, 1, Vec::new(), completed).unwrap();
        let journal = load_journal(&journal_path).unwrap();
        assert_eq!(journal.completed.len(), COMPLETED_LEASE_LIMIT);
        assert!(
            journal
                .completed
                .iter()
                .any(|lease| lease.lease_id == "lease-299")
        );
        assert!(
            !journal
                .completed
                .iter()
                .any(|lease| lease.lease_id == "lease-000")
        );
        fs::remove_dir_all(temp_directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn unsupported_vsync_request_is_declined_before_any_provider_mutation() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        let before_profiles = manager.provider.profiles.clone();
        let response = handle_runtime_operation(
            "caller.a",
            serde_json::json!({
                "action":"apply",
                "version":1,
                "session_id":"1001",
                "executable_path":r"C:\Games\game.exe",
                "settings":{
                    "frame_limiter_enable":true,
                    "frame_limiter_provider":"rtss",
                    "frame_limiter_fps_limit_millihz":60000,
                    "frame_limiter_disable_vsync":true,
                    "frame_limiter_auto_virtual_framegen":"enabled",
                    "rtss_frame_limit_type":"async",
                    "rtss_install_path":r"C:\Program Files (x86)\RivaTuner Statistics Server",
                    "rtss_allow_virtual_display_override":false,
                    "mangohud_preset":"custom",
                    "mangohud_always_show_graph":false,
                    "mangohud_limiter_method":"late"
                }
            }),
            &mut manager,
        );
        assert_eq!(response["state"], "runtime_unavailable");
        assert_eq!(
            response["diagnostics"][0],
            "rtss_cannot_apply_disable_vsync"
        );
        assert_eq!(manager.provider.profiles, before_profiles);
        assert!(manager.records().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn apply_rollback_failure_returns_the_retained_session_cleanup_lease() {
        let mut provider = FakeProvider::new();
        provider.mismatch_writeback = true;
        let mut manager = LeaseManager::in_memory(provider);
        let response = handle_runtime_operation(
            "caller.a",
            serde_json::json!({
                "action":"apply",
                "version":1,
                "session_id":"1001",
                "executable_path":r"C:\Games\game.exe",
                "settings":{
                    "frame_limiter_enable":true,
                    "frame_limiter_provider":"rtss",
                    "frame_limiter_fps_limit_millihz":59500,
                    "frame_limiter_disable_vsync":false,
                    "frame_limiter_auto_virtual_framegen":"enabled",
                    "rtss_frame_limit_type":"async",
                    "rtss_install_path":r"C:\Program Files (x86)\RivaTuner Statistics Server",
                    "rtss_allow_virtual_display_override":false,
                    "mangohud_preset":"custom",
                    "mangohud_always_show_graph":false,
                    "mangohud_limiter_method":"late"
                }
            }),
            &mut manager,
        );
        assert_eq!(response["state"], "restore_failed");
        assert_eq!(response["applied"], false);
        assert_eq!(response["leases"].as_array().unwrap().len(), 1);
        assert_eq!(response["leases"][0]["state"], "stale_lease");
        assert!(!response["leases"][0]["lease"].as_str().unwrap().is_empty());
        assert_eq!(response["leases"][0]["session_id"], "1001");
    }

    #[cfg(windows)]
    #[test]
    fn active_retry_conflict_precedes_a_policy_noop_and_keeps_owner_status() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        let initial = runtime_apply_request();
        let applied = handle_runtime_operation("caller.a", initial.clone(), &mut manager);
        assert_eq!(applied["state"], "applied");
        let lease = applied["lease"].as_str().unwrap().to_owned();

        let duplicate = handle_runtime_operation("caller.a", initial, &mut manager);
        assert_eq!(duplicate["state"], "already_applied");
        assert_eq!(duplicate["lease"], lease);

        let mut changed = runtime_apply_request();
        changed["settings"]["frame_limiter_enable"] = serde_json::json!(false);
        changed["requested_stream_fps_millihz"] = serde_json::json!(0);
        changed["client_display_mode_override_millihz"] = serde_json::json!(0);
        changed["lossless_scaling_limit_millihz"] = serde_json::json!(0);
        changed["virtual_display_active"] = serde_json::json!(false);
        changed["physical_framegen_capture"] = serde_json::json!(false);
        changed["game_frame_generation_mode"] = serde_json::json!("none");
        let conflict = handle_runtime_operation("caller.a", changed, &mut manager);
        assert_eq!(conflict["state"], "lease_conflict");
        assert_eq!(conflict["applied"], false);
        assert_eq!(conflict["leases"][0]["lease"], lease);
        assert_eq!(conflict["leases"][0]["applied"], true);
    }

    #[cfg(windows)]
    #[test]
    fn restore_failure_reports_applied_when_fake_provider_still_matches_lease() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        let applied = handle_runtime_operation("caller.a", runtime_apply_request(), &mut manager);
        let lease = applied["lease"].as_str().unwrap().to_owned();
        manager.provider.fail_writes = true;
        let restored = handle_runtime_operation(
            "caller.a",
            serde_json::json!({
                "action": "restore",
                "version": crate::CONTRACT_VERSION,
                "lease": lease
            }),
            &mut manager,
        );
        assert_eq!(restored["state"], "restore_failed");
        assert_eq!(restored["applied"], true);
        assert_eq!(restored["lease"], lease);
        assert_eq!(restored["leases"][0]["applied"], true);
    }

    #[cfg(windows)]
    #[test]
    fn wire_retry_and_status_do_not_claim_unrestorable_legacy_effect() {
        let mut manager = LeaseManager::in_memory(FakeProvider::new());
        let request = runtime_apply_request();
        let applied = handle_runtime_operation("caller.a", request.clone(), &mut manager);
        let lease = applied["lease"].as_str().unwrap().to_owned();
        manager.provider.mutation_supported = false;

        let retry = handle_runtime_operation("caller.a", request, &mut manager);
        assert_eq!(retry["state"], "runtime_unavailable");
        assert_eq!(retry["applied"], false);
        assert_eq!(retry["leases"][0]["lease"], lease);
        assert_eq!(retry["leases"][0]["state"], "stale_lease");
        assert_eq!(retry["leases"][0]["applied"], false);

        let status = handle_runtime_operation(
            "caller.a",
            serde_json::json!({"action":"status","version":crate::CONTRACT_VERSION}),
            &mut manager,
        );
        assert_eq!(status["state"], "stale_lease");
        assert_eq!(status["applied"], false);
        assert_eq!(status["leases"][0]["lease"], lease);

        let restored = handle_runtime_operation(
            "caller.a",
            serde_json::json!({"action":"restore","version":crate::CONTRACT_VERSION,"lease":lease}),
            &mut manager,
        );
        assert_eq!(restored["state"], "restore_failed");
        assert_eq!(restored["applied"], false);
        assert_eq!(restored["leases"][0]["state"], "stale_lease");
        assert_eq!(manager.records().len(), 1);
    }
}
