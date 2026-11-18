//! Durable ownership of the driver's global profile edits. Native persistence
//! is separate from the lease journal; unknown saves retain ownership.
use super::{Changes, DriverSettings, Error, Profile, Setting, Snapshot};
use serde::{Deserialize, Serialize};
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Pending,
    Active,
    Restoring,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Lease {
    pub owner: String,
    pub target: String,
    pub fingerprint: String,
    pub profile: Profile,
    pub before: Snapshot,
    pub applied: Changes,
    pub phase: Phase,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Completed {
    pub owner: String,
    pub target: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub version: u32,
    pub revision: u64,
    pub active: Option<Lease>,
    pub completed: Vec<Completed>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            revision: 1,
            active: None,
            completed: vec![],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Applied,
    AlreadyApplied,
    Restored,
    NotFound,
    Unavailable(&'static str),
    Conflict,
    RecoveryRequired(&'static str),
}

pub(crate) struct Manager<D> {
    driver: D,
    state: State,
    journal: Option<super::journal::Journal>,
    failed: bool,
}

impl<D: DriverSettings> Manager<D> {
    pub(crate) fn open(driver: D, path: &std::path::Path) -> Result<Self, &'static str> {
        let (journal, state) = super::journal::Journal::open(path)?;
        Ok(Self {
            driver,
            state,
            journal: Some(journal),
            failed: false,
        })
    }
    #[cfg(test)]
    pub(crate) fn in_memory(driver: D) -> Self {
        Self {
            driver,
            state: State::default(),
            journal: None,
            failed: false,
        }
    }
    pub(crate) fn revision(&self) -> u64 {
        self.state.revision
    }
    pub(crate) fn active_target(&self) -> Option<(&str, &str)> {
        self.state
            .active
            .as_ref()
            .map(|lease| (lease.owner.as_str(), lease.target.as_str()))
    }
    #[cfg(windows)]
    pub(crate) fn targets(&self, owner: &str) -> Vec<String> {
        self.state
            .active
            .iter()
            .filter(|lease| lease.owner == owner)
            .map(|lease| lease.target.clone())
            .chain(
                self.state
                    .completed
                    .iter()
                    .filter(|lease| lease.owner == owner)
                    .map(|lease| lease.target.clone()),
            )
            .collect()
    }
    pub(crate) fn owns(&self, owner: &str, target: &str) -> bool {
        self.state
            .active
            .as_ref()
            .is_some_and(|lease| lease.owner == owner && lease.target == target)
            || self
                .state
                .completed
                .iter()
                .any(|entry| entry.owner == owner && entry.target == target)
    }
    pub(crate) fn verify(&mut self, owner: &str, target: &str, fingerprint: &str) -> Outcome {
        let Some(active) = &self.state.active else {
            return Outcome::NotFound;
        };
        if active.owner != owner || active.target != target || active.fingerprint != fingerprint {
            return Outcome::Conflict;
        }
        if active.phase != Phase::Active {
            return Outcome::RecoveryRequired("nvcp_pending_save");
        }
        let keys: Vec<_> = active.applied.keys().copied().collect();
        match self.driver.read(&active.profile, &keys) {
            Ok(current) if matches_applied(active, &current) => Outcome::AlreadyApplied,
            _ => Outcome::RecoveryRequired("nvcp_owned_settings_changed"),
        }
    }
    fn persist(&mut self) -> Result<(), &'static str> {
        self.state.revision = self
            .state
            .revision
            .checked_add(1)
            .ok_or("nvcp_revision_exhausted")?;
        if let Some(journal) = &mut self.journal {
            journal.save(&self.state)?;
        }
        Ok(())
    }

    pub(crate) fn apply(
        &mut self,
        owner: &str,
        target: &str,
        fingerprint: &str,
        applied: &Changes,
    ) -> Outcome {
        if self.failed {
            return Outcome::RecoveryRequired("nvcp_journal_unavailable");
        }
        if !valid_identity(owner)
            || !valid_identity(target)
            || fingerprint.len() > 4096
            || applied.is_empty()
            || !valid_changes(applied)
        {
            return Outcome::Unavailable("nvcp_invalid_request");
        }
        if let Some(active) = &self.state.active {
            if active.owner != owner
                || active.target != target
                || active.fingerprint != fingerprint
                || active.applied != *applied
            {
                return Outcome::Conflict;
            }
            if active.phase != Phase::Active {
                return Outcome::RecoveryRequired("nvcp_pending_save");
            }
            let keys: Vec<_> = applied.keys().copied().collect();
            return match self.driver.read(&active.profile, &keys) {
                Ok(current) if matches_applied(active, &current) => Outcome::AlreadyApplied,
                _ => Outcome::RecoveryRequired("nvcp_owned_settings_changed"),
            };
        }
        if self
            .state
            .completed
            .iter()
            .any(|entry| entry.owner == owner && entry.target == target)
        {
            return Outcome::Conflict;
        }
        let profile = match self.driver.current_profile() {
            Ok(profile) => profile,
            Err(error) => return error_outcome(error),
        };
        let keys: Vec<_> = applied.keys().copied().collect();
        let before = match self.driver.read(&profile, &keys) {
            Ok(snapshot) => snapshot,
            Err(error) => return error_outcome(error),
        };
        if before.keys().ne(applied.keys()) {
            return Outcome::Unavailable("nvcp_incomplete_snapshot");
        }
        self.state.active = Some(Lease {
            owner: owner.into(),
            target: target.into(),
            fingerprint: fingerprint.into(),
            profile: profile.clone(),
            before: before.clone(),
            applied: applied.clone(),
            phase: Phase::Pending,
        });
        if let Err(reason) = self.persist() {
            self.failed = true;
            return Outcome::RecoveryRequired(reason);
        }
        match self.driver.commit(&profile, &before, applied) {
            Ok(()) => {
                self.state.active.as_mut().unwrap().phase = Phase::Active;
                if let Err(reason) = self.persist() {
                    self.failed = true;
                    return Outcome::RecoveryRequired(reason);
                }
                Outcome::Applied
            }
            Err(Error::Uncertain(reason)) => Outcome::RecoveryRequired(reason),
            Err(error) => {
                // The provider guarantees that no native save occurred.
                self.complete();
                if let Err(reason) = self.persist() {
                    self.failed = true;
                    return Outcome::RecoveryRequired(reason);
                }
                error_outcome(error)
            }
        }
    }

    pub(crate) fn restore(&mut self, owner: &str, target: &str) -> Outcome {
        if self.failed {
            return Outcome::RecoveryRequired("nvcp_journal_unavailable");
        }
        let Some(lease) = self.state.active.clone() else {
            return if self
                .state
                .completed
                .iter()
                .any(|entry| entry.owner == owner && entry.target == target)
            {
                Outcome::Restored
            } else {
                Outcome::NotFound
            };
        };
        if lease.owner != owner || lease.target != target {
            return Outcome::NotFound;
        }
        self.restore_lease(lease)
    }

    fn restore_lease(&mut self, lease: Lease) -> Outcome {
        let keys: Vec<_> = lease.applied.keys().copied().collect();
        let current = match self.driver.read(&lease.profile, &keys) {
            Ok(current) => current,
            Err(error) => return error_outcome(error),
        };
        if !known_snapshot(&lease, &current) {
            return Outcome::RecoveryRequired("nvcp_owned_settings_changed");
        }
        if !matches_before(&lease, &current) {
            self.state.active.as_mut().unwrap().phase = Phase::Restoring;
            if let Err(reason) = self.persist() {
                self.failed = true;
                return Outcome::RecoveryRequired(reason);
            }
            let before = lease
                .before
                .iter()
                .map(|(key, value)| (*key, value.explicit))
                .collect();
            if let Err(error) = self.driver.commit(&lease.profile, &current, &before) {
                return error_outcome(error);
            }
        }
        self.complete();
        if let Err(reason) = self.persist() {
            self.failed = true;
            return Outcome::RecoveryRequired(reason);
        }
        Outcome::Restored
    }

    pub(crate) fn recover(&mut self) -> Outcome {
        let Some(lease) = self.state.active.clone() else {
            return Outcome::NotFound;
        };
        let keys: Vec<_> = lease.applied.keys().copied().collect();
        let current = match self.driver.read(&lease.profile, &keys) {
            Ok(current) => current,
            Err(error) => return error_outcome(error),
        };
        if matches_before(&lease, &current) {
            return self.restore_lease(lease);
        }
        if matches_applied(&lease, &current) && lease.phase != Phase::Restoring {
            if lease.phase == Phase::Pending {
                self.state.active.as_mut().unwrap().phase = Phase::Active;
                if let Err(reason) = self.persist() {
                    self.failed = true;
                    return Outcome::RecoveryRequired(reason);
                }
            }
            return Outcome::AlreadyApplied;
        }
        if lease.phase != Phase::Active && known_snapshot(&lease, &current) {
            return self.restore_lease(lease);
        }
        Outcome::RecoveryRequired("nvcp_owned_settings_changed")
    }

    fn complete(&mut self) {
        if let Some(lease) = self.state.active.take() {
            self.state.completed.push(Completed {
                owner: lease.owner,
                target: lease.target,
                fingerprint: lease.fingerprint,
            });
            if self.state.completed.len() > 256 {
                self.state.completed.remove(0);
            }
        }
    }
}

fn error_outcome(error: Error) -> Outcome {
    match error {
        Error::Unavailable(reason) => Outcome::Unavailable(reason),
        Error::Changed => Outcome::RecoveryRequired("nvcp_owned_settings_changed"),
        Error::Uncertain(reason) => Outcome::RecoveryRequired(reason),
    }
}
fn matches_before(lease: &Lease, current: &Snapshot) -> bool {
    current.keys().eq(lease.before.keys())
        && current
            .iter()
            .all(|(setting, value)| value.explicit == lease.before[setting].explicit)
}
fn matches_applied(lease: &Lease, current: &Snapshot) -> bool {
    current.keys().eq(lease.applied.keys())
        && current
            .iter()
            .all(|(setting, value)| value.explicit == lease.applied[setting])
}
fn known_snapshot(lease: &Lease, current: &Snapshot) -> bool {
    current.keys().eq(lease.before.keys())
        && current.iter().all(|(setting, value)| {
            value.explicit == lease.before[setting].explicit
                || value.explicit == lease.applied[setting]
        })
}
fn valid_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}
fn valid_changes(changes: &Changes) -> bool {
    changes.iter().all(|(setting, value)| {
        matches!(
            (setting, value),
            (Setting::FrameLimit, Some(0..=1023))
                | (Setting::Vsync, Some(0x0841_6747))
                | (Setting::PrerenderLimit, Some(1))
                | (
                    Setting::UltraLowLatencyMode | Setting::UltraLowLatencyEnabled,
                    Some(0)
                )
                | (Setting::SmoothMotion, Some(1))
                | (Setting::SmoothMotionApiMask, Some(7))
        )
    })
}

pub(super) fn validate(state: &State) -> Result<(), &'static str> {
    if state.version != 1 || state.revision == 0 || state.completed.len() > 256 {
        return Err("nvcp_journal_invalid");
    }
    if let Some(lease) = &state.active
        && (!valid_identity(&lease.owner)
            || !valid_identity(&lease.target)
            || lease.fingerprint.len() > 4096
            || lease.profile.name.encode_utf16().count() >= 2048
            || lease.profile.name.contains('\0')
            || lease.before.is_empty()
            || lease.before.keys().ne(lease.applied.keys())
            || !valid_changes(&lease.applied))
    {
        return Err("nvcp_journal_invalid");
    }
    if state.completed.iter().any(|entry| {
        !valid_identity(&entry.owner)
            || !valid_identity(&entry.target)
            || entry.fingerprint.len() > 4096
    }) {
        return Err("nvcp_journal_invalid");
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn journal_has_effects(path: &std::path::Path) -> Result<bool, &'static str> {
    let Some(bytes) = super::journal::read(path)? else {
        return Ok(false);
    };
    let state: State = serde_json::from_slice(&bytes).map_err(|_| "nvcp_journal_invalid")?;
    validate(&state)?;
    Ok(state.active.is_some())
}
