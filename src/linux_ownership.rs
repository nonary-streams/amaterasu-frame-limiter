//! Provider-owned generations for Proton policy transitions.
//!
//! The worker performs the actual compare-and-set. This ledger must only be
//! committed after the worker confirms the exact effect; an uncertain outcome
//! remains a recovery problem rather than permission to retry a mutation.
use amaterasu_module_sdk::extension_api::LifecycleTarget;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_SESSIONS: usize = 32;
const MAX_RETIRED_TARGETS: usize = 256;
const MAX_COMPLETED_SESSIONS: usize = 256;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding {
    target: LifecycleTarget,
    revision: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Session {
    current: Option<Binding>,
    retired: BTreeSet<String>,
    generation: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Change {
    pub session: String,
    pub target: LifecycleTarget,
    pub expected_revision: Option<String>,
    pub new_revision: Option<String>,
    generation: u64,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ownership {
    sessions: BTreeMap<String, Session>,
    completed: BTreeMap<String, String>,
    completion_order: VecDeque<String>,
    pending: Option<Change>,
}

fn hash(value: &impl serde::Serialize) -> Result<String, &'static str> {
    let bytes = serde_json::to_vec(value).map_err(|_| "invalid_identity")?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn session_key(target: &LifecycleTarget) -> Result<String, &'static str> {
    let (epoch, session) = match target {
        LifecycleTarget::Session {
            host_epoch,
            session_id,
            ..
        }
        | LifecycleTarget::Stream {
            host_epoch,
            session_id,
            ..
        } => (host_epoch, session_id),
        LifecycleTarget::Validation { .. } => return Err("invalid_target"),
    };
    if epoch.is_empty() || session.is_empty() {
        return Err("invalid_target");
    }
    Ok(format!("session-{}", hash(&(epoch, session))?))
}

fn target_key(target: &LifecycleTarget) -> Result<String, &'static str> {
    hash(target)
}

impl Ownership {
    pub(crate) fn remember_retired_target(
        &mut self,
        target: &LifecycleTarget,
    ) -> Result<(), &'static str> {
        let key = session_key(target)?;
        if self.completed.contains_key(&key) {
            return Ok(());
        }
        if !self.sessions.contains_key(&key) && self.sessions.len() >= MAX_SESSIONS {
            return Err("session_capacity_exhausted");
        }
        let target = target_key(target)?;
        let entry = self.sessions.entry(key).or_default();
        if !entry.retired.contains(&target) && entry.retired.len() >= MAX_RETIRED_TARGETS {
            return Err("retirement_capacity_exhausted");
        }
        entry.retired.insert(target);
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.sessions.len() > MAX_SESSIONS
            || self.completed.len() > MAX_COMPLETED_SESSIONS
            || self.completed.len() != self.completion_order.len()
            || self.completion_order.iter().collect::<BTreeSet<_>>().len()
                != self.completion_order.len()
            || self
                .completion_order
                .iter()
                .any(|key| !self.completed.contains_key(key))
        {
            return Err("invalid_ownership_journal");
        }
        let valid_hash =
            |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
        let valid_session = |value: &str| value.strip_prefix("session-").is_some_and(valid_hash);
        for (key, session) in &self.sessions {
            if !valid_session(key)
                || self.completed.contains_key(key)
                || session.retired.len() > MAX_RETIRED_TARGETS
                || session.retired.iter().any(|value| !valid_hash(value))
            {
                return Err("invalid_ownership_journal");
            }
            if let Some(current) = &session.current
                && (session_key(&current.target)? != *key
                    || current
                        .revision
                        .strip_prefix("revision-")
                        .is_none_or(|value| !valid_hash(value))
                    || session.retired.contains(&target_key(&current.target)?))
            {
                return Err("invalid_ownership_journal");
            }
        }
        if self
            .completed
            .iter()
            .any(|(key, value)| !valid_session(key) || !valid_hash(value))
        {
            return Err("invalid_ownership_journal");
        }
        if let Some(pending) = &self.pending {
            let current = self.sessions.get(&pending.session);
            if session_key(&pending.target)? != pending.session
                || current.map_or(0, |entry| entry.generation) != pending.generation
                || current.and_then(|entry| entry.current.as_ref().map(|entry| &entry.revision))
                    != pending.expected_revision.as_ref()
                || pending.new_revision.as_deref().is_some_and(|revision| {
                    revision
                        .strip_prefix("revision-")
                        .is_none_or(|value| !valid_hash(value))
                })
            {
                return Err("invalid_ownership_journal");
            }
        }
        Ok(())
    }

    /// Called only after a replacement worker proves the prior owner's policy
    /// file absent. Remember targets for cleanup, without reviving their effects.
    pub(crate) fn retire_after_worker_restart(&mut self) -> Result<(), &'static str> {
        let mut retired = self.clone();
        if let Some(change) = retired.pending.take() {
            let entry = retired.sessions.entry(change.session).or_default();
            entry.retired.insert(target_key(&change.target)?);
        }
        for session in retired.sessions.values_mut() {
            if let Some(binding) = session.current.take() {
                session.retired.insert(target_key(&binding.target)?);
            }
            if session.retired.len() > MAX_RETIRED_TARGETS {
                return Err("retirement_capacity_exhausted");
            }
            session.generation = session
                .generation
                .checked_add(1)
                .ok_or("ownership_generation_exhausted")?;
        }
        retired.validate()?;
        *self = retired;
        Ok(())
    }

    pub(crate) fn knows_target(&self, target: &LifecycleTarget) -> bool {
        let (Ok(session), Ok(target_id)) = (session_key(target), target_key(target)) else {
            return false;
        };
        self.completed.get(&session) == Some(&target_id)
            || self.sessions.get(&session).is_some_and(|entry| {
                entry.retired.contains(&target_id)
                    || entry
                        .current
                        .as_ref()
                        .is_some_and(|binding| binding.target == *target)
            })
    }

    /// Reserve no effect: callers send this exact expected revision to the
    /// worker and call `commit` only after the matching successful reply.
    pub(crate) fn prepare(
        &mut self,
        target: &LifecycleTarget,
        transition: &str,
    ) -> Result<Change, &'static str> {
        if self.pending.is_some() {
            return Err("ownership_change_pending");
        }
        if transition.is_empty()
            || transition.len() > 128
            || transition.chars().any(char::is_control)
        {
            return Err("invalid_transition");
        }
        let session = session_key(target)?;
        if self.completed.contains_key(&session) {
            return Err("retired_session");
        }
        let existing = self.sessions.get(&session);
        if existing.is_none() && self.sessions.len() >= MAX_SESSIONS {
            return Err("session_capacity_exhausted");
        }
        if existing.is_some_and(|value| value.generation == u64::MAX) {
            return Err("ownership_generation_exhausted");
        }
        let target_id = target_key(target)?;
        if existing.is_some_and(|value| value.retired.contains(&target_id)) {
            return Err("retired_target");
        }
        if let Some(current) = existing.and_then(|value| value.current.as_ref()) {
            if current.target != *target && matches!(current.target, LifecycleTarget::Stream { .. })
            {
                return Err("previous_stream_not_retired");
            }
            if current.target != *target
                && existing.is_some_and(|value| value.retired.len() >= MAX_RETIRED_TARGETS)
            {
                return Err("retirement_capacity_exhausted");
            }
        }
        let change = Change {
            session,
            target: target.clone(),
            expected_revision: existing.and_then(|value| {
                value
                    .current
                    .as_ref()
                    .map(|binding| binding.revision.clone())
            }),
            new_revision: Some(format!("revision-{}", hash(&(target, transition))?)),
            generation: existing.map_or(0, |value| value.generation),
        };
        self.pending = Some(change.clone());
        Ok(change)
    }

    /// A missing target is unknown, not proof that a previous effect was removed.
    pub(crate) fn release(
        &mut self,
        target: &LifecycleTarget,
    ) -> Result<Option<Change>, &'static str> {
        if self.pending.is_some() {
            return Err("ownership_change_pending");
        }
        let session = session_key(target)?;
        let target_id = target_key(target)?;
        if self.completed.get(&session) == Some(&target_id) {
            return Ok(None);
        }
        let entry = self.sessions.get(&session).ok_or("ownership_unknown")?;
        if entry.retired.contains(&target_id) {
            return Ok(None);
        }
        let current = entry.current.as_ref().ok_or("ownership_unknown")?;
        if current.target != *target {
            return Err("target_not_current");
        }
        if entry.generation == u64::MAX {
            return Err("ownership_generation_exhausted");
        }
        if entry.retired.len() >= MAX_RETIRED_TARGETS {
            return Err("retirement_capacity_exhausted");
        }
        let change = Change {
            session,
            target: target.clone(),
            expected_revision: Some(current.revision.clone()),
            new_revision: None,
            generation: entry.generation,
        };
        self.pending = Some(change.clone());
        Ok(Some(change))
    }

    pub(crate) fn commit(&mut self, change: Change) -> Result<(), &'static str> {
        if self.pending.as_ref() != Some(&change) {
            return Err("ownership_change_not_reserved");
        }
        let existing = self.sessions.get(&change.session);
        if existing.map_or(0, |entry| entry.generation) != change.generation
            || existing.and_then(|entry| entry.current.as_ref().map(|binding| &binding.revision))
                != change.expected_revision.as_ref()
        {
            return Err("ownership_changed");
        }
        let next_generation = change
            .generation
            .checked_add(1)
            .ok_or("ownership_generation_exhausted")?;
        if existing.is_none() && self.sessions.len() >= MAX_SESSIONS {
            return Err("session_capacity_exhausted");
        }
        let entry = self.sessions.entry(change.session).or_default();
        if let Some(current) = &entry.current
            && (current.target != change.target || change.new_revision.is_none())
        {
            if entry.retired.len() >= MAX_RETIRED_TARGETS {
                return Err("retirement_capacity_exhausted");
            }
            entry.retired.insert(target_key(&current.target)?);
        }
        entry.current = change.new_revision.map(|revision| Binding {
            target: change.target,
            revision,
        });
        entry.generation = next_generation;
        self.pending = None;
        Ok(())
    }

    /// Abort only when the worker definitively did not perform the change.
    pub(crate) fn abort(&mut self, change: &Change) -> Result<(), &'static str> {
        if self.pending.as_ref() != Some(change) {
            return Err("ownership_change_not_reserved");
        }
        self.pending = None;
        Ok(())
    }

    /// Retire an ended session only after its last worker effect is confirmed
    /// absent. Keep bounded tombstones so repeated cleanup remains idempotent.
    pub(crate) fn finish_session(&mut self, target: &LifecycleTarget) -> Result<(), &'static str> {
        if self.pending.is_some() {
            return Err("ownership_change_pending");
        }
        if !matches!(target, LifecycleTarget::Session { .. }) {
            return Err("invalid_target");
        }
        let key = session_key(target)?;
        let target_id = target_key(target)?;
        if self.completed.get(&key) == Some(&target_id) {
            return Ok(());
        }
        let entry = self.sessions.get(&key).ok_or("ownership_unknown")?;
        if entry.current.is_some() || !entry.retired.contains(&target_id) {
            return Err("session_not_retired");
        }
        self.sessions.remove(&key);
        self.completed.insert(key.clone(), target_id);
        self.completion_order.push_back(key);
        while self.completion_order.len() > MAX_COMPLETED_SESSIONS {
            if let Some(oldest) = self.completion_order.pop_front() {
                self.completed.remove(&oldest);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn session() -> LifecycleTarget {
        LifecycleTarget::Session {
            host_epoch: "epoch".into(),
            session_id: "one".into(),
            generation: 1,
        }
    }
    fn stream(id: &str) -> LifecycleTarget {
        LifecycleTarget::Stream {
            host_epoch: "epoch".into(),
            session_id: "one".into(),
            stream_id: id.into(),
            generation: 1,
        }
    }

    #[test]
    fn old_cleanup_cannot_retire_a_resumed_stream() {
        let mut owner = Ownership::default();
        let first = owner.prepare(&session(), "prepare-session").unwrap();
        owner.commit(first).unwrap();
        let first_stream = owner.prepare(&stream("first"), "start-first").unwrap();
        owner.commit(first_stream).unwrap();
        let release = owner.release(&stream("first")).unwrap().unwrap();
        owner.commit(release).unwrap();
        let second = owner.prepare(&stream("second"), "start-second").unwrap();
        owner.commit(second).unwrap();
        assert!(owner.release(&stream("first")).unwrap().is_none());
        assert!(owner.release(&session()).unwrap().is_none());
        assert_eq!(owner.release(&stream("unknown")), Err("target_not_current"));
        let current = owner.release(&stream("second")).unwrap().unwrap();
        owner.commit(current).unwrap();
        owner.finish_session(&session()).unwrap();
        assert!(owner.release(&session()).unwrap().is_none());
        assert_eq!(owner.prepare(&session(), "late"), Err("retired_session"));
    }

    #[test]
    fn stale_worker_reply_cannot_commit_over_a_newer_change() {
        let mut owner = Ownership::default();
        let a = owner.prepare(&session(), "one").unwrap();
        assert_eq!(
            owner.prepare(&session(), "two"),
            Err("ownership_change_pending")
        );
        owner.commit(a.clone()).unwrap();
        assert_eq!(owner.commit(a), Err("ownership_change_not_reserved"));
        assert_eq!(owner.release(&stream("unknown")), Err("target_not_current"));
    }

    #[test]
    fn uncertain_changes_remain_fenced_until_the_owner_confirms_no_effect() {
        let mut owner = Ownership::default();
        let pending = owner.prepare(&session(), "one").unwrap();
        assert_eq!(owner.release(&session()), Err("ownership_change_pending"));
        owner.abort(&pending).unwrap();
        assert_eq!(owner.release(&session()), Err("ownership_unknown"));
        let replacement = owner.prepare(&session(), "two").unwrap();
        owner.commit(replacement).unwrap();
    }

    #[test]
    fn unknown_and_unretired_streams_are_not_silently_discarded() {
        let mut owner = Ownership::default();
        assert_eq!(owner.release(&session()), Err("ownership_unknown"));
        let first = owner.prepare(&stream("first"), "one").unwrap();
        owner.commit(first).unwrap();
        assert_eq!(
            owner.prepare(&stream("second"), "two"),
            Err("previous_stream_not_retired")
        );
        assert_eq!(owner.release(&session()), Err("target_not_current"));
        assert_eq!(owner.finish_session(&session()), Err("session_not_retired"));
    }
}
