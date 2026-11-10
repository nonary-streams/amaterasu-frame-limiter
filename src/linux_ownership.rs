//! Provider-owned generations for Proton policy transitions.
//!
//! The application root and its current stream have independent worker entries.
//! Changes commit only after the exact native compare-and-set is acknowledged;
//! uncertain effects stay fenced until verified worker retirement.
use amaterasu_module_sdk::extension_api::LifecycleTarget;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_SESSIONS: usize = 32;
const MAX_SESSION_HISTORY: usize = MAX_SESSIONS + MAX_COMPLETED_SESSIONS;
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
    // Older journals stored either a session or stream here. Preserve that exact
    // binding until verified recovery retires it; never synthesize a root from
    // a retired target hash or a legacy stream binding.
    current: Option<Binding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root: Option<Binding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retiring_root: Option<LifecycleTarget>,
    retired: BTreeSet<String>,
    generation: u64,
}

impl Session {
    fn root(&self) -> Option<&Binding> {
        self.root.as_ref().or_else(|| {
            self.current
                .as_ref()
                .filter(|binding| matches!(binding.target, LifecycleTarget::Session { .. }))
        })
    }

    fn binding(&self, target: &LifecycleTarget) -> Option<&Binding> {
        match target {
            LifecycleTarget::Session { .. } => self.root(),
            LifecycleTarget::Stream { .. } => self
                .current
                .as_ref()
                .filter(|binding| matches!(binding.target, LifecycleTarget::Stream { .. })),
            LifecycleTarget::Validation { .. } => None,
        }
    }

    fn has_bindings(&self) -> bool {
        self.root.is_some() || self.current.is_some()
    }

    fn tracked_targets(&self) -> usize {
        self.retired.len() + usize::from(self.root.is_some()) + usize::from(self.current.is_some())
    }

    fn migrate_legacy_root(&mut self) -> Result<(), &'static str> {
        if self
            .current
            .as_ref()
            .is_some_and(|binding| matches!(binding.target, LifecycleTarget::Session { .. }))
        {
            if self.root.is_some() {
                return Err("invalid_ownership_journal");
            }
            self.root = self.current.take();
        }
        Ok(())
    }
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

impl Change {
    pub(crate) fn policy_key(&self) -> Result<String, &'static str> {
        if session_key(&self.target)? != self.session {
            return Err("invalid_identity");
        }
        match &self.target {
            LifecycleTarget::Session { .. } => Ok(self.session.clone()),
            LifecycleTarget::Stream { .. } => Ok(format!("stream-{}", target_key(&self.target)?)),
            LifecycleTarget::Validation { .. } => Err("invalid_target"),
        }
    }
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

pub(crate) fn session_key(target: &LifecycleTarget) -> Result<String, &'static str> {
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
    // Worker retirement removes native bindings but keeps exact target history
    // for late cleanup. That history must not occupy live policy slots.
    fn check_capacity(&self, session: &str, preparing: bool) -> Result<(), &'static str> {
        let existing = self.sessions.get(session);
        if existing.is_none() && self.sessions.len() >= MAX_SESSION_HISTORY {
            return Err("retirement_capacity_exhausted");
        }
        if preparing
            && existing.is_none_or(|entry| !entry.has_bindings())
            && self
                .sessions
                .values()
                .filter(|entry| entry.has_bindings())
                .count()
                >= MAX_SESSIONS
        {
            return Err("session_capacity_exhausted");
        }
        Ok(())
    }

    pub(crate) fn has_root(&self, session: &str) -> bool {
        self.sessions
            .get(session)
            .is_some_and(|entry| entry.root().is_some())
    }

    pub(crate) fn remember_retired_target(
        &mut self,
        target: &LifecycleTarget,
    ) -> Result<(), &'static str> {
        let key = session_key(target)?;
        if self.completed.contains_key(&key) {
            return Ok(());
        }
        self.check_capacity(&key, false)?;
        let target = target_key(target)?;
        let entry = self.sessions.entry(key).or_default();
        if !entry.retired.contains(&target) && entry.tracked_targets() >= MAX_RETIRED_TARGETS {
            return Err("retirement_capacity_exhausted");
        }
        entry.retired.insert(target);
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.sessions.len() > MAX_SESSION_HISTORY
            || self
                .sessions
                .values()
                .filter(|entry| entry.has_bindings())
                .count()
                > MAX_SESSIONS
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
                || session.tracked_targets() > MAX_RETIRED_TARGETS
                || session.retired.iter().any(|value| !valid_hash(value))
                || (session.root.is_some()
                    && session.current.as_ref().is_some_and(|binding| {
                        matches!(binding.target, LifecycleTarget::Session { .. })
                    }))
            {
                return Err("invalid_ownership_journal");
            }
            for binding in session.root.iter().chain(session.current.iter()) {
                if session_key(&binding.target)? != *key
                    || binding
                        .revision
                        .strip_prefix("revision-")
                        .is_none_or(|value| !valid_hash(value))
                    || session.retired.contains(&target_key(&binding.target)?)
                {
                    return Err("invalid_ownership_journal");
                }
            }
            if session
                .root
                .as_ref()
                .is_some_and(|binding| !matches!(binding.target, LifecycleTarget::Session { .. }))
            {
                return Err("invalid_ownership_journal");
            }
            if let Some(target) = &session.retiring_root
                && (!matches!(target, LifecycleTarget::Session { .. })
                    || session_key(target)? != *key
                    || !session.retired.contains(&target_key(target)?)
                    || session.root().is_some())
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
                || current.and_then(|entry| {
                    entry
                        .binding(&pending.target)
                        .map(|binding| &binding.revision)
                }) != pending.expected_revision.as_ref()
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

    /// Called only after the replacement worker proves all prior owned policy
    /// entries absent. Preserve exact root/stream targets without replaying them.
    pub(crate) fn retire_after_worker_restart(&mut self) -> Result<(), &'static str> {
        let mut retired = self.clone();
        if let Some(change) = retired.pending.take() {
            let entry = retired.sessions.entry(change.session).or_default();
            entry.retired.insert(target_key(&change.target)?);
        }
        for session in retired.sessions.values_mut() {
            for binding in session
                .root
                .take()
                .into_iter()
                .chain(session.current.take())
            {
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
                        .binding(target)
                        .is_some_and(|binding| binding.target == *target)
            })
    }

    /// Reserve one exact slot; its sibling root/stream entry remains independent.
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
        self.check_capacity(&session, true)?;
        if existing.is_some_and(|entry| entry.retiring_root.is_some()) {
            return Err("retired_session");
        }
        if existing.is_some_and(|entry| entry.generation == u64::MAX) {
            return Err("ownership_generation_exhausted");
        }
        let target_id = target_key(target)?;
        if existing.is_some_and(|entry| entry.retired.contains(&target_id)) {
            return Err("retired_target");
        }
        let binding = existing.and_then(|entry| entry.binding(target));
        if let Some(binding) = binding
            && binding.target != *target
        {
            return Err(match target {
                LifecycleTarget::Stream { .. } => "previous_stream_not_retired",
                _ => "previous_session_not_retired",
            });
        }
        if binding.is_none()
            && existing.is_some_and(|entry| entry.tracked_targets() >= MAX_RETIRED_TARGETS)
        {
            return Err("retirement_capacity_exhausted");
        }
        let change = Change {
            session,
            target: target.clone(),
            expected_revision: binding.map(|binding| binding.revision.clone()),
            new_revision: Some(format!("revision-{}", hash(&(target, transition))?)),
            generation: existing.map_or(0, |entry| entry.generation),
        };
        self.pending = Some(change.clone());
        Ok(change)
    }

    /// Unknown targets never authorize cleanup of either live slot.
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
        let entry = self.sessions.get_mut(&session).ok_or("ownership_unknown")?;
        if entry.retired.contains(&target_id) {
            if matches!(target, LifecycleTarget::Session { .. }) {
                if entry.root().is_some()
                    || entry
                        .retiring_root
                        .as_ref()
                        .is_some_and(|root| root != target)
                {
                    return Err("target_not_current");
                }
                entry.retiring_root = Some(target.clone());
            }
            return Ok(None);
        }
        let current = entry.binding(target).ok_or(if entry.has_bindings() {
            "target_not_current"
        } else {
            "ownership_unknown"
        })?;
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
            || existing.and_then(|entry| {
                entry
                    .binding(&change.target)
                    .map(|binding| &binding.revision)
            }) != change.expected_revision.as_ref()
        {
            return Err("ownership_changed");
        }
        let next_generation = change
            .generation
            .checked_add(1)
            .ok_or("ownership_generation_exhausted")?;
        self.check_capacity(&change.session, change.new_revision.is_some())?;
        let entry = self.sessions.entry(change.session).or_default();
        entry.migrate_legacy_root()?;
        let slot = match change.target {
            LifecycleTarget::Session { .. } => &mut entry.root,
            LifecycleTarget::Stream { .. } => &mut entry.current,
            LifecycleTarget::Validation { .. } => return Err("invalid_target"),
        };
        if let Some(current) = slot.as_ref()
            && (current.target != change.target || change.new_revision.is_none())
        {
            if entry.retired.len() >= MAX_RETIRED_TARGETS {
                return Err("retirement_capacity_exhausted");
            }
            entry.retired.insert(target_key(&current.target)?);
        }
        if change.new_revision.is_none() && matches!(change.target, LifecycleTarget::Session { .. })
        {
            entry.retiring_root = Some(change.target.clone());
        }
        *slot = change.new_revision.map(|revision| Binding {
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

    /// Finish either cleanup order once the root release was acknowledged and
    /// both independent native entries have gone. A paused root stays live.
    pub(crate) fn finish_session_if_idle(
        &mut self,
        target: &LifecycleTarget,
    ) -> Result<bool, &'static str> {
        if self.pending.is_some() {
            return Err("ownership_change_pending");
        }
        let key = session_key(target)?;
        if self.completed.contains_key(&key) {
            return Ok(true);
        }
        let entry = self.sessions.get(&key).ok_or("ownership_unknown")?;
        if entry.has_bindings() {
            return Ok(false);
        }
        let Some(root) = entry.retiring_root.clone() else {
            return Ok(false);
        };
        self.finish_session(&root)?;
        Ok(true)
    }

    /// Strict completion requires exact root retirement and no surviving stream.
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
        if entry.has_bindings()
            || !entry.retired.contains(&target_id)
            || entry
                .retiring_root
                .as_ref()
                .is_some_and(|root| root != target)
        {
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
        let root_release = owner.release(&session()).unwrap().unwrap();
        owner.commit(root_release).unwrap();
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
    #[test]
    fn pausing_and_resuming_preserves_the_exact_root_claim() {
        let mut owner = Ownership::default();
        let root = owner.prepare(&session(), "prepare-root").unwrap();
        let root_key = root.policy_key().unwrap();
        let root_revision = root.new_revision.clone();
        assert_eq!(root_key, session_key(&session()).unwrap());
        assert!(root_key.len() <= 128);
        owner.commit(root).unwrap();
        let first = owner.prepare(&stream("first"), "prepare-first").unwrap();
        let first_key = first.policy_key().unwrap();
        assert!(first_key.starts_with("stream-"));
        assert!(first_key.len() <= 128);
        assert_ne!(first_key, root_key);
        owner.commit(first).unwrap();
        let pause = owner.release(&stream("first")).unwrap().unwrap();
        owner.commit(pause).unwrap();
        assert!(owner.has_root(&root_key));
        assert!(!owner.finish_session_if_idle(&stream("first")).unwrap());
        let resumed = owner.prepare(&stream("resumed"), "resume").unwrap();
        assert_eq!(resumed.expected_revision, None);
        assert_ne!(resumed.policy_key().unwrap(), first_key);
        let resumed_revision = resumed.new_revision.clone();
        owner.commit(resumed).unwrap();
        assert!(owner.release(&stream("first")).unwrap().is_none());
        let root_release = owner.release(&session()).unwrap().unwrap();
        assert_eq!(root_release.expected_revision, root_revision);
        owner.abort(&root_release).unwrap();
        let resumed_release = owner.release(&stream("resumed")).unwrap().unwrap();
        assert_eq!(resumed_release.expected_revision, resumed_revision);
        owner.abort(&resumed_release).unwrap();
        owner.validate().unwrap();
    }

    #[test]
    fn final_cleanup_finishes_only_after_both_independent_claims_retire() {
        for root_first in [true, false] {
            let mut owner = Ownership::default();
            let root = owner.prepare(&session(), "root").unwrap();
            owner.commit(root).unwrap();
            let active_stream = stream("active");
            let claim = owner.prepare(&active_stream, "stream").unwrap();
            owner.commit(claim).unwrap();
            let (first, last) = if root_first {
                (session(), active_stream.clone())
            } else {
                (active_stream.clone(), session())
            };
            let release = owner.release(&first).unwrap().unwrap();
            owner.commit(release).unwrap();
            assert!(!owner.finish_session_if_idle(&first).unwrap());
            assert_eq!(
                owner.has_root(&session_key(&session()).unwrap()),
                !root_first
            );
            if root_first {
                assert_eq!(
                    owner.prepare(&stream("late"), "late"),
                    Err("retired_session")
                );
            }
            let mut restored: Ownership =
                serde_json::from_value(serde_json::to_value(&owner).unwrap()).unwrap();
            restored.validate().unwrap();
            let release = restored.release(&last).unwrap().unwrap();
            restored.commit(release).unwrap();
            assert!(restored.finish_session_if_idle(&last).unwrap());
            assert!(restored.finish_session_if_idle(&first).unwrap());
            assert!(restored.sessions.is_empty());
            assert_eq!(restored.completed.len(), 1);
            assert_eq!(restored.prepare(&session(), "late"), Err("retired_session"));
            restored.validate().unwrap();
        }
    }

    #[test]
    fn verified_worker_retirement_remembers_both_claims_without_replaying_them() {
        let mut owner = Ownership::default();
        let root = owner.prepare(&session(), "root").unwrap();
        owner.commit(root).unwrap();
        let active = stream("active");
        let claim = owner.prepare(&active, "stream").unwrap();
        owner.commit(claim).unwrap();
        let pending = owner.prepare(&active, "uncertain-update").unwrap();
        let mut restored: Ownership =
            serde_json::from_value(serde_json::to_value(&owner).unwrap()).unwrap();
        restored.validate().unwrap();
        assert_eq!(
            restored.release(&session()),
            Err("ownership_change_pending")
        );
        restored.retire_after_worker_restart().unwrap();
        assert_eq!(
            restored.commit(pending),
            Err("ownership_change_not_reserved")
        );
        assert!(!restored.has_root(&session_key(&session()).unwrap()));
        assert!(restored.knows_target(&session()));
        assert!(restored.knows_target(&active));
        assert!(!restored.finish_session_if_idle(&active).unwrap());
        assert!(restored.release(&session()).unwrap().is_none());
        assert!(restored.finish_session_if_idle(&session()).unwrap());
        restored.validate().unwrap();
    }

    #[test]
    fn legacy_journal_keeps_only_its_exact_binding_until_verified_retirement() {
        for original in [session(), stream("legacy")] {
            let key = session_key(&original).unwrap();
            let journal = serde_json::json!({
                "sessions": {key.clone(): {
                    "current": {"target": original, "revision": format!("revision-{}", "a".repeat(64))},
                    "retired": [], "generation": 1
                }},
                "completed": {}, "completion_order": [], "pending": null
            });
            let mut owner: Ownership = serde_json::from_value(journal).unwrap();
            owner.validate().unwrap();
            assert_eq!(
                owner.has_root(&key),
                matches!(original, LifecycleTarget::Session { .. })
            );
            owner.retire_after_worker_restart().unwrap();
            assert!(!owner.has_root(&key));
            assert!(owner.knows_target(&original));
            assert_eq!(owner.knows_target(&session()), original == session());
            assert!(owner.sessions[&key].root.is_none());
            assert!(owner.sessions[&key].current.is_none());
            owner.validate().unwrap();
        }
    }

    #[test]
    fn retired_root_hash_is_never_reconstructed_as_a_live_root() {
        let mut owner = Ownership::default();
        owner.remember_retired_target(&session()).unwrap();
        let active = stream("legacy-stream");
        let claim = owner.prepare(&active, "stream").unwrap();
        owner.commit(claim).unwrap();
        let key = session_key(&session()).unwrap();
        assert!(!owner.has_root(&key));
        assert!(owner.release(&session()).unwrap().is_none());
        assert!(!owner.finish_session_if_idle(&session()).unwrap());
        let release = owner.release(&active).unwrap().unwrap();
        owner.commit(release).unwrap();
        assert!(owner.finish_session_if_idle(&active).unwrap());
        owner.validate().unwrap();
    }

    #[test]
    fn independent_slots_reserve_bounded_retirement_storage() {
        let mut owner = Ownership::default();
        let root = owner.prepare(&session(), "root").unwrap();
        owner.commit(root).unwrap();
        for index in 0..(MAX_RETIRED_TARGETS - 1) {
            owner
                .remember_retired_target(&stream(&format!("retired-{index}")))
                .unwrap();
        }
        assert_eq!(
            owner.prepare(&stream("overflow"), "stream"),
            Err("retirement_capacity_exhausted")
        );
        assert_eq!(
            owner.remember_retired_target(&stream("overflow")),
            Err("retirement_capacity_exhausted")
        );
        let release = owner.release(&session()).unwrap().unwrap();
        owner.commit(release).unwrap();
        assert!(owner.finish_session_if_idle(&session()).unwrap());
        owner.validate().unwrap();
    }

    #[test]
    fn session_root_and_stream_claim_keep_independent_native_revisions() {
        let mut owner = Ownership::default();
        let root = owner.prepare(&session(), "prepare-root").unwrap();
        let root_revision = root.new_revision.clone();
        owner.commit(root).unwrap();
        let stream_change = owner.prepare(&stream("first"), "prepare-stream").unwrap();
        assert_eq!(
            stream_change.expected_revision, None,
            "a new stream is a distinct worker policy entry"
        );
        let stream_revision = stream_change.new_revision.clone();
        owner.commit(stream_change).unwrap();
        let release_root = owner
            .release(&session())
            .unwrap()
            .expect("stream preparation must preserve the session root");
        assert_eq!(release_root.expected_revision, root_revision);
        owner.commit(release_root).unwrap();
        let release_stream = owner.release(&stream("first")).unwrap().unwrap();
        assert_eq!(release_stream.expected_revision, stream_revision);
        owner.commit(release_stream).unwrap();
    }
    #[test]
    fn retired_worker_history_does_not_consume_live_policy_capacity() {
        let mut owner = Ownership::default();
        let mut targets = Vec::new();
        for index in 0..MAX_SESSIONS + 1 {
            let target = LifecycleTarget::Session {
                host_epoch: "epoch".into(),
                session_id: format!("session-{index}"),
                generation: 1,
            };
            let change = owner.prepare(&target, "prepare").unwrap();
            owner.commit(change).unwrap();
            owner.retire_after_worker_restart().unwrap();
            targets.push(target);
        }
        let mut owner: Ownership =
            serde_json::from_value(serde_json::to_value(owner).unwrap()).unwrap();
        owner.validate().unwrap();
        for target in targets {
            assert!(owner.release(&target).unwrap().is_none());
            owner.finish_session(&target).unwrap();
        }
        assert!(owner.sessions.is_empty());
    }

    #[test]
    fn retained_history_does_not_expand_live_policy_limit() {
        let mut owner = Ownership::default();
        for index in 0..MAX_SESSIONS + 1 {
            let target = LifecycleTarget::Session {
                host_epoch: "epoch".into(),
                session_id: format!("session-{index}"),
                generation: 1,
            };
            if index == MAX_SESSIONS {
                assert_eq!(
                    owner.prepare(&target, "prepare"),
                    Err("session_capacity_exhausted")
                );
            } else {
                let change = owner.prepare(&target, "prepare").unwrap();
                owner.commit(change).unwrap();
            }
        }
    }
}
