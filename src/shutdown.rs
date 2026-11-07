//! The host announces one absolute budget before dependency-ordered cleanup.
//! Recording it must not begin retirement while consumers still own the policy.
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct Shutdown {
    deadline: Option<Instant>,
    started: bool,
}

impl Shutdown {
    pub(crate) fn announce(&mut self, remaining_ms: u64) -> Instant {
        let now = Instant::now();
        self.announce_until(
            now.checked_add(Duration::from_millis(remaining_ms))
                .unwrap_or(now),
        )
    }

    pub(crate) fn announce_until(&mut self, deadline: Instant) -> Instant {
        let deadline = self.deadline.map_or(deadline, |old| old.min(deadline));
        self.deadline = Some(deadline);
        deadline
    }

    pub(crate) fn begin(&mut self) -> Instant {
        let deadline = match self.deadline {
            Some(deadline) => deadline,
            None => self.announce(20_000),
        };
        self.started = true;
        deadline
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub(crate) fn started(&self) -> bool {
        self.started
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_announcement_and_begin_never_renew_the_first_budget() {
        let mut shutdown = Shutdown::default();
        let expired = Instant::now() - Duration::from_secs(1);
        assert_eq!(shutdown.announce_until(expired), expired);
        assert!(!shutdown.started());
        assert_eq!(shutdown.announce(300_000), expired);
        assert_eq!(shutdown.begin(), expired);
        assert_eq!(shutdown.begin(), expired);
    }
}
