use super::*;

impl Worker {
    /// Announcement closes outside admission, but declared consumers can keep
    /// using lifecycle callbacks until the host actually quiesces this provider.
    pub(crate) fn prepare_shutdown(&mut self, remaining_ms: u64) {
        let deadline = Instant::now() + Duration::from_millis(remaining_ms.min(30_000));
        self.shutdown_deadline = Some(
            self.shutdown_deadline
                .map_or(deadline, |old| old.min(deadline)),
        );
    }

    pub(crate) fn quiesce(&mut self) -> Result<bool, &'static str> {
        if self.shutdown_complete {
            return Ok(true);
        }
        if self.shutdown_deadline.is_none() {
            self.prepare_shutdown(5_000);
        }
        if !self.shutdown_started {
            self.shutdown_started = true;
            let queued: Vec<_> = self.queue.drain(..).collect();
            for id in queued {
                let value = match &self.jobs[&id].operation {
                    Operation::Lifecycle { .. } => {
                        serde_json::to_value(ProviderResponse::Rejected {
                            reason: "native_worker_stopping_before_effect".into(),
                        })
                        .unwrap()
                    }
                    operation => error_value(operation, "native_worker_stopping_before_effect"),
                };
                self.finish(id, value);
            }
            if self.process.is_none()
                && !self.wanted
                && crate::lease::journal_has_effects(&self.config.rtss_journal) == Ok(false)
                && crate::nvcp::lease::journal_has_effects(&self.config.nvcp_journal) == Ok(false)
            {
                self.shutdown_complete = true;
                return Ok(true);
            }
            // Initialize a never-started worker only when it can still recover
            // retained journals. No new native call starts after cutoff.
            if self.process.is_none() && self.failure.is_none() {
                if Instant::now() >= self.shutdown_deadline.unwrap() {
                    self.failure = Some("native_worker_shutdown_deadline");
                } else if let Err(reason) = self.advance_inner() {
                    self.fail(reason);
                }
            }
            if let Some(process) = &self.process {
                process.close_input();
            }
        }
        if self.process.is_none() {
            return Err(self.failure.unwrap_or("native_worker_shutdown_unconfirmed"));
        }
        for _ in 0..64 {
            let value = match self.process.as_ref().unwrap().poll() {
                Ok(Some(value)) => value,
                Ok(None) | Err("native_worker_stopped") => break,
                Err(reason) => {
                    self.failure.get_or_insert(reason);
                    break;
                }
            };
            match serde_json::from_value::<Reply>(value) {
                Ok(Reply::Stopped) if self.starting.is_none() && self.active.is_none() => {
                    self.shutdown_restored = true;
                }
                Ok(Reply::Ready { snapshot }) if self.starting.is_some() => {
                    if let Err(reason) = validate_snapshot(&snapshot) {
                        self.failure.get_or_insert(reason);
                    }
                    self.snapshot = Some(snapshot);
                    self.starting = None;
                }
                Ok(Reply::Stage { .. }) => (),
                Ok(Reply::Result {
                    id,
                    value,
                    snapshot,
                }) if self.active == Some(id) => {
                    let valid = validate_snapshot(&snapshot).is_ok()
                        && match &self.jobs[&id].operation {
                            Operation::Lifecycle { request, .. } => {
                                serde_json::from_value::<ProviderResponse>(value.clone()).is_ok_and(
                                    |response| {
                                        api::validate_provider_response(request, &response).is_ok()
                                    },
                                )
                            }
                            _ => true,
                        };
                    if valid {
                        self.snapshot = Some(snapshot);
                        self.active = None;
                        self.finish(id, value);
                    } else {
                        self.failure.get_or_insert("native_worker_invalid_reply");
                    }
                }
                Ok(Reply::Fatal { .. }) => {
                    self.failure.get_or_insert("native_worker_cleanup_failed");
                }
                _ => {
                    self.failure.get_or_insert("native_worker_invalid_reply");
                }
            }
        }
        let exit = self.process.as_mut().unwrap().poll_exit()?;
        if exit.is_none()
            && Instant::now() >= self.shutdown_deadline.unwrap()
            && !self.shutdown_forced
        {
            self.shutdown_forced = true;
            // Exact owned job/child only. A successful kill request proves no
            // restoration, and it does not grant another confirmation window.
            self.fail("native_worker_shutdown_deadline");
        }
        match exit {
            None if self.shutdown_forced => Err("native_worker_shutdown_deadline"),
            None => Ok(false),
            Some(success) => {
                self.process.take();
                if success
                    && self.shutdown_restored
                    && !self.shutdown_forced
                    && self.failure.is_none()
                {
                    self.shutdown_complete = true;
                    Ok(true)
                } else {
                    let reason = self.failure.unwrap_or("native_worker_cleanup_unconfirmed");
                    self.fail(reason);
                    Err(reason)
                }
            }
        }
    }
}
