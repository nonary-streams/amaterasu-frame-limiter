//! Bounded process bridge to the plugin-owned Proton policy worker.
//!
//! The worker's code is embedded in the module, so installation never depends
//! on a source checkout. A worker reports readiness separately from policy or
//! hook installation, and its EOF guard retires policy when the module exits.
use serde_json::Value;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const MAX_FRAME_BYTES: usize = 65_536;
const QUEUE_CAPACITY: usize = 32;
const LIMITER: &str = include_str!("../proton/amaterasu_limiter.py");
const INSTALLER: &str = include_str!("../proton/install_hook.py");
const STORE: &str = include_str!("../proton/policy_store.py");
const DISCOVERY: &str = include_str!("../proton/discovery.py");
const WORKER: &str = include_str!("../proton/worker.py");
const BOOTSTRAP: &str = r#"
import sys, types
for name, source in zip(('amaterasu_limiter', 'install_hook', 'policy_store', 'discovery', 'limiter_worker'), sys.argv[4:]):
    module = types.ModuleType(name)
    sys.modules[name] = module
    exec(compile(source, '<amaterasu:' + name + '>', 'exec'), module.__dict__)
import json
sys.modules['limiter_worker'].run(sys.argv[1], sys.argv[4].encode('utf-8'), sys.argv[2], json.loads(sys.argv[3]))
"#;

const MAX_IO_STEPS: usize = 64;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

struct WorkerIo {
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
    commands: VecDeque<Vec<u8>>,
    write_offset: usize,
    incoming: Vec<u8>,
    replies: VecDeque<Value>,
    read_ended: bool,
    retiring: bool,
    failure: Option<&'static str>,
}

impl WorkerIo {
    fn begin_retirement(&mut self) {
        if self.retiring {
            return;
        }
        self.retiring = true;
        self.commands.clear();
        self.write_offset = 0;
        self.incoming.clear();
        self.replies.clear();
        self.failure = None;
        // Closing the sole writer delivers EOF after bytes already admitted to
        // the pipe. The Python worker retires its policy in its context guard.
        self.input.take();
    }

    fn pump(&mut self) -> Result<(), &'static str> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let result = self.flush_commands().and_then(|()| self.read_replies());
        if let Err(error) = result {
            self.failure = Some(error);
        }
        result
    }

    fn flush_commands(&mut self) -> Result<(), &'static str> {
        for _ in 0..MAX_IO_STEPS {
            let Some(frame) = self.commands.front() else {
                return Ok(());
            };
            let input = self.input.as_mut().ok_or("worker_stopped")?;
            match input.write(&frame[self.write_offset..]) {
                Ok(0) => return Err("worker_stopped"),
                Ok(written) => {
                    self.write_offset += written;
                    if self.write_offset == frame.len() {
                        self.commands.pop_front();
                        self.write_offset = 0;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("worker_stopped"),
            }
        }
        Ok(())
    }

    fn read_replies(&mut self) -> Result<(), &'static str> {
        if self.read_ended {
            return Ok(());
        }
        let mut bytes = [0u8; 8192];
        for _ in 0..MAX_IO_STEPS {
            let Some(output) = self.output.as_mut() else {
                return Ok(());
            };
            let count = match output.read(&mut bytes) {
                Ok(0) => {
                    self.read_ended = true;
                    break;
                }
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("worker_reply_unavailable"),
            };
            if self.retiring {
                // Retirement needs child exit and policy absence, not an ACK.
                // Drain bounded output so a full pipe cannot prevent EOF exit.
                continue;
            }
            self.incoming.extend_from_slice(&bytes[..count]);
            while let Some(end) = self.incoming.iter().position(|byte| *byte == b'\n') {
                if end + 1 > MAX_FRAME_BYTES || self.replies.len() >= QUEUE_CAPACITY {
                    return Err("invalid_worker_reply");
                }
                let reply = serde_json::from_slice(&self.incoming[..end])
                    .map_err(|_| "invalid_worker_reply")?;
                self.incoming.drain(..=end);
                self.replies.push_back(reply);
            }
            if self.incoming.len() >= MAX_FRAME_BYTES {
                return Err("invalid_worker_reply");
            }
        }
        Ok(())
    }
}

pub(crate) struct ProtonWorker {
    child: Child,
    io: RefCell<WorkerIo>,
    policy_path: PathBuf,
    shutdown_deadline: Option<Instant>,
    kill_requested: bool,
    exit_status: Option<ExitStatus>,
}

impl ProtonWorker {
    pub(crate) fn start(
        runtime_root: &Path,
        owner_id: &str,
        expected_policies: &[Vec<Value>],
    ) -> Result<Self, &'static str> {
        if !runtime_root.is_absolute() {
            return Err("runtime_root_not_absolute");
        }
        if owner_id.len() != 32 || !owner_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid_policy_owner");
        }
        let expected =
            serde_json::to_string(expected_policies).map_err(|_| "invalid_policy_intent")?;
        if expected.len() > MAX_FRAME_BYTES {
            return Err("policy_intent_too_large");
        }
        let child = Command::new("python3")
            .args(["-I", "-u", "-c", BOOTSTRAP])
            .arg(runtime_root)
            .arg(owner_id)
            .arg(expected)
            .args([LIMITER, INSTALLER, STORE, DISCOVERY, WORKER])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "proton_worker_spawn_failed")?;
        Ok(Self::from_child(
            child,
            runtime_root.join("amaterasu/frame-limiter/active.json"),
        ))
    }

    fn from_child(mut child: Child, policy_path: PathBuf) -> Self {
        let mut input = child.stdin.take();
        let mut output = child.stdout.take();
        let failure = match (&input, &output) {
            (Some(input), Some(output)) => set_nonblocking(input.as_raw_fd())
                .and_then(|()| set_nonblocking(output.as_raw_fd()))
                .err(),
            _ => Some("proton_worker_pipe_unavailable"),
        };
        if failure.is_some() {
            // Keep the exact child even when transport initialization fails.
            // Closing these pipes requests EOF; the lifecycle owner must still
            // observe exit before replacing this worker or claiming retirement.
            input.take();
            output.take();
        }
        Self {
            child,
            io: RefCell::new(WorkerIo {
                input,
                output,
                commands: VecDeque::new(),
                write_offset: 0,
                incoming: Vec::new(),
                replies: VecDeque::new(),
                read_ended: false,
                retiring: false,
                failure,
            }),
            policy_path,
            shutdown_deadline: None,
            kill_requested: false,
            exit_status: None,
        }
    }

    pub(crate) fn submit(&self, request: &Value) -> Result<(), &'static str> {
        let mut frame = serde_json::to_vec(request).map_err(|_| "invalid_worker_request")?;
        if frame.len() >= MAX_FRAME_BYTES {
            return Err("worker_request_too_large");
        }
        frame.push(b'\n');
        let mut io = self.io.borrow_mut();
        if io.retiring {
            return Err("worker_stopped");
        }
        io.pump()?;
        if io.commands.len() >= QUEUE_CAPACITY {
            return Err("worker_queue_full");
        }
        io.commands.push_back(frame);
        io.pump()
    }

    pub(crate) fn poll(&self) -> Result<Option<Value>, &'static str> {
        let mut io = self.io.borrow_mut();
        io.pump()?;
        if let Some(reply) = io.replies.pop_front() {
            return Ok(Some(reply));
        }
        if io.read_ended || io.retiring {
            Err("worker_stopped")
        } else {
            Ok(None)
        }
    }

    fn observe_exit(&mut self) -> Result<Option<ExitStatus>, &'static str> {
        if self.exit_status.is_none() {
            self.exit_status = self
                .child
                .try_wait()
                .map_err(|_| "worker_status_unavailable")?;
        }
        Ok(self.exit_status)
    }

    pub(crate) fn is_running(&mut self) -> Result<bool, &'static str> {
        self.observe_exit().map(|status| status.is_none())
    }

    pub(crate) fn prepare_shutdown(&mut self, deadline: Instant) {
        self.shutdown_deadline = Some(
            self.shutdown_deadline
                .map_or(deadline, |old| old.min(deadline)),
        );
    }

    #[cfg(test)]
    pub(crate) fn shutdown_deadline_for_test(&self) -> Option<Instant> {
        self.shutdown_deadline
    }

    pub(crate) fn quiesce(&mut self) -> Result<bool, &'static str> {
        let deadline = *self
            .shutdown_deadline
            .get_or_insert_with(|| Instant::now() + SHUTDOWN_TIMEOUT);
        self.io.get_mut().begin_retirement();
        let io_result = self.io.get_mut().pump();
        if let Some(status) = self.observe_exit()? {
            self.io.get_mut().output.take();
            if !status.success() {
                return Err("worker_exit_unsuccessful");
            }
            return match std::fs::symlink_metadata(&self.policy_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
                _ => Err("worker_policy_retirement_unverified"),
            };
        }
        // The exact Child handle was just observed running. An elapsed clock
        // alone or submission of a kill never proves process retirement.
        if Instant::now() >= deadline && !self.kill_requested {
            self.child.kill().map_err(|_| "worker_force_stop_failed")?;
            self.kill_requested = true;
        }
        io_result?;
        Ok(false)
    }

    #[cfg(test)]
    pub(crate) fn crash_for_test(&mut self) {
        if self.is_running() == Ok(true) {
            self.child.kill().unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.is_running() == Ok(true) {
            assert!(Instant::now() < deadline, "test child did not exit");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn set_nonblocking(fd: RawFd) -> Result<(), &'static str> {
    // SAFETY: the owned pipe remains live throughout both calls; fcntl changes
    // only its status flags and neither transfers ownership nor retains a pointer.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("proton_worker_pipe_unavailable");
    }
    Ok(())
}

impl Drop for ProtonWorker {
    fn drop(&mut self) {
        // The lifecycle owner retains this exact child until quiesce proves
        // retirement. Unexpected teardown can request EOF but must not block
        // DLL unload on a wait or detach module-owned bridge threads.
        let _ = self.quiesce();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{Duration, Instant};

    fn reply(worker: &ProtonWorker) -> Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(reply) = worker.poll().expect("worker alive") {
                return reply;
            }
            assert!(Instant::now() < deadline, "worker did not reply");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn embedded_worker_sets_and_retires_a_policy_in_a_disposable_root() {
        let root =
            std::env::temp_dir().join(format!("amaterasu-proton-worker-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let steam = root.join("steam");
        let tool = steam.join("steamapps/common/ProtonFixture");
        std::fs::create_dir_all(&tool).unwrap();
        std::fs::write(tool.join("proton"), b"fixture").unwrap();
        std::fs::write(
            tool.join("user_settings.sample.py"),
            b"user_settings = {}\n",
        )
        .unwrap();
        let mut worker =
            ProtonWorker::start(&root, "0123456789abcdef0123456789abcdef", &[vec![]]).unwrap();
        assert_eq!(reply(&worker)["state"], "ready");
        worker
            .submit(&json!({"id":10,"operation":"discover","roots":[steam]}))
            .unwrap();
        assert_eq!(reply(&worker)["tools"], json!([tool]));
        worker
            .submit(&json!({"id":11,"operation":"install","tool":tool}))
            .unwrap();
        assert_eq!(reply(&worker)["state"], "installed");
        assert!(tool.join("user_settings.py").is_file());
        let target = amaterasu_module_sdk::extension_api::LifecycleTarget::Session {
            host_epoch: "epoch".into(),
            session_id: "session-1".into(),
            generation: 1,
        };
        let mut ownership = crate::linux_ownership::Ownership::default();
        let admitted = ownership.prepare(&target, "transition-1").unwrap();
        worker
            .submit(&json!({"id":1,"operation":"set","session":admitted.session,
            "expected_revision":admitted.expected_revision,"revision":admitted.new_revision,
            "policy":policy_from_client_context()}))
            .unwrap();
        assert_eq!(reply(&worker)["state"], "stored");
        ownership.commit(admitted).unwrap();
        let state = root.join("amaterasu/frame-limiter/active.json");
        assert!(state.is_file());
        let content: Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
        assert_eq!(content["policies"][0]["limit_millihz"], 59940);
        let release = ownership.release(&target).unwrap().unwrap();
        worker
            .submit(
                &json!({"id":2,"operation":"remove","session":release.session,
            "expected_revision":release.expected_revision}),
            )
            .unwrap();
        assert_eq!(reply(&worker)["state"], "removed");
        ownership.commit(release).unwrap();
        ownership.finish_session(&target).unwrap();
        assert!(!state.exists());
        complete_retirement(&mut worker);
        drop(worker);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn temporary_root(label: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "amaterasu-proton-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        root
    }

    fn policy_worker(root: &Path) -> ProtonWorker {
        let worker =
            ProtonWorker::start(root, "0123456789abcdef0123456789abcdef", &[vec![]]).unwrap();
        assert_eq!(reply(&worker)["state"], "ready");
        worker
            .submit(&json!({"id":1,"operation":"set","session":"session",
                "expected_revision":null,"revision":"revision-1","policy":policy_from_client_context()}))
            .unwrap();
        assert_eq!(reply(&worker)["state"], "stored");
        worker
    }

    fn fixture_worker(root: &Path, source: &str) -> ProtonWorker {
        let child = Command::new("python3")
            .args(["-I", "-u", "-c", source])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        ProtonWorker::from_child(child, root.join("amaterasu/frame-limiter/active.json"))
    }

    fn complete_retirement(worker: &mut ProtonWorker) {
        let deadline = Instant::now() + Duration::from_secs(5);
        worker.prepare_shutdown(deadline);
        loop {
            if worker.quiesce().expect("cooperative retirement") {
                assert_eq!(worker.is_running(), Ok(false));
                return;
            }
            assert!(Instant::now() < deadline, "worker did not retire");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn wait_for_exit(worker: &mut ProtonWorker) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while worker.is_running() == Ok(true) {
            assert!(Instant::now() < deadline, "worker did not exit");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(worker.is_running(), Ok(false));
    }

    #[test]
    fn shutdown_preparation_preserves_policy_until_cooperative_eof_retires_it() {
        let root = temporary_root("eof-retirement");
        let mut worker = policy_worker(&root);
        let state = root.join("amaterasu/frame-limiter/active.json");
        worker.prepare_shutdown(Instant::now() + Duration::from_secs(5));
        assert_eq!(worker.is_running(), Ok(true));
        assert!(state.is_file(), "preparation must not end the live policy");
        complete_retirement(&mut worker);
        assert!(
            !state.exists(),
            "EOF retirement must remove the owned policy"
        );
        assert_eq!(worker.quiesce(), Ok(true));
        assert_eq!(
            worker.submit(&json!({"id":2,"operation":"close"})),
            Err("worker_stopped")
        );
        drop(worker);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn close_ack_and_kill_submission_never_prove_busy_worker_retirement() {
        let root = temporary_root("busy-retirement");
        let mut worker = fixture_worker(
            &root,
            "import time; print('{\"state\":\"closed\"}', flush=True); time.sleep(60)",
        );
        assert_eq!(reply(&worker)["state"], "closed");
        worker.prepare_shutdown(Instant::now() + Duration::from_millis(30));
        let first_deadline = worker.shutdown_deadline_for_test().unwrap();
        worker.prepare_shutdown(Instant::now() + Duration::from_secs(60));
        let started = Instant::now();
        assert_eq!(worker.quiesce(), Ok(false));
        assert!(started.elapsed() < Duration::from_millis(100));
        assert_eq!(worker.is_running(), Ok(true));
        std::thread::sleep(
            first_deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
        );
        assert_eq!(
            worker.quiesce(),
            Ok(false),
            "kill submission is not an exit receipt"
        );
        wait_for_exit(&mut worker);
        assert_eq!(worker.quiesce(), Err("worker_exit_unsuccessful"));
        drop(worker);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn successful_child_exit_without_policy_removal_remains_unverified() {
        let root = temporary_root("unverified-retirement");
        let directory = root.join("amaterasu/frame-limiter");
        std::fs::create_dir_all(&directory).unwrap();
        let state = directory.join("active.json");
        std::fs::write(&state, b"preserve unretired policy evidence").unwrap();
        let mut worker = fixture_worker(&root, "import sys; sys.stdin.buffer.read()");
        worker.prepare_shutdown(Instant::now() + Duration::from_secs(5));
        assert_eq!(worker.quiesce(), Ok(false));
        wait_for_exit(&mut worker);
        assert_eq!(worker.quiesce(), Err("worker_policy_retirement_unverified"));
        assert_eq!(
            std::fs::read(&state).unwrap(),
            b"preserve unretired policy evidence"
        );
        drop(worker);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_pipe_initialization_retains_the_exact_child_until_exit() {
        let root = temporary_root("failed-pipes");
        let child = Command::new("python3")
            .args(["-I", "-c", "import time; time.sleep(60)"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut worker = ProtonWorker::from_child(child, root.join("active.json"));
        assert_eq!(worker.poll(), Err("proton_worker_pipe_unavailable"));
        assert_eq!(worker.is_running(), Ok(true));
        worker.prepare_shutdown(Instant::now());
        assert_eq!(worker.quiesce(), Ok(false));
        wait_for_exit(&mut worker);
        assert_eq!(worker.quiesce(), Err("worker_exit_unsuccessful"));
        drop(worker);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn full_command_pipe_does_not_block_eof_or_target_another_child() {
        let root = temporary_root("backpressure-retirement");
        let mut worker = fixture_worker(&root, "import time; time.sleep(60)");
        let mut other = fixture_worker(&root, "import time; time.sleep(60)");
        let request = json!({"padding":"x".repeat(60_000)});
        for _ in 0..QUEUE_CAPACITY + 1 {
            if worker.submit(&request) == Err("worker_queue_full") {
                break;
            }
        }
        worker.prepare_shutdown(Instant::now());
        let started = Instant::now();
        assert_eq!(worker.quiesce(), Ok(false));
        assert!(started.elapsed() < Duration::from_millis(100));
        wait_for_exit(&mut worker);
        assert_eq!(worker.quiesce(), Err("worker_exit_unsuccessful"));
        assert_eq!(
            other.is_running(),
            Ok(true),
            "only the exact owned child may be killed"
        );
        other.prepare_shutdown(Instant::now());
        assert_eq!(other.quiesce(), Ok(false));
        wait_for_exit(&mut other);
        assert_eq!(other.quiesce(), Err("worker_exit_unsuccessful"));
        drop(worker);
        drop(other);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn policy_from_client_context() -> Value {
        use amaterasu_module_sdk::extension_api::{
            ClientContext, ClientDisplayMode, LifecycleTarget, ProviderContext, VideoMode,
        };
        let mut settings = amaterasu_configuration_schema::defaults(
            &crate::settings_descriptor::definitions(crate::Platform::Linux),
        )
        .unwrap();
        settings.insert("frame_limiter_enable".into(), json!(true));
        settings.insert("frame_limiter_provider".into(), json!("proton"));
        let context = ProviderContext {
            target: LifecycleTarget::Session {
                host_epoch: "epoch".into(),
                session_id: "session-1".into(),
                generation: 1,
            },
            application: json!({"kind":"desktop"}),
            requested_video: Some(VideoMode {
                width: 1920,
                height: 1080,
                refresh_millihz: 60000,
                hdr: false,
            }),
            client: Some(ClientContext {
                properties: None,
                client_ref: Some("client-1".into()),
                display_mode: Some(ClientDisplayMode {
                    width: 1920,
                    height: 1080,
                    refresh_millihz: 59940,
                }),
            }),
        };
        crate::lifecycle_policy::proton_policy(
            &serde_json::to_value(settings).unwrap(),
            &context,
            true,
        )
        .unwrap()
        .unwrap()
    }
}
