//! Bounded process bridge to the plugin-owned Proton policy worker.
//!
//! The worker's code is embedded in the module, so installation never depends
//! on a source checkout. A worker reports readiness separately from policy or
//! hook installation, and its EOF guard retires policy when the module exits.
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};

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

pub(crate) struct ProtonWorker {
    child: Child,
    commands: Option<SyncSender<Vec<u8>>>,
    replies: Receiver<Result<Value, &'static str>>,
    writer: Option<JoinHandle<()>>,
    reader: Option<JoinHandle<()>>,
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
        let mut child = Command::new("python3")
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
        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("proton_worker_pipe_unavailable");
        };
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("proton_worker_pipe_unavailable");
        };
        let (command_send, command_receive) = mpsc::sync_channel::<Vec<u8>>(QUEUE_CAPACITY);
        let (reply_send, reply_receive) = mpsc::sync_channel(QUEUE_CAPACITY);
        let writer = thread::spawn(move || {
            while let Ok(frame) = command_receive.recv() {
                if stdin.write_all(&frame).and_then(|_| stdin.flush()).is_err() {
                    break;
                }
            }
        });
        let reader = thread::spawn(move || {
            let mut input = BufReader::new(stdout);
            loop {
                let mut bytes = Vec::new();
                let result = input
                    .by_ref()
                    .take((MAX_FRAME_BYTES + 1) as u64)
                    .read_until(b'\n', &mut bytes);
                let reply = match result {
                    Ok(0) => break,
                    Ok(_) if bytes.len() <= MAX_FRAME_BYTES && bytes.last() == Some(&b'\n') => {
                        serde_json::from_slice(&bytes).map_err(|_| "invalid_worker_reply")
                    }
                    _ => Err("invalid_worker_reply"),
                };
                let invalid = reply.is_err();
                if reply_send.try_send(reply).is_err() || invalid {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            commands: Some(command_send),
            replies: reply_receive,
            writer: Some(writer),
            reader: Some(reader),
        })
    }

    pub(crate) fn submit(&self, request: &Value) -> Result<(), &'static str> {
        let mut frame = serde_json::to_vec(request).map_err(|_| "invalid_worker_request")?;
        if frame.len() >= MAX_FRAME_BYTES {
            return Err("worker_request_too_large");
        }
        frame.push(b'\n');
        match self
            .commands
            .as_ref()
            .ok_or("worker_stopped")?
            .try_send(frame)
        {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err("worker_queue_full"),
            Err(TrySendError::Disconnected(_)) => Err("worker_stopped"),
        }
    }

    pub(crate) fn poll(&self) -> Result<Option<Value>, &'static str> {
        match self.replies.try_recv() {
            Ok(Ok(reply)) => Ok(Some(reply)),
            Ok(Err(error)) => Err(error),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err("worker_stopped"),
        }
    }

    pub(crate) fn is_running(&mut self) -> Result<bool, &'static str> {
        self.child
            .try_wait()
            .map(|status| status.is_none())
            .map_err(|_| "worker_status_unavailable")
    }

    #[cfg(test)]
    pub(crate) fn crash_for_test(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

impl Drop for ProtonWorker {
    fn drop(&mut self) {
        self.commands.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
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
        let worker =
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
        drop(worker);
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
