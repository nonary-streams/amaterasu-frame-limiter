//! Bounded, nonblocking parent transport. Native work runs in another process;
//! process retirement precedes joining every thread that uses this module.
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread::{self, JoinHandle},
};

pub(crate) const MAX_FRAME: usize = 256 * 1024;
const QUEUE: usize = 32;

pub(crate) struct Process {
    child: Child,
    commands: Option<SyncSender<Vec<u8>>>,
    replies: Receiver<Result<Value, &'static str>>,
    stopped: Arc<AtomicBool>,
    writer: Option<JoinHandle<()>>,
    reader: Option<JoinHandle<()>>,
    #[cfg(windows)]
    _job: std::fs::File,
}

impl Process {
    pub(crate) fn spawn(mut command: Command) -> Result<Self, &'static str> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "native_worker_spawn_failed")?;
        #[cfg(windows)]
        let job = match process_job(&child) {
            Ok(job) => job,
            Err(reason) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(reason);
            }
        };
        let Some(mut input) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("native_worker_pipe_failed");
        };
        let Some(output) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("native_worker_pipe_failed");
        };
        let stopped = Arc::new(AtomicBool::new(false));
        let (commands, command_rx) = mpsc::sync_channel::<Vec<u8>>(QUEUE);
        let writer_stop = stopped.clone();
        let writer = thread::spawn(move || {
            while let Ok(bytes) = command_rx.recv() {
                if writer_stop.load(Ordering::Acquire)
                    || input.write_all(&bytes).and_then(|_| input.flush()).is_err()
                {
                    break;
                }
            }
        });
        let (reply_tx, replies) = mpsc::sync_channel(QUEUE);
        let reader_stop = stopped.clone();
        let reader = thread::spawn(move || {
            let mut output = BufReader::new(output);
            while !reader_stop.load(Ordering::Acquire) {
                let mut bytes = Vec::new();
                let read = output
                    .by_ref()
                    .take((MAX_FRAME + 1) as u64)
                    .read_until(b'\n', &mut bytes);
                if matches!(read, Ok(0)) {
                    break;
                }
                let reply = match read {
                    Ok(_) if bytes.len() <= MAX_FRAME && bytes.last() == Some(&b'\n') => {
                        serde_json::from_slice(&bytes).map_err(|_| "native_worker_invalid_reply")
                    }
                    _ => Err("native_worker_invalid_reply"),
                };
                let invalid = reply.is_err();
                if reply_tx.try_send(reply).is_err() || invalid {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            commands: Some(commands),
            replies,
            stopped,
            writer: Some(writer),
            reader: Some(reader),
            #[cfg(windows)]
            _job: job,
        })
    }

    pub(crate) fn submit(&self, request: &Value) -> Result<(), &'static str> {
        let mut bytes = serde_json::to_vec(request).map_err(|_| "native_worker_invalid_request")?;
        if bytes.len() >= MAX_FRAME {
            return Err("native_worker_request_too_large");
        }
        bytes.push(b'\n');
        match self
            .commands
            .as_ref()
            .ok_or("native_worker_stopped")?
            .try_send(bytes)
        {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err("native_worker_busy"),
            Err(TrySendError::Disconnected(_)) => Err("native_worker_stopped"),
        }
    }

    pub(crate) fn poll(&self) -> Result<Option<Value>, &'static str> {
        match self.replies.try_recv() {
            Ok(Ok(value)) => Ok(Some(value)),
            Ok(Err(reason)) => Err(reason),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err("native_worker_stopped"),
        }
    }

    pub(crate) fn is_running(&mut self) -> Result<bool, &'static str> {
        self.child
            .try_wait()
            .map(|status| status.is_none())
            .map_err(|_| "native_worker_status_failed")
    }

    #[cfg(windows)]
    pub(crate) fn retire(self) -> Result<(), &'static str> {
        let result = terminate_job(&self._job);
        drop(self);
        result
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        self.commands.take();
        #[cfg(windows)]
        let _ = terminate_job(&self._job);
        let _ = self.child.kill();
        let _ = self.child.wait();
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            // SAFETY: these handles identify only the I/O threads owned below.
            // Cancel a pipe operation if a descendant kept its other end open.
            for thread in [&self.writer, &self.reader].into_iter().flatten() {
                unsafe {
                    windows_sys::Win32::System::IO::CancelSynchronousIo(thread.as_raw_handle())
                };
            }
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[cfg(windows)]
pub(crate) fn terminate_job(job: &std::fs::File) -> Result<(), &'static str> {
    use std::{
        os::windows::io::AsRawHandle,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::System::JobObjects::*;
    // SAFETY: this plugin owns the unnamed job and all processes assigned to it.
    if unsafe { TerminateJobObject(job.as_raw_handle(), 0) } == 0 {
        return Err("native_worker_tree_stop_failed");
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: the SDK output structure and job handle remain live throughout this call.
        if unsafe {
            QueryInformationJobObject(
                job.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&accounting) as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err("native_worker_tree_stop_unconfirmed");
        }
        if accounting.ActiveProcesses == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("native_worker_tree_stop_unconfirmed");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(windows)]
fn process_job(child: &Child) -> Result<std::fs::File, &'static str> {
    use std::os::windows::io::AsRawHandle;
    job_for_handle(child.as_raw_handle(), true)
}

#[cfg(windows)]
pub(crate) fn job_for_handle(
    process: windows_sys::Win32::Foundation::HANDLE,
    allow_breakaway: bool,
) -> Result<std::fs::File, &'static str> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::System::JobObjects::*;
    // SAFETY: the job is unnamed and non-inheritable. Its handle is owned below.
    let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if raw.is_null() {
        return Err("native_worker_job_failed");
    }
    // SAFETY: CreateJobObjectW returned a new owned handle.
    let job = unsafe { std::fs::File::from_raw_handle(raw) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | if allow_breakaway {
            JOB_OBJECT_LIMIT_BREAKAWAY_OK
        } else {
            0
        };
    // SAFETY: the complete SDK structure and child process handles are live.
    if unsafe {
        SetInformationJobObject(
            raw,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of_val(&limits) as u32,
        )
    } == 0
        || unsafe { AssignProcessToJobObject(raw, process) } == 0
    {
        return Err("native_worker_job_failed");
    }
    Ok(job)
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{Duration, Instant};
    #[test]
    fn native_transport_bounds_frames_and_retires_a_stalled_process() {
        let mut command = Command::new("python3");
        command.args(["-I", "-u", "-c", "import json,sys,time\nprint(json.dumps({'ready':True}),flush=True)\nfor line in sys.stdin:\n request=json.loads(line)\n if request.get('hang'): time.sleep(60)\n else: print(json.dumps(request),flush=True)"]);
        let mut worker = Process::spawn(command).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while worker.poll().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
        worker.submit(&json!({"id":1})).unwrap();
        loop {
            if let Some(value) = worker.poll().unwrap() {
                assert_eq!(value, json!({"id":1}));
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(
            worker.submit(&json!("x".repeat(MAX_FRAME))),
            Err("native_worker_request_too_large")
        );
        worker.submit(&json!({"hang":true})).unwrap();
        assert!(worker.is_running().unwrap());
        let stopped = Instant::now();
        drop(worker);
        assert!(stopped.elapsed() < Duration::from_secs(2));
    }
}
