//! Polling transport: no parent thread can outlive the provider DLL.
#[path = "windows_worker/process_io.rs"]
mod process_io;
use serde_json::Value;
use std::{
    cell::RefCell,
    process::{Child, Command, Stdio},
};

pub(crate) const MAX_FRAME: usize = 256 * 1024;

pub(crate) struct Process {
    child: Child,
    io: RefCell<process_io::Transport>,
    exit: Option<std::process::ExitStatus>,
    #[cfg(windows)]
    _job: std::fs::File,
}

impl Process {
    pub(crate) fn spawn(mut command: Command) -> Result<Self, &'static str> {
        let (input, output, transport) = process_io::Transport::pipes()?;
        let child = command
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(output))
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "native_worker_spawn_failed")?;
        #[cfg(windows)]
        let job = match process_job(&child) {
            Ok(job) => job,
            Err(reason) => {
                let mut child = child;
                let _ = child.kill();
                let _ = child.try_wait();
                return Err(reason);
            }
        };
        Ok(Self {
            child,
            io: RefCell::new(transport),
            exit: None,
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
        self.io.borrow_mut().submit(bytes)
    }

    pub(crate) fn poll(&self) -> Result<Option<Value>, &'static str> {
        self.io.borrow_mut().poll()
    }

    pub(crate) fn is_running(&mut self) -> Result<bool, &'static str> {
        self.observe_exit()?;
        Ok(self.exit.is_none())
    }

    pub(crate) fn close_input(&self) {
        self.io.borrow_mut().close_input();
    }

    pub(crate) fn force_stop(&mut self) -> Result<(), &'static str> {
        #[cfg(windows)]
        return request_job_stop(&self._job);
        #[cfg(not(windows))]
        {
            if self.is_running()? {
                self.child.kill().map_err(|_| "native_worker_stop_failed")?;
            }
            Ok(())
        }
    }

    fn observe_exit(&mut self) -> Result<(), &'static str> {
        if self.exit.is_none() {
            self.exit = self
                .child
                .try_wait()
                .map_err(|_| "native_worker_status_failed")?;
        }
        Ok(())
    }

    /// A termination request is never exit proof, including for descendants.
    pub(crate) fn poll_exit(&mut self) -> Result<Option<bool>, &'static str> {
        self.observe_exit()?;
        let Some(status) = self.exit else {
            return Ok(None);
        };
        #[cfg(windows)]
        if !job_exited(&self._job)? {
            return Ok(None);
        }
        Ok(Some(status.success()))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // Last containment attempt only. Cooperative shutdown retains this
        // object until poll_exit proves retirement; Drop grants no new budget.
        let _ = self.force_stop();
        let _ = self.observe_exit();
    }
}

#[cfg(windows)]
fn request_job_stop(job: &std::fs::File) -> Result<(), &'static str> {
    use std::os::windows::io::AsRawHandle;
    // SAFETY: this unnamed job is owned by this Process, never a numeric PID.
    if unsafe { windows_sys::Win32::System::JobObjects::TerminateJobObject(job.as_raw_handle(), 0) }
        == 0
    {
        return Err("native_worker_tree_stop_failed");
    }
    Ok(())
}

#[cfg(windows)]
fn job_exited(job: &std::fs::File) -> Result<bool, &'static str> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::JobObjects::*;
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    // SAFETY: the owned job and full output structure are live for the call.
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
    Ok(accounting.ActiveProcesses == 0)
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
    use std::thread;
    use std::time::{Duration, Instant};
    #[test]
    fn cooperative_eof_drains_partial_frames_before_closing_input() {
        let mut command = Command::new("python3");
        command.args(["-I", "-u", "-c", "import json,sys\nrequest=json.loads(sys.stdin.readline())\nassert sys.stdin.read() == ''\nprint(json.dumps({'length':len(request['data'])}),flush=True)"]);
        let mut process = Process::spawn(command).unwrap();
        process
            .submit(&json!({"data":"x".repeat(MAX_FRAME / 2)}))
            .unwrap();
        process.close_input();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(value) = process.poll().unwrap() {
                assert_eq!(value["length"], MAX_FRAME / 2);
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
        while process.poll_exit().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
    }
    #[test]
    fn exited_worker_with_inherited_pipe_does_not_block_module_drop() {
        let mut command = Command::new("python3");
        command.args(["-I", "-u", "-c", "import subprocess,sys\nsubprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(1)'],stdin=subprocess.DEVNULL)\nprint('{}',flush=True)"]);
        let mut process = Process::spawn(command).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while process.is_running().unwrap() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
        let started = Instant::now();
        drop(process);
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "Drop joined an I/O thread waiting on a descendant's inherited pipe"
        );
    }
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
