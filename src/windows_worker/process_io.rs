//! Byte pipes polled on the module thread. No native I/O callback or Rust
//! thread remains inside the DLL after its owner is dropped.
use serde_json::Value;
use std::{
    collections::VecDeque,
    fs::File,
    io::{Read, Write},
};

pub(super) struct Transport {
    input: Option<File>,
    output: File,
    queued: VecDeque<Vec<u8>>,
    written: usize,
    incoming: Vec<u8>,
    closing: bool,
    eof: bool,
}

impl Transport {
    pub(super) fn pipes() -> Result<(File, File, Self), &'static str> {
        let (input, child_input) = pipe(false)?;
        let (output, child_output) = pipe(true)?;
        Ok((
            child_input,
            child_output,
            Self {
                input: Some(input),
                output,
                queued: VecDeque::new(),
                written: 0,
                incoming: Vec::new(),
                closing: false,
                eof: false,
            },
        ))
    }

    pub(super) fn submit(&mut self, bytes: Vec<u8>) -> Result<(), &'static str> {
        if self.closing {
            return Err("native_worker_stopped");
        }
        if self.queued.len() >= 32 {
            return Err("native_worker_busy");
        }
        self.queued.push_back(bytes);
        Ok(())
    }

    pub(super) fn close_input(&mut self) {
        self.closing = true;
    }

    pub(super) fn poll(&mut self) -> Result<Option<Value>, &'static str> {
        // At most one bounded write/read per poll. Partial frames retain their
        // offsets; EOF is sent only after complete accepted frames are written.
        if let Some(bytes) = self.queued.front() {
            match self
                .input
                .as_mut()
                .ok_or("native_worker_stopped")?
                .write(&bytes[self.written..])
            {
                Ok(count) => {
                    self.written += count;
                    if self.written == bytes.len() {
                        self.queued.pop_front();
                        self.written = 0;
                    }
                }
                Err(error) if would_block(&error) => (),
                Err(_) => return Err("native_worker_input_failed"),
            }
        }
        if self.closing && self.queued.is_empty() {
            self.input.take();
        }
        if !self.incoming.contains(&b'\n') && !self.eof {
            let mut bytes = [0_u8; 4096];
            match self.output.read(&mut bytes) {
                Ok(0) => self.eof = true,
                Ok(count) => self.incoming.extend_from_slice(&bytes[..count]),
                Err(error) if would_block(&error) => (),
                #[cfg(windows)]
                Err(error) if error.raw_os_error() == Some(109) => self.eof = true,
                Err(_) => return Err("native_worker_output_failed"),
            }
        }
        if let Some(end) = self.incoming.iter().position(|byte| *byte == b'\n') {
            if end >= super::MAX_FRAME {
                return Err("native_worker_invalid_reply");
            }
            let frame: Vec<_> = self.incoming.drain(..=end).collect();
            return serde_json::from_slice(&frame)
                .map(Some)
                .map_err(|_| "native_worker_invalid_reply");
        }
        if self.incoming.len() > super::MAX_FRAME || (self.eof && !self.incoming.is_empty()) {
            return Err("native_worker_invalid_reply");
        }
        if self.eof {
            return Err("native_worker_stopped");
        }
        Ok(None)
    }
}

fn would_block(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        || cfg!(windows) && error.raw_os_error() == Some(232) // ERROR_NO_DATA
}

#[cfg(not(windows))]
fn pipe(parent_reads: bool) -> Result<(File, File), &'static str> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let mut handles = [-1; 2];
    // SAFETY: pipe2 initializes both descriptors, which become owned Files.
    if unsafe { libc::pipe2(handles.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err("native_worker_pipe_failed");
    }
    let (read, write) = unsafe { (File::from_raw_fd(handles[0]), File::from_raw_fd(handles[1])) };
    let (parent, child) = if parent_reads {
        (read, write)
    } else {
        (write, read)
    };
    // SAFETY: only the parent's endpoint is changed; child I/O remains blocking.
    if unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        return Err("native_worker_pipe_failed");
    }
    Ok((parent, child))
}

#[cfg(windows)]
fn pipe(parent_reads: bool) -> Result<(File, File), &'static str> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, PIPE_ACCESS_INBOUND,
            PIPE_ACCESS_OUTBOUND,
        },
        System::Pipes::{CreateNamedPipeW, PIPE_NOWAIT, PIPE_REJECT_REMOTE_CLIENTS},
    };
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| "native_worker_pipe_failed")?;
    let name: Vec<_> = format!(
        "\\\\.\\pipe\\amaterasu-limiter-{:032x}",
        u128::from_le_bytes(nonce)
    )
    .encode_utf16()
    .chain(Some(0))
    .collect();
    // SAFETY: unique local byte pipe, no inherited server handle. PIPE_NOWAIT
    // makes synchronous ReadFile/WriteFile return immediately, including when
    // the native child is stuck. Byte writes may be partial and are retried.
    let raw = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            if parent_reads {
                PIPE_ACCESS_INBOUND
            } else {
                PIPE_ACCESS_OUTBOUND
            },
            PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            std::ptr::null(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err("native_worker_pipe_failed");
    }
    let parent = unsafe { File::from_raw_handle(raw) };
    // SAFETY: the private client endpoint is owned below and duplicated by
    // Command into the child's standard handles. Default client mode blocks.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            if parent_reads {
                GENERIC_WRITE
            } else {
                GENERIC_READ
            },
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err("native_worker_pipe_failed");
    }
    let child = unsafe { File::from_raw_handle(raw) };
    // CreateFile connects the sole client; no blocking ConnectNamedPipe call.
    Ok((parent, child))
}
