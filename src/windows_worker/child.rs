//! Native code executes only behind this plugin-owned process entrypoint.
use super::{Call, Config, Operation, Reply, Snapshot};
use crate::{
    lease::{LeaseManager, handle_runtime_operation},
    rtss::RtssProvider,
    windows_lifecycle::Backend,
};
use std::{
    cell::RefCell,
    io::{BufRead, Read, Write},
    rc::Rc,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

static CHILD: AtomicBool = AtomicBool::new(false);
static OPERATION: AtomicU64 = AtomicU64::new(0);

pub(crate) fn stage(stage: &str) {
    if CHILD.load(Ordering::Relaxed) {
        let _ = write(&Reply::Stage {
            id: OPERATION.load(Ordering::Relaxed),
            stage: stage.into(),
        });
    }
}

fn read<T: serde::de::DeserializeOwned>(
    input: &mut impl BufRead,
) -> Result<Option<T>, &'static str> {
    let mut bytes = Vec::new();
    let count = input
        .take((crate::native_worker_process::MAX_FRAME + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "native_worker_input_failed")?;
    if count == 0 {
        return Ok(None);
    }
    if bytes.len() > crate::native_worker_process::MAX_FRAME || bytes.last() != Some(&b'\n') {
        return Err("native_worker_input_too_large");
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| "native_worker_input_invalid")
}
fn write(reply: &Reply) -> Result<(), &'static str> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, reply).map_err(|_| "native_worker_output_failed")?;
    output
        .write_all(b"\n")
        .and_then(|_| output.flush())
        .map_err(|_| "native_worker_output_failed")
}
fn snapshot(backend: &Backend<RtssProvider>) -> Result<Snapshot, &'static str> {
    let (revision, targets) = backend.snapshot()?;
    Ok(Snapshot { revision, targets })
}

fn run() -> Result<(), &'static str> {
    let mut input = std::io::stdin().lock();
    let config: Config = read(&mut input)?.ok_or("native_worker_config_missing")?;
    if config.version != 1
        || !config.rtss_journal.is_absolute()
        || !config.nvcp_journal.is_absolute()
        || config.rtss_journal == config.nvcp_journal
    {
        return Err("native_worker_config_invalid");
    }
    let mut provider = RtssProvider::new();
    provider.disable_after_stall(config.disable_stalled_rtss);
    let mut leases = LeaseManager::open(provider, config.rtss_journal)?;
    leases.recover()?;
    let leases = Rc::new(RefCell::new(leases));
    let mut backend = Backend::configured_at(leases.clone(), &config.nvcp_journal)
        .map_err(|_| "native_worker_driver_recovery_failed")?;
    write(&Reply::Ready {
        snapshot: snapshot(&backend)?,
    })?;
    while let Some(call) = read::<Call>(&mut input)? {
        if call.id == 0 {
            return Err("native_worker_call_invalid");
        }
        OPERATION.store(call.id, Ordering::Relaxed);
        let value = match call.operation {
            Operation::Lifecycle { request, policy } => {
                serde_json::to_value(backend.begin(&request, policy))
                    .map_err(|_| "native_worker_output_failed")?
            }
            Operation::Legacy { caller, payload } => {
                let restoring =
                    payload.get("action").and_then(serde_json::Value::as_str) == Some("restore");
                let result = handle_runtime_operation(&caller, payload, &mut leases.borrow_mut());
                if restoring && let Err(error) = leases.borrow_mut().retire_provider_if_idle() {
                    return Err(error.diagnostic());
                }
                result
            }
            Operation::Ping => serde_json::json!({"ok":true}),
        };
        write(&Reply::Result {
            id: call.id,
            value,
            snapshot: snapshot(&backend)?,
        })?;
        OPERATION.store(0, Ordering::Relaxed);
    }
    Ok(())
}

/// Rundll32 calls this fixed WINAPI entrypoint with four arguments. The command
/// string is intentionally unused; all bounded input arrives on the private pipe.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn amaterasu_frame_limiter_worker(
    _window: *mut std::ffi::c_void,
    _instance: *mut std::ffi::c_void,
    _command: *mut u8,
    _show: i32,
) {
    CHILD.store(true, Ordering::Relaxed);
    if let Err(reason) = run() {
        let _ = write(&Reply::Fatal {
            reason: reason.into(),
        });
    }
}
