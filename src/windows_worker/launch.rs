//! Launch the already selected plugin DLL in a disposable Windows process.
use std::os::windows::{ffi::OsStringExt, process::CommandExt};
use std::{path::PathBuf, process::Command};
use windows_sys::Win32::System::{
    LibraryLoader::{
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        GetModuleFileNameW, GetModuleHandleExW,
    },
    SystemInformation::GetSystemDirectoryW,
};

pub(super) fn command() -> Result<Command, &'static str> {
    let mut module = std::ptr::null_mut();
    // SAFETY: FROM_ADDRESS interprets this address inside our loaded DLL, not a
    // string. UNCHANGED_REFCOUNT borrows the host-owned module for this call.
    if unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            super::child::amaterasu_frame_limiter_worker as *const () as *const u16,
            &mut module,
        )
    } == 0
    {
        return Err("native_worker_module_unknown");
    }
    let mut path = vec![0_u16; 32768];
    // SAFETY: path is writable for the complete advertised UTF-16 capacity.
    let count =
        unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) } as usize;
    if count == 0 || count >= path.len() {
        return Err("native_worker_module_unknown");
    }
    let plugin = PathBuf::from(std::ffi::OsString::from_wide(&path[..count]));
    command_for(&plugin)
}

pub(super) fn command_for(plugin: &std::path::Path) -> Result<Command, &'static str> {
    if !plugin.is_absolute() || plugin.as_os_str().to_string_lossy().contains('"') {
        return Err("native_worker_module_unknown");
    }
    let mut path = vec![0_u16; 32768];
    // SAFETY: path is writable for the complete advertised UTF-16 capacity.
    let count = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
    if count == 0 || count >= path.len() {
        return Err("native_worker_system_directory_unknown");
    }
    let program = PathBuf::from(std::ffi::OsString::from_wide(&path[..count])).join("rundll32.exe");
    let mut command = Command::new(program);
    // Rundll32 requires the comma outside the quoted module filename. Windows
    // filenames cannot contain quotes; the exported symbol is a fixed constant.
    command
        .raw_arg(format!(
            "\"{}\",amaterasu_frame_limiter_worker",
            plugin.display()
        ))
        .creation_flags(0x0800_0000);
    Ok(command)
}
