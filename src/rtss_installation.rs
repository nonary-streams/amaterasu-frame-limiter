//! Resolve and pin the installed RTSS code before loading or starting it.
//! All trust decisions and process ownership stay in the limiter plugin.
use crate::lease::ProviderError;
use std::{
    fs::{File, OpenOptions},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{self, Authorization::*, Cryptography::*, WinTrust::*},
    Storage::FileSystem::*,
    System::{Com::CoTaskMemFree, LibraryLoader::GetModuleFileNameW, Threading::*},
    UI::{Shell::*, WindowsAndMessaging::*},
};

const MUTATE_FILE: u32 = 0x2 | 0x4 | 0x10 | 0x100 | 0x10000 | 0x40000 | 0x80000;
const MUTATE_DIRECTORY: u32 = MUTATE_FILE | 0x40;
const EXECUTABLES: [&str; 2] = ["RTSS.exe", "RTSS64.exe"];

fn failure(code: &'static str) -> ProviderError {
    ProviderError::Unavailable(code)
}

pub(crate) fn program_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for id in [
        FOLDERID_ProgramFilesX86,
        FOLDERID_ProgramFilesX64,
        FOLDERID_ProgramFiles,
    ] {
        let mut raw = std::ptr::null_mut();
        // SAFETY: the system allocates this terminated known-folder path.
        if unsafe { SHGetKnownFolderPath(&id, 0, std::ptr::null_mut(), &mut raw) } < 0
            || raw.is_null()
        {
            continue;
        }
        let mut length = 0;
        // SAFETY: known-folder paths are terminated UTF-16 strings.
        unsafe {
            while length < 32768 && *raw.add(length) != 0 {
                length += 1;
            }
        }
        let path = if length < 32768 {
            // SAFETY: length is the checked terminator offset within the allocation.
            Some(PathBuf::from(std::ffi::OsString::from_wide(unsafe {
                std::slice::from_raw_parts(raw, length)
            })))
        } else {
            None
        };
        // SAFETY: this is precisely the allocation returned by the shell API.
        unsafe {
            CoTaskMemFree(raw.cast());
        }
        if let Some(path) = path.and_then(|path| {
            no_reparse(&path).ok()?;
            std::fs::canonicalize(path).ok()
        }) && !roots.contains(&path)
        {
            roots.push(path);
        }
    }
    roots
}

fn no_reparse(path: &Path) -> Result<(), ProviderError> {
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|_| failure("rtss_install_path_not_found"))?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(failure("rtss_reparse_path_rejected"));
        }
    }
    Ok(())
}

fn below(path: &Path, root: &Path) -> bool {
    let path = plain_path(path);
    let root = plain_path(root);
    let path: Vec<_> = path.components().collect();
    let root: Vec<_> = root.components().collect();
    path.len() > root.len()
        && path
            .iter()
            .zip(&root)
            .all(|(left, right)| left.as_os_str().eq_ignore_ascii_case(right.as_os_str()))
}

fn plain_path(path: &Path) -> PathBuf {
    let wide: Vec<_> = path.as_os_str().encode_wide().collect();
    if wide.starts_with(&[92, 92, 63, 92]) {
        PathBuf::from(std::ffi::OsString::from_wide(&wide[4..]))
    } else {
        path.into()
    }
}

fn require_same_path(file: &File, expected: &Path) -> Result<(), ProviderError> {
    let mut path = vec![0_u16; 32768];
    // SAFETY: file is pinned and the output buffer remains writable for its stated length.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            0,
        )
    } as usize;
    if length == 0 || length >= path.len() {
        return Err(failure("rtss_pinned_path_unavailable"));
    }
    let actual = PathBuf::from(std::ffi::OsString::from_wide(&path[..length]));
    if !plain_path(&actual)
        .as_os_str()
        .eq_ignore_ascii_case(plain_path(expected).as_os_str())
    {
        return Err(failure("rtss_pinned_path_changed"));
    }
    Ok(())
}

fn trusted_root(path: &Path, roots: &[PathBuf]) -> Result<PathBuf, ProviderError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(failure("rtss_install_path_invalid"));
    }
    no_reparse(path)?;
    let canonical =
        std::fs::canonicalize(path).map_err(|_| failure("rtss_install_path_not_found"))?;
    if !roots
        .iter()
        .any(|root| below(path, root) && below(&canonical, root))
    {
        return Err(failure("rtss_install_path_not_trusted"));
    }
    Ok(canonical)
}

struct Token(File);
impl Token {
    fn user() -> Result<Self, ProviderError> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: output handle storage is live; the returned token is owned.
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                Security::TOKEN_QUERY | Security::TOKEN_DUPLICATE,
                &mut raw,
            )
        } == 0
        {
            return Err(failure("rtss_token_unavailable"));
        }
        // SAFETY: OpenProcessToken returned an owned handle, closed with File.
        let primary = unsafe { File::from_raw_handle(raw) };
        let mut elevation = 0_i32;
        let mut length = 0;
        // SAFETY: the fixed elevation buffer matches TOKEN_ELEVATION_TYPE.
        if unsafe {
            Security::GetTokenInformation(
                raw,
                Security::TokenElevationType,
                (&mut elevation as *mut i32).cast(),
                4,
                &mut length,
            )
        } == 0
        {
            return Err(failure("rtss_token_unavailable"));
        }
        let linked = if elevation == Security::TokenElevationTypeFull {
            let mut linked = Security::TOKEN_LINKED_TOKEN::default();
            // SAFETY: this fixed output matches TOKEN_LINKED_TOKEN; its handle is owned.
            if unsafe {
                Security::GetTokenInformation(
                    raw,
                    Security::TokenLinkedToken,
                    (&mut linked as *mut Security::TOKEN_LINKED_TOKEN).cast(),
                    std::mem::size_of_val(&linked) as u32,
                    &mut length,
                )
            } == 0
                || linked.LinkedToken.is_null()
            {
                return Err(failure("rtss_token_unavailable"));
            }
            // SAFETY: GetTokenInformation returned an owned linked token.
            Some(unsafe { File::from_raw_handle(linked.LinkedToken) })
        } else {
            None
        };
        let token = linked.as_ref().unwrap_or(&primary);
        let mut impersonation = std::ptr::null_mut();
        // SAFETY: AccessCheck needs an identification-level impersonation token.
        if unsafe {
            Security::DuplicateToken(
                token.as_raw_handle(),
                Security::SecurityIdentification,
                &mut impersonation,
            )
        } == 0
        {
            return Err(failure("rtss_token_unavailable"));
        }
        // SAFETY: DuplicateToken returned a newly owned handle.
        Ok(Self(unsafe { File::from_raw_handle(impersonation) }))
    }

    fn require_immutable(&self, file: &File, mask: u32) -> Result<(), ProviderError> {
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: the API allocates a self-relative descriptor for the live file handle.
        let result = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                Security::OWNER_SECURITY_INFORMATION
                    | Security::GROUP_SECURITY_INFORMATION
                    | Security::DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if result != ERROR_SUCCESS || descriptor.is_null() {
            if !descriptor.is_null() {
                // SAFETY: the security API may allocate before reporting failure.
                unsafe {
                    LocalFree(descriptor);
                }
            }
            return Err(failure("rtss_code_permissions_unavailable"));
        }
        let mapping = Security::GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        };
        let mut privileges = [0_u64; 128];
        let mut privilege_size = std::mem::size_of_val(&privileges) as u32;
        let mut granted = 0;
        let mut allowed = 0;
        // SAFETY: all buffers remain live; the aligned privilege buffer is bounded.
        let checked = unsafe {
            Security::AccessCheck(
                descriptor,
                self.0.as_raw_handle(),
                0x0200_0000,
                &mapping,
                privileges.as_mut_ptr().cast(),
                &mut privilege_size,
                &mut granted,
                &mut allowed,
            )
        };
        // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
        unsafe {
            LocalFree(descriptor);
        }
        if checked == 0 || allowed == 0 || granted & mask != 0 {
            return Err(failure("rtss_code_mutable_by_user"));
        }
        Ok(())
    }
}

struct Code {
    file: File,
    path: PathBuf,
    signer: [u8; 32],
}
impl Code {
    fn open(path: &Path, token: &Token) -> Result<Self, ProviderError> {
        no_reparse(path)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| failure("rtss_code_unavailable"))?;
        let metadata = file
            .metadata()
            .map_err(|_| failure("rtss_code_unavailable"))?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(failure("rtss_code_path_invalid"));
        }
        require_same_path(&file, path)?;
        token.require_immutable(&file, MUTATE_FILE)?;
        let signer = signature(&file, path)?;
        Ok(Self {
            file,
            path: path.into(),
            signer,
        })
    }
}

fn signature(file: &File, path: &Path) -> Result<[u8; 32], ProviderError> {
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: file.as_raw_handle(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut info },
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: the file, UTF-16 name and versioned structures stay live through verification and close.
    let status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    let result = (|| {
        if status != 0 {
            return Err(failure("rtss_signature_untrusted"));
        }
        // SAFETY: a successful verification owns this provider state until CLOSE below.
        let provider = unsafe { WTHelperProvDataFromStateData(data.hWVTStateData) };
        if provider.is_null() {
            return Err(failure("rtss_signer_unavailable"));
        }
        // SAFETY: the provider is valid and signer zero is the authenticated primary signer.
        let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
        if signer.is_null()
            || unsafe { (*signer).csCertChain == 0 || (*signer).pasCertChain.is_null() }
        {
            return Err(failure("rtss_signer_unavailable"));
        }
        // SAFETY: the checked first certificate is owned by the active trust state.
        let certificate = unsafe { (*(*signer).pasCertChain).pCert };
        let mut fingerprint = [0_u8; 32];
        let mut length = 32;
        if certificate.is_null()
            || unsafe {
                CertGetCertificateContextProperty(
                    certificate,
                    CERT_SHA256_HASH_PROP_ID,
                    fingerprint.as_mut_ptr().cast(),
                    &mut length,
                )
            } == 0
            || length != 32
        {
            return Err(failure("rtss_signer_unavailable"));
        }
        Ok(fingerprint)
    })();
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: release exactly the trust state created above, even on verification failure.
    unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
    }
    result
}

pub(crate) struct Installation {
    pub root: PathBuf,
    _directory: File,
    executable: Code,
    hooks: Code,
}
impl Installation {
    pub(crate) fn open(root: &Path) -> Result<Self, ProviderError> {
        let roots = program_roots();
        Self::open_below(root, &roots)
    }
    fn open_below(root: &Path, roots: &[PathBuf]) -> Result<Self, ProviderError> {
        let root = trusted_root(root, roots)?;
        let token = Token::user()?;
        let directory = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&root)
            .map_err(|_| failure("rtss_install_path_unavailable"))?;
        let metadata = directory
            .metadata()
            .map_err(|_| failure("rtss_install_path_unavailable"))?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(failure("rtss_reparse_path_rejected"));
        }
        require_same_path(&directory, &root)?;
        token.require_immutable(&directory, MUTATE_DIRECTORY)?;
        let executable = EXECUTABLES
            .iter()
            .find_map(|name| Code::open(&root.join(name), &token).ok())
            .ok_or(failure("rtss_executable_not_trusted"))?;
        let hooks = Code::open(&root.join("RTSSHooks64.dll"), &token)?;
        if executable.signer != hooks.signer {
            return Err(failure("rtss_signer_mismatch"));
        }
        Ok(Self {
            root,
            _directory: directory,
            executable,
            hooks,
        })
    }
    pub(crate) fn discover(configured: &str) -> Result<Self, ProviderError> {
        let roots = program_roots();
        if !configured.is_empty() {
            let path = Path::new(configured);
            if path.is_absolute() {
                return Self::open_below(path, &roots);
            }
            for root in &roots {
                if let Ok(installation) = Self::open_below(&root.join(path), &roots) {
                    return Ok(installation);
                }
            }
            return Err(failure("rtss_install_path_not_trusted"));
        }
        roots
            .iter()
            .find_map(|root| {
                Self::open_below(&root.join("RivaTuner Statistics Server"), &roots).ok()
            })
            .ok_or(failure("rtss_installation_unavailable"))
    }
    pub(crate) fn hooks_path(&self) -> &Path {
        &self.hooks.path
    }
    pub(crate) fn check_loaded(&self, module: HMODULE) -> Result<(), ProviderError> {
        let mut path = vec![0_u16; 32768];
        // SAFETY: module is the newly loaded hooks DLL, and path is a full writable buffer.
        let length =
            unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) } as usize;
        if length == 0 || length >= path.len() {
            return Err(failure("rtss_loaded_code_unavailable"));
        }
        let path = PathBuf::from(std::ffi::OsString::from_wide(&path[..length]));
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(path)
            .map_err(|_| failure("rtss_loaded_code_unavailable"))?;
        let mut expected = BY_HANDLE_FILE_INFORMATION::default();
        let mut actual = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: both handles are pinned files and the fixed metadata outputs are live.
        if unsafe { GetFileInformationByHandle(self.hooks.file.as_raw_handle(), &mut expected) }
            == 0
            || unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut actual) } == 0
            || (
                expected.dwVolumeSerialNumber,
                expected.nFileIndexHigh,
                expected.nFileIndexLow,
            ) != (
                actual.dwVolumeSerialNumber,
                actual.nFileIndexHigh,
                actual.nFileIndexLow,
            )
        {
            return Err(failure("rtss_loaded_code_mismatch"));
        }
        Ok(())
    }
    pub(crate) fn start(&self) -> Result<StartedProcess, ProviderError> {
        let application: Vec<u16> = self
            .executable
            .path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut command: Vec<u16> = format!("\"{}\"", self.executable.path.display())
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let directory: Vec<u16> = self.root.as_os_str().encode_wide().chain(Some(0)).collect();
        let startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESHOWWINDOW,
            wShowWindow: SW_HIDE as u16,
            ..Default::default()
        };
        let mut process = PROCESS_INFORMATION::default();
        // SAFETY: all strings and structures remain live; no handles are inherited.
        // The image and directory stay pinned by this verified installation.
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_NO_WINDOW | CREATE_SUSPENDED,
                std::ptr::null(),
                directory.as_ptr(),
                &startup,
                &mut process,
            )
        } == 0
        {
            return Err(failure("rtss_start_failed"));
        }
        // SAFETY: successful CreateProcess transfers both handles to this scope.
        let thread = unsafe { File::from_raw_handle(process.hThread) };
        let handle = unsafe { File::from_raw_handle(process.hProcess) };
        let mut child = StartedProcess {
            handle,
            pid: process.dwProcessId,
            job: None,
        };
        // Assign a private kill-on-close job before the image executes. This
        // retains ownership even when RTSS launches another process and exits.
        child.job = Some(
            crate::native_worker_process::job_for_handle(child.handle.as_raw_handle(), false)
                .map_err(|_| failure("rtss_process_job_failed"))?,
        );
        // SAFETY: this is the primary thread created suspended above.
        if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
            return Err(failure("rtss_resume_failed"));
        }
        drop(thread);
        Ok(child)
    }
}

pub(crate) struct StartedProcess {
    handle: File,
    pid: u32,
    job: Option<File>,
}
impl StartedProcess {
    fn running(&self) -> Result<bool, ProviderError> {
        let mut code = 0;
        // SAFETY: the owned process handle is live and the exit-code output is writable.
        if unsafe { GetExitCodeProcess(self.handle.as_raw_handle(), &mut code) } == 0 {
            return Err(failure("rtss_process_status_failed"));
        }
        Ok(code == 259)
    }
    pub(crate) fn wait_ready(
        &mut self,
        mut ready: impl FnMut() -> bool,
    ) -> Result<(), ProviderError> {
        // SAFETY: the owned child handle remains live throughout the bounded GUI wait.
        unsafe {
            WaitForInputIdle(self.handle.as_raw_handle(), 1000);
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if ready() {
                return Ok(());
            }
            if !self.running()? {
                return Err(failure("rtss_exited_before_ready"));
            }
            if Instant::now() >= deadline {
                return Err(failure("rtss_start_not_ready"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    pub(crate) fn stop(&mut self) -> Result<(), ProviderError> {
        if self.running()? {
            // SAFETY: callback posts only WM_CLOSE to windows of this exact live process.
            unsafe {
                EnumWindows(Some(close_window), self.pid as isize);
                WaitForSingleObject(self.handle.as_raw_handle(), 200);
            }
            if self.running()? && self.job.is_none() {
                // SAFETY: terminate only the process created and retained by this owner.
                if unsafe { TerminateProcess(self.handle.as_raw_handle(), 0) } == 0 {
                    return Err(failure("rtss_stop_failed"));
                }
            }
        }
        if let Some(job) = &self.job {
            crate::native_worker_process::terminate_job(job)
                .map_err(|_| failure("rtss_stop_unconfirmed"))?;
        }
        // SAFETY: the process handle remains owned during the bounded retirement wait.
        if unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 500) } != WAIT_OBJECT_0 {
            return Err(failure("rtss_stop_unconfirmed"));
        }
        Ok(())
    }
}
impl Drop for StartedProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

unsafe extern "system" fn close_window(window: HWND, context: LPARAM) -> i32 {
    let mut pid = 0;
    // SAFETY: window is supplied by EnumWindows and the PID output is live.
    unsafe {
        GetWindowThreadProcessId(window, &mut pid);
    }
    if pid == context as u32 {
        // SAFETY: no pointers are transferred; WM_CLOSE is asynchronous to the owned process.
        unsafe {
            PostMessageW(window, WM_CLOSE, 0, 0);
        }
    }
    1
}

#[cfg(test)]
mod tests;
