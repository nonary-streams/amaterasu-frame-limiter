//! RTSS profile inspection and guarded global or executable-profile updates.
use crate::lease::{FrameLimitProvider, ProfileValues, ProviderError};
#[cfg(all(windows, target_pointer_width = "64"))]
use crate::rtss_profile::{create_profile_file_verified, write_profile_file_verified};
#[cfg(all(windows, target_pointer_width = "64"))]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
#[cfg(all(windows, target_pointer_width = "64"))]
use std::path::{Path, PathBuf};

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
const LIMITER_DISABLED_FLAG: u32 = 1 << 2;
/// Internal profile identity; external compatibility requests still resolve an executable.
#[cfg(any(windows, test))]
pub(crate) const GLOBAL_PROFILE: &str = "@global";

pub(crate) struct RtssProvider {
    #[cfg(windows)]
    disabled_after_stall: bool,
    #[cfg(all(windows, target_pointer_width = "64"))]
    api: Option<WindowsRtssApi>,
    #[cfg(all(windows, target_pointer_width = "64"))]
    install_path: Option<PathBuf>,
    #[cfg(all(windows, target_pointer_width = "64"))]
    started: Option<crate::rtss_installation::StartedProcess>,
    #[cfg(not(all(windows, target_pointer_width = "64")))]
    _unsupported: (),
}

impl RtssProvider {
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(windows)]
            disabled_after_stall: false,
            #[cfg(all(windows, target_pointer_width = "64"))]
            api: None,
            #[cfg(all(windows, target_pointer_width = "64"))]
            install_path: None,
            #[cfg(all(windows, target_pointer_width = "64"))]
            started: None,
            #[cfg(not(all(windows, target_pointer_width = "64")))]
            _unsupported: (),
        }
    }
    #[cfg(windows)]
    pub(crate) fn disable_after_stall(&mut self, disabled: bool) {
        self.disabled_after_stall = disabled;
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn regular_profile_exists(path: &Path) -> Result<bool, ProviderError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        _ => Err(ProviderError::ReadFailed("rtss_profile_path_invalid")),
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
impl FrameLimitProvider for RtssProvider {
    fn select_installation(&mut self, path: &str) -> Result<String, ProviderError> {
        crate::windows_worker::child_stage("rtss");
        if self.disabled_after_stall {
            return Err(ProviderError::Unavailable("rtss_disabled_after_stall"));
        }
        let trusted = resolve_installation(path)?;
        let canonical = trusted.root.clone();
        let api = WindowsRtssApi::load(trusted)?;
        self.api = Some(api);
        self.install_path = Some(canonical.clone());
        Ok(canonical.to_string_lossy().into_owned())
    }

    fn prepare_installation(&mut self, path: &str) -> Result<String, ProviderError> {
        if self.disabled_after_stall || rtss_is_running()? {
            return self.select_installation(path);
        }
        crate::windows_worker::child_stage("rtss_startup");
        let trusted = crate::rtss_installation::Installation::discover(path)?;
        let root = trusted.root.clone();
        let mut process = trusted.start()?;
        process.wait_ready(|| rtss_is_running().unwrap_or(false))?;
        let result = self.select_installation(
            root.to_str()
                .ok_or(ProviderError::Unavailable("rtss_install_path_invalid"))?,
        );
        match result {
            Ok(path) => {
                self.started = Some(process);
                Ok(path)
            }
            Err(error) => {
                process.stop()?;
                Err(error)
            }
        }
    }

    fn retire_idle(&mut self) -> Result<(), ProviderError> {
        if let Some(started) = &mut self.started {
            crate::windows_worker::child_stage("rtss");
            self.api = None;
            started.stop()?;
            self.started = None;
        }
        Ok(())
    }

    fn profile_exists(&mut self, profile: &str) -> Result<bool, ProviderError> {
        validate_profile_name(profile)?;
        let path = self.profile_path(profile)?;
        regular_profile_exists(&path)
    }

    fn read_profile(&mut self, profile: &str) -> Result<ProfileValues, ProviderError> {
        crate::windows_worker::child_stage("rtss");
        validate_profile_name(profile)?;
        let api = self.api()?;
        api.load_profile(hooks_profile_name(profile)?)?;
        api.read_profile_values()
    }

    fn ensure_safe_writes_supported(&mut self) -> Result<(), ProviderError> {
        self.api()?;
        Ok(())
    }

    fn missing_profile_baseline(&mut self, profile: &str) -> Result<ProfileValues, ProviderError> {
        if profile != GLOBAL_PROFILE {
            return Err(ProviderError::Unavailable(
                "rtss_profile_missing_safe_create_unsupported",
            ));
        }
        self.api()?;
        Ok(crate::lease::DEFAULT_PROFILE)
    }

    fn create_profile_verified(
        &mut self,
        profile: &str,
        values: ProfileValues,
    ) -> Result<(), ProviderError> {
        crate::windows_worker::child_stage("rtss");
        if profile != GLOBAL_PROFILE || values != crate::lease::DEFAULT_PROFILE {
            return Err(ProviderError::Unavailable(
                "rtss_profile_missing_safe_create_unsupported",
            ));
        }
        let path = self.profile_path(profile)?;
        let directory = path
            .parent()
            .ok_or(ProviderError::Unavailable("rtss_profile_directory_invalid"))?;
        if !directory.exists() {
            match std::fs::create_dir(directory) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(_) => {
                    return Err(ProviderError::Unavailable(
                        "rtss_profile_directory_unavailable",
                    ));
                }
            }
        }
        create_profile_file_verified(&path, values)?;
        let api = self.api()?;
        api.load_profile("")?;
        api.update_profiles();
        api.load_profile("")?;
        if api.read_profile_values()? != values {
            return Err(ProviderError::VerifyFailed(
                "rtss_profile_initialization_failed",
            ));
        }
        Ok(())
    }

    fn write_profile_verified(
        &mut self,
        profile: &str,
        expected: ProfileValues,
        values: ProfileValues,
    ) -> Result<(), ProviderError> {
        crate::windows_worker::child_stage("rtss");
        validate_profile_name(profile)?;
        let path = self.profile_path(profile)?;
        // The locked file comparison is authoritative for writes. A Hooks
        // snapshot can lag a direct profile-file edit, so it must not be used
        // to accept or reject the expected file state.
        write_profile_file_verified(&path, expected, values)?;

        let current = {
            let api = self.api()?;
            // Match RTSS's disk-reload sequence: select the global profile,
            // publish all profiles, then inspect the executable profile.
            api.load_profile("")?;
            api.update_profiles();
            api.load_profile(hooks_profile_name(profile)?)?;
            api.read_profile_values()?
        };
        if current != values {
            return Err(ProviderError::VerifyFailed(
                "rtss_profile_write_verification_failed",
            ));
        }
        Ok(())
    }

    fn limiter_disabled(&mut self) -> Result<bool, ProviderError> {
        crate::windows_worker::child_stage("rtss");
        self.api()?.limiter_disabled()
    }

    fn ensure_limiter_flag_writes_supported(&mut self) -> Result<(), ProviderError> {
        self.api()?;
        Ok(())
    }

    fn set_limiter_disabled_verified(
        &mut self,
        expected: bool,
        desired: bool,
    ) -> Result<(), ProviderError> {
        let api = self.api()?;
        if api.limiter_disabled()? != expected {
            return Err(ProviderError::VerifyFailed("rtss_limiter_flag_changed"));
        }
        if expected != desired {
            let (and_mask, xor_mask) = limiter_flag_update(desired);
            // SAFETY: SetFlags is resolved from this live RTSSHooks64 module;
            // masks touch only the limiter-disable bit and preserve other flags.
            unsafe { (api.set_flags)(and_mask, xor_mask) };
        }
        if api.limiter_disabled()? != desired {
            return Err(ProviderError::VerifyFailed(
                "rtss_limiter_flag_verification_failed",
            ));
        }
        Ok(())
    }
}

#[cfg(all(windows, target_pointer_width = "32"))]
impl FrameLimitProvider for RtssProvider {
    fn select_installation(&mut self, _path: &str) -> Result<String, ProviderError> {
        Err(ProviderError::Unavailable("rtss_64_bit_windows_required"))
    }

    fn profile_exists(&mut self, _profile: &str) -> Result<bool, ProviderError> {
        Err(ProviderError::Unavailable("rtss_64_bit_windows_required"))
    }

    fn read_profile(&mut self, _profile: &str) -> Result<ProfileValues, ProviderError> {
        Err(ProviderError::Unavailable("rtss_64_bit_windows_required"))
    }

    fn ensure_safe_writes_supported(&mut self) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable("rtss_64_bit_windows_required"))
    }

    fn write_profile_verified(
        &mut self,
        _profile: &str,
        _expected: ProfileValues,
        _values: ProfileValues,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable("rtss_64_bit_windows_required"))
    }

    fn limiter_disabled(&mut self) -> Result<bool, ProviderError> {
        Err(ProviderError::Unavailable("rtss_64_bit_windows_required"))
    }
}

#[cfg(not(windows))]
impl FrameLimitProvider for RtssProvider {
    fn select_installation(&mut self, _path: &str) -> Result<String, ProviderError> {
        Err(ProviderError::Unavailable("rtss_supported_on_windows_only"))
    }

    fn profile_exists(&mut self, _profile: &str) -> Result<bool, ProviderError> {
        Err(ProviderError::Unavailable("rtss_supported_on_windows_only"))
    }

    fn read_profile(&mut self, _profile: &str) -> Result<ProfileValues, ProviderError> {
        Err(ProviderError::Unavailable("rtss_supported_on_windows_only"))
    }

    fn ensure_safe_writes_supported(&mut self) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable("rtss_supported_on_windows_only"))
    }

    fn write_profile_verified(
        &mut self,
        _profile: &str,
        _expected: ProfileValues,
        _values: ProfileValues,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable("rtss_supported_on_windows_only"))
    }

    fn limiter_disabled(&mut self) -> Result<bool, ProviderError> {
        Err(ProviderError::Unavailable("rtss_supported_on_windows_only"))
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
impl RtssProvider {
    fn api(&mut self) -> Result<&mut WindowsRtssApi, ProviderError> {
        let install_path = self
            .install_path
            .as_deref()
            .ok_or(ProviderError::Unavailable("rtss_install_path_required"))?;
        let active_install_path = discover_install_path()?;
        if active_install_path != install_path {
            self.api = None;
            return Err(ProviderError::Unavailable(
                "rtss_install_path_does_not_match_running_instance",
            ));
        }
        if self.api.is_none() {
            self.api = Some(WindowsRtssApi::load(
                crate::rtss_installation::Installation::open(install_path)?,
            )?);
        }
        self.api
            .as_mut()
            .ok_or(ProviderError::Unavailable("rtss_api_unavailable"))
    }

    fn profile_path(&self, profile: &str) -> Result<PathBuf, ProviderError> {
        let install_path = self
            .install_path
            .as_deref()
            .ok_or(ProviderError::Unavailable("rtss_install_path_required"))?;
        let profiles = install_path.join("Profiles");
        match std::fs::symlink_metadata(&profiles) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(profiles.join(profile_file_name(profile)?));
            }
            _ => return Err(ProviderError::ReadFailed("rtss_profile_directory_invalid")),
        }
        Ok(profiles.join(profile_file_name(profile)?))
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
const RTSS_SHARED_MEMORY_NAME: &str = "RTSSSharedMemoryV2";

#[cfg(all(windows, target_pointer_width = "64"))]
type GetProfileProperty = unsafe extern "system" fn(*const i8, *mut u8, u32) -> i32;
#[cfg(all(windows, target_pointer_width = "64"))]
type ProfileOperation = unsafe extern "system" fn(*const i8);
#[cfg(all(windows, target_pointer_width = "64"))]
type UpdateProfiles = unsafe extern "system" fn();
#[cfg(all(windows, target_pointer_width = "64"))]
type GetFlags = unsafe extern "system" fn() -> u32;
#[cfg(all(windows, target_pointer_width = "64"))]
type SetFlags = unsafe extern "system" fn(u32, u32) -> u32;

#[cfg(all(windows, target_pointer_width = "64"))]
struct WindowsRtssApi {
    _trusted: crate::rtss_installation::Installation,
    library: *mut std::ffi::c_void,
    get_profile_property: GetProfileProperty,
    load_profile: ProfileOperation,
    update_profiles: UpdateProfiles,
    get_flags: GetFlags,
    set_flags: SetFlags,
}

#[cfg(all(windows, target_pointer_width = "64"))]
impl WindowsRtssApi {
    fn load(trusted: crate::rtss_installation::Installation) -> Result<Self, ProviderError> {
        let install_path = &trusted.root;
        if !rtss_is_running()? {
            return Err(ProviderError::Unavailable("rtss_not_running"));
        }
        let dll_path = trusted.hooks_path().to_path_buf();
        let canonical_dll = std::fs::canonicalize(&dll_path)
            .map_err(|_| ProviderError::Unavailable("rtss_api_dll_not_found"))?;
        if canonical_dll.parent() != Some(install_path) {
            return Err(ProviderError::Unavailable(
                "rtss_api_dll_outside_install_path",
            ));
        }
        let wide_path: Vec<u16> = canonical_dll
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: the path is canonicalized beneath the configured RTSS install
        // directory. Search is limited to that DLL's directory and System32.
        let library = unsafe {
            LoadLibraryExW(
                wide_path.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if library.is_null() {
            return Err(ProviderError::Unavailable("rtss_api_load_failed"));
        }
        if let Err(error) = trusted.check_loaded(library) {
            // SAFETY: this failed load still owns its module handle.
            unsafe { FreeLibrary(library) };
            return Err(error);
        }

        // SAFETY: every symbol is resolved from the configured RTSSHooks DLL;
        // each pointer is converted only to its documented C ABI signature.
        let result = (|| unsafe {
            Ok(Self {
                _trusted: trusted,
                library,
                get_profile_property: resolve_symbol(library, b"GetProfileProperty\0")?,
                load_profile: resolve_symbol(library, b"LoadProfile\0")?,
                update_profiles: resolve_symbol(library, b"UpdateProfiles\0")?,
                get_flags: resolve_symbol(library, b"GetFlags\0")?,
                set_flags: resolve_symbol(library, b"SetFlags\0")?,
            })
        })();
        if result.is_err() {
            // SAFETY: library is a valid handle returned by LoadLibraryExW.
            unsafe { FreeLibrary(library) };
        }
        result
    }

    fn load_profile(&mut self, profile: &str) -> Result<(), ProviderError> {
        let profile = std::ffi::CString::new(profile)
            .map_err(|_| ProviderError::ReadFailed("rtss_profile_name_invalid"))?;
        // SAFETY: the profile name is a valid NUL-terminated ANSI string, and
        // the loaded module owns the resolved function pointer.
        unsafe { (self.load_profile)(profile.as_ptr()) };
        Ok(())
    }

    fn read_profile_values(&self) -> Result<ProfileValues, ProviderError> {
        Ok(ProfileValues {
            frame_limit: self.get_i32_property("FramerateLimit")?,
            frame_limit_denominator: self.get_i32_property("FramerateLimitDenominator")?,
            sync_limiter: self.get_i32_property("SyncLimiter")?,
        })
    }

    fn limiter_disabled(&self) -> Result<bool, ProviderError> {
        // SAFETY: GetFlags is a read-only RTSSHooks export with no arguments.
        let flags = unsafe { (self.get_flags)() };
        Ok(flags & LIMITER_DISABLED_FLAG != 0)
    }

    fn update_profiles(&self) {
        // SAFETY: this no-argument RTSSHooks export is resolved from the
        // configured installation and the library remains owned by `self`.
        unsafe { (self.update_profiles)() };
    }

    fn get_i32_property(&self, property: &str) -> Result<i32, ProviderError> {
        let property = std::ffi::CString::new(property)
            .map_err(|_| ProviderError::ReadFailed("rtss_property_name_invalid"))?;
        let mut value = 0_i32;
        // SAFETY: value is writable for exactly four bytes, and the property
        // string remains alive through the API call.
        let success = unsafe {
            (self.get_profile_property)(
                property.as_ptr(),
                (&mut value as *mut i32).cast(),
                std::mem::size_of::<i32>() as u32,
            )
        };
        if success == 0 {
            return Err(ProviderError::ReadFailed(
                "rtss_profile_property_unreadable",
            ));
        }
        Ok(value)
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
impl Drop for WindowsRtssApi {
    fn drop(&mut self) {
        if !self.library.is_null() {
            // SAFETY: this handle is owned by this struct and no function calls
            // are in flight while it is dropped on the single module thread.
            unsafe { FreeLibrary(self.library) };
        }
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn resolve_installation(
    path: &str,
) -> Result<crate::rtss_installation::Installation, ProviderError> {
    let active_install = discover_install_path()?;
    let trusted = if path.is_empty() {
        crate::rtss_installation::Installation::open(&active_install)?
    } else {
        crate::rtss_installation::Installation::discover(path)?
    };
    if active_install != trusted.root {
        return Err(ProviderError::Unavailable(
            "rtss_install_path_does_not_match_running_instance",
        ));
    }
    Ok(trusted)
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn discover_install_path() -> Result<PathBuf, ProviderError> {
    if !rtss_is_running()? {
        return Err(ProviderError::Unavailable("rtss_not_running"));
    }
    // An empty configured path means auto-detect the running RTSS image and
    // load only the sibling API DLL from that exact canonical installation.
    let session = process_session_id(std::process::id())?;
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(ProviderError::Unavailable("rtss_process_probe_failed"));
    }
    let result = (|| {
        let mut entry = ProcessEntry32W {
            dw_size: std::mem::size_of::<ProcessEntry32W>() as u32,
            ..ProcessEntry32W::default()
        };
        let mut found = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
        while found {
            let image_name = String::from_utf16_lossy(&entry.sz_exe_file);
            if is_rtss_process_name(image_name.trim_end_matches('\0'))
                && process_session_id(entry.th32_process_id).ok() == Some(session)
            {
                let process = unsafe {
                    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32_process_id)
                };
                if process.is_null() {
                    return Err(ProviderError::Unavailable("rtss_process_path_unavailable"));
                }
                let mut image_path = vec![0_u16; 32768];
                let mut length = image_path.len() as u32;
                // SAFETY: image_path is writable for `length` UTF-16 units; the
                // process handle is opened only for query access.
                let queried = unsafe {
                    QueryFullProcessImageNameW(process, 0, image_path.as_mut_ptr(), &mut length)
                };
                unsafe { CloseHandle(process) };
                if queried == 0 || length == 0 {
                    return Err(ProviderError::Unavailable("rtss_process_path_unavailable"));
                }
                image_path.truncate(length as usize);
                let image = PathBuf::from(std::ffi::OsString::from_wide(&image_path));
                if !image
                    .file_name()
                    .is_some_and(|name| is_rtss_process_name(&name.to_string_lossy()))
                {
                    return Err(ProviderError::Unavailable("rtss_process_path_invalid"));
                }
                let directory = image
                    .parent()
                    .ok_or(ProviderError::Unavailable("rtss_install_path_invalid"))?;
                return std::fs::canonicalize(directory)
                    .map_err(|_| ProviderError::Unavailable("rtss_install_path_not_found"));
            }
            found = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
        }
        Err(ProviderError::Unavailable("rtss_process_not_found"))
    })();
    unsafe { CloseHandle(snapshot) };
    result
}

#[cfg(all(windows, target_pointer_width = "64"))]
pub(super) fn process_session_id(pid: u32) -> Result<u32, ProviderError> {
    let mut session = 0;
    // SAFETY: only a process identifier is passed, and the fixed output is live.
    if unsafe { windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(pid, &mut session) }
        == 0
    {
        return Err(ProviderError::Unavailable(
            "rtss_process_session_unavailable",
        ));
    }
    Ok(session)
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn is_rtss_process_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("RTSS.exe") || name.eq_ignore_ascii_case("RTSS64.exe")
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
fn validate_profile_name(profile: &str) -> Result<(), ProviderError> {
    let safe = profile == GLOBAL_PROFILE
        || profile.ends_with(".exe")
            && profile.len() <= 255
            && profile
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if safe {
        Ok(())
    } else {
        Err(ProviderError::Unavailable("rtss_profile_name_unsupported"))
    }
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
fn profile_file_name(profile: &str) -> Result<String, ProviderError> {
    validate_profile_name(profile)?;
    Ok(if profile == GLOBAL_PROFILE {
        "Global".into()
    } else {
        format!("{profile}.cfg")
    })
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
fn hooks_profile_name(profile: &str) -> Result<&str, ProviderError> {
    validate_profile_name(profile)?;
    Ok(if profile == GLOBAL_PROFILE {
        ""
    } else {
        profile
    })
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
fn limiter_flag_update(disabled: bool) -> (u32, u32) {
    (
        !LIMITER_DISABLED_FLAG,
        if disabled { LIMITER_DISABLED_FLAG } else { 0 },
    )
}

#[cfg(test)]
mod profile_target_tests {
    use super::*;
    #[test]
    fn limiter_masks_preserve_every_unrelated_global_flag() {
        for flags in [0, u32::MAX, 0x12345678, 0x87654321] {
            for disabled in [false, true] {
                let (and_mask, xor_mask) = limiter_flag_update(disabled);
                let updated = (flags & and_mask) ^ xor_mask;
                assert_eq!(
                    updated & !LIMITER_DISABLED_FLAG,
                    flags & !LIMITER_DISABLED_FLAG
                );
                assert_eq!(updated & LIMITER_DISABLED_FLAG != 0, disabled);
            }
        }
    }
    #[test]
    fn global_target_uses_the_native_global_file_and_empty_hooks_name() {
        assert_eq!(profile_file_name(GLOBAL_PROFILE).unwrap(), "Global");
        assert_eq!(hooks_profile_name(GLOBAL_PROFILE).unwrap(), "");
        assert_eq!(profile_file_name("Game.exe").unwrap(), "Game.exe.cfg");
        assert_eq!(hooks_profile_name("Game.exe").unwrap(), "Game.exe");
        for invalid in ["", "Global", "../Global", "..\\Global", "@global.exe/other"] {
            assert!(profile_file_name(invalid).is_err());
            assert!(hooks_profile_name(invalid).is_err());
        }
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn rtss_is_running() -> Result<bool, ProviderError> {
    let name: Vec<u16> = RTSS_SHARED_MEMORY_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: the mapping name is a fixed, valid NUL-terminated string. The
    // handle is closed immediately and never mapped or modified.
    let handle = unsafe { OpenFileMappingW(FILE_MAP_READ, 0, name.as_ptr()) };
    if handle.is_null() {
        return Ok(false);
    }
    // SAFETY: this closes only the handle returned by OpenFileMappingW above.
    unsafe { CloseHandle(handle) };
    Ok(true)
}

#[cfg(all(windows, target_pointer_width = "64"))]
unsafe fn resolve_symbol<T: Copy>(
    library: *mut std::ffi::c_void,
    symbol_name: &[u8],
) -> Result<T, ProviderError> {
    // SAFETY: callers pass a live module handle and a NUL-terminated symbol name.
    let symbol = unsafe { GetProcAddress(library, symbol_name.as_ptr().cast()) };
    let Some(symbol) = symbol else {
        return Err(ProviderError::Unavailable("rtss_api_symbol_missing"));
    };
    // SAFETY: each call site requests the exact RTSS C ABI function signature.
    Ok(unsafe { std::mem::transmute_copy(&symbol) })
}

#[cfg(all(windows, target_pointer_width = "64"))]
const FILE_MAP_READ: u32 = 0x0004;
#[cfg(all(windows, target_pointer_width = "64"))]
const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
#[cfg(all(windows, target_pointer_width = "64"))]
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
#[cfg(all(windows, target_pointer_width = "64"))]
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
#[cfg(all(windows, target_pointer_width = "64"))]
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
#[cfg(all(windows, target_pointer_width = "64"))]
const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1_isize as *mut std::ffi::c_void;

#[cfg(all(windows, target_pointer_width = "64"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}

#[cfg(all(windows, target_pointer_width = "64"))]
impl Default for ProcessEntry32W {
    fn default() -> Self {
        Self {
            dw_size: 0,
            cnt_usage: 0,
            th32_process_id: 0,
            th32_default_heap_id: 0,
            th32_module_id: 0,
            cnt_threads: 0,
            th32_parent_process_id: 0,
            pc_pri_class_base: 0,
            dw_flags: 0,
            sz_exe_file: [0; 260],
        }
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(
        file_name: *const u16,
        file: *mut std::ffi::c_void,
        flags: u32,
    ) -> *mut std::ffi::c_void;
    fn GetProcAddress(
        module: *mut std::ffi::c_void,
        name: *const i8,
    ) -> Option<unsafe extern "system" fn()>;
    fn FreeLibrary(module: *mut std::ffi::c_void) -> i32;
    fn OpenFileMappingW(
        desired_access: u32,
        inherit_handle: i32,
        name: *const u16,
    ) -> *mut std::ffi::c_void;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> *mut std::ffi::c_void;
    fn Process32FirstW(snapshot: *mut std::ffi::c_void, entry: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snapshot: *mut std::ffi::c_void, entry: *mut ProcessEntry32W) -> i32;
    fn OpenProcess(
        desired_access: u32,
        inherit_handle: i32,
        process_id: u32,
    ) -> *mut std::ffi::c_void;
    fn QueryFullProcessImageNameW(
        process: *mut std::ffi::c_void,
        flags: u32,
        image_name: *mut u16,
        size: *mut u32,
    ) -> i32;
}
