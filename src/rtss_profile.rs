//! Exclusive profile initialization and compare-before-write transactions.
use crate::lease::{ProfileValues, ProviderError};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
#[cfg(all(windows, target_pointer_width = "64"))]
use std::path::Path;

const MAX_PROFILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone)]
struct ProfileValueSpan {
    range: Range<usize>,
    value: i32,
}

fn profile_value_spans(content: &[u8]) -> Result<[ProfileValueSpan; 3], ProviderError> {
    let mut spans: [Option<ProfileValueSpan>; 3] = [None, None, None];
    let mut framerate_section_seen = false;
    let mut in_framerate_section = false;
    let mut line_start = 0;

    while line_start < content.len() {
        let line_end = content[line_start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(content.len(), |offset| line_start + offset);
        let content_end = if line_end > line_start && content[line_end - 1] == b'\r' {
            line_end - 1
        } else {
            line_end
        };
        let mut visible_start = line_start;
        if line_start == 0 && content.starts_with(b"\xEF\xBB\xBF") {
            visible_start += 3;
        }
        let raw_line = &content[visible_start..content_end];
        let line_leading_space = raw_line
            .iter()
            .take_while(|byte| byte.is_ascii_whitespace())
            .count();
        let line_start_in_content = visible_start + line_leading_space;
        let line = trim_ascii(raw_line);

        if line.first() == Some(&b'[') && line.last() == Some(&b']') {
            let section = trim_ascii(&line[1..line.len() - 1]);
            in_framerate_section = section.eq_ignore_ascii_case(b"Framerate");
            if in_framerate_section {
                if framerate_section_seen {
                    return Err(profile_format_error());
                }
                framerate_section_seen = true;
            }
        } else if in_framerate_section
            && !line.is_empty()
            && !line.starts_with(b";")
            && !line.starts_with(b"#")
        {
            let Some(equals_offset) = line.iter().position(|byte| *byte == b'=') else {
                line_start = next_line_start(line_end, content.len());
                continue;
            };
            let key = trim_ascii(&line[..equals_offset]);
            let Some(index) = profile_key_index(key) else {
                line_start = next_line_start(line_end, content.len());
                continue;
            };
            if spans[index].is_some() {
                return Err(profile_format_error());
            }

            let value_start = line_start_in_content + equals_offset + 1;
            let raw_value = &content[value_start..content_end];
            let leading_space = raw_value
                .iter()
                .take_while(|byte| byte.is_ascii_whitespace())
                .count();
            let trimmed_value = trim_ascii(raw_value);
            let value_end = value_start + leading_space + trimmed_value.len();
            let value = std::str::from_utf8(trimmed_value)
                .ok()
                .and_then(|text| text.parse::<i32>().ok())
                .ok_or_else(profile_format_error)?;
            spans[index] = Some(ProfileValueSpan {
                range: value_start + leading_space..value_end,
                value,
            });
        }

        line_start = next_line_start(line_end, content.len());
    }

    if !framerate_section_seen {
        return Err(profile_format_error());
    }

    let Some(frame_limit) = spans[0].clone() else {
        return Err(profile_format_error());
    };
    let Some(frame_limit_denominator) = spans[1].clone() else {
        return Err(profile_format_error());
    };
    let Some(sync_limiter) = spans[2].clone() else {
        return Err(profile_format_error());
    };
    Ok([frame_limit, frame_limit_denominator, sync_limiter])
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn next_line_start(line_end: usize, content_len: usize) -> usize {
    if line_end < content_len {
        line_end + 1
    } else {
        content_len
    }
}

fn profile_key_index(key: &[u8]) -> Option<usize> {
    if key.eq_ignore_ascii_case(b"Limit") {
        Some(0)
    } else if key.eq_ignore_ascii_case(b"LimitDenominator") {
        Some(1)
    } else if key.eq_ignore_ascii_case(b"SyncLimiter") {
        Some(2)
    } else {
        None
    }
}

fn profile_format_error() -> ProviderError {
    ProviderError::ReadFailed("rtss_profile_values_unreadable")
}

fn profile_values(spans: &[ProfileValueSpan; 3]) -> ProfileValues {
    ProfileValues {
        frame_limit: spans[0].value,
        frame_limit_denominator: spans[1].value,
        sync_limiter: spans[2].value,
    }
}

fn profile_targets(values: ProfileValues) -> [i32; 3] {
    [
        values.frame_limit,
        values.frame_limit_denominator,
        values.sync_limiter,
    ]
}

fn replace_profile_values(
    content: &[u8],
    expected: ProfileValues,
    values: ProfileValues,
) -> Result<Vec<u8>, ProviderError> {
    let spans = profile_value_spans(content)?;
    let observed = profile_values(&spans);
    if observed != expected {
        return Err(ProviderError::ProfileMismatch {
            code: "rtss_profile_changed_before_write",
            observed,
        });
    }

    let mut replacements = Vec::with_capacity(spans.len());
    for (span, value) in spans.iter().zip(profile_targets(values)) {
        replacements.push((span.range.clone(), value.to_string().into_bytes()));
    }
    replacements.sort_by_key(|(range, _)| std::cmp::Reverse(range.start));

    let mut updated = content.to_vec();
    for (range, value) in replacements {
        updated.splice(range, value);
    }
    if updated.len() as u64 > MAX_PROFILE_BYTES {
        return Err(ProviderError::ReadFailed("rtss_profile_too_large"));
    }
    Ok(updated)
}

fn read_profile_file(file: &mut File) -> Result<Vec<u8>, ProviderError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ProviderError::ReadFailed("rtss_profile_read_failed"))?;
    let mut content = Vec::new();
    file.take(MAX_PROFILE_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(|_| ProviderError::ReadFailed("rtss_profile_read_failed"))?;
    if content.len() as u64 > MAX_PROFILE_BYTES {
        return Err(ProviderError::ReadFailed("rtss_profile_too_large"));
    }
    Ok(content)
}

fn write_profile_file(file: &mut File, content: &[u8]) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.write_all(content)?;
    file.set_len(content.len() as u64)?;
    file.flush()?;
    file.sync_all()
}

fn restore_profile_file(file: &mut File, original: &[u8]) -> std::io::Result<()> {
    write_profile_file(file, original)?;
    file.seek(SeekFrom::Start(0))?;
    let mut restored = Vec::with_capacity(original.len());
    file.read_to_end(&mut restored)?;
    if restored == original {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "RTSS profile rollback did not verify",
        ))
    }
}

fn update_locked_profile_file(
    file: &mut File,
    expected: ProfileValues,
    values: ProfileValues,
) -> Result<(), ProviderError> {
    let original = read_profile_file(file)?;
    let updated = replace_profile_values(&original, expected, values)?;
    if updated == original {
        return Ok(());
    }

    if write_profile_file(file, &updated).is_err() {
        if restore_profile_file(file, &original).is_err() {
            return Err(ProviderError::VerifyFailed(
                "rtss_profile_write_rollback_failed",
            ));
        }
        return Err(ProviderError::Unavailable("rtss_profile_write_failed"));
    }

    let written = match read_profile_file(file) {
        Ok(written) => written,
        Err(error) => {
            if restore_profile_file(file, &original).is_err() {
                return Err(ProviderError::VerifyFailed(
                    "rtss_profile_write_rollback_failed",
                ));
            }
            return Err(error);
        }
    };
    if written == updated {
        Ok(())
    } else if restore_profile_file(file, &original).is_err() {
        Err(ProviderError::VerifyFailed(
            "rtss_profile_write_rollback_failed",
        ))
    } else {
        Err(ProviderError::Unavailable("rtss_profile_write_failed"))
    }
}

fn initialize_new_profile_file(
    file: &mut File,
    values: ProfileValues,
) -> Result<(), ProviderError> {
    if file.metadata().map_err(|_| profile_format_error())?.len() != 0 {
        return Err(ProviderError::CreationConflict(
            "rtss_profile_already_exists",
        ));
    }
    let content = format!(
        "[Framerate]\r\nLimit={}\r\nLimitDenominator={}\r\nSyncLimiter={}\r\n",
        values.frame_limit, values.frame_limit_denominator, values.sync_limiter
    );
    write_profile_file(file, content.as_bytes())
        .map_err(|_| ProviderError::VerifyFailed("rtss_profile_initialization_failed"))?;
    if read_profile_file(file)? != content.as_bytes() {
        return Err(ProviderError::VerifyFailed(
            "rtss_profile_initialization_failed",
        ));
    }
    Ok(())
}

#[cfg(all(windows, target_pointer_width = "64"))]
pub(crate) fn create_profile_file_verified(
    path: &Path,
    values: ProfileValues,
) -> Result<(), ProviderError> {
    use std::os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::FromRawHandle,
    };
    let parent = path
        .parent()
        .ok_or(ProviderError::Unavailable("rtss_profile_directory_invalid"))?;
    // Pin the final directory against normal rename/delete while creating the file.
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(parent)
        .map_err(|_| ProviderError::Unavailable("rtss_profile_directory_unavailable"))?;
    let metadata = directory.metadata().map_err(|_| profile_format_error())?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProviderError::Unavailable("rtss_profile_directory_invalid"));
    }
    let path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: this UTF-16 path is terminated. CREATE_NEW never truncates an
    // existing file; sharing is denied until initialization and verification finish.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | DELETE_ACCESS,
            0,
            std::ptr::null_mut(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(80 | 183) => ProviderError::CreationConflict("rtss_profile_already_exists"),
            _ => ProviderError::Unavailable("rtss_profile_create_failed"),
        });
    }
    // SAFETY: CreateFileW transferred this new, exclusively shared handle to us.
    let mut file = unsafe { File::from_raw_handle(handle) };
    let result = initialize_new_profile_file(&mut file, values);
    if result.is_err() {
        let delete = true;
        // SAFETY: FILE_DISPOSITION_INFO contains one Windows BOOLEAN. This marks
        // only our still-open newly created file, so a replacement path is never deleted.
        let marked = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                4,
                (&delete as *const bool).cast(),
                std::mem::size_of::<bool>() as u32,
            )
        };
        if marked == 0 {
            return Err(ProviderError::VerifyFailed(
                "rtss_profile_create_cleanup_unconfirmed",
            ));
        }
    }
    result
}

#[cfg(all(windows, target_pointer_width = "64"))]
pub(crate) fn write_profile_file_verified(
    path: &Path,
    expected: ProfileValues,
    values: ProfileValues,
) -> Result<(), ProviderError> {
    let mut profile = LockedProfileFile::open(path)?;
    update_locked_profile_file(&mut profile.file, expected, values)
}

#[cfg(all(windows, target_pointer_width = "64"))]
struct LockedProfileFile {
    file: File,
    lock: Overlapped,
}

#[cfg(all(windows, target_pointer_width = "64"))]
impl LockedProfileFile {
    fn open(path: &Path) -> Result<Self, ProviderError> {
        use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};

        let path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // Deny write and delete sharing for the transaction. In particular,
        // refuse a preexisting writer rather than depend solely on byte-lock
        // enforcement (which differs in compatibility runtimes). Read-only
        // handles remain compatible; the byte lock also serializes their I/O.
        // SAFETY: `path` is NUL-terminated UTF-16 and the remaining pointers are
        // either null optional attributes or a null template handle, as allowed
        // for OPEN_EXISTING. A successful handle is owned below by `File`.
        let raw_file = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if raw_file == INVALID_HANDLE_VALUE {
            return Err(ProviderError::Unavailable("rtss_profile_lock_unavailable"));
        }

        // SAFETY: CreateFileW returned a valid owned handle, now transferred to
        // File so every early return closes it.
        let file = unsafe { File::from_raw_handle(raw_file) };
        let metadata = file
            .metadata()
            .map_err(|_| ProviderError::ReadFailed("rtss_profile_path_invalid"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(ProviderError::ReadFailed("rtss_profile_path_invalid"));
        }

        let mut lock = Overlapped::default();
        // Lock the full addressable byte range, including future extension.
        // SAFETY: `file` is a live handle for this regular disk file and `lock`
        // is a stable, zero-initialized OVERLAPPED record owned until unlock.
        // The nonblocking flag prevents a pending asynchronous lock operation.
        let locked = unsafe {
            LockFileEx(
                file.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut lock,
            )
        };
        if locked == 0 {
            return Err(ProviderError::Unavailable("rtss_profile_lock_unavailable"));
        }
        Ok(Self { file, lock })
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
impl Drop for LockedProfileFile {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;

        // SAFETY: the lock and its OVERLAPPED offset belong to this still-open
        // file handle and are released before File closes the handle.
        unsafe {
            UnlockFileEx(
                self.file.as_raw_handle(),
                0,
                u32::MAX,
                u32::MAX,
                &mut self.lock,
            );
        }
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[repr(C)]
#[derive(Default)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: *mut std::ffi::c_void,
}

#[cfg(all(windows, target_pointer_width = "64"))]
use std::os::windows::io::AsRawHandle;

#[cfg(all(windows, target_pointer_width = "64"))]
const GENERIC_READ: u32 = 0x8000_0000;
#[cfg(all(windows, target_pointer_width = "64"))]
const GENERIC_WRITE: u32 = 0x4000_0000;
#[cfg(all(windows, target_pointer_width = "64"))]
const DELETE_ACCESS: u32 = 0x0001_0000;
#[cfg(all(windows, target_pointer_width = "64"))]
const CREATE_NEW: u32 = 1;
#[cfg(all(windows, target_pointer_width = "64"))]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
#[cfg(all(windows, target_pointer_width = "64"))]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
#[cfg(all(windows, target_pointer_width = "64"))]
const FILE_SHARE_READ: u32 = 0x0000_0001;
#[cfg(all(windows, target_pointer_width = "64"))]
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
#[cfg(all(windows, target_pointer_width = "64", test))]
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
#[cfg(all(windows, target_pointer_width = "64"))]
const OPEN_EXISTING: u32 = 3;
#[cfg(all(windows, target_pointer_width = "64"))]
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
#[cfg(all(windows, target_pointer_width = "64"))]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(all(windows, target_pointer_width = "64"))]
const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
#[cfg(all(windows, target_pointer_width = "64"))]
const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
#[cfg(all(windows, target_pointer_width = "64"))]
const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1_isize as *mut std::ffi::c_void;

#[cfg(all(windows, target_pointer_width = "64"))]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetFileInformationByHandle(
        file: *mut std::ffi::c_void,
        class: i32,
        information: *const std::ffi::c_void,
        size: u32,
    ) -> i32;
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *mut std::ffi::c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    fn LockFileEx(
        file: *mut std::ffi::c_void,
        flags: u32,
        reserved: u32,
        bytes_to_lock_low: u32,
        bytes_to_lock_high: u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn UnlockFileEx(
        file: *mut std::ffi::c_void,
        reserved: u32,
        bytes_to_unlock_low: u32,
        bytes_to_unlock_high: u32,
        overlapped: *mut Overlapped,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::{initialize_new_profile_file, replace_profile_values, update_locked_profile_file};
    use crate::lease::{ProfileValues, ProviderError};
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);
    const ORIGINAL_VALUES: ProfileValues = ProfileValues {
        frame_limit: 60,
        frame_limit_denominator: 1,
        sync_limiter: 0,
    };
    const APPLIED_VALUES: ProfileValues = ProfileValues {
        frame_limit: 72,
        frame_limit_denominator: 1,
        sync_limiter: 2,
    };

    struct ProfileFixture {
        directory: PathBuf,
        file: Option<File>,
        path: PathBuf,
    }

    impl ProfileFixture {
        fn new(content: &[u8]) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "amaterasu-rtss-profile-test-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            let path = directory.join("game.exe.cfg");
            fs::write(&path, content).unwrap();
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            Self {
                directory,
                file: Some(file),
                path,
            }
        }

        fn file_mut(&mut self) -> &mut File {
            self.file.as_mut().unwrap()
        }

        fn contents(&mut self) -> Vec<u8> {
            if self.file.is_none() {
                return fs::read(&self.path).unwrap();
            }
            self.file_mut().seek(SeekFrom::Start(0)).unwrap();
            let mut content = Vec::new();
            self.file_mut().read_to_end(&mut content).unwrap();
            content
        }
    }

    impl Drop for ProfileFixture {
        fn drop(&mut self) {
            drop(self.file.take());
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    const PROFILE: &[u8] = b"; retain this comment\r\n[Framerate]\r\nLimit=60\r\nLimitDenominator=1\r\nSyncLimiter=0\r\n[Compatibility]\r\nApp=game.exe\r\n";

    #[test]
    fn initialization_writes_a_complete_default_and_never_overwrites_existing_content() {
        let mut fixture = ProfileFixture::new(b"");
        initialize_new_profile_file(fixture.file_mut(), crate::lease::DEFAULT_PROFILE).unwrap();
        assert_eq!(
            fixture.contents(),
            b"[Framerate]\r\nLimit=0\r\nLimitDenominator=1\r\nSyncLimiter=0\r\n"
        );
        let before = fixture.contents();
        assert!(matches!(
            initialize_new_profile_file(fixture.file_mut(), APPLIED_VALUES),
            Err(ProviderError::CreationConflict(_))
        ));
        assert_eq!(fixture.contents(), before);
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    #[test]
    fn create_new_refuses_a_racing_file_and_preserves_the_default_profile() {
        let fixture = ProfileFixture::new(b"");
        let path = fixture.directory.join("Global");
        super::create_profile_file_verified(&path, crate::lease::DEFAULT_PROFILE).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            super::create_profile_file_verified(&path, APPLIED_VALUES),
            Err(ProviderError::CreationConflict(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    #[test]
    fn guarded_windows_update_preserves_other_settings_and_refuses_stale_values() {
        let mut fixture = ProfileFixture::new(PROFILE);
        drop(fixture.file.take());
        super::write_profile_file_verified(&fixture.path, ORIGINAL_VALUES, APPLIED_VALUES).unwrap();
        let applied = fixture.contents();
        assert!(applied.ends_with(b"[Compatibility]\r\nApp=game.exe\r\n"));
        assert_eq!(
            super::write_profile_file_verified(&fixture.path, ORIGINAL_VALUES, ORIGINAL_VALUES),
            Err(ProviderError::ProfileMismatch {
                code: "rtss_profile_changed_before_write",
                observed: APPLIED_VALUES,
            })
        );
        assert_eq!(fixture.contents(), applied);
        super::write_profile_file_verified(&fixture.path, APPLIED_VALUES, ORIGINAL_VALUES).unwrap();
        assert_eq!(fixture.contents(), PROFILE);
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    #[test]
    fn guarded_windows_file_cannot_be_replaced_while_the_transaction_is_open() {
        let mut fixture = ProfileFixture::new(PROFILE);
        drop(fixture.file.take());
        let replacement = fixture.directory.join("replacement.cfg");
        fs::write(&replacement, b"foreign configuration").unwrap();
        let guard = super::LockedProfileFile::open(&fixture.path).unwrap();
        assert!(fs::rename(&replacement, &fixture.path).is_err());
        assert!(fs::remove_file(&fixture.path).is_err());
        drop(guard);
        assert_eq!(fixture.contents(), PROFILE);
        assert_eq!(fs::read(&replacement).unwrap(), b"foreign configuration");
    }

    #[test]
    fn verified_update_changes_only_rtss_framerate_values() {
        let mut fixture = ProfileFixture::new(PROFILE);
        update_locked_profile_file(fixture.file_mut(), ORIGINAL_VALUES, APPLIED_VALUES).unwrap();
        assert!(fixture.path.is_file());
        assert_eq!(
            fixture.contents(),
            b"; retain this comment\r\n[Framerate]\r\nLimit=72\r\nLimitDenominator=1\r\nSyncLimiter=2\r\n[Compatibility]\r\nApp=game.exe\r\n"
        );
    }

    #[test]
    fn verified_update_rejects_external_values_without_mutating_fixture() {
        let mut fixture =
            ProfileFixture::new(b"[Framerate]\nLimit=61\nLimitDenominator=1\nSyncLimiter=0\n");
        let before = fixture.contents();
        assert_eq!(
            update_locked_profile_file(fixture.file_mut(), ORIGINAL_VALUES, APPLIED_VALUES),
            Err(ProviderError::ProfileMismatch {
                code: "rtss_profile_changed_before_write",
                observed: ProfileValues {
                    frame_limit: 61,
                    frame_limit_denominator: 1,
                    sync_limiter: 0,
                },
            })
        );
        assert_eq!(fixture.contents(), before);
    }

    #[test]
    fn verified_update_rejects_ambiguous_or_incomplete_profile_without_mutating_fixture() {
        for content in [
            b"[Framerate]\nLimit=60\nLimit=72\nLimitDenominator=1\nSyncLimiter=0\n".as_slice(),
            b"[Framerate]\nLimit=60\nLimitDenominator=1\n".as_slice(),
            b"[Framerate]\nLimit=60x\nLimitDenominator=1\nSyncLimiter=0\n".as_slice(),
            b"[Framerate]\nLimit=60\nLimitDenominator=1\nSyncLimiter=0\n[Framerate]\nLimit=60\n"
                .as_slice(),
        ] {
            let mut fixture = ProfileFixture::new(content);
            let before = fixture.contents();
            assert!(matches!(
                update_locked_profile_file(fixture.file_mut(), ORIGINAL_VALUES, APPLIED_VALUES),
                Err(ProviderError::ReadFailed("rtss_profile_values_unreadable"))
            ));
            assert_eq!(fixture.contents(), before);
        }
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    #[test]
    fn write_guard_refuses_a_preexisting_writer_and_blocks_new_writers() {
        use super::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, LockedProfileFile};
        use std::os::windows::fs::OpenOptionsExt;

        let mut fixture = ProfileFixture::new(PROFILE);
        let external_writer = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&fixture.path)
            .unwrap();
        assert!(LockedProfileFile::open(&fixture.path).is_err());
        drop(external_writer);
        drop(fixture.file.take());
        let lock = LockedProfileFile::open(&fixture.path).unwrap();
        assert!(OpenOptions::new().write(true).open(&fixture.path).is_err());
        drop(lock);
        assert_eq!(fixture.contents(), PROFILE);
    }

    #[test]
    fn pure_transform_refuses_a_different_expected_snapshot() {
        assert_eq!(
            replace_profile_values(
                b"[Framerate]\nLimit=60\nLimitDenominator=1\nSyncLimiter=0\n",
                APPLIED_VALUES,
                ORIGINAL_VALUES,
            ),
            Err(ProviderError::ProfileMismatch {
                code: "rtss_profile_changed_before_write",
                observed: ORIGINAL_VALUES,
            })
        );
    }
}
