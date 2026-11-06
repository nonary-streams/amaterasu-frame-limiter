//! Small locked journal for NVIDIA driver leases, independent of SDK transport.
use super::lease::{State, validate};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const LIMIT: u64 = 2 * 1024 * 1024;
pub(super) struct Journal {
    path: PathBuf,
    _lock: File,
    previous: Option<Vec<u8>>,
}

impl Journal {
    pub(super) fn open(path: &Path) -> Result<(Self, State), &'static str> {
        let parent = path.parent().ok_or("nvcp_journal_path_invalid")?;
        std::fs::create_dir_all(parent).map_err(|_| "nvcp_journal_unavailable")?;
        let mut lock_options = OpenOptions::new();
        lock_options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false);
        no_follow(&mut lock_options);
        let lock = lock_options
            .open(path.with_extension("lock"))
            .map_err(|_| "nvcp_journal_unavailable")?;
        check_file(&lock)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => return Err("nvcp_journal_busy"),
            }
        }
        let previous = read(path)?;
        let state = if let Some(bytes) = &previous {
            serde_json::from_slice(bytes).map_err(|_| "nvcp_journal_invalid")?
        } else {
            State::default()
        };
        validate(&state)?;
        Ok((
            Self {
                path: path.into(),
                _lock: lock,
                previous,
            },
            state,
        ))
    }
    pub(super) fn save(&mut self, state: &State) -> Result<(), &'static str> {
        validate(state)?;
        let bytes = serde_json::to_vec(state).map_err(|_| "nvcp_journal_invalid")?;
        if bytes.len() as u64 > LIMIT {
            return Err("nvcp_journal_too_large");
        }
        if read(&self.path)? != self.previous {
            return Err("nvcp_journal_changed_externally");
        }
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| "nvcp_journal_unavailable")?;
        let temporary = self
            .path
            .with_extension(format!("tmp-{:032x}", u128::from_le_bytes(nonce)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| "nvcp_journal_unavailable")?;
        let result = (|| {
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "nvcp_journal_unavailable")?;
            if read(&self.path)? != self.previous {
                return Err("nvcp_journal_changed_externally");
            }
            // Close before replacement so Windows can rename the source file.
            drop(file);
            replace(&temporary, &self.path)?;
            #[cfg(unix)]
            File::open(self.path.parent().unwrap())
                .and_then(|parent| parent.sync_all())
                .map_err(|_| "nvcp_journal_unavailable")?;
            self.previous = Some(bytes);
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }
}

#[cfg(not(windows))]
fn replace(source: &Path, target: &Path) -> Result<(), &'static str> {
    std::fs::rename(source, target).map_err(|_| "nvcp_journal_unavailable")
}

#[cfg(windows)]
fn replace(source: &Path, target: &Path) -> Result<(), &'static str> {
    use std::os::windows::ffi::OsStrExt;
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let target: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both paths are terminated and owned until return. ReplaceExisting
    // plus WriteThrough publishes the flushed intent before a native driver save.
    if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), 0x1 | 0x8) } == 0 {
        Err("nvcp_journal_unavailable")
    } else {
        Ok(())
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn MoveFileExW(source: *const u16, target: *const u16, flags: u32) -> i32;
}

fn no_follow(options: &mut OpenOptions) {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        options.mode(0o600);
    }
}
fn check_file(file: &File) -> Result<(), &'static str> {
    let metadata = file.metadata().map_err(|_| "nvcp_journal_unavailable")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("nvcp_journal_path_invalid");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("nvcp_journal_path_invalid");
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
            return Err("nvcp_journal_path_invalid");
        }
    }
    Ok(())
}
pub(super) fn read(path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    let mut options = OpenOptions::new();
    options.read(true);
    no_follow(&mut options);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("nvcp_journal_unavailable"),
    };
    check_file(&file)?;
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "nvcp_journal_unavailable")?;
    if bytes.len() as u64 > LIMIT {
        return Err("nvcp_journal_too_large");
    }
    Ok(Some(bytes))
}
