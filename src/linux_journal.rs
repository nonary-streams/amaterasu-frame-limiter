//! Plugin-private receipt and ownership persistence. The directory handle pins
//! every journal operation; no pathname from a request is used for storage.
use crate::linux_ownership::Ownership;
use amaterasu_module_sdk::extension_api::{LifecycleTarget, ProviderRequest, ProviderResponse};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::CStr,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

const MAX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RECEIPTS: usize = 288;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    pub target: LifecycleTarget,
    pub transition_id: String,
    pub operation_id: String,
    pub provider_sequence: u64,
    pub fingerprint: String,
    pub expected_response: ProviderResponse,
    pub response: Option<ProviderResponse>,
}

impl Receipt {
    pub(crate) fn new(
        request: &ProviderRequest,
        policy: &Option<Value>,
        expected_response: ProviderResponse,
    ) -> Self {
        Self {
            target: request.target.clone(),
            transition_id: request.transition_id.clone(),
            operation_id: request.operation_id.clone(),
            provider_sequence: request.provider_sequence,
            fingerprint: fingerprint(request, policy),
            expected_response,
            response: None,
        }
    }

    pub(crate) fn matches(&self, request: &ProviderRequest, policy: &Option<Value>) -> bool {
        self.fingerprint == fingerprint(request, policy)
    }

    pub(crate) fn is_cleanup(&self) -> bool {
        matches!(self.expected_response, ProviderResponse::Cleanup { .. })
    }
}

fn fingerprint(request: &ProviderRequest, policy: &Option<Value>) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(request, policy)).expect("serializable request"))
    )
}

pub(crate) fn receipt_id(request: &ProviderRequest) -> String {
    receipt_key(
        &request.transition_id,
        &request.operation_id,
        request.provider_sequence,
    )
}

fn receipt_key(transition: &str, operation: &str, sequence: u64) -> String {
    format!(
        "limiter-{:x}",
        Sha256::digest(
            serde_json::to_vec(&(transition, operation, sequence)).expect("serializable identity")
        )
    )
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    version: u32,
    pub owner_id: String,
    pub revision: u64,
    pub ownership: Ownership,
    pub worker_policies: BTreeMap<String, Value>,
    pub pending_policies: Option<BTreeMap<String, Value>>,
    pub receipts: BTreeMap<String, Receipt>,
    pub completed: VecDeque<String>,
}

impl State {
    pub(crate) fn uninitialized() -> Self {
        Self {
            version: 1,
            owner_id: String::new(),
            revision: 1,
            ownership: Ownership::default(),
            worker_policies: BTreeMap::new(),
            pending_policies: None,
            receipts: BTreeMap::new(),
            completed: VecDeque::new(),
        }
    }

    fn new() -> Result<Self, &'static str> {
        let mut id = [0_u8; 16];
        getrandom::fill(&mut id).map_err(|_| "journal_owner_id_unavailable")?;
        Ok(Self {
            version: 1,
            owner_id: format!("{:032x}", u128::from_le_bytes(id)),
            revision: 1,
            ownership: Ownership::default(),
            worker_policies: BTreeMap::new(),
            pending_policies: None,
            receipts: BTreeMap::new(),
            completed: VecDeque::new(),
        })
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1
            || self.revision == 0
            || self.owner_id.len() != 32
            || !self.owner_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.receipts.len() > MAX_RECEIPTS
            || self.worker_policies.len() > 32
            || self
                .pending_policies
                .as_ref()
                .is_some_and(|policies| policies.len() > 32)
            || self
                .receipts
                .values()
                .filter(|receipt| receipt.response.is_none())
                .count()
                > 32
            || self.completed.len() > 256
            || self.completed.iter().collect::<BTreeSet<_>>().len() != self.completed.len()
            || self.completed.iter().any(|id| {
                self.receipts
                    .get(id)
                    .is_none_or(|receipt| receipt.response.is_none())
            })
        {
            return Err("invalid_lifecycle_journal");
        }
        self.ownership.validate()?;
        for (id, receipt) in &self.receipts {
            if id
                != &receipt_key(
                    &receipt.transition_id,
                    &receipt.operation_id,
                    receipt.provider_sequence,
                )
                || receipt.transition_id.is_empty()
                || receipt.transition_id.len() > 128
                || receipt.operation_id.is_empty()
                || receipt.operation_id.len() > 128
                || receipt.fingerprint.len() != 64
                || !receipt
                    .fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || !matches!(
                    receipt.expected_response,
                    ProviderResponse::Prepared { .. } | ProviderResponse::Cleanup { .. }
                )
                || serde_json::to_vec(&receipt.expected_response)
                    .map_err(|_| "invalid_lifecycle_journal")?
                    .len()
                    > 12 * 1024
                || receipt.response.as_ref().is_some_and(|response| {
                    matches!(
                        response,
                        ProviderResponse::Pending { .. } | ProviderResponse::Planned { .. }
                    )
                })
                || receipt.response.as_ref().is_some_and(|response| {
                    serde_json::to_vec(response).map_or(true, |bytes| bytes.len() > 12 * 1024)
                })
            {
                return Err("invalid_lifecycle_journal");
            }
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self, id: &str, response: ProviderResponse) {
        self.receipts
            .get_mut(id)
            .expect("admitted receipt")
            .response = Some(response);
        if !self.completed.iter().any(|item| item == id) {
            self.completed.push_back(id.into());
        }
        while self.completed.len() > 256 {
            if let Some(oldest) = self.completed.pop_front() {
                self.receipts.remove(&oldest);
            }
        }
    }

    pub(crate) fn retire_after_worker_restart(&mut self) -> Result<(), &'static str> {
        self.ownership.retire_after_worker_restart()?;
        self.worker_policies.clear();
        self.pending_policies = None;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or("provider_revision_exhausted")?;
        let pending: Vec<_> = self
            .receipts
            .iter()
            .filter(|(_, receipt)| receipt.response.is_none())
            .map(|(id, _)| id.clone())
            .collect();
        for receipt in self.receipts.values_mut() {
            if receipt.response.is_none() {
                self.ownership.remember_retired_target(&receipt.target)?;
            }
            let response = match &receipt.response {
                Some(ProviderResponse::Rejected { .. })
                | Some(ProviderResponse::Cleanup { .. }) => receipt.response.clone().unwrap(),
                _ if receipt.is_cleanup() => receipt.expected_response.clone(),
                _ => ProviderResponse::RecoveryRequired {
                    reason: "policy_retired_after_restart".into(),
                },
            };
            receipt.response = Some(response);
        }
        for id in pending {
            let response = self.receipts[&id]
                .response
                .clone()
                .expect("retired response");
            self.finish(&id, response);
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
struct Identity(u64, u64, u64, i64, i64, i64, i64);

fn identity(file: &File) -> Result<Identity, &'static str> {
    let info = file.metadata().map_err(|_| "journal_unavailable")?;
    // SAFETY: getuid has no arguments or pointer lifetimes.
    if !info.is_file()
        || info.uid() != unsafe { libc::getuid() }
        || info.nlink() != 1
        || info.mode() & 0o022 != 0
    {
        return Err("journal_not_private");
    }
    Ok(Identity(
        info.dev(),
        info.ino(),
        info.len(),
        info.mtime(),
        info.mtime_nsec(),
        info.ctime(),
        info.ctime_nsec(),
    ))
}

pub(crate) struct Journal {
    directory: File,
    _lock: File,
    current: Option<Identity>,
}

impl Journal {
    /// Keep lifecycle revisions and ownership across login sessions and reboots.
    /// The worker's sockets and transient policy files still use the runtime
    /// directory. Import its old journal only on the first persistent open,
    /// holding both journal locks throughout the copy.
    pub(crate) fn open_persistent(
        root: &Path,
        legacy_root: Option<&Path>,
    ) -> Result<(Self, State, bool), &'static str> {
        use std::os::unix::fs::DirBuilderExt;
        if !root.is_absolute() {
            return Err("state_directory_unavailable");
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)
            .map_err(|_| "state_directory_unavailable")?;
        let destination = root.join("amaterasu/frame-limiter/lifecycle.json");
        let legacy = legacy_root.filter(|legacy| *legacy != root);
        let imported = if destination
            .try_exists()
            .map_err(|_| "journal_unavailable")?
        {
            None
        } else if let Some(legacy) = legacy
            && legacy
                .join("amaterasu/frame-limiter/lifecycle.json")
                .try_exists()
                .map_err(|_| "journal_unavailable")?
        {
            Some(Self::open(legacy)?)
        } else {
            None
        };
        if let Some((_legacy_lock, imported, _recovering)) = imported {
            return Self::open_seeded(root, Some(imported));
        }
        Self::open(root)
    }

    pub(crate) fn open(root: &Path) -> Result<(Self, State, bool), &'static str> {
        Self::open_seeded(root, None)
    }

    fn open_seeded(root: &Path, seed: Option<State>) -> Result<(Self, State, bool), &'static str> {
        use std::os::unix::fs::OpenOptionsExt;
        if !root.is_absolute() {
            return Err("runtime_directory_unavailable");
        }
        let mut directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root)
            .map_err(|_| "runtime_directory_unavailable")?;
        check_directory(&directory)?;
        for part in [c"amaterasu", c"frame-limiter"] {
            // SAFETY: directory is live; part is a fixed single-component C string.
            let created = unsafe { libc::mkdirat(directory.as_raw_fd(), part.as_ptr(), 0o700) };
            if created != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
            {
                return Err("journal_directory_unavailable");
            }
            directory = open_at(&directory, part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            check_directory(&directory)?;
        }
        let lock = open_at(
            &directory,
            c"lifecycle.lock",
            libc::O_RDWR | libc::O_CREAT,
            0o600,
        )?;
        identity(&lock)?;
        // A concurrently forked child can briefly retain this CLOEXEC file
        // description until exec, even after the old module closes its copy.
        // Allow that bounded retirement window without ever breaking a lock.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => return Err("lifecycle_owner_already_active"),
            }
        }
        let mut journal = Self {
            directory,
            _lock: lock,
            current: None,
        };
        match journal.read()? {
            Some((file, bytes)) => {
                let state: State =
                    serde_json::from_slice(&bytes).map_err(|_| "invalid_lifecycle_journal")?;
                state.validate()?;
                journal.current = Some(identity(&file)?);
                let recovery = !state.receipts.is_empty()
                    || !state.worker_policies.is_empty()
                    || state.pending_policies.is_some();
                Ok((journal, state, recovery))
            }
            None => {
                let state = match seed {
                    Some(state) => state,
                    None => State::new()?,
                };
                let recovering = !state.receipts.is_empty()
                    || !state.worker_policies.is_empty()
                    || state.pending_policies.is_some();
                journal.save(&state)?;
                Ok((journal, state, recovering))
            }
        }
    }

    fn read(&self) -> Result<Option<(File, Vec<u8>)>, &'static str> {
        let file = match open_at(
            &self.directory,
            c"lifecycle.json",
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => file,
            Err("journal_file_missing") => return Ok(None),
            Err(error) => return Err(error),
        };
        let info = identity(&file)?;
        if info.2 > MAX_BYTES {
            return Err("lifecycle_journal_too_large");
        }
        let mut content = Vec::new();
        (&file)
            .take(MAX_BYTES + 1)
            .read_to_end(&mut content)
            .map_err(|_| "journal_unavailable")?;
        if content.len() as u64 > MAX_BYTES {
            return Err("lifecycle_journal_too_large");
        }
        Ok(Some((file, content)))
    }

    fn check_unchanged(&self) -> Result<(), &'static str> {
        let current = self.read()?.map(|(file, _)| identity(&file)).transpose()?;
        if current != self.current {
            return Err("lifecycle_journal_changed_externally");
        }
        Ok(())
    }

    pub(crate) fn save(&mut self, state: &State) -> Result<(), &'static str> {
        state.validate()?;
        let content = serde_json::to_vec(state).map_err(|_| "invalid_lifecycle_journal")?;
        if content.len() as u64 > MAX_BYTES {
            return Err("lifecycle_journal_too_large");
        }
        self.check_unchanged()?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| "journal_unavailable")?;
        let name =
            std::ffi::CString::new(format!(".lifecycle-{:032x}", u128::from_le_bytes(nonce)))
                .expect("hex name");
        let mut file = open_at(
            &self.directory,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let result = (|| {
            file.write_all(&content)
                .and_then(|_| file.sync_all())
                .map_err(|_| "journal_unavailable")?;
            self.check_unchanged()?;
            // SAFETY: both names are fixed or random single components within our pinned directory.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    self.directory.as_raw_fd(),
                    c"lifecycle.json".as_ptr(),
                )
            } != 0
            {
                return Err("journal_unavailable");
            }
            self.directory
                .sync_all()
                .map_err(|_| "journal_unavailable")?;
            self.current = Some(identity(&file)?);
            Ok(())
        })();
        if result.is_err() {
            // SAFETY: remove only this call's random temporary name within the pinned directory.
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
        }
        result
    }
}

fn check_directory(directory: &File) -> Result<(), &'static str> {
    let metadata = directory
        .metadata()
        .map_err(|_| "journal_directory_unavailable")?;
    // SAFETY: getuid has no arguments or pointer lifetimes.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err("journal_directory_not_private");
    }
    Ok(())
}

fn open_at(
    directory: &File,
    name: &CStr,
    flags: i32,
    mode: libc::mode_t,
) -> Result<File, &'static str> {
    // SAFETY: directory is live, name is NUL-terminated, and mode is supplied for O_CREAT.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                "journal_file_missing"
            } else {
                "journal_unavailable"
            },
        );
    }
    // SAFETY: openat returned a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};

    #[test]
    fn persistent_journal_survives_runtime_directory_loss() {
        let runtime = Fixture::new();
        let persistent = Fixture::new();
        let (mut legacy, mut state, _) = Journal::open(&runtime.0).unwrap();
        state.revision = 197;
        legacy.save(&state).unwrap();
        let owner = state.owner_id.clone();
        drop(legacy);

        let (journal, state, _) =
            Journal::open_persistent(&persistent.0, Some(&runtime.0)).unwrap();
        assert_eq!(state.revision, 197);
        assert_eq!(state.owner_id, owner);
        drop(journal);
        std::fs::remove_dir_all(runtime.0.join("amaterasu")).unwrap();

        // A reboot creates a fresh runtime directory and a revision-1 journal.
        let (legacy, _, _) = Journal::open(&runtime.0).unwrap();
        drop(legacy);
        let (_, state, _) = Journal::open_persistent(&persistent.0, Some(&runtime.0)).unwrap();
        assert_eq!(state.revision, 197);
        assert_eq!(state.owner_id, owner);
    }

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let mut nonce = [0_u8; 16];
            getrandom::fill(&mut nonce).unwrap();
            let path = std::env::temp_dir().join(format!(
                "limiter-journal-{:032x}",
                u128::from_le_bytes(nonce)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
        fn journal(&self) -> std::path::PathBuf {
            self.0.join("amaterasu/frame-limiter/lifecycle.json")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn journal_round_trip_preserves_owner_and_refuses_external_replacement() {
        let fixture = Fixture::new();
        let (mut journal, mut state, recovered) = Journal::open(&fixture.0).unwrap();
        assert!(!recovered);
        state.revision = 42;
        journal.save(&state).unwrap();
        let owner = state.owner_id.clone();
        drop(journal);
        let (mut journal, loaded, recovered) = Journal::open(&fixture.0).unwrap();
        assert!(
            !recovered,
            "an unused plugin does not need to start a worker"
        );
        assert_eq!(loaded.owner_id, owner);
        assert_eq!(loaded.revision, 42);
        let replacement = fixture.0.join("replacement.json");
        std::fs::write(&replacement, b"external configuration").unwrap();
        std::fs::rename(&replacement, fixture.journal()).unwrap();
        assert_eq!(
            journal.save(&loaded),
            Err("lifecycle_journal_changed_externally")
        );
        assert_eq!(
            std::fs::read(fixture.journal()).unwrap(),
            b"external configuration"
        );
    }

    #[test]
    fn journal_refuses_symlinks_hardlinks_and_writable_shared_state() {
        let fixture = Fixture::new();
        let (journal, _, _) = Journal::open(&fixture.0).unwrap();
        drop(journal);
        let original = fixture.0.join("original.json");
        std::fs::rename(fixture.journal(), &original).unwrap();
        symlink(&original, fixture.journal()).unwrap();
        assert!(Journal::open(&fixture.0).is_err());
        std::fs::remove_file(fixture.journal()).unwrap();
        std::fs::hard_link(&original, fixture.journal()).unwrap();
        assert!(Journal::open(&fixture.0).is_err());
        std::fs::remove_file(fixture.journal()).unwrap();
        std::fs::rename(&original, fixture.journal()).unwrap();
        std::fs::set_permissions(fixture.journal(), std::fs::Permissions::from_mode(0o666))
            .unwrap();
        assert!(Journal::open(&fixture.0).is_err());
        std::fs::set_permissions(fixture.journal(), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let directory = fixture.0.join("amaterasu/frame-limiter");
        let moved = fixture.0.join("moved");
        std::fs::rename(&directory, &moved).unwrap();
        symlink(&moved, &directory).unwrap();
        assert!(Journal::open(&fixture.0).is_err());
    }

    #[test]
    fn journal_corruption_and_size_limits_preserve_the_original_file() {
        let fixture = Fixture::new();
        let (journal, _, _) = Journal::open(&fixture.0).unwrap();
        drop(journal);
        std::fs::write(fixture.journal(), b"not json").unwrap();
        assert!(matches!(
            Journal::open(&fixture.0),
            Err("invalid_lifecycle_journal")
        ));
        assert_eq!(std::fs::read(fixture.journal()).unwrap(), b"not json");
        File::options()
            .write(true)
            .open(fixture.journal())
            .unwrap()
            .set_len(MAX_BYTES + 1)
            .unwrap();
        assert!(matches!(
            Journal::open(&fixture.0),
            Err("lifecycle_journal_too_large")
        ));
        assert_eq!(
            std::fs::metadata(fixture.journal()).unwrap().len(),
            MAX_BYTES + 1
        );
    }

    #[test]
    fn restart_at_receipt_capacity_preserves_pending_cleanup_and_bounded_history() {
        let mut state = State::new().unwrap();
        for sequence in 1..=288 {
            let target = LifecycleTarget::Session {
                host_epoch: "epoch".into(),
                session_id: format!("session-{sequence}"),
                generation: 1,
            };
            let operation_id = format!("operation-{sequence}");
            let transition_id = format!("transition-{sequence}");
            let id = receipt_key(&transition_id, &operation_id, sequence);
            let response = ProviderResponse::Cleanup {
                outcomes: vec![],
                outputs: vec![],
            };
            state.receipts.insert(
                id.clone(),
                Receipt {
                    target,
                    operation_id,
                    transition_id,
                    provider_sequence: sequence,
                    fingerprint: "0".repeat(64),
                    expected_response: response.clone(),
                    response: None,
                },
            );
            if sequence <= 256 {
                state.finish(&id, response);
            }
        }
        state.validate().unwrap();
        state.retire_after_worker_restart().unwrap();
        state.validate().unwrap();
        assert_eq!(state.receipts.len(), 256);
        assert_eq!(state.completed.len(), 256);
        assert!(
            state
                .receipts
                .values()
                .all(|receipt| matches!(receipt.response, Some(ProviderResponse::Cleanup { .. })))
        );
    }
}
