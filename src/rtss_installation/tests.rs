use super::*;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path =
            std::env::temp_dir().join(format!("rtss-trust-{:032x}", u128::from_le_bytes(nonce)));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn installation_must_be_a_strict_descendant_of_a_trusted_root() {
    let root = Path::new(r"C:\Program Files");
    assert!(below(Path::new(r"c:\PROGRAM files\RTSS"), root));
    assert!(below(Path::new(r"\\?\C:\Program Files\RTSS"), root));
    for path in [
        r"C:\Program Files",
        r"C:\Program Files Backup\RTSS",
        r"D:\Program Files\RTSS",
        r"\\server\Program Files\RTSS",
    ] {
        assert!(!below(Path::new(path), root), "{path}");
    }
    assert!(matches!(
        trusted_root(Path::new(r"RTSS"), &[root.into()]),
        Err(ProviderError::Unavailable("rtss_install_path_invalid"))
    ));
    assert!(matches!(
        trusted_root(Path::new(r"C:\Program Files\..\RTSS"), &[root.into()]),
        Err(ProviderError::Unavailable("rtss_install_path_invalid"))
    ));
}

#[test]
fn ordinary_user_writable_installation_is_rejected() {
    let root = Directory::new();
    let installation = root.0.join("RTSS");
    std::fs::create_dir(&installation).unwrap();
    assert!(matches!(
        Installation::open_below(&installation, std::slice::from_ref(&root.0)),
        Err(ProviderError::Unavailable("rtss_code_mutable_by_user"))
    ));
}

#[test]
fn unsigned_code_is_rejected_by_authenticode_verification() {
    let root = Directory::new();
    let path = root.0.join("unsigned.exe");
    std::fs::write(&path, b"not signed code").unwrap();
    let file = File::open(&path).unwrap();
    assert!(matches!(
        signature(&file, &path),
        Err(ProviderError::Unavailable("rtss_signature_untrusted"))
    ));
}

#[test]
fn pinned_identity_cannot_be_attributed_to_another_path() {
    let root = Directory::new();
    let path = root.0.join("code.exe");
    std::fs::write(&path, b"fixture").unwrap();
    let path = std::fs::canonicalize(path).unwrap();
    let file = File::open(&path).unwrap();
    require_same_path(&file, &path).unwrap();
    assert!(matches!(
        require_same_path(&file, &root.0.join("other.exe")),
        Err(ProviderError::Unavailable("rtss_pinned_path_changed"))
    ));
}

struct IndependentProcess(std::process::Child);
impl Drop for IndependentProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// This seam tests process ownership without trusting fixture code as an installation.
// Production can only build Installation through the path, ACL and signature checks.
fn fixture_installation(root: &Path, fixture: &Path) -> Installation {
    let path = root.join("RTSS.exe");
    std::fs::copy(fixture, &path).unwrap();
    let code = || Code {
        file: OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .unwrap(),
        path: path.clone(),
        signer: [0; 32],
    };
    Installation {
        root: root.into(),
        _directory: OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(root)
            .unwrap(),
        executable: code(),
        hooks: code(),
    }
}

#[test]
#[ignore = "requires the Windows rtss_startup_fixture example; creates only disposable child processes"]
fn retirement_kills_owned_descendants_and_preserves_an_independent_process() {
    let fixture = PathBuf::from(
        std::env::var_os("AMATERASU_RTSS_STARTUP_FIXTURE")
            .expect("supply startup fixture executable"),
    );
    let root = Directory::new();
    let independent_root = Directory::new();
    let mut independent = IndependentProcess(
        std::process::Command::new(&fixture)
            .arg("--independent")
            .current_dir(&independent_root.0)
            .spawn()
            .unwrap(),
    );
    let installation = fixture_installation(&root.0, &fixture);
    let mut started = installation.start().unwrap();
    started
        .wait_ready(|| root.0.join("descendant.ready").exists())
        .unwrap();
    assert_eq!(
        crate::rtss::process_session_id(started.pid).unwrap(),
        crate::rtss::process_session_id(std::process::id()).unwrap()
    );
    let pid: u32 = std::fs::read_to_string(root.0.join("descendant.pid"))
        .unwrap()
        .parse()
        .unwrap();
    // SAFETY: OpenProcess returns an owned synchronization handle to this fixture descendant.
    let raw = unsafe { OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    assert!(!raw.is_null());
    // SAFETY: raw is the owned, checked handle returned by OpenProcess above.
    let descendant = unsafe { File::from_raw_handle(raw) };
    started.stop().unwrap();
    assert!(!started.running().unwrap());
    // SAFETY: the descendant handle stays open, so this tests the same process despite PID reuse.
    assert_eq!(
        unsafe { WaitForSingleObject(descendant.as_raw_handle(), 0) },
        WAIT_OBJECT_0
    );
    assert!(independent.0.try_wait().unwrap().is_none());
    drop(started);
    drop(installation);
}

#[test]
#[ignore = "requires the Windows rtss_startup_fixture example; creates only disposable child processes"]
fn failed_readiness_remains_bounded_and_drop_retires_the_owned_tree() {
    let fixture = PathBuf::from(
        std::env::var_os("AMATERASU_RTSS_STARTUP_FIXTURE")
            .expect("supply startup fixture executable"),
    );
    let root = Directory::new();
    let installation = fixture_installation(&root.0, &fixture);
    let mut started = installation.start().unwrap();
    started
        .wait_ready(|| root.0.join("descendant.ready").exists())
        .unwrap();
    let handle = started.handle.try_clone().unwrap();
    let now = Instant::now();
    assert!(matches!(
        started.wait_ready(|| false),
        Err(ProviderError::Unavailable("rtss_start_not_ready"))
    ));
    assert!(now.elapsed() < Duration::from_secs(3));
    drop(started);
    // SAFETY: duplicated process handle stays owned across the startup guard drop.
    assert_eq!(
        unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) },
        WAIT_OBJECT_0
    );
    drop(installation);
}

#[test]
#[ignore = "requires the Windows rtss_startup_fixture example; creates only disposable child processes"]
fn worker_retirement_confirms_descendants_exit_before_permitting_fallback() {
    let fixture = PathBuf::from(
        std::env::var_os("AMATERASU_RTSS_STARTUP_FIXTURE")
            .expect("supply startup fixture executable"),
    );
    let root = Directory::new();
    let mut command = std::process::Command::new(fixture);
    command.arg("--wait-input").current_dir(&root.0);
    let worker = crate::native_worker_process::Process::spawn(command).unwrap();
    worker.submit(&serde_json::json!({"start":true})).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !root.0.join("descendant.ready").exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    let pid: u32 = std::fs::read_to_string(root.0.join("descendant.pid"))
        .unwrap()
        .parse()
        .unwrap();
    // SAFETY: OpenProcess grants only query and synchronization on this fixture process.
    let raw = unsafe { OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    assert!(!raw.is_null());
    // SAFETY: raw is a new owned process handle checked above.
    let descendant = unsafe { File::from_raw_handle(raw) };
    worker.retire().unwrap();
    // SAFETY: this handle pins the descendant process identity across retirement.
    assert_eq!(
        unsafe { WaitForSingleObject(descendant.as_raw_handle(), 0) },
        WAIT_OBJECT_0
    );
}
