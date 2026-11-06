//! Read-only executable discovery for the optional Linux overlay.
use serde_json::Value;
use std::{
    ffi::{CString, c_char, c_int},
    path::{Path, PathBuf},
};

const MAX_SEARCH_PATHS: usize = 128;

pub(crate) struct MangoHudProbe {
    search_paths: Vec<PathBuf>,
}

impl MangoHudProbe {
    pub(crate) fn from_environment() -> Self {
        let paths = std::env::var_os("PATH").unwrap_or_default();
        Self {
            search_paths: std::env::split_paths(&paths)
                .filter(|path| path.is_absolute())
                .take(MAX_SEARCH_PATHS)
                .collect(),
        }
    }

    pub(crate) fn configured(settings: &Value) -> Result<Self, &'static str> {
        let Some(paths) = settings.get("mangohud_search_paths") else {
            return Ok(Self::from_environment());
        };
        let search_paths: Vec<PathBuf> =
            serde_json::from_value(paths.clone()).map_err(|_| "invalid_mangohud_search_paths")?;
        if search_paths.len() > MAX_SEARCH_PATHS
            || search_paths.iter().any(|path| {
                !path.is_absolute()
                    || path.as_os_str().as_encoded_bytes().len() > 4096
                    || path.as_os_str().as_encoded_bytes().contains(&0)
            })
        {
            return Err("invalid_mangohud_search_paths");
        }
        Ok(Self { search_paths })
    }

    pub(crate) fn available(&self) -> bool {
        self.search_paths
            .iter()
            .any(|directory| executable(&directory.join("mangohud")))
    }
}

fn executable(path: &Path) -> bool {
    if !std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file()) {
        return false;
    }
    let Ok(path) = CString::new(path.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    // SAFETY: access only reads a NUL-terminated path borrowed from this CString,
    // which remains alive through the call. X_OK checks this user's permissions.
    unsafe { access(path.as_ptr(), 1) == 0 }
}

unsafe extern "C" {
    fn access(path: *const c_char, mode: c_int) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn discovery_requires_an_executable_and_never_runs_it() {
        let root = std::env::temp_dir().join(format!(
            "amaterasu-overlay-probe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let probe = MangoHudProbe::configured(&json!({"mangohud_search_paths":[root]})).unwrap();
        assert!(!probe.available());
        let executable = root.join("mangohud");
        // An invalid executable format is sufficient: discovery must not invoke it.
        std::fs::write(&executable, b"do not run this fixture").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!probe.available());
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(probe.available());
        std::fs::remove_file(&executable).unwrap();
        assert!(!probe.available());
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn operator_search_paths_are_bounded_absolute_and_may_disable_discovery() {
        assert!(
            !MangoHudProbe::configured(&json!({"mangohud_search_paths":[]}))
                .unwrap()
                .available()
        );
        for value in [
            json!(["."]),
            json!([""]),
            json!("/usr/bin"),
            json!(vec!["/usr/bin"; 129]),
        ] {
            assert!(MangoHudProbe::configured(&json!({"mangohud_search_paths":value})).is_err());
        }
    }
}
