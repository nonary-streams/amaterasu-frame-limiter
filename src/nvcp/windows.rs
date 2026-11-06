//! Minimal NVAPI DRS boundary. Only the system driver's DLL is loaded. Native
//! handles and ABI buffers never leave this provider.
use super::{Changes, DriverSettings, Error, Profile, Setting, Snapshot, Value};
use std::{ffi::c_void, ptr};
#[cfg(test)]
mod tests;

type Handle = *mut c_void;
type Status = i32;
type Query = unsafe extern "C" fn(u32) -> *mut c_void;
type Initialize = unsafe extern "C" fn() -> Status;
type CreateSession = unsafe extern "C" fn(*mut Handle) -> Status;
type SessionOperation = unsafe extern "C" fn(Handle) -> Status;
type GetProfile = unsafe extern "C" fn(Handle, *mut Handle) -> Status;
type FindProfile = unsafe extern "C" fn(Handle, *const u16, *mut Handle) -> Status;
type GetProfileInfo = unsafe extern "C" fn(Handle, Handle, *mut RawProfile) -> Status;
type GetSetting = unsafe extern "C" fn(Handle, Handle, u32, *mut RawSetting) -> Status;
type NewGetSetting = unsafe extern "C" fn(Handle, Handle, u32, *mut RawSetting, *mut u32) -> Status;
type SetSetting = unsafe extern "C" fn(Handle, Handle, *mut RawSetting) -> Status;
type NewSetSetting = unsafe extern "C" fn(Handle, Handle, *mut RawSetting, u32, u32) -> Status;
type DeleteSetting = unsafe extern "C" fn(Handle, Handle, u32) -> Status;
type DriverVersion = unsafe extern "C" fn(*mut u32, *mut i8) -> Status;

// NVIDIA's NVDRS_SETTING_V1 uses four-byte packing. Each union is large enough
// for a 4096-byte binary payload plus its length; this provider uses DWORDs only.
#[repr(C)]
struct RawSetting {
    version: u32,
    name: [u16; 2048],
    id: u32,
    kind: u32,
    location: u32,
    predefined: u32,
    predefined_valid: u32,
    default_value: [u32; 1025],
    current_value: [u32; 1025],
}
impl RawSetting {
    fn new(setting: Setting) -> Self {
        Self {
            version: std::mem::size_of::<Self>() as u32 | (1 << 16),
            name: [0; 2048],
            id: setting.id(),
            kind: 0,
            location: 0,
            predefined: 0,
            predefined_valid: 0,
            default_value: [0; 1025],
            current_value: [0; 1025],
        }
    }
}

#[repr(C)]
struct RawProfile {
    version: u32,
    name: [u16; 2048],
    gpu_support: u32,
    predefined: u32,
    applications: u32,
    settings: u32,
}
impl RawProfile {
    fn new() -> Self {
        Self {
            version: std::mem::size_of::<Self>() as u32 | (1 << 16),
            name: [0; 2048],
            gpu_support: 0,
            predefined: 0,
            applications: 0,
            settings: 0,
        }
    }
}

enum SettingReader {
    Legacy(GetSetting),
    Current(NewGetSetting),
}
enum SettingWriter {
    Legacy(SetSetting),
    Current(NewSetSetting),
}

struct Api {
    library: Handle,
    unload: Initialize,
    create: CreateSession,
    destroy: SessionOperation,
    load: SessionOperation,
    save: SessionOperation,
    global: Option<GetProfile>,
    base: GetProfile,
    find: FindProfile,
    info: GetProfileInfo,
    get: SettingReader,
    set: SettingWriter,
    delete: DeleteSetting,
    driver_version: u32,
}

impl Api {
    fn open() -> Result<Self, Error> {
        let name: Vec<u16> = "nvapi64.dll".encode_utf16().chain(Some(0)).collect();
        // SAFETY: name is terminated and loading is restricted to System32.
        let library = unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), 0x800) };
        if library.is_null() {
            return Err(Error::Unavailable("nvcp_driver_unavailable"));
        }
        let result = (|| {
            // SAFETY: the export belongs to this live system DLL and implements NVAPI QueryInterface.
            let symbol = unsafe { GetProcAddress(library, c"nvapi_QueryInterface".as_ptr()) };
            let symbol = symbol.ok_or(Error::Unavailable("nvcp_query_unavailable"))?;
            let query: Query = unsafe { std::mem::transmute(symbol) };
            // SAFETY: IDs and prototypes are from the NVIDIA NVAPI SDK interface table.
            unsafe {
                let initialize: Initialize = required(query, 0x0150_e828)?;
                let unload = required(query, 0xd22b_dd7e)?;
                let api = Self {
                    library,
                    unload,
                    create: required(query, 0x0694_d52e)?,
                    destroy: required(query, 0xdad9_cff8)?,
                    load: required(query, 0x375d_bd6b)?,
                    save: required(query, 0xfcbc_7e14)?,
                    global: optional(query, 0x617b_ff9f),
                    base: required(query, 0xda84_66a0)?,
                    find: required(query, 0x7e4a_9a0b)?,
                    info: required(query, 0x61cd_6fd6)?,
                    get: if let Some(get) = optional(query, 0xea99_498d) {
                        SettingReader::Current(get)
                    } else {
                        SettingReader::Legacy(required(query, 0x73bf_8338)?)
                    },
                    set: if let Some(set) = optional(query, 0x8a2c_f5f5) {
                        SettingWriter::Current(set)
                    } else {
                        SettingWriter::Legacy(required(query, 0x577d_d202)?)
                    },
                    delete: optional(query, 0xd20d_29df)
                        .map_or_else(|| required(query, 0xe4a2_6362), Ok)?,
                    driver_version: 0,
                };
                // Do not construct an initialized owner until this succeeds.
                // Manually disarm Drop on this failure; Initialize acquired no reference.
                if initialize() != 0 {
                    std::mem::forget(api);
                    return Err(Error::Unavailable("nvcp_initialize_failed"));
                }
                let mut api = api;
                if let Some(version) = optional::<DriverVersion>(query, 0x2926_aaad) {
                    let mut branch = [0_i8; 64];
                    let mut number = 0;
                    if version(&mut number, branch.as_mut_ptr()) == 0 {
                        api.driver_version = number;
                    }
                }
                Ok(api)
            }
        })();
        if result.is_err() {
            // SAFETY: no Api owns the module when construction fails.
            unsafe { FreeLibrary(library) };
        }
        result
    }

    fn session(&self) -> Result<Session<'_>, Error> {
        let mut handle = ptr::null_mut();
        // SAFETY: output storage is live, and the initialized API remains owned by self.
        if unsafe { (self.create)(&mut handle) } != 0 || handle.is_null() {
            return Err(Error::Unavailable("nvcp_session_unavailable"));
        }
        let session = Session { api: self, handle };
        // SAFETY: session owns this live DRS handle until Drop.
        if unsafe { (self.load)(handle) } != 0 {
            return Err(Error::Unavailable("nvcp_settings_unavailable"));
        }
        Ok(session)
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        // SAFETY: this owner has the matching successful Initialize reference,
        // no Session survives it, and no native call is in flight on this thread.
        unsafe {
            (self.unload)();
            if !self.library.is_null() {
                FreeLibrary(self.library);
            }
        }
    }
}

struct Session<'a> {
    api: &'a Api,
    handle: Handle,
}
impl Drop for Session<'_> {
    fn drop(&mut self) {
        // SAFETY: this session owns the handle and its API outlives it.
        unsafe { (self.api.destroy)(self.handle) };
    }
}

impl Session<'_> {
    fn profile_info(&self, handle: Handle, base: bool) -> Result<Profile, Error> {
        let mut info = RawProfile::new();
        // SAFETY: the live profile/session handles and full versioned buffer match the SDK ABI.
        if unsafe { (self.api.info)(self.handle, handle, &mut info) } != 0 {
            return Err(Error::Unavailable("nvcp_profile_unavailable"));
        }
        let end = info
            .name
            .iter()
            .position(|value| *value == 0)
            .ok_or(Error::Unavailable("nvcp_profile_name_invalid"))?;
        let name = String::from_utf16(&info.name[..end])
            .map_err(|_| Error::Unavailable("nvcp_profile_name_invalid"))?;
        Ok(Profile { name, base })
    }

    fn current_profile(&self) -> Result<(Handle, Profile), Error> {
        let mut handle = ptr::null_mut();
        // SAFETY: the optional function writes one profile handle owned by this DRS session.
        if self
            .api
            .global
            .is_some_and(|global| unsafe { global(self.handle, &mut handle) == 0 })
            && !handle.is_null()
            && self
                .read_setting(handle, false, Setting::FrameLimit)
                .is_ok()
        {
            return Ok((handle, self.profile_info(handle, false)?));
        }
        // SAFETY: output storage and session are live.
        if unsafe { (self.api.base)(self.handle, &mut handle) } != 0 || handle.is_null() {
            return Err(Error::Unavailable("nvcp_profile_unavailable"));
        }
        Ok((handle, self.profile_info(handle, true)?))
    }

    fn recorded_profile(&self, profile: &Profile) -> Result<Handle, Error> {
        let mut handle = ptr::null_mut();
        let status = if profile.base {
            // SAFETY: output storage and session are live.
            unsafe { (self.api.base)(self.handle, &mut handle) }
        } else if profile.name.is_empty() {
            let global = self
                .api
                .global
                .ok_or(Error::Unavailable("nvcp_profile_unavailable"))?;
            // SAFETY: output storage and session are live.
            unsafe { global(self.handle, &mut handle) }
        } else {
            if profile.name.contains('\0') || profile.name.encode_utf16().count() >= 2048 {
                return Err(Error::Unavailable("nvcp_profile_name_invalid"));
            }
            let name: Vec<u16> = profile.name.encode_utf16().chain(Some(0)).collect();
            // SAFETY: name is terminated and output storage is live for this call.
            unsafe { (self.api.find)(self.handle, name.as_ptr(), &mut handle) }
        };
        if status != 0 || handle.is_null() || self.profile_info(handle, profile.base)? != *profile {
            return Err(Error::Changed);
        }
        Ok(handle)
    }

    fn read_setting(&self, profile: Handle, base: bool, setting: Setting) -> Result<Value, Error> {
        let mut raw = RawSetting::new(setting);
        // SAFETY: signatures distinguish the current five-argument entrypoint
        // from the legacy four-argument entrypoint; both receive a full SDK buffer.
        let status = unsafe {
            match self.api.get {
                SettingReader::Legacy(get) => get(self.handle, profile, setting.id(), &mut raw),
                SettingReader::Current(get) => {
                    get(self.handle, profile, setting.id(), &mut raw, &mut 0_u32)
                }
            }
        };
        if status == -160 {
            return Ok(Value {
                effective: None,
                explicit: None,
            });
        }
        if status != 0 || raw.kind != 0 || raw.id != setting.id() {
            return Err(Error::Unavailable("nvcp_setting_unreadable"));
        }
        let local =
            raw.location == 0 || (base && raw.location == 2) || (!base && raw.location == 1);
        Ok(Value {
            effective: Some(raw.current_value[0]),
            explicit: (local && raw.predefined == 0).then_some(raw.current_value[0]),
        })
    }

    fn read(&self, profile: Handle, base: bool, settings: &[Setting]) -> Result<Snapshot, Error> {
        settings
            .iter()
            .map(|setting| Ok((*setting, self.read_setting(profile, base, *setting)?)))
            .collect()
    }

    fn stage(&self, profile: Handle, setting: Setting, value: Option<u32>) -> Result<(), Error> {
        // SAFETY: all native handles are owned by this session and versioned
        // settings remain live through the call. No save occurs in this method.
        let status = unsafe {
            if let Some(value) = value {
                let mut raw = RawSetting::new(setting);
                raw.current_value[0] = value;
                match self.api.set {
                    SettingWriter::Legacy(set) => set(self.handle, profile, &mut raw),
                    SettingWriter::Current(set) => set(self.handle, profile, &mut raw, 0, 0),
                }
            } else {
                (self.api.delete)(self.handle, profile, setting.id())
            }
        };
        if status == 0 || (value.is_none() && status == -160) {
            Ok(())
        } else {
            Err(Error::Unavailable("nvcp_setting_not_supported"))
        }
    }
}

pub(crate) struct Driver {
    api: Option<Api>,
}
impl Driver {
    pub(crate) fn new() -> Self {
        Self { api: None }
    }
    fn api(&mut self) -> Result<&Api, Error> {
        crate::windows_worker::child_stage("nvcp");
        if self.api.is_none() {
            self.api = Some(Api::open()?);
        }
        Ok(self.api.as_ref().expect("loaded API"))
    }
}
impl DriverSettings for Driver {
    fn current_profile(&mut self) -> Result<Profile, Error> {
        self.api()?
            .session()?
            .current_profile()
            .map(|(_, profile)| profile)
    }
    fn read(&mut self, profile: &Profile, settings: &[Setting]) -> Result<Snapshot, Error> {
        let session = self.api()?.session()?;
        session.read(session.recorded_profile(profile)?, profile.base, settings)
    }
    fn commit(
        &mut self,
        profile: &Profile,
        expected: &Snapshot,
        changes: &Changes,
    ) -> Result<(), Error> {
        if expected.keys().ne(changes.keys()) {
            return Err(Error::Unavailable("nvcp_invalid_change_set"));
        }
        let settings: Vec<_> = changes.keys().copied().collect();
        let api = self.api()?;
        if changes.keys().any(|setting| {
            matches!(
                setting,
                Setting::SmoothMotion | Setting::SmoothMotionApiMask
            )
        }) && api.driver_version < 57186
        {
            return Err(Error::Unavailable("nvcp_smooth_motion_driver_unsupported"));
        }
        let session = api.session()?;
        let handle = session.recorded_profile(profile)?;
        if session.read(handle, profile.base, &settings)? != *expected {
            return Err(Error::Changed);
        }
        let mut changed = false;
        for (setting, desired) in changes {
            if expected[setting].explicit != *desired {
                session.stage(handle, *setting, *desired)?;
                changed = true;
            }
        }
        if changed {
            // SAFETY: all staging succeeded on this live private DRS session.
            if unsafe { (api.save)(session.handle) } != 0 {
                return Err(Error::Uncertain("nvcp_save_unconfirmed"));
            }
        }
        drop(session);
        let verify = api
            .session()
            .map_err(|_| Error::Uncertain("nvcp_readback_unavailable"))?;
        let handle = verify
            .recorded_profile(profile)
            .map_err(|_| Error::Uncertain("nvcp_profile_changed"))?;
        let current = verify
            .read(handle, profile.base, &settings)
            .map_err(|_| Error::Uncertain("nvcp_readback_unavailable"))?;
        if changes
            .iter()
            .any(|(setting, value)| current[setting].explicit != *value)
        {
            return Err(Error::Uncertain("nvcp_readback_mismatch"));
        }
        Ok(())
    }
}

unsafe fn optional<T: Copy>(query: Query, id: u32) -> Option<T> {
    // SAFETY: caller selects T to match the SDK function identified by id.
    let pointer = unsafe { query(id) };
    if pointer.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute_copy(&pointer) })
    }
}
unsafe fn required<T: Copy>(query: Query, id: u32) -> Result<T, Error> {
    // SAFETY: caller supplies the exact function prototype for this id.
    unsafe { optional(query, id) }.ok_or(Error::Unavailable("nvcp_api_unavailable"))
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(name: *const u16, file: Handle, flags: u32) -> Handle;
    fn GetProcAddress(module: Handle, name: *const i8) -> Option<unsafe extern "system" fn()>;
    fn FreeLibrary(module: Handle) -> i32;
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    #[test]
    fn dword_buffers_match_the_sdk_layout_and_version() {
        assert_eq!(std::mem::size_of::<RawSetting>(), 12320);
        assert_eq!(std::mem::offset_of!(RawSetting, id), 4100);
        assert_eq!(std::mem::offset_of!(RawSetting, current_value), 8220);
        assert_eq!(std::mem::size_of::<RawProfile>(), 4116);
        assert_eq!(RawSetting::new(Setting::FrameLimit).version, 0x13020);
        assert_eq!(RawProfile::new().version, 0x11014);
    }
}
