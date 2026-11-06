//! Exercise the actual native adapter with an in-process DRS ABI fixture.
//! No system NVIDIA driver entrypoint is loaded or called by these tests.
use super::*;
use std::{cell::RefCell, collections::BTreeMap};

#[derive(Default)]
struct Database {
    disk: BTreeMap<u32, u32>,
    staging: BTreeMap<u32, u32>,
    saves: usize,
    fail_setting: Option<u32>,
    fail_save: bool,
}
thread_local! { static DATABASE: RefCell<Database> = RefCell::new(Database::default()); }

unsafe extern "C" fn unload() -> Status {
    0
}
unsafe extern "C" fn create(output: *mut Handle) -> Status {
    // SAFETY: adapter lends one writable handle output to this ABI fixture.
    unsafe {
        *output = 1_usize as Handle;
    }
    0
}
unsafe extern "C" fn destroy(_: Handle) -> Status {
    0
}
unsafe extern "C" fn load(_: Handle) -> Status {
    DATABASE.with(|database| {
        let mut database = database.borrow_mut();
        database.staging = database.disk.clone();
    });
    0
}
unsafe extern "C" fn save(_: Handle) -> Status {
    DATABASE.with(|database| {
        let mut database = database.borrow_mut();
        database.saves += 1;
        if database.fail_save {
            return -1;
        }
        database.disk = database.staging.clone();
        0
    })
}
unsafe extern "C" fn get_profile(_: Handle, output: *mut Handle) -> Status {
    // SAFETY: adapter lends one writable handle output to this ABI fixture.
    unsafe {
        *output = 1_usize as Handle;
    }
    0
}
unsafe extern "C" fn find_profile(session: Handle, _: *const u16, output: *mut Handle) -> Status {
    // SAFETY: forwards the fixture's writable output with the same lifetime.
    unsafe { get_profile(session, output) }
}
unsafe extern "C" fn info(_: Handle, _: Handle, output: *mut RawProfile) -> Status {
    // SAFETY: adapter lends one complete initialized SDK profile buffer.
    let output = unsafe { &mut *output };
    if output.version != 0x11014 {
        return -1;
    }
    for (index, value) in "Global".encode_utf16().enumerate() {
        output.name[index] = value;
    }
    0
}
unsafe extern "C" fn get(_: Handle, _: Handle, id: u32, output: *mut RawSetting) -> Status {
    // SAFETY: adapter lends one complete initialized SDK setting buffer.
    let output = unsafe { &mut *output };
    if output.version != 0x13020 || output.id != id {
        return -1;
    }
    DATABASE.with(|database| {
        let database = database.borrow();
        match database.staging.get(&id) {
            Some(value) => {
                output.current_value[0] = *value;
                output.predefined = 0;
                output.location = 0;
            }
            None => {
                output.current_value[0] = if id == Setting::FrameLimit.id() {
                    144
                } else {
                    1
                };
                output.predefined = 1;
                output.location = 3;
            }
        }
    });
    0
}
unsafe extern "C" fn get_current(
    session: Handle,
    profile: Handle,
    id: u32,
    output: *mut RawSetting,
    extra: *mut u32,
) -> Status {
    if extra.is_null() {
        return -1;
    }
    // SAFETY: forwards the same fixture buffers to the compatible implementation.
    unsafe { get(session, profile, id, output) }
}
unsafe extern "C" fn set(_: Handle, _: Handle, input: *mut RawSetting) -> Status {
    // SAFETY: adapter lends one complete SDK setting buffer for this call.
    let input = unsafe { &*input };
    if input.version != 0x13020 || input.kind != 0 || input.location != 0 {
        return -1;
    }
    DATABASE.with(|database| {
        let mut database = database.borrow_mut();
        if database.fail_setting == Some(input.id) {
            return -1;
        }
        database.staging.insert(input.id, input.current_value[0]);
        0
    })
}
unsafe extern "C" fn set_current(
    session: Handle,
    profile: Handle,
    input: *mut RawSetting,
    first: u32,
    second: u32,
) -> Status {
    if first != 0 || second != 0 {
        return -1;
    }
    // SAFETY: forwards the same fixture buffer to the compatible implementation.
    unsafe { set(session, profile, input) }
}
unsafe extern "C" fn delete(_: Handle, _: Handle, id: u32) -> Status {
    DATABASE.with(|database| {
        database.borrow_mut().staging.remove(&id);
    });
    0
}

fn driver(current: bool) -> Driver {
    DATABASE.with(|database| *database.borrow_mut() = Database::default());
    Driver {
        api: Some(Api {
            library: ptr::null_mut(),
            unload,
            create,
            destroy,
            load,
            save,
            global: Some(get_profile),
            base: get_profile,
            find: find_profile,
            info,
            get: if current {
                SettingReader::Current(get_current)
            } else {
                SettingReader::Legacy(get)
            },
            set: if current {
                SettingWriter::Current(set_current)
            } else {
                SettingWriter::Legacy(set)
            },
            delete,
            driver_version: 60000,
        }),
    }
}

#[test]
fn native_adapter_applies_and_deletes_overrides_through_both_entrypoint_generations() {
    for current in [false, true] {
        let mut driver = driver(current);
        let profile = driver.current_profile().unwrap();
        let keys = [Setting::FrameLimit, Setting::Vsync];
        let before = driver.read(&profile, &keys).unwrap();
        assert_eq!(
            before[&Setting::FrameLimit],
            Value {
                effective: Some(144),
                explicit: None
            }
        );
        let changes = super::super::changes(Some(60_000), false, true, false, false);
        driver.commit(&profile, &before, &changes).unwrap();
        let applied = driver.read(&profile, &keys).unwrap();
        assert_eq!(applied[&Setting::FrameLimit].explicit, Some(60));
        driver
            .commit(
                &profile,
                &applied,
                &keys.into_iter().map(|key| (key, None)).collect(),
            )
            .unwrap();
        assert_eq!(driver.read(&profile, &keys).unwrap(), before);
        DATABASE.with(|database| assert_eq!(database.borrow().saves, 2));
    }
}

#[test]
fn native_adapter_does_not_save_failed_staging_or_changed_snapshots() {
    let mut driver = driver(true);
    let profile = driver.current_profile().unwrap();
    let keys = [Setting::FrameLimit, Setting::Vsync];
    let before = driver.read(&profile, &keys).unwrap();
    let changes = super::super::changes(Some(60_000), false, true, false, false);
    DATABASE.with(|database| database.borrow_mut().fail_setting = Some(Setting::Vsync.id()));
    assert_eq!(
        driver.commit(&profile, &before, &changes),
        Err(Error::Unavailable("nvcp_setting_not_supported"))
    );
    DATABASE.with(|database| {
        assert!(database.borrow().disk.is_empty());
        assert_eq!(database.borrow().saves, 0);
    });
    DATABASE.with(|database| {
        database
            .borrow_mut()
            .disk
            .insert(Setting::FrameLimit.id(), 30)
    });
    assert_eq!(
        driver.commit(&profile, &before, &changes),
        Err(Error::Changed)
    );
    DATABASE.with(|database| assert_eq!(database.borrow().saves, 0));
}

#[test]
fn native_adapter_keeps_save_failure_uncertain_and_checks_smooth_motion_version() {
    let mut driver = driver(true);
    let profile = driver.current_profile().unwrap();
    let before = driver.read(&profile, &[Setting::FrameLimit]).unwrap();
    DATABASE.with(|database| database.borrow_mut().fail_save = true);
    assert_eq!(
        driver.commit(
            &profile,
            &before,
            &super::super::changes(Some(60_000), false, false, false, false)
        ),
        Err(Error::Uncertain("nvcp_save_unconfirmed"))
    );
    driver.api.as_mut().unwrap().driver_version = 57185;
    let keys = [Setting::SmoothMotion, Setting::SmoothMotionApiMask];
    let before = driver.read(&profile, &keys).unwrap();
    assert_eq!(
        driver.commit(
            &profile,
            &before,
            &super::super::changes(None, false, false, false, true)
        ),
        Err(Error::Unavailable("nvcp_smooth_motion_driver_unsupported"))
    );
}
