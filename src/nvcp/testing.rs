use super::*;
use std::{cell::RefCell, path::PathBuf, rc::Rc};

pub(crate) struct Unavailable;
impl DriverSettings for Unavailable {
    fn current_profile(&mut self) -> Result<Profile, Error> {
        Err(Error::Unavailable("driver_unavailable"))
    }
    fn read(&mut self, _: &Profile, _: &[Setting]) -> Result<Snapshot, Error> {
        Err(Error::Unavailable("driver_unavailable"))
    }
    fn commit(&mut self, _: &Profile, _: &Snapshot, _: &Changes) -> Result<(), Error> {
        Err(Error::Unavailable("driver_unavailable"))
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Fault {
    BeforeSave,
    PartialSave,
    LostReply,
}
pub(crate) struct Memory {
    pub values: Snapshot,
    pub inherited: BTreeMap<Setting, u32>,
    pub available: bool,
    pub fault: Option<Fault>,
    pub commits: usize,
    pub journal: Option<PathBuf>,
}
#[derive(Clone)]
pub(crate) struct Fake(pub Rc<RefCell<Memory>>);
impl Fake {
    pub(crate) fn new() -> Self {
        let inherited = BTreeMap::from([
            (Setting::FrameLimit, 144),
            (Setting::Vsync, 1),
            (Setting::PrerenderLimit, 3),
            (Setting::UltraLowLatencyMode, 2),
            (Setting::UltraLowLatencyEnabled, 1),
            (Setting::SmoothMotion, 0),
            (Setting::SmoothMotionApiMask, 0),
        ]);
        let values = inherited
            .iter()
            .map(|(key, value)| {
                (
                    *key,
                    Value {
                        effective: Some(*value),
                        explicit: None,
                    },
                )
            })
            .collect();
        Self(Rc::new(RefCell::new(Memory {
            values,
            inherited,
            available: true,
            fault: None,
            commits: 0,
            journal: None,
        })))
    }
    pub(crate) fn external(&self, setting: Setting, value: u32) {
        self.0.borrow_mut().values.insert(
            setting,
            Value {
                effective: Some(value),
                explicit: Some(value),
            },
        );
    }
}
impl DriverSettings for Fake {
    fn current_profile(&mut self) -> Result<Profile, Error> {
        if !self.0.borrow().available {
            return Err(Error::Unavailable("driver_unavailable"));
        }
        Ok(Profile {
            name: "Global".into(),
            base: false,
        })
    }
    fn read(&mut self, profile: &Profile, settings: &[Setting]) -> Result<Snapshot, Error> {
        if *profile != self.current_profile()? {
            return Err(Error::Changed);
        }
        let memory = self.0.borrow();
        Ok(settings
            .iter()
            .map(|key| (*key, memory.values[key]))
            .collect())
    }
    fn commit(
        &mut self,
        profile: &Profile,
        expected: &Snapshot,
        changes: &Changes,
    ) -> Result<(), Error> {
        if self.read(profile, &expected.keys().copied().collect::<Vec<_>>())? != *expected {
            return Err(Error::Changed);
        }
        let mut memory = self.0.borrow_mut();
        if let Some(path) = &memory.journal {
            let journal: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert!(
                matches!(
                    journal["active"]["phase"].as_str(),
                    Some("pending" | "restoring")
                ),
                "native mutation needs a durable intent"
            );
        }
        let fault = memory.fault.take();
        if matches!(fault, Some(Fault::BeforeSave)) {
            return Err(Error::Unavailable("staging_failed"));
        }
        memory.commits += 1;
        for (index, (setting, explicit)) in changes.iter().enumerate() {
            let effective = explicit.or_else(|| memory.inherited.get(setting).copied());
            memory.values.insert(
                *setting,
                Value {
                    effective,
                    explicit: *explicit,
                },
            );
            if index == 0 && matches!(fault, Some(Fault::PartialSave)) {
                return Err(Error::Uncertain("partial_save"));
            }
        }
        if matches!(fault, Some(Fault::LostReply)) {
            return Err(Error::Uncertain("lost_reply"));
        }
        Ok(())
    }
}
