//! NVIDIA driver settings owned by this plugin. Snapshots retain override
//! provenance: removing a temporary override must restore inheritance.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
mod journal;
pub(crate) mod lease;
#[cfg(test)]
pub(crate) mod testing;

#[cfg(all(windows, target_pointer_width = "64"))]
mod windows;
#[cfg(all(windows, target_pointer_width = "64"))]
pub(crate) use windows::Driver;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Setting {
    FrameLimit,
    Vsync,
    PrerenderLimit,
    UltraLowLatencyMode,
    UltraLowLatencyEnabled,
    SmoothMotion,
    SmoothMotionApiMask,
}

impl Setting {
    pub(crate) fn id(self) -> u32 {
        match self {
            Self::FrameLimit => 0x1083_5002,
            Self::Vsync => 0x00a8_79cf,
            Self::PrerenderLimit => 0x007b_a09e,
            Self::UltraLowLatencyMode => 0x0005_f543,
            Self::UltraLowLatencyEnabled => 0x1083_5000,
            Self::SmoothMotion => 0xb0d3_84c0,
            Self::SmoothMotionApiMask => 0xb0cc_0875,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    pub name: String,
    pub base: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Value {
    pub effective: Option<u32>,
    pub explicit: Option<u32>,
}

pub(crate) type Snapshot = BTreeMap<Setting, Value>;
pub(crate) type Changes = BTreeMap<Setting, Option<u32>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    /// The operation did not save any driver settings.
    Unavailable(&'static str),
    /// The target no longer matches the caller's expected state; no save occurred.
    Changed,
    /// A save may have occurred. Ownership must remain reserved for recovery.
    Uncertain(&'static str),
}

pub(crate) trait DriverSettings {
    fn current_profile(&mut self) -> Result<Profile, Error>;
    fn read(&mut self, profile: &Profile, settings: &[Setting]) -> Result<Snapshot, Error>;
    fn commit(
        &mut self,
        profile: &Profile,
        expected: &Snapshot,
        changes: &Changes,
    ) -> Result<(), Error>;
}

pub(crate) fn rounded_fps(millihz: u32) -> u32 {
    ((u64::from(millihz) + 500) / 1000).clamp(1, 1023) as u32
}

pub(crate) fn changes(
    limit_millihz: Option<u32>,
    disable_driver_limit: bool,
    disable_vsync: bool,
    disable_low_latency: bool,
    smooth_motion: bool,
) -> Changes {
    let mut values = BTreeMap::new();
    if let Some(rate) = limit_millihz {
        values.insert(Setting::FrameLimit, Some(rounded_fps(rate)));
    } else if disable_driver_limit {
        values.insert(Setting::FrameLimit, Some(0));
    }
    if disable_vsync {
        values.insert(Setting::Vsync, Some(0x0841_6747));
    }
    if disable_low_latency {
        values.insert(Setting::PrerenderLimit, Some(1));
        values.insert(Setting::UltraLowLatencyMode, Some(0));
        values.insert(Setting::UltraLowLatencyEnabled, Some(0));
    }
    if smooth_motion {
        values.insert(Setting::SmoothMotion, Some(1));
        values.insert(Setting::SmoothMotionApiMask, Some(7));
    }
    values
}

#[cfg(not(all(windows, target_pointer_width = "64")))]
pub(crate) struct Driver;
#[cfg(not(all(windows, target_pointer_width = "64")))]
#[cfg(windows)]
impl Driver {
    pub(crate) fn new() -> Self {
        Self
    }
}
#[cfg(not(all(windows, target_pointer_width = "64")))]
impl DriverSettings for Driver {
    fn current_profile(&mut self) -> Result<Profile, Error> {
        Err(Error::Unavailable("nvcp_64_bit_windows_required"))
    }
    fn read(&mut self, _: &Profile, _: &[Setting]) -> Result<Snapshot, Error> {
        Err(Error::Unavailable("nvcp_64_bit_windows_required"))
    }
    fn commit(&mut self, _: &Profile, _: &Snapshot, _: &Changes) -> Result<(), Error> {
        Err(Error::Unavailable("nvcp_64_bit_windows_required"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn driver_limit_rounds_like_the_reference_and_respects_the_driver_range() {
        assert_eq!(rounded_fps(59_940), 60);
        assert_eq!(rounded_fps(59_499), 59);
        assert_eq!(rounded_fps(59_500), 60);
        assert_eq!(rounded_fps(1), 1);
        assert_eq!(rounded_fps(u32::MAX), 1023);
    }
    #[test]
    fn rtss_auxiliary_settings_disable_the_driver_cap_and_preserve_requested_controls() {
        let settings = changes(None, true, true, true, true);
        assert_eq!(settings.len(), 7);
        assert_eq!(settings[&Setting::FrameLimit], Some(0));
        assert_eq!(settings[&Setting::Vsync], Some(0x0841_6747));
        assert_eq!(settings[&Setting::SmoothMotionApiMask], Some(7));
        assert_eq!(
            changes(Some(120_000), true, false, false, false)[&Setting::FrameLimit],
            Some(120)
        );
        assert!(changes(None, false, false, false, false).is_empty());
        let ids: std::collections::BTreeSet<_> =
            settings.keys().map(|setting| setting.id()).collect();
        assert_eq!(ids.len(), settings.len());
    }
}
