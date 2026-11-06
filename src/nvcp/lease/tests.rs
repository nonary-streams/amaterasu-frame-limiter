use super::*;
use crate::nvcp::{
    self,
    testing::{Fake, Fault},
};
use std::path::PathBuf;

struct Fixture {
    root: PathBuf,
    pub driver: Fake,
    pub manager: Option<Manager<Fake>>,
}
impl Fixture {
    fn new() -> Self {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let root =
            std::env::temp_dir().join(format!("nvcp-lease-{:032x}", u128::from_le_bytes(nonce)));
        std::fs::create_dir(&root).unwrap();
        let driver = Fake::new();
        driver.0.borrow_mut().journal = Some(root.join("nvcp.json"));
        let manager = Manager::open(driver.clone(), &root.join("nvcp.json")).unwrap();
        Self {
            root,
            driver,
            manager: Some(manager),
        }
    }
    fn manager(&mut self) -> &mut Manager<Fake> {
        self.manager.as_mut().unwrap()
    }
    fn restart(&mut self) {
        self.manager.take();
        self.manager =
            Some(Manager::open(self.driver.clone(), &self.root.join("nvcp.json")).unwrap());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.manager.take();
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn durable_apply_restores_explicit_settings_and_inheritance() {
    let mut fixture = Fixture::new();
    fixture.driver.external(Setting::PrerenderLimit, 4);
    let before = fixture.driver.0.borrow().values.clone();
    let changes = nvcp::changes(Some(59940), false, true, true, true);
    assert_eq!(
        fixture
            .manager()
            .apply("owner", "session", "settings", &changes),
        Outcome::Applied
    );
    assert_eq!(
        fixture.driver.0.borrow().values[&Setting::FrameLimit].explicit,
        Some(60)
    );
    assert_eq!(
        fixture
            .manager()
            .apply("owner", "session", "settings", &changes),
        Outcome::AlreadyApplied
    );
    assert_eq!(fixture.driver.0.borrow().commits, 1);
    fixture.restart();
    assert_eq!(fixture.manager().recover(), Outcome::AlreadyApplied);
    assert_eq!(
        fixture.manager().restore("owner", "session"),
        Outcome::Restored
    );
    assert_eq!(fixture.driver.0.borrow().values, before);
    assert_eq!(
        fixture.manager().restore("owner", "session"),
        Outcome::Restored
    );
    assert_eq!(
        fixture
            .manager()
            .apply("owner", "session", "settings", &changes),
        Outcome::Conflict
    );
}

#[test]
fn external_override_is_preserved_and_reserves_ownership() {
    let driver = Fake::new();
    let mut manager = Manager::in_memory(driver.clone());
    let changes = nvcp::changes(Some(60_000), false, true, false, false);
    assert_eq!(
        manager.apply("one", "stream", "settings", &changes),
        Outcome::Applied
    );
    driver.external(Setting::Vsync, 99);
    let external = driver.0.borrow().values.clone();
    assert!(matches!(
        manager.restore("one", "stream"),
        Outcome::RecoveryRequired(_)
    ));
    assert_eq!(
        manager.apply("two", "other", "settings", &changes),
        Outcome::Conflict
    );
    assert_eq!(driver.0.borrow().values, external);
    assert_eq!(manager.restore("two", "stream"), Outcome::NotFound);
}

#[test]
fn interrupted_saves_are_reconciled_without_overwriting_a_third_state() {
    for fault in [Fault::PartialSave, Fault::LostReply] {
        let mut fixture = Fixture::new();
        let before = fixture.driver.0.borrow().values.clone();
        fixture.driver.0.borrow_mut().fault = Some(fault);
        let changes = nvcp::changes(Some(120000), false, true, false, false);
        assert!(matches!(
            fixture
                .manager()
                .apply("one", "stream", "settings", &changes),
            Outcome::RecoveryRequired(_)
        ));
        fixture.restart();
        let recovered = fixture.manager().recover();
        if matches!(fault, Fault::LostReply) {
            assert_eq!(recovered, Outcome::AlreadyApplied);
            assert_eq!(
                fixture.manager().restore("one", "stream"),
                Outcome::Restored
            );
        } else {
            assert_eq!(recovered, Outcome::Restored);
        }
        assert_eq!(fixture.driver.0.borrow().values, before);
    }
    let mut fixture = Fixture::new();
    fixture.driver.0.borrow_mut().fault = Some(Fault::LostReply);
    let changes = nvcp::changes(Some(120000), false, true, false, false);
    fixture
        .manager()
        .apply("one", "stream", "settings", &changes);
    fixture.driver.external(Setting::FrameLimit, 75);
    fixture.restart();
    assert!(matches!(
        fixture.manager().recover(),
        Outcome::RecoveryRequired(_)
    ));
    assert_eq!(
        fixture.driver.0.borrow().values[&Setting::FrameLimit].explicit,
        Some(75)
    );
}

#[test]
fn restored_inheritance_uses_the_current_parent_value() {
    let driver = Fake::new();
    let mut manager = Manager::in_memory(driver.clone());
    let changes = nvcp::changes(Some(60_000), false, false, false, false);
    manager.apply("one", "stream", "settings", &changes);
    driver
        .0
        .borrow_mut()
        .inherited
        .insert(Setting::FrameLimit, 165);
    assert_eq!(manager.restore("one", "stream"), Outcome::Restored);
    assert_eq!(
        driver.0.borrow().values[&Setting::FrameLimit],
        nvcp::Value {
            effective: Some(165),
            explicit: None
        }
    );
}

#[test]
fn failed_staging_and_failed_journal_do_not_mutate_driver_settings() {
    let mut fixture = Fixture::new();
    let before = fixture.driver.0.borrow().values.clone();
    fixture.driver.0.borrow_mut().fault = Some(Fault::BeforeSave);
    let changes = nvcp::changes(Some(60_000), false, true, false, false);
    assert_eq!(
        fixture
            .manager()
            .apply("one", "stream", "settings", &changes),
        Outcome::Unavailable("staging_failed")
    );
    assert_eq!(fixture.driver.0.borrow().values, before);
    let path = fixture.root.join("nvcp.json");
    std::fs::write(&path, b"foreign data").unwrap();
    assert!(matches!(
        fixture.manager().apply("one", "new", "settings", &changes),
        Outcome::RecoveryRequired(_)
    ));
    assert_eq!(fixture.driver.0.borrow().values, before);
    assert_eq!(std::fs::read(path).unwrap(), b"foreign data");
}

#[test]
fn interrupted_restore_finishes_after_restart() {
    let mut fixture = Fixture::new();
    let before = fixture.driver.0.borrow().values.clone();
    let changes = nvcp::changes(Some(60_000), false, true, false, false);
    fixture
        .manager()
        .apply("one", "stream", "settings", &changes);
    fixture.driver.0.borrow_mut().fault = Some(Fault::PartialSave);
    assert!(matches!(
        fixture.manager().restore("one", "stream"),
        Outcome::RecoveryRequired(_)
    ));
    fixture.restart();
    assert_eq!(fixture.manager().recover(), Outcome::Restored);
    assert_eq!(fixture.driver.0.borrow().values, before);
}
