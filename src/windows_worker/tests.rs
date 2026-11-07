use super::*;

#[cfg(windows)]
fn reply(process: &Process) -> Reply {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(value) = process.poll().unwrap() {
            return serde_json::from_value(value).unwrap();
        }
        assert!(Instant::now() < deadline, "child did not reply");
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(not(windows))]
fn shutdown_fixture(mode: &str) -> Worker {
    let mut command = std::process::Command::new("python3");
    command.args(["-I", "-u", "-c", "import json,sys,time\njson.loads(sys.stdin.readline())\nprint(json.dumps({'kind':'ready','snapshot':{'revision':2,'targets':[]}}),flush=True)\nfor line in sys.stdin: pass\nif sys.argv[1] != 'missing': print(json.dumps({'kind':'stopped'}),flush=True)\nif sys.argv[1] == 'linger': time.sleep(1)", mode]);
    let mut worker =
        Worker::new(std::env::temp_dir().join("amaterasu-unused-shutdown-fixture.json"));
    let process = Process::spawn(command).unwrap();
    process
        .submit(&serde_json::to_value(&worker.config).unwrap())
        .unwrap();
    worker.process = Some(process);
    worker.starting = Some(Instant::now());
    worker.wanted = true;
    pump(&mut worker, |worker| worker.snapshot.is_some());
    worker
}

#[cfg(not(windows))]
#[test]
fn shutdown_announcement_preserves_consumer_callbacks_and_closes_legacy_admission() {
    let mut worker = shutdown_fixture("clean");
    worker.prepare_shutdown(0);
    let deadline = worker.shutdown_deadline;
    worker.prepare_shutdown(30_000);
    assert_eq!(worker.shutdown_deadline, deadline);
    worker.advance();
    assert!(worker.process.as_mut().unwrap().is_running().unwrap());
    assert!(!worker.shutdown_started);
    assert_eq!(
        worker.legacy("test", json!({"action":"apply"}), 100),
        Err("host_stopping")
    );
    assert!(
        worker
            .legacy("test", json!({"action":"restore"}), 100)
            .is_ok()
    );
    assert!(
        worker
            .legacy("test", json!({"action":"status"}), 100)
            .is_ok()
    );
    let (request, policy) = callback(&worker, crate::windows_policy::Provider::Auto);
    assert!(!worker.has_receipt(&request));
    assert!(!worker.owns_target(&request.target));
    assert!(matches!(
        worker.begin(&request, Some(policy.clone()), 5_000),
        ProviderResponse::Pending { .. }
    ));
    assert_ne!(worker.quiesce(), Ok(true));
    assert!(worker.has_receipt(&request));
    let mut foreign = request.clone();
    foreign.operation_id.push_str("-foreign");
    assert!(!worker.has_receipt(&foreign));
    let id = worker.receipts[&receipt_id(&request)];
    assert!(matches!(
        serde_json::from_value::<ProviderResponse>(worker.result(id).unwrap()).unwrap(),
        ProviderResponse::Rejected { .. }
    ));
}

#[test]
fn admitted_snapshot_policy_and_cached_receipt_survive_root_retirement() {
    let mut worker = Worker::new(PathBuf::from("unused-rtss.json"));
    let session: api::LifecycleTarget = serde_json::from_value(
        json!({"kind":"session","host_epoch":"epoch","session_id":"session","generation":1}),
    )
    .unwrap();
    let root_id = crate::windows_lifecycle::target_identity(&session)
        .unwrap()
        .1;
    let frozen = Policy {
        provider: crate::windows_policy::Provider::Rtss,
        installation: String::new(),
        profile: crate::rtss::GLOBAL_PROFILE.into(),
        values: crate::lease::ProfileValues {
            frame_limit: 60,
            frame_limit_denominator: 1,
            sync_limiter: 0,
        },
        driver_limit_millihz: Some(60000),
        disable_vsync: false,
        smooth_motion: false,
    };
    let root = crate::windows_lifecycle::ownership::Root {
        target: session,
        policy: frozen.clone(),
        rtss_lease: Some("owned-lease".into()),
        driver: false,
        application: true,
        streams: Default::default(),
        releasing: Default::default(),
        retired_streams: Default::default(),
        phase: crate::windows_lifecycle::ownership::Phase::Active,
    };
    worker.snapshot = Some(Snapshot {
        revision: 2,
        targets: vec![root_id],
        root: Some(root.clone()),
    });
    validate_snapshot(worker.snapshot.as_ref().unwrap()).unwrap();
    let (mut request, mut changed) = callback(&worker, crate::windows_policy::Provider::Nvidia);
    request.target = serde_json::from_value(json!({"kind":"stream","host_epoch":"epoch","session_id":"session","stream_id":"stream","generation":1})).unwrap();
    request.phase = api::LifecyclePhase::StreamPrepare;
    request.operation = api::ProviderOperation::ResourcePlan;
    request.approved_plan = None;
    request.admission_id = None;
    request.plan_revision = None;
    changed.values.frame_limit = 90;
    changed.driver_limit_millihz = Some(90000);
    let plan = worker.plan(&request, Some(&changed)).unwrap();
    assert_eq!(
        plan.constraints["policy"],
        serde_json::to_value(&frozen).unwrap()
    );
    request.operation = api::ProviderOperation::LifecycleCallback;
    request.plan_revision = Some(plan.revision);
    request.admission_id = Some("admitted".into());
    request.approved_plan = Some(plan);
    assert!(matches!(
        worker.begin(&request, Some(changed.clone()), 5_000),
        ProviderResponse::Pending { .. }
    ));
    let id = worker.receipts[&receipt_id(&request)];
    worker.finish(id, json!({"status":"prepared","candidate":null,"obligations":request.approved_plan.as_ref().unwrap().obligations,"outputs":[]}));
    worker.snapshot.as_mut().unwrap().root = None;
    assert!(matches!(
        worker.begin(&request, Some(changed), 5_000),
        ProviderResponse::Prepared { .. }
    ));
    let mut release = request.clone();
    release.phase = api::LifecyclePhase::StreamRelease;
    release.operation = api::ProviderOperation::ResourcePlan;
    release.operation_id = "release".into();
    release.approved_plan = None;
    release.admission_id = None;
    release.plan_revision = None;
    let plan = worker.plan(&release, None).unwrap();
    release.operation = api::ProviderOperation::LifecycleCallback;
    release.plan_revision = Some(plan.revision);
    release.admission_id = Some("release-admitted".into());
    release.approved_plan = Some(plan);
    assert!(
        matches!(
            worker.begin(&release, None, 5_000),
            ProviderResponse::Pending { .. }
        ),
        "cleanup does not require a prepare policy argument"
    );
    let mut invalid = worker.snapshot.clone().unwrap();
    invalid.root = Some(crate::windows_lifecycle::ownership::Root {
        target: request.target.clone(),
        policy: frozen,
        rtss_lease: None,
        driver: false,
        application: true,
        streams: Default::default(),
        releasing: Default::default(),
        retired_streams: Default::default(),
        phase: crate::windows_lifecycle::ownership::Phase::Active,
    });
    assert!(validate_snapshot(&invalid).is_err());
    let mut oversized = root.clone();
    oversized.policy.installation = "x".repeat(4096);
    assert!(crate::windows_lifecycle::ownership::validate_root(&oversized).is_err());
    let mut too_many = root;
    for index in 0..33 {
        let target: api::LifecycleTarget = serde_json::from_value(json!({"kind":"stream","host_epoch":"epoch","session_id":"session","stream_id":format!("stream-{index}"),"generation":1})).unwrap();
        too_many.streams.insert(
            crate::windows_lifecycle::target_identity(&target)
                .unwrap()
                .1,
        );
    }
    assert!(crate::windows_lifecycle::ownership::validate_root(&too_many).is_err());
}

#[test]
fn new_callback_rejects_policy_that_differs_from_its_admitted_plan() {
    let mut worker = Worker::new(PathBuf::from("unused-rtss.json"));
    worker.snapshot = Some(Snapshot {
        revision: 2,
        targets: vec![],
        root: None,
    });
    let (mut request, policy) = callback(&worker, crate::windows_policy::Provider::Rtss);
    request.approved_plan.as_mut().unwrap().constraints["policy"]["values"]["frame_limit"] =
        json!(144);
    assert!(matches!(
        worker.begin(&request, Some(policy), 5_000),
        ProviderResponse::Rejected { .. }
    ));
    assert!(worker.jobs.is_empty());
}

#[cfg(not(windows))]
#[test]
fn shutdown_requires_both_restoration_acknowledgement_and_exact_child_exit() {
    for mode in ["clean", "missing"] {
        let mut worker = shutdown_fixture(mode);
        worker.prepare_shutdown(2_000);
        let deadline = Instant::now() + Duration::from_secs(2);
        let outcome = loop {
            match worker.quiesce() {
                Ok(false) => {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(2));
                }
                outcome => break outcome,
            }
        };
        assert_eq!(outcome.is_ok(), mode == "clean");
        assert!(
            worker.process.is_none(),
            "confirmed child exit must retire the owned handle"
        );
        assert_eq!(worker.quiesce().is_ok(), mode == "clean");
    }
}

#[cfg(not(windows))]
#[test]
fn expired_shutdown_never_renews_budget_or_confuses_acknowledgement_with_exit() {
    let mut worker = shutdown_fixture("linger");
    worker.prepare_shutdown(2_000);
    assert_eq!(worker.quiesce(), Ok(false));
    let deadline = Instant::now() + Duration::from_secs(1);
    while !worker.shutdown_restored {
        assert_eq!(worker.quiesce(), Ok(false));
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(worker.process.as_mut().unwrap().is_running().unwrap());
    worker.prepare_shutdown(0);
    let retained = worker.shutdown_deadline;
    assert!(worker.quiesce().is_err());
    worker.prepare_shutdown(30_000);
    assert_eq!(worker.shutdown_deadline, retained);
    assert!(worker.quiesce().is_err());
    assert!(!worker.shutdown_complete);
    let started = Instant::now();
    drop(worker);
    assert!(started.elapsed() < Duration::from_millis(200));
}

#[cfg(not(windows))]
#[test]
fn unconfirmed_retirement_is_bounded_and_retains_the_owned_process() {
    let mut worker = shutdown_fixture("clean");
    let id = worker.submit(Operation::Ping, 30_000).unwrap();
    worker.queue.clear();
    worker.active = Some(id);
    worker.retiring = Some(Retirement {
        job: id,
        deadline: Instant::now(),
    });
    let started = Instant::now();
    worker.advance();
    assert!(started.elapsed() < Duration::from_millis(200));
    assert_eq!(worker.failure, Some("native_worker_tree_stop_unconfirmed"));
    assert!(
        worker.process.is_some(),
        "failed confirmation must retain its exact native handle"
    );
    assert!(worker.result(id).is_some());
}

#[cfg(not(windows))]
#[test]
fn shutdown_rejects_acknowledgement_with_a_missing_active_result() {
    let mut worker = shutdown_fixture("clean");
    let id = worker.submit(Operation::Ping, 5_000).unwrap();
    worker.advance();
    assert_eq!(worker.active, Some(id));
    worker.prepare_shutdown(2_000);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match worker.quiesce() {
            Ok(false) => {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(2));
            }
            Ok(true) => panic!("missing operation result was accepted as clean shutdown"),
            Err(_) => break,
        }
    }
    assert_eq!(
        worker.result(id).unwrap()["error"]["code"],
        "native_worker_invalid_reply"
    );
    assert!(!worker.shutdown_complete);
}

#[test]
#[cfg(windows)]
#[ignore = "requires the independently built Windows frame-limiter DLL; uses private temporary journals"]
fn packaged_dll_runs_its_private_worker_and_retires_without_host_native_effects() {
    let library = PathBuf::from(
        std::env::var_os("AMATERASU_FRAME_LIMITER_LIBRARY").expect("supply frame-limiter DLL"),
    );
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).unwrap();
    let root = std::env::temp_dir().join(format!(
        "limiter child, {:032x}",
        u128::from_le_bytes(nonce)
    ));
    std::fs::create_dir(&root).unwrap();
    let copied = root.join("limiter test, module.dll");
    std::fs::copy(library, &copied).unwrap();
    let process = Process::spawn(launch::command_for(&copied).unwrap()).unwrap();
    let config = Config {
        version: 1,
        rtss_journal: root.join("rtss.json"),
        nvcp_journal: root.join("nvcp.json"),
        disable_stalled_rtss: false,
    };
    process
        .submit(&serde_json::to_value(config).unwrap())
        .unwrap();
    let Reply::Ready { snapshot } = reply(&process) else {
        panic!("worker not ready");
    };
    assert_eq!(snapshot.revision, 2);
    assert!(snapshot.targets.is_empty());
    process
        .submit(
            &serde_json::to_value(Call {
                id: 1,
                operation: Operation::Ping,
            })
            .unwrap(),
        )
        .unwrap();
    let Reply::Result { id, value, .. } = reply(&process) else {
        panic!("missing response");
    };
    assert_eq!(id, 1);
    assert_eq!(value, json!({"ok":true}));
    process
        .submit(
            &serde_json::to_value(Call {
                id: 2,
                operation: Operation::Legacy {
                    caller: "test".into(),
                    payload: json!({"invalid":"request"}),
                },
            })
            .unwrap(),
        )
        .unwrap();
    let Reply::Result { id, value, .. } = reply(&process) else {
        panic!("missing compatibility response");
    };
    assert_eq!(id, 2);
    assert_ne!(value["ok"], true);
    let stopped = Instant::now();
    drop(process);
    assert!(stopped.elapsed() < Duration::from_secs(2));
    std::fs::remove_dir_all(root).unwrap();
}

fn callback(
    worker: &Worker,
    provider: crate::windows_policy::Provider,
) -> (ProviderRequest, Policy) {
    let policy = Policy {
        provider,
        installation: String::new(),
        profile: crate::rtss::GLOBAL_PROFILE.into(),
        values: crate::lease::ProfileValues {
            frame_limit: 60,
            frame_limit_denominator: 1,
            sync_limiter: 0,
        },
        driver_limit_millihz: Some(60000),
        disable_vsync: false,
        smooth_motion: false,
    };
    let mut request: ProviderRequest = serde_json::from_value(json!({"version":1,"provider_sequence":1,"operation":"resource_plan",
        "transition_id":"transition","operation_id":"operation","target":{"kind":"session","host_epoch":"epoch","session_id":"session","generation":1},"phase":"session.prepare",
        "settings_revision":"r","settings":{},"intent":null,"reason":null,"requested_video":null,
        "consumer_requirements":{"execution_domain":"desktop","capture_providers":[],"selector_schemas":[]},
        "remaining_ms":5000,"plan_revision":null,"admission_id":null,"approved_plan":null})).unwrap();
    let plan = worker.plan(&request, Some(&policy)).unwrap();
    request.operation = api::ProviderOperation::LifecycleCallback;
    request.provider_sequence = 2;
    request.plan_revision = Some(plan.revision);
    request.admission_id = Some("admitted".into());
    request.approved_plan = Some(plan);
    (request, policy)
}

fn pump(worker: &mut Worker, condition: impl Fn(&Worker) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition(worker) {
        worker.advance();
        assert!(Instant::now() < deadline, "worker did not settle");
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
#[ignore = "requires the Windows native_worker_fixture example; operates only in private temporary directories"]
fn stalled_calls_are_retired_and_fallback_requires_proven_absence_of_effects() {
    let program = PathBuf::from(
        std::env::var_os("AMATERASU_FRAME_LIMITER_WORKER_FIXTURE")
            .expect("supply fixture executable"),
    );
    for (mode, provider, fallback) in [
        ("stall_clean", crate::windows_policy::Provider::Auto, true),
        ("stall_clean", crate::windows_policy::Provider::Rtss, true),
        ("stall_startup", crate::windows_policy::Provider::Auto, true),
        (
            "stall_unknown",
            crate::windows_policy::Provider::Auto,
            false,
        ),
        ("stall_nvcp", crate::windows_policy::Provider::Auto, false),
    ] {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!(
            "native-timeout-{:032x}",
            u128::from_le_bytes(nonce)
        ));
        std::fs::create_dir(&root).unwrap();
        let mut worker = Worker::new(root.join("rtss.json"));
        worker.fixture = Some((program.clone(), mode.into()));
        assert!(worker.initializing());
        pump(&mut worker, |worker| worker.snapshot.is_some());
        let (request, policy) = callback(&worker, provider);
        let ProviderResponse::Pending { receipt_id } =
            worker.begin(&request, Some(policy), request.remaining_ms)
        else {
            panic!("not queued");
        };
        let status = ProviderStatusRequest {
            provider_sequence: request.provider_sequence,
            operation_id: request.operation_id.clone(),
            transition_id: request.transition_id.clone(),
            receipt_id,
        };
        pump(&mut worker, |worker| {
            worker
                .active
                .is_some_and(|id| !worker.jobs[&id].stage.is_empty())
        });
        let id = worker.active.unwrap();
        if mode == "stall_startup" {
            worker.jobs.get_mut(&id).unwrap().last_progress =
                Instant::now() - Duration::from_secs(2);
            worker.advance();
            assert!(
                worker.failure.is_none(),
                "startup has a separate bounded warm-up window"
            );
            assert!(!worker.config.disable_stalled_rtss);
        }
        worker.jobs.get_mut(&id).unwrap().last_progress = Instant::now() - Duration::from_secs(5);
        let stopped = Instant::now();
        worker.advance();
        assert!(
            stopped.elapsed() < Duration::from_secs(2),
            "retiring a stalled child blocked the parent"
        );
        if fallback {
            pump(&mut worker, |worker| {
                !matches!(worker.status(&status), ProviderResponse::Pending { .. })
            });
            assert!(matches!(
                worker.status(&status),
                ProviderResponse::Prepared { .. }
            ));
            assert!(worker.config.disable_stalled_rtss);
            assert!(worker.failure.is_none());
        } else {
            pump(&mut worker, |worker| {
                !matches!(worker.status(&status), ProviderResponse::Pending { .. })
            });
            assert!(matches!(
                worker.status(&status),
                ProviderResponse::RecoveryRequired { .. }
            ));
            assert!(!worker.config.disable_stalled_rtss);
            assert!(worker.failure.is_some());
        }
        drop(worker);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
#[ignore = "requires the Windows native_worker_fixture example; uses a private pipe and temporary directory"]
fn queued_cancellation_conflicting_retries_and_capacity_do_not_start_effects() {
    let program = PathBuf::from(
        std::env::var_os("AMATERASU_FRAME_LIMITER_WORKER_FIXTURE")
            .expect("supply fixture executable"),
    );
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).unwrap();
    let root =
        std::env::temp_dir().join(format!("native-queue-{:032x}", u128::from_le_bytes(nonce)));
    std::fs::create_dir(&root).unwrap();
    let mut worker = Worker::new(root.join("rtss.json"));
    worker.fixture = Some((program, String::new()));
    worker.initializing();
    pump(&mut worker, |worker| worker.snapshot.is_some());
    let (request, mut policy) = callback(&worker, crate::windows_policy::Provider::Auto);
    assert!(matches!(
        worker.begin(&request, Some(policy.clone()), 0),
        ProviderResponse::Rejected { .. }
    ));
    assert!(worker.queue.is_empty());
    let ProviderResponse::Pending { receipt_id } =
        worker.begin(&request, Some(policy.clone()), request.remaining_ms)
    else {
        panic!("not admitted");
    };
    let id = worker.receipts[&receipt_id];
    worker.cancel(id);
    pump(&mut worker, |worker| worker.result(id).is_some());
    let status = ProviderStatusRequest {
        provider_sequence: request.provider_sequence,
        operation_id: request.operation_id.clone(),
        transition_id: request.transition_id.clone(),
        receipt_id,
    };
    assert!(matches!(
        worker.status(&status),
        ProviderResponse::Rejected { .. }
    ));
    assert!(worker.failure.is_none());
    policy.disable_vsync = true;
    assert!(matches!(
        worker.begin(&request, Some(policy), request.remaining_ms),
        ProviderResponse::Rejected { .. }
    ));
    assert_eq!(
        worker.legacy(
            "test",
            json!("x".repeat(crate::native_worker_process::MAX_FRAME)),
            5000
        ),
        Err("native_worker_request_too_large")
    );
    for _ in 0..32 {
        worker.legacy("test", Value::Null, 5000).unwrap();
    }
    assert_eq!(
        worker.legacy("test", Value::Null, 5000),
        Err("native_worker_busy")
    );
    assert!(worker.active.is_none());
    drop(worker);
    std::fs::remove_dir_all(root).unwrap();
}
