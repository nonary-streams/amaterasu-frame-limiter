use super::*;

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

#[test]
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
