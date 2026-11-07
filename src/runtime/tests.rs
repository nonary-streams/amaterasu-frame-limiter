use super::*;
use amaterasu_module_sdk::abi;
use std::ffi::c_void;

unsafe extern "C" fn unavailable(
    _context: *mut c_void,
    _input: abi::BorrowedBytes,
    _reply: abi::ReplySink,
) -> abi::Status {
    abi::STATUS_INTERNAL_ERROR
}

#[test]
fn module_quiesce_does_not_report_pending_lifecycle_context_drained() {
    let endpoint = abi::HostApi {
        header: abi::AbiHeader::of::<abi::HostApi>(),
        context: std::ptr::null_mut(),
        invoke: unavailable,
    };
    // SAFETY: this static callback has no borrowed context and outlives the client.
    let runtime = unsafe { RuntimeClient::from_endpoint(endpoint) };
    let selected = crate::lifecycle::selection(&json!({
        "lifecycle_coordinator":{"principal":"coordinator","service":"lifecycle/1"}
    }))
    .unwrap()
    .unwrap();
    let mut lifecycle = crate::lifecycle::Bridge::new(selected);
    let request = json!({"provider_sequence":1,"operation":"resource_plan","version":1,
        "transition_id":"transition","operation_id":"plan","target":{"kind":"session",
        "host_epoch":"epoch","session_id":"session","generation":1},"phase":"session.prepare",
        "settings_revision":"revision","settings":{},"intent":null,"reason":null,
        "requested_video":null,"consumer_requirements":{"execution_domain":"seat",
        "capture_providers":["capture"],"selector_schemas":["selector/1"]},
        "remaining_ms":5000,"plan_revision":null,"admission_id":null,"approved_plan":null});
    let envelope = json!({"method":"resource_plan","interface_major":1,"interface_minor":0,
        "arguments":request});
    assert!(lifecycle.accept(7, "coordinator", envelope, 5000).is_none());
    // The read may already have been admitted even if its acknowledgement was
    // lost. Shutdown must retain and resolve that broker identity before ready.
    lifecycle.advance(&runtime).unwrap();
    let native = LeaseManager::open(
        RtssProvider::new(),
        std::env::temp_dir().join(format!(
            "amaterasu-limiter-unused-{}-quiesce.json",
            std::process::id()
        )),
    )
    .unwrap();
    let mut module = FrameLimiterModule {
        runtime,
        native: Rc::new(RefCell::new(native)),
        registry_principal: None,
        lifecycle: Some(lifecycle),
        shutdown: Default::default(),
    };
    assert!(!module.quiesce().unwrap());
}
