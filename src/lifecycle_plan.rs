//! Provider-owned resource and cleanup declarations for limiter effects.
use amaterasu_module_sdk::extension_api::{
    self, ConsumerChange, LifecyclePhase, LifecycleTarget, MethodRef, MutationDomainPlan,
    PlannedResource, ProviderOperation, ProviderRequest, ResourceAccess, ResourceObligation,
    ResourcePlan,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn digest(value: &impl serde::Serialize) -> Result<String, &'static str> {
    let bytes = serde_json::to_vec(value).map_err(|_| "invalid_target")?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(target_os = "linux")]
pub(crate) fn build(
    request: &ProviderRequest,
    policy: Option<&Value>,
    domain_revision: u64,
) -> Result<ResourcePlan, &'static str> {
    validate_plan_input(request, policy.is_some(), domain_revision)?;
    let environment = policy
        .map(crate::linux_environment::contribution)
        .transpose()?;
    build_effect(
        request,
        policy,
        domain_revision,
        extension_api::LAUNCH_ENVIRONMENT_CAPABILITY,
        environment,
    )
}

#[cfg(any(windows, test))]
pub(crate) fn build_native(
    request: &ProviderRequest,
    policy: Option<&Value>,
    domain_revision: u64,
) -> Result<ResourcePlan, &'static str> {
    build_effect(
        request,
        policy,
        domain_revision,
        crate::windows_policy::CAPABILITY,
        None,
    )
}

fn build_effect(
    request: &ProviderRequest,
    policy: Option<&Value>,
    domain_revision: u64,
    capability: &str,
    environment: Option<extension_api::LaunchEnvironmentContribution>,
) -> Result<ResourcePlan, &'static str> {
    let preparing = validate_plan_input(request, policy.is_some(), domain_revision)?;
    build_validated_effect(
        request,
        policy,
        domain_revision,
        capability,
        environment,
        preparing,
    )
}

fn validate_plan_input(
    request: &ProviderRequest,
    has_policy: bool,
    domain_revision: u64,
) -> Result<bool, &'static str> {
    if request.version != extension_api::CONTRACT_VERSION
        || request.operation != ProviderOperation::ResourcePlan
        || extension_api::validate_provider_request(request).is_err()
    {
        return Err("unsupported_lifecycle_request");
    }
    let preparing = match (&request.phase, &request.target) {
        (LifecyclePhase::SessionPrepare, LifecycleTarget::Session { .. })
        | (LifecyclePhase::StreamPrepare, LifecycleTarget::Stream { .. }) => true,
        (LifecyclePhase::SessionRelease, LifecycleTarget::Session { .. })
        | (LifecyclePhase::StreamRelease, LifecycleTarget::Stream { .. }) => false,
        _ => return Err("invalid_phase_target"),
    };
    if preparing != has_policy || domain_revision == 0 {
        return Err("invalid_policy_phase");
    }
    Ok(preparing)
}

fn build_validated_effect(
    request: &ProviderRequest,
    policy: Option<&Value>,
    domain_revision: u64,
    capability: &str,
    environment: Option<extension_api::LaunchEnvironmentContribution>,
    preparing: bool,
) -> Result<ResourcePlan, &'static str> {
    let target = digest(&request.target)?;
    let resource_id = format!("limiter-{target}");
    let domain = "amaterasu.frame-limiter/policy".to_owned();
    let obligation = ResourceObligation {
        obligation_id: format!("cleanup-{target}"),
        provider: crate::settings_descriptor::PROVIDER.into(),
        resource_id: resource_id.clone(),
        mutation_domain: Some(domain.clone()),
        depends_on: vec![],
        cleanup_method: MethodRef {
            service: crate::settings_descriptor::SERVICE.into(),
            method: "lifecycle_callback".into(),
            interface_major: 1,
            interface_minor: 0,
            schema_revision: 1,
        },
        payload: json!({}),
    };
    let plan = ResourcePlan {
        plan_id: format!("limiter-plan-{}", digest(&request.transition_id)?),
        revision: request.provider_sequence,
        resources: vec![PlannedResource {
            provider: crate::settings_descriptor::PROVIDER.into(),
            resource_id,
            incarnation: None,
            expected_revision: None,
            execution_domain: request.consumer_requirements.execution_domain.clone(),
            mutation_domains: vec![domain.clone()],
            access: ResourceAccess::Exclusive,
        }],
        mutation_domains: vec![MutationDomainPlan {
            domain,
            expected_revision: domain_revision,
            borrowers: Default::default(),
            access: ResourceAccess::Exclusive,
        }],
        required_capabilities: if preparing {
            vec![capability.into()]
        } else {
            vec![]
        },
        constraints: {
            let mut constraints = json!({"policy":policy});
            if let Some(contribution) = environment {
                constraints["launch_environment"] =
                    json!(extension_api::LaunchEnvironmentRequirement {
                        schema: extension_api::launch_environment_schema(),
                        contribution,
                    });
            }
            constraints
        },
        obligations: vec![obligation],
        affected_consumers: vec![],
        consumer_change: ConsumerChange::Live,
        candidate_constraint: None,
        allowed_degradation: vec![],
        control_proposals: vec![],
        resource_disposition: None,
    };
    extension_api::validate_resource_plan(&plan).map_err(|_| "invalid_plan")?;
    Ok(plan)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn request(phase: &str, target: Value) -> ProviderRequest {
        serde_json::from_value(json!({"provider_sequence":1,"operation":"resource_plan","version":1,
            "transition_id":"transition","operation_id":"plan","target":target,"phase":phase,
            "settings_revision":"revision","settings":{},"intent":null,"reason":null,"requested_video":null,
            "consumer_requirements":{"execution_domain":"seat","capture_providers":["capture"],"selector_schemas":["selector/1"]},
            "remaining_ms":5000,"plan_revision":null,"admission_id":null,"approved_plan":null})).unwrap()
    }

    #[test]
    fn plan_declares_cleanup_and_matches_the_release_target() {
        let target =
            json!({"kind":"session","host_epoch":"epoch","session_id":"session","generation":1});
        let policy = json!({"app_id":null,"provider":"proton","limit_millihz":59940,"preset":"custom","method":"late","graph":false});
        let prepare = build(
            &request("session.prepare", target.clone()),
            Some(&policy),
            1,
        )
        .unwrap();
        let release = build(&request("session.release", target.clone()), None, 2).unwrap();
        assert_eq!(prepare.obligations, release.obligations);
        assert_eq!(
            prepare.obligations[0].cleanup_method.method,
            "lifecycle_callback"
        );
        assert_eq!(
            prepare.resources[0].resource_id,
            prepare.obligations[0].resource_id
        );
        let other =
            json!({"kind":"session","host_epoch":"epoch","session_id":"other","generation":1});
        assert_ne!(
            prepare.obligations,
            build(&request("session.release", other), None, 2)
                .unwrap()
                .obligations
        );
    }

    #[test]
    fn v2_and_wrong_phase_do_not_silently_claim_support() {
        let target =
            json!({"kind":"session","host_epoch":"epoch","session_id":"session","generation":1});
        let mut unsupported = request("session.prepare", target.clone());
        unsupported.version = 2;
        assert_eq!(
            build(&unsupported, Some(&json!({})), 1),
            Err("unsupported_lifecycle_request")
        );
        assert_eq!(
            build(&request("stream.prepare", target), Some(&json!({})), 1),
            Err("invalid_phase_target")
        );
    }
}
