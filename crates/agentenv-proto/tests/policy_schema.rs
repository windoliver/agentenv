use agentenv_proto::{
    ApplyPolicyParams, FilesystemPolicy, InferencePolicy, InferenceRoute, NetworkAccessPolicy,
    NetworkPolicy, NetworkRule, NetworkTarget, PolicyReloadability, ProcessPolicy, SandboxSpec,
};

#[test]
fn expanded_policy_round_trips_all_domains() {
    let policy = NetworkPolicy {
        network: NetworkAccessPolicy {
            reloadability: PolicyReloadability::HotReload,
            allow: vec![NetworkRule {
                target: NetworkTarget::Host {
                    host: "api.github.com".to_owned(),
                    port: Some(443),
                    scheme: Some("https".to_owned()),
                },
            }],
            deny: vec![NetworkRule {
                target: NetworkTarget::Cidr {
                    cidr: "10.0.0.0/8".to_owned(),
                },
            }],
            approval_required: vec![NetworkRule {
                target: NetworkTarget::HttpMethodPath {
                    host: Some("api.github.com".to_owned()),
                    method: "POST".to_owned(),
                    path: "/repos/*".to_owned(),
                },
            }],
        },
        filesystem: FilesystemPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            read_only: vec!["/usr".to_owned(), "/etc".to_owned()],
            read_write: vec!["/sandbox".to_owned(), "/tmp".to_owned()],
        },
        process: ProcessPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            run_as_user: "sandbox".to_owned(),
            run_as_group: "sandbox".to_owned(),
            profile: "restricted".to_owned(),
            allow_syscalls: Vec::new(),
            deny_syscalls: Vec::new(),
        },
        inference: InferencePolicy {
            reloadability: PolicyReloadability::HotReload,
            routes: vec![InferenceRoute {
                matcher: "default".to_owned(),
                provider: "openai".to_owned(),
                model: "gpt-5.4".to_owned(),
                base_url: None,
                timeout_seconds: Some(60),
            }],
        },
    };

    let policy_json = serde_json::to_value(&policy).expect("serialize policy");
    assert_eq!(policy_json["network"]["allow"][0]["target"]["kind"], "host");
    assert_eq!(
        policy_json["filesystem"]["reloadability"],
        "locked_at_create"
    );
    assert_eq!(policy_json["process"]["reloadability"], "locked_at_create");
    assert_eq!(policy_json["inference"]["routes"][0]["matcher"], "default");

    let policy_round_trip: NetworkPolicy =
        serde_json::from_value(policy_json).expect("round-trip policy");
    assert_eq!(policy_round_trip, policy);

    let spec = SandboxSpec {
        image: Some("ghcr.io/example/sandbox:latest".to_owned()),
        env: Default::default(),
        policy: Some(policy.clone()),
        metadata: Default::default(),
    };
    let params = ApplyPolicyParams {
        handle: "sb-123".to_owned(),
        policy,
    };

    let spec_round_trip: SandboxSpec =
        serde_json::from_value(serde_json::to_value(&spec).expect("serialize sandbox spec"))
            .expect("round-trip sandbox spec");
    assert_eq!(spec_round_trip, spec);

    let params_round_trip: ApplyPolicyParams =
        serde_json::from_value(serde_json::to_value(&params).expect("serialize params"))
            .expect("round-trip apply policy params");
    assert_eq!(params_round_trip, params);
}
