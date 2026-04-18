use agentenv_policy::{
    compose_policy, InferenceUpdate, OpenShellTranslator, PolicyError, PolicyTranslator,
    PresetRegistry, Tier,
};
use agentenv_proto::{
    FilesystemPolicy, InferencePolicy, InferenceRoute, NetworkAccessPolicy, NetworkPolicy,
    NetworkRule, NetworkTarget, PolicyReloadability, ProcessPolicy,
};

#[test]
fn openshell_translation_matches_the_golden_file_for_balanced_default_policy() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");

    let translated = translator().translate(&policy).expect("translate policy");

    assert_eq!(translated.format, "openshell");
    assert_eq!(
        translated.policy_yaml,
        include_str!("golden/openshell_balanced_default.yaml")
    );
    assert!(translated.inference_update.is_none());
}

#[test]
fn known_profile_labels_are_accepted_when_syscall_lists_are_empty() {
    for profile in ["restricted", "balanced", "open"] {
        let mut policy = supported_policy();
        policy.process.profile = profile.to_owned();

        translator()
            .translate(&policy)
            .unwrap_or_else(|err| panic!("profile {profile} should translate: {err}"));
    }
}

#[test]
fn unknown_process_profile_is_rejected() {
    let mut policy = supported_policy();
    policy.process.profile = "custom".to_owned();

    let err = translator()
        .translate(&policy)
        .expect_err("unknown process.profile should be rejected");

    assert_translation_unsupported(err, "unsupported process.profile");
}

#[test]
fn allow_syscalls_are_rejected() {
    let mut policy = supported_policy();
    policy.process.allow_syscalls.push("clone3".to_owned());

    let err = translator()
        .translate(&policy)
        .expect_err("allow_syscalls should be rejected");

    assert_translation_unsupported(err, "process.allow_syscalls");
}

#[test]
fn deny_syscalls_are_rejected() {
    let mut policy = supported_policy();
    policy.process.deny_syscalls.push("socket".to_owned());

    let err = translator()
        .translate(&policy)
        .expect_err("deny_syscalls should be rejected");

    assert_translation_unsupported(err, "process.deny_syscalls");
}

#[test]
fn deny_rules_are_rejected() {
    let mut policy = supported_policy();
    policy.network.deny.push(host_rule("api.github.com"));

    let err = translator()
        .translate(&policy)
        .expect_err("deny rules should be rejected");

    assert_translation_unsupported(err, "deny");
}

#[test]
fn approval_required_rule_without_host_is_rejected() {
    let mut policy = supported_policy();
    policy.network.approval_required.push(NetworkRule {
        target: NetworkTarget::HttpMethodPath {
            host: None,
            method: "POST".to_owned(),
            path: "/repos/*".to_owned(),
        },
    });

    let err = translator()
        .translate(&policy)
        .expect_err("hostless approval rule should be rejected");

    assert_translation_unsupported(err, "approval_required host");
}

#[test]
fn approval_required_rule_for_unknown_host_is_rejected() {
    let mut policy = supported_policy();
    policy.network.approval_required.push(NetworkRule {
        target: NetworkTarget::HttpMethodPath {
            host: Some("example.com".to_owned()),
            method: "POST".to_owned(),
            path: "/repos/*".to_owned(),
        },
    });

    let err = translator()
        .translate(&policy)
        .expect_err("approval rule for unknown host should be rejected");

    assert_translation_unsupported(err, "no matching allow host");
}

#[test]
fn host_rule_without_scheme_is_rejected() {
    let mut policy = supported_policy();
    policy.network.allow.push(NetworkRule {
        target: NetworkTarget::Host {
            host: "api.github.com".to_owned(),
            port: Some(443),
            scheme: None,
        },
    });

    let err = translator()
        .translate(&policy)
        .expect_err("scheme-less host should be rejected");

    assert_translation_unsupported(err, "unsupported host scheme");
}

#[test]
fn host_rule_with_non_443_port_is_rejected() {
    let mut policy = supported_policy();
    policy.network.allow.push(NetworkRule {
        target: NetworkTarget::Host {
            host: "api.github.com".to_owned(),
            port: Some(8443),
            scheme: Some("https".to_owned()),
        },
    });

    let err = translator()
        .translate(&policy)
        .expect_err("non-443 host should be rejected");

    assert_translation_unsupported(err, "unsupported host port");
}

#[test]
fn wildcard_host_rules_are_rejected() {
    let mut policy = supported_policy();
    policy.network.allow.push(NetworkRule {
        target: NetworkTarget::Host {
            host: "*".to_owned(),
            port: Some(443),
            scheme: Some("https".to_owned()),
        },
    });

    let err = translator()
        .translate(&policy)
        .expect_err("wildcard host rules should be rejected");

    assert_translation_unsupported(err, "unsupported wildcard host");
}

#[test]
fn inference_update_comes_from_the_first_route() {
    let mut policy = supported_policy();
    policy.inference.routes = vec![
        InferenceRoute {
            matcher: "default".to_owned(),
            provider: "openai".to_owned(),
            model: "gpt-5".to_owned(),
            base_url: Some("https://api.openai.com/v1".to_owned()),
            timeout_seconds: Some(30),
        },
        InferenceRoute {
            matcher: "fallback".to_owned(),
            provider: "anthropic".to_owned(),
            model: "claude-sonnet-4".to_owned(),
            base_url: None,
            timeout_seconds: Some(60),
        },
    ];

    let translated = translator().translate(&policy).expect("translate policy");

    assert_eq!(
        translated.inference_update,
        Some(InferenceUpdate {
            provider: "openai".to_owned(),
            model: "gpt-5".to_owned(),
            timeout_seconds: Some(30),
        })
    );
}

fn translator() -> OpenShellTranslator {
    OpenShellTranslator::new([
        "/usr/local/bin/claude",
        "/usr/local/bin/codex",
        "/usr/bin/curl",
    ])
}

fn supported_policy() -> NetworkPolicy {
    NetworkPolicy {
        network: NetworkAccessPolicy {
            reloadability: PolicyReloadability::HotReload,
            allow: vec![host_rule("api.github.com"), host_rule("github.com")],
            deny: Vec::new(),
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
            read_only: vec![
                "/etc".to_owned(),
                "/lib".to_owned(),
                "/usr".to_owned(),
                "/var/log".to_owned(),
            ],
            read_write: vec!["/sandbox".to_owned(), "/tmp".to_owned()],
        },
        process: ProcessPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            run_as_user: "sandbox".to_owned(),
            run_as_group: "sandbox".to_owned(),
            profile: "balanced".to_owned(),
            allow_syscalls: Vec::new(),
            deny_syscalls: Vec::new(),
        },
        inference: InferencePolicy {
            reloadability: PolicyReloadability::HotReload,
            routes: Vec::new(),
        },
    }
}

fn host_rule(host: &str) -> NetworkRule {
    NetworkRule {
        target: NetworkTarget::Host {
            host: host.to_owned(),
            port: Some(443),
            scheme: Some("https".to_owned()),
        },
    }
}

fn assert_translation_unsupported(err: PolicyError, expected_fragment: &str) {
    match err {
        PolicyError::TranslationUnsupported {
            translator,
            message,
        } => {
            assert_eq!(translator, "openshell");
            assert!(message.contains(expected_fragment), "{message}");
        }
        other => panic!("expected TranslationUnsupported, got {other:?}"),
    }
}
