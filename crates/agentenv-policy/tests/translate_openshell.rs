use agentenv_policy::{
    compose_policy, InferenceUpdate, OpenShellTranslator, PolicyError, PolicyTranslator,
    PresetRegistry, Tier,
};
use agentenv_proto::{
    FilesystemPolicy, HttpAccessLevel, InferencePolicy, InferenceRoute, NetworkAccessPolicy,
    NetworkPolicy, NetworkRule, NetworkTarget, PolicyReloadability, ProcessPolicy,
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
fn open_tier_policy_is_rejected_by_current_openshell_subset() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let policy = compose_policy(Tier::Open, &[], None, &registry).expect("compose");

    let err = translator()
        .translate(&policy)
        .expect_err("open tier should not translate");

    assert_translation_unsupported(err, "unsupported wildcard host");
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
            http_access: None,
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
            http_access: None,
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
            http_access: None,
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

#[test]
fn compose_policy_preserves_inference_route_precedence_for_translation() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let overrides = NetworkPolicy {
        inference: InferencePolicy {
            reloadability: PolicyReloadability::HotReload,
            routes: vec![
                InferenceRoute {
                    matcher: "z-default".to_owned(),
                    provider: "openai".to_owned(),
                    model: "gpt-5".to_owned(),
                    base_url: Some("https://api.openai.com/v1".to_owned()),
                    timeout_seconds: Some(30),
                },
                InferenceRoute {
                    matcher: "a-fallback".to_owned(),
                    provider: "anthropic".to_owned(),
                    model: "claude-sonnet-4".to_owned(),
                    base_url: None,
                    timeout_seconds: Some(60),
                },
            ],
        },
        ..supported_policy()
    };

    let policy =
        compose_policy(Tier::Restricted, &[], Some(overrides), &registry).expect("compose");
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

#[test]
fn readwrite_presets_translate_to_read_write_access() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let policy = compose_policy(
        Tier::Restricted,
        &[agentenv_policy::PresetSelection::from_slug("github_readwrite").expect("parse preset")],
        None,
        &registry,
    )
    .expect("compose");

    let translated = translator().translate(&policy).expect("translate policy");

    assert_eq!(
        endpoint_access(&translated.policy_yaml, "api.github.com"),
        Some("read-write".to_owned())
    );
    assert_eq!(
        endpoint_access(&translated.policy_yaml, "github.com"),
        Some("read-write".to_owned())
    );
}

#[test]
fn openshell_translation_keeps_dns_upstreams_out_of_agent_visible_allow_rules() {
    let mut policy = supported_policy();
    policy.network.dns = agentenv_proto::DnsPolicy {
        resolvers_allowed: vec!["1.1.1.1".to_owned()],
        doh_upstreams_allowed: vec!["https://dns.google/dns-query".to_owned()],
        dot_upstreams_allowed: vec!["1.1.1.1:853".to_owned()],
        log_all_queries: true,
        pin_resolved_ips: true,
    };

    let translated = translator().translate(&policy).expect("translate policy");

    assert!(!translated.policy_yaml.contains("dns.google"));
    assert!(!translated.policy_yaml.contains("1.1.1.1"));
    assert_eq!(
        endpoint_access(&translated.policy_yaml, "api.github.com"),
        Some("read-only".to_owned())
    );
}

#[test]
fn persisted_home_marker_translates_to_absolute_sandbox_home() {
    let mut policy = supported_policy();
    policy.filesystem.read_write.push("$HOME".to_owned());

    let translated = translator().translate(&policy).expect("translate policy");
    let document: serde_yaml::Value =
        serde_yaml::from_str(&translated.policy_yaml).expect("parse policy yaml");
    let read_write = document["filesystem_policy"]["read_write"]
        .as_sequence()
        .expect("read_write sequence")
        .iter()
        .filter_map(serde_yaml::Value::as_str)
        .collect::<Vec<_>>();

    assert!(read_write.contains(&"/home/sandbox"));
    assert!(!read_write.contains(&"$HOME"));
}

#[test]
fn full_npm_registry_access_translates_to_l4_passthrough() {
    let mut policy = supported_policy();
    policy.network.allow = vec![NetworkRule {
        target: NetworkTarget::Host {
            host: "registry.npmjs.org".to_owned(),
            port: Some(443),
            scheme: Some("https".to_owned()),
            http_access: Some(HttpAccessLevel::Full),
        },
    }];
    policy.network.approval_required.clear();

    let translated = translator().translate(&policy).expect("translate policy");
    let endpoint = endpoint_for_host(&translated.policy_yaml, "registry.npmjs.org")
        .expect("npm endpoint should exist");

    assert!(endpoint.get("protocol").is_none());
    assert!(endpoint.get("enforcement").is_none());
    assert!(endpoint.get("access").is_none());
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
            dns: agentenv_proto::DnsPolicy::default(),
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
            http_access: None,
        },
    }
}

fn endpoint_access(policy_yaml: &str, host: &str) -> Option<String> {
    endpoint_for_host(policy_yaml, host)
        .and_then(|endpoint| endpoint["access"].as_str().map(ToOwned::to_owned))
}

fn endpoint_for_host(policy_yaml: &str, host: &str) -> Option<serde_yaml::Mapping> {
    let document: serde_yaml::Value = serde_yaml::from_str(policy_yaml).expect("parse yaml");
    let policies = document["network_policies"]
        .as_mapping()
        .expect("network_policies mapping");

    for policy in policies.values() {
        let endpoints = policy["endpoints"]
            .as_sequence()
            .expect("endpoints sequence");
        for endpoint in endpoints {
            if endpoint["host"].as_str() == Some(host) {
                return endpoint.as_mapping().cloned();
            }
        }
    }

    None
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
