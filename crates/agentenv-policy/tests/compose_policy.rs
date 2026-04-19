use agentenv_policy::{compose_policy, PresetRegistry, PresetSelection, Tier};
use agentenv_proto::{
    FilesystemPolicy, InferencePolicy, NetworkAccessPolicy, NetworkPolicy, NetworkRule,
    NetworkTarget, PolicyReloadability, ProcessPolicy,
};

#[test]
fn compose_policy_is_deterministic_for_balanced_and_github_read() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let presets = vec![PresetSelection::from_slug("github_read").unwrap()];

    let first = compose_policy(Tier::Balanced, &presets, None, &registry).expect("compose");
    let second = compose_policy(Tier::Balanced, &presets, None, &registry).expect("compose");

    assert_eq!(first, second);
    assert!(first.network.allow.iter().any(|rule| {
        matches!(
            rule.target,
            agentenv_proto::NetworkTarget::Host { ref host, .. } if host == "api.github.com"
        )
    }));
}

#[test]
fn unknown_presets_report_available_entries() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let err = compose_policy(
        Tier::Restricted,
        &[PresetSelection::from_slug("does_not_exist_read").unwrap()],
        None,
        &registry,
    )
    .expect_err("unknown preset should fail");

    assert!(err.to_string().contains("does_not_exist"));
    assert!(err.to_string().contains("github"));
}

#[test]
fn readwrite_presets_require_a_readwrite_block() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let err = compose_policy(
        Tier::Restricted,
        &[PresetSelection::from_slug("npm_readwrite").unwrap()],
        None,
        &registry,
    )
    .expect_err("missing readwrite block should fail");

    assert!(err.to_string().contains("npm"));
    assert!(err.to_string().contains("readwrite"));
}

#[test]
fn balanced_tier_includes_dev_tooling_defaults_without_messaging() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");

    assert!(has_host(&policy, "api.github.com"));
    assert!(has_host(&policy, "github.com"));
    assert!(has_host(&policy, "registry.npmjs.org"));
    assert!(has_host(&policy, "pypi.org"));
    assert!(has_host(&policy, "crates.io"));
    assert!(has_host(&policy, "registry-1.docker.io"));
    assert!(!has_host(&policy, "slack.com"));
    assert!(!has_host(&policy, "discord.com"));
    assert!(!has_host(&policy, "api.telegram.org"));
}

#[test]
fn balanced_tier_explicit_github_readwrite_supersedes_default_github_read() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let policy = compose_policy(
        Tier::Balanced,
        &[PresetSelection::from_slug("github_readwrite").unwrap()],
        None,
        &registry,
    )
    .expect("compose");

    assert!(has_host(&policy, "api.github.com"));
    assert!(!has_http_method_path(
        &policy,
        Some("api.github.com"),
        "POST",
        "/repos/*"
    ));
}

#[test]
fn network_overrides_replace_conflicting_baseline_rules() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let overrides = NetworkPolicy {
        network: NetworkAccessPolicy {
            reloadability: PolicyReloadability::HotReload,
            allow: Vec::new(),
            deny: vec![host_rule("api.github.com")],
            approval_required: Vec::new(),
        },
        ..empty_overrides()
    };

    let policy = compose_policy(
        Tier::Restricted,
        &[PresetSelection::from_slug("github_read").unwrap()],
        Some(overrides),
        &registry,
    )
    .expect("compose");

    assert!(!policy.network.allow.contains(&host_rule("api.github.com")));
    assert!(policy.network.deny.contains(&host_rule("api.github.com")));
}

#[test]
fn filesystem_overrides_replace_conflicting_baseline_paths() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let overrides = NetworkPolicy {
        filesystem: FilesystemPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            read_only: vec!["/tmp".to_owned()],
            read_write: Vec::new(),
        },
        ..empty_overrides()
    };

    let policy =
        compose_policy(Tier::Restricted, &[], Some(overrides), &registry).expect("compose");

    assert!(policy.filesystem.read_only.contains(&"/tmp".to_owned()));
    assert!(!policy.filesystem.read_write.contains(&"/tmp".to_owned()));
}

fn has_host(policy: &NetworkPolicy, host: &str) -> bool {
    policy.network.allow.iter().any(|rule| {
        matches!(
            rule.target,
            NetworkTarget::Host { host: ref rule_host, .. } if rule_host == host
        )
    })
}

fn has_http_method_path(
    policy: &NetworkPolicy,
    host: Option<&str>,
    method: &str,
    path: &str,
) -> bool {
    policy.network.approval_required.iter().any(|rule| {
        matches!(
            &rule.target,
            NetworkTarget::HttpMethodPath {
                host: rule_host,
                method: rule_method,
                path: rule_path,
            } if rule_host.as_deref() == host
                && rule_method == method
                && rule_path == path
        )
    })
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

fn empty_overrides() -> NetworkPolicy {
    NetworkPolicy {
        network: NetworkAccessPolicy {
            reloadability: PolicyReloadability::HotReload,
            allow: Vec::new(),
            deny: Vec::new(),
            approval_required: Vec::new(),
        },
        filesystem: FilesystemPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            read_only: Vec::new(),
            read_write: Vec::new(),
        },
        process: ProcessPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            run_as_user: String::new(),
            run_as_group: String::new(),
            profile: String::new(),
            allow_syscalls: Vec::new(),
            deny_syscalls: Vec::new(),
        },
        inference: InferencePolicy {
            reloadability: PolicyReloadability::HotReload,
            routes: Vec::new(),
        },
    }
}
