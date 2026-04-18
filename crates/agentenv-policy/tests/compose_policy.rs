use agentenv_policy::{compose_policy, PresetRegistry, PresetSelection, Tier};

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
