use agentenv_policy::{
    compose_policy, OpenShellTranslator, PolicyTranslator, PresetRegistry, PresetSelection, Tier,
};

#[test]
fn openshell_translation_matches_the_golden_file() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let policy = compose_policy(
        Tier::Balanced,
        &[PresetSelection::from_slug("github_readwrite").unwrap()],
        None,
        &registry,
    )
    .expect("compose");

    let translator = OpenShellTranslator;
    let translated = translator.translate(&policy).expect("translate policy");

    assert_eq!(translated.format, "openshell");
    assert_eq!(
        translated.policy_yaml,
        include_str!("golden/openshell_balanced_github_readwrite.yaml")
    );
    assert!(translated.inference_update.is_none());
}
