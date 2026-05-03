use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use agentenv_policy::{
    apply_hardening_to_policy, builtin_hardening_profile, compose_policy, hardening_metadata,
    resolve_hardening_profile, HardeningProfile, PresetRegistry, Tier,
};

#[test]
fn built_in_hardening_profiles_parse_and_differ() {
    let baseline = builtin_hardening_profile("baseline").expect("load baseline");
    let strict = builtin_hardening_profile("strict").expect("load strict");
    let open = builtin_hardening_profile("open").expect("load open");

    assert!(baseline.packages.strip.contains(&"gcc".to_owned()));
    assert!(strict.packages.strip.contains(&"curl".to_owned()));
    assert!(!open.packages.strip.contains(&"gcc".to_owned()));

    assert_eq!(baseline.ulimits.nproc, Some(512));
    assert_eq!(baseline.ulimits.nofile, Some(4096));
    assert!(strict.disable_core_dumps);
    assert!(strict.disable_user_namespaces);

    assert!(baseline.dockerfile.marker.contains("baseline"));
    assert!(strict.dockerfile.marker.contains("strict"));
    assert!(open.dockerfile.marker.contains("open"));
}

#[test]
fn unknown_hardening_profile_reports_available_names() {
    let err = builtin_hardening_profile("unknown").expect_err("unknown profile should fail");
    let message = err.to_string();

    assert!(message.contains("unknown"));
    assert!(message.contains("baseline"));
    assert!(message.contains("strict"));
    assert!(message.contains("open"));
}

#[test]
fn resolve_hardening_profile_loads_custom_yaml_path() {
    let path = temp_profile_path("custom-profile.yaml");
    fs::write(
        &path,
        r#"
name: custom
description: Custom profile for tests.
packages:
  strip: []
mounts:
  read_only: []
  read_write: []
  tmpfs:
    - path: /cache
      size: 64m
ulimits: {}
capabilities:
  drop: []
dockerfile:
  marker: AGENTENV_HARDENING_PROFILE=custom
  fragment: |
    RUN true
disable_core_dumps: false
disable_user_namespaces: false
"#,
    )
    .expect("write temp profile");

    let profile = resolve_hardening_profile(path.to_str().expect("utf-8 path")).expect("resolve");

    assert_eq!(profile.name, "custom");
    assert_eq!(profile.mounts.tmpfs[0].path, "/cache");
    assert_eq!(profile.mounts.tmpfs[0].size.as_deref(), Some("64m"));

    fs::remove_file(path).expect("remove temp profile");
}

#[test]
fn hardening_merge_updates_filesystem_policy_and_persisted_home() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let mut policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");
    let baseline = builtin_hardening_profile("baseline").expect("load baseline");

    apply_hardening_to_policy(&mut policy, &baseline, true).expect("apply hardening");

    assert!(policy.filesystem.read_only.contains(&"/etc".to_owned()));
    assert!(policy.filesystem.read_only.contains(&"/opt".to_owned()));
    assert!(policy
        .filesystem
        .read_write
        .contains(&"/workspace".to_owned()));
    assert!(policy.filesystem.read_write.contains(&"/tmp".to_owned()));
    assert!(policy
        .filesystem
        .read_write
        .contains(&"/var/tmp".to_owned()));
    assert!(policy.filesystem.read_write.contains(&"$HOME".to_owned()));
}

#[test]
fn hardening_metadata_is_stable_json() {
    let strict = builtin_hardening_profile("strict").expect("load strict");
    let metadata = hardening_metadata(&strict).expect("metadata");

    assert_eq!(metadata["hardening_profile"], "strict");
    assert_eq!(metadata["hardening_ulimit_nproc"], 512);
    assert_eq!(metadata["hardening_disable_core_dumps"], true);
    assert!(metadata["hardening_packages_strip"]
        .as_array()
        .expect("strip array")
        .contains(&serde_json::Value::String("curl".to_owned())));
}

#[test]
fn invalid_profile_rejects_non_positive_ulimits() {
    let err = HardeningProfile::from_yaml(
        "bad",
        r#"
name: bad
description: Bad profile for tests.
packages:
  strip: []
mounts:
  read_only: []
  read_write: []
  tmpfs: []
ulimits:
  nproc: 0
capabilities:
  drop: []
dockerfile:
  marker: AGENTENV_HARDENING_PROFILE=bad
  fragment: |
    RUN true
disable_core_dumps: false
disable_user_namespaces: false
"#,
    )
    .expect_err("non-positive ulimit should fail");

    let message = err.to_string();
    assert!(message.contains("nproc"));
    assert!(message.contains("positive"));
}

fn temp_profile_path(name: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("agentenv-policy-{unique}-{name}"))
}
