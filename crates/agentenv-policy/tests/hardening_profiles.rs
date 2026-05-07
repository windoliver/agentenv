use std::{
    fs,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use agentenv_policy::{
    apply_hardening_to_policy, builtin_hardening_profile, compose_policy, hardening_metadata,
    resolve_hardening_profile, HardeningProfile, HardeningUlimits, PresetRegistry, Tier,
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
fn minimal_custom_profile_uses_empty_defaults() {
    let profile = HardeningProfile::from_yaml(
        "minimal",
        r#"
name: minimal
description: Minimal custom profile for tests.
dockerfile:
  marker: AGENTENV_HARDENING_PROFILE=minimal
  fragment: |
    RUN true
"#,
    )
    .expect("minimal profile should parse");

    assert!(profile.packages.strip.is_empty());
    assert!(profile.mounts.read_only.is_empty());
    assert!(profile.mounts.read_write.is_empty());
    assert!(profile.mounts.tmpfs.is_empty());
    assert_eq!(profile.ulimits.nproc, None);
    assert_eq!(profile.ulimits.nofile, None);
    assert!(profile.capabilities.drop.is_empty());
    assert!(!profile.disable_core_dumps);
    assert!(!profile.disable_user_namespaces);
}

#[test]
fn resolve_hardening_profile_loads_env_dir_yaml_name() {
    let _guard = env_mutex().lock().expect("env mutex");
    let dir = temp_profile_path("env-dir");
    fs::create_dir_all(&dir).expect("create temp profile dir");
    fs::write(
        dir.join("env-custom.yaml"),
        r#"
name: env-custom
description: Env dir custom profile for tests.
dockerfile:
  marker: AGENTENV_HARDENING_PROFILE=env-custom
  fragment: |
    RUN true
"#,
    )
    .expect("write env profile");

    let _env_guard = EnvVarGuard::set("AGENTENV_HARDENING_PROFILE_DIR", &dir);

    let resolved = resolve_hardening_profile("env-custom");
    fs::remove_dir_all(dir).expect("remove temp profile dir");

    let profile = resolved.expect("resolve env profile");
    assert_eq!(profile.name, "env-custom");
}

#[test]
fn invalid_profile_rejects_non_absolute_filesystem_paths() {
    for (field, path) in [
        ("read_only", "relative"),
        ("read_only", ""),
        ("read_write", "relative"),
        ("read_write", ""),
    ] {
        let yaml = format!(
            r#"
name: bad-path
description: Bad filesystem path profile for tests.
mounts:
  {field}:
    - "{path}"
dockerfile:
  marker: AGENTENV_HARDENING_PROFILE=bad-path
  fragment: |
    RUN true
"#
        );

        let err = HardeningProfile::from_yaml("bad-path", &yaml)
            .expect_err("relative or empty path should fail");
        let message = err.to_string();

        assert!(message.contains(field));
        assert!(message.contains("path"));
        assert!(message.contains("absolute") || message.contains("non-empty"));
    }
}

#[test]
fn invalid_profile_rejects_unknown_nested_fields() {
    let err = HardeningProfile::from_yaml(
        "bad-field",
        r#"
name: bad-field
description: Misspelled field profile for tests.
mounts:
  readwrite:
    - /tmp
dockerfile:
  marker: AGENTENV_HARDENING_PROFILE=bad-field
  fragment: |
    RUN true
"#,
    )
    .expect_err("unknown field should fail");

    let message = err.to_string();
    assert!(message.contains("unknown field"));
    assert!(message.contains("readwrite"));
}

#[test]
fn invalid_profile_rejects_empty_or_whitespace_capability_drops() {
    for capability in ["", "SYS ADMIN"] {
        let yaml = format!(
            r#"
name: bad-capability
description: Bad capability profile for tests.
capabilities:
  drop:
    - "{capability}"
dockerfile:
  marker: AGENTENV_HARDENING_PROFILE=bad-capability
  fragment: |
    RUN true
"#
        );

        let err = HardeningProfile::from_yaml("bad-capability", &yaml)
            .expect_err("invalid capability should fail");
        let message = err.to_string();

        assert!(message.contains("capabilities.drop"));
        assert!(message.contains("non-empty"));
        assert!(message.contains("whitespace"));
    }
}

#[test]
fn hardening_merge_rejects_directly_constructed_invalid_filesystem_paths() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let mut policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");
    let mut profile = builtin_hardening_profile("open").expect("load open");
    profile.mounts.read_write = vec!["relative".to_owned()];
    profile.ulimits = HardeningUlimits::default();

    let err = apply_hardening_to_policy(&mut policy, &profile, false)
        .expect_err("apply should validate directly constructed profile");
    let message = err.to_string();

    assert!(message.contains("read_write"));
    assert!(message.contains("path"));
    assert!(message.contains("absolute"));
    assert!(!policy
        .filesystem
        .read_write
        .contains(&"relative".to_owned()));
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
    assert_eq!(metadata["hardening_ulimit_nofile"], 4096);
    assert_eq!(metadata["hardening_disable_core_dumps"], true);
    assert!(metadata["hardening_packages_strip"]
        .as_array()
        .expect("strip array")
        .contains(&serde_json::Value::String("curl".to_owned())));

    let open = builtin_hardening_profile("open").expect("load open");
    let open_metadata = hardening_metadata(&open).expect("metadata");

    assert_eq!(
        open_metadata["hardening_ulimit_nproc"],
        serde_json::Value::Null
    );
    assert_eq!(
        open_metadata["hardening_ulimit_nofile"],
        serde_json::Value::Null
    );
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

fn env_mutex() -> &'static Mutex<()> {
    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_MUTEX.get_or_init(|| Mutex::new(()))
}

struct EnvVarGuard {
    name: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = std::env::var_os(name);
        // SAFETY: callers hold env_mutex while this guard is live, serializing
        // mutation of the process environment for this test.
        unsafe {
            std::env::set_var(name, value);
        }
        Self { name, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // SAFETY: callers hold env_mutex while this guard is live, serializing
        // mutation of the process environment for this test.
        unsafe {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.name, previous);
            } else {
                std::env::remove_var(self.name);
            }
        }
    }
}
