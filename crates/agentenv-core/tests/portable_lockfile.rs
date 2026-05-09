use agentenv_core::{
    driver_artifact::DriverArtifact,
    driver_catalog::DriverSource,
    lockfile::{DriverSourcePin, LockfileDocument, SkillPin},
    portable_lockfile::{
        build_portable_lockfile, verify_portable_lockfile_yaml, PortableLockfileError,
        PortableLockfileInput, PortableVerifyIssueKind,
    },
    registry::DriverKind,
};
use agentenv_proto::{NetworkTarget, SCHEMA_VERSION};
use semver::Version;
use sha2::{Digest, Sha256};

#[test]
fn portable_lockfile_builder_is_byte_identical_for_repeated_calls() {
    let yaml = reference_yaml();
    let artifacts = built_in_artifacts();
    let input = PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: yaml.clone(),
        driver_artifacts: artifacts.clone(),
    };

    let first = build_portable_lockfile(input.clone())
        .expect("build first lockfile")
        .to_yaml_deterministic()
        .expect("render first lockfile");
    let second = build_portable_lockfile(input)
        .expect("build second lockfile")
        .to_yaml_deterministic()
        .expect("render second lockfile");

    assert_eq!(first, second);
    assert!(first.contains("version: 0.2.0"));
    let expected_single_quoted = format!("driver_protocol_version: '{SCHEMA_VERSION}'");
    let expected_double_quoted = format!("driver_protocol_version: \"{SCHEMA_VERSION}\"");
    assert!(
        first.contains(&expected_single_quoted) || first.contains(&expected_double_quoted),
        "lockfile should include current driver protocol version {SCHEMA_VERSION}: {first}"
    );
    assert!(!first.contains("sk-known-secret"));
}

#[test]
fn portable_lockfile_builder_records_resolved_policy_and_driver_sources() {
    let lockfile = build_portable_lockfile(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: reference_yaml(),
        driver_artifacts: built_in_artifacts(),
    })
    .expect("build lockfile");

    assert_eq!(lockfile.policy.declared.tier, "balanced");
    assert!(!lockfile.policy.resolved.filesystem.read_write.is_empty());
    assert_eq!(lockfile.drivers["agent"].source, DriverSourcePin::BuiltIn);
    assert_eq!(
        lockfile.drivers["agent"].digest,
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    assert_eq!(
        lockfile.credentials["OPENAI_API_KEY"].reference.as_deref(),
        Some("OPENAI_API_KEY")
    );
}

#[test]
fn portable_lockfile_builder_applies_declared_policy_overrides() {
    let lockfile = build_portable_lockfile(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: override_yaml(),
        driver_artifacts: built_in_artifacts(),
    })
    .expect("build lockfile");

    assert!(lockfile.policy.declared.overrides.iter().any(|item| {
        item.allow.as_deref() == Some("https://example.com:8443")
            && item.deny.as_deref() == Some("blocked.internal")
            && item.approval.as_deref() == Some("https://example.com/path")
    }));
    assert!(lockfile.policy.resolved.network.allow.iter().any(|rule| {
        matches!(
            &rule.target,
            NetworkTarget::Host {
                host,
                port: Some(8443),
                scheme: Some(scheme),
                ..
            } if host == "example.com" && scheme == "https"
        )
    }));
    assert!(lockfile.policy.resolved.network.deny.iter().any(|rule| {
        matches!(
            &rule.target,
            NetworkTarget::UrlPattern { pattern } if pattern == "blocked.internal"
        )
    }));
    assert!(lockfile
        .policy
        .resolved
        .network
        .approval_required
        .iter()
        .any(|rule| {
            matches!(
                &rule.target,
                NetworkTarget::HttpMethodPath {
                    host: Some(host),
                    method,
                    path,
                } if host == "example.com" && method == "*" && path == "/path"
            )
        }));
}

#[test]
fn portable_lockfile_builder_preserves_explicit_image_artifacts() {
    let lockfile = build_portable_lockfile(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: image_yaml(),
        driver_artifacts: built_in_artifacts(),
    })
    .expect("build lockfile");

    assert_eq!(
        lockfile.artifacts["sandbox-image"],
        "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    );
}

#[test]
fn portable_lockfile_builder_reports_missing_driver_artifact() {
    let error = build_portable_lockfile(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: reference_yaml(),
        driver_artifacts: built_in_artifacts()
            .into_iter()
            .filter(|artifact| artifact.kind != DriverKind::Agent)
            .collect(),
    })
    .expect_err("missing artifact should fail");

    assert!(matches!(
        error,
        PortableLockfileError::MissingDriverArtifact {
            kind: DriverKind::Agent,
            ref name,
            ref version,
        } if name == "codex" && version == env!("CARGO_PKG_VERSION")
    ));
    assert!(error
        .to_string()
        .contains("missing artifact for agent driver `codex`"));
}

#[test]
fn portable_lockfile_builder_resolves_external_driver_from_artifacts() {
    let lockfile = build_portable_lockfile(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: external_context_yaml(),
        driver_artifacts: artifacts_with_external_context(),
    })
    .expect("build lockfile with external context driver");

    assert_eq!(lockfile.composition.context.driver, "demo-context");
    assert_eq!(lockfile.composition.context.version, "1.2.3");
    assert_eq!(
        lockfile.drivers["context"].source,
        DriverSourcePin::Installed
    );
    assert_eq!(
        lockfile.drivers["context"].digest,
        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    );
}

#[test]
fn portable_lockfile_builder_rejects_ambiguous_driver_artifacts() {
    let mut artifacts = built_in_artifacts();
    artifacts.push(DriverArtifact {
        kind: DriverKind::Agent,
        name: "codex".to_owned(),
        version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version is semver"),
        source: DriverSource::InstalledSubprocess,
        digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            .to_owned(),
        install_hint: Some("/tmp/demo-driver".to_owned()),
        entry: None,
    });

    let error = build_portable_lockfile(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: reference_yaml(),
        driver_artifacts: artifacts,
    })
    .expect_err("ambiguous artifacts should fail");

    assert!(matches!(
        error,
        PortableLockfileError::AmbiguousDriverArtifact {
            kind: DriverKind::Agent,
            ref name,
            ref version,
        } if name == "codex" && version == env!("CARGO_PKG_VERSION")
    ));
    assert!(error
        .to_string()
        .contains("ambiguous artifacts for agent driver `codex`"));
}

#[test]
fn portable_lockfile_document_round_trips_builder_output() {
    let rendered = build_portable_lockfile(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: reference_yaml(),
        driver_artifacts: built_in_artifacts(),
    })
    .expect("build lockfile")
    .to_yaml_deterministic()
    .expect("render lockfile");

    let parsed = LockfileDocument::from_yaml(&rendered).expect("parse rendered lockfile");
    assert!(matches!(parsed, LockfileDocument::Portable(_)));
}

#[test]
fn portable_lockfile_serializes_skill_pins_deterministically() {
    let mut lockfile = reference_portable_lockfile();
    lockfile.skills = vec![
        SkillPin {
            name: "zeta".to_owned(),
            version: "2.0.0".to_owned(),
            source: "file:///skills/zeta".to_owned(),
            digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
            signatures: Vec::new(),
        },
        SkillPin {
            name: "alpha".to_owned(),
            version: "1.0.0".to_owned(),
            source: "oci://ghcr.io/agentenv-community/alpha:1.0.0".to_owned(),
            digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            signatures: vec!["ed25519:test-key:cccc".to_owned()],
        },
    ];

    let rendered = lockfile.to_yaml_deterministic().expect("render lockfile");
    let alpha_index = rendered.find("name: alpha").expect("alpha skill rendered");
    let zeta_index = rendered.find("name: zeta").expect("zeta skill rendered");
    assert!(
        alpha_index < zeta_index,
        "skills should serialize sorted: {rendered}"
    );
    assert!(rendered.contains("skills:"));
    assert!(rendered.contains("ed25519:test-key:cccc"));

    let reparsed = LockfileDocument::from_yaml(&rendered).expect("parse rendered lockfile");
    let LockfileDocument::Portable(reparsed) = reparsed else {
        panic!("expected portable lockfile");
    };
    assert_eq!(reparsed.skills[0].name, "alpha");
    assert_eq!(reparsed.skills[1].name, "zeta");
}

#[test]
fn portable_lockfile_rejects_duplicate_skill_pins() {
    let mut lockfile = reference_portable_lockfile();
    lockfile.skills = vec![
        SkillPin {
            name: "code-review".to_owned(),
            version: "1.2.0".to_owned(),
            source: "file:///skills/code-review".to_owned(),
            digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            signatures: Vec::new(),
        },
        SkillPin {
            name: "code-review".to_owned(),
            version: "1.2.0".to_owned(),
            source: "file:///skills/code-review".to_owned(),
            digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
            signatures: Vec::new(),
        },
    ];

    let err = lockfile
        .to_yaml_deterministic()
        .expect_err("duplicate skill pin should fail validation");
    assert!(err.to_string().contains("duplicate skill pin"));
}

#[test]
fn portable_lockfile_verify_reports_missing_driver_artifact() {
    let rendered = reference_portable_lockfile_yaml();
    let report = verify_portable_lockfile_yaml(
        &rendered,
        &built_in_artifacts()
            .into_iter()
            .filter(|artifact| artifact.kind != DriverKind::Agent)
            .collect::<Vec<_>>(),
    )
    .expect("verify portable lockfile");

    assert!(!report.is_ok());
    assert!(report.errors.iter().any(|issue| {
        issue.kind == PortableVerifyIssueKind::MissingDriverArtifact
            && issue.role.as_deref() == Some("agent")
    }));
    assert!(report.warnings.is_empty());
}

#[test]
fn portable_lockfile_verify_reports_driver_digest_mismatch() {
    let rendered = reference_portable_lockfile_yaml();
    let mut artifacts = built_in_artifacts();
    let agent_artifact = artifacts
        .iter_mut()
        .find(|artifact| artifact.kind == DriverKind::Agent)
        .expect("agent artifact");
    agent_artifact.digest =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();

    let report =
        verify_portable_lockfile_yaml(&rendered, &artifacts).expect("verify portable lockfile");

    assert!(!report.is_ok());
    assert!(report.errors.iter().any(|issue| {
        issue.kind == PortableVerifyIssueKind::DriverDigestMismatch
            && issue.role.as_deref() == Some("agent")
    }));
}

#[test]
fn portable_lockfile_verify_rejects_driver_pin_that_disagrees_with_composition() {
    let mut lockfile = reference_portable_lockfile();
    let mut artifacts = built_in_artifacts();
    artifacts.push(DriverArtifact {
        kind: DriverKind::Agent,
        name: "claude".to_owned(),
        version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version is semver"),
        source: DriverSource::BuiltIn,
        digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333"
            .to_owned(),
        install_hint: None,
        entry: None,
    });

    let pin = lockfile.drivers.get_mut("agent").expect("agent pin exists");
    pin.name = "claude".to_owned();
    pin.digest =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333".to_owned();

    let rendered = lockfile
        .to_yaml_deterministic()
        .expect("render tampered lockfile");
    let report =
        verify_portable_lockfile_yaml(&rendered, &artifacts).expect("verify portable lockfile");

    assert!(!report.is_ok());
    assert!(report.errors.iter().any(|issue| {
        issue.kind == PortableVerifyIssueKind::DriverPinMismatch
            && issue.role.as_deref() == Some("agent")
    }));
}

#[test]
fn portable_lockfile_verify_rejects_unexpected_driver_role() {
    let mut lockfile = reference_portable_lockfile();
    let agent_pin = lockfile.drivers["agent"].clone();
    lockfile.drivers.insert("extra".to_owned(), agent_pin);

    let rendered = lockfile
        .to_yaml_deterministic()
        .expect("render tampered lockfile");
    let report = verify_portable_lockfile_yaml(&rendered, &built_in_artifacts())
        .expect("verify portable lockfile");

    assert!(!report.is_ok());
    assert!(report.errors.iter().any(|issue| {
        issue.kind == PortableVerifyIssueKind::DriverPinMismatch
            && issue.role.as_deref() == Some("extra")
    }));
}

#[test]
fn portable_lockfile_verify_rejects_unexpected_inference_pin() {
    let mut lockfile = build_portable_lockfile(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: no_inference_yaml(),
        driver_artifacts: built_in_artifacts(),
    })
    .expect("build lockfile");
    let inference_pin = reference_portable_lockfile().drivers["inference"].clone();
    assert!(lockfile.composition.inference.is_none());
    lockfile
        .drivers
        .insert("inference".to_owned(), inference_pin);

    let rendered = lockfile
        .to_yaml_deterministic()
        .expect("render tampered lockfile");
    let report = verify_portable_lockfile_yaml(&rendered, &built_in_artifacts())
        .expect("verify portable lockfile");

    assert!(!report.is_ok());
    assert!(report.errors.iter().any(|issue| {
        issue.kind == PortableVerifyIssueKind::DriverPinMismatch
            && issue.role.as_deref() == Some("inference")
    }));
}

#[test]
fn portable_lockfile_verify_reports_successful_verification() {
    let rendered = reference_portable_lockfile_yaml();
    let report = verify_portable_lockfile_yaml(&rendered, &built_in_artifacts())
        .expect("verify portable lockfile");

    assert!(report.is_ok());
    assert!(report.errors.is_empty());
    assert!(report.warnings.is_empty());
}

#[test]
fn portable_lockfile_verify_reports_blueprint_hash_mismatch() {
    let lockfile = reference_portable_lockfile();
    let rendered = lockfile
        .to_yaml_deterministic()
        .expect("render portable lockfile")
        .replace(
            &format!("blueprint_hash: {}", lockfile.blueprint_hash),
            "blueprint_hash: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );

    let report = verify_portable_lockfile_yaml(&rendered, &built_in_artifacts())
        .expect("verify portable lockfile");

    assert!(!report.is_ok());
    assert!(report.errors.iter().any(|issue| {
        issue.kind == PortableVerifyIssueKind::BlueprintHashMismatch && issue.role.is_none()
    }));
}

#[test]
fn portable_lockfile_verify_rejects_invalid_composition() {
    let mut lockfile = reference_portable_lockfile();
    lockfile.composition.context.extra.insert(
        "hub_url".to_owned(),
        serde_yaml::Value::String("http://169.254.169.254/latest".to_owned()),
    );
    lockfile.blueprint_hash = portable_blueprint_hash_for_test(&lockfile.composition);
    let rendered = lockfile
        .to_yaml_deterministic()
        .expect("render tampered lockfile");

    let report = verify_portable_lockfile_yaml(&rendered, &built_in_artifacts())
        .expect("verify portable lockfile");

    assert!(!report.is_ok());
    assert!(report.errors.iter().any(|issue| {
        issue.role.is_none() && issue.message.contains("portable composition is invalid")
    }));
}

#[test]
fn portable_lockfile_parse_rejects_unknown_resolved_policy_field() {
    let rendered = reference_portable_lockfile_yaml().replace(
        "network:\n      reloadability: hot_reload",
        "network:\n      reloadability: hot_reload\n      unexpected: true",
    );

    let error = LockfileDocument::from_yaml(&rendered)
        .expect_err("unknown resolved policy fields should be rejected");

    assert!(
        error.to_string().contains("unknown field")
            || error
                .to_string()
                .contains("unexpected resolved policy field"),
        "unexpected error: {error}"
    );
}

#[test]
fn portable_lockfile_verify_rejects_artifact_map_mismatch() {
    let mut lockfile = build_portable_lockfile(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: image_yaml(),
        driver_artifacts: built_in_artifacts(),
    })
    .expect("build image lockfile");
    lockfile.artifacts.clear();
    let rendered = lockfile
        .to_yaml_deterministic()
        .expect("render tampered lockfile");

    let report = verify_portable_lockfile_yaml(&rendered, &built_in_artifacts())
        .expect("verify portable lockfile");

    assert!(!report.is_ok());
    assert!(report.errors.iter().any(|issue| {
        issue.role.is_none()
            && issue
                .message
                .contains("artifact map does not match composition")
    }));
}

#[test]
fn portable_lockfile_verify_rejects_credential_map_mismatch() {
    let mut lockfile = reference_portable_lockfile();
    lockfile.credentials.clear();
    let rendered = lockfile
        .to_yaml_deterministic()
        .expect("render tampered lockfile");

    let report = verify_portable_lockfile_yaml(&rendered, &built_in_artifacts())
        .expect("verify portable lockfile");

    assert!(!report.is_ok());
    assert!(report.errors.iter().any(|issue| {
        issue.role.is_none()
            && issue
                .message
                .contains("credential map does not match composition")
    }));

    let mut lockfile = reference_portable_lockfile();
    lockfile
        .credentials
        .get_mut("OPENAI_API_KEY")
        .expect("top-level credential")
        .reference = Some("OTHER_OPENAI_API_KEY".to_owned());
    let rendered = lockfile
        .to_yaml_deterministic()
        .expect("render tampered lockfile");
    let report = verify_portable_lockfile_yaml(&rendered, &built_in_artifacts())
        .expect("verify portable lockfile");

    assert!(!report.is_ok());
    assert!(report.errors.iter().any(|issue| {
        issue.role.is_none()
            && issue
                .message
                .contains("credential map does not match composition")
    }));
}

#[test]
fn portable_lockfile_verify_rejects_policy_declared_composition_mismatch() {
    let mut lockfile = build_portable_lockfile(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: no_inference_yaml(),
        driver_artifacts: built_in_artifacts(),
    })
    .expect("build restricted lockfile");
    let open_lockfile = build_portable_lockfile(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: open_policy_yaml(),
        driver_artifacts: built_in_artifacts(),
    })
    .expect("build open lockfile");
    lockfile.policy = open_lockfile.policy;
    let rendered = lockfile
        .to_yaml_deterministic()
        .expect("render tampered lockfile");

    let report = verify_portable_lockfile_yaml(&rendered, &built_in_artifacts())
        .expect("verify portable lockfile");

    assert!(!report.is_ok());
    assert!(report.errors.iter().any(|issue| {
        issue.role.is_none()
            && issue
                .message
                .contains("policy.declared does not match composition.policy")
    }));
}

#[test]
fn portable_lockfile_verify_reports_policy_drift_as_warning() {
    let mut lockfile = reference_portable_lockfile();
    lockfile
        .policy
        .resolved
        .network
        .allow
        .push(agentenv_proto::NetworkRule {
            target: NetworkTarget::Host {
                host: "pinned-drift.example".to_owned(),
                port: Some(443),
                scheme: Some("https".to_owned()),
                http_access: None,
            },
        });
    let rendered = lockfile
        .to_yaml_deterministic()
        .expect("render drifted lockfile");

    let report = verify_portable_lockfile_yaml(&rendered, &built_in_artifacts())
        .expect("verify portable lockfile");

    assert!(report.errors.is_empty());
    assert!(report.is_ok());
    assert!(!report.warnings.is_empty());
    assert!(report.warnings.iter().any(|issue| {
        issue.kind == PortableVerifyIssueKind::PolicyDrift && issue.role.is_none()
    }));
}

#[test]
fn portable_lockfile_verify_reports_legacy_lockfile_warning() {
    let report = verify_portable_lockfile_yaml(&legacy_lockfile_yaml(), &built_in_artifacts())
        .expect("verify legacy lockfile");

    assert!(report.errors.is_empty());
    assert!(report.is_ok());
    assert!(!report.warnings.is_empty());
    assert!(report.warnings.iter().any(|issue| {
        issue.kind == PortableVerifyIssueKind::LegacyLockfile && issue.role.is_none()
    }));
}

fn reference_portable_lockfile() -> agentenv_core::lockfile::PortableLockfile {
    build_portable_lockfile(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: reference_yaml(),
        driver_artifacts: built_in_artifacts(),
    })
    .expect("build lockfile")
}

fn reference_portable_lockfile_yaml() -> String {
    reference_portable_lockfile()
        .to_yaml_deterministic()
        .expect("render lockfile")
}

fn portable_blueprint_hash_for_test(
    composition: &agentenv_core::lockfile::PortableComposition,
) -> String {
    let value = serde_yaml::to_value(composition).expect("serialize composition");
    let rendered =
        serde_yaml::to_string(&canonicalize_yaml_value_for_test(value)).expect("render yaml");
    let digest = Sha256::digest(rendered.as_bytes());
    hex::encode(digest)
}

fn canonicalize_yaml_value_for_test(value: serde_yaml::Value) -> serde_yaml::Value {
    match value {
        serde_yaml::Value::Sequence(items) => serde_yaml::Value::Sequence(
            items
                .into_iter()
                .map(canonicalize_yaml_value_for_test)
                .collect::<Vec<_>>(),
        ),
        serde_yaml::Value::Mapping(map) => {
            let mut entries = map
                .into_iter()
                .map(|(key, value)| {
                    (
                        canonicalize_yaml_value_for_test(key),
                        canonicalize_yaml_value_for_test(value),
                    )
                })
                .collect::<Vec<_>>();
            entries.sort_by(|(left_key, _), (right_key, _)| {
                canonical_yaml_sort_key_for_test(left_key)
                    .cmp(&canonical_yaml_sort_key_for_test(right_key))
            });

            let mut canonical = serde_yaml::Mapping::new();
            for (key, value) in entries {
                canonical.insert(key, value);
            }
            serde_yaml::Value::Mapping(canonical)
        }
        serde_yaml::Value::Tagged(tagged) => {
            serde_yaml::Value::Tagged(Box::new(serde_yaml::value::TaggedValue {
                tag: tagged.tag,
                value: canonicalize_yaml_value_for_test(tagged.value),
            }))
        }
        other => other,
    }
}

fn canonical_yaml_sort_key_for_test(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::Null => "n:null".to_owned(),
        serde_yaml::Value::Bool(boolean) => format!("b:{boolean}"),
        serde_yaml::Value::Number(number) => format!("d:{number}"),
        serde_yaml::Value::String(string) => format!("s:{string}"),
        serde_yaml::Value::Sequence(items) => {
            let mut rendered = String::from("q:[");
            for item in items {
                rendered.push_str(&canonical_yaml_sort_key_for_test(item));
                rendered.push(',');
            }
            rendered.push(']');
            rendered
        }
        serde_yaml::Value::Mapping(map) => {
            let mut rendered = String::from("m:{");
            for (key, value) in map {
                rendered.push_str(&canonical_yaml_sort_key_for_test(key));
                rendered.push('=');
                rendered.push_str(&canonical_yaml_sort_key_for_test(value));
                rendered.push(',');
            }
            rendered.push('}');
            rendered
        }
        serde_yaml::Value::Tagged(tagged) => {
            format!(
                "t:{}:{}",
                tagged.tag,
                canonical_yaml_sort_key_for_test(&tagged.value)
            )
        }
    }
}

fn reference_yaml() -> String {
    r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
  credentials:
    OPENAI_API_KEY:
      source: env
      required: true
      note: sk-known-secret
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets:
    - github_read
state:
  persist_home: true
"#
    .to_owned()
}

fn override_yaml() -> String {
    r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
policy:
  tier: restricted
  presets: []
  overrides:
    - allow: https://example.com:8443
      deny: blocked.internal
      approval: https://example.com/path
"#
    .to_owned()
}

fn image_yaml() -> String {
    r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  image: ghcr.io/example/sandbox:latest
  digest: sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
agent:
  driver: codex
context:
  driver: filesystem
policy:
  tier: restricted
  presets: []
"#
    .to_owned()
}

fn external_context_yaml() -> String {
    r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: demo-context
  version: 1.2.3
policy:
  tier: restricted
  presets: []
"#
    .to_owned()
}

fn no_inference_yaml() -> String {
    r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
policy:
  tier: restricted
  presets: []
"#
    .to_owned()
}

fn open_policy_yaml() -> String {
    r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
policy:
  tier: open
  presets: []
"#
    .to_owned()
}

fn artifacts_with_external_context() -> Vec<DriverArtifact> {
    let mut artifacts = built_in_artifacts()
        .into_iter()
        .filter(|artifact| artifact.kind != DriverKind::Context)
        .collect::<Vec<_>>();
    artifacts.push(DriverArtifact {
        kind: DriverKind::Context,
        name: "demo-context".to_owned(),
        version: Version::parse("1.2.3").expect("test version is semver"),
        source: DriverSource::InstalledSubprocess,
        digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .to_owned(),
        install_hint: Some("/tmp/demo-context".to_owned()),
        entry: None,
    });
    artifacts
}

fn built_in_artifacts() -> Vec<DriverArtifact> {
    let version = Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version is semver");
    [
        (DriverKind::Sandbox, "openshell"),
        (DriverKind::Agent, "codex"),
        (DriverKind::Context, "filesystem"),
        (DriverKind::Inference, "passthrough"),
    ]
    .into_iter()
    .map(|(kind, name)| DriverArtifact {
        kind,
        name: name.to_owned(),
        version: version.clone(),
        source: DriverSource::BuiltIn,
        digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_owned(),
        install_hint: None,
        entry: None,
    })
    .collect()
}

fn legacy_lockfile_yaml() -> String {
    r#"
version: 0.1.0
protocol_version: "0.1"
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
drivers:
  sandbox:
    name: openshell
    version: 0.0.1-alpha0
  agent:
    name: codex
    version: 0.0.1-alpha0
  context:
    name: filesystem
    version: 0.0.1-alpha0
"#
    .to_owned()
}
