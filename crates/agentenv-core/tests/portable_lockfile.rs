use agentenv_core::{
    driver_artifact::DriverArtifact,
    driver_catalog::DriverSource,
    lockfile::{DriverSourcePin, LockfileDocument},
    portable_lockfile::{build_portable_lockfile, PortableLockfileError, PortableLockfileInput},
    registry::DriverKind,
};
use agentenv_proto::NetworkTarget;
use semver::Version;

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
    assert!(
        first.contains("driver_protocol_version: '1.0'")
            || first.contains("driver_protocol_version: \"1.0\"")
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
    })
    .collect()
}
