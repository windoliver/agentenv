use std::fs;

use agentenv_core::driver_artifact::{
    digest_driver_root, digest_file, discover_driver_artifacts, DriverArtifactError,
};
use agentenv_core::driver_catalog::{DriverDiscoveryConfig, DriverSource};
use agentenv_core::registry::DriverKind;

#[test]
fn driver_root_digest_is_stable_across_file_creation_order() {
    let left = tempfile_dir("driver-root-left");
    let right = tempfile_dir("driver-root-right");
    write_file(&left, "manifest.json", "{}\n");
    write_file(&left, "bin/driver", "#!/bin/sh\nexit 0\n");
    write_file(&right, "bin/driver", "#!/bin/sh\nexit 0\n");
    write_file(&right, "manifest.json", "{}\n");

    let left_digest = digest_driver_root(&left).unwrap();
    let right_digest = digest_driver_root(&right).unwrap();

    assert_eq!(left_digest, right_digest);
    assert!(left_digest.starts_with("sha256:"));
}

#[test]
fn driver_root_digest_delimits_file_payloads_from_later_entries() {
    let one_file = tempfile_dir("driver-root-one-file");
    let two_files = tempfile_dir("driver-root-two-files");
    write_bytes(&one_file, "a", b"payloadfile\0b\0tail");
    write_bytes(&two_files, "a", b"payload");
    write_bytes(&two_files, "b", b"tail");

    let one_file_digest = digest_driver_root(&one_file).unwrap();
    let two_files_digest = digest_driver_root(&two_files).unwrap();

    assert_ne!(one_file_digest, two_files_digest);
}

#[test]
#[cfg(unix)]
fn driver_root_digest_changes_when_executable_mode_changes() {
    use std::os::unix::fs::PermissionsExt;

    let plain = tempfile_dir("driver-root-mode-plain");
    let executable = tempfile_dir("driver-root-mode-executable");
    write_file(&plain, "bin/driver", "#!/bin/sh\nexit 0\n");
    write_file(&executable, "bin/driver", "#!/bin/sh\nexit 0\n");
    let mut permissions = fs::metadata(executable.join("bin/driver"))
        .unwrap()
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(executable.join("bin/driver"), permissions).unwrap();

    let plain_digest = digest_driver_root(&plain).unwrap();
    let executable_digest = digest_driver_root(&executable).unwrap();

    assert_ne!(plain_digest, executable_digest);
}

#[test]
#[cfg(unix)]
fn driver_root_digest_hashes_symlink_metadata_without_following() {
    let root = tempfile_dir("driver-root-symlink");
    write_file(&root, "manifest.json", "{}\n");
    write_file(&root, "bin/driver", "#!/bin/sh\nexit 0\n");
    std::os::unix::fs::symlink("driver", root.join("bin/link")).unwrap();

    let digest = digest_driver_root(&root).unwrap();

    assert!(digest.starts_with("sha256:"));
}

#[test]
#[cfg(unix)]
fn driver_root_digest_rejects_symlink_that_escapes_root() {
    let root = tempfile_dir("driver-root-symlink-escape");
    let outside = tempfile_dir("driver-root-symlink-outside");
    write_file(&root, "manifest.json", "{}\n");
    write_file(&root, "bin/driver", "#!/bin/sh\nexit 0\n");
    write_file(&outside, "shared.sh", "echo outside\n");
    std::os::unix::fs::symlink(outside.join("shared.sh"), root.join("bin/shared.sh")).unwrap();

    let error = digest_driver_root(&root).unwrap_err();

    assert!(matches!(error, DriverArtifactError::PathEscapesRoot { .. }));
}

#[test]
#[cfg(unix)]
fn driver_root_digest_changes_when_symlink_target_text_changes() {
    let left = tempfile_dir("driver-root-link-left");
    let right = tempfile_dir("driver-root-link-right");
    write_file(&left, "manifest.json", "{}\n");
    write_file(&right, "manifest.json", "{}\n");
    write_file(&left, "target-a", "same bytes\n");
    write_file(&right, "target-b", "same bytes\n");
    std::os::unix::fs::symlink("target-a", left.join("link")).unwrap();
    std::os::unix::fs::symlink("target-b", right.join("link")).unwrap();

    let left_digest = digest_driver_root(&left).unwrap();
    let right_digest = digest_driver_root(&right).unwrap();

    assert_ne!(left_digest, right_digest);
}

#[test]
#[cfg(unix)]
fn driver_root_digest_does_not_collapse_backslash_filename() {
    let backslash_name = tempfile_dir("driver-root-backslash-name");
    let nested_name = tempfile_dir("driver-root-nested-name");
    write_file(&backslash_name, "a\\b", "same bytes\n");
    write_file(&nested_name, "a/b", "same bytes\n");

    let backslash_digest = digest_driver_root(&backslash_name).unwrap();
    let nested_digest = digest_driver_root(&nested_name).unwrap();

    assert_ne!(backslash_digest, nested_digest);
}

#[test]
fn discover_driver_artifacts_includes_installed_subprocess_digest() {
    let installed = tempfile_dir("installed-drivers");
    let root = installed.join("context-demo");
    let built_in_binary = installed.join("agentenv-test-binary");
    write_file(&installed, "agentenv-test-binary", "fake agentenv binary\n");
    write_file(&root, "bin/driver", "#!/bin/sh\nexit 0\n");
    write_file(
        &root,
        "manifest.json",
        r#"{
          "schema_version": "1.0",
          "name": "demo-context",
          "kind": "context",
          "version": "1.2.3",
          "binary": "./bin/driver"
        }"#,
    );

    let artifacts = discover_driver_artifacts(
        DriverDiscoveryConfig::new(installed, Vec::new()),
        Some(built_in_binary),
    )
    .unwrap();

    let artifact = artifacts
        .iter()
        .find(|item| item.kind == DriverKind::Context && item.name == "demo-context")
        .expect("missing demo-context artifact");
    assert_eq!(artifact.version.to_string(), "1.2.3");
    assert_eq!(artifact.source, DriverSource::InstalledSubprocess);
    assert!(artifact.digest.starts_with("sha256:"));
    assert_eq!(artifact.digest, digest_driver_root(&root).unwrap());
}

#[test]
fn discover_driver_artifacts_hashes_built_ins_from_override_binary() {
    let installed = tempfile_dir("built-in-artifacts");
    let built_in_binary = installed.join("agentenv-test-binary");
    write_file(&installed, "agentenv-test-binary", "fake agentenv binary\n");

    let artifacts = discover_driver_artifacts(
        DriverDiscoveryConfig::new(installed, Vec::new()),
        Some(built_in_binary.clone()),
    )
    .unwrap();

    let built_in = artifacts
        .iter()
        .find(|item| item.source == DriverSource::BuiltIn)
        .expect("missing built-in artifact");
    assert_eq!(built_in.digest, digest_file(&built_in_binary).unwrap());
}

#[test]
fn discover_driver_artifacts_includes_shadowed_subprocess_digest() {
    let installed = tempfile_dir("shadowed-installed-drivers");
    let override_parent = tempfile_dir("shadowing-override-drivers");
    let installed_root = installed.join("context-demo");
    let override_root = override_parent.join("context-demo");
    let built_in_binary = installed.join("agentenv-test-binary");
    write_file(&installed, "agentenv-test-binary", "fake agentenv binary\n");
    write_driver_manifest(&installed_root, "demo-context", "context", "1.0.0");
    write_driver_manifest(&override_root, "demo-context", "context", "2.0.0");

    let artifacts = discover_driver_artifacts(
        DriverDiscoveryConfig::new(installed, vec![override_parent]),
        Some(built_in_binary),
    )
    .unwrap();

    let mut demo_versions: Vec<_> = artifacts
        .iter()
        .filter(|item| item.kind == DriverKind::Context && item.name == "demo-context")
        .map(|item| (item.version.to_string(), item.source))
        .collect();
    demo_versions.sort();

    assert_eq!(
        demo_versions,
        vec![
            ("1.0.0".to_string(), DriverSource::InstalledSubprocess),
            ("2.0.0".to_string(), DriverSource::DevelopmentOverride),
        ]
    );
}

#[test]
fn digest_driver_root_rejects_missing_root() {
    let root = tempfile_dir("missing-driver-root");
    fs::remove_dir(&root).unwrap();

    let error = digest_driver_root(&root).unwrap_err();

    assert!(matches!(error, DriverArtifactError::Io { .. }));
}

fn tempfile_dir(prefix: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn write_file(root: &std::path::Path, relative: &str, contents: &str) {
    write_bytes(root, relative, contents.as_bytes());
}

fn write_bytes(root: &std::path::Path, relative: &str, contents: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

fn write_driver_manifest(root: &std::path::Path, name: &str, kind: &str, version: &str) {
    write_file(root, "bin/driver", "#!/bin/sh\nexit 0\n");
    write_file(
        root,
        "manifest.json",
        &format!(
            r#"{{
          "schema_version": "1.0",
          "name": "{name}",
          "kind": "{kind}",
          "version": "{version}",
          "binary": "./bin/driver"
        }}"#
        ),
    );
}
