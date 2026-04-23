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
#[cfg(unix)]
fn driver_root_digest_hashes_symlink_metadata_without_following() {
    let root = tempfile_dir("driver-root-symlink");
    write_file(&root, "manifest.json", "{}\n");
    write_file(&root, "bin/driver", "#!/bin/sh\nexit 0\n");
    std::os::unix::fs::symlink("../outside", root.join("bin/link")).unwrap();

    let digest = digest_driver_root(&root).unwrap();

    assert!(digest.starts_with("sha256:"));
}

#[test]
#[cfg(unix)]
fn driver_root_digest_changes_when_symlink_target_text_changes() {
    let left = tempfile_dir("driver-root-link-left");
    let right = tempfile_dir("driver-root-link-right");
    write_file(&left, "manifest.json", "{}\n");
    write_file(&right, "manifest.json", "{}\n");
    std::os::unix::fs::symlink("../outside-a", left.join("link")).unwrap();
    std::os::unix::fs::symlink("../outside-b", right.join("link")).unwrap();

    let left_digest = digest_driver_root(&left).unwrap();
    let right_digest = digest_driver_root(&right).unwrap();

    assert_ne!(left_digest, right_digest);
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
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}
