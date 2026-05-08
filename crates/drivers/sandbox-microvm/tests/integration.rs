use std::{collections::BTreeMap, env, path::Path};

use agentenv_core::driver::SandboxDriver;
use agentenv_proto::{
    CopyInParams, CopyOutParams, DestroyParams, ExecParams, InitializeParams, LogLevel, LogsParams,
    PreflightParams, SandboxSpec, SandboxStatusParams, StopParams, SCHEMA_VERSION,
};
use sandbox_microvm::MicroVmDriver;
use serde_json::json;

fn init_params(workdir: &Path) -> InitializeParams {
    InitializeParams {
        schema_version: SCHEMA_VERSION.to_owned(),
        core_version: env!("CARGO_PKG_VERSION").to_owned(),
        workdir: workdir.to_string_lossy().into_owned(),
        log_level: LogLevel::Info,
    }
}

fn env_var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

#[tokio::test]
#[ignore]
async fn firecracker_process_lifecycle_on_linux_kvm() {
    if env_var("AGENTENV_RUN_MICROVM_INTEGRATION").is_none() {
        eprintln!("set AGENTENV_RUN_MICROVM_INTEGRATION=1 to run this test");
        return;
    }
    let Some(kernel) = env_var("AGENTENV_MICROVM_KERNEL") else {
        eprintln!("set AGENTENV_MICROVM_KERNEL to a bootable Firecracker kernel path");
        return;
    };
    let Some(rootfs) = env_var("AGENTENV_MICROVM_ROOTFS") else {
        eprintln!("set AGENTENV_MICROVM_ROOTFS to a bootable Firecracker rootfs path");
        return;
    };

    let temp = tempfile::tempdir().expect("tempdir");
    let mut driver = MicroVmDriver::default();
    driver
        .initialize(init_params(temp.path()))
        .await
        .expect("initialize");
    let preflight = driver
        .preflight(PreflightParams::default())
        .await
        .expect("preflight");
    assert!(preflight.ok, "preflight failed: {preflight:?}");

    let mut metadata = BTreeMap::from([
        ("name".to_owned(), json!("agentenv-fc-it")),
        ("runtime".to_owned(), json!("firecracker")),
        ("kernel".to_owned(), json!(kernel)),
        ("rootfs".to_owned(), json!(rootfs)),
        (
            "memory_mb".to_owned(),
            json!(env_var("AGENTENV_MICROVM_MEMORY_MB").unwrap_or_else(|| "512".to_owned())),
        ),
        (
            "cpus".to_owned(),
            json!(env_var("AGENTENV_MICROVM_CPUS").unwrap_or_else(|| "1".to_owned())),
        ),
    ]);
    if let Some(tap) = env_var("AGENTENV_MICROVM_TAP") {
        metadata.insert("tap".to_owned(), json!(tap));
    }
    if let Some(host) = env_var("AGENTENV_MICROVM_SSH_HOST") {
        metadata.insert("ssh_host".to_owned(), json!(host));
    }
    if let Some(port) = env_var("AGENTENV_MICROVM_SSH_PORT") {
        metadata.insert("ssh_port".to_owned(), json!(port));
    }
    if let Some(user) = env_var("AGENTENV_MICROVM_SSH_USER") {
        metadata.insert("ssh_user".to_owned(), json!(user));
    }
    if let Some(identity_file) = env_var("AGENTENV_MICROVM_SSH_IDENTITY_FILE") {
        metadata.insert("ssh_identity_file".to_owned(), json!(identity_file));
    }

    let handle = driver
        .create(SandboxSpec {
            image: None,
            env: BTreeMap::new(),
            policy: None,
            metadata,
        })
        .await
        .expect("create firecracker");
    let status = driver
        .status(SandboxStatusParams {
            handle: handle.handle.clone(),
        })
        .await
        .expect("status");
    assert!(status.healthy, "status: {status:?}");

    if env_var("AGENTENV_MICROVM_SSH_HOST").is_some() {
        let result = driver
            .exec(ExecParams {
                handle: handle.handle.clone(),
                cmd: "true".to_owned(),
                tty: false,
                env: BTreeMap::new(),
            })
            .await
            .expect("exec true over ssh");
        assert_eq!(result.status, 0, "exec failed: {result:?}");
    }

    driver
        .stop(StopParams {
            handle: handle.handle.clone(),
        })
        .await
        .expect("stop");
    driver
        .destroy(DestroyParams {
            handle: handle.handle,
        })
        .await
        .expect("destroy");
}

#[tokio::test]
#[ignore]
async fn apple_container_lifecycle_on_macos() {
    if env_var("AGENTENV_RUN_APPLE_CONTAINER_INTEGRATION").is_none() {
        eprintln!("set AGENTENV_RUN_APPLE_CONTAINER_INTEGRATION=1 to run this test");
        return;
    }
    let image =
        env_var("AGENTENV_APPLE_CONTAINER_IMAGE").unwrap_or_else(|| "alpine:latest".to_owned());
    let temp = tempfile::tempdir().expect("tempdir");
    let mut driver = MicroVmDriver::default();
    driver
        .initialize(init_params(temp.path()))
        .await
        .expect("initialize");
    let preflight = driver
        .preflight(PreflightParams::default())
        .await
        .expect("preflight");
    assert!(preflight.ok, "preflight failed: {preflight:?}");

    let handle = driver
        .create(SandboxSpec {
            image: Some(image),
            env: BTreeMap::from([("AGENTENV_APPLE_CONTAINER_IT".to_owned(), "ok".to_owned())]),
            policy: None,
            metadata: BTreeMap::from([
                ("name".to_owned(), json!("agentenv-apple-it")),
                ("runtime".to_owned(), json!("apple-container")),
                ("memory_mb".to_owned(), json!(512)),
                ("cpus".to_owned(), json!(1)),
            ]),
        })
        .await
        .expect("create apple-container");

    let result = driver
        .exec(ExecParams {
            handle: handle.handle.clone(),
            cmd: "test \"$AGENTENV_APPLE_CONTAINER_IT\" = ok".to_owned(),
            tty: false,
            env: BTreeMap::new(),
        })
        .await
        .expect("exec env probe");
    assert_eq!(result.status, 0, "exec failed: {result:?}");

    let src = temp.path().join("copy-in.txt");
    std::fs::write(&src, "hello\n").expect("write copy source");
    driver
        .copy_in(CopyInParams {
            handle: handle.handle.clone(),
            src_host_path: src.display().to_string(),
            dst_sandbox_path: "/sandbox/copy-in.txt".to_owned(),
        })
        .await
        .expect("copy in");
    let result = driver
        .exec(ExecParams {
            handle: handle.handle.clone(),
            cmd: "cat /sandbox/copy-in.txt".to_owned(),
            tty: false,
            env: BTreeMap::new(),
        })
        .await
        .expect("cat copied file");
    assert_eq!(result.stdout, "hello\n");

    let dst = temp.path().join("copy-out.txt");
    driver
        .copy_out(CopyOutParams {
            handle: handle.handle.clone(),
            src_sandbox_path: "/sandbox/copy-in.txt".to_owned(),
            dst_host_path: dst.display().to_string(),
        })
        .await
        .expect("copy out");
    assert_eq!(
        std::fs::read_to_string(dst).expect("read copy out"),
        "hello\n"
    );

    let logs = driver
        .logs(LogsParams {
            handle: handle.handle.clone(),
            since: None,
            follow: false,
        })
        .await
        .expect("logs");
    assert!(logs.entries.len() <= 1);

    driver
        .destroy(DestroyParams {
            handle: handle.handle,
        })
        .await
        .expect("destroy");
}
