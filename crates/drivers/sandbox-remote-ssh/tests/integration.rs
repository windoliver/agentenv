#![cfg(feature = "integration")]

use std::{collections::BTreeMap, env, fs};

use agentenv_core::driver::SandboxDriver;
use agentenv_proto::{
    CopyInParams, CopyOutParams, DestroyParams, ExecParams, SandboxSpec, SandboxStatusParams,
};
use sandbox_remote_ssh::RemoteSshDriver;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires a reachable SSH host configured through AGENTENV_REMOTE_SSH_*"]
async fn remote_ssh_create_exec_copy_status_destroy_flow() {
    if !should_run_integration() {
        eprintln!(
            "skipping remote SSH integration test: set AGENTENV_RUN_REMOTE_SSH_INTEGRATION=1"
        );
        return;
    }

    let host = env::var("AGENTENV_REMOTE_SSH_HOST").expect("remote host");
    let user = env::var("AGENTENV_REMOTE_SSH_USER").expect("remote user");
    let port = env::var("AGENTENV_REMOTE_SSH_PORT").unwrap_or_else(|_| "22".to_owned());
    let identity_file = env::var("AGENTENV_REMOTE_SSH_IDENTITY_FILE").ok();
    let jump_host = env::var("AGENTENV_REMOTE_SSH_JUMP_HOST").ok();

    let marker = format!("agentenv-remote-ssh-{}", Uuid::new_v4());
    let env_name = format!("remote-ssh-{}", Uuid::new_v4());
    let mut metadata = BTreeMap::from([
        ("name".to_owned(), serde_json::json!(env_name)),
        ("host".to_owned(), serde_json::json!(host)),
        ("user".to_owned(), serde_json::json!(user)),
        ("port".to_owned(), serde_json::json!(port)),
    ]);
    if let Some(identity_file) = identity_file {
        metadata.insert("identity_file".to_owned(), serde_json::json!(identity_file));
    }
    if let Some(jump_host) = jump_host {
        metadata.insert("jump_host".to_owned(), serde_json::json!(jump_host));
    }

    let driver = RemoteSshDriver::default();
    let handle = driver
        .create(SandboxSpec {
            image: None,
            env: BTreeMap::from([("AGENTENV_REMOTE_SSH_MARKER".to_owned(), marker.clone())]),
            policy: None,
            metadata,
        })
        .await
        .expect("create remote ssh sandbox")
        .handle;

    let exec = driver
        .exec(ExecParams {
            handle: handle.clone(),
            cmd: "printf '%s\\n' \"$AGENTENV_REMOTE_SSH_MARKER\"".to_owned(),
            tty: false,
            env: BTreeMap::new(),
        })
        .await
        .expect("exec marker");
    assert_eq!(
        exec.status, 0,
        "stdout={} stderr={}",
        exec.stdout, exec.stderr
    );
    assert!(exec.stdout.contains(&marker));

    let tempdir = env::temp_dir().join(format!("agentenv-remote-ssh-it-{}", Uuid::new_v4()));
    fs::create_dir_all(&tempdir).expect("create tempdir");
    let src = tempdir.join("in.txt");
    let dst = tempdir.join("out.txt");
    fs::write(&src, format!("{marker}\n")).expect("write source");
    let remote_path = format!("/sandbox/.agentenv/{}.txt", marker);

    driver
        .copy_in(CopyInParams {
            handle: handle.clone(),
            src_host_path: src.display().to_string(),
            dst_sandbox_path: remote_path.clone(),
        })
        .await
        .expect("copy_in");
    driver
        .copy_out(CopyOutParams {
            handle: handle.clone(),
            src_sandbox_path: remote_path,
            dst_host_path: dst.display().to_string(),
        })
        .await
        .expect("copy_out");
    assert_eq!(
        fs::read_to_string(&dst).expect("read output"),
        format!("{marker}\n")
    );

    let status = driver
        .status(SandboxStatusParams {
            handle: handle.clone(),
        })
        .await
        .expect("status");
    assert!(status.healthy);

    driver
        .destroy(DestroyParams { handle })
        .await
        .expect("destroy no-op");
    fs::remove_dir_all(&tempdir).expect("remove tempdir");
}

fn should_run_integration() -> bool {
    matches!(
        env::var("AGENTENV_RUN_REMOTE_SSH_INTEGRATION").as_deref(),
        Ok("1")
    )
}
