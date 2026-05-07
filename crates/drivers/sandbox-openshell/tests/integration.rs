#![cfg(feature = "integration")]

use std::{collections::BTreeMap, env, sync::Arc};

use agentenv_core::driver::SandboxDriver;
use agentenv_proto::{
    ApplyPolicyParams, DestroyParams, ExecParams, FilesystemPolicy, HttpAccessLevel,
    InferencePolicy, NetworkAccessPolicy, NetworkPolicy, NetworkRule, NetworkTarget,
    PolicyReloadability, ProcessPolicy, SandboxSpec,
};
use sandbox_openshell::OpenShellDriver;
use tokio::runtime::Builder;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires OpenShell >= 0.0.30, Docker, and a working gateway"]
async fn openshell_create_exec_policy_logs_and_destroy_flow() {
    if !should_run_integration() {
        eprintln!("skipping OpenShell integration test: set AGENTENV_RUN_OPENSHELL_INTEGRATION=1");
        return;
    }

    let driver = Arc::new(OpenShellDriver::default());
    let sandbox_name = format!("agentenv-it-{}", Uuid::new_v4());
    let metadata = BTreeMap::from([(
        "name".to_owned(),
        serde_json::Value::String(sandbox_name.clone()),
    )]);

    let handle = driver
        .create(SandboxSpec {
            image: Some("openclaw".to_owned()),
            env: BTreeMap::new(),
            policy: Some(default_deny_policy()),
            metadata,
        })
        .await
        .expect("create sandbox")
        .handle;
    let mut cleanup = DestroyOnDrop::new(Arc::clone(&driver), handle.clone());

    let whoami = driver
        .exec(ExecParams {
            handle: handle.clone(),
            cmd: "whoami".to_owned(),
            tty: false,
            env: BTreeMap::new(),
        })
        .await
        .expect("run whoami");
    assert_eq!(whoami.status, 0, "whoami failed: {}", whoami.stderr);

    let denied = driver
        .exec(ExecParams {
            handle: handle.clone(),
            cmd: "curl -s https://api.github.com/zen".to_owned(),
            tty: false,
            env: BTreeMap::new(),
        })
        .await
        .expect("run denied curl");
    assert_ne!(
        denied.status, 0,
        "default-deny curl unexpectedly succeeded: stdout={} stderr={}",
        denied.stdout, denied.stderr
    );

    let policy = github_read_policy();
    let apply_result = driver
        .apply_policy(ApplyPolicyParams {
            handle: handle.clone(),
            policy: policy.clone(),
        })
        .await
        .expect("apply GitHub read policy");
    assert!(apply_result.hot_reloaded);

    let allowed = driver
        .exec(ExecParams {
            handle: handle.clone(),
            cmd: "curl -s https://api.github.com/zen".to_owned(),
            tty: false,
            env: BTreeMap::new(),
        })
        .await
        .expect("run allowed curl");
    assert_eq!(allowed.status, 0, "allowed curl failed: {}", allowed.stderr);

    let logs = driver
        .logs(agentenv_proto::LogsParams {
            handle: handle.clone(),
            since: Some("5m".to_owned()),
            follow: false,
        })
        .await
        .expect("read logs");

    if !logs.entries.is_empty() {
        assert!(
            logs.entries.iter().any(|entry| {
                entry.msg.contains("api.github.com")
                    || entry
                        .kv
                        .values()
                        .any(|value| value.to_string().contains("api.github.com"))
            }),
            "expected at least one log entry to mention api.github.com"
        );
    }

    driver
        .destroy(DestroyParams {
            handle: handle.clone(),
        })
        .await
        .expect("destroy sandbox");
    cleanup.disarm();
}

#[tokio::test]
#[ignore = "requires OpenShell >= 0.0.30, Docker, and a working gateway"]
async fn credentials_do_not_appear_in_sandbox_filesystem() {
    if !should_run_integration() {
        eprintln!("skipping OpenShell integration test: set AGENTENV_RUN_OPENSHELL_INTEGRATION=1");
        return;
    }

    let driver = Arc::new(OpenShellDriver::default());
    let sandbox_name = format!("agentenv-it-{}", Uuid::new_v4());
    let marker = format!("agentenv-secret-{}", Uuid::new_v4());
    let metadata = BTreeMap::from([(
        "name".to_owned(),
        serde_json::Value::String(sandbox_name.clone()),
    )]);

    let handle = driver
        .create(SandboxSpec {
            image: Some("openclaw".to_owned()),
            env: BTreeMap::from([("AGENTENV_SECRET_MARKER".to_owned(), marker.clone())]),
            policy: None,
            metadata,
        })
        .await
        .expect("create sandbox")
        .handle;
    let mut cleanup = DestroyOnDrop::new(Arc::clone(&driver), handle.clone());

    let output = driver
        .exec(ExecParams {
            handle: handle.clone(),
            cmd: format!(
                "sh -lc {}",
                shell_single_quote(&format!(
                    "if grep -R --fixed-strings --line-number -- {} /sandbox /tmp /var/tmp /var/log /root 2>/dev/null; then exit 10; else exit 0; fi",
                    shell_single_quote(&marker)
                ))
            ),
            tty: false,
            env: BTreeMap::new(),
        })
        .await
        .expect("grep for secret marker");

    assert_eq!(
        output.status, 0,
        "filesystem probe failed or marker was found: stdout={} stderr={}",
        output.stdout, output.stderr
    );
    assert!(
        !output.stdout.contains(&marker),
        "grep output leaked the secret marker: {}",
        output.stdout
    );

    driver
        .destroy(DestroyParams {
            handle: handle.clone(),
        })
        .await
        .expect("destroy sandbox");
    cleanup.disarm();
}

fn should_run_integration() -> bool {
    matches!(
        env::var("AGENTENV_RUN_OPENSHELL_INTEGRATION").as_deref(),
        Ok("1")
    )
}

fn github_read_policy() -> NetworkPolicy {
    let mut policy = default_deny_policy();
    policy.network.allow.push(NetworkRule {
        target: NetworkTarget::Host {
            host: "api.github.com".to_owned(),
            port: Some(443),
            scheme: Some("https".to_owned()),
            http_access: Some(HttpAccessLevel::ReadOnly),
        },
    });
    policy
}

fn default_deny_policy() -> NetworkPolicy {
    NetworkPolicy {
        network: NetworkAccessPolicy {
            reloadability: PolicyReloadability::HotReload,
            allow: Vec::new(),
            deny: Vec::new(),
            approval_required: Vec::new(),
        },
        filesystem: live_openshell_filesystem_policy(),
        process: ProcessPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            run_as_user: "sandbox".to_owned(),
            run_as_group: "sandbox".to_owned(),
            profile: String::new(),
            allow_syscalls: Vec::new(),
            deny_syscalls: Vec::new(),
        },
        inference: InferencePolicy {
            reloadability: PolicyReloadability::HotReload,
            routes: Vec::new(),
        },
    }
}

fn live_openshell_filesystem_policy() -> FilesystemPolicy {
    FilesystemPolicy {
        reloadability: PolicyReloadability::LockedAtCreate,
        read_only: vec![
            "/usr".to_owned(),
            "/lib".to_owned(),
            "/proc".to_owned(),
            "/dev/urandom".to_owned(),
            "/app".to_owned(),
            "/etc".to_owned(),
            "/var/log".to_owned(),
        ],
        read_write: vec![
            "/sandbox".to_owned(),
            "/tmp".to_owned(),
            "/dev/null".to_owned(),
        ],
    }
}

fn shell_single_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }

    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

struct DestroyOnDrop {
    driver: Arc<OpenShellDriver>,
    handle: Option<String>,
}

impl DestroyOnDrop {
    fn new(driver: Arc<OpenShellDriver>, handle: String) -> Self {
        Self {
            driver,
            handle: Some(handle),
        }
    }

    fn disarm(&mut self) {
        self.handle = None;
    }
}

impl Drop for DestroyOnDrop {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };

        let driver = Arc::clone(&self.driver);
        let join_result = std::thread::spawn(move || {
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build cleanup runtime");
            runtime.block_on(async move {
                let _ = driver.destroy(DestroyParams { handle }).await;
            });
        })
        .join();

        if let Err(err) = join_result {
            eprintln!("cleanup destroy task panicked: {:?}", err);
        }
    }
}
