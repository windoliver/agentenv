use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use agentenv_approvals::{
    ApprovalConfig, ApprovalCoordinator, ApprovalCoordinatorConfig, ApprovalNotifier,
    ApprovalStore, UrlValidator,
};
use agentenv_events::{
    ActivityEvent, ActivityKind, ActivityResult, EventEmitter, NoopEventEmitter,
};
use agentenv_policy::{compose_policy, PresetRegistry, PresetSelection, Tier};
use agentenv_proto::{
    AgentSpec, Capabilities, ContextSpec, DriverKind, InferenceSpec, InitializeParams,
    InitializeResult, LogLevel, PreflightParams, SandboxCapabilities, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    driver::{
        ensure_protocol_compatible, AgentDriver, ContextDriver, DriverError, InferenceDriver,
        SandboxDriver,
    },
    egress_proxy::{
        build_egress_proxy_plan, prepare_egress_proxy_launch_files, start_egress_proxy_process,
        stop_egress_proxy_pid, stop_egress_proxy_process, CredentialDisposition,
        EgressProxyLaunchError, EgressProxyPlan, EgressProxyPlanInput, EgressProxyProcess,
        ExplicitEgressRoutes, McpProxySource,
    },
    env::EnvError,
};

#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    pub root: PathBuf,
    pub log_level: LogLevel,
    pub non_interactive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverSelection {
    pub sandbox: String,
    pub agent: String,
    pub context: String,
    pub inference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverPinIdentity {
    pub kind: DriverKind,
    pub name: String,
    pub version: String,
    pub source: crate::lockfile::DriverSourcePin,
    pub digest: String,
    pub verified_entry: Option<crate::driver_catalog::DiscoveredDriver>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DriverPinSet {
    pins: BTreeMap<String, DriverPinIdentity>,
}

impl DriverPinSet {
    pub fn from_portable_lockfile(
        lockfile: &crate::lockfile::PortableLockfile,
    ) -> RuntimeResult<Self> {
        let mut pins = BTreeMap::new();
        for (role, pin) in &lockfile.drivers {
            let kind = parse_driver_kind(&pin.kind).ok_or_else(|| {
                RuntimeError::PortableLockfileVerification {
                    details: format!(
                        "pinned {role} driver has unsupported kind `{}` and cannot be materialized",
                        pin.kind
                    ),
                }
            })?;
            pins.insert(
                role.clone(),
                DriverPinIdentity {
                    kind,
                    name: pin.name.clone(),
                    version: pin.version.clone(),
                    source: pin.source.clone(),
                    digest: pin.digest.clone(),
                    verified_entry: None,
                },
            );
        }
        Ok(Self { pins })
    }

    pub fn from_portable_lockfile_and_artifacts(
        lockfile: &crate::lockfile::PortableLockfile,
        artifacts: &[crate::driver_artifact::DriverArtifact],
    ) -> RuntimeResult<Self> {
        let mut pin_set = Self::from_portable_lockfile(lockfile)?;
        for (role, pin) in &mut pin_set.pins {
            if pin.source == crate::lockfile::DriverSourcePin::BuiltIn {
                continue;
            }
            let Some(source) = source_pin_to_driver_source(&pin.source) else {
                return Err(RuntimeError::PortableLockfileVerification {
                    details: format!("pinned {role} driver has unsupported source"),
                });
            };
            let Some(artifact) = artifacts.iter().find(|artifact| {
                artifact.kind == driver_kind_to_catalog_kind(&pin.kind)
                    && artifact.name == pin.name
                    && artifact.version.to_string() == pin.version
                    && artifact.source == source
                    && artifact.digest == pin.digest
            }) else {
                return Err(RuntimeError::PortableLockfileVerification {
                    details: format!(
                        "pinned {role} driver `{}` version `{}` was not verified against a local artifact",
                        pin.name, pin.version
                    ),
                });
            };
            let Some(entry) = artifact.entry.clone() else {
                return Err(RuntimeError::PortableLockfileVerification {
                    details: format!(
                        "pinned {role} driver `{}` version `{}` has no verified materialization entry",
                        pin.name, pin.version
                    ),
                });
            };
            pin.verified_entry = Some(entry);
        }
        Ok(pin_set)
    }

    pub fn get(&self, role: &str) -> Option<&DriverPinIdentity> {
        self.pins.get(role)
    }

    pub fn roles(&self) -> impl Iterator<Item = &str> {
        self.pins.keys().map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }
}

fn driver_kind_to_catalog_kind(kind: &DriverKind) -> crate::registry::DriverKind {
    match kind {
        DriverKind::Sandbox => crate::registry::DriverKind::Sandbox,
        DriverKind::Agent => crate::registry::DriverKind::Agent,
        DriverKind::Context => crate::registry::DriverKind::Context,
        DriverKind::Inference => crate::registry::DriverKind::Inference,
    }
}

fn source_pin_to_driver_source(
    source: &crate::lockfile::DriverSourcePin,
) -> Option<crate::driver_catalog::DriverSource> {
    match source {
        crate::lockfile::DriverSourcePin::BuiltIn => None,
        crate::lockfile::DriverSourcePin::Installed => {
            Some(crate::driver_catalog::DriverSource::InstalledSubprocess)
        }
        crate::lockfile::DriverSourcePin::Override => {
            Some(crate::driver_catalog::DriverSource::DevelopmentOverride)
        }
    }
}

pub struct DriverSet {
    pub sandbox: Box<dyn SandboxDriver>,
    pub agent: Box<dyn AgentDriver>,
    pub context: Box<dyn ContextDriver>,
    pub inference: Option<Box<dyn InferenceDriver>>,
}

pub trait DriverFactory {
    fn build(&self, selection: &DriverSelection) -> RuntimeResult<DriverSet>;

    fn build_observed(
        &self,
        selection: &DriverSelection,
        _events: Arc<dyn EventEmitter>,
    ) -> RuntimeResult<DriverSet> {
        self.build(selection)
    }

    fn build_for_env_observed(
        &self,
        selection: &DriverSelection,
        _env: &str,
        events: Arc<dyn EventEmitter>,
        _approval_coordinator: Option<ApprovalCoordinator>,
    ) -> RuntimeResult<DriverSet> {
        self.build_observed(selection, events)
    }

    fn build_pinned(
        &self,
        selection: &DriverSelection,
        _pins: &DriverPinSet,
    ) -> RuntimeResult<DriverSet> {
        self.build(selection)
    }

    fn build_pinned_observed(
        &self,
        selection: &DriverSelection,
        pins: &DriverPinSet,
        _events: Arc<dyn EventEmitter>,
    ) -> RuntimeResult<DriverSet> {
        self.build_pinned(selection, pins)
    }

    fn build_pinned_for_env_observed(
        &self,
        selection: &DriverSelection,
        pins: &DriverPinSet,
        _env: &str,
        events: Arc<dyn EventEmitter>,
        _approval_coordinator: Option<ApprovalCoordinator>,
    ) -> RuntimeResult<DriverSet> {
        self.build_pinned_observed(selection, pins, events)
    }
}

pub trait CredentialProvider {
    fn resolve(
        &mut self,
        requirement: &agentenv_proto::CredentialRequirement,
    ) -> RuntimeResult<Option<RuntimeSecret>>;
    fn backend_name(&self, name: &str) -> RuntimeResult<Option<String>>;
}

struct CreateEnvInput<'a> {
    name: &'a str,
    blueprint_yaml: &'a str,
    lock_yaml: Option<String>,
    resolved_blueprint: Option<crate::lifecycle::ResolvedBlueprint>,
    resolved_policy: Option<agentenv_proto::NetworkPolicy>,
    driver_pins: Option<DriverPinSet>,
}

#[derive(Clone)]
pub struct RuntimeSecret(String);

impl RuntimeSecret {
    pub fn new(secret: String) -> Self {
        Self(secret)
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RuntimeSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimeSecret([redacted])")
    }
}

impl fmt::Display for RuntimeSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Env(#[from] EnvError),
    #[error(transparent)]
    Driver(#[from] DriverError),
    #[error(transparent)]
    DriverArtifact(#[from] crate::driver_artifact::DriverArtifactError),
    #[error(transparent)]
    Lifecycle(#[from] crate::lifecycle::LifecycleError),
    #[error(transparent)]
    Lockfile(#[from] crate::lockfile::LockfileError),
    #[error(transparent)]
    PortableLockfile(#[from] crate::portable_lockfile::PortableLockfileError),
    #[error(transparent)]
    Snapshot(#[from] crate::snapshot::SnapshotError),
    #[error(transparent)]
    Blueprint(#[from] crate::error::BlueprintError),
    #[error(transparent)]
    Hardening(#[from] crate::hardening::HardeningError),
    #[error("invalid DNS policy: {0}")]
    DnsPolicy(#[from] crate::security::dns_policy::DnsPolicyError),
    #[error(transparent)]
    ApprovalConfig(#[from] agentenv_approvals::ApprovalConfigError),
    #[error(transparent)]
    ApprovalNotification(#[from] agentenv_approvals::ApprovalNotificationError),
    #[error("unsupported driver `{name}` for {kind}")]
    UnsupportedDriver { kind: &'static str, name: String },
    #[error("unknown policy tier `{tier}`")]
    InvalidPolicyTier { tier: String },
    #[error("invalid policy.egress_proxy: {details}")]
    InvalidEgressProxyPolicy { details: String },
    #[error("missing credential `{name}`")]
    MissingCredential { name: String },
    #[error("host egress proxy is required for brokered {service} credentials, but sandbox driver `{driver}` does not support it")]
    HostEgressProxyUnsupported { service: String, driver: String },
    #[error("failed to allocate host egress proxy listen address: {source}")]
    EgressProxyListen {
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    EgressProxyPlan(#[from] crate::egress_proxy::EgressProxyPlanError),
    #[error(transparent)]
    EgressProxyLaunch(#[from] EgressProxyLaunchError),
    #[error("legacy 0.1.0 lockfiles are not portable; use `agentenv create --reproduce <lockfile>` with a companion blueprint")]
    LegacyLockfileReproduce,
    #[error("lockfile verification failed: {details}")]
    PortableLockfileVerification { details: String },
    #[error("command exited with status {status}")]
    CommandStatus { status: i32 },
    #[error("failed to convert component config key `{key}`: {source}")]
    ComponentConfigConversion {
        key: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid initialize handshake for {helper}: expected kind `{expected_kind:?}` and capabilities `{expected_capability}`, got kind `{actual_kind:?}` and capabilities `{actual_capability}`")]
    InvalidDriverHandshake {
        helper: &'static str,
        expected_kind: DriverKind,
        actual_kind: DriverKind,
        expected_capability: &'static str,
        actual_capability: &'static str,
    },
    #[error("missing selected {kind} driver `{name}` from driver set")]
    MissingSelectedDriver { kind: &'static str, name: String },
    #[error("env `{name}` is missing required sandbox handle")]
    MissingSandboxHandle { name: String },
    #[error("sandbox handle `{handle}` was not found in the env registry")]
    SandboxHandleNotFound { handle: String },
    #[error("state name `{actual}` does not match env `{expected}`")]
    StateNameMismatch { expected: String, actual: String },
    #[error("frozen lockfile {role} driver pin `{actual_name}` version `{actual_version}` does not match persisted env state `{expected_name}` version `{expected_version}`")]
    FrozenLockfileDriverMismatch {
        role: &'static str,
        expected_name: String,
        expected_version: String,
        actual_name: String,
        actual_version: String,
    },
}

pub type RuntimeResult<T> = Result<T, RuntimeError>;

#[derive(Debug, Clone)]
pub struct CreateResult {
    pub admission: crate::admission::AdmissionReport,
    pub state: crate::env::EnvStateFile,
    pub state_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkEnvResult {
    pub source: String,
    pub name: String,
    pub snapshot_id: String,
    pub sandbox_handle: String,
    pub state_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SnapshotEnvArgs {
    pub env: String,
    pub output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotEnvResult {
    pub path: PathBuf,
    pub file_count: usize,
    pub merkle_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRestoreArgs {
    pub snapshot: PathBuf,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRestoreResult {
    pub name: String,
    pub snapshot: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotVerifyResult {
    pub path: PathBuf,
    pub file_count: usize,
    pub merkle_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EnvListRow {
    pub name: String,
    pub agent: String,
    pub sandbox: String,
    pub context: String,
    pub inference: Option<String>,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionListRow {
    pub env: String,
    pub session_id: String,
    pub name: String,
    pub status: agentenv_proto::SessionStatus,
    pub command: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EnvDescription {
    pub state: crate::env::EnvStateFile,
    pub blueprint_yaml: String,
    pub lock_yaml: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenEnvBundleSource {
    pub env_name: String,
    pub blueprint_yaml: String,
    pub lockfile_yaml: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverHealthSummary {
    pub healthy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvStatusSummary {
    pub healthy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<DriverHealthSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<DriverHealthSummary>,
}

struct CreateEnvRollback<'a> {
    temp_workspace: PathBuf,
    final_env_dir: Option<PathBuf>,
    egress_proxy: Option<EgressProxyProcess>,
    sandbox: Option<(&'a dyn SandboxDriver, String)>,
    context: Option<(&'a dyn ContextDriver, String)>,
    inference: Option<(&'a dyn InferenceDriver, String)>,
}

impl<'a> CreateEnvRollback<'a> {
    fn new(temp_workspace: PathBuf) -> Self {
        Self {
            temp_workspace,
            final_env_dir: None,
            egress_proxy: None,
            sandbox: None,
            context: None,
            inference: None,
        }
    }

    fn set_final_env_dir(&mut self, env_dir: PathBuf) {
        self.final_env_dir = Some(env_dir);
    }

    fn set_context(&mut self, driver: &'a dyn ContextDriver, handle: String) {
        self.context = Some((driver, handle));
    }

    fn set_inference(&mut self, driver: &'a dyn InferenceDriver, handle: String) {
        self.inference = Some((driver, handle));
    }

    fn set_sandbox(&mut self, driver: &'a dyn SandboxDriver, handle: String) {
        self.sandbox = Some((driver, handle));
    }

    fn set_egress_proxy(&mut self, process: EgressProxyProcess) {
        self.egress_proxy = Some(process);
    }

    async fn rollback(&mut self) {
        if let Some(process) = self.egress_proxy.take() {
            let _ = stop_egress_proxy_process(process).await;
        }
        if let Some((driver, handle)) = self.sandbox.as_ref() {
            let _ = driver
                .destroy(agentenv_proto::DestroyParams {
                    handle: handle.clone(),
                })
                .await;
        }
        if let Some((driver, handle)) = self.inference.as_ref() {
            let _ = driver
                .teardown(agentenv_proto::InferenceHandleRequest {
                    handle: handle.clone(),
                })
                .await;
        }
        if let Some((driver, handle)) = self.context.as_ref() {
            let _ = driver
                .teardown(agentenv_proto::ContextHandleRequest {
                    handle: handle.clone(),
                })
                .await;
        }
        if let Some(final_env_dir) = self.final_env_dir.as_ref() {
            let _ = fs::remove_dir_all(final_env_dir);
        }
        let _ = fs::remove_dir_all(&self.temp_workspace);
    }
}

static CREATE_WORKSPACE_SEQ: AtomicU64 = AtomicU64::new(0);
const AGENT_ENTRYPOINT_PATH: &str = "/sandbox/.agentenv/bin/agentenv-agent";
const BUILD_ONEFLIGHT_KIND: &str = "byo-openshell-v1";
const BUILD_ONEFLIGHT_SEED_VERSION: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnterResult {
    Attached(agentenv_proto::ExecResult),
    Detached(agentenv_proto::ShellHandle),
}

pub struct RunningLogStream {
    _set: DriverSet,
}

struct AgentSandboxSetup {
    install_commands: Vec<AgentInstallCommand>,
    can_skip_install_if_probe_passes: bool,
    mcp_config_host_path: PathBuf,
    mcp_config_sandbox_path: String,
    entrypoint_host_path: PathBuf,
    health_probe: agentenv_proto::AgentHealthCheckProbe,
}

struct AgentInstallCommand {
    cmd: String,
    env: BTreeMap<String, String>,
}

fn create_policy_for_agent_install(
    policy: &agentenv_proto::NetworkPolicy,
    setup: &AgentSandboxSetup,
) -> agentenv_proto::NetworkPolicy {
    if setup.install_commands.is_empty() {
        return policy.clone();
    }

    let mut install_policy = policy.clone();
    let npm_rule = agent_install_npm_registry_rule();
    if !install_policy.network.allow.contains(&npm_rule) {
        install_policy.network.allow.push(npm_rule);
    }
    install_policy
}

fn agent_install_npm_registry_rule() -> agentenv_proto::NetworkRule {
    agentenv_proto::NetworkRule {
        target: agentenv_proto::NetworkTarget::Host {
            host: "registry.npmjs.org".to_owned(),
            port: Some(443),
            scheme: Some("https".to_owned()),
            http_access: Some(agentenv_proto::HttpAccessLevel::Full),
        },
    }
}

pub async fn initialize_sandbox_driver(
    options: &RuntimeOptions,
    driver: &mut dyn SandboxDriver,
) -> RuntimeResult<InitializeResult> {
    let result = driver
        .initialize(initialize_params(options))
        .await
        .map_err(RuntimeError::from)?;
    ensure_runtime_handshake(DriverKind::Sandbox, "sandbox", &result)?;
    Ok(result)
}

pub async fn initialize_agent_driver(
    options: &RuntimeOptions,
    driver: &mut dyn AgentDriver,
) -> RuntimeResult<InitializeResult> {
    let result = driver
        .initialize(initialize_params(options))
        .await
        .map_err(RuntimeError::from)?;
    ensure_runtime_handshake(DriverKind::Agent, "agent", &result)?;
    Ok(result)
}

pub async fn initialize_context_driver(
    options: &RuntimeOptions,
    driver: &mut dyn ContextDriver,
) -> RuntimeResult<InitializeResult> {
    let result = driver
        .initialize(initialize_params(options))
        .await
        .map_err(RuntimeError::from)?;
    ensure_runtime_handshake(DriverKind::Context, "context", &result)?;
    Ok(result)
}

pub async fn initialize_inference_driver(
    options: &RuntimeOptions,
    driver: &mut dyn InferenceDriver,
) -> RuntimeResult<InitializeResult> {
    let result = driver
        .initialize(initialize_params(options))
        .await
        .map_err(RuntimeError::from)?;
    ensure_runtime_handshake(DriverKind::Inference, "inference", &result)?;
    Ok(result)
}

pub fn env_events_db_path(options: &RuntimeOptions, env: &str) -> RuntimeResult<PathBuf> {
    Ok(env_paths(options, env)?.env_dir().join("events.db"))
}

pub fn env_approval_overlay_path(options: &RuntimeOptions, env: &str) -> RuntimeResult<PathBuf> {
    Ok(env_paths(options, env)?
        .env_dir()
        .join("approval-policy-overlay.yaml"))
}

pub fn env_approval_proposals_path(options: &RuntimeOptions, env: &str) -> RuntimeResult<PathBuf> {
    Ok(env_paths(options, env)?
        .env_dir()
        .join("approval-policy-proposals.yaml"))
}

pub fn approval_coordinator_for_env(
    options: &RuntimeOptions,
    env: &str,
    events: Arc<dyn EventEmitter>,
) -> RuntimeResult<ApprovalCoordinator> {
    let store = ApprovalStore::open(env_events_db_path(options, env)?).map_err(|err| {
        RuntimeError::Driver(DriverError::ApprovalUnavailable {
            request_id: "<coordinator>".to_owned(),
            message: err.to_string(),
        })
    })?;
    Ok(ApprovalCoordinator::new(ApprovalCoordinatorConfig {
        store,
        events,
        poll_interval: Duration::from_millis(250),
        overlay_path: Some(env_approval_overlay_path(options, env)?),
        proposal_path: Some(env_approval_proposals_path(options, env)?),
        notifications: approval_notifications(options)?,
    }))
}

fn approval_notifications(
    options: &RuntimeOptions,
) -> RuntimeResult<Option<Arc<ApprovalNotifier>>> {
    let config = ApprovalConfig::load(&options.root.join("config.yaml"))?;
    Ok(ApprovalNotifier::from_config(config, approval_url_validator())?.map(Arc::new))
}

fn approval_url_validator() -> UrlValidator {
    Arc::new(|raw_url| {
        let url = url::Url::parse(raw_url).map_err(|error| error.to_string())?;
        crate::security::ssrf::validate_outbound(
            &url,
            crate::security::ssrf::SsrfOptions::default(),
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    })
}

fn env_paths(options: &RuntimeOptions, env: &str) -> RuntimeResult<crate::env::EnvPaths> {
    Ok(crate::env::EnvPaths::new(
        options.root.clone(),
        crate::env::validate_env_name(env)?,
    ))
}

pub async fn run_preflight_only(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    env: &str,
    selection: &DriverSelection,
) -> RuntimeResult<crate::admission::AdmissionReport> {
    run_preflight_with_pins(
        options,
        factory,
        env,
        selection,
        None,
        Arc::new(NoopEventEmitter),
    )
    .await
}

pub fn add_byo_dockerfile_preflight_warnings(
    report: &mut crate::admission::AdmissionReport,
    sandbox_extra: &BTreeMap<String, serde_yaml::Value>,
) {
    let sandbox = crate::blueprint::ComponentSection {
        driver: "openshell".to_owned(),
        version: None,
        credentials: None,
        extra: sandbox_extra.clone(),
    };
    let issues = match crate::hardening::lint_sandbox_hardening(&sandbox, Path::new(".")) {
        Ok(report) => hardening_lint_preflight_issues(&report.diagnostics),
        Err(error) => vec![agentenv_proto::PreflightIssue {
            severity: agentenv_proto::IssueSeverity::Error,
            code: "dockerfile_lint_failed".to_owned(),
            message: format!("failed to lint BYO Dockerfile hardening: {error}"),
            remediation: Some("Check sandbox.image and sandbox.hardening configuration".to_owned()),
        }],
    };
    if issues.is_empty() {
        return;
    }

    if let Some(check) = report
        .checks
        .iter_mut()
        .find(|check| check.kind == DriverKind::Sandbox)
    {
        check.issues.extend(issues);
        refresh_preflight_status(report);
        return;
    }

    report.checks.push(crate::admission::PreflightCheck {
        kind: DriverKind::Sandbox,
        driver: "openshell".to_owned(),
        ok: true,
        issues,
    });
    refresh_preflight_status(report);
}

fn hardening_lint_preflight_issues(
    diagnostics: &[crate::hardening::HardeningLintDiagnostic],
) -> Vec<agentenv_proto::PreflightIssue> {
    diagnostics
        .iter()
        .map(|diagnostic| agentenv_proto::PreflightIssue {
            severity: match diagnostic.severity {
                crate::hardening::HardeningLintSeverity::Info => {
                    agentenv_proto::IssueSeverity::Info
                }
                crate::hardening::HardeningLintSeverity::Warning => {
                    agentenv_proto::IssueSeverity::Warning
                }
                crate::hardening::HardeningLintSeverity::Error => {
                    agentenv_proto::IssueSeverity::Error
                }
            },
            code: diagnostic.code.clone(),
            message: diagnostic.message.clone(),
            remediation: diagnostic.remediation.clone(),
        })
        .collect()
}

fn refresh_preflight_status(report: &mut crate::admission::AdmissionReport) {
    let has_error = report.checks.iter().any(|check| {
        !check.ok
            || check
                .issues
                .iter()
                .any(|issue| issue.severity == agentenv_proto::IssueSeverity::Error)
    });
    report.status = if has_error {
        crate::admission::AdmissionStatus::Rejected
    } else {
        crate::admission::AdmissionStatus::Accepted
    };
    report.reason_code = if has_error {
        crate::admission::ReasonCode::PreflightFailed
    } else {
        crate::admission::ReasonCode::Created
    };
}

async fn run_preflight_with_pins(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    env: &str,
    selection: &DriverSelection,
    pins: Option<&DriverPinSet>,
    events: Arc<dyn EventEmitter>,
) -> RuntimeResult<crate::admission::AdmissionReport> {
    let mut set = build_driver_set(factory, selection, pins, events)?;
    initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
    initialize_agent_driver(options, set.agent.as_mut()).await?;
    initialize_context_driver(options, set.context.as_mut()).await?;
    let sandbox_preflight = set.sandbox.preflight(empty_preflight_params()).await?;
    let agent_preflight = set.agent.preflight(empty_preflight_params()).await?;
    let context_preflight = set.context.preflight(empty_preflight_params()).await?;

    let sandbox_check = crate::admission::PreflightCheck {
        kind: DriverKind::Sandbox,
        driver: selection.sandbox.clone(),
        ok: sandbox_preflight.ok,
        issues: sandbox_preflight.issues,
    };
    let agent_check = crate::admission::PreflightCheck {
        kind: DriverKind::Agent,
        driver: selection.agent.clone(),
        ok: agent_preflight.ok,
        issues: agent_preflight.issues,
    };
    let context_check = crate::admission::PreflightCheck {
        kind: DriverKind::Context,
        driver: selection.context.clone(),
        ok: context_preflight.ok,
        issues: context_preflight.issues,
    };

    let mut checks = vec![sandbox_check, agent_check, context_check];

    match (selection.inference.as_ref(), set.inference.as_mut()) {
        (Some(inference_name), Some(inference)) => {
            initialize_inference_driver(options, inference.as_mut()).await?;
            let inference_preflight = inference.preflight(empty_preflight_params()).await?;
            checks.push(crate::admission::PreflightCheck {
                kind: DriverKind::Inference,
                driver: inference_name.clone(),
                ok: inference_preflight.ok,
                issues: inference_preflight.issues,
            });
        }
        (Some(inference_name), None) => {
            return Err(RuntimeError::MissingSelectedDriver {
                kind: "inference",
                name: inference_name.clone(),
            });
        }
        (None, _) => {}
    }

    Ok(crate::admission::AdmissionReport::from_checks(env, checks))
}

fn build_driver_set(
    factory: &dyn DriverFactory,
    selection: &DriverSelection,
    pins: Option<&DriverPinSet>,
    events: Arc<dyn EventEmitter>,
) -> RuntimeResult<DriverSet> {
    match pins {
        Some(pins) if !pins.is_empty() => factory.build_pinned_observed(selection, pins, events),
        _ => factory.build_observed(selection, events),
    }
}

pub async fn create_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    credentials: &mut dyn CredentialProvider,
    name: &str,
    blueprint_yaml: &str,
) -> RuntimeResult<CreateResult> {
    create_env_observed(
        options,
        factory,
        credentials,
        name,
        blueprint_yaml,
        Arc::new(NoopEventEmitter),
    )
    .await
}

pub async fn create_env_observed(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    credentials: &mut dyn CredentialProvider,
    name: &str,
    blueprint_yaml: &str,
    events: Arc<dyn EventEmitter>,
) -> RuntimeResult<CreateResult> {
    create_env_with_input(
        options,
        factory,
        credentials,
        CreateEnvInput {
            name,
            blueprint_yaml,
            lock_yaml: None,
            resolved_blueprint: None,
            resolved_policy: None,
            driver_pins: None,
        },
        events,
    )
    .await
}

async fn create_env_with_input(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    credentials: &mut dyn CredentialProvider,
    input: CreateEnvInput<'_>,
    events: Arc<dyn EventEmitter>,
) -> RuntimeResult<CreateResult> {
    let name = input.name;
    let blueprint_yaml = input.blueprint_yaml;
    let env_name = crate::env::validate_env_name(name)?;
    let trace_id = new_trace_id();
    emit_runtime_event(
        events.as_ref(),
        core_activity_event(
            ActivityKind::SpawnRequested,
            ActivityResult::Ok,
            &trace_id,
            Some(name),
        ),
    );
    let paths = crate::env::EnvPaths::new(options.root.clone(), env_name.clone());
    let env_dir = paths.env_dir();
    if env_dir.exists() {
        emit_runtime_event(
            events.as_ref(),
            core_activity_event(
                ActivityKind::SpawnRejected,
                ActivityResult::Denied,
                &trace_id,
                Some(name),
            )
            .with_reason_code(crate::admission::ReasonCode::EnvExists.as_str()),
        );
        return Err(crate::env::EnvError::AlreadyExists {
            name: name.to_owned(),
        }
        .into());
    }

    let resolved = match input.resolved_blueprint {
        Some(resolved) => resolved,
        None => match crate::lifecycle::verify_blueprint_yaml(blueprint_yaml) {
            Ok(resolved) => resolved,
            Err(err) => {
                emit_runtime_event(
                    events.as_ref(),
                    core_activity_event(
                        ActivityKind::SpawnRejected,
                        ActivityResult::Denied,
                        &trace_id,
                        Some(name),
                    )
                    .with_reason_code(crate::admission::ReasonCode::InvalidBlueprint.as_str()),
                );
                return Err(err.into());
            }
        },
    };
    let lock_yaml = match input.lock_yaml {
        Some(lock_yaml) => lock_yaml,
        None => crate::lifecycle::freeze_from_blueprint_yaml(blueprint_yaml)?,
    };
    let selection = DriverSelection {
        sandbox: resolved.sandbox.driver.clone(),
        agent: resolved.agent.driver.clone(),
        context: resolved.context.driver.clone(),
        inference: resolved
            .inference
            .as_ref()
            .map(|driver| driver.driver.clone()),
    };
    let admission = match run_preflight_with_pins(
        options,
        factory,
        name,
        &selection,
        input.driver_pins.as_ref(),
        Arc::clone(&events),
    )
    .await
    {
        Ok(admission) => admission,
        Err(err) => {
            emit_runtime_event(
                events.as_ref(),
                core_activity_event(
                    ActivityKind::SpawnRejected,
                    ActivityResult::Denied,
                    &trace_id,
                    Some(name),
                )
                .with_reason_code(runtime_error_reason_code(&err)),
            );
            return Err(err);
        }
    };
    if admission.status == crate::admission::AdmissionStatus::Rejected {
        emit_runtime_event(
            events.as_ref(),
            core_activity_event(
                ActivityKind::SpawnRejected,
                ActivityResult::Denied,
                &trace_id,
                Some(name),
            )
            .with_reason_code(admission.reason_code.as_str()),
        );
        return Ok(CreateResult {
            admission,
            state: empty_state(name, selection),
            state_path: paths.state_path(),
        });
    }
    emit_runtime_event(
        events.as_ref(),
        core_activity_event(
            ActivityKind::SpawnAdmitted,
            ActivityResult::Ok,
            &trace_id,
            Some(name),
        )
        .with_reason_code(admission.reason_code.as_str()),
    );

    let mut set = build_driver_set(
        factory,
        &selection,
        input.driver_pins.as_ref(),
        Arc::clone(&events),
    )?;
    let temp_workspace = create_temp_workspace(&options.root, env_name.as_str());
    let temp_paths = crate::env::EnvPaths::new(temp_workspace.clone(), env_name.clone());
    let mut rollback = CreateEnvRollback::new(temp_workspace.clone());

    emit_runtime_event(
        events.as_ref(),
        core_activity_event(
            ActivityKind::SpawnStarted,
            ActivityResult::Ok,
            &trace_id,
            Some(name),
        ),
    );

    let result = async {
        let sandbox_init = initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
        initialize_agent_driver(options, set.agent.as_mut()).await?;
        initialize_context_driver(options, set.context.as_mut()).await?;
        if let Some(inference) = set.inference.as_mut() {
            initialize_inference_driver(options, inference.as_mut()).await?;
        }

        let agent_spec = agent_spec(
            resolved.blueprint.agent.extra.clone(),
            resolved.blueprint.agent.version.clone(),
        )?;
        let mut requirements = set
            .agent
            .credential_requirements(agent_spec.clone())
            .await?
            .requirements;
        requirements.extend(
            set.context
                .credential_requirements(agentenv_proto::CredentialRequirementsParams {})
                .await?
                .requirements,
        );
        if let Some(inference) = set.inference.as_ref() {
            requirements.extend(
                inference
                    .credential_requirements(agentenv_proto::CredentialRequirementsParams {})
                    .await?
                    .requirements,
            );
        }

        fs::create_dir_all(temp_paths.env_dir()).map_err(|source| crate::env::EnvError::Io {
            path: temp_paths.env_dir(),
            source,
        })?;
        fs::write(temp_paths.blueprint_path(), blueprint_yaml).map_err(|source| {
            crate::env::EnvError::Io {
                path: temp_paths.blueprint_path(),
                source,
            }
        })?;
        fs::write(temp_paths.lock_path(), &lock_yaml).map_err(|source| {
            crate::env::EnvError::Io {
                path: temp_paths.lock_path(),
                source,
            }
        })?;

        let context_handle = set
            .context
            .provision(context_spec(resolved.blueprint.context.extra.clone())?)
            .await?;
        rollback.set_context(set.context.as_ref(), context_handle.handle.clone());
        let context_endpoint = set
            .context
            .mcp_endpoint(agentenv_proto::ContextHandleRequest {
                handle: context_handle.handle.clone(),
            })
            .await?;
        let context_network_rules = set
            .context
            .required_network_rules(agentenv_proto::ContextHandleRequest {
                handle: context_handle.handle.clone(),
            })
            .await?;
        let send_hardening_metadata = input.resolved_policy.is_none()
            || crate::hardening::sandbox_hardening_declared(&resolved.blueprint.sandbox);
        let resolved_hardening = if send_hardening_metadata {
            Some(crate::hardening::resolve_sandbox_hardening(
                &resolved.blueprint.sandbox,
            )?)
        } else {
            None
        };
        let persist_home = resolved
            .blueprint
            .state
            .as_ref()
            .and_then(|state| state.persist_home)
            .unwrap_or(false);

        let (inference_handle, inference_endpoint) = match (
            set.inference.as_ref(),
            resolved.blueprint.inference.as_ref(),
        ) {
            (Some(inference), Some(component)) => {
                let handle = inference
                    .provision(inference_spec(component.extra.clone())?)
                    .await?;
                rollback.set_inference(inference.as_ref(), handle.handle.clone());
                let endpoint = inference
                    .endpoint_in_sandbox(agentenv_proto::InferenceHandleRequest {
                        handle: handle.handle.clone(),
                    })
                    .await?;
                (Some(handle.handle), Some(endpoint.url))
            }
            _ => (None, None),
        };

        let mut policy = match input.resolved_policy.as_ref() {
            Some(policy) => policy.clone(),
            None => compose_policy(
                parse_tier(&resolved.blueprint.policy.tier)?,
                &parse_presets(&resolved.blueprint.policy.presets)?,
                policy_overrides(&resolved.blueprint.policy)?,
                &PresetRegistry::load_builtin().map_err(|err| {
                    RuntimeError::Driver(crate::driver::DriverError::PolicyTranslation {
                        message: err.to_string(),
                    })
                })?,
            )
            .map_err(|err| {
                RuntimeError::Driver(crate::driver::DriverError::PolicyTranslation {
                    message: err.to_string(),
                })
            })?,
        };
        if let (None, Some(resolved_hardening)) =
            (input.resolved_policy.as_ref(), resolved_hardening.as_ref())
        {
            crate::hardening::apply_resolved_hardening_to_policy(
                &mut policy,
                resolved_hardening,
                persist_home,
            )?;
            policy.network.allow.extend(context_network_rules.rules);
        }

        let egress_proxy_plan = build_runtime_egress_proxy_plan(RuntimeEgressProxyPlanInput {
            env_name: name,
            requirements: &requirements,
            policy: &policy,
            context_endpoint: &context_endpoint,
            inference_endpoint: inference_endpoint.as_deref(),
            policy_extra: &resolved.blueprint.policy.extra,
            sandbox_capabilities: &sandbox_init.capabilities,
            sandbox_driver: &selection.sandbox,
        })?;
        let context_endpoint_for_sandbox =
            rewrite_context_endpoint_for_proxy(&context_endpoint, &egress_proxy_plan);
        let mut env = sandbox_env_for_credential_plan(
            credentials,
            &requirements,
            &egress_proxy_plan,
            events.as_ref(),
            &trace_id,
            name,
        )?;
        env.extend(egress_proxy_plan.sandbox_env.clone());
        let credential_names = credential_names_for_plan(&requirements, &egress_proxy_plan);
        let agent_setup = prepare_agent_sandbox_setup(
            &temp_workspace,
            set.agent.as_ref(),
            agent_spec.clone(),
            vec![context_endpoint_for_sandbox.clone()],
        )
        .await?;

        let supports_hot_reload_policy = supports_hot_reload_policy(&sandbox_init.capabilities);
        let create_policy = if supports_hot_reload_policy {
            create_policy_for_agent_install(&policy, &agent_setup)
        } else {
            policy.clone()
        };
        validate_runtime_dns_policy(&create_policy)?;
        ensure_dns_policy_supported(&sandbox_init.capabilities, &create_policy)?;
        let restore_policy_after_install = supports_hot_reload_policy && create_policy != policy;

        let build_oneflight_seed = build_oneflight_seed_for_byo(
            blueprint_yaml,
            &lock_yaml,
            &selection,
            &resolved,
            &context_endpoint_for_sandbox,
            &resolved.blueprint.sandbox.extra,
        )?;

        let sandbox_create_start = Instant::now();
        let sandbox_spec = sandbox_spec_for_create(
            name,
            &selection,
            &resolved.blueprint.sandbox.extra,
            &context_endpoint_for_sandbox,
            SandboxSpecCreateOptions {
                env,
                policy: Some(create_policy.clone()),
                build_oneflight_seed,
                resolved_hardening: resolved_hardening.as_ref(),
            },
        )?;
        let sandbox_handle = match set.sandbox.create(sandbox_spec).await {
            Ok(handle) => {
                emit_runtime_event(
                    events.as_ref(),
                    core_activity_event(
                        ActivityKind::SandboxCreate,
                        ActivityResult::Ok,
                        &trace_id,
                        Some(name),
                    )
                    .with_subject_value("handle", serde_json::json!(handle.handle.clone()))
                    .with_latency_ms(elapsed_ms(sandbox_create_start)),
                );
                emit_runtime_event(
                    events.as_ref(),
                    core_policy_applied_event(
                        ActivityResult::Ok,
                        &trace_id,
                        Some(name),
                        &handle.handle,
                        "sandbox_create",
                        &create_policy,
                        elapsed_ms(sandbox_create_start),
                    ),
                );
                handle
            }
            Err(err) => {
                emit_runtime_event(
                    events.as_ref(),
                    core_activity_event(
                        ActivityKind::SandboxCreate,
                        ActivityResult::Error,
                        &trace_id,
                        Some(name),
                    )
                    .with_reason_code(crate::admission::ReasonCode::DriverCommandFailed.as_str())
                    .with_latency_ms(elapsed_ms(sandbox_create_start)),
                );
                return Err(err.into());
            }
        };
        let sandbox_handle_value = sandbox_handle.handle.clone();
        rollback.set_sandbox(set.sandbox.as_ref(), sandbox_handle_value.clone());
        record_computed_byo_image_digest(
            &temp_paths,
            &options.root,
            name,
            &resolved.blueprint.sandbox.extra,
        )?;
        install_agent_in_sandbox(set.sandbox.as_ref(), &sandbox_handle_value, &agent_setup).await?;
        if restore_policy_after_install {
            validate_runtime_dns_policy(&policy)?;
            ensure_dns_policy_supported(&sandbox_init.capabilities, &policy)?;
            let apply_policy_start = Instant::now();
            match set
                .sandbox
                .apply_policy(agentenv_proto::ApplyPolicyParams {
                    handle: sandbox_handle_value.clone(),
                    policy: policy.clone(),
                })
                .await
            {
                Ok(result) => {
                    emit_runtime_event(
                        events.as_ref(),
                        core_policy_applied_event(
                            ActivityResult::Ok,
                            &trace_id,
                            Some(name),
                            &sandbox_handle_value,
                            "restore_after_install",
                            &policy,
                            elapsed_ms(apply_policy_start),
                        )
                        .with_subject_value("hot_reloaded", serde_json::json!(result.hot_reloaded)),
                    );
                }
                Err(err) => {
                    emit_runtime_event(
                        events.as_ref(),
                        core_policy_applied_event(
                            ActivityResult::Error,
                            &trace_id,
                            Some(name),
                            &sandbox_handle_value,
                            "restore_after_install",
                            &policy,
                            elapsed_ms(apply_policy_start),
                        )
                        .with_reason_code(
                            crate::admission::ReasonCode::DriverCommandFailed.as_str(),
                        ),
                    );
                    return Err(err.into());
                }
            }
        }

        let now = now_utc_string();
        let drivers = crate::env::StateDriverSet {
            sandbox: crate::env::DriverRecord::new(
                &selection.sandbox,
                resolved.sandbox.version.to_string(),
            ),
            agent: crate::env::DriverRecord::new(
                &selection.agent,
                resolved.agent.version.to_string(),
            ),
            context: crate::env::DriverRecord::new(
                &selection.context,
                resolved.context.version.to_string(),
            ),
            inference: resolved.inference.as_ref().map(|driver| {
                crate::env::DriverRecord::new(&driver.driver, driver.version.to_string())
            }),
        };

        let mut state = crate::env::EnvStateFile {
            version: crate::env::STATE_VERSION.to_owned(),
            name: name.to_owned(),
            phase: crate::env::EnvPhase::Running,
            created_at: now.clone(),
            updated_at: now,
            drivers,
            handles: crate::env::DriverHandles {
                sandbox: Some(sandbox_handle.handle),
                context: Some(context_handle.handle),
                inference: inference_handle,
            },
            endpoints: crate::env::EndpointState {
                context_mcp: Some(crate::env::PersistedMcpEndpoint::from_mcp(
                    context_endpoint_for_sandbox,
                )),
                inference: inference_endpoint,
            },
            egress_proxy: None,
            resolved_policy: Some(policy.clone()),
            credential_names: credential_names.clone(),
            health: BTreeMap::new(),
            first_enter_hint_shown: false,
        };

        crate::env::write_state(&temp_paths, &state)?;
        crate::env::append_event(
            &temp_paths,
            serde_json::json!({
                "kind": "admission",
                "status": "accepted",
                "reason_code": crate::admission::ReasonCode::Created.as_str(),
                "env": name,
            }),
        )?;

        fs::create_dir_all(paths.envs_dir()).map_err(|source| crate::env::EnvError::Io {
            path: paths.envs_dir(),
            source,
        })?;
        if env_dir.exists() {
            return Err(crate::env::EnvError::AlreadyExists {
                name: name.to_owned(),
            }
            .into());
        }
        fs::rename(temp_paths.env_dir(), &env_dir).map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                crate::env::EnvError::AlreadyExists {
                    name: name.to_owned(),
                }
            } else {
                crate::env::EnvError::Io {
                    path: env_dir.clone(),
                    source,
                }
            }
        })?;
        rollback.set_final_env_dir(env_dir.clone());
        let _ = fs::remove_dir_all(&temp_workspace);

        if !egress_proxy_plan.routes.is_empty() {
            let launch = prepare_egress_proxy_launch_files(
                name,
                &env_dir,
                &egress_proxy_plan,
                credential_names.iter().map(String::as_str),
                &policy,
            )?;
            let process = start_egress_proxy_process(
                name,
                &launch.config_path,
                env_events_db_path(options, name)?,
            )
            .await?;
            let proxy_pid = process.pid;
            rollback.set_egress_proxy(process);
            state.egress_proxy = Some(crate::env::EgressProxyState {
                pid: Some(proxy_pid),
                listen_url: egress_proxy_plan.listen_url.clone(),
                config_path: launch.config_path,
                policy_path: launch.policy_path,
                routes: egress_proxy_plan
                    .routes
                    .iter()
                    .map(|route| route.id.clone())
                    .collect(),
            });
            state.updated_at = now_utc_string();
            crate::env::write_state(&paths, &state)?;
        }

        emit_runtime_event(
            events.as_ref(),
            core_activity_event(
                ActivityKind::SpawnReady,
                ActivityResult::Ok,
                &trace_id,
                Some(name),
            )
            .with_subject_value("handle", serde_json::json!(sandbox_handle_value)),
        );

        Ok(CreateResult {
            admission: crate::admission::AdmissionReport::accepted(name),
            state,
            state_path: paths.state_path(),
        })
    }
    .await;

    if let Err(err) = &result {
        emit_runtime_event(
            events.as_ref(),
            core_activity_event(
                ActivityKind::SpawnRejected,
                ActivityResult::Error,
                &trace_id,
                Some(name),
            )
            .with_reason_code(runtime_error_reason_code(err)),
        );
        rollback.rollback().await;
    }

    result
}

pub fn list_envs(options: &RuntimeOptions) -> RuntimeResult<Vec<EnvListRow>> {
    let envs_dir = options.root.join("envs");
    if !envs_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut rows = Vec::new();
    for entry in fs::read_dir(&envs_dir).map_err(|source| crate::env::EnvError::Io {
        path: envs_dir.clone(),
        source,
    })? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) => {
                return Err(crate::env::EnvError::Io {
                    path: envs_dir.clone(),
                    source,
                }
                .into());
            }
        };

        let file_type = entry
            .file_type()
            .map_err(|source| crate::env::EnvError::Io {
                path: entry.path(),
                source,
            })?;
        if !file_type.is_dir() {
            continue;
        }

        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(env_name) = crate::env::validate_env_name(&name) else {
            continue;
        };

        let paths = crate::env::EnvPaths::new(options.root.clone(), env_name);
        let state = crate::env::read_state(&paths)?;
        if state.name != name {
            return Err(RuntimeError::StateNameMismatch {
                expected: name,
                actual: state.name,
            });
        }

        rows.push(EnvListRow {
            name,
            agent: state.drivers.agent.name,
            sandbox: state.drivers.sandbox.name,
            context: state.drivers.context.name,
            inference: state.drivers.inference.map(|driver| driver.name),
            status: env_phase_status(state.phase),
            created_at: state.created_at,
        });
    }

    rows.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(rows)
}

pub fn describe_env(options: &RuntimeOptions, name: &str) -> RuntimeResult<EnvDescription> {
    let env_name = crate::env::validate_env_name(name)?;
    let paths = crate::env::EnvPaths::new(options.root.clone(), env_name);
    let env_dir = paths.env_dir();
    match fs::symlink_metadata(&env_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(crate::env::EnvError::NotFound {
                name: name.to_owned(),
            }
            .into());
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(crate::env::EnvError::NotFound {
                name: name.to_owned(),
            }
            .into());
        }
        Err(source) => {
            return Err(crate::env::EnvError::Io {
                path: env_dir,
                source,
            }
            .into());
        }
    }

    let state = crate::env::read_state(&paths)?;
    if state.name != name {
        return Err(RuntimeError::StateNameMismatch {
            expected: name.to_owned(),
            actual: state.name.clone(),
        });
    }
    let blueprint_path = paths.blueprint_path();
    let blueprint_yaml = String::from_utf8(crate::env::read_regular_file(&blueprint_path)?)
        .map_err(|source| crate::env::EnvError::Io {
            path: blueprint_path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
        })?;
    let lock_path = paths.lock_path();
    let lock_yaml =
        String::from_utf8(crate::env::read_regular_file(&lock_path)?).map_err(|source| {
            crate::env::EnvError::Io {
                path: lock_path.clone(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
            }
        })?;

    Ok(EnvDescription {
        state,
        blueprint_yaml,
        lock_yaml,
    })
}

fn describe_env_for_fork_source(
    options: &RuntimeOptions,
    source: &str,
) -> RuntimeResult<EnvDescription> {
    let mut valid_env_not_found = None;
    if crate::env::validate_env_name(source).is_ok() {
        match describe_env(options, source) {
            Ok(description) => return Ok(description),
            Err(RuntimeError::Env(crate::env::EnvError::NotFound { name })) => {
                valid_env_not_found = Some(name);
            }
            Err(err) => return Err(err),
        }
    }

    if let Some(description) = describe_env_by_sandbox_handle(options, source)? {
        return Ok(description);
    }

    match valid_env_not_found {
        Some(name) => Err(crate::env::EnvError::NotFound { name }.into()),
        None => Err(RuntimeError::SandboxHandleNotFound {
            handle: source.to_owned(),
        }),
    }
}

fn describe_env_by_sandbox_handle(
    options: &RuntimeOptions,
    handle: &str,
) -> RuntimeResult<Option<EnvDescription>> {
    let envs_dir = options.root.join("envs");
    if !envs_dir.is_dir() {
        return Ok(None);
    }

    for entry in fs::read_dir(&envs_dir).map_err(|source| crate::env::EnvError::Io {
        path: envs_dir.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| crate::env::EnvError::Io {
            path: envs_dir.clone(),
            source,
        })?;
        let file_type = entry
            .file_type()
            .map_err(|source| crate::env::EnvError::Io {
                path: entry.path(),
                source,
            })?;
        if !file_type.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(env_name) = crate::env::validate_env_name(&name) else {
            continue;
        };
        let paths = crate::env::EnvPaths::new(options.root.clone(), env_name);
        let state = crate::env::read_state(&paths)?;
        if state.name != name {
            return Err(RuntimeError::StateNameMismatch {
                expected: name,
                actual: state.name,
            });
        }
        if state.handles.sandbox.as_deref() == Some(handle) {
            return describe_env(options, &name).map(Some);
        }
    }

    Ok(None)
}

fn write_env_registry_file(content: &str, path: &Path) -> RuntimeResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| crate::env::EnvError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::write(path, content).map_err(|source| crate::env::EnvError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

pub fn freeze_env_lockfile(options: &RuntimeOptions, name: &str) -> RuntimeResult<String> {
    let description = describe_env(options, name)?;
    freeze_env_lockfile_from_description(options, description)
}

fn freeze_env_lockfile_from_description(
    options: &RuntimeOptions,
    description: EnvDescription,
) -> RuntimeResult<String> {
    let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
    discovery_config.installed_root = options.root.join("drivers");
    let driver_artifacts =
        crate::driver_artifact::discover_driver_artifacts(discovery_config, None)?;

    if let crate::lockfile::LockfileDocument::Portable(mut lockfile) =
        crate::lockfile::LockfileDocument::from_yaml(&description.lock_yaml)?
    {
        let env_blueprint = crate::blueprint::Blueprint::from_yaml(&description.blueprint_yaml)?;
        let env_hardening_declared =
            crate::hardening::sandbox_hardening_declared(&env_blueprint.sandbox);
        let expected_lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: description.state.name.clone(),
                blueprint_yaml: description.blueprint_yaml.clone(),
                driver_artifacts: driver_artifacts.clone(),
            },
        )?;
        if !portable_lockfile_matches_env_blueprint(
            &lockfile,
            &expected_lockfile,
            env_hardening_declared,
        )? {
            return Err(RuntimeError::PortableLockfileVerification {
                details:
                    "portable lockfile composition does not match env blueprint or declared policy"
                        .to_owned(),
            });
        }

        let report = crate::portable_lockfile::verify_portable_lockfile_yaml(
            &description.lock_yaml,
            &driver_artifacts,
        )?;
        if !report.errors.is_empty() {
            let details = report
                .errors
                .iter()
                .map(|issue| issue.message.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(RuntimeError::PortableLockfileVerification { details });
        }

        validate_frozen_lockfile_pins(&description.state, &lockfile)?;
        if let Some(resolved_policy) = description.state.resolved_policy.clone() {
            lockfile.policy.resolved = resolved_policy;
        }
        lockfile.name = description.state.name.clone();
        return Ok(lockfile.to_yaml_deterministic()?);
    }

    let mut lockfile = crate::portable_lockfile::build_portable_lockfile(
        crate::portable_lockfile::PortableLockfileInput {
            name: description.state.name.clone(),
            blueprint_yaml: description.blueprint_yaml,
            driver_artifacts,
        },
    )?;
    validate_frozen_lockfile_pins(&description.state, &lockfile)?;
    if let Some(resolved_policy) = description.state.resolved_policy {
        lockfile.policy.resolved = resolved_policy;
    }

    Ok(lockfile.to_yaml_deterministic()?)
}

pub fn freeze_env_for_bundle(
    options: &RuntimeOptions,
    name: &str,
) -> RuntimeResult<FrozenEnvBundleSource> {
    let description = describe_env(options, name)?;
    let env_name = description.state.name.clone();
    let blueprint_yaml = description.blueprint_yaml.clone();
    let lockfile_yaml = freeze_env_lockfile_from_description(options, description)?;
    Ok(FrozenEnvBundleSource {
        env_name,
        blueprint_yaml,
        lockfile_yaml,
    })
}

fn portable_lockfile_matches_env_blueprint(
    lockfile: &crate::lockfile::PortableLockfile,
    expected: &crate::lockfile::PortableLockfile,
    env_hardening_declared: bool,
) -> RuntimeResult<bool> {
    if lockfile.policy.declared != expected.composition.policy {
        return Ok(false);
    }
    if lockfile.composition == expected.composition
        && lockfile.blueprint_hash == expected.blueprint_hash
    {
        return Ok(true);
    }
    if env_hardening_declared || lockfile.composition.sandbox.extra.contains_key("hardening") {
        return Ok(false);
    }

    let mut legacy_expected = expected.composition.clone();
    legacy_expected.sandbox.extra.remove("hardening");
    let legacy_hash = crate::lifecycle::portable_blueprint_hash(&legacy_expected)?;
    Ok(lockfile.composition == legacy_expected && lockfile.blueprint_hash == legacy_hash)
}

pub async fn snapshot_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    args: SnapshotEnvArgs,
) -> RuntimeResult<SnapshotEnvResult> {
    reject_existing_snapshot_output(&args.output)?;

    let env_name = crate::env::validate_env_name(&args.env)?;
    let description = describe_env(options, env_name.as_str())?;
    let verified_lock_yaml = freeze_env_lockfile(options, env_name.as_str())?;
    let lockfile = portable_snapshot_lockfile(&verified_lock_yaml)?;
    let policy = lockfile
        .as_ref()
        .map(|lockfile| lockfile.policy.resolved.clone())
        .or_else(|| description.state.resolved_policy.clone())
        .unwrap_or_else(empty_policy_override);
    let credential_requirements = lockfile
        .as_ref()
        .map(snapshot_credential_requirements)
        .unwrap_or_default();
    let persist_home = blueprint_persist_home(&description.blueprint_yaml, lockfile.as_ref());

    let selection = selection_from_state(&description.state);
    let handle = required_sandbox_handle(&description.state, env_name.as_str())?;
    let events: Arc<dyn EventEmitter> = Arc::new(NoopEventEmitter);
    let mut set = factory.build_for_env_observed(
        &selection,
        env_name.as_str(),
        Arc::clone(&events),
        Some(approval_coordinator_for_env(
            options,
            env_name.as_str(),
            Arc::clone(&events),
        )?),
    )?;
    initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;

    let staging_dir = create_temp_snapshot_dir(&options.root, env_name.as_str());
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir).map_err(|source| crate::env::EnvError::Io {
            path: staging_dir.clone(),
            source,
        })?;
    }
    fs::create_dir_all(&staging_dir).map_err(|source| crate::env::EnvError::Io {
        path: staging_dir.clone(),
        source,
    })?;

    let result = async {
        write_snapshot_registry_files(
            options,
            env_name.as_str(),
            &staging_dir,
            &description.blueprint_yaml,
            &verified_lock_yaml,
            &policy,
        )?;
        copy_sandbox_path_out(
            set.sandbox.as_ref(),
            &handle,
            "/sandbox",
            &staging_dir.join("workspace"),
        )
        .await?;
        if persist_home {
            let home = resolve_sandbox_home(set.sandbox.as_ref(), &handle).await?;
            copy_sandbox_path_out(
                set.sandbox.as_ref(),
                &handle,
                &home,
                &staging_dir.join("home"),
            )
            .await?;
        }

        let sanitizer_report = crate::snapshot::sanitize_snapshot_tree(&staging_dir)?;
        let manifest = crate::snapshot::manifest_for_snapshot_dir(
            &staging_dir,
            env_name.as_str(),
            credential_requirements,
            sanitizer_report.stripped,
        )?;
        let signing_key = options.root.join("snapshot-signing.key");
        crate::snapshot::write_signed_manifest(&staging_dir, &signing_key, &manifest)?;
        let verified = crate::snapshot::verify_snapshot_dir(&staging_dir)?;
        Ok::<crate::snapshot::SnapshotManifest, RuntimeError>(verified)
    }
    .await;

    let manifest = match result {
        Ok(manifest) => manifest,
        Err(error) => {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(error);
        }
    };

    finalize_snapshot_dir_no_clobber(&staging_dir, &args.output)?;

    Ok(SnapshotEnvResult {
        path: args.output,
        file_count: manifest.files.len(),
        merkle_root: manifest.merkle_root,
    })
}

pub fn verify_snapshot(path: &Path) -> RuntimeResult<SnapshotVerifyResult> {
    let manifest = crate::snapshot::verify_snapshot_dir(path)?;
    verify_snapshot_contents(path, &manifest)?;
    Ok(SnapshotVerifyResult {
        path: path.to_path_buf(),
        file_count: manifest.files.len(),
        merkle_root: manifest.merkle_root,
    })
}

fn verify_snapshot_contents(
    snapshot: &Path,
    manifest: &crate::snapshot::SnapshotManifest,
) -> RuntimeResult<()> {
    verify_snapshot_manifest_compatibility(manifest)?;

    let snapshot_policy = read_snapshot_policy(&snapshot.join("policy.yaml"))?;
    let lock_path = snapshot.join("lock.yaml");
    let lock_yaml = fs::read_to_string(&lock_path).map_err(|source| crate::env::EnvError::Io {
        path: lock_path,
        source,
    })?;
    let lockfile = verify_snapshot_lockfile(&lock_yaml)?;
    if lockfile.policy.resolved != snapshot_policy {
        return Err(RuntimeError::PortableLockfileVerification {
            details: "snapshot policy.yaml does not match lock.yaml resolved policy".to_owned(),
        });
    }

    Ok(())
}

fn verify_snapshot_manifest_compatibility(
    manifest: &crate::snapshot::SnapshotManifest,
) -> RuntimeResult<()> {
    let min_agentenv_version =
        semver::Version::parse(&manifest.min_agentenv_version).map_err(|source| {
            RuntimeError::PortableLockfileVerification {
                details: format!(
                    "snapshot min_agentenv_version `{}` is invalid: {source}",
                    manifest.min_agentenv_version
                ),
            }
        })?;
    let current_agentenv_version =
        semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version must be semver");
    if min_agentenv_version > current_agentenv_version {
        return Err(RuntimeError::PortableLockfileVerification {
            details: format!(
                "snapshot min_agentenv_version `{}` is newer than current agentenv version `{}`",
                manifest.min_agentenv_version,
                env!("CARGO_PKG_VERSION")
            ),
        });
    }

    agentenv_proto::assert_compatible_schema_version(&manifest.driver_protocol_version).map_err(
        |_| RuntimeError::PortableLockfileVerification {
            details: format!(
                "snapshot driver protocol version `{}` is incompatible with `{SCHEMA_VERSION}`",
                manifest.driver_protocol_version
            ),
        },
    )?;

    Ok(())
}

fn verify_snapshot_lockfile(lock_yaml: &str) -> RuntimeResult<crate::lockfile::PortableLockfile> {
    let document = crate::lockfile::LockfileDocument::from_yaml(lock_yaml)?;
    let crate::lockfile::LockfileDocument::Portable(lockfile) = document else {
        return Err(RuntimeError::PortableLockfileVerification {
            details: "snapshot lock.yaml must be a portable 0.2.0 lockfile".to_owned(),
        });
    };

    if lockfile.policy.declared != lockfile.composition.policy {
        return Err(RuntimeError::PortableLockfileVerification {
            details: "lock.yaml policy.declared does not match composition.policy".to_owned(),
        });
    }

    Ok(lockfile)
}

pub async fn restore_snapshot_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    credentials: &mut dyn CredentialProvider,
    args: SnapshotRestoreArgs,
) -> RuntimeResult<SnapshotRestoreResult> {
    let manifest = crate::snapshot::verify_snapshot_dir(&args.snapshot)?;
    verify_snapshot_contents(&args.snapshot, &manifest)?;
    let name = args.name.unwrap_or_else(|| manifest.source_env.clone());
    let env_name = crate::env::validate_env_name(&name)?;
    let paths = crate::env::EnvPaths::new(options.root.clone(), env_name.clone());
    if paths.env_dir().exists() {
        return Err(crate::env::EnvError::AlreadyExists { name }.into());
    }
    check_snapshot_credentials(credentials, &manifest)?;

    let policy_path = args.snapshot.join("policy.yaml");
    let snapshot_policy = read_snapshot_policy(&policy_path)?;
    let lock_path = args.snapshot.join("lock.yaml");
    let lock_yaml = fs::read_to_string(&lock_path).map_err(|source| crate::env::EnvError::Io {
        path: lock_path,
        source,
    })?;
    let lock_yaml = restore_lock_yaml_with_snapshot_policy(&lock_yaml, snapshot_policy)?;

    let staging_dir = create_temp_snapshot_dir(&options.root, env_name.as_str());
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir).map_err(|source| crate::env::EnvError::Io {
            path: staging_dir.clone(),
            source,
        })?;
    }
    let _staging_cleanup = SnapshotStagingCleanup::new(staging_dir.clone());
    copy_verified_snapshot_to_staging(&args.snapshot, &staging_dir)?;
    crate::snapshot::sanitize_snapshot_tree(&staging_dir)?;
    validate_restore_payload_symlinks(&staging_dir)?;

    let result = async {
        reproduce_env(options, factory, credentials, env_name.as_str(), &lock_yaml).await?;

        let description = describe_env(options, env_name.as_str())?;
        let selection = selection_from_state(&description.state);
        let handle = required_sandbox_handle(&description.state, env_name.as_str())?;
        let events: Arc<dyn EventEmitter> = Arc::new(NoopEventEmitter);
        let mut set = factory.build_for_env_observed(
            &selection,
            env_name.as_str(),
            Arc::clone(&events),
            Some(approval_coordinator_for_env(
                options,
                env_name.as_str(),
                Arc::clone(&events),
            )?),
        )?;
        initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;

        copy_host_path_into_sandbox(
            set.sandbox.as_ref(),
            &handle,
            &staging_dir.join("workspace"),
            "/sandbox",
        )
        .await?;

        let home_path = staging_dir.join("home");
        if home_path.is_dir() {
            let home = resolve_sandbox_home(set.sandbox.as_ref(), &handle).await?;
            copy_host_path_into_sandbox(set.sandbox.as_ref(), &handle, &home_path, &home).await?;
        }

        Ok::<(), RuntimeError>(())
    }
    .await;

    result?;

    Ok(SnapshotRestoreResult {
        name: env_name.as_str().to_owned(),
        snapshot: args.snapshot,
    })
}

struct SnapshotStagingCleanup {
    path: PathBuf,
}

impl SnapshotStagingCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for SnapshotStagingCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn read_snapshot_policy(path: &Path) -> RuntimeResult<agentenv_proto::NetworkPolicy> {
    let policy_yaml = fs::read_to_string(path).map_err(|source| crate::env::EnvError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_yaml::from_str(&policy_yaml)
        .map_err(|source| RuntimeError::Snapshot(crate::snapshot::SnapshotError::Yaml(source)))
}

fn restore_lock_yaml_with_snapshot_policy(
    lock_yaml: &str,
    snapshot_policy: agentenv_proto::NetworkPolicy,
) -> RuntimeResult<String> {
    let document = crate::lockfile::LockfileDocument::from_yaml(lock_yaml)?;
    let mut lockfile = match document {
        crate::lockfile::LockfileDocument::Legacy(_) => {
            return Err(RuntimeError::LegacyLockfileReproduce);
        }
        crate::lockfile::LockfileDocument::Portable(lockfile) => lockfile,
    };
    lockfile.policy.resolved = snapshot_policy;
    Ok(lockfile.to_yaml_deterministic()?)
}

fn copy_verified_snapshot_to_staging(snapshot: &Path, staging_dir: &Path) -> RuntimeResult<()> {
    fs::create_dir_all(staging_dir).map_err(|source| crate::env::EnvError::Io {
        path: staging_dir.to_path_buf(),
        source,
    })?;
    for entry in fs::read_dir(snapshot).map_err(|source| crate::env::EnvError::Io {
        path: snapshot.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| crate::env::EnvError::Io {
            path: snapshot.to_path_buf(),
            source,
        })?;
        let src = entry.path();
        let dst = staging_dir.join(entry.file_name());
        copy_host_tree_entry(&src, &dst)?;
    }
    Ok(())
}

fn validate_restore_payload_symlinks(root: &Path) -> RuntimeResult<()> {
    validate_restore_payload_symlinks_inner(root, root)
}

fn validate_restore_payload_symlinks_inner(root: &Path, current: &Path) -> RuntimeResult<()> {
    for entry in fs::read_dir(current).map_err(|source| crate::env::EnvError::Io {
        path: current.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| crate::env::EnvError::Io {
            path: current.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| crate::env::EnvError::Io {
            path: path.clone(),
            source,
        })?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            validate_restore_payload_symlinks_inner(root, &path)?;
            continue;
        }

        if file_type.is_symlink() {
            let target = fs::read_link(&path).map_err(|source| crate::env::EnvError::Io {
                path: path.clone(),
                source,
            })?;
            if symlink_target_escapes_restore_payload(&target) {
                let relative = path
                    .strip_prefix(root)
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|_| path.display().to_string());
                return Err(RuntimeError::Driver(DriverError::InvalidInput {
                    message: format!(
                        "unsafe snapshot symlink `{relative}` points outside restore payload"
                    ),
                }));
            }
        }
    }

    Ok(())
}

fn symlink_target_escapes_restore_payload(target: &Path) -> bool {
    target.is_absolute()
        || target
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
}

fn copy_host_tree_entry(src: &Path, dst: &Path) -> RuntimeResult<()> {
    let metadata = fs::symlink_metadata(src).map_err(|source| crate::env::EnvError::Io {
        path: src.to_path_buf(),
        source,
    })?;
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        fs::create_dir_all(dst).map_err(|source| crate::env::EnvError::Io {
            path: dst.to_path_buf(),
            source,
        })?;
        for entry in fs::read_dir(src).map_err(|source| crate::env::EnvError::Io {
            path: src.to_path_buf(),
            source,
        })? {
            let entry = entry.map_err(|source| crate::env::EnvError::Io {
                path: src.to_path_buf(),
                source,
            })?;
            copy_host_tree_entry(&entry.path(), &dst.join(entry.file_name()))?;
        }
        return Ok(());
    }

    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|source| crate::env::EnvError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    if file_type.is_file() {
        fs::copy(src, dst).map_err(|source| crate::env::EnvError::Io {
            path: dst.to_path_buf(),
            source,
        })?;
        return Ok(());
    }

    if file_type.is_symlink() {
        let target = fs::read_link(src).map_err(|source| crate::env::EnvError::Io {
            path: src.to_path_buf(),
            source,
        })?;
        create_host_symlink(&target, dst).map_err(|source| crate::env::EnvError::Io {
            path: dst.to_path_buf(),
            source,
        })?;
        return Ok(());
    }

    Err(RuntimeError::Driver(DriverError::InvalidInput {
        message: format!("unsupported snapshot payload path `{}`", src.display()),
    }))
}

#[cfg(unix)]
fn create_host_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_host_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

pub async fn reproduce_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    credentials: &mut dyn CredentialProvider,
    name: &str,
    lockfile_yaml: &str,
) -> RuntimeResult<CreateResult> {
    let document = crate::lockfile::LockfileDocument::from_yaml(lockfile_yaml)?;
    let mut lockfile = match document {
        crate::lockfile::LockfileDocument::Legacy(_) => {
            return Err(RuntimeError::LegacyLockfileReproduce);
        }
        crate::lockfile::LockfileDocument::Portable(lockfile) => lockfile,
    };

    let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
    discovery_config.installed_root = options.root.join("drivers");
    let driver_artifacts =
        crate::driver_artifact::discover_driver_artifacts(discovery_config, None)?;
    let report =
        crate::portable_lockfile::verify_portable_lockfile_yaml(lockfile_yaml, &driver_artifacts)?;
    if !report.errors.is_empty() {
        let details = report
            .errors
            .iter()
            .map(|issue| issue.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(RuntimeError::PortableLockfileVerification { details });
    }

    verify_reproduce_skill_pins(options, &lockfile)?;
    check_required_lockfile_credentials(credentials, &lockfile)?;
    let credential_bindings = credential_bindings_from_portable_lockfile(&lockfile);
    let blueprint_yaml = blueprint_yaml_from_portable_lockfile(&lockfile)?;
    let artifact_registry = registry_from_driver_artifacts(&driver_artifacts);
    let mut resolved_blueprint =
        crate::lifecycle::verify_blueprint_yaml_with_registry(&blueprint_yaml, &artifact_registry)?;
    // Portable composition component versions are driver pins. AgentSpec.version controls
    // agent package installation, so do not replay the driver version as a package version.
    resolved_blueprint.blueprint.agent.version = None;
    let driver_pins =
        DriverPinSet::from_portable_lockfile_and_artifacts(&lockfile, &driver_artifacts)?;
    lockfile.name = name.to_owned();
    let persisted_lock_yaml = lockfile.to_yaml_deterministic()?;
    let mut aliased_credentials = ReproducedCredentialProvider {
        inner: credentials,
        bindings: credential_bindings,
    };
    create_env_with_input(
        options,
        factory,
        &mut aliased_credentials,
        CreateEnvInput {
            name,
            blueprint_yaml: &blueprint_yaml,
            lock_yaml: Some(persisted_lock_yaml),
            resolved_blueprint: Some(resolved_blueprint),
            resolved_policy: Some(lockfile.policy.resolved.clone()),
            driver_pins: Some(driver_pins),
        },
        Arc::new(NoopEventEmitter),
    )
    .await
}

fn verify_reproduce_skill_pins(
    options: &RuntimeOptions,
    lockfile: &crate::lockfile::PortableLockfile,
) -> RuntimeResult<()> {
    if lockfile.skills.is_empty() {
        return Ok(());
    }

    let layout = crate::skills::SkillCacheLayout::new(&options.root);
    let trust_keys = crate::skills::load_skill_trust_keys(&layout).map_err(|error| {
        RuntimeError::PortableLockfileVerification {
            details: error.to_string(),
        }
    })?;
    let report = crate::skills::verify_skill_pins(
        &layout,
        &lockfile.skills,
        crate::skills::SkillVerifyOptions {
            trust_keys,
            run_self_tests: false,
        },
    )
    .map_err(|error| RuntimeError::PortableLockfileVerification {
        details: error.to_string(),
    })?;

    if report.is_ok() {
        return Ok(());
    }

    let details = report
        .skills
        .iter()
        .filter(|entry| entry.status == crate::skills::SkillVerifyStatus::Failed)
        .map(|entry| {
            let errors = if entry.errors.is_empty() {
                "unknown error".to_owned()
            } else {
                entry.errors.join("; ")
            };
            format!(
                "skill `{}` version `{}`: {errors}",
                entry.name, entry.version
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    Err(RuntimeError::PortableLockfileVerification { details })
}

fn registry_from_driver_artifacts(
    artifacts: &[crate::driver_artifact::DriverArtifact],
) -> crate::registry::DriverRegistry {
    let mut registry = crate::registry::DriverRegistry::default();
    for artifact in artifacts {
        registry.register_version(
            artifact.kind,
            artifact.name.clone(),
            artifact.version.clone(),
        );
    }
    registry
}

fn parse_driver_kind(kind: &str) -> Option<DriverKind> {
    match kind {
        "sandbox" => Some(DriverKind::Sandbox),
        "agent" => Some(DriverKind::Agent),
        "context" => Some(DriverKind::Context),
        "inference" => Some(DriverKind::Inference),
        _ => None,
    }
}

fn validate_frozen_lockfile_pins(
    state: &crate::env::EnvStateFile,
    lockfile: &crate::lockfile::PortableLockfile,
) -> RuntimeResult<()> {
    validate_frozen_lockfile_pin("sandbox", &state.drivers.sandbox, lockfile)?;
    validate_frozen_lockfile_pin("agent", &state.drivers.agent, lockfile)?;
    validate_frozen_lockfile_pin("context", &state.drivers.context, lockfile)?;

    match state.drivers.inference.as_ref() {
        Some(record) => validate_frozen_lockfile_pin("inference", record, lockfile)?,
        None if lockfile.drivers.contains_key("inference") => {
            let pin = &lockfile.drivers["inference"];
            return Err(RuntimeError::FrozenLockfileDriverMismatch {
                role: "inference",
                expected_name: "<none>".to_owned(),
                expected_version: "<none>".to_owned(),
                actual_name: pin.name.clone(),
                actual_version: pin.version.clone(),
            });
        }
        None => {}
    }

    Ok(())
}

fn validate_frozen_lockfile_pin(
    role: &'static str,
    state_record: &crate::env::DriverRecord,
    lockfile: &crate::lockfile::PortableLockfile,
) -> RuntimeResult<()> {
    let Some(pin) = lockfile.drivers.get(role) else {
        return Err(RuntimeError::FrozenLockfileDriverMismatch {
            role,
            expected_name: state_record.name.clone(),
            expected_version: state_record.version.clone(),
            actual_name: "<missing>".to_owned(),
            actual_version: "<missing>".to_owned(),
        });
    };

    if pin.name != state_record.name || pin.version != state_record.version {
        return Err(RuntimeError::FrozenLockfileDriverMismatch {
            role,
            expected_name: state_record.name.clone(),
            expected_version: state_record.version.clone(),
            actual_name: pin.name.clone(),
            actual_version: pin.version.clone(),
        });
    }

    Ok(())
}

fn check_required_lockfile_credentials(
    credentials: &mut dyn CredentialProvider,
    lockfile: &crate::lockfile::PortableLockfile,
) -> RuntimeResult<()> {
    for (name, credential) in &lockfile.credentials {
        let requirement = credential_requirement_from_lockfile_ref(name, credential);
        if credentials.resolve(&requirement)?.is_none() && requirement.required {
            return Err(RuntimeError::MissingCredential {
                name: requirement.name,
            });
        }
    }

    Ok(())
}

fn credential_requirement_from_lockfile_ref(
    name: &str,
    credential: &crate::lockfile::CredentialRef,
) -> agentenv_proto::CredentialRequirement {
    let reference = credential.reference.as_deref().unwrap_or(name);
    credential_requirement(reference, credential.required.unwrap_or(true))
}

fn check_snapshot_credentials(
    credentials: &mut dyn CredentialProvider,
    manifest: &crate::snapshot::SnapshotManifest,
) -> RuntimeResult<()> {
    for credential in &manifest.credential_requirements {
        let reference = credential.reference.as_deref().unwrap_or(&credential.name);
        let required = credential.required.unwrap_or(true);
        let requirement = credential_requirement(reference, required);
        if credentials.resolve(&requirement)?.is_none() && required {
            return Err(RuntimeError::MissingCredential {
                name: requirement.name,
            });
        }
    }

    Ok(())
}

fn credential_requirement(name: &str, required: bool) -> agentenv_proto::CredentialRequirement {
    agentenv_proto::CredentialRequirement {
        name: name.to_owned(),
        description: String::new(),
        kind: Default::default(),
        required,
        validator: None,
    }
}

struct RuntimeEgressProxyPlanInput<'a> {
    env_name: &'a str,
    requirements: &'a [agentenv_proto::CredentialRequirement],
    policy: &'a agentenv_proto::NetworkPolicy,
    context_endpoint: &'a agentenv_proto::McpEndpoint,
    inference_endpoint: Option<&'a str>,
    policy_extra: &'a BTreeMap<String, serde_yaml::Value>,
    sandbox_capabilities: &'a Capabilities,
    sandbox_driver: &'a str,
}

fn build_runtime_egress_proxy_plan(
    input: RuntimeEgressProxyPlanInput<'_>,
) -> RuntimeResult<EgressProxyPlan> {
    let explicit_routes = explicit_egress_routes_from_policy_extra(input.policy_extra)?;
    if !supports_host_egress_proxy(input.sandbox_capabilities) {
        if egress_proxy_required_by_policy_extra(input.policy_extra) {
            return Err(RuntimeError::HostEgressProxyUnsupported {
                service: required_egress_proxy_service_label(
                    input.requirements,
                    &explicit_routes,
                    input.context_endpoint,
                ),
                driver: input.sandbox_driver.to_owned(),
            });
        }
        return sandbox_env_only_egress_proxy_plan(input.env_name, input.requirements);
    }

    Ok(build_egress_proxy_plan(EgressProxyPlanInput {
        env_name: input.env_name.to_owned(),
        proxy_base_url: allocate_egress_proxy_base_url()?,
        credential_requirements: input.requirements.to_vec(),
        network_policy: input.policy.clone(),
        context_mcp: mcp_proxy_source_for_context_endpoint(input.context_endpoint),
        inference_endpoint: parse_inference_endpoint_url(input.inference_endpoint)?,
        explicit_routes,
    })?)
}

fn allocate_egress_proxy_base_url() -> RuntimeResult<url::Url> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|source| RuntimeError::EgressProxyListen { source })?;
    let port = listener
        .local_addr()
        .map_err(|source| RuntimeError::EgressProxyListen { source })?
        .port();
    drop(listener);
    url::Url::parse(&format!("http://127.0.0.1:{port}")).map_err(|source| {
        RuntimeError::Driver(DriverError::InvalidInput {
            message: format!("failed to parse allocated egress proxy base URL: {source}"),
        })
    })
}

fn sandbox_env_only_egress_proxy_plan(
    env_name: &str,
    requirements: &[agentenv_proto::CredentialRequirement],
) -> RuntimeResult<EgressProxyPlan> {
    let credential_dispositions = requirements
        .iter()
        .map(|requirement| {
            let disposition = if requirement.required {
                CredentialDisposition::SandboxEnv
            } else {
                CredentialDisposition::UnusedOptional
            };
            (requirement.name.clone(), disposition)
        })
        .collect();
    Ok(EgressProxyPlan {
        env_name: env_name.to_owned(),
        listen_url: url::Url::parse("http://127.0.0.1:0").map_err(|source| {
            RuntimeError::Driver(DriverError::InvalidInput {
                message: format!("failed to parse disabled egress proxy URL: {source}"),
            })
        })?,
        sandbox_env: BTreeMap::new(),
        routes: Vec::new(),
        credential_dispositions,
        brokered_credentials: BTreeMap::new(),
        rewritten_context_mcp_url: None,
        redacted_policy_path: None,
    })
}

fn parse_inference_endpoint_url(endpoint: Option<&str>) -> RuntimeResult<Option<url::Url>> {
    endpoint
        .map(|value| {
            url::Url::parse(value).map_err(|source| {
                RuntimeError::Driver(DriverError::InvalidInput {
                    message: format!("inference endpoint `{value}` is not a valid URL: {source}"),
                })
            })
        })
        .transpose()
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeEgressProxyConfig {
    #[serde(default)]
    github: bool,
    #[serde(default)]
    oci: RuntimeEgressProxyOciConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeEgressProxyOciConfig {
    #[serde(default)]
    registries: BTreeSet<String>,
}

fn explicit_egress_routes_from_policy_extra(
    policy_extra: &BTreeMap<String, serde_yaml::Value>,
) -> RuntimeResult<ExplicitEgressRoutes> {
    let Some(value) = policy_extra.get("egress_proxy") else {
        return Ok(ExplicitEgressRoutes::default());
    };
    if value.is_null() {
        return Ok(ExplicitEgressRoutes::default());
    }

    let config: RuntimeEgressProxyConfig =
        serde_yaml::from_value(value.clone()).map_err(|source| {
            RuntimeError::InvalidEgressProxyPolicy {
                details: source.to_string(),
            }
        })?;
    Ok(ExplicitEgressRoutes {
        github: config.github,
        oci_registries: config.oci.registries,
    })
}

fn egress_proxy_required_by_policy_extra(
    policy_extra: &BTreeMap<String, serde_yaml::Value>,
) -> bool {
    policy_extra
        .get("egress_proxy")
        .is_some_and(|value| !value.is_null())
}

fn required_egress_proxy_service_label(
    requirements: &[agentenv_proto::CredentialRequirement],
    explicit_routes: &ExplicitEgressRoutes,
    context_endpoint: &agentenv_proto::McpEndpoint,
) -> String {
    if explicit_routes.github {
        return "github".to_owned();
    }
    if let Some(registry) = explicit_routes.oci_registries.iter().next() {
        return format!("oci.{registry}");
    }
    if requirements
        .iter()
        .any(|requirement| requirement.name == "OPENAI_API_KEY")
    {
        return "openai".to_owned();
    }
    if requirements
        .iter()
        .any(|requirement| requirement.name == "ANTHROPIC_API_KEY")
    {
        return "anthropic".to_owned();
    }
    if mcp_proxy_source_for_context_endpoint(context_endpoint).is_some() {
        return "mcp".to_owned();
    }
    "egress_proxy".to_owned()
}

fn mcp_proxy_source_for_context_endpoint(
    endpoint: &agentenv_proto::McpEndpoint,
) -> Option<McpProxySource> {
    if !matches!(
        endpoint.transport,
        agentenv_proto::McpTransport::Http | agentenv_proto::McpTransport::HttpSse
    ) {
        return None;
    }

    let upstream_url = url::Url::parse(&endpoint.url).ok()?;
    if !matches!(upstream_url.scheme(), "http" | "https") {
        return None;
    }

    Some(McpProxySource {
        route_id: "context".to_owned(),
        upstream_url,
        token_credential_name: Some("MCP_TOKEN".to_owned()),
    })
}

fn rewrite_context_endpoint_for_proxy(
    endpoint: &agentenv_proto::McpEndpoint,
    plan: &EgressProxyPlan,
) -> agentenv_proto::McpEndpoint {
    let Some(url) = plan.context_mcp_url() else {
        return endpoint.clone();
    };

    let mut rewritten = endpoint.clone();
    rewritten.url = url.as_str().to_owned();
    rewritten.headers.clear();
    rewritten
}

fn sandbox_env_for_credential_plan(
    credentials: &mut dyn CredentialProvider,
    requirements: &[agentenv_proto::CredentialRequirement],
    plan: &EgressProxyPlan,
    events: &dyn EventEmitter,
    trace_id: &str,
    env_name: &str,
) -> RuntimeResult<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    let mut emitted_brokered = BTreeSet::new();

    for requirement in requirements {
        match credential_disposition_for_requirement(plan, requirement) {
            CredentialDisposition::Brokered => {
                emit_brokered_credential_injected_event_once(
                    events,
                    trace_id,
                    env_name,
                    &requirement.name,
                    &mut emitted_brokered,
                );
            }
            CredentialDisposition::SandboxEnv => {
                if let Some(value) = credentials.resolve(requirement)? {
                    emit_credential_injected_event(
                        events,
                        trace_id,
                        env_name,
                        &requirement.name,
                        "sandbox_env",
                    );
                    env.insert(requirement.name.clone(), value.expose_secret().to_owned());
                } else if requirement.required {
                    return Err(RuntimeError::MissingCredential {
                        name: requirement.name.clone(),
                    });
                }
            }
            CredentialDisposition::UnusedOptional => {}
        }
    }
    for credential_name in plan.brokered_credentials.keys() {
        emit_brokered_credential_injected_event_once(
            events,
            trace_id,
            env_name,
            credential_name,
            &mut emitted_brokered,
        );
    }

    Ok(env)
}

fn credential_disposition_for_requirement(
    plan: &EgressProxyPlan,
    requirement: &agentenv_proto::CredentialRequirement,
) -> CredentialDisposition {
    plan.credential_disposition(&requirement.name)
        .unwrap_or(if requirement.required {
            CredentialDisposition::SandboxEnv
        } else {
            CredentialDisposition::UnusedOptional
        })
}

fn emit_credential_injected_event(
    events: &dyn EventEmitter,
    trace_id: &str,
    env_name: &str,
    credential_name: &str,
    delivery: &str,
) {
    emit_runtime_event(
        events,
        core_activity_event(
            ActivityKind::CredentialInjected,
            ActivityResult::Ok,
            trace_id,
            Some(env_name),
        )
        .with_subject_value("name", serde_json::json!(credential_name))
        .with_subject_value("delivery", serde_json::json!(delivery)),
    );
}

fn emit_brokered_credential_injected_event_once(
    events: &dyn EventEmitter,
    trace_id: &str,
    env_name: &str,
    credential_name: &str,
    emitted_brokered: &mut BTreeSet<String>,
) {
    if emitted_brokered.insert(credential_name.to_owned()) {
        emit_credential_injected_event(events, trace_id, env_name, credential_name, "egress_proxy");
    }
}

fn credential_names_for_plan(
    requirements: &[agentenv_proto::CredentialRequirement],
    plan: &EgressProxyPlan,
) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut names = Vec::new();

    for requirement in requirements {
        if seen.insert(requirement.name.clone()) {
            names.push(requirement.name.clone());
        }
    }
    for name in plan.brokered_credentials.keys() {
        if seen.insert(name.clone()) {
            names.push(name.clone());
        }
    }

    names
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReproducedCredentialBinding {
    source: String,
    reference: String,
}

fn credential_bindings_from_portable_lockfile(
    lockfile: &crate::lockfile::PortableLockfile,
) -> BTreeMap<String, ReproducedCredentialBinding> {
    lockfile
        .credentials
        .iter()
        .map(|(name, credential)| {
            let reference = credential.reference.clone().unwrap_or_else(|| name.clone());
            (
                name.clone(),
                ReproducedCredentialBinding {
                    source: credential.source.clone(),
                    reference,
                },
            )
        })
        .collect()
}

fn is_credstore_backend(backend: &str) -> bool {
    matches!(backend, "keyring" | "file")
}

struct ReproducedCredentialProvider<'a> {
    inner: &'a mut dyn CredentialProvider,
    bindings: BTreeMap<String, ReproducedCredentialBinding>,
}

impl CredentialProvider for ReproducedCredentialProvider<'_> {
    fn resolve(
        &mut self,
        requirement: &agentenv_proto::CredentialRequirement,
    ) -> RuntimeResult<Option<RuntimeSecret>> {
        let Some(binding) = self.bindings.get(&requirement.name) else {
            return self.inner.resolve(requirement);
        };

        let mut aliased_requirement = requirement.clone();
        aliased_requirement.name = binding.reference.clone();
        match binding.source.as_str() {
            "env" => self.inner.resolve(&aliased_requirement),
            "credstore" => match self.inner.backend_name(&binding.reference)? {
                Some(backend) if is_credstore_backend(&backend) => {
                    self.inner.resolve(&aliased_requirement)
                }
                _ if requirement.required => Err(RuntimeError::MissingCredential {
                    name: binding.reference.clone(),
                }),
                _ => Ok(None),
            },
            _ => self.inner.resolve(&aliased_requirement),
        }
    }

    fn backend_name(&self, name: &str) -> RuntimeResult<Option<String>> {
        let reference = self
            .bindings
            .get(name)
            .map_or(name, |binding| binding.reference.as_str());
        self.inner.backend_name(reference)
    }
}

fn blueprint_yaml_from_portable_lockfile(
    lockfile: &crate::lockfile::PortableLockfile,
) -> RuntimeResult<String> {
    let composition = &lockfile.composition;
    let blueprint = crate::blueprint::Blueprint {
        version: composition.version.clone(),
        min_agentenv_version: composition.min_agentenv_version.clone(),
        sandbox: blueprint_component_from_portable(&composition.sandbox),
        agent: blueprint_component_from_portable(&composition.agent),
        context: blueprint_component_from_portable(&composition.context),
        inference: composition
            .inference
            .as_ref()
            .map(blueprint_component_from_portable),
        policy: composition.policy.clone(),
        state: composition.state.clone(),
    };

    serde_yaml::to_string(&blueprint).map_err(RuntimeError::lockfile_serialize)
}

fn blueprint_component_from_portable(
    component: &crate::lockfile::PortableComponent,
) -> crate::blueprint::ComponentSection {
    crate::blueprint::ComponentSection {
        driver: component.driver.clone(),
        version: Some(component.version.clone()),
        credentials: if component.credentials.is_empty() {
            None
        } else {
            Some(
                component
                    .credentials
                    .iter()
                    .map(|(name, credential)| {
                        (
                            name.clone(),
                            crate::blueprint::CredentialRef {
                                source: credential.source.clone(),
                                required: credential.required,
                                value: credential.reference.clone(),
                                extra: BTreeMap::new(),
                            },
                        )
                    })
                    .collect(),
            )
        },
        extra: component.extra.clone(),
    }
}

#[derive(Serialize)]
struct BuildOneflightSeed<'a> {
    version: &'static str,
    blueprint_yaml: &'a str,
    lock_yaml: &'a str,
    sandbox_driver: &'a str,
    sandbox_driver_version: String,
    agent_driver: &'a str,
    agent_driver_version: String,
    context_driver: &'a str,
    context_driver_version: String,
    inference_driver: Option<&'a str>,
    inference_driver_version: Option<String>,
    metadata: BTreeMap<&'static str, String>,
}

fn build_oneflight_seed_for_byo(
    blueprint_yaml: &str,
    lock_yaml: &str,
    selection: &DriverSelection,
    resolved: &crate::lifecycle::ResolvedBlueprint,
    context_endpoint: &agentenv_proto::McpEndpoint,
    sandbox_extra: &BTreeMap<String, serde_yaml::Value>,
) -> RuntimeResult<Option<String>> {
    if !sandbox_image_is_byo(sandbox_extra) {
        return Ok(None);
    }

    let metadata = BTreeMap::from([
        ("agentenv_version", env!("CARGO_PKG_VERSION").to_owned()),
        ("agentenv_agent", selection.agent.clone()),
        (
            "agentenv_mcp_port",
            mcp_endpoint_port(context_endpoint).unwrap_or_default(),
        ),
        ("agentenv_workspace_mount", "/sandbox".to_owned()),
    ]);
    let seed = BuildOneflightSeed {
        version: BUILD_ONEFLIGHT_SEED_VERSION,
        blueprint_yaml,
        lock_yaml,
        sandbox_driver: &selection.sandbox,
        sandbox_driver_version: resolved.sandbox.version.to_string(),
        agent_driver: &selection.agent,
        agent_driver_version: resolved.agent.version.to_string(),
        context_driver: &selection.context,
        context_driver_version: resolved.context.version.to_string(),
        inference_driver: selection.inference.as_deref(),
        inference_driver_version: resolved
            .inference
            .as_ref()
            .map(|driver| driver.version.to_string()),
        metadata,
    };
    let bytes = serde_json::to_vec(&seed).map_err(|source| {
        RuntimeError::Driver(DriverError::InvalidInput {
            message: format!("failed to serialize build oneflight seed: {source}"),
        })
    })?;
    Ok(Some(format!(
        "sha256:{}",
        crate::digest::sha256_hex(&bytes)
    )))
}

fn sandbox_image_is_byo(sandbox_extra: &BTreeMap<String, serde_yaml::Value>) -> bool {
    sandbox_extra
        .get("image")
        .and_then(serde_yaml::Value::as_mapping)
        .is_some_and(|image| yaml_mapping_string(image, "source") == Some("byo"))
}

struct SandboxSpecCreateOptions<'a> {
    env: BTreeMap<String, String>,
    policy: Option<agentenv_proto::NetworkPolicy>,
    build_oneflight_seed: Option<String>,
    resolved_hardening: Option<&'a crate::hardening::ResolvedHardening>,
}

fn sandbox_spec_for_create(
    name: &str,
    selection: &DriverSelection,
    sandbox_extra: &BTreeMap<String, serde_yaml::Value>,
    context_endpoint: &agentenv_proto::McpEndpoint,
    options: SandboxSpecCreateOptions<'_>,
) -> RuntimeResult<agentenv_proto::SandboxSpec> {
    let SandboxSpecCreateOptions {
        env,
        policy,
        build_oneflight_seed,
        resolved_hardening,
    } = options;
    let mut metadata = BTreeMap::from([
        ("name".to_owned(), serde_json::json!(name)),
        (
            "agentenv_version".to_owned(),
            serde_json::json!(env!("CARGO_PKG_VERSION")),
        ),
        (
            "agentenv_agent".to_owned(),
            serde_json::json!(selection.agent.clone()),
        ),
        (
            "agentenv_mcp_port".to_owned(),
            serde_json::json!(mcp_endpoint_port(context_endpoint).unwrap_or_default()),
        ),
        (
            "agentenv_workspace_mount".to_owned(),
            serde_json::json!("/sandbox"),
        ),
    ]);
    for (key, value) in sandbox_extra {
        if matches!(key.as_str(), "image" | "hardening") {
            continue;
        }
        if is_reserved_sandbox_metadata_key(key) {
            return Err(RuntimeError::Driver(DriverError::InvalidInput {
                message: format!("sandbox.{key} is reserved metadata and cannot be set directly"),
            }));
        }
        let value = serde_json::to_value(value).map_err(|source| {
            RuntimeError::ComponentConfigConversion {
                key: key.clone(),
                source,
            }
        })?;
        metadata.insert(key.clone(), value);
    }
    if let Some(resolved_hardening) = resolved_hardening {
        metadata.extend(resolved_hardening.metadata.clone());
    }
    let image = match sandbox_extra.get("image") {
        Some(serde_yaml::Value::String(image)) => Some(image.clone()),
        Some(serde_yaml::Value::Mapping(image)) => {
            let source = optional_yaml_mapping_string(image, "source", "sandbox.image.source")?
                .unwrap_or_default();
            if source != "byo" {
                return Err(RuntimeError::Driver(DriverError::InvalidInput {
                    message: format!("unsupported sandbox image source `{source}`"),
                }));
            }
            let dockerfile =
                required_yaml_mapping_string(image, "dockerfile", "sandbox.image.dockerfile")?
                    .ok_or_else(|| {
                        RuntimeError::Driver(DriverError::InvalidInput {
                            message: "sandbox.image.dockerfile is required when source is `byo`"
                                .to_owned(),
                        })
                    })?;
            metadata.insert("byo_dockerfile".to_owned(), serde_json::json!(dockerfile));
            if let Some(expected_digest) = optional_yaml_mapping_string(
                image,
                "expected_digest",
                "sandbox.image.expected_digest",
            )? {
                metadata.insert(
                    "byo_expected_digest".to_owned(),
                    serde_json::json!(expected_digest),
                );
            }
            None
        }
        Some(_) => {
            return Err(RuntimeError::Driver(DriverError::InvalidInput {
                message: "sandbox.image must be a string or mapping".to_owned(),
            }));
        }
        None => None,
    };

    if let Some(seed) = build_oneflight_seed {
        metadata.insert(
            "agentenv_build_oneflight".to_owned(),
            serde_json::json!(BUILD_ONEFLIGHT_KIND),
        );
        metadata.insert("agentenv_build_seed".to_owned(), serde_json::json!(seed));
        metadata.insert(
            "agentenv_build_seed_version".to_owned(),
            serde_json::json!(BUILD_ONEFLIGHT_SEED_VERSION),
        );
    }

    Ok(agentenv_proto::SandboxSpec {
        image,
        env,
        policy,
        metadata,
    })
}

fn is_reserved_sandbox_metadata_key(key: &str) -> bool {
    key == "name"
        || key.starts_with("agentenv_")
        || matches!(key, "byo_dockerfile" | "byo_expected_digest")
}

fn record_computed_byo_image_digest(
    temp_paths: &crate::env::EnvPaths,
    runtime_root: &Path,
    name: &str,
    sandbox_extra: &BTreeMap<String, serde_yaml::Value>,
) -> RuntimeResult<()> {
    if !byo_image_needs_computed_digest(sandbox_extra) {
        return Ok(());
    }

    let digest_path = runtime_root
        .join("build")
        .join(sanitize_byo_build_name(name))
        .join("image-digest");
    let digest = fs::read_to_string(&digest_path).map_err(|source| crate::env::EnvError::Io {
        path: digest_path.clone(),
        source,
    })?;
    let digest = digest.trim();
    crate::digest::parse_sha256_digest(digest).map_err(|source| {
        RuntimeError::Driver(DriverError::InvalidInput {
            message: format!(
                "invalid computed BYO image digest in `{}`: {source}",
                digest_path.display()
            ),
        })
    })?;

    let lock_path = temp_paths.lock_path();
    let lock_yaml =
        String::from_utf8(crate::env::read_regular_file(&lock_path)?).map_err(|source| {
            crate::env::EnvError::Io {
                path: lock_path.clone(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
            }
        })?;
    let mut lockfile = crate::lockfile::Lockfile::from_yaml(&lock_yaml)?;
    lockfile
        .artifacts
        .insert("sandbox-image".to_owned(), digest.to_owned());
    let rendered = lockfile.to_yaml_deterministic()?;
    fs::write(&lock_path, rendered).map_err(|source| crate::env::EnvError::Io {
        path: lock_path,
        source,
    })?;
    Ok(())
}

fn byo_image_needs_computed_digest(sandbox_extra: &BTreeMap<String, serde_yaml::Value>) -> bool {
    sandbox_extra
        .get("image")
        .and_then(serde_yaml::Value::as_mapping)
        .is_some_and(|image| {
            yaml_mapping_string(image, "source") == Some("byo")
                && yaml_mapping_string(image, "expected_digest").is_none()
        })
}

fn sanitize_byo_build_name(name: &str) -> String {
    let mut output = String::new();
    for byte in name.bytes() {
        let ch = byte.to_ascii_lowercase() as char;
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '-' | '_') {
            output.push(ch);
        } else {
            output.push('-');
        }
    }
    let trimmed = output.trim_matches('-');
    if trimmed.is_empty() {
        "sandbox".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn yaml_mapping_string<'a>(mapping: &'a serde_yaml::Mapping, key: &str) -> Option<&'a str> {
    yaml_mapping_value(mapping, key).and_then(serde_yaml::Value::as_str)
}

fn yaml_mapping_value<'a>(
    mapping: &'a serde_yaml::Mapping,
    key: &str,
) -> Option<&'a serde_yaml::Value> {
    mapping.get(serde_yaml::Value::String(key.to_owned()))
}

fn required_yaml_mapping_string<'a>(
    mapping: &'a serde_yaml::Mapping,
    key: &str,
    path: &str,
) -> RuntimeResult<Option<&'a str>> {
    optional_yaml_mapping_string(mapping, key, path)
}

fn optional_yaml_mapping_string<'a>(
    mapping: &'a serde_yaml::Mapping,
    key: &str,
    path: &str,
) -> RuntimeResult<Option<&'a str>> {
    match yaml_mapping_value(mapping, key) {
        Some(serde_yaml::Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(RuntimeError::Driver(DriverError::InvalidInput {
            message: format!("{path} must be a string when set"),
        })),
        None => Ok(None),
    }
}

fn mcp_endpoint_port(endpoint: &agentenv_proto::McpEndpoint) -> Option<String> {
    url::Url::parse(&endpoint.url)
        .ok()
        .and_then(|url| url.port_or_known_default())
        .map(|port| port.to_string())
}

impl RuntimeError {
    fn lockfile_serialize(source: serde_yaml::Error) -> Self {
        Self::Lockfile(crate::lockfile::LockfileError::Serialize(source))
    }
}

pub async fn exec_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
    command: Vec<String>,
) -> RuntimeResult<agentenv_proto::ExecResult> {
    exec_env_observed(options, factory, name, command, Arc::new(NoopEventEmitter)).await
}

pub async fn exec_env_observed(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
    command: Vec<String>,
    events: Arc<dyn EventEmitter>,
) -> RuntimeResult<agentenv_proto::ExecResult> {
    let trace_id = new_trace_id();
    let state = describe_env(options, name)?.state;
    let selection = selection_from_state(&state);
    let handle = required_sandbox_handle(&state, name)?;
    let mut set = factory.build_for_env_observed(
        &selection,
        name,
        Arc::clone(&events),
        Some(approval_coordinator_for_env(
            options,
            name,
            Arc::clone(&events),
        )?),
    )?;
    if let Err(err) = initialize_sandbox_driver(options, set.sandbox.as_mut()).await {
        emit_runtime_event(
            events.as_ref(),
            with_command_metadata(
                core_activity_event(
                    ActivityKind::Exec,
                    ActivityResult::Error,
                    &trace_id,
                    Some(name),
                )
                .with_subject_value("handle", serde_json::json!(handle.clone()))
                .with_reason_code(runtime_error_reason_code(&err)),
                &command,
            ),
        );
        return Err(err);
    }

    let cmd = command.join(" ");
    let exec_start = Instant::now();
    match set
        .sandbox
        .exec(agentenv_proto::ExecParams {
            handle: handle.clone(),
            cmd,
            tty: false,
            env: BTreeMap::new(),
        })
        .await
    {
        Ok(result) => {
            let event_result = if result.status == 0 {
                ActivityResult::Ok
            } else {
                ActivityResult::Error
            };
            let mut event = with_command_metadata(
                core_activity_event(ActivityKind::Exec, event_result, &trace_id, Some(name))
                    .with_subject_value("handle", serde_json::json!(handle))
                    .with_latency_ms(elapsed_ms(exec_start)),
                &command,
            );
            if result.status != 0 {
                event = event.with_reason_code("command_status");
            }
            emit_runtime_event(events.as_ref(), event);
            Ok(result)
        }
        Err(err) => {
            emit_runtime_event(
                events.as_ref(),
                with_command_metadata(
                    core_activity_event(
                        ActivityKind::Exec,
                        ActivityResult::Error,
                        &trace_id,
                        Some(name),
                    )
                    .with_subject_value("handle", serde_json::json!(handle))
                    .with_reason_code(crate::admission::ReasonCode::DriverCommandFailed.as_str())
                    .with_latency_ms(elapsed_ms(exec_start)),
                    &command,
                ),
            );
            Err(err.into())
        }
    }
}

pub async fn enter_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
    detach: bool,
    new_session: bool,
) -> RuntimeResult<EnterResult> {
    let state = describe_env(options, name)?.state;
    let selection = selection_from_state(&state);
    let handle = required_sandbox_handle(&state, name)?;
    let mut set = factory.build(&selection)?;
    let init = initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
    let supports_sessions = supports_persistent_sessions(&init.capabilities);

    if !supports_sessions {
        if detach || new_session {
            return Err(RuntimeError::Driver(
                crate::driver::persistent_sessions_missing(),
            ));
        }

        return enter_env_via_foreground_exec(set.sandbox.as_ref(), handle).await;
    }

    let env_name = crate::env::validate_env_name(name)?;
    let paths = crate::env::EnvPaths::new(options.root.clone(), env_name);
    let mut sessions = crate::sessions::read_sessions(&paths, name)?;
    let existing_default = sessions
        .default_session_id
        .as_deref()
        .and_then(|id| crate::sessions::find_session(&sessions, id).ok())
        .filter(|session| crate::sessions::is_live_status(&session.status))
        .cloned();

    let driver_session_id =
        if let Some(session) = (!new_session).then_some(existing_default).flatten() {
            session.driver_session_id
        } else {
            let created = match set
                .sandbox
                .create_session(agentenv_proto::CreateSessionParams {
                    handle: handle.clone(),
                    name: next_session_name(name, &sessions),
                    command: AGENT_ENTRYPOINT_PATH.to_owned(),
                    detached: detach,
                    metadata: BTreeMap::new(),
                })
                .await
            {
                Ok(created) => created,
                Err(DriverError::CapabilityMissing { capability })
                    if capability == "supports_persistent_sessions" && !detach && !new_session =>
                {
                    return enter_env_via_foreground_exec(set.sandbox.as_ref(), handle).await;
                }
                Err(err) => return Err(RuntimeError::Driver(err)),
            };
            let driver_session_id = created.session_id.clone();
            let make_default = !new_session || sessions.default_session_id.is_none();
            crate::sessions::upsert_session(
                &mut sessions,
                persisted_from_driver_session(created),
                make_default,
            );
            crate::sessions::write_sessions(&paths, &sessions)?;
            driver_session_id
        };

    if detach {
        return Ok(EnterResult::Detached(agentenv_proto::ShellHandle {
            session_id: driver_session_id,
            tty: true,
            working_dir: Some("/sandbox".to_owned()),
        }));
    }

    let result = set
        .sandbox
        .attach_session(agentenv_proto::AttachSessionParams {
            handle,
            session_id: driver_session_id,
        })
        .await?;
    Ok(EnterResult::Attached(result))
}

async fn enter_env_via_foreground_exec(
    sandbox: &dyn SandboxDriver,
    handle: String,
) -> RuntimeResult<EnterResult> {
    let result = sandbox
        .exec(agentenv_proto::ExecParams {
            handle,
            cmd: AGENT_ENTRYPOINT_PATH.to_owned(),
            tty: true,
            env: BTreeMap::new(),
        })
        .await?;
    Ok(EnterResult::Attached(result))
}

pub async fn resume_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
    session_id: Option<&str>,
) -> RuntimeResult<agentenv_proto::ExecResult> {
    let state = describe_env(options, name)?.state;
    let selection = selection_from_state(&state);
    let handle = required_sandbox_handle(&state, name)?;
    let mut set = factory.build(&selection)?;
    let init = initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
    if !supports_persistent_sessions(&init.capabilities) {
        return Err(RuntimeError::Driver(
            crate::driver::persistent_sessions_missing(),
        ));
    }

    let paths =
        crate::env::EnvPaths::new(options.root.clone(), crate::env::validate_env_name(name)?);
    let sessions =
        reconcile_sessions_with_driver(&paths, name, set.sandbox.as_ref(), &handle).await?;
    let (selected, requested_id) = match session_id {
        Some(id) => (find_session_or_invalid(&sessions, id)?, id),
        None => {
            let default_id = sessions.default_session_id.as_deref().ok_or_else(|| {
                RuntimeError::Driver(DriverError::InvalidHandle {
                    handle: name.to_owned(),
                    message: "no default session exists".to_owned(),
                })
            })?;
            (find_session_or_invalid(&sessions, default_id)?, default_id)
        }
    };
    if !crate::sessions::is_live_status(&selected.status) {
        return Err(RuntimeError::Driver(DriverError::InvalidHandle {
            handle: requested_id.to_owned(),
            message: format!("session `{requested_id}` is not live"),
        }));
    }

    set.sandbox
        .attach_session(agentenv_proto::AttachSessionParams {
            handle,
            session_id: selected.driver_session_id.clone(),
        })
        .await
        .map_err(Into::into)
}

pub async fn list_sessions_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    env: Option<&str>,
) -> RuntimeResult<Vec<SessionListRow>> {
    let envs = match env {
        Some(name) => vec![describe_env(options, name)?.state],
        None => list_envs(options)?
            .into_iter()
            .map(|row| describe_env(options, &row.name).map(|description| description.state))
            .collect::<RuntimeResult<Vec<_>>>()?,
    };

    let mut rows = Vec::new();
    for state in envs {
        let env_name = state.name.clone();
        let selection = selection_from_state(&state);
        let handle = required_sandbox_handle(&state, &env_name)?;
        let mut set = factory.build(&selection)?;
        let init = initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
        if !supports_persistent_sessions(&init.capabilities) {
            if env.is_some() {
                return Err(RuntimeError::Driver(
                    crate::driver::persistent_sessions_missing(),
                ));
            }
            continue;
        }

        let paths = crate::env::EnvPaths::new(
            options.root.clone(),
            crate::env::validate_env_name(&env_name)?,
        );
        let sessions =
            reconcile_sessions_with_driver(&paths, &env_name, set.sandbox.as_ref(), &handle)
                .await?;

        rows.extend(sessions.sessions.into_iter().map(|session| SessionListRow {
            env: env_name.clone(),
            session_id: session.id,
            name: session.name,
            status: session.status,
            command: session.command,
            updated_at: session.updated_at,
        }));
    }

    rows.sort_by(|left, right| {
        left.env
            .cmp(&right.env)
            .then_with(|| left.session_id.cmp(&right.session_id))
    });
    Ok(rows)
}

pub async fn kill_session_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    session_id: &str,
) -> RuntimeResult<()> {
    for row in list_envs(options)? {
        let state = describe_env(options, &row.name)?.state;
        let paths = crate::env::EnvPaths::new(
            options.root.clone(),
            crate::env::validate_env_name(&row.name)?,
        );
        let mut sessions = crate::sessions::read_sessions(&paths, &row.name)?;
        let Some(index) = sessions.sessions.iter().position(|session| {
            session.id == session_id || session.driver_session_id == session_id
        }) else {
            continue;
        };

        let selection = selection_from_state(&state);
        let handle = required_sandbox_handle(&state, &row.name)?;
        let mut set = factory.build(&selection)?;
        let init = initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
        if !supports_persistent_sessions(&init.capabilities) {
            return Err(RuntimeError::Driver(
                crate::driver::persistent_sessions_missing(),
            ));
        }

        let driver_session_id = sessions.sessions[index].driver_session_id.clone();
        set.sandbox
            .kill_session(agentenv_proto::KillSessionParams {
                handle,
                session_id: driver_session_id,
            })
            .await?;
        sessions.sessions[index].status = agentenv_proto::SessionStatus::Killed;
        sessions.sessions[index].updated_at = now_utc_string();
        crate::sessions::write_sessions(&paths, &sessions)?;
        return Ok(());
    }

    Err(RuntimeError::Driver(DriverError::InvalidHandle {
        handle: session_id.to_owned(),
        message: "session not found".to_owned(),
    }))
}

pub async fn status_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
) -> RuntimeResult<EnvStatusSummary> {
    status_env_observed(options, factory, name, Arc::new(NoopEventEmitter)).await
}

pub async fn status_env_observed(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
    events: Arc<dyn EventEmitter>,
) -> RuntimeResult<EnvStatusSummary> {
    let state = describe_env(options, name)?.state;
    let selection = selection_from_state(&state);
    let mut set = factory.build_for_env_observed(
        &selection,
        name,
        Arc::clone(&events),
        Some(approval_coordinator_for_env(
            options,
            name,
            Arc::clone(&events),
        )?),
    )?;

    let sandbox = match state.handles.sandbox.clone() {
        Some(handle) => {
            initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
            let status = set
                .sandbox
                .status(agentenv_proto::SandboxStatusParams { handle })
                .await?;
            Some(DriverHealthSummary {
                healthy: status.healthy,
                detail: Some(format!("{:?}", status.phase).to_lowercase()),
            })
        }
        None => None,
    };

    let context = match state.handles.context.clone() {
        Some(handle) => {
            initialize_context_driver(options, set.context.as_mut()).await?;
            let status = set
                .context
                .status(agentenv_proto::ContextHandleRequest { handle })
                .await?;
            Some(DriverHealthSummary {
                healthy: status.healthy,
                detail: status.detail,
            })
        }
        None => None,
    };

    let healthy = sandbox.as_ref().map(|value| value.healthy).unwrap_or(false)
        && context.as_ref().map(|value| value.healthy).unwrap_or(false);

    Ok(EnvStatusSummary {
        healthy,
        sandbox,
        context,
    })
}

pub async fn logs_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
    follow: bool,
) -> RuntimeResult<agentenv_proto::LogsResult> {
    logs_env_observed(options, factory, name, follow, Arc::new(NoopEventEmitter)).await
}

pub async fn logs_env_observed(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
    follow: bool,
    events: Arc<dyn EventEmitter>,
) -> RuntimeResult<agentenv_proto::LogsResult> {
    if follow {
        let _guard = start_logs_stream_env(options, factory, name).await?;
        return Ok(agentenv_proto::LogsResult {
            entries: Vec::new(),
        });
    }

    let state = describe_env(options, name)?.state;
    let selection = selection_from_state(&state);
    let handle = required_sandbox_handle(&state, name)?;
    let mut set = factory.build_for_env_observed(
        &selection,
        name,
        Arc::clone(&events),
        Some(approval_coordinator_for_env(
            options,
            name,
            Arc::clone(&events),
        )?),
    )?;
    initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;

    set.sandbox
        .logs(agentenv_proto::LogsParams {
            handle,
            since: None,
            follow,
        })
        .await
        .map_err(Into::into)
}

pub async fn start_logs_stream_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
) -> RuntimeResult<RunningLogStream> {
    let state = describe_env(options, name)?.state;
    let selection = selection_from_state(&state);
    let handle = required_sandbox_handle(&state, name)?;
    let mut set = factory.build(&selection)?;
    initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
    set.sandbox
        .logs_stream(agentenv_proto::LogsStreamParams {
            handle,
            since: None,
        })
        .await?;
    Ok(RunningLogStream { _set: set })
}

pub async fn fork_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    source: &str,
    name: &str,
) -> RuntimeResult<ForkEnvResult> {
    let target_env_name = crate::env::validate_env_name(name)?;
    let target_paths = crate::env::EnvPaths::new(options.root.clone(), target_env_name.clone());
    let target_env_dir = target_paths.env_dir();
    if target_env_dir.exists() {
        return Err(crate::env::EnvError::AlreadyExists {
            name: name.to_owned(),
        }
        .into());
    }

    let source_description = describe_env_for_fork_source(options, source)?;
    let source_env = source_description.state.name.clone();
    let source_state = source_description.state;
    let source_handle = required_sandbox_handle(&source_state, &source_env)?;
    let selection = selection_from_state(&source_state);
    let mut set = factory.build(&selection)?;
    let init = initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
    crate::driver::require_capability(
        "supports_snapshots",
        supports_snapshots(&init.capabilities),
    )?;
    crate::driver::require_capability("supports_fork", supports_fork(&init.capabilities))?;

    let snapshot = set
        .sandbox
        .snapshot(agentenv_proto::SnapshotParams {
            handle: source_handle,
            name: Some(name.to_owned()),
        })
        .await?;
    let forked = set
        .sandbox
        .fork_from_snapshot(agentenv_proto::ForkFromSnapshotParams {
            snapshot: snapshot.clone(),
            spec: agentenv_proto::ForkSpec {
                name: name.to_owned(),
                metadata: BTreeMap::new(),
            },
        })
        .await?;
    let forked_handle = forked.handle.clone();

    let temp_workspace = create_temp_workspace(&options.root, target_env_name.as_str());
    let temp_paths = crate::env::EnvPaths::new(temp_workspace.clone(), target_env_name);
    let result = (|| -> RuntimeResult<ForkEnvResult> {
        fs::create_dir_all(temp_paths.env_dir()).map_err(|source| crate::env::EnvError::Io {
            path: temp_paths.env_dir(),
            source,
        })?;
        write_env_registry_file(
            &source_description.blueprint_yaml,
            &temp_paths.blueprint_path(),
        )?;
        write_env_registry_file(&source_description.lock_yaml, &temp_paths.lock_path())?;

        let now = now_utc_string();
        let mut target_state = source_state;
        target_state.name = name.to_owned();
        target_state.phase = crate::env::EnvPhase::Running;
        target_state.created_at = now.clone();
        target_state.updated_at = now;
        target_state.handles.sandbox = Some(forked_handle.clone());
        target_state.handles.context = None;
        target_state.handles.inference = None;
        target_state.health.clear();
        target_state.first_enter_hint_shown = false;
        crate::env::write_state(&temp_paths, &target_state)?;
        crate::env::append_event(
            &temp_paths,
            serde_json::json!({
                "kind": "admission",
                "status": "accepted",
                "reason_code": crate::admission::ReasonCode::Created.as_str(),
                "env": name,
                "source_env": source_env.clone(),
                "snapshot": snapshot.id.clone(),
            }),
        )?;

        fs::create_dir_all(target_paths.envs_dir()).map_err(|source| crate::env::EnvError::Io {
            path: target_paths.envs_dir(),
            source,
        })?;
        if target_env_dir.exists() {
            return Err(crate::env::EnvError::AlreadyExists {
                name: name.to_owned(),
            }
            .into());
        }
        fs::rename(temp_paths.env_dir(), &target_env_dir).map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                crate::env::EnvError::AlreadyExists {
                    name: name.to_owned(),
                }
            } else {
                crate::env::EnvError::Io {
                    path: target_env_dir.clone(),
                    source,
                }
            }
        })?;

        Ok(ForkEnvResult {
            source: source_env,
            name: name.to_owned(),
            snapshot_id: snapshot.id,
            sandbox_handle: forked_handle.clone(),
            state_path: target_paths.state_path(),
        })
    })();

    let _ = fs::remove_dir_all(&temp_workspace);
    if result.is_err() {
        let _ = set
            .sandbox
            .destroy(agentenv_proto::DestroyParams {
                handle: forked_handle,
            })
            .await;
    }
    result
}

pub async fn destroy_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
) -> RuntimeResult<crate::admission::AdmissionReport> {
    destroy_env_observed(options, factory, name, Arc::new(NoopEventEmitter)).await
}

pub async fn destroy_env_observed(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
    events: Arc<dyn EventEmitter>,
) -> RuntimeResult<crate::admission::AdmissionReport> {
    let trace_id = new_trace_id();
    let mut state = describe_env(options, name)?.state;
    let destroy_event_handle = state
        .handles
        .sandbox
        .clone()
        .or_else(|| state.handles.context.clone())
        .or_else(|| state.handles.inference.clone());
    let selection = selection_from_state(&state);
    let mut set = factory.build_for_env_observed(
        &selection,
        name,
        Arc::clone(&events),
        Some(approval_coordinator_for_env(
            options,
            name,
            Arc::clone(&events),
        )?),
    )?;
    let paths =
        crate::env::EnvPaths::new(options.root.clone(), crate::env::validate_env_name(name)?);
    let mut destroy_error_emitted = false;

    let result = async {
        if state.handles.inference.is_some() && set.inference.is_none() {
            return Err(missing_inference_driver(&state));
        }

        if let Some(handle) = state.handles.sandbox.clone() {
            let init = initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
            if supports_persistent_sessions(&init.capabilities) {
                let session_file = crate::sessions::read_sessions(&paths, name)
                    .unwrap_or_else(|_| crate::sessions::empty_session_file(name));
                for session in session_file
                    .sessions
                    .iter()
                    .filter(|session| crate::sessions::is_live_status(&session.status))
                {
                    let _ = set
                        .sandbox
                        .kill_session(agentenv_proto::KillSessionParams {
                            handle: handle.clone(),
                            session_id: session.driver_session_id.clone(),
                        })
                        .await;
                }
            }
            let destroy_start = Instant::now();
            match set
                .sandbox
                .destroy(agentenv_proto::DestroyParams {
                    handle: handle.clone(),
                })
                .await
            {
                Ok(_) => {
                    emit_runtime_event(
                        events.as_ref(),
                        core_activity_event(
                            ActivityKind::SandboxDestroy,
                            ActivityResult::Ok,
                            &trace_id,
                            Some(name),
                        )
                        .with_subject_value("handle", serde_json::json!(handle.clone()))
                        .with_latency_ms(elapsed_ms(destroy_start)),
                    );
                }
                Err(err) => {
                    destroy_error_emitted = true;
                    emit_runtime_event(
                        events.as_ref(),
                        core_activity_event(
                            ActivityKind::SandboxDestroy,
                            ActivityResult::Error,
                            &trace_id,
                            Some(name),
                        )
                        .with_subject_value("handle", serde_json::json!(handle))
                        .with_reason_code(
                            crate::admission::ReasonCode::DriverCommandFailed.as_str(),
                        )
                        .with_latency_ms(elapsed_ms(destroy_start)),
                    );
                    return Err(err.into());
                }
            }
            state.handles.sandbox = None;
            crate::env::write_state(&paths, &state)?;
        }

        if let Some(proxy) = state.egress_proxy.clone() {
            if let Some(pid) = proxy.pid {
                let _ = stop_egress_proxy_pid(pid).await;
            }
            state.egress_proxy = None;
            crate::env::write_state(&paths, &state)?;
        }

        if let Some(handle) = state.handles.inference.clone() {
            let Some(inference) = set.inference.as_mut() else {
                return Err(missing_inference_driver(&state));
            };
            initialize_inference_driver(options, inference.as_mut()).await?;
            inference
                .teardown(agentenv_proto::InferenceHandleRequest { handle })
                .await?;
            state.handles.inference = None;
            crate::env::write_state(&paths, &state)?;
        }

        if let Some(handle) = state.handles.context.clone() {
            initialize_context_driver(options, set.context.as_mut()).await?;
            set.context
                .teardown(agentenv_proto::ContextHandleRequest { handle })
                .await?;
            state.handles.context = None;
            crate::env::write_state(&paths, &state)?;
        }

        fs::remove_dir_all(paths.env_dir()).map_err(|source| crate::env::EnvError::Io {
            path: paths.env_dir(),
            source,
        })?;

        Ok(crate::admission::AdmissionReport {
            status: crate::admission::AdmissionStatus::Accepted,
            reason_code: crate::admission::ReasonCode::Destroyed,
            env: name.to_owned(),
            checks: Vec::new(),
        })
    }
    .await;

    if let Err(err) = &result {
        if !destroy_error_emitted {
            let mut event = core_activity_event(
                ActivityKind::SandboxDestroy,
                ActivityResult::Error,
                &trace_id,
                Some(name),
            )
            .with_reason_code(runtime_error_reason_code(err));
            if let Some(handle) = destroy_event_handle {
                event = event.with_subject_value("handle", serde_json::json!(handle));
            }
            emit_runtime_event(events.as_ref(), event);
        }
    }

    result
}

fn selection_from_state(state: &crate::env::EnvStateFile) -> DriverSelection {
    DriverSelection {
        sandbox: state.drivers.sandbox.name.clone(),
        agent: state.drivers.agent.name.clone(),
        context: state.drivers.context.name.clone(),
        inference: state
            .drivers
            .inference
            .as_ref()
            .map(|driver| driver.name.clone()),
    }
}

fn supports_persistent_sessions(capabilities: &Capabilities) -> bool {
    matches!(
        capabilities,
        Capabilities::Sandbox(agentenv_proto::SandboxCapabilities {
            supports_persistent_sessions: true,
            ..
        })
    )
}

fn supports_hot_reload_policy(capabilities: &Capabilities) -> bool {
    matches!(
        capabilities,
        Capabilities::Sandbox(agentenv_proto::SandboxCapabilities {
            supports_hot_reload_policy: true,
            ..
        })
    )
}

fn supports_host_egress_proxy(capabilities: &Capabilities) -> bool {
    matches!(
        capabilities,
        Capabilities::Sandbox(agentenv_proto::SandboxCapabilities {
            supports_host_egress_proxy: true,
            ..
        })
    )
}

fn supports_snapshots(capabilities: &Capabilities) -> bool {
    matches!(
        capabilities,
        Capabilities::Sandbox(agentenv_proto::SandboxCapabilities {
            supports_snapshots: true,
            ..
        })
    )
}

fn supports_fork(capabilities: &Capabilities) -> bool {
    matches!(
        capabilities,
        Capabilities::Sandbox(agentenv_proto::SandboxCapabilities {
            supports_fork: true,
            ..
        })
    )
}

async fn reconcile_sessions_with_driver(
    paths: &crate::env::EnvPaths,
    env: &str,
    sandbox: &dyn SandboxDriver,
    handle: &str,
) -> RuntimeResult<crate::sessions::SessionStateFile> {
    let mut sessions = crate::sessions::read_sessions(paths, env)?;
    let live_sessions = sandbox
        .list_sessions(agentenv_proto::ListSessionsParams {
            handle: handle.to_owned(),
        })
        .await?;
    reconcile_session_state(&mut sessions, live_sessions);
    crate::sessions::write_sessions(paths, &sessions)?;
    Ok(sessions)
}

fn reconcile_session_state(
    sessions: &mut crate::sessions::SessionStateFile,
    live_sessions: agentenv_proto::ListSessionsResult,
) {
    let reported_live_ids = live_sessions
        .sessions
        .iter()
        .map(|session| session.session_id.clone())
        .collect::<BTreeSet<_>>();
    for session in live_sessions.sessions {
        let stable_identity = crate::sessions::find_session(sessions, &session.session_id)
            .map(|persisted| (persisted.id.clone(), persisted.name.clone()));
        let mut persisted = persisted_from_driver_session(session);
        if let Ok((id, name)) = stable_identity {
            persisted.id = id;
            persisted.name = name;
        }
        crate::sessions::upsert_session(sessions, persisted, false);
    }

    let now = now_utc_string();
    for session in sessions
        .sessions
        .iter_mut()
        .filter(|session| crate::sessions::is_live_status(&session.status))
    {
        if !reported_live_ids.contains(&session.driver_session_id)
            && !reported_live_ids.contains(&session.id)
        {
            session.status = agentenv_proto::SessionStatus::Unknown;
            session.updated_at = now.clone();
        }
    }
}

fn next_session_name(env: &str, sessions: &crate::sessions::SessionStateFile) -> String {
    if sessions.sessions.is_empty() {
        env.to_owned()
    } else {
        format!("{env}-{}", sessions.sessions.len() + 1)
    }
}

fn persisted_from_driver_session(
    session: agentenv_proto::SessionHandle,
) -> crate::sessions::PersistedSession {
    crate::sessions::PersistedSession {
        id: session.session_id.clone(),
        driver_session_id: session.session_id,
        name: session.name,
        status: session.status,
        command: session.command,
        created_at: session.created_at,
        updated_at: session.updated_at,
        working_dir: session.working_dir,
        metadata: BTreeMap::new(),
    }
}

fn find_session_or_invalid<'a>(
    sessions: &'a crate::sessions::SessionStateFile,
    session_id: &str,
) -> RuntimeResult<&'a crate::sessions::PersistedSession> {
    crate::sessions::find_session(sessions, session_id).map_err(|_| {
        RuntimeError::Driver(DriverError::InvalidHandle {
            handle: session_id.to_owned(),
            message: "session not found".to_owned(),
        })
    })
}

fn required_sandbox_handle(state: &crate::env::EnvStateFile, name: &str) -> RuntimeResult<String> {
    state
        .handles
        .sandbox
        .clone()
        .ok_or_else(|| RuntimeError::MissingSandboxHandle {
            name: name.to_owned(),
        })
}

async fn copy_sandbox_path_out(
    sandbox: &dyn SandboxDriver,
    handle: &str,
    src_sandbox_path: &str,
    dst_host_path: &Path,
) -> RuntimeResult<()> {
    sandbox
        .copy_out(agentenv_proto::CopyOutParams {
            handle: handle.to_owned(),
            src_sandbox_path: src_sandbox_path.to_owned(),
            dst_host_path: dst_host_path.display().to_string(),
        })
        .await?;
    Ok(())
}

async fn copy_host_path_into_sandbox(
    sandbox: &dyn SandboxDriver,
    handle: &str,
    src_host_path: &Path,
    dst_sandbox_path: &str,
) -> RuntimeResult<()> {
    sandbox
        .copy_in(agentenv_proto::CopyInParams {
            handle: handle.to_owned(),
            src_host_path: src_host_path.display().to_string(),
            dst_sandbox_path: dst_sandbox_path.to_owned(),
        })
        .await?;
    Ok(())
}

async fn resolve_sandbox_home(sandbox: &dyn SandboxDriver, handle: &str) -> RuntimeResult<String> {
    let command = r#"printf %s "$HOME""#;
    let result = sandbox
        .exec(agentenv_proto::ExecParams {
            handle: handle.to_owned(),
            cmd: command.to_owned(),
            tty: false,
            env: BTreeMap::new(),
        })
        .await?;
    ensure_command_success(command, &result, &[0])?;

    let home = result.stdout.trim().to_owned();
    if home.is_empty() {
        return Err(RuntimeError::Driver(DriverError::InvalidInput {
            message: "sandbox HOME resolved to an empty path".to_owned(),
        }));
    }
    Ok(home)
}

fn blueprint_persist_home(
    blueprint_yaml: &str,
    lockfile: Option<&crate::lockfile::PortableLockfile>,
) -> bool {
    if lockfile
        .and_then(|lockfile| lockfile.composition.state.as_ref())
        .and_then(|state| state.persist_home)
        .unwrap_or(false)
    {
        return true;
    }

    serde_yaml::from_str::<serde_yaml::Value>(blueprint_yaml)
        .ok()
        .and_then(|value| {
            value
                .get("state")
                .and_then(|state| state.get("persist_home"))
                .and_then(serde_yaml::Value::as_bool)
        })
        .unwrap_or(false)
}

fn snapshot_credential_requirements(
    lockfile: &crate::lockfile::PortableLockfile,
) -> Vec<crate::snapshot::SnapshotCredentialRequirement> {
    lockfile
        .credentials
        .iter()
        .map(
            |(name, credential)| crate::snapshot::SnapshotCredentialRequirement {
                name: name.clone(),
                source: credential.source.clone(),
                reference: credential.reference.clone(),
                required: credential.required,
            },
        )
        .collect()
}

fn portable_snapshot_lockfile(
    lock_yaml: &str,
) -> RuntimeResult<Option<crate::lockfile::PortableLockfile>> {
    match crate::lockfile::LockfileDocument::from_yaml(lock_yaml)? {
        crate::lockfile::LockfileDocument::Portable(lockfile) => Ok(Some(lockfile)),
        crate::lockfile::LockfileDocument::Legacy(_) => Ok(None),
    }
}

fn reject_existing_snapshot_output(output: &Path) -> RuntimeResult<()> {
    match fs::symlink_metadata(output) {
        Ok(_) => Err(snapshot_output_exists_error(output)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(crate::env::EnvError::Io {
            path: output.to_path_buf(),
            source,
        }
        .into()),
    }
}

fn finalize_snapshot_dir_no_clobber(staging_dir: &Path, output: &Path) -> RuntimeResult<()> {
    match fs::create_dir(output) {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_dir_all(staging_dir);
            return Err(snapshot_output_exists_error(output));
        }
        Err(source) => {
            let _ = fs::remove_dir_all(staging_dir);
            return Err(crate::env::EnvError::Io {
                path: output.to_path_buf(),
                source,
            }
            .into());
        }
    }

    let result = move_snapshot_entries(staging_dir, output);
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_dir_all(output);
            let _ = fs::remove_dir_all(staging_dir);
            Err(error)
        }
    }
}

fn move_snapshot_entries(staging_dir: &Path, output: &Path) -> RuntimeResult<()> {
    let entries = fs::read_dir(staging_dir).map_err(|source| crate::env::EnvError::Io {
        path: staging_dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| crate::env::EnvError::Io {
            path: staging_dir.to_path_buf(),
            source,
        })?;
        let file_name = entry.file_name();
        let destination = output.join(file_name);
        fs::rename(entry.path(), &destination).map_err(|source| crate::env::EnvError::Io {
            path: destination,
            source,
        })?;
    }
    fs::remove_dir(staging_dir).map_err(|source| crate::env::EnvError::Io {
        path: staging_dir.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn snapshot_output_exists_error(output: &Path) -> RuntimeError {
    RuntimeError::Driver(DriverError::InvalidInput {
        message: format!("snapshot output `{}` already exists", output.display()),
    })
}

fn write_snapshot_registry_files(
    options: &RuntimeOptions,
    env: &str,
    staging_dir: &Path,
    blueprint_yaml: &str,
    lock_yaml: &str,
    policy: &agentenv_proto::NetworkPolicy,
) -> RuntimeResult<()> {
    fs::write(staging_dir.join("blueprint.yaml"), blueprint_yaml).map_err(|source| {
        crate::env::EnvError::Io {
            path: staging_dir.join("blueprint.yaml"),
            source,
        }
    })?;
    fs::write(staging_dir.join("lock.yaml"), lock_yaml).map_err(|source| {
        crate::env::EnvError::Io {
            path: staging_dir.join("lock.yaml"),
            source,
        }
    })?;
    let rendered_policy =
        serde_yaml::to_string(policy).map_err(RuntimeError::lockfile_serialize)?;
    fs::write(staging_dir.join("policy.yaml"), rendered_policy).map_err(|source| {
        crate::env::EnvError::Io {
            path: staging_dir.join("policy.yaml"),
            source,
        }
    })?;

    let paths =
        crate::env::EnvPaths::new(options.root.clone(), crate::env::validate_env_name(env)?);
    let events_db = paths.env_dir().join("events.db");
    match fs::symlink_metadata(&events_db) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::copy(&events_db, staging_dir.join("events.db")).map_err(|source| {
                crate::env::EnvError::Io {
                    path: events_db.clone(),
                    source,
                }
            })?;
        }
        Ok(_) => {
            return Err(RuntimeError::Driver(DriverError::InvalidInput {
                message: format!(
                    "events database `{}` is not a regular file",
                    events_db.display()
                ),
            }));
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(crate::env::EnvError::Io {
                path: events_db,
                source,
            }
            .into());
        }
    }
    Ok(())
}

fn missing_inference_driver(state: &crate::env::EnvStateFile) -> RuntimeError {
    let name = state
        .drivers
        .inference
        .as_ref()
        .map(|driver| driver.name.clone())
        .unwrap_or_else(|| "<unknown>".to_owned());
    RuntimeError::MissingSelectedDriver {
        kind: "inference",
        name,
    }
}

fn create_temp_workspace(root: &Path, name: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let seq = CREATE_WORKSPACE_SEQ.fetch_add(1, Ordering::Relaxed);

    root.join(".agentenv-tmp")
        .join(format!("create-{name}-{pid}-{nanos}-{seq}"))
}

fn create_temp_snapshot_dir(root: &Path, name: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let seq = CREATE_WORKSPACE_SEQ.fetch_add(1, Ordering::Relaxed);

    root.join(".agentenv-tmp")
        .join(format!("snapshot-{name}-{pid}-{nanos}-{seq}"))
}

fn env_phase_status(phase: crate::env::EnvPhase) -> String {
    match phase {
        crate::env::EnvPhase::Creating => "creating",
        crate::env::EnvPhase::Running => "running",
        crate::env::EnvPhase::Destroying => "destroying",
        crate::env::EnvPhase::Destroyed => "destroyed",
        crate::env::EnvPhase::Error => "error",
    }
    .to_owned()
}

fn ensure_runtime_handshake(
    expected_kind: DriverKind,
    helper: &'static str,
    result: &InitializeResult,
) -> RuntimeResult<()> {
    ensure_protocol_compatible(result).map_err(RuntimeError::from)?;

    if result.driver.kind != expected_kind {
        return Err(RuntimeError::InvalidDriverHandshake {
            helper,
            expected_kind: expected_kind.clone(),
            actual_kind: result.driver.kind.clone(),
            expected_capability: expected_capability_name(&expected_kind),
            actual_capability: actual_capability_name(&result.capabilities),
        });
    }

    let expected_capability = expected_capability_name(&expected_kind);
    let actual_capability = actual_capability_name(&result.capabilities);

    if actual_capability != expected_capability {
        return Err(RuntimeError::InvalidDriverHandshake {
            helper,
            expected_kind: expected_kind.clone(),
            actual_kind: result.driver.kind.clone(),
            expected_capability,
            actual_capability,
        });
    }

    Ok(())
}

fn expected_capability_name(expected: &DriverKind) -> &'static str {
    match expected {
        DriverKind::Sandbox => "sandbox",
        DriverKind::Agent => "agent",
        DriverKind::Context => "context",
        DriverKind::Inference => "inference",
    }
}

fn actual_capability_name(capabilities: &Capabilities) -> &'static str {
    match capabilities {
        Capabilities::Sandbox(_) => "sandbox",
        Capabilities::Agent(_) => "agent",
        Capabilities::Context(_) => "context",
        Capabilities::Inference(_) => "inference",
    }
}

fn initialize_params(options: &RuntimeOptions) -> InitializeParams {
    InitializeParams {
        schema_version: SCHEMA_VERSION.to_owned(),
        core_version: env!("CARGO_PKG_VERSION").to_owned(),
        workdir: options.root.display().to_string(),
        log_level: options.log_level.clone(),
    }
}

pub fn empty_preflight_params() -> PreflightParams {
    PreflightParams {}
}

pub fn component_spec(
    extra: BTreeMap<String, serde_yaml::Value>,
) -> RuntimeResult<serde_json::Map<String, serde_json::Value>> {
    extra
        .into_iter()
        .map(|(key, value)| match serde_json::to_value(value) {
            Ok(value) => Ok((key, value)),
            Err(source) => Err(RuntimeError::ComponentConfigConversion { key, source }),
        })
        .collect()
}

pub fn agent_spec(
    extra: BTreeMap<String, serde_yaml::Value>,
    version: Option<String>,
) -> RuntimeResult<AgentSpec> {
    Ok(AgentSpec {
        version,
        config: component_spec(extra)?.into_iter().collect(),
    })
}

pub fn context_spec(extra: BTreeMap<String, serde_yaml::Value>) -> RuntimeResult<ContextSpec> {
    Ok(ContextSpec {
        config: component_spec(extra)?.into_iter().collect(),
    })
}

pub fn inference_spec(extra: BTreeMap<String, serde_yaml::Value>) -> RuntimeResult<InferenceSpec> {
    Ok(InferenceSpec {
        config: component_spec(extra)?.into_iter().collect(),
    })
}

async fn prepare_agent_sandbox_setup(
    temp_workspace: &Path,
    agent: &dyn AgentDriver,
    spec: AgentSpec,
    endpoints: Vec<agentenv_proto::McpEndpoint>,
) -> RuntimeResult<AgentSandboxSetup> {
    let can_skip_install_if_probe_passes = spec.version.is_none();
    let install_steps = agent.install_steps(spec.clone()).await?;
    let install_commands = install_commands_from_steps(install_steps.steps)?;
    let mcp_config_path = agent
        .mcp_config_path(agentenv_proto::McpConfigPathParams::default())
        .await?;
    let mcp_config = agent
        .render_mcp_config(agentenv_proto::RenderMcpConfigParams { endpoints })
        .await?;
    let entrypoint = agent.render_entrypoint(spec.clone()).await?;
    let health_probe = agent.health_check_probe(spec).await?;

    let agent_dir = temp_workspace.join("agent-assets");
    fs::create_dir_all(&agent_dir).map_err(|source| crate::env::EnvError::Io {
        path: agent_dir.clone(),
        source,
    })?;
    let mcp_config_host_path = agent_dir.join("mcp-config");
    fs::write(&mcp_config_host_path, mcp_config.content).map_err(|source| {
        crate::env::EnvError::Io {
            path: mcp_config_host_path.clone(),
            source,
        }
    })?;
    let entrypoint_host_path = agent_dir.join("entrypoint");
    fs::write(&entrypoint_host_path, entrypoint.content).map_err(|source| {
        crate::env::EnvError::Io {
            path: entrypoint_host_path.clone(),
            source,
        }
    })?;

    Ok(AgentSandboxSetup {
        install_commands,
        can_skip_install_if_probe_passes,
        mcp_config_host_path,
        mcp_config_sandbox_path: normalize_agent_sandbox_path(&mcp_config_path.path)?,
        entrypoint_host_path,
        health_probe,
    })
}

async fn install_agent_in_sandbox(
    sandbox: &dyn SandboxDriver,
    handle: &str,
    setup: &AgentSandboxSetup,
) -> RuntimeResult<()> {
    let skip_install = setup.can_skip_install_if_probe_passes
        && !setup.install_commands.is_empty()
        && agent_health_probe_succeeds(sandbox, handle, setup).await?;
    if !skip_install {
        for command in &setup.install_commands {
            let result = sandbox
                .exec(agentenv_proto::ExecParams {
                    handle: handle.to_owned(),
                    cmd: command.cmd.clone(),
                    tty: false,
                    env: command.env.clone(),
                })
                .await?;
            ensure_command_success(&command.cmd, &result, &[0])?;
        }
    }

    copy_agent_file_into_sandbox(
        sandbox,
        handle,
        &setup.mcp_config_host_path,
        &setup.mcp_config_sandbox_path,
        "0600",
    )
    .await?;
    copy_agent_file_into_sandbox(
        sandbox,
        handle,
        &setup.entrypoint_host_path,
        AGENT_ENTRYPOINT_PATH,
        "0755",
    )
    .await?;

    let result = sandbox
        .exec(agentenv_proto::ExecParams {
            handle: handle.to_owned(),
            cmd: setup.health_probe.cmd.clone(),
            tty: setup.health_probe.tty,
            env: setup.health_probe.env.clone(),
        })
        .await?;
    ensure_command_success(
        &setup.health_probe.cmd,
        &result,
        &setup.health_probe.success_exit_codes,
    )
}

async fn agent_health_probe_succeeds(
    sandbox: &dyn SandboxDriver,
    handle: &str,
    setup: &AgentSandboxSetup,
) -> RuntimeResult<bool> {
    let result = sandbox
        .exec(agentenv_proto::ExecParams {
            handle: handle.to_owned(),
            cmd: setup.health_probe.cmd.clone(),
            tty: setup.health_probe.tty,
            env: setup.health_probe.env.clone(),
        })
        .await?;
    Ok(command_status_succeeded(
        result.status,
        &setup.health_probe.success_exit_codes,
    ))
}

async fn copy_agent_file_into_sandbox(
    sandbox: &dyn SandboxDriver,
    handle: &str,
    host_path: &Path,
    sandbox_path: &str,
    mode: &str,
) -> RuntimeResult<()> {
    let parent = sandbox_parent_dir(sandbox_path)?;
    let mkdir = format!("mkdir -p {}", shell_quote(&parent));
    let result = sandbox
        .exec(agentenv_proto::ExecParams {
            handle: handle.to_owned(),
            cmd: mkdir.clone(),
            tty: false,
            env: BTreeMap::new(),
        })
        .await?;
    ensure_command_success(&mkdir, &result, &[0])?;

    sandbox
        .copy_in(agentenv_proto::CopyInParams {
            handle: handle.to_owned(),
            src_host_path: host_path.display().to_string(),
            dst_sandbox_path: sandbox_path.to_owned(),
        })
        .await?;

    let chmod = format!("chmod {mode} {}", shell_quote(sandbox_path));
    let result = sandbox
        .exec(agentenv_proto::ExecParams {
            handle: handle.to_owned(),
            cmd: chmod.clone(),
            tty: false,
            env: BTreeMap::new(),
        })
        .await?;
    ensure_command_success(&chmod, &result, &[0])
}

fn ensure_command_success(
    command: &str,
    result: &agentenv_proto::ExecResult,
    success_exit_codes: &[i32],
) -> RuntimeResult<()> {
    if command_status_succeeded(result.status, success_exit_codes) {
        Ok(())
    } else {
        Err(RuntimeError::Driver(
            crate::driver::DriverError::CommandFailed {
                command: command.to_owned(),
                status: Some(result.status),
                stdout: result.stdout.clone(),
                stderr: result.stderr.clone(),
            },
        ))
    }
}

fn command_status_succeeded(status: i32, success_exit_codes: &[i32]) -> bool {
    if success_exit_codes.is_empty() {
        status == 0
    } else {
        success_exit_codes.contains(&status)
    }
}

fn install_commands_from_steps(
    steps: Vec<agentenv_proto::DockerfileFragment>,
) -> RuntimeResult<Vec<AgentInstallCommand>> {
    let mut commands = Vec::new();
    let mut env = BTreeMap::new();
    for step in steps {
        for line in step.content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("ARG ") {
                let (key, value) = parse_dockerfile_arg(rest)?;
                env.insert(key, value);
                continue;
            }
            if let Some(command) = line.strip_prefix("RUN ") {
                commands.push(AgentInstallCommand {
                    cmd: command.to_owned(),
                    env: env.clone(),
                });
                continue;
            }
            return Err(RuntimeError::Driver(
                crate::driver::DriverError::InvalidInput {
                    message: format!("unsupported agent install Dockerfile instruction `{line}`"),
                },
            ));
        }
    }
    Ok(commands)
}

fn parse_dockerfile_arg(input: &str) -> RuntimeResult<(String, String)> {
    let (key, value) = input
        .split_once('=')
        .map(|(key, value)| (key.trim(), value.trim()))
        .unwrap_or((input.trim(), ""));
    if key.is_empty()
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(RuntimeError::Driver(
            crate::driver::DriverError::InvalidInput {
                message: format!("invalid agent install ARG name `{key}`"),
            },
        ));
    }
    Ok((key.to_owned(), unquote_dockerfile_arg(value)))
}

fn unquote_dockerfile_arg(value: &str) -> String {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!(
            (bytes[0], bytes[value.len() - 1]),
            (b'"', b'"') | (b'\'', b'\'')
        ) {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

fn normalize_agent_sandbox_path(path: &str) -> RuntimeResult<String> {
    if let Some(rest) = path.strip_prefix("~/") {
        return Ok(format!("/sandbox/{rest}"));
    }
    if path.starts_with('/') {
        return Ok(path.to_owned());
    }
    Err(RuntimeError::Driver(
        crate::driver::DriverError::InvalidInput {
            message: format!("agent sandbox path `{path}` must be absolute or start with `~/`"),
        },
    ))
}

fn sandbox_parent_dir(path: &str) -> RuntimeResult<String> {
    Path::new(path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| parent.display().to_string())
        .ok_or_else(|| {
            RuntimeError::Driver(crate::driver::DriverError::InvalidInput {
                message: format!("agent sandbox path `{path}` has no parent directory"),
            })
        })
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn empty_state(name: &str, selection: DriverSelection) -> crate::env::EnvStateFile {
    let now = now_utc_string();
    let drivers = crate::env::StateDriverSet {
        sandbox: crate::env::DriverRecord::new(selection.sandbox, ""),
        agent: crate::env::DriverRecord::new(selection.agent, ""),
        context: crate::env::DriverRecord::new(selection.context, ""),
        inference: selection
            .inference
            .map(|name| crate::env::DriverRecord::new(name, "")),
    };

    crate::env::EnvStateFile {
        version: crate::env::STATE_VERSION.to_owned(),
        name: name.to_owned(),
        phase: crate::env::EnvPhase::Error,
        created_at: now.clone(),
        updated_at: now,
        drivers,
        handles: crate::env::DriverHandles::default(),
        endpoints: crate::env::EndpointState::default(),
        egress_proxy: None,
        resolved_policy: None,
        credential_names: Vec::new(),
        health: BTreeMap::new(),
        first_enter_hint_shown: false,
    }
}

fn now_utc_string() -> String {
    match time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339) {
        Ok(value) => value,
        Err(_) => "1970-01-01T00:00:00Z".to_owned(),
    }
}

fn new_trace_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

fn elapsed_ms(start: Instant) -> u64 {
    let millis = start.elapsed().as_millis();
    if millis > u128::from(u64::MAX) {
        u64::MAX
    } else {
        millis as u64
    }
}

fn core_activity_event(
    kind: ActivityKind,
    result: ActivityResult,
    trace_id: &str,
    env: Option<&str>,
) -> ActivityEvent {
    let mut event = ActivityEvent::new(now_utc_string(), kind, result, trace_id)
        .with_actor_value("kind", serde_json::json!("core"));
    if let Some(env) = env {
        event = event.with_env(env);
    }
    event
}

fn core_policy_applied_event(
    result: ActivityResult,
    trace_id: &str,
    env: Option<&str>,
    handle: &str,
    phase: &str,
    policy: &agentenv_proto::NetworkPolicy,
    latency_ms: u64,
) -> ActivityEvent {
    core_activity_event(ActivityKind::PolicyApplied, result, trace_id, env)
        .with_subject_value("handle", serde_json::json!(handle))
        .with_subject_value("phase", serde_json::json!(phase))
        .with_subject_value("policy", policy_json_value(policy))
        .with_latency_ms(latency_ms)
}

fn validate_runtime_dns_policy(policy: &agentenv_proto::NetworkPolicy) -> RuntimeResult<()> {
    crate::security::dns_policy::validate_dns_policy(&policy.network.dns).map_err(Into::into)
}

fn supports_dns_egress_control(capabilities: &Capabilities) -> bool {
    matches!(
        capabilities,
        Capabilities::Sandbox(SandboxCapabilities {
            supports_dns_egress_control: true,
            ..
        })
    )
}

fn ensure_dns_policy_supported(
    capabilities: &Capabilities,
    policy: &agentenv_proto::NetworkPolicy,
) -> RuntimeResult<()> {
    if policy.network.dns.is_active() && !supports_dns_egress_control(capabilities) {
        return Err(RuntimeError::Driver(
            crate::driver::DriverError::CapabilityMissing {
                capability: "supports_dns_egress_control".to_owned(),
            },
        ));
    }

    Ok(())
}

fn policy_json_value(policy: &agentenv_proto::NetworkPolicy) -> serde_json::Value {
    serde_json::to_value(policy).unwrap_or(serde_json::Value::Null)
}

fn emit_runtime_event(events: &dyn EventEmitter, event: ActivityEvent) {
    events.emit(event.redacted());
}

fn with_command_metadata(event: ActivityEvent, command: &[String]) -> ActivityEvent {
    event
        .with_subject_value("command_present", serde_json::json!(!command.is_empty()))
        .with_subject_value("command_argc", serde_json::json!(command.len()))
}

fn runtime_error_reason_code(error: &RuntimeError) -> &'static str {
    match error {
        RuntimeError::Env(EnvError::AlreadyExists { .. }) => {
            crate::admission::ReasonCode::EnvExists.as_str()
        }
        RuntimeError::Env(EnvError::NotFound { .. })
        | RuntimeError::SandboxHandleNotFound { .. } => {
            crate::admission::ReasonCode::EnvNotFound.as_str()
        }
        RuntimeError::Env(EnvError::InvalidName { .. })
        | RuntimeError::InvalidPolicyTier { .. }
        | RuntimeError::InvalidEgressProxyPolicy { .. }
        | RuntimeError::Lifecycle(_)
        | RuntimeError::Lockfile(_)
        | RuntimeError::PortableLockfile(_)
        | RuntimeError::Snapshot(_)
        | RuntimeError::Blueprint(_)
        | RuntimeError::Hardening(_)
        | RuntimeError::DnsPolicy(_)
        | RuntimeError::ApprovalConfig(_)
        | RuntimeError::EgressProxyPlan(_)
        | RuntimeError::LegacyLockfileReproduce
        | RuntimeError::PortableLockfileVerification { .. }
        | RuntimeError::ComponentConfigConversion { .. }
        | RuntimeError::FrozenLockfileDriverMismatch { .. } => {
            crate::admission::ReasonCode::InvalidBlueprint.as_str()
        }
        RuntimeError::MissingCredential { .. } => {
            crate::admission::ReasonCode::MissingCredential.as_str()
        }
        RuntimeError::MissingSelectedDriver { .. }
        | RuntimeError::UnsupportedDriver { .. }
        | RuntimeError::InvalidDriverHandshake { .. }
        | RuntimeError::MissingSandboxHandle { .. }
        | RuntimeError::HostEgressProxyUnsupported { .. }
        | RuntimeError::StateNameMismatch { .. } => {
            crate::admission::ReasonCode::CapabilityMissing.as_str()
        }
        RuntimeError::Env(EnvError::Io { .. })
        | RuntimeError::Env(EnvError::Json { .. })
        | RuntimeError::ApprovalNotification(_)
        | RuntimeError::EgressProxyListen { .. }
        | RuntimeError::EgressProxyLaunch(_)
        | RuntimeError::Driver(_)
        | RuntimeError::DriverArtifact(_)
        | RuntimeError::CommandStatus { .. } => {
            crate::admission::ReasonCode::DriverCommandFailed.as_str()
        }
    }
}

fn parse_tier(value: &str) -> RuntimeResult<Tier> {
    match value {
        "restricted" => Ok(Tier::Restricted),
        "balanced" => Ok(Tier::Balanced),
        "open" => Ok(Tier::Open),
        _ => Err(RuntimeError::InvalidPolicyTier {
            tier: value.to_owned(),
        }),
    }
}

fn parse_presets(values: &[String]) -> RuntimeResult<Vec<PresetSelection>> {
    values
        .iter()
        .map(|value| {
            PresetSelection::from_slug(value).map_err(|err| {
                RuntimeError::Driver(crate::driver::DriverError::PolicyTranslation {
                    message: err.to_string(),
                })
            })
        })
        .collect()
}

fn policy_overrides(
    policy: &crate::blueprint::PolicySection,
) -> RuntimeResult<Option<agentenv_proto::NetworkPolicy>> {
    if policy.overrides.is_empty() && policy_dns_override(policy).is_none() {
        return Ok(None);
    }

    let mut override_policy = empty_policy_override();
    for item in &policy.overrides {
        if let Some(allow) = item.allow.as_ref() {
            override_policy
                .network
                .allow
                .push(policy_override_network_rule(
                    allow,
                    PolicyOverrideTargetKind::AllowOrDeny,
                ));
        }
        if let Some(deny) = item.deny.as_ref() {
            override_policy
                .network
                .deny
                .push(policy_override_network_rule(
                    deny,
                    PolicyOverrideTargetKind::AllowOrDeny,
                ));
        }
        if let Some(approval) = item.approval.as_ref() {
            override_policy
                .network
                .approval_required
                .push(policy_override_network_rule(
                    approval,
                    PolicyOverrideTargetKind::Approval,
                ));
        }
    }
    if let Some(dns) = policy_dns_override(policy) {
        override_policy.network.dns = dns;
    }

    Ok(Some(override_policy))
}

fn policy_dns_override(
    policy: &crate::blueprint::PolicySection,
) -> Option<agentenv_proto::DnsPolicy> {
    policy.dns.as_ref().map(|dns| agentenv_proto::DnsPolicy {
        resolvers_allowed: dns.resolvers_allowed.clone(),
        doh_upstreams_allowed: dns.doh_upstreams_allowed.clone(),
        dot_upstreams_allowed: dns.dot_upstreams_allowed.clone(),
        log_all_queries: dns.log_all_queries,
        pin_resolved_ips: dns.pin_resolved_ips,
    })
}

enum PolicyOverrideTargetKind {
    AllowOrDeny,
    Approval,
}

fn policy_override_network_rule(
    pattern: &str,
    kind: PolicyOverrideTargetKind,
) -> agentenv_proto::NetworkRule {
    if let Ok(url) = url::Url::parse(pattern) {
        if matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
        {
            let host = url.host_str().unwrap_or_default().to_owned();
            return agentenv_proto::NetworkRule {
                target: match kind {
                    PolicyOverrideTargetKind::AllowOrDeny => agentenv_proto::NetworkTarget::Host {
                        host,
                        port: url.port_or_known_default(),
                        scheme: Some(url.scheme().to_owned()),
                        http_access: None,
                    },
                    PolicyOverrideTargetKind::Approval => {
                        agentenv_proto::NetworkTarget::HttpMethodPath {
                            host: Some(host),
                            method: "*".to_owned(),
                            path: url.path().to_owned(),
                        }
                    }
                },
            };
        }
    }

    url_pattern_rule(pattern)
}

fn empty_policy_override() -> agentenv_proto::NetworkPolicy {
    agentenv_proto::NetworkPolicy {
        network: agentenv_proto::NetworkAccessPolicy {
            reloadability: agentenv_proto::PolicyReloadability::HotReload,
            allow: Vec::new(),
            deny: Vec::new(),
            approval_required: Vec::new(),
            dns: agentenv_proto::DnsPolicy::default(),
        },
        filesystem: agentenv_proto::FilesystemPolicy {
            reloadability: agentenv_proto::PolicyReloadability::LockedAtCreate,
            read_only: Vec::new(),
            read_write: Vec::new(),
        },
        process: agentenv_proto::ProcessPolicy {
            reloadability: agentenv_proto::PolicyReloadability::LockedAtCreate,
            run_as_user: String::new(),
            run_as_group: String::new(),
            profile: String::new(),
            allow_syscalls: Vec::new(),
            deny_syscalls: Vec::new(),
        },
        inference: agentenv_proto::InferencePolicy {
            reloadability: agentenv_proto::PolicyReloadability::HotReload,
            routes: Vec::new(),
        },
    }
}

fn url_pattern_rule(pattern: &str) -> agentenv_proto::NetworkRule {
    agentenv_proto::NetworkRule {
        target: agentenv_proto::NetworkTarget::UrlPattern {
            pattern: pattern.to_owned(),
        },
    }
}

impl fmt::Debug for DriverSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DriverSet").finish_non_exhaustive()
    }
}

#[cfg(test)]
pub mod tests_support {
    use agentenv_proto::{
        AgentCapabilities, AgentHealthCheckProbe, AgentSpec, Capabilities,
        CredentialRequirementsResult, DriverInfo, DriverKind, EmptyResult, InitializeParams,
        InitializeResult, InstallStepsResult, McpConfigPathParams, McpConfigPathResult,
        PreflightParams, PreflightResult, RenderEntrypointResult, RenderMcpConfigParams,
        RenderMcpConfigResult, SCHEMA_VERSION,
    };
    use async_trait::async_trait;

    use crate::driver::{AgentDriver, DriverResult};

    pub struct TinyAgentDriver;

    #[async_trait]
    impl AgentDriver for TinyAgentDriver {
        async fn initialize(
            &mut self,
            _params: InitializeParams,
        ) -> DriverResult<InitializeResult> {
            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "codex".to_owned(),
                    kind: DriverKind::Agent,
                    version: "0.0.1-alpha0".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: Capabilities::Agent(AgentCapabilities {
                    supports_mcp: true,
                    supports_slash_commands: true,
                    supports_tui: true,
                    supports_headless: true,
                }),
            })
        }
        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }
        async fn install_steps(&self, _spec: AgentSpec) -> DriverResult<InstallStepsResult> {
            Ok(InstallStepsResult { steps: Vec::new() })
        }
        async fn mcp_config_path(
            &self,
            _params: McpConfigPathParams,
        ) -> DriverResult<McpConfigPathResult> {
            Ok(McpConfigPathResult {
                path: "~/.codex/config.toml".to_owned(),
            })
        }
        async fn render_mcp_config(
            &self,
            _params: RenderMcpConfigParams,
        ) -> DriverResult<RenderMcpConfigResult> {
            Ok(RenderMcpConfigResult {
                content: String::new(),
            })
        }
        async fn render_entrypoint(
            &self,
            _spec: AgentSpec,
        ) -> DriverResult<RenderEntrypointResult> {
            Ok(RenderEntrypointResult {
                content: "#!/usr/bin/env sh\nexec codex \"$@\"\n".to_owned(),
            })
        }
        async fn credential_requirements(
            &self,
            _spec: AgentSpec,
        ) -> DriverResult<CredentialRequirementsResult> {
            Ok(CredentialRequirementsResult {
                requirements: Vec::new(),
            })
        }
        async fn health_check_probe(
            &self,
            _spec: AgentSpec,
        ) -> DriverResult<AgentHealthCheckProbe> {
            Ok(AgentHealthCheckProbe {
                cmd: "codex --version".to_owned(),
                tty: false,
                env: Default::default(),
                success_exit_codes: vec![0],
            })
        }
        async fn shutdown(
            &mut self,
            _params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
    }

    pub struct EmptyCredentialProvider;

    impl super::CredentialProvider for EmptyCredentialProvider {
        fn resolve(
            &mut self,
            _requirement: &agentenv_proto::CredentialRequirement,
        ) -> super::RuntimeResult<Option<super::RuntimeSecret>> {
            Ok(None)
        }

        fn backend_name(&self, _name: &str) -> super::RuntimeResult<Option<String>> {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Mutex, MutexGuard, OnceLock,
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    use agentenv_events::{
        ActivityEvent, ActivityKind, ActivityResult, EventEmitter, RecordingEventEmitter,
    };
    use agentenv_proto::{
        Capabilities, ContextCapabilities, DriverInfo, DriverKind, EmptyResult,
        InferenceCapabilities, InitializeParams, InitializeResult, LogLevel, NetworkTarget,
        PreflightParams, PreflightResult, SandboxCapabilities, SCHEMA_VERSION,
    };
    use async_trait::async_trait;

    use crate::driver::{ContextDriver, DriverResult, InferenceDriver, SandboxDriver};

    use super::{
        approval_coordinator_for_env, component_spec, env_approval_overlay_path,
        env_approval_proposals_path, env_events_db_path, freeze_env_for_bundle,
        initialize_context_driver, initialize_sandbox_driver, DriverFactory, DriverSet,
        RuntimeError, RuntimeOptions, RuntimeSecret,
    };

    fn unique_root(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }

    fn write_runtime_skill_pin(
        root: &std::path::Path,
        manifest_schema_version: &str,
    ) -> crate::lockfile::SkillPin {
        write_runtime_skill_pin_with_self_test(root, manifest_schema_version, None)
    }

    fn write_runtime_skill_pin_with_self_test(
        root: &std::path::Path,
        manifest_schema_version: &str,
        self_test: Option<crate::skills::SkillSelfTest>,
    ) -> crate::lockfile::SkillPin {
        let skill_dir = root.join("skills").join("code-review").join("1.2.0");
        fs::create_dir_all(skill_dir.join(".agentenv")).expect("create skill metadata dir");
        fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: code-review\nversion: 1.2.0\n---\n# code-review\n",
        )
        .expect("write skill");

        let archive_bytes = b"runtime pinned skill archive";
        let archive_hex = crate::digest::sha256_hex(archive_bytes);
        let digest = format!("sha256:{archive_hex}");
        let archive_dir = root.join("cache").join("skills");
        fs::create_dir_all(&archive_dir).expect("create skill archive dir");
        fs::write(
            archive_dir.join(format!("{archive_hex}.tar.zst")),
            archive_bytes,
        )
        .expect("write skill archive");

        let manifest = crate::skills::cache::SkillManifest {
            schema_version: manifest_schema_version.to_owned(),
            name: "code-review".to_owned(),
            version: "1.2.0".to_owned(),
            source: "file:///skills/code-review".to_owned(),
            digest: digest.clone(),
            signatures: Vec::new(),
            archive: Some(crate::skills::SkillArchive {
                digest: digest.clone(),
                cache_key: format!("{archive_hex}.tar.zst"),
            }),
            self_test,
        };
        fs::write(
            skill_dir.join(".agentenv/manifest.json"),
            serde_json::to_string_pretty(&manifest).expect("render manifest"),
        )
        .expect("write skill manifest");

        let provenance = crate::skills::SkillProvenance {
            schema_version: crate::skills::SKILL_METADATA_SCHEMA_VERSION.to_owned(),
            subject: crate::skills::SkillProvenanceSubject {
                name: "code-review".to_owned(),
                version: "1.2.0".to_owned(),
                digest: digest.clone(),
            },
            attestations: Vec::new(),
        };
        fs::write(
            skill_dir.join(".agentenv/provenance.json"),
            serde_json::to_string_pretty(&provenance).expect("render provenance"),
        )
        .expect("write skill provenance");

        crate::lockfile::SkillPin {
            name: manifest.name,
            version: manifest.version,
            source: manifest.source,
            digest: manifest.digest,
            signatures: Vec::new(),
        }
    }

    fn state_fixture(name: &str) -> crate::env::EnvStateFile {
        crate::env::EnvStateFile {
            version: crate::env::STATE_VERSION.to_owned(),
            name: name.to_owned(),
            phase: crate::env::EnvPhase::Running,
            created_at: "2026-04-21T00:00:00Z".to_owned(),
            updated_at: "2026-04-21T00:00:00Z".to_owned(),
            drivers: crate::env::StateDriverSet {
                sandbox: crate::env::DriverRecord::new("openshell", "0.0.1-alpha0"),
                agent: crate::env::DriverRecord::new("codex", "0.0.1-alpha0"),
                context: crate::env::DriverRecord::new("filesystem", "0.0.1-alpha0"),
                inference: None,
            },
            handles: crate::env::DriverHandles::default(),
            endpoints: crate::env::EndpointState::default(),
            egress_proxy: None,
            resolved_policy: None,
            credential_names: Vec::new(),
            health: BTreeMap::new(),
            first_enter_hint_shown: false,
        }
    }

    #[test]
    fn freeze_env_for_bundle_returns_persisted_blueprint_and_portable_lockfile() {
        let root = unique_root("agentenv-runtime-freeze-bundle-source");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let env_dir = root.join("envs").join("demo");
        fs::create_dir_all(&env_dir).unwrap();
        let driver_version = env!("CARGO_PKG_VERSION");
        fs::write(
            env_dir.join("state.json"),
            serde_json::json!({
                "version": "0.1.0",
                "name": "demo",
                "phase": "running",
                "created_at": "2026-05-09T00:00:00Z",
                "updated_at": "2026-05-09T00:00:00Z",
                "drivers": {
                    "sandbox": {"name": "openshell", "version": driver_version},
                    "agent": {"name": "codex", "version": driver_version},
                    "context": {"name": "filesystem", "version": driver_version},
                    "inference": {"name": "passthrough", "version": driver_version}
                },
                "handles": {},
                "endpoints": {},
                "first_enter_hint_shown": false
            })
            .to_string(),
        )
        .unwrap();
        let blueprint_yaml = r#"version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#;
        fs::write(env_dir.join("blueprint.yaml"), blueprint_yaml).unwrap();
        let lock_yaml = crate::lifecycle::freeze_from_blueprint_yaml(blueprint_yaml).unwrap();
        fs::write(env_dir.join("lock.yaml"), lock_yaml).unwrap();

        let frozen = freeze_env_for_bundle(&options, "demo").unwrap();

        assert_eq!(frozen.env_name, "demo");
        assert_eq!(frozen.blueprint_yaml, blueprint_yaml);
        let crate::lockfile::LockfileDocument::Portable(lockfile) =
            crate::lockfile::LockfileDocument::from_yaml(&frozen.lockfile_yaml).unwrap()
        else {
            panic!("bundle source should include a portable lockfile");
        };
        let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
        discovery_config.installed_root = root.join("drivers");
        let driver_artifacts =
            crate::driver_artifact::discover_driver_artifacts(discovery_config, None).unwrap();
        let expected = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: "demo".to_owned(),
                blueprint_yaml: frozen.blueprint_yaml.clone(),
                driver_artifacts,
            },
        )
        .unwrap();

        assert_eq!(lockfile.name, "demo");
        assert_eq!(lockfile.version, crate::lockfile::PORTABLE_LOCKFILE_VERSION);
        assert_eq!(lockfile.composition, expected.composition);
        assert_eq!(lockfile.blueprint_hash, expected.blueprint_hash);
    }

    fn write_state_json(env_dir: &std::path::Path, state: crate::env::EnvStateFile) {
        fs::create_dir_all(env_dir).unwrap();
        let rendered = serde_json::to_string_pretty(&state).unwrap();
        fs::write(env_dir.join("state.json"), rendered).unwrap();
    }

    trait StateFixtureExt {
        fn with_sandbox_handle(self, handle: &str) -> Self;
    }

    impl StateFixtureExt for crate::env::EnvStateFile {
        fn with_sandbox_handle(mut self, handle: &str) -> Self {
            self.handles.sandbox = Some(handle.to_owned());
            self
        }
    }

    fn snapshot_blueprint_yaml() -> &'static str {
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#
    }

    fn snapshot_persist_home_blueprint_yaml() -> &'static str {
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
state:
  persist_home: true
"#
    }

    #[tokio::test]
    async fn fork_env_persists_forked_sandbox_state() {
        let root = unique_root("fork-env");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let source_paths =
            crate::env::EnvPaths::new(root.clone(), crate::env::validate_env_name("demo").unwrap());
        fs::create_dir_all(source_paths.env_dir()).unwrap();
        fs::write(
            source_paths.blueprint_path(),
            "sandbox:\n  driver: microvm\n",
        )
        .unwrap();
        fs::write(source_paths.lock_path(), "drivers: {}\n").unwrap();
        fs::write(source_paths.events_path(), "").unwrap();

        let mut state = state_fixture("demo")
            .with_sandbox_handle("microvm://firecracker/demo?workdir=/tmp/demo");
        state.drivers.sandbox = crate::env::DriverRecord::new("microvm", "0.0.1-alpha0");
        state.handles.context = Some("ctx-source".to_owned());
        state.endpoints.context_mcp = Some(crate::env::PersistedMcpEndpoint {
            url: "stdio://filesystem".to_owned(),
            transport: agentenv_proto::McpTransport::Stdio,
        });
        write_state_json(&source_paths.env_dir(), state);

        let calls = Arc::new(Mutex::new(ForkCalls::default()));
        let factory = ForkingFactory {
            calls: Arc::clone(&calls),
            supports_snapshots: true,
            supports_fork: true,
        };

        let result = super::fork_env(&options, &factory, "demo", "experiment")
            .await
            .expect("fork should succeed");

        assert_eq!(result.source, "demo");
        assert_eq!(result.name, "experiment");
        assert!(result.state_path.ends_with("envs/experiment/state.json"));

        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.snapshot_handle.as_deref(),
            Some("microvm://firecracker/demo?workdir=/tmp/demo")
        );
        assert_eq!(calls.snapshot_name.as_deref(), Some("experiment"));
        assert_eq!(
            calls.fork_snapshot_id.as_deref(),
            Some("microvm-snapshot://demo/base")
        );
        assert_eq!(calls.fork_name.as_deref(), Some("experiment"));

        let target_paths = crate::env::EnvPaths::new(
            root.clone(),
            crate::env::validate_env_name("experiment").unwrap(),
        );
        let target = crate::env::read_state(&target_paths).unwrap();
        assert_eq!(target.name, "experiment");
        assert_eq!(target.phase, crate::env::EnvPhase::Running);
        assert_eq!(
            target.handles.sandbox.as_deref(),
            Some("microvm://firecracker/experiment")
        );
        assert_eq!(target.handles.context, None);
        assert_eq!(target.handles.inference, None);
        assert_eq!(
            target
                .endpoints
                .context_mcp
                .as_ref()
                .map(|endpoint| &endpoint.url),
            Some(&"stdio://filesystem".to_owned())
        );
        assert_eq!(
            fs::read_to_string(target_paths.blueprint_path()).unwrap(),
            "sandbox:\n  driver: microvm\n"
        );
        assert_eq!(
            fs::read_to_string(target_paths.lock_path()).unwrap(),
            "drivers: {}\n"
        );
        assert!(target_paths.events_path().is_file());
    }

    fn snapshot_credential_blueprint_yaml() -> &'static str {
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
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#
    }

    fn snapshot_lockfile_yaml(root: &std::path::Path, name: &str, blueprint_yaml: &str) -> String {
        let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
        discovery_config.installed_root = root.join("drivers");
        let driver_artifacts =
            crate::driver_artifact::discover_driver_artifacts(discovery_config, None)
                .expect("discover driver artifacts");
        let lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: name.to_owned(),
                blueprint_yaml: blueprint_yaml.to_owned(),
                driver_artifacts,
            },
        )
        .expect("build portable lockfile");
        lockfile.to_yaml_deterministic().expect("render lockfile")
    }

    fn snapshot_lockfile_yaml_with_policy(
        root: &std::path::Path,
        name: &str,
        blueprint_yaml: &str,
        policy: agentenv_proto::NetworkPolicy,
    ) -> String {
        let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
        discovery_config.installed_root = root.join("drivers");
        let driver_artifacts =
            crate::driver_artifact::discover_driver_artifacts(discovery_config, None)
                .expect("discover driver artifacts");
        let mut lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: name.to_owned(),
                blueprint_yaml: blueprint_yaml.to_owned(),
                driver_artifacts,
            },
        )
        .expect("build portable lockfile");
        lockfile.policy.resolved = policy;
        lockfile.to_yaml_deterministic().expect("render lockfile")
    }

    fn write_snapshot_env_fixture(root: &std::path::Path, name: &str, blueprint_yaml: &str) {
        let env_dir = root.join("envs").join(name);
        let lock_yaml = snapshot_lockfile_yaml(root, name, blueprint_yaml);
        fs::create_dir_all(&env_dir).unwrap();
        fs::write(env_dir.join("blueprint.yaml"), blueprint_yaml).unwrap();
        fs::write(env_dir.join("lock.yaml"), lock_yaml).unwrap();
        let _store = agentenv_approvals::ApprovalStore::open(env_dir.join("events.db")).unwrap();
        write_state_json(
            &env_dir,
            state_fixture(name).with_sandbox_handle("sb-snapshot"),
        );
    }

    fn write_signed_snapshot_fixture(
        root: &std::path::Path,
        source_env: &str,
        credential_requirements: Vec<crate::snapshot::SnapshotCredentialRequirement>,
    ) -> std::path::PathBuf {
        write_signed_snapshot_fixture_with(
            root,
            source_env,
            credential_requirements,
            super::empty_policy_override(),
            |_| {},
        )
    }

    fn write_signed_snapshot_fixture_with(
        root: &std::path::Path,
        source_env: &str,
        credential_requirements: Vec<crate::snapshot::SnapshotCredentialRequirement>,
        policy: agentenv_proto::NetworkPolicy,
        populate: impl FnOnce(&std::path::Path),
    ) -> std::path::PathBuf {
        write_signed_snapshot_fixture_with_blueprint(
            root,
            source_env,
            credential_requirements,
            policy,
            snapshot_blueprint_yaml(),
            populate,
        )
    }

    fn write_signed_snapshot_fixture_with_blueprint(
        root: &std::path::Path,
        source_env: &str,
        credential_requirements: Vec<crate::snapshot::SnapshotCredentialRequirement>,
        policy: agentenv_proto::NetworkPolicy,
        blueprint_yaml: &str,
        populate: impl FnOnce(&std::path::Path),
    ) -> std::path::PathBuf {
        let snapshot_dir = root.join(format!("{source_env}.agentenvsnap"));
        fs::create_dir_all(snapshot_dir.join("workspace")).unwrap();
        fs::write(snapshot_dir.join("workspace").join("README.md"), "hello\n").unwrap();
        populate(&snapshot_dir);
        fs::write(snapshot_dir.join("blueprint.yaml"), blueprint_yaml).unwrap();
        fs::write(
            snapshot_dir.join("lock.yaml"),
            snapshot_lockfile_yaml_with_policy(root, source_env, blueprint_yaml, policy.clone()),
        )
        .unwrap();
        fs::write(
            snapshot_dir.join("policy.yaml"),
            serde_yaml::to_string(&policy).unwrap(),
        )
        .unwrap();
        let manifest = crate::snapshot::manifest_for_snapshot_dir(
            &snapshot_dir,
            source_env,
            credential_requirements,
            Vec::new(),
        )
        .expect("manifest");
        crate::snapshot::write_signed_manifest(
            &snapshot_dir,
            &root.join("snapshot-signing.key"),
            &manifest,
        )
        .expect("write signed manifest");
        snapshot_dir
    }

    fn write_custom_signed_snapshot(
        root: &std::path::Path,
        source_env: &str,
        lock_yaml: &str,
        policy_yaml: &str,
    ) -> std::path::PathBuf {
        write_custom_signed_snapshot_with_manifest(root, source_env, lock_yaml, policy_yaml, |_| {})
    }

    fn write_custom_signed_snapshot_with_manifest(
        root: &std::path::Path,
        source_env: &str,
        lock_yaml: &str,
        policy_yaml: &str,
        mutate_manifest: impl FnOnce(&mut crate::snapshot::SnapshotManifest),
    ) -> std::path::PathBuf {
        let snapshot_dir = root.join(format!("{source_env}.agentenvsnap"));
        fs::create_dir_all(snapshot_dir.join("workspace")).unwrap();
        fs::write(snapshot_dir.join("workspace").join("README.md"), "hello\n").unwrap();
        fs::write(
            snapshot_dir.join("blueprint.yaml"),
            snapshot_blueprint_yaml(),
        )
        .unwrap();
        fs::write(snapshot_dir.join("lock.yaml"), lock_yaml).unwrap();
        fs::write(snapshot_dir.join("policy.yaml"), policy_yaml).unwrap();
        let mut manifest = crate::snapshot::manifest_for_snapshot_dir(
            &snapshot_dir,
            source_env,
            Vec::new(),
            Vec::new(),
        )
        .expect("manifest");
        mutate_manifest(&mut manifest);
        crate::snapshot::write_signed_manifest(
            &snapshot_dir,
            &root.join("snapshot-signing.key"),
            &manifest,
        )
        .expect("write signed manifest");
        snapshot_dir
    }

    struct EnvVarGuard {
        _lock: MutexGuard<'static, ()>,
        name: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn unset(name: &'static str) -> Self {
            static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let lock = ENV_LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .expect("env var test lock");
            let previous = std::env::var_os(name);
            std::env::remove_var(name);
            Self {
                _lock: lock,
                name,
                previous,
            }
        }

        fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let lock = ENV_LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .expect("env var test lock");
            let previous = std::env::var_os(name);
            std::env::set_var(name, value);
            Self {
                _lock: lock,
                name,
                previous,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.as_ref() {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
            }
        }
    }

    #[cfg(unix)]
    fn fake_egress_proxy_bin(root: &std::path::Path) -> EnvVarGuard {
        use std::os::unix::fs::PermissionsExt;

        fs::create_dir_all(root).expect("create fake proxy root");
        let fake_proxy = root.join("fake-agentenv-proxy.sh");
        fs::write(&fake_proxy, "#!/bin/sh\nsleep 30\n").expect("write fake proxy");
        fs::set_permissions(&fake_proxy, fs::Permissions::from_mode(0o755))
            .expect("fake proxy executable");
        EnvVarGuard::set(crate::egress_proxy::EGRESS_PROXY_BIN_ENV, &fake_proxy)
    }

    #[test]
    fn approval_overlay_path_helpers_validate_env_and_stay_under_env_dir() {
        let root = unique_root("agentenv-approval-paths");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: false,
        };

        assert_eq!(
            env_events_db_path(&options, "demo").unwrap(),
            root.join("envs").join("demo").join("events.db")
        );
        assert_eq!(
            env_approval_overlay_path(&options, "demo").unwrap(),
            root.join("envs")
                .join("demo")
                .join("approval-policy-overlay.yaml")
        );
        assert_eq!(
            env_approval_proposals_path(&options, "demo").unwrap(),
            root.join("envs")
                .join("demo")
                .join("approval-policy-proposals.yaml")
        );
        assert!(matches!(
            env_approval_overlay_path(&options, "../demo"),
            Err(RuntimeError::Env(crate::env::EnvError::InvalidName { .. }))
        ));
    }

    #[test]
    fn approval_runtime_paths_are_env_scoped() {
        let root = unique_root("approval-runtime-paths");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: agentenv_proto::LogLevel::Info,
            non_interactive: true,
        };

        assert_eq!(
            env_approval_overlay_path(&options, "demo").unwrap(),
            root.join("envs")
                .join("demo")
                .join("approval-policy-overlay.yaml")
        );
    }

    #[tokio::test]
    async fn approval_coordinator_helper_writes_to_env_scoped_store() {
        let root = unique_root("approval-coordinator");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let coordinator = approval_coordinator_for_env(
            &options,
            "demo",
            Arc::new(RecordingEventEmitter::default()),
        )
        .unwrap();

        coordinator
            .submit_request(agentenv_approvals::ApprovalRequest::new(
                "req-1",
                "demo",
                agentenv_approvals::ApprovalKind::EgressHost,
                "example.com",
                "network request",
                serde_json::json!({}),
                time::OffsetDateTime::UNIX_EPOCH,
                agentenv_approvals::ApprovalScope::Once,
                std::time::Duration::from_secs(60),
                "trace-1",
            ))
            .await
            .unwrap();

        assert!(root.join("envs").join("demo").join("events.db").exists());
    }

    #[derive(Default)]
    struct TinyFactory;

    impl DriverFactory for TinyFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(TinySandboxDriver),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    struct DnsCapabilityFactory {
        sandbox_capabilities: SandboxCapabilities,
    }

    impl Default for DnsCapabilityFactory {
        fn default() -> Self {
            Self {
                sandbox_capabilities: SandboxCapabilities {
                    supports_hot_reload_policy: true,
                    supports_filesystem_lockdown: true,
                    supports_syscall_filter: true,
                    supports_native_inference_routing: true,
                    supports_remote_host: false,
                    supports_host_egress_proxy: false,
                    supports_persistent_sessions: false,
                    supports_dns_egress_control: false,
                    supports_snapshots: false,
                    supports_fork: false,
                },
            }
        }
    }

    impl DriverFactory for DnsCapabilityFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(DnsCapabilitySandboxDriver {
                    capabilities: self.sandbox_capabilities.clone(),
                }),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    struct DnsCapabilitySandboxDriver {
        capabilities: SandboxCapabilities,
    }

    #[async_trait]
    impl SandboxDriver for DnsCapabilitySandboxDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            assert_eq!(params.schema_version, SCHEMA_VERSION);
            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "openshell".to_owned(),
                    kind: DriverKind::Sandbox,
                    version: "0.0.1-alpha0".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: Capabilities::Sandbox(self.capabilities.clone()),
            })
        }

        async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
            TinySandboxDriver.preflight(params).await
        }

        async fn create(
            &self,
            spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            TinySandboxDriver.create(spec).await
        }

        async fn connect(
            &self,
            params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            TinySandboxDriver.connect(params).await
        }

        async fn exec(
            &self,
            params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            TinySandboxDriver.exec(params).await
        }

        async fn copy_in(&self, params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_in(params).await
        }

        async fn copy_out(
            &self,
            params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_out(params).await
        }

        async fn apply_policy(
            &self,
            params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            TinySandboxDriver.apply_policy(params).await
        }

        async fn status(
            &self,
            params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            TinySandboxDriver.status(params).await
        }

        async fn logs(
            &self,
            params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            TinySandboxDriver.logs(params).await
        }

        async fn logs_stream(
            &self,
            params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.logs_stream(params).await
        }

        async fn stop(&self, params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.stop(params).await
        }

        async fn destroy(
            &self,
            params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.destroy(params).await
        }

        async fn shutdown(
            &mut self,
            params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.shutdown(params).await
        }
    }

    fn dns_policy_blueprint() -> &'static str {
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
  dns:
    resolvers_allowed: [1.1.1.1]
    log_all_queries: true
    pin_resolved_ips: true
"#
    }

    #[derive(Clone, Default)]
    struct SnapshotFactory {
        copied_out: Arc<Mutex<Vec<(String, String)>>>,
        copied_in: Arc<Mutex<Vec<(String, String)>>>,
        copied_in_entries: SnapshotCopyInEntries,
        execs: Arc<Mutex<Vec<String>>>,
        env_builds: Arc<Mutex<Vec<String>>>,
        output_race: Arc<Mutex<Option<SnapshotOutputRace>>>,
    }

    impl DriverFactory for SnapshotFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            self.build_snapshot_driver_set()
        }

        fn build_for_env_observed(
            &self,
            _selection: &super::DriverSelection,
            env: &str,
            _events: Arc<dyn EventEmitter>,
            _approval_coordinator: Option<agentenv_approvals::ApprovalCoordinator>,
        ) -> super::RuntimeResult<DriverSet> {
            self.env_builds
                .lock()
                .expect("env build tracker")
                .push(env.to_owned());
            self.build_snapshot_driver_set()
        }
    }

    impl SnapshotFactory {
        fn build_snapshot_driver_set(&self) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(SnapshotSandbox {
                    copied_out: Arc::clone(&self.copied_out),
                    copied_in: Arc::clone(&self.copied_in),
                    copied_in_entries: Arc::clone(&self.copied_in_entries),
                    execs: Arc::clone(&self.execs),
                    output_race: Arc::clone(&self.output_race),
                }),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    #[derive(Clone)]
    enum SnapshotOutputRace {
        File(std::path::PathBuf),
        Directory(std::path::PathBuf),
    }

    type SnapshotCopyInEntry = (String, String, Vec<String>);
    type SnapshotCopyInEntries = Arc<Mutex<Vec<SnapshotCopyInEntry>>>;

    struct SnapshotSandbox {
        copied_out: Arc<Mutex<Vec<(String, String)>>>,
        copied_in: Arc<Mutex<Vec<(String, String)>>>,
        copied_in_entries: SnapshotCopyInEntries,
        execs: Arc<Mutex<Vec<String>>>,
        output_race: Arc<Mutex<Option<SnapshotOutputRace>>>,
    }

    fn snapshot_copy_in_entries(path: &std::path::Path) -> std::io::Result<Vec<String>> {
        let mut entries = Vec::new();
        if path.is_dir() {
            snapshot_copy_in_entries_inner(path, path, &mut entries)?;
        } else if path.exists() {
            entries.push(String::new());
        }
        entries.sort();
        Ok(entries)
    }

    fn snapshot_copy_in_entries_inner(
        root: &std::path::Path,
        current: &std::path::Path,
        entries: &mut Vec<String>,
    ) -> std::io::Result<()> {
        for entry in fs::read_dir(current)? {
            let path = entry?.path();
            let relative = path
                .strip_prefix(root)
                .map_err(std::io::Error::other)?
                .to_string_lossy()
                .replace('\\', "/");
            entries.push(relative);
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_dir() {
                snapshot_copy_in_entries_inner(root, &path, entries)?;
            }
        }
        Ok(())
    }

    #[async_trait]
    impl SandboxDriver for SnapshotSandbox {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            TinySandboxDriver.initialize(params).await
        }

        async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
            TinySandboxDriver.preflight(params).await
        }

        async fn create(
            &self,
            spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            TinySandboxDriver.create(spec).await
        }

        async fn connect(
            &self,
            params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            TinySandboxDriver.connect(params).await
        }

        async fn exec(
            &self,
            params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            self.execs
                .lock()
                .expect("exec tracker")
                .push(params.cmd.clone());
            if params.cmd == r#"printf %s "$HOME""# {
                return Ok(agentenv_proto::ExecResult {
                    status: 0,
                    stdout: "/home/agent".to_owned(),
                    stderr: String::new(),
                });
            }
            TinySandboxDriver.exec(params).await
        }

        async fn copy_in(&self, params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult> {
            self.copied_in.lock().expect("copy in tracker").push((
                params.src_host_path.clone(),
                params.dst_sandbox_path.clone(),
            ));
            let entries = snapshot_copy_in_entries(std::path::Path::new(&params.src_host_path))
                .map_err(|source| crate::driver::DriverError::InvalidInput {
                    message: format!("read copy-in source entries: {source}"),
                })?;
            self.copied_in_entries
                .lock()
                .expect("copy in entry tracker")
                .push((
                    params.src_host_path.clone(),
                    params.dst_sandbox_path.clone(),
                    entries,
                ));
            TinySandboxDriver.copy_in(params).await
        }

        async fn copy_out(
            &self,
            params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            self.copied_out.lock().expect("copy out tracker").push((
                params.src_sandbox_path.clone(),
                params.dst_host_path.clone(),
            ));
            if let Some(race) = self.output_race.lock().expect("output race tracker").take() {
                match race {
                    SnapshotOutputRace::File(path) => {
                        fs::write(path, "existing output\n").map_err(|source| {
                            crate::driver::DriverError::InvalidInput {
                                message: format!("create raced output file: {source}"),
                            }
                        })?;
                    }
                    SnapshotOutputRace::Directory(path) => {
                        fs::create_dir_all(&path).map_err(|source| {
                            crate::driver::DriverError::InvalidInput {
                                message: format!("create raced output dir: {source}"),
                            }
                        })?;
                    }
                }
            }
            let dst = std::path::PathBuf::from(&params.dst_host_path);
            fs::create_dir_all(&dst).map_err(|source| {
                crate::driver::DriverError::InvalidInput {
                    message: format!("create copy-out dir `{}`: {source}", dst.display()),
                }
            })?;
            fs::write(
                dst.join("copied.txt"),
                format!("copied from {}\n", params.src_sandbox_path),
            )
            .map_err(|source| crate::driver::DriverError::InvalidInput {
                message: format!("write copied file under `{}`: {source}", dst.display()),
            })?;
            Ok(EmptyResult {})
        }

        async fn apply_policy(
            &self,
            params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            TinySandboxDriver.apply_policy(params).await
        }

        async fn status(
            &self,
            params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            TinySandboxDriver.status(params).await
        }

        async fn logs(
            &self,
            params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            TinySandboxDriver.logs(params).await
        }

        async fn logs_stream(
            &self,
            params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.logs_stream(params).await
        }

        async fn stop(&self, params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.stop(params).await
        }

        async fn destroy(
            &self,
            params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.destroy(params).await
        }

        async fn shutdown(
            &mut self,
            params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.shutdown(params).await
        }
    }

    struct ObservedFactory;

    impl DriverFactory for ObservedFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(TinySandboxDriver),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }

        fn build_observed(
            &self,
            selection: &super::DriverSelection,
            events: Arc<dyn EventEmitter>,
        ) -> super::RuntimeResult<DriverSet> {
            events.emit(
                ActivityEvent::new(
                    "2026-04-26T12:00:00Z",
                    ActivityKind::Log,
                    ActivityResult::Ok,
                    "factory-trace",
                )
                .with_actor_value("driver", serde_json::json!("observed-factory")),
            );
            self.build(selection)
        }
    }

    struct InitializingFactory {
        sandbox_initialized: Arc<AtomicBool>,
    }

    impl DriverFactory for InitializingFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(InitTrackingSandboxDriver {
                    initialized: Arc::clone(&self.sandbox_initialized),
                }),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    struct FailingContextTeardownFactory {
        sandbox_destroyed: Arc<AtomicBool>,
    }

    impl DriverFactory for FailingContextTeardownFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(DestroyTrackingSandboxDriver {
                    destroyed: Arc::clone(&self.sandbox_destroyed),
                }),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(FailingTeardownContextDriver),
                inference: None,
            })
        }
    }

    struct FailingContextProvisionFactory;

    impl DriverFactory for FailingContextProvisionFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(TinySandboxDriver),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(FailingProvisionContextDriver),
                inference: None,
            })
        }
    }

    #[derive(Default)]
    struct AgentSetupTracker {
        copied_paths: Mutex<Vec<String>>,
        exec_cmds: Mutex<Vec<String>>,
        agent_spec_versions: Mutex<Vec<Option<String>>>,
        agent_credential_requirements: Mutex<Vec<agentenv_proto::CredentialRequirement>>,
        mcp_config_endpoints: Mutex<Vec<Vec<agentenv_proto::McpEndpoint>>>,
        create_specs: Mutex<Vec<agentenv_proto::SandboxSpec>>,
        create_policies: Mutex<Vec<agentenv_proto::NetworkPolicy>>,
        applied_policies: Mutex<Vec<agentenv_proto::NetworkPolicy>>,
        byo_digest_root: Mutex<Option<std::path::PathBuf>>,
        byo_digest: Mutex<Option<String>>,
        preinstall_probe_succeeds: AtomicBool,
        supports_host_egress_proxy: AtomicBool,
    }

    struct AgentSetupFactory {
        tracker: Arc<AgentSetupTracker>,
    }

    impl DriverFactory for AgentSetupFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(AgentSetupSandboxDriver {
                    tracker: Arc::clone(&self.tracker),
                    supports_hot_reload_policy: true,
                }),
                agent: Box::new(AgentSetupAgentDriver {
                    tracker: Arc::clone(&self.tracker),
                }),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    struct NoHotReloadAgentSetupFactory {
        tracker: Arc<AgentSetupTracker>,
    }

    impl DriverFactory for NoHotReloadAgentSetupFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(AgentSetupSandboxDriver {
                    tracker: Arc::clone(&self.tracker),
                    supports_hot_reload_policy: false,
                }),
                agent: Box::new(AgentSetupAgentDriver {
                    tracker: Arc::clone(&self.tracker),
                }),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    struct RequiredRuleFactory {
        tracker: Arc<AgentSetupTracker>,
        required_rule: agentenv_proto::NetworkRule,
    }

    impl DriverFactory for RequiredRuleFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(AgentSetupSandboxDriver {
                    tracker: Arc::clone(&self.tracker),
                    supports_hot_reload_policy: true,
                }),
                agent: Box::new(AgentSetupAgentDriver {
                    tracker: Arc::clone(&self.tracker),
                }),
                context: Box::new(RequiredRuleContextDriver {
                    required_rule: self.required_rule.clone(),
                }),
                inference: None,
            })
        }
    }

    struct RequiredRuleContextDriver {
        required_rule: agentenv_proto::NetworkRule,
    }

    #[async_trait]
    impl ContextDriver for RequiredRuleContextDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            TinyContextDriver.initialize(params).await
        }

        async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
            TinyContextDriver.preflight(params).await
        }

        async fn provision(
            &self,
            params: agentenv_proto::ContextSpec,
        ) -> DriverResult<agentenv_proto::ContextHandle> {
            TinyContextDriver.provision(params).await
        }

        async fn mcp_endpoint(
            &self,
            params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::McpEndpoint> {
            TinyContextDriver.mcp_endpoint(params).await
        }

        async fn required_network_rules(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::RequiredNetworkRulesResult> {
            Ok(agentenv_proto::RequiredNetworkRulesResult {
                rules: vec![self.required_rule.clone()],
            })
        }

        async fn credential_requirements(
            &self,
            params: agentenv_proto::CredentialRequirementsParams,
        ) -> DriverResult<agentenv_proto::CredentialRequirementsResult> {
            TinyContextDriver.credential_requirements(params).await
        }

        async fn status(
            &self,
            params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::ContextStatus> {
            TinyContextDriver.status(params).await
        }

        async fn teardown(
            &self,
            params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<EmptyResult> {
            TinyContextDriver.teardown(params).await
        }

        async fn shutdown(
            &mut self,
            params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            TinyContextDriver.shutdown(params).await
        }
    }

    struct HttpMcpContextFactory {
        tracker: Arc<AgentSetupTracker>,
        transport: agentenv_proto::McpTransport,
    }

    impl DriverFactory for HttpMcpContextFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(AgentSetupSandboxDriver {
                    tracker: Arc::clone(&self.tracker),
                    supports_hot_reload_policy: true,
                }),
                agent: Box::new(AgentSetupAgentDriver {
                    tracker: Arc::clone(&self.tracker),
                }),
                context: Box::new(HttpMcpContextDriver {
                    transport: self.transport.clone(),
                }),
                inference: None,
            })
        }
    }

    struct HttpMcpContextDriver {
        transport: agentenv_proto::McpTransport,
    }

    #[async_trait]
    impl ContextDriver for HttpMcpContextDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            TinyContextDriver.initialize(params).await
        }

        async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
            TinyContextDriver.preflight(params).await
        }

        async fn provision(
            &self,
            params: agentenv_proto::ContextSpec,
        ) -> DriverResult<agentenv_proto::ContextHandle> {
            TinyContextDriver.provision(params).await
        }

        async fn mcp_endpoint(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::McpEndpoint> {
            Ok(agentenv_proto::McpEndpoint {
                url: "https://mcp.example.test/rpc".to_owned(),
                transport: self.transport.clone(),
                headers: BTreeMap::from([(
                    "authorization".to_owned(),
                    "Bearer real-upstream-token".to_owned(),
                )]),
            })
        }

        async fn required_network_rules(
            &self,
            params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::RequiredNetworkRulesResult> {
            TinyContextDriver.required_network_rules(params).await
        }

        async fn credential_requirements(
            &self,
            _params: agentenv_proto::CredentialRequirementsParams,
        ) -> DriverResult<agentenv_proto::CredentialRequirementsResult> {
            Ok(agentenv_proto::CredentialRequirementsResult {
                requirements: vec![required_runtime_credential("MCP_TOKEN")],
            })
        }

        async fn status(
            &self,
            params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::ContextStatus> {
            TinyContextDriver.status(params).await
        }

        async fn teardown(
            &self,
            params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<EmptyResult> {
            TinyContextDriver.teardown(params).await
        }

        async fn shutdown(
            &mut self,
            params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            TinyContextDriver.shutdown(params).await
        }
    }

    #[derive(Default)]
    struct PinTrackingFactory {
        normal_builds: AtomicU64,
        pinned_builds: AtomicU64,
        pin_roles: Mutex<Vec<String>>,
    }

    impl DriverFactory for PinTrackingFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            self.normal_builds.fetch_add(1, Ordering::SeqCst);
            Ok(DriverSet {
                sandbox: Box::new(TinySandboxDriver),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }

        fn build_pinned(
            &self,
            _selection: &super::DriverSelection,
            pins: &super::DriverPinSet,
        ) -> super::RuntimeResult<DriverSet> {
            self.pinned_builds.fetch_add(1, Ordering::SeqCst);
            self.pin_roles
                .lock()
                .expect("pin roles")
                .extend(pins.roles().map(str::to_owned));
            Ok(DriverSet {
                sandbox: Box::new(TinySandboxDriver),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    struct BackendOnlyCredentialProvider {
        backend: Option<String>,
    }

    impl super::CredentialProvider for BackendOnlyCredentialProvider {
        fn resolve(
            &mut self,
            _requirement: &agentenv_proto::CredentialRequirement,
        ) -> super::RuntimeResult<Option<RuntimeSecret>> {
            Ok(None)
        }

        fn backend_name(&self, _name: &str) -> super::RuntimeResult<Option<String>> {
            Ok(self.backend.clone())
        }
    }

    #[derive(Default)]
    struct ResolvingCredentialProvider {
        values: BTreeMap<String, String>,
        resolved: Vec<agentenv_proto::CredentialRequirement>,
    }

    impl ResolvingCredentialProvider {
        fn with_value(name: &str, value: &str) -> Self {
            Self {
                values: BTreeMap::from([(name.to_owned(), value.to_owned())]),
                resolved: Vec::new(),
            }
        }
    }

    impl super::CredentialProvider for ResolvingCredentialProvider {
        fn resolve(
            &mut self,
            requirement: &agentenv_proto::CredentialRequirement,
        ) -> super::RuntimeResult<Option<RuntimeSecret>> {
            self.resolved.push(requirement.clone());
            Ok(self
                .values
                .get(&requirement.name)
                .map(|value| RuntimeSecret::new(value.clone())))
        }

        fn backend_name(&self, _name: &str) -> super::RuntimeResult<Option<String>> {
            Ok(None)
        }
    }

    fn required_runtime_credential(name: &str) -> agentenv_proto::CredentialRequirement {
        super::credential_requirement(name, true)
    }

    struct AgentSetupAgentDriver {
        tracker: Arc<AgentSetupTracker>,
    }

    #[async_trait]
    impl crate::driver::AgentDriver for AgentSetupAgentDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            let mut inner = super::tests_support::TinyAgentDriver;
            inner.initialize(params).await
        }

        async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
            super::tests_support::TinyAgentDriver
                .preflight(params)
                .await
        }

        async fn install_steps(
            &self,
            spec: agentenv_proto::AgentSpec,
        ) -> DriverResult<agentenv_proto::InstallStepsResult> {
            self.tracker
                .agent_spec_versions
                .lock()
                .expect("agent spec versions")
                .push(spec.version);
            Ok(agentenv_proto::InstallStepsResult {
                steps: vec![agentenv_proto::DockerfileFragment {
                    name: Some("install-agent".to_owned()),
                    content: "RUN printf agent-installed > /tmp/agent-installed".to_owned(),
                }],
            })
        }

        async fn mcp_config_path(
            &self,
            _params: agentenv_proto::McpConfigPathParams,
        ) -> DriverResult<agentenv_proto::McpConfigPathResult> {
            Ok(agentenv_proto::McpConfigPathResult {
                path: "~/.codex/config.toml".to_owned(),
            })
        }

        async fn render_mcp_config(
            &self,
            params: agentenv_proto::RenderMcpConfigParams,
        ) -> DriverResult<agentenv_proto::RenderMcpConfigResult> {
            self.tracker
                .mcp_config_endpoints
                .lock()
                .expect("mcp config endpoint tracker")
                .push(params.endpoints);
            Ok(agentenv_proto::RenderMcpConfigResult {
                content: "[mcp_servers.endpoint_0]\ncommand = \"agentenv-fs-mcp\"\n".to_owned(),
            })
        }

        async fn render_entrypoint(
            &self,
            _spec: agentenv_proto::AgentSpec,
        ) -> DriverResult<agentenv_proto::RenderEntrypointResult> {
            Ok(agentenv_proto::RenderEntrypointResult {
                content: "#!/usr/bin/env sh\nexec codex \"$@\"\n".to_owned(),
            })
        }

        async fn credential_requirements(
            &self,
            _spec: agentenv_proto::AgentSpec,
        ) -> DriverResult<agentenv_proto::CredentialRequirementsResult> {
            Ok(agentenv_proto::CredentialRequirementsResult {
                requirements: self
                    .tracker
                    .agent_credential_requirements
                    .lock()
                    .expect("agent credential requirements")
                    .clone(),
            })
        }

        async fn health_check_probe(
            &self,
            _spec: agentenv_proto::AgentSpec,
        ) -> DriverResult<agentenv_proto::AgentHealthCheckProbe> {
            Ok(agentenv_proto::AgentHealthCheckProbe {
                cmd: "agentenv-agent --version".to_owned(),
                tty: false,
                env: BTreeMap::new(),
                success_exit_codes: vec![0],
            })
        }

        async fn shutdown(
            &mut self,
            params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            let mut inner = super::tests_support::TinyAgentDriver;
            inner.shutdown(params).await
        }
    }

    struct AgentSetupSandboxDriver {
        tracker: Arc<AgentSetupTracker>,
        supports_hot_reload_policy: bool,
    }

    #[async_trait]
    impl SandboxDriver for AgentSetupSandboxDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            let mut inner = TinySandboxDriver;
            let mut result = inner.initialize(params).await?;
            if let Capabilities::Sandbox(capabilities) = &mut result.capabilities {
                capabilities.supports_hot_reload_policy = self.supports_hot_reload_policy;
                capabilities.supports_host_egress_proxy = self
                    .tracker
                    .supports_host_egress_proxy
                    .load(Ordering::SeqCst);
            }
            Ok(result)
        }

        async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
            TinySandboxDriver.preflight(params).await
        }

        async fn create(
            &self,
            spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            self.tracker
                .create_specs
                .lock()
                .expect("create spec tracker")
                .push(spec.clone());
            if spec.metadata.contains_key("byo_dockerfile") {
                let root = self
                    .tracker
                    .byo_digest_root
                    .lock()
                    .expect("digest root tracker")
                    .clone();
                let digest = self
                    .tracker
                    .byo_digest
                    .lock()
                    .expect("digest tracker")
                    .clone();
                if let (Some(root), Some(digest)) = (root, digest) {
                    let name = spec
                        .metadata
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("demo");
                    let path = root
                        .join("build")
                        .join(super::sanitize_byo_build_name(name))
                        .join("image-digest");
                    fs::create_dir_all(path.parent().expect("digest parent"))
                        .expect("create digest dir");
                    fs::write(path, format!("{digest}\n")).expect("write digest sidecar");
                }
            }
            if let Some(policy) = spec.policy.clone() {
                self.tracker
                    .create_policies
                    .lock()
                    .expect("create policy tracker")
                    .push(policy);
            }
            TinySandboxDriver.create(spec).await
        }

        async fn connect(
            &self,
            params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            TinySandboxDriver.connect(params).await
        }

        async fn exec(
            &self,
            params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            self.tracker
                .exec_cmds
                .lock()
                .expect("exec tracker")
                .push(params.cmd.clone());
            if params.cmd == "agentenv-agent --version" {
                let copied_paths = self.tracker.copied_paths.lock().expect("copy tracker");
                if !copied_paths.contains(&super::AGENT_ENTRYPOINT_PATH.to_owned())
                    && !self
                        .tracker
                        .preinstall_probe_succeeds
                        .load(Ordering::SeqCst)
                {
                    return Ok(agentenv_proto::ExecResult {
                        status: 127,
                        stdout: String::new(),
                        stderr: "agentenv-agent: not found".to_owned(),
                    });
                }
            }
            TinySandboxDriver.exec(params).await
        }

        async fn copy_in(&self, params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult> {
            self.tracker
                .copied_paths
                .lock()
                .expect("copy tracker")
                .push(params.dst_sandbox_path.clone());
            TinySandboxDriver.copy_in(params).await
        }

        async fn copy_out(
            &self,
            params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_out(params).await
        }

        async fn apply_policy(
            &self,
            params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            self.tracker
                .applied_policies
                .lock()
                .expect("apply policy tracker")
                .push(params.policy.clone());
            if !self.supports_hot_reload_policy {
                return Err(crate::driver::DriverError::CapabilityMissing {
                    capability: "supports_hot_reload_policy".to_owned(),
                });
            }
            TinySandboxDriver.apply_policy(params).await
        }

        async fn status(
            &self,
            params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            TinySandboxDriver.status(params).await
        }

        async fn logs(
            &self,
            params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            TinySandboxDriver.logs(params).await
        }

        async fn logs_stream(
            &self,
            params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.logs_stream(params).await
        }

        async fn stop(&self, params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.stop(params).await
        }

        async fn destroy(
            &self,
            params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.destroy(params).await
        }

        async fn shutdown(
            &mut self,
            params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            let mut inner = TinySandboxDriver;
            inner.shutdown(params).await
        }
    }

    #[derive(Default)]
    struct StreamTracker {
        logs_called: AtomicBool,
        logs_stream_called: AtomicBool,
    }

    struct StreamFactory {
        tracker: Arc<StreamTracker>,
    }

    impl DriverFactory for StreamFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(StreamTrackingSandboxDriver {
                    tracker: Arc::clone(&self.tracker),
                }),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    struct StreamTrackingSandboxDriver {
        tracker: Arc<StreamTracker>,
    }

    #[async_trait]
    impl SandboxDriver for StreamTrackingSandboxDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            let mut inner = TinySandboxDriver;
            inner.initialize(params).await
        }

        async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
            TinySandboxDriver.preflight(params).await
        }

        async fn create(
            &self,
            spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            TinySandboxDriver.create(spec).await
        }

        async fn connect(
            &self,
            params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            TinySandboxDriver.connect(params).await
        }

        async fn exec(
            &self,
            params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            TinySandboxDriver.exec(params).await
        }

        async fn copy_in(&self, params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_in(params).await
        }

        async fn copy_out(
            &self,
            params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_out(params).await
        }

        async fn apply_policy(
            &self,
            params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            TinySandboxDriver.apply_policy(params).await
        }

        async fn status(
            &self,
            params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            TinySandboxDriver.status(params).await
        }

        async fn logs(
            &self,
            _params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            self.tracker.logs_called.store(true, Ordering::SeqCst);
            Ok(agentenv_proto::LogsResult {
                entries: Vec::new(),
            })
        }

        async fn logs_stream(
            &self,
            _params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            self.tracker
                .logs_stream_called
                .store(true, Ordering::SeqCst);
            Ok(EmptyResult {})
        }

        async fn stop(&self, params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.stop(params).await
        }

        async fn destroy(
            &self,
            params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.destroy(params).await
        }

        async fn shutdown(
            &mut self,
            params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            let mut inner = TinySandboxDriver;
            inner.shutdown(params).await
        }
    }

    #[derive(Default)]
    struct TinyInferenceFactory;

    impl DriverFactory for TinyInferenceFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(TinySandboxDriver),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: Some(Box::new(TinyInferenceDriver)),
            })
        }
    }

    struct TinySandboxDriver;

    struct InitTrackingSandboxDriver {
        initialized: Arc<AtomicBool>,
    }

    struct DestroyTrackingSandboxDriver {
        destroyed: Arc<AtomicBool>,
    }

    struct KillTrackingUnsupportedSessionFactory {
        kill_called: Arc<AtomicBool>,
    }

    impl DriverFactory for KillTrackingUnsupportedSessionFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(KillTrackingUnsupportedSessionSandboxDriver {
                    kill_called: Arc::clone(&self.kill_called),
                }),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    struct KillTrackingUnsupportedSessionSandboxDriver {
        kill_called: Arc<AtomicBool>,
    }

    #[derive(Default)]
    struct ForkCalls {
        snapshot_handle: Option<String>,
        snapshot_name: Option<String>,
        fork_snapshot_id: Option<String>,
        fork_name: Option<String>,
    }

    struct ForkingSandboxDriver {
        calls: Arc<Mutex<ForkCalls>>,
        supports_snapshots: bool,
        supports_fork: bool,
    }

    struct ForkingFactory {
        calls: Arc<Mutex<ForkCalls>>,
        supports_snapshots: bool,
        supports_fork: bool,
    }

    impl DriverFactory for ForkingFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(ForkingSandboxDriver {
                    calls: Arc::clone(&self.calls),
                    supports_snapshots: self.supports_snapshots,
                    supports_fork: self.supports_fork,
                }),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    #[async_trait]
    impl SandboxDriver for TinySandboxDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            assert_eq!(params.schema_version, SCHEMA_VERSION);
            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "openshell".to_owned(),
                    kind: DriverKind::Sandbox,
                    version: "0.0.1-alpha0".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: Capabilities::Sandbox(SandboxCapabilities {
                    supports_hot_reload_policy: true,
                    supports_filesystem_lockdown: true,
                    supports_syscall_filter: true,
                    supports_native_inference_routing: true,
                    supports_remote_host: false,
                    supports_host_egress_proxy: false,
                    supports_persistent_sessions: false,
                    supports_dns_egress_control: false,
                    supports_snapshots: false,
                    supports_fork: false,
                }),
            })
        }

        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }

        async fn create(
            &self,
            _spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            Ok(agentenv_proto::SandboxHandle {
                handle: "sb-1".to_owned(),
            })
        }

        async fn connect(
            &self,
            _params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            Ok(agentenv_proto::ShellHandle {
                session_id: "sh-1".to_owned(),
                tty: true,
                working_dir: None,
            })
        }

        async fn exec(
            &self,
            _params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            Ok(agentenv_proto::ExecResult {
                status: 0,
                stdout: "ok\n".to_owned(),
                stderr: String::new(),
            })
        }

        async fn copy_in(
            &self,
            _params: agentenv_proto::CopyInParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn copy_out(
            &self,
            _params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn apply_policy(
            &self,
            _params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            Ok(agentenv_proto::ApplyPolicyResult { hot_reloaded: true })
        }
        async fn status(
            &self,
            _params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            Ok(agentenv_proto::SandboxStatus {
                phase: agentenv_proto::SandboxPhase::Running,
                healthy: true,
                last_ping: Some("2026-04-21T00:00:00Z".to_owned()),
            })
        }
        async fn logs(
            &self,
            _params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            Ok(agentenv_proto::LogsResult {
                entries: Vec::new(),
            })
        }
        async fn logs_stream(
            &self,
            _params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn stop(&self, _params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn destroy(
            &self,
            _params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn shutdown(
            &mut self,
            _params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
    }

    #[async_trait]
    impl SandboxDriver for ForkingSandboxDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            assert_eq!(params.schema_version, SCHEMA_VERSION);
            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "microvm".to_owned(),
                    kind: DriverKind::Sandbox,
                    version: "0.0.1-alpha0".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: Capabilities::Sandbox(SandboxCapabilities {
                    supports_hot_reload_policy: false,
                    supports_filesystem_lockdown: true,
                    supports_syscall_filter: true,
                    supports_native_inference_routing: false,
                    supports_remote_host: false,
                    supports_host_egress_proxy: false,
                    supports_persistent_sessions: false,
                    supports_dns_egress_control: false,
                    supports_snapshots: self.supports_snapshots,
                    supports_fork: self.supports_fork,
                }),
            })
        }

        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }

        async fn create(
            &self,
            _spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            unreachable!("fork_env should not cold-create a sandbox")
        }

        async fn snapshot(
            &self,
            params: agentenv_proto::SnapshotParams,
        ) -> DriverResult<agentenv_proto::SnapshotId> {
            let mut calls = self.calls.lock().unwrap();
            calls.snapshot_handle = Some(params.handle);
            calls.snapshot_name = params.name;
            Ok(agentenv_proto::SnapshotId {
                id: "microvm-snapshot://demo/base".to_owned(),
            })
        }

        async fn fork_from_snapshot(
            &self,
            params: agentenv_proto::ForkFromSnapshotParams,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            let mut calls = self.calls.lock().unwrap();
            calls.fork_snapshot_id = Some(params.snapshot.id);
            calls.fork_name = Some(params.spec.name);
            Ok(agentenv_proto::SandboxHandle {
                handle: "microvm://firecracker/experiment".to_owned(),
            })
        }

        async fn connect(
            &self,
            _params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            unreachable!("fork_env should not connect")
        }

        async fn exec(
            &self,
            _params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            unreachable!("fork_env should not exec")
        }

        async fn copy_in(
            &self,
            _params: agentenv_proto::CopyInParams,
        ) -> DriverResult<EmptyResult> {
            unreachable!("fork_env should not copy into the sandbox")
        }

        async fn copy_out(
            &self,
            _params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            unreachable!("fork_env should not copy out of the sandbox")
        }

        async fn apply_policy(
            &self,
            _params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            unreachable!("fork_env should not apply policy")
        }

        async fn status(
            &self,
            _params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            Ok(agentenv_proto::SandboxStatus {
                phase: agentenv_proto::SandboxPhase::Running,
                healthy: true,
                last_ping: None,
            })
        }

        async fn logs(
            &self,
            _params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            Ok(agentenv_proto::LogsResult {
                entries: Vec::new(),
            })
        }

        async fn logs_stream(
            &self,
            _params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn stop(&self, _params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn destroy(
            &self,
            _params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn shutdown(
            &mut self,
            _params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
    }

    #[async_trait]
    impl SandboxDriver for InitTrackingSandboxDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            self.initialized.store(true, Ordering::SeqCst);
            let mut inner = TinySandboxDriver;
            inner.initialize(params).await
        }

        async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
            TinySandboxDriver.preflight(params).await
        }

        async fn create(
            &self,
            spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            TinySandboxDriver.create(spec).await
        }

        async fn connect(
            &self,
            params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            TinySandboxDriver.connect(params).await
        }

        async fn exec(
            &self,
            params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            TinySandboxDriver.exec(params).await
        }

        async fn copy_in(&self, params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_in(params).await
        }

        async fn copy_out(
            &self,
            params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_out(params).await
        }

        async fn apply_policy(
            &self,
            params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            TinySandboxDriver.apply_policy(params).await
        }

        async fn status(
            &self,
            params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            TinySandboxDriver.status(params).await
        }

        async fn logs(
            &self,
            params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            TinySandboxDriver.logs(params).await
        }

        async fn logs_stream(
            &self,
            params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.logs_stream(params).await
        }

        async fn stop(&self, params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.stop(params).await
        }

        async fn destroy(
            &self,
            params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.destroy(params).await
        }

        async fn shutdown(
            &mut self,
            params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            let mut inner = TinySandboxDriver;
            inner.shutdown(params).await
        }
    }

    #[async_trait]
    impl SandboxDriver for DestroyTrackingSandboxDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            let mut inner = TinySandboxDriver;
            inner.initialize(params).await
        }

        async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
            TinySandboxDriver.preflight(params).await
        }

        async fn create(
            &self,
            spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            TinySandboxDriver.create(spec).await
        }

        async fn connect(
            &self,
            params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            TinySandboxDriver.connect(params).await
        }

        async fn exec(
            &self,
            params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            TinySandboxDriver.exec(params).await
        }

        async fn copy_in(&self, params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_in(params).await
        }

        async fn copy_out(
            &self,
            params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_out(params).await
        }

        async fn apply_policy(
            &self,
            params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            TinySandboxDriver.apply_policy(params).await
        }

        async fn status(
            &self,
            params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            TinySandboxDriver.status(params).await
        }

        async fn logs(
            &self,
            params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            TinySandboxDriver.logs(params).await
        }

        async fn logs_stream(
            &self,
            params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.logs_stream(params).await
        }

        async fn stop(&self, params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.stop(params).await
        }

        async fn destroy(
            &self,
            params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            self.destroyed.store(true, Ordering::SeqCst);
            TinySandboxDriver.destroy(params).await
        }

        async fn shutdown(
            &mut self,
            params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            let mut inner = TinySandboxDriver;
            inner.shutdown(params).await
        }
    }

    #[async_trait]
    impl SandboxDriver for KillTrackingUnsupportedSessionSandboxDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            let mut inner = TinySandboxDriver;
            inner.initialize(params).await
        }

        async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
            TinySandboxDriver.preflight(params).await
        }

        async fn create(
            &self,
            spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            TinySandboxDriver.create(spec).await
        }

        async fn connect(
            &self,
            params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            TinySandboxDriver.connect(params).await
        }

        async fn kill_session(
            &self,
            _params: agentenv_proto::KillSessionParams,
        ) -> DriverResult<EmptyResult> {
            self.kill_called.store(true, Ordering::SeqCst);
            Err(crate::driver::persistent_sessions_missing())
        }

        async fn exec(
            &self,
            params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            TinySandboxDriver.exec(params).await
        }

        async fn copy_in(&self, params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_in(params).await
        }

        async fn copy_out(
            &self,
            params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_out(params).await
        }

        async fn apply_policy(
            &self,
            params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            TinySandboxDriver.apply_policy(params).await
        }

        async fn status(
            &self,
            params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            TinySandboxDriver.status(params).await
        }

        async fn logs(
            &self,
            params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            TinySandboxDriver.logs(params).await
        }

        async fn logs_stream(
            &self,
            params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.logs_stream(params).await
        }

        async fn stop(&self, params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.stop(params).await
        }

        async fn destroy(
            &self,
            params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.destroy(params).await
        }

        async fn shutdown(
            &mut self,
            params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            let mut inner = TinySandboxDriver;
            inner.shutdown(params).await
        }
    }

    struct ObservingSandboxDriver {
        root: std::path::PathBuf,
        observed_final_dir_exists: Arc<AtomicBool>,
    }

    #[async_trait]
    impl SandboxDriver for ObservingSandboxDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            assert_eq!(params.schema_version, SCHEMA_VERSION);
            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "openshell".to_owned(),
                    kind: DriverKind::Sandbox,
                    version: "0.0.1-alpha0".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: Capabilities::Sandbox(SandboxCapabilities {
                    supports_hot_reload_policy: true,
                    supports_filesystem_lockdown: true,
                    supports_syscall_filter: true,
                    supports_native_inference_routing: true,
                    supports_remote_host: false,
                    supports_host_egress_proxy: false,
                    supports_persistent_sessions: false,
                    supports_dns_egress_control: false,
                    supports_snapshots: false,
                    supports_fork: false,
                }),
            })
        }

        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }

        async fn create(
            &self,
            _spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            let final_env_dir = self.root.join("envs").join("demo");
            self.observed_final_dir_exists
                .store(final_env_dir.exists(), Ordering::SeqCst);
            Ok(agentenv_proto::SandboxHandle {
                handle: "sb-1".to_owned(),
            })
        }

        async fn connect(
            &self,
            _params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            Ok(agentenv_proto::ShellHandle {
                session_id: "sh-1".to_owned(),
                tty: true,
                working_dir: None,
            })
        }

        async fn exec(
            &self,
            _params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            Ok(agentenv_proto::ExecResult {
                status: 0,
                stdout: "ok\n".to_owned(),
                stderr: String::new(),
            })
        }

        async fn copy_in(
            &self,
            _params: agentenv_proto::CopyInParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn copy_out(
            &self,
            _params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn apply_policy(
            &self,
            _params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            Ok(agentenv_proto::ApplyPolicyResult { hot_reloaded: true })
        }

        async fn status(
            &self,
            _params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            Ok(agentenv_proto::SandboxStatus {
                phase: agentenv_proto::SandboxPhase::Running,
                healthy: true,
                last_ping: Some("2026-04-21T00:00:00Z".to_owned()),
            })
        }

        async fn logs(
            &self,
            _params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            Ok(agentenv_proto::LogsResult {
                entries: Vec::new(),
            })
        }

        async fn logs_stream(
            &self,
            _params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn stop(&self, _params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn destroy(
            &self,
            _params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn shutdown(
            &mut self,
            _params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
    }

    struct ObservingFactory {
        root: std::path::PathBuf,
        observed_final_dir_exists: Arc<AtomicBool>,
    }

    impl DriverFactory for ObservingFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(ObservingSandboxDriver {
                    root: self.root.clone(),
                    observed_final_dir_exists: Arc::clone(&self.observed_final_dir_exists),
                }),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    struct TinyContextDriver;

    #[async_trait]
    impl ContextDriver for TinyContextDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            assert_eq!(params.schema_version, SCHEMA_VERSION);
            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "filesystem".to_owned(),
                    kind: DriverKind::Context,
                    version: "0.0.1-alpha0".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: Capabilities::Context(ContextCapabilities {
                    is_remote: false,
                    is_shared: false,
                    supports_zones: false,
                    supports_snapshots: false,
                }),
            })
        }
        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }
        async fn provision(
            &self,
            _spec: agentenv_proto::ContextSpec,
        ) -> DriverResult<agentenv_proto::ContextHandle> {
            Ok(agentenv_proto::ContextHandle {
                handle: "ctx-1".to_owned(),
            })
        }
        async fn mcp_endpoint(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::McpEndpoint> {
            Ok(agentenv_proto::McpEndpoint {
                url: "agentenv-fs-mcp".to_owned(),
                transport: agentenv_proto::McpTransport::Stdio,
                headers: BTreeMap::new(),
            })
        }
        async fn required_network_rules(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::RequiredNetworkRulesResult> {
            Ok(agentenv_proto::RequiredNetworkRulesResult { rules: Vec::new() })
        }
        async fn credential_requirements(
            &self,
            _params: agentenv_proto::CredentialRequirementsParams,
        ) -> DriverResult<agentenv_proto::CredentialRequirementsResult> {
            Ok(agentenv_proto::CredentialRequirementsResult {
                requirements: Vec::new(),
            })
        }
        async fn status(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::ContextStatus> {
            Ok(agentenv_proto::ContextStatus {
                healthy: true,
                detail: None,
            })
        }
        async fn teardown(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn shutdown(
            &mut self,
            _params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
    }

    struct FailingTeardownContextDriver;

    #[async_trait]
    impl ContextDriver for FailingTeardownContextDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            let mut inner = TinyContextDriver;
            inner.initialize(params).await
        }

        async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
            TinyContextDriver.preflight(params).await
        }

        async fn provision(
            &self,
            spec: agentenv_proto::ContextSpec,
        ) -> DriverResult<agentenv_proto::ContextHandle> {
            TinyContextDriver.provision(spec).await
        }

        async fn mcp_endpoint(
            &self,
            params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::McpEndpoint> {
            TinyContextDriver.mcp_endpoint(params).await
        }

        async fn required_network_rules(
            &self,
            params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::RequiredNetworkRulesResult> {
            TinyContextDriver.required_network_rules(params).await
        }

        async fn credential_requirements(
            &self,
            params: agentenv_proto::CredentialRequirementsParams,
        ) -> DriverResult<agentenv_proto::CredentialRequirementsResult> {
            TinyContextDriver.credential_requirements(params).await
        }

        async fn status(
            &self,
            params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::ContextStatus> {
            TinyContextDriver.status(params).await
        }

        async fn teardown(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<EmptyResult> {
            Err(crate::driver::DriverError::CleanupFailed {
                message: "context teardown failed".to_owned(),
            })
        }

        async fn shutdown(
            &mut self,
            params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            let mut inner = TinyContextDriver;
            inner.shutdown(params).await
        }
    }

    struct FailingProvisionContextDriver;

    #[async_trait]
    impl ContextDriver for FailingProvisionContextDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            let mut inner = TinyContextDriver;
            inner.initialize(params).await
        }

        async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
            TinyContextDriver.preflight(params).await
        }

        async fn provision(
            &self,
            _spec: agentenv_proto::ContextSpec,
        ) -> DriverResult<agentenv_proto::ContextHandle> {
            Err(crate::driver::DriverError::CleanupFailed {
                message: "context provision failed".to_owned(),
            })
        }

        async fn mcp_endpoint(
            &self,
            params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::McpEndpoint> {
            TinyContextDriver.mcp_endpoint(params).await
        }

        async fn required_network_rules(
            &self,
            params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::RequiredNetworkRulesResult> {
            TinyContextDriver.required_network_rules(params).await
        }

        async fn credential_requirements(
            &self,
            params: agentenv_proto::CredentialRequirementsParams,
        ) -> DriverResult<agentenv_proto::CredentialRequirementsResult> {
            TinyContextDriver.credential_requirements(params).await
        }

        async fn status(
            &self,
            params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::ContextStatus> {
            TinyContextDriver.status(params).await
        }

        async fn teardown(
            &self,
            params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<EmptyResult> {
            TinyContextDriver.teardown(params).await
        }

        async fn shutdown(
            &mut self,
            params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            let mut inner = TinyContextDriver;
            inner.shutdown(params).await
        }
    }

    struct TinyInferenceDriver;

    #[async_trait]
    impl InferenceDriver for TinyInferenceDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            assert_eq!(params.schema_version, SCHEMA_VERSION);
            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "passthrough".to_owned(),
                    kind: DriverKind::Inference,
                    version: "0.0.1-alpha0".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: Capabilities::Inference(InferenceCapabilities {
                    strips_caller_credentials: true,
                    supports_model_switching: false,
                }),
            })
        }

        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }

        async fn provision(
            &self,
            _spec: agentenv_proto::InferenceSpec,
        ) -> DriverResult<agentenv_proto::InferenceHandle> {
            Ok(agentenv_proto::InferenceHandle {
                handle: "inf-1".to_owned(),
            })
        }

        async fn endpoint_in_sandbox(
            &self,
            _params: agentenv_proto::InferenceHandleRequest,
        ) -> DriverResult<agentenv_proto::EndpointInSandboxResult> {
            Ok(agentenv_proto::EndpointInSandboxResult {
                url: "http://inference.local".to_owned(),
            })
        }

        async fn credential_requirements(
            &self,
            _params: agentenv_proto::CredentialRequirementsParams,
        ) -> DriverResult<agentenv_proto::CredentialRequirementsResult> {
            Ok(agentenv_proto::CredentialRequirementsResult {
                requirements: Vec::new(),
            })
        }

        async fn teardown(
            &self,
            _params: agentenv_proto::InferenceHandleRequest,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn shutdown(
            &mut self,
            _params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
    }

    #[derive(Default)]
    struct RollbackTracker {
        context_teardown_called: AtomicBool,
        inference_teardown_called: AtomicBool,
        sandbox_destroy_called: AtomicBool,
    }

    struct RollbackFactory {
        tracker: Arc<RollbackTracker>,
    }

    impl DriverFactory for RollbackFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(FailingCreateSandboxDriver {
                    tracker: Arc::clone(&self.tracker),
                }),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TrackingContextDriver {
                    tracker: Arc::clone(&self.tracker),
                }),
                inference: Some(Box::new(TrackingInferenceDriver {
                    tracker: Arc::clone(&self.tracker),
                })),
            })
        }
    }

    struct FailingCreateSandboxDriver {
        tracker: Arc<RollbackTracker>,
    }

    #[async_trait]
    impl SandboxDriver for FailingCreateSandboxDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            assert_eq!(params.schema_version, SCHEMA_VERSION);
            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "openshell".to_owned(),
                    kind: DriverKind::Sandbox,
                    version: "0.0.1-alpha0".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: Capabilities::Sandbox(SandboxCapabilities {
                    supports_hot_reload_policy: true,
                    supports_filesystem_lockdown: true,
                    supports_syscall_filter: true,
                    supports_native_inference_routing: true,
                    supports_remote_host: false,
                    supports_host_egress_proxy: false,
                    supports_persistent_sessions: false,
                    supports_dns_egress_control: false,
                    supports_snapshots: false,
                    supports_fork: false,
                }),
            })
        }

        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }

        async fn create(
            &self,
            _spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            let _ = &self.tracker;
            Err(crate::driver::DriverError::InvalidInput {
                message: "sandbox create failed".to_owned(),
            })
        }

        async fn connect(
            &self,
            _params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            Ok(agentenv_proto::ShellHandle {
                session_id: "sh-1".to_owned(),
                tty: true,
                working_dir: None,
            })
        }

        async fn exec(
            &self,
            _params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            Ok(agentenv_proto::ExecResult {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }

        async fn copy_in(
            &self,
            _params: agentenv_proto::CopyInParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn copy_out(
            &self,
            _params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn apply_policy(
            &self,
            _params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            Ok(agentenv_proto::ApplyPolicyResult { hot_reloaded: true })
        }

        async fn status(
            &self,
            _params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            Ok(agentenv_proto::SandboxStatus {
                phase: agentenv_proto::SandboxPhase::Running,
                healthy: true,
                last_ping: None,
            })
        }

        async fn logs(
            &self,
            _params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            Ok(agentenv_proto::LogsResult {
                entries: Vec::new(),
            })
        }

        async fn logs_stream(
            &self,
            _params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn stop(&self, _params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn destroy(
            &self,
            _params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            self.tracker
                .sandbox_destroy_called
                .store(true, Ordering::SeqCst);
            Ok(EmptyResult {})
        }

        async fn shutdown(
            &mut self,
            _params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
    }

    struct TrackingContextDriver {
        tracker: Arc<RollbackTracker>,
    }

    #[async_trait]
    impl ContextDriver for TrackingContextDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            assert_eq!(params.schema_version, SCHEMA_VERSION);
            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "filesystem".to_owned(),
                    kind: DriverKind::Context,
                    version: "0.0.1-alpha0".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: Capabilities::Context(ContextCapabilities {
                    is_remote: false,
                    is_shared: false,
                    supports_zones: false,
                    supports_snapshots: false,
                }),
            })
        }

        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }

        async fn provision(
            &self,
            _spec: agentenv_proto::ContextSpec,
        ) -> DriverResult<agentenv_proto::ContextHandle> {
            Ok(agentenv_proto::ContextHandle {
                handle: "ctx-1".to_owned(),
            })
        }

        async fn mcp_endpoint(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::McpEndpoint> {
            Ok(agentenv_proto::McpEndpoint {
                url: "agentenv-fs-mcp".to_owned(),
                transport: agentenv_proto::McpTransport::Stdio,
                headers: BTreeMap::new(),
            })
        }

        async fn required_network_rules(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::RequiredNetworkRulesResult> {
            Ok(agentenv_proto::RequiredNetworkRulesResult { rules: Vec::new() })
        }

        async fn credential_requirements(
            &self,
            _params: agentenv_proto::CredentialRequirementsParams,
        ) -> DriverResult<agentenv_proto::CredentialRequirementsResult> {
            Ok(agentenv_proto::CredentialRequirementsResult {
                requirements: Vec::new(),
            })
        }

        async fn status(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::ContextStatus> {
            Ok(agentenv_proto::ContextStatus {
                healthy: true,
                detail: None,
            })
        }

        async fn teardown(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<EmptyResult> {
            self.tracker
                .context_teardown_called
                .store(true, Ordering::SeqCst);
            Ok(EmptyResult {})
        }

        async fn shutdown(
            &mut self,
            _params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
    }

    struct TrackingInferenceDriver {
        tracker: Arc<RollbackTracker>,
    }

    #[async_trait]
    impl InferenceDriver for TrackingInferenceDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            assert_eq!(params.schema_version, SCHEMA_VERSION);
            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "passthrough".to_owned(),
                    kind: DriverKind::Inference,
                    version: "0.0.1-alpha0".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: Capabilities::Inference(InferenceCapabilities {
                    strips_caller_credentials: true,
                    supports_model_switching: false,
                }),
            })
        }

        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }

        async fn provision(
            &self,
            _spec: agentenv_proto::InferenceSpec,
        ) -> DriverResult<agentenv_proto::InferenceHandle> {
            Ok(agentenv_proto::InferenceHandle {
                handle: "inf-1".to_owned(),
            })
        }

        async fn endpoint_in_sandbox(
            &self,
            _params: agentenv_proto::InferenceHandleRequest,
        ) -> DriverResult<agentenv_proto::EndpointInSandboxResult> {
            Ok(agentenv_proto::EndpointInSandboxResult {
                url: "http://inference.local".to_owned(),
            })
        }

        async fn credential_requirements(
            &self,
            _params: agentenv_proto::CredentialRequirementsParams,
        ) -> DriverResult<agentenv_proto::CredentialRequirementsResult> {
            Ok(agentenv_proto::CredentialRequirementsResult {
                requirements: Vec::new(),
            })
        }

        async fn teardown(
            &self,
            _params: agentenv_proto::InferenceHandleRequest,
        ) -> DriverResult<EmptyResult> {
            self.tracker
                .inference_teardown_called
                .store(true, Ordering::SeqCst);
            Ok(EmptyResult {})
        }

        async fn shutdown(
            &mut self,
            _params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
    }

    #[tokio::test]
    async fn initialize_helpers_use_current_protocol() {
        let mut sandbox = TinySandboxDriver;
        let mut context = TinyContextDriver;
        let options = RuntimeOptions {
            root: std::env::temp_dir(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };

        let sandbox_info = initialize_sandbox_driver(&options, &mut sandbox)
            .await
            .unwrap();
        let context_info = initialize_context_driver(&options, &mut context)
            .await
            .unwrap();

        assert_eq!(sandbox_info.driver.name, "openshell");
        assert_eq!(context_info.driver.name, "filesystem");
    }

    #[tokio::test]
    async fn preflight_only_returns_per_driver_checks() {
        let options = RuntimeOptions {
            root: std::env::temp_dir(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let selection = super::DriverSelection {
            sandbox: "openshell".to_owned(),
            agent: "codex".to_owned(),
            context: "filesystem".to_owned(),
            inference: None,
        };

        let report = super::run_preflight_only(&options, &TinyFactory, "demo", &selection)
            .await
            .unwrap();

        assert_eq!(report.status, crate::admission::AdmissionStatus::Accepted);
        assert_eq!(report.checks.len(), 3);
        assert_eq!(report.checks[0].kind, DriverKind::Sandbox);
        assert_eq!(report.checks[1].kind, DriverKind::Agent);
        assert_eq!(report.checks[2].kind, DriverKind::Context);
    }

    #[tokio::test]
    async fn preflight_only_reports_selected_driver_names() {
        let options = RuntimeOptions {
            root: std::env::temp_dir(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let selection = super::DriverSelection {
            sandbox: "sandbox-openshell".to_owned(),
            agent: "agent-codex".to_owned(),
            context: "context-filesystem".to_owned(),
            inference: None,
        };

        let report = super::run_preflight_only(&options, &TinyFactory, "demo", &selection)
            .await
            .unwrap();

        let drivers = report
            .checks
            .iter()
            .map(|check| check.driver.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            drivers,
            ["sandbox-openshell", "agent-codex", "context-filesystem"]
        );
    }

    #[tokio::test]
    async fn preflight_only_errors_when_requested_inference_driver_missing() {
        let options = RuntimeOptions {
            root: std::env::temp_dir(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let selection = super::DriverSelection {
            sandbox: "openshell".to_owned(),
            agent: "codex".to_owned(),
            context: "filesystem".to_owned(),
            inference: Some("passthrough".to_owned()),
        };

        let err = super::run_preflight_only(&options, &TinyFactory, "demo", &selection)
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("missing selected inference driver `passthrough`"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn preflight_only_includes_selected_inference_driver_name() {
        let options = RuntimeOptions {
            root: std::env::temp_dir(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let selection = super::DriverSelection {
            sandbox: "openshell".to_owned(),
            agent: "codex".to_owned(),
            context: "filesystem".to_owned(),
            inference: Some("inference-passthrough".to_owned()),
        };

        let report = super::run_preflight_only(&options, &TinyInferenceFactory, "demo", &selection)
            .await
            .unwrap();

        assert_eq!(report.status, crate::admission::AdmissionStatus::Accepted);
        assert_eq!(report.checks.len(), 4);
        assert_eq!(report.checks[3].kind, DriverKind::Inference);
        assert_eq!(report.checks[3].driver, "inference-passthrough");
    }

    #[tokio::test]
    async fn create_env_writes_registry_files() {
        let root = unique_root("agentenv-create");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
inference:
  driver: passthrough
policy:
  tier: restricted
  presets: []
"#;
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let result = super::create_env(
            &options,
            &TinyInferenceFactory,
            &mut credentials,
            "demo",
            yaml,
        )
        .await
        .unwrap();

        assert_eq!(
            result.admission.status,
            crate::admission::AdmissionStatus::Accepted
        );
        assert_eq!(result.state.name, "demo");
        assert_eq!(result.state.handles.sandbox.as_deref(), Some("sb-1"));

        let env_dir = root.join("envs").join("demo");
        assert!(env_dir.join("blueprint.yaml").is_file());
        assert!(env_dir.join("lock.yaml").is_file());
        assert!(env_dir.join("state.json").is_file());
        assert!(env_dir.join("events.jsonl").is_file());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn create_env_with_brokered_openai_omits_real_secret_from_sandbox_env() {
        let root = unique_root("agentenv-create-brokered-openai");
        let _proxy_bin_guard = fake_egress_proxy_bin(&root);
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        tracker
            .supports_host_egress_proxy
            .store(true, Ordering::SeqCst);
        *tracker
            .agent_credential_requirements
            .lock()
            .expect("agent credential requirements") =
            vec![required_runtime_credential("OPENAI_API_KEY")];
        let factory = AgentSetupFactory {
            tracker: Arc::clone(&tracker),
        };
        let mut credentials =
            ResolvingCredentialProvider::with_value("OPENAI_API_KEY", "sk-real-provider-secret");
        let events = RecordingEventEmitter::default();

        let result = super::create_env_observed(
            &options,
            &factory,
            &mut credentials,
            "demo",
            yaml,
            Arc::new(events.clone()),
        )
        .await
        .expect("brokered OpenAI credential should create env");

        let specs = tracker.create_specs.lock().expect("create spec tracker");
        assert_eq!(specs.len(), 1);
        let sandbox_env = &specs[0].env;
        assert_eq!(
            sandbox_env.get("OPENAI_API_KEY").map(String::as_str),
            Some("agentenv-brokered")
        );
        assert!(
            sandbox_env
                .get("OPENAI_BASE_URL")
                .is_some_and(|url| url.ends_with("/v1/openai")),
            "sandbox env should point OpenAI clients at the host egress proxy"
        );
        assert!(
            !sandbox_env
                .values()
                .any(|value| value.contains("sk-real-provider-secret")),
            "real provider secret must not enter the sandbox env"
        );
        assert!(
            credentials
                .resolved
                .iter()
                .all(|requirement| requirement.name != "OPENAI_API_KEY"),
            "brokered credentials must not be resolved during env create"
        );
        assert!(result
            .state
            .credential_names
            .contains(&"OPENAI_API_KEY".to_owned()));

        let credential_event = events
            .recorded()
            .into_iter()
            .find(|event| {
                event.kind == ActivityKind::CredentialInjected
                    && event.subject.get("name") == Some(&serde_json::json!("OPENAI_API_KEY"))
            })
            .expect("brokered credential injection event should be emitted");
        assert_eq!(
            credential_event.subject.get("delivery"),
            Some(&serde_json::json!("egress_proxy"))
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn create_env_resolves_unmatched_required_credential_but_not_brokered_openai() {
        let root = unique_root("agentenv-create-brokered-and-unmatched");
        let _proxy_bin_guard = fake_egress_proxy_bin(&root);
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        tracker
            .supports_host_egress_proxy
            .store(true, Ordering::SeqCst);
        *tracker
            .agent_credential_requirements
            .lock()
            .expect("agent credential requirements") = vec![
            required_runtime_credential("OPENAI_API_KEY"),
            required_runtime_credential("CUSTOM_TOKEN"),
        ];
        let factory = AgentSetupFactory {
            tracker: Arc::clone(&tracker),
        };
        let mut credentials = ResolvingCredentialProvider {
            values: BTreeMap::from([
                (
                    "OPENAI_API_KEY".to_owned(),
                    "sk-real-provider-secret".to_owned(),
                ),
                ("CUSTOM_TOKEN".to_owned(), "custom-secret".to_owned()),
            ]),
            resolved: Vec::new(),
        };

        super::create_env(&options, &factory, &mut credentials, "demo", yaml)
            .await
            .expect("unmatched credential should still be injected");

        let resolved_names = credentials
            .resolved
            .iter()
            .map(|requirement| requirement.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(resolved_names, vec!["CUSTOM_TOKEN"]);
        let specs = tracker.create_specs.lock().expect("create spec tracker");
        let sandbox_env = &specs[0].env;
        assert_eq!(
            sandbox_env.get("OPENAI_API_KEY").map(String::as_str),
            Some("agentenv-brokered")
        );
        assert_eq!(
            sandbox_env.get("CUSTOM_TOKEN").map(String::as_str),
            Some("custom-secret")
        );
        assert!(
            !sandbox_env
                .values()
                .any(|value| value.contains("sk-real-provider-secret")),
            "brokered provider secret must not enter the sandbox env"
        );
    }

    #[tokio::test]
    async fn create_env_without_proxy_capability_injects_provider_credential_when_not_required() {
        let root = unique_root("agentenv-create-proxy-unsupported-legacy-openai");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        *tracker
            .agent_credential_requirements
            .lock()
            .expect("agent credential requirements") =
            vec![required_runtime_credential("OPENAI_API_KEY")];
        let factory = AgentSetupFactory {
            tracker: Arc::clone(&tracker),
        };
        let mut credentials =
            ResolvingCredentialProvider::with_value("OPENAI_API_KEY", "sk-real-provider-secret");

        super::create_env(&options, &factory, &mut credentials, "demo", yaml)
            .await
            .expect(
                "provider credential should use legacy env injection when broker is not required",
            );

        let resolved_names = credentials
            .resolved
            .iter()
            .map(|requirement| requirement.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(resolved_names, vec!["OPENAI_API_KEY"]);
        let specs = tracker.create_specs.lock().expect("create spec tracker");
        assert_eq!(
            specs[0].env.get("OPENAI_API_KEY").map(String::as_str),
            Some("sk-real-provider-secret")
        );
        assert!(!specs[0].env.contains_key("OPENAI_BASE_URL"));
    }

    #[tokio::test]
    async fn create_env_fails_closed_when_proxy_required_but_sandbox_lacks_capability() {
        let root = unique_root("agentenv-create-proxy-capability-missing");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
  egress_proxy:
    github: true
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        *tracker
            .agent_credential_requirements
            .lock()
            .expect("agent credential requirements") =
            vec![required_runtime_credential("GITHUB_TOKEN")];
        let factory = AgentSetupFactory {
            tracker: Arc::clone(&tracker),
        };
        let mut credentials =
            ResolvingCredentialProvider::with_value("GITHUB_TOKEN", "ghp-real-provider-secret");

        let err = super::create_env(&options, &factory, &mut credentials, "demo", yaml)
            .await
            .expect_err("brokered route must require host egress proxy support");

        assert!(matches!(
            err,
            RuntimeError::HostEgressProxyUnsupported { ref service, ref driver }
                if service == "github" && driver == "openshell"
        ));
        assert_eq!(
            super::runtime_error_reason_code(&err),
            crate::admission::ReasonCode::CapabilityMissing.as_str()
        );
        assert!(
            tracker
                .create_specs
                .lock()
                .expect("create spec tracker")
                .is_empty(),
            "sandbox must not be created when host egress proxy support is missing"
        );
        assert!(
            credentials.resolved.is_empty(),
            "brokered credential should not be resolved before the fail-closed check"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn create_env_starts_proxy_and_persists_egress_proxy_state() {
        let root = unique_root("agentenv-create-starts-egress-proxy");
        let _proxy_bin_guard = fake_egress_proxy_bin(&root);
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        tracker
            .supports_host_egress_proxy
            .store(true, Ordering::SeqCst);
        *tracker
            .agent_credential_requirements
            .lock()
            .expect("agent credential requirements") =
            vec![required_runtime_credential("OPENAI_API_KEY")];
        let factory = AgentSetupFactory {
            tracker: Arc::clone(&tracker),
        };
        let mut credentials =
            ResolvingCredentialProvider::with_value("OPENAI_API_KEY", "sk-real-provider-secret");

        let result = super::create_env(&options, &factory, &mut credentials, "demo", yaml)
            .await
            .expect("brokered env should start proxy");

        let proxy = result
            .state
            .egress_proxy
            .as_ref()
            .expect("egress proxy state should be persisted");
        assert!(proxy.pid.is_some_and(|pid| pid > 0));
        assert_ne!(proxy.listen_url.port(), Some(0));
        assert_eq!(proxy.routes, vec!["openai".to_owned()]);
        assert_eq!(
            proxy.config_path,
            root.join("envs")
                .join("demo")
                .join("egress-proxy")
                .join("config.json")
        );
        assert!(proxy.config_path.is_file());
        assert!(proxy.policy_path.is_file());
        let openai_base_url = {
            let specs = tracker.create_specs.lock().expect("create spec tracker");
            specs[0]
                .env
                .get("OPENAI_BASE_URL")
                .expect("OpenAI base URL should be injected")
                .clone()
        };
        assert!(!openai_base_url.contains(":0/"));

        if let Some(pid) = proxy.pid {
            let _ = crate::egress_proxy::stop_egress_proxy_pid(pid).await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn create_env_rewrites_http_context_mcp_endpoint_when_mcp_token_is_brokered() {
        let root = unique_root("agentenv-create-http-mcp-proxy");
        let _proxy_bin_guard = fake_egress_proxy_bin(&root);
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: mcp-generic
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        tracker
            .supports_host_egress_proxy
            .store(true, Ordering::SeqCst);
        let factory = HttpMcpContextFactory {
            tracker: Arc::clone(&tracker),
            transport: agentenv_proto::McpTransport::Http,
        };
        let mut credentials =
            ResolvingCredentialProvider::with_value("MCP_TOKEN", "mcp-real-provider-secret");

        let result = super::create_env(&options, &factory, &mut credentials, "demo", yaml)
            .await
            .expect("HTTP MCP endpoint should be proxied");

        let rewritten = result
            .state
            .endpoints
            .context_mcp
            .as_ref()
            .map(|endpoint| endpoint.url.as_str())
            .expect("context endpoint should be persisted");
        assert!(rewritten.starts_with("http://127.0.0.1:"));
        assert!(rewritten.ends_with("/v1/mcp/context"));
        assert!(!rewritten.contains(":0/"));
        assert!(
            credentials
                .resolved
                .iter()
                .all(|requirement| requirement.name != "MCP_TOKEN"),
            "brokered MCP token must not be resolved during env create"
        );

        let endpoint_batches = tracker
            .mcp_config_endpoints
            .lock()
            .expect("mcp config endpoint tracker");
        assert_eq!(endpoint_batches.len(), 1);
        assert_eq!(endpoint_batches[0].len(), 1);
        assert_eq!(endpoint_batches[0][0].url, rewritten);
        assert!(
            endpoint_batches[0][0].headers.is_empty(),
            "rewritten MCP endpoint must not pass upstream headers into sandbox config"
        );

        let specs = tracker.create_specs.lock().expect("create spec tracker");
        let sandbox_env = &specs[0].env;
        assert_eq!(
            sandbox_env.get("MCP_TOKEN").map(String::as_str),
            Some("agentenv-brokered")
        );
        assert!(
            !sandbox_env
                .values()
                .any(|value| value.contains("mcp-real-provider-secret")),
            "real MCP token must not enter the sandbox env"
        );
    }

    #[tokio::test]
    async fn create_env_does_not_proxy_ssh_http_mcp_endpoint_even_with_https_url() {
        let root = unique_root("agentenv-create-ssh-http-mcp-no-proxy");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: mcp-generic
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        tracker
            .supports_host_egress_proxy
            .store(true, Ordering::SeqCst);
        let factory = HttpMcpContextFactory {
            tracker: Arc::clone(&tracker),
            transport: agentenv_proto::McpTransport::SshHttp,
        };
        let mut credentials =
            ResolvingCredentialProvider::with_value("MCP_TOKEN", "mcp-real-provider-secret");

        let result = super::create_env(&options, &factory, &mut credentials, "demo", yaml)
            .await
            .expect("ssh+http MCP endpoint should not be proxied by host egress broker");

        assert_eq!(
            result
                .state
                .endpoints
                .context_mcp
                .as_ref()
                .map(|endpoint| endpoint.url.as_str()),
            Some("https://mcp.example.test/rpc")
        );
        let resolved_names = credentials
            .resolved
            .iter()
            .map(|requirement| requirement.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(resolved_names, vec!["MCP_TOKEN"]);

        let endpoint_batches = tracker
            .mcp_config_endpoints
            .lock()
            .expect("mcp config endpoint tracker");
        assert_eq!(endpoint_batches.len(), 1);
        assert_eq!(endpoint_batches[0][0].url, "https://mcp.example.test/rpc");
        assert_eq!(
            endpoint_batches[0][0]
                .headers
                .get("authorization")
                .map(String::as_str),
            Some("Bearer real-upstream-token")
        );

        let specs = tracker.create_specs.lock().expect("create spec tracker");
        assert_eq!(
            specs[0].env.get("MCP_TOKEN").map(String::as_str),
            Some("mcp-real-provider-secret")
        );
    }

    #[tokio::test]
    async fn create_env_invalid_egress_proxy_policy_maps_to_invalid_blueprint() {
        let root = unique_root("agentenv-create-invalid-egress-proxy-policy");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
  egress_proxy:
    unknown: true
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        tracker
            .supports_host_egress_proxy
            .store(true, Ordering::SeqCst);
        let factory = AgentSetupFactory { tracker };
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let err = super::create_env(&options, &factory, &mut credentials, "demo", yaml)
            .await
            .expect_err("invalid egress proxy policy should fail");

        assert!(matches!(
            err,
            RuntimeError::InvalidEgressProxyPolicy { ref details }
                if details.contains("unknown field")
        ));
        assert_eq!(
            super::runtime_error_reason_code(&err),
            crate::admission::ReasonCode::InvalidBlueprint.as_str()
        );
    }

    #[tokio::test]
    async fn create_rejects_dns_policy_when_sandbox_lacks_dns_egress_control() {
        let root = unique_root("agentenv-create-dns-no-capability");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let mut factory = DnsCapabilityFactory::default();
        factory.sandbox_capabilities.supports_dns_egress_control = false;
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let err = super::create_env(
            &options,
            &factory,
            &mut credentials,
            "dns-no-capability",
            dns_policy_blueprint(),
        )
        .await
        .expect_err("dns policy should require sandbox capability");

        assert!(err.to_string().contains("supports_dns_egress_control"));
    }

    #[tokio::test]
    async fn create_accepts_dns_policy_when_sandbox_supports_dns_egress_control() {
        let root = unique_root("agentenv-create-dns-capability");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let mut factory = DnsCapabilityFactory::default();
        factory.sandbox_capabilities.supports_dns_egress_control = true;
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let result = super::create_env(
            &options,
            &factory,
            &mut credentials,
            "dns-capability",
            dns_policy_blueprint(),
        )
        .await
        .expect("dns policy should pass with capability");

        assert_eq!(result.state.name, "dns-capability");
    }

    #[tokio::test]
    async fn create_env_passes_byo_dockerfile_metadata_to_sandbox() {
        let root = unique_root("agentenv-create-byo-dockerfile");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  image:
    source: byo
    dockerfile: /tmp/enterprise-sandbox/Containerfile
    expected_digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::create_env(
            &options,
            &AgentSetupFactory {
                tracker: Arc::clone(&tracker),
            },
            &mut credentials,
            "demo",
            yaml,
        )
        .await
        .unwrap();

        let specs = tracker.create_specs.lock().expect("create spec tracker");
        assert_eq!(specs.len(), 1);
        let metadata = &specs[0].metadata;
        assert_eq!(metadata["name"], serde_json::json!("demo"));
        assert_eq!(
            metadata["byo_dockerfile"],
            serde_json::json!("/tmp/enterprise-sandbox/Containerfile")
        );
        assert_eq!(
            metadata["byo_expected_digest"],
            serde_json::json!(
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )
        );
        assert_eq!(metadata["agentenv_agent"], serde_json::json!("codex"));
        assert_eq!(
            metadata["agentenv_build_oneflight"],
            serde_json::json!("byo-openshell-v1")
        );
        assert_eq!(
            metadata["agentenv_build_seed_version"],
            serde_json::json!("1")
        );
        let seed = metadata["agentenv_build_seed"]
            .as_str()
            .expect("seed metadata is a string");
        crate::digest::parse_sha256_digest(seed).expect("seed is a sha256 digest");
    }

    #[tokio::test]
    async fn create_env_omits_build_oneflight_metadata_for_non_byo_image() {
        let root = unique_root("agentenv-create-non-byo-no-build-seed");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  image: openclaw
  digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::create_env(
            &options,
            &AgentSetupFactory {
                tracker: Arc::clone(&tracker),
            },
            &mut credentials,
            "demo",
            yaml,
        )
        .await
        .unwrap();

        let specs = tracker.create_specs.lock().expect("create spec tracker");
        let metadata = &specs[0].metadata;
        assert!(!metadata.contains_key("agentenv_build_oneflight"));
        assert!(!metadata.contains_key("agentenv_build_seed"));
        assert!(!metadata.contains_key("agentenv_build_seed_version"));
    }

    #[tokio::test]
    async fn sandbox_spec_defaults_to_baseline_hardening_metadata() {
        let root = unique_root("agentenv-create-baseline-hardening");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::create_env(
            &options,
            &AgentSetupFactory {
                tracker: Arc::clone(&tracker),
            },
            &mut credentials,
            "demo",
            yaml,
        )
        .await
        .unwrap();

        let specs = tracker.create_specs.lock().expect("create spec tracker");
        assert_eq!(specs.len(), 1);
        assert_eq!(
            specs[0].metadata["hardening_profile"],
            serde_json::json!("baseline")
        );
        assert!(specs[0]
            .metadata
            .contains_key("hardening_dockerfile_fragment"));
    }

    #[tokio::test]
    async fn sandbox_spec_propagates_strict_hardening_metadata() {
        let root = unique_root("agentenv-create-strict-hardening");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  hardening: strict
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::create_env(
            &options,
            &AgentSetupFactory {
                tracker: Arc::clone(&tracker),
            },
            &mut credentials,
            "demo",
            yaml,
        )
        .await
        .unwrap();

        let specs = tracker.create_specs.lock().expect("create spec tracker");
        assert_eq!(specs.len(), 1);
        assert_eq!(
            specs[0].metadata["hardening_profile"],
            serde_json::json!("strict")
        );
        assert_eq!(
            specs[0].metadata["hardening_ulimit_nproc"],
            serde_json::json!(512)
        );
    }

    #[test]
    fn portable_lockfile_records_default_hardening_profile() {
        let root = unique_root("agentenv-portable-default-hardening");
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
        discovery_config.installed_root = root.join("drivers");
        let driver_artifacts =
            crate::driver_artifact::discover_driver_artifacts(discovery_config, None)
                .expect("discover driver artifacts");
        let lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: "demo".to_owned(),
                blueprint_yaml: yaml.to_owned(),
                driver_artifacts,
            },
        )
        .expect("build portable lockfile");

        assert_eq!(
            lockfile.composition.sandbox.extra["hardening"],
            serde_yaml::Value::String("baseline".to_owned())
        );
        assert!(lockfile
            .policy
            .resolved
            .filesystem
            .read_only
            .contains(&"/etc".to_owned()));
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn create_env_rejects_direct_byo_dockerfile_sandbox_metadata_extra() {
        let root = unique_root("agentenv-create-direct-byo-dockerfile");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  byo_dockerfile: /tmp/evil
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let err = super::create_env(
            &options,
            &AgentSetupFactory {
                tracker: Arc::clone(&tracker),
            },
            &mut credentials,
            "demo",
            yaml,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("sandbox.byo_dockerfile"),
            "unexpected error: {err}"
        );
        assert!(tracker
            .create_specs
            .lock()
            .expect("create spec tracker")
            .is_empty());
    }

    #[tokio::test]
    async fn create_env_rejects_agentenv_prefixed_sandbox_metadata_extra() {
        let root = unique_root("agentenv-create-agentenv-metadata-extra");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: remote-ssh
  agentenv_agent: evil
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let err = super::create_env(
            &options,
            &AgentSetupFactory {
                tracker: Arc::clone(&tracker),
            },
            &mut credentials,
            "demo",
            yaml,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("sandbox.agentenv_agent"),
            "unexpected error: {err}"
        );
        assert!(tracker
            .create_specs
            .lock()
            .expect("create spec tracker")
            .is_empty());
    }

    #[tokio::test]
    async fn create_env_passes_generic_sandbox_extra_metadata_to_sandbox() {
        let root = unique_root("agentenv-create-remote-ssh-metadata");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: remote-ssh
  host: dev-vm.example.com
  user: alice
  port: 2222
  identity_file: ~/.ssh/id_ed25519
  jump_host: bastion.example.com
  enforce_remote_firewall: false
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::create_env(
            &options,
            &AgentSetupFactory {
                tracker: Arc::clone(&tracker),
            },
            &mut credentials,
            "demo",
            yaml,
        )
        .await
        .unwrap();

        let specs = tracker.create_specs.lock().expect("create spec tracker");
        assert_eq!(specs.len(), 1);
        let metadata = &specs[0].metadata;
        assert_eq!(metadata["name"], serde_json::json!("demo"));
        assert_eq!(metadata["host"], serde_json::json!("dev-vm.example.com"));
        assert_eq!(metadata["user"], serde_json::json!("alice"));
        assert_eq!(metadata["port"], serde_json::json!(2222));
        assert_eq!(
            metadata["identity_file"],
            serde_json::json!("~/.ssh/id_ed25519")
        );
        assert_eq!(
            metadata["jump_host"],
            serde_json::json!("bastion.example.com")
        );
        assert_eq!(
            metadata["enforce_remote_firewall"],
            serde_json::json!(false)
        );
        assert!(!metadata.contains_key("image"));
    }

    #[tokio::test]
    async fn create_env_records_computed_byo_digest_in_lockfile() {
        let root = unique_root("agentenv-create-byo-digest-lock");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  image:
    source: byo
    dockerfile: /tmp/enterprise-sandbox/Containerfile
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        *tracker.byo_digest_root.lock().expect("digest root tracker") = Some(root.clone());
        *tracker.byo_digest.lock().expect("digest tracker") = Some(
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
        );
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::create_env(
            &options,
            &AgentSetupFactory {
                tracker: Arc::clone(&tracker),
            },
            &mut credentials,
            "demo",
            yaml,
        )
        .await
        .unwrap();

        let lock_yaml = fs::read_to_string(root.join("envs").join("demo").join("lock.yaml"))
            .expect("read persisted lockfile");
        let lockfile = crate::lockfile::Lockfile::from_yaml(&lock_yaml).unwrap();
        assert_eq!(
            lockfile.artifacts["sandbox-image"],
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
    }

    #[test]
    fn byo_dockerfile_preflight_warnings_detect_conflicting_patterns() {
        let root = unique_root("agentenv-byo-preflight-warnings");
        fs::create_dir_all(root.join("sandbox")).unwrap();
        let dockerfile = root.join("sandbox").join("Dockerfile");
        fs::write(
            &dockerfile,
            r#"
FROM alpine:3.20
RUN docker run --privileged alpine true
RUN echo cap_add: NET_ADMIN
USER root
"#,
        )
        .unwrap();
        let mut image = serde_yaml::Mapping::new();
        image.insert(
            serde_yaml::Value::String("source".to_owned()),
            serde_yaml::Value::String("byo".to_owned()),
        );
        image.insert(
            serde_yaml::Value::String("dockerfile".to_owned()),
            serde_yaml::Value::String(dockerfile.display().to_string()),
        );
        let sandbox_extra =
            BTreeMap::from([("image".to_owned(), serde_yaml::Value::Mapping(image))]);
        let mut report = crate::admission::AdmissionReport::from_checks(
            "demo",
            vec![crate::admission::PreflightCheck {
                kind: DriverKind::Sandbox,
                driver: "openshell".to_owned(),
                ok: true,
                issues: Vec::new(),
            }],
        );

        super::add_byo_dockerfile_preflight_warnings(&mut report, &sandbox_extra);

        assert_eq!(report.status, crate::admission::AdmissionStatus::Rejected);
        assert_eq!(
            report.reason_code,
            crate::admission::ReasonCode::PreflightFailed
        );
        let codes = report.checks[0]
            .issues
            .iter()
            .map(|issue| issue.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"dockerfile_privileged"));
        assert!(codes.contains(&"dockerfile_cap_add"));
        assert!(codes.contains(&"dockerfile_user_root"));
        assert!(codes.contains(&"dockerfile_missing_hardening_marker"));
        assert!(report.checks[0]
            .issues
            .iter()
            .any(|issue| issue.code == "dockerfile_user_root"
                && issue.severity == agentenv_proto::IssueSeverity::Error));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn create_env_observed_emits_spawn_lifecycle_events() {
        let root = unique_root("agentenv-create-observed-events");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let events = RecordingEventEmitter::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::create_env_observed(
            &options,
            &TinyFactory,
            &mut credentials,
            "demo",
            yaml,
            Arc::new(events.clone()),
        )
        .await
        .unwrap();

        let recorded = events.recorded();
        let kinds = recorded.iter().map(|event| event.kind).collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                ActivityKind::SpawnRequested,
                ActivityKind::SpawnAdmitted,
                ActivityKind::SpawnStarted,
                ActivityKind::SandboxCreate,
                ActivityKind::PolicyApplied,
                ActivityKind::SpawnReady,
            ]
        );
        assert!(!kinds.contains(&ActivityKind::SpawnQueued));
        assert!(recorded
            .iter()
            .all(|event| event.env.as_deref() == Some("demo")));
        assert!(recorded
            .iter()
            .all(|event| event.actor["kind"] == serde_json::json!("core")));
        assert!(recorded.iter().all(|event| !event.trace_id.is_empty()));
        assert!(recorded
            .iter()
            .all(|event| event.trace_id == recorded[0].trace_id));

        let sandbox_create = recorded
            .iter()
            .find(|event| event.kind == ActivityKind::SandboxCreate)
            .expect("sandbox create event");
        assert_eq!(sandbox_create.result, ActivityResult::Ok);
        assert_eq!(sandbox_create.subject["handle"], serde_json::json!("sb-1"));

        let policy_applied = recorded
            .iter()
            .find(|event| event.kind == ActivityKind::PolicyApplied)
            .expect("policy applied event");
        assert_eq!(policy_applied.result, ActivityResult::Ok);
        assert_eq!(policy_applied.subject["handle"], serde_json::json!("sb-1"));
        assert_eq!(
            policy_applied.subject["phase"],
            serde_json::json!("sandbox_create")
        );
        assert!(policy_applied.subject.contains_key("policy"));

        let ready = recorded
            .iter()
            .find(|event| event.kind == ActivityKind::SpawnReady)
            .expect("spawn ready event");
        assert_eq!(ready.result, ActivityResult::Ok);
        assert_eq!(ready.subject["handle"], serde_json::json!("sb-1"));
    }

    #[tokio::test]
    async fn create_env_observed_passes_event_emitter_to_driver_factory() {
        let root = unique_root("agentenv-create-observed-factory-events");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let events = RecordingEventEmitter::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::create_env_observed(
            &options,
            &ObservedFactory,
            &mut credentials,
            "demo",
            yaml,
            Arc::new(events.clone()),
        )
        .await
        .unwrap();

        let recorded = events.recorded();
        assert!(recorded.iter().any(|event| {
            event.trace_id == "factory-trace"
                && event.actor["driver"] == serde_json::json!("observed-factory")
        }));
    }

    #[tokio::test]
    async fn create_env_observed_emits_terminal_event_after_post_start_failure() {
        let root = unique_root("agentenv-create-observed-failure");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let events = RecordingEventEmitter::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let err = super::create_env_observed(
            &options,
            &FailingContextProvisionFactory,
            &mut credentials,
            "demo",
            yaml,
            Arc::new(events.clone()),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("context provision failed"));
        let recorded = events.recorded();
        let started_index = recorded
            .iter()
            .position(|event| event.kind == ActivityKind::SpawnStarted)
            .expect("spawn started event");
        let failure = recorded
            .iter()
            .enumerate()
            .skip(started_index + 1)
            .find(|(_, event)| {
                event.kind == ActivityKind::SpawnRejected && event.result == ActivityResult::Error
            })
            .map(|(_, event)| event)
            .expect("terminal create failure event");
        assert_eq!(
            failure.reason_code.as_deref(),
            Some(crate::admission::ReasonCode::DriverCommandFailed.as_str())
        );
    }

    #[tokio::test]
    async fn list_and_describe_read_persisted_state() {
        let root = unique_root("agentenv-list-describe");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::create_env(&options, &TinyFactory, &mut credentials, "demo", yaml)
            .await
            .unwrap();

        let rows = super::list_envs(&options).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "demo");
        assert_eq!(rows[0].agent, "codex");

        let described = super::describe_env(&options, "demo").unwrap();
        assert_eq!(described.state.name, "demo");
        assert!(described.blueprint_yaml.contains("driver: codex"));
        assert!(described.lock_yaml.contains("blueprint_hash:"));
    }

    #[test]
    fn list_envs_skips_dot_prefixed_registry_dirs() {
        let root = unique_root("agentenv-list-hidden");
        let env_dir = root.join("envs").join(".demo.creating");
        write_state_json(&env_dir, state_fixture(".demo.creating"));
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };

        let rows = super::list_envs(&options).unwrap();

        assert!(rows.is_empty());
    }

    #[test]
    fn list_envs_errors_on_corrupt_visible_state() {
        let root = unique_root("agentenv-list-corrupt");
        let env_dir = root.join("envs").join("demo");
        fs::create_dir_all(&env_dir).unwrap();
        fs::write(env_dir.join("state.json"), "{").unwrap();
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };

        let err = super::list_envs(&options).unwrap_err();

        assert!(matches!(
            err,
            RuntimeError::Env(crate::env::EnvError::Json { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn list_envs_errors_on_symlinked_state_file() {
        let root = unique_root("agentenv-list-state-symlink");
        let env_dir = root.join("envs").join("demo");
        fs::create_dir_all(&env_dir).unwrap();
        let outside_state = root.join("outside-state.json");
        fs::write(
            &outside_state,
            serde_json::to_string_pretty(&state_fixture("demo")).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside_state, env_dir.join("state.json")).unwrap();
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };

        let err = super::list_envs(&options).unwrap_err();

        assert!(err.to_string().contains("not a regular file"));
    }

    #[test]
    fn describe_env_rejects_state_name_mismatch() {
        let root = unique_root("agentenv-describe-mismatch");
        let env_dir = root.join("envs").join("demo");
        write_state_json(&env_dir, state_fixture("other"));
        fs::write(env_dir.join("blueprint.yaml"), "agent:\n  driver: codex\n").unwrap();
        fs::write(env_dir.join("lock.yaml"), "blueprint_hash: test\n").unwrap();
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };

        let err = super::describe_env(&options, "demo").unwrap_err();

        assert!(err
            .to_string()
            .contains("state name `other` does not match env `demo`"));
    }

    #[cfg(unix)]
    #[test]
    fn describe_env_rejects_symlinked_registry_dir() {
        let root = unique_root("agentenv-describe-symlink");
        let envs_dir = root.join("envs");
        let target_dir = root.join("outside-demo");
        write_state_json(&target_dir, state_fixture("demo"));
        fs::write(
            target_dir.join("blueprint.yaml"),
            "agent:\n  driver: codex\n",
        )
        .unwrap();
        fs::write(target_dir.join("lock.yaml"), "blueprint_hash: test\n").unwrap();
        fs::create_dir_all(&envs_dir).unwrap();
        std::os::unix::fs::symlink(&target_dir, envs_dir.join("demo")).unwrap();
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };

        let err = super::describe_env(&options, "demo").unwrap_err();

        assert!(matches!(
            err,
            RuntimeError::Env(crate::env::EnvError::NotFound { name }) if name == "demo"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn describe_env_rejects_symlinked_registry_files() {
        for (label, linked_file, regular_file) in [
            ("blueprint", "blueprint.yaml", "lock.yaml"),
            ("lock", "lock.yaml", "blueprint.yaml"),
        ] {
            let root = unique_root(&format!("agentenv-describe-{label}-symlink"));
            let env_dir = root.join("envs").join("demo");
            write_state_json(&env_dir, state_fixture("demo"));
            fs::write(env_dir.join(regular_file), "regular: true\n").unwrap();
            let outside_file = root.join(format!("outside-{linked_file}"));
            fs::write(&outside_file, "external: true\n").unwrap();
            std::os::unix::fs::symlink(&outside_file, env_dir.join(linked_file)).unwrap();
            let options = RuntimeOptions {
                root,
                log_level: LogLevel::Info,
                non_interactive: true,
            };

            let err = super::describe_env(&options, "demo").unwrap_err();

            assert!(
                err.to_string().contains("not a regular file"),
                "expected {linked_file} symlink to be rejected, got {err}"
            );
        }
    }

    #[tokio::test]
    async fn create_env_does_not_expose_final_dir_before_publish() {
        let root = unique_root("agentenv-atomic-create");
        let observed_final_dir_exists = Arc::new(AtomicBool::new(false));
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let factory = ObservingFactory {
            root: root.clone(),
            observed_final_dir_exists: Arc::clone(&observed_final_dir_exists),
        };
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let result = super::create_env(&options, &factory, &mut credentials, "demo", yaml)
            .await
            .unwrap();

        assert_eq!(
            result.admission.status,
            crate::admission::AdmissionStatus::Accepted
        );
        assert!(
            !observed_final_dir_exists.load(Ordering::SeqCst),
            "final env dir was visible before publish"
        );
        assert!(root.join("envs").join("demo").is_dir());
    }

    #[tokio::test]
    async fn snapshot_env_copies_workspace_and_writes_signed_manifest() {
        let root = unique_root("agentenv-runtime-snapshot");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let blueprint_yaml = snapshot_blueprint_yaml();
        write_snapshot_env_fixture(&root, "demo", blueprint_yaml);
        let output = root.join("demo.agentenvsnap");
        let factory = SnapshotFactory::default();

        let result = super::snapshot_env(
            &options,
            &factory,
            super::SnapshotEnvArgs {
                env: "demo".to_owned(),
                output: output.clone(),
            },
        )
        .await
        .expect("snapshot env");

        assert_eq!(result.path, output);
        assert!(result.file_count > 0);
        assert!(!result.merkle_root.is_empty());
        assert!(output.join("manifest.json").is_file());
        assert!(output.join("signatures.json").is_file());
        assert!(output.join("blueprint.yaml").is_file());
        assert!(output.join("lock.yaml").is_file());
        assert!(output.join("policy.yaml").is_file());
        assert!(output.join("events.db").is_file());
        assert!(output.join("workspace").join("copied.txt").is_file());
        let manifest =
            crate::snapshot::verify_snapshot_dir(&output).expect("snapshot should verify");
        assert_eq!(manifest.source_env, "demo");
        assert_eq!(manifest.files.len(), result.file_count);
        assert_eq!(manifest.merkle_root, result.merkle_root);
        let copied_out = factory.copied_out.lock().expect("copy out tracker").clone();
        assert!(copied_out.iter().any(|(src, dst)| {
            src == "/sandbox" && std::path::Path::new(dst).ends_with("workspace")
        }));
        assert_eq!(
            *factory.env_builds.lock().expect("env build tracker"),
            vec!["demo".to_owned()]
        );
    }

    #[tokio::test]
    async fn snapshot_env_rejects_output_file_created_during_finalize_without_clobbering() {
        let root = unique_root("agentenv-runtime-snapshot-output-file");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        write_snapshot_env_fixture(&root, "demo", snapshot_blueprint_yaml());
        let output = root.join("demo.agentenvsnap");
        let factory = SnapshotFactory::default();
        *factory.output_race.lock().expect("output race tracker") =
            Some(SnapshotOutputRace::File(output.clone()));

        let err = super::snapshot_env(
            &options,
            &factory,
            super::SnapshotEnvArgs {
                env: "demo".to_owned(),
                output: output.clone(),
            },
        )
        .await
        .expect_err("snapshot must reject raced output file");

        assert!(matches!(
            err,
            RuntimeError::Driver(crate::driver::DriverError::InvalidInput { .. })
        ));
        assert_eq!(fs::read_to_string(&output).unwrap(), "existing output\n");
    }

    #[tokio::test]
    async fn snapshot_env_rejects_output_directory_created_during_finalize_without_clobbering() {
        let root = unique_root("agentenv-runtime-snapshot-output-dir");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        write_snapshot_env_fixture(&root, "demo", snapshot_blueprint_yaml());
        let output = root.join("demo.agentenvsnap");
        let factory = SnapshotFactory::default();
        *factory.output_race.lock().expect("output race tracker") =
            Some(SnapshotOutputRace::Directory(output.clone()));

        let err = super::snapshot_env(
            &options,
            &factory,
            super::SnapshotEnvArgs {
                env: "demo".to_owned(),
                output: output.clone(),
            },
        )
        .await
        .expect_err("snapshot must reject raced output directory");

        assert!(matches!(
            err,
            RuntimeError::Driver(crate::driver::DriverError::InvalidInput { .. })
        ));
        assert!(output.is_dir());
        assert!(!output.join("manifest.json").exists());
    }

    #[tokio::test]
    async fn snapshot_env_persist_home_resolves_home_and_copies_it_out() {
        let root = unique_root("agentenv-runtime-snapshot-home");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        write_snapshot_env_fixture(&root, "demo", snapshot_persist_home_blueprint_yaml());
        let output = root.join("demo.agentenvsnap");
        let factory = SnapshotFactory::default();

        super::snapshot_env(
            &options,
            &factory,
            super::SnapshotEnvArgs {
                env: "demo".to_owned(),
                output: output.clone(),
            },
        )
        .await
        .expect("snapshot env");

        assert!(factory
            .execs
            .lock()
            .expect("exec tracker")
            .contains(&r#"printf %s "$HOME""#.to_owned()));
        let copied_out = factory.copied_out.lock().expect("copy out tracker").clone();
        assert!(copied_out.iter().any(|(src, dst)| {
            src == "/home/agent" && std::path::Path::new(dst).ends_with("home")
        }));
        let manifest = crate::snapshot::verify_snapshot_dir(&output).expect("verify snapshot");
        assert!(manifest.sections.contains_key("home"));
    }

    #[tokio::test]
    async fn snapshot_env_manifest_includes_portable_lockfile_credential_requirements() {
        let root = unique_root("agentenv-runtime-snapshot-credentials");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        write_snapshot_env_fixture(&root, "demo", snapshot_credential_blueprint_yaml());
        let output = root.join("demo.agentenvsnap");
        let factory = SnapshotFactory::default();

        super::snapshot_env(
            &options,
            &factory,
            super::SnapshotEnvArgs {
                env: "demo".to_owned(),
                output: output.clone(),
            },
        )
        .await
        .expect("snapshot env");

        let manifest = crate::snapshot::verify_snapshot_dir(&output).expect("verify snapshot");
        assert_eq!(manifest.credential_requirements.len(), 1);
        assert_eq!(manifest.credential_requirements[0].name, "OPENAI_API_KEY");
        assert_eq!(manifest.credential_requirements[0].source, "env");
        assert_eq!(
            manifest.credential_requirements[0].reference.as_deref(),
            Some("OPENAI_API_KEY")
        );
        assert_eq!(manifest.credential_requirements[0].required, Some(true));

        let lock_yaml = fs::read_to_string(output.join("lock.yaml")).unwrap();
        let crate::lockfile::LockfileDocument::Portable(lockfile) =
            crate::lockfile::LockfileDocument::from_yaml(&lock_yaml)
                .expect("snapshot lockfile should remain parseable")
        else {
            panic!("snapshot lockfile should be portable");
        };
        assert_eq!(
            lockfile.credentials["OPENAI_API_KEY"].reference.as_deref(),
            Some("OPENAI_API_KEY")
        );
        assert_eq!(
            lockfile.composition.agent.credentials["OPENAI_API_KEY"]
                .reference
                .as_deref(),
            Some("OPENAI_API_KEY")
        );
    }

    #[test]
    fn verify_snapshot_returns_manifest_summary() {
        let root = unique_root("agentenv-runtime-verify-snapshot");
        let snapshot_dir = root.join("minimal.agentenvsnap");
        fs::create_dir_all(snapshot_dir.join("workspace")).unwrap();
        fs::write(snapshot_dir.join("workspace").join("README.md"), "hello\n").unwrap();
        fs::write(
            snapshot_dir.join("blueprint.yaml"),
            snapshot_blueprint_yaml(),
        )
        .unwrap();
        fs::write(
            snapshot_dir.join("lock.yaml"),
            snapshot_lockfile_yaml_with_policy(
                &root,
                "demo",
                snapshot_blueprint_yaml(),
                super::empty_policy_override(),
            ),
        )
        .unwrap();
        fs::write(
            snapshot_dir.join("policy.yaml"),
            serde_yaml::to_string(&super::empty_policy_override()).unwrap(),
        )
        .unwrap();
        let manifest = crate::snapshot::manifest_for_snapshot_dir(
            &snapshot_dir,
            "demo",
            Vec::new(),
            Vec::new(),
        )
        .expect("manifest");
        crate::snapshot::write_signed_manifest(
            &snapshot_dir,
            &root.join("snapshot-signing.key"),
            &manifest,
        )
        .expect("write signed manifest");

        let result = super::verify_snapshot(&snapshot_dir).expect("verify snapshot");

        assert_eq!(result.path, snapshot_dir);
        assert_eq!(result.file_count, manifest.files.len());
        assert_eq!(result.merkle_root, manifest.merkle_root);
    }

    #[test]
    fn verify_snapshot_rejects_malformed_embedded_lockfile() {
        let root = unique_root("agentenv-runtime-verify-malformed-lock");
        let snapshot_dir = write_custom_signed_snapshot(
            &root,
            "demo",
            "version: 0.2.0\ncredentials: '[redacted]'\n",
            &serde_yaml::to_string(&super::empty_policy_override()).unwrap(),
        );

        let err = super::verify_snapshot(&snapshot_dir)
            .expect_err("signed snapshot with malformed lockfile must fail verification");

        assert!(
            err.to_string().contains("lockfile") || err.to_string().contains("credentials"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_snapshot_rejects_malformed_snapshot_policy() {
        let root = unique_root("agentenv-runtime-verify-malformed-policy");
        let snapshot_dir = write_custom_signed_snapshot(
            &root,
            "demo",
            &snapshot_lockfile_yaml_with_policy(
                &root,
                "demo",
                snapshot_blueprint_yaml(),
                super::empty_policy_override(),
            ),
            "filesystem: [\n",
        );

        let err = super::verify_snapshot(&snapshot_dir)
            .expect_err("signed snapshot with malformed policy must fail verification");

        assert!(
            err.to_string().contains("YAML") || err.to_string().contains("policy"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_snapshot_rejects_incompatible_min_agentenv_version() {
        let root = unique_root("agentenv-runtime-verify-min-version");
        let snapshot_dir = write_custom_signed_snapshot_with_manifest(
            &root,
            "demo",
            &snapshot_lockfile_yaml_with_policy(
                &root,
                "demo",
                snapshot_blueprint_yaml(),
                super::empty_policy_override(),
            ),
            &serde_yaml::to_string(&super::empty_policy_override()).unwrap(),
            |manifest| {
                manifest.min_agentenv_version = "999.0.0".to_owned();
            },
        );

        let err = super::verify_snapshot(&snapshot_dir)
            .expect_err("signed snapshot with future min_agentenv_version must fail");

        assert!(
            err.to_string().contains("min_agentenv_version")
                || err.to_string().contains("agentenv version"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_snapshot_rejects_incompatible_driver_protocol_version() {
        let root = unique_root("agentenv-runtime-verify-driver-protocol");
        let snapshot_dir = write_custom_signed_snapshot_with_manifest(
            &root,
            "demo",
            &snapshot_lockfile_yaml_with_policy(
                &root,
                "demo",
                snapshot_blueprint_yaml(),
                super::empty_policy_override(),
            ),
            &serde_yaml::to_string(&super::empty_policy_override()).unwrap(),
            |manifest| {
                manifest.driver_protocol_version = "999.0".to_owned();
            },
        );

        let err = super::verify_snapshot(&snapshot_dir)
            .expect_err("signed snapshot with incompatible driver protocol must fail");

        assert!(
            err.to_string().contains("driver protocol"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn restore_snapshot_refuses_missing_credentials_before_create() {
        let root = unique_root("agentenv-runtime-restore-missing-credential");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let _env_guard = EnvVarGuard::unset("OPENAI_API_KEY");
        let snapshot_dir = write_signed_snapshot_fixture(
            &root,
            "demo",
            vec![crate::snapshot::SnapshotCredentialRequirement {
                name: "OPENAI_API_KEY".to_owned(),
                source: "env".to_owned(),
                reference: Some("OPENAI_API_KEY".to_owned()),
                required: Some(true),
            }],
        );
        let factory = SnapshotFactory::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let err = super::restore_snapshot_env(
            &options,
            &factory,
            &mut credentials,
            super::SnapshotRestoreArgs {
                snapshot: snapshot_dir,
                name: Some("restored".to_owned()),
            },
        )
        .await
        .expect_err("restore must fail before creating env");

        assert!(err.to_string().contains("OPENAI_API_KEY"));
        assert!(
            !root.join("envs").join("restored").exists(),
            "credential failure must happen before env creation"
        );
    }

    #[tokio::test]
    async fn restore_snapshot_refuses_existing_target_before_credentials() {
        let root = unique_root("agentenv-runtime-restore-existing-before-credential");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let _env_guard = EnvVarGuard::unset("OPENAI_API_KEY");
        let snapshot_dir = write_signed_snapshot_fixture(
            &root,
            "demo",
            vec![crate::snapshot::SnapshotCredentialRequirement {
                name: "OPENAI_API_KEY".to_owned(),
                source: "env".to_owned(),
                reference: Some("OPENAI_API_KEY".to_owned()),
                required: Some(true),
            }],
        );
        write_snapshot_env_fixture(&root, "restored", snapshot_blueprint_yaml());
        let factory = SnapshotFactory::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let err = super::restore_snapshot_env(
            &options,
            &factory,
            &mut credentials,
            super::SnapshotRestoreArgs {
                snapshot: snapshot_dir,
                name: Some("restored".to_owned()),
            },
        )
        .await
        .expect_err("restore must reject existing target before credentials");

        assert!(matches!(
            err,
            RuntimeError::Env(crate::env::EnvError::AlreadyExists { ref name }) if name == "restored"
        ));
        assert!(!err.to_string().contains("OPENAI_API_KEY"));
        assert!(
            factory
                .env_builds
                .lock()
                .expect("env build tracker")
                .is_empty(),
            "restore must not reproduce an existing env"
        );
        assert!(
            factory
                .copied_in
                .lock()
                .expect("copy in tracker")
                .is_empty(),
            "restore must not copy into an existing env"
        );
    }

    #[tokio::test]
    async fn restore_snapshot_resolves_manifest_credentials_through_provider() {
        let root = unique_root("agentenv-runtime-restore-provider-credential");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let _env_guard = EnvVarGuard::unset("OPENAI_API_KEY");
        let snapshot_dir = write_signed_snapshot_fixture(
            &root,
            "demo",
            vec![crate::snapshot::SnapshotCredentialRequirement {
                name: "OPENAI_API_KEY".to_owned(),
                source: "env".to_owned(),
                reference: Some("OPENAI_API_KEY".to_owned()),
                required: Some(true),
            }],
        );
        let factory = SnapshotFactory::default();
        let mut credentials =
            ResolvingCredentialProvider::with_value("OPENAI_API_KEY", "sk-test-provider");

        let result = super::restore_snapshot_env(
            &options,
            &factory,
            &mut credentials,
            super::SnapshotRestoreArgs {
                snapshot: snapshot_dir.clone(),
                name: Some("restored".to_owned()),
            },
        )
        .await
        .expect("restore should use provider-resolved snapshot credential");

        assert_eq!(result.name, "restored");
        assert_eq!(result.snapshot, snapshot_dir);
        assert_eq!(credentials.resolved.len(), 1);
        assert_eq!(credentials.resolved[0].name, "OPENAI_API_KEY");
        assert!(credentials.resolved[0].required);
        assert!(root
            .join("envs")
            .join("restored")
            .join("state.json")
            .is_file());
    }

    #[tokio::test]
    async fn restore_snapshot_resolves_lockfile_credentials_through_provider_without_env() {
        let root = unique_root("agentenv-runtime-restore-provider-lockfile-credential");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let _env_guard = EnvVarGuard::unset("OPENAI_API_KEY");
        let snapshot_dir = write_signed_snapshot_fixture_with_blueprint(
            &root,
            "demo",
            vec![crate::snapshot::SnapshotCredentialRequirement {
                name: "OPENAI_API_KEY".to_owned(),
                source: "env".to_owned(),
                reference: Some("OPENAI_API_KEY".to_owned()),
                required: Some(true),
            }],
            super::empty_policy_override(),
            snapshot_credential_blueprint_yaml(),
            |_| {},
        );
        let factory = SnapshotFactory::default();
        let mut credentials =
            ResolvingCredentialProvider::with_value("OPENAI_API_KEY", "sk-test-provider");

        let result = super::restore_snapshot_env(
            &options,
            &factory,
            &mut credentials,
            super::SnapshotRestoreArgs {
                snapshot: snapshot_dir.clone(),
                name: Some("restored".to_owned()),
            },
        )
        .await
        .expect("restore should use provider-resolved lockfile credential");

        assert_eq!(result.name, "restored");
        assert_eq!(result.snapshot, snapshot_dir);
        assert!(
            credentials
                .resolved
                .iter()
                .filter(|requirement| requirement.name == "OPENAI_API_KEY")
                .count()
                >= 2,
            "restore should resolve both manifest and lockfile credential requirements"
        );
        assert!(root
            .join("envs")
            .join("restored")
            .join("state.json")
            .is_file());
        let copied_in = factory.copied_in.lock().expect("copy in tracker").clone();
        assert!(copied_in.iter().any(|(src, dst)| {
            std::path::Path::new(src).ends_with("workspace") && dst == "/sandbox"
        }));
        let copied_in_entries = factory
            .copied_in_entries
            .lock()
            .expect("copy in entry tracker")
            .clone();
        let (_, _, workspace_entries) = copied_in_entries
            .iter()
            .find(|(_, dst, _)| dst == "/sandbox")
            .expect("workspace copy-in should be recorded");
        assert!(
            workspace_entries.iter().any(|entry| entry == "README.md"),
            "workspace staging directory must remain populated until copy-in"
        );
    }

    #[tokio::test]
    async fn restore_snapshot_rejects_required_manifest_credential_when_provider_returns_none() {
        let root = unique_root("agentenv-runtime-restore-provider-missing");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let _env_guard = EnvVarGuard::unset("OPENAI_API_KEY");
        let snapshot_dir = write_signed_snapshot_fixture(
            &root,
            "demo",
            vec![crate::snapshot::SnapshotCredentialRequirement {
                name: "OPENAI_API_KEY".to_owned(),
                source: "env".to_owned(),
                reference: Some("OPENAI_API_KEY".to_owned()),
                required: Some(true),
            }],
        );
        let factory = SnapshotFactory::default();
        let mut credentials = ResolvingCredentialProvider::default();

        let err = super::restore_snapshot_env(
            &options,
            &factory,
            &mut credentials,
            super::SnapshotRestoreArgs {
                snapshot: snapshot_dir,
                name: Some("restored".to_owned()),
            },
        )
        .await
        .expect_err("restore should reject unresolved required snapshot credential");

        assert!(matches!(
            err,
            RuntimeError::MissingCredential { ref name } if name == "OPENAI_API_KEY"
        ));
        assert_eq!(credentials.resolved.len(), 1);
        assert!(
            factory
                .env_builds
                .lock()
                .expect("env build tracker")
                .is_empty(),
            "credential failure must happen before env reproduction"
        );
        assert!(
            !root.join("envs").join("restored").exists(),
            "credential failure must happen before env creation"
        );
    }

    #[tokio::test]
    async fn restore_snapshot_allows_optional_unresolved_manifest_credential() {
        let root = unique_root("agentenv-runtime-restore-provider-optional");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let _env_guard = EnvVarGuard::unset("OPENAI_API_KEY");
        let snapshot_dir = write_signed_snapshot_fixture(
            &root,
            "demo",
            vec![crate::snapshot::SnapshotCredentialRequirement {
                name: "OPENAI_API_KEY".to_owned(),
                source: "env".to_owned(),
                reference: Some("OPENAI_API_KEY".to_owned()),
                required: Some(false),
            }],
        );
        let factory = SnapshotFactory::default();
        let mut credentials = ResolvingCredentialProvider::default();

        let result = super::restore_snapshot_env(
            &options,
            &factory,
            &mut credentials,
            super::SnapshotRestoreArgs {
                snapshot: snapshot_dir.clone(),
                name: Some("restored".to_owned()),
            },
        )
        .await
        .expect("optional unresolved snapshot credential should not block restore");

        assert_eq!(result.name, "restored");
        assert_eq!(result.snapshot, snapshot_dir);
        assert_eq!(credentials.resolved.len(), 1);
        assert!(!credentials.resolved[0].required);
        assert!(root
            .join("envs")
            .join("restored")
            .join("state.json")
            .is_file());
    }

    #[tokio::test]
    async fn restore_snapshot_reproduces_then_copies_workspace() {
        let root = unique_root("agentenv-runtime-restore-workspace");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let snapshot_dir = write_signed_snapshot_fixture(&root, "demo", Vec::new());
        let factory = SnapshotFactory::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let result = super::restore_snapshot_env(
            &options,
            &factory,
            &mut credentials,
            super::SnapshotRestoreArgs {
                snapshot: snapshot_dir.clone(),
                name: Some("restored".to_owned()),
            },
        )
        .await
        .expect("restore snapshot");

        assert_eq!(result.name, "restored");
        assert_eq!(result.snapshot, snapshot_dir);
        assert!(root
            .join("envs")
            .join("restored")
            .join("state.json")
            .is_file());
        let copied_in = factory.copied_in.lock().expect("copy in tracker").clone();
        assert!(copied_in.iter().any(|(src, dst)| {
            std::path::Path::new(src).ends_with("workspace") && dst == "/sandbox"
        }));
    }

    #[tokio::test]
    async fn restore_snapshot_persists_snapshot_policy_yaml() {
        let root = unique_root("agentenv-runtime-restore-policy");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let distinctive_rule = agentenv_proto::NetworkRule {
            target: NetworkTarget::Host {
                host: "snapshot-policy.example".to_owned(),
                port: Some(443),
                scheme: Some("https".to_owned()),
                http_access: None,
            },
        };
        let mut snapshot_policy = super::empty_policy_override();
        snapshot_policy.network.allow.push(distinctive_rule.clone());
        let snapshot_dir =
            write_signed_snapshot_fixture_with(&root, "demo", Vec::new(), snapshot_policy, |_| {});
        let factory = SnapshotFactory::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::restore_snapshot_env(
            &options,
            &factory,
            &mut credentials,
            super::SnapshotRestoreArgs {
                snapshot: snapshot_dir,
                name: Some("restored".to_owned()),
            },
        )
        .await
        .expect("restore snapshot");

        let description = super::describe_env(&options, "restored").expect("describe restored env");
        let restored_policy = description
            .state
            .resolved_policy
            .expect("restored policy should be persisted");
        assert!(restored_policy.network.allow.contains(&distinctive_rule));
    }

    #[tokio::test]
    async fn restore_snapshot_sanitizes_workspace_before_copying() {
        let root = unique_root("agentenv-runtime-restore-sanitize-workspace");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let snapshot_dir = write_signed_snapshot_fixture_with(
            &root,
            "demo",
            Vec::new(),
            super::empty_policy_override(),
            |snapshot_dir| {
                fs::write(
                    snapshot_dir.join("workspace").join("credentials.local"),
                    "credential payload\n",
                )
                .unwrap();
            },
        );
        let factory = SnapshotFactory::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::restore_snapshot_env(
            &options,
            &factory,
            &mut credentials,
            super::SnapshotRestoreArgs {
                snapshot: snapshot_dir.clone(),
                name: Some("restored".to_owned()),
            },
        )
        .await
        .expect("restore snapshot");

        assert!(snapshot_dir
            .join("workspace")
            .join("credentials.local")
            .is_file());
        let copied_in_entries = factory
            .copied_in_entries
            .lock()
            .expect("copy in entry tracker")
            .clone();
        let workspace_entries = copied_in_entries
            .iter()
            .find(|(_, dst, _)| dst == "/sandbox")
            .expect("workspace copied into sandbox");
        assert!(workspace_entries.2.contains(&"README.md".to_owned()));
        assert!(!workspace_entries
            .2
            .contains(&"credentials.local".to_owned()));
    }

    #[tokio::test]
    async fn restore_snapshot_rejects_leaked_secret_before_create() {
        let root = unique_root("agentenv-runtime-restore-leaked-secret");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let leaked_secret = "sk-testMALFORMEDSECRET";
        let snapshot_dir = write_signed_snapshot_fixture_with(
            &root,
            "demo",
            Vec::new(),
            super::empty_policy_override(),
            |snapshot_dir| {
                fs::write(
                    snapshot_dir.join("workspace").join("leak.txt"),
                    format!("token={leaked_secret}\n"),
                )
                .unwrap();
            },
        );
        let factory = SnapshotFactory::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let err = super::restore_snapshot_env(
            &options,
            &factory,
            &mut credentials,
            super::SnapshotRestoreArgs {
                snapshot: snapshot_dir,
                name: Some("restored".to_owned()),
            },
        )
        .await
        .expect_err("leaked snapshot secret should fail restore");

        let rendered = err.to_string();
        assert!(rendered.contains("secret patterns"));
        assert!(rendered.contains("workspace/leak.txt"));
        assert!(
            !rendered.contains(leaked_secret),
            "restore error leaked secret: {rendered}"
        );
        assert!(
            !root.join("envs").join("restored").exists(),
            "sanitizer failure must happen before env creation"
        );
    }

    #[tokio::test]
    async fn restore_snapshot_strips_unsafe_symlink_before_copying() {
        let root = unique_root("agentenv-runtime-restore-unsafe-symlink");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let snapshot_dir = write_signed_snapshot_fixture_with(
            &root,
            "demo",
            Vec::new(),
            super::empty_policy_override(),
            |snapshot_dir| {
                super::create_host_symlink(
                    std::path::Path::new("../outside"),
                    &snapshot_dir.join("workspace").join("escape"),
                )
                .expect("create unsafe workspace symlink");
            },
        );
        let factory = SnapshotFactory::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let result = super::restore_snapshot_env(
            &options,
            &factory,
            &mut credentials,
            super::SnapshotRestoreArgs {
                snapshot: snapshot_dir,
                name: Some("restored".to_owned()),
            },
        )
        .await
        .expect("unsafe snapshot symlink should be stripped before restore copy-in");

        assert_eq!(result.name, "restored");
        assert!(
            root.join("envs").join("restored").exists(),
            "restore should create the target env after stripping unsafe symlinks"
        );
        let copied_in_entries = factory
            .copied_in_entries
            .lock()
            .expect("copy in entry tracker")
            .clone();
        let (_, _, workspace_entries) = copied_in_entries
            .iter()
            .find(|(_, dst, _)| dst == "/sandbox")
            .expect("workspace copy-in should be recorded");
        assert!(workspace_entries.iter().any(|entry| entry == "README.md"));
        assert!(
            !workspace_entries.iter().any(|entry| entry == "escape"),
            "unsafe symlink must not be copied into the restored sandbox"
        );
    }

    #[tokio::test]
    async fn restore_snapshot_sanitizes_home_before_copying() {
        let root = unique_root("agentenv-runtime-restore-sanitize-home");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let snapshot_dir = write_signed_snapshot_fixture_with(
            &root,
            "demo",
            Vec::new(),
            super::empty_policy_override(),
            |snapshot_dir| {
                fs::create_dir_all(snapshot_dir.join("home").join(".codex")).unwrap();
                fs::write(
                    snapshot_dir
                        .join("home")
                        .join(".codex")
                        .join("credentials.json"),
                    "{}\n",
                )
                .unwrap();
                fs::write(snapshot_dir.join("home").join("notes.txt"), "safe\n").unwrap();
            },
        );
        let factory = SnapshotFactory::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::restore_snapshot_env(
            &options,
            &factory,
            &mut credentials,
            super::SnapshotRestoreArgs {
                snapshot: snapshot_dir,
                name: Some("restored".to_owned()),
            },
        )
        .await
        .expect("restore snapshot");

        let copied_in_entries = factory
            .copied_in_entries
            .lock()
            .expect("copy in entry tracker")
            .clone();
        let home_entries = copied_in_entries
            .iter()
            .find(|(_, dst, _)| dst == "/home/agent")
            .expect("home copied into sandbox");
        assert!(home_entries.2.contains(&"notes.txt".to_owned()));
        assert!(!home_entries
            .2
            .contains(&".codex/credentials.json".to_owned()));
    }

    #[tokio::test]
    async fn create_env_installs_agent_config_entrypoint_and_probe() {
        let root = unique_root("agentenv-agent-setup");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        let factory = AgentSetupFactory {
            tracker: Arc::clone(&tracker),
        };
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::create_env(&options, &factory, &mut credentials, "demo", yaml)
            .await
            .unwrap();

        let copied_paths = tracker.copied_paths.lock().expect("copy tracker").clone();
        assert!(copied_paths.contains(&"/sandbox/.codex/config.toml".to_owned()));
        assert!(copied_paths.contains(&super::AGENT_ENTRYPOINT_PATH.to_owned()));
        let exec_cmds = tracker.exec_cmds.lock().expect("exec tracker").clone();
        assert!(exec_cmds
            .iter()
            .any(|cmd| cmd.contains("printf agent-installed")));
        assert!(exec_cmds
            .iter()
            .any(|cmd| cmd.contains("chmod 0755") && cmd.contains(super::AGENT_ENTRYPOINT_PATH)));
        assert!(exec_cmds
            .iter()
            .any(|cmd| cmd == "agentenv-agent --version"));
        let create_policies = tracker
            .create_policies
            .lock()
            .expect("create policy tracker")
            .clone();
        assert_eq!(create_policies.len(), 1);
        assert!(create_policies[0]
            .network
            .allow
            .contains(&super::agent_install_npm_registry_rule()));
        let applied_policies = tracker
            .applied_policies
            .lock()
            .expect("apply policy tracker")
            .clone();
        assert_eq!(applied_policies.len(), 1);
        assert!(!applied_policies[0]
            .network
            .allow
            .contains(&super::agent_install_npm_registry_rule()));
        assert!(
            !options
                .root
                .join("envs")
                .join("demo")
                .join("agent")
                .exists(),
            "rendered agent files can contain credentials and must not persist in the registry"
        );
    }

    #[tokio::test]
    async fn create_env_does_not_restore_policy_when_sandbox_lacks_hot_reload() {
        let root = unique_root("agentenv-agent-setup-no-hot-reload");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: remote-ssh
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        let factory = NoHotReloadAgentSetupFactory {
            tracker: Arc::clone(&tracker),
        };
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::create_env(&options, &factory, &mut credentials, "demo", yaml)
            .await
            .expect("create env");

        let exec_cmds = tracker.exec_cmds.lock().expect("exec tracker").clone();
        assert!(exec_cmds
            .iter()
            .any(|cmd| cmd.contains("printf agent-installed")));
        let create_policies = tracker
            .create_policies
            .lock()
            .expect("create policy tracker")
            .clone();
        assert_eq!(create_policies.len(), 1);
        assert!(
            !create_policies[0]
                .network
                .allow
                .contains(&super::agent_install_npm_registry_rule()),
            "sandbox create should use final policy when hot reload is unavailable"
        );
        let applied_policies = tracker
            .applied_policies
            .lock()
            .expect("apply policy tracker")
            .clone();
        assert!(
            applied_policies.is_empty(),
            "sandbox policy restore should not be attempted without hot reload"
        );
    }

    #[tokio::test]
    async fn create_env_skips_agent_install_when_probe_already_passes() {
        let root = unique_root("agentenv-agent-preinstalled");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        tracker
            .preinstall_probe_succeeds
            .store(true, Ordering::SeqCst);
        let factory = AgentSetupFactory {
            tracker: Arc::clone(&tracker),
        };
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::create_env(&options, &factory, &mut credentials, "demo", yaml)
            .await
            .unwrap();

        let exec_cmds = tracker.exec_cmds.lock().expect("exec tracker").clone();
        assert!(exec_cmds
            .iter()
            .any(|cmd| cmd == "agentenv-agent --version"));
        assert!(!exec_cmds
            .iter()
            .any(|cmd| cmd.contains("printf agent-installed")));
    }

    #[tokio::test]
    async fn reproduce_env_uses_lockfile_resolved_policy_for_sandbox() {
        let root = unique_root("agentenv-reproduce-pinned-policy");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  image:
    source: byo
    dockerfile: /tmp/legacy-sandbox/Dockerfile
    expected_digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
        discovery_config.installed_root = root.join("drivers");
        let driver_artifacts =
            crate::driver_artifact::discover_driver_artifacts(discovery_config, None)
                .expect("discover driver artifacts");
        let mut lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: "demo".to_owned(),
                blueprint_yaml: yaml.to_owned(),
                driver_artifacts,
            },
        )
        .expect("build portable lockfile");
        lockfile.composition.sandbox.extra.remove("hardening");
        lockfile.blueprint_hash = crate::lifecycle::portable_blueprint_hash(&lockfile.composition)
            .expect("recompute legacy blueprint hash");
        let registry = agentenv_policy::PresetRegistry::load_builtin().expect("load presets");
        lockfile.policy.resolved = agentenv_policy::compose_policy(
            agentenv_policy::Tier::Restricted,
            &[],
            None,
            &registry,
        )
        .expect("compose legacy policy");
        let pinned_rule = agentenv_proto::NetworkRule {
            target: NetworkTarget::Host {
                host: "pinned.example".to_owned(),
                port: Some(443),
                scheme: Some("https".to_owned()),
                http_access: None,
            },
        };
        lockfile
            .policy
            .resolved
            .network
            .allow
            .push(pinned_rule.clone());
        let context_rule = agentenv_proto::NetworkRule {
            target: NetworkTarget::Host {
                host: "context-required.example".to_owned(),
                port: Some(443),
                scheme: Some("https".to_owned()),
                http_access: None,
            },
        };
        let lockfile_yaml = lockfile
            .to_yaml_deterministic()
            .expect("render portable lockfile");
        let tracker = Arc::new(AgentSetupTracker::default());
        let factory = RequiredRuleFactory {
            tracker: Arc::clone(&tracker),
            required_rule: context_rule.clone(),
        };
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::reproduce_env(&options, &factory, &mut credentials, "demo", &lockfile_yaml)
            .await
            .expect("reproduce env");

        let create_policies = tracker
            .create_policies
            .lock()
            .expect("create policy tracker")
            .clone();
        assert_eq!(create_policies.len(), 1);
        assert!(
            create_policies[0].network.allow.contains(&pinned_rule),
            "sandbox create policy should include the pinned lockfile policy"
        );
        assert!(
            !create_policies[0].network.allow.contains(&context_rule),
            "sandbox create policy should not add context-required rules during reproduce"
        );
        let create_specs = tracker
            .create_specs
            .lock()
            .expect("create spec tracker")
            .clone();
        assert_eq!(create_specs.len(), 1);
        assert_eq!(
            create_specs[0].metadata["byo_dockerfile"],
            serde_json::json!("/tmp/legacy-sandbox/Dockerfile")
        );
        assert!(
            !create_specs[0]
                .metadata
                .contains_key("hardening_dockerfile_fragment"),
            "legacy lockfiles without sandbox.hardening must not inject image hardening"
        );
        assert!(
            !create_specs[0].metadata.contains_key("hardening_profile"),
            "legacy lockfiles without sandbox.hardening must not default hardening metadata"
        );
        let applied_policies = tracker
            .applied_policies
            .lock()
            .expect("apply policy tracker")
            .clone();
        assert_eq!(applied_policies.len(), 1);
        assert!(
            applied_policies[0].network.allow.contains(&pinned_rule),
            "post-install restored policy should include the pinned lockfile policy"
        );
        assert!(
            !applied_policies[0].network.allow.contains(&context_rule),
            "post-install restored policy should not add context-required rules during reproduce"
        );
    }

    #[tokio::test]
    async fn reproduce_env_passes_driver_pins_to_factory_and_create_uses_normal_build() {
        let root = unique_root("agentenv-reproduce-pinned-factory");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
        discovery_config.installed_root = root.join("drivers");
        let driver_artifacts =
            crate::driver_artifact::discover_driver_artifacts(discovery_config, None)
                .expect("discover driver artifacts");
        let lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: "demo".to_owned(),
                blueprint_yaml: yaml.to_owned(),
                driver_artifacts,
            },
        )
        .expect("build portable lockfile");
        let lockfile_yaml = lockfile
            .to_yaml_deterministic()
            .expect("render portable lockfile");
        let factory = PinTrackingFactory::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::create_env(&options, &factory, &mut credentials, "created", yaml)
            .await
            .expect("create env");

        assert_eq!(factory.normal_builds.load(Ordering::SeqCst), 2);
        assert_eq!(factory.pinned_builds.load(Ordering::SeqCst), 0);

        super::reproduce_env(
            &options,
            &factory,
            &mut credentials,
            "reproduced",
            &lockfile_yaml,
        )
        .await
        .expect("reproduce env");

        assert_eq!(
            factory.normal_builds.load(Ordering::SeqCst),
            2,
            "portable reproduce must not use normal factory resolution"
        );
        assert_eq!(factory.pinned_builds.load(Ordering::SeqCst), 2);
        let mut roles = factory.pin_roles.lock().expect("pin roles").clone();
        roles.sort();
        roles.dedup();
        assert_eq!(roles, vec!["agent", "context", "sandbox"]);
    }

    #[tokio::test]
    async fn reproduce_env_does_not_forward_driver_pin_as_agent_package_version() {
        let root = unique_root("agentenv-reproduce-agent-spec-version");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
        discovery_config.installed_root = root.join("drivers");
        let driver_artifacts =
            crate::driver_artifact::discover_driver_artifacts(discovery_config, None)
                .expect("discover driver artifacts");
        let lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: "demo".to_owned(),
                blueprint_yaml: yaml.to_owned(),
                driver_artifacts,
            },
        )
        .expect("build portable lockfile");
        assert_eq!(
            lockfile.composition.agent.version,
            env!("CARGO_PKG_VERSION")
        );
        let lockfile_yaml = lockfile
            .to_yaml_deterministic()
            .expect("render portable lockfile");
        let tracker = Arc::new(AgentSetupTracker::default());
        let factory = AgentSetupFactory {
            tracker: Arc::clone(&tracker),
        };
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::reproduce_env(&options, &factory, &mut credentials, "demo", &lockfile_yaml)
            .await
            .expect("reproduce env");

        assert_eq!(
            tracker
                .agent_spec_versions
                .lock()
                .expect("agent spec versions")
                .as_slice(),
            &[None],
            "portable driver pins must not be forwarded as agent package versions"
        );
    }

    #[tokio::test]
    async fn reproduce_env_rejects_missing_skill_pin_before_driver_materialization() {
        let root = unique_root("agentenv-reproduce-missing-skill");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
        discovery_config.installed_root = root.join("drivers");
        let driver_artifacts =
            crate::driver_artifact::discover_driver_artifacts(discovery_config, None)
                .expect("discover driver artifacts");
        let mut lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: "demo".to_owned(),
                blueprint_yaml: yaml.to_owned(),
                driver_artifacts,
            },
        )
        .expect("build portable lockfile");
        lockfile.skills.push(crate::lockfile::SkillPin {
            name: "code-review".to_owned(),
            version: "1.2.0".to_owned(),
            source: "file:///skills/code-review".to_owned(),
            digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            signatures: Vec::new(),
        });
        let lockfile_yaml = lockfile
            .to_yaml_deterministic()
            .expect("render portable lockfile");
        let factory = PinTrackingFactory::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let err =
            super::reproduce_env(&options, &factory, &mut credentials, "demo", &lockfile_yaml)
                .await
                .expect_err("missing skill pin should fail");

        let message = err.to_string();
        assert!(message.contains("missing skill pin"), "{message}");
        assert_eq!(
            factory.normal_builds.load(Ordering::SeqCst)
                + factory.pinned_builds.load(Ordering::SeqCst),
            0,
            "skill pin verification should fail before driver materialization"
        );
    }

    #[tokio::test]
    async fn reproduce_env_rejects_unsupported_skill_manifest_schema_before_driver_materialization()
    {
        let root = unique_root("agentenv-reproduce-skill-schema");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
        discovery_config.installed_root = root.join("drivers");
        let driver_artifacts =
            crate::driver_artifact::discover_driver_artifacts(discovery_config, None)
                .expect("discover driver artifacts");
        let mut lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: "demo".to_owned(),
                blueprint_yaml: yaml.to_owned(),
                driver_artifacts,
            },
        )
        .expect("build portable lockfile");
        lockfile
            .skills
            .push(write_runtime_skill_pin(&options.root, "9.9"));
        let lockfile_yaml = lockfile
            .to_yaml_deterministic()
            .expect("render portable lockfile");
        let factory = PinTrackingFactory::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let err =
            super::reproduce_env(&options, &factory, &mut credentials, "demo", &lockfile_yaml)
                .await
                .expect_err("unsupported skill manifest schema should fail");

        let message = err.to_string();
        assert!(
            message.contains("unsupported skill manifest schema version"),
            "{message}"
        );
        assert_eq!(
            factory.normal_builds.load(Ordering::SeqCst)
                + factory.pinned_builds.load(Ordering::SeqCst),
            0,
            "skill pin verification should fail before driver materialization"
        );
    }

    #[tokio::test]
    async fn reproduce_env_skips_pinned_skill_self_test_commands() {
        let root = unique_root("agentenv-reproduce-skill-self-test");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
        discovery_config.installed_root = root.join("drivers");
        let driver_artifacts =
            crate::driver_artifact::discover_driver_artifacts(discovery_config, None)
                .expect("discover driver artifacts");
        let mut lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: "demo".to_owned(),
                blueprint_yaml: yaml.to_owned(),
                driver_artifacts,
            },
        )
        .expect("build portable lockfile");
        let self_test = crate::skills::SkillSelfTest {
            timeout_seconds: 5,
            assertions: vec![crate::skills::SkillSelfTestAssertion::CommandExitsZero {
                cmd: "echo marker > host-side-marker".to_owned(),
            }],
        };
        lockfile.skills.push(write_runtime_skill_pin_with_self_test(
            &options.root,
            crate::skills::SKILL_METADATA_SCHEMA_VERSION,
            Some(self_test),
        ));
        let marker_path = options
            .root
            .join("skills")
            .join("code-review")
            .join("1.2.0")
            .join("host-side-marker");
        let lockfile_yaml = lockfile
            .to_yaml_deterministic()
            .expect("render portable lockfile");
        let factory = PinTrackingFactory::default();
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::reproduce_env(&options, &factory, &mut credentials, "demo", &lockfile_yaml)
            .await
            .expect("reproduce env");

        assert!(
            !marker_path.exists(),
            "reproduce-time skill pin verification executed a host-side self-test command"
        );
    }

    #[tokio::test]
    async fn reproduce_env_rejects_required_credstore_credential_satisfied_only_by_env() {
        let root = unique_root("agentenv-reproduce-strict-credstore");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
  credentials:
    api_token:
      source: credstore
      value: stored_api_token
policy:
  tier: restricted
  presets: []
"#;
        let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
        discovery_config.installed_root = root.join("drivers");
        let driver_artifacts =
            crate::driver_artifact::discover_driver_artifacts(discovery_config, None)
                .expect("discover driver artifacts");
        let lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: "demo".to_owned(),
                blueprint_yaml: yaml.to_owned(),
                driver_artifacts,
            },
        )
        .expect("build portable lockfile");
        let lockfile_yaml = lockfile
            .to_yaml_deterministic()
            .expect("render portable lockfile");
        let factory = PinTrackingFactory::default();
        let mut credentials = BackendOnlyCredentialProvider {
            backend: Some("env".to_owned()),
        };

        let err =
            super::reproduce_env(&options, &factory, &mut credentials, "demo", &lockfile_yaml)
                .await
                .expect_err("credstore pin must not be satisfied by env");

        assert!(matches!(
            err,
            RuntimeError::MissingCredential { ref name } if name == "stored_api_token"
        ));
        assert_eq!(
            factory.normal_builds.load(Ordering::SeqCst)
                + factory.pinned_builds.load(Ordering::SeqCst),
            0,
            "credential preflight should fail before driver materialization"
        );
    }

    #[tokio::test]
    async fn freeze_after_reproduce_preserves_lockfile_resolved_policy() {
        let root = unique_root("agentenv-freeze-reproduced-pinned-policy");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
        discovery_config.installed_root = root.join("drivers");
        let driver_artifacts =
            crate::driver_artifact::discover_driver_artifacts(discovery_config, None)
                .expect("discover driver artifacts");
        let mut lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: "source-demo".to_owned(),
                blueprint_yaml: yaml.to_owned(),
                driver_artifacts,
            },
        )
        .expect("build portable lockfile");
        lockfile
            .policy
            .resolved
            .network
            .allow
            .push(agentenv_proto::NetworkRule {
                target: NetworkTarget::Host {
                    host: "frozen-pinned.example".to_owned(),
                    port: Some(443),
                    scheme: Some("https".to_owned()),
                    http_access: None,
                },
            });
        let lockfile_yaml = lockfile
            .to_yaml_deterministic()
            .expect("render portable lockfile");
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::reproduce_env(
            &options,
            &TinyFactory,
            &mut credentials,
            "renamed-demo",
            &lockfile_yaml,
        )
        .await
        .expect("reproduce env");

        let persisted_lock =
            fs::read_to_string(root.join("envs").join("renamed-demo").join("lock.yaml"))
                .expect("read persisted lockfile");
        assert!(persisted_lock.contains("version: 0.2.0"));
        assert!(persisted_lock.contains("name: renamed-demo"));
        assert!(!persisted_lock.contains("name: source-demo"));
        assert!(persisted_lock.contains("frozen-pinned.example"));

        let frozen = super::freeze_env_lockfile(&options, "renamed-demo").expect("freeze env");

        assert!(frozen.contains("name: renamed-demo"));
        assert!(frozen.contains("resolved:"));
        assert!(frozen.contains("frozen-pinned.example"));
    }

    #[tokio::test]
    async fn freeze_after_reproduce_accepts_legacy_lockfile_without_hardening() {
        let root = unique_root("agentenv-freeze-legacy-no-hardening");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
        discovery_config.installed_root = root.join("drivers");
        let driver_artifacts =
            crate::driver_artifact::discover_driver_artifacts(discovery_config, None)
                .expect("discover driver artifacts");
        let mut lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: "source-demo".to_owned(),
                blueprint_yaml: yaml.to_owned(),
                driver_artifacts,
            },
        )
        .expect("build portable lockfile");
        lockfile.composition.sandbox.extra.remove("hardening");
        lockfile.blueprint_hash = crate::lifecycle::portable_blueprint_hash(&lockfile.composition)
            .expect("recompute legacy blueprint hash");
        let registry = agentenv_policy::PresetRegistry::load_builtin().expect("load presets");
        lockfile.policy.resolved = agentenv_policy::compose_policy(
            agentenv_policy::Tier::Restricted,
            &[],
            None,
            &registry,
        )
        .expect("compose legacy policy");
        lockfile
            .policy
            .resolved
            .network
            .allow
            .push(agentenv_proto::NetworkRule {
                target: NetworkTarget::Host {
                    host: "legacy-pinned.example".to_owned(),
                    port: Some(443),
                    scheme: Some("https".to_owned()),
                    http_access: None,
                },
            });
        let lockfile_yaml = lockfile
            .to_yaml_deterministic()
            .expect("render portable lockfile");
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::reproduce_env(
            &options,
            &TinyFactory,
            &mut credentials,
            "legacy-demo",
            &lockfile_yaml,
        )
        .await
        .expect("reproduce env");

        let frozen = super::freeze_env_lockfile(&options, "legacy-demo").expect("freeze env");

        assert!(frozen.contains("legacy-pinned.example"));
        assert!(
            !frozen.contains("hardening: baseline"),
            "freezing a reproduced legacy lockfile should preserve absent hardening"
        );
    }

    #[tokio::test]
    async fn freeze_preserves_created_context_required_policy_for_reproduce() {
        let root = unique_root("agentenv-freeze-context-required-policy");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let frozen_context_rule = agentenv_proto::NetworkRule {
            target: NetworkTarget::Host {
                host: "frozen-context.example".to_owned(),
                port: Some(443),
                scheme: Some("https".to_owned()),
                http_access: None,
            },
        };
        let recomputed_context_rule = agentenv_proto::NetworkRule {
            target: NetworkTarget::Host {
                host: "recomputed-context.example".to_owned(),
                port: Some(443),
                scheme: Some("https".to_owned()),
                http_access: None,
            },
        };
        let create_tracker = Arc::new(AgentSetupTracker::default());
        let create_factory = RequiredRuleFactory {
            tracker: Arc::clone(&create_tracker),
            required_rule: frozen_context_rule.clone(),
        };
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        super::create_env(
            &options,
            &create_factory,
            &mut credentials,
            "source-demo",
            yaml,
        )
        .await
        .expect("create env");

        let frozen = super::freeze_env_lockfile(&options, "source-demo").expect("freeze env");
        let crate::lockfile::LockfileDocument::Portable(lockfile) =
            crate::lockfile::LockfileDocument::from_yaml(&frozen).expect("parse frozen lockfile")
        else {
            panic!("freeze should render a portable lockfile");
        };
        assert!(lockfile
            .policy
            .resolved
            .network
            .allow
            .contains(&frozen_context_rule));

        let reproduce_tracker = Arc::new(AgentSetupTracker::default());
        let reproduce_factory = RequiredRuleFactory {
            tracker: Arc::clone(&reproduce_tracker),
            required_rule: recomputed_context_rule.clone(),
        };
        super::reproduce_env(
            &options,
            &reproduce_factory,
            &mut credentials,
            "replayed-demo",
            &frozen,
        )
        .await
        .expect("reproduce env");

        let create_policies = reproduce_tracker
            .create_policies
            .lock()
            .expect("create policy tracker")
            .clone();
        assert_eq!(create_policies.len(), 1);
        assert!(create_policies[0]
            .network
            .allow
            .contains(&frozen_context_rule));
        assert!(!create_policies[0]
            .network
            .allow
            .contains(&recomputed_context_rule));
    }

    #[tokio::test]
    async fn freeze_env_rejects_portable_lockfile_with_stale_composition() {
        let root = unique_root("agentenv-freeze-stale-portable-composition");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let blueprint_a = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: ./current
policy:
  tier: restricted
  presets: []
"#;
        let blueprint_b = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: ./stale
policy:
  tier: restricted
  presets: []
"#;
        let mut credentials = super::tests_support::EmptyCredentialProvider;
        super::create_env(
            &options,
            &TinyFactory,
            &mut credentials,
            "demo",
            blueprint_a,
        )
        .await
        .expect("create env");
        let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
        discovery_config.installed_root = root.join("drivers");
        let driver_artifacts =
            crate::driver_artifact::discover_driver_artifacts(discovery_config, None)
                .expect("discover driver artifacts");
        let stale_lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: "demo".to_owned(),
                blueprint_yaml: blueprint_b.to_owned(),
                driver_artifacts,
            },
        )
        .expect("build stale lockfile")
        .to_yaml_deterministic()
        .expect("render stale lockfile");
        fs::write(
            root.join("envs").join("demo").join("lock.yaml"),
            stale_lockfile,
        )
        .expect("write stale persisted lockfile");

        let err = super::freeze_env_lockfile(&options, "demo").expect_err("freeze should fail");

        assert!(
            err.to_string()
                .contains("portable lockfile composition does not match env blueprint"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn create_env_preserves_existing_hidden_env_name_during_reservation() {
        let root = unique_root("agentenv-hidden-reservation");
        let hidden_env_dir = root.join("envs").join(".demo.creating");
        fs::create_dir_all(&hidden_env_dir).unwrap();
        fs::write(hidden_env_dir.join("sentinel"), "keep me").unwrap();

        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let result = super::create_env(&options, &TinyFactory, &mut credentials, "demo", yaml)
            .await
            .unwrap();

        assert_eq!(
            result.admission.status,
            crate::admission::AdmissionStatus::Accepted
        );
        assert!(hidden_env_dir.join("sentinel").is_file());
        assert!(root.join("envs").join("demo").join("state.json").is_file());
    }

    #[tokio::test]
    async fn create_env_rejects_unknown_policy_tier() {
        let root = unique_root("agentenv-unknown-tier");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: balanceed
  presets: []
"#;
        let mut credentials = super::tests_support::EmptyCredentialProvider;

        let err = super::create_env(&options, &TinyFactory, &mut credentials, "demo", yaml)
            .await
            .unwrap_err();

        assert!(matches!(err, RuntimeError::InvalidPolicyTier { .. }));
        assert!(!root.join("envs").join("demo").exists());
    }

    #[tokio::test]
    async fn create_env_rolls_back_provisioned_resources_on_sandbox_create_failure() {
        let root = unique_root("agentenv-rollback");
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
inference:
  driver: passthrough
policy:
  tier: restricted
  presets: []
"#;
        let mut credentials = super::tests_support::EmptyCredentialProvider;
        let tracker = Arc::new(RollbackTracker::default());
        let factory = RollbackFactory {
            tracker: Arc::clone(&tracker),
        };

        let err = super::create_env(&options, &factory, &mut credentials, "demo", yaml)
            .await
            .unwrap_err();

        assert!(matches!(err, RuntimeError::Driver(_)));
        assert!(tracker.context_teardown_called.load(Ordering::SeqCst));
        assert!(tracker.inference_teardown_called.load(Ordering::SeqCst));
        assert!(!tracker.sandbox_destroy_called.load(Ordering::SeqCst));
        assert!(!root.join("envs").join("demo").exists());
    }

    #[test]
    fn policy_overrides_url_allow_uses_host_rule() {
        let overrides = vec![crate::blueprint::PolicyOverride {
            allow: Some("https://example.com".to_owned()),
            deny: None,
            approval: Some("https://example.com/api".to_owned()),
            extra: BTreeMap::new(),
        }];

        let section = crate::blueprint::PolicySection {
            tier: "restricted".to_owned(),
            presets: Vec::new(),
            overrides,
            dns: None,
            extra: BTreeMap::new(),
        };
        let policy = super::policy_overrides(&section)
            .unwrap()
            .expect("expected overrides policy");

        match &policy.network.allow[0].target {
            NetworkTarget::Host {
                host,
                port,
                scheme,
                http_access,
            } => {
                assert_eq!(host, "example.com");
                assert_eq!(*port, Some(443));
                assert_eq!(scheme.as_deref(), Some("https"));
                assert_eq!(*http_access, None);
            }
            other => panic!("unexpected allow target: {other:?}"),
        }

        match &policy.network.approval_required[0].target {
            NetworkTarget::HttpMethodPath { host, method, path } => {
                assert_eq!(host.as_deref(), Some("example.com"));
                assert_eq!(method, "*");
                assert_eq!(path, "/api");
            }
            other => panic!("unexpected approval target: {other:?}"),
        }
    }

    fn bad_initialize_result(
        kind: DriverKind,
        protocol_version: &str,
        capabilities: Capabilities,
    ) -> InitializeResult {
        InitializeResult {
            driver: DriverInfo {
                name: format!("{kind:?}").to_lowercase(),
                kind,
                version: "0.0.1-alpha0".to_owned(),
                protocol_version: protocol_version.to_owned(),
            },
            capabilities,
        }
    }

    struct HandshakeSandboxDriver {
        init_result: InitializeResult,
    }

    #[async_trait]
    impl SandboxDriver for HandshakeSandboxDriver {
        async fn initialize(
            &mut self,
            _params: InitializeParams,
        ) -> DriverResult<InitializeResult> {
            Ok(self.init_result.clone())
        }

        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }
        async fn create(
            &self,
            _spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            Ok(agentenv_proto::SandboxHandle {
                handle: "sb-1".to_owned(),
            })
        }
        async fn connect(
            &self,
            _params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            Ok(agentenv_proto::ShellHandle {
                session_id: "sh-1".to_owned(),
                tty: true,
                working_dir: None,
            })
        }
        async fn exec(
            &self,
            _params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            Ok(agentenv_proto::ExecResult {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
        async fn copy_in(
            &self,
            _params: agentenv_proto::CopyInParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn copy_out(
            &self,
            _params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn apply_policy(
            &self,
            _params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            Ok(agentenv_proto::ApplyPolicyResult {
                hot_reloaded: false,
            })
        }
        async fn status(
            &self,
            _params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            Ok(agentenv_proto::SandboxStatus {
                phase: agentenv_proto::SandboxPhase::Running,
                healthy: true,
                last_ping: None,
            })
        }
        async fn logs(
            &self,
            _params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            Ok(agentenv_proto::LogsResult {
                entries: Vec::new(),
            })
        }
        async fn logs_stream(
            &self,
            _params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn stop(&self, _params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn destroy(
            &self,
            _params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn shutdown(
            &mut self,
            _params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
    }

    #[tokio::test]
    async fn initialize_sandbox_driver_rejects_wrong_protocol() {
        let mut driver = HandshakeSandboxDriver {
            init_result: bad_initialize_result(
                DriverKind::Sandbox,
                "0.0.0",
                Capabilities::Sandbox(SandboxCapabilities {
                    supports_hot_reload_policy: true,
                    supports_filesystem_lockdown: true,
                    supports_syscall_filter: true,
                    supports_native_inference_routing: true,
                    supports_remote_host: false,
                    supports_host_egress_proxy: false,
                    supports_persistent_sessions: false,
                    supports_dns_egress_control: false,
                    supports_snapshots: false,
                    supports_fork: false,
                }),
            ),
        };
        let options = RuntimeOptions {
            root: std::env::temp_dir(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };

        let err = initialize_sandbox_driver(&options, &mut driver)
            .await
            .unwrap_err();
        assert!(matches!(err, RuntimeError::Driver(_)));
    }

    #[tokio::test]
    async fn initialize_sandbox_driver_rejects_wrong_kind_or_capabilities() {
        let options = RuntimeOptions {
            root: std::env::temp_dir(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };

        let mut wrong_kind = HandshakeSandboxDriver {
            init_result: bad_initialize_result(
                DriverKind::Context,
                SCHEMA_VERSION,
                Capabilities::Context(ContextCapabilities {
                    is_remote: false,
                    is_shared: false,
                    supports_zones: false,
                    supports_snapshots: false,
                }),
            ),
        };
        let mut wrong_capabilities = HandshakeSandboxDriver {
            init_result: bad_initialize_result(
                DriverKind::Sandbox,
                SCHEMA_VERSION,
                Capabilities::Context(ContextCapabilities {
                    is_remote: false,
                    is_shared: false,
                    supports_zones: false,
                    supports_snapshots: false,
                }),
            ),
        };

        let wrong_kind = initialize_sandbox_driver(&options, &mut wrong_kind)
            .await
            .unwrap_err();
        let wrong_capabilities = initialize_sandbox_driver(&options, &mut wrong_capabilities)
            .await
            .unwrap_err();

        assert!(matches!(
            wrong_kind,
            RuntimeError::InvalidDriverHandshake { .. }
        ));
        assert!(matches!(
            wrong_capabilities,
            RuntimeError::InvalidDriverHandshake { .. }
        ));
    }

    #[test]
    fn component_spec_preserves_conversion_errors() {
        let bad_yaml = "pkg:\n  ? [foo, bar]: value\n";
        let extra: BTreeMap<String, serde_yaml::Value> =
            serde_yaml::from_str(bad_yaml).expect("test yaml parse");

        let err = component_spec(extra).unwrap_err();
        match err {
            RuntimeError::ComponentConfigConversion { key, .. } => {
                assert_eq!(key, "pkg");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn runtime_secret_masks_secret_in_logs() {
        let secret = RuntimeSecret::new("super-secret-value".to_owned());

        assert_eq!(secret.expose_secret(), "super-secret-value");
        assert!(!format!("{:?}", secret).contains("super-secret-value"));
        assert!(!format!("{}", secret).contains("super-secret-value"));
    }

    #[test]
    fn factory_trait_builds_driver_set() {
        let selection = super::DriverSelection {
            sandbox: "openshell".to_owned(),
            agent: "codex".to_owned(),
            context: "filesystem".to_owned(),
            inference: None,
        };
        let set = TinyFactory.build(&selection).unwrap();
        let _set: Arc<str> = Arc::from(selection.agent.as_str());
        drop(set);
    }

    async fn command_test_runtime(label: &str) -> (RuntimeOptions, TinyFactory) {
        let root = unique_root(&format!("agentenv-command-{label}"));
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let mut credentials = super::tests_support::EmptyCredentialProvider;
        super::create_env(&options, &TinyFactory, &mut credentials, "demo", yaml)
            .await
            .unwrap();

        (options, TinyFactory)
    }

    async fn session_test_runtime(label: &str) -> (RuntimeOptions, SessionFactory) {
        create_session_test_runtime(label, SessionFactory).await
    }

    async fn stale_session_test_runtime(label: &str) -> (RuntimeOptions, StaleSessionFactory) {
        create_session_test_runtime(label, StaleSessionFactory).await
    }

    async fn create_session_test_runtime<F>(label: &str, factory: F) -> (RuntimeOptions, F)
    where
        F: DriverFactory,
    {
        let root = unique_root(&format!("agentenv-session-{label}"));
        let options = RuntimeOptions {
            root: root.clone(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let mut credentials = super::tests_support::EmptyCredentialProvider;
        super::create_env(&options, &factory, &mut credentials, "demo", yaml)
            .await
            .unwrap();

        (options, factory)
    }

    struct SessionFactory;

    impl DriverFactory for SessionFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(SessionSandboxDriver {
                    report_sessions: true,
                }),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    struct StaleSessionFactory;

    impl DriverFactory for StaleSessionFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(SessionSandboxDriver {
                    report_sessions: false,
                }),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    struct MissingSessionBackendFactory {
        tracker: Arc<AgentSetupTracker>,
    }

    impl DriverFactory for MissingSessionBackendFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(MissingSessionBackendSandboxDriver {
                    tracker: Arc::clone(&self.tracker),
                }),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    struct MissingSessionBackendSandboxDriver {
        tracker: Arc<AgentSetupTracker>,
    }

    struct SessionSandboxDriver {
        report_sessions: bool,
    }

    #[async_trait]
    impl SandboxDriver for SessionSandboxDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            let mut result = TinySandboxDriver.initialize(params).await?;
            if let Capabilities::Sandbox(capabilities) = &mut result.capabilities {
                capabilities.supports_persistent_sessions = true;
            }
            Ok(result)
        }

        async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
            TinySandboxDriver.preflight(params).await
        }

        async fn create(
            &self,
            spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            TinySandboxDriver.create(spec).await
        }

        async fn connect(
            &self,
            params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            TinySandboxDriver.connect(params).await
        }

        async fn create_session(
            &self,
            params: agentenv_proto::CreateSessionParams,
        ) -> DriverResult<agentenv_proto::SessionHandle> {
            Ok(agentenv_proto::SessionHandle {
                session_id: "sh-1".to_owned(),
                name: params.name,
                status: if params.detached {
                    agentenv_proto::SessionStatus::Detached
                } else {
                    agentenv_proto::SessionStatus::Attached
                },
                created_at: "2026-04-24T17:00:00Z".to_owned(),
                updated_at: "2026-04-24T17:00:00Z".to_owned(),
                command: params.command,
                working_dir: Some("/sandbox".to_owned()),
            })
        }

        async fn attach_session(
            &self,
            _params: agentenv_proto::AttachSessionParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            Ok(agentenv_proto::ExecResult {
                status: 0,
                stdout: "attached\n".to_owned(),
                stderr: String::new(),
            })
        }

        async fn list_sessions(
            &self,
            _params: agentenv_proto::ListSessionsParams,
        ) -> DriverResult<agentenv_proto::ListSessionsResult> {
            if !self.report_sessions {
                return Ok(agentenv_proto::ListSessionsResult {
                    sessions: Vec::new(),
                });
            }

            Ok(agentenv_proto::ListSessionsResult {
                sessions: vec![agentenv_proto::SessionHandle {
                    session_id: "sh-1".to_owned(),
                    name: "demo".to_owned(),
                    status: agentenv_proto::SessionStatus::Detached,
                    created_at: "2026-04-24T17:00:00Z".to_owned(),
                    updated_at: "2026-04-24T17:00:00Z".to_owned(),
                    command: super::AGENT_ENTRYPOINT_PATH.to_owned(),
                    working_dir: Some("/sandbox".to_owned()),
                }],
            })
        }

        async fn kill_session(
            &self,
            _params: agentenv_proto::KillSessionParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn exec(
            &self,
            params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            TinySandboxDriver.exec(params).await
        }

        async fn copy_in(&self, params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_in(params).await
        }

        async fn copy_out(
            &self,
            params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_out(params).await
        }

        async fn apply_policy(
            &self,
            params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            TinySandboxDriver.apply_policy(params).await
        }

        async fn status(
            &self,
            params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            TinySandboxDriver.status(params).await
        }

        async fn logs(
            &self,
            params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            TinySandboxDriver.logs(params).await
        }

        async fn logs_stream(
            &self,
            params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.logs_stream(params).await
        }

        async fn stop(&self, params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.stop(params).await
        }

        async fn destroy(
            &self,
            params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.destroy(params).await
        }

        async fn shutdown(
            &mut self,
            params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            let mut inner = TinySandboxDriver;
            inner.shutdown(params).await
        }
    }

    #[async_trait]
    impl SandboxDriver for MissingSessionBackendSandboxDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            let mut result = TinySandboxDriver.initialize(params).await?;
            if let Capabilities::Sandbox(capabilities) = &mut result.capabilities {
                capabilities.supports_persistent_sessions = true;
            }
            Ok(result)
        }

        async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
            TinySandboxDriver.preflight(params).await
        }

        async fn create(
            &self,
            spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            TinySandboxDriver.create(spec).await
        }

        async fn connect(
            &self,
            params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            TinySandboxDriver.connect(params).await
        }

        async fn create_session(
            &self,
            _params: agentenv_proto::CreateSessionParams,
        ) -> DriverResult<agentenv_proto::SessionHandle> {
            Err(crate::driver::persistent_sessions_missing())
        }

        async fn attach_session(
            &self,
            _params: agentenv_proto::AttachSessionParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            Ok(agentenv_proto::ExecResult {
                status: 0,
                stdout: "attached\n".to_owned(),
                stderr: String::new(),
            })
        }

        async fn list_sessions(
            &self,
            _params: agentenv_proto::ListSessionsParams,
        ) -> DriverResult<agentenv_proto::ListSessionsResult> {
            Ok(agentenv_proto::ListSessionsResult {
                sessions: Vec::new(),
            })
        }

        async fn kill_session(
            &self,
            _params: agentenv_proto::KillSessionParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }

        async fn exec(
            &self,
            params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            self.tracker
                .exec_cmds
                .lock()
                .expect("exec tracker")
                .push(params.cmd.clone());
            TinySandboxDriver.exec(params).await
        }

        async fn copy_in(&self, params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_in(params).await
        }

        async fn copy_out(
            &self,
            params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.copy_out(params).await
        }

        async fn apply_policy(
            &self,
            params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            TinySandboxDriver.apply_policy(params).await
        }

        async fn status(
            &self,
            params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            TinySandboxDriver.status(params).await
        }

        async fn logs(
            &self,
            params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            TinySandboxDriver.logs(params).await
        }

        async fn logs_stream(
            &self,
            params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.logs_stream(params).await
        }

        async fn stop(&self, params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            TinySandboxDriver.stop(params).await
        }

        async fn destroy(
            &self,
            params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            TinySandboxDriver.destroy(params).await
        }

        async fn shutdown(
            &mut self,
            params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            let mut inner = TinySandboxDriver;
            inner.shutdown(params).await
        }
    }

    #[tokio::test]
    async fn exec_env_returns_sandbox_exec_result() {
        let (options, factory) = command_test_runtime("exec").await;
        let result = super::exec_env(
            &options,
            &factory,
            "demo",
            vec!["echo".to_owned(), "ok".to_owned()],
        )
        .await
        .unwrap();

        assert_eq!(result.status, 0);
        assert_eq!(result.stdout, "ok\n");
    }

    #[tokio::test]
    async fn exec_env_observed_emits_exec_event() {
        let (options, factory) = command_test_runtime("exec-observed").await;
        let events = RecordingEventEmitter::default();
        let fake_secret = "sk-test-value-that-must-not-persist";
        let result = super::exec_env_observed(
            &options,
            &factory,
            "demo",
            vec!["echo".to_owned(), fake_secret.to_owned()],
            Arc::new(events.clone()),
        )
        .await
        .unwrap();

        assert_eq!(result.status, 0);

        let recorded = events.recorded();
        assert_eq!(recorded.len(), 1);
        let event = &recorded[0];
        assert_eq!(event.kind, ActivityKind::Exec);
        assert_eq!(event.result, ActivityResult::Ok);
        assert_eq!(event.env.as_deref(), Some("demo"));
        assert_eq!(event.actor["kind"], serde_json::json!("core"));
        assert_eq!(event.subject["handle"], serde_json::json!("sb-1"));
        assert_eq!(event.subject["command_argc"], serde_json::json!(2));
        assert!(!event.subject.contains_key("command"));
        assert!(!event.trace_id.is_empty());

        let rendered = serde_json::to_string(&recorded).unwrap();
        assert!(!rendered.contains(fake_secret));
        assert!(!rendered.contains("echo"));
    }

    #[tokio::test]
    async fn exec_env_initializes_sandbox_driver_before_command() {
        let (options, _) = command_test_runtime("exec-init").await;
        let sandbox_initialized = Arc::new(AtomicBool::new(false));
        let factory = InitializingFactory {
            sandbox_initialized: Arc::clone(&sandbox_initialized),
        };

        super::exec_env(
            &options,
            &factory,
            "demo",
            vec!["echo".to_owned(), "ok".to_owned()],
        )
        .await
        .unwrap();

        assert!(sandbox_initialized.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn enter_env_returns_shell_handle() {
        let (options, factory) = session_test_runtime("enter").await;
        let shell = super::enter_env(&options, &factory, "demo", true, false)
            .await
            .unwrap();

        let super::EnterResult::Detached(shell) = shell else {
            panic!("detached enter should return a shell handle");
        };
        assert_eq!(shell.session_id, "sh-1");
        assert!(shell.tty);
    }

    #[tokio::test]
    async fn enter_env_attaches_to_agent_entrypoint_when_not_detached() {
        let root = unique_root("agentenv-enter-attached");
        let options = RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
        let tracker = Arc::new(AgentSetupTracker::default());
        let factory = AgentSetupFactory {
            tracker: Arc::clone(&tracker),
        };
        let mut credentials = super::tests_support::EmptyCredentialProvider;
        super::create_env(&options, &factory, &mut credentials, "demo", yaml)
            .await
            .unwrap();
        tracker.exec_cmds.lock().expect("exec tracker").clear();

        let result = super::enter_env(&options, &factory, "demo", false, false)
            .await
            .unwrap();

        let super::EnterResult::Attached(result) = result else {
            panic!("attached enter should return an exec result");
        };
        assert_eq!(result.status, 0);
        assert_eq!(
            tracker.exec_cmds.lock().expect("exec tracker").as_slice(),
            &[super::AGENT_ENTRYPOINT_PATH.to_owned()]
        );
    }

    #[tokio::test]
    async fn enter_env_falls_back_to_exec_when_session_backend_is_missing() {
        let tracker = Arc::new(AgentSetupTracker::default());
        let factory = MissingSessionBackendFactory {
            tracker: Arc::clone(&tracker),
        };
        let (options, factory) =
            create_session_test_runtime("enter-missing-session-backend", factory).await;
        tracker.exec_cmds.lock().expect("exec tracker").clear();

        let result = super::enter_env(&options, &factory, "demo", false, false)
            .await
            .unwrap();

        let super::EnterResult::Attached(result) = result else {
            panic!("foreground enter fallback should return an exec result");
        };
        assert_eq!(result.status, 0);
        assert_eq!(
            tracker.exec_cmds.lock().expect("exec tracker").as_slice(),
            &[super::AGENT_ENTRYPOINT_PATH.to_owned()]
        );
    }

    #[tokio::test]
    async fn enter_env_preserves_missing_session_backend_error_for_detach_and_new() {
        let tracker = Arc::new(AgentSetupTracker::default());
        let factory = MissingSessionBackendFactory { tracker };
        let (options, factory) =
            create_session_test_runtime("enter-missing-session-backend-required", factory).await;

        for (detach, new_session) in [(true, false), (false, true)] {
            let err = super::enter_env(&options, &factory, "demo", detach, new_session)
                .await
                .expect_err("required session operation should not fall back");
            assert!(matches!(
                err,
                RuntimeError::Driver(crate::driver::DriverError::CapabilityMissing { capability })
                    if capability == "supports_persistent_sessions"
            ));
        }
    }

    #[tokio::test]
    async fn enter_detach_creates_and_persists_default_session() {
        let (options, factory) = session_test_runtime("enter-detach-session").await;
        let result = super::enter_env(&options, &factory, "demo", true, false)
            .await
            .unwrap();
        let super::EnterResult::Detached(shell) = result else {
            panic!("expected detached session");
        };
        assert_eq!(shell.session_id, "sh-1");

        let env_name = crate::env::validate_env_name("demo").unwrap();
        let paths = crate::env::EnvPaths::new(options.root.clone(), env_name);
        let sessions = crate::sessions::read_sessions(&paths, "demo").unwrap();
        assert_eq!(sessions.default_session_id.as_deref(), Some("sh-1"));
        assert_eq!(sessions.sessions.len(), 1);
    }

    #[tokio::test]
    async fn resume_env_attaches_default_session() {
        let (options, factory) = session_test_runtime("resume-default-session").await;
        super::enter_env(&options, &factory, "demo", true, false)
            .await
            .unwrap();
        let result = super::resume_env(&options, &factory, "demo", None)
            .await
            .unwrap();
        assert_eq!(result.status, 0);
    }

    #[tokio::test]
    async fn list_sessions_marks_missing_live_persisted_sessions_unknown() {
        let (options, factory) = stale_session_test_runtime("list-stale-session").await;
        super::enter_env(&options, &factory, "demo", true, false)
            .await
            .unwrap();

        let rows = super::list_sessions_env(&options, &factory, Some("demo"))
            .await
            .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].session_id, "sh-1");
        assert_eq!(rows[0].status, agentenv_proto::SessionStatus::Unknown);

        let env_name = crate::env::validate_env_name("demo").unwrap();
        let paths = crate::env::EnvPaths::new(options.root.clone(), env_name);
        let sessions = crate::sessions::read_sessions(&paths, "demo").unwrap();
        assert_eq!(
            sessions.sessions[0].status,
            agentenv_proto::SessionStatus::Unknown
        );
    }

    #[tokio::test]
    async fn resume_env_rejects_non_live_default_session() {
        let (options, factory) = stale_session_test_runtime("resume-non-live").await;
        super::enter_env(&options, &factory, "demo", true, false)
            .await
            .unwrap();

        let env_name = crate::env::validate_env_name("demo").unwrap();
        let paths = crate::env::EnvPaths::new(options.root.clone(), env_name);
        let mut sessions = crate::sessions::read_sessions(&paths, "demo").unwrap();
        sessions.sessions[0].status = agentenv_proto::SessionStatus::Killed;
        crate::sessions::write_sessions(&paths, &sessions).unwrap();

        let err = super::resume_env(&options, &factory, "demo", None)
            .await
            .expect_err("non-live default session should not attach");

        assert!(matches!(
            err,
            RuntimeError::Driver(crate::driver::DriverError::InvalidHandle { handle, message })
                if handle == "sh-1" && message.contains("not live")
        ));
    }

    #[tokio::test]
    async fn list_sessions_revives_unknown_session_reported_live_by_driver() {
        let (options, factory) = session_test_runtime("list-revived-session").await;
        super::enter_env(&options, &factory, "demo", true, false)
            .await
            .unwrap();

        let env_name = crate::env::validate_env_name("demo").unwrap();
        let paths = crate::env::EnvPaths::new(options.root.clone(), env_name);
        let mut sessions = crate::sessions::read_sessions(&paths, "demo").unwrap();
        sessions.sessions[0].name = "custom session name".to_owned();
        sessions.sessions[0].status = agentenv_proto::SessionStatus::Unknown;
        crate::sessions::write_sessions(&paths, &sessions).unwrap();

        let rows = super::list_sessions_env(&options, &factory, Some("demo"))
            .await
            .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].session_id, "sh-1");
        assert_eq!(rows[0].name, "custom session name");
        assert_eq!(rows[0].status, agentenv_proto::SessionStatus::Detached);

        let sessions = crate::sessions::read_sessions(&paths, "demo").unwrap();
        assert_eq!(sessions.default_session_id.as_deref(), Some("sh-1"));
        assert_eq!(sessions.sessions[0].name, "custom session name");
        assert_eq!(
            sessions.sessions[0].status,
            agentenv_proto::SessionStatus::Detached
        );
    }

    #[tokio::test]
    async fn reconcile_preserves_core_session_id_when_driver_id_matches() {
        let (options, factory) = session_test_runtime("reconcile-core-id").await;
        let env_name = crate::env::validate_env_name("demo").unwrap();
        let paths = crate::env::EnvPaths::new(options.root.clone(), env_name);

        let mut sessions = crate::sessions::empty_session_file("demo");
        crate::sessions::upsert_session(
            &mut sessions,
            crate::sessions::PersistedSession {
                id: "core-default".to_owned(),
                driver_session_id: "sh-1".to_owned(),
                name: "custom session name".to_owned(),
                status: agentenv_proto::SessionStatus::Unknown,
                command: super::AGENT_ENTRYPOINT_PATH.to_owned(),
                created_at: "2026-04-24T17:00:00Z".to_owned(),
                updated_at: "2026-04-24T17:00:00Z".to_owned(),
                working_dir: Some("/sandbox".to_owned()),
                metadata: BTreeMap::new(),
            },
            true,
        );
        crate::sessions::write_sessions(&paths, &sessions).unwrap();

        let rows = super::list_sessions_env(&options, &factory, Some("demo"))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].session_id, "core-default");
        assert_eq!(rows[0].name, "custom session name");
        assert_eq!(rows[0].status, agentenv_proto::SessionStatus::Detached);

        let sessions = crate::sessions::read_sessions(&paths, "demo").unwrap();
        assert_eq!(sessions.default_session_id.as_deref(), Some("core-default"));
        assert_eq!(sessions.sessions.len(), 1);
        assert_eq!(sessions.sessions[0].id, "core-default");
        assert_eq!(sessions.sessions[0].driver_session_id, "sh-1");
        assert_eq!(sessions.sessions[0].name, "custom session name");

        let mut sessions = crate::sessions::empty_session_file("demo");
        crate::sessions::upsert_session(
            &mut sessions,
            crate::sessions::PersistedSession {
                id: "core-default".to_owned(),
                driver_session_id: "sh-1".to_owned(),
                name: "custom session name".to_owned(),
                status: agentenv_proto::SessionStatus::Unknown,
                command: super::AGENT_ENTRYPOINT_PATH.to_owned(),
                created_at: "2026-04-24T17:00:00Z".to_owned(),
                updated_at: "2026-04-24T17:00:00Z".to_owned(),
                working_dir: Some("/sandbox".to_owned()),
                metadata: BTreeMap::new(),
            },
            true,
        );
        crate::sessions::write_sessions(&paths, &sessions).unwrap();

        let result = super::resume_env(&options, &factory, "demo", None)
            .await
            .unwrap();
        assert_eq!(result.status, 0);

        let sessions = crate::sessions::read_sessions(&paths, "demo").unwrap();
        assert_eq!(sessions.default_session_id.as_deref(), Some("core-default"));
        assert_eq!(sessions.sessions.len(), 1);
        assert_eq!(sessions.sessions[0].id, "core-default");
        assert_eq!(sessions.sessions[0].driver_session_id, "sh-1");
        assert_eq!(
            sessions.sessions[0].status,
            agentenv_proto::SessionStatus::Detached
        );
    }

    #[tokio::test]
    async fn resume_env_rejects_stale_live_default_session() {
        let (options, factory) = stale_session_test_runtime("resume-stale-live").await;
        super::enter_env(&options, &factory, "demo", true, false)
            .await
            .unwrap();

        let err = super::resume_env(&options, &factory, "demo", None)
            .await
            .expect_err("stale live default session should not attach");

        assert!(matches!(
            err,
            RuntimeError::Driver(crate::driver::DriverError::InvalidHandle { handle, message })
                if handle == "sh-1" && message.contains("not live")
        ));

        let env_name = crate::env::validate_env_name("demo").unwrap();
        let paths = crate::env::EnvPaths::new(options.root.clone(), env_name);
        let sessions = crate::sessions::read_sessions(&paths, "demo").unwrap();
        assert_eq!(
            sessions.sessions[0].status,
            agentenv_proto::SessionStatus::Unknown
        );
    }

    #[tokio::test]
    async fn enter_detach_without_session_support_returns_capability_missing() {
        let (options, factory) = command_test_runtime("enter-detach-unsupported").await;
        let err = super::enter_env(&options, &factory, "demo", true, false)
            .await
            .expect_err("unsupported detached enter should fail");

        assert!(matches!(
            err,
            RuntimeError::Driver(crate::driver::DriverError::CapabilityMissing { capability })
                if capability == "supports_persistent_sessions"
        ));
    }

    #[tokio::test]
    async fn destroy_env_skips_session_cleanup_without_session_support() {
        let (options, _) = command_test_runtime("destroy-session-unsupported").await;
        let env_name = crate::env::validate_env_name("demo").unwrap();
        let paths = crate::env::EnvPaths::new(options.root.clone(), env_name);
        let mut sessions = crate::sessions::empty_session_file("demo");
        crate::sessions::upsert_session(
            &mut sessions,
            crate::sessions::PersistedSession {
                id: "sh-1".to_owned(),
                driver_session_id: "sh-1".to_owned(),
                name: "demo".to_owned(),
                status: agentenv_proto::SessionStatus::Detached,
                command: super::AGENT_ENTRYPOINT_PATH.to_owned(),
                created_at: "2026-04-24T17:00:00Z".to_owned(),
                updated_at: "2026-04-24T17:00:00Z".to_owned(),
                working_dir: Some("/sandbox".to_owned()),
                metadata: BTreeMap::new(),
            },
            true,
        );
        crate::sessions::write_sessions(&paths, &sessions).unwrap();

        let kill_called = Arc::new(AtomicBool::new(false));
        let factory = KillTrackingUnsupportedSessionFactory {
            kill_called: Arc::clone(&kill_called),
        };

        super::destroy_env(&options, &factory, "demo")
            .await
            .unwrap();

        assert!(!kill_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn logs_env_returns_sandbox_logs() {
        let (options, factory) = command_test_runtime("logs").await;
        let logs = super::logs_env(&options, &factory, "demo", false)
            .await
            .unwrap();

        assert!(logs.entries.is_empty());
    }

    #[tokio::test]
    async fn start_logs_stream_env_uses_sandbox_streaming_path() {
        let (options, _) = command_test_runtime("logs-stream").await;
        let tracker = Arc::new(StreamTracker::default());
        let factory = StreamFactory {
            tracker: Arc::clone(&tracker),
        };

        let guard = super::start_logs_stream_env(&options, &factory, "demo")
            .await
            .unwrap();

        assert!(tracker.logs_stream_called.load(Ordering::SeqCst));
        assert!(!tracker.logs_called.load(Ordering::SeqCst));
        drop(guard);
    }

    #[tokio::test]
    async fn status_env_reports_healthy_sandbox() {
        let (options, factory) = command_test_runtime("status").await;
        let status = super::status_env(&options, &factory, "demo").await.unwrap();

        assert!(status.healthy);
        assert!(status.sandbox.as_ref().unwrap().healthy);
        assert_eq!(
            serde_json::to_value(&status).unwrap()["sandbox"]["healthy"],
            serde_json::json!(true)
        );
    }

    #[tokio::test]
    async fn status_env_without_sandbox_handle_returns_unhealthy_summary() {
        let (options, factory) = command_test_runtime("status-missing-handle").await;
        let paths = crate::env::EnvPaths::new(
            options.root.clone(),
            crate::env::validate_env_name("demo").unwrap(),
        );
        let mut state = crate::env::read_state(&paths).unwrap();
        state.handles.sandbox = None;
        crate::env::write_state(&paths, &state).unwrap();

        let status = super::status_env(&options, &factory, "demo").await.unwrap();

        assert!(!status.healthy);
        assert!(status.sandbox.is_none());
        assert!(status.context.as_ref().unwrap().healthy);
    }

    #[tokio::test]
    async fn status_env_without_context_handle_returns_unhealthy_summary() {
        let (options, factory) = command_test_runtime("status-missing-context").await;
        let paths = crate::env::EnvPaths::new(
            options.root.clone(),
            crate::env::validate_env_name("demo").unwrap(),
        );
        let mut state = crate::env::read_state(&paths).unwrap();
        state.handles.context = None;
        crate::env::write_state(&paths, &state).unwrap();

        let status = super::status_env(&options, &factory, "demo").await.unwrap();

        assert!(!status.healthy);
        assert!(status.sandbox.as_ref().unwrap().healthy);
        assert!(status.context.is_none());
    }

    #[tokio::test]
    async fn destroy_env_removes_registry_on_success() {
        let (options, factory) = command_test_runtime("destroy").await;
        let report = super::destroy_env(&options, &factory, "demo")
            .await
            .unwrap();

        assert_eq!(report.status, crate::admission::AdmissionStatus::Accepted);
        assert_eq!(report.reason_code, crate::admission::ReasonCode::Destroyed);
        assert!(!options.root.join("envs").join("demo").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn destroy_env_stops_persisted_egress_proxy_process() {
        let (options, factory) = command_test_runtime("destroy-egress-proxy").await;
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 30")
            .spawn()
            .expect("spawn fake proxy");
        let pid = child.id();
        let paths = crate::env::EnvPaths::new(
            options.root.clone(),
            crate::env::validate_env_name("demo").unwrap(),
        );
        let mut state = crate::env::read_state(&paths).unwrap();
        state.egress_proxy = Some(crate::env::EgressProxyState {
            pid: Some(pid),
            listen_url: "http://127.0.0.1:31099".parse().unwrap(),
            config_path: paths.env_dir().join("egress-proxy").join("config.json"),
            policy_path: paths.env_dir().join("egress-proxy").join("policy.json"),
            routes: vec!["openai".to_owned()],
        });
        crate::env::write_state(&paths, &state).unwrap();

        let report = super::destroy_env(&options, &factory, "demo")
            .await
            .unwrap();

        assert_eq!(report.status, crate::admission::AdmissionStatus::Accepted);
        assert_eq!(report.reason_code, crate::admission::ReasonCode::Destroyed);
        for _ in 0..20 {
            if child.try_wait().expect("poll fake proxy").is_some() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let _ = child.kill();
        panic!("destroy should stop persisted egress proxy pid {pid}");
    }

    #[tokio::test]
    async fn destroy_env_removes_registry_without_sandbox_handle() {
        let (options, factory) = command_test_runtime("destroy-missing-handle").await;
        let paths = crate::env::EnvPaths::new(
            options.root.clone(),
            crate::env::validate_env_name("demo").unwrap(),
        );
        let mut state = crate::env::read_state(&paths).unwrap();
        state.handles.sandbox = None;
        crate::env::write_state(&paths, &state).unwrap();

        let report = super::destroy_env(&options, &factory, "demo")
            .await
            .unwrap();

        assert_eq!(report.status, crate::admission::AdmissionStatus::Accepted);
        assert_eq!(report.reason_code, crate::admission::ReasonCode::Destroyed);
        assert!(!options.root.join("envs").join("demo").exists());
    }

    #[tokio::test]
    async fn destroy_env_persists_sandbox_progress_before_sidecar_failure() {
        let (options, _) = command_test_runtime("destroy-progress").await;
        let sandbox_destroyed = Arc::new(AtomicBool::new(false));
        let factory = FailingContextTeardownFactory {
            sandbox_destroyed: Arc::clone(&sandbox_destroyed),
        };

        let err = super::destroy_env(&options, &factory, "demo")
            .await
            .unwrap_err();

        assert!(err.to_string().contains("context teardown failed"));
        assert!(sandbox_destroyed.load(Ordering::SeqCst));

        let paths = crate::env::EnvPaths::new(
            options.root.clone(),
            crate::env::validate_env_name("demo").unwrap(),
        );
        let state = crate::env::read_state(&paths).unwrap();
        assert!(state.handles.sandbox.is_none());
        assert_eq!(state.handles.context.as_deref(), Some("ctx-1"));
    }

    #[tokio::test]
    async fn destroy_env_observed_emits_sandbox_destroy_error_for_sidecar_failure() {
        let (options, _) = command_test_runtime("destroy-observed-sidecar-failure").await;
        let sandbox_destroyed = Arc::new(AtomicBool::new(false));
        let factory = FailingContextTeardownFactory {
            sandbox_destroyed: Arc::clone(&sandbox_destroyed),
        };
        let events = RecordingEventEmitter::default();

        let err = super::destroy_env_observed(&options, &factory, "demo", Arc::new(events.clone()))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("context teardown failed"));
        assert!(sandbox_destroyed.load(Ordering::SeqCst));

        let recorded = events.recorded();
        assert!(recorded.iter().any(|event| {
            event.kind == ActivityKind::SandboxDestroy && event.result == ActivityResult::Ok
        }));
        let failure = recorded
            .iter()
            .find(|event| {
                event.kind == ActivityKind::SandboxDestroy && event.result == ActivityResult::Error
            })
            .expect("sandbox destroy terminal failure event");
        assert_eq!(
            failure.reason_code.as_deref(),
            Some(crate::admission::ReasonCode::DriverCommandFailed.as_str())
        );
    }

    #[tokio::test]
    async fn destroy_env_preserves_registry_when_inference_handle_has_no_driver() {
        let (options, factory) = command_test_runtime("destroy-missing-inference-driver").await;
        let paths = crate::env::EnvPaths::new(
            options.root.clone(),
            crate::env::validate_env_name("demo").unwrap(),
        );
        let mut state = crate::env::read_state(&paths).unwrap();
        state.drivers.inference =
            Some(crate::env::DriverRecord::new("passthrough", "0.0.1-alpha0"));
        state.handles.inference = Some("inf-1".to_owned());
        crate::env::write_state(&paths, &state).unwrap();

        let err = super::destroy_env(&options, &factory, "demo")
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            RuntimeError::MissingSelectedDriver { kind: "inference", name } if name == "passthrough"
        ));
        assert!(options.root.join("envs").join("demo").exists());
        let state = crate::env::read_state(&paths).unwrap();
        assert_eq!(state.handles.sandbox.as_deref(), Some("sb-1"));
        assert_eq!(state.handles.inference.as_deref(), Some("inf-1"));
    }

    #[tokio::test]
    async fn exec_env_requires_persisted_sandbox_handle() {
        let (options, factory) = command_test_runtime("missing-handle").await;
        let paths = crate::env::EnvPaths::new(
            options.root.clone(),
            crate::env::validate_env_name("demo").unwrap(),
        );
        let mut state = crate::env::read_state(&paths).unwrap();
        state.handles.sandbox = None;
        crate::env::write_state(&paths, &state).unwrap();

        let err = super::exec_env(
            &options,
            &factory,
            "demo",
            vec!["echo".to_owned(), "ok".to_owned()],
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            RuntimeError::MissingSandboxHandle { name } if name == "demo"
        ));
    }
}
