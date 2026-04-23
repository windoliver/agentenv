use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use agentenv_policy::{compose_policy, PresetRegistry, PresetSelection, Tier};
use agentenv_proto::{
    AgentSpec, Capabilities, ContextSpec, DriverKind, InferenceSpec, InitializeParams,
    InitializeResult, LogLevel, PreflightParams, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    driver::{
        ensure_protocol_compatible, AgentDriver, ContextDriver, DriverError, InferenceDriver,
        SandboxDriver,
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
                },
            );
        }
        Ok(Self { pins })
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

pub struct DriverSet {
    pub sandbox: Box<dyn SandboxDriver>,
    pub agent: Box<dyn AgentDriver>,
    pub context: Box<dyn ContextDriver>,
    pub inference: Option<Box<dyn InferenceDriver>>,
}

pub trait DriverFactory {
    fn build(&self, selection: &DriverSelection) -> RuntimeResult<DriverSet>;

    fn build_pinned(
        &self,
        selection: &DriverSelection,
        _pins: &DriverPinSet,
    ) -> RuntimeResult<DriverSet> {
        self.build(selection)
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
    #[error("unsupported driver `{name}` for {kind}")]
    UnsupportedDriver { kind: &'static str, name: String },
    #[error("unknown policy tier `{tier}`")]
    InvalidPolicyTier { tier: String },
    #[error("missing credential `{name}`")]
    MissingCredential { name: String },
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EnvDescription {
    pub state: crate::env::EnvStateFile,
    pub blueprint_yaml: String,
    pub lock_yaml: String,
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
    sandbox: Option<(&'a dyn SandboxDriver, String)>,
    context: Option<(&'a dyn ContextDriver, String)>,
    inference: Option<(&'a dyn InferenceDriver, String)>,
}

impl<'a> CreateEnvRollback<'a> {
    fn new(temp_workspace: PathBuf) -> Self {
        Self {
            temp_workspace,
            sandbox: None,
            context: None,
            inference: None,
        }
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

    async fn rollback(&self) {
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
        let _ = fs::remove_dir_all(&self.temp_workspace);
    }
}

static CREATE_WORKSPACE_SEQ: AtomicU64 = AtomicU64::new(0);
const AGENT_ENTRYPOINT_PATH: &str = "/sandbox/.agentenv/bin/agentenv-agent";

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

pub async fn run_preflight_only(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    env: &str,
    selection: &DriverSelection,
) -> RuntimeResult<crate::admission::AdmissionReport> {
    run_preflight_with_pins(options, factory, env, selection, None).await
}

async fn run_preflight_with_pins(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    env: &str,
    selection: &DriverSelection,
    pins: Option<&DriverPinSet>,
) -> RuntimeResult<crate::admission::AdmissionReport> {
    let mut set = build_driver_set(factory, selection, pins)?;
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
) -> RuntimeResult<DriverSet> {
    match pins {
        Some(pins) if !pins.is_empty() => factory.build_pinned(selection, pins),
        _ => factory.build(selection),
    }
}

pub async fn create_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    credentials: &mut dyn CredentialProvider,
    name: &str,
    blueprint_yaml: &str,
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
    )
    .await
}

async fn create_env_with_input(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    credentials: &mut dyn CredentialProvider,
    input: CreateEnvInput<'_>,
) -> RuntimeResult<CreateResult> {
    let name = input.name;
    let blueprint_yaml = input.blueprint_yaml;
    let env_name = crate::env::validate_env_name(name)?;
    let paths = crate::env::EnvPaths::new(options.root.clone(), env_name.clone());
    let env_dir = paths.env_dir();
    if env_dir.exists() {
        return Err(crate::env::EnvError::AlreadyExists {
            name: name.to_owned(),
        }
        .into());
    }

    let resolved = match input.resolved_blueprint {
        Some(resolved) => resolved,
        None => crate::lifecycle::verify_blueprint_yaml(blueprint_yaml)?,
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
    let admission = run_preflight_with_pins(
        options,
        factory,
        name,
        &selection,
        input.driver_pins.as_ref(),
    )
    .await?;
    if admission.status == crate::admission::AdmissionStatus::Rejected {
        return Ok(CreateResult {
            admission,
            state: empty_state(name, selection),
            state_path: paths.state_path(),
        });
    }

    let mut set = build_driver_set(factory, &selection, input.driver_pins.as_ref())?;
    let temp_workspace = create_temp_workspace(&options.root, env_name.as_str());
    let temp_paths = crate::env::EnvPaths::new(temp_workspace.clone(), env_name.clone());
    let mut rollback = CreateEnvRollback::new(temp_workspace.clone());

    let result = async {
        initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
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

        let mut env = BTreeMap::new();
        let mut credential_names = Vec::new();
        for requirement in requirements {
            credential_names.push(requirement.name.clone());
            if let Some(value) = credentials.resolve(&requirement)? {
                env.insert(requirement.name, value.expose_secret().to_owned());
            } else if requirement.required {
                return Err(RuntimeError::MissingCredential {
                    name: requirement.name,
                });
            }
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
        fs::write(temp_paths.lock_path(), lock_yaml).map_err(|source| {
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
        let agent_setup = prepare_agent_sandbox_setup(
            &temp_workspace,
            set.agent.as_ref(),
            agent_spec.clone(),
            vec![context_endpoint.clone()],
        )
        .await?;
        let context_network_rules = set
            .context
            .required_network_rules(agentenv_proto::ContextHandleRequest {
                handle: context_handle.handle.clone(),
            })
            .await?;

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
                policy_overrides(&resolved.blueprint.policy.overrides)?,
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
        if input.resolved_policy.is_none() {
            policy.network.allow.extend(context_network_rules.rules);
        }

        let create_policy = create_policy_for_agent_install(&policy, &agent_setup);
        let restore_policy_after_install = create_policy != policy;

        let sandbox_handle = set
            .sandbox
            .create(agentenv_proto::SandboxSpec {
                image: None,
                env,
                policy: Some(create_policy),
                metadata: BTreeMap::new(),
            })
            .await?;
        let sandbox_handle_value = sandbox_handle.handle.clone();
        rollback.set_sandbox(set.sandbox.as_ref(), sandbox_handle_value.clone());
        install_agent_in_sandbox(set.sandbox.as_ref(), &sandbox_handle_value, &agent_setup).await?;
        if restore_policy_after_install {
            set.sandbox
                .apply_policy(agentenv_proto::ApplyPolicyParams {
                    handle: sandbox_handle_value.clone(),
                    policy: policy.clone(),
                })
                .await?;
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

        let state = crate::env::EnvStateFile {
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
                context_mcp: Some(crate::env::PersistedMcpEndpoint::from_mcp(context_endpoint)),
                inference: inference_endpoint,
            },
            resolved_policy: Some(policy.clone()),
            credential_names,
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
        let _ = fs::remove_dir_all(&temp_workspace);

        Ok(CreateResult {
            admission: crate::admission::AdmissionReport::accepted(name),
            state,
            state_path: paths.state_path(),
        })
    }
    .await;

    if result.is_err() {
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

pub fn freeze_env_lockfile(options: &RuntimeOptions, name: &str) -> RuntimeResult<String> {
    let description = describe_env(options, name)?;
    let mut discovery_config = crate::driver_catalog::DriverDiscoveryConfig::from_env();
    discovery_config.installed_root = options.root.join("drivers");
    let driver_artifacts =
        crate::driver_artifact::discover_driver_artifacts(discovery_config, None)?;

    if let crate::lockfile::LockfileDocument::Portable(mut lockfile) =
        crate::lockfile::LockfileDocument::from_yaml(&description.lock_yaml)?
    {
        let expected_lockfile = crate::portable_lockfile::build_portable_lockfile(
            crate::portable_lockfile::PortableLockfileInput {
                name: description.state.name.clone(),
                blueprint_yaml: description.blueprint_yaml.clone(),
                driver_artifacts: driver_artifacts.clone(),
            },
        )?;
        if lockfile.composition != expected_lockfile.composition
            || lockfile.blueprint_hash != expected_lockfile.blueprint_hash
            || lockfile.policy.declared != expected_lockfile.composition.policy
        {
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

    check_required_lockfile_credentials(credentials, &lockfile)?;
    let credential_bindings = credential_bindings_from_portable_lockfile(&lockfile);
    let blueprint_yaml = blueprint_yaml_from_portable_lockfile(&lockfile)?;
    let artifact_registry = registry_from_driver_artifacts(&driver_artifacts);
    let resolved_blueprint =
        crate::lifecycle::verify_blueprint_yaml_with_registry(&blueprint_yaml, &artifact_registry)?;
    let driver_pins = DriverPinSet::from_portable_lockfile(&lockfile)?;
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
    )
    .await
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
        if credential.required == Some(false) {
            continue;
        }

        let reference = credential.reference.as_deref().unwrap_or(name);
        match credential.source.as_str() {
            "env" if std::env::var_os(reference).is_none() => {
                return Err(RuntimeError::MissingCredential {
                    name: reference.to_owned(),
                });
            }
            "credstore" => match credentials.backend_name(reference)? {
                Some(backend) if is_credstore_backend(&backend) => {}
                _ => {
                    return Err(RuntimeError::MissingCredential {
                        name: reference.to_owned(),
                    });
                }
            },
            _ => {}
        }
    }

    Ok(())
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
            "env" => match std::env::var(&binding.reference) {
                Ok(value) => Ok(Some(RuntimeSecret::new(value))),
                Err(_) if requirement.required => Err(RuntimeError::MissingCredential {
                    name: binding.reference.clone(),
                }),
                Err(_) => Ok(None),
            },
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
    let state = describe_env(options, name)?.state;
    let selection = selection_from_state(&state);
    let handle = required_sandbox_handle(&state, name)?;
    let mut set = factory.build(&selection)?;
    initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;

    set.sandbox
        .exec(agentenv_proto::ExecParams {
            handle,
            cmd: command.join(" "),
            tty: false,
            env: BTreeMap::new(),
        })
        .await
        .map_err(Into::into)
}

pub async fn enter_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
    detach: bool,
) -> RuntimeResult<EnterResult> {
    let state = describe_env(options, name)?.state;
    let selection = selection_from_state(&state);
    let handle = required_sandbox_handle(&state, name)?;
    let mut set = factory.build(&selection)?;
    initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;

    if detach {
        let shell = set
            .sandbox
            .connect(agentenv_proto::ConnectParams { handle })
            .await?;
        return Ok(EnterResult::Detached(shell));
    }

    let result = set
        .sandbox
        .exec(agentenv_proto::ExecParams {
            handle,
            cmd: AGENT_ENTRYPOINT_PATH.to_owned(),
            tty: true,
            env: BTreeMap::new(),
        })
        .await?;
    Ok(EnterResult::Attached(result))
}

pub async fn status_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
) -> RuntimeResult<EnvStatusSummary> {
    let state = describe_env(options, name)?.state;
    let selection = selection_from_state(&state);
    let mut set = factory.build(&selection)?;

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
    if follow {
        let _guard = start_logs_stream_env(options, factory, name).await?;
        return Ok(agentenv_proto::LogsResult {
            entries: Vec::new(),
        });
    }

    let state = describe_env(options, name)?.state;
    let selection = selection_from_state(&state);
    let handle = required_sandbox_handle(&state, name)?;
    let mut set = factory.build(&selection)?;
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

pub async fn destroy_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
) -> RuntimeResult<crate::admission::AdmissionReport> {
    let mut state = describe_env(options, name)?.state;
    let selection = selection_from_state(&state);
    let mut set = factory.build(&selection)?;
    let paths =
        crate::env::EnvPaths::new(options.root.clone(), crate::env::validate_env_name(name)?);

    if state.handles.inference.is_some() && set.inference.is_none() {
        return Err(missing_inference_driver(&state));
    }

    if let Some(handle) = state.handles.sandbox.clone() {
        initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
        set.sandbox
            .destroy(agentenv_proto::DestroyParams { handle })
            .await?;
        state.handles.sandbox = None;
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

fn required_sandbox_handle(state: &crate::env::EnvStateFile, name: &str) -> RuntimeResult<String> {
    state
        .handles
        .sandbox
        .clone()
        .ok_or_else(|| RuntimeError::MissingSandboxHandle {
            name: name.to_owned(),
        })
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
    overrides: &[crate::blueprint::PolicyOverride],
) -> RuntimeResult<Option<agentenv_proto::NetworkPolicy>> {
    if overrides.is_empty() {
        return Ok(None);
    }

    let mut policy = empty_policy_override();
    for item in overrides {
        if let Some(allow) = item.allow.as_ref() {
            policy.network.allow.push(policy_override_network_rule(
                allow,
                PolicyOverrideTargetKind::AllowOrDeny,
            ));
        }
        if let Some(deny) = item.deny.as_ref() {
            policy.network.deny.push(policy_override_network_rule(
                deny,
                PolicyOverrideTargetKind::AllowOrDeny,
            ));
        }
        if let Some(approval) = item.approval.as_ref() {
            policy
                .network
                .approval_required
                .push(policy_override_network_rule(
                    approval,
                    PolicyOverrideTargetKind::Approval,
                ));
        }
    }

    Ok(Some(policy))
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
            Arc, Mutex,
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    use agentenv_proto::{
        Capabilities, ContextCapabilities, DriverInfo, DriverKind, EmptyResult,
        InferenceCapabilities, InitializeParams, InitializeResult, LogLevel, NetworkTarget,
        PreflightParams, PreflightResult, SandboxCapabilities, SCHEMA_VERSION,
    };
    use async_trait::async_trait;

    use crate::driver::{ContextDriver, DriverResult, InferenceDriver, SandboxDriver};

    use super::{
        component_spec, initialize_context_driver, initialize_sandbox_driver, DriverFactory,
        DriverSet, RuntimeError, RuntimeOptions, RuntimeSecret,
    };

    fn unique_root(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
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
            resolved_policy: None,
            credential_names: Vec::new(),
            health: BTreeMap::new(),
            first_enter_hint_shown: false,
        }
    }

    fn write_state_json(env_dir: &std::path::Path, state: crate::env::EnvStateFile) {
        fs::create_dir_all(env_dir).unwrap();
        let rendered = serde_json::to_string_pretty(&state).unwrap();
        fs::write(env_dir.join("state.json"), rendered).unwrap();
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

    #[derive(Default)]
    struct AgentSetupTracker {
        copied_paths: Mutex<Vec<String>>,
        exec_cmds: Mutex<Vec<String>>,
        create_policies: Mutex<Vec<agentenv_proto::NetworkPolicy>>,
        applied_policies: Mutex<Vec<agentenv_proto::NetworkPolicy>>,
        preinstall_probe_succeeds: AtomicBool,
    }

    struct AgentSetupFactory {
        tracker: Arc<AgentSetupTracker>,
    }

    impl DriverFactory for AgentSetupFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(AgentSetupSandboxDriver {
                    tracker: Arc::clone(&self.tracker),
                }),
                agent: Box::new(AgentSetupAgentDriver),
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
                }),
                agent: Box::new(AgentSetupAgentDriver),
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

    struct AgentSetupAgentDriver;

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
            _spec: agentenv_proto::AgentSpec,
        ) -> DriverResult<agentenv_proto::InstallStepsResult> {
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
            _params: agentenv_proto::RenderMcpConfigParams,
        ) -> DriverResult<agentenv_proto::RenderMcpConfigResult> {
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
                requirements: Vec::new(),
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
    }

    #[async_trait]
    impl SandboxDriver for AgentSetupSandboxDriver {
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

        let policy = super::policy_overrides(&overrides)
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
        let (options, factory) = command_test_runtime("enter").await;
        let shell = super::enter_env(&options, &factory, "demo", true)
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

        let result = super::enter_env(&options, &factory, "demo", false)
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
