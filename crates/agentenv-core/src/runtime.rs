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

pub struct DriverSet {
    pub sandbox: Box<dyn SandboxDriver>,
    pub agent: Box<dyn AgentDriver>,
    pub context: Box<dyn ContextDriver>,
    pub inference: Option<Box<dyn InferenceDriver>>,
}

pub trait DriverFactory {
    fn build(&self, selection: &DriverSelection) -> RuntimeResult<DriverSet>;
}

pub trait CredentialProvider {
    fn resolve(
        &mut self,
        requirement: &agentenv_proto::CredentialRequirement,
    ) -> RuntimeResult<Option<RuntimeSecret>>;
    fn backend_name(&self, name: &str) -> RuntimeResult<Option<String>>;
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
    Lifecycle(#[from] crate::lifecycle::LifecycleError),
    #[error("unsupported driver `{name}` for {kind}")]
    UnsupportedDriver { kind: &'static str, name: String },
    #[error("unknown policy tier `{tier}`")]
    InvalidPolicyTier { tier: String },
    #[error("missing credential `{name}`")]
    MissingCredential { name: String },
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
}

pub type RuntimeResult<T> = Result<T, RuntimeError>;

#[derive(Debug, Clone)]
pub struct CreateResult {
    pub admission: crate::admission::AdmissionReport,
    pub state: crate::env::EnvStateFile,
    pub state_path: PathBuf,
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
    let mut set = factory.build(selection)?;
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

pub async fn create_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    credentials: &mut dyn CredentialProvider,
    name: &str,
    blueprint_yaml: &str,
) -> RuntimeResult<CreateResult> {
    let env_name = crate::env::validate_env_name(name)?;
    let paths = crate::env::EnvPaths::new(options.root.clone(), env_name.clone());
    let env_dir = paths.env_dir();
    if env_dir.exists() {
        return Err(crate::env::EnvError::AlreadyExists {
            name: name.to_owned(),
        }
        .into());
    }

    let resolved = crate::lifecycle::verify_blueprint_yaml(blueprint_yaml)?;
    let lock_yaml = crate::lifecycle::freeze_from_blueprint_yaml(blueprint_yaml)?;
    let selection = DriverSelection {
        sandbox: resolved.sandbox.driver.clone(),
        agent: resolved.agent.driver.clone(),
        context: resolved.context.driver.clone(),
        inference: resolved
            .inference
            .as_ref()
            .map(|driver| driver.driver.clone()),
    };
    let admission = run_preflight_only(options, factory, name, &selection).await?;
    if admission.status == crate::admission::AdmissionStatus::Rejected {
        return Ok(CreateResult {
            admission,
            state: empty_state(name, selection),
            state_path: paths.state_path(),
        });
    }

    let mut set = factory.build(&selection)?;
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
            .credential_requirements(agent_spec)
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

        let mut policy = compose_policy(
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
        })?;
        policy.network.allow.extend(context_network_rules.rules);

        let sandbox_handle = set
            .sandbox
            .create(agentenv_proto::SandboxSpec {
                image: None,
                env,
                policy: Some(policy),
                metadata: BTreeMap::new(),
            })
            .await?;
        rollback.set_sandbox(set.sandbox.as_ref(), sandbox_handle.handle.clone());

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
            atomic::{AtomicBool, Ordering},
            Arc,
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
}
