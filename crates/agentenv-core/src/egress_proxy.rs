use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use agentenv_proto::{CredentialRequirement, NetworkPolicy};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::process::{Child, Command};
use url::Url;

const BROKERED_DUMMY_VALUE: &str = "agentenv-brokered";
pub const EGRESS_PROXY_BIN_ENV: &str = "AGENTENV_EGRESS_PROXY_BIN";
const DEFAULT_EGRESS_PROXY_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const OPENAI_CREDENTIAL: &str = "OPENAI_API_KEY";
const ANTHROPIC_CREDENTIAL: &str = "ANTHROPIC_API_KEY";
const GITHUB_CREDENTIAL: &str = "GITHUB_TOKEN";
const GH_CREDENTIAL: &str = "GH_TOKEN";
const DEFAULT_MCP_CREDENTIAL: &str = "MCP_TOKEN";
const DEFAULT_OPENAI_RATE_LIMIT: u32 = 60;
const DEFAULT_ANTHROPIC_RATE_LIMIT: u32 = 60;
const DEFAULT_GITHUB_RATE_LIMIT: u32 = 120;
const DEFAULT_MCP_RATE_LIMIT: u32 = 120;
const DEFAULT_OCI_RATE_LIMIT: u32 = 240;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialDisposition {
    Brokered,
    SandboxEnv,
    UnusedOptional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrokerService {
    OpenAi,
    Anthropic,
    GitHub,
    Mcp { route_id: String },
    Oci { registry: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokeredCredential {
    pub name: String,
    pub route_id: String,
    pub route_credential_name: String,
    pub service: BrokerService,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerRoute {
    pub id: String,
    pub service: BrokerService,
    #[serde(with = "url_serde")]
    pub upstream_base_url: Url,
    pub credential_name: String,
    pub request_path_prefix: String,
    pub allowed_hosts: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_guard: Option<agentenv_proto::McpGuardConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplicitEgressRoutes {
    #[serde(default)]
    pub github: bool,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub oci_registries: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rate_limits: BTreeMap<String, EgressProxyRateLimit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpProxySource {
    pub route_id: String,
    pub upstream_url: Url,
    pub token_credential_name: Option<String>,
    pub guard_config: Option<agentenv_proto::McpGuardConfig>,
}

#[derive(Debug, Clone)]
pub struct EgressProxyPlanInput {
    pub env_name: String,
    pub proxy_base_url: Url,
    pub credential_requirements: Vec<CredentialRequirement>,
    pub network_policy: NetworkPolicy,
    pub context_mcp: Option<McpProxySource>,
    pub inference_endpoint: Option<Url>,
    pub explicit_routes: ExplicitEgressRoutes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressProxyPlan {
    pub env_name: String,
    #[serde(with = "url_serde")]
    pub listen_url: Url,
    #[serde(with = "url_serde")]
    pub sandbox_base_url: Url,
    pub sandbox_env: BTreeMap<String, String>,
    pub routes: Vec<BrokerRoute>,
    pub credential_dispositions: BTreeMap<String, CredentialDisposition>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub brokered_credentials: BTreeMap<String, BrokeredCredential>,
    #[serde(
        default,
        with = "optional_url_serde",
        skip_serializing_if = "Option::is_none"
    )]
    pub rewritten_context_mcp_url: Option<Url>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_policy_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rate_limits: BTreeMap<String, EgressProxyRateLimit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressProxyLaunchConfig {
    pub env_name: String,
    #[serde(with = "url_serde")]
    pub listen_url: Url,
    pub routes: Vec<BrokerRoute>,
    pub credential_names: Vec<String>,
    pub policy_path: PathBuf,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rate_limits: BTreeMap<String, EgressProxyRateLimit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressProxyRateLimit {
    pub requests_per_minute: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressProxyLaunchFiles {
    pub config_path: PathBuf,
    pub policy_path: PathBuf,
}

#[derive(Debug)]
pub struct EgressProxyProcess {
    pub pid: u32,
    pub child: Child,
}

#[derive(Debug, Error)]
pub enum EgressProxyPlanError {
    #[error("invalid proxy URL: {0}")]
    InvalidProxyUrl(String),
}

#[derive(Debug, Error)]
pub enum EgressProxyLaunchError {
    #[error("egress proxy launch file IO error at `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to serialize egress proxy launch file `{path}`: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to locate current executable for egress proxy launch: {source}")]
    CurrentExe {
        #[source]
        source: std::io::Error,
    },
    #[error("current executable path for egress proxy launch is not a file: `{path}`")]
    InvalidCurrentExe { path: PathBuf },
    #[error("egress proxy binary from {env_var} is not a file: `{path}`")]
    InvalidProxyBinary {
        env_var: &'static str,
        path: PathBuf,
    },
    #[error("failed to spawn egress proxy process `{program}`: {source}")]
    Spawn {
        program: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("egress proxy launch config `{path}` has invalid listen URL `{listen_url}`")]
    InvalidListenUrl { path: PathBuf, listen_url: Url },
    #[error("egress proxy process `{program}` exited during startup with status {status}")]
    ExitedDuringStartup {
        program: PathBuf,
        status: std::process::ExitStatus,
    },
    #[error("egress proxy process {pid} did not listen on {listen_url} within {timeout:?}")]
    StartupTimeout {
        pid: u32,
        listen_url: Url,
        timeout: Duration,
    },
    #[error("spawned egress proxy process did not report a pid")]
    MissingPid,
    #[error("failed to stop egress proxy process {pid}: {source}")]
    Stop {
        pid: u32,
        #[source]
        source: std::io::Error,
    },
    #[error("timed out waiting {timeout:?} for egress proxy process {pid} to stop")]
    StopTimeout { pid: u32, timeout: Duration },
}

impl EgressProxyPlan {
    pub fn credential_disposition(&self, name: &str) -> Option<CredentialDisposition> {
        self.credential_dispositions.get(name).copied()
    }

    pub fn brokered_credential(&self, name: &str) -> Option<&BrokeredCredential> {
        self.brokered_credentials.get(name)
    }

    pub fn context_mcp_url(&self) -> Option<&Url> {
        self.rewritten_context_mcp_url.as_ref()
    }
}

pub fn prepare_egress_proxy_launch_files<N>(
    env_name: impl AsRef<str>,
    env_dir: impl AsRef<Path>,
    plan: &EgressProxyPlan,
    credential_names: impl IntoIterator<Item = N>,
    network_policy: &NetworkPolicy,
) -> Result<EgressProxyLaunchFiles, EgressProxyLaunchError>
where
    N: AsRef<str>,
{
    let launch_dir = env_dir.as_ref().join("egress-proxy");
    fs::create_dir_all(&launch_dir).map_err(|source| EgressProxyLaunchError::Io {
        path: launch_dir.clone(),
        source,
    })?;

    let config_path = launch_dir.join("config.json");
    let policy_path = launch_dir.join("policy.json");
    let mut credential_names = credential_names
        .into_iter()
        .map(|name| name.as_ref().to_owned())
        .collect::<Vec<_>>();
    credential_names.sort();
    credential_names.dedup();

    let config = EgressProxyLaunchConfig {
        env_name: env_name.as_ref().to_owned(),
        listen_url: plan.listen_url.clone(),
        routes: plan.routes.clone(),
        credential_names,
        policy_path: policy_path.clone(),
        rate_limits: rate_limits_for_routes(&plan.routes, &plan.rate_limits),
    };

    write_json_atomically(&policy_path, network_policy)?;
    write_json_atomically(&config_path, &config)?;

    Ok(EgressProxyLaunchFiles {
        config_path,
        policy_path,
    })
}

pub async fn start_egress_proxy_process(
    env_name: impl AsRef<str>,
    config_path: impl AsRef<Path>,
    events_db_path: impl AsRef<Path>,
) -> Result<EgressProxyProcess, EgressProxyLaunchError> {
    let uses_proxy_bin_override = env::var_os(EGRESS_PROXY_BIN_ENV).is_some();
    let listen_url = if uses_proxy_bin_override {
        None
    } else {
        Some(read_launch_listen_url(config_path.as_ref())?)
    };
    let program = egress_proxy_binary_path()?;
    let mut command = Command::new(&program);
    command
        .arg("proxy")
        .arg("run")
        .arg("--env")
        .arg(env_name.as_ref())
        .arg("--config")
        .arg(config_path.as_ref())
        .arg("--events-db")
        .arg(events_db_path.as_ref())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut child = command
        .spawn()
        .map_err(|source| EgressProxyLaunchError::Spawn {
            program: program.clone(),
            source,
        })?;
    let pid = child.id().ok_or(EgressProxyLaunchError::MissingPid)?;
    if let Some(listen_url) = listen_url {
        wait_for_proxy_listener(
            &mut child,
            pid,
            &program,
            config_path.as_ref(),
            &listen_url,
            Duration::from_secs(5),
        )
        .await?;
    } else {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if let Some(status) = child
            .try_wait()
            .map_err(|source| EgressProxyLaunchError::Stop { pid, source })?
        {
            return Err(EgressProxyLaunchError::ExitedDuringStartup { program, status });
        }
    }

    Ok(EgressProxyProcess { pid, child })
}

pub async fn stop_egress_proxy_process(
    handle: EgressProxyProcess,
) -> Result<(), EgressProxyLaunchError> {
    stop_egress_proxy_process_with_timeout(handle, DEFAULT_EGRESS_PROXY_STOP_TIMEOUT).await
}

pub async fn stop_egress_proxy_process_with_timeout(
    mut handle: EgressProxyProcess,
    timeout: Duration,
) -> Result<(), EgressProxyLaunchError> {
    let pid = handle.pid;
    if handle
        .child
        .try_wait()
        .map_err(|source| EgressProxyLaunchError::Stop { pid, source })?
        .is_some()
    {
        return Ok(());
    }

    if let Err(source) = handle.child.start_kill() {
        if let Ok(Some(_)) = handle.child.try_wait() {
            return Ok(());
        }
        return Err(EgressProxyLaunchError::Stop { pid, source });
    }

    match tokio::time::timeout(timeout, handle.child.wait()).await {
        Ok(Ok(_status)) => Ok(()),
        Ok(Err(source)) => Err(EgressProxyLaunchError::Stop { pid, source }),
        Err(_elapsed) => Err(EgressProxyLaunchError::StopTimeout { pid, timeout }),
    }
}

pub async fn stop_egress_proxy_pid(pid: u32) -> Result<(), EgressProxyLaunchError> {
    stop_egress_proxy_pid_with_timeout(pid, DEFAULT_EGRESS_PROXY_STOP_TIMEOUT).await
}

pub async fn stop_egress_proxy_pid_with_timeout(
    pid: u32,
    _timeout: Duration,
) -> Result<(), EgressProxyLaunchError> {
    terminate_process_pid(pid).await
}

pub fn build_egress_proxy_plan(
    input: EgressProxyPlanInput,
) -> Result<EgressProxyPlan, EgressProxyPlanError> {
    validate_proxy_base_url(&input.proxy_base_url)?;

    let sandbox_base_url = input.proxy_base_url;
    let proxy_base = sandbox_base_url.as_str().trim_end_matches('/').to_owned();
    let declared_names = input
        .credential_requirements
        .iter()
        .map(|requirement| requirement.name.clone())
        .collect::<BTreeSet<_>>();

    let mut routes = Vec::new();
    let mut sandbox_env = BTreeMap::new();
    let mut brokered_credentials = BTreeMap::new();

    if declared_names.contains(OPENAI_CREDENTIAL) {
        broker_credential(
            OPENAI_CREDENTIAL,
            "openai",
            OPENAI_CREDENTIAL,
            BrokerService::OpenAi,
            &mut brokered_credentials,
            &mut sandbox_env,
        );
        sandbox_env.insert(
            "OPENAI_BASE_URL".to_owned(),
            proxy_url_string(&proxy_base, "/v1/openai"),
        );
        routes.push(provider_route(
            "openai",
            BrokerService::OpenAi,
            "https://api.openai.com/v1",
            OPENAI_CREDENTIAL,
            "/v1/openai",
        )?);
    }

    if declared_names.contains(ANTHROPIC_CREDENTIAL) {
        broker_credential(
            ANTHROPIC_CREDENTIAL,
            "anthropic",
            ANTHROPIC_CREDENTIAL,
            BrokerService::Anthropic,
            &mut brokered_credentials,
            &mut sandbox_env,
        );
        sandbox_env.insert(
            "ANTHROPIC_BASE_URL".to_owned(),
            proxy_url_string(&proxy_base, "/v1/anthropic"),
        );
        routes.push(provider_route(
            "anthropic",
            BrokerService::Anthropic,
            "https://api.anthropic.com",
            ANTHROPIC_CREDENTIAL,
            "/v1/anthropic",
        )?);
    }

    if input.explicit_routes.github
        || declared_names.contains(GITHUB_CREDENTIAL)
        || declared_names.contains(GH_CREDENTIAL)
    {
        let github_credential = github_route_credential(&declared_names);
        broker_credential(
            github_credential,
            "github.api",
            github_credential,
            BrokerService::GitHub,
            &mut brokered_credentials,
            &mut sandbox_env,
        );
        for credential_name in [GITHUB_CREDENTIAL, GH_CREDENTIAL] {
            if declared_names.contains(credential_name) {
                broker_credential(
                    credential_name,
                    "github.api",
                    github_credential,
                    BrokerService::GitHub,
                    &mut brokered_credentials,
                    &mut sandbox_env,
                );
            }
        }
        sandbox_env.insert(
            "GITHUB_API_URL".to_owned(),
            proxy_url_string(&proxy_base, "/v1/github/api"),
        );
        sandbox_env.insert("GIT_CONFIG_COUNT".to_owned(), "1".to_owned());
        sandbox_env.insert(
            "GIT_CONFIG_KEY_0".to_owned(),
            format!(
                "url.{}.insteadOf",
                proxy_url_string(&proxy_base, "/v1/github/git/")
            ),
        );
        sandbox_env.insert(
            "GIT_CONFIG_VALUE_0".to_owned(),
            "https://github.com/".to_owned(),
        );
        routes.push(provider_route(
            "github.api",
            BrokerService::GitHub,
            "https://api.github.com",
            github_credential,
            "/v1/github/api",
        )?);
        routes.push(provider_route(
            "github.git",
            BrokerService::GitHub,
            "https://github.com",
            github_credential,
            "/v1/github/git",
        )?);
    }

    let rewritten_context_mcp_url = if let Some(source) = input.context_mcp {
        let credential_name = source
            .token_credential_name
            .unwrap_or_else(|| DEFAULT_MCP_CREDENTIAL.to_owned());
        let route_id = source.route_id;
        validate_mcp_route_id(&route_id)?;
        let request_path_prefix = format!("/v1/mcp/{route_id}");
        let rewritten_url = proxy_route_url(&proxy_base, &request_path_prefix)?;
        let route_plan_id = format!("mcp.{route_id}");
        let service = BrokerService::Mcp {
            route_id: route_id.clone(),
        };
        broker_credential(
            &credential_name,
            &route_plan_id,
            &credential_name,
            service.clone(),
            &mut brokered_credentials,
            &mut sandbox_env,
        );
        routes.push(BrokerRoute {
            id: route_plan_id,
            service,
            upstream_base_url: source.upstream_url.clone(),
            credential_name,
            request_path_prefix,
            allowed_hosts: allowed_hosts_for_url(&source.upstream_url),
            mcp_guard: source.guard_config,
        });
        Some(rewritten_url)
    } else {
        None
    };

    let mut planned_oci_registries = BTreeSet::new();
    for registry in input.explicit_routes.oci_registries {
        let registry = normalize_oci_registry(&registry)?;
        if !planned_oci_registries.insert(registry.registry.clone()) {
            continue;
        }

        let credential_name = format!("oci.{}", registry.registry);
        let route_id = format!("oci.{}", registry.registry);
        let request_path_prefix = format!("/v1/oci/{}", registry.registry);
        let service = BrokerService::Oci {
            registry: registry.registry.clone(),
        };
        broker_credential(
            &credential_name,
            &route_id,
            &credential_name,
            service.clone(),
            &mut brokered_credentials,
            &mut sandbox_env,
        );
        routes.push(BrokerRoute {
            id: route_id,
            service,
            upstream_base_url: registry.upstream_base_url.clone(),
            credential_name,
            request_path_prefix,
            allowed_hosts: allowed_hosts_for_url(&registry.upstream_base_url),
            mcp_guard: None,
        });
    }

    let mut credential_dispositions = BTreeMap::new();
    for requirement in input.credential_requirements {
        let disposition = if brokered_credentials.contains_key(&requirement.name) {
            CredentialDisposition::Brokered
        } else if requirement.required {
            CredentialDisposition::SandboxEnv
        } else {
            CredentialDisposition::UnusedOptional
        };

        credential_dispositions
            .entry(requirement.name)
            .and_modify(|existing| {
                *existing = merge_credential_disposition(*existing, disposition);
            })
            .or_insert(disposition);
    }

    for brokered_name in brokered_credentials.keys() {
        credential_dispositions.insert(brokered_name.clone(), CredentialDisposition::Brokered);
    }

    let rate_limits = rate_limits_for_routes(&routes, &input.explicit_routes.rate_limits);

    Ok(EgressProxyPlan {
        env_name: input.env_name,
        listen_url: sandbox_base_url.clone(),
        sandbox_base_url,
        sandbox_env,
        routes,
        credential_dispositions,
        brokered_credentials,
        rewritten_context_mcp_url,
        redacted_policy_path: None,
        rate_limits,
    })
}

fn rate_limits_for_routes(
    routes: &[BrokerRoute],
    overrides: &BTreeMap<String, EgressProxyRateLimit>,
) -> BTreeMap<String, EgressProxyRateLimit> {
    let mut limits = routes
        .iter()
        .map(|route| {
            (
                route.id.clone(),
                EgressProxyRateLimit {
                    requests_per_minute: default_rate_limit_for_service(&route.service),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    for (route_id, limit) in overrides {
        limits.insert(route_id.clone(), limit.clone());
    }
    limits
}

fn default_rate_limit_for_service(service: &BrokerService) -> u32 {
    match service {
        BrokerService::OpenAi => DEFAULT_OPENAI_RATE_LIMIT,
        BrokerService::Anthropic => DEFAULT_ANTHROPIC_RATE_LIMIT,
        BrokerService::GitHub => DEFAULT_GITHUB_RATE_LIMIT,
        BrokerService::Mcp { .. } => DEFAULT_MCP_RATE_LIMIT,
        BrokerService::Oci { .. } => DEFAULT_OCI_RATE_LIMIT,
    }
}

fn broker_credential(
    credential_name: &str,
    route_id: &str,
    route_credential_name: &str,
    service: BrokerService,
    brokered_credentials: &mut BTreeMap<String, BrokeredCredential>,
    sandbox_env: &mut BTreeMap<String, String>,
) {
    brokered_credentials.insert(
        credential_name.to_owned(),
        BrokeredCredential {
            name: credential_name.to_owned(),
            route_id: route_id.to_owned(),
            route_credential_name: route_credential_name.to_owned(),
            service,
        },
    );
    sandbox_env.insert(credential_name.to_owned(), BROKERED_DUMMY_VALUE.to_owned());
}

fn merge_credential_disposition(
    left: CredentialDisposition,
    right: CredentialDisposition,
) -> CredentialDisposition {
    match (left, right) {
        (CredentialDisposition::Brokered, _) | (_, CredentialDisposition::Brokered) => {
            CredentialDisposition::Brokered
        }
        (CredentialDisposition::SandboxEnv, _) | (_, CredentialDisposition::SandboxEnv) => {
            CredentialDisposition::SandboxEnv
        }
        (CredentialDisposition::UnusedOptional, CredentialDisposition::UnusedOptional) => {
            CredentialDisposition::UnusedOptional
        }
    }
}

fn github_route_credential(declared_names: &BTreeSet<String>) -> &'static str {
    if declared_names.contains(GITHUB_CREDENTIAL) {
        GITHUB_CREDENTIAL
    } else if declared_names.contains(GH_CREDENTIAL) {
        GH_CREDENTIAL
    } else {
        GITHUB_CREDENTIAL
    }
}

fn provider_route(
    id: &str,
    service: BrokerService,
    upstream: &str,
    credential_name: &str,
    request_path_prefix: &str,
) -> Result<BrokerRoute, EgressProxyPlanError> {
    let upstream_base_url = parse_route_url(upstream)?;

    Ok(BrokerRoute {
        id: id.to_owned(),
        service,
        allowed_hosts: allowed_hosts_for_url(&upstream_base_url),
        upstream_base_url,
        credential_name: credential_name.to_owned(),
        request_path_prefix: request_path_prefix.to_owned(),
        mcp_guard: None,
    })
}

fn allowed_hosts_for_url(url: &Url) -> BTreeSet<String> {
    url_host_with_optional_port(url).into_iter().collect()
}

#[derive(Debug, Clone)]
struct NormalizedOciRegistry {
    registry: String,
    upstream_base_url: Url,
}

fn normalize_oci_registry(registry: &str) -> Result<NormalizedOciRegistry, EgressProxyPlanError> {
    if registry.contains("://") {
        normalize_oci_registry_url(registry)
    } else {
        normalize_plain_oci_registry(registry)
    }
}

fn normalize_oci_registry_url(
    registry: &str,
) -> Result<NormalizedOciRegistry, EgressProxyPlanError> {
    let url = parse_route_url(registry)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !origin_path_is_empty(&url)
    {
        return Err(EgressProxyPlanError::InvalidProxyUrl(format!(
            "OCI registry `{registry}` must be an origin-only URL"
        )));
    }

    let registry = url_host_with_optional_port(&url).ok_or_else(|| {
        EgressProxyPlanError::InvalidProxyUrl(format!(
            "OCI registry `{registry}` must include a host"
        ))
    })?;
    validate_oci_registry_segment(&registry)?;
    let upstream_base_url = parse_route_url(&format!("{}://{registry}", url.scheme()))?;

    Ok(NormalizedOciRegistry {
        registry,
        upstream_base_url,
    })
}

fn normalize_plain_oci_registry(
    registry: &str,
) -> Result<NormalizedOciRegistry, EgressProxyPlanError> {
    validate_oci_registry_segment(registry)?;
    let upstream_base_url = parse_route_url(&format!("https://{registry}"))?;
    let registry = url_host_with_optional_port(&upstream_base_url).ok_or_else(|| {
        EgressProxyPlanError::InvalidProxyUrl(format!(
            "OCI registry `{registry}` must include a host"
        ))
    })?;
    validate_oci_registry_segment(&registry)?;

    Ok(NormalizedOciRegistry {
        registry,
        upstream_base_url,
    })
}

fn proxy_route_url(proxy_base: &str, path: &str) -> Result<Url, EgressProxyPlanError> {
    parse_route_url(&proxy_url_string(proxy_base, path))
}

fn proxy_url_string(proxy_base: &str, path: &str) -> String {
    format!("{proxy_base}{path}")
}

fn validate_proxy_base_url(url: &Url) -> Result<(), EgressProxyPlanError> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !origin_path_is_empty(url)
    {
        return Err(EgressProxyPlanError::InvalidProxyUrl(url.to_string()));
    }

    Ok(())
}

fn validate_mcp_route_id(route_id: &str) -> Result<(), EgressProxyPlanError> {
    validate_route_segment(route_id, "MCP route id", |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
    })
}

fn validate_oci_registry_segment(registry: &str) -> Result<(), EgressProxyPlanError> {
    validate_route_segment(registry, "OCI registry", |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
    })?;

    if let Some((host, port)) = registry.split_once(':') {
        if host.is_empty()
            || port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.contains(':')
        {
            return Err(invalid_route_segment("OCI registry", registry));
        }
    }

    Ok(())
}

fn validate_route_segment<F>(
    segment: &str,
    label: &str,
    is_allowed_byte: F,
) -> Result<(), EgressProxyPlanError>
where
    F: Fn(u8) -> bool,
{
    if segment.is_empty()
        || segment == "."
        || segment == ".."
        || !segment.is_ascii()
        || !segment.bytes().all(is_allowed_byte)
    {
        return Err(invalid_route_segment(label, segment));
    }

    Ok(())
}

fn invalid_route_segment(label: &str, segment: &str) -> EgressProxyPlanError {
    EgressProxyPlanError::InvalidProxyUrl(format!(
        "{label} `{segment}` contains unsafe route segment characters"
    ))
}

fn origin_path_is_empty(url: &Url) -> bool {
    matches!(url.path(), "" | "/")
}

fn url_host_with_optional_port(url: &Url) -> Option<String> {
    url.host_str().map(|host| match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

fn parse_route_url(value: &str) -> Result<Url, EgressProxyPlanError> {
    Url::parse(value).map_err(|err| EgressProxyPlanError::InvalidProxyUrl(err.to_string()))
}

fn write_json_atomically<T>(path: &Path, value: &T) -> Result<(), EgressProxyLaunchError>
where
    T: Serialize + ?Sized,
{
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| EgressProxyLaunchError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let rendered =
        serde_json::to_vec_pretty(value).map_err(|source| EgressProxyLaunchError::Json {
            path: path.to_path_buf(),
            source,
        })?;
    let temp_path = temporary_json_path(path)?;

    let mut options = OpenOptions::new();
    restrict_file_permissions(&mut options);
    let mut tmp_file = options
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|source| EgressProxyLaunchError::Io {
            path: temp_path.clone(),
            source,
        })?;

    let write_result = (|| -> std::io::Result<()> {
        tmp_file.write_all(&rendered)?;
        tmp_file.write_all(b"\n")?;
        tmp_file.sync_all()
    })();
    if let Err(source) = write_result {
        drop(tmp_file);
        let _ = fs::remove_file(&temp_path);
        return Err(EgressProxyLaunchError::Io {
            path: temp_path,
            source,
        });
    }
    drop(tmp_file);

    fs::rename(&temp_path, path).map_err(|source| {
        let _ = fs::remove_file(&temp_path);
        EgressProxyLaunchError::Io {
            path: path.to_path_buf(),
            source,
        }
    })?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| EgressProxyLaunchError::Io {
            path: parent.to_path_buf(),
            source,
        })
}

fn temporary_json_path(path: &Path) -> Result<PathBuf, EgressProxyLaunchError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| EgressProxyLaunchError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::other(source),
        })?;
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "launch.json".into());
    let temp_name = format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        timestamp.as_nanos()
    );
    Ok(path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(temp_name))
}

#[cfg(unix)]
fn restrict_file_permissions(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn restrict_file_permissions(_options: &mut OpenOptions) {}

fn egress_proxy_binary_path() -> Result<PathBuf, EgressProxyLaunchError> {
    if let Some(path) = env::var_os(EGRESS_PROXY_BIN_ENV).map(PathBuf::from) {
        return validate_env_proxy_binary(path);
    }

    let path =
        env::current_exe().map_err(|source| EgressProxyLaunchError::CurrentExe { source })?;
    if path.as_os_str().is_empty() || !path.is_file() {
        return Err(EgressProxyLaunchError::InvalidCurrentExe { path });
    }

    Ok(path)
}

fn validate_env_proxy_binary(path: PathBuf) -> Result<PathBuf, EgressProxyLaunchError> {
    if path.as_os_str().is_empty() || !path.is_file() {
        return Err(EgressProxyLaunchError::InvalidProxyBinary {
            env_var: EGRESS_PROXY_BIN_ENV,
            path,
        });
    }

    Ok(path)
}

fn read_launch_listen_url(path: &Path) -> Result<Url, EgressProxyLaunchError> {
    let bytes = fs::read(path).map_err(|source| EgressProxyLaunchError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let config: EgressProxyLaunchConfig =
        serde_json::from_slice(&bytes).map_err(|source| EgressProxyLaunchError::Json {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(config.listen_url)
}

async fn wait_for_proxy_listener(
    child: &mut Child,
    pid: u32,
    program: &Path,
    config_path: &Path,
    listen_url: &Url,
    timeout: Duration,
) -> Result<(), EgressProxyLaunchError> {
    let addr = proxy_listen_socket_addr(listen_url, config_path)?;
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|source| EgressProxyLaunchError::Stop { pid, source })?
        {
            return Err(EgressProxyLaunchError::ExitedDuringStartup {
                program: program.to_path_buf(),
                status,
            });
        }
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(EgressProxyLaunchError::StartupTimeout {
                pid,
                listen_url: listen_url.clone(),
                timeout,
            });
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn proxy_listen_socket_addr(
    listen_url: &Url,
    config_path: &Path,
) -> Result<SocketAddr, EgressProxyLaunchError> {
    let Some(host) = listen_url.host_str() else {
        return Err(EgressProxyLaunchError::InvalidListenUrl {
            path: config_path.to_path_buf(),
            listen_url: listen_url.clone(),
        });
    };
    let Some(port) = listen_url.port() else {
        return Err(EgressProxyLaunchError::InvalidListenUrl {
            path: config_path.to_path_buf(),
            listen_url: listen_url.clone(),
        });
    };
    let connect_host = if host == "0.0.0.0" { "127.0.0.1" } else { host };
    format!("{connect_host}:{port}")
        .parse()
        .map_err(|_| EgressProxyLaunchError::InvalidListenUrl {
            path: config_path.to_path_buf(),
            listen_url: listen_url.clone(),
        })
}

#[cfg(unix)]
async fn terminate_process_pid(pid: u32) -> Result<(), EgressProxyLaunchError> {
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|source| EgressProxyLaunchError::Stop { pid, source })?;
    if !status.success() && process_is_running(pid).await? {
        return Err(EgressProxyLaunchError::Stop {
            pid,
            source: std::io::Error::other(format!("kill exited with status {status}")),
        });
    }
    Ok(())
}

#[cfg(windows)]
async fn terminate_process_pid(pid: u32) -> Result<(), EgressProxyLaunchError> {
    let status = Command::new("taskkill")
        .arg("/PID")
        .arg(pid.to_string())
        .arg("/T")
        .arg("/F")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|source| EgressProxyLaunchError::Stop { pid, source })?;
    if !status.success() && process_is_running(pid).await? {
        return Err(EgressProxyLaunchError::Stop {
            pid,
            source: std::io::Error::other(format!("taskkill exited with status {status}")),
        });
    }
    Ok(())
}

#[cfg(unix)]
async fn process_is_running(pid: u32) -> Result<bool, EgressProxyLaunchError> {
    let status = Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|source| EgressProxyLaunchError::Stop { pid, source })?;
    Ok(status.success())
}

#[cfg(windows)]
async fn process_is_running(pid: u32) -> Result<bool, EgressProxyLaunchError> {
    let status = Command::new("tasklist")
        .arg("/FI")
        .arg(format!("PID eq {pid}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|source| EgressProxyLaunchError::Stop { pid, source })?;
    Ok(status.success())
}

mod url_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use url::Url;

    pub fn serialize<S>(url: &Url, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(url.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Url, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Url::parse(&value).map_err(serde::de::Error::custom)
    }
}

mod optional_url_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use url::Url;

    pub fn serialize<S>(url: &Option<Url>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match url {
            Some(url) => serializer.serialize_some(url.as_str()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Url>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .map(|value| Url::parse(&value).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use agentenv_proto::{
        CredentialKind, CredentialRequirement, DnsPolicy, FilesystemPolicy, InferencePolicy,
        NetworkAccessPolicy, NetworkPolicy, PolicyReloadability, ProcessPolicy,
    };

    use super::*;

    fn required(name: &str) -> CredentialRequirement {
        CredentialRequirement {
            name: name.to_owned(),
            description: String::new(),
            kind: CredentialKind::ApiKey,
            required: true,
            validator: None,
        }
    }

    fn optional(name: &str) -> CredentialRequirement {
        CredentialRequirement {
            required: false,
            ..required(name)
        }
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }

    fn policy() -> NetworkPolicy {
        NetworkPolicy {
            network: NetworkAccessPolicy {
                reloadability: PolicyReloadability::HotReload,
                allow: Vec::new(),
                deny: Vec::new(),
                approval_required: Vec::new(),
                dns: DnsPolicy::default(),
            },
            filesystem: FilesystemPolicy {
                reloadability: PolicyReloadability::LockedAtCreate,
                read_only: Vec::new(),
                read_write: Vec::new(),
            },
            process: ProcessPolicy {
                reloadability: PolicyReloadability::LockedAtCreate,
                run_as_user: "agent".to_owned(),
                run_as_group: "agent".to_owned(),
                profile: "default".to_owned(),
                allow_syscalls: Vec::new(),
                deny_syscalls: Vec::new(),
            },
            inference: InferencePolicy {
                reloadability: PolicyReloadability::HotReload,
                routes: Vec::new(),
            },
        }
    }

    #[test]
    fn plan_brokers_provider_credentials_and_leaves_unmatched_env_vars() {
        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31001".parse().unwrap(),
            credential_requirements: vec![
                required("OPENAI_API_KEY"),
                required("ANTHROPIC_API_KEY"),
                required("CUSTOM_TOKEN"),
            ],
            network_policy: policy(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes::default(),
        })
        .expect("plan builds");

        assert_eq!(
            plan.credential_disposition("OPENAI_API_KEY"),
            Some(CredentialDisposition::Brokered)
        );
        assert_eq!(
            plan.credential_disposition("ANTHROPIC_API_KEY"),
            Some(CredentialDisposition::Brokered)
        );
        assert_eq!(
            plan.credential_disposition("CUSTOM_TOKEN"),
            Some(CredentialDisposition::SandboxEnv)
        );
        assert!(plan
            .routes
            .iter()
            .any(|route| route.service == BrokerService::OpenAi));
        let openai_route = plan
            .routes
            .iter()
            .find(|route| route.service == BrokerService::OpenAi)
            .expect("OpenAI route should be present");
        assert_eq!(
            openai_route.upstream_base_url.as_str(),
            "https://api.openai.com/v1"
        );
        assert!(plan
            .routes
            .iter()
            .any(|route| route.service == BrokerService::Anthropic));
    }

    #[test]
    fn plan_rewrites_context_mcp_endpoint_to_proxy_route() {
        let endpoint = McpProxySource {
            route_id: "primary".to_owned(),
            upstream_url: "https://mcp.example.test/rpc".parse().unwrap(),
            token_credential_name: Some("MCP_TOKEN".to_owned()),
            guard_config: None,
        };

        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31002".parse().unwrap(),
            credential_requirements: vec![required("MCP_TOKEN")],
            network_policy: policy(),
            context_mcp: Some(endpoint),
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes::default(),
        })
        .expect("plan builds");

        assert_eq!(
            plan.credential_disposition("MCP_TOKEN"),
            Some(CredentialDisposition::Brokered)
        );
        assert_eq!(
            plan.context_mcp_url().unwrap().as_str(),
            "http://127.0.0.1:31002/v1/mcp/primary"
        );
        let route = plan
            .routes
            .iter()
            .find(|route| route.id == "mcp.primary")
            .expect("MCP route should be present");
        assert!(route.allowed_hosts.contains("mcp.example.test"));
    }

    #[test]
    fn mcp_route_carries_guard_config_when_supplied() {
        let endpoint = McpProxySource {
            route_id: "primary".to_owned(),
            upstream_url: "https://mcp.example.test/rpc".parse().unwrap(),
            token_credential_name: Some("MCP_TOKEN".to_owned()),
            guard_config: Some(agentenv_proto::McpGuardConfig {
                enabled: true,
                default_approval: agentenv_proto::McpApprovalMode::PerCall,
                tool_policies: BTreeMap::new(),
                cross_tool_flows: agentenv_proto::McpCrossToolFlowPolicy::default(),
                ..agentenv_proto::McpGuardConfig::default()
            }),
        };

        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31002".parse().unwrap(),
            credential_requirements: vec![required("MCP_TOKEN")],
            network_policy: policy(),
            context_mcp: Some(endpoint),
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes::default(),
        })
        .expect("plan builds");

        let route = plan
            .routes
            .iter()
            .find(|route| route.id == "mcp.primary")
            .expect("MCP route should be present");
        assert!(route.mcp_guard.as_ref().is_some_and(|guard| guard.enabled));
    }

    #[test]
    fn plan_adds_explicit_github_and_oci_routes() {
        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31003".parse().unwrap(),
            credential_requirements: vec![required("GITHUB_TOKEN"), required("oci.ghcr.io")],
            network_policy: policy(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes {
                github: true,
                oci_registries: ["ghcr.io".to_owned()].into_iter().collect(),
                ..ExplicitEgressRoutes::default()
            },
        })
        .expect("plan builds");

        assert_eq!(
            plan.credential_disposition("GITHUB_TOKEN"),
            Some(CredentialDisposition::Brokered)
        );
        assert_eq!(
            plan.credential_disposition("oci.ghcr.io"),
            Some(CredentialDisposition::Brokered)
        );
        assert!(plan
            .routes
            .iter()
            .any(|route| route.service == BrokerService::GitHub
                && route.request_path_prefix == "/v1/github/api"));
        assert!(plan
            .routes
            .iter()
            .any(|route| route.service == BrokerService::GitHub
                && route.request_path_prefix == "/v1/github/git"));
        assert_eq!(
            plan.sandbox_env.get("GIT_CONFIG_KEY_0").map(String::as_str),
            Some("url.http://127.0.0.1:31003/v1/github/git/.insteadOf")
        );
        assert_eq!(
            plan.sandbox_env
                .get("GIT_CONFIG_VALUE_0")
                .map(String::as_str),
            Some("https://github.com/")
        );
        let route = plan
            .routes
            .iter()
            .find(|route| {
                route.service
                    == BrokerService::Oci {
                        registry: "ghcr.io".to_owned(),
                    }
            })
            .expect("OCI route should be present");
        assert_eq!(route.request_path_prefix, "/v1/oci/ghcr.io");
        assert!(route.allowed_hosts.contains("ghcr.io"));
    }

    #[test]
    fn explicit_github_route_exposes_brokered_credential_without_driver_requirement() {
        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31004".parse().unwrap(),
            credential_requirements: Vec::new(),
            network_policy: policy(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes {
                github: true,
                oci_registries: BTreeSet::new(),
                ..ExplicitEgressRoutes::default()
            },
        })
        .expect("plan builds");

        let route = plan
            .routes
            .iter()
            .find(|route| route.service == BrokerService::GitHub)
            .expect("GitHub route should be present");
        assert_eq!(route.credential_name, "GITHUB_TOKEN");
        assert_eq!(
            plan.credential_disposition("GITHUB_TOKEN"),
            Some(CredentialDisposition::Brokered)
        );
    }

    #[test]
    fn explicit_oci_route_exposes_brokered_credential_without_driver_requirement() {
        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31005".parse().unwrap(),
            credential_requirements: Vec::new(),
            network_policy: policy(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes {
                github: false,
                oci_registries: ["ghcr.io".to_owned()].into_iter().collect(),
                ..ExplicitEgressRoutes::default()
            },
        })
        .expect("plan builds");

        let route = plan
            .routes
            .iter()
            .find(|route| {
                route.service
                    == BrokerService::Oci {
                        registry: "ghcr.io".to_owned(),
                    }
            })
            .expect("OCI route should be present");
        assert_eq!(route.credential_name, "oci.ghcr.io");
        assert_eq!(
            plan.credential_disposition("oci.ghcr.io"),
            Some(CredentialDisposition::Brokered)
        );
    }

    #[test]
    fn github_route_uses_gh_token_when_github_token_is_absent() {
        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31006".parse().unwrap(),
            credential_requirements: vec![required("GH_TOKEN")],
            network_policy: policy(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes::default(),
        })
        .expect("plan builds");

        let route = plan
            .routes
            .iter()
            .find(|route| route.service == BrokerService::GitHub)
            .expect("GitHub route should be present");
        assert_eq!(route.credential_name, "GH_TOKEN");
        assert_eq!(
            plan.credential_disposition("GH_TOKEN"),
            Some(CredentialDisposition::Brokered)
        );
        assert_eq!(plan.credential_disposition("GITHUB_TOKEN"), None);
    }

    #[test]
    fn brokered_credential_returns_openai_metadata() {
        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31007".parse().unwrap(),
            credential_requirements: vec![required("OPENAI_API_KEY")],
            network_policy: policy(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes::default(),
        })
        .expect("plan builds");

        let credential = plan
            .brokered_credential("OPENAI_API_KEY")
            .expect("OpenAI credential should be brokered");
        assert_eq!(credential.name, "OPENAI_API_KEY");
        assert_eq!(credential.route_id, "openai");
        assert_eq!(credential.route_credential_name, "OPENAI_API_KEY");
        assert_eq!(credential.service, BrokerService::OpenAi);
    }

    #[test]
    fn github_brokered_credential_metadata_tracks_alias_and_route_credential() {
        let gh_only = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31008".parse().unwrap(),
            credential_requirements: vec![required("GH_TOKEN")],
            network_policy: policy(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes::default(),
        })
        .expect("plan builds");

        let credential = gh_only
            .brokered_credential("GH_TOKEN")
            .expect("GH_TOKEN should be brokered");
        assert_eq!(credential.route_id, "github.api");
        assert_eq!(credential.route_credential_name, "GH_TOKEN");
        assert_eq!(credential.service, BrokerService::GitHub);

        let both = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31009".parse().unwrap(),
            credential_requirements: vec![required("GITHUB_TOKEN"), required("GH_TOKEN")],
            network_policy: policy(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes::default(),
        })
        .expect("plan builds");

        let credential = both
            .brokered_credential("GH_TOKEN")
            .expect("GH_TOKEN should be brokered");
        assert_eq!(credential.route_id, "github.api");
        assert_eq!(credential.route_credential_name, "GITHUB_TOKEN");
        assert_eq!(credential.service, BrokerService::GitHub);
    }

    #[test]
    fn oci_plain_registry_with_port_preserves_port_in_upstream_and_allowed_hosts() {
        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31010".parse().unwrap(),
            credential_requirements: Vec::new(),
            network_policy: policy(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes {
                github: false,
                oci_registries: ["localhost:5000".to_owned()].into_iter().collect(),
                ..ExplicitEgressRoutes::default()
            },
        })
        .expect("plan builds");

        let route = plan
            .routes
            .iter()
            .find(|route| {
                route.service
                    == BrokerService::Oci {
                        registry: "localhost:5000".to_owned(),
                    }
            })
            .expect("OCI route should be present");
        assert_eq!(route.upstream_base_url.as_str(), "https://localhost:5000/");
        assert!(route.allowed_hosts.contains("localhost:5000"));
    }

    #[test]
    fn oci_url_registry_normalizes_to_host_port() {
        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31011".parse().unwrap(),
            credential_requirements: Vec::new(),
            network_policy: policy(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes {
                github: false,
                oci_registries: ["https://localhost:5000".to_owned()].into_iter().collect(),
                ..ExplicitEgressRoutes::default()
            },
        })
        .expect("plan builds");

        let route = plan
            .routes
            .iter()
            .find(|route| route.id == "oci.localhost:5000")
            .expect("normalized OCI route should be present");
        assert_eq!(
            route.service,
            BrokerService::Oci {
                registry: "localhost:5000".to_owned(),
            }
        );
        assert_eq!(route.request_path_prefix, "/v1/oci/localhost:5000");
        assert_eq!(route.credential_name, "oci.localhost:5000");
        assert!(route.allowed_hosts.contains("localhost:5000"));
    }

    #[test]
    fn oci_url_registry_with_path_query_fragment_or_credentials_is_rejected() {
        for registry in [
            "https://localhost:5000/v2",
            "https://localhost:5000?x=1",
            "https://localhost:5000#v2",
            "https://user:pass@localhost:5000",
        ] {
            let result = build_egress_proxy_plan(EgressProxyPlanInput {
                env_name: "demo".to_owned(),
                proxy_base_url: "http://127.0.0.1:31012".parse().unwrap(),
                credential_requirements: Vec::new(),
                network_policy: policy(),
                context_mcp: None,
                inference_endpoint: None,
                explicit_routes: ExplicitEgressRoutes {
                    github: false,
                    oci_registries: [registry.to_owned()].into_iter().collect(),
                    ..ExplicitEgressRoutes::default()
                },
            });

            assert!(result.is_err(), "{registry} should be rejected");
        }
    }

    #[test]
    fn oci_plain_registry_with_unsafe_path_characters_is_rejected() {
        for registry in [
            "registry.example/repo",
            "registry.example?repo",
            "registry.example#repo",
            "token@registry.example",
            "registry.example%2frepo",
            r"registry.example\repo",
        ] {
            let result = build_egress_proxy_plan(EgressProxyPlanInput {
                env_name: "demo".to_owned(),
                proxy_base_url: "http://127.0.0.1:31013".parse().unwrap(),
                credential_requirements: Vec::new(),
                network_policy: policy(),
                context_mcp: None,
                inference_endpoint: None,
                explicit_routes: ExplicitEgressRoutes {
                    github: false,
                    oci_registries: [registry.to_owned()].into_iter().collect(),
                    ..ExplicitEgressRoutes::default()
                },
            });

            assert!(result.is_err(), "{registry} should be rejected");
        }
    }

    #[test]
    fn mcp_route_id_with_slash_or_encoded_slash_is_rejected() {
        for route_id in ["primary/extra", "primary%2fextra"] {
            let result = build_egress_proxy_plan(EgressProxyPlanInput {
                env_name: "demo".to_owned(),
                proxy_base_url: "http://127.0.0.1:31014".parse().unwrap(),
                credential_requirements: vec![required("MCP_TOKEN")],
                network_policy: policy(),
                context_mcp: Some(McpProxySource {
                    route_id: route_id.to_owned(),
                    upstream_url: "https://mcp.example.test/rpc".parse().unwrap(),
                    token_credential_name: Some("MCP_TOKEN".to_owned()),
                    guard_config: None,
                }),
                inference_endpoint: None,
                explicit_routes: ExplicitEgressRoutes::default(),
            });

            assert!(result.is_err(), "{route_id} should be rejected");
        }
    }

    #[test]
    fn proxy_base_url_with_path_or_query_is_rejected() {
        for proxy_base_url in ["http://127.0.0.1:31015/proxy", "http://127.0.0.1:31015?x=1"] {
            let result = build_egress_proxy_plan(EgressProxyPlanInput {
                env_name: "demo".to_owned(),
                proxy_base_url: proxy_base_url.parse().unwrap(),
                credential_requirements: Vec::new(),
                network_policy: policy(),
                context_mcp: None,
                inference_endpoint: None,
                explicit_routes: ExplicitEgressRoutes::default(),
            });

            assert!(result.is_err(), "{proxy_base_url} should be rejected");
        }
    }

    #[test]
    fn duplicate_optional_and_required_unmatched_credential_becomes_sandbox_env() {
        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31016".parse().unwrap(),
            credential_requirements: vec![required("CUSTOM_TOKEN"), optional("CUSTOM_TOKEN")],
            network_policy: policy(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes::default(),
        })
        .expect("plan builds");

        assert_eq!(
            plan.credential_disposition("CUSTOM_TOKEN"),
            Some(CredentialDisposition::SandboxEnv)
        );
    }

    #[test]
    fn launcher_writes_redacted_config_and_policy_files() {
        let root = temp_dir("egress-proxy-launcher-redacted");
        let env_dir = root.join("env");
        fs::create_dir_all(&env_dir).expect("temp env dir should be created");

        let fake_secret = "sk-real-secret";
        let mut openai = required("OPENAI_API_KEY");
        openai.description = fake_secret.to_owned();
        let network_policy = policy();
        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31017".parse().unwrap(),
            credential_requirements: vec![openai],
            network_policy: network_policy.clone(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes::default(),
        })
        .expect("plan builds");

        let files = prepare_egress_proxy_launch_files(
            "demo",
            &env_dir,
            &plan,
            vec!["OPENAI_API_KEY".to_owned()],
            &network_policy,
        )
        .expect("launch files should be prepared");

        assert_eq!(
            files.config_path,
            env_dir.join("egress-proxy").join("config.json")
        );
        assert_eq!(
            files.policy_path,
            env_dir.join("egress-proxy").join("policy.json")
        );

        let config_json =
            fs::read_to_string(&files.config_path).expect("config should be readable");
        assert!(config_json.contains("OPENAI_API_KEY"));
        assert!(config_json.contains("openai"));
        assert!(config_json.contains("api.openai.com"));
        assert!(!config_json.contains(fake_secret));
        assert!(!config_json.contains("sandbox_env"));

        let config: EgressProxyLaunchConfig =
            serde_json::from_str(&config_json).expect("config should deserialize");
        assert_eq!(config.env_name, "demo");
        assert_eq!(config.listen_url.as_str(), "http://127.0.0.1:31017/");
        assert_eq!(config.policy_path, files.policy_path);
        assert_eq!(config.credential_names, vec!["OPENAI_API_KEY"]);
        assert!(config
            .routes
            .iter()
            .any(|route| route.service == BrokerService::OpenAi));

        let policy_json =
            fs::read_to_string(&files.policy_path).expect("policy should be readable");
        assert!(policy_json.contains("\"network\""));
        assert!(!policy_json.contains(fake_secret));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn launcher_writes_route_rate_limits_from_plan() {
        let root = temp_dir("egress-proxy-launcher-rate-limits");
        let env_dir = root.join("env");
        fs::create_dir_all(&env_dir).expect("temp env dir should be created");
        let mut rate_limits = BTreeMap::new();
        rate_limits.insert(
            "openai".to_owned(),
            EgressProxyRateLimit {
                requests_per_minute: 60,
            },
        );
        let network_policy = policy();
        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31018".parse().unwrap(),
            credential_requirements: vec![required("OPENAI_API_KEY")],
            network_policy: network_policy.clone(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes {
                rate_limits,
                ..ExplicitEgressRoutes::default()
            },
        })
        .expect("plan builds");

        let files = prepare_egress_proxy_launch_files(
            "demo",
            &env_dir,
            &plan,
            vec!["OPENAI_API_KEY".to_owned()],
            &network_policy,
        )
        .expect("launch files should be prepared");

        let config_json =
            fs::read_to_string(&files.config_path).expect("config should be readable");
        let config: EgressProxyLaunchConfig =
            serde_json::from_str(&config_json).expect("config should deserialize");

        assert_eq!(
            config
                .rate_limits
                .get("openai")
                .map(|limit| limit.requests_per_minute),
            Some(60)
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn launcher_writes_default_route_rate_limits() {
        let root = temp_dir("egress-proxy-launcher-default-rate-limits");
        let env_dir = root.join("env");
        fs::create_dir_all(&env_dir).expect("temp env dir should be created");
        let network_policy = policy();
        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31019".parse().unwrap(),
            credential_requirements: vec![
                required("OPENAI_API_KEY"),
                required("ANTHROPIC_API_KEY"),
                required("GITHUB_TOKEN"),
            ],
            network_policy: network_policy.clone(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes::default(),
        })
        .expect("plan builds");

        let files = prepare_egress_proxy_launch_files(
            "demo",
            &env_dir,
            &plan,
            vec![
                "OPENAI_API_KEY".to_owned(),
                "ANTHROPIC_API_KEY".to_owned(),
                "GITHUB_TOKEN".to_owned(),
            ],
            &network_policy,
        )
        .expect("launch files should be prepared");

        let config_json =
            fs::read_to_string(&files.config_path).expect("config should be readable");
        let config: EgressProxyLaunchConfig =
            serde_json::from_str(&config_json).expect("config should deserialize");

        assert_eq!(
            config
                .rate_limits
                .get("openai")
                .map(|limit| limit.requests_per_minute),
            Some(DEFAULT_OPENAI_RATE_LIMIT)
        );
        assert_eq!(
            config
                .rate_limits
                .get("anthropic")
                .map(|limit| limit.requests_per_minute),
            Some(DEFAULT_ANTHROPIC_RATE_LIMIT)
        );
        assert_eq!(
            config
                .rate_limits
                .get("github.api")
                .map(|limit| limit.requests_per_minute),
            Some(DEFAULT_GITHUB_RATE_LIMIT)
        );
        assert_eq!(
            config
                .rate_limits
                .get("github.git")
                .map(|limit| limit.requests_per_minute),
            Some(DEFAULT_GITHUB_RATE_LIMIT)
        );

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn launcher_uses_env_override_for_proxy_binary() {
        use std::os::unix::fs::PermissionsExt;

        struct EnvVarGuard {
            _lock: std::sync::MutexGuard<'static, ()>,
            key: &'static str,
            previous: Option<std::ffi::OsString>,
        }

        impl Drop for EnvVarGuard {
            fn drop(&mut self) {
                match &self.previous {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }

        let root = temp_dir("egress-proxy-launcher-env-override");
        fs::create_dir_all(&root).expect("temp dir should be created");
        let script_path = root.join("fake-agentenv-proxy.sh");
        fs::write(&script_path, "#!/bin/sh\nsleep 30\n").expect("script should be written");
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755))
            .expect("script should be executable");
        let config_path = root.join("config.json");
        let events_db_path = root.join("events.db");
        fs::write(&config_path, "{}").expect("config placeholder should be written");

        let guard = EnvVarGuard {
            _lock: crate::env_var_test_lock(),
            key: EGRESS_PROXY_BIN_ENV,
            previous: std::env::var_os(EGRESS_PROXY_BIN_ENV),
        };
        std::env::set_var(EGRESS_PROXY_BIN_ENV, &script_path);

        let handle = start_egress_proxy_process("demo", &config_path, &events_db_path)
            .await
            .expect("proxy process should start");
        assert!(handle.pid > 0);

        stop_egress_proxy_process_with_timeout(handle, Duration::from_secs(2))
            .await
            .expect("proxy process should stop");

        drop(guard);
        let _ = fs::remove_dir_all(root);
    }
}
