use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use agentenv_proto::{CredentialRequirement, NetworkPolicy};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

const BROKERED_DUMMY_VALUE: &str = "agentenv-brokered";
const OPENAI_CREDENTIAL: &str = "OPENAI_API_KEY";
const ANTHROPIC_CREDENTIAL: &str = "ANTHROPIC_API_KEY";
const GITHUB_CREDENTIAL: &str = "GITHUB_TOKEN";
const GH_CREDENTIAL: &str = "GH_TOKEN";
const DEFAULT_MCP_CREDENTIAL: &str = "MCP_TOKEN";

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
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplicitEgressRoutes {
    #[serde(default)]
    pub github: bool,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub oci_registries: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpProxySource {
    pub route_id: String,
    pub upstream_url: Url,
    pub token_credential_name: Option<String>,
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
}

#[derive(Debug, Error)]
pub enum EgressProxyPlanError {
    #[error("invalid proxy URL: {0}")]
    InvalidProxyUrl(String),
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

pub fn build_egress_proxy_plan(
    input: EgressProxyPlanInput,
) -> Result<EgressProxyPlan, EgressProxyPlanError> {
    validate_proxy_base_url(&input.proxy_base_url)?;

    let proxy_base_url = input.proxy_base_url;
    let proxy_base = proxy_base_url.as_str().trim_end_matches('/').to_owned();
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
        routes.push(provider_route(
            "github.api",
            BrokerService::GitHub,
            "https://api.github.com",
            github_credential,
            "/v1/github/api",
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

    Ok(EgressProxyPlan {
        env_name: input.env_name,
        listen_url: proxy_base_url,
        sandbox_env,
        routes,
        credential_dispositions,
        brokered_credentials,
        rewritten_context_mcp_url,
        redacted_policy_path: None,
    })
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
}
