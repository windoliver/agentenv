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
    let required_names = input
        .credential_requirements
        .iter()
        .map(|requirement| requirement.name.as_str())
        .collect::<BTreeSet<_>>();

    let mut routes = Vec::new();
    let mut sandbox_env = BTreeMap::new();
    let mut brokered_names = BTreeSet::new();

    if required_names.contains(OPENAI_CREDENTIAL) {
        broker_credential(OPENAI_CREDENTIAL, &mut brokered_names, &mut sandbox_env);
        sandbox_env.insert(
            "OPENAI_BASE_URL".to_owned(),
            proxy_url_string(&proxy_base, "/v1/openai"),
        );
        routes.push(provider_route(
            "openai",
            BrokerService::OpenAi,
            "https://api.openai.com",
            OPENAI_CREDENTIAL,
            "/v1/openai",
        )?);
    }

    if required_names.contains(ANTHROPIC_CREDENTIAL) {
        broker_credential(ANTHROPIC_CREDENTIAL, &mut brokered_names, &mut sandbox_env);
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

    if input.explicit_routes.github || required_names.contains(GITHUB_CREDENTIAL) {
        broker_credential(GITHUB_CREDENTIAL, &mut brokered_names, &mut sandbox_env);
        sandbox_env.insert(
            "GITHUB_API_URL".to_owned(),
            proxy_url_string(&proxy_base, "/v1/github/api"),
        );
        routes.push(provider_route(
            "github.api",
            BrokerService::GitHub,
            "https://api.github.com",
            GITHUB_CREDENTIAL,
            "/v1/github/api",
        )?);
    }

    let rewritten_context_mcp_url = if let Some(source) = input.context_mcp {
        let credential_name = source
            .token_credential_name
            .unwrap_or_else(|| DEFAULT_MCP_CREDENTIAL.to_owned());
        broker_credential(&credential_name, &mut brokered_names, &mut sandbox_env);
        let route_id = source.route_id;
        let request_path_prefix = format!("/v1/mcp/{route_id}");
        let rewritten_url = proxy_route_url(&proxy_base, &request_path_prefix)?;
        routes.push(BrokerRoute {
            id: format!("mcp.{route_id}"),
            service: BrokerService::Mcp {
                route_id: route_id.clone(),
            },
            upstream_base_url: source.upstream_url.clone(),
            credential_name,
            request_path_prefix,
            allowed_hosts: allowed_hosts_for_url(&source.upstream_url),
        });
        Some(rewritten_url)
    } else {
        None
    };

    for registry in input.explicit_routes.oci_registries {
        let credential_name = format!("oci.{registry}");
        broker_credential(&credential_name, &mut brokered_names, &mut sandbox_env);
        let upstream = oci_registry_upstream_url(&registry)?;
        routes.push(BrokerRoute {
            id: format!("oci.{registry}"),
            service: BrokerService::Oci {
                registry: registry.clone(),
            },
            upstream_base_url: upstream.clone(),
            credential_name,
            request_path_prefix: format!("/v1/oci/{registry}"),
            allowed_hosts: allowed_hosts_for_url(&upstream),
        });
    }

    let credential_dispositions = input
        .credential_requirements
        .into_iter()
        .map(|requirement| {
            let disposition = if brokered_names.contains(&requirement.name) {
                CredentialDisposition::Brokered
            } else if requirement.required {
                CredentialDisposition::SandboxEnv
            } else {
                CredentialDisposition::UnusedOptional
            };
            (requirement.name, disposition)
        })
        .collect();

    Ok(EgressProxyPlan {
        env_name: input.env_name,
        listen_url: proxy_base_url,
        sandbox_env,
        routes,
        credential_dispositions,
        rewritten_context_mcp_url,
        redacted_policy_path: None,
    })
}

fn broker_credential(
    credential_name: &str,
    brokered_names: &mut BTreeSet<String>,
    sandbox_env: &mut BTreeMap<String, String>,
) {
    brokered_names.insert(credential_name.to_owned());
    sandbox_env.insert(credential_name.to_owned(), BROKERED_DUMMY_VALUE.to_owned());
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
    url.host_str().into_iter().map(str::to_owned).collect()
}

fn oci_registry_upstream_url(registry: &str) -> Result<Url, EgressProxyPlanError> {
    if let Ok(url) = Url::parse(registry) {
        let host = url.host_str().ok_or_else(|| {
            EgressProxyPlanError::InvalidProxyUrl(format!(
                "OCI registry `{registry}` must include a host"
            ))
        })?;
        return parse_route_url(&format!("https://{host}{}", url.path()));
    }

    parse_route_url(&format!("https://{registry}"))
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
    {
        return Err(EgressProxyPlanError::InvalidProxyUrl(url.to_string()));
    }

    Ok(())
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
}
