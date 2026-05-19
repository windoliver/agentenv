use std::{collections::BTreeMap, env};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use thiserror::Error;
use url::Url;

use crate::error::BlueprintError;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Blueprint {
    pub version: String,
    pub min_agentenv_version: String,
    pub sandbox: ComponentSection,
    pub agent: ComponentSection,
    pub context: ComponentSection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference: Option<ComponentSection>,
    pub policy: PolicySection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StateSection>,
    #[serde(default, skip_serializing_if = "SkillsSection::is_empty")]
    pub skills: SkillsSection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability: Option<ObservabilitySection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ComponentSection {
    pub driver: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<BTreeMap<String, CredentialRef>>,
    #[schemars(with = "BTreeMap<String, serde_json::Value>")]
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CredentialRef {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[schemars(with = "BTreeMap<String, serde_json::Value>")]
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicySection {
    pub tier: String,
    #[serde(default)]
    pub presets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overrides: Vec<PolicyOverride>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<PolicyDnsSection>,
    #[schemars(with = "BTreeMap<String, serde_json::Value>")]
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyDnsSection {
    #[serde(default)]
    pub resolvers_allowed: Vec<String>,
    #[serde(default)]
    pub doh_upstreams_allowed: Vec<String>,
    #[serde(default)]
    pub dot_upstreams_allowed: Vec<String>,
    #[serde(default)]
    pub log_all_queries: bool,
    #[serde(default)]
    pub pin_resolved_ips: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
    #[schemars(with = "BTreeMap<String, serde_json::Value>")]
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StateSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persist_home: Option<bool>,
    #[schemars(with = "BTreeMap<String, serde_json::Value>")]
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SkillsSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_discovery: Option<SkillRuntimeDiscoverySection>,
}

impl SkillsSection {
    pub fn is_empty(&self) -> bool {
        self.runtime_discovery.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillRuntimeDiscoverySection {
    pub mcp_endpoint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SkillRuntimeDiscoveryEndpointError {
    #[error("mcp_endpoint must not be empty")]
    Empty,
    #[error("mcp_endpoint must use the mcp+http or mcp+https scheme")]
    MissingMcpScheme,
    #[error("mcp_endpoint uses unsupported inner scheme `{scheme}`")]
    UnsupportedScheme { scheme: String },
    #[error("mcp_endpoint must be a valid URL")]
    Malformed,
    #[error("mcp_endpoint must include a host")]
    MissingHost,
}

impl SkillRuntimeDiscoverySection {
    pub fn mcp_endpoint(
        &self,
    ) -> Result<agentenv_proto::McpEndpoint, SkillRuntimeDiscoveryEndpointError> {
        let url = normalize_runtime_discovery_mcp_endpoint(&self.mcp_endpoint)?;
        Ok(agentenv_proto::McpEndpoint {
            url,
            transport: agentenv_proto::McpTransport::Http,
            headers: BTreeMap::new(),
        })
    }
}

fn normalize_runtime_discovery_mcp_endpoint(
    raw: &str,
) -> Result<String, SkillRuntimeDiscoveryEndpointError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(SkillRuntimeDiscoveryEndpointError::Empty);
    }
    let inner = trimmed
        .strip_prefix("mcp+")
        .ok_or(SkillRuntimeDiscoveryEndpointError::MissingMcpScheme)?;
    let parsed = Url::parse(inner).map_err(|_| SkillRuntimeDiscoveryEndpointError::Malformed)?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(SkillRuntimeDiscoveryEndpointError::UnsupportedScheme {
            scheme: parsed.scheme().to_owned(),
        });
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(SkillRuntimeDiscoveryEndpointError::MissingHost);
    }

    Ok(parsed.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ObservabilitySection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otel: Option<OtelObservabilitySection>,
    #[schemars(with = "BTreeMap<String, serde_json::Value>")]
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OtelObservabilitySection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[schemars(with = "BTreeMap<String, serde_json::Value>")]
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

pub trait InterpolationResolver {
    fn resolve_env(&self, name: &str) -> Result<String, BlueprintError>;
    fn resolve_credstore(&self, name: &str) -> Result<String, BlueprintError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultInterpolationResolver;

impl InterpolationResolver for DefaultInterpolationResolver {
    fn resolve_env(&self, name: &str) -> Result<String, BlueprintError> {
        env::var(name).map_err(|_| BlueprintError::UnresolvedEnvVar {
            name: name.to_string(),
        })
    }

    fn resolve_credstore(&self, name: &str) -> Result<String, BlueprintError> {
        Err(BlueprintError::UnresolvedCredential {
            name: name.to_string(),
        })
    }
}

impl Blueprint {
    pub fn from_yaml(yaml: &str) -> Result<Self, BlueprintError> {
        Self::from_yaml_with_resolver(yaml, &DefaultInterpolationResolver)
    }

    pub fn from_yaml_with_resolver(
        yaml: &str,
        resolver: &dyn InterpolationResolver,
    ) -> Result<Self, BlueprintError> {
        let mut value: Value = serde_yaml::from_str(yaml).map_err(BlueprintError::ParseYaml)?;
        interpolate_value(&mut value, resolver, "$")?;
        serde_yaml::from_value(value).map_err(BlueprintError::Deserialize)
    }
}

fn interpolate_value(
    value: &mut Value,
    resolver: &dyn InterpolationResolver,
    path: &str,
) -> Result<(), BlueprintError> {
    if is_credentials_object_path(path) {
        return Ok(());
    }

    match value {
        Value::String(string) => {
            let updated =
                interpolate_string(string, resolver).map_err(|error| error.at_path(path))?;
            *string = updated;
            Ok(())
        }
        Value::Sequence(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                interpolate_value(item, resolver, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        Value::Mapping(map) => {
            for (key, item) in map.iter_mut() {
                let child_path = if path == "$" {
                    yaml_path_segment(key)
                } else {
                    format!("{path}.{}", yaml_path_segment(key))
                };
                interpolate_value(item, resolver, &child_path)?;
            }
            Ok(())
        }
        Value::Tagged(tagged) => interpolate_value(&mut tagged.value, resolver, path),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn interpolate_string(
    input: &str,
    resolver: &dyn InterpolationResolver,
) -> Result<String, BlueprintError> {
    let mut output = String::new();
    let mut remaining = input;

    while let Some(start) = remaining.find("${") {
        output.push_str(&remaining[..start]);
        let expr_start = start + 2;
        let expr_end = remaining[expr_start..]
            .find('}')
            .map(|offset| expr_start + offset)
            .ok_or_else(|| BlueprintError::InvalidInterpolation {
                expression: remaining[start..].to_string(),
            })?;
        let expression = &remaining[expr_start..expr_end];
        let replacement = if let Some(name) = expression.strip_prefix("credstore:") {
            if name.is_empty() {
                return Err(BlueprintError::InvalidInterpolation {
                    expression: expression.to_string(),
                });
            }
            resolver.resolve_credstore(name)?
        } else {
            if expression.is_empty() {
                return Err(BlueprintError::InvalidInterpolation {
                    expression: expression.to_string(),
                });
            }
            resolver.resolve_env(expression)?
        };
        output.push_str(&replacement);
        remaining = &remaining[expr_end + 1..];
    }

    output.push_str(remaining);
    Ok(output)
}

fn is_credentials_object_path(path: &str) -> bool {
    let mut segments = path.split('.');
    while let Some(segment) = segments.next() {
        if segment == "credentials" {
            return segments.next().is_some();
        }
    }

    false
}

fn yaml_path_segment(value: &Value) -> String {
    match value {
        Value::String(key) => key.clone(),
        other => match serde_yaml::to_string(other) {
            Ok(rendered) => rendered.trim().to_string(),
            Err(_) => "<non-string-key>".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_otel_endpoint_parses_and_roundtrips() {
        let yaml = r#"
version: "0.1"
min_agentenv_version: "0.0.1"
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
policy:
  tier: restricted
observability:
  otel:
    endpoint: grpc://collector:4317
"#;

        let blueprint = Blueprint::from_yaml(yaml).expect("parse blueprint");
        let endpoint = blueprint
            .observability
            .as_ref()
            .and_then(|section| section.otel.as_ref())
            .and_then(|otel| otel.endpoint.as_deref());
        assert_eq!(endpoint, Some("grpc://collector:4317"));

        let rendered = serde_yaml::to_string(&blueprint).expect("serialize blueprint");
        assert!(
            rendered.contains("observability:"),
            "rendered blueprint did not preserve observability: {rendered}"
        );
        assert!(
            rendered.contains("endpoint: grpc://collector:4317"),
            "rendered blueprint did not preserve OTEL endpoint: {rendered}"
        );
    }
}
