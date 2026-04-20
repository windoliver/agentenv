use std::{collections::BTreeMap, path::PathBuf};

use agentenv_proto::{
    Capabilities, ContextCapabilities, CredentialRequirementsResult, DriverInfo, DriverKind,
    EmptyResult, HttpAccessLevel, InitializeResult, McpEndpoint, NetworkRule, NetworkTarget,
    PreflightResult, RequiredNetworkRulesResult, SCHEMA_VERSION,
};
use serde_json::{Map, Value};

use crate::driver::{DriverError, DriverResult};

pub fn context_initialize(
    driver_name: &str,
    capabilities: ContextCapabilities,
) -> InitializeResult {
    InitializeResult {
        driver: DriverInfo {
            name: driver_name.to_owned(),
            kind: DriverKind::Context,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_version: SCHEMA_VERSION.to_owned(),
        },
        capabilities: Capabilities::Context(capabilities),
    }
}

pub fn local_context_capabilities() -> ContextCapabilities {
    ContextCapabilities {
        is_remote: false,
        is_shared: false,
        supports_zones: false,
        supports_snapshots: false,
    }
}

pub fn remote_context_capabilities() -> ContextCapabilities {
    ContextCapabilities {
        is_remote: true,
        is_shared: true,
        supports_zones: false,
        supports_snapshots: false,
    }
}

pub fn successful_preflight() -> PreflightResult {
    PreflightResult {
        ok: true,
        issues: Vec::new(),
    }
}

pub fn empty_result() -> EmptyResult {
    EmptyResult {}
}

pub fn empty_network_rules() -> RequiredNetworkRulesResult {
    RequiredNetworkRulesResult { rules: Vec::new() }
}

pub fn empty_credential_requirements() -> CredentialRequirementsResult {
    CredentialRequirementsResult {
        requirements: Vec::new(),
    }
}

pub fn required_string(config: &BTreeMap<String, Value>, field: &str) -> DriverResult<String> {
    match config.get(field) {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value.clone()),
        Some(Value::String(_)) => Err(invalid_config(field, "must not be empty")),
        Some(_) => Err(invalid_config(field, "must be a string")),
        None => Err(invalid_config(field, "is required")),
    }
}

pub fn optional_string(
    config: &BTreeMap<String, Value>,
    field: &str,
) -> DriverResult<Option<String>> {
    match config.get(field) {
        None => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) => Err(invalid_config(field, "must not be empty")),
        Some(_) => Err(invalid_config(field, "must be a string")),
    }
}

pub fn optional_bool(config: &BTreeMap<String, Value>, field: &str) -> DriverResult<Option<bool>> {
    match config.get(field) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(invalid_config(field, "must be a boolean")),
    }
}

pub fn optional_string_list(
    config: &BTreeMap<String, Value>,
    field: &str,
) -> DriverResult<Vec<String>> {
    match config.get(field) {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .enumerate()
            .map(|(index, value)| match value {
                Value::String(item) if !item.trim().is_empty() => Ok(item.clone()),
                Value::String(_) => Err(invalid_config(
                    field,
                    &format!("item {index} must not be empty"),
                )),
                _ => Err(invalid_config(
                    field,
                    &format!("item {index} must be a string"),
                )),
            })
            .collect(),
        Some(_) => Err(invalid_config(field, "must be an array of strings")),
    }
}

pub fn required_object<'a>(
    config: &'a BTreeMap<String, Value>,
    field: &str,
) -> DriverResult<&'a Map<String, Value>> {
    match config.get(field) {
        Some(Value::Object(object)) => Ok(object),
        Some(_) => Err(invalid_config(field, "must be an object")),
        None => Err(invalid_config(field, "is required")),
    }
}

pub fn object_required_string(object: &Map<String, Value>, field: &str) -> DriverResult<String> {
    match object.get(field) {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value.clone()),
        Some(Value::String(_)) => Err(invalid_config(field, "must not be empty")),
        Some(_) => Err(invalid_config(field, "must be a string")),
        None => Err(invalid_config(field, "is required")),
    }
}

pub fn endpoint_host_rule(endpoint: &McpEndpoint) -> DriverResult<NetworkRule> {
    let parsed = url::Url::parse(&endpoint.url)
        .map_err(|_| invalid_config("endpoint.url", "must be a valid URL"))?;

    let host = parsed
        .host_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_config("endpoint.url", "must include a host"))?;
    let port = parsed.port_or_known_default();
    let scheme = Some(parsed.scheme().to_owned());

    Ok(NetworkRule {
        target: NetworkTarget::Host {
            host,
            port,
            scheme,
            http_access: Some(HttpAccessLevel::Full),
        },
    })
}

pub fn expand_tilde(path: &str, home: Option<&str>) -> PathBuf {
    match (path.strip_prefix("~/"), home) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ if path == "~" => home.map_or_else(|| PathBuf::from(path), PathBuf::from),
        _ => PathBuf::from(path),
    }
}

pub fn invalid_config(field: &str, message: &str) -> DriverError {
    DriverError::InvalidConfig {
        field: field.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use agentenv_proto::{
        Capabilities, ContextCapabilities, ContextSpec, DriverKind, HttpAccessLevel, McpEndpoint,
        McpTransport, NetworkTarget, SCHEMA_VERSION,
    };
    use serde_json::json;

    use super::{
        context_initialize, empty_credential_requirements, empty_network_rules, empty_result,
        endpoint_host_rule, expand_tilde, local_context_capabilities, object_required_string,
        optional_bool, optional_string, optional_string_list, remote_context_capabilities,
        required_object, required_string, successful_preflight,
    };

    #[test]
    fn context_initialize_reports_context_driver_metadata() {
        let result = context_initialize("filesystem", local_context_capabilities());

        assert_eq!(result.driver.name, "filesystem");
        assert_eq!(result.driver.kind, DriverKind::Context);
        assert_eq!(result.driver.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(result.driver.protocol_version, SCHEMA_VERSION);
        let Capabilities::Context(capabilities) = result.capabilities else {
            panic!("expected context capabilities");
        };
        assert_eq!(
            capabilities,
            ContextCapabilities {
                is_remote: false,
                is_shared: false,
                supports_zones: false,
                supports_snapshots: false,
            }
        );
    }

    #[test]
    fn remote_context_capabilities_are_remote_and_shared() {
        assert_eq!(
            remote_context_capabilities(),
            ContextCapabilities {
                is_remote: true,
                is_shared: true,
                supports_zones: false,
                supports_snapshots: false,
            }
        );
    }

    #[test]
    fn config_helpers_parse_expected_types() {
        let spec = ContextSpec {
            config: BTreeMap::from([
                ("mount".to_owned(), json!("/tmp/project")),
                ("nickname".to_owned(), json!("alice")),
                ("readonly".to_owned(), json!(false)),
                ("exclude".to_owned(), json!([".git/", "target/"])),
                (
                    "endpoint".to_owned(),
                    json!({"url": "https://example.com/mcp"}),
                ),
            ]),
        };

        assert_eq!(
            required_string(&spec.config, "mount").unwrap(),
            "/tmp/project"
        );
        assert_eq!(
            optional_string(&spec.config, "nickname").unwrap(),
            Some("alice".to_owned())
        );
        assert_eq!(
            optional_bool(&spec.config, "readonly").unwrap(),
            Some(false)
        );
        assert_eq!(
            optional_string_list(&spec.config, "exclude").unwrap(),
            vec![".git/".to_owned(), "target/".to_owned()]
        );
        assert_eq!(
            required_object(&spec.config, "endpoint")
                .unwrap()
                .get("url")
                .unwrap(),
            &json!("https://example.com/mcp")
        );
    }

    #[test]
    fn config_helpers_reject_invalid_types_and_empty_strings() {
        let spec = ContextSpec {
            config: BTreeMap::from([
                ("nickname".to_owned(), json!(42)),
                ("profile".to_owned(), json!("")),
            ]),
        };

        let err = optional_string(&spec.config, "nickname").expect_err("wrong type must fail");
        assert!(matches!(
            err,
            crate::driver::DriverError::InvalidConfig { field, message }
                if field == "nickname" && message == "must be a string"
        ));

        let err = object_required_string(
            required_object(
                &BTreeMap::from([("profile".to_owned(), json!({"name": ""}))]),
                "profile",
            )
            .unwrap(),
            "name",
        )
        .expect_err("empty string must fail");
        assert!(matches!(
            err,
            crate::driver::DriverError::InvalidConfig { field, message }
                if field == "name" && message == "must not be empty"
        ));
    }

    #[test]
    fn endpoint_host_rule_preserves_host_port_scheme_and_full_access() {
        let rule = endpoint_host_rule(&McpEndpoint {
            url: "https://mcp.example.com:8443/sse".to_owned(),
            transport: McpTransport::HttpSse,
            headers: BTreeMap::new(),
        })
        .unwrap();

        let NetworkTarget::Host {
            host,
            port,
            scheme,
            http_access,
        } = rule.target
        else {
            panic!("expected host rule");
        };

        assert_eq!(host, "mcp.example.com");
        assert_eq!(port, Some(8443));
        assert_eq!(scheme.as_deref(), Some("https"));
        assert_eq!(http_access, Some(HttpAccessLevel::Full));
    }

    #[test]
    fn empty_results_are_empty() {
        assert_eq!(empty_result(), agentenv_proto::EmptyResult {});
        assert!(empty_network_rules().rules.is_empty());
        assert!(empty_credential_requirements().requirements.is_empty());
    }

    #[test]
    fn successful_preflight_reports_ok_without_issues() {
        assert_eq!(successful_preflight().ok, true);
        assert!(successful_preflight().issues.is_empty());
    }

    #[test]
    fn tilde_expansion_uses_home_when_available() {
        let expanded = expand_tilde("~/project", Some("/home/alice"));

        assert_eq!(expanded.to_string_lossy(), "/home/alice/project");
    }

    #[test]
    fn tilde_expansion_handles_root_and_plain_paths() {
        assert_eq!(
            expand_tilde("~", Some("/home/alice")).to_string_lossy(),
            "/home/alice"
        );
        assert_eq!(
            expand_tilde("plain/path", Some("/home/alice")).to_string_lossy(),
            "plain/path"
        );
    }
}
