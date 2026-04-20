#![forbid(unsafe_code)]

use std::{
    collections::{btree_map::Entry, BTreeMap},
    sync::{Mutex, MutexGuard},
};

use agentenv_core::{
    context_common::{
        context_initialize, endpoint_host_rule, object_required_string,
        remote_context_capabilities, required_object, successful_preflight,
    },
    driver::{ContextDriver, DriverError, DriverResult},
    security::ssrf::{DnsResolver, SsrfOptions, SystemDnsResolver},
};
use agentenv_mcp::validate_mcp_endpoint;
use agentenv_proto::{
    ContextHandle, ContextHandleRequest, ContextSpec, ContextStatus, CredentialKind,
    CredentialRequirement, CredentialRequirementsParams, CredentialRequirementsResult, EmptyResult,
    InitializeParams, InitializeResult, McpEndpoint, McpTransport, PreflightParams,
    PreflightResult, RequiredNetworkRulesResult, ShutdownParams,
};
use async_trait::async_trait;
use serde_json::json;

pub const CRATE_NAME: &str = "context-mcp-generic";
const DRIVER_NAME: &str = "mcp-generic";

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub enum ProbeExpectation {
    ValidInitialize,
    InvalidInitialize,
}

#[derive(Debug, Clone)]
struct GenericMcpState {
    endpoint: McpEndpoint,
}

#[derive(Debug)]
struct GenericMcpStore {
    next_id: u64,
    states: BTreeMap<String, GenericMcpState>,
}

#[derive(Debug, Clone, Copy)]
struct ProbeSettings {
    enabled: bool,
    validate_ssrf: bool,
}

#[derive(Debug)]
pub struct GenericMcpContextDriver {
    store: Mutex<GenericMcpStore>,
    probe: ProbeSettings,
}

impl Default for GenericMcpContextDriver {
    fn default() -> Self {
        Self {
            store: Mutex::new(GenericMcpStore {
                next_id: 1,
                states: BTreeMap::new(),
            }),
            probe: ProbeSettings {
                enabled: true,
                validate_ssrf: true,
            },
        }
    }
}

impl GenericMcpContextDriver {
    pub fn new_for_tests_without_probe() -> Self {
        Self {
            probe: ProbeSettings {
                enabled: false,
                validate_ssrf: false,
            },
            ..Self::default()
        }
    }

    fn state(&self, handle: &str) -> DriverResult<GenericMcpState> {
        let store = self.store()?;
        store
            .states
            .get(handle)
            .cloned()
            .ok_or_else(|| invalid_handle(handle))
    }

    fn store(&self) -> DriverResult<MutexGuard<'_, GenericMcpStore>> {
        self.store.lock().map_err(|_| DriverError::CleanupFailed {
            message: "generic MCP context store mutex poisoned".to_owned(),
        })
    }
}

#[async_trait]
impl ContextDriver for GenericMcpContextDriver {
    async fn initialize(&mut self, _params: InitializeParams) -> DriverResult<InitializeResult> {
        Ok(context_initialize(
            DRIVER_NAME,
            remote_context_capabilities(),
        ))
    }

    async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
        Ok(successful_preflight())
    }

    async fn provision(&self, spec: ContextSpec) -> DriverResult<ContextHandle> {
        let endpoint = endpoint_from_spec(&spec)?;
        if self.probe.validate_ssrf {
            validate_endpoint_for_driver(&endpoint, &SystemDnsResolver)?;
        }

        if self.probe.enabled
            && matches!(
                endpoint.transport,
                McpTransport::Http | McpTransport::HttpSse
            )
        {
            probe_mcp_initialize(&endpoint.url).await?;
        }

        let mut store = self.store()?;
        let handle = loop {
            let handle = format!("{DRIVER_NAME}|{}", store.next_id);
            store.next_id += 1;
            if let Entry::Vacant(entry) = store.states.entry(handle.clone()) {
                entry.insert(GenericMcpState {
                    endpoint: endpoint.clone(),
                });
                break handle;
            }
        };

        Ok(ContextHandle { handle })
    }

    async fn mcp_endpoint(&self, params: ContextHandleRequest) -> DriverResult<McpEndpoint> {
        Ok(self.state(&params.handle)?.endpoint)
    }

    async fn required_network_rules(
        &self,
        params: ContextHandleRequest,
    ) -> DriverResult<RequiredNetworkRulesResult> {
        let endpoint = self.state(&params.handle)?.endpoint;
        Ok(RequiredNetworkRulesResult {
            rules: vec![endpoint_host_rule(&endpoint)?],
        })
    }

    async fn credential_requirements(
        &self,
        _params: CredentialRequirementsParams,
    ) -> DriverResult<CredentialRequirementsResult> {
        Ok(CredentialRequirementsResult {
            requirements: vec![CredentialRequirement {
                name: "MCP_TOKEN".to_owned(),
                description: "Optional bearer token for generic MCP endpoints.".to_owned(),
                kind: CredentialKind::Token,
                required: false,
                validator: None,
            }],
        })
    }

    async fn status(&self, params: ContextHandleRequest) -> DriverResult<ContextStatus> {
        self.state(&params.handle)?;
        Ok(ContextStatus {
            healthy: true,
            detail: Some("generic MCP endpoint configured".to_owned()),
        })
    }

    async fn teardown(&self, params: ContextHandleRequest) -> DriverResult<EmptyResult> {
        let mut store = self.store()?;
        store
            .states
            .remove(&params.handle)
            .ok_or_else(|| invalid_handle(&params.handle))?;
        Ok(EmptyResult::default())
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        Ok(EmptyResult::default())
    }
}

pub fn endpoint_from_spec(spec: &ContextSpec) -> DriverResult<McpEndpoint> {
    let endpoint = required_object(&spec.config, "endpoint")?;
    let url = object_required_string(endpoint, "url")?;
    let transport = match object_required_string(endpoint, "transport")?.as_str() {
        "http" => McpTransport::Http,
        "http+sse" => McpTransport::HttpSse,
        "ssh+http" => McpTransport::SshHttp,
        other => {
            return Err(DriverError::InvalidConfig {
                field: "endpoint.transport".to_owned(),
                message: format!("unsupported MCP transport `{other}`"),
            });
        }
    };

    Ok(McpEndpoint {
        url,
        transport,
        headers: BTreeMap::new(),
    })
}

pub fn validate_endpoint_for_driver(
    endpoint: &McpEndpoint,
    resolver: &dyn DnsResolver,
) -> DriverResult<()> {
    let options = SsrfOptions {
        allow_ssh_http: true,
        ..SsrfOptions::default()
    };

    validate_mcp_endpoint(endpoint, options, resolver)
        .map(|_| ())
        .map_err(|err| DriverError::InvalidConfig {
            field: "endpoint.url".to_owned(),
            message: err.to_string(),
        })
}

pub async fn probe_mcp_initialize(url: &str) -> DriverResult<()> {
    let request_body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "agentenv",
                "version": env!("CARGO_PKG_VERSION"),
            },
        },
    }))
    .map_err(|err| DriverError::PreflightFailed {
        message: format!("MCP initialize request serialization failed: {err}"),
    })?;

    let response = reqwest::Client::new()
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(request_body)
        .send()
        .await
        .map_err(|err| DriverError::PreflightFailed {
            message: format!("MCP initialize request failed: {err}"),
        })?;

    if !response.status().is_success() {
        return Err(DriverError::PreflightFailed {
            message: format!("MCP initialize returned HTTP {}", response.status()),
        });
    }

    let body = response
        .text()
        .await
        .map_err(|err| DriverError::PreflightFailed {
            message: format!("MCP initialize response read failed: {err}"),
        })?;
    let body: serde_json::Value =
        serde_json::from_str(&body).map_err(|err| DriverError::PreflightFailed {
            message: format!("MCP initialize response was not JSON: {err}"),
        })?;

    if body.get("jsonrpc").and_then(serde_json::Value::as_str) != Some("2.0")
        || body.get("id") != Some(&json!(1))
        || body.get("result").is_none()
        || body.get("result") == Some(&serde_json::Value::Null)
    {
        return Err(DriverError::PreflightFailed {
            message: "MCP initialize response did not contain a JSON-RPC result".to_owned(),
        });
    }

    Ok(())
}

fn invalid_handle(handle: &str) -> DriverError {
    DriverError::InvalidHandle {
        handle: handle.to_owned(),
        message: "unknown generic MCP context handle".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use agentenv_core::{driver::ContextDriver, security::ssrf::StaticDnsResolver};
    use agentenv_proto::{
        Capabilities, ContextHandleRequest, ContextSpec, CredentialRequirementsParams,
        InitializeParams, LogLevel, McpTransport, NetworkTarget, SCHEMA_VERSION,
    };
    use serde_json::{json, Value};

    use super::{
        endpoint_from_spec, probe_mcp_initialize, validate_endpoint_for_driver,
        GenericMcpContextDriver, ProbeExpectation,
    };

    fn init_params() -> InitializeParams {
        InitializeParams {
            schema_version: SCHEMA_VERSION.to_owned(),
            core_version: "0.0.1-alpha0".to_owned(),
            workdir: "/tmp/agentenv-test".to_owned(),
            log_level: LogLevel::Info,
        }
    }

    fn spec(url: &str, transport: &str) -> ContextSpec {
        ContextSpec {
            config: BTreeMap::from([(
                "endpoint".to_owned(),
                json!({
                    "url": url,
                    "transport": transport,
                }),
            )]),
        }
    }

    #[test]
    fn endpoint_from_spec_accepts_http_sse() {
        let endpoint =
            endpoint_from_spec(&spec("https://mcp.example.com/sse", "http+sse")).unwrap();

        assert_eq!(endpoint.url, "https://mcp.example.com/sse");
        assert_eq!(endpoint.transport, McpTransport::HttpSse);
        assert!(endpoint.headers.is_empty());
    }

    #[test]
    fn endpoint_from_spec_rejects_unsupported_transport() {
        let err =
            endpoint_from_spec(&spec("https://mcp.example.com/sse", "websocket")).unwrap_err();

        assert!(err.to_string().contains("unsupported MCP transport"));
    }

    #[test]
    fn endpoint_validation_rejects_ssrf_blocked_targets() {
        let endpoint =
            endpoint_from_spec(&spec("https://metadata.example.test/sse", "http+sse")).unwrap();
        let resolver =
            StaticDnsResolver::try_from_pairs([("metadata.example.test", ["169.254.169.254"])])
                .unwrap();

        let err = validate_endpoint_for_driver(&endpoint, &resolver).unwrap_err();

        assert!(err.to_string().contains("blocked"));
    }

    #[tokio::test]
    async fn initialize_probe_accepts_mock_mcp_response() {
        let server = spawn_probe_server(ProbeExpectation::ValidInitialize);

        probe_mcp_initialize(&server.url()).await.unwrap();
    }

    #[tokio::test]
    async fn initialize_probe_rejects_non_mcp_response() {
        let server = spawn_probe_server(ProbeExpectation::InvalidInitialize);

        let err = probe_mcp_initialize(&server.url()).await.unwrap_err();

        assert!(err.to_string().contains("MCP initialize"));
    }

    #[tokio::test]
    async fn driver_reports_remote_shared_capabilities() {
        let mut driver = GenericMcpContextDriver::new_for_tests_without_probe();
        let result = driver.initialize(init_params()).await.unwrap();

        assert_eq!(result.driver.name, "mcp-generic");
        let Capabilities::Context(capabilities) = result.capabilities else {
            panic!("expected context capabilities");
        };
        assert!(capabilities.is_remote);
        assert!(capabilities.is_shared);
        assert!(!capabilities.supports_zones);
        assert!(!capabilities.supports_snapshots);
    }

    #[tokio::test]
    async fn provision_stores_endpoint_and_network_rule_without_query_in_handle() {
        let driver = GenericMcpContextDriver::new_for_tests_without_probe();
        let handle = driver
            .provision(spec(
                "https://mcp.example.com:8443/sse?state=abc",
                "http+sse",
            ))
            .await
            .unwrap();

        assert!(!handle.handle.contains("state=abc"));

        let request = ContextHandleRequest {
            handle: handle.handle,
        };
        let endpoint = driver.mcp_endpoint(request.clone()).await.unwrap();
        let rules = driver.required_network_rules(request).await.unwrap();

        assert_eq!(endpoint.url, "https://mcp.example.com:8443/sse?state=abc");
        assert_eq!(rules.rules.len(), 1);
        let NetworkTarget::Host {
            host, port, scheme, ..
        } = &rules.rules[0].target
        else {
            panic!("expected host network rule");
        };
        assert_eq!(host, "mcp.example.com");
        assert_eq!(port, &Some(8443));
        assert_eq!(scheme.as_deref(), Some("https"));
    }

    #[tokio::test]
    async fn credential_requirements_declare_optional_mcp_token() {
        let driver = GenericMcpContextDriver::new_for_tests_without_probe();
        let requirements = driver
            .credential_requirements(CredentialRequirementsParams::default())
            .await
            .unwrap();

        assert_eq!(requirements.requirements.len(), 1);
        assert_eq!(requirements.requirements[0].name, "MCP_TOKEN");
        assert!(!requirements.requirements[0].required);
    }

    #[tokio::test]
    async fn generic_driver_satisfies_context_conformance_contract() {
        let mut driver = GenericMcpContextDriver::new_for_tests_without_probe();

        driver_conformance::assert_context_driver_contract(
            &mut driver,
            spec("https://mcp.example.com/sse", "http+sse"),
        )
        .await
        .unwrap();
    }

    struct ProbeServer {
        url: String,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl ProbeServer {
        fn url(&self) -> String {
            self.url.clone()
        }
    }

    impl Drop for ProbeServer {
        fn drop(&mut self) {
            if let Some(thread) = self.thread.take() {
                thread.join().expect("probe server thread should finish");
            }
        }
    }

    fn spawn_probe_server(expectation: ProbeExpectation) -> ProbeServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0; 4096];
            let read = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..read]);
            assert!(request.contains("initialize"));

            let body: Value = match expectation {
                ProbeExpectation::ValidInitialize => json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "serverInfo": {"name": "mock", "version": "0.0.1"}
                    }
                }),
                ProbeExpectation::InvalidInitialize => json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": null
                }),
            };
            let body = serde_json::to_string(&body).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });

        ProbeServer {
            url,
            thread: Some(thread),
        }
    }
}
