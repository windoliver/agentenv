use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const JSON_RPC_PARSE_ERROR: i64 = -32700;
pub const JSON_RPC_INVALID_REQUEST: i64 = -32600;
pub const JSON_RPC_METHOD_NOT_FOUND: i64 = -32601;
pub const JSON_RPC_INVALID_PARAMS: i64 = -32602;
pub const JSON_RPC_INTERNAL_ERROR: i64 = -32603;
pub const ERROR_CAPABILITY_MISSING: i64 = -32000;
pub const ERROR_PREFLIGHT_FAILED: i64 = -32001;
pub const ERROR_SCHEMA_VERSION_INCOMPATIBLE: i64 = -32002;
pub const ERROR_RESOURCE_NOT_FOUND: i64 = -32003;
pub const ERROR_CREDENTIAL_MISSING: i64 = -32004;
pub const ERROR_POLICY_TRANSLATION_FAILED: i64 = -32005;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DriverKind {
    Sandbox,
    Agent,
    Context,
    Inference,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IssueSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxPhase {
    Creating,
    Running,
    Stopped,
    Destroyed,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    EgressDenied,
    ApprovalRequested,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RichActivityKind {
    SandboxCreate,
    SandboxDestroy,
    Exec,
    EgressAllowed,
    EgressDenied,
    McpToolCall,
    PolicyApplied,
    CredentialInjected,
    CredentialSet,
    CredentialReset,
    Auth,
    ApprovalRequested,
    ApprovalDecided,
    SpawnRequested,
    SpawnQueued,
    SpawnAdmitted,
    SpawnRejected,
    SpawnStarted,
    SpawnReady,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RichActivityResult {
    Ok,
    Error,
    Denied,
    PendingApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    EgressHost,
    McpTool,
    ZoneAccess,
    PackageInstall,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum ApprovalScope {
    #[serde(rename = "once")]
    Once,
    #[serde(rename = "session")]
    Session,
    #[serde(rename = "persist-sandbox")]
    PersistSandbox,
    #[serde(rename = "propose-for-baseline")]
    ProposeForBaseline,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum McpTransport {
    #[serde(rename = "stdio")]
    Stdio,
    #[serde(rename = "http")]
    Http,
    #[serde(rename = "http+sse")]
    HttpSse,
    #[serde(rename = "ssh+http")]
    SshHttp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum McpApprovalMode {
    Never,
    PerCall,
    PerSession,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceTag {
    Trusted,
    Tenant,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceSourceKind {
    Operator,
    SignedBlueprint,
    LocalFile,
    LocalRepo,
    Web,
    GithubIssue,
    RemoteMcp,
    ToolResult,
    Approval,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceSummary {
    pub tag: ProvenanceTag,
    pub source_kind: ProvenanceSourceKind,
    pub source_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolCapability {
    ReadFs,
    WriteFs,
    Exec,
    GitRead,
    GitWrite,
    Network,
    McpTool,
    CredentialBroker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolArgumentPolicy {
    pub pointer: String,
    pub max_input_taint: ProvenanceTag,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolCapabilityDeclaration {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<ToolCapability>,
    pub max_input_taint: ProvenanceTag,
    #[serde(default = "default_mcp_approval")]
    pub approval: McpApprovalMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argument_policies: Vec<ToolArgumentPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpProvenanceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub required: bool,
    #[serde(default = "default_unannotated_source")]
    pub default_unannotated_source: ProvenanceTag,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpGuardConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mcp_approval")]
    pub default_approval: McpApprovalMode,
    #[serde(default)]
    pub tool_policies: BTreeMap<String, McpToolPolicy>,
    #[serde(default)]
    pub cross_tool_flows: McpCrossToolFlowPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<McpProvenanceConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tool_capabilities: BTreeMap<String, ToolCapabilityDeclaration>,
}

impl Default for McpGuardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_approval: McpApprovalMode::Never,
            tool_policies: BTreeMap::new(),
            cross_tool_flows: McpCrossToolFlowPolicy::default(),
            provenance: None,
            tool_capabilities: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpToolPolicy {
    #[serde(default)]
    pub approval: Option<McpApprovalMode>,
    #[serde(default, deserialize_with = "deserialize_mcp_rate_limit")]
    pub rate_limit: Option<McpSessionRateLimit>,
    #[serde(default)]
    pub url_allowlist: Vec<String>,
    #[serde(default)]
    pub redact_args: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpCrossToolFlowPolicy {
    #[serde(default)]
    pub forbid_read_to_write_turns: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct McpSessionRateLimit {
    pub calls: u32,
}

fn default_mcp_approval() -> McpApprovalMode {
    McpApprovalMode::Never
}

fn default_unannotated_source() -> ProvenanceTag {
    ProvenanceTag::Untrusted
}

fn deserialize_mcp_rate_limit<'de, D>(
    deserializer: D,
) -> Result<Option<McpSessionRateLimit>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RateLimitWire {
        Text(String),
        Object { calls: u32 },
    }

    let wire = Option::<RateLimitWire>::deserialize(deserializer)?;
    match wire {
        Some(RateLimitWire::Text(value)) => parse_mcp_session_rate_limit(&value)
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(RateLimitWire::Object { calls }) => Ok(Some(McpSessionRateLimit { calls })),
        None => Ok(None),
    }
}

fn parse_mcp_session_rate_limit(value: &str) -> Result<McpSessionRateLimit, String> {
    let (calls, scope) = value
        .split_once('/')
        .ok_or_else(|| "expected MCP rate limit in the form <calls>/session".to_owned())?;
    if scope != "session" {
        return Err("only MCP rate limits scoped to /session are supported".to_owned());
    }
    let calls = calls
        .parse::<u32>()
        .map_err(|_| "MCP rate limit calls must be an unsigned integer".to_owned())?;
    Ok(McpSessionRateLimit { calls })
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct DriverInfo {
    pub name: String,
    pub kind: DriverKind,
    pub version: String,
    pub protocol_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct SandboxCapabilities {
    pub supports_hot_reload_policy: bool,
    pub supports_filesystem_lockdown: bool,
    pub supports_syscall_filter: bool,
    pub supports_native_inference_routing: bool,
    pub supports_remote_host: bool,
    #[serde(default)]
    pub supports_host_egress_proxy: bool,
    #[serde(default)]
    pub supports_persistent_sessions: bool,
    #[serde(default)]
    pub supports_dns_egress_control: bool,
    #[serde(default)]
    pub supports_snapshots: bool,
    #[serde(default)]
    pub supports_fork: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct AgentCapabilities {
    pub supports_mcp: bool,
    pub supports_slash_commands: bool,
    pub supports_tui: bool,
    pub supports_headless: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ContextCapabilities {
    pub is_remote: bool,
    pub is_shared: bool,
    pub supports_zones: bool,
    pub supports_snapshots: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct InferenceCapabilities {
    pub strips_caller_credentials: bool,
    pub supports_model_switching: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(untagged)]
pub enum Capabilities {
    Sandbox(SandboxCapabilities),
    Agent(AgentCapabilities),
    Context(ContextCapabilities),
    Inference(InferenceCapabilities),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct InitializeParams {
    pub schema_version: String,
    pub core_version: String,
    pub workdir: String,
    pub log_level: LogLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct InitializeResult {
    pub driver: DriverInfo,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
pub struct PreflightParams {}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PreflightIssue {
    pub severity: IssueSeverity,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PreflightResult {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<PreflightIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
pub struct ShutdownParams {}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
pub struct EmptyResult {}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyReloadability {
    HotReload,
    LockedAtCreate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpAccessLevel {
    ReadOnly,
    ReadWrite,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetworkTarget {
    Host {
        host: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        http_access: Option<HttpAccessLevel>,
    },
    Cidr {
        cidr: String,
    },
    Port {
        port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protocol: Option<String>,
    },
    UrlPattern {
        pattern: String,
    },
    HttpMethodPath {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        method: String,
        path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct NetworkRule {
    pub target: NetworkTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
pub struct DnsPolicy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers_allowed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub doh_upstreams_allowed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dot_upstreams_allowed: Vec<String>,
    #[serde(default)]
    pub log_all_queries: bool,
    #[serde(default)]
    pub pin_resolved_ips: bool,
}

impl DnsPolicy {
    pub fn is_active(&self) -> bool {
        !self.is_inactive()
    }

    pub fn is_inactive(&self) -> bool {
        self.resolvers_allowed.is_empty()
            && self.doh_upstreams_allowed.is_empty()
            && self.dot_upstreams_allowed.is_empty()
            && !self.log_all_queries
            && !self.pin_resolved_ips
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct NetworkAccessPolicy {
    pub reloadability: PolicyReloadability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<NetworkRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<NetworkRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_required: Vec<NetworkRule>,
    #[serde(default, skip_serializing_if = "DnsPolicy::is_inactive")]
    pub dns: DnsPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct FilesystemPolicy {
    pub reloadability: PolicyReloadability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_only: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_write: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ProcessPolicy {
    pub reloadability: PolicyReloadability,
    pub run_as_user: String,
    pub run_as_group: String,
    pub profile: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_syscalls: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_syscalls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct InferenceRoute {
    pub matcher: String,
    pub provider: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct InferencePolicy {
    pub reloadability: PolicyReloadability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<InferenceRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub network: NetworkAccessPolicy,
    pub filesystem: FilesystemPolicy,
    pub process: ProcessPolicy,
    pub inference: InferencePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    #[default]
    ApiKey,
    Token,
    Certificate,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ValidatorSpec {
    Regex { pattern: String },
    CurlProbe { url: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CredentialRequirement {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub kind: CredentialKind,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator: Option<ValidatorSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct SandboxSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<NetworkPolicy>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct SandboxHandle {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct SnapshotParams {
    pub handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct SnapshotId {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ForkSpec {
    pub name: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ForkFromSnapshotParams {
    pub snapshot: SnapshotId,
    pub spec: ForkSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ConnectParams {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ShellHandle {
    pub session_id: String,
    pub tty: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Starting,
    Attached,
    Detached,
    Exited,
    Killed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CreateSessionParams {
    pub handle: String,
    pub name: String,
    pub command: String,
    pub detached: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct AttachSessionParams {
    pub handle: String,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct KillSessionParams {
    pub handle: String,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ListSessionsParams {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct SessionHandle {
    pub session_id: String,
    pub name: String,
    pub status: SessionStatus,
    pub created_at: String,
    pub updated_at: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ListSessionsResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sessions: Vec<SessionHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ExecParams {
    pub handle: String,
    pub cmd: String,
    pub tty: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ExecResult {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CopyInParams {
    pub handle: String,
    pub src_host_path: String,
    pub dst_sandbox_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CopyOutParams {
    pub handle: String,
    pub src_sandbox_path: String,
    pub dst_host_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ApplyPolicyParams {
    pub handle: String,
    pub policy: NetworkPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ApplyPolicyResult {
    pub hot_reloaded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct SandboxStatusParams {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct SandboxStatus {
    pub phase: SandboxPhase,
    pub healthy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ping: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct LogsParams {
    pub handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    pub follow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct LogEntry {
    pub level: LogLevel,
    pub ts: String,
    pub msg: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub kv: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct LogsResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<LogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct LogsStreamParams {
    pub handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct StopParams {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct DestroyParams {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct AgentSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct AgentHealthCheckProbe {
    pub cmd: String,
    pub tty: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(
        default = "default_success_exit_codes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub success_exit_codes: Vec<i32>,
}

fn default_success_exit_codes() -> Vec<i32> {
    vec![0]
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct DockerfileFragment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct InstallStepsResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<DockerfileFragment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
pub struct McpConfigPathParams {}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct McpConfigPathResult {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct McpEndpoint {
    pub url: String,
    pub transport: McpTransport,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct RenderMcpConfigParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<McpEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct RenderMcpConfigResult {
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct RenderEntrypointResult {
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
pub struct CredentialRequirementsParams {}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CredentialRequirementsResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requirements: Vec<CredentialRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ContextSpec {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ContextHandle {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ContextHandleRequest {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct RequiredNetworkRulesResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<NetworkRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ContextStatus {
    pub healthy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct InferenceSpec {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct InferenceHandle {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct InferenceHandleRequest {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct EndpointInSandboxResult {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct EventLogParams {
    pub level: LogLevel,
    pub ts: String,
    pub msg: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub kv: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ActivityEventParams {
    pub kind: ActivityKind,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub ts: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct RichActivityEventParams {
    pub ts: String,
    pub kind: RichActivityKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub actor: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub subject: BTreeMap<String, Value>,
    pub result: RichActivityResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    pub trace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extras: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(untagged)]
pub enum DriverActivityEventParams {
    Rich(RichActivityEventParams),
    Legacy(ActivityEventParams),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ApprovalRequestedParams {
    pub request_id: String,
    pub kind: ApprovalKind,
    pub subject: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_ttl: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ApprovalDecisionParams {
    pub request_id: String,
    pub decision: ApprovalDecision,
    pub scope: ApprovalScope,
    pub decided_by: String,
    pub decided_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_capabilities_default_missing_host_egress_proxy_to_false() {
        let json = serde_json::json!({
            "supports_hot_reload_policy": true,
            "supports_filesystem_lockdown": false,
            "supports_syscall_filter": false,
            "supports_native_inference_routing": true,
            "supports_remote_host": false
        });

        let caps: SandboxCapabilities =
            serde_json::from_value(json).expect("capabilities deserialize");

        assert!(!caps.supports_host_egress_proxy);
    }

    #[test]
    fn approval_kind_accepts_package_install_wire_value() {
        let kind: ApprovalKind =
            serde_json::from_value(serde_json::json!("package_install")).unwrap();
        assert_eq!(kind, ApprovalKind::PackageInstall);
    }

    #[test]
    fn provenance_tag_serializes_stable_values() {
        assert_eq!(
            serde_json::to_value(ProvenanceTag::Trusted).unwrap(),
            serde_json::json!("trusted")
        );
        assert_eq!(
            serde_json::to_value(ProvenanceTag::Tenant).unwrap(),
            serde_json::json!("tenant")
        );
        assert_eq!(
            serde_json::to_value(ProvenanceTag::Untrusted).unwrap(),
            serde_json::json!("untrusted")
        );
    }

    #[test]
    fn mcp_guard_config_parses_full_yaml() {
        let yaml = r#"
enabled: true
default_approval: per-call
tool_policies:
  "filesystem.read":
    approval: never
    rate_limit: 50/session
  "web.fetch":
    approval: per-call
    url_allowlist: ["api.github.com", "crates.io"]
    redact_args: true
  "*.write":
    approval: per-session
cross_tool_flows:
  forbid_read_to_write_turns: 5
"#;

        let config: McpGuardConfig = serde_yaml::from_str(yaml).expect("config parses");

        assert!(config.enabled);
        assert_eq!(config.default_approval, McpApprovalMode::PerCall);
        assert_eq!(
            config.tool_policies["filesystem.read"].approval,
            Some(McpApprovalMode::Never)
        );
        assert_eq!(
            config.tool_policies["filesystem.read"].rate_limit,
            Some(McpSessionRateLimit { calls: 50 })
        );
        assert_eq!(
            config.tool_policies["web.fetch"].url_allowlist,
            vec!["api.github.com".to_owned(), "crates.io".to_owned()]
        );
        assert_eq!(config.cross_tool_flows.forbid_read_to_write_turns, Some(5));
    }

    #[test]
    fn mcp_guard_config_rejects_unknown_fields() {
        let yaml = r#"
enabled: true
surprise: true
"#;

        let error = serde_yaml::from_str::<McpGuardConfig>(yaml)
            .expect_err("unknown fields must fail closed");

        assert!(error.to_string().contains("surprise"));
    }

    #[test]
    fn mcp_guard_config_parses_provenance_and_tool_capabilities() {
        let yaml = r#"
enabled: true
default_approval: per-call
provenance:
  enabled: true
  required: true
  default_unannotated_source: untrusted
tool_capabilities:
  git.commit:
    caps: [git_write]
    max_input_taint: trusted
    approval: per-call
    argument_policies:
      - pointer: /message
        max_input_taint: trusted
  filesystem.read:
    caps: [read_fs]
    max_input_taint: tenant
    approval: never
"#;

        let config: McpGuardConfig = serde_yaml::from_str(yaml).expect("config parses");

        let provenance = config.provenance.expect("provenance config");
        assert!(provenance.enabled);
        assert!(provenance.required);
        assert_eq!(
            provenance.default_unannotated_source,
            ProvenanceTag::Untrusted
        );

        let git = config
            .tool_capabilities
            .get("git.commit")
            .expect("git.commit declaration");
        assert_eq!(git.caps, vec![ToolCapability::GitWrite]);
        assert_eq!(git.max_input_taint, ProvenanceTag::Trusted);
        assert_eq!(git.approval, McpApprovalMode::PerCall);
        assert_eq!(git.argument_policies[0].pointer, "/message");
        assert_eq!(
            git.argument_policies[0].max_input_taint,
            ProvenanceTag::Trusted
        );
    }

    #[test]
    fn mcp_guard_config_defaults_provenance_to_disabled() {
        let config: McpGuardConfig = serde_yaml::from_str("enabled: true\n").unwrap();

        assert!(config.provenance.is_none());
        assert!(config.tool_capabilities.is_empty());
    }
}
