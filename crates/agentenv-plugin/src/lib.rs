#![forbid(unsafe_code)]

pub mod agent;
pub mod context;
pub mod jsonrpc;

pub use agent::{validate_agent_initialize, SubprocessAgentDriver};
pub use context::{validate_context_initialize, SubprocessContextDriver};
pub use jsonrpc::{
    notification_to_activity_event, read_framed_json_blocking, write_framed_json_blocking,
    JsonRpcClient, JsonRpcClientConfig, JsonRpcError, RpcErrorObject, RpcNotificationEnvelope,
    RpcResponseEnvelope,
};
