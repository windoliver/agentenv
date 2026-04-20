#![forbid(unsafe_code)]

pub mod jsonrpc;

pub use jsonrpc::{
    read_framed_json_blocking, write_framed_json_blocking, JsonRpcClient, JsonRpcClientConfig,
    JsonRpcError, RpcErrorObject, RpcNotificationEnvelope, RpcResponseEnvelope,
};
