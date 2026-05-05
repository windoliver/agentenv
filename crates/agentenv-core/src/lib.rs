#![forbid(unsafe_code)]

pub mod admission;
pub mod agent_common;
pub mod blueprint;
pub mod context_common;
pub mod digest;
pub mod driver;
pub mod driver_artifact;
pub mod driver_catalog;
pub mod env;
pub mod error;
pub mod inference;
pub mod lifecycle;
pub mod lockfile;
pub mod portable_lockfile;
pub mod registry;
pub mod runtime;
pub mod security;
pub mod sessions;
pub mod snapshot;

/// Placeholder surface for the M1 workspace scaffold.
pub const CRATE_NAME: &str = "agentenv-core";
