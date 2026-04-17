#![forbid(unsafe_code)]

pub mod blueprint;
pub mod digest;
pub mod error;
pub mod lifecycle;
pub mod lockfile;
pub mod registry;

/// Placeholder surface for the M1 workspace scaffold.
pub const CRATE_NAME: &str = "agentenv-core";
