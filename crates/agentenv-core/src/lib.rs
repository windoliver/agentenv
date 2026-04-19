#![forbid(unsafe_code)]

pub mod blueprint;
pub mod digest;
pub mod driver;
pub mod error;
pub mod lifecycle;
pub mod lockfile;
pub mod registry;
pub mod security;

/// Placeholder surface for the M1 workspace scaffold.
pub const CRATE_NAME: &str = "agentenv-core";
