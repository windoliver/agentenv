#![forbid(unsafe_code)]

pub mod admission;
pub mod agent_common;
pub mod blueprint;
pub mod bundle;
pub mod context_common;
pub mod digest;
pub mod driver;
pub mod driver_artifact;
pub mod driver_catalog;
pub mod egress_proxy;
pub mod env;
pub mod error;
pub mod eval;
pub mod hardening;
pub mod inference;
pub mod lifecycle;
pub mod lockfile;
pub mod portable_lockfile;
pub mod registry;
pub mod runtime;
pub mod security;
pub mod sessions;
pub mod skills;
pub mod snapshot;

/// Placeholder surface for the M1 workspace scaffold.
pub const CRATE_NAME: &str = "agentenv-core";

#[cfg(test)]
pub(crate) fn env_var_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    ENV_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .expect("env var test lock")
}
