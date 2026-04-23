use std::time::Duration;

use agentenv_core::{
    driver::{DriverError, InferenceDriver},
    driver_catalog::{DiscoveredDriver, DriverCatalog, DriverSource},
    registry::DriverKind as CatalogKind,
    runtime::{DriverFactory, DriverSelection, DriverSet, RuntimeError, RuntimeResult},
};

#[allow(dead_code)]
pub struct BuiltInDriverFactory;

const SUBPROCESS_DRIVER_TIMEOUT: Duration = Duration::from_secs(30);

impl DriverFactory for BuiltInDriverFactory {
    fn build(&self, selection: &DriverSelection) -> RuntimeResult<DriverSet> {
        let mut catalog = None;
        Ok(DriverSet {
            sandbox: match selection.sandbox.as_str() {
                "openshell" | "sandbox-openshell" => {
                    Box::new(sandbox_openshell::OpenShellDriver::default())
                }
                other => {
                    return Err(RuntimeError::UnsupportedDriver {
                        kind: "sandbox",
                        name: other.to_owned(),
                    });
                }
            },
            agent: match selection.agent.as_str() {
                "claude" | "agent-claude" => Box::new(agent_claude::ClaudeDriver),
                "codex" | "agent-codex" => Box::new(agent_codex::CodexDriver),
                "openclaw" | "agent-openclaw" => Box::new(agent_openclaw::OpenClawDriver),
                other => match subprocess_entry(&mut catalog, CatalogKind::Agent, other)? {
                    Some(entry) => Box::new(
                        agentenv_plugin::SubprocessAgentDriver::from_discovered_unstarted(
                            entry,
                            SUBPROCESS_DRIVER_TIMEOUT,
                        )?,
                    ),
                    None => {
                        return Err(RuntimeError::UnsupportedDriver {
                            kind: "agent",
                            name: other.to_owned(),
                        });
                    }
                },
            },
            context: match selection.context.as_str() {
                "filesystem" | "context-filesystem" => {
                    Box::new(context_filesystem::FilesystemContextDriver::default())
                }
                "mcp-generic" | "context-mcp-generic" => {
                    Box::new(context_mcp_generic::GenericMcpContextDriver::default())
                }
                "none" | "context-none" => Box::new(context_none::NoneContextDriver),
                other => match subprocess_entry(&mut catalog, CatalogKind::Context, other)? {
                    Some(entry) => Box::new(
                        agentenv_plugin::SubprocessContextDriver::from_discovered_unstarted(
                            entry,
                            SUBPROCESS_DRIVER_TIMEOUT,
                        )?,
                    ),
                    None => {
                        return Err(RuntimeError::UnsupportedDriver {
                            kind: "context",
                            name: other.to_owned(),
                        });
                    }
                },
            },
            inference: match selection.inference.as_deref() {
                None => None,
                Some("passthrough" | "inference-passthrough") => {
                    Some(Box::new(inference_passthrough::PassthroughInferenceDriver)
                        as Box<dyn InferenceDriver>)
                }
                Some("openai" | "inference-openai") => {
                    Some(Box::new(inference_openai::OpenAiInferenceDriver)
                        as Box<dyn InferenceDriver>)
                }
                Some("anthropic" | "inference-anthropic") => {
                    Some(Box::new(inference_anthropic::AnthropicInferenceDriver)
                        as Box<dyn InferenceDriver>)
                }
                Some("ollama" | "inference-ollama") => {
                    Some(Box::new(inference_ollama::OllamaInferenceDriver)
                        as Box<dyn InferenceDriver>)
                }
                Some(other) => {
                    return Err(RuntimeError::UnsupportedDriver {
                        kind: "inference",
                        name: other.to_owned(),
                    });
                }
            },
        })
    }
}

fn discover_catalog() -> RuntimeResult<DriverCatalog> {
    DriverCatalog::discover_from_environment().map_err(|err| {
        RuntimeError::Driver(DriverError::Subprocess {
            driver: "driver-catalog".to_owned(),
            message: err.to_string(),
        })
    })
}

fn subprocess_entry(
    catalog: &mut Option<DriverCatalog>,
    kind: CatalogKind,
    name: &str,
) -> RuntimeResult<Option<DiscoveredDriver>> {
    if catalog.is_none() {
        *catalog = Some(discover_catalog()?);
    }
    Ok(catalog
        .as_ref()
        .expect("catalog initialized")
        .entries
        .iter()
        .find(|entry| {
            entry.kind == kind && entry.name == name && entry.source != DriverSource::BuiltIn
        })
        .cloned())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use agentenv_core::runtime::{DriverFactory, DriverSelection};

    use super::BuiltInDriverFactory;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn builds_supported_reference_driver_set() {
        let selection = DriverSelection {
            sandbox: "openshell".to_owned(),
            agent: "codex".to_owned(),
            context: "filesystem".to_owned(),
            inference: Some("passthrough".to_owned()),
        };

        let set = BuiltInDriverFactory.build(&selection).unwrap();
        drop(set);
    }

    #[test]
    fn built_in_selection_ignores_unrelated_broken_installed_manifest() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        let bad_driver = home.join(".agentenv").join("drivers").join("bad");
        std::fs::create_dir_all(&bad_driver).expect("bad driver dir");
        std::fs::write(bad_driver.join("manifest.json"), "{").expect("bad manifest");
        let _env_guard = EnvGuard::set([
            ("HOME", home.into_os_string()),
            (
                "AGENTENV_DRIVER_PATH",
                temp.path().join("missing-driver-path").into_os_string(),
            ),
        ]);
        let selection = DriverSelection {
            sandbox: "openshell".to_owned(),
            agent: "codex".to_owned(),
            context: "filesystem".to_owned(),
            inference: Some("passthrough".to_owned()),
        };

        let set = BuiltInDriverFactory.build(&selection).unwrap();
        drop(set);
    }

    #[test]
    fn unsupported_external_driver_is_explicit() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).expect("home");
        let _env_guard = EnvGuard::set([
            ("HOME", home.into_os_string()),
            (
                "AGENTENV_DRIVER_PATH",
                temp.path().join("missing-driver-path").into_os_string(),
            ),
        ]);
        let selection = DriverSelection {
            sandbox: "openshell".to_owned(),
            agent: "hermes".to_owned(),
            context: "nexus".to_owned(),
            inference: None,
        };

        let err = BuiltInDriverFactory.build(&selection).unwrap_err();
        assert!(err.to_string().contains("unsupported driver"));
    }

    #[test]
    fn builds_subprocess_hermes_and_nexus_from_driver_path() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).expect("home");
        let hermes = temp.path().join("agent-hermes");
        let nexus = temp.path().join("context-nexus");
        write_manifest(&hermes, "agent", "hermes", "agentenv-driver-hermes");
        write_manifest(&nexus, "context", "nexus", "agentenv-driver-nexus");
        let driver_path = std::env::join_paths([&hermes, &nexus]).expect("join driver path");
        let _env_guard = EnvGuard::set([
            ("HOME", home.into_os_string()),
            ("AGENTENV_DRIVER_PATH", driver_path),
        ]);

        let selection = DriverSelection {
            sandbox: "openshell".to_owned(),
            agent: "hermes".to_owned(),
            context: "nexus".to_owned(),
            inference: Some("passthrough".to_owned()),
        };

        let set = BuiltInDriverFactory.build(&selection).unwrap();
        drop(set);
    }

    fn write_manifest(root: &std::path::Path, kind: &str, name: &str, binary_name: &str) {
        let bin_dir = root.join("bin");
        std::fs::create_dir_all(&bin_dir).expect("bin dir");
        std::fs::write(bin_dir.join(binary_name), "#!/bin/sh\nexit 0\n").expect("binary");
        std::fs::write(
            root.join("manifest.json"),
            format!(
                r#"{{
                  "schema_version": "1.0",
                  "name": "{name}",
                  "kind": "{kind}",
                  "version": "0.1.0",
                  "binary": "./bin/{binary_name}"
                }}"#
            ),
        )
        .expect("manifest");
    }

    struct EnvGuard {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvGuard {
        fn set<const N: usize>(vars: [(&'static str, std::ffi::OsString); N]) -> Self {
            let saved = vars
                .iter()
                .map(|(key, _)| (*key, std::env::var_os(key)))
                .collect::<Vec<_>>();
            for (key, value) in vars {
                std::env::set_var(key, value);
            }
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..) {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }
}
