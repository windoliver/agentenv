use std::time::Duration;

use agentenv_core::{
    driver::{DriverError, InferenceDriver},
    driver_catalog::{DiscoveredDriver, DriverCatalog, DriverSource},
    registry::DriverKind as CatalogKind,
    runtime::{
        DriverFactory, DriverPinIdentity, DriverPinSet, DriverSelection, DriverSet, RuntimeError,
        RuntimeResult,
    },
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

    fn build_pinned(
        &self,
        selection: &DriverSelection,
        pins: &DriverPinSet,
    ) -> RuntimeResult<DriverSet> {
        let mut catalog = None;
        Ok(DriverSet {
            sandbox: build_pinned_sandbox(selection, pins)?,
            agent: build_pinned_agent(selection, pins.get("agent"), &mut catalog)?,
            context: build_pinned_context(selection, pins.get("context"), &mut catalog)?,
            inference: build_pinned_inference(selection)?,
        })
    }
}

fn build_pinned_sandbox(
    selection: &DriverSelection,
    _pins: &DriverPinSet,
) -> RuntimeResult<Box<dyn agentenv_core::driver::SandboxDriver>> {
    match selection.sandbox.as_str() {
        "openshell" | "sandbox-openshell" => {
            Ok(Box::new(sandbox_openshell::OpenShellDriver::default()))
        }
        other => Err(RuntimeError::UnsupportedDriver {
            kind: "sandbox",
            name: other.to_owned(),
        }),
    }
}

fn build_pinned_agent(
    selection: &DriverSelection,
    pin: Option<&DriverPinIdentity>,
    catalog: &mut Option<DriverCatalog>,
) -> RuntimeResult<Box<dyn agentenv_core::driver::AgentDriver>> {
    match pin {
        Some(pin) if pin.source != agentenv_core::lockfile::DriverSourcePin::BuiltIn => {
            let Some(source) = subprocess_source_from_pin(&pin.source) else {
                return Err(RuntimeError::UnsupportedDriver {
                    kind: "agent",
                    name: pin.name.clone(),
                });
            };
            match exact_subprocess_entry(
                catalog,
                CatalogKind::Agent,
                &pin.name,
                &pin.version,
                source,
            )? {
                Some(entry) => Ok(Box::new(
                    agentenv_plugin::SubprocessAgentDriver::from_discovered_unstarted(
                        entry,
                        SUBPROCESS_DRIVER_TIMEOUT,
                    )?,
                )),
                None => Err(RuntimeError::UnsupportedDriver {
                    kind: "agent",
                    name: pin.name.clone(),
                }),
            }
        }
        _ => match selection.agent.as_str() {
            "claude" | "agent-claude" => Ok(Box::new(agent_claude::ClaudeDriver)),
            "codex" | "agent-codex" => Ok(Box::new(agent_codex::CodexDriver)),
            "openclaw" | "agent-openclaw" => Ok(Box::new(agent_openclaw::OpenClawDriver)),
            other => Err(RuntimeError::UnsupportedDriver {
                kind: "agent",
                name: other.to_owned(),
            }),
        },
    }
}

fn build_pinned_context(
    selection: &DriverSelection,
    pin: Option<&DriverPinIdentity>,
    catalog: &mut Option<DriverCatalog>,
) -> RuntimeResult<Box<dyn agentenv_core::driver::ContextDriver>> {
    match pin {
        Some(pin) if pin.source != agentenv_core::lockfile::DriverSourcePin::BuiltIn => {
            let Some(source) = subprocess_source_from_pin(&pin.source) else {
                return Err(RuntimeError::UnsupportedDriver {
                    kind: "context",
                    name: pin.name.clone(),
                });
            };
            match exact_subprocess_entry(
                catalog,
                CatalogKind::Context,
                &pin.name,
                &pin.version,
                source,
            )? {
                Some(entry) => Ok(Box::new(
                    agentenv_plugin::SubprocessContextDriver::from_discovered_unstarted(
                        entry,
                        SUBPROCESS_DRIVER_TIMEOUT,
                    )?,
                )),
                None => Err(RuntimeError::UnsupportedDriver {
                    kind: "context",
                    name: pin.name.clone(),
                }),
            }
        }
        _ => match selection.context.as_str() {
            "filesystem" | "context-filesystem" => Ok(Box::new(
                context_filesystem::FilesystemContextDriver::default(),
            )),
            "mcp-generic" | "context-mcp-generic" => Ok(Box::new(
                context_mcp_generic::GenericMcpContextDriver::default(),
            )),
            "none" | "context-none" => Ok(Box::new(context_none::NoneContextDriver)),
            other => Err(RuntimeError::UnsupportedDriver {
                kind: "context",
                name: other.to_owned(),
            }),
        },
    }
}

fn build_pinned_inference(
    selection: &DriverSelection,
) -> RuntimeResult<Option<Box<dyn InferenceDriver>>> {
    match selection.inference.as_deref() {
        None => Ok(None),
        Some("passthrough" | "inference-passthrough") => Ok(Some(Box::new(
            inference_passthrough::PassthroughInferenceDriver,
        )
            as Box<dyn InferenceDriver>)),
        Some("openai" | "inference-openai") => Ok(Some(Box::new(
            inference_openai::OpenAiInferenceDriver,
        ) as Box<dyn InferenceDriver>)),
        Some("anthropic" | "inference-anthropic") => Ok(Some(Box::new(
            inference_anthropic::AnthropicInferenceDriver,
        )
            as Box<dyn InferenceDriver>)),
        Some("ollama" | "inference-ollama") => Ok(Some(Box::new(
            inference_ollama::OllamaInferenceDriver,
        ) as Box<dyn InferenceDriver>)),
        Some(other) => Err(RuntimeError::UnsupportedDriver {
            kind: "inference",
            name: other.to_owned(),
        }),
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

fn exact_subprocess_entry(
    catalog: &mut Option<DriverCatalog>,
    kind: CatalogKind,
    name: &str,
    version: &str,
    source: DriverSource,
) -> RuntimeResult<Option<DiscoveredDriver>> {
    if catalog.is_none() {
        *catalog = Some(discover_catalog()?);
    }
    let Some(catalog) = catalog.as_ref() else {
        return Ok(None);
    };
    Ok(catalog
        .registry_entries()
        .find(|entry| {
            entry.kind == kind
                && entry.name == name
                && entry.version.to_string() == version
                && entry.source == source
        })
        .cloned())
}

fn subprocess_source_from_pin(
    source: &agentenv_core::lockfile::DriverSourcePin,
) -> Option<DriverSource> {
    match source {
        agentenv_core::lockfile::DriverSourcePin::BuiltIn => None,
        agentenv_core::lockfile::DriverSourcePin::Installed => {
            Some(DriverSource::InstalledSubprocess)
        }
        agentenv_core::lockfile::DriverSourcePin::Override => {
            Some(DriverSource::DevelopmentOverride)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use agentenv_core::{
        driver_catalog::DriverSource,
        registry::DriverKind as CatalogKind,
        runtime::{DriverFactory, DriverSelection},
    };

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

    #[test]
    fn pinned_subprocess_selection_uses_exact_installed_source_when_override_shares_name_version() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        let installed = home
            .join(".agentenv")
            .join("drivers")
            .join("agent-hermes-installed");
        let override_driver = temp.path().join("agent-hermes-override");
        write_manifest(&installed, "agent", "hermes", "agentenv-driver-hermes");
        write_manifest(
            &override_driver,
            "agent",
            "hermes",
            "agentenv-driver-hermes",
        );
        let _env_guard = EnvGuard::set([
            ("HOME", home.into_os_string()),
            ("AGENTENV_DRIVER_PATH", override_driver.into_os_string()),
        ]);
        let mut catalog = None;

        let selected = super::exact_subprocess_entry(
            &mut catalog,
            CatalogKind::Agent,
            "hermes",
            "0.1.0",
            DriverSource::InstalledSubprocess,
        )
        .expect("exact selection")
        .expect("installed hermes selected");

        assert_eq!(selected.source, DriverSource::InstalledSubprocess);
        assert_eq!(
            selected
                .manifest_path
                .as_ref()
                .and_then(|path| path.parent())
                .expect("manifest parent"),
            installed.as_path()
        );
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
