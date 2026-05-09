use std::sync::Arc;
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
use agentenv_events::{EventEmitter, NoopEventEmitter};

#[allow(dead_code)]
pub struct BuiltInDriverFactory;

const SUBPROCESS_DRIVER_TIMEOUT: Duration = Duration::from_secs(30);

impl DriverFactory for BuiltInDriverFactory {
    fn build(&self, selection: &DriverSelection) -> RuntimeResult<DriverSet> {
        build_driver_set_with_events(selection, Arc::new(NoopEventEmitter))
    }

    fn build_observed(
        &self,
        selection: &DriverSelection,
        events: Arc<dyn EventEmitter>,
    ) -> RuntimeResult<DriverSet> {
        build_driver_set_with_context(selection, events, None)
    }

    fn build_for_env_observed(
        &self,
        selection: &DriverSelection,
        env: &str,
        events: Arc<dyn EventEmitter>,
        approval_coordinator: Option<agentenv_approvals::ApprovalCoordinator>,
    ) -> RuntimeResult<DriverSet> {
        let approval_context = approval_coordinator.map(|coordinator| SubprocessApprovalContext {
            env_name: env.to_owned(),
            coordinator,
        });
        build_driver_set_with_context(selection, events, approval_context.as_ref())
    }

    fn build_pinned(
        &self,
        selection: &DriverSelection,
        pins: &DriverPinSet,
    ) -> RuntimeResult<DriverSet> {
        build_pinned_driver_set_with_events(selection, pins, Arc::new(NoopEventEmitter))
    }

    fn build_pinned_observed(
        &self,
        selection: &DriverSelection,
        pins: &DriverPinSet,
        events: Arc<dyn EventEmitter>,
    ) -> RuntimeResult<DriverSet> {
        build_pinned_driver_set_with_context(selection, pins, events, None)
    }

    fn build_pinned_for_env_observed(
        &self,
        selection: &DriverSelection,
        pins: &DriverPinSet,
        env: &str,
        events: Arc<dyn EventEmitter>,
        approval_coordinator: Option<agentenv_approvals::ApprovalCoordinator>,
    ) -> RuntimeResult<DriverSet> {
        let approval_context = approval_coordinator.map(|coordinator| SubprocessApprovalContext {
            env_name: env.to_owned(),
            coordinator,
        });
        build_pinned_driver_set_with_context(selection, pins, events, approval_context.as_ref())
    }
}

fn build_driver_set_with_events(
    selection: &DriverSelection,
    events: Arc<dyn EventEmitter>,
) -> RuntimeResult<DriverSet> {
    build_driver_set_with_context(selection, events, None)
}

#[derive(Clone)]
struct SubprocessApprovalContext {
    env_name: String,
    coordinator: agentenv_approvals::ApprovalCoordinator,
}

fn build_driver_set_with_context(
    selection: &DriverSelection,
    events: Arc<dyn EventEmitter>,
    approval_context: Option<&SubprocessApprovalContext>,
) -> RuntimeResult<DriverSet> {
    let mut catalog = None;
    Ok(DriverSet {
        sandbox: match selection.sandbox.as_str() {
            "openshell" | "sandbox-openshell" => Box::new(
                sandbox_openshell::OpenShellDriver::default()
                    .with_event_emitter(Arc::clone(&events)),
            ),
            "remote-ssh" | "sandbox-remote-ssh" => {
                Box::new(sandbox_remote_ssh::RemoteSshDriver::default())
            }
            "microvm" | "sandbox-microvm" => Box::new(sandbox_microvm::MicroVmDriver::default()),
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
                Some(entry) => Box::new(subprocess_agent_driver(
                    entry,
                    Arc::clone(&events),
                    approval_context,
                )?),
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
                Some(entry) => Box::new(subprocess_context_driver(
                    entry,
                    Arc::clone(&events),
                    approval_context,
                )?),
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
                Some(Box::new(inference_openai::OpenAiInferenceDriver) as Box<dyn InferenceDriver>)
            }
            Some("anthropic" | "inference-anthropic") => {
                Some(Box::new(inference_anthropic::AnthropicInferenceDriver)
                    as Box<dyn InferenceDriver>)
            }
            Some("ollama" | "inference-ollama") => {
                Some(Box::new(inference_ollama::OllamaInferenceDriver) as Box<dyn InferenceDriver>)
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

fn build_pinned_driver_set_with_events(
    selection: &DriverSelection,
    pins: &DriverPinSet,
    events: Arc<dyn EventEmitter>,
) -> RuntimeResult<DriverSet> {
    build_pinned_driver_set_with_context(selection, pins, events, None)
}

fn build_pinned_driver_set_with_context(
    selection: &DriverSelection,
    pins: &DriverPinSet,
    events: Arc<dyn EventEmitter>,
    approval_context: Option<&SubprocessApprovalContext>,
) -> RuntimeResult<DriverSet> {
    Ok(DriverSet {
        sandbox: build_pinned_sandbox(selection, pins.get("sandbox"), Arc::clone(&events))?,
        agent: build_pinned_agent(
            selection,
            pins.get("agent"),
            Arc::clone(&events),
            approval_context,
        )?,
        context: build_pinned_context(selection, pins.get("context"), events, approval_context)?,
        inference: build_pinned_inference(selection, pins.get("inference"))?,
    })
}

fn build_pinned_sandbox(
    selection: &DriverSelection,
    pin: Option<&DriverPinIdentity>,
    events: Arc<dyn EventEmitter>,
) -> RuntimeResult<Box<dyn agentenv_core::driver::SandboxDriver>> {
    match selection.sandbox.as_str() {
        "openshell" | "sandbox-openshell" => {
            validate_builtin_pin(
                "sandbox",
                agentenv_proto::DriverKind::Sandbox,
                &["openshell", "sandbox-openshell"],
                pin,
            )?;
            Ok(Box::new(
                sandbox_openshell::OpenShellDriver::default().with_event_emitter(events),
            ))
        }
        "remote-ssh" | "sandbox-remote-ssh" => {
            validate_builtin_pin(
                "sandbox",
                agentenv_proto::DriverKind::Sandbox,
                &["remote-ssh", "sandbox-remote-ssh"],
                pin,
            )?;
            Ok(Box::new(sandbox_remote_ssh::RemoteSshDriver::default()))
        }
        "microvm" | "sandbox-microvm" => {
            validate_builtin_pin(
                "sandbox",
                agentenv_proto::DriverKind::Sandbox,
                &["microvm", "sandbox-microvm"],
                pin,
            )?;
            Ok(Box::new(sandbox_microvm::MicroVmDriver::default()))
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
    events: Arc<dyn EventEmitter>,
    approval_context: Option<&SubprocessApprovalContext>,
) -> RuntimeResult<Box<dyn agentenv_core::driver::AgentDriver>> {
    match pin {
        Some(pin) if pin.source != agentenv_core::lockfile::DriverSourcePin::BuiltIn => {
            let entry = verified_subprocess_entry(pin, CatalogKind::Agent, "agent")?;
            Ok(Box::new(subprocess_agent_driver(
                entry,
                events,
                approval_context,
            )?))
        }
        _ => match selection.agent.as_str() {
            "claude" | "agent-claude" => {
                validate_builtin_pin(
                    "agent",
                    agentenv_proto::DriverKind::Agent,
                    &["claude", "agent-claude"],
                    pin,
                )?;
                Ok(Box::new(agent_claude::ClaudeDriver))
            }
            "codex" | "agent-codex" => {
                validate_builtin_pin(
                    "agent",
                    agentenv_proto::DriverKind::Agent,
                    &["codex", "agent-codex"],
                    pin,
                )?;
                Ok(Box::new(agent_codex::CodexDriver))
            }
            "openclaw" | "agent-openclaw" => {
                validate_builtin_pin(
                    "agent",
                    agentenv_proto::DriverKind::Agent,
                    &["openclaw", "agent-openclaw"],
                    pin,
                )?;
                Ok(Box::new(agent_openclaw::OpenClawDriver))
            }
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
    events: Arc<dyn EventEmitter>,
    approval_context: Option<&SubprocessApprovalContext>,
) -> RuntimeResult<Box<dyn agentenv_core::driver::ContextDriver>> {
    match pin {
        Some(pin) if pin.source != agentenv_core::lockfile::DriverSourcePin::BuiltIn => {
            let entry = verified_subprocess_entry(pin, CatalogKind::Context, "context")?;
            Ok(Box::new(subprocess_context_driver(
                entry,
                events,
                approval_context,
            )?))
        }
        _ => match selection.context.as_str() {
            "filesystem" | "context-filesystem" => {
                validate_builtin_pin(
                    "context",
                    agentenv_proto::DriverKind::Context,
                    &["filesystem", "context-filesystem"],
                    pin,
                )?;
                Ok(Box::new(
                    context_filesystem::FilesystemContextDriver::default(),
                ))
            }
            "mcp-generic" | "context-mcp-generic" => {
                validate_builtin_pin(
                    "context",
                    agentenv_proto::DriverKind::Context,
                    &["mcp-generic", "context-mcp-generic"],
                    pin,
                )?;
                Ok(Box::new(
                    context_mcp_generic::GenericMcpContextDriver::default(),
                ))
            }
            "none" | "context-none" => {
                validate_builtin_pin(
                    "context",
                    agentenv_proto::DriverKind::Context,
                    &["none", "context-none"],
                    pin,
                )?;
                Ok(Box::new(context_none::NoneContextDriver))
            }
            other => Err(RuntimeError::UnsupportedDriver {
                kind: "context",
                name: other.to_owned(),
            }),
        },
    }
}

fn subprocess_agent_driver(
    entry: DiscoveredDriver,
    events: Arc<dyn EventEmitter>,
    approval_context: Option<&SubprocessApprovalContext>,
) -> RuntimeResult<agentenv_plugin::SubprocessAgentDriver> {
    let driver = agentenv_plugin::SubprocessAgentDriver::from_discovered_unstarted(
        entry,
        SUBPROCESS_DRIVER_TIMEOUT,
    )?
    .with_event_emitter(events);
    Ok(match approval_context {
        Some(context) => {
            driver.with_approval_coordinator(context.env_name.clone(), context.coordinator.clone())
        }
        None => driver,
    })
}

fn subprocess_context_driver(
    entry: DiscoveredDriver,
    events: Arc<dyn EventEmitter>,
    approval_context: Option<&SubprocessApprovalContext>,
) -> RuntimeResult<agentenv_plugin::SubprocessContextDriver> {
    let driver = agentenv_plugin::SubprocessContextDriver::from_discovered_unstarted(
        entry,
        SUBPROCESS_DRIVER_TIMEOUT,
    )?
    .with_event_emitter(events);
    Ok(match approval_context {
        Some(context) => {
            driver.with_approval_coordinator(context.env_name.clone(), context.coordinator.clone())
        }
        None => driver,
    })
}

fn build_pinned_inference(
    selection: &DriverSelection,
    pin: Option<&DriverPinIdentity>,
) -> RuntimeResult<Option<Box<dyn InferenceDriver>>> {
    match selection.inference.as_deref() {
        None => match pin {
            Some(pin) => Err(RuntimeError::UnsupportedDriver {
                kind: "inference",
                name: pin.name.clone(),
            }),
            None => Ok(None),
        },
        Some("passthrough" | "inference-passthrough") => {
            validate_builtin_pin(
                "inference",
                agentenv_proto::DriverKind::Inference,
                &["passthrough", "inference-passthrough"],
                pin,
            )?;
            Ok(Some(
                Box::new(inference_passthrough::PassthroughInferenceDriver)
                    as Box<dyn InferenceDriver>,
            ))
        }
        Some("openai" | "inference-openai") => {
            validate_builtin_pin(
                "inference",
                agentenv_proto::DriverKind::Inference,
                &["openai", "inference-openai"],
                pin,
            )?;
            Ok(Some(
                Box::new(inference_openai::OpenAiInferenceDriver) as Box<dyn InferenceDriver>
            ))
        }
        Some("anthropic" | "inference-anthropic") => {
            validate_builtin_pin(
                "inference",
                agentenv_proto::DriverKind::Inference,
                &["anthropic", "inference-anthropic"],
                pin,
            )?;
            Ok(Some(
                Box::new(inference_anthropic::AnthropicInferenceDriver) as Box<dyn InferenceDriver>,
            ))
        }
        Some("ollama" | "inference-ollama") => {
            validate_builtin_pin(
                "inference",
                agentenv_proto::DriverKind::Inference,
                &["ollama", "inference-ollama"],
                pin,
            )?;
            Ok(Some(
                Box::new(inference_ollama::OllamaInferenceDriver) as Box<dyn InferenceDriver>
            ))
        }
        Some(other) => Err(RuntimeError::UnsupportedDriver {
            kind: "inference",
            name: other.to_owned(),
        }),
    }
}

fn validate_builtin_pin(
    role: &'static str,
    expected_kind: agentenv_proto::DriverKind,
    expected_names: &[&str],
    pin: Option<&DriverPinIdentity>,
) -> RuntimeResult<()> {
    let Some(pin) = pin else {
        return Ok(());
    };

    if pin.kind != expected_kind
        || pin.source != agentenv_core::lockfile::DriverSourcePin::BuiltIn
        || !expected_names.contains(&pin.name.as_str())
        || pin.version != env!("CARGO_PKG_VERSION")
    {
        return Err(RuntimeError::UnsupportedDriver {
            kind: role,
            name: pin.name.clone(),
        });
    }

    Ok(())
}

fn verified_subprocess_entry(
    pin: &DriverPinIdentity,
    expected_kind: CatalogKind,
    role: &'static str,
) -> RuntimeResult<DiscoveredDriver> {
    let Some(source) = subprocess_source_from_pin(&pin.source) else {
        return Err(RuntimeError::UnsupportedDriver {
            kind: role,
            name: pin.name.clone(),
        });
    };
    let Some(entry) = pin.verified_entry.clone() else {
        return Err(RuntimeError::UnsupportedDriver {
            kind: role,
            name: pin.name.clone(),
        });
    };
    if entry.kind != expected_kind
        || entry.name != pin.name
        || entry.version.to_string() != pin.version
        || entry.source != source
    {
        return Err(RuntimeError::UnsupportedDriver {
            kind: role,
            name: pin.name.clone(),
        });
    }
    Ok(entry)
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
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    use agentenv_core::{
        driver_artifact::discover_driver_artifacts,
        driver_catalog::{DriverDiscoveryConfig, DriverSource},
        lockfile::{
            DriverSourcePin, PortableComponent, PortableComposition, PortableDriverPin,
            PortableLockfile, PortablePolicy,
        },
        registry::DriverKind as CatalogKind,
        runtime::{DriverFactory, DriverPinSet, DriverSelection},
    };
    use agentenv_proto::{
        DriverKind as ProtoDriverKind, FilesystemPolicy, InferencePolicy, NetworkAccessPolicy,
        NetworkPolicy, PolicyReloadability, ProcessPolicy, SCHEMA_VERSION,
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
    fn builds_remote_ssh_sandbox_aliases() {
        for sandbox in ["remote-ssh", "sandbox-remote-ssh"] {
            let selection = DriverSelection {
                sandbox: sandbox.to_owned(),
                agent: "codex".to_owned(),
                context: "filesystem".to_owned(),
                inference: Some("passthrough".to_owned()),
            };

            let set = BuiltInDriverFactory.build(&selection).unwrap();
            drop(set);
        }
    }

    #[test]
    fn builds_microvm_sandbox_aliases() {
        for sandbox in ["microvm", "sandbox-microvm"] {
            let selection = DriverSelection {
                sandbox: sandbox.to_owned(),
                agent: "codex".to_owned(),
                context: "filesystem".to_owned(),
                inference: Some("passthrough".to_owned()),
            };

            let set = BuiltInDriverFactory.build(&selection).unwrap();
            drop(set);
        }
    }

    #[test]
    fn openshell_driver_receives_observed_event_emitter() {
        let factory = BuiltInDriverFactory;
        let selection = DriverSelection {
            sandbox: "openshell".to_owned(),
            agent: "codex".to_owned(),
            context: "filesystem".to_owned(),
            inference: None,
        };
        let events = Arc::new(agentenv_events::RecordingEventEmitter::default());

        let mut set = factory
            .build_observed(
                &selection,
                Arc::clone(&events) as Arc<dyn agentenv_events::EventEmitter>,
            )
            .expect("driver set");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime
            .block_on(async {
                set.sandbox
                    .shutdown(agentenv_proto::ShutdownParams {})
                    .await
            })
            .expect("shutdown");

        assert!(events.recorded().iter().any(|event| {
            event.actor.get("driver") == Some(&serde_json::json!("openshell"))
                && event.subject.get("operation") == Some(&serde_json::json!("shutdown"))
                && event.reason_code.as_deref() == Some("openshell_shutdown")
        }));
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
    fn subprocess_approval_context_helpers_preserve_driver_construction() {
        let temp = tempfile::tempdir().expect("tempdir");
        let hermes = temp.path().join("agent-hermes");
        let nexus = temp.path().join("context-nexus");
        write_manifest(&hermes, "agent", "hermes", "agentenv-driver-hermes");
        write_manifest(&nexus, "context", "nexus", "agentenv-driver-nexus");
        let agent_entry = agentenv_core::driver_catalog::DiscoveredDriver {
            kind: CatalogKind::Agent,
            name: "hermes".to_owned(),
            version: "0.1.0".parse().expect("version"),
            source: DriverSource::DevelopmentOverride,
            description: None,
            binary: Some(hermes.join("bin").join("agentenv-driver-hermes")),
            manifest_path: Some(hermes.join("manifest.json")),
            args: Vec::new(),
            env: BTreeMap::new(),
            capabilities_preview: serde_json::Value::Null,
        };
        let context_entry = agentenv_core::driver_catalog::DiscoveredDriver {
            kind: CatalogKind::Context,
            name: "nexus".to_owned(),
            version: "0.1.0".parse().expect("version"),
            source: DriverSource::DevelopmentOverride,
            description: None,
            binary: Some(nexus.join("bin").join("agentenv-driver-nexus")),
            manifest_path: Some(nexus.join("manifest.json")),
            args: Vec::new(),
            env: BTreeMap::new(),
            capabilities_preview: serde_json::Value::Null,
        };
        let store = agentenv_approvals::ApprovalStore::open(
            temp.path().join("envs").join("demo").join("events.db"),
        )
        .expect("store");
        let coordinator = agentenv_approvals::ApprovalCoordinator::new(
            agentenv_approvals::ApprovalCoordinatorConfig {
                store,
                events: std::sync::Arc::new(agentenv_events::NoopEventEmitter),
                poll_interval: std::time::Duration::from_millis(10),
                overlay_path: None,
                proposal_path: None,
                notifications: None,
            },
        );
        let context = super::SubprocessApprovalContext {
            env_name: "demo".to_owned(),
            coordinator,
        };

        let agent = super::subprocess_agent_driver(
            agent_entry,
            std::sync::Arc::new(agentenv_events::NoopEventEmitter),
            Some(&context),
        )
        .expect("agent driver should build with approval context");
        let context = super::subprocess_context_driver(
            context_entry,
            std::sync::Arc::new(agentenv_events::NoopEventEmitter),
            Some(&context),
        )
        .expect("context driver should build with approval context");
        drop((agent, context));
    }

    #[test]
    fn env_aware_factory_path_builds_subprocess_agent_and_context_with_approval_context() {
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
            inference: None,
        };
        let store = agentenv_approvals::ApprovalStore::open(
            temp.path().join("envs").join("demo").join("events.db"),
        )
        .expect("store");
        let coordinator = agentenv_approvals::ApprovalCoordinator::new(
            agentenv_approvals::ApprovalCoordinatorConfig {
                store,
                events: std::sync::Arc::new(agentenv_events::NoopEventEmitter),
                poll_interval: std::time::Duration::from_millis(10),
                overlay_path: None,
                proposal_path: None,
                notifications: None,
            },
        );

        let set = BuiltInDriverFactory
            .build_for_env_observed(
                &selection,
                "demo",
                std::sync::Arc::new(agentenv_events::NoopEventEmitter),
                Some(coordinator),
            )
            .expect("env-aware factory path should build subprocess agent and context");

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

    #[test]
    fn pinned_subprocess_build_uses_verified_artifact_manifest_without_rediscovery() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let installed_parent = temp.path().join("verified-drivers");
        let installed = installed_parent.join("agent-hermes");
        let built_in_binary = temp.path().join("agentenv-test-binary");
        std::fs::write(&built_in_binary, "fake agentenv binary\n").expect("built-in binary");
        write_manifest(&installed, "agent", "hermes", "agentenv-driver-hermes");
        let artifacts = discover_driver_artifacts(
            DriverDiscoveryConfig::new(installed_parent, Vec::new()),
            Some(built_in_binary),
        )
        .expect("discover artifacts");
        let hermes = artifacts
            .iter()
            .find(|artifact| {
                artifact.kind == CatalogKind::Agent
                    && artifact.name == "hermes"
                    && artifact.source == DriverSource::InstalledSubprocess
            })
            .expect("hermes artifact");
        let lockfile = lockfile_with_pin(
            "agent",
            ProtoDriverKind::Agent,
            "hermes",
            "0.1.0",
            DriverSourcePin::Installed,
            &hermes.digest,
        );
        let pins = DriverPinSet::from_portable_lockfile_and_artifacts(&lockfile, &artifacts)
            .expect("pin set");
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
            context: "filesystem".to_owned(),
            inference: None,
        };

        let set = BuiltInDriverFactory
            .build_pinned(&selection, &pins)
            .expect("verified artifact should materialize without rediscovery");
        drop(set);
    }

    #[test]
    fn pinned_env_aware_factory_path_builds_subprocess_agent_and_context_with_approval_context() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let installed_parent = temp.path().join("verified-drivers");
        let hermes_driver = installed_parent.join("agent-hermes");
        let nexus_driver = installed_parent.join("context-nexus");
        let built_in_binary = temp.path().join("agentenv-test-binary");
        std::fs::write(&built_in_binary, "fake agentenv binary\n").expect("built-in binary");
        write_manifest(&hermes_driver, "agent", "hermes", "agentenv-driver-hermes");
        write_manifest(&nexus_driver, "context", "nexus", "agentenv-driver-nexus");
        let artifacts = discover_driver_artifacts(
            DriverDiscoveryConfig::new(installed_parent, Vec::new()),
            Some(built_in_binary),
        )
        .expect("discover artifacts");
        let hermes = artifacts
            .iter()
            .find(|artifact| {
                artifact.kind == CatalogKind::Agent
                    && artifact.name == "hermes"
                    && artifact.source == DriverSource::InstalledSubprocess
            })
            .expect("hermes artifact");
        let nexus = artifacts
            .iter()
            .find(|artifact| {
                artifact.kind == CatalogKind::Context
                    && artifact.name == "nexus"
                    && artifact.source == DriverSource::InstalledSubprocess
            })
            .expect("nexus artifact");
        let mut lockfile = lockfile_with_pin(
            "agent",
            ProtoDriverKind::Agent,
            "hermes",
            "0.1.0",
            DriverSourcePin::Installed,
            &hermes.digest,
        );
        lockfile.drivers.insert(
            "context".to_owned(),
            PortableDriverPin {
                kind: proto_kind_label(ProtoDriverKind::Context).to_owned(),
                name: "nexus".to_owned(),
                version: "0.1.0".to_owned(),
                source: DriverSourcePin::Installed,
                digest: nexus.digest.clone(),
            },
        );
        let pins = DriverPinSet::from_portable_lockfile_and_artifacts(&lockfile, &artifacts)
            .expect("pin set");
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
        let store = agentenv_approvals::ApprovalStore::open(
            temp.path().join("envs").join("demo").join("events.db"),
        )
        .expect("store");
        let coordinator = agentenv_approvals::ApprovalCoordinator::new(
            agentenv_approvals::ApprovalCoordinatorConfig {
                store,
                events: std::sync::Arc::new(agentenv_events::NoopEventEmitter),
                poll_interval: std::time::Duration::from_millis(10),
                overlay_path: None,
                proposal_path: None,
                notifications: None,
            },
        );

        let set = BuiltInDriverFactory
            .build_pinned_for_env_observed(
                &selection,
                &pins,
                "demo",
                std::sync::Arc::new(agentenv_events::NoopEventEmitter),
                Some(coordinator),
            )
            .expect("pinned env-aware factory path should build subprocess agent and context");

        drop(set);
    }

    #[test]
    fn pinned_build_rejects_non_builtin_sandbox_pin() {
        let selection = DriverSelection {
            sandbox: "openshell".to_owned(),
            agent: "codex".to_owned(),
            context: "filesystem".to_owned(),
            inference: None,
        };
        let pins = pin_set(
            "sandbox",
            ProtoDriverKind::Sandbox,
            "openshell",
            env!("CARGO_PKG_VERSION"),
            DriverSourcePin::Installed,
        );

        let err = BuiltInDriverFactory
            .build_pinned(&selection, &pins)
            .expect_err("non-built-in sandbox pin cannot be materialized");

        assert!(err.to_string().contains("unsupported driver"));
    }

    #[test]
    fn pinned_build_accepts_remote_ssh_sandbox_alias() {
        let selection = DriverSelection {
            sandbox: "remote-ssh".to_owned(),
            agent: "codex".to_owned(),
            context: "filesystem".to_owned(),
            inference: None,
        };
        let pins = pin_set(
            "sandbox",
            ProtoDriverKind::Sandbox,
            "remote-ssh",
            env!("CARGO_PKG_VERSION"),
            DriverSourcePin::BuiltIn,
        );

        let set = BuiltInDriverFactory
            .build_pinned(&selection, &pins)
            .unwrap();
        drop(set);
    }

    #[test]
    fn pinned_build_rejects_builtin_inference_version_mismatch() {
        let selection = DriverSelection {
            sandbox: "openshell".to_owned(),
            agent: "codex".to_owned(),
            context: "filesystem".to_owned(),
            inference: Some("passthrough".to_owned()),
        };
        let pins = pin_set(
            "inference",
            ProtoDriverKind::Inference,
            "passthrough",
            "9.9.9",
            DriverSourcePin::BuiltIn,
        );

        let err = BuiltInDriverFactory
            .build_pinned(&selection, &pins)
            .expect_err("mismatched built-in inference pin cannot be materialized");

        assert!(err.to_string().contains("unsupported driver"));
    }

    fn pin_set(
        role: &str,
        kind: ProtoDriverKind,
        name: &str,
        version: &str,
        source: DriverSourcePin,
    ) -> DriverPinSet {
        let lockfile = lockfile_with_pin(
            role,
            kind,
            name,
            version,
            source,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
        DriverPinSet::from_portable_lockfile(&lockfile).expect("pin set")
    }

    fn lockfile_with_pin(
        role: &str,
        kind: ProtoDriverKind,
        name: &str,
        version: &str,
        source: DriverSourcePin,
        digest: &str,
    ) -> PortableLockfile {
        let mut drivers = BTreeMap::new();
        drivers.insert(
            role.to_owned(),
            PortableDriverPin {
                kind: proto_kind_label(kind).to_owned(),
                name: name.to_owned(),
                version: version.to_owned(),
                source,
                digest: digest.to_owned(),
            },
        );
        PortableLockfile {
            version: agentenv_core::lockfile::PORTABLE_LOCKFILE_VERSION.to_owned(),
            driver_protocol_version: SCHEMA_VERSION.to_owned(),
            name: "demo".to_owned(),
            blueprint_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
            composition: PortableComposition {
                version: "0.1.0".to_owned(),
                min_agentenv_version: "0.0.1-alpha0".to_owned(),
                sandbox: portable_component("openshell"),
                agent: portable_component("codex"),
                context: portable_component("filesystem"),
                inference: None,
                policy: agentenv_core::blueprint::PolicySection {
                    tier: "restricted".to_owned(),
                    presets: Vec::new(),
                    overrides: Vec::new(),
                    extra: BTreeMap::new(),
                },
                state: None,
            },
            policy: PortablePolicy {
                declared: agentenv_core::blueprint::PolicySection {
                    tier: "restricted".to_owned(),
                    presets: Vec::new(),
                    overrides: Vec::new(),
                    extra: BTreeMap::new(),
                },
                resolved: empty_policy(),
            },
            drivers,
            artifacts: BTreeMap::new(),
            credentials: BTreeMap::new(),
        }
    }

    fn proto_kind_label(kind: ProtoDriverKind) -> &'static str {
        match kind {
            ProtoDriverKind::Sandbox => "sandbox",
            ProtoDriverKind::Agent => "agent",
            ProtoDriverKind::Context => "context",
            ProtoDriverKind::Inference => "inference",
        }
    }

    fn portable_component(driver: &str) -> PortableComponent {
        PortableComponent {
            driver: driver.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            credentials: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }

    fn empty_policy() -> NetworkPolicy {
        NetworkPolicy {
            network: NetworkAccessPolicy {
                reloadability: PolicyReloadability::HotReload,
                allow: Vec::new(),
                deny: Vec::new(),
                approval_required: Vec::new(),
                dns: agentenv_proto::DnsPolicy::default(),
            },
            filesystem: FilesystemPolicy {
                reloadability: PolicyReloadability::LockedAtCreate,
                read_only: Vec::new(),
                read_write: Vec::new(),
            },
            process: ProcessPolicy {
                reloadability: PolicyReloadability::LockedAtCreate,
                run_as_user: "sandbox".to_owned(),
                run_as_group: "sandbox".to_owned(),
                profile: "restricted".to_owned(),
                allow_syscalls: Vec::new(),
                deny_syscalls: Vec::new(),
            },
            inference: InferencePolicy {
                reloadability: PolicyReloadability::HotReload,
                routes: Vec::new(),
            },
        }
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
