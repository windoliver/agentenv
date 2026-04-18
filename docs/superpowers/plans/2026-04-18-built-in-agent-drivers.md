# Built-in Agent Drivers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the built-in Claude, Codex, and OpenClaw agent drivers with a shared `agent_common` layer, a `0.2` protocol bump, conformance coverage, and gated OpenShell integration tests.

**Architecture:** Bump the agent-driver protocol so credential requirements are `AgentSpec`-aware and agent health checking becomes a declarative probe. Centralize shared agent behavior in `agentenv-core::agent_common`, then keep each agent crate thin and declarative around binary name, install step, MCP path/format, credential policy, and entrypoint rendering.

**Tech Stack:** Rust 2021, `async-trait`, `serde`, `serde_json`, `schemars`, Cargo workspace tests, JSON Schema generation, OpenShell driver traits

---

## File Structure

### Core protocol and shared logic

- Modify: `crates/agentenv-proto/src/schema_version.rs`
- Modify: `crates/agentenv-proto/src/types.rs`
- Modify: `crates/agentenv-proto/src/lib.rs`
- Modify: `crates/agentenv-proto/build.rs`
- Modify: `crates/agentenv-core/src/driver.rs`
- Modify: `crates/agentenv-core/src/lib.rs`
- Create: `crates/agentenv-core/src/agent_common.rs`

### Agent drivers

- Modify: `crates/drivers/agent-claude/Cargo.toml`
- Modify: `crates/drivers/agent-claude/src/lib.rs`
- Modify: `crates/drivers/agent-claude/README.md`
- Modify: `crates/drivers/agent-codex/Cargo.toml`
- Modify: `crates/drivers/agent-codex/src/lib.rs`
- Modify: `crates/drivers/agent-codex/README.md`
- Modify: `crates/drivers/agent-openclaw/Cargo.toml`
- Modify: `crates/drivers/agent-openclaw/src/lib.rs`
- Modify: `crates/drivers/agent-openclaw/README.md`

### Tests and docs

- Modify: `tests/driver-conformance/Cargo.toml`
- Modify: `tests/driver-conformance/src/lib.rs`
- Modify: `tests/driver-conformance/src/bin/mock-driver.rs`
- Modify: `tests/driver-conformance/tests/mock_driver.rs`
- Modify: `docs/DRIVER_PROTOCOL.md`
- Modify: `blueprints/openclaw+nexus+openshell.yaml`
- Create: `crates/drivers/agent-claude/tests/openshell_install.rs`
- Create: `crates/drivers/agent-codex/tests/openshell_install.rs`
- Create: `crates/drivers/agent-openclaw/tests/openshell_install.rs`

### Verification commands

- `cargo fmt`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

## Task 1: Bump `agentenv-proto` To `0.2`

**Files:**
- Modify: `crates/agentenv-proto/src/schema_version.rs`
- Modify: `crates/agentenv-proto/src/types.rs`
- Modify: `crates/agentenv-proto/src/lib.rs`
- Modify: `crates/agentenv-proto/build.rs`
- Test: `crates/agentenv-proto/src/lib.rs`

- [ ] **Step 1: Write the failing protocol tests**

Add these tests to `crates/agentenv-proto/src/lib.rs`:

```rust
#[test]
fn schema_version_is_0_2() {
    assert_eq!(SCHEMA_VERSION, "0.2");
}

#[test]
fn agent_health_check_probe_defaults_to_zero_exit_code() {
    let probe = AgentHealthCheckProbe {
        cmd: "codex --version".to_owned(),
        tty: false,
        env: std::collections::BTreeMap::new(),
        success_exit_codes: vec![0],
    };

    assert_eq!(probe.success_exit_codes, vec![0]);
}
```

- [ ] **Step 2: Run the proto tests to verify they fail**

Run: `cargo test -p agentenv-proto --lib`

Expected: FAIL with `SCHEMA_VERSION` still set to `0.1` and a compile error for missing `AgentHealthCheckProbe`

- [ ] **Step 3: Implement the `0.2` protocol surface**

Update `crates/agentenv-proto/src/schema_version.rs`:

```rust
pub const SCHEMA_VERSION: &str = "0.2";
```

Update `crates/agentenv-proto/src/types.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct AgentHealthCheckProbe {
    pub cmd: String,
    pub tty: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(default = "default_success_exit_codes", skip_serializing_if = "Vec::is_empty")]
    pub success_exit_codes: Vec<i32>,
}

fn default_success_exit_codes() -> Vec<i32> {
    vec![0]
}
```

Replace the static credential params and old health-check request/response exports with the `AgentSpec` input and `AgentHealthCheckProbe` output in the generated-schema list in `crates/agentenv-proto/build.rs`:

```rust
write_schema::<types::AgentSpec>(&schema_dir, "credential-requirements-params");
write_schema::<types::AgentHealthCheckProbe>(&schema_dir, "agent-health-check-probe");
```

- [ ] **Step 4: Regenerate schemas and rerun the proto tests**

Run: `cargo test -p agentenv-proto --lib`

Expected: PASS

- [ ] **Step 5: Commit the protocol bump**

```bash
git add crates/agentenv-proto/src/schema_version.rs \
        crates/agentenv-proto/src/types.rs \
        crates/agentenv-proto/src/lib.rs \
        crates/agentenv-proto/build.rs \
        crates/agentenv-proto/schema
git commit -m "feat: bump agent driver protocol to 0.2"
```

## Task 2: Add `agent_common` And Update The Core Trait Surface

**Files:**
- Modify: `crates/agentenv-core/src/driver.rs`
- Modify: `crates/agentenv-core/src/lib.rs`
- Create: `crates/agentenv-core/src/agent_common.rs`
- Test: `crates/agentenv-core/src/agent_common.rs`

- [ ] **Step 1: Write the failing shared-logic tests**

Create `crates/agentenv-core/src/agent_common.rs` with this initial test module:

```rust
#[cfg(test)]
mod tests {
    use super::{version_probe, AgentMode, SharedAgentConfig};

    #[test]
    fn shared_agent_config_defaults_to_tui() {
        let cfg = SharedAgentConfig::default();
        assert_eq!(cfg.mode, AgentMode::Tui);
    }

    #[test]
    fn version_probe_is_non_tty_and_accepts_exit_code_zero() {
        let probe = version_probe("claude");
        assert_eq!(probe.cmd, "claude --version");
        assert!(!probe.tty);
        assert_eq!(probe.success_exit_codes, vec![0]);
    }
}
```

- [ ] **Step 2: Run the core tests to verify they fail**

Run: `cargo test -p agentenv-core`

Expected: FAIL with missing `agent_common` module items and old `AgentDriver` method signatures

- [ ] **Step 3: Implement the shared module and trait updates**

Add this core surface to `crates/agentenv-core/src/agent_common.rs`:

```rust
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentMode {
    #[default]
    Tui,
    Headless,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SharedAgentConfig {
    pub mode: AgentMode,
}

pub fn version_probe(binary: &str) -> AgentHealthCheckProbe {
    AgentHealthCheckProbe {
        cmd: format!("{binary} --version"),
        tty: false,
        env: BTreeMap::new(),
        success_exit_codes: vec![0],
    }
}
```

Update `crates/agentenv-core/src/driver.rs`:

```rust
async fn credential_requirements(
    &self,
    spec: AgentSpec,
) -> DriverResult<CredentialRequirementsResult>;

async fn health_check_probe(
    &self,
    spec: AgentSpec,
) -> DriverResult<agentenv_proto::AgentHealthCheckProbe>;
```

Export the module from `crates/agentenv-core/src/lib.rs`:

```rust
pub mod agent_common;
pub mod driver;
```

- [ ] **Step 4: Rerun the core tests**

Run: `cargo test -p agentenv-core`

Expected: PASS

- [ ] **Step 5: Commit the shared core changes**

```bash
git add crates/agentenv-core/src/driver.rs \
        crates/agentenv-core/src/lib.rs \
        crates/agentenv-core/src/agent_common.rs
git commit -m "feat: add shared built-in agent helpers"
```

## Task 3: Implement The Claude Driver

**Files:**
- Modify: `crates/drivers/agent-claude/Cargo.toml`
- Modify: `crates/drivers/agent-claude/src/lib.rs`
- Modify: `crates/drivers/agent-claude/README.md`
- Test: `crates/drivers/agent-claude/src/lib.rs`

- [ ] **Step 1: Write the failing Claude tests**

Add these tests to `crates/drivers/agent-claude/src/lib.rs`:

```rust
#[tokio::test]
async fn claude_driver_reports_anthropic_credential_and_probe() {
    let driver = ClaudeDriver::default();
    let spec = AgentSpec { version: None, config: BTreeMap::new() };

    let credentials = driver.credential_requirements(spec.clone()).await.unwrap();
    let probe = driver.health_check_probe(spec).await.unwrap();

    assert_eq!(credentials.requirements[0].name, "ANTHROPIC_API_KEY");
    assert_eq!(probe.cmd, "claude --version");
}

#[tokio::test]
async fn claude_driver_renders_headless_entrypoint() {
    let driver = ClaudeDriver::default();
    let spec = AgentSpec {
        version: None,
        config: BTreeMap::from([("mode".to_owned(), serde_json::json!("headless"))]),
    };

    let entrypoint = driver.render_entrypoint(spec).await.unwrap();
    assert!(entrypoint.content.contains("claude --headless"));
}
```

- [ ] **Step 2: Run the Claude crate tests to verify they fail**

Run: `cargo test -p agent-claude`

Expected: FAIL with missing `ClaudeDriver`

- [ ] **Step 3: Implement the Claude driver**

Update `crates/drivers/agent-claude/Cargo.toml`:

```toml
[dependencies]
agentenv-core = { path = "../../agentenv-core" }
agentenv-proto = { path = "../../agentenv-proto" }
async-trait.workspace = true
serde.workspace = true
serde_json.workspace = true

[dev-dependencies]
tokio.workspace = true
```

Replace `crates/drivers/agent-claude/src/lib.rs` with:

```rust
#[derive(Debug, Default)]
pub struct ClaudeDriver;

#[async_trait]
impl AgentDriver for ClaudeDriver {
    async fn install_steps(&self, _spec: AgentSpec) -> DriverResult<InstallStepsResult> {
        Ok(InstallStepsResult {
            steps: vec![DockerfileFragment {
                name: Some("install-claude".to_owned()),
                content: "RUN npm install -g @anthropic-ai/claude-code".to_owned(),
            }],
        })
    }

    async fn mcp_config_path(&self, _params: McpConfigPathParams) -> DriverResult<McpConfigPathResult> {
        Ok(McpConfigPathResult {
            path: "~/.claude/mcp_servers.json".to_owned(),
        })
    }

    async fn credential_requirements(&self, _spec: AgentSpec) -> DriverResult<CredentialRequirementsResult> {
        Ok(CredentialRequirementsResult {
            requirements: vec![CredentialRequirement {
                name: "ANTHROPIC_API_KEY".to_owned(),
                kind: CredentialKind::ApiKey,
                required: true,
                description: "Claude Code API key".to_owned(),
                validator: None,
            }],
        })
    }

    async fn health_check_probe(&self, _spec: AgentSpec) -> DriverResult<AgentHealthCheckProbe> {
        Ok(version_probe("claude"))
    }
}
```

- [ ] **Step 4: Rerun the Claude tests**

Run: `cargo test -p agent-claude`

Expected: PASS

- [ ] **Step 5: Commit the Claude driver**

```bash
git add crates/drivers/agent-claude/Cargo.toml \
        crates/drivers/agent-claude/src/lib.rs \
        crates/drivers/agent-claude/README.md
git commit -m "feat: implement claude agent driver"
```

## Task 4: Implement The Codex Driver

**Files:**
- Modify: `crates/drivers/agent-codex/Cargo.toml`
- Modify: `crates/drivers/agent-codex/src/lib.rs`
- Modify: `crates/drivers/agent-codex/README.md`
- Test: `crates/drivers/agent-codex/src/lib.rs`

- [ ] **Step 1: Write the failing Codex tests**

Add these tests to `crates/drivers/agent-codex/src/lib.rs`:

```rust
#[tokio::test]
async fn codex_driver_reports_openai_credential_and_probe() {
    let driver = CodexDriver::default();
    let spec = AgentSpec { version: None, config: BTreeMap::new() };

    let credentials = driver.credential_requirements(spec.clone()).await.unwrap();
    let probe = driver.health_check_probe(spec).await.unwrap();

    assert_eq!(credentials.requirements[0].name, "OPENAI_API_KEY");
    assert_eq!(probe.cmd, "codex --version");
}

#[tokio::test]
async fn codex_driver_renders_headless_entrypoint() {
    let driver = CodexDriver::default();
    let spec = AgentSpec {
        version: None,
        config: BTreeMap::from([("mode".to_owned(), serde_json::json!("headless"))]),
    };

    let entrypoint = driver.render_entrypoint(spec).await.unwrap();
    assert!(entrypoint.content.contains("codex exec"));
}
```

- [ ] **Step 2: Run the Codex crate tests to verify they fail**

Run: `cargo test -p agent-codex`

Expected: FAIL with missing `CodexDriver`

- [ ] **Step 3: Implement the Codex driver**

Update `crates/drivers/agent-codex/Cargo.toml`:

```toml
[dependencies]
agentenv-core = { path = "../../agentenv-core" }
agentenv-proto = { path = "../../agentenv-proto" }
async-trait.workspace = true
serde.workspace = true
serde_json.workspace = true

[dev-dependencies]
tokio.workspace = true
```

Replace `crates/drivers/agent-codex/src/lib.rs` with:

```rust
#[derive(Debug, Default)]
pub struct CodexDriver;

#[async_trait]
impl AgentDriver for CodexDriver {
    async fn install_steps(&self, _spec: AgentSpec) -> DriverResult<InstallStepsResult> {
        Ok(InstallStepsResult {
            steps: vec![DockerfileFragment {
                name: Some("install-codex".to_owned()),
                content: "RUN npm install -g @openai/codex".to_owned(),
            }],
        })
    }

    async fn mcp_config_path(&self, _params: McpConfigPathParams) -> DriverResult<McpConfigPathResult> {
        Ok(McpConfigPathResult {
            path: "~/.codex/mcp_servers.json".to_owned(),
        })
    }

    async fn credential_requirements(&self, _spec: AgentSpec) -> DriverResult<CredentialRequirementsResult> {
        Ok(CredentialRequirementsResult {
            requirements: vec![CredentialRequirement {
                name: "OPENAI_API_KEY".to_owned(),
                kind: CredentialKind::ApiKey,
                required: true,
                description: "Codex API key".to_owned(),
                validator: None,
            }],
        })
    }

    async fn health_check_probe(&self, _spec: AgentSpec) -> DriverResult<AgentHealthCheckProbe> {
        Ok(version_probe("codex"))
    }
}
```

- [ ] **Step 4: Rerun the Codex tests**

Run: `cargo test -p agent-codex`

Expected: PASS

- [ ] **Step 5: Commit the Codex driver**

```bash
git add crates/drivers/agent-codex/Cargo.toml \
        crates/drivers/agent-codex/src/lib.rs \
        crates/drivers/agent-codex/README.md
git commit -m "feat: implement codex agent driver"
```

## Task 5: Implement The OpenClaw Driver

**Files:**
- Modify: `crates/drivers/agent-openclaw/Cargo.toml`
- Modify: `crates/drivers/agent-openclaw/src/lib.rs`
- Modify: `crates/drivers/agent-openclaw/README.md`
- Test: `crates/drivers/agent-openclaw/src/lib.rs`

- [ ] **Step 1: Write the failing OpenClaw tests**

Add these tests to `crates/drivers/agent-openclaw/src/lib.rs`:

```rust
#[tokio::test]
async fn openclaw_defaults_to_openai_credentials() {
    let driver = OpenClawDriver::default();
    let spec = AgentSpec { version: None, config: BTreeMap::new() };

    let credentials = driver.credential_requirements(spec).await.unwrap();
    assert_eq!(credentials.requirements[0].name, "OPENAI_API_KEY");
}

#[tokio::test]
async fn openclaw_uses_anthropic_credentials_for_anthropic_provider() {
    let driver = OpenClawDriver::default();
    let spec = AgentSpec {
        version: None,
        config: BTreeMap::from([("provider".to_owned(), serde_json::json!("anthropic"))]),
    };

    let credentials = driver.credential_requirements(spec).await.unwrap();
    assert_eq!(credentials.requirements[0].name, "ANTHROPIC_API_KEY");
}

#[tokio::test]
async fn openclaw_renders_headless_entrypoint() {
    let driver = OpenClawDriver::default();
    let spec = AgentSpec {
        version: None,
        config: BTreeMap::from([("mode".to_owned(), serde_json::json!("headless"))]),
    };

    let entrypoint = driver.render_entrypoint(spec).await.unwrap();
    assert!(entrypoint.content.contains("openclaw agent --headless"));
}
```

- [ ] **Step 2: Run the OpenClaw crate tests to verify they fail**

Run: `cargo test -p agent-openclaw`

Expected: FAIL with missing `OpenClawDriver`

- [ ] **Step 3: Implement the OpenClaw driver and provider resolution**

Update `crates/drivers/agent-openclaw/Cargo.toml`:

```toml
[dependencies]
agentenv-core = { path = "../../agentenv-core" }
agentenv-proto = { path = "../../agentenv-proto" }
async-trait.workspace = true
serde.workspace = true
serde_json.workspace = true

[dev-dependencies]
tokio.workspace = true
```

Add this core logic to `crates/drivers/agent-openclaw/src/lib.rs`:

```rust
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OpenClawProvider {
    Openai,
    Anthropic,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
struct OpenClawConfig {
    mode: AgentMode,
    provider: Option<OpenClawProvider>,
    model: Option<String>,
}

fn resolve_provider(cfg: &OpenClawConfig) -> DriverResult<OpenClawProvider> {
    match (&cfg.provider, cfg.model.as_deref()) {
        (Some(provider), Some(model)) if model.starts_with("openai/") && *provider != OpenClawProvider::Openai => {
            Err(DriverError::CapabilityMissing { capability: "openclaw_provider_model_conflict".to_owned() })
        }
        (Some(provider), Some(model)) if model.starts_with("anthropic/") && *provider != OpenClawProvider::Anthropic => {
            Err(DriverError::CapabilityMissing { capability: "openclaw_provider_model_conflict".to_owned() })
        }
        (Some(provider), _) => Ok(provider.clone()),
        (None, Some(model)) if model.starts_with("anthropic/") => Ok(OpenClawProvider::Anthropic),
        (None, _) => Ok(OpenClawProvider::Openai),
    }
}
```

- [ ] **Step 4: Rerun the OpenClaw tests**

Run: `cargo test -p agent-openclaw`

Expected: PASS

- [ ] **Step 5: Commit the OpenClaw driver**

```bash
git add crates/drivers/agent-openclaw/Cargo.toml \
        crates/drivers/agent-openclaw/src/lib.rs \
        crates/drivers/agent-openclaw/README.md
git commit -m "feat: implement openclaw agent driver"
```

## Task 6: Extend Conformance Coverage For Built-In Agent Drivers

**Files:**
- Modify: `tests/driver-conformance/Cargo.toml`
- Modify: `tests/driver-conformance/src/lib.rs`
- Modify: `tests/driver-conformance/src/bin/mock-driver.rs`
- Modify: `tests/driver-conformance/tests/mock_driver.rs`
- Test: `crates/drivers/agent-claude/src/lib.rs`
- Test: `crates/drivers/agent-codex/src/lib.rs`
- Test: `crates/drivers/agent-openclaw/src/lib.rs`

- [ ] **Step 1: Write the failing in-process conformance helper test**

Add this helper test to `tests/driver-conformance/src/lib.rs`:

```rust
use std::collections::BTreeMap;

#[tokio::test]
async fn agent_driver_contract_checks_probe_and_credentials() {
    #[derive(Default)]
    struct FakeDriver;

    #[async_trait::async_trait]
    impl agentenv_core::driver::AgentDriver for FakeDriver {
        async fn initialize(
            &mut self,
            _params: agentenv_proto::InitializeParams,
        ) -> agentenv_core::driver::DriverResult<agentenv_proto::InitializeResult> {
            Ok(agentenv_proto::InitializeResult {
                driver: agentenv_proto::DriverInfo {
                    name: "fake-agent".to_owned(),
                    kind: agentenv_proto::DriverKind::Agent,
                    version: "0.0.1".to_owned(),
                    protocol_version: agentenv_proto::SCHEMA_VERSION.to_owned(),
                },
                capabilities: agentenv_proto::Capabilities::Agent(agentenv_proto::AgentCapabilities {
                    supports_mcp: true,
                    supports_slash_commands: true,
                    supports_tui: true,
                    supports_headless: true,
                }),
            })
        }

        async fn preflight(
            &self,
            _params: agentenv_proto::PreflightParams,
        ) -> agentenv_core::driver::DriverResult<agentenv_proto::PreflightResult> {
            Ok(agentenv_proto::PreflightResult { ok: true, issues: vec![] })
        }

        async fn install_steps(
            &self,
            _spec: agentenv_proto::AgentSpec,
        ) -> agentenv_core::driver::DriverResult<agentenv_proto::InstallStepsResult> {
            Ok(agentenv_proto::InstallStepsResult { steps: vec![] })
        }

        async fn mcp_config_path(
            &self,
            _params: agentenv_proto::McpConfigPathParams,
        ) -> agentenv_core::driver::DriverResult<agentenv_proto::McpConfigPathResult> {
            Ok(agentenv_proto::McpConfigPathResult {
                path: "~/.fake/mcp_servers.json".to_owned(),
            })
        }

        async fn render_mcp_config(
            &self,
            _params: agentenv_proto::RenderMcpConfigParams,
        ) -> agentenv_core::driver::DriverResult<agentenv_proto::RenderMcpConfigResult> {
            Ok(agentenv_proto::RenderMcpConfigResult {
                content: "{}".to_owned(),
            })
        }

        async fn render_entrypoint(
            &self,
            _spec: agentenv_proto::AgentSpec,
        ) -> agentenv_core::driver::DriverResult<agentenv_proto::RenderEntrypointResult> {
            Ok(agentenv_proto::RenderEntrypointResult {
                content: "fake-agent".to_owned(),
            })
        }

        async fn credential_requirements(
            &self,
            _spec: agentenv_proto::AgentSpec,
        ) -> agentenv_core::driver::DriverResult<agentenv_proto::CredentialRequirementsResult> {
            Ok(agentenv_proto::CredentialRequirementsResult {
                requirements: vec![agentenv_proto::CredentialRequirement {
                    name: "FAKE_API_KEY".to_owned(),
                    kind: agentenv_proto::CredentialKind::ApiKey,
                    required: true,
                    description: "fake".to_owned(),
                    validator: None,
                }],
            })
        }

        async fn health_check_probe(
            &self,
            _spec: agentenv_proto::AgentSpec,
        ) -> agentenv_core::driver::DriverResult<agentenv_proto::AgentHealthCheckProbe> {
            Ok(agentenv_proto::AgentHealthCheckProbe {
                cmd: "fake-agent --version".to_owned(),
                tty: false,
                env: BTreeMap::new(),
                success_exit_codes: vec![0],
            })
        }

        async fn shutdown(
            &mut self,
            _params: agentenv_proto::ShutdownParams,
        ) -> agentenv_core::driver::DriverResult<agentenv_proto::EmptyResult> {
            Ok(agentenv_proto::EmptyResult {})
        }
    }

    let mut driver = FakeDriver::default();
    let spec = agentenv_proto::AgentSpec {
        version: None,
        config: BTreeMap::new(),
    };

    assert_agent_driver_contract(&mut driver, spec).await.unwrap();
}
```

- [ ] **Step 2: Run the conformance crate tests to verify they fail**

Run: `cargo test -p driver-conformance`

Expected: FAIL because the crate has no in-process `AgentDriver` helper yet

- [ ] **Step 3: Implement the shared helper and wire drivers to it**

Update `tests/driver-conformance/Cargo.toml`:

```toml
[dependencies]
agentenv-core = { path = "../../crates/agentenv-core" }
agentenv-proto = { path = "../../crates/agentenv-proto" }
anyhow.workspace = true
async-trait.workspace = true
serde.workspace = true
serde_json.workspace = true
tokio.workspace = true
```

Add this helper to `tests/driver-conformance/src/lib.rs`:

```rust
pub async fn assert_agent_driver_contract<D: agentenv_core::driver::AgentDriver>(
    driver: &mut D,
    spec: agentenv_proto::AgentSpec,
) -> anyhow::Result<()> {
    let init = driver.initialize(agentenv_proto::InitializeParams {
        schema_version: agentenv_proto::SCHEMA_VERSION.to_owned(),
        core_version: "0.0.1".to_owned(),
        workdir: "/tmp/agentenv".to_owned(),
        log_level: agentenv_proto::LogLevel::Info,
    }).await?;

    agentenv_core::driver::ensure_protocol_compatible(&init)?;
    let preflight = driver.preflight(agentenv_proto::PreflightParams::default()).await?;
    anyhow::ensure!(preflight.ok, "preflight must pass");
    let _ = driver.credential_requirements(spec.clone()).await?;
    let _ = driver.health_check_probe(spec).await?;
    Ok(())
}
```

Then add a `driver_conformance::assert_agent_driver_contract(...)` test to each agent crate.

- [ ] **Step 4: Rerun crate-level tests**

Run: `cargo test -p driver-conformance -p agent-claude -p agent-codex -p agent-openclaw`

Expected: PASS

- [ ] **Step 5: Commit the conformance updates**

```bash
git add tests/driver-conformance/Cargo.toml \
        tests/driver-conformance/src/lib.rs \
        tests/driver-conformance/src/bin/mock-driver.rs \
        tests/driver-conformance/tests/mock_driver.rs \
        crates/drivers/agent-claude/src/lib.rs \
        crates/drivers/agent-codex/src/lib.rs \
        crates/drivers/agent-openclaw/src/lib.rs
git commit -m "test: extend conformance coverage to built-in agent drivers"
```

## Task 7: Add Gated OpenShell Integration Tests

**Files:**
- Create: `crates/drivers/agent-claude/tests/openshell_install.rs`
- Create: `crates/drivers/agent-codex/tests/openshell_install.rs`
- Create: `crates/drivers/agent-openclaw/tests/openshell_install.rs`
- Modify: `crates/drivers/agent-claude/Cargo.toml`
- Modify: `crates/drivers/agent-codex/Cargo.toml`
- Modify: `crates/drivers/agent-openclaw/Cargo.toml`

- [ ] **Step 1: Write the ignored integration test for Claude**

Create `crates/drivers/agent-claude/tests/openshell_install.rs`:

```rust
use std::collections::BTreeMap;

use agent_claude::ClaudeDriver;
use agentenv_core::driver::AgentDriver;
use agentenv_proto::AgentSpec;

#[tokio::test]
#[ignore = "enable once sandbox-openshell implements create + exec"]
async fn claude_install_and_probe_work_in_fresh_sandbox() {
    let driver = ClaudeDriver::default();
    let spec = AgentSpec { version: None, config: BTreeMap::new() };

    let install = driver.install_steps(spec.clone()).await.unwrap();
    let probe = driver.health_check_probe(spec).await.unwrap();

    assert!(!install.steps.is_empty());
    assert_eq!(probe.cmd, "claude --version");
}
```

- [ ] **Step 2: Add matching ignored tests for Codex and OpenClaw**

Create the same shape in:

```rust
// crates/drivers/agent-codex/tests/openshell_install.rs
use std::collections::BTreeMap;

use agent_codex::CodexDriver;
use agentenv_core::driver::AgentDriver;
use agentenv_proto::AgentSpec;

#[tokio::test]
#[ignore = "enable once sandbox-openshell implements create + exec"]
async fn codex_install_and_probe_work_in_fresh_sandbox() {
    let driver = CodexDriver::default();
    let spec = AgentSpec { version: None, config: BTreeMap::new() };

    let install = driver.install_steps(spec.clone()).await.unwrap();
    let probe = driver.health_check_probe(spec).await.unwrap();

    assert!(!install.steps.is_empty());
    assert_eq!(probe.cmd, "codex --version");
}

// crates/drivers/agent-openclaw/tests/openshell_install.rs
use std::collections::BTreeMap;

use agent_openclaw::OpenClawDriver;
use agentenv_core::driver::AgentDriver;
use agentenv_proto::AgentSpec;

#[tokio::test]
#[ignore = "enable once sandbox-openshell implements create + exec"]
async fn openclaw_install_and_probe_work_in_fresh_sandbox() {
    let driver = OpenClawDriver::default();
    let spec = AgentSpec { version: None, config: BTreeMap::new() };

    let install = driver.install_steps(spec.clone()).await.unwrap();
    let probe = driver.health_check_probe(spec).await.unwrap();

    assert!(!install.steps.is_empty());
    assert_eq!(probe.cmd, "openclaw --version");
}
```

- [ ] **Step 3: Run the ignored-test inventory**

Run: `cargo test -p agent-claude -p agent-codex -p agent-openclaw -- --ignored`

Expected: PASS with the three ignored tests executed successfully

- [ ] **Step 4: Add a short README note for the gate**

Append this sentence to each driver README:

```md
OpenShell-backed install/probe tests live under `tests/openshell_install.rs` and stay ignored until `sandbox-openshell` supports `create + exec`.
```

- [ ] **Step 5: Commit the gated integration test scaffolding**

```bash
git add crates/drivers/agent-claude/tests/openshell_install.rs \
        crates/drivers/agent-codex/tests/openshell_install.rs \
        crates/drivers/agent-openclaw/tests/openshell_install.rs \
        crates/drivers/agent-claude/README.md \
        crates/drivers/agent-codex/README.md \
        crates/drivers/agent-openclaw/README.md
git commit -m "test: scaffold gated openshell agent driver checks"
```

## Task 8: Update Docs, Blueprint, And Run Full Verification

**Files:**
- Modify: `docs/DRIVER_PROTOCOL.md`
- Modify: `blueprints/openclaw+nexus+openshell.yaml`
- Modify: `crates/drivers/agent-claude/README.md`
- Modify: `crates/drivers/agent-codex/README.md`
- Modify: `crates/drivers/agent-openclaw/README.md`

- [ ] **Step 1: Write the failing docs/fixture test via grep**

Run:

```bash
rg -n "credential_requirements\\(\\{\\}\\)|health_check\\(\\{handle\\}\\)|OPENAI_API_KEY:" docs/DRIVER_PROTOCOL.md blueprints/openclaw+nexus+openshell.yaml
```

Expected: MATCHES showing the stale `0.1` method signatures and the old OpenClaw blueprint credential block

- [ ] **Step 2: Update the protocol doc and blueprint**

Apply these exact edits:

```md
| `credential_requirements` | `AgentSpec` | `[CredentialRequirement]` |
| `health_check_probe` | `AgentSpec` | `AgentHealthCheckProbe` |
```

```yaml
agent:
  driver: openclaw
  config:
    provider: openai
  credentials:
    OPENAI_API_KEY:
      source: env
      required: true
```

- [ ] **Step 3: Run the full repo verification**

Run:

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected:

```text
Formatting complete
Finished `dev` profile ...
test result: ok.
```

- [ ] **Step 4: Inspect the final diff**

Run: `git diff --stat HEAD~8..HEAD`

Expected: touched crates include `agentenv-proto`, `agentenv-core`, all three `agent-*` crates, `tests/driver-conformance`, `docs/DRIVER_PROTOCOL.md`, and `blueprints/openclaw+nexus+openshell.yaml`

- [ ] **Step 5: Commit the docs and final cleanup**

```bash
git add docs/DRIVER_PROTOCOL.md \
        blueprints/openclaw+nexus+openshell.yaml \
        crates/drivers/agent-claude/README.md \
        crates/drivers/agent-codex/README.md \
        crates/drivers/agent-openclaw/README.md
git commit -m "docs: update built-in agent driver protocol references"
```
