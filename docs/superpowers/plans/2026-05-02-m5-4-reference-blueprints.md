# M5-4 Reference Blueprints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand agentenv's reference blueprints into a documented nine-blueprint starter set with sample projects and an optional live integration harness.

**Architecture:** Keep fast YAML parse, validate, and resolve checks in `agentenv-core` so normal test runs stay deterministic. Add human-facing docs and examples beside the blueprint files, then place live `create -> exec -> destroy` validation in a dedicated `tests/blueprint-integration/` workspace crate gated by an `integration` feature and explicit ignored tests.

**Tech Stack:** Rust 2021, Cargo workspace integration tests, `serde_yaml`, `serde_json`, `uuid`, existing `agentenv` CLI, existing `agentenv-core` blueprint parser and lifecycle verification, YAML reference files.

---

## File Structure

Create:

- `blueprints/codex+filesystem+openshell.yaml`: getting-started Codex blueprint with local filesystem context.
- `blueprints/openclaw+filesystem+openshell.yaml`: getting-started OpenClaw blueprint with local filesystem context.
- `blueprints/claude+mcp-generic+openshell.yaml`: Claude blueprint for arbitrary MCP endpoints.
- `blueprints/hermes+filesystem+openshell.yaml`: Hermes subprocess-agent blueprint with local filesystem context.
- `blueprints/claude+nexus+openshell.yaml`: Claude enterprise blueprint for Nexus hub context.
- `docs/BLUEPRINTS.md`: catalog of all nine blueprints, prerequisites, trade-offs, and usage.
- `examples/quickstart/agentenv.yaml`: minimal quickstart project blueprint.
- `examples/quickstart/README.md`: quickstart lifecycle walkthrough.
- `examples/enterprise-hub/agentenv.yaml`: Nexus hub template.
- `examples/enterprise-hub/Dockerfile`: company base-image example used by the README.
- `examples/enterprise-hub/certs/company-ca.pem`: non-secret example CA certificate text.
- `examples/enterprise-hub/README.md`: enterprise hub setup and lifecycle walkthrough.
- `examples/headless-ci/agentenv.yaml`: non-interactive CI template.
- `examples/headless-ci/README.md`: headless CI workflow.
- `tests/blueprint-integration/Cargo.toml`: dedicated integration test package.
- `tests/blueprint-integration/tests/reference_blueprints.rs`: live blueprint harness.

Modify:

- `Cargo.toml`: add `tests/blueprint-integration` as a workspace member.
- `crates/agentenv-core/tests/reference_blueprints.rs`: expand fast reference blueprint coverage and add docs/example coverage.

Test:

- `crates/agentenv-core/tests/reference_blueprints.rs`: default fast checks for all blueprints, docs catalog entries, and sample project blueprint parsing.
- `tests/blueprint-integration/tests/reference_blueprints.rs`: ignored live checks for create, exec, and destroy when driver prerequisites exist.

---

### Task 1: Fast Coverage For All Nine Reference Blueprints

**Files:**
- Modify: `crates/agentenv-core/tests/reference_blueprints.rs`

- [ ] **Step 1: Write the failing all-blueprints test**

In `crates/agentenv-core/tests/reference_blueprints.rs`, add these definitions after `workspace_path`:

```rust
struct ReferenceBlueprint {
    path: &'static str,
    agent_driver: &'static str,
    context_driver: &'static str,
    tier: &'static str,
    persists_home: Option<bool>,
    context: ContextExpectation,
}

enum ContextExpectation {
    Filesystem { mount: &'static str },
    GenericMcp {
        url: &'static str,
        transport: &'static str,
    },
    Nexus { hub_url: &'static str },
}

fn reference_blueprints() -> Vec<ReferenceBlueprint> {
    vec![
        ReferenceBlueprint {
            path: "blueprints/claude+filesystem+openshell.yaml",
            agent_driver: "claude",
            context_driver: "filesystem",
            tier: "balanced",
            persists_home: Some(true),
            context: ContextExpectation::Filesystem {
                mount: "~/projects",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/codex+filesystem+openshell.yaml",
            agent_driver: "codex",
            context_driver: "filesystem",
            tier: "balanced",
            persists_home: Some(true),
            context: ContextExpectation::Filesystem {
                mount: "~/projects",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/openclaw+filesystem+openshell.yaml",
            agent_driver: "openclaw",
            context_driver: "filesystem",
            tier: "balanced",
            persists_home: Some(true),
            context: ContextExpectation::Filesystem {
                mount: "~/projects",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/claude+mcp-generic+openshell.yaml",
            agent_driver: "claude",
            context_driver: "mcp-generic",
            tier: "restricted",
            persists_home: Some(true),
            context: ContextExpectation::GenericMcp {
                url: "https://93.184.216.34",
                transport: "http+sse",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/hermes+filesystem+openshell.yaml",
            agent_driver: "hermes",
            context_driver: "filesystem",
            tier: "balanced",
            persists_home: None,
            context: ContextExpectation::Filesystem {
                mount: "~/projects",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/claude+nexus+openshell.yaml",
            agent_driver: "claude",
            context_driver: "nexus",
            tier: "balanced",
            persists_home: Some(true),
            context: ContextExpectation::Nexus {
                hub_url: "https://93.184.216.35",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/codex+mcp-generic+openshell.yaml",
            agent_driver: "codex",
            context_driver: "mcp-generic",
            tier: "restricted",
            persists_home: None,
            context: ContextExpectation::GenericMcp {
                url: "https://93.184.216.34",
                transport: "http+sse",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/hermes+nexus+openshell.yaml",
            agent_driver: "hermes",
            context_driver: "nexus",
            tier: "balanced",
            persists_home: None,
            context: ContextExpectation::Nexus {
                hub_url: "https://93.184.216.35",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/openclaw+nexus+openshell.yaml",
            agent_driver: "openclaw",
            context_driver: "nexus",
            tier: "balanced",
            persists_home: Some(true),
            context: ContextExpectation::Nexus {
                hub_url: "https://93.184.216.35",
            },
        },
    ]
}
```

Replace `all_reference_blueprints_parse` with:

```rust
#[test]
fn all_reference_blueprints_parse() {
    let _guard = env_lock().lock().unwrap();

    std::env::set_var("MCP_URL", "https://93.184.216.34");
    std::env::set_var("NEXUS_HUB_URL", "https://93.184.216.35");

    for case in reference_blueprints() {
        let doc = std::fs::read_to_string(workspace_path(case.path)).unwrap();
        let blueprint = Blueprint::from_yaml(&doc).unwrap();

        assert_eq!(blueprint.version, "0.1.0", "{}", case.path);
        assert_eq!(
            blueprint.min_agentenv_version,
            env!("CARGO_PKG_VERSION"),
            "{}",
            case.path
        );
        assert_eq!(blueprint.sandbox.driver, "openshell", "{}", case.path);
        assert_eq!(blueprint.agent.driver, case.agent_driver, "{}", case.path);
        assert_eq!(
            blueprint.context.driver, case.context_driver,
            "{}",
            case.path
        );
        assert_eq!(blueprint.policy.tier, case.tier, "{}", case.path);
        assert_eq!(
            blueprint
                .inference
                .as_ref()
                .map(|section| section.driver.as_str()),
            Some("passthrough"),
            "{}",
            case.path
        );
        assert_eq!(
            blueprint
                .state
                .as_ref()
                .and_then(|state| state.persist_home),
            case.persists_home,
            "{}",
            case.path
        );

        match case.context {
            ContextExpectation::Filesystem { mount } => {
                assert_eq!(
                    blueprint
                        .context
                        .extra
                        .get("mount")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    mount,
                    "{}",
                    case.path
                );
            }
            ContextExpectation::GenericMcp { url, transport } => {
                let endpoint = blueprint.context.extra.get("endpoint").unwrap();
                assert_eq!(yaml_string_field(endpoint, "url"), url, "{}", case.path);
                assert_eq!(
                    yaml_string_field(endpoint, "transport"),
                    transport,
                    "{}",
                    case.path
                );
            }
            ContextExpectation::Nexus { hub_url } => {
                assert_eq!(
                    blueprint
                        .context
                        .extra
                        .get("mode")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "hub",
                    "{}",
                    case.path
                );
                assert_eq!(
                    blueprint
                        .context
                        .extra
                        .get("hub_url")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    hub_url,
                    "{}",
                    case.path
                );
            }
        }
    }
}
```

- [ ] **Step 2: Run the test to verify RED**

Run:

```sh
cargo test -p agentenv-core --test reference_blueprints all_reference_blueprints_parse
```

Expected: FAIL because at least `blueprints/codex+filesystem+openshell.yaml` does not exist.

- [ ] **Step 3: Commit the failing test**

```bash
git add crates/agentenv-core/tests/reference_blueprints.rs
git commit -m "test: cover full reference blueprint set"
```

---

### Task 2: Add Missing Reference Blueprints

**Files:**
- Create: `blueprints/codex+filesystem+openshell.yaml`
- Create: `blueprints/openclaw+filesystem+openshell.yaml`
- Create: `blueprints/claude+mcp-generic+openshell.yaml`
- Create: `blueprints/hermes+filesystem+openshell.yaml`
- Create: `blueprints/claude+nexus+openshell.yaml`

- [ ] **Step 1: Add `codex+filesystem+openshell.yaml`**

Create `blueprints/codex+filesystem+openshell.yaml`:

```yaml
# Reference blueprint - OpenAI Codex in OpenShell with a local filesystem context.
# Good for: getting started with Codex against a local project tree.
#
# Prerequisites:
#   export OPENAI_API_KEY=sk-openai-example
#
# Usage:
#   agentenv create myapp --blueprint blueprints/codex+filesystem+openshell.yaml
#   agentenv enter myapp

version: 0.1.0
min_agentenv_version: 0.0.1-alpha0

sandbox:
  driver: openshell
  version: ">=0.0.1-alpha0,<0.1"

agent:
  driver: codex
  credentials:
    OPENAI_API_KEY:
      source: env
      required: true

context:
  driver: filesystem
  mount: ~/projects

inference:
  driver: passthrough

policy:
  tier: balanced
  presets:
    - github_read
    - npm_read

state:
  persist_home: true
```

- [ ] **Step 2: Add `openclaw+filesystem+openshell.yaml`**

Create `blueprints/openclaw+filesystem+openshell.yaml`:

```yaml
# Reference blueprint - OpenClaw in OpenShell with a local filesystem context.
# Good for: getting started with an always-on OpenClaw assistant over local code.
#
# Prerequisites:
#   export OPENAI_API_KEY=sk-openai-example
#
# Usage:
#   agentenv create assistant --blueprint blueprints/openclaw+filesystem+openshell.yaml
#   agentenv enter assistant

version: 0.1.0
min_agentenv_version: 0.0.1-alpha0

sandbox:
  driver: openshell
  version: ">=0.0.1-alpha0,<0.1"

agent:
  driver: openclaw
  config:
    provider: openai
  credentials:
    OPENAI_API_KEY:
      source: env
      required: true

context:
  driver: filesystem
  mount: ~/projects

inference:
  driver: passthrough

policy:
  tier: balanced
  presets:
    - github_read
    - npm_read

state:
  persist_home: true
```

- [ ] **Step 3: Add `claude+mcp-generic+openshell.yaml`**

Create `blueprints/claude+mcp-generic+openshell.yaml`:

```yaml
# Reference blueprint - Claude Code in OpenShell with a generic MCP context server.
# Good for: connecting Claude to any MCP-compatible knowledge service.
#
# Prerequisites:
#   export ANTHROPIC_API_KEY=sk-ant-example
#   export MCP_URL=https://mcp.internal.company.com
#   export MCP_TOKEN=mcp-token-example
#
# Usage:
#   agentenv create docs --blueprint blueprints/claude+mcp-generic+openshell.yaml
#   agentenv enter docs

version: 0.1.0
min_agentenv_version: 0.0.1-alpha0

sandbox:
  driver: openshell
  version: ">=0.0.1-alpha0,<0.1"

agent:
  driver: claude
  credentials:
    ANTHROPIC_API_KEY:
      source: env
      required: true

context:
  driver: mcp-generic
  endpoint:
    url: ${MCP_URL}
    transport: http+sse
  credentials:
    MCP_TOKEN:
      source: env
      required: true

inference:
  driver: passthrough

policy:
  tier: restricted
  presets: []
  overrides:
    - allow: "${MCP_URL}"

state:
  persist_home: true
```

- [ ] **Step 4: Add `hermes+filesystem+openshell.yaml`**

Create `blueprints/hermes+filesystem+openshell.yaml`:

```yaml
# Reference blueprint - Hermes subprocess agent in OpenShell with a local filesystem context.
# Good for: demonstrating an external polyglot agent driver against local code.
#
# Prerequisites:
#   export OPENAI_API_KEY=sk-openai-example
#   agentenv drivers list   # confirm the hermes agent driver is installed
#
# Usage:
#   agentenv create research --blueprint blueprints/hermes+filesystem+openshell.yaml
#   agentenv enter research

version: 0.1.0
min_agentenv_version: 0.0.1-alpha0

sandbox:
  driver: openshell
  version: ">=0.0.1-alpha0,<0.1"

agent:
  driver: hermes
  credentials:
    OPENAI_API_KEY:
      source: env
      required: true

context:
  driver: filesystem
  mount: ~/projects

inference:
  driver: passthrough

policy:
  tier: balanced
  presets:
    - github_read
```

- [ ] **Step 5: Add `claude+nexus+openshell.yaml`**

Create `blueprints/claude+nexus+openshell.yaml`:

```yaml
# Reference blueprint - Claude Code in OpenShell with a shared Nexus hub.
# Good for: enterprise teams using Claude with shared company context.
#
# Prerequisites:
#   export ANTHROPIC_API_KEY=sk-ant-example
#   export NEXUS_HUB_URL=https://nexus.company.com
#   export NEXUS_TOKEN=nexus-token-example
#   agentenv drivers list   # confirm the nexus context driver is installed
#
# Usage:
#   agentenv create enterprise --blueprint blueprints/claude+nexus+openshell.yaml
#   agentenv enter enterprise

version: 0.1.0
min_agentenv_version: 0.0.1-alpha0

sandbox:
  driver: openshell
  version: ">=0.0.1-alpha0,<0.1"

agent:
  driver: claude
  credentials:
    ANTHROPIC_API_KEY:
      source: env
      required: true

context:
  driver: nexus
  mode: hub
  hub_url: ${NEXUS_HUB_URL}
  credentials:
    NEXUS_TOKEN:
      source: env
      required: true

inference:
  driver: passthrough

policy:
  tier: balanced
  presets:
    - github_read
    - npm_read
  overrides:
    - allow: "${NEXUS_HUB_URL}"

state:
  persist_home: true
```

- [ ] **Step 6: Normalize existing reference blueprint headers**

Replace only the leading comment block in `blueprints/claude+filesystem+openshell.yaml` with:

```yaml
# Reference blueprint - Claude Code in OpenShell with a local filesystem context.
# Good for: getting started with Claude against a local project tree.
#
# Prerequisites:
#   export ANTHROPIC_API_KEY=sk-ant-example
#
# Usage:
#   agentenv create myapp --blueprint blueprints/claude+filesystem+openshell.yaml
#   agentenv enter myapp
```

Replace only the leading comment block in `blueprints/codex+mcp-generic+openshell.yaml` with:

```yaml
# Reference blueprint - OpenAI Codex in OpenShell with a generic MCP context server.
# Good for: connecting Codex to any MCP-compatible knowledge service.
#
# Prerequisites:
#   export OPENAI_API_KEY=sk-openai-example
#   export MCP_URL=https://mcp.internal.company.com
#   export MCP_TOKEN=mcp-token-example
#
# Usage:
#   agentenv create legal --blueprint blueprints/codex+mcp-generic+openshell.yaml
#   agentenv enter legal
```

Replace only the leading comment block in `blueprints/hermes+nexus+openshell.yaml` with:

```yaml
# Reference blueprint - Hermes subprocess agent in OpenShell with a shared Nexus hub.
# Good for: demonstrating external Hermes and Nexus subprocess drivers together.
#
# Prerequisites:
#   export OPENAI_API_KEY=sk-openai-example
#   export NEXUS_HUB_URL=https://nexus.company.com
#   export NEXUS_TOKEN=nexus-token-example
#   agentenv drivers list   # confirm hermes and nexus drivers are installed
#
# Usage:
#   agentenv create research --blueprint blueprints/hermes+nexus+openshell.yaml
#   agentenv enter research
#   agentenv destroy research --yes
```

Replace only the leading comment block in `blueprints/openclaw+nexus+openshell.yaml` with:

```yaml
# Reference blueprint - OpenClaw in OpenShell with a shared Nexus hub.
# Good for: enterprise teams using OpenClaw with shared company context.
#
# Prerequisites:
#   export OPENAI_API_KEY=sk-openai-example
#   export NEXUS_HUB_URL=https://nexus.company.com
#   export NEXUS_TOKEN=nexus-token-example
#   agentenv drivers list   # confirm the nexus context driver is installed
#
# Usage:
#   agentenv create assistant --blueprint blueprints/openclaw+nexus+openshell.yaml
#   agentenv enter assistant
```

- [ ] **Step 7: Run the all-blueprints test to verify GREEN**

Run:

```sh
cargo test -p agentenv-core --test reference_blueprints all_reference_blueprints_parse
```

Expected: PASS.

- [ ] **Step 8: Commit the new blueprints**

```bash
git add blueprints crates/agentenv-core/tests/reference_blueprints.rs
git commit -m "feat: add reference blueprint set"
```

---

### Task 3: Fast Coverage For Blueprint Docs And Sample Projects

**Files:**
- Modify: `crates/agentenv-core/tests/reference_blueprints.rs`

- [ ] **Step 1: Write failing docs and examples tests**

Add these tests above `interpolation_resolves_env_variable`:

```rust
#[test]
fn docs_catalog_mentions_every_reference_blueprint() {
    let docs = std::fs::read_to_string(workspace_path("docs/BLUEPRINTS.md")).unwrap();

    for case in reference_blueprints() {
        let file_name = case.path.strip_prefix("blueprints/").unwrap();
        assert!(
            docs.contains(file_name),
            "docs/BLUEPRINTS.md must mention {file_name}"
        );
    }
}

#[test]
fn sample_project_blueprints_parse() {
    let _guard = env_lock().lock().unwrap();

    std::env::set_var("NEXUS_HUB_URL", "https://93.184.216.35");

    for path in [
        "examples/quickstart/agentenv.yaml",
        "examples/enterprise-hub/agentenv.yaml",
        "examples/headless-ci/agentenv.yaml",
    ] {
        let doc = std::fs::read_to_string(workspace_path(path)).unwrap();
        let blueprint = Blueprint::from_yaml(&doc).unwrap();

        assert_eq!(blueprint.version, "0.1.0", "{path}");
        assert_eq!(blueprint.sandbox.driver, "openshell", "{path}");
        assert_eq!(
            blueprint
                .inference
                .as_ref()
                .map(|section| section.driver.as_str()),
            Some("passthrough"),
            "{path}"
        );
    }
}
```

- [ ] **Step 2: Run the focused tests to verify RED**

Run:

```sh
cargo test -p agentenv-core --test reference_blueprints
```

Expected: FAIL because `docs/BLUEPRINTS.md` and `examples/` do not exist. The earlier blueprint tests should still pass.

- [ ] **Step 3: Commit the failing docs/examples tests**

```bash
git add crates/agentenv-core/tests/reference_blueprints.rs
git commit -m "test: require blueprint docs and examples"
```

---

### Task 4: Add Blueprint Catalog And Sample Projects

**Files:**
- Create: `docs/BLUEPRINTS.md`
- Create: `examples/quickstart/agentenv.yaml`
- Create: `examples/quickstart/README.md`
- Create: `examples/enterprise-hub/agentenv.yaml`
- Create: `examples/enterprise-hub/Dockerfile`
- Create: `examples/enterprise-hub/certs/company-ca.pem`
- Create: `examples/enterprise-hub/README.md`
- Create: `examples/headless-ci/agentenv.yaml`
- Create: `examples/headless-ci/README.md`

- [ ] **Step 1: Add the catalog document**

Create `docs/BLUEPRINTS.md`:

```markdown
# Reference Blueprints

Reference blueprints are checked-in `agentenv.yaml` compositions that double as starter templates. Each file is runnable as-is after its listed credentials, URLs, and external drivers are available.

| Blueprint | Audience | Context | Policy | Pick it when |
|---|---|---|---|---|
| `claude+filesystem+openshell.yaml` | Getting started | Local filesystem | `balanced` | You want Claude Code over local projects. |
| `codex+filesystem+openshell.yaml` | Getting started | Local filesystem | `balanced` | You want Codex over local projects. |
| `openclaw+filesystem+openshell.yaml` | Getting started | Local filesystem | `balanced` | You want an OpenClaw assistant with persistent home state. |
| `claude+mcp-generic+openshell.yaml` | Integrators | Generic MCP endpoint | `restricted` | You have an MCP service and want Claude as the agent. |
| `hermes+filesystem+openshell.yaml` | Polyglot demos | Local filesystem | `balanced` | You want to exercise an external Hermes agent driver. |
| `claude+nexus+openshell.yaml` | Enterprise reference | Nexus hub | `balanced` | You use Claude with shared company context. |
| `codex+mcp-generic+openshell.yaml` | Integrators | Generic MCP endpoint | `restricted` | You have an MCP service and want Codex as the agent. |
| `hermes+nexus+openshell.yaml` | Polyglot enterprise demos | Nexus hub | `balanced` | You want Hermes through subprocess drivers with Nexus context. |
| `openclaw+nexus+openshell.yaml` | Enterprise reference | Nexus hub | `balanced` | You want OpenClaw with shared company context. |

## Getting-Started Filesystem Blueprints

`claude+filesystem+openshell.yaml`, `codex+filesystem+openshell.yaml`, and `openclaw+filesystem+openshell.yaml` mount `~/projects` through the filesystem context driver and expose it over MCP inside OpenShell. They are the lowest-friction templates because they do not require remote context infrastructure.

Required credentials:

- Claude: `ANTHROPIC_API_KEY`
- Codex and OpenClaw: `OPENAI_API_KEY`

Usage:

```sh
agentenv create myapp --blueprint blueprints/claude+filesystem+openshell.yaml
agentenv enter myapp
```

Trade-off: `balanced` policy includes common package and GitHub read presets, so these are better for local development than for tightly regulated data.

## Generic MCP Blueprints

`claude+mcp-generic+openshell.yaml` and `codex+mcp-generic+openshell.yaml` connect agents to any MCP-compatible HTTP+SSE endpoint.

Required environment:

- `MCP_URL`
- `MCP_TOKEN`
- agent API key for the selected agent

Usage:

```sh
export MCP_URL=https://mcp.internal.company.com
export MCP_TOKEN=mcp-token-example
agentenv create docs --blueprint blueprints/codex+mcp-generic+openshell.yaml
```

Trade-off: the `restricted` policy keeps egress narrow and allows only the configured MCP endpoint by default.

## Hermes Blueprints

`hermes+filesystem+openshell.yaml` and `hermes+nexus+openshell.yaml` use the external Hermes subprocess agent driver. Confirm it is installed before creating the env:

```sh
agentenv drivers list
```

Required environment:

- `OPENAI_API_KEY`
- `NEXUS_HUB_URL` and `NEXUS_TOKEN` for the Nexus variant

Trade-off: these blueprints demonstrate third-party driver composition, so they depend on driver installation in addition to normal credentials.

## Nexus Blueprints

`claude+nexus+openshell.yaml`, `hermes+nexus+openshell.yaml`, and `openclaw+nexus+openshell.yaml` connect to a shared Nexus hub.

Required environment:

- `NEXUS_HUB_URL`
- `NEXUS_TOKEN`
- agent API key for the selected agent

Usage:

```sh
export NEXUS_HUB_URL=https://nexus.company.com
export NEXUS_TOKEN=nexus-token-example
agentenv create enterprise --blueprint blueprints/claude+nexus+openshell.yaml
```

Trade-off: Nexus blueprints are the best fit for shared enterprise context, but they require a reachable hub and installed Nexus context driver.

## Sample Projects

- `examples/quickstart/` shows the smallest local project flow.
- `examples/enterprise-hub/` shows a Nexus hub template with company CA and internal base-image conventions.
- `examples/headless-ci/` shows a non-interactive CI template for automated code maintenance.
```

- [ ] **Step 2: Add the quickstart sample project**

Create `examples/quickstart/agentenv.yaml`:

```yaml
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0

sandbox:
  driver: openshell
  version: ">=0.0.1-alpha0,<0.1"

agent:
  driver: claude
  credentials:
    ANTHROPIC_API_KEY:
      source: env
      required: true

context:
  driver: filesystem
  mount: .

inference:
  driver: passthrough

policy:
  tier: balanced
  presets:
    - github_read
    - npm_read

state:
  persist_home: true
```

Create `examples/quickstart/README.md`:

```markdown
# Quickstart Example

This project is the smallest local agentenv template. It mounts the current directory as the filesystem context and starts Claude Code in OpenShell.

## Prerequisites

```sh
export ANTHROPIC_API_KEY=sk-ant-example
```

## Lifecycle

```sh
agentenv create quickstart
agentenv enter quickstart
agentenv exec quickstart -- echo ok
agentenv freeze quickstart --output agentenv.lock
agentenv destroy quickstart --yes
```

Run the commands from this directory so `agentenv create` discovers `agentenv.yaml`.
```

- [ ] **Step 3: Add the enterprise hub sample project**

Create `examples/enterprise-hub/agentenv.yaml`:

```yaml
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0

sandbox:
  driver: openshell
  version: ">=0.0.1-alpha0,<0.1"
  image: registry.internal.example.com/agentenv/company-base:latest

agent:
  driver: claude
  credentials:
    ANTHROPIC_API_KEY:
      source: env
      required: true

context:
  driver: nexus
  mode: hub
  hub_url: ${NEXUS_HUB_URL}
  credentials:
    NEXUS_TOKEN:
      source: env
      required: true

inference:
  driver: passthrough

policy:
  tier: balanced
  presets:
    - github_read
    - npm_read
  overrides:
    - allow: "${NEXUS_HUB_URL}"

state:
  persist_home: true
```

Create `examples/enterprise-hub/Dockerfile`:

```dockerfile
FROM ubuntu:24.04

COPY certs/company-ca.pem /usr/local/share/ca-certificates/company-ca.crt
RUN update-ca-certificates
```

Create `examples/enterprise-hub/certs/company-ca.pem`:

```text
-----BEGIN CERTIFICATE-----
MIIBlTCCATugAwIBAgIUWmFnZW50ZW52ZXhhbXBsZWNhMDAwMDAwCgYIKoZIzj0E
AwIwGDEWMBQGA1UEAwwNYWdlbnRlbnYtZGVtbzAeFw0yNjAxMDEwMDAwMDBaFw0y
NzAxMDEwMDAwMDBaMBgxFjAUBgNVBAMMDWFnZW50ZW52LWRlbW8wWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAASw7hRkMzX9nF2f7nK1KoCx5qBR0Y0x7pMVn8A8Y2xC
6jV+W0b+ZQz8vDq1dR6m1xJxq7Hf4d7Qf0GmVYqQ8o1MwUTAdBgNVHQ4EFgQUeXhh
bXBsZS1jYS1ub3QtZm9yLXByb2QwHwYDVR0jBBgwFoAUeXhhbXBsZS1jYS1ub3Qt
Zm9yLXByb2QwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiA7h2V4
examplecertificatebodyforagentenvdemoonlyAAAAAIhAIhAL2h2V4examplecert
ificatebodyforagentenvdemoonlyBBBBB
-----END CERTIFICATE-----
```

Create `examples/enterprise-hub/README.md`:

```markdown
# Enterprise Hub Example

This template assumes a shared Nexus hub, a company CA, and an internal OpenShell base image.

## Prerequisites

```sh
export ANTHROPIC_API_KEY=sk-ant-example
export NEXUS_HUB_URL=https://nexus.company.com
export NEXUS_TOKEN=nexus-token-example
agentenv drivers list
```

Build and publish the internal base image referenced by `agentenv.yaml`:

```sh
docker build -t registry.internal.example.com/agentenv/company-base:latest .
docker push registry.internal.example.com/agentenv/company-base:latest
```

## Lifecycle

```sh
agentenv create enterprise-hub
agentenv enter enterprise-hub
agentenv freeze enterprise-hub --output agentenv.lock
agentenv destroy enterprise-hub --yes
```

Run the lifecycle commands from this directory so `agentenv create` discovers `agentenv.yaml`.
```

- [ ] **Step 4: Add the headless CI sample project**

Create `examples/headless-ci/agentenv.yaml`:

```yaml
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0

sandbox:
  driver: openshell
  version: ">=0.0.1-alpha0,<0.1"

agent:
  driver: codex
  credentials:
    OPENAI_API_KEY:
      source: env
      required: true

context:
  driver: filesystem
  mount: .

inference:
  driver: passthrough

policy:
  tier: balanced
  presets:
    - github_read
    - npm_read

state:
  persist_home: false
```

Create `examples/headless-ci/README.md`:

```markdown
# Headless CI Example

This template runs Codex in non-interactive mode for repository maintenance jobs such as lint fixes.

## Prerequisites

```sh
export OPENAI_API_KEY=sk-openai-example
```

## CI Flow

```sh
agentenv create ci-fix --non-interactive
agentenv exec ci-fix -- sh -lc 'echo ok'
agentenv freeze ci-fix --output agentenv.lock
agentenv destroy ci-fix --yes --non-interactive
```

Use your CI system to run project-specific commands inside `agentenv exec`, then inspect the working tree before committing changes.
```

- [ ] **Step 5: Run docs/examples tests to verify GREEN**

Run:

```sh
cargo test -p agentenv-core --test reference_blueprints
```

Expected: PASS.

- [ ] **Step 6: Commit docs and examples**

```bash
git add docs/BLUEPRINTS.md examples crates/agentenv-core/tests/reference_blueprints.rs
git commit -m "docs: catalog blueprints and examples"
```

---

### Task 5: Dedicated Blueprint Integration Crate

**Files:**
- Modify: `Cargo.toml`
- Create: `tests/blueprint-integration/Cargo.toml`
- Create: `tests/blueprint-integration/tests/reference_blueprints.rs`

- [ ] **Step 1: Add the workspace member and test package**

Add `"tests/blueprint-integration",` to the root `Cargo.toml` `members` list after `"tests/driver-conformance",`.

Create `tests/blueprint-integration/Cargo.toml`:

```toml
[package]
name = "blueprint-integration"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
homepage.workspace = true
authors.workspace = true

[features]
integration = []

[dev-dependencies]
serde_json.workspace = true
uuid.workspace = true
```

- [ ] **Step 2: Write the integration harness**

Create `tests/blueprint-integration/tests/reference_blueprints.rs`:

```rust
#![cfg(feature = "integration")]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use uuid::Uuid;

struct BlueprintCase {
    path: &'static str,
    required_env: &'static [&'static str],
    required_drivers: &'static [DriverRequirement],
}

#[derive(Clone, Copy)]
struct DriverRequirement {
    kind: &'static str,
    name: &'static str,
}

const HERMES: DriverRequirement = DriverRequirement {
    kind: "agent",
    name: "hermes",
};

const NEXUS: DriverRequirement = DriverRequirement {
    kind: "context",
    name: "nexus",
};

fn cases() -> Vec<BlueprintCase> {
    vec![
        BlueprintCase {
            path: "blueprints/claude+filesystem+openshell.yaml",
            required_env: &["ANTHROPIC_API_KEY"],
            required_drivers: &[],
        },
        BlueprintCase {
            path: "blueprints/codex+filesystem+openshell.yaml",
            required_env: &["OPENAI_API_KEY"],
            required_drivers: &[],
        },
        BlueprintCase {
            path: "blueprints/openclaw+filesystem+openshell.yaml",
            required_env: &["OPENAI_API_KEY"],
            required_drivers: &[],
        },
        BlueprintCase {
            path: "blueprints/claude+mcp-generic+openshell.yaml",
            required_env: &["ANTHROPIC_API_KEY", "MCP_URL", "MCP_TOKEN"],
            required_drivers: &[],
        },
        BlueprintCase {
            path: "blueprints/hermes+filesystem+openshell.yaml",
            required_env: &["OPENAI_API_KEY"],
            required_drivers: &[HERMES],
        },
        BlueprintCase {
            path: "blueprints/claude+nexus+openshell.yaml",
            required_env: &["ANTHROPIC_API_KEY", "NEXUS_HUB_URL", "NEXUS_TOKEN"],
            required_drivers: &[NEXUS],
        },
        BlueprintCase {
            path: "blueprints/codex+mcp-generic+openshell.yaml",
            required_env: &["OPENAI_API_KEY", "MCP_URL", "MCP_TOKEN"],
            required_drivers: &[],
        },
        BlueprintCase {
            path: "blueprints/hermes+nexus+openshell.yaml",
            required_env: &["OPENAI_API_KEY", "NEXUS_HUB_URL", "NEXUS_TOKEN"],
            required_drivers: &[HERMES, NEXUS],
        },
        BlueprintCase {
            path: "blueprints/openclaw+nexus+openshell.yaml",
            required_env: &["OPENAI_API_KEY", "NEXUS_HUB_URL", "NEXUS_TOKEN"],
            required_drivers: &[NEXUS],
        },
    ]
}

#[test]
#[ignore = "requires OpenShell and blueprint-specific credentials or subprocess drivers"]
fn reference_blueprints_create_exec_destroy() {
    if let Some(reason) = missing_openshell() {
        eprintln!("skipping blueprint integration: {reason}");
        return;
    }

    for case in cases() {
        if let Some(reason) = missing_case_prerequisite(&case) {
            eprintln!("skipping {}: {reason}", case.path);
            continue;
        }

        run_case(&case);
    }
}

fn run_case(case: &BlueprintCase) {
    let root = workspace_root();
    let home = env::temp_dir().join(format!(
        "agentenv-blueprint-it-{}",
        Uuid::new_v4()
    ));
    let projects = home.join("projects");
    fs::create_dir_all(&projects).unwrap();
    fs::write(projects.join("README.md"), "blueprint integration\n").unwrap();

    let name = case
        .path
        .strip_prefix("blueprints/")
        .unwrap()
        .strip_suffix(".yaml")
        .unwrap()
        .replace('+', "-");
    let blueprint = root.join(case.path);
    let mut created = false;
    let result = (|| -> Result<(), String> {
        let create = agentenv_command()
            .arg("create")
            .arg(&name)
            .arg("--blueprint")
            .arg(&blueprint)
            .arg("--non-interactive")
            .env("HOME", &home)
            .env("AGENTENV_DISABLE_KEYRING", "1")
            .output()
            .unwrap();
        require_success(&format!("create {}", case.path), &create)?;
        created = true;

        let exec = agentenv_command()
            .arg("exec")
            .arg(&name)
            .arg("--")
            .arg("echo")
            .arg("ok")
            .env("HOME", &home)
            .env("AGENTENV_DISABLE_KEYRING", "1")
            .output()
            .unwrap();
        require_success(&format!("exec {}", case.path), &exec)?;
        let stdout = String::from_utf8_lossy(&exec.stdout);
        if !stdout.contains("ok") {
            return Err(format!("exec output for {} did not contain ok:\n{}", case.path, output_summary(&exec)));
        }

        Ok(())
    })();

    if created {
        let destroy = agentenv_command()
            .arg("destroy")
            .arg(&name)
            .arg("--yes")
            .arg("--non-interactive")
            .env("HOME", &home)
            .env("AGENTENV_DISABLE_KEYRING", "1")
            .output()
            .unwrap();
        if !destroy.status.success() {
            panic!(
                "destroy failed after {}:\n{}",
                case.path,
                output_summary(&destroy)
            );
        }
    }

    if let Err(message) = result {
        panic!("{message}");
    }
}

fn missing_case_prerequisite(case: &BlueprintCase) -> Option<String> {
    for name in case.required_env {
        match env::var(name) {
            Ok(value) if !value.trim().is_empty() => {}
            _ => return Some(format!("missing environment variable {name}")),
        }
    }

    for requirement in case.required_drivers {
        if !driver_list_contains(requirement.kind, requirement.name) {
            return Some(format!(
                "missing {} driver {}",
                requirement.kind, requirement.name
            ));
        }
    }

    None
}

fn missing_openshell() -> Option<String> {
    match Command::new("openshell").arg("--version").output() {
        Ok(output) if output.status.success() => None,
        Ok(output) => Some(format!(
            "openshell --version exited unsuccessfully:\n{}",
            output_summary(&output)
        )),
        Err(error) => Some(format!("openshell binary unavailable: {error}")),
    }
}

fn driver_list_contains(kind: &str, name: &str) -> bool {
    let output = agentenv_command()
        .arg("drivers")
        .arg("list")
        .arg("--json")
        .output()
        .unwrap();
    if !output.status.success() {
        return false;
    }
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return false;
    };
    json["drivers"].as_array().is_some_and(|drivers| {
        drivers
            .iter()
            .any(|driver| driver["kind"] == kind && driver["name"] == name)
    })
}

fn agentenv_command() -> Command {
    if let Some(path) = env::var_os("AGENTENV_BIN") {
        Command::new(path)
    } else {
        let mut command = Command::new(env!("CARGO"));
        command
            .arg("run")
            .arg("--quiet")
            .arg("-p")
            .arg("agentenv")
            .arg("--");
        command
    }
}

fn require_success(label: &str, output: &Output) -> Result<(), String> {
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{label} failed:\n{}", output_summary(output)))
    }
}

fn output_summary(output: &Output) -> String {
    format!(
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output
            .status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".to_owned()),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}
```

- [ ] **Step 3: Run the integration package without the feature**

Run:

```sh
cargo test -p blueprint-integration
```

Expected: PASS with no live OpenShell operations.

- [ ] **Step 4: Run the ignored integration harness and verify skip behavior**

Run:

```sh
cargo test -p blueprint-integration --features integration -- --ignored --nocapture
```

Expected on a machine without OpenShell or credentials: PASS with `skipping` messages naming missing prerequisites. Expected on a fully provisioned machine: each eligible blueprint creates an env, runs `echo ok`, and destroys the env.

- [ ] **Step 5: Commit the integration crate**

```bash
git add Cargo.toml tests/blueprint-integration
git commit -m "test: add blueprint integration harness"
```

---

### Task 6: Final Verification And Cleanup

**Files:**
- Review: all changed files from Tasks 1-5

- [ ] **Step 1: Run formatting**

Run:

```sh
cargo fmt
```

Expected: exit 0.

- [ ] **Step 2: Run clippy**

Run:

```sh
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: exit 0 with no warnings.

- [ ] **Step 3: Run the full workspace test suite**

Run:

```sh
cargo test --workspace
```

Expected: exit 0. Ignored live tests remain ignored in the default run.

- [ ] **Step 4: Run the live harness command for skip evidence**

Run:

```sh
cargo test -p blueprint-integration --features integration -- --ignored --nocapture
```

Expected: exit 0. On this machine, unavailable live prerequisites may produce visible `skipping` messages instead of creating envs.

- [ ] **Step 5: Inspect the final diff**

Run:

```sh
git status --short
git diff --stat HEAD
```

Expected: only issue #20 files are changed.

- [ ] **Step 6: Commit final verification fixes if formatting changed files**

If `cargo fmt` changed files after Task 5, commit those formatting-only changes:

```bash
git add Cargo.toml crates/agentenv-core/tests/reference_blueprints.rs tests/blueprint-integration
git commit -m "chore: format blueprint integration changes"
```

If `cargo fmt` did not change files, do not create an empty commit.
