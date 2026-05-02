# M5-4 Design: Reference Blueprints And Sample Projects

- Date: 2026-05-02
- Issue: https://github.com/windoliver/agentenv/issues/20
- Milestone: M5 packaging, DX, and security
- Affected crates: `agentenv-core`, `agentenv`, new `tests/blueprint-integration`
- Affected docs and templates: `blueprints/`, `docs/BLUEPRINTS.md`, `examples/`, `Cargo.toml`

## 1. Context And Goals

Issue #20 turns the reference blueprints into both documentation and starter templates. The repository already has four blueprints, fast parser coverage in `agentenv-core/tests/reference_blueprints.rs`, built-in drivers for Claude, Codex, OpenClaw, filesystem, MCP generic, and passthrough inference, and subprocess discovery support for Hermes and Nexus.

This work should expand the blueprint set to nine files, add sample projects, document the trade-offs, and add an optional integration harness that can run real create, exec, and destroy flows when the required drivers and credentials are present.

The implementation must preserve agentenv's narrow-waist architecture: blueprints describe sandbox, agent, context, inference, policy, and state; they should not bypass MCP or driver capability handshakes.

## 2. Recommended Architecture

Use three validation layers:

1. `agentenv-core/tests/reference_blueprints.rs` remains the fast default suite for all reference blueprints. It parses, validates, resolves, and checks expected driver composition for all nine files.
2. `docs/BLUEPRINTS.md` and top-of-file comments provide human-facing guidance. They explain what each blueprint is for, which environment variables or subprocess drivers it needs, and what policy posture it uses.
3. A new workspace crate at `tests/blueprint-integration/` owns optional end-to-end tests behind an `integration` feature. These tests run `create -> exec "echo ok" -> destroy` for each blueprint only when the relevant prerequisites are available.

This keeps normal test runs fast and deterministic while giving release or driver-equipped environments a single place to exercise live blueprints.

## 3. Blueprint Set

Ship these files under `blueprints/`:

| File | Composition | Audience |
|---|---|---|
| `claude+filesystem+openshell.yaml` | Claude + filesystem + OpenShell | Getting started |
| `codex+filesystem+openshell.yaml` | Codex + filesystem + OpenShell | Getting started |
| `openclaw+filesystem+openshell.yaml` | OpenClaw + filesystem + OpenShell | Getting started |
| `claude+mcp-generic+openshell.yaml` | Claude + generic MCP + OpenShell | Integrators |
| `hermes+filesystem+openshell.yaml` | Hermes subprocess agent + filesystem + OpenShell | Polyglot demo |
| `claude+nexus+openshell.yaml` | Claude + Nexus hub + OpenShell | Enterprise reference |
| `codex+mcp-generic+openshell.yaml` | Codex + generic MCP + OpenShell | Integrators |
| `hermes+nexus+openshell.yaml` | Hermes subprocess agent + Nexus hub + OpenShell | Polyglot enterprise demo |
| `openclaw+nexus+openshell.yaml` | OpenClaw + Nexus hub + OpenShell | Enterprise reference |

Each blueprint should use the current `version: 0.1.0`, `min_agentenv_version: 0.0.1-alpha0`, OpenShell sandbox, and passthrough inference unless the existing format changes before implementation. URL placeholders should remain environment-variable based so checked-in files never hard-code internal endpoints.

Top comments should be consistent:

1. one-line purpose.
2. prerequisite environment variables or installed subprocess drivers.
3. a minimal usage block with `agentenv create`.
4. a note when the blueprint depends on remote MCP or Nexus.

## 4. Documentation And Examples

Add `docs/BLUEPRINTS.md` with a catalog table and short sections for each blueprint. Each section should cover:

1. audience and intended use.
2. required credentials and environment variables.
3. driver prerequisites.
4. policy tier and presets.
5. trade-offs and when to pick a different blueprint.

Add three sample projects:

1. `examples/quickstart/`
   - `agentenv.yaml` based on `claude+filesystem+openshell.yaml`.
   - `README.md` walks through `create -> enter -> work -> freeze -> destroy`.
2. `examples/enterprise-hub/`
   - `agentenv.yaml` based on a Nexus blueprint.
   - include company CA and internal Dockerfile assumptions as placeholders, not secrets.
   - `README.md` explains required `NEXUS_HUB_URL`, `NEXUS_TOKEN`, and local CA/Dockerfile paths.
3. `examples/headless-ci/`
   - `agentenv.yaml` optimized for non-interactive CI.
   - `README.md` shows a lint-fix style flow using non-interactive create, exec, freeze, and destroy commands.

Examples should be runnable templates, not prose-only docs. Placeholder values are acceptable when they are explicitly environment-driven and documented.

## 5. Integration Harness

Add a new workspace member:

```text
tests/blueprint-integration/
```

The crate should expose an `integration` feature and tests that are ignored or skipped unless explicitly enabled. Its responsibility is live end-to-end validation, not YAML parsing. The harness should:

1. enumerate the nine blueprint paths from one table.
2. check prerequisites per blueprint before attempting create:
   - OpenShell availability.
   - required agent credentials such as `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`.
   - `MCP_URL` and `MCP_TOKEN` for generic MCP.
   - `NEXUS_HUB_URL`, `NEXUS_TOKEN`, and installed Nexus subprocess driver for Nexus.
   - installed Hermes subprocess driver for Hermes.
3. skip unavailable cases with a clear message naming the missing prerequisite.
4. create a unique env name per test.
5. run `agentenv create <name> --blueprint <path> --non-interactive`.
6. run `agentenv exec <name> "echo ok"` and assert stdout contains `ok`.
7. always attempt `agentenv destroy <name> --yes --non-interactive` after successful create, even if exec fails.

The harness can shell out to the built `agentenv` binary using Rust test helpers. It should avoid requiring live remote MCP or Nexus in default CI.

## 6. Fast Test Coverage

Update `agentenv-core/tests/reference_blueprints.rs` to cover all nine files. The test should keep deterministic placeholder values for URL environment variables so SSRF validation accepts them and interpolation can resolve.

Assertions should verify:

1. blueprint version and minimum agentenv version.
2. selected sandbox, agent, context, and inference drivers.
3. expected policy tier.
4. expected state persistence where relevant.
5. context-specific fields, including filesystem mount, generic MCP endpoint, and Nexus hub URL.

This test should not depend on installed subprocess drivers or live credentials.

## 7. Error Handling And Cleanup

Reference files should prefer explicit environment placeholders over literal internal URLs or secrets. Credential values must remain references only; no checked-in sample should contain a real token.

Integration cleanup should be best effort. Once create succeeds, destroy should run in a cleanup path regardless of the exec result. Cleanup failures should be reported in the test output because they may leave a local sandbox behind.

Skips should be intentional and visible. A missing prerequisite is a skip; a failed create, exec, or destroy after prerequisites are present is a test failure.

## 8. Scope And Non-Goals

In scope:

1. Add the missing five reference blueprints and polish the existing four.
2. Add `docs/BLUEPRINTS.md`.
3. Add three sample project directories.
4. Extend fast parse, validate, and resolve coverage.
5. Add the optional end-to-end integration crate.

Out of scope:

1. Changing the blueprint schema version.
2. Changing the driver protocol.
3. Implementing or modifying Hermes or Nexus subprocess drivers.
4. Adding a new context transport.
5. Making live remote MCP or Nexus mandatory in default CI.

## 9. Implementation Notes

The implementation should start test-first:

1. extend the reference blueprint test table to include all nine expected files and watch it fail for missing files.
2. add missing blueprint files and adjust existing files until the fast suite passes.
3. add docs and examples with lightweight file-presence or parse coverage where useful.
4. add the integration crate and verify skipped behavior locally without live prerequisites.

Full verification before completion should include:

```sh
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The live harness should be documented as:

```sh
cargo test -p blueprint-integration --features integration -- --ignored
```

The exact package name may be adjusted to fit Cargo naming conventions, but the path should remain `tests/blueprint-integration/`.
