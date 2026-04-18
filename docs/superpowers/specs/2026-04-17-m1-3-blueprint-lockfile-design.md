# M1-3 Design: Blueprint Format, Lockfile, and Digest Verification

- Date: 2026-04-17
- Issue: https://github.com/windoliver/agentenv/issues/4
- Milestone: M1 Foundations
- Affected crates: `agentenv-core`, `agentenv`

## 1. Context and Goals

Issue #4 establishes the first non-scaffold implementation for declarative environment materialization. The required capabilities are:

1. Parse and validate `agentenv.yaml` blueprints matching the four reference files in `blueprints/`.
2. Produce deterministic lockfiles (`agentenv.lock`) through `agentenv freeze`.
3. Recreate equivalent environment state from a lockfile through `agentenv reproduce`.
4. Verify blueprint and lock integrity, including digest and version checks.
5. Preserve security posture by stripping credential values from lockfiles and rejecting lockfiles that contain secret values.

The implementation must preserve the architecture’s narrow waist and env-manager vocabulary while avoiding protocol churn in M1.

## 2. Scope and Non-Goals

### In scope

1. Typed blueprint and lockfile models in `agentenv-core`.
2. Interpolation support for `${VAR}` and `${credstore:NAME}`.
3. Semantic validation for known drivers, semver ranges, and digest requirements.
4. Lifecycle primitives (`resolve`, `verify`, `plan`, `apply`, `status`) implemented as core APIs with deterministic behavior.
5. CLI commands: `verify-blueprint`, `freeze`, and `reproduce`.
6. Acceptance-focused tests aligned with issue #4.

### Out of scope

1. Credential persistence backend implementation (M1-4).
2. Full policy engine implementation (M1-5).
3. Real driver-side apply/teardown behavior (M2+).
4. Any `agentenv-proto` method signature or schema version changes.

## 3. Module Design

## 3.1 `agentenv-core::blueprint`

Create a blueprint module with these responsibilities:

1. Data model: strongly typed top-level struct with sections:
   - `version`
   - `min_agentenv_version`
   - `sandbox`
   - `agent`
   - `context`
   - `inference`
   - `policy`
   - `state`
2. Section model:
   - Required `driver: String`
   - Optional `version: String` (semver requirement expression)
   - Optional `credentials: BTreeMap<String, CredentialRef>`
   - `#[serde(flatten)] extra: BTreeMap<String, serde_yaml::Value>` for driver-specific fields.
3. Interpolation:
   - `${VAR}` resolved from process env.
   - `${credstore:NAME}` resolved via a resolver trait (`CredentialResolver`) so M1-4 can plug in later.
   - Interpolation occurs prior to semantic validation.
4. Schema:
   - Generate JSON Schema via `schemars` for the typed model.
   - Provide a validation entrypoint that can surface structured diagnostics with key-path information.

## 3.2 `agentenv-core::lockfile`

Define deterministic lockfile structures:

1. `Lockfile` fields:
   - `version`
   - `protocol_version`
   - `blueprint_hash` (sha256 hex)
   - `drivers` (section -> name/version pin records)
   - `artifacts` (named artifact -> `sha256:...` digest)
   - `credentials` references only (never values)
2. Determinism:
   - Use `BTreeMap` for all map-like serialized fields.
   - Use stable emission order and no implicit timestamps.
3. Security rule:
   - Validation rejects any lockfile credential entry that appears to contain inline values.

## 3.3 `agentenv-core::lifecycle`

Implement lifecycle API with explicit stage types:

1. `resolve`:
   - Parse YAML into typed model.
   - Apply interpolation.
   - Validate semver requirement syntax and known driver names.
   - Pin driver versions deterministically from a registry abstraction.
2. `verify`:
   - Verify digest format (`sha256:<64 lowercase hex>`).
   - Verify required digest presence where applicable.
   - Compare lockfile blueprint hash against current blueprint when lockfile provided.
   - Perform offline verification only in M1-3; online fetch+hash remains apply-time behavior.
3. `plan`:
   - Build deterministic high-level operation steps from resolved model.
   - Stub `preflight`/future `plan` RPC integration points without protocol changes.
4. `apply`:
   - Execute deterministic no-op transactional scaffold (state transition only) suitable for round-trip testing.
5. `status`:
   - Return aggregated lifecycle status for describe/round-trip assertions.

## 3.4 `agentenv-core::registry`

Add a simple in-memory registry abstraction used by lifecycle resolve:

1. Driver index keyed by `(kind, name)` with available versions.
2. Deterministic pinning to highest satisfying version.
3. Explicit errors for unknown drivers and unsatisfied version ranges.

## 3.5 `agentenv-core::digest`

Add helper functions for:

1. `sha256` hashing for blueprint canonical bytes.
2. Digest string parsing/validation.
3. Stable hash generation for freeze/reproduce checks.

## 4. CLI Design (`crates/agentenv`)

Add subcommands while preserving env-manager vocabulary:

1. `agentenv verify-blueprint <file>`
   - Parse + validate + resolve + verify.
   - Exit non-zero with structured error summary on failures.
2. `agentenv freeze <env> [--blueprint <file>] [--out <path>]`
   - Resolve environment inputs.
   - Emit deterministic lockfile bytes.
   - Strip credential values and error if values remain.
3. `agentenv reproduce <lockfile>`
   - Load lockfile.
   - Validate lock integrity.
   - Reconstruct equivalent resolved state.

## 5. Error Model

Use `thiserror` in `agentenv-core` with clear categories:

1. Parse/serde errors.
2. Interpolation resolution errors (missing env var, missing credential reference).
3. Validation errors (unknown driver, bad semver, missing/invalid digest).
4. Lockfile security errors (credential values present).
5. Hash mismatch errors (blueprint vs lockfile).

Each user-facing error includes machine-readable key path where possible and human-readable remediation guidance.

## 6. Testing Strategy (TDD)

Implement tests first, then code, following red-green-refactor:

1. Blueprint parse/validate/resolve tests for all four reference blueprints.
2. `verify-blueprint` failure tests:
   - missing digest
   - invalid semver requirement
   - unknown driver name
3. Deterministic `freeze` snapshot test asserting byte-for-byte identical output from identical input.
4. Lockfile credential-value rejection test.
5. Round-trip lifecycle test:
   - create -> freeze -> destroy -> reproduce -> describe
   - final describe equals initial describe fixture.

## 7. Trade-Offs

1. Typed top-level plus flattened driver-specific fields balances safety and future extension.
2. Offline verification in `verify-blueprint` keeps M1 bounded while preserving architecture intent for online apply-time verification.
3. Deterministic lockfile output may require explicit ordering/canonicalization work now, but avoids long-term reproducibility drift.

## 8. Acceptance Mapping

1. Reference blueprints parse/validate/resolve: covered by Section 6.1.
2. Deterministic freeze output: covered by Section 6.3.
3. Reproduce identical environment: covered by Section 6.5.
4. Verify catches missing digest/invalid semver/unknown driver: covered by Section 6.2.
5. Lockfile with credential values rejected: covered by Section 6.4.
6. Round-trip identity test: covered by Section 6.5.

## 9. Implementation Order

1. Add core models and error types (`blueprint`, `lockfile`, `digest`, `registry`, `lifecycle`).
2. Add core tests for model and lifecycle behavior.
3. Add CLI command parsing and command handlers.
4. Add CLI integration tests for failure/success paths.
5. Run full formatting/linting/tests and refine error messaging.
