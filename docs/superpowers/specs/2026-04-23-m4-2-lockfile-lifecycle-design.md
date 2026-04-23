# M4-2 Design: Portable Lockfile Lifecycle

- Date: 2026-04-23
- Issue: https://github.com/windoliver/agentenv/issues/15
- Milestone: M4 CLI and lifecycle
- Depends on: M4-1 core CLI and lifecycle, merged in https://github.com/windoliver/agentenv/pull/69
- Affected crates: `agentenv-core`, `agentenv`, `agentenv-plugin`
- Related crates consumed but not redesigned: `agentenv-policy`, `agentenv-credstore`, `agentenv-proto`

## 1. Context And Goals

Issue #15 completes the portable environment story:

1. `freeze` captures the exact, non-secret composition of a created env.
2. `verify` checks a lockfile offline and reports malformed data, impossible versions, missing drivers, and digest mismatches.
3. `reproduce` recreates an env from that lockfile on another machine.

The repo already has important foundation:

1. `agentenv-core::lockfile` supports a deterministic `0.1.0` lockfile with driver pins, artifact digests, credential references, and a blueprint hash.
2. `agentenv-core::lifecycle` can resolve a blueprint and freeze deterministic bytes from it.
3. M4-1 introduced persistent env state under `~/.agentenv/envs/<name>/` with `blueprint.yaml`, `lock.yaml`, `state.json`, and `events.jsonl`.
4. M4-1 create already persists a lockfile for each env, but the old lockfile is not sufficient to reproduce without locating the original blueprint.
5. `agentenv-policy` can compose tier and preset policy into the concrete `NetworkPolicy` type.
6. `DriverCatalog` discovers built-in and subprocess drivers and has enough local metadata to verify installed subprocess binaries.

M4-2 should build on that foundation rather than adding a separate orchestrator or a second serialization format. The lockfile becomes the portable artifact. Blueprints remain the authoring artifact.

## 2. Scope And Non-Goals

### In scope

1. Change `agentenv freeze <name>` to freeze an existing env from `~/.agentenv/envs/<name>/`.
2. Add `agentenv freeze <name> [--output <file>]` with default output `agentenv.lock`; `--output -` prints to stdout.
3. Add `agentenv verify <lockfile>`.
4. Add `agentenv reproduce <lockfile> [--name <name>]`.
5. Expand emitted lockfiles so they are self-contained for reproduction.
6. Preserve compatibility parsing for existing `0.1.0` lockfiles where useful.
7. Record every selected driver as `(kind, name, version, source, sha256 digest)`.
8. Record every explicit image/artifact as `sha256:<64 lowercase hex>`.
9. Record the driver protocol version using `agentenv_proto::SCHEMA_VERSION`.
10. Record the resolved policy as both declaration and expanded `NetworkPolicy`.
11. Preserve credential references by name/source/reference only; never values.
12. Verify installed subprocess driver digests before use.
13. Fail loudly on unresolved versions, missing drivers, mismatched digests, malformed lockfiles, and credential-value fields.
14. Add round-trip coverage: create, freeze, destroy, reproduce, describe comparison.

### Out of scope

1. Designing or implementing the future signed remote registry at `registry.agentenv.dev`.
2. Automatically installing missing remote drivers over the network.
3. Changing driver JSON-RPC method signatures.
4. Adding a new serialization format.
5. Storing credential values or opaque credential material in lockfiles.
6. Solving host-specific path portability for arbitrary driver config. M4-2 should normalize known host paths during comparison and make path limitations explicit.

The issue mentions installing missing drivers at pinned versions. In this repository state, there is no signed remote registry protocol to do that safely. M4-2 should implement local built-in and installed-driver verification now, then return actionable install guidance for missing external drivers. Remote install remains the future registry hook.

## 3. Lockfile Model

Freeze should emit a new lockfile schema version, `0.2.0`. The existing `0.1.0` parser remains available for old files, but new `freeze` output uses the richer schema.

Required top-level fields:

```yaml
version: 0.2.0
driver_protocol_version: "1.0"
name: myapp
blueprint_hash: "<sha256 hex of canonical resolved blueprint>"
composition:
  version: 0.1.0
  min_agentenv_version: 0.0.1-alpha0
  sandbox: {}
  agent: {}
  context: {}
  inference: {}
policy:
  declared:
    tier: balanced
    presets:
      - github_read
      - npm_read
    overrides: []
  resolved:
    network: {}
    filesystem: {}
    process: {}
    inference: {}
drivers:
  sandbox:
    kind: sandbox
    name: openshell
    version: 0.0.1-alpha0
    source: built-in
    digest: sha256:...
artifacts:
  sandbox-image: sha256:...
credentials:
  ANTHROPIC_API_KEY:
    source: env
    reference: ANTHROPIC_API_KEY
    required: true
```

### `composition`

`composition` is the sanitized resolved blueprint content needed to recreate the env:

1. top-level blueprint version fields.
2. sandbox, agent, context, and optional inference components.
3. each component's driver name and pinned version.
4. component-specific config from the original blueprint.
5. credential declarations with references only.
6. state declarations such as `persist_home`.

It must not contain credential values. If a blueprint credential uses `source: env` with a `value`, that value is interpreted as an env var name and stored as `reference`; the literal env var value is never interpolated into the composition.

The existing canonical blueprint hash should remain stable for semantically identical resolved blueprints. If adding `composition` changes hash inputs, the implementation must define the canonical hash over the same normalized resolved blueprint used to build `composition`, not over incidental lockfile ordering.

### `policy`

`policy.declared` preserves the user-facing policy declaration: tier, presets, and overrides.

`policy.resolved` stores the fully expanded `agentenv_proto::NetworkPolicy` produced by `agentenv-policy`. This lets `verify` and `reproduce` detect policy drift and recreate the same sandbox policy even if built-in preset definitions change later.

During reproduce, the resolved policy is authoritative. The declared policy is retained for inspectability and for detecting drift against the current policy engine.

### `drivers`

Each selected driver role stores:

1. role key: `sandbox`, `agent`, `context`, or `inference`.
2. `kind`: same semantic value as the role.
3. `name`: selected driver name.
4. `version`: exact semver.
5. `source`: `built-in`, `installed`, or `override`.
6. `digest`: a `sha256:<hex>` digest.

For built-in drivers, the digest is the current `agentenv` executable digest. Built-ins are linked into the binary, so the executable is the verifiable artifact.

For subprocess drivers, the digest is computed over the installed driver root. The root digest must be deterministic:

1. recursively walk entries under the manifest root.
2. hash regular file bytes.
3. hash symlink entries as link metadata and target text; do not follow symlinks.
4. reject a manifest binary path that resolves outside the driver root, matching current manifest validation.
5. sort paths lexicographically by normalized relative path.
6. hash each regular file entry as `relative_path`, NUL, file mode class, NUL, file bytes.
7. hash each symlink entry as `relative_path`, NUL, `symlink`, NUL, link target bytes.
8. include `manifest.json` and launchers.
9. exclude transient build caches only if they are explicitly listed in an agentenv-owned ignore rule.

If a future installer writes package digest metadata, that metadata can be used only after verifying it against the local root digest. M4-2 should not trust unverified metadata alone.

### `artifacts`

`artifacts` records explicit images and other content-addressed artifacts. Current blueprint support already requires image digests when an image is referenced. M4-2 keeps that behavior and stores every artifact as `sha256:<64 lowercase hex>`.

### `credentials`

Credential entries allow only:

1. `source`: `env` or `credstore`.
2. `reference`: env var name or credstore key.
3. `required`: optional boolean.

Unknown fields under credential entries are hard errors. `value`, `secret`, `token`, `api_key`, and any other inline-value field must fail deserialization or validation.

## 4. Verification Semantics

`agentenv verify <lockfile>` is an offline check. It does not create resources.

Verification steps:

1. Parse YAML with `deny_unknown_fields` for every lockfile struct.
2. Validate lockfile schema version.
3. Validate `driver_protocol_version` major compatibility with `agentenv_proto::SCHEMA_VERSION`.
4. Validate `blueprint_hash` format.
5. Validate all artifact digest strings.
6. Validate all credential references and reject inline-value fields.
7. Validate `composition` can be converted back to an internal resolved blueprint.
8. Recompute the canonical blueprint hash from `composition` and compare with `blueprint_hash`.
9. Recompose policy from `policy.declared` using the current policy engine.
10. Compare recomposed policy with `policy.resolved`.
11. Discover local drivers through `DriverCatalog`.
12. Verify each lockfile driver has an installed or built-in candidate with exact `(kind, name, version)`.
13. Recompute the local candidate digest and compare with the lockfile digest.
14. Report all inconsistencies found in one result when practical.

The policy drift check should be a warning by default, not a hard failure, when `policy.resolved` is present and internally valid. The resolved policy is the pinned reproduction input; drift means the current policy presets changed since freeze. Reproduce can still proceed with the pinned policy.

Hard failures:

1. malformed YAML or unknown lockfile fields.
2. unsupported lockfile major version.
3. incompatible driver protocol major version.
4. missing required drivers.
5. invalid or mismatched digest.
6. missing local driver.
7. credential value fields.
8. blueprint hash mismatch.
9. missing `policy.resolved`.

Output should be human-readable by default and have a `--json` option if M4-1 render patterns make that straightforward. JSON output is useful but not required for the first M4-2 acceptance slice unless tests already cover the CLI render path.

## 5. Reproduce Semantics

`agentenv reproduce <lockfile> [--name <name>]` creates a new env using the lockfile as the source of truth.

Name selection:

1. explicit `--name`.
2. lockfile `name` for `0.2.0` lockfiles.
3. file stem for old `0.1.0` lockfiles, using existing suffix stripping behavior for `.lock.yaml`, `.lock.yml`, `.yaml`, `.yml`, and `.lock`.

Reproduce steps:

1. Run the same verification as `agentenv verify`.
2. Fail before resource creation on hard verification failures.
3. Convert `composition` back into blueprint YAML or directly into the resolved create input.
4. Use exact driver names and versions from `drivers`.
5. Use `policy.resolved` as the sandbox policy.
6. Resolve credential references:
   - `source: env` requires the referenced env var to be set.
   - `source: credstore` reads the named credstore entry.
   - missing required credentials fail before resource creation.
   - interactive re-prompting is allowed only through the existing M4-1 credential provider path.
7. Provision context and inference through selected drivers.
8. Create the sandbox and install/configure the agent through the M4-1 runtime path.
9. Persist `blueprint.yaml`, `lock.yaml`, `state.json`, and `events.jsonl` under the new env.

The implementation should reuse M4-1 create as much as possible. The clean shape is a new core entrypoint such as:

```rust
pub async fn reproduce_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    credentials: &mut dyn CredentialProvider,
    name: &str,
    lockfile_yaml: &str,
) -> RuntimeResult<CreateResult>
```

Internally, `create_env` and `reproduce_env` should converge after input resolution. The divergence is only source material:

1. `create_env`: blueprint declaration is authoritative, policy is composed from current presets.
2. `reproduce_env`: lockfile composition and resolved policy are authoritative.

## 6. Freeze Semantics

`agentenv freeze <name> [--output <file>]` reads an existing M4-1 env:

1. validate env name.
2. load `state.json`, `blueprint.yaml`, and `lock.yaml`.
3. verify state name matches the requested env.
4. resolve and canonicalize the stored blueprint.
5. compose resolved policy.
6. discover and digest selected drivers from state/lock.
7. build a `0.2.0` lockfile.
8. validate the lockfile before writing.
9. write to `agentenv.lock` by default, write to explicit file with `--output`, or print to stdout with `--output -`.

Freezing should be deterministic for unchanged env composition and unchanged driver artifacts. Timestamps, state health, events, and host-specific runtime handles must not enter the lockfile.

The current `freeze <env> --blueprint --out` CLI shape should be replaced by the issue shape. If compatibility is needed, `--out` may remain as a hidden alias for `--output` for one release, but new docs and tests should use `--output`.

## 7. Driver Registry And Digest Resolution

M4-2 needs a resolver that can answer:

1. Which drivers are available locally?
2. Does a local driver exactly match a lockfile pin?
3. What digest represents that local driver?
4. If missing, what should the user install?

Add a small core module or extend `driver_catalog` with:

```rust
pub struct DriverArtifact {
    pub kind: DriverKind,
    pub name: String,
    pub version: Version,
    pub source: DriverSource,
    pub digest: String,
    pub install_hint: Option<String>,
}
```

Built-ins register all aliases at the current workspace version and resolve to the current executable digest. Subprocess entries come from `DriverCatalog::discover_from_environment()`.

Digest mismatch is a hard verification error. Version mismatch is also hard: reproduce must not silently select the highest compatible version. Lockfiles store exact versions.

The future remote registry can later implement the same resolver interface with signed manifests. This design intentionally leaves that as an additive backend instead of blocking M4-2 on a remote service.

## 8. Credential Handling

Freeze must strip values at the earliest transformation boundary. The lockfile builder should accept only `LockfileCredentialRef`-style data, not raw runtime secrets.

Reproduce credential handling:

1. `source: env`: if the referenced env var is unset and required, fail with a credential-specific error before creating resources.
2. `source: credstore`: if the entry is absent and interactive mode is available, prompt through the existing credential provider; otherwise fail.
3. Optional credentials may be omitted, but validator failures for present optional credentials are errors, matching M4-1 behavior.

Tests must include a known secret string and assert it is absent from:

1. frozen lockfile bytes.
2. persisted `state.json`.
3. CLI stdout/stderr for successful freeze and verify paths.

## 9. CLI Details

Top-level commands after M4-2:

```text
agentenv freeze <name> [--output <file>]
agentenv verify <lockfile>
agentenv reproduce <lockfile> [--name <name>]
```

`verify-blueprint` remains as a blueprint authoring/debugging command.

`create --reproduce <lockfile>` can remain from M4-1 as a compatibility path, but `reproduce` is the preferred env-manager verb. If both exist, they must share the same lockfile reproduction core path.

Human output:

1. `freeze`: `Lockfile written: agentenv.lock` or no prose when `--output -`.
2. `verify`: `Lockfile verified: <path>` with warnings listed below.
3. `reproduce`: M4-1 admission output plus a ready summary.

Failure output must include the exact target: driver kind/name/version, artifact name, credential name, or field path.

## 10. Backward Compatibility

Existing `0.1.0` lockfiles should still parse through the current `Lockfile` model. Behavior:

1. `verify` can validate structure, artifact digests, and credential references.
2. `verify` warns that the lockfile is not self-contained for reproduction.
3. `reproduce` requires a companion blueprint for `0.1.0` lockfiles, using the M4-1 matching behavior.
4. `freeze` always emits `0.2.0`.

This keeps existing tests meaningful while moving the portable artifact forward.

## 11. Testing Strategy

Use TDD for implementation.

Core tests:

1. `freeze_env_lockfile_is_byte_identical_for_repeated_calls`.
2. `lockfile_02_rejects_credential_value_fields`.
3. `lockfile_02_recomputes_blueprint_hash_from_composition`.
4. `lockfile_02_records_resolved_policy`.
5. `verify_reports_missing_driver`.
6. `verify_reports_driver_digest_mismatch`.
7. `verify_warns_on_policy_preset_drift`.
8. `reproduce_uses_resolved_policy_not_current_policy_presets`.
9. `driver_root_digest_is_stable_across_directory_iteration_order`.
10. `builtin_driver_digest_uses_current_executable`.

CLI tests:

1. `freeze_defaults_to_agentenv_lock`.
2. `freeze_output_dash_prints_lockfile_to_stdout`.
3. `verify_succeeds_for_generated_lockfile`.
4. `verify_fails_for_malformed_lockfile`.
5. `reproduce_name_override_creates_requested_env`.
6. `reproduce_missing_env_credential_fails_before_create`.
7. `round_trip_create_freeze_destroy_reproduce_describe_matches`.

Security tests:

1. known secret never appears in lockfile.
2. known secret never appears in state.
3. known secret never appears in successful freeze/verify output.

Gated integration:

1. real OpenShell/Codex/filesystem lifecycle remains behind existing host prerequisite environment variables.
2. default CI uses mock or in-memory driver factory tests for deterministic coverage.

## 12. Acceptance Mapping

Issue acceptance criteria map as follows:

1. `freeze` byte-identical output: Section 6 and tests 11.1.
2. `reproduce` same `describe` output minus host paths: Section 5 and round-trip CLI test.
3. `verify` catches malformed lockfiles, version conflicts, missing drivers: Section 4 tests.
4. lockfiles never contain credential values: Sections 3, 8, and security tests.
5. create, freeze, destroy, reproduce, describe round-trip: Section 11 CLI tests.

## 13. Trade-Offs

1. Emitting `0.2.0` instead of mutating `0.1.0` is a clean schema boundary. It costs compatibility code but avoids ambiguous reproduction behavior.
2. Using the executable digest for built-ins is coarse but correct for a statically linked binary. Per-crate digests would be misleading after linking.
3. Verifying subprocess driver roots locally avoids trusting unsigned metadata. It may make large driver bundles slower to verify, but correctness matters more than speed for freeze/reproduce.
4. Treating policy drift as a warning preserves reproducibility while still surfacing that current presets changed.
5. Deferring remote install avoids inventing an unsigned supply-chain mechanism. The resolver interface keeps the future registry additive.

## 14. Implementation Order

1. Add the `0.2.0` lockfile structs and parser support alongside the existing model.
2. Add deterministic driver artifact digest helpers.
3. Add local driver artifact resolver over built-ins and `DriverCatalog`.
4. Add core lockfile verification API with structured errors and warnings.
5. Add lockfile-to-reproduction input conversion.
6. Refactor M4-1 create so blueprint and lockfile reproduction converge after input resolution.
7. Update CLI args and handlers for `freeze`, `verify`, and `reproduce`.
8. Add compatibility behavior for `0.1.0` lockfiles.
9. Add round-trip and security tests.
10. Run `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
