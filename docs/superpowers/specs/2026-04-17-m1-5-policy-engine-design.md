# M1-5 Policy Model, Engine, and Translator Design

Date: 2026-04-17
Issue: [#6](https://github.com/windoliver/agentenv/issues/6)
Milestone: M1 - Foundations

## Summary

Implement the generic policy model, deterministic tier/preset composition engine, and
translator framework described in issue #6 without expanding the CLI beyond the issue's
stated M1 scope. The resulting design keeps the policy contract on the protocol narrow
waist, centralizes composition and translation in `agentenv-policy`, and keeps sandbox
drivers thin at the integration boundary.

## Affected Crates

- `crates/agentenv-proto`
- `crates/agentenv-policy`
- `crates/drivers/sandbox-openshell`

## Scope

In scope:

- Expand the shared wire schema so the driver protocol can carry the full generic policy
  surface for network, filesystem, process, and inference controls.
- Implement `agentenv-policy` as the composition and translation crate.
- Load named presets from YAML files under `crates/agentenv-policy/presets/`.
- Provide the `PolicyTranslator` trait, an `OpenShellTranslator`, and a stub
  `DockerTranslator`.
- Enforce hot-reload versus recreate semantics for policy updates.
- Add deterministic tests for policy composition and translated output.

Out of scope:

- Full user-facing CLI support beyond what is already explicitly deferred to M4 in the
  issue description.
- Real Docker policy translation or runtime integration.
- Any new transport, protocol, or serialization format.

## Goals

1. Preserve a single canonical policy schema across the core and drivers.
2. Make policy composition deterministic and data-driven.
3. Make translation testable and driver-agnostic.
4. Preserve the architecture rule that sandbox drivers translate generic policy instead
   of defining driver-specific policy as the public contract.

## Architecture

### Canonical Schema in `agentenv-proto`

`agentenv-proto` becomes the canonical wire model for policy exchange. The current
`NetworkPolicy` host/port lists expand into a structured generic policy with four
domains:

- `network`
- `filesystem`
- `process`
- `inference`

Each domain carries explicit reload semantics in the type surface so callers and
drivers can determine whether a change is hot-reloadable or requires environment
recreation. The existing `apply_policy` RPC remains the policy update path, but it now
accepts the complete generic model rather than a reduced network-only subset.

Reloadability is a schema-level contract, not caller-provided mutable data. The
canonical model exposes dedicated domain sections, and the implementation treats
`network` and `inference` as hot-reloadable while `filesystem` and `process` are
create-time locked.

The protocol remains unchanged in shape: core and drivers still exchange policy through
the existing JSON-RPC methods. The work is a schema expansion, not a protocol redesign.

### Composition and Translation in `agentenv-policy`

`agentenv-policy` owns the implementation logic around the canonical model rather than
redefining it. This crate will provide:

- model helpers built around the canonical proto types
- tier and preset composition
- preset registry loading and validation
- policy normalization for deterministic output
- translator traits and implementations
- structured translation and policy-update errors

This avoids maintaining a second internal policy model that can drift from the wire
schema.

### Thin Driver Boundary in `sandbox-openshell`

`sandbox-openshell` remains small. It accepts the canonical policy, calls the
OpenShell translator, and enforces capability and recreate semantics at the driver
boundary. The driver should not own tier logic, preset loading, or OpenShell-specific
policy assembly beyond the final translation step.

## Policy Model

### Network Domain

The network domain supports the rule buckets described in issue #6:

- `allow`
- `deny`
- `approval_required`

Supported rule kinds:

- host
- CIDR
- port
- URL pattern
- HTTP method plus path

The generic model should allow these rule kinds to coexist in a stable, serializable
form that other drivers can translate later.

### Filesystem Domain

The filesystem domain represents path-scoped access with read/write intent and is
explicitly locked at create time. Runtime changes to filesystem policy must produce a
`requires_recreate` style error rather than silently degrading.

### Process Domain

The process domain represents allow/deny or profile-oriented syscall controls and is
also locked at create time. Runtime mutation attempts must fail with recreate-required
errors.

### Inference Domain

The inference domain represents routing rules for model access and is hot-reloadable.
It lives in the canonical policy model because the architecture treats inference
routing as a policy surface, not an implementation detail hidden in one sandbox driver.

## Tier and Preset Engine

### Tiers

The composition engine exposes three built-in tiers:

- `restricted`
- `balanced` (default)
- `open`

Each tier defines a distinct baseline posture. The implementation must prove in tests
that these baselines compose into distinct outputs.

### Presets

Preset definitions live as YAML files in `crates/agentenv-policy/presets/`. The initial
catalog covers:

- `github_read`
- `github_readwrite`
- `npm_read`
- `pypi_read`
- `crates_read`
- `docker_hub_read`
- `messaging_slack`
- `messaging_discord`
- `messaging_telegram`

The registry layer loads these presets, validates their schema, and produces actionable
errors for unknown names or invalid definitions.

### Access Modes

Preset expansion handles read versus readwrite at composition time. Presets declare the
rules they contribute for each supported access mode, and the engine selects the
matching group when composing policy. The engine does not mutate an already-expanded
preset after the fact.

### Deterministic Composition

`compose_policy(tier, presets, overrides)` applies:

1. the tier baseline
2. preset expansions in the exact user-supplied order
3. explicit overrides last

Before serialization or translation, the result is normalized so equivalent inputs
produce byte-identical output. Determinism includes stable field ordering, stable rule
ordering, and deterministic YAML loading behavior.

## Translation Framework

### Trait

`agentenv-policy::translate` exposes a translator trait over the canonical policy model:

- `PolicyTranslator`

This trait translates generic policy into a driver-native representation and returns
structured failures instead of driver-specific strings.

### OpenShell Translator

`OpenShellTranslator` is the first concrete implementation. It emits OpenShell policy
YAML in a stable field and rule order suitable for:

- golden-file tests
- byte-identical repeat generation
- direct handoff to the sandbox driver without post-processing

### Docker Stub

`DockerTranslator` exists as a stub behind the same trait so the extensibility point is
real now, while the actual Docker seccomp and iptables implementation remains
post-MVP.

## Runtime Update Semantics

Policy update behavior is enforced explicitly:

- network: hot-reloadable
- inference: hot-reloadable
- filesystem: requires recreate
- process: requires recreate

When a caller attempts to mutate a locked domain on an existing environment, the system
returns a structured recreate-required error. The implementation should not silently
drop those changes or pretend they were hot-reloaded.

## Testing Strategy

### `agentenv-proto`

- serde round-trip tests for the expanded policy types
- schema generation coverage for the expanded policy model

### `agentenv-policy`

- tier distinctness tests
- preset registry load tests
- unknown preset error tests
- access mode selection tests
- deterministic composition tests
- translator golden-file tests

### `sandbox-openshell`

- integration coverage proving the translated YAML is accepted by the OpenShell-facing
  path in this repository
- recreate-required behavior tests for locked policy domains
- hot-reload behavior tests for network and inference updates

If the real OpenShell CLI is not present in the test environment, integration coverage
should degrade cleanly rather than making the workspace unusable.

## Deferred CLI Surface

Issue #6 explicitly marks the CLI surface as partial and completed in M4. This design
therefore does not add broad end-user policy commands now. The M1 work should expose
the core policy model, composition, translation, and update semantics so that the later
CLI work can bind to stable internals rather than force another policy redesign.

## Risks and Trade-offs

- Expanding `agentenv-proto` increases schema surface early, but it preserves the narrow
  waist and avoids a second internal-only model.
- Deterministic translation requires deliberate normalization logic rather than relying
  on incidental map or vector order.
- Representing future driver needs in the generic schema adds some upfront design cost,
  but it is lower risk than adding driver-specific escape hatches later.

## Acceptance Mapping

- Distinct tier baselines: covered by tier composition tests.
- Preset registry loaded from YAML with actionable unknown-name errors: covered by
  registry loading and error tests.
- Per-preset read/readwrite toggle: covered by access mode composition tests.
- OpenShell translator output accepted unmodified: covered by driver-facing integration
  coverage.
- Hot-reload semantics enforced: covered by recreate-required and hot-reload tests.
- Deterministic output: covered by normalization and golden output tests.
