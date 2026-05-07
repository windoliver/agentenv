# M5-6 Design: Image Hardening Profiles

- Date: 2026-05-03
- Issue: https://github.com/windoliver/agentenv/issues/22
- Milestone: M5 packaging, DX, and security
- Affected crates: `agentenv-policy`, `agentenv-core`, `agentenv`, `agentenv-proto`, `sandbox-openshell`
- Affected docs and profiles: `docs/DRIVER_PROTOCOL.md`, `docs/BLUEPRINTS.md`, `crates/agentenv-policy/hardening/`

## 1. Context And Goals

Issue #22 adds image-hardening profiles for container-image-backed sandboxes. It depends on the BYO Dockerfile work from #19, which now provides `sandbox.image.source: byo`, `agentenv create --from`, OpenShell Dockerfile staging, image digest verification, and basic Dockerfile preflight warnings.

The goal is to make hardening a reusable profile system that applies to agentenv-owned images and BYO Dockerfiles. The first implementation should ship `baseline`, `strict`, and `open`; default to `baseline`; propagate selected hardening into image build inputs and runtime sandbox creation; and add a Dockerfile linter that checks a blueprint against the selected profile.

This design keeps agentenv's driver protocol stable. It follows the #19 pattern: core resolves user-facing blueprint configuration, then passes create-time sandbox details through existing `SandboxSpec` policy and metadata fields. A separate `SandboxDriver::apply_hardening` method can be added later if multiple sandbox drivers need a post-create or independently reloadable hardening operation.

## 2. Recommended Architecture

Hardening belongs in `agentenv-policy`, because it is another policy preset family rather than a fifth pluggable axis. Add first-class hardening types, validation, and built-in profile loading there, with YAML profile files under:

```text
crates/agentenv-policy/hardening/
```

Core resolves `sandbox.hardening` from the existing flattened sandbox component. If omitted, it uses `baseline`. The resolved profile is merged into the existing create-time `NetworkPolicy` for fields that already fit the four-domain model:

- filesystem read-only paths.
- filesystem read-write paths.
- process profile markers.

Settings that do not fit the current policy model stay as hardening metadata in `SandboxSpec.metadata`:

- packages to strip.
- tmpfs mount recommendations.
- `ulimit` values.
- capability drops.
- disable core dumps.
- disable user namespaces.
- generated Dockerfile hardening fragment content and marker.

OpenShell enforces hardening during sandbox creation. It injects image-layer hardening into BYO Dockerfile staging before building, and maps runtime hardening metadata into OpenShell create or policy behavior where the underlying CLI supports it. Unsupported profile recommendations produce deterministic preflight or lint diagnostics rather than disappearing silently.

## 3. Hardening Profiles

Each built-in profile is a YAML bundle with a stable typed schema:

```yaml
name: baseline
description: Default production hardening for agentenv sandbox images.
packages:
  strip: []
mounts:
  read_only: []
  read_write: []
  tmpfs: []
ulimits:
  nproc: 512
  nofile: 4096
capabilities:
  drop: []
disable_core_dumps: false
disable_user_namespaces: false
dockerfile:
  marker: AGENTENV_HARDENING_PROFILE=baseline
  fragment: |
    RUN set -eu; \
        find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true
```

`baseline` is the default. It strips build and network-debug tools (`gcc`, `g++`, `make`, `nc`, `tcpdump`, `nmap`, `strace`, `gdb`), makes `/etc`, `/usr`, and `/opt` read-only, leaves `/workspace`, `/tmp`, and `/var/tmp` writable, adds `$HOME` as writable when `state.persist_home: true`, tightens `nproc` and `nofile`, and removes SUID binaries in the image layer.

`strict` includes baseline and adds removal of `curl`, `wget`, and `git` unless explicitly allowed by future profile extensions. It puts `/tmp` on size-capped tmpfs, disables core dumps, and requests user namespaces disabled inside the sandbox.

`open` keeps only minimal hardening. It should still run as the sandbox user and avoid SUID binaries, but it does not strip developer tools or network-debug tools. This profile is for research and exploratory environments where tool availability is more important than production hardening.

Custom profile support is allowed through the same resolver, but the first implementation should keep it narrow: a non-built-in `sandbox.hardening` value resolves to a local YAML file path, then to a named profile under `AGENTENV_HARDENING_PROFILE_DIR`, then to `~/.agentenv/hardening/`. Invalid or missing profiles are create and lint errors.

## 4. Blueprint And Runtime Flow

Blueprint shape:

```yaml
sandbox:
  driver: openshell
  hardening: strict
```

The existing `ComponentSection.extra` representation can carry this field without changing the blueprint schema version. Runtime should add typed helpers so the rest of the code does not inspect raw YAML maps repeatedly.

On `agentenv create`:

1. CLI optionally overlays `--from` into `sandbox.image.source: byo`, as it does now.
2. Core verifies the blueprint and resolves the effective hardening profile, defaulting to `baseline`.
3. Core composes the existing policy and merges hardening filesystem/process defaults into the create-time policy.
4. Core builds `SandboxSpec` with the effective policy plus `hardening_*` metadata.
5. OpenShell stages and builds BYO Dockerfile contexts with an injected hardening fragment.
6. OpenShell creates the sandbox with available runtime hardening settings.
7. If agent installation temporarily broadens network policy, core restores the final policy exactly as it does now.

For agentenv-owned images, this repository does not currently contain base-image Dockerfiles. The implementation should still expose the generated built-in hardening fragment and test it directly, so future base-image build code can reuse the same fragment rather than duplicating hardening shell.

## 5. OpenShell Driver Enforcement

The OpenShell driver already has a clear BYO build boundary:

```text
resolve Dockerfile -> stage context -> docker build -> inspect digest -> openshell sandbox create --from
```

Hardening should extend that boundary. The staged Dockerfile should receive an agentenv-generated hardening fragment after user content, with a profile marker comment or environment marker that the linter can recognize. The fragment should be deterministic and shell-portable enough for common Debian and Alpine images. Unsupported package managers should fail the build with a readable message rather than reporting success without hardening.

Runtime metadata should be parsed into a driver-local config struct rather than scattered string lookups. The driver should map known settings to available OpenShell behavior. If OpenShell cannot express a recommendation yet, preflight and lint should report the gap with a stable diagnostic code. Create should fail only for malformed metadata or settings that the selected profile marks as required.

The implementation must preserve existing BYO digest behavior: expected digest mismatches still fail, and omitted digest values are still recorded in the lockfile after build.

## 6. Dockerfile Linter

Add:

```text
agentenv blueprint lint <agentenv.yaml>
agentenv blueprint lint <agentenv.yaml> --json
```

The linter resolves the blueprint, effective hardening profile, and BYO Dockerfile path if present. It does not create a sandbox or build an image. It should reuse the same profile loader and Dockerfile analysis logic used by preflight.

Initial diagnostics:

- `hardening_unknown_profile`: selected profile cannot be resolved.
- `hardening_invalid_profile`: profile YAML fails validation.
- `dockerfile_unreadable`: BYO Dockerfile cannot be read.
- `dockerfile_user_root`: final stage leaves `USER root` or `USER 0`.
- `dockerfile_privileged`: file references `--privileged`.
- `dockerfile_cap_add`: file references `cap_add` or `cap-add`.
- `dockerfile_missing_hardening_marker`: file does not include the expected agentenv hardening marker.
- `dockerfile_reintroduces_stripped_package`: file installs a package stripped by the selected profile.
- `hardening_runtime_unsupported`: selected profile asks for a runtime setting the selected sandbox driver does not advertise or cannot map.

`USER root` should be an error for `baseline` and `strict`. Package reintroduction should be a warning for `baseline` and an error for `strict`. `open` should keep anti-patterns as warnings unless the Dockerfile is unreadable.

The linter should be conservative. It should parse common Dockerfile instructions and report what it can prove. It should not claim to fully evaluate build args, multi-platform conditionals, or shell scripts.

## 7. Error Handling

Fail early during create, verify, and lint for:

- malformed `sandbox.hardening` values.
- missing custom profile files.
- invalid hardening YAML types.
- non-positive ulimit values.
- invalid tmpfs size strings.
- invalid package names.
- invalid generated Dockerfile fragments.

Warnings are appropriate for:

- unsupported runtime recommendations on a driver that can still safely create a sandbox.
- Dockerfile patterns that may be legitimate but weaken hardening.
- linter limitations when a Dockerfile uses dynamic shell or build-arg behavior.

Driver errors should stay in existing `DriverError` variants. This avoids broadening public error shape while still giving users actionable messages.

## 8. Documentation

Update `docs/DRIVER_PROTOCOL.md` to state that this implementation carries hardening through create-time `SandboxSpec.policy` and `SandboxSpec.metadata`, without adding a new method. The document should explicitly reserve a future additive method if post-create hardening becomes necessary.

Update `docs/BLUEPRINTS.md` and relevant reference examples with a short explanation of `sandbox.hardening`, defaults, and when to choose `strict` or `open`.

Add crate-level policy docs or README text describing the three built-in profiles and the YAML schema. The profile descriptions should match the shipped YAML exactly.

## 9. Test Coverage

`agentenv-policy`:

- built-in profiles parse and validate.
- `baseline`, `strict`, and `open` differ as documented.
- invalid profiles report field-specific errors.
- hardening-to-policy merge handles `persist_home`.

`agentenv-core`:

- omitted `sandbox.hardening` defaults to `baseline`.
- `hardening: strict` propagates expected policy and metadata.
- unknown and malformed profiles fail before sandbox creation.
- `--from` overlay still preserves hardening behavior.

`sandbox-openshell`:

- BYO staging injects the selected hardening fragment.
- build args and digest behavior remain intact.
- runtime hardening metadata is parsed into a typed config.
- unsupported settings produce deterministic diagnostics.

`agentenv` CLI:

- `agentenv blueprint lint` text and JSON output.
- `USER root`, privileged/cap_add, missing marker, and strict package bans.
- existing `verify-blueprint`, create preflight, and `--from` tests keep passing.

Full verification before implementation completion:

```sh
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## 10. Scope And Non-Goals

In scope:

1. Ship built-in hardening profiles.
2. Default create flows to `baseline`.
3. Propagate `strict` and `open` through policy, image build, runtime metadata, and linting.
4. Preserve the driver protocol for this issue.
5. Add deterministic Dockerfile lint diagnostics.

Out of scope:

1. Adding a fifth pluggable axis.
2. Adding a new serialization format.
3. Implementing a Docker, E2B, or Firecracker sandbox driver.
4. Fully interpreting Dockerfile shell semantics.
5. Rebuilding or publishing agentenv-owned base images from this repository.
6. Adding post-create hardening reload behavior.

## 11. Implementation Notes

Start test-first:

1. Add profile parsing and validation tests in `agentenv-policy`.
2. Add core tests that assert the default baseline and strict metadata propagation.
3. Add CLI lint tests before implementing the subcommand.
4. Add OpenShell staging tests that fail until the hardening fragment is injected.
5. Implement the smallest runtime metadata mapping needed for the built-in profiles.

Before writing implementation code, post the selected approach on issue #22. The comment should state that this implementation keeps the driver protocol stable and uses create-time `SandboxSpec` policy and metadata, matching the #19 BYO Dockerfile pattern.
