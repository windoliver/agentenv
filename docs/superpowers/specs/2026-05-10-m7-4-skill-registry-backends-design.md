# M7-4 Skill Registry Backends Design

- Date: 2026-05-10
- Issue: https://github.com/windoliver/agentenv/issues/30
- Milestone: M7 Skills axis and registry
- Depends on:
  - https://github.com/windoliver/agentenv/issues/27
  - https://github.com/windoliver/agentenv/issues/28
- Affected crates: `agentenv-core`, `agentenv`

## Context

M7-1 decided that skills are core-managed resources, not a new driver
kind and not a `ContextDriver` subtype. M7-2 added the first
`agentenv skills` lifecycle CLI and the core skill service. Current
`origin/main` already contains filesystem, HTTP, and OCI registry
adapters under `agentenv-core::skills`.

This issue completes the registry-backend surface as a cohesive feature:
audit the existing filesystem, HTTP, and OCI adapters against the issue
contract, add the missing git backend, and close integration gaps in
config parsing, CLI overrides, provenance, documentation, and tests.

## Goals

- Keep skills as core-managed artifacts resolved before sandbox creation.
- Keep registry adapters out of the driver protocol and avoid a schema
  bump in `agentenv-proto`.
- Support the four registry types from the issue: filesystem, OCI, HTTP,
  and git.
- Reuse the existing `SkillService` and `RegistryAdapter` shape unless
  tests expose a real contract mismatch.
- Preserve the config precedence from M7-2: CLI flag, then project
  `agentenv.yaml`, then user `~/.config/agentenv/config.toml`.
- Preserve shared manifest, digest, signature, install, and provenance
  handling across all backends.
- Prefer additive compatibility when current M7-2 behavior differs from
  the issue text, so existing filesystem, HTTP, and OCI users do not lose
  working registry layouts.
- Add coverage that proves full-registry behavior rather than only config
  parsing.

## Non-Goals

- Do not add a fifth pluggable axis.
- Do not add a `SkillsDriver` or any JSON-RPC driver method.
- Do not introduce libgit2, OpenSSL, Python, Node, Docker, ORAS, or any
  other build-time dependency to core.
- Do not redesign the whole skills cache or CLI if the existing M7-2/M7-3
  implementation already satisfies the contract.
- Do not implement in-sandbox agent discovery beyond preserving installed
  skill metadata for later injection work.

## Architecture

The implementation remains inside `agentenv-core::skills`.

The existing service boundary should stay the main entry point:

```rust
pub struct SkillService { /* root, config, credentials, ssrf */ }

impl SkillService {
    pub async fn search(&self, query: &str) -> Result<Vec<SkillSearchHit>, SkillError>;
    pub async fn add(&self, request: SkillAddRequest) -> Result<InstalledSkill, SkillError>;
    pub async fn publish(&self, request: SkillPublishRequest) -> Result<SkillSearchHit, SkillError>;
}
```

Each backend implements the existing `RegistryAdapter` trait:

```rust
#[async_trait]
pub trait RegistryAdapter {
    async fn search(&self, query: &str) -> Result<Vec<SkillSearchHit>, SkillError>;
    async fn fetch(&self, name: &str, version: Option<&str>) -> Result<FetchedSkill, SkillError>;
    async fn publish(
        &self,
        bundle_path: &Path,
        allow_unsigned: bool,
    ) -> Result<SkillSearchHit, SkillError>;
}
```

The adapter owns transport details only. Identity validation, manifest
loading, digest checks, signature enforcement, staging cleanup, and final
install remain shared service/store behavior. Installed provenance should
continue to use source labels in the existing pattern:

```text
filesystem:<registry>:<name>@<version>
http:<registry>:<name>@<version>
oci:<registry>:<name>@<version>
git:<registry>:<name>@<version>
```

## Registry Config

The config model supports all four registry kinds:

```yaml
skills:
  registries:
    - name: community
      type: oci
      url: ghcr.io/agentenv-community
    - name: corp
      type: http
      url: https://skills.acme.internal
      auth: bearer-from-credstore
    - name: local-dev
      type: filesystem
      path: /home/alice/dev/skills
    - name: git-dev
      type: git
      url: git+https://github.com/acme/skills
```

Validation rules:

- `filesystem` requires `path`.
- `http` requires an `http` or `https` URL with no user info.
- `oci` requires a normalized registry/repository reference or `oci://`
  URL that normalizes to one.
- `git` requires a `git+https` URL, with no user info, query, or fragment.
- Registry names keep the same conservative skill-name validation already
  used by M7-2.
- CLI `--registry` direct-source overrides may accept `git+https://...`;
  ambiguous shorthand remains OCI-oriented and should not be extended to git.

## Backend Behavior

### Filesystem

Filesystem remains the local development backend:

- `path` points at a local registry directory.
- Search reads the existing registry index layout and, if no index is
  present, scans issue-compatible skill subdirectories that contain
  `skill.yaml` or `SKILL.md` frontmatter.
- Fetch copies a specific skill version into a staging directory.
- Fetch without a version selects the highest semver version.
- Publish writes an immutable `bundles/<name>/<version>` tree and updates
  the registry index.
- Publishing the same version with different digest remains an error.

The audit should confirm filesystem index entries cannot bypass manifest
identity checks or escape the registry root through symlinks or traversal.
The subdirectory scanner is read-only compatibility; publish continues to
use the indexed layout so local registries remain deterministic.

### HTTP

HTTP remains a static registry backend:

- Search reads the issue layout at `<url>/index.json`. Existing YAML index
  support may stay as a fallback for already-landed tests and registries.
- Fetch downloads `<url>/skills/<name>/<version>.tar.zst` and verifies the
  sidecar signature at `<url>/skills/<name>/<version>.tar.zst.sig` when a
  signature is declared. Existing expanded static-bundle fetch support may
  stay as a compatibility path.
- Signature sidecars are used where the current implementation supports
  them.
- Every outbound URL is validated through the existing SSRF module before
  request.
- Auth uses the current bearer credential resolver and must not put token
  values in persisted metadata or error strings.

The audit should confirm relative artifact paths cannot redirect fetches
outside the configured registry authority.

### OCI

OCI remains the preferred remote registry backend:

- `url` is an OCI reference such as `ghcr.io/<org>[/<repo>]`.
- Skill artifacts use media type
  `application/vnd.agentenv.skill.v1+tar`.
- Search, fetch, and publish use the OCI Distribution API through
  `reqwest` with `rustls`.
- Auth stays bearer-token based through the same credential resolver.
- No Docker, ORAS, or external registry CLI dependency is added.

The audit should confirm references are normalized consistently and unsafe
authorities are rejected before network access.

### Git

Git is the new backend:

- `url: git+https://github.com/<org>/<repo>` identifies the source repo.
- Skills are subdirectories in the repository. A valid skill directory is
  one containing `skill.yaml` and its declared entry file.
- Version resolution supports semantic versions from skill manifests. If
  the requested handle omits a version, fetch selects the highest semver
  version discovered for that skill.
- Fetch supports exact semver versions and commit-ish refs where the
  implementation can resolve them safely without ambiguity.
- Search inspects a local clone cache and returns matching skill summaries.
- Publish is unsupported in the first implementation and returns a typed
  `SkillError` explaining that git registry publish is not supported.

Implementation should shell out to `git` rather than link a new git
library. Commands must be non-interactive and bounded:

- use `GIT_TERMINAL_PROMPT=0`
- avoid shell interpolation by using `std::process::Command` arguments
- use a cache path under the agentenv root or a temporary staging area
- validate clone/fetch destination paths through existing safe-path helpers
  or new equivalents
- prefer sparse checkout for large repos when it can be added without
  making correctness depend on optional git features

Git URL validation is intentionally conservative for this issue:
`git+https` only. SSH, local `file://`, raw `https://` inference, and
authenticated URLs can be added later with explicit policy and credential
design.

Tests that need a local repository should use a small command-runner seam
or an internal fixture path that does not broaden production URL policy.

## Error Handling

Library errors stay in `SkillError` using `thiserror`. CLI commands add
context with `anyhow` but do not pattern-match string messages.

New or audited errors should cover:

- invalid git registry URL
- missing `git` executable
- git clone/fetch/list failure
- missing skill in git registry
- ambiguous or invalid git skill version
- unsupported git publish
- unsafe artifact path or repository path
- remote registry URL blocked by SSRF validation
- artifact identity mismatch after fetch

No `.unwrap()` should be introduced outside tests.

## CLI Behavior

The existing skills CLI should remain thin:

```text
agentenv skills search <query> [--registry <name-or-source>]
agentenv skills add <name>[@version] [--registry <name-or-source>]
agentenv skills publish <path> [--registry <name-or-source>]
```

`--registry git+https://github.com/acme/skills` should create a one-off git
registry named `cli`, matching existing direct-source override behavior for
file, HTTP, and OCI. `publish` to a git registry should fail with the typed
unsupported-publish error.

Output formats from M7-2 remain unchanged except for the new `git` source
type appearing in JSON and table output where provenance is shown.

## Testing Strategy

Implementation should follow TDD for behavior changes.

Core tests:

- git registry config parses from project YAML and user TOML
- direct CLI override parses `git+https://...`
- invalid git URLs are rejected before any `git` command runs
- HTTP registry search prefers `index.json` and keeps legacy index fallback
- HTTP registry fetch validates tarball and signature-sidecar paths stay
  under the configured authority
- filesystem registry search scans subdirectories when no index exists
- git registry search finds skills through a fake command runner or safe
  local fixture
- git registry add installs an exact version through the same seam
- git registry add without version selects the highest semver
- git registry fetch records `git:<registry>:<name>@<version>` provenance
- git publish returns the unsupported-publish error
- missing `git` executable is reported cleanly if command lookup can be
  simulated without relying on host mutation
- existing filesystem, HTTP, and OCI behavior remains green

CLI tests:

- command inventory still includes `skills`
- `skills search --registry git+https://...` works against a local fixture
  served through a safe test path or a temporary repo URL if practical
- `skills add --registry git+https://...` installs and reports git
  provenance
- `skills publish --registry git+https://...` exits non-zero with a clear
  unsupported-publish diagnostic

Full verification before completion:

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

If host `git` is not available, git-backend tests should skip only the
subprocess-dependent fixture tests and still run pure config/validation
coverage.

## Rollout Notes

This issue should not require a driver protocol version bump. The PR
description should list `agentenv-core` and `agentenv` as affected crates,
note that `agentenv-proto` is unchanged, and call out any backend behavior
that intentionally degrades, especially read-only git publish support.
