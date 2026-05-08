# M7-2 Design: `agentenv skills` Lifecycle CLI

- Date: 2026-05-07
- Issue: https://github.com/windoliver/agentenv/issues/28
- Milestone: M7 Skills axis and registry
- Depends on: https://github.com/windoliver/agentenv/issues/27
- Affected crates: `agentenv`, `agentenv-core`

## 1. Context and Goals

Issue #28 adds first-class CLI support for the skill lifecycle:

```text
agentenv skills search <query>
agentenv skills add <name>[@version]
agentenv skills install --from <path>
agentenv skills list
agentenv skills info <name>
agentenv skills remove <name>
agentenv skills publish <path> --registry <url>
agentenv skills verify <name>
```

Issue #27 chose the architectural lane: skills are core-managed resources, not
`ContextDriver` sub-kinds and not a fifth pluggable axis. The implementation
therefore belongs in core-owned lifecycle code and a thin CLI facade. Registry
backends are package-registry adapters, not JSON-RPC drivers.

The feature must provide one coherent PR for the full issue surface. The PR
should make local, HTTP, and OCI skill workflows useful end to end without
adding a runtime dependency, and preserve the narrow waist: MCP remains the
agent-to-context protocol and JSON-RPC remains only the core-to-driver protocol.

## 2. Scope and Non-Goals

### In scope

1. A new `agentenv-core::skills` module that owns skill manifests, registry
   configuration, resolution, fetch, verification, install, remove, listing,
   info, and publish behavior.
2. The `agentenv skills` CLI group and all subcommands listed in issue #28.
3. A deterministic skill cache under `~/.agentenv/skills/<name>/<version>/`.
4. An installed-skill index used by `list`, `info`, `remove`, and `verify`.
5. Skill bundle manifest parsing from `skill.yaml`.
6. Deterministic SHA-256 bundle digests over declared files.
7. Ed25519 signature verification for registry-installed bundles.
8. Local development installs from `install --from <path>`.
9. Filesystem registry search, add, verify, and publish.
10. HTTP registry search, add, verify, and publish through SSRF-validated URLs.
11. OCI registry search, add, verify, and publish through the OCI Distribution
    API with `reqwest` and `rustls`.
12. Config precedence: CLI flag, then project `agentenv.yaml`, then
    `~/.config/agentenv/config.toml`.
13. Tests for core behavior and CLI behavior.

### Out of scope

1. A new driver kind, new driver RPC method, or driver protocol schema bump.
2. In-sandbox agent discovery and injection of selected skills during
   `agentenv create`; that belongs to later M7 create/freeze integration.
3. A network approval queue for registry fetches. This issue gates registry
   URLs through the core SSRF validator; richer operator approval policy remains
   a later policy/approvals integration.
4. OpenPGP, x509, cosign, or alternate signature formats.
5. Adding Python, Node, OpenSSL, ORAS, Docker, or another build-time/runtime
   dependency to core.

## 3. Architecture

### 3.1 Core skill service

Add `agentenv-core::skills` with focused submodules:

1. `manifest` parses and validates `skill.yaml`.
2. `digest` computes deterministic bundle digests.
3. `signature` verifies Ed25519 signatures.
4. `index` reads and writes the installed-skill index.
5. `registry` defines registry config and adapter traits.
6. `store` owns cache paths and atomic install/remove operations.
7. `service` exposes high-level operations used by the CLI.

The service API should make the CLI thin:

```rust
pub struct SkillService { /* root, config, registries */ }

impl SkillService {
    pub fn search(&self, query: &str) -> Result<Vec<SkillSearchHit>, SkillError>;
    pub fn add(&self, request: SkillAddRequest) -> Result<InstalledSkill, SkillError>;
    pub fn install_from_path(&self, request: SkillInstallRequest) -> Result<InstalledSkill, SkillError>;
    pub fn list(&self) -> Result<Vec<InstalledSkill>, SkillError>;
    pub fn info(&self, name: &str) -> Result<InstalledSkillInfo, SkillError>;
    pub fn remove(&self, name: &str) -> Result<SkillRemoveReport, SkillError>;
    pub fn publish(&self, request: SkillPublishRequest) -> Result<SkillPublishReport, SkillError>;
    pub fn verify(&self, name: &str) -> Result<SkillVerifyReport, SkillError>;
}
```

`thiserror` owns library errors. The CLI uses `anyhow` only to add command
context and render human-readable failures.

### 3.2 CLI facade

Add `Skills(SkillsArgs)` to `crates/agentenv/src/main.rs` with these
subcommands:

```text
skills search <query> [--registry <name-or-url>] [--json]
skills add <name>[@version] [--registry <name-or-url>] [--allow-unsigned] [--json]
skills install --from <path> [--allow-unsigned] [--json]
skills list [--json]
skills info <name> [--version <version>] [--json]
skills remove <name> [--version <version>] [--yes] [--json]
skills publish <path> --registry <name-or-url> [--allow-unsigned] [--json]
skills verify <name> [--version <version>] [--json]
```

The issue surface does not require JSON output, but existing CLI tests already
use stable JSON for machine paths. Adding `--json` for skills keeps this command
usable in automation and makes tests precise.

`info`, `remove`, and `verify` accept a name plus optional version. If a name is
installed in exactly one version, the command resolves that version. If multiple
versions are installed and no `--version` is provided, the command returns an
ambiguous-name error listing available versions.

### 3.3 Bundle manifest

Each skill bundle has a `skill.yaml` at its root:

```yaml
name: example-skill
version: 0.1.0
description: Short description
entry: SKILL.md
files:
  - SKILL.md
  - references/**
self_test:
  command: agentenv-skill-test
signatures:
  ed25519: <hex signature>
```

Required fields:

1. `name`
2. `version`
3. `entry`
4. `files`

Optional fields:

1. `description`
2. `self_test.command`
3. `signatures.ed25519`
4. additional metadata preserved as opaque YAML for future compatibility

`name` is a conservative package identifier: ASCII lowercase letters, digits,
dash, underscore, and dot, with no leading dot and no path separators.
`version` must be valid semantic version syntax. `entry` and every expanded
file path must stay under the bundle root, must be relative, and must not
contain parent traversal.

### 3.4 Installed index and cache layout

Core stores immutable installed bundles under:

```text
~/.agentenv/skills/
  index.yaml
  <name>/
    <version>/
      skill.yaml
      content/
        ...
      installed.yaml
```

`installed.yaml` records:

1. name
2. version
3. source registry or local path
4. source type: `local`, `filesystem`, `http`, or `oci`
5. bundle digest
6. signature status
7. signature public key or trust record when available
8. installed timestamp
9. entry path

The index is a derived lookup file optimized for CLI reads. The directory
contents remain the source of truth for verification. Index writes should be
atomic: write a temporary file next to `index.yaml`, then rename.

## 4. Registry Behavior

### 4.1 Registry config

Support the issue's config shape:

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
```

The core config model also supports explicit resolution order:

```yaml
skills:
  registry_order:
    - corp
    - community
    - local-dev
```

If `registry_order` is omitted, the listed order of `registries` is used.

### 4.2 Config precedence

The CLI builds a final skills config from three sources:

1. CLI flags, such as `--registry`.
2. Project `agentenv.yaml`, using its top-level `skills` section when present.
3. User config at `~/.config/agentenv/config.toml`.

Project `agentenv.yaml` remains YAML. User config is TOML to match the issue.
The same typed `SkillsConfig` should deserialize from both formats. CLI flags
do not mutate config; they narrow the operation for the current command.

### 4.3 Filesystem registry

A filesystem registry is a directory tree with this layout:

```text
registry-root/
  index.yaml
  bundles/
    <name>/
      <version>/
        skill.yaml
        content/
          ...
```

`search <query>` reads `index.yaml` and returns name/description/version hits.
`add <name>[@version]` copies the selected bundle through the same verification
and install path used by HTTP. `publish <path>` validates and verifies the local
bundle, then writes it under `bundles/<name>/<version>/` and updates
`index.yaml` atomically.

### 4.4 HTTP registry

HTTP registries expose a simple static layout:

```text
GET /index.yaml
GET /bundles/<name>/<version>/skill.yaml
GET /bundles/<name>/<version>/content/<path>
PUT /bundles/<name>/<version>/...
PUT /index.yaml
```

The first implementation uses static YAML index and bundle files instead of a
custom API. Every HTTP URL goes through the core SSRF validator before fetch or
publish. Redirects are handled only through a validator-aware fetch helper; the
implementation must not follow unsafe redirects.

`auth: bearer-from-credstore` means the CLI resolves a bearer token from the
credential store and passes it into the HTTP adapter. The default credential
name is `AGENTENV_SKILLS_<REGISTRY_NAME>_TOKEN`, where the registry name is
uppercased and non-alphanumeric characters become underscores. Config may also
use `auth: bearer-from-credstore:<credential-name>` to name the credential
explicitly. Credential values are not written to the installed index or driver
RPC payloads.

### 4.5 OCI registry

OCI registries use the OCI Distribution API directly through `reqwest` with the
workspace's existing `rustls` TLS posture. No Docker, ORAS, Python, Node,
OpenSSL, or external binary is introduced.

The registry layout is agentenv-specific but OCI-native:

```text
<registry>/<namespace>/skills-index:latest
<registry>/<namespace>/<skill-name>:<version>
```

`skills-index:latest` is an OCI artifact whose config blob contains the
registry search index as YAML. Each skill artifact has:

1. an OCI config blob containing normalized skill metadata
2. one layer for canonical `skill.yaml`
3. one layer per declared bundle file, each annotated with
   `io.agentenv.skill.path`
4. annotations for `org.opencontainers.image.title`,
   `io.agentenv.skill.name`, `io.agentenv.skill.version`,
   `io.agentenv.skill.digest`, and `io.agentenv.skill.signature.ed25519`

`search <query>` pulls the `skills-index:latest` artifact and filters its
entries locally. `add <name>[@version]` resolves through the index, pulls the
selected skill artifact, verifies the manifest, digest, and signature, then
installs it into the local cache. `publish <path>` pushes the skill artifact,
then updates `skills-index:latest` with a compare-and-retry loop using the
current index digest when the registry exposes one.

The first implementation supports bearer tokens resolved from the credential
store. Anonymous reads are allowed when the registry permits them. Challenge
negotiation for every OCI auth variant is not required; unsupported auth
schemes return typed registry-auth errors.

## 5. Resolution Semantics

`skills add <name>[@version]` resolves by:

1. Parsing the handle into name plus optional exact version.
2. Building the registry list from config and any `--registry` override.
3. Searching registries in order.
4. Selecting the exact version if specified.
5. Selecting the highest semantic version if no version is specified.
6. Fetching the bundle into a staging directory.
7. Validating manifest, files, digest, and signature.
8. Moving the verified bundle into the immutable cache path.
9. Updating the installed index atomically.

If multiple registries contain the same name/version, the first registry in
resolution order wins. If a selected version is already installed with the same
digest, the operation is idempotent. If the same name/version is installed with
a different digest, the command fails and tells the user to remove the existing
version first.

## 6. Verification Semantics

Verification has three layers.

### 6.1 Manifest validation

The manifest must have required fields, a valid package name, semantic version,
a relative entry path, and declared files that stay under the bundle root.
Glob-like file patterns are expanded deterministically and sorted
lexicographically. Empty file expansions are errors because a manifest that
claims a file but packages nothing is not reproducible.

### 6.2 Content digest

Core computes a SHA-256 digest over declared files using a canonical byte stream:

```text
agentenv-skill-v1
<relative-path>\0
<file-size-decimal>\0
<file-bytes>
...
```

Relative paths are normalized to `/` separators before hashing. The digest is
rendered as `sha256:<64 lowercase hex>`, matching existing digest conventions in
the repo.

### 6.3 Signature verification

The Ed25519 signature covers:

```text
agentenv-skill-signature-v1
<canonical JSON bytes of normalized manifest without signatures>
<content digest>
```

Registry-installed bundles must have a valid Ed25519 signature. Local
`install --from` may install unsigned bundles only when `--allow-unsigned` is
passed. Filesystem registry installs follow registry semantics and require
signatures unless the command explicitly passes `--allow-unsigned`.

`skills verify <name>` re-runs manifest validation, content digest computation,
signature verification when applicable, and optional `self_test.command` if it
is present. Self-tests execute with the bundle root as the current directory and
must not receive credential environment variables from core.

## 7. Publish Semantics

`skills publish <path> --registry <name-or-url>`:

1. Loads and validates the local bundle.
2. Computes its content digest.
3. Requires a valid signature before publishing to HTTP or OCI registries.
4. Allows unsigned publish only to filesystem registries when the local command
   passes `--allow-unsigned`.
5. Refuses to overwrite an existing name/version with a different digest.
6. Updates the target registry index atomically where the backend supports it.

For HTTP registries, publish uses validator-checked `PUT` requests. For
filesystem registries, publish writes to a temporary directory under the target
registry root, then renames into place. For OCI registries, publish pushes the
OCI artifact and updates the OCI index artifact in the same registry namespace.

## 8. Error Model

Use `thiserror` in `agentenv-core::skills`. Errors should distinguish:

1. invalid manifest
2. invalid skill name
3. invalid semantic version
4. unsafe bundle path
5. missing declared file
6. digest mismatch
7. missing signature
8. invalid signature
9. unsupported registry authentication scheme
10. registry not found
11. skill not found
12. ambiguous installed version
13. already installed with different digest
14. index read/write failure
15. SSRF-blocked registry URL
16. credential reference not available
17. self-test failure

CLI messages should be concise and actionable. JSON output should expose stable
machine fields such as `kind`, `name`, `version`, `registry`, `digest`, and
`verified`.

## 9. Testing Strategy

Follow TDD for each behavior.

### 9.1 Core tests

Add focused tests under `crates/agentenv-core/tests/skills.rs` or inline module
tests:

1. manifest parser accepts a minimal valid manifest
2. manifest parser rejects invalid names
3. manifest parser rejects invalid semantic versions
4. path validation rejects absolute paths and parent traversal
5. file expansion is deterministic
6. digest is stable for sorted declared files
7. digest changes when content changes
8. signature verification accepts a valid Ed25519 signature
9. signature verification rejects tampered content
10. local install writes cache files and index entries
11. repeated install with same digest is idempotent
12. repeated install with different digest fails
13. remove deletes the selected installed version
14. info errors on ambiguous installed versions
15. verify reruns digest and signature checks
16. filesystem registry search/add/publish works
17. HTTP registry search/add/publish uses validated URLs
18. unsafe HTTP registry URLs are rejected before request
19. OCI registry search reads the index artifact
20. OCI registry add pulls and verifies a skill artifact
21. OCI registry publish pushes a skill artifact and updates the index artifact
22. config precedence merges user, project, and CLI registry selection

### 9.2 CLI tests

Add tests under `crates/agentenv/tests/cli_behavior.rs`:

1. top-level help includes `skills`
2. `skills --help` lists every subcommand from issue #28
3. `skills install --from <path> --allow-unsigned` installs a local bundle
4. `skills list --json` returns installed records
5. `skills info <name> --json` reports manifest and digest
6. `skills remove <name> --yes` removes the installed skill
7. `skills verify <name>` succeeds for an untampered installed skill
8. `skills verify <name>` fails after installed content is changed
9. `skills search <query>` reads configured filesystem registries
10. `skills add <name>@<version>` installs from a filesystem registry
11. `skills publish <path> --registry <filesystem-name>` updates registry
12. `--registry` overrides project and user registry order
13. an OCI fixture registry can search, add, and publish through local HTTP

### 9.3 Required verification commands

Run at minimum:

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## 10. Rollout and PR Notes

The PR description should list affected crates: `agentenv` and
`agentenv-core`. It should call out that no driver protocol schema changes were
made. It should also explicitly note that OCI support is implemented directly
through the OCI Distribution API and does not add external runtime dependencies.

The PR should reference issue #28 and mention that issue #27 is already
completed by the architecture decision in `docs/ARCHITECTURE.md`.
