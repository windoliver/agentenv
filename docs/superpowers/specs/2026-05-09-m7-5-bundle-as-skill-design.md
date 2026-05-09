# M7-5 Design: Blueprint To Skill Bundle Emission

- Date: 2026-05-09
- Issue: https://github.com/windoliver/agentenv/issues/31
- Milestone: M7 Skills axis and registry
- Depends on: https://github.com/windoliver/agentenv/issues/27, https://github.com/windoliver/agentenv/issues/29, M4-2 freeze/reproduce
- Affected crates: `agentenv`, `agentenv-core`
- Protocol impact: no driver protocol or schema-version change

## 1. Context And Goals

Issue #31 turns `agentenv` into a producer of portable agent skills. A working
environment can be frozen and emitted as a skill bundle that other agents can
load to reconstruct the same development environment.

The design must satisfy two constraints that now exist in the repository:

1. Issue #28 already implemented the `agentenv skills` lifecycle around a root
   `skill.yaml` manifest. Registry, install, digest, and verification behavior
   depend on that file.
2. Issue #31 asks for an Anthropic-style `SKILL.md` with frontmatter so the
   same artifact is useful to Claude, Gemini CLI, Codex, and other skill
   consumers.

The approved direction is to emit both metadata surfaces from one source of
truth. `skill.yaml` remains the canonical `agentenv` package manifest.
`SKILL.md` carries cross-agent frontmatter and the human instructions for
reconstructing the environment.

The bundle should represent a known-good frozen environment. It should not be a
thin copy of arbitrary `agentenv.yaml` into a skill-shaped directory. The first
implementation therefore exports from an existing environment and uses the
same freeze path that powers `agentenv freeze`.

## 2. Scope And Non-Goals

In scope:

1. Add `agentenv bundle <source> --as-skill --out <dir>` as the skill export
   command.
2. Export from an existing environment, freezing it through the current runtime
   path before writing the bundle.
3. Allow `<source>` to be either an environment name or a project directory
   whose basename or explicit `--env <name>` identifies the environment to
   freeze.
4. Emit a portable skill directory with:

```text
<out>/
|-- SKILL.md
|-- skill.yaml
|-- blueprint.yaml
|-- agentenv.lock
|-- scripts/
|   `-- bootstrap.sh
|-- references/
|   `-- architecture.md
`-- .agentenv/
    |-- manifest.json
    `-- provenance.json
```

5. Keep generated bundles installable through the existing
   `agentenv skills install --from <dir> --allow-unsigned` path.
6. Generate deterministic bundle content except for explicit provenance fields
   such as `created_at`.
7. Record digests for the emitted blueprint, lockfile, bootstrap script, skill
   entrypoint, optional reference document, and bundle metadata.
8. Generate a bootstrap script that uses existing CLI verbs:
   `agentenv verify agentenv.lock` and `agentenv reproduce agentenv.lock`.
9. Add tests for command parsing, output layout, metadata parity, provenance,
   overwrite safety, and install compatibility.

Out of scope:

1. A new driver kind, registry adapter kind, or driver protocol method.
2. Changing existing skill registries from `skill.yaml` to `SKILL.md`
   frontmatter.
3. Snapshotting workspace files, home directories, databases, or event stores.
   That belongs to M6-4 snapshots, not skill bundle export.
4. Publishing the generated bundle to HTTP, OCI, or filesystem registries.
   Existing `agentenv skills publish` handles publishing after export.
5. Signing exported skill bundles. The first slice emits unsigned local bundles
   that can be installed with `--allow-unsigned`.
6. A broad documentation packager. The first slice only includes one selected
   reference document when one is available.
7. Introducing a new `apply` command. The generated instructions should use
   current `freeze` and `reproduce` vocabulary.

## 3. Command Shape

Add a top-level `Bundle(BundleArgs)` command to `crates/agentenv/src/main.rs`
and keep the implementation in a small CLI facade:

```text
agentenv bundle <source> --as-skill --out <dir> [--env <name>] \
  [--name <skill-name>] [--version <semver>] [--description <text>] \
  [--author <text>] [--license <text>] [--tag <tag>]... [--json]
```

Required arguments:

1. `<source>` is an existing environment name or a project directory.
2. `--as-skill` is required for the first implementation. The verb is named
   `bundle` so future bundle forms can share the command, but this issue only
   implements skill emission.
3. `--out <dir>` is required. The command rejects an existing path.

Optional arguments:

1. `--env <name>` disambiguates the environment when `<source>` is a project
   directory.
2. `--name <skill-name>` overrides the generated skill name. It must pass the
   existing `skills::validate_skill_name` rules.
3. `--version <semver>` overrides the skill version. Default: `1.0.0`.
4. `--description <text>` overrides the generated description.
5. `--author <text>` and `--license <text>` override detected metadata.
6. `--tag <tag>` adds tags. Tags are lowercase ASCII identifiers using the
   same character set as skill names, except dots are discouraged but accepted
   for parity with skill names.
7. `--json` prints a machine-readable summary containing output path, skill
   name, version, bundle digest, blueprint digest, and lockfile digest.

Do not add `--force` in the first slice. Refusing existing output keeps the
first implementation simple and avoids deleting user files. A later PR can add
safe replacement semantics after there is a generated-directory marker to
validate.

## 4. Source Resolution

The exporter resolves `<source>` as follows:

1. If `<source>` is not an existing filesystem path, treat it as an environment
   name and freeze that environment.
2. If `<source>` is a directory and `--env <name>` is provided, freeze that
   environment and use the directory only for metadata detection and reference
   document discovery.
3. If `<source>` is a directory and no `--env` is provided, derive the
   environment name from the directory basename and freeze that environment.
4. If the derived or explicit environment does not exist, fail with an error
   that tells the user to run `agentenv create <name> --blueprint <path>` and
   then retry the bundle command.

This preserves the issue's example shape:

```text
agentenv bundle ./myapp --as-skill --out ./myapp-skill/
```

after the user has materialized an environment named `myapp`.

The bundle source model has two outputs:

1. Frozen runtime state from `agentenv_core::runtime::freeze_env_lockfile`.
2. Optional project metadata from the project directory, such as git author,
   license, README, or `docs/ARCHITECTURE.md`.

Project metadata must never replace the frozen runtime state. If the project
directory's `agentenv.yaml` differs from the persisted environment blueprint,
the command emits a warning and writes the frozen environment blueprint.

## 5. Core Architecture

Add `agentenv_core::bundle` with these focused responsibilities:

1. `model` defines serializable bundle inputs, outputs, manifest JSON, and
   provenance JSON.
2. `metadata` normalizes skill names, versions, descriptions, tags, author, and
   license.
3. `writer` creates the output layout in a staging directory, writes files, and
   atomically publishes the final directory.
4. `references` selects at most one source document for
   `references/architecture.md`.
5. `digest` computes `sha256:<hex>` digests for emitted files and directories.

The CLI owns source resolution and optional git metadata detection because it
already depends on local process context. Core owns deterministic rendering and
validation. Core errors use `thiserror`; the CLI wraps them with `anyhow`
context.

The core entrypoint should be shaped like this:

```rust
pub struct SkillBundleInput {
    pub source: BundleSource,
    pub metadata: SkillBundleMetadata,
    pub blueprint_yaml: String,
    pub lockfile_yaml: String,
    pub reference_document: Option<ReferenceDocument>,
    pub output_dir: PathBuf,
}

pub struct SkillBundleOutput {
    pub output_dir: PathBuf,
    pub skill_name: String,
    pub version: String,
    pub bundle_digest: String,
    pub blueprint_digest: String,
    pub lockfile_digest: String,
}

pub fn emit_skill_bundle(input: SkillBundleInput) -> Result<SkillBundleOutput, BundleError>;
```

The runtime layer should expose a small helper for the CLI to obtain frozen
source material from an environment:

```rust
pub struct FrozenEnvBundleSource {
    pub env_name: String,
    pub blueprint_yaml: String,
    pub lockfile_yaml: String,
}

pub fn freeze_env_for_bundle(
    options: &RuntimeOptions,
    name: &str,
) -> RuntimeResult<FrozenEnvBundleSource>;
```

`freeze_env_for_bundle` should reuse the same validation as
`freeze_env_lockfile` and return the persisted environment blueprint alongside
the deterministic portable lockfile.

## 6. Output Files

### 6.1 `SKILL.md`

`SKILL.md` is the skill entrypoint and contains frontmatter plus concise
instructions:

````markdown
---
name: myapp
description: Reproducible dev env for myapp - Rust + Postgres + Redis
version: 1.0.0
author: Alice Example
license: MIT
tags: [rust, postgres, redis, dev-env]
agentenv-bundle: true
agentenv-schema: "0.1"
---

# myapp

This skill reconstructs the `myapp` development environment with `agentenv`.

## Bootstrap

Run this from the skill directory:

```bash
scripts/bootstrap.sh
```

The script verifies `agentenv.lock` and reproduces the environment with:

```bash
agentenv verify agentenv.lock
agentenv reproduce agentenv.lock --name myapp
```

## Included Files

- `blueprint.yaml` is the frozen blueprint used to create the environment.
- `agentenv.lock` pins drivers, artifacts, policy, and credential references.
- `references/architecture.md` contains copied project architecture notes when available.
````

`author`, `license`, and `tags` are omitted from frontmatter when no value is
available. The boolean `agentenv-bundle` and string `agentenv-schema` fields
are always present.

### 6.2 `skill.yaml`

`skill.yaml` keeps compatibility with the existing skills package code:

```yaml
name: myapp
version: 1.0.0
description: Reproducible dev env for myapp - Rust + Postgres + Redis
entry: SKILL.md
files:
  - SKILL.md
  - blueprint.yaml
  - agentenv.lock
  - scripts/**
  - .agentenv/**
  - references/**
agentenv_bundle: true
agentenv_schema: "0.1"
```

If no reference document is emitted, omit `references/**` from `files`. This is
required because the existing manifest parser rejects empty glob matches.

The following fields must be generated from the same `SkillBundleMetadata`
value in both `SKILL.md` and `skill.yaml`:

1. name
2. version
3. description
4. tags when present
5. `agentenv` schema marker

### 6.3 `blueprint.yaml`

`blueprint.yaml` is the environment blueprint that corresponds to the frozen
lockfile. It is copied from persisted runtime state, not from the source
project directory. This prevents drift when the project file has changed since
the environment was created.

The writer must normalize the file with a trailing newline and must not perform
credential interpolation. Credential values remain absent because persisted
blueprints and portable lockfiles store references, not secrets.

### 6.4 `agentenv.lock`

`agentenv.lock` is the deterministic YAML returned by the existing portable
lockfile path. The exporter verifies it with
`portable_lockfile::verify_portable_lockfile_yaml` before writing output.

The file name is `agentenv.lock` because it is the committed project artifact
and the existing `reproduce` command accepts any lockfile path.

### 6.5 `scripts/bootstrap.sh`

The bootstrap script is POSIX shell:

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_NAME="${AGENTENV_ENV_NAME:-myapp}"

cd "${BUNDLE_DIR}"
agentenv verify agentenv.lock
agentenv reproduce agentenv.lock --name "${ENV_NAME}"
```

On Unix, set mode `0o755`. On Windows, write the same file without relying on
the executable bit.

### 6.6 `references/architecture.md`

When the source is a project directory, select the first existing file in this
order:

1. `docs/ARCHITECTURE.md`
2. `ARCHITECTURE.md`
3. `README.md`

Copy it to `references/architecture.md` with a short generated header that
records the source relative path. If none exist, omit `references/` and omit
`references/**` from `skill.yaml`.

The exporter must not copy arbitrary project files. Skill export packages
instructions and reproducibility metadata, not source code.

### 6.7 `.agentenv/manifest.json`

`manifest.json` is the deterministic inventory for generated bundle content,
excluding `.agentenv/provenance.json` to avoid timestamp churn.

```json
{
  "version": "0.1",
  "kind": "agentenv.skill_bundle",
  "skill": {
    "name": "myapp",
    "version": "1.0.0",
    "entry": "SKILL.md"
  },
  "agentenv": {
    "schema": "0.1",
    "bundle": true
  },
  "files": [
    {"path": "SKILL.md", "sha256": "sha256:..."},
    {"path": "skill.yaml", "sha256": "sha256:..."},
    {"path": "blueprint.yaml", "sha256": "sha256:..."},
    {"path": "agentenv.lock", "sha256": "sha256:..."},
    {"path": "scripts/bootstrap.sh", "sha256": "sha256:..."},
    {"path": "references/architecture.md", "sha256": "sha256:..."}
  ]
}
```

Files are listed in lexicographic path order. Paths are slash-separated,
relative, UTF-8, and cannot contain `..`.

### 6.8 `.agentenv/provenance.json`

`provenance.json` records how the bundle was produced:

```json
{
  "version": "0.1",
  "created_at": "2026-05-09T00:00:00Z",
  "agentenv_version": "0.0.1-alpha0",
  "source": {
    "kind": "environment",
    "env_name": "myapp",
    "project_path": "/abs/path/myapp",
    "project_git_commit": "abc123",
    "project_git_dirty": false
  },
  "digests": {
    "blueprint": "sha256:...",
    "lockfile": "sha256:...",
    "manifest": "sha256:..."
  }
}
```

`project_path`, `project_git_commit`, and `project_git_dirty` are omitted when
they are unavailable. Do not write fallback strings such as `unknown`.

## 7. Metadata Detection

Defaults:

1. Skill name defaults to the environment name, normalized through
   `validate_skill_name`. Invalid generated names require `--name`.
2. Version defaults to `1.0.0`.
3. Description defaults to `Reproducible dev env for <name>`.
4. Tags default to detected driver names and selected blueprint attributes:
   sandbox driver, agent driver, context driver, inference driver when present,
   and `dev-env`.

Project directory detection:

1. Author comes from `git config user.name` in the source repository.
2. License comes from package metadata when obvious, in this order:
   root `Cargo.toml` package or workspace `license`, then a conventional
   `LICENSE` file name whose stem is a known SPDX identifier.
3. Git commit comes from `git rev-parse HEAD`.
4. Dirty state comes from `git status --porcelain`.

Detection failures are non-fatal. Omit unavailable optional fields instead of
writing fallback values.

## 8. Security And Safety

Credential handling:

1. The exporter writes the portable lockfile credential requirements and
   references that `freeze` already emits.
2. It must not read credential values from `agentenv-credstore`.
3. It must not copy sandbox home directories, host home directories, or
   arbitrary workspace files.

Filesystem safety:

1. Reject an output path that already exists.
2. Write to a staging directory next to the target and atomically rename after
   validation succeeds.
3. Reject symlinks in the output path ancestry when creating the staging and
   final directories.
4. Use existing skill bundle path validation rules before computing the final
   bundle digest.

Network safety:

1. The exporter does not fetch remote content.
2. It does not publish to registries.
3. It does not contact GitHub or other services during bundle creation.

## 9. Validation Flow

After writing the staging directory, validate it before publishing:

1. Load `skill.yaml` with `skills::load_skill_manifest`.
2. Compute `skills::compute_bundle_digest` over the generated bundle.
3. Verify `agentenv.lock` with `portable_lockfile::verify_portable_lockfile_yaml`.
4. Confirm the manifest inventory digests match the generated files.
5. Confirm `SKILL.md` frontmatter and `skill.yaml` agree on name, version,
   description, tags, and schema marker.
6. Confirm `scripts/bootstrap.sh` references `agentenv verify` and
   `agentenv reproduce`.

If validation fails, remove the staging directory and leave no final output
path.

## 10. Error Handling

Expected user-facing errors:

1. Missing `--as-skill`: `bundle currently supports only --as-skill`.
2. Missing `--out`: `bundle --as-skill requires --out <dir>`.
3. Existing output path: `output path already exists`.
4. Missing source environment: `environment '<name>' does not exist; create it before bundling`.
5. Invalid generated skill name: `derived skill name '<name>' is invalid; pass --name`.
6. Lockfile verification failure: include the portable lockfile verifier's
   error details.
7. Reference document read failure: include the selected source path.

Warnings:

1. Project `agentenv.yaml` differs from the frozen environment blueprint.
2. Metadata fields such as author or license could not be detected.

Warnings should print to stderr in text mode and appear in the `warnings` array
for `--json`.

## 11. Testing Strategy

Core tests in `crates/agentenv-core/tests/bundle.rs`:

1. `emit_skill_bundle_writes_expected_layout`
2. `emit_skill_bundle_omits_references_when_no_document_exists`
3. `emit_skill_bundle_keeps_skill_yaml_and_frontmatter_in_sync`
4. `emit_skill_bundle_rejects_existing_output_path`
5. `emit_skill_bundle_records_blueprint_lockfile_and_manifest_digests`
6. `emit_skill_bundle_validates_with_existing_skill_manifest_loader`

CLI tests in `crates/agentenv/tests/cli_behavior.rs`:

1. `bundle_help_lists_as_skill_and_out_flags`
2. `bundle_as_skill_rejects_missing_env`
3. `bundle_as_skill_exports_existing_env`
4. `bundle_as_skill_json_reports_digest_summary`
5. `bundle_as_skill_output_installs_as_local_skill`

The CLI export test can create a minimal environment using the existing test
runtime helpers, freeze it, export the bundle, and run:

```text
agentenv skills install --from <bundle-dir> --allow-unsigned --json
agentenv skills verify <skill-name> --json
```

Required final verification for the PR:

```text
cargo fmt
cargo clippy --workspace -- -D warnings
cargo test -p agentenv-core --test bundle
cargo test -p agentenv --test cli_behavior bundle
cargo test --workspace
```

## 12. Implementation Plan Shape

The implementation plan should split work into these commits:

1. Add core bundle models and deterministic writer tests.
2. Add `freeze_env_for_bundle` runtime helper and source resolution tests.
3. Wire `agentenv bundle --as-skill` CLI and help behavior.
4. Add metadata detection and reference document selection.
5. Add end-to-end CLI tests proving install compatibility.
6. Update docs and issue references.

Each commit should keep the CLI facade thin and preserve existing skills
registry behavior.

## 13. Trade-Offs

Keeping `skill.yaml` avoids breaking the skills cache, registry adapters, and
install verification that already exist. Adding `SKILL.md` frontmatter gives
cross-agent consumers the portable surface requested by issue #31.

Exporting from an existing environment makes the command stricter than a pure
`agentenv.yaml` packager. That is intentional: a produced skill should mean
the environment has already gone through the same lifecycle that `freeze` and
`reproduce` trust.

The first slice omits signing because local unsigned installs are already a
supported workflow and because signing policy should be handled consistently
across all skill publishing paths, not only bundle export.
