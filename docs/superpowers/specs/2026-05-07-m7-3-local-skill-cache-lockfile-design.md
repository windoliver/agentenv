# M7-3 Local Skill Cache And Lockfile Design

## Context

Issue: https://github.com/windoliver/agentenv/issues/29

M7-1 decided that skills are a core-managed resource, not a `ContextDriver`
sub-kind and not a fifth pluggable axis. This design implements the local
cache and lockfile slice of that decision. Registry backends, publishing, and
runtime MCP skill discovery remain separate M7 issues.

## Goals

- Define a deterministic local cache layout for installed skill versions.
- Store content-addressed skill archives so identical artifacts dedupe across
  registries.
- Record installed skills in a deterministic `index.json`.
- Extend portable lockfiles with exact skill pins.
- Support `agentenv skills prune` for unreferenced archive cleanup.
- Support `agentenv skills verify --all` with real local validation:
  manifest validation, digest checks, signature checks, and declared self-tests.

## Non-Goals

- Do not add a `SkillsDriver` or any driver-protocol method.
- Do not implement registry search, add, publish, or registry backends.
- Do not remove extracted installed skill versions during prune.
- Do not implement full sandboxed agent regression from M7-7; this design
  leaves a compatible self-test metadata shape and implements local assertions.

## Affected Crates

- `crates/agentenv-core`: local skill cache, metadata types, verification,
  prune planning, and portable lockfile skill pins.
- `crates/agentenv`: CLI plumbing for `agentenv skills verify --all` and
  `agentenv skills prune`.
- `crates/agentenv-core/tests` and `crates/agentenv/tests`: cache, lockfile,
  verification, prune, and CLI coverage.

## Local Layout

The cache root is the existing agentenv root, normally `~/.agentenv`.

```text
~/.agentenv/
├── skills/
│   ├── <name>/
│   │   ├── <version>/
│   │   │   ├── SKILL.md
│   │   │   ├── .agentenv/
│   │   │   │   ├── manifest.json
│   │   │   │   └── provenance.json
│   │   │   └── <skill contents>
│   │   └── current -> <version>
│   └── index.json
└── cache/
    └── skills/
        └── <sha256>.tar.zst
```

`SkillCacheLayout` owns all path construction. It rejects skill names,
versions, and digest keys that would escape the cache root or collide with
reserved entries such as `index.json`.

The content-addressed archive filename is the lowercase SHA-256 hex digest
without the `sha256:` prefix. The manifest stores the digest with the prefix.

## Metadata

Each installed skill version has `.agentenv/manifest.json`:

```json
{
  "schema_version": "0.1",
  "name": "code-review",
  "version": "1.2.0",
  "source": "oci://ghcr.io/agentenv-community/code-review:1.2.0",
  "digest": "sha256:abc123...",
  "signatures": ["ed25519:..."],
  "archive": {
    "digest": "sha256:abc123...",
    "cache_key": "abc123....tar.zst"
  },
  "self_test": {
    "timeout_seconds": 120,
    "assertions": [
      { "type": "command_exits_zero", "cmd": "cargo test" },
      { "type": "file_exists", "path": "SKILL.md" }
    ]
  }
}
```

`provenance.json` records a structured attestation chain:

```json
{
  "schema_version": "0.1",
  "subject": {
    "name": "code-review",
    "version": "1.2.0",
    "digest": "sha256:abc123..."
  },
  "attestations": []
}
```

Both files use `deny_unknown_fields` so verification fails on misspelled or
future fields. Future registry issues can add fields only through explicit
schema changes.

`skills/index.json` is a flat deterministic index:

```json
{
  "schema_version": "0.1",
  "skills": [
    {
      "name": "code-review",
      "version": "1.2.0",
      "source": "oci://ghcr.io/agentenv-community/code-review:1.2.0",
      "digest": "sha256:abc123...",
      "current": true,
      "path": "skills/code-review/1.2.0"
    }
  ]
}
```

The index is derived data. Install, remove, verify, and prune flows may rebuild
it by scanning installed manifests, sorting by `(name, version)`, and writing
stable JSON.

## Lockfile Entries

Portable lockfiles gain a top-level `skills` collection. YAML is used to match
the existing lockfile format.

```yaml
skills:
  - name: code-review
    version: 1.2.0
    source: oci://ghcr.io/agentenv-community/code-review:1.2.0
    digest: sha256:abc123...
    signatures:
      - ed25519:...
```

The lockfile validator parses each digest with the existing SHA-256 parser and
sorts skill pins deterministically by `(name, version, source)`. A lockfile with
duplicate `(name, version, source)` skill pins is invalid.

Freeze records installed skills selected by the resolved composition. Until the
M7-2/M7-4 install and registry work lands, tests can build lockfiles directly
with skill pins and runtime code can verify local cache availability for those
pins during reproduce.

## Verification

`agentenv skills verify --all` scans every installed skill version under
`~/.agentenv/skills`.

For each skill, verification:

1. Parses `SKILL.md` frontmatter and requires `name` and `version`.
2. Parses `.agentenv/manifest.json` and `.agentenv/provenance.json`.
3. Verifies that path, `SKILL.md`, manifest, and provenance agree on name,
   version, and digest.
4. Verifies the content-addressed archive exists and its SHA-256 digest matches
   `manifest.digest`. If the archive is missing, verification recomputes a
   deterministic tree digest for the extracted skill directory and reports that
   archive verification is unavailable.
5. Verifies every listed Ed25519 signature over the pinned digest using
   configured trust keys. If signatures are listed and no matching trust key is
   configured, verification fails.
6. Runs declared local self-test assertions with a timeout.

Supported local self-test assertions for this issue:

- `file_exists`: path must exist inside the installed skill directory.
- `command_exits_zero`: command runs with the installed skill directory as the
  working directory and must exit successfully before the timeout.

The report includes one status per installed skill version and exits non-zero if
any skill fails. Verification does not mutate installed content except for
rewriting `index.json` from successfully scanned metadata.

## Prune

`agentenv skills prune` removes only unreferenced content-addressed archives
under `~/.agentenv/cache/skills`.

References come from:

- Installed `.agentenv/manifest.json` archive digests.
- Local environment lockfiles managed by the runtime state backend.
- Explicit lockfile paths if the CLI later grows a `--lockfile` option.

The prune planner returns a deterministic list of archive paths to delete. The
CLI supports `--dry-run`; without it, the CLI deletes the planned archive files
and prints a concise summary. Prune never deletes extracted installed skill
directories. That behavior belongs to `agentenv skills remove` from M7-2.

After a successful prune, `index.json` is rebuilt from installed manifests.

## Error Handling

Core exposes typed errors through `thiserror`:

- invalid cache path input
- missing `SKILL.md`
- invalid skill frontmatter
- manifest/provenance parse failure
- name/version/digest mismatch
- archive digest mismatch
- missing trust key for listed signature
- invalid signature
- self-test command failure
- self-test timeout
- prune delete failure

The CLI maps verify failures to non-zero exit with per-skill diagnostics. Prune
delete failures abort the command after reporting the failed path.

## Testing

Core tests cover:

- deterministic layout paths and path traversal rejection
- deterministic `index.json` ordering
- manifest/provenance parsing with unknown-field rejection
- portable lockfile serialization and validation with skill pins
- duplicate skill pin rejection
- archive digest success and mismatch failure
- extracted tree digest fallback when archive is missing
- Ed25519 signature success and failure using generated test keys
- missing trust key failure when signatures are listed
- `file_exists` self-test pass/fail
- `command_exits_zero` self-test pass/fail/timeout
- prune keeps referenced archives and removes only unreferenced archives

CLI tests cover:

- `agentenv skills verify --all` exits zero for a valid cache
- `agentenv skills verify --all` exits non-zero for a broken skill
- `agentenv skills prune --dry-run` prints planned deletions without deleting
- `agentenv skills prune` deletes only planned unreferenced archive files

Required final checks for implementation:

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Risks And Trade-Offs

Implementing signature and local self-test verification in M7-3 makes the issue
larger, but it prevents `verify --all` from becoming a stub. Keeping
the self-test runner local and assertion-based avoids pulling the M7-7 sandboxed
functional regression scope forward.

Using a dedicated `agentenv-core::skills` module adds a new core surface, but it
keeps skill cache behavior out of the already large runtime and lockfile modules.
The module remains core-managed resource code, not a pluggable driver axis.
