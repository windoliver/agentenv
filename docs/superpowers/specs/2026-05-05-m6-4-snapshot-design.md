# M6-4 Design: Env Snapshot And Safe Migration

- Date: 2026-05-05
- Issue: https://github.com/windoliver/agentenv/issues/26
- Milestone: M6 Day-2 operations
- Depends on: M4-2 freeze/reproduce and M6-1 events/audit
- Affected crates: `agentenv-core`, `agentenv`, `agentenv-events`
- Related crates consumed but not redesigned: `agentenv-proto`, `agentenv-credstore`, `agentenv-policy`

## 1. Context And Goals

Issue #26 extends `agentenv freeze` from portable composition to portable state.
`freeze` already writes a lockfile that can reproduce the selected drivers,
blueprint, artifact digests, policy, and credential references. `snapshot`
adds the runtime state needed for backup, disaster recovery, migration, and
audit takeout:

1. the frozen blueprint and portable lockfile
2. the current workspace tree
3. the persisted home tree when `state.persist_home: true`
4. the per-env event and audit SQLite database
5. the resolved policy
6. a manifest, digest tree, Merkle root, and Ed25519 signature

The security constraint is stronger than the portability constraint:
credentials must never be bundled. Restore prompts or resolves credentials
again through the existing credential provider path.

## 2. Scope For The First Slice

The first PR should implement a reviewable vertical slice:

1. `agentenv snapshot <env> [--output <path>]`
2. `agentenv snapshot verify <path>`
3. `agentenv snapshot restore <path> [--as <new-name>]`
4. an unpacked `.agentenvsnap` directory format
5. manifest inventory, per-file digests, Merkle root, and Ed25519 signature
6. credential stripping and fail-closed leaked-secret detection
7. restore through the existing portable `reproduce` runtime path
8. tests for tamper detection, signature failure, credential stripping, and
   credential re-resolution

Out of scope for the first PR:

1. compressed archive packaging
2. `agentenv snapshot diff <a> <b>`
3. `agentenv snapshot export --audit`
4. scheduled snapshots, retention, and remote destinations
5. a new driver protocol method
6. remote trust distribution for signing keys

This keeps the first implementation anchored in the existing lifecycle and
driver contract. The existing `SandboxDriver::copy_out` and
`SandboxDriver::copy_in` methods are enough for workspace and home movement.

## 3. Snapshot Directory Format

The first slice writes an unpacked directory:

```text
myenv-2026-05-05T120000Z.agentenvsnap/
├── manifest.json
├── blueprint.yaml
├── lock.yaml
├── workspace/
├── home/
├── events.db
├── policy.yaml
├── signatures.json
└── NOTES.md
```

`workspace/` is required for a successful first-slice snapshot because the
feature is stateful backup, not metadata-only export. `home/` is present only
when the blueprint state requests persisted home. `events.db` is present when
the per-env SQLite store exists. `NOTES.md` is reserved for a later CLI flag
and is verified like any other file if present.

The first slice should reject an output path that already exists. Later archive
packaging can wrap the same directory model in tar or zstd without changing the
manifest schema.

## 4. Manifest Model

`manifest.json` is the authoritative inventory. It should be deterministic
apart from timestamps and source env identity.

```json
{
  "version": "0.1.0",
  "agentenv_version": "0.0.1-alpha0",
  "source_env": "myenv",
  "created_at": "2026-05-05T12:00:00Z",
  "min_agentenv_version": "0.0.1-alpha0",
  "driver_protocol_version": "1.1",
  "sections": {
    "blueprint": {"path": "blueprint.yaml", "sha256": "sha256:..."},
    "lockfile": {"path": "lock.yaml", "sha256": "sha256:..."},
    "workspace": {"path": "workspace", "sha256": "sha256:...", "kind": "directory"},
    "home": {"path": "home", "sha256": "sha256:...", "kind": "directory"},
    "events": {"path": "events.db", "sha256": "sha256:..."},
    "policy": {"path": "policy.yaml", "sha256": "sha256:..."}
  },
  "files": [
    {
      "path": "workspace/src/main.rs",
      "kind": "file",
      "mode": "file",
      "size": 1234,
      "sha256": "sha256:..."
    }
  ],
  "credential_requirements": [
    {"name": "OPENAI_API_KEY", "source": "env", "reference": "OPENAI_API_KEY", "required": true}
  ],
  "stripped": [
    {"path": "home/.codex/credentials.json", "reason": "credential_path"}
  ],
  "merkle_root": "sha256:..."
}
```

Inventory rules:

1. Paths are relative, UTF-8, slash-separated, and cannot contain `..`.
2. Regular files are hashed by bytes.
3. Directories are hashed from sorted child entries.
4. Symlinks are stored as symlink metadata and target text; the snapshotter does
   not follow symlinks while inventorying.
5. Manifest and signature files are not part of the payload Merkle tree. The
   signature covers the manifest hash and the payload Merkle root.
6. Section digests are derived from their payload tree roots.
7. File order is lexicographic by normalized relative path.
8. Verification rejects extra payload files that are not listed in the
   manifest.

## 5. Signing And Verification

`signatures.json` stores:

```json
{
  "version": "0.1.0",
  "signature_algorithm": "ed25519",
  "hash_algorithm": "sha256",
  "public_key": "<hex>",
  "manifest_sha256": "sha256:...",
  "merkle_root": "sha256:...",
  "signature": "<hex>"
}
```

Snapshot creation signs a canonical manifest-hash plus Merkle-root message
with a local snapshot signing key under the agentenv root. The implementation
may reuse the hardened file-permission checks from `agentenv-events::audit`,
but snapshot signing should have a separate key path from the audit log so a
snapshot workflow cannot mutate audit trust state.

The signed message is a canonical JSON object containing
`manifest_sha256` and `merkle_root`. Signing both values prevents an attacker
from changing credential requirements, stripped-file records, version fields,
or section metadata without invalidating the signature.

`snapshot verify` performs these checks in order:

1. parse `manifest.json` and `signatures.json` with unknown-field denial
2. validate schema, version, relative paths, and digest formats
3. verify every payload file and symlink digest
4. recompute section tree roots
5. recompute the manifest Merkle root
6. compare the recomputed root to `manifest.merkle_root`
7. compare the manifest root to `signatures.json.merkle_root`
8. compute the `manifest.json` SHA-256 and compare it to
   `signatures.json.manifest_sha256`
9. verify the Ed25519 signature over the canonical signed message
10. verify `lock.yaml` through existing portable lockfile verification
11. verify `policy.yaml` parses as the pinned resolved policy
12. fail on minimum agentenv or driver protocol incompatibility

This first slice proves integrity and accidental tamper detection. A future
remote backup flow can add trusted-key pinning and signer identity policy.

## 6. Credential Stripping

Snapshot creation must never write credential material into the snapshot
directory. It should copy into a staging directory, sanitize there, scan the
result, then move sanitized content into the final snapshot.

The sanitizer has two modes:

1. **Path exclusion** removes files and directories that are known credential
   stores.
2. **Content redaction** rewrites structured and text files where the secret can
   be removed safely.

Credential paths to exclude:

1. `*/.agentenv/credentials*`
2. `*/.codex/credentials*`
3. `*/.claude/credentials*`
4. `*/.openclaw/credentials*`
5. `*/.config/gh/hosts.yml`
6. any path component named `.aws` that contains `credentials`
7. any path whose basename starts with `credentials`

Deny patterns to detect after redaction:

1. OpenAI-style `sk-` tokens
2. Anthropic-style `sk-ant-` tokens
3. GitHub `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, and `github_pat_` tokens
4. AWS `AKIA` and `ASIA` access key IDs
5. Slack `xoxb-`, `xoxp-`, and `xapp-` tokens
6. generic webhook secret key names paired with non-empty values
7. MCP token keys paired with non-empty values
8. Nexus token keys paired with non-empty values

Structured JSON and YAML redaction should redact secret-like keys before the
final scan. Other text formats are treated as text and scanned with deny
patterns rather than introducing another parser. Secret-like key names include
`token`, `secret`, `password`, `api_key`, `apikey`, `authorization`,
`credential`, and provider-specific variants. Existing
`agentenv-events::redaction` can be reused or promoted into a more general
helper, but tests must cover filesystem snapshot use directly.

If the post-redaction scan still matches a deny pattern, snapshot creation
fails and removes the staging snapshot directory. Error messages include only
relative paths and pattern class names, not matched secret text.

## 7. Snapshot Creation Flow

`agentenv snapshot <env> [--output <path>]` runs:

1. validate env name and load `state.json`, `blueprint.yaml`, and `lock.yaml`
2. verify the persisted lockfile with existing portable verification
3. initialize the selected sandbox driver from persisted state
4. require a sandbox handle for stateful workspace/home capture
5. copy `/sandbox` from the sandbox to a temporary staging directory with
   `SandboxDriver::copy_out`
6. when `state.persist_home: true`, resolve `$HOME` inside the sandbox through
   `SandboxDriver::exec` and copy that path out with `copy_out`
7. copy `blueprint.yaml`, `lock.yaml`, `events.db`, and rendered `policy.yaml`
   from the env registry
8. run credential path exclusion and content redaction over staged payloads
9. run a final deny-pattern scan over every staged payload file
10. build deterministic inventory and manifest
11. compute the Merkle root
12. hash the manifest and sign the canonical manifest-hash plus Merkle-root
    message
13. move the complete staging directory to the requested output path

The default output path is `<env>-<timestamp>.agentenvsnap` in the current
directory. `--output -` is not supported for snapshots because the first slice
uses an unpacked directory.

## 8. Restore Flow

`agentenv snapshot restore <path> [--as <new-name>]` runs:

1. verify the snapshot
2. choose the target env name from `--as`, then `manifest.source_env`
3. reject if the target env already exists
4. resolve all `manifest.credential_requirements` through the existing
   credential provider path
5. fail before resource creation if a required credential is missing
6. call existing runtime reproduce using the snapshot `lock.yaml`
7. copy `workspace/` into `/sandbox` with `SandboxDriver::copy_in`
8. when `home/` exists, resolve `$HOME` in the restored sandbox and copy the
   sanitized home payload into that path with `copy_in`
9. persist `policy.yaml` as the restored resolved policy
10. leave credentials absent from the restored filesystem

Restore should not trust `workspace/` or `home/` until verification succeeds.
Restore should not create the env until credentials have been resolved. This
preserves the current credential rule: values come from env vars, keyring, or
interactive prompt, never from portable artifacts.

## 9. CLI Shape

The first slice adds a `Snapshot` subcommand under the existing Clap CLI:

```text
agentenv snapshot <env> [--output <path>]
agentenv snapshot verify <path>
agentenv snapshot restore <path> [--as <new-name>]
```

This deliberately mirrors env-manager verbs instead of orchestration verbs.
`snapshot diff` and `snapshot export --audit` remain documented follow-up
commands because they are useful only after the snapshot data model is stable.

CLI output should be concise:

1. create prints the snapshot path and Merkle root
2. verify prints the snapshot path, file count, Merkle root, and signature status
3. restore prints the new env name and source snapshot path
4. errors identify failing relative paths without exposing matched secret text

## 10. Crate Boundaries

`agentenv-core::snapshot` owns:

1. manifest and signature structs
2. inventory walking
3. tree digest and Merkle root calculation
4. path validation
5. sanitizer and deny-pattern scanner
6. create, verify, and restore planning primitives
7. typed `SnapshotError` with `thiserror`

`agentenv-core::runtime` owns:

1. driver initialization from persisted state
2. sandbox `copy_out`, `copy_in`, and `$HOME` resolution helpers
3. calling reproduce for restore
4. using env registry paths for lockfile, blueprint, events, and policy

`agentenv-events` may expose a small reusable redaction helper if snapshot
sanitization needs the same structured redaction rules as events. Do not put
snapshot domain logic in `agentenv-events`.

`agentenv` owns:

1. CLI parsing
2. output rendering
3. converting errors into `anyhow` context
4. wiring the existing credential provider into restore

No driver protocol schemas change in this slice. If a future driver offers a
native snapshot capability, that should be a separate protocol design and
schema-version discussion.

## 11. Testing Strategy

Core tests:

1. manifest inventory is deterministic for identical trees
2. Merkle root changes when a payload file changes
3. verification detects a changed payload file
4. verification detects a changed `signatures.json` signature
5. verification rejects absolute paths and `..` paths in manifest entries
6. credential path exclusion removes known credentials files
7. content redaction removes structured secret-like fields
8. deny-pattern scan rejects leaked `sk-`, `ghp_`, `github_pat_`, and `AKIA`
   fixtures
9. error messages never contain the injected secret values
10. restore planning refuses missing required credentials before env creation
11. restore planning accepts credentials resolved from env or credstore

Runtime tests:

1. snapshot creation uses `copy_out` for `/sandbox`
2. persisted home is copied only when `state.persist_home: true`
3. snapshot creation removes staging output on sanitizer failure
4. restore calls reproduce before `copy_in`
5. restore copies workspace and home only after successful verification
6. restored `describe` output matches the source except credentials, host paths,
   snapshot timestamps, and sandbox handles

CLI tests:

1. `snapshot <env> --output <dir>` writes an unpacked snapshot directory
2. `snapshot verify <dir>` reports success for an untampered snapshot
3. `snapshot verify <dir>` reports failure after tampering
4. `snapshot restore <dir> --as <name>` rejects missing credentials without
   creating the target env
5. secret-looking fixtures do not appear in stdout or stderr

Verification commands for the implementation PR:

```bash
cargo fmt
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## 12. Acceptance Mapping

This first slice satisfies or partially satisfies the issue acceptance criteria:

1. `.agentenvsnap` format is spec'd and documented: satisfied by this design and
   follow-up CLI docs.
2. Signed and hash-chained end to end: satisfied for unpacked snapshot
   directories.
3. Credential stripping covers declared patterns: satisfied by sanitizer and
   injected-secret tests.
4. `verify` detects tampering and wrong signatures: satisfied.
5. Version mismatch detection: satisfied for agentenv and driver protocol
   minimums.
6. Restore re-prompts for credentials and refuses to proceed without them:
   satisfied through the existing credential provider path.
7. Round-trip snapshot/destroy/restore compare: satisfied for workspace,
   persisted home, lockfile, policy, and describe normalization.
8. Scheduled snapshots with local destination: deferred to the next slice.

## 13. Risks And Trade-Offs

The unpacked directory format is easier to review and test than a compressed
archive, but it is less convenient to move as one file. The manifest and Merkle
tree are designed so a later packaging layer can be added without changing
restore semantics.

The first slice uses generic sandbox `copy_out` and `copy_in` instead of a new
snapshot driver method. That avoids a protocol bump and keeps the narrow waist
stable. The trade-off is that state capture depends on known sandbox paths:
`/sandbox` for workspace and `$HOME` for persisted home.

Signature verification proves payload integrity and catches tampering relative
to the stored public key. It does not by itself establish organizational trust
in the signer. Trusted signer policy belongs with remote backup and federation
work, not this first local snapshot slice.
