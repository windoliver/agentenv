# M7-7 Skill Self-Test Gate Design

- Date: 2026-05-12
- Issue: https://github.com/windoliver/agentenv/issues/33
- Milestone: M7 Skills axis and registry
- Depends on:
  - https://github.com/windoliver/agentenv/issues/27
  - https://github.com/windoliver/agentenv/issues/28
- Related:
  - https://github.com/windoliver/agentenv/issues/29
  - https://github.com/windoliver/agentenv/issues/30
  - M7-10 four-tier CI
- Affected crates: `agentenv-core`, `agentenv`
- Protocol impact: no driver protocol or schema-version change

## Context

Skills are already core-managed artifacts. The current code has the first
skills CLI, registry adapters, install/verify/publish paths, local cache
metadata, and a basic `self_test.command` verifier for installed skills.

Issue #33 raises the bar from "a skill can declare a local command" to "no
skill can be installed locally or published to a registry unless a functional
self-test proves the artifact is reproducible enough." The full PR needs to
cover local verification, publish gating, score interpretation, and signed
attestation material that a hub publish API can enforce.

This remains core skill lifecycle work. It does not add a fifth pluggable axis,
does not add `SkillsDriver`, and does not change the JSON-RPC driver protocol.

## Goals

- Parse the issue's structured `self_test` block from `SKILL.md` frontmatter or
  sibling `skill-test.yaml`.
- Preserve compatibility with existing `skill.yaml` `self_test.command`
  bundles by translating them into one `command_exits_zero` assertion.
- Run functional self-tests for installed skills and publish candidates.
- Support these first assertion types:
  - `command_exits_zero`
  - `file_exists`
  - `agent_produces`
- Score results as passed assertions divided by total assertions.
- Treat `score >= 0.8` as publishable and `< 0.8` as rejected.
- Make `agentenv skills verify <name>` run the full self-test and persist the
  latest signed result for the exact artifact digest.
- Make `agentenv skills add` and `agentenv skills install --from` refuse to
  install a skill into the user's local set unless the artifact has a passing
  self-test result.
- Make `agentenv skills publish` refuse when a self-test is missing, stale,
  unsigned, for a different digest, or below `0.8`.
- Publish attestation material alongside skill artifacts so registry and hub
  implementations can reject artifacts without a recent successful run.
- Add reusable core verification APIs for server-side hub enforcement.
- Keep registry adapters focused on transport and artifact storage; keep gate
  policy in `SkillService`.

## Non-Goals

- Do not introduce a new serialization format. Use YAML for author-facing
  self-test declarations and JSON for stored attestations/metadata.
- Do not add Python, Node, Docker, ORAS, OpenSSL, or another runtime dependency
  to core.
- Do not depend on an external hosted hub service for tests. The PR should add
  the signed attestation format and validation API that a hub uses, plus local
  HTTP/OCI/filesystem fixture coverage.
- Do not broaden registry auth or git URL policy.
- Do not implement broad language-model evaluation. `agent_produces` is a
  deterministic smoke assertion over captured agent output.

## Author-Facing Self-Test Format

The canonical format is:

```yaml
self_test:
  runner: agentenv
  blueprint: ./test/minimal.yaml
  assertions:
    - type: command_exits_zero
      cmd: "cargo build"
    - type: file_exists
      path: "target/debug/myapp"
    - type: agent_produces
      prompt: "summarize the project structure"
      expect_tokens_matching: ["Cargo.toml", "src/"]
      min_match_ratio: 0.8
  timeout_seconds: 120
```

Supported declaration locations:

1. `skill-test.yaml` at the bundle root.
2. `SKILL.md` frontmatter under `self_test`.
3. `skill.yaml` under `self_test` for backward compatibility.

If more than one location is present, the declarations must be structurally
equivalent after normalization. Conflicting declarations fail verification,
install, add, and publish. This prevents one file from passing review while
another controls the artifact that lands in a user's local set or registry.

Field rules:

- `runner` is required and must be `agentenv`.
- `blueprint` is required when any assertion needs a throwaway environment,
  including `agent_produces`; it is optional for pure local file/command
  assertions.
- `assertions` must contain at least one assertion.
- `timeout_seconds` defaults to `120` and applies to the whole self-test run.
- Assertion paths are safe relative paths under the self-test workspace.
- Commands run through the platform shell with a cleared environment plus a
  small allowlist needed by `agentenv` itself.

Compatibility translation:

```yaml
self_test:
  command: "test -f SKILL.md"
```

becomes:

```yaml
self_test:
  runner: agentenv
  assertions:
    - type: command_exits_zero
      cmd: "test -f SKILL.md"
  timeout_seconds: 30
```

## Core Model

Add focused modules under `agentenv-core::skills`:

- `self_test`: author spec parsing, normalization, validation, execution, and
  scoring.
- `attestation`: signed result envelopes, canonical payload construction,
  signature verification, recency checks, and artifact-subject matching.
- `publish_gate`: policy helpers used by `SkillService::publish`.

Primary types:

```rust
pub struct SkillSelfTestSpec {
    pub runner: SkillSelfTestRunner,
    pub blueprint: Option<PathBuf>,
    pub assertions: Vec<SkillSelfTestAssertion>,
    pub timeout_seconds: u64,
}

pub enum SkillSelfTestAssertion {
    CommandExitsZero { cmd: String },
    FileExists { path: PathBuf },
    AgentProduces {
        prompt: String,
        expect_tokens_matching: Vec<String>,
        min_match_ratio: f64,
    },
}

pub struct SkillSelfTestReport {
    pub name: String,
    pub version: String,
    pub digest: String,
    pub self_test_digest: String,
    pub score: f64,
    pub passed: usize,
    pub total: usize,
    pub publishable: bool,
    pub assertions: Vec<SkillAssertionResult>,
    pub started_at: OffsetDateTime,
    pub completed_at: OffsetDateTime,
}
```

The self-test digest is a deterministic SHA-256 digest of the normalized
`SkillSelfTestSpec`. Publish gates require the attestation's `digest` and
`self_test_digest` to match the candidate bundle, so changing the skill content
or the test invalidates old runs.

## Execution Semantics

Self-tests run against a throwaway workspace, not the user's installed skill
directory in place.

1. Stage the candidate skill contents into a temporary directory.
2. If `blueprint` is present, validate the blueprint path inside the staged
   bundle and create a throwaway environment named
   `.skill-test-<name>-<version>-<short-digest>`.
3. Run file and command assertions with the staged skill root as the working
   directory unless a throwaway environment is active.
4. For `agent_produces`, enter the throwaway env in headless mode, send the
   prompt to the configured agent, capture bounded stdout/stderr output, and
   match expected tokens case-sensitively unless a later schema adds options.
5. Destroy the throwaway environment on success, failure, timeout, or panic-safe
   unwind boundaries.

`agent_produces` score:

- Count each expected token that appears at least once in the captured agent
  output.
- `match_ratio = matched_tokens / expected_tokens`.
- The assertion passes when `match_ratio >= min_match_ratio`.
- Empty `expect_tokens_matching` is invalid.

Overall score:

- Each assertion has equal weight.
- `score = passed_assertions / total_assertions`.
- `1.0` means all assertions pass.
- `0.8` through `0.99` is publishable with minor failures.
- `< 0.8` is rejected.

Timeout behavior:

- The whole self-test has one deadline from `timeout_seconds`.
- Timed-out commands and throwaway env sessions are terminated.
- A timeout counts as a failed assertion and the remaining assertions are
  marked skipped due to timeout.

## Attestations

Store the latest self-test result under the agentenv root:

```text
~/.agentenv/
  skills/
    attestations/
      <name>/
        <version>/
          <digest-hex>.json
```

Installed-cache metadata may also embed the latest attestation summary in
`.agentenv/provenance.json` so `skills verify --all`, lockfile verification,
and future hub code share one representation.

Attestation envelope:

```json
{
  "schema_version": "0.1",
  "predicate_type": "https://agentenv.dev/attestations/skill-self-test/v1",
  "subject": {
    "name": "my-skill",
    "version": "0.1.0",
    "digest": "sha256:..."
  },
  "self_test_digest": "sha256:...",
  "runner": "agentenv",
  "score": 1.0,
  "publishable": true,
  "started_at": "2026-05-12T10:00:00Z",
  "completed_at": "2026-05-12T10:00:03Z",
  "assertions": [
    {
      "type": "file_exists",
      "status": "passed",
      "message": "SKILL.md exists"
    }
  ],
  "signature": {
    "key_id": "local-agentenv",
    "algorithm": "ed25519",
    "value": "..."
  }
}
```

Signing key:

- Generate or load an Ed25519 key from
  `~/.agentenv/skills/self-test-signing-key.json`.
- Store only the public key in exported registry metadata.
- The key file is mode `0600` on Unix where permissions can be enforced.
- Tests use deterministic in-memory keys.

Recency:

- An attestation is recent when it matches the exact subject digest and
  self-test digest and was completed no more than 24 hours before publish.
- The default max age is `86400` seconds.
- Core exposes the max age as an option for CI/hub callers.

## CLI Behavior

`agentenv skills verify <name> [--version <version>] [--json]`:

- Resolves the installed skill selector.
- Loads and validates the structured self-test spec.
- Runs assertions and computes score.
- Writes a signed attestation for the installed artifact digest.
- Exits zero when `score >= 0.8`.
- Exits non-zero when no self-test exists, no assertions exist, the run fails
  below `0.8`, the declaration is invalid, or teardown fails in a way that
  leaves resources behind.

Text output:

```text
verified my-skill 0.1.0 score=1.00 publishable=true
```

JSON output returns the complete `SkillSelfTestReport` plus the attestation
path.

`agentenv skills verify --all`:

- Continues to verify local cache integrity.
- Runs structured self-tests for every installed skill with a declaration.
- Fails skills with no self-test only when `--require-self-test` is added.
- Adds `--json` support as part of this PR so CI can consume one report.

`agentenv skills add <name>[@version]` and
`agentenv skills install --from <path>`:

- Fetch or stage the candidate bundle before committing it into
  `~/.agentenv/skills`.
- Load the self-test spec and run it in the same throwaway execution path used
  by `skills verify`.
- Refuse installation when no self-test exists, the declaration is invalid, or
  the score is below `0.8`.
- Store the signed self-test attestation with the installed metadata when the
  install succeeds.

`agentenv skills publish <path> --registry <name-or-source>`:

- Loads the candidate bundle and self-test spec before selecting the registry
  adapter.
- Finds a recent signed attestation for the exact digest and self-test digest.
- If none exists, runs the self-test once unless `--no-self-test-run` is passed.
- Refuses publish if the final attestation is missing, invalid, stale, unsigned,
  mismatched, or below `0.8`.
- Publishes the bundle and its attestation together.

CLI additions:

```text
agentenv skills add <name>[@version] [--self-test-attestation <path>]
agentenv skills install --from <path> [--self-test-attestation <path>]
agentenv skills publish <path> --registry <name> [--self-test-attestation <path>]
agentenv skills publish <path> --registry <name> [--no-self-test-run]
agentenv skills verify <name> [--require-self-test] [--json]
agentenv skills verify --all [--require-self-test] [--json]
```

`--allow-unsigned` continues to mean "allow unsigned skill package signatures."
It does not bypass the self-test gate. Add an explicit test-only
`AGENTENV_UNSAFE_SKIP_SKILL_SELF_TEST_GATE=1` environment variable for fixture
setup paths that need to publish intentionally broken bundles.

## Registry And Hub Enforcement

`SkillService::publish` owns the gate. Registry adapters receive only artifacts
that already passed the policy.

Extend `RegistryAdapter::publish` to accept an optional verified attestation:

```rust
async fn publish(
    &self,
    bundle_path: &Path,
    allow_unsigned: bool,
    attestation: Option<&SkillSelfTestAttestation>,
) -> Result<SkillSearchHit, SkillError>;
```

Filesystem registry:

- Store `self-test-attestation.json` next to the published bundle.
- Include attestation digest and score in `index.yaml`.

HTTP registry:

- Upload `self-test-attestation.json` next to expanded bundle files and tarball
  artifacts.
- Fixture server rejects publish requests missing the attestation path.

OCI registry:

- Add the attestation as a layer with media type
  `application/vnd.agentenv.skill.self-test-attestation.v1+json`.
- Add OCI annotations for score, self-test digest, and completed timestamp.

Git registry:

- Publish remains unsupported, so no gate change is needed beyond preserving
  the typed unsupported-publish error.

Hub enforcement:

- Add `validate_skill_publish_attestation` in core. It accepts bundle identity,
  normalized self-test digest, attestation JSON, trusted public keys, and max
  age.
- HTTP and OCI fixture tests call the same function to reject missing, stale,
  mismatched, or low-score attestations.
- A future hosted hub can call this function directly; no separate hub crate is
  required in this repository.

## Error Handling

Add typed `SkillError` variants for:

- missing self-test
- invalid self-test declaration
- conflicting self-test declarations
- self-test timeout
- self-test assertion failure summary
- self-test score below threshold
- missing attestation
- stale attestation
- attestation subject mismatch
- attestation self-test digest mismatch
- invalid attestation signature
- unsafe self-test blueprint path
- throwaway env create/destroy failure
- unsupported agent headless run for `agent_produces`

Library code uses `thiserror`. CLI code uses `anyhow` only to add command
context. Error strings must not include secrets, bearer tokens, or full prompt
outputs from `agent_produces`; bounded output snippets are allowed for local
diagnostics.

## Testing

Core tests cover:

- loading `self_test` from `skill-test.yaml`
- loading `self_test` from `SKILL.md` frontmatter
- compatibility translation from `skill.yaml self_test.command`
- conflict detection across declaration locations
- validation for invalid runner, missing assertions, unsafe paths, empty token
  expectations, and invalid match ratios
- `file_exists` pass/fail
- `command_exits_zero` pass/fail/timeout
- `agent_produces` scoring with a fake headless agent runner
- score boundary behavior at `1.0`, `0.8`, `0.799`
- attestation signing and verification
- attestation subject, self-test digest, timestamp, and signature failures
- publish gate accepts recent score `0.8`
- publish gate rejects no self-test, no attestation, stale attestation, and low
  score
- local install gate rejects no self-test and low score before writing the final
  installed directory
- registry adapters persist attestation metadata for filesystem, HTTP, and OCI
- `validate_skill_publish_attestation` rejects invalid hub-side submissions

CLI tests cover:

- `skills verify <name> --json` writes an attestation and returns score data
- `skills verify <name>` exits non-zero below `0.8`
- `skills verify --all --json` returns per-skill integrity and self-test
  results
- `skills add` and `skills install --from` refuse skills without passing
  self-tests
- `skills publish` auto-runs self-test when no recent attestation exists
- `skills publish --no-self-test-run` fails without a recent attestation
- `skills publish --self-test-attestation <path>` accepts matching attestations
  and rejects mismatches
- `--allow-unsigned` does not bypass the self-test gate

Required final checks:

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Risks And Trade-Offs

Running `agent_produces` through a real throwaway environment makes the feature
more expensive than local file/command assertions, but it is the assertion that
proves the skill works for an agent rather than only for the shell. Tests should
use a fake runner so normal workspace tests remain fast.

The attestation model adds local signing key management. Keeping the key scoped
to self-test attestations avoids touching package signatures and keeps the
existing `--allow-unsigned` behavior clear.

The repository does not currently contain a hosted hub service. Implementing a
core validation API and making registry fixtures enforce it gives the full
artifact and policy contract in this PR without inventing a new server
architecture inside M7-7.
