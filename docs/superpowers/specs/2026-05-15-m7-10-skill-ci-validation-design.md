# M7-10 Skill CI Validation Design

- Date: 2026-05-15
- Issue: https://github.com/windoliver/agentenv/issues/36
- Milestone: M7 Skills axis and registry
- Depends on:
  - https://github.com/windoliver/agentenv/issues/33
  - https://github.com/windoliver/agentenv/issues/34
- Affected crates: `agentenv-core`, `agentenv`
- Other affected files: `.github/workflows/skill-ci.yaml`
- Protocol impact: no driver protocol or schema-version change

## Context

Skills are core-managed artifacts. The current code already owns skill
manifests, bundle digests, signatures, registry adapters, local install
metadata, self-test execution, and self-test attestations. The reference hub
from issue #34 is intentionally outside this repository, but its publish API
should not need to reimplement the trust policy that core already enforces.

Issue #36 adds a quality gate for skill hub publishes: four sequential tiers
that fail fast from cheapest to most expensive. The right boundary is a
reusable core validation engine and CLI command in this repository, plus a
GitHub Actions workflow that calls the command. The hub can later invoke the
same binary or library API server-side before accepting a publish.

## Goals

- Add a four-tier CI validation engine for a candidate skill bundle or skill
  directory.
- Run tiers sequentially and stop at the first failing tier by default.
- Keep skill validation policy inside `agentenv-core::skills`, not inside a
  driver, workflow script, or separate serialization format.
- Expose the engine through `agentenv skills ci <path>`.
- Emit stable JSON suitable for hub APIs, workflow comments, and tests.
- Emit SARIF for tier 1 and tier 2 findings so GitHub code scanning can show
  actionable diagnostics.
- Add `.github/workflows/skill-ci.yaml` as a reusable workflow that validates
  changed skill bundles on pull requests and workflow calls.
- Reuse the existing self-test gate from issue #33 for tier 4.
- Provide a clean seam for future hub-backed semantic dedup using pgvector,
  Milvus, or another vector index without adding those services to core.

## Non-Goals

- Do not implement the skill hub service in this repository.
- Do not add a fifth pluggable axis or a `SkillsDriver`.
- Do not change the JSON-RPC driver protocol.
- Do not add Python, Node, Docker, OpenSSL, Milvus, pgvector, or a model SDK as
  a build-time dependency of core.
- Do not require network access for local tests.
- Do not make true LLM judging mandatory for CI. Tier 2 gets a deterministic
  local reviewer first, with an interface that a hub or later command can back
  with an LLM provider.
- Do not persist registry publish decisions from the CI command. The command
  validates and reports; publish code still owns storage and attestation
  persistence.

## User-Facing CLI

Add:

```text
agentenv skills ci <path> [--registry-snapshot <path>] [--sarif <path>] [--json] [--no-fail-fast]
```

Behavior:

- `<path>` points to an expanded skill directory or bundle path accepted by
  existing skill loading code.
- `--json` prints the complete validation report to stdout.
- `--sarif <path>` writes SARIF containing tier 1 and tier 2 findings.
- `--registry-snapshot <path>` points to a local JSON file containing existing
  skill summaries for tier 3 dedup checks. This keeps local CI deterministic
  and lets the hub export its own registry state later.
- `--no-fail-fast` runs all tiers even after a failure. The default fail-fast
  behavior matches the issue's cost model.

Exit codes:

- `0`: all requested tiers passed.
- `1`: at least one tier failed.
- `2`: CLI usage or unreadable input error.

## Core API

Add a focused module:

```text
crates/agentenv-core/src/skills/ci.rs
```

Primary model:

```rust
pub struct SkillCiRequest {
    pub candidate_path: PathBuf,
    pub registry_snapshot: Option<SkillCiRegistrySnapshot>,
    pub fail_fast: bool,
}

pub struct SkillCiReport {
    pub candidate: SkillCiCandidate,
    pub status: SkillCiStatus,
    pub tiers: Vec<SkillCiTierReport>,
    pub started_at: OffsetDateTime,
    pub completed_at: OffsetDateTime,
}

pub enum SkillCiTier {
    StaticLint,
    AgentReview,
    SemanticDedup,
    FunctionalRegression,
}

pub enum SkillCiStatus {
    Passed,
    Failed,
    Skipped,
}
```

The module stays below `SkillService` rather than replacing service publish
gates. `SkillService::publish` can later call the same validator when hub
policy needs to require the entire four-tier result, but this issue should
start with the CLI/workflow validation path.

## Tier 1 - Static Lint

Tier 1 validates the bundle without model calls or sandbox work.

Checks:

- `skill.yaml` exists and passes existing manifest loading.
- `SKILL.md` exists at the declared entry path.
- `SKILL.md` frontmatter, when present, is YAML and agrees with manifest
  identity fields already enforced by cache verification.
- Markdown is structurally well formed for the first implementation:
  headings are nested without jumping more than one level, fenced code blocks
  are closed, and frontmatter has a closing delimiter.
- No secret-like content appears in bundled text files. Core uses a small
  deterministic scanner for common credential shapes. If `gitleaks` is present
  on PATH, the CLI also runs it and merges findings, but missing `gitleaks`
  does not fail the tier.
- Manifest version parses as semver and is not a prerelease unless the command
  is later given an explicit prerelease policy flag.
- Package signature verifies through existing Ed25519 verification unless the
  command is later extended with an explicit unsigned-development flag.
- Self-test declaration loads and normalizes without conflicts.

Findings include severity, message, path, and optional line. The tier fails on
errors and passes with warnings.

## Tier 2 - Agent Review

Tier 2 reviews skill prose for clarity, safety, and structural accuracy with a
bounded deterministic reviewer in the first implementation.

The reviewer analyzes the manifest, `SKILL.md`, and self-test declaration. It
emits:

- `clarity`: description names the skill behavior, the body has enough
  procedure detail, and required inputs are identifiable.
- `safety`: destructive commands, credential handling, privilege escalation,
  and irreversible file operations require explicit user consent.
- `accuracy`: code blocks and examples are structurally plausible for their
  declared language, referenced files exist in the bundle, and self-test
  examples match supported assertion names.

This tier intentionally does not add a required model provider. The core API
uses a trait boundary:

```rust
pub trait SkillReviewJudge {
    fn review(&self, input: SkillReviewInput) -> Result<SkillReviewReport, SkillError>;
}
```

The default `RuleBasedSkillReviewJudge` is deterministic and used in CI. A
future hub process can supply an LLM-backed judge through this same shape while
keeping token budget and provider policy outside core.

Tier 2 fails when any review item has `decision: fail`. It also contributes
SARIF diagnostics for actionable line-level findings.

## Tier 3 - Semantic Dedup

Tier 3 computes a local semantic duplication result from candidate manifest and
skill prose.

For this issue, core should reuse the existing local scoring idea from
`skills::propose`: normalized token similarity, exact fingerprint matching, and
novelty buckets. This keeps CI deterministic and avoids a database dependency.

Inputs:

- Candidate manifest name, version, description, entry content, and digest.
- Optional registry snapshot supplied by `--registry-snapshot`.

Snapshot format:

```json
{
  "skills": [
    {
      "name": "existing-skill",
      "version": "0.1.0",
      "description": "Short summary",
      "procedure_text": "Skill body or indexed summary",
      "fingerprint": "sha256:..."
    }
  ]
}
```

Output:

- `nearest_neighbors`: ordered list with name, version, similarity, and reason.
- `novelty_score`: one of `0.0`, `0.3`, `0.6`, or `0.9`.
- `probable_duplicate`: true when similarity is greater than `0.92` or an
  exact fingerprint match exists.

Tier 3 fails when `probable_duplicate` is true. A later hub can replace the
local snapshot implementation with pgvector or Milvus while preserving this
report shape.

## Tier 4 - Functional Regression

Tier 4 runs the existing self-test engine from issue #33.

Behavior:

- Load and normalize the candidate self-test declaration.
- Run the self-test with the existing `AgentProduceRunner` integration used by
  `agentenv skills verify` and `agentenv skills publish`.
- Require score `>= 0.8`.
- Include the self-test report and signed attestation summary in the CI report.

Tier 4 fails if the self-test is missing, stale, below threshold, times out, or
cannot produce a valid report. It does not publish or store the candidate.

## JSON Report

The top-level JSON report is stable enough for workflow comments and hub API
consumers:

```json
{
  "schema_version": "0.1",
  "candidate": {
    "name": "demo",
    "version": "0.1.0",
    "digest": "sha256:..."
  },
  "status": "failed",
  "tiers": [
    {
      "tier": "static_lint",
      "status": "passed",
      "duration_ms": 42,
      "findings": []
    }
  ]
}
```

The CLI may render a concise table for humans when `--json` is not set, but
tests should assert the JSON shape.

## SARIF

Add a small SARIF serializer for tier 1 and tier 2 findings. The serializer
should be implemented in core with no extra crate unless an already-present
workspace dependency provides enough structure.

Rules:

- One SARIF run named `agentenv skill ci`.
- Rule IDs use stable strings such as `agentenv.skill.manifest.invalid`,
  `agentenv.skill.markdown.unclosed-fence`, and
  `agentenv.skill.review.destructive-without-consent`.
- Only include line information when the checker can locate it reliably.
- Do not include secret values in SARIF messages.

## GitHub Actions Workflow

Add `.github/workflows/skill-ci.yaml`.

Shape:

- Trigger on `workflow_call` so hub repositories can reuse it.
- Trigger on `pull_request` for this repository when paths likely containing
  skills change, including `.agents/skills/**`, `skills/**`, and examples added
  later.
- Build or install the local `agentenv` binary.
- Discover candidate skill directories by looking for `skill.yaml`.
- Run `agentenv skills ci <dir> --json --sarif <file>` for each candidate.
- Upload SARIF when any SARIF file was produced.
- Post a PR comment summarizing tier-by-tier results when running in a pull
  request context.

The workflow should not invent policy in shell. Shell only discovers inputs,
calls the CLI, and formats the CLI's JSON report.

## Error Handling

Library code returns `SkillError` variants for:

- invalid CI candidate path
- markdown lint failure
- secret-like bundled content
- failed skill review
- invalid registry snapshot
- probable duplicate skill
- SARIF serialization failure
- CI tier failure summary

CLI code uses `anyhow` for command context and maps validation failures to exit
code `1`. It must not pattern-match opaque strings.

No `.unwrap()` should be introduced outside tests.

## Testing

Core tests should cover:

- Tier 1 accepts a valid signed skill with a self-test.
- Tier 1 rejects invalid semver, missing entry file, unclosed Markdown fence,
  frontmatter conflict, secret-like text, and invalid signature.
- Tier 2 fails a skill that instructs destructive operations without consent.
- Tier 2 passes a clear, bounded, non-destructive skill.
- Tier 3 flags exact fingerprint matches and similarity above `0.92`.
- Tier 3 maps novelty scores to `0.0`, `0.3`, `0.6`, and `0.9`.
- Tier 4 delegates to the existing self-test engine and fails below `0.8`.
- Fail-fast stops after the first failed tier.
- `--no-fail-fast` reports later tiers as passed, failed, or skipped.
- SARIF output contains stable rule IDs and redacts secret-like content.

CLI tests should cover:

- `agentenv skills ci <dir> --json` exits `0` for a passing fixture.
- `agentenv skills ci <dir> --json` exits `1` and reports the failing tier for
  an invalid fixture.
- `--sarif <path>` writes a valid SARIF JSON file.
- `--registry-snapshot <path>` drives dedup failure deterministically.

Workflow validation can stay light: parse the YAML in tests or add a repository
smoke check that the workflow references `agentenv skills ci`.

## Documentation

Update user-facing docs once the implementation lands:

- Mention `agentenv skills ci` in the skills CLI section.
- Document the registry snapshot format.
- Document that `gitleaks` is optional local enrichment, not a required core
  dependency.
- Note that hub deployments should call the same CI command or core API before
  accepting publishes.

## Open Trade-Offs

- The first Tier 2 judge is deterministic rather than a true LLM-as-judge. This
  keeps the core binary dependency-free and testable. The trait boundary keeps
  the issue compatible with a hub-provided LLM judge later.
- The first Tier 3 dedup path uses a local snapshot rather than Milvus or
  pgvector. This preserves the single-binary core and lets the hub own its
  preferred vector backend without changing the CLI report contract.
- Optional `gitleaks` support improves developer CI where the binary is
  installed, but the built-in scanner remains the portable baseline.
