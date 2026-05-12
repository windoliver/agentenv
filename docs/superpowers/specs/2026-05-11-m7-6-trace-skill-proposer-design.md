# M7-6 Design: Trace To Skill Proposer

- Date: 2026-05-11
- Issue: https://github.com/windoliver/agentenv/issues/32
- Milestone: M7 Skills axis and registry
- Depends on: https://github.com/windoliver/agentenv/issues/27, https://github.com/windoliver/agentenv/issues/23, https://github.com/windoliver/agentenv/issues/28
- Affected crates: `agentenv`, `agentenv-core`, `agentenv-events`
- Protocol impact: no driver protocol or schema-version change

## 1. Context And Goals

Issue #32 adds a trace-to-skill flywheel:

```text
agentenv skills propose --from-traces --blueprint myapp.yaml --min-occurrences 3 --min-novelty 0.6
```

Successful agent runs are already represented by the M6 activity stream.
M7 has also established that skills are core-managed static artifacts, not a
new driver kind and not a fifth pluggable axis. This issue should connect
those two surfaces: read successful activity traces, detect repeated
procedures, generalize them into reusable skill drafts, score novelty, run a
regression self-test, and emit proposals that an operator can curate.

The requested scope is the full pipeline:

1. Consume activity traces.
2. Extract repeated tool-call sequences by `blueprint_id`.
3. Generalize concrete arguments into template variables with an LLM provider.
4. Score novelty and utility, including semantic dedup.
5. Gate proposals with a self-test score of at least `0.8` by default.
6. Emit PR-ready skill drafts under `~/.agentenv/skills/proposed/<name>/`.
7. Optionally open a draft PR to a user's skills repository.

The implementation should still degrade clearly. Local deterministic trace
mining should work without network access. LLM generalization, semantic vector
dedup, and PR publishing require explicit configuration and fail with actionable
messages when requested but unavailable.

## 2. Scope And Non-Goals

In scope:

1. Add `agentenv skills propose` with the issue command shape.
2. Add trace-oriented activity-store queries in `agentenv-events`.
3. Add an `agentenv-core::skills::propose` module for trace extraction,
   candidate modeling, generalization schemas, scoring, self-test evaluation,
   and proposal emission.
4. Support grouping successful `mcp_tool_call` traces by `blueprint_id`.
5. Detect repeated normalized tool-call sequences across at least
   `--min-occurrences` traces.
6. Redact secret-like data before any candidate, prompt, or proposal reaches
   disk or a model provider.
7. Use a configured LLM provider for full-scope generalization.
8. Validate LLM output through strict serde models before writing files.
9. Deduplicate against installed and already proposed skills with exact,
   structural, and semantic scoring.
10. Support a local semantic fallback and a pluggable vector-search adapter
    for deployments that use pgvector, Milvus, or another embedding backend.
11. Implement the novelty ladder required by the issue:
    - `0.0`: duplicate of an existing skill
    - `0.3`: minor variation or parameter difference
    - `0.6`: distinct variant or new target
    - `0.9`: genuinely new capability
12. Implement a self-test gate against the source trace abstraction.
13. Emit proposed skill directories under
    `~/.agentenv/skills/proposed/<name>/`.
14. Support optional draft PR creation with explicit `--open-pr --repo owner/repo`.
15. Add tests for trace reads, extraction, redaction, LLM output validation,
    novelty scoring, self-test scoring, proposal layout, CLI behavior, and PR
    publishing command construction.

Out of scope:

1. A driver protocol change or schema bump.
2. A new registry adapter kind for proposed skills.
3. Installing proposed skills automatically. Operators still curate and merge.
4. Rerunning arbitrary agent tools during self-test. The first self-test
   replays against the trace abstraction.
5. Sending raw event rows, credentials, or unredacted command arguments to an
   LLM or vector backend.
6. Adding Python, Node, OpenSSL, Docker, or another runtime dependency to the
   core binary.
7. Creating a new CLI vocabulary outside the established `skills` lifecycle.

Note: the repo workflow asks for an approach comment on architectural issues
before code. The GitHub app returned `403 Resource not accessible by
integration` when attempting to post that comment for issue #32 in this
session. This design document records the approved approach instead.

## 3. Architecture

Keep the pipeline core-managed and modular:

```text
agentenv skills propose
  -> read activity events from SQLite
  -> filter successful traces by blueprint_id
  -> normalize ordered MCP/tool-call sequences
  -> extract repeated candidates
  -> generalize candidates through a configured LLM provider
  -> score exact, structural, semantic, and utility signals
  -> run regression self-test against source traces
  -> write proposed skill draft
  -> optionally open draft PR
```

`agentenv-events` should expose trace-oriented read APIs over the existing
SQLite store. The CLI should not hand-write SQL against `activity_events`.

`agentenv-core` should own the deterministic pipeline and data models:

1. `trace`: raw trace records, normalized tool calls, blueprint filtering.
2. `extract`: repeated sequence detection and candidate formation.
3. `generalize`: strict request/response models and provider trait.
4. `score`: novelty, utility, and semantic dedup abstractions.
5. `self_test`: regression scoring against trace abstractions.
6. `emit`: proposed-skill directory rendering.

`agentenv` should remain CLI glue:

1. Parse flags.
2. Load skills config and credential references.
3. Resolve the activity database path.
4. Construct concrete LLM, embedding, vector-search, and PR publisher adapters.
5. Render JSON or table output.

This boundary keeps core logic testable without network access while still
supporting full-scope integrations through traits.

## 4. Command Shape

Add a `Propose(SkillsProposeArgs)` subcommand under `agentenv skills`:

```text
agentenv skills propose --from-traces --blueprint <path> \
  [--events-db <path>] [--env <name>] \
  [--min-occurrences <n>] [--min-novelty <score>] \
  [--min-self-test-score <score>] \
  [--llm-provider <name>] [--semantic-backend <name>] \
  [--out <dir>] [--json] \
  [--open-pr --repo <owner/repo>]
```

Required:

1. `--from-traces` is required for the first implementation. It leaves room for
   additional sources without creating a new top-level verb.
2. `--blueprint <path>` identifies the blueprint scope.

Defaults:

1. `--min-occurrences 3`
2. `--min-novelty 0.6`
3. `--min-self-test-score 0.8`
4. `--out ~/.agentenv/skills/proposed`
5. `--events-db` defaults to the global activity database, with env-scoped
   reads merged when `--env` is provided and the env store exists.
6. `--llm-provider` defaults to the configured skills proposal provider.
7. `--semantic-backend local` unless config chooses an external backend.

Validation:

1. `--min-occurrences` must be at least `2`.
2. `--min-novelty` and `--min-self-test-score` must be between `0.0` and `1.0`.
3. `--open-pr` requires `--repo`.
4. `--repo` must be `owner/name` with conservative characters.
5. `--events-db` must pass the same no-symlink final-component safety used by
   the activity store.

Human output should list proposed names, novelty score, self-test score,
occurrence count, output path, and PR URL when present. JSON output should use a
stable response model with the same fields plus warnings.

## 5. Configuration And Credentials

Add optional proposal config to the existing skills config surface:

```yaml
skills:
  proposal:
    llm:
      provider: default
      endpoint: https://llm.example.test/v1
      model: proposal-generalizer
      credential: AGENTENV_SKILL_PROPOSER_TOKEN
    semantic:
      backend: local
      embedding_provider: default
      embedding_model: proposal-embedding
      credential: AGENTENV_SKILL_PROPOSER_EMBEDDING_TOKEN
    pr:
      default_repo: owner/skills
```

The same shape should be accepted in `~/.config/agentenv/config.toml`.
Project config overrides user config for project-local proposals, and CLI flags
override both.

Credential handling:

1. Credential names are resolved through the existing CLI credential store.
2. Credential values are never stored in proposal files.
3. Credential values are injected only into concrete HTTP or GitHub adapters.
4. Generalization prompts include redacted trace summaries, not raw event rows.
5. External semantic requests include only redacted candidate text and
   generated proposal summaries.

If full-scope generalization is requested and no LLM provider is configured,
the command should fail with a message that names the missing config and
credential. A deterministic-only mode would be a separate opt-in path and is
not the full-scope default requested for this issue.

## 6. Trace Selection

The proposer reads `ActivityEvent` rows and builds `TraceRun` values:

```rust
pub struct TraceRun {
    pub trace_id: String,
    pub env: Option<String>,
    pub blueprint_id: String,
    pub started_at: String,
    pub calls: Vec<TraceToolCall>,
    pub terminal_result: ActivityResult,
}

pub struct TraceToolCall {
    pub ordinal: u32,
    pub tool: String,
    pub args: serde_json::Value,
    pub args_shape: serde_json::Value,
    pub result: ActivityResult,
    pub subject: serde_json::Value,
}
```

Blueprint scope:

1. Resolve `--blueprint` and compute a stable `blueprint_id`.
2. Prefer explicit `extras.blueprint_id` values in activity events.
3. If older events lack `blueprint_id`, support an env-scoped fallback only
   when the persisted env state can be tied unambiguously to the same
   blueprint digest.
4. If neither path can establish scope, skip the trace and record a warning.

Successful traces:

1. Include only traces with at least one successful `mcp_tool_call`.
2. Exclude traces that contain `egress_denied`, `spawn_rejected`,
   `approval_requested` without a matching successful `approval_decided`, or
   any terminal `error` result for the same `trace_id`.
3. Exclude tool calls whose subject lacks a textual `tool` name.
4. Apply event redaction before normalization.

Ordering:

1. Within a trace, order calls by event id.
2. Preserve repeated calls to the same tool.
3. Use `trace_id` as the run boundary.

## 7. Candidate Extraction

Normalize each tool call into a fingerprint:

```text
tool + normalized_arg_shape + selected_subject_keys + result
```

Argument normalization:

1. Preserve JSON types and object keys.
2. Replace scalar values with shape markers for sequence matching.
3. Preserve small enumerations when every occurrence shares the same value.
4. Redact values for secret-like keys and URLs before computing candidate
   material.
5. Treat paths, URLs, branch names, package names, and env names as potential
   template variables.

Candidate formation:

1. Group exact normalized sequences.
2. Allow argument variation inside the same sequence if tool order and shape
   remain stable.
3. Require at least `--min-occurrences` distinct trace ids.
4. Prefer shorter maximal repeated sequences when a larger sequence has
   unrelated setup or cleanup calls around the repeatable procedure.
5. Generate a draft name from blueprint context and dominant tools, then
   validate it with `validate_skill_name`.

Candidate provenance should include:

1. Source `blueprint_id`.
2. Source event database path.
3. Trace ids.
4. Event id ranges.
5. Normalized sequence fingerprint.
6. Redaction counts.

## 8. LLM Generalization

Core should define the provider trait and validated schema:

```rust
#[async_trait]
pub trait SkillGeneralizer: Send + Sync {
    async fn generalize(
        &self,
        request: SkillGeneralizationRequest,
    ) -> Result<SkillGeneralization, ProposeError>;
}
```

Request contents:

1. Candidate summary.
2. Redacted representative traces.
3. Argument variation summary.
4. Blueprint metadata.
5. Existing installed and proposed skill summaries.
6. Required output schema version.

Response contents:

```rust
pub struct SkillGeneralization {
    pub name: String,
    pub description: String,
    pub template_variables: Vec<TemplateVariable>,
    pub procedure_steps: Vec<ProcedureStep>,
    pub self_test: ProposedSelfTest,
    pub skill_md_body: String,
}
```

Validation:

1. Name must pass `validate_skill_name`.
2. Description must be present and concise.
3. Template variables must be referenced by at least one procedure step.
4. Procedure steps must refer only to tools present in the source candidate or
   to clear human-instruction steps.
5. `SKILL.md` body must not include secrets, raw trace ids, absolute home paths,
   or provider-specific credentials.
6. Output must be rejected if it is not valid JSON, has unknown top-level
   fields, or references files outside the proposal bundle.

The concrete provider in the CLI can call an OpenAI-compatible or other
configured HTTP endpoint through `reqwest` and `rustls`. The provider should
request JSON-only output and then parse locally. The core should not trust the
model to enforce security or schema rules.

## 9. Novelty And Utility Scoring

Compute a score report rather than a single opaque number:

```rust
pub struct ProposalScore {
    pub novelty: f32,
    pub utility: f32,
    pub final_score: f32,
    pub nearest_matches: Vec<SkillMatch>,
    pub reasons: Vec<String>,
}
```

Novelty steps:

1. Exact duplicate: compare generated `SKILL.md`, `skill.yaml`, procedure
   steps, and normalized fingerprints against installed and proposed skills.
2. Structural duplicate: compare ordered tools, variable names, and step
   structure.
3. Semantic duplicate: query the selected semantic backend with the generated
   description and procedure summary.

Semantic backends:

1. `local`: token/Jaccard similarity over existing skill names, descriptions,
   tags, and procedure text. This gives deterministic offline behavior.
2. `embedding-local-cache`: use a configured embedding provider and store
   vectors in a local SQLite table under `~/.agentenv/skills/proposed/index.db`.
3. `external`: call a configured HTTP adapter for Milvus, pgvector, or an
   organization-specific vector service. The adapter contract uses JSON over
   HTTPS and SSRF validation. Direct database or gRPC clients are unnecessary
   for this issue because the HTTP adapter keeps core dependencies narrow.

Ladder mapping:

1. `0.0`: exact duplicate or semantic similarity above the duplicate threshold.
2. `0.3`: same sequence with only parameter/target variation.
3. `0.6`: distinct sequence variant or new target family.
4. `0.9`: no close match and a new capability category.

Utility scoring:

1. Higher occurrence count increases utility.
2. More distinct trace ids and timestamps increase confidence.
3. Failed or noisy nearby events reduce utility.
4. Candidates with too many template variables are penalized.

The CLI enforces `--min-novelty` against the novelty score. The self-test gate
is separate.

## 10. Self-Test Gate

The self-test does not rerun arbitrary tools. It evaluates the generated skill
against the trace abstraction:

1. Each generated procedure step must map to one or more source tool calls or a
   clear human instruction.
2. Template variables must explain observed argument variation.
3. Constant values must match the source traces.
4. The generated self-test command must be syntactically valid metadata but is
   not executed during proposal generation unless it is a safe local file check.
5. The generated `SKILL.md` must contain enough procedure detail to reproduce
   the source sequence at a high level.

Self-test report:

```rust
pub struct ProposalSelfTestReport {
    pub score: f32,
    pub matched_steps: u32,
    pub total_steps: u32,
    pub matched_variables: u32,
    pub total_variables: u32,
    pub failures: Vec<String>,
}
```

Default gate: `score >= 0.8`.

Rejected proposals are not emitted by default. Diagnostic emission of rejected
proposals is out of scope for this issue so the proposal output remains clean.

## 11. Proposal Emission

Emit each accepted proposal to:

```text
~/.agentenv/skills/proposed/<name>/
|-- SKILL.md
|-- skill.yaml
|-- proposal.yaml
|-- self-test.json
`-- traces/
    `-- provenance.json
```

`SKILL.md` should include frontmatter compatible with the existing skill
ecosystem:

```yaml
---
name: proposed-skill
description: Short generated description
version: 0.1.0
tags: [agentenv-proposed, trace-derived]
agentenv-proposal: true
agentenv-schema: "0.1"
---
```

`skill.yaml` remains the package manifest used by existing skills code:

```yaml
name: proposed-skill
version: 0.1.0
description: Short generated description
entry: SKILL.md
files:
  - SKILL.md
  - proposal.yaml
  - self-test.json
  - traces/provenance.json
self_test:
  command: test -f SKILL.md
agentenv_proposal: true
agentenv_schema: "0.1"
```

`proposal.yaml` should include candidate metadata, scores, provider metadata,
source blueprint id, and curation status:

```yaml
schema_version: "0.1"
status: proposed
blueprint_id: sha256:...
occurrences: 3
novelty: 0.6
utility: 0.8
self_test_score: 0.91
generated_by:
  agentenv_version: 0.0.1-alpha0
  llm_provider: default
```

Safety:

1. Refuse to overwrite an existing proposal directory unless the content is
   byte-identical. Replacement behavior is out of scope for this issue.
2. Use staging plus atomic rename where possible.
3. Validate the emitted bundle with `load_skill_manifest`.
4. Compute a bundle digest and include it in CLI output.
5. Keep trace provenance redacted and bounded. Store summaries, not full raw
   event rows.

## 12. Optional PR Publishing

When `--open-pr --repo owner/repo` is provided:

1. Create a branch name such as
   `agentenv/proposed-skill/<proposal-name>-<short-digest>`.
2. Add only the emitted proposal directory to the target skills repository.
3. Commit with a message such as
   `feat: propose trace-derived skill <name>`.
4. Push the branch.
5. Open a draft PR with summary, scores, source blueprint id, and self-test
   report.

Implementation options:

1. Prefer the GitHub app connector when available for PR creation.
2. Use local `git` and `gh` only when the connector cannot operate on the
   target repo from the current checkout.
3. If neither path is configured, leave the proposal on disk and fail only the
   publishing step with a clear message.

Publishing must never include credential values, raw event databases, or
unredacted traces.

## 13. Error Handling

Use `thiserror` in core and `anyhow` in CLI glue.

Representative errors:

1. Missing activity database.
2. Blueprint file cannot be read or verified.
3. No matching traces for `blueprint_id`.
4. Not enough repeated traces for `--min-occurrences`.
5. Missing LLM provider config or credential.
6. LLM response failed schema validation.
7. Semantic backend unavailable.
8. Novelty below threshold.
9. Self-test below threshold.
10. Proposal output path exists.
11. PR publishing unavailable or failed after local proposal emission.

Partial success should be explicit. If proposal emission succeeds but PR
publishing fails, return a non-zero exit only for the publishing command path
and print the local proposal path so the user can recover.

## 14. Testing

Core tests:

1. Trace query helper groups rows by `trace_id` and filters by `blueprint_id`.
2. Trace selection excludes denied, rejected, and error traces.
3. Extraction finds repeated sequences and ignores singletons.
4. Normalization redacts secrets, URLs with credentials, and token-like values.
5. LLM response parsing rejects malformed JSON, unknown fields, invalid names,
   unsafe paths, and leaked secrets.
6. Novelty scoring maps exact, structural, semantic, and new-capability cases
   to the required ladder.
7. Self-test scoring accepts well-mapped proposals and rejects under-specified
   proposals.
8. Proposal writer emits the expected layout and validates with
   `load_skill_manifest`.
9. Proposal writer rejects existing output paths and unsafe proposal names.

CLI tests:

1. `agentenv skills --help` lists `propose`.
2. Missing `--from-traces` or `--blueprint` fails cleanly.
3. A fixture activity database produces a proposed skill under a temp
   `AGENTENV_HOME`.
4. `--json` emits stable proposal metadata.
5. Missing LLM config in full mode fails with a precise message.
6. A fake LLM provider can drive a deterministic accepted proposal.
7. A low novelty proposal is skipped.
8. A low self-test score is skipped.
9. `--open-pr` validates `--repo` and constructs a draft PR request without
   touching unrelated files.

Verification before PR:

```bash
cargo fmt
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## 15. Rollout Notes

This issue touches architectural surface but does not require a driver schema
bump because it only reads the existing activity store and writes core-managed
skill artifacts.

The PR description should list the affected crates:

1. `agentenv-events`
2. `agentenv-core`
3. `agentenv`

It should also call out:

1. No driver protocol impact.
2. Which semantic backends are implemented in the PR.
3. How LLM and embedding credentials are configured.
4. That proposed skills are emitted locally by default and are not installed
   automatically.
