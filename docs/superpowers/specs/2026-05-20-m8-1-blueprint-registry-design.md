# M8-1 Design: Blueprint Registry

- Date: 2026-05-20
- Issue: https://github.com/windoliver/agentenv/issues/46
- Milestone: M8 Team-mode adoption
- Depends on:
  - https://github.com/windoliver/agentenv/issues/27
  - https://github.com/windoliver/agentenv/issues/28
  - https://github.com/windoliver/agentenv/issues/31
- Affected future crates: `agentenv`, `agentenv-core`
- Protocol impact: no driver protocol or schema-version change

## Context

M7 established that skills are core-managed artifacts, not a `ContextDriver`
sub-kind and not a fifth pluggable axis. The skills registry already owns the
hard parts that a blueprint registry would otherwise duplicate: registry
configuration, filesystem/HTTP/OCI/git adapters, artifact digests, signature
checks, self-test attestations, local cache layout, publish gates, and
provenance.

M7-5 also made a frozen `agentenv` environment exportable as an installable
skill bundle. That bundle contains `blueprint.yaml`, `agentenv.lock`, and
metadata marking it as an `agentenv` bundle. M8 should treat that bundle as the
canonical published blueprint artifact instead of inventing a separate package
format.

The user-facing goal remains blueprint-native:

```text
agentenv install github.com/alice/myapp
agentenv create myapp --from alice/myapp
agentenv publish --blueprint ./myapp --registry ghcr.io/alice
```

The implementation behind that UX should reuse the M7 skill registry and trust
chain.

## Goals

1. Let users install reusable blueprints published by other users or teams.
2. Reuse the M7 skills registry adapters and trust model.
3. Keep installed blueprints available through stable handles such as
   `alice/myapp` for `agentenv create --from`.
4. Verify the bundled `agentenv.lock` before recording an installed blueprint.
5. Make `agentenv install <source>` fetch and verify only. It must not create
   or apply an environment.
6. Let `agentenv create --from <source>` either use an installed handle or
   perform an explicit one-shot fetch, verify, and create flow.
7. Preserve the four-axis architecture and avoid any driver protocol change.

## Non-Goals

1. Do not add a standalone blueprint registry service for the first M8 slice.
2. Do not add a `BlueprintDriver`, `RegistryDriver`, or any new JSON-RPC driver
   method.
3. Do not introduce a second serialization format. Published blueprint bundles
   remain YAML plus the existing skill package metadata.
4. Do not make `agentenv install` create, start, or mutate an environment.
5. Do not support unverified remote blueprint installation as the default.
   Remote installs require a lockfile and the same artifact verification rules
   used by skills.

## Registry Decision

### Recommended: merged registry, blueprint-specific view

Blueprints should piggy-back on the M7 skills registry. A published blueprint is
an `agentenv` skill bundle whose manifest includes the existing bundle markers
and whose contents include `blueprint.yaml` and `agentenv.lock`.

Installation writes the artifact into the existing immutable skills cache, then
records a blueprint-specific alias under `~/.agentenv/blueprints/`. The alias is
a view over the installed artifact, not a second copy of the bundle.

This gives users a blueprint-native handle while keeping one artifact store and
one trust chain:

```text
~/.agentenv/
  skills/
    myapp/
      1.2.0/
        content/
          skill.yaml
          SKILL.md
          blueprint.yaml
          agentenv.lock
        installed.yaml
  blueprints/
    index.json
    alice/
      myapp/
        1.2.0/
          installed.json
```

`installed.json` records:

1. scope and name, for example `alice/myapp`
2. version
3. source, registry, and source kind
4. skill artifact name, version, digest, and installed path
5. relative blueprint path, normally `blueprint.yaml`
6. relative lockfile path, normally `agentenv.lock`
7. verification status and verified timestamp
8. deprecation or yanking metadata when supplied by the registry

### Alternative: separate blueprint registry

A separate registry would keep semantics clean because skills and blueprints
are not identical user concepts. It would also duplicate registry config,
credential resolution, SSRF validation, artifact signatures, cache behavior,
publish gates, yanking, and provenance. That creates two hubs to run and two
trust chains to audit before there is evidence that blueprints need a different
transport.

### Alternative: local-only blueprint clones

`agentenv install` could clone or fetch directly into
`~/.agentenv/blueprints/<scope>/<name>/` without touching the skills cache.
That matches the simplest reading of the issue, but it bypasses M7's artifact
dedupe, registry search, signatures, self-test attestations, and publish
infrastructure. It also makes M7-5 bundle export less useful.

## Artifact Contract

A registry-published blueprint artifact should be an M7 skill bundle with these
requirements:

1. `skill.yaml` is present and valid.
2. `agentenv_bundle: true` and `agentenv_schema: "0.1"` are present.
3. `blueprint.yaml` is listed in `files`.
4. `agentenv.lock` is listed in `files`.
5. The bundle digest and signature policy pass the existing skills verifier.
6. `agentenv verify agentenv.lock` passes before the blueprint alias is
   recorded.
7. The lockfile blueprint hash matches `blueprint.yaml`.

GitHub shorthand sources may start as raw blueprint repositories for authoring
convenience. A raw repository install is valid only when the root contains
`agentenv.yaml` and `agentenv.lock`. Core normalizes that into an internal
transient bundle during install, pins the resolved commit, verifies the
lockfile, and records the same blueprint alias metadata. Publishing should
still produce the canonical M7 skill bundle.

## URL Scheme Spec

### Installed handles

```text
<scope>/<name>
<scope>/<name>@<version>
```

Handles resolve through `~/.agentenv/blueprints/index.json`. Without a version,
the current installed version is used. Installing a newer version may move the
current pointer only after verification succeeds.

### GitHub shorthand

```text
github.com/<owner>/<repo>
github.com/<owner>/<repo>@<semver-or-ref>
github.com/<owner>/<repo>//<subdir>
```

The first implementation should support the root path form. Subdirectory and
explicit ref support can be added without changing the overall model.

Resolution rules:

1. Normalize to `git+https://github.com/<owner>/<repo>`.
2. Use non-interactive git fetch behavior from the M7 git registry backend.
3. Resolve the default branch unless a version or ref is explicit.
4. Require `agentenv.yaml` and `agentenv.lock` at the resolved blueprint root
   for raw repositories.
5. Pin the commit SHA in `installed.json`.
6. Run lockfile verification before installing the alias.

If the repository root contains a complete M7 bundle, install it through the
skill service and then create the blueprint alias from the bundled files.

### OCI

```text
ghcr.io/<owner>/<name>:<version>
oci://ghcr.io/<owner>/<name>:<version>
```

OCI uses the existing M7 OCI registry adapter and skill artifact media type.
Blueprint artifacts are distinguished by bundle metadata and optional OCI
annotations, not by a new driver or new protocol. The install flow rejects OCI
artifacts that do not contain `blueprint.yaml` and `agentenv.lock`.

### HTTP registry

```text
https://registry.agentenv.dev/community/<name>
https://registry.agentenv.dev/community/<name>@<version>
```

HTTP registries may expose blueprint discovery at:

```text
/.well-known/agent-blueprints
```

The well-known document maps blueprint handles to existing skill-registry
artifact descriptors. The HTTP adapter still validates every outbound URL
through the SSRF module and rejects redirects or artifact paths outside the
configured registry authority.

## Install UX

```text
agentenv install <source> [--name <scope/name>] [--version <semver>] [--json]
agentenv install <source> --as blueprint
```

`--as blueprint` is optional when the artifact declares `agentenv_bundle: true`
or when the source shape is clearly a raw blueprint repository. If detection is
ambiguous, the CLI should ask in interactive mode and fail with a clear
diagnostic in non-interactive mode.

Install steps:

1. Parse the source as an installed handle, GitHub shorthand, OCI reference,
   HTTP registry URL, filesystem path, or git URL.
2. Fetch into a staging directory through the existing skills registry service
   when possible.
3. Validate bundle metadata or normalize a raw GitHub blueprint repo into a
   transient bundle.
4. Verify signatures, digest, self-test attestation policy, and
   `agentenv.lock`.
5. Install the artifact into `~/.agentenv/skills/`.
6. Write or update the blueprint alias under `~/.agentenv/blueprints/`.
7. Print the handle that can be used with `agentenv create --from`.

Install must not create an environment. It should be safe to run repeatedly; an
existing identical digest is a no-op, while a same-version different digest is
an error unless a later design adds explicit replacement semantics.

## Publish UX

```text
agentenv publish --blueprint <env-or-path> --registry <name-or-url> \
  [--name <scope/name>] [--version <semver>] [--json]
```

This is a user-friendly facade over two existing M7 concepts:

1. freeze and bundle an environment as a skill with `agentenv bundle --as-skill`
2. publish the resulting bundle with the skills registry service

For a directory source, the command should require enough information to freeze
an existing environment or use a supplied lockfile. It should not publish a
bare `agentenv.yaml` without a lockfile.

Publish steps:

1. Resolve the source environment or project directory.
2. Produce or validate `blueprint.yaml` and `agentenv.lock`.
3. Emit an M7-compatible skill bundle with blueprint markers.
4. Run the skill CI and self-test attestation gate required by M7 publish.
5. Publish through filesystem, HTTP, or OCI registries.
6. Return a blueprint handle and install URL.

Git registry publish remains unsupported in the first implementation, matching
M7's read-only git backend.

## `agentenv create --from`

The existing CLI already uses `--from <DOCKERFILE>` together with `--blueprint`
for BYO Dockerfile overlays. M8 can add blueprint source semantics without
breaking that flow by interpreting `--from` based on context:

1. `agentenv create <env> --blueprint <file> --from <dockerfile>` keeps the
   existing Dockerfile overlay behavior.
2. `agentenv create <env> --from <source>` with no `--blueprint` treats
   `<source>` as a blueprint handle, URL, registry reference, or local bundle.
3. A future explicit `--from-dockerfile <path>` alias can make the old meaning
   easier to discover, but the old paired form should continue to work.

Create from an installed handle:

```text
agentenv create myapp --from alice/myapp
```

Core reads the alias, loads the cached `blueprint.yaml` and `agentenv.lock`,
verifies that the installed artifact digest still matches the alias, verifies
the lockfile, and then runs the normal create/reproduce planning path.

Create from a URL:

```text
agentenv create myapp --from github.com/alice/myapp
```

Core performs the same resolution and verification as `agentenv install`, then
continues into create. This is an explicit apply operation because the user
chose `create`. The resolved artifact should be cached and aliased when the
source declares a stable scope/name; one-shot anonymous URLs may remain in the
content-addressed cache without a friendly alias.

## Error Handling

Core should expose typed errors for:

1. unsupported blueprint source scheme
2. ambiguous source kind
3. missing `blueprint.yaml`, `agentenv.yaml`, or `agentenv.lock`
4. lockfile verification failure
5. artifact kind mismatch, such as installing a plain skill as a blueprint
6. alias collision with different digest
7. yanked version install attempt
8. deprecated version warning
9. GitHub source missing a pinned commit after fetch
10. registry URL rejected by SSRF validation

CLI errors should include the source and the failing phase, but must not leak
credentials or bearer tokens from registry configuration.

## Versioning, Yanking, And Deprecation

Blueprint versions use semantic versions from the underlying bundle manifest.
Registry resolution follows M7 patterns:

1. exact versions are reproducible and preferred for automation
2. omitted versions select the highest non-yanked semver at install time
3. installed aliases are pinned after installation and do not float during
   `create`
4. yanked versions cannot be newly installed unless a later recovery flag is
   explicitly added
5. deprecated versions may be installed but print a warning and record the
   deprecation message in alias metadata

`agentenv freeze` and `agentenv reproduce` continue to rely on exact lockfile
pins. Registry metadata helps users find and install artifacts; it does not
replace lockfile reproducibility.

## Security And Trust

Blueprint registry support must reuse the existing security posture:

1. registry URLs pass through the SSRF validator
2. signatures and self-test attestations are enforced through M7 skill publish
   rules
3. credentials stay in the host credstore and do not flow through driver RPC
4. raw GitHub installs pin the resolved commit
5. remote installs require a lockfile
6. install and create plans display the source, version, digest, and registry
   before applying environment changes

No additional runtime dependency is required. Git sources use the existing
non-interactive `git` command strategy from the M7 backend; HTTP and OCI keep
using `reqwest` with `rustls`.

## Future Implementation Shape

Implementation should add a small core layer above skills rather than changing
the skills service itself:

```rust
pub struct BlueprintInstallService { /* root, skills, ssrf */ }

impl BlueprintInstallService {
    pub async fn install(&self, request: BlueprintInstallRequest)
        -> Result<InstalledBlueprint, BlueprintInstallError>;

    pub async fn resolve_for_create(&self, source: &str)
        -> Result<ResolvedBlueprintSource, BlueprintInstallError>;
}
```

The service owns alias metadata, source parsing, raw GitHub normalization, and
lockfile verification. It delegates artifact fetch, signature checks, publish,
and local cache writes to `SkillService`.

Future tests should cover:

1. installing an M7 bundle as a blueprint alias
2. rejecting a plain skill without blueprint files
3. rejecting a remote blueprint without `agentenv.lock`
4. create from installed alias uses pinned cached content
5. create from URL performs fetch, verify, cache, and create
6. existing `--blueprint <file> --from <dockerfile>` behavior remains intact
7. HTTP and OCI sources reject artifacts outside the configured authority
8. yanked and deprecated registry metadata affects install decisions

## Rollout Notes

The first implementation PR should list `agentenv` and `agentenv-core` as
affected crates and explicitly note that `agentenv-proto` is unchanged. The PR
should also call out the CLI compatibility rule for the existing Dockerfile
`--from` behavior, because that is the main user-facing ambiguity introduced by
this design.
