# Build Oneflight Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add digest-keyed oneflight for OpenShell BYO image materialization so concurrent creates share one Docker build while still creating independent sandboxes.

**Architecture:** `agentenv-core` computes stable BYO build seed metadata from verified create inputs. `sandbox-openshell` completes the final build key from Dockerfile/context inputs, coordinates builders and waiters with a file-backed cache, and emits build oneflight activity events. `agentenv-events` derives the required Prometheus metrics from those activity events.

**Tech Stack:** Rust 2021, Tokio tests, `serde`/`serde_json`, `sha256:` digests through `agentenv-core::digest`, filesystem locks with atomic directory creation, existing `EventEmitter` and SQLite-backed metrics.

---

## File Structure

- Modify `crates/agentenv-events/src/activity.rs`: add build oneflight activity kinds.
- Modify `crates/agentenv-events/src/store.rs`: add aggregate queries for hit/miss counts and latest queue depth.
- Modify `crates/agentenv-events/src/metrics.rs`: add snapshot fields and Prometheus rendering.
- Modify `crates/agentenv-core/src/runtime.rs`: compute and pass BYO oneflight seed metadata.
- Modify `crates/drivers/sandbox-openshell/Cargo.toml`: add `agentenv-events` and `serde` dependencies.
- Modify `crates/drivers/sandbox-openshell/src/lib.rs`: add event emitter support, parse oneflight metadata, route BYO builds through the cache, and update tests.
- Create `crates/drivers/sandbox-openshell/src/build_cache.rs`: own build-key computation, metadata persistence, cache validation, queue guards, file locks, and failure marker handling.
- Modify `crates/agentenv/src/builtin_factory.rs`: pass event emitters to OpenShell drivers.

## Task 1: Activity Kinds And Prometheus Metrics

**Files:**
- Modify: `crates/agentenv-events/src/activity.rs`
- Modify: `crates/agentenv-events/src/store.rs`
- Modify: `crates/agentenv-events/src/metrics.rs`

- [ ] **Step 1: Write failing activity-kind serialization test**

Add these assertions to `activity_kind_serializes_to_stable_snake_case` in `crates/agentenv-events/src/activity.rs`:

```rust
assert_eq!(
    serde_json::to_value(ActivityKind::BuildOneflightHit).unwrap(),
    serde_json::json!("build_oneflight_hit")
);
assert_eq!(
    serde_json::to_value(ActivityKind::BuildOneflightMiss).unwrap(),
    serde_json::json!("build_oneflight_miss")
);
assert_eq!(
    serde_json::to_value(ActivityKind::BuildQueueDepth).unwrap(),
    serde_json::json!("build_queue_depth")
);
```

- [ ] **Step 2: Run activity test to verify it fails**

Run:

```bash
cargo test -p agentenv-events activity_kind_serializes_to_stable_snake_case
```

Expected: FAIL with errors that `ActivityKind` has no variants named `BuildOneflightHit`, `BuildOneflightMiss`, and `BuildQueueDepth`.

- [ ] **Step 3: Add activity variants**

Add these variants to `ActivityKind` in `crates/agentenv-events/src/activity.rs`, after `SpawnReady` and before `Log`:

```rust
BuildOneflightHit,
BuildOneflightMiss,
BuildQueueDepth,
```

- [ ] **Step 4: Run activity test to verify it passes**

Run:

```bash
cargo test -p agentenv-events activity_kind_serializes_to_stable_snake_case
```

Expected: PASS.

- [ ] **Step 5: Write failing metrics tests**

Add this test to `crates/agentenv-events/src/metrics.rs` inside `mod tests`:

```rust
#[test]
fn prometheus_render_includes_build_oneflight_metrics() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();
    store
        .append_many(&[
            event(
                "2026-05-06T12:00:00Z",
                ActivityKind::BuildOneflightHit,
                ActivityResult::Ok,
            ),
            event(
                "2026-05-06T12:00:01Z",
                ActivityKind::BuildOneflightHit,
                ActivityResult::Ok,
            ),
            event(
                "2026-05-06T12:00:02Z",
                ActivityKind::BuildOneflightMiss,
                ActivityResult::Ok,
            ),
            event(
                "2026-05-06T12:00:03Z",
                ActivityKind::BuildQueueDepth,
                ActivityResult::Ok,
            )
            .with_extra("depth", serde_json::json!(3)),
            event(
                "2026-05-06T12:00:04Z",
                ActivityKind::BuildQueueDepth,
                ActivityResult::Ok,
            )
            .with_extra("depth", serde_json::json!(1)),
        ])
        .unwrap();

    let snapshot = MetricsSnapshot::from_store(&store, &[]).unwrap();
    let rendered = render_prometheus(&snapshot);

    assert!(rendered.contains("# HELP agentenv_build_oneflight_hits_total "));
    assert!(rendered.contains("# TYPE agentenv_build_oneflight_hits_total counter"));
    assert!(rendered.contains("agentenv_build_oneflight_hits_total 2"));
    assert!(rendered.contains("# HELP agentenv_build_oneflight_misses_total "));
    assert!(rendered.contains("# TYPE agentenv_build_oneflight_misses_total counter"));
    assert!(rendered.contains("agentenv_build_oneflight_misses_total 1"));
    assert!(rendered.contains("# HELP agentenv_build_queue_depth "));
    assert!(rendered.contains("# TYPE agentenv_build_queue_depth gauge"));
    assert!(rendered.contains("agentenv_build_queue_depth 1"));
}

#[test]
fn build_queue_depth_defaults_to_zero() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();
    let snapshot = MetricsSnapshot::from_store(&store, &[]).unwrap();
    let rendered = render_prometheus(&snapshot);

    assert!(rendered.contains("agentenv_build_queue_depth 0"));
}
```

- [ ] **Step 6: Run metrics tests to verify they fail**

Run:

```bash
cargo test -p agentenv-events prometheus_render_includes_build_oneflight_metrics build_queue_depth_defaults_to_zero
```

Expected: FAIL because `MetricsSnapshot` has no build oneflight fields and `render_prometheus` does not render those series.

- [ ] **Step 7: Add store aggregate methods**

Add these methods to `impl SqliteEventStore` in `crates/agentenv-events/src/store.rs`, after `counts_by_kind_result`:

```rust
pub fn count_events_by_kind(&self, kind: ActivityKind) -> StoreResult<u64> {
    let conn = self.connection()?;
    let kind = enum_to_db_string(kind, "kind")?;
    let count = conn.query_row(
        r#"
        SELECT COUNT(*)
        FROM activity_events
        WHERE kind = ?1
        "#,
        params![kind],
        |row| row.get::<_, i64>(0),
    )?;
    count_to_u64(count)
}

pub fn latest_build_queue_depth(&self) -> StoreResult<u64> {
    let conn = self.connection()?;
    let kind = enum_to_db_string(ActivityKind::BuildQueueDepth, "kind")?;
    let value = conn.query_row(
        r#"
        SELECT
            CASE
                WHEN json_type(extras_json, '$.depth') = 'integer'
                THEN json_extract(extras_json, '$.depth')
                ELSE 0
            END
        FROM activity_events
        WHERE kind = ?1
        ORDER BY id DESC
        LIMIT 1
        "#,
        params![kind],
        |row| row.get::<_, Option<i64>>(0),
    );

    match value {
        Ok(Some(depth)) if depth >= 0 => count_to_u64(depth),
        Ok(Some(depth)) => Err(StoreError::CountOutOfRange(depth)),
        Ok(None) => Ok(0),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
        Err(err) => Err(err.into()),
    }
}
```

- [ ] **Step 8: Add metrics snapshot fields and rendering**

In `crates/agentenv-events/src/metrics.rs`, add these fields to `MetricsSnapshot`:

```rust
pub build_oneflight_hits_total: u64,
pub build_oneflight_misses_total: u64,
pub build_queue_depth: u64,
```

In `MetricsSnapshot::from_store`, populate them:

```rust
let build_oneflight_hits_total = store.count_events_by_kind(ActivityKind::BuildOneflightHit)?;
let build_oneflight_misses_total = store.count_events_by_kind(ActivityKind::BuildOneflightMiss)?;
let build_queue_depth = store.latest_build_queue_depth()?;
```

Add the fields to the returned `Self`:

```rust
build_oneflight_hits_total,
build_oneflight_misses_total,
build_queue_depth,
```

In `render_prometheus`, render these series before event sink metrics:

```rust
render_help_type(
    &mut output,
    "agentenv_build_oneflight_hits_total",
    "Total build oneflight cache hits and waiters.",
    "counter",
);
render_scalar(
    &mut output,
    "agentenv_build_oneflight_hits_total",
    snapshot.build_oneflight_hits_total,
);

render_help_type(
    &mut output,
    "agentenv_build_oneflight_misses_total",
    "Total build oneflight builder requests.",
    "counter",
);
render_scalar(
    &mut output,
    "agentenv_build_oneflight_misses_total",
    snapshot.build_oneflight_misses_total,
);

render_help_type(
    &mut output,
    "agentenv_build_queue_depth",
    "Latest observed number of build oneflight waiters.",
    "gauge",
);
render_scalar(
    &mut output,
    "agentenv_build_queue_depth",
    snapshot.build_queue_depth,
);
```

Update every explicit `MetricsSnapshot` test literal to include:

```rust
build_oneflight_hits_total: 0,
build_oneflight_misses_total: 0,
build_queue_depth: 0,
```

- [ ] **Step 9: Run metrics tests to verify they pass**

Run:

```bash
cargo test -p agentenv-events prometheus_render_includes_required_series prometheus_render_includes_build_oneflight_metrics build_queue_depth_defaults_to_zero
```

Expected: PASS.

- [ ] **Step 10: Commit metrics work**

Run:

```bash
git add crates/agentenv-events/src/activity.rs crates/agentenv-events/src/store.rs crates/agentenv-events/src/metrics.rs
git commit -m "feat(events): expose build oneflight metrics"
```

## Task 2: Core BYO Build Seed Metadata

**Files:**
- Modify: `crates/agentenv-core/src/runtime.rs`

- [ ] **Step 1: Write failing test for BYO seed metadata**

Extend `create_env_passes_byo_dockerfile_metadata_to_sandbox` in `crates/agentenv-core/src/runtime.rs` with these assertions after `agentenv_agent`:

```rust
assert_eq!(
    metadata["agentenv_build_oneflight"],
    serde_json::json!("byo-openshell-v1")
);
assert_eq!(metadata["agentenv_build_seed_version"], serde_json::json!("1"));
let seed = metadata["agentenv_build_seed"]
    .as_str()
    .expect("seed metadata is a string");
crate::digest::parse_sha256_digest(seed).expect("seed is a sha256 digest");
```

- [ ] **Step 2: Write failing test for non-BYO metadata omission**

Add this test near `create_env_passes_byo_dockerfile_metadata_to_sandbox`:

```rust
#[tokio::test]
async fn create_env_omits_build_oneflight_metadata_for_non_byo_image() {
    let root = unique_root("agentenv-create-non-byo-no-build-seed");
    let options = RuntimeOptions {
        root,
        log_level: LogLevel::Info,
        non_interactive: true,
    };
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  image: openclaw
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
    let tracker = Arc::new(AgentSetupTracker::default());
    let mut credentials = super::tests_support::EmptyCredentialProvider;

    super::create_env(
        &options,
        &AgentSetupFactory {
            tracker: Arc::clone(&tracker),
        },
        &mut credentials,
        "demo",
        yaml,
    )
    .await
    .unwrap();

    let specs = tracker.create_specs.lock().expect("create spec tracker");
    let metadata = &specs[0].metadata;
    assert!(!metadata.contains_key("agentenv_build_oneflight"));
    assert!(!metadata.contains_key("agentenv_build_seed"));
    assert!(!metadata.contains_key("agentenv_build_seed_version"));
}
```

- [ ] **Step 3: Run core tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core create_env_passes_byo_dockerfile_metadata_to_sandbox create_env_omits_build_oneflight_metadata_for_non_byo_image
```

Expected: FAIL because the metadata keys are absent.

- [ ] **Step 4: Add constants and seed helper**

In `crates/agentenv-core/src/runtime.rs`, add constants near `AGENT_ENTRYPOINT_PATH`:

```rust
const BUILD_ONEFLIGHT_KIND: &str = "byo-openshell-v1";
const BUILD_ONEFLIGHT_SEED_VERSION: &str = "1";
```

Add these structs and helper functions near `sandbox_spec_for_create`:

```rust
#[derive(Serialize)]
struct BuildOneflightSeed<'a> {
    version: &'static str,
    blueprint_yaml: &'a str,
    lock_yaml: &'a str,
    sandbox_driver: &'a str,
    sandbox_driver_version: &'a str,
    agent_driver: &'a str,
    agent_driver_version: &'a str,
    context_driver: &'a str,
    context_driver_version: &'a str,
    inference_driver: Option<&'a str>,
    inference_driver_version: Option<&'a str>,
    metadata: BTreeMap<&'static str, String>,
}

fn build_oneflight_seed_for_byo(
    blueprint_yaml: &str,
    lock_yaml: &str,
    selection: &DriverSelection,
    resolved: &crate::lifecycle::ResolvedBlueprint,
    context_endpoint: &agentenv_proto::McpEndpoint,
    sandbox_extra: &BTreeMap<String, serde_yaml::Value>,
) -> RuntimeResult<Option<String>> {
    if !sandbox_image_is_byo(sandbox_extra) {
        return Ok(None);
    }

    let metadata = BTreeMap::from([
        (
            "agentenv_version",
            env!("CARGO_PKG_VERSION").to_owned(),
        ),
        ("agentenv_agent", selection.agent.clone()),
        (
            "agentenv_mcp_port",
            mcp_endpoint_port(context_endpoint).unwrap_or_default(),
        ),
        ("agentenv_workspace_mount", "/sandbox".to_owned()),
    ]);
    let seed = BuildOneflightSeed {
        version: BUILD_ONEFLIGHT_SEED_VERSION,
        blueprint_yaml,
        lock_yaml,
        sandbox_driver: &selection.sandbox,
        sandbox_driver_version: &resolved.sandbox.version.to_string(),
        agent_driver: &selection.agent,
        agent_driver_version: &resolved.agent.version.to_string(),
        context_driver: &selection.context,
        context_driver_version: &resolved.context.version.to_string(),
        inference_driver: selection.inference.as_deref(),
        inference_driver_version: resolved
            .inference
            .as_ref()
            .map(|driver| driver.version.to_string())
            .as_deref(),
        metadata,
    };
    let bytes = serde_json::to_vec(&seed).map_err(|source| {
        RuntimeError::Driver(DriverError::InvalidInput {
            message: format!("failed to serialize build oneflight seed: {source}"),
        })
    })?;
    Ok(Some(format!("sha256:{}", crate::digest::sha256_hex(&bytes))))
}

fn sandbox_image_is_byo(sandbox_extra: &BTreeMap<String, serde_yaml::Value>) -> bool {
    sandbox_extra
        .get("image")
        .and_then(serde_yaml::Value::as_mapping)
        .is_some_and(|image| yaml_mapping_string(image, "source") == Some("byo"))
}
```

- [ ] **Step 5: Pass seed metadata into sandbox spec**

Change `sandbox_spec_for_create` to accept a seed:

```rust
fn sandbox_spec_for_create(
    name: &str,
    selection: &DriverSelection,
    sandbox_extra: &BTreeMap<String, serde_yaml::Value>,
    context_endpoint: &agentenv_proto::McpEndpoint,
    env: BTreeMap<String, String>,
    policy: Option<agentenv_proto::NetworkPolicy>,
    build_oneflight_seed: Option<String>,
) -> RuntimeResult<agentenv_proto::SandboxSpec> {
```

Before returning `SandboxSpec`, add:

```rust
if let Some(seed) = build_oneflight_seed {
    metadata.insert(
        "agentenv_build_oneflight".to_owned(),
        serde_json::json!(BUILD_ONEFLIGHT_KIND),
    );
    metadata.insert(
        "agentenv_build_seed".to_owned(),
        serde_json::json!(seed),
    );
    metadata.insert(
        "agentenv_build_seed_version".to_owned(),
        serde_json::json!(BUILD_ONEFLIGHT_SEED_VERSION),
    );
}
```

At the call site before `sandbox_spec_for_create`, compute the seed:

```rust
let build_oneflight_seed = build_oneflight_seed_for_byo(
    blueprint_yaml,
    &lock_yaml,
    &selection,
    &resolved,
    &context_endpoint,
    &resolved.blueprint.sandbox.extra,
)?;
```

Pass `build_oneflight_seed` as the final argument.

- [ ] **Step 6: Run core tests to verify they pass**

Run:

```bash
cargo test -p agentenv-core create_env_passes_byo_dockerfile_metadata_to_sandbox create_env_omits_build_oneflight_metadata_for_non_byo_image create_env_records_computed_byo_digest_in_lockfile
```

Expected: PASS.

- [ ] **Step 7: Commit core seed work**

Run:

```bash
git add crates/agentenv-core/src/runtime.rs
git commit -m "feat(core): add byo build oneflight seed"
```

## Task 3: OpenShell Driver Event Emitter Wiring

**Files:**
- Modify: `crates/drivers/sandbox-openshell/Cargo.toml`
- Modify: `crates/drivers/sandbox-openshell/src/lib.rs`
- Modify: `crates/agentenv/src/builtin_factory.rs`

- [ ] **Step 1: Write failing built-in factory test**

Add this test to `crates/agentenv/src/builtin_factory.rs` inside `mod tests`:

```rust
#[test]
fn openshell_driver_receives_observed_event_emitter() {
    let factory = BuiltInDriverFactory;
    let selection = DriverSelection {
        sandbox: "openshell".to_owned(),
        agent: "codex".to_owned(),
        context: "filesystem".to_owned(),
        inference: None,
    };
    let events = Arc::new(agentenv_events::RecordingEventEmitter::default());

    let mut set = factory
        .build_observed(&selection, Arc::clone(&events) as Arc<dyn agentenv_events::EventEmitter>)
        .expect("driver set");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime
        .block_on(async {
            set.sandbox
                .shutdown(agentenv_proto::ShutdownParams {})
                .await
        })
        .expect("shutdown");

    assert!(events
        .recorded()
        .iter()
        .any(|event| event.actor.get("driver") == Some(&serde_json::json!("openshell"))));
}
```

- [ ] **Step 2: Run factory test to verify it fails**

Run:

```bash
cargo test -p agentenv openshell_driver_receives_observed_event_emitter
```

Expected: FAIL because `OpenShellDriver` does not store or emit through the provided emitter.

- [ ] **Step 3: Add dependencies**

In `crates/drivers/sandbox-openshell/Cargo.toml`, add:

```toml
agentenv-events = { path = "../../agentenv-events" }
serde.workspace = true
```

- [ ] **Step 4: Add event emitter to OpenShellDriver**

In `crates/drivers/sandbox-openshell/src/lib.rs`, add imports:

```rust
use agentenv_events::{ActivityEvent, ActivityKind, ActivityResult, EventEmitter, NoopEventEmitter};
```

Add a field to `OpenShellDriver`:

```rust
events: Arc<dyn EventEmitter>,
```

Add this field to every `OpenShellDriver` constructor:

```rust
events: Arc::new(NoopEventEmitter),
```

Add this method to `impl OpenShellDriver`:

```rust
pub fn with_event_emitter(mut self, events: Arc<dyn EventEmitter>) -> Self {
    self.events = events;
    self
}
```

For the failing test, add this harmless shutdown event at the start of `shutdown`:

```rust
self.events.emit(
    ActivityEvent::new(
        now_rfc3339(),
        ActivityKind::Log,
        ActivityResult::Ok,
        format!("openshell-shutdown-{}", Uuid::new_v4()),
    )
    .with_actor_value("driver", serde_json::json!("openshell")),
);
```

- [ ] **Step 5: Pass emitters from built-in factory**

In `crates/agentenv/src/builtin_factory.rs`, replace OpenShell construction in both unpinned and pinned paths:

```rust
Box::new(sandbox_openshell::OpenShellDriver::default().with_event_emitter(Arc::clone(&events)))
```

For `build_pinned_sandbox`, add an `events: Arc<dyn EventEmitter>` parameter and pass it from `build_pinned_driver_set_with_context`. Use the same construction expression after `validate_builtin_pin`.

- [ ] **Step 6: Run factory test to verify it passes**

Run:

```bash
cargo test -p agentenv openshell_driver_receives_observed_event_emitter
```

Expected: PASS.

- [ ] **Step 7: Commit emitter wiring**

Run:

```bash
git add crates/drivers/sandbox-openshell/Cargo.toml crates/drivers/sandbox-openshell/src/lib.rs crates/agentenv/src/builtin_factory.rs
git commit -m "feat(openshell): wire build event emitter"
```

## Task 4: Build Cache Data Model And Cache Hit Path

**Files:**
- Create: `crates/drivers/sandbox-openshell/src/build_cache.rs`
- Modify: `crates/drivers/sandbox-openshell/src/lib.rs`

- [ ] **Step 1: Write failing cache-hit test**

Add this test to `crates/drivers/sandbox-openshell/src/lib.rs` inside `driver_tests`:

```rust
#[test]
fn create_reuses_valid_byo_build_cache() {
    let tempdir = unique_tempdir("sandbox-openshell-byo-cache-hit");
    let workdir = tempdir.join(".agentenv");
    let dockerfile_dir = tempdir.join("enterprise-sandbox");
    std::fs::create_dir_all(&dockerfile_dir).expect("create source context");
    let dockerfile = dockerfile_dir.join("Dockerfile");
    std::fs::write(&dockerfile, "FROM alpine:3.20\n").expect("write source Dockerfile");
    let key_stage_dir = workdir.join("build").join("devbox-key");
    super::stage_build_context(&dockerfile_dir, &dockerfile, &key_stage_dir)
        .expect("stage key context");
    let context_digest =
        super::build_cache::BuildCache::digest_staged_context(&key_stage_dir)
            .expect("context digest");
    let noop = agentenv_events::NoopEventEmitter;
    let cache = super::build_cache::BuildCache::new(workdir.clone(), &noop);
    let input = super::build_cache::BuildInput {
        env_name: "devbox".to_owned(),
        dockerfile: dockerfile.clone(),
        staged_context: key_stage_dir.clone(),
        context_digest: context_digest.clone(),
        expected_digest: None,
        agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
        agent: "codex".to_owned(),
        mcp_port: "3333".to_owned(),
        workspace_mount: "/sandbox".to_owned(),
        seed: Some("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned()),
    };
    let cache_key = cache.build_key(&input).expect("build key");
    let cache_dir = cache.cache_dir(&cache_key);
    let context_dir = cache_dir.join("context");
    std::fs::create_dir_all(&cache_dir).expect("create cache dir");
    std::fs::rename(&key_stage_dir, &context_dir).expect("move staged context to cache");
    let digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    std::fs::write(cache_dir.join("image-digest"), format!("{digest}\n"))
        .expect("write digest");
    std::fs::write(
        cache_dir.join("metadata.json"),
        serde_json::json!({
            "version": 1,
            "build_key": cache_key,
            "driver": "openshell",
            "driver_version": env!("CARGO_PKG_VERSION"),
            "image_ref": context_dir.display().to_string(),
            "image_digest": digest,
            "created_at": "2026-05-06T12:00:00Z",
            "source": {
                "dockerfile": dockerfile.display().to_string(),
                "context_digest": context_digest
            }
        })
        .to_string(),
    )
    .expect("write metadata");

    let tag = super::build_cache::tag_for_key(&cache_key);
    let runner = Arc::new(FlexibleCommandRunner::new(vec![
        FlexibleCommandExpectation::success(
            "docker",
            move |call| {
                assert_eq!(
                    call.request.args,
                    vec![
                        "image".to_owned(),
                        "inspect".to_owned(),
                        "--format".to_owned(),
                        "{{.Id}}".to_owned(),
                        tag.to_owned(),
                    ]
                );
            },
            &format!("{digest}\n"),
            "",
        ),
        FlexibleCommandExpectation::success(
            "openshell",
            {
                let context_arg = context_dir.display().to_string();
                move |call| {
                    assert_eq!(
                        call.request,
                        command_request(&[
                            "sandbox",
                            "create",
                            "--name",
                            "devbox",
                            "--no-auto-providers",
                            "--from",
                            &context_arg,
                            "--",
                            "true",
                        ])
                    );
                }
            },
            "",
            "",
        ),
    ]));
    let driver = OpenShellDriver::with_command_runner_and_workdir(runner.clone(), &workdir);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime
        .block_on(async {
            driver
                .create(SandboxSpec {
                    image: None,
                    env: BTreeMap::new(),
                    policy: None,
                    metadata: BTreeMap::from([
                        ("name".to_owned(), json!("devbox")),
                        ("byo_dockerfile".to_owned(), json!(dockerfile.display().to_string())),
                        ("agentenv_agent".to_owned(), json!("codex")),
                        ("agentenv_mcp_port".to_owned(), json!("3333")),
                        ("agentenv_workspace_mount".to_owned(), json!("/sandbox")),
                        ("agentenv_version".to_owned(), json!(env!("CARGO_PKG_VERSION"))),
                        ("agentenv_build_oneflight".to_owned(), json!("byo-openshell-v1")),
                        ("agentenv_build_seed_version".to_owned(), json!("1")),
                        ("agentenv_build_seed".to_owned(), json!("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")),
                    ]),
                })
                .await
        })
        .expect("create");

    assert_eq!(runner.calls().len(), 2);
    assert_eq!(
        std::fs::read_to_string(workdir.join("build").join("devbox").join("image-digest"))
            .expect("per env digest"),
        format!("{digest}\n")
    );
    std::fs::remove_dir_all(tempdir).expect("remove tempdir");
}
```

- [ ] **Step 2: Run cache-hit test to verify it fails**

Run:

```bash
cargo test -p sandbox-openshell create_reuses_valid_byo_build_cache
```

Expected: FAIL because no build cache module exists and create still runs `docker build`.

- [ ] **Step 3: Create build cache module skeleton**

Create `crates/drivers/sandbox-openshell/src/build_cache.rs` with:

```rust
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, SystemTime},
};

use agentenv_core::{
    digest::{parse_sha256_digest, sha256_hex},
    driver::{DriverError, DriverResult},
};
use agentenv_events::{ActivityEvent, ActivityKind, ActivityResult, EventEmitter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{now_rfc3339, CommandOutput, CommandRequest, CommandRunner};

static BUILD_QUEUE_DEPTH: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_BUILDERS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone)]
pub(super) struct BuildQueueConfig {
    pub max_inflight: usize,
    pub queue_limit: usize,
    pub lock_timeout: Duration,
}

impl BuildQueueConfig {
    pub fn from_env() -> Self {
        Self {
            max_inflight: env_usize("AGENTENV_BUILD_MAX_INFLIGHT", 4).max(1),
            queue_limit: env_usize("AGENTENV_BUILD_QUEUE_LIMIT", 128),
            lock_timeout: Duration::from_secs(env_usize("AGENTENV_BUILD_LOCK_TIMEOUT_SECS", 900) as u64),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct BuildInput {
    pub env_name: String,
    pub dockerfile: PathBuf,
    pub staged_context: PathBuf,
    pub context_digest: String,
    pub expected_digest: Option<String>,
    pub agentenv_version: String,
    pub agent: String,
    pub mcp_port: String,
    pub workspace_mount: String,
    pub seed: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct BuildMaterialization {
    pub image_ref: String,
    pub image_digest: String,
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BuildMetadata {
    version: u8,
    build_key: String,
    driver: String,
    driver_version: String,
    image_ref: String,
    image_digest: String,
    created_at: String,
    source: BuildSourceMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BuildSourceMetadata {
    dockerfile: String,
    context_digest: String,
}

pub(super) struct BuildCache<'a> {
    root: PathBuf,
    config: BuildQueueConfig,
    events: &'a dyn EventEmitter,
}

impl<'a> BuildCache<'a> {
    pub(super) fn new(root: PathBuf, events: &'a dyn EventEmitter) -> Self {
        Self {
            root,
            config: BuildQueueConfig::from_env(),
            events,
        }
    }

    pub(super) fn materialize_cached(
        &self,
        input: &BuildInput,
        runner: &dyn CommandRunner,
    ) -> DriverResult<Option<BuildMaterialization>> {
        let key = self.build_key(input)?;
        let cache_dir = self.cache_dir(&key);
        let Some(metadata) = self.read_valid_metadata(&key, &cache_dir, runner)? else {
            return Ok(None);
        };
        self.emit(ActivityKind::BuildOneflightHit, 0);
        self.write_env_digest(&input.env_name, &metadata.image_digest)?;
        Ok(Some(BuildMaterialization {
            image_ref: metadata.image_ref,
            image_digest: metadata.image_digest,
            tag: tag_for_key(&key),
        }))
    }

    pub(super) fn build_key(&self, input: &BuildInput) -> DriverResult<String> {
        let dockerfile = fs::canonicalize(&input.dockerfile).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to resolve BYO Dockerfile `{}`: {source}", input.dockerfile.display()),
        })?;
        let seed = input.seed.as_deref().unwrap_or("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        let material = serde_json::json!({
            "version": 1,
            "seed": seed,
            "dockerfile": dockerfile.display().to_string(),
            "context_digest": input.context_digest,
            "agentenv_version": input.agentenv_version,
            "agent": input.agent,
            "mcp_port": input.mcp_port,
            "workspace_mount": input.workspace_mount,
            "driver_version": env!("CARGO_PKG_VERSION")
        });
        Ok(format!("sha256:{}", sha256_hex(material.to_string().as_bytes())))
    }

    pub(super) fn digest_staged_context(path: &Path) -> DriverResult<String> {
        let mut entries = Vec::new();
        collect_context_entries(path, path, &mut entries)?;
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let mut bytes = Vec::new();
        for (relative, payload) in entries {
            bytes.extend_from_slice(relative.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&payload);
            bytes.push(0);
        }
        Ok(format!("sha256:{}", sha256_hex(&bytes)))
    }

    pub(super) fn cache_dir(&self, key: &str) -> PathBuf {
        self.root.join("build-cache").join(cache_dir_name(key))
    }

    pub(super) fn write_env_digest(&self, env_name: &str, digest: &str) -> DriverResult<()> {
        parse_sha256_digest(digest).map_err(|source| DriverError::InvalidInput {
            message: format!("cached BYO image digest `{digest}` is invalid: {source}"),
        })?;
        let digest_dir = self.root.join("build").join(crate::sanitize_build_name(env_name));
        fs::create_dir_all(&digest_dir).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to create BYO digest sidecar `{}`: {source}", digest_dir.display()),
        })?;
        fs::write(digest_dir.join("image-digest"), format!("{digest}\n")).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to write BYO digest sidecar for `{env_name}`: {source}"),
        })?;
        Ok(())
    }

    fn read_valid_metadata(
        &self,
        key: &str,
        cache_dir: &Path,
        runner: &dyn CommandRunner,
    ) -> DriverResult<Option<BuildMetadata>> {
        let metadata_path = cache_dir.join("metadata.json");
        if !metadata_path.is_file() {
            return Ok(None);
        }
        let metadata_bytes = fs::read(&metadata_path).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to read build cache metadata `{}`: {source}", metadata_path.display()),
        })?;
        let metadata: BuildMetadata = serde_json::from_slice(&metadata_bytes).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to parse build cache metadata `{}`: {source}", metadata_path.display()),
        })?;
        if metadata.version != 1
            || metadata.build_key != key
            || metadata.driver != "openshell"
            || metadata.driver_version != env!("CARGO_PKG_VERSION")
        {
            let _ = fs::remove_file(&metadata_path);
            return Ok(None);
        }
        let image_ref = PathBuf::from(&metadata.image_ref);
        if !image_ref.starts_with(cache_dir.join("context")) || !image_ref.is_dir() {
            let _ = fs::remove_file(&metadata_path);
            return Ok(None);
        }
        parse_sha256_digest(&metadata.image_digest).map_err(|source| DriverError::InvalidInput {
            message: format!("cached BYO image digest `{}` is invalid: {source}", metadata.image_digest),
        })?;
        let inspect = runner.run("docker", &CommandRequest {
            args: vec![
                "image".to_owned(),
                "inspect".to_owned(),
                "--format".to_owned(),
                "{{.Id}}".to_owned(),
                tag_for_key(key),
            ],
            env: std::collections::BTreeMap::new(),
        }).map_err(|source| DriverError::CommandSpawn {
            command: "docker image inspect".to_owned(),
            source,
        })?;
        if inspect.status != Some(0) || inspect.stdout.trim() != metadata.image_digest {
            let _ = fs::remove_file(&metadata_path);
            return Ok(None);
        }
        Ok(Some(metadata))
    }

    fn emit(&self, kind: ActivityKind, depth: usize) {
        self.events.emit(
            ActivityEvent::new(now_rfc3339(), kind, ActivityResult::Ok, format!("build-{}", Uuid::new_v4()))
                .with_actor_value("driver", serde_json::json!("openshell"))
                .with_extra("depth", serde_json::json!(depth)),
        );
    }
}

pub(super) fn cache_dir_name(key: &str) -> String {
    key.replace(':', "-")
}

pub(super) fn tag_for_key(key: &str) -> String {
    let hex = key.strip_prefix("sha256:").unwrap_or(key);
    format!("agentenv-byo-{}:latest", &hex[..12])
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn collect_context_entries(
    root: &Path,
    current: &Path,
    entries: &mut Vec<(String, Vec<u8>)>,
) -> DriverResult<()> {
    for entry in fs::read_dir(current).map_err(|source| DriverError::InvalidInput {
        message: format!("failed to read staged context `{}`: {source}", current.display()),
    })? {
        let entry = entry.map_err(|source| DriverError::InvalidInput {
            message: format!("failed to read staged context entry: {source}"),
        })?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let metadata = fs::symlink_metadata(&path).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to stat staged context `{}`: {source}", path.display()),
        })?;
        if metadata.is_dir() {
            collect_context_entries(root, &path, entries)?;
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path).map_err(|source| DriverError::InvalidInput {
                message: format!("failed to read staged symlink `{}`: {source}", path.display()),
            })?;
            entries.push((format!("symlink:{relative}"), target.to_string_lossy().into_owned().into_bytes()));
        } else if metadata.is_file() {
            let contents = fs::read(&path).map_err(|source| DriverError::InvalidInput {
                message: format!("failed to read staged file `{}`: {source}", path.display()),
            })?;
            entries.push((format!("file:{relative}"), contents));
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Include module and try cache hit in BYO prepare**

In `crates/drivers/sandbox-openshell/src/lib.rs`, add:

```rust
mod build_cache;
```

Extend `ByoDockerfileConfig`:

```rust
build_seed: Option<String>,
```

In `byo_dockerfile_config`, set:

```rust
build_seed: optional_metadata_string(metadata, "agentenv_build_seed")?,
```

In `prepare_byo_dockerfile_context`, stage to a temporary per-env key directory before checking the cache:

```rust
let cache = build_cache::BuildCache::new(self.workdir(), self.events.as_ref());
let key_stage_dir = self
    .workdir()
    .join("build")
    .join(format!("{}-key", sanitize_build_name(name)));
stage_build_context(context_dir, &dockerfile, &key_stage_dir)?;
let context_digest = build_cache::BuildCache::digest_staged_context(&key_stage_dir)?;
let input = build_cache::BuildInput {
    env_name: name.to_owned(),
    dockerfile: config.dockerfile.clone(),
    staged_context: key_stage_dir.clone(),
    context_digest,
    expected_digest: config.expected_digest.clone(),
    agentenv_version: config.agentenv_version.clone(),
    agent: config.agent.clone(),
    mcp_port: config.mcp_port.clone(),
    workspace_mount: config.workspace_mount.clone(),
    seed: config.build_seed.clone(),
};
if let Some(materialized) = cache.materialize_cached(&input, self.runner.as_ref())? {
    let _ = fs::remove_dir_all(&key_stage_dir);
    return Ok(materialized.image_ref);
}
```

- [ ] **Step 5: Run cache-hit test to verify it passes**

Run:

```bash
cargo test -p sandbox-openshell create_reuses_valid_byo_build_cache
```

Expected: PASS.

- [ ] **Step 6: Commit cache hit work**

Run:

```bash
git add crates/drivers/sandbox-openshell/src/build_cache.rs crates/drivers/sandbox-openshell/src/lib.rs
git commit -m "feat(openshell): reuse byo build cache"
```

## Task 5: Builder Path, Metadata Persistence, And Invalidation

**Files:**
- Modify: `crates/drivers/sandbox-openshell/src/build_cache.rs`
- Modify: `crates/drivers/sandbox-openshell/src/lib.rs`

- [ ] **Step 1: Write failing test for key-based build metadata**

Update `create_builds_byo_dockerfile_and_uses_staged_context` so expected build paths use `build-cache/<key>/context`, and add these assertions after the existing digest assertion:

```rust
let metadata_files = std::fs::read_dir(workdir.join("build-cache"))
    .expect("build cache dir")
    .map(|entry| entry.expect("cache entry").path().join("metadata.json"))
    .collect::<Vec<_>>();
assert_eq!(metadata_files.len(), 1);
let metadata: serde_json::Value = serde_json::from_str(
    &std::fs::read_to_string(&metadata_files[0]).expect("metadata json"),
)
.expect("parse metadata");
assert_eq!(metadata["version"], serde_json::json!(1));
assert_eq!(metadata["driver"], serde_json::json!("openshell"));
assert_eq!(metadata["driver_version"], serde_json::json!(env!("CARGO_PKG_VERSION")));
assert_eq!(metadata["image_digest"], serde_json::json!(digest));
assert!(metadata["build_key"].as_str().unwrap().starts_with("sha256:"));
```

Keep the existing command-runner assertions strict: one `docker build`, one `docker image inspect`, and one `openshell sandbox create`.

- [ ] **Step 2: Run builder metadata test to verify it fails**

Run:

```bash
cargo test -p sandbox-openshell create_builds_byo_dockerfile_and_uses_staged_context
```

Expected: FAIL because a successful build does not write `build-cache/<key>/metadata.json`.

- [ ] **Step 3: Add build-slot guard and builder persistence**

Add these structs and methods to `crates/drivers/sandbox-openshell/src/build_cache.rs`:

```rust
pub(super) struct BuildSlotGuard;

impl BuildSlotGuard {
    fn acquire(config: &BuildQueueConfig) -> DriverResult<Self> {
        let previous = ACTIVE_BUILDERS.fetch_add(1, Ordering::SeqCst);
        if previous >= config.max_inflight {
            ACTIVE_BUILDERS.fetch_sub(1, Ordering::SeqCst);
            return Err(DriverError::PreflightFailed {
                message: format!(
                    "build queue saturated: {} builders active, max {}",
                    previous, config.max_inflight
                ),
            });
        }
        Ok(Self)
    }
}

impl Drop for BuildSlotGuard {
    fn drop(&mut self) {
        ACTIVE_BUILDERS.fetch_sub(1, Ordering::SeqCst);
    }
}

impl<'a> BuildCache<'a> {
    pub(super) fn materialize_built(
        &self,
        input: &BuildInput,
        image_ref: String,
        image_digest: String,
    ) -> DriverResult<BuildMaterialization> {
        parse_sha256_digest(&image_digest).map_err(|source| DriverError::InvalidInput {
            message: format!("Docker image returned invalid digest `{image_digest}`: {source}"),
        })?;
        let key = self.build_key(input)?;
        let cache_dir = self.cache_dir(&key);
        let context_dir = cache_dir.join("context");
        fs::create_dir_all(&cache_dir).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to create build cache `{}`: {source}", cache_dir.display()),
        })?;
        if PathBuf::from(&image_ref) != context_dir {
            if context_dir.exists() {
                fs::remove_dir_all(&context_dir).map_err(|source| DriverError::InvalidInput {
                    message: format!("failed to clear cached context `{}`: {source}", context_dir.display()),
                })?;
            }
            fs::rename(&image_ref, &context_dir).map_err(|source| DriverError::InvalidInput {
                message: format!("failed to move staged context into build cache `{}`: {source}", context_dir.display()),
            })?;
        }
        fs::write(cache_dir.join("image-digest"), format!("{image_digest}\n")).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to write cached image digest `{}`: {source}", cache_dir.display()),
        })?;
        let metadata = BuildMetadata {
            version: 1,
            build_key: key.clone(),
            driver: "openshell".to_owned(),
            driver_version: env!("CARGO_PKG_VERSION").to_owned(),
            image_ref: context_dir.display().to_string(),
            image_digest: image_digest.clone(),
            created_at: now_rfc3339(),
            source: BuildSourceMetadata {
                dockerfile: input.dockerfile.display().to_string(),
                context_digest: input.context_digest.clone(),
            },
        };
        let metadata_json = serde_json::to_vec_pretty(&metadata).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to serialize build cache metadata: {source}"),
        })?;
        fs::write(cache_dir.join("metadata.json"), metadata_json).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to write build cache metadata `{}`: {source}", cache_dir.display()),
        })?;
        self.write_env_digest(&input.env_name, &image_digest)?;
        self.emit(ActivityKind::BuildOneflightMiss, BUILD_QUEUE_DEPTH.load(Ordering::SeqCst));
        Ok(BuildMaterialization {
            image_ref: context_dir.display().to_string(),
            image_digest,
            tag: tag_for_key(&key),
        })
    }

    pub(super) fn acquire_build_slot(&self) -> DriverResult<BuildSlotGuard> {
        BuildSlotGuard::acquire(&self.config)
    }
}
```

- [ ] **Step 4: Route successful builds through persistence**

In `prepare_byo_dockerfile_context`, change the staging directory and tag:

```rust
let cache = build_cache::BuildCache::new(self.workdir(), self.events.as_ref());
let key_stage_dir = self
    .workdir()
    .join("build")
    .join(format!("{}-key", sanitize_build_name(name)));
stage_build_context(context_dir, &dockerfile, &key_stage_dir)?;
let context_digest = build_cache::BuildCache::digest_staged_context(&key_stage_dir)?;
let input = build_cache::BuildInput {
    env_name: name.to_owned(),
    dockerfile: config.dockerfile.clone(),
    staged_context: key_stage_dir.clone(),
    context_digest,
    expected_digest: config.expected_digest.clone(),
    agentenv_version: config.agentenv_version.clone(),
    agent: config.agent.clone(),
    mcp_port: config.mcp_port.clone(),
    workspace_mount: config.workspace_mount.clone(),
    seed: config.build_seed.clone(),
};
if let Some(materialized) = cache.materialize_cached(&input, self.runner.as_ref())? {
    return Ok(materialized.image_ref);
}
let _slot = cache.acquire_build_slot()?;
let key = cache.build_key(&input)?;
let stage_dir = cache.cache_dir(&key).join("context.tmp");
fs::rename(&key_stage_dir, &stage_dir).map_err(|source| DriverError::InvalidInput {
    message: format!("failed to move staged BYO context into build cache: {source}"),
})?;
let tag = build_cache::tag_for_key(&key);
```

After Docker inspect and expected-digest verification, replace the direct sidecar write and `Ok(stage_arg)` with:

```rust
let materialized = cache.materialize_built(&input, stage_arg, digest.to_owned())?;
Ok(materialized.image_ref)
```

- [ ] **Step 5: Run builder metadata test to verify it passes**

Run:

```bash
cargo test -p sandbox-openshell create_builds_byo_dockerfile_and_uses_staged_context
```

Expected: PASS after updating expected command paths to cache paths.

- [ ] **Step 6: Write failing invalidation test**

Add this test to `driver_tests`:

```rust
#[test]
fn create_rebuilds_when_cached_docker_image_digest_differs() {
    let tempdir = unique_tempdir("sandbox-openshell-byo-cache-invalid");
    let workdir = tempdir.join(".agentenv");
    let dockerfile_dir = tempdir.join("enterprise-sandbox");
    std::fs::create_dir_all(&dockerfile_dir).expect("create source context");
    let dockerfile = dockerfile_dir.join("Dockerfile");
    std::fs::write(&dockerfile, "FROM alpine:3.20\n").expect("write source Dockerfile");
    let cached_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let rebuilt_digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let key_stage_dir = workdir.join("build").join("devbox-key");
    super::stage_build_context(&dockerfile_dir, &dockerfile, &key_stage_dir)
        .expect("stage key context");
    let context_digest =
        super::build_cache::BuildCache::digest_staged_context(&key_stage_dir)
            .expect("context digest");
    let noop = agentenv_events::NoopEventEmitter;
    let cache = super::build_cache::BuildCache::new(workdir.clone(), &noop);
    let input = super::build_cache::BuildInput {
        env_name: "devbox".to_owned(),
        dockerfile: dockerfile.clone(),
        staged_context: key_stage_dir.clone(),
        context_digest: context_digest.clone(),
        expected_digest: None,
        agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
        agent: "codex".to_owned(),
        mcp_port: "3333".to_owned(),
        workspace_mount: "/sandbox".to_owned(),
        seed: Some("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned()),
    };
    let cache_key = cache.build_key(&input).expect("build key");
    let cache_dir = cache.cache_dir(&cache_key);
    let context_dir = cache_dir.join("context");
    std::fs::create_dir_all(&cache_dir).expect("create cache dir");
    std::fs::rename(&key_stage_dir, &context_dir).expect("move cached context");
    std::fs::write(cache_dir.join("image-digest"), format!("{cached_digest}\n")).expect("digest");
    std::fs::write(
        cache_dir.join("metadata.json"),
        serde_json::json!({
            "version": 1,
            "build_key": cache_key,
            "driver": "openshell",
            "driver_version": env!("CARGO_PKG_VERSION"),
            "image_ref": context_dir.display().to_string(),
            "image_digest": cached_digest,
            "created_at": "2026-05-06T12:00:00Z",
            "source": {
                "dockerfile": dockerfile.display().to_string(),
                "context_digest": context_digest
            }
        })
        .to_string(),
    )
    .expect("metadata");

    let runner = Arc::new(FlexibleCommandRunner::new(vec![
        FlexibleCommandExpectation::success("docker", |_| {}, "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n", ""),
        FlexibleCommandExpectation::success("docker", |_| {}, "", ""),
        FlexibleCommandExpectation::success("docker", |_| {}, &format!("{rebuilt_digest}\n"), ""),
        FlexibleCommandExpectation::success("openshell", |_| {}, "", ""),
    ]));
    let driver = OpenShellDriver::with_command_runner_and_workdir(runner.clone(), &workdir);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime
        .block_on(async {
            driver
                .create(SandboxSpec {
                    image: None,
                    env: BTreeMap::new(),
                    policy: None,
                    metadata: BTreeMap::from([
                        ("name".to_owned(), json!("devbox")),
                        ("byo_dockerfile".to_owned(), json!(dockerfile.display().to_string())),
                        ("agentenv_agent".to_owned(), json!("codex")),
                        ("agentenv_mcp_port".to_owned(), json!("3333")),
                        ("agentenv_workspace_mount".to_owned(), json!("/sandbox")),
                        ("agentenv_version".to_owned(), json!(env!("CARGO_PKG_VERSION"))),
                        ("agentenv_build_oneflight".to_owned(), json!("byo-openshell-v1")),
                        ("agentenv_build_seed_version".to_owned(), json!("1")),
                        ("agentenv_build_seed".to_owned(), json!("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")),
                    ]),
                })
                .await
        })
        .expect("create");

    assert_eq!(runner.calls().len(), 4);
    assert_eq!(
        std::fs::read_to_string(workdir.join("build").join("devbox").join("image-digest"))
            .expect("per env digest"),
        format!("{rebuilt_digest}\n")
    );
    std::fs::remove_dir_all(tempdir).expect("remove tempdir");
}
```

- [ ] **Step 7: Run invalidation test to verify it fails**

Run:

```bash
cargo test -p sandbox-openshell create_rebuilds_when_cached_docker_image_digest_differs
```

Expected: FAIL until cache validation evicts metadata and rebuilds.

- [ ] **Step 8: Make validation evict and rebuild**

In `read_valid_metadata`, when Docker inspect digest differs, remove `metadata.json` and `image-digest`, then return `Ok(None)`:

```rust
if inspect.status != Some(0) || inspect.stdout.trim() != metadata.image_digest {
    let _ = fs::remove_file(&metadata_path);
    let _ = fs::remove_file(cache_dir.join("image-digest"));
    return Ok(None);
}
```

Use the same removal block for version, key, driver, and image-ref validation failures.

- [ ] **Step 9: Run invalidation test to verify it passes**

Run:

```bash
cargo test -p sandbox-openshell create_rebuilds_when_cached_docker_image_digest_differs
```

Expected: PASS.

- [ ] **Step 10: Commit builder and invalidation work**

Run:

```bash
git add crates/drivers/sandbox-openshell/src/build_cache.rs crates/drivers/sandbox-openshell/src/lib.rs
git commit -m "feat(openshell): persist byo build metadata"
```

## Task 6: File-Backed Oneflight Waiters And Queue Limits

**Files:**
- Modify: `crates/drivers/sandbox-openshell/src/build_cache.rs`
- Modify: `crates/drivers/sandbox-openshell/src/lib.rs`

- [ ] **Step 1: Write failing concurrent oneflight test**

Add a thread-safe runner to `driver_tests`:

```rust
#[derive(Debug)]
struct OneflightRunner {
    calls: Mutex<Vec<CommandCall>>,
    build_count: AtomicUsize,
    inspect_count: AtomicUsize,
    build_started: std::sync::Barrier,
    release_build: std::sync::Barrier,
    digest: String,
}

impl CommandRunner for OneflightRunner {
    fn run(&self, program: &str, request: &super::CommandRequest) -> io::Result<super::CommandOutput> {
        self.calls.lock().expect("calls mutex").push(CommandCall {
            program: program.to_owned(),
            request: request.clone(),
        });
        if program == "docker" && request.args.first().map(String::as_str) == Some("build") {
            self.build_count.fetch_add(1, Ordering::SeqCst);
            self.build_started.wait();
            self.release_build.wait();
            return Ok(CommandOutput {
                status: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            });
        }
        if program == "docker" && request.args.first().map(String::as_str) == Some("image") {
            self.inspect_count.fetch_add(1, Ordering::SeqCst);
            return Ok(CommandOutput {
                status: Some(0),
                stdout: format!("{}\n", self.digest),
                stderr: String::new(),
            });
        }
        if program == "openshell" {
            return Ok(CommandOutput {
                status: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            });
        }
        Err(io::Error::other("unexpected command"))
    }

    fn spawn(&self, _program: &str, _request: &super::CommandRequest) -> io::Result<Box<dyn super::SpawnedCommand>> {
        Ok(Box::new(super::NoopSpawnedCommand))
    }
}
```

Add this test:

```rust
#[test]
fn concurrent_byo_creates_share_one_build() {
    let tempdir = unique_tempdir("sandbox-openshell-byo-oneflight");
    let workdir = tempdir.join(".agentenv");
    let dockerfile_dir = tempdir.join("enterprise-sandbox");
    std::fs::create_dir_all(&dockerfile_dir).expect("create source context");
    let dockerfile = dockerfile_dir.join("Dockerfile");
    std::fs::write(&dockerfile, "FROM alpine:3.20\n").expect("write source Dockerfile");
    let digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let runner = Arc::new(OneflightRunner {
        calls: Mutex::new(Vec::new()),
        build_count: AtomicUsize::new(0),
        inspect_count: AtomicUsize::new(0),
        build_started: std::sync::Barrier::new(2),
        release_build: std::sync::Barrier::new(2),
        digest: digest.to_owned(),
    });

    let first_driver = Arc::new(OpenShellDriver::with_command_runner_and_workdir(runner.clone(), &workdir));
    let second_driver = Arc::new(OpenShellDriver::with_command_runner_and_workdir(runner.clone(), &workdir));
    let first_spec = SandboxSpec {
        image: None,
        env: BTreeMap::new(),
        policy: None,
        metadata: BTreeMap::from([
            ("name".to_owned(), json!("devbox-a")),
            ("byo_dockerfile".to_owned(), json!(dockerfile.display().to_string())),
            ("agentenv_agent".to_owned(), json!("codex")),
            ("agentenv_mcp_port".to_owned(), json!("3333")),
            ("agentenv_workspace_mount".to_owned(), json!("/sandbox")),
            ("agentenv_version".to_owned(), json!(env!("CARGO_PKG_VERSION"))),
            ("agentenv_build_oneflight".to_owned(), json!("byo-openshell-v1")),
            ("agentenv_build_seed_version".to_owned(), json!("1")),
            ("agentenv_build_seed".to_owned(), json!("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")),
        ]),
    };
    let mut second_spec = first_spec.clone();
    second_spec.metadata.insert("name".to_owned(), json!("devbox-b"));

    let first = {
        let driver = Arc::clone(&first_driver);
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async { driver.create(first_spec).await })
        })
    };
    runner.build_started.wait();
    let second = {
        let driver = Arc::clone(&second_driver);
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async { driver.create(second_spec).await })
        })
    };
    runner.release_build.wait();

    first.join().expect("first thread").expect("first create");
    second.join().expect("second thread").expect("second create");

    assert_eq!(runner.build_count.load(Ordering::SeqCst), 1);
    assert!(workdir.join("build").join("devbox-a").join("image-digest").is_file());
    assert!(workdir.join("build").join("devbox-b").join("image-digest").is_file());
    std::fs::remove_dir_all(tempdir).expect("remove tempdir");
}
```

- [ ] **Step 2: Run concurrent test to verify it fails**

Run:

```bash
cargo test -p sandbox-openshell concurrent_byo_creates_share_one_build
```

Expected: FAIL because the second create starts its own Docker build.

- [ ] **Step 3: Add file lock and waiter path**

Add to `build_cache.rs`:

```rust
struct BuildLock {
    path: PathBuf,
}

impl Drop for BuildLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

impl<'a> BuildCache<'a> {
    pub(super) fn try_lock(&self, key: &str) -> DriverResult<Option<BuildLock>> {
        let lock_dir = self.cache_dir(key).join("lock");
        match fs::create_dir_all(lock_dir.parent().expect("lock parent")) {
            Ok(()) => {}
            Err(source) => {
                return Err(DriverError::InvalidInput {
                    message: format!("failed to create build cache lock parent: {source}"),
                });
            }
        }
        match fs::create_dir(&lock_dir) {
            Ok(()) => Ok(Some(BuildLock { path: lock_dir })),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(source) => Err(DriverError::InvalidInput {
                message: format!("failed to create build cache lock `{}`: {source}", lock_dir.display()),
            }),
        }
    }

    pub(super) fn wait_for_materialization(
        &self,
        key: &str,
        input: &BuildInput,
        runner: &dyn CommandRunner,
    ) -> DriverResult<BuildMaterialization> {
        let depth = BUILD_QUEUE_DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
        self.emit(ActivityKind::BuildQueueDepth, depth);
        self.emit(ActivityKind::BuildOneflightHit, depth);
        let guard = QueueDepthGuard { events: self.events };
        let started = SystemTime::now();
        loop {
            if let Some(metadata) = self.read_valid_metadata(key, &self.cache_dir(key), runner)? {
                self.write_env_digest(&input.env_name, &metadata.image_digest)?;
                return Ok(BuildMaterialization {
                    image_ref: metadata.image_ref,
                    image_digest: metadata.image_digest,
                    tag: tag_for_key(key),
                });
            }
            if started.elapsed().unwrap_or(Duration::ZERO) > self.config.lock_timeout {
                return Err(DriverError::PreflightFailed {
                    message: format!("timed out waiting for BYO build {key}"),
                });
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

struct QueueDepthGuard<'a> {
    events: &'a dyn EventEmitter,
}

impl Drop for QueueDepthGuard<'_> {
    fn drop(&mut self) {
        let depth = BUILD_QUEUE_DEPTH.fetch_sub(1, Ordering::SeqCst).saturating_sub(1);
        self.events.emit(
            ActivityEvent::new(now_rfc3339(), ActivityKind::BuildQueueDepth, ActivityResult::Ok, format!("build-{}", Uuid::new_v4()))
                .with_actor_value("driver", serde_json::json!("openshell"))
                .with_extra("depth", serde_json::json!(depth)),
        );
    }
}
```

- [ ] **Step 4: Use lock in BYO prepare**

In `prepare_byo_dockerfile_context`, after computing `key` and before acquiring the build slot:

```rust
let Some(_build_lock) = cache.try_lock(&key)? else {
    let materialized = cache.wait_for_materialization(&key, &input, self.runner.as_ref())?;
    return Ok(materialized.image_ref);
};
let _slot = cache.acquire_build_slot()?;
```

- [ ] **Step 5: Run concurrent test to verify it passes**

Run:

```bash
cargo test -p sandbox-openshell concurrent_byo_creates_share_one_build
```

Expected: PASS.

- [ ] **Step 6: Write failing queue-limit test**

Add this test:

```rust
#[test]
fn build_queue_limit_rejects_waiter_before_sandbox_create() {
    let _guard = EnvVarGuard::set("AGENTENV_BUILD_QUEUE_LIMIT", "0");
    let tempdir = unique_tempdir("sandbox-openshell-byo-queue-limit");
    let workdir = tempdir.join(".agentenv");
    let dockerfile_dir = tempdir.join("enterprise-sandbox");
    std::fs::create_dir_all(&dockerfile_dir).expect("create source context");
    let dockerfile = dockerfile_dir.join("Dockerfile");
    std::fs::write(&dockerfile, "FROM alpine:3.20\n").expect("write source Dockerfile");
    let key_stage_dir = workdir.join("build").join("devbox-key");
    super::stage_build_context(&dockerfile_dir, &dockerfile, &key_stage_dir)
        .expect("stage key context");
    let context_digest =
        super::build_cache::BuildCache::digest_staged_context(&key_stage_dir)
            .expect("context digest");
    let noop = agentenv_events::NoopEventEmitter;
    let cache = super::build_cache::BuildCache::new(workdir.clone(), &noop);
    let seed = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let input = super::build_cache::BuildInput {
        env_name: "devbox".to_owned(),
        dockerfile: dockerfile.clone(),
        staged_context: key_stage_dir,
        context_digest,
        expected_digest: None,
        agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
        agent: "codex".to_owned(),
        mcp_port: "3333".to_owned(),
        workspace_mount: "/sandbox".to_owned(),
        seed: Some(seed.to_owned()),
    };
    let key = cache.build_key(&input).expect("build key");
    std::fs::create_dir_all(cache.cache_dir(&key).join("lock")).expect("create active lock");
    let runner = Arc::new(FlexibleCommandRunner::new(Vec::new()));
    let driver = OpenShellDriver::with_command_runner_and_workdir(runner.clone(), &workdir);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let err = runtime
        .block_on(async {
            driver
                .create(SandboxSpec {
                    image: None,
                    env: BTreeMap::new(),
                    policy: None,
                    metadata: BTreeMap::from([
                        ("name".to_owned(), json!("devbox")),
                        ("byo_dockerfile".to_owned(), json!(dockerfile.display().to_string())),
                        ("agentenv_agent".to_owned(), json!("codex")),
                        ("agentenv_mcp_port".to_owned(), json!("3333")),
                        ("agentenv_workspace_mount".to_owned(), json!("/sandbox")),
                        ("agentenv_version".to_owned(), json!(env!("CARGO_PKG_VERSION"))),
                        ("agentenv_build_oneflight".to_owned(), json!("byo-openshell-v1")),
                        ("agentenv_build_seed_version".to_owned(), json!("1")),
                        ("agentenv_build_seed".to_owned(), json!(seed)),
                    ]),
                })
                .await
        })
        .expect_err("queue limit should reject");

    assert!(err.to_string().contains("build queue saturated"));
    assert!(runner.calls().is_empty());
    std::fs::remove_dir_all(tempdir).expect("remove tempdir");
}
```

Add `EnvVarGuard` to test helpers:

```rust
struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}
```

- [ ] **Step 7: Run queue-limit test to verify it fails**

Run:

```bash
cargo test -p sandbox-openshell build_queue_limit_rejects_waiter_before_sandbox_create
```

Expected: FAIL until `wait_for_materialization` checks `queue_limit`.

- [ ] **Step 8: Enforce waiter queue limit**

At the top of `wait_for_materialization`, before incrementing depth:

```rust
let current = BUILD_QUEUE_DEPTH.load(Ordering::SeqCst);
if current >= self.config.queue_limit {
    return Err(DriverError::PreflightFailed {
        message: format!(
            "build queue saturated: {} waiters active, limit {}",
            current, self.config.queue_limit
        ),
    });
}
```

- [ ] **Step 9: Run oneflight and queue tests**

Run:

```bash
cargo test -p sandbox-openshell concurrent_byo_creates_share_one_build build_queue_limit_rejects_waiter_before_sandbox_create
```

Expected: PASS.

- [ ] **Step 10: Commit oneflight queue work**

Run:

```bash
git add crates/drivers/sandbox-openshell/src/build_cache.rs crates/drivers/sandbox-openshell/src/lib.rs
git commit -m "feat(openshell): add byo build oneflight queue"
```

## Task 7: Builder Failure Propagation

**Files:**
- Modify: `crates/drivers/sandbox-openshell/src/build_cache.rs`
- Modify: `crates/drivers/sandbox-openshell/src/lib.rs`

- [ ] **Step 1: Write failing failure-propagation test**

Add this test to `driver_tests`:

```rust
#[test]
fn concurrent_byo_waiter_receives_builder_failure() {
    let tempdir = unique_tempdir("sandbox-openshell-byo-oneflight-failure");
    let workdir = tempdir.join(".agentenv");
    let dockerfile_dir = tempdir.join("enterprise-sandbox");
    std::fs::create_dir_all(&dockerfile_dir).expect("create source context");
    let dockerfile = dockerfile_dir.join("Dockerfile");
    std::fs::write(&dockerfile, "FROM alpine:3.20\n").expect("write source Dockerfile");
    let runner = Arc::new(FlexibleCommandRunner::new(vec![
        FlexibleCommandExpectation::output("docker", |_| {}, Some(1), "", "build failed"),
    ]));
    let driver = OpenShellDriver::with_command_runner_and_workdir(runner.clone(), &workdir);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let err = runtime
        .block_on(async {
            driver
                .create(SandboxSpec {
                    image: None,
                    env: BTreeMap::new(),
                    policy: None,
                    metadata: BTreeMap::from([
                        ("name".to_owned(), json!("devbox")),
                        ("byo_dockerfile".to_owned(), json!(dockerfile.display().to_string())),
                        ("agentenv_agent".to_owned(), json!("codex")),
                        ("agentenv_mcp_port".to_owned(), json!("3333")),
                        ("agentenv_workspace_mount".to_owned(), json!("/sandbox")),
                        ("agentenv_version".to_owned(), json!(env!("CARGO_PKG_VERSION"))),
                        ("agentenv_build_oneflight".to_owned(), json!("byo-openshell-v1")),
                        ("agentenv_build_seed_version".to_owned(), json!("1")),
                        ("agentenv_build_seed".to_owned(), json!("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")),
                    ]),
                })
                .await
        })
        .expect_err("build should fail");

    let failure_files = std::fs::read_dir(workdir.join("build-cache"))
        .expect("build cache dir")
        .flat_map(|entry| {
            let path = entry.expect("cache entry").path().join("failure.json");
            path.exists().then_some(path)
        })
        .collect::<Vec<_>>();
    assert_eq!(failure_files.len(), 1);
    let failure = std::fs::read_to_string(&failure_files[0]).expect("failure marker");
    assert!(failure.contains("docker_build_failed"));
    assert!(err.to_string().contains("build failed"));
    std::fs::remove_dir_all(tempdir).expect("remove tempdir");
}

#[test]
fn byo_waiter_receives_builder_failure_marker() {
    let tempdir = unique_tempdir("sandbox-openshell-byo-waiter-failure");
    let workdir = tempdir.join(".agentenv");
    let dockerfile_dir = tempdir.join("enterprise-sandbox");
    std::fs::create_dir_all(&dockerfile_dir).expect("create source context");
    let dockerfile = dockerfile_dir.join("Dockerfile");
    std::fs::write(&dockerfile, "FROM alpine:3.20\n").expect("write source Dockerfile");
    let key_stage_dir = workdir.join("build").join("devbox-key");
    super::stage_build_context(&dockerfile_dir, &dockerfile, &key_stage_dir)
        .expect("stage key context");
    let context_digest =
        super::build_cache::BuildCache::digest_staged_context(&key_stage_dir)
            .expect("context digest");
    let noop = agentenv_events::NoopEventEmitter;
    let cache = super::build_cache::BuildCache::new(workdir.clone(), &noop);
    let seed = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let input = super::build_cache::BuildInput {
        env_name: "devbox".to_owned(),
        dockerfile: dockerfile.clone(),
        staged_context: key_stage_dir,
        context_digest,
        expected_digest: None,
        agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
        agent: "codex".to_owned(),
        mcp_port: "3333".to_owned(),
        workspace_mount: "/sandbox".to_owned(),
        seed: Some(seed.to_owned()),
    };
    let key = cache.build_key(&input).expect("build key");
    let cache_dir = cache.cache_dir(&key);
    std::fs::create_dir_all(cache_dir.join("lock")).expect("active build lock");
    std::fs::write(
        cache_dir.join("failure.json"),
        serde_json::json!({
            "build_key": key,
            "ts": "2026-05-06T12:00:00Z",
            "reason_code": "docker_build_failed",
            "message": "docker failed for peer"
        })
        .to_string(),
    )
    .expect("failure marker");
    let runner = Arc::new(FlexibleCommandRunner::new(Vec::new()));
    let driver = OpenShellDriver::with_command_runner_and_workdir(runner.clone(), &workdir);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let err = runtime
        .block_on(async {
            driver
                .create(SandboxSpec {
                    image: None,
                    env: BTreeMap::new(),
                    policy: None,
                    metadata: BTreeMap::from([
                        ("name".to_owned(), json!("devbox")),
                        ("byo_dockerfile".to_owned(), json!(dockerfile.display().to_string())),
                        ("agentenv_agent".to_owned(), json!("codex")),
                        ("agentenv_mcp_port".to_owned(), json!("3333")),
                        ("agentenv_workspace_mount".to_owned(), json!("/sandbox")),
                        ("agentenv_version".to_owned(), json!(env!("CARGO_PKG_VERSION"))),
                        ("agentenv_build_oneflight".to_owned(), json!("byo-openshell-v1")),
                        ("agentenv_build_seed_version".to_owned(), json!("1")),
                        ("agentenv_build_seed".to_owned(), json!(seed)),
                    ]),
                })
                .await
        })
        .expect_err("waiter should receive failure marker");

    assert!(err.to_string().contains("docker failed for peer"));
    assert!(runner.calls().is_empty());
    std::fs::remove_dir_all(tempdir).expect("remove tempdir");
}
```

- [ ] **Step 2: Run failure test to verify it fails**

Run:

```bash
cargo test -p sandbox-openshell concurrent_byo_waiter_receives_builder_failure byo_waiter_receives_builder_failure_marker
```

Expected: FAIL because no `failure.json` marker is written.

- [ ] **Step 3: Add failure marker support**

Add to `build_cache.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BuildFailureMarker {
    build_key: String,
    ts: String,
    reason_code: String,
    message: String,
}

impl<'a> BuildCache<'a> {
    pub(super) fn write_failure(&self, key: &str, error: &DriverError) -> DriverResult<()> {
        let cache_dir = self.cache_dir(key);
        fs::create_dir_all(&cache_dir).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to create build cache `{}`: {source}", cache_dir.display()),
        })?;
        let marker = BuildFailureMarker {
            build_key: key.to_owned(),
            ts: now_rfc3339(),
            reason_code: "docker_build_failed".to_owned(),
            message: error.to_string(),
        };
        let bytes = serde_json::to_vec_pretty(&marker).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to serialize build failure marker: {source}"),
        })?;
        fs::write(cache_dir.join("failure.json"), bytes).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to write build failure marker `{}`: {source}", cache_dir.display()),
        })?;
        Ok(())
    }

    fn read_failure(&self, key: &str) -> DriverResult<Option<BuildFailureMarker>> {
        let path = self.cache_dir(key).join("failure.json");
        if !path.is_file() {
            return Ok(None);
        }
        let bytes = fs::read(&path).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to read build failure marker `{}`: {source}", path.display()),
        })?;
        let marker = serde_json::from_slice(&bytes).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to parse build failure marker `{}`: {source}", path.display()),
        })?;
        Ok(Some(marker))
    }
}
```

In `wait_for_materialization`, check the marker in the loop:

```rust
if let Some(failure) = self.read_failure(key)? {
    return Err(DriverError::PreflightFailed {
        message: failure.message,
    });
}
```

- [ ] **Step 4: Write failure marker from builder path**

In `prepare_byo_dockerfile_context`, wrap the Docker build call:

```rust
if let Err(err) = self.run_checked_host_command(
    "docker",
    CommandRequest {
        args: build_args,
        env: BTreeMap::new(),
    },
) {
    let _ = cache.write_failure(&key, &err);
    return Err(err);
}
```

- [ ] **Step 5: Run failure test to verify it passes**

Run:

```bash
cargo test -p sandbox-openshell concurrent_byo_waiter_receives_builder_failure byo_waiter_receives_builder_failure_marker
```

Expected: PASS.

- [ ] **Step 6: Commit failure propagation**

Run:

```bash
git add crates/drivers/sandbox-openshell/src/build_cache.rs crates/drivers/sandbox-openshell/src/lib.rs
git commit -m "feat(openshell): propagate byo build failures"
```

## Task 8: Integration Verification And Cleanup

**Files:**
- Modify only files changed by previous tasks if verification exposes issues.

- [ ] **Step 1: Run focused test suites**

Run:

```bash
cargo test -p agentenv-events
cargo test -p agentenv-core create_env_passes_byo_dockerfile_metadata_to_sandbox create_env_omits_build_oneflight_metadata_for_non_byo_image create_env_records_computed_byo_digest_in_lockfile
cargo test -p sandbox-openshell create_builds_byo_dockerfile_and_uses_staged_context create_reuses_valid_byo_build_cache create_rebuilds_when_cached_docker_image_digest_differs concurrent_byo_creates_share_one_build build_queue_limit_rejects_waiter_before_sandbox_create concurrent_byo_waiter_receives_builder_failure byo_waiter_receives_builder_failure_marker
cargo test -p agentenv openshell_driver_receives_observed_event_emitter
```

Expected: all commands PASS.

- [ ] **Step 2: Run formatting**

Run:

```bash
cargo fmt --check
```

Expected: PASS. If it fails, run:

```bash
cargo fmt
```

Then rerun:

```bash
cargo fmt --check
```

- [ ] **Step 3: Run clippy**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: PASS.

- [ ] **Step 4: Run full workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: PASS.

- [ ] **Step 5: Inspect final diff**

Run:

```bash
git status --short
git diff --stat HEAD
git diff --check
```

Expected: working tree contains only intended oneflight implementation changes and `git diff --check` reports no whitespace errors.

- [ ] **Step 6: Commit final fixes if verification changed files**

If Step 1 through Step 4 required fixes after the previous commits, run:

```bash
git add crates/agentenv-events/src/activity.rs crates/agentenv-events/src/store.rs crates/agentenv-events/src/metrics.rs crates/agentenv-core/src/runtime.rs crates/drivers/sandbox-openshell/Cargo.toml crates/drivers/sandbox-openshell/src/lib.rs crates/drivers/sandbox-openshell/src/build_cache.rs crates/agentenv/src/builtin_factory.rs
git commit -m "test: verify build oneflight integration"
```

Expected: commit created only when verification fixes were needed.
