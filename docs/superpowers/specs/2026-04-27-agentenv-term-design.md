# agentenv term Design

## Context

Issue [#24](https://github.com/windoliver/agentenv/issues/24) is the M6-2 day-2 operations TUI. It depends on M6-1 activity events and asks for `agentenv term`, a real-time ratatui operator interface for env status, recent activity, pending approvals, and env detail.

The current checkout has the foundations needed for a local implementation:

- `crates/agentenv` already exposes CLI commands for `list`, `describe`, `logs`, `destroy`, `status`, and session operations.
- `crates/agentenv-core` persists env state under `~/.agentenv/envs/<name>/state.json` and appends compatibility activity lines to `events.jsonl`.
- `crates/agentenv-events`, `crates/agentenv-approvals`, and `crates/tui` are still scaffolding crates.

This spec covers the full issue scope locally. Remote daemon support remains future work: `agentenv term --remote <endpoint>` should parse and fail with a clear unsupported error until an agentenv daemon exists.

## Goals

- Add `agentenv term`.
- Render all four panes from the issue: Envs, Events, Approvals, and Detail.
- Provide smooth keyboard navigation without visible redraw artifacts.
- Implement `:destroy <env>` command mode end-to-end through the existing runtime destroy path.
- Implement one-keystroke approval and denial in the TUI.
- Honor `--no-color` and `NO_COLOR` with a legible monochrome theme.
- Keep idle CPU low by redrawing only when input or observed state changes.

## Non-Goals

- Do not add a remote daemon or remote TUI transport.
- Do not change the driver protocol schema for this issue.
- Do not bypass MCP or the existing core-to-driver JSON-RPC path.
- Do not add non-Rust build-time runtime dependencies.

## Affected Crates

- `crates/agentenv`: CLI command wiring, local runtime adapter, integration tests.
- `crates/tui`: ratatui application, rendering, input handling, command parsing, async event loop.
- `crates/agentenv-events`: typed activity records, local durable event store, JSONL compatibility.
- `crates/agentenv-approvals`: pending approval queue, approval decisions, event emission.
- `crates/agentenv-core`: only narrow helper additions if needed for shared state paths or event append integration.

## Chosen Approach

Use a strict local full implementation.

The TUI should be a real operator surface over local agentenv state, not a display-only view over loose logs. `agentenv-events` owns durable typed activity storage. `agentenv-approvals` owns pending approval state and decisions. `crates/tui` consumes typed snapshots and calls an adapter for env lifecycle actions.

This gives the issue a complete local implementation while preserving the roadmap split where `--remote` talks to a future daemon.

## Architecture

`crates/tui` is the feature crate. It owns:

- app state and pane selection
- render functions for Envs, Events, Approvals, Detail, help, logs, policy, and command mode
- command parser for `:destroy <env>`
- keyboard input handling
- dirty-state redraw coordination
- a small `OpsBackend` interface used by tests and by the CLI adapter

`crates/agentenv` adds:

- `term` subcommand
- `--no-color`
- `--remote <endpoint>`
- local adapter implementation that calls existing runtime functions

`crates/agentenv-events` adds:

- typed event model with env name, timestamp, kind, subject, reason, driver, and metadata
- local SQLite-backed store at `~/.agentenv/ops.sqlite3`
- recent-event query with optional selected-env filter
- events-per-minute aggregation
- JSONL compatibility reader/importer for existing per-env `events.jsonl` files

`crates/agentenv-approvals` adds:

- pending approval request model
- decision model for allow and deny
- local persistence in approval tables in `~/.agentenv/ops.sqlite3`
- event emission for requests and decisions

The core runtime remains the source of truth for env lifecycle. The TUI destroys envs by calling the same runtime destroy path as `agentenv destroy --yes`.

## Data Model

Activity events are typed and durable. The store captures:

- stable event id
- env name
- timestamp
- kind
- subject
- optional reason
- optional driver
- optional handle
- structured metadata

Approval requests capture:

- request id
- env name
- agent name if known
- approval kind
- subject
- reason
- status: pending, allowed, denied, stale
- requested timestamp
- decided timestamp and actor when decided
- decision scope
- structured context

Approval decisions should also append activity events so the Events pane reflects operator actions.

Existing `events.jsonl` remains supported as an input compatibility layer. On startup and refresh, the local backend imports new JSONL lines into `~/.agentenv/ops.sqlite3` using a stable per-env offset so envs that predate the store still appear in the Events pane.

## Data Flow

On startup, `agentenv term` creates a local backend from `~/.agentenv` and loads:

- env list from `agentenv_core::runtime::list_envs`
- selected env detail from `agentenv_core::runtime::describe_env`
- recent activity from `agentenv-events`
- pending approvals from `agentenv-approvals`

The terminal loop has two input sources:

- terminal events from `crossterm`
- a bounded refresh tick used to notice file or database changes

The app marks itself dirty when input changes state or when a refreshed snapshot differs from the previous snapshot. It renders only while dirty. This provides responsive redraws without a busy loop.

Operational flow:

```text
driver/runtime activity -> event store -> TUI snapshot -> Events pane
approval request        -> approval queue -> TUI snapshot -> Approvals pane
allow/deny key          -> decision store -> decision event -> refreshed panes
:destroy <env>          -> runtime destroy -> event append -> env/detail refresh
```

## Interaction Model

Required keys:

- `Tab` cycles panes forward.
- `Shift+Tab` cycles panes backward.
- `j` and `k` move within the active pane.
- `Enter` drills into the selected env or selected approval.
- `a-z` jumps to a visible env by letter index.
- `A` switches to the approvals pane.
- `L` opens a full-screen logs view.
- `P` opens a policy-focused detail view.
- `:` opens command mode.
- `?` opens help.
- `q` exits when command mode is inactive.

Approval pane keys:

- `y` or `a` allows the selected pending approval.
- `n` or `d` denies the selected pending approval.

Command mode:

- `:destroy <env>` destroys the named env through the existing runtime path.
- Unknown commands show a status error.
- Runtime failures show a status error and keep the TUI running.
- `Esc` cancels command mode.

The TUI should not add a second interactive confirmation prompt for `:destroy <env>`. The command is explicit, and the runtime call should use the same non-interactive path as `agentenv destroy --yes`.

## Rendering

The default layout renders:

- header with product name, env count, and events/min
- Envs pane with letter labels, driver names, context, and health/status
- Events pane with recent activity filtered by selected env
- Approvals pane with pending requests
- Detail pane with selected env policy, drivers, capabilities, sessions, and health where available
- footer with key hints

The logs and policy views are full-screen modes entered with `L` and `P`; they preserve enough app state to return to the normal four-pane layout.

Monochrome mode must not rely on color. It should use labels, borders, prefix markers, and selection indicators to distinguish:

- active pane
- selected row
- healthy, degraded, error, and destroyed states
- pending approvals
- errors and command feedback

## Error Handling

Startup errors should fail the command with a normal CLI error. In-TUI action errors should be captured in app status state and rendered without panicking.

Expected recoverable errors:

- env disappears during refresh
- selected approval is already decided
- event or approval database is temporarily locked
- corrupt legacy JSONL event line
- runtime destroy returns an error
- unknown command mode input

Corrupt JSONL lines should be skipped with a diagnostic event or status message, not treated as fatal for the TUI.

`--remote <endpoint>` should return a stable unsupported error that explains remote term requires a future agentenv daemon.

## Accessibility

`--no-color` and `NO_COLOR` both select the monochrome theme. Help is available in the TUI through `?`, and `agentenv term --help` must list the key bindings and flags.

Keyboard-only operation is required. Every action in the acceptance criteria must be possible without a mouse.

## Performance

The TUI should target responsive redraws without constant rendering:

- terminal input triggers immediate state handling
- refresh ticks are bounded and low-frequency while idle
- rendering occurs only when the app is dirty
- database queries are scoped to small recent windows for the main screen

The implementation should make the dirty/redraw logic testable so idle behavior is not left to manual observation alone.

## Testing Strategy

Use TDD for each behavior.

`agentenv-events` tests:

- initializes the local store schema
- appends and lists events
- filters recent events by env
- computes events per minute
- imports or reads legacy JSONL events
- skips corrupt JSONL lines without failing the whole read

`agentenv-approvals` tests:

- creates pending requests
- lists pending requests by env and globally
- records allow decisions
- records deny decisions
- treats stale or already-decided requests idempotently
- emits decision activity events

`crates/tui` tests:

- pane cycling with `Tab` and `Shift+Tab`
- `j/k` selection movement
- `a-z` env jump behavior
- command parser accepts `:destroy <env>`
- command parser rejects unknown commands
- help overlay toggles
- no-color theme uses non-color markers
- approval allow/deny keys call the backend
- dirty flag is set only by input or changed snapshots
- render tests with `ratatui::backend::TestBackend` cover the four-pane layout and narrow terminal sizes

CLI integration tests:

- `agentenv term --help` includes key bindings and flags
- `agentenv term --remote <endpoint>` fails with unsupported remote mode
- seeded env/event/approval state can launch the TUI and exit with `q`
- `:destroy <env>` removes the env directory and records an event

Final verification:

- `cargo fmt`
- `cargo clippy -D warnings`
- `cargo test --workspace`

## Open Decisions Resolved

- The implementation is full local scope, not a display-only MVP.
- SQLite-backed local ops state is part of the implementation.
- Remote daemon mode is parsed but unsupported.
- `:destroy <env>` does not prompt for a second confirmation inside the TUI.
- Approval decisions are durable and emit events.
