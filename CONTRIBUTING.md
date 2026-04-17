# Contributing to agentenv

> Alpha, scaffolding. If you've arrived early, welcome. The fastest path into the codebase is to read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/DRIVER_PROTOCOL.md`](docs/DRIVER_PROTOCOL.md), then pick an issue from the [roadmap](docs/ROADMAP.md).

## Development setup

Requires:
- Rust (MSRV `1.80`, enforced in `Cargo.toml`)
- `just` (optional, recommended)
- Docker (for running integration tests against sandbox drivers)
- A recent `openshell` CLI on `PATH` (for `sandbox-openshell` tests)

```bash
git clone https://github.com/windoliver/agentenv
cd agentenv
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

## Repository layout

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#crate-layout).

## Coding standards

- **Errors**: library crates use `thiserror`; the bin crate uses `anyhow`. Never `.unwrap()` outside tests.
- **Async**: `tokio` multi-thread throughout. Every blocking operation goes through `spawn_blocking`.
- **Tracing**: use `tracing` macros with structured fields. No `println!` in library code.
- **Naming**: snake_case modules, UpperCamelCase types, SCREAMING_SNAKE_CASE consts.
- **No un-`cfg`-gated OS-specific code** outside `crates/drivers/*` and `crates/agentenv-credstore`.

## Adding a new driver

Drivers come in two flavors (see architecture doc):

1. **Built-in Rust driver.** Add a new crate under `crates/drivers/`, implement the relevant trait from `agentenv-core::driver::*`, register it in `agentenv-core::registry`. Keep the crate dependency surface narrow.
2. **External subprocess driver.** Any language. Implement the RPC methods from `docs/DRIVER_PROTOCOL.md`. Ship a `manifest.json` and an executable; the core discovers it via `~/.agentenv/drivers/`. Third-party drivers should live in [`agentenv-community`](https://github.com/windoliver/agentenv-community) once that exists.

## Tests

- Per-crate unit tests.
- Integration tests in `crates/<crate>/tests/` — use feature flags to gate tests that require Docker / OpenShell / network.
- **Protocol conformance tests** in `tests/driver-conformance/` run the same JSON-RPC suite against every driver implementation, built-in or external. If you add a driver, it must pass conformance.

## Commits and PRs

- Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- One logical change per PR.
- Reference an issue (`Fixes #N`) when applicable.
- `cargo fmt` + `cargo clippy -D warnings` + `cargo test` before opening a PR.

## License

MIT. See [`LICENSE`](LICENSE).
