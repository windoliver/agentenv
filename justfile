set shell := ["zsh", "-cu"]

build:
    cargo build --workspace --all-targets

test:
    cargo test --workspace

lint:
    cargo clippy --workspace --all-targets -- -D warnings

fmt:
    cargo fmt --all

watch:
    cargo watch -x "test --workspace"

install:
    cargo install --path crates/agentenv --locked

doc:
    cargo doc --workspace --no-deps
