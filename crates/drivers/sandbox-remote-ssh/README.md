# sandbox-remote-ssh

Built-in `SandboxDriver` for pre-provisioned remote VMs reachable through SSH.

The driver does not provision, stop, or power off VMs. It expects the remote
user to have a writable `/sandbox` directory and basic POSIX shell tools.

Run live integration tests with:

```bash
AGENTENV_RUN_REMOTE_SSH_INTEGRATION=1 \
AGENTENV_REMOTE_SSH_HOST=dev-vm.example.com \
AGENTENV_REMOTE_SSH_USER=alice \
AGENTENV_REMOTE_SSH_IDENTITY_FILE=/Users/alice/.ssh/id_ed25519 \
cargo test -p sandbox-remote-ssh --features integration -- --ignored
```
