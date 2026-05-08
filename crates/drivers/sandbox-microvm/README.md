# sandbox-microvm

Built-in `SandboxDriver` for microVM-backed agent environments.

The driver supports two host-specific runtime paths:

- `runtime: firecracker` on Linux hosts with KVM access through `/dev/kvm`.
- `runtime: apple-container` on Apple silicon Macs with Apple's `container`
  CLI installed and `container system start` completed.

`runtime: kata` is reserved and returns an explicit capability error until that
host integration is implemented.

Example sandbox section:

```yaml
sandbox:
  driver: microvm
  runtime: firecracker
  kernel: /var/lib/agentenv/kernel/vmlinux-6.8
  rootfs: /var/lib/agentenv/rootfs.ext4
  memory_mb: 2048
  cpus: 2
  tap: tap-agentenv0
```

macOS example:

```yaml
sandbox:
  driver: microvm
  runtime: apple-container
  image: ubuntu:24.04
  memory_mb: 2048
  cpus: 2
```

Optional SSH metadata enables `connect`, `exec`, `copy_in`, and `copy_out` when
the guest image already exposes SSH:

```yaml
sandbox:
  driver: microvm
  runtime: firecracker
  kernel: /var/lib/agentenv/kernel/vmlinux-6.8
  rootfs: /var/lib/agentenv/rootfs.ext4
  ssh_host: 127.0.0.1
  ssh_port: 10022
  ssh_user: root
```

## Snapshot and fork

The Firecracker runtime implements the schema 1.2 sandbox snapshot/fork
primitive used by:

```bash
agentenv fork <sandbox-handle> --name experiment
```

The driver pauses the source VM, calls Firecracker's snapshot API, resumes the
source VM, clones the rootfs with a reflink/sparse copy when the host supports
it, starts a child Firecracker process, and loads the snapshot into the child VM.
The fork inherits the source SSH metadata and tap name unless the caller uses
`ForkSpec.metadata` to override them.

Apple Container and Kata runtimes return explicit capability errors for
snapshot/fork until their host-specific implementations are designed.

Run live integration tests with:

```bash
AGENTENV_RUN_MICROVM_INTEGRATION=1 \
AGENTENV_MICROVM_KERNEL=/var/lib/agentenv/kernel/vmlinux-6.8 \
AGENTENV_MICROVM_ROOTFS=/var/lib/agentenv/rootfs.ext4 \
cargo test -p sandbox-microvm --features integration firecracker_process_lifecycle_on_linux_kvm -- --ignored
```

For macOS:

```bash
AGENTENV_RUN_APPLE_CONTAINER_INTEGRATION=1 \
cargo test -p sandbox-microvm --features integration apple_container_lifecycle_on_macos -- --ignored
```

The Firecracker test requires Linux, readable/writable `/dev/kvm`, a
`firecracker` binary on `PATH`, and a bootable kernel/rootfs pair prepared by the
operator. Docker on macOS does not satisfy this requirement unless its Linux VM
itself exposes `/dev/kvm`.
