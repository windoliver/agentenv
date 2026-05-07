# sandbox-microvm

Built-in `SandboxDriver` for microVM-backed agent environments.

The driver currently implements the Firecracker runtime on Linux/KVM hosts and
reserves the same driver surface for future Apple Container and Kata support.
Those runtime names are parsed but return explicit capability errors until their
host integrations are implemented.

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

Run live integration tests with:

```bash
AGENTENV_RUN_MICROVM_INTEGRATION=1 \
cargo test -p sandbox-microvm --features integration -- --ignored
```

Live tests require Linux, `/dev/kvm`, a `firecracker` binary on `PATH`, and a
bootable kernel/rootfs pair prepared by the operator.
