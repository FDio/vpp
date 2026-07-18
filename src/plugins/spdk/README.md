# SPDK NVMe/TCP target plugin

This Linux plugin embeds SPDK in the VPP process and provides an SPDK socket
backend named `vpp`, implemented with built-in HostStack sessions. SPDK parses
NVMe/TCP and handles bdev requests; VPP owns TCP, its timers and session FIFOs.
Listeners using this backend do not use Linux TCP sockets or VCL.

## Build

The default VPP build does not download or compile SPDK and does not build this
plugin. Opt in explicitly, including when installing build dependencies:

```sh
make install-dep VPP_WITH_SPDK=y
make build VPP_WITH_SPDK=y
```

`build/external/packages/spdk.mk` pins an upstream SPDK v27.01-pre snapshot by
full commit and archive SHA256. No downstream SPDK patches are applied. ISA-L,
DPDK, RDMA and VFIO-user dependencies are disabled; VPP supplies the SPDK
environment implementation in `spdk_vpp_env.c`. This is independent of the NIC
driver selected by VPP, including whether VPP itself uses DPDK.

For a direct CMake build, first build/install the external SPDK package, then
pass `-DVPP_BUILD_SPDK_PLUGIN=ON` and include its installation prefix in
`CMAKE_PREFIX_PATH`. An explicitly enabled plugin fails configuration when its
dependencies cannot be found instead of silently disabling itself.

## Scheduling and ownership

The integration uses public `spdk_thread_lib_init_ext()` and `spdk_thread_poll()`
APIs. SPDK lightweight threads are polled from VPP input nodes; no dedicated
SPDK reactor pthread is added. Data sockets and their SPDK poll groups must run
on the VPP worker that owns the underlying session. Per-worker queues handle
normal I/O; listener and cross-worker notifications retain synchronization.

The default reactor mask uses all VPP workers, or the main thread when no
workers exist. An explicit mask must contain exactly those dataplane CPUs.
`show spdk` displays their mapping and basic socket/polling counters.

## Start and configure

Enable sessions and the plugin in the VPP startup configuration, for example:

```text
session { enable }
plugins { plugin spdk_plugin.so { enable } }
```

Start SPDK and configure a software-backed namespace through its standard RPC
interface. The example requires a VPP interface reachable at `192.0.2.2`:

```text
spdk app start name vpp_spdk rpc /run/vpp/spdk.sock no-pci
show spdk
```

```sh
rpc.py -s /run/vpp/spdk.sock bdev_malloc_create 128 4096 -b Malloc0
rpc.py -s /run/vpp/spdk.sock nvmf_create_transport -t TCP
rpc.py -s /run/vpp/spdk.sock nvmf_create_subsystem nqn.2026-10.io.vpp:example -a
rpc.py -s /run/vpp/spdk.sock nvmf_subsystem_add_ns nqn.2026-10.io.vpp:example Malloc0
rpc.py -s /run/vpp/spdk.sock nvmf_subsystem_add_listener nqn.2026-10.io.vpp:example \
  -t tcp -a 192.0.2.2 -s 4420 -S vpp
```

The plugin selects `vpp` as the default socket implementation. Set `-S vpp`
explicitly on listeners so a configuration mistake cannot select POSIX TCP.
The allow-any-host example is for an isolated test network, not a production
authorization policy. Stop initiator I/O and disconnect controllers before:

```text
spdk app stop
```

## Initial scope

- Standard copied RX and TX using upstream SPDK and existing VPP session APIs.
- Software bdevs such as Malloc and Null; `no-pci` is required. Native PCI NVMe
  requires a separate environment/DMA integration and is not supported here.
- Busy polling, not interrupt/eventfd-driven operation.
- Plain TCP only. TLS/kTLS/PSK socket options are rejected, not silently
  interpreted as an unencrypted connection.
- No FIFO reservations, `c2h_direct_sock`, deferred RX buffers, `recv_next`
  zero-copy backend, or TX-vlib-buffer prototype. These remain separate work.
- No changes to TCP, FIFO layout, NIC drivers or VPP's DPDK dependency.

SPDK and its modules share the VPP process and failure domain. A fault in an
embedded module can terminate VPP. The environment implementation, scheduling
and shutdown behavior need review before production use. Throughput tests on
a Null bdev are not a substitute for payload-integrity tests on a Malloc bdev.

## Opt-in integration test

`test_integration.py` starts its own VPP process, creates a temporary TAP on
`198.18.16.0/30` and exposes a private 64 MiB Malloc bdev to the Linux NVMe/TCP
initiator. It refuses to run if that subnet already has a route. Three cycles
exercise SPDK startup, 4 KiB and 128 KiB fio CRC verification, controller
disconnect and SPDK shutdown. Only the test NQN is disconnected; the private
TAP is removed when the test VPP exits. Physical interfaces and disks are not
used.

Run it as root in an isolated Linux test environment. It requires fio,
nvme-cli, iproute2, the nvme_tcp kernel module, and a VPP build containing the
SPDK, TAP, ping and unittest plugins. Pass the executable paths with `--vpp`,
`--vppctl`, the plugin directory with `--plugins`, upstream SPDK's `rpc.py`
with `--rpc`, and a new results directory with `--results`. Main/worker CPU
IDs and the cycle count are configurable; use `--help` for all arguments.
