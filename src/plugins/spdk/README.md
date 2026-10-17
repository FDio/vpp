# SPDK NVMe/TCP target plugin

This Linux plugin embeds SPDK in the VPP process and provides an SPDK socket
backend named `vpp`, implemented with built-in HostStack sessions. SPDK parses
NVMe/TCP and handles bdev requests; VPP owns TCP, its timers and session FIFOs.
Listeners using this backend do not use Linux TCP sockets or VCL.

## Build

The default VPP build does not download or compile SPDK and does not build this
plugin. Install VPP's normal build dependencies with `make install-dep`.
SPDK-specific prerequisites are installed separately and are not added to
VPP's default dependency lists. On Debian/Ubuntu:

```sh
sudo apt-get install libaio-dev uuid-dev python3-tabulate python3-jinja2
```

On Fedora/RHEL, install `libaio-devel`, `libuuid-devel`, `python3-tabulate`,
`python3-jinja2` and `gcc-c++`. When building with Clang, also install the C++
development headers matching its selected GCC toolchain (for example,
`libstdc++-14-dev` for GCC 14 on Debian/Ubuntu). SPDK uses these headers even
though its standalone applications are disabled.

Build the optional dependency and enable the plugin explicitly:

```sh
make install-opt-deps VPP_WITH_SPDK=y
make build VPP_EXTRA_CMAKE_ARGS=-DVPP_BUILD_SPDK_PLUGIN=ON
```

`VPP_WITH_SPDK=y` selects the SPDK package in `build/optional` only. It does
not enable the plugin; the existing `VPP_EXTRA_CMAKE_ARGS` mechanism passes
the explicit CMake option without adding SPDK-specific build glue.

`build/optional/packages/spdk.mk` pins an upstream SPDK v27.01-pre snapshot by
full commit and archive SHA256. This RX review stack applies ten patches from
`build/optional/patches/spdk_zcrx-public-20261025`; its README records their
public provenance through 29602 PS1, including the separately reviewed stream
tracker exhaustion fix. Change 29257 is upstream and is not reapplied. ISA-L,
DPDK, RDMA and VFIO-user dependencies are disabled; VPP supplies the SPDK
environment implementation in `spdk_vpp_env.c`. This is independent of the NIC
driver selected by VPP, including whether VPP itself uses DPDK.

For a direct CMake build, first build/install the optional SPDK package, then
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

## Scope of the RX review stack

- FIFO-backed RX zero-copy with a copied fallback and standard copied TX.
- Software bdevs such as Malloc and Null; `no-pci` is required. Native PCI NVMe
  requires a separate environment/DMA integration and is not supported here.
- Busy polling, not interrupt/eventfd-driven operation.
- Plain TCP only. TLS/kTLS/PSK socket options are rejected, not silently
  interpreted as an unencrypted connection.
- No FIFO TX reservations, `c2h_direct_sock` or TX-vlib-buffer prototype.
- The dependency is the public 46940 PS14, on top of the merged plugin
  baseline. This binding adds no further TCP/FIFO changes, NIC driver
  changes or changes to VPP's DPDK dependency.

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
The test reserves a 1 GiB VPP main heap; `--main-heap-size` overrides it.
SPDK's large software-bdev allocations can fall back to this heap when
hugepages are unavailable. Leave headroom for aligned allocations and repeated
startup/shutdown; system-wide free RAM alone does not measure that capacity.
The test records main-heap usage around each cycle.
The default MTU is 1500; use `--mtu 9000` to exercise jumbo packets with the
same 2 KiB VPP buffers. The test sets both TAP endpoints and the TCP MTU.
It leaves the framework's per-worker retained-segment limit at its default.

For this RX stack, repeat with `--rx-mode direct`, `--rx-mode copied` and
`--rx-mode pressure`. The latter sets the group loan budget to one byte to
force the copied fallback. Tests require direct/copied counters consistent
with the selected mode and no outstanding loans after disconnect.

## FIFO-backed RX ownership

For host-to-controller writes, the socket backend implements SPDK's
`spdk_sock_recv_next()` API using the FIFO-backed deferred RX interface from
VPP change 46940, patch set 14. This experimental integration depends on that API
and the SPDK socket receive-buffer review series; it does not change TCP or
FIFO implementation code.

The minimal ownership sequence is:

1. Enable deferred RX with `session_set_deferred_rx(s, 1)` after assigning
   the socket to its owner worker.
2. Inspect the borrowed linked-list prefix with
   `session_get_deferred_rx_segments(s, &count)`.
3. Check the group byte budget and allocate token metadata before calling
   `session_acquire_deferred_rx_segments(s, &batch)`.
4. Return segment data, length and release tokens through `recv_next()`.
   SPDK may retain these tokens until the NVMe/TCP request finishes.
5. Release the complete batch with
   `session_release_deferred_rx_segments(&batch)` after its final token is
   returned, on the same owner worker.

Both the normal RX callback and `recv_next()` resolve the FIFO prefix through
the same helper. Readable FIFO bytes include buffer-backed bytes, so an
ordinary dequeue must not skip ahead to a copied suffix. When direct delivery
is disabled, metadata allocation fails, the byte budget is reached or acquire
cannot proceed, the helper materializes the prefix with
`session_flush_deferred_rx()`. A failed flush leaves the prefix pending and
returns `-EAGAIN`; an empty read allocates nothing.

The framework's `deferred-rx-max-segs` limit accounts for staged and acquired
segments across sessions on each worker. The binding additionally enforces a
socket-group byte budget. These are not a bound on total session memory or a
new global packet-pool reserve. Acquisition, reference counting and release
stay on the owner worker without introducing a new lock or atomic counter.

Before session close, SPDK must finish or abort requests holding returned
tokens. The socket group must outlive all its tokens; group destruction is
rejected while outstanding loans remain. Closing a socket releases only
tokens not yet handed to SPDK.

`show spdk` reports direct/copied RX bytes, outstanding loans and fallbacks.
The `test spdk direct-rx on|off` command is for controlled A/B measurements.
This RX review stack does not enable the optional TX reservation API or the
separate experimental TX-vlib-buffer path.

Native-NVMe DMA is not supported by this software-bdev review stack.
