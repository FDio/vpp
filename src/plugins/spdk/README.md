# SPDK VPP Plugin

This plugin embeds SPDK in the VPP process and registers an SPDK socket
implementation backed by VPP HostStack builtin sessions. It uses SPDK's public
thread API: SPDK lightweight threads are assigned to VPP dataplane threads and
VPP input-node polling calls `spdk_thread_poll()` directly. No SPDK-owned
pthread is added to the dataplane.

The plugin registers one SPDK socket implementation, `vpp`. It implements the
SPDK socket API with VPP builtin HostStack sessions. SPDK's NVMe/TCP transport
still parses and produces NVMe/TCP PDUs, but VPP owns the TCP state machine,
timers, congestion control and RX/TX FIFOs. Linux TCP sockets are not used by
listeners configured with `sock_impl: "vpp"`.

VPP builds a pinned vanilla SPDK release as an external dependency. It verifies
the source archive checksum and then applies the versioned patches in
`build/external/patches/spdk_<version>/`.  The rationale, optional feature pair,
removed patches and validation evidence are recorded in that directory's
`README.md`.
Build the normal VPP tree with:

```bash
make build
```

The package definition is `build/external/packages/spdk.mk`.  SPDK is configured
with `--without-dpdk` and a VPP environment description from
`build/external/spdk-env-vpp`; neither VPP's DPDK package nor SPDK's DPDK
submodule is required. The plugin supplies CPU, memory, mempool, ring and timing
services through `spdk_vpp_env.c`. Allocations that fit in a VPP physical-memory
page use VPP physical memory. Larger software-only allocations use anonymous
hugepage mappings, with aligned process memory as a fallback when hugepages are
unavailable; both are deliberately rejected by `spdk_vtophys()`. PCI
enumeration is rejected for now, so the embedded application must be started
with `no-pci`. Supporting native PCI NVMe later requires a VPP PCI/VFIO-backed
SPDK environment provider; it does not require DPDK. The plugin discovers the
installed SPDK headers, archives and `pkg-config` metadata through VPP's
`CMAKE_PREFIX_PATH`.
SPDK archives are linked with `--whole-archive` so module constructors are
preserved.  Set `-DVPP_BUILD_SPDK_PLUGIN=OFF` in `VPP_EXTRA_CMAKE_ARGS` to omit
the plugin while retaining the external package.

Start from VPP CLI:

```text
spdk app start name vpp_spdk json /path/to/nvmf.json reactor-mask 0x2 no-pci
show spdk
spdk app stop
```

If `reactor-mask` is omitted, the plugin uses all VPP workers and excludes
`vpp_main`. With no workers, it uses the main thread. An explicit mask must map
exactly one SPDK lcore to every VPP dataplane thread. `show spdk` displays the
mapping as `vpp<thread-index>=<spdk-lcore>`.

The plugin sets the default SPDK socket implementation to `vpp` before startup.
NVMe/TCP listeners should still specify `sock_impl: "vpp"` explicitly so a
configuration error cannot silently select the POSIX backend. The vanilla SPDK
acceptor creates one VPP listener and dispatches each accepted qpair to the
SPDK poll group running on the VPP worker that owns the HostStack session.

The socket backend also implements SPDK's optional transmit-reservation API.
An experimental NVMe/TCP transport option, `c2h_direct_sock`, makes SPDK bdev
reads target writable regions of the HostStack session TX FIFO.  A reservation
assigns its position in the TCP byte stream and provisions the corresponding
FIFO chunks before the bdev read is submitted.  On I/O completion, commit marks
the region ready; only a contiguous committed prefix is published to TCP, so
out-of-order bdev completions cannot expose uninitialised bytes.  Regular socket
writes wait behind outstanding reservations.  Only the newest reservation can
be aborted without leaving a FIFO hole; a failure to abort causes NVMe/TCP to
quiesce the qpair rather than risk corrupting the stream.  The path currently
supports I/O qpairs without DIF or header/data digests and supports both values
of `c2h_success`.

The option defaults to `false`.  It eliminates the bdev-to-session-FIFO copy:
the bdev fills FIFO storage directly.  The regular HostStack TCP output path
still copies FIFO data into output packet buffers, so this is not end-to-end
NIC zero copy yet.  Reservation descriptors are cached per socket to avoid a
heap allocation per I/O.

Each FIFO span consumes one NVMe/TCP request iovec.  A reservation must fit in
the current 34-entry iovec limit.  The physical benchmark configuration uses
32 KiB VPP packet buffers for the later TCP-output stage.

For host-to-controller writes, the socket backend implements SPDK's
`spdk_sock_recv_next()` API on top of HostStack's deferred RX interface. The
normal built-in application callback may take the ordered VLIB buffer-backed
segments immediately and expose them to SPDK as receive tokens. SPDK releases
each token after NVMe/TCP has finished consuming the payload, and the plugin
returns the associated buffers on their owning VPP worker.

Data is materialized into the session FIFO when direct delivery is disabled,
stream ordering requires it, a segment cannot be represented safely, or the
buffer-pool admission guard refuses a loan. The guard accounts outstanding
loans for the whole VLIB buffer pool and preserves one per-thread cache refill
as a reserve. A separate per-worker byte limit bounds application retention.
`show spdk` reports direct and copied RX bytes, loan lifetime, fallbacks and
pool low-watermarks. The `test spdk direct-rx on|off` command is intended only
for controlled A/B measurements.

The physical benchmark uses SPDK Malloc bdevs.  A native DMA bdev additionally
requires every FIFO chunk exposed to the bdev to be DMA-safe and registered in
SPDK's memory map.  The following asynchronous, non-destructive diagnostic
only validates VPP packet-buffer pool registration and direct reads into those
packet buffers:

```text
test spdk vpp-buffer-dma bdev <name> bytes 128K data-align 512 register-pool
show spdk vpp-buffer-dma-test
```

`register-pool` is currently explicit and intended for this diagnostic.  It
does not register session FIFO chunks, so native-NVMe DMA directly into the
FIFO is not a production-supported path yet.

The current backend intentionally keeps interrupt fd polling disabled.
