# SPDK VPP Plugin

This plugin embeds an SPDK application in the VPP process and registers an
SPDK socket implementation backed by VPP HostStack builtin sessions. SPDK is
started in external reactor mode: VPP input-node polling drives the SPDK
reactors, so the SPDK poll-mode loops are shared with VPP threads instead of
running on SPDK-owned pthreads.

The plugin registers one SPDK socket implementation, `vpp`. It implements the
SPDK socket API with VPP builtin HostStack sessions. SPDK's NVMe/TCP transport
still parses and produces NVMe/TCP PDUs, but VPP owns the TCP state machine,
timers, congestion control and RX/TX FIFOs. Linux TCP sockets are not used by
listeners configured with `sock_impl: "vpp"`.

Build VPP with:

```bash
cmake -S src -B build-spdk \
  -DVPP_BUILD_SPDK_PLUGIN=ON \
  -DSPDK_ROOT=/path/to/spdk
cmake --build build-spdk --target spdk_plugin
```

`SPDK_ROOT` must point to an SPDK tree that has already been built. The plugin
uses `pkg-config` files from `SPDK_ROOT/build/lib/pkgconfig` and
`SPDK_ROOT/dpdk/build/lib/pkgconfig` to select the SPDK modules needed by an
NVMe/TCP target. SPDK archives are linked with `--whole-archive` so module
constructors are preserved, while DPDK is kept static to avoid a runtime
dependency on `librte_*.so`.

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
reads target detached VPP packet buffers.  A reservation consumes socket TX
credit but does not take a position in the TCP byte stream.  On I/O completion,
the buffers are appended atomically to the HostStack TX FIFO in completion
order; any incomplete reservation can be aborted without leaving a stream
hole.  It currently supports I/O qpairs without DIF or header/data digests and
supports both values of `c2h_success`.

The option defaults to `false`.  This implementation removes the earlier
reservation-order head-of-line blocking, but it still copies completed VPP
buffers into the session FIFO, after which the regular HostStack TCP path
copies FIFO data into output packets.  It is therefore a completion-ordered
buffer handoff and DMA-enablement step, not end-to-end TCP zero copy yet.
Reservation descriptors are cached per socket to avoid a heap allocation per
I/O.

Each reserved VPP buffer consumes one NVMe/TCP request iovec.  With the current
34-entry limit, a 128 KiB request requires a VPP default buffer data size of at
least about 4 KiB; the physical benchmark configuration uses 10 KiB buffers.

For a native DMA bdev, start SPDK without `no-pci` and register the VPP buffer
pool with SPDK's memory map before issuing I/O.  The following asynchronous,
non-destructive read diagnostic validates the mapping and reads directly into
VPP buffers:

```text
test spdk vpp-buffer-dma bdev <name> bytes 128K data-align 512 register-pool
show spdk vpp-buffer-dma-test
```

`register-pool` is currently explicit and intended for this diagnostic.  A
production native-NVMe path must register all pools during plugin startup and
unregister them only after all DMA has stopped.

The current backend intentionally keeps interrupt fd polling disabled.
