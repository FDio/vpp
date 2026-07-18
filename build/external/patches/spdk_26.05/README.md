# SPDK 26.05 patch audit

The source archive is the unmodified SPDK `v26.05` GitHub tag.  The full VPP
HostStack datapath applies four patches.  They are kept as separate logical
changes so that upstreaming or dropping an optional feature does not require a
single VPP-specific monolithic patch.

## Required patch set

| Patch | Required for | Why it remains |
| --- | --- | --- |
| `0001-event-allow-external-polling-of-SPDK-reactors.patch` | The in-process plugin | Vanilla `spdk_app_start()` owns and blocks in SPDK reactor threads.  VPP instead polls one SPDK reactor from each existing VPP worker.  Reimplementing the SPDK event framework in the plugin would duplicate private SPDK lifecycle code. |
| `0002-sock-add-optional-transmit-buffer-reservations.patch` | Direct C2H data | This is the socket-layer contract that lets a socket implementation expose writable TX storage and publish it only after the bdev I/O completes.  It is optional for all existing SPDK socket implementations. |
| `0003-nvmf-tcp-read-C2H-data-into-reserved-socket-buffers.patch` | Direct C2H data | The NVMe/TCP target must reserve the stream region before submitting a controller-to-host bdev read, then build and commit the PDU after completion.  Vanilla SPDK's existing zcopy mode does not remove the later copy into the socket backend. |
| `0004-build-allow-disabling-ISA-L-dependencies.patch` | Reproducible VPP external build | The GitHub tag archive does not contain the `isa-l` and `isa-l-crypto` submodules, while vanilla `configure` forces ISA-L on x86-64 and AArch64.  VPP does not use the affected crypto/compression modules.  This patch changes build configuration only, not runtime code. |

Patches 0002 and 0003 form one optional feature pair.  A copy-mode-only build
could drop both after conditionally excluding the VPP socket reservation hooks;
the current plugin source and high-performance configuration enable
`c2h_direct_sock` and therefore need both.  Patch 0001 is the only SPDK runtime
patch intrinsically required by the base in-process architecture.  Patch 0004
is also needed by the current source-archive packaging.

Patch 0004 can be removed if packaging also downloads the exact ISA-L sources
referenced by the SPDK tag (`isa-l` commit
`c196241ae89b1aa4f62efeb849a937c011b3a926` and `isa-l-crypto` commit
`07d0b253843ace996aa5a44f538c9b83b085aba6`).  That alternative builds and links
two unused dependencies, so the small explicit disable option is preferred.

## Removed patches

Two patches from the original six-patch stack were unnecessary:

- The public `spdk_env_set_current_core()` addition was removed.  The VPP
  environment owns its current-core TLS value, and the plugin now updates it
  with the private `spdk_vpp_env_set_current_core()` before initialization and
  each externally polled reactor.  No generic SPDK environment API change is
  needed.
- The SPDK header-install patch was removed.  The VPP external-package install
  recipe copies the two internal headers required to build an external socket
  implementation.  This is a consumer packaging responsibility and does not
  require changing SPDK source.

## Validation

The reduced stack was validated on AArch64 on 2026-07-16:

- all four patches applied cleanly to the checksum-pinned vanilla archive;
- SPDK configured with `--without-dpdk`, built, and installed;
- the package recipe installed `spdk_internal/sock_module.h` and
  `spdk_internal/trace_defs.h` without an SPDK patch;
- `spdk_plugin.so` compiled and linked without DPDK or
  `spdk_env_set_current_core` references;
- VPP started the embedded app with four workers/reactors `[2,3,4,5]` and
  reported `last rc: 0`;
- the 128 KiB `Malloc0` VPP-buffer DMA functional test completed successfully;
- shutdown completed with `last rc: 0`.

A negative configure test against the same unpatched source archive failed with
`ISA-L is required but was not found`, confirming why patch 0004 remains in the
current packaging model.
