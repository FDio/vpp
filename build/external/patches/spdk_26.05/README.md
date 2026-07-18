# SPDK 26.05 patch audit

The source archive is the unmodified SPDK `v26.05` GitHub tag. The VPP
HostStack datapath applies three focused patches. SPDK thread scheduling uses
the public `spdk_thread_lib_init_ext()` and `spdk_thread_poll()` APIs and does
not require an SPDK scheduling patch.

## Patch set

| Patch | Required for | Why it remains |
| --- | --- | --- |
| `0001-sock-add-optional-transmit-buffer-reservations.patch` | Direct C2H data | This socket-layer contract lets a socket implementation expose writable TX storage and publish it only after the bdev I/O completes. It is optional for existing SPDK socket implementations. |
| `0002-nvmf-tcp-read-C2H-data-into-reserved-socket-buffers.patch` | Direct C2H data | The NVMe/TCP target reserves the stream region before submitting a controller-to-host bdev read, then builds and commits the PDU after completion. SPDK's existing zcopy mode does not remove the later copy into the socket backend. |
| `0003-build-allow-disabling-ISA-L-dependencies.patch` | Reproducible VPP external build | The GitHub tag archive does not contain the `isa-l` and `isa-l-crypto` submodules, while `configure` enables ISA-L on x86-64 and AArch64. VPP does not use the affected crypto/compression modules. This patch changes build configuration only, not runtime code. |

Patches 0001 and 0002 form one feature pair. A copy-mode-only build can drop
both after conditionally excluding the VPP socket reservation hooks; the
high-performance configuration enables `c2h_direct_sock` and therefore needs
both. Patch 0003 is needed by the current source-archive packaging.

Patch 0003 can be removed if packaging also downloads the exact ISA-L sources
referenced by the SPDK tag (`isa-l` commit
`c196241ae89b1aa4f62efeb849a937c011b3a926` and `isa-l-crypto` commit
`07d0b253843ace996aa5a44f538c9b83b085aba6`). That alternative builds and links
two unused dependencies, so the explicit disable option is preferred.

SPDK's two internal headers used by the socket implementation are installed by
the VPP package recipe. This is a consumer packaging responsibility and does
not require changing SPDK source.

## Validation

The stack was validated on AArch64 on 2026-07-18 by applying all patches to the
checksum-pinned archive, configuring SPDK with `--without-dpdk`, building the
package, and linking the VPP plugin. A four-worker smoke test reported
`spdk_thread_poll driven by VPP`, mapped VPP workers to lcores 2-5, and stopped
cleanly with zero SPDK threads and `last rc: 0`.

A negative configure test against the same unpatched source archive failed with
`ISA-L is required but was not found`, confirming why patch 0003 remains in the
current packaging model.
