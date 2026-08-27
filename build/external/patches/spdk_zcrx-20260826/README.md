# SPDK RX zero-copy experiment

This private WIP package records the exact SPDK source series used by the
VPP/SPDK BlueField-3 RX zero-copy experiment on 2026-08-26.

The checksum-pinned source archive is SPDK commit
`3230130e6a4114a97991d7e27cecd5ab64b696c3`.  The numbered patches reproduce
the source tree through commit
`8052325bccc3f16dbc6588ff157fe7130abea5ac`.

Patches 0001 through 0018 are Ben Walker's socket refactor and RX zero-copy
series.  The four review changes that define the receive-buffer API and its
NVMf/TCP use are:

- https://review.spdk.io/c/spdk/spdk/+/27033
- https://review.spdk.io/c/spdk/spdk/+/27037
- https://review.spdk.io/c/spdk/spdk/+/27048
- https://review.spdk.io/c/spdk/spdk/+/27049

The earlier patches are retained because they are parents and prerequisites
of that review series.  Patch 0019 lets VPP workers drive SPDK reactors.
Patches 0020 and 0021 are local integration fixes: correct fallback accounting
and permit the MTU-sized receive segments used by the VPP socket backend.

This is an experimental, reproducibility-oriented package.  It intentionally
does not contain the later SPDK RX identity diagnostics and does not modify
SPDK's DPDK submodule.
