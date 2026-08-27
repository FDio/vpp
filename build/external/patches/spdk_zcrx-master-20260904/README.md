# SPDK RX zero-copy integration stack

This experimental package is based on SPDK commit
`96ce991932382f19b4ca737fa7e86a1ace45d569` (master on 2026-09-04).

Patches 0001 through 0018 are Ben Walker's RX zero-copy review series
rebased on that commit. Patch 0019 fixes the scattered receive fallback.
Patches 0020 and 0021 retain the normal request/PDU vector sizes and grow
them on demand. Patch 0022 adds the `--without-isal` build option. VPP
uses the existing `spdk_thread_lib_init_ext()` and `spdk_thread_poll()`
interfaces; this stack does not add a reactor-polling API.

The VPP socket backend must implement `recv_next` and release each returned
buffer token. Its HostStack dependency is Florin Coras's deferred RX series,
followed by the experimental `take` API and pool-wide loan admission guard.

This stack is local and has not been submitted to VPP Gerrit.
