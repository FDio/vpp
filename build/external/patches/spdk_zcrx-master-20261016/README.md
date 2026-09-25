# SPDK RX zero-copy integration stack

This experimental package is based on SPDK master commit
`4828014884dcfafaaae1a741d613a45c57b64816` (`v27.01-pre`). The source
archive is pinned by commit and SHA-256; it does not track master at build time.

The socket receive API, memory-domain API, extended asynchronous write API,
socket-group requirement and io_uring receive implementation are now upstream.
Their six former patches are removed from this queue. Change 29254
(`--without-isal`) is also upstream; the VPP build still uses that option.

Patch 0001 imports change 29257 PS18, reviewed independently on SPDK master.
It retains the inline request vector by default and selects an extended vector
explicitly through `spdk_nvmf_request_set_iov()`. Its ABI change advances the
nvmf library major SO version to 25. The release note uses the upstream
`changelog.d` format.

Patches 0002 through 0007 import the remaining socket XLIO and NVMf/TCP
receive review stack, through changes 27048 PS48 and 27049 PS49. These
changes are still under review; rebased copies here are integration-only
and do not replace their upstream reviews.

Patch 0008 imports change 29255 PS12, fixing the scattered receive fallback.
Patch 0009 imports the pending update to 29258: dynamically grown vectors
use the explicit selection API and remain selected across request reuse.
It includes regression tests for both cases raised during review. This
update is not yet a published SPDK patchset; its original Change-Id is
preserved for traceability.

SPDK is built with matching C and C++ compilers. On Debian-derived
systems, `make install-dep` also installs C++ headers for the GCC runtime
selected by the C compiler. Clang may select a newer installed runtime
than the default g++, and SPDK's trace parser still needs its C++ headers
even when applications and examples are disabled.

VPP change 46734 includes the matching socket API adaptation, so the
intermediate commit uses copied RX. Change 46736 adds FIFO-backed deferred
RX acquisition and release using change 46940 PS7. The binding embeds the
SPDK buffer token in its backend token and records the owning socket group.
Returned buffers must be released before that group is closed.

This is a public WIP/RFC reproducibility dependency, not a permanent
downstream patch queue. The separate RX stream-tracker pool forward-progress
fix is not included. Many-session tests exposed exhaustion of the fixed
SPDK tracker pool while requests retained receive segments; that correction
will be reviewed separately. The experimental TX-vlib-buffer prototype is
also excluded, and this RX stack does not enable the optional VPP TX
reservation API.
