# Experimental SPDK RX review stack

Base: upstream `f2b83390b8e8e7f50a2f11788ba6fc50be281008`.
The base already contains merged changes 29254, 27033, 27037 and 29257.
The archive plus the ten patches reproduces the public commit
`8aae4264c35b134e352de03e83b7ec78b9a61958` (29602 PS1), not a private
replacement for the SPDK review series.

The first five patches carry the socket release notes, XLIO socket module
and NVMf/TCP receive helper/API prerequisites from that public ancestry.
XLIO itself is not enabled or required by the VPP backend.

- Patch 6: 27048 PS49, direct in-capsule receive buffers.
- Patch 7: 27049 PS50, direct H2C receive buffers.
- Patch 8: 29255 PS14, copied fallback accounting and DMA-compatible storage.
- Patch 9: 29258 PS13, dynamically grown receive vectors and request reuse.
- Patch 10: 29602 PS1, receive-stream descriptor exhaustion/backpressure.

The tracker-pool correction remains a separately reviewed SPDK change. It
is included here explicitly for multi-qpair forward-progress validation;
it is not hidden in the VPP socket binding or HostStack implementation.

The matching VPP candidate uses the public 46940 PS14 on top of the merged
plugin baseline. The binding carries no additional HostStack or TCP changes.
No public patchset belonging to another author is replaced by this export.
No TX reservations, C2H direct placement or TX-vlib prototype are included.
This remains optional experimental RX work, not the merged minimal plugin.
