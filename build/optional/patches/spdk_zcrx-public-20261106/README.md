# Experimental SPDK RX review stack

Base: upstream `652aadef06e5c73d08e099f1b12ce3abcd42b50b`, the parent of
the current 27049 PS52 review stack. The base already contains merged changes
29254, 27033, 27037 and 29257.

The archive and ten patches reproduce a local integration of these public
patchsets, in order:

- Patches 1-5: socket release notes, XLIO socket module and NVMf/TCP receive
  helper/API prerequisites from the 27049 PS52 ancestry. XLIO is not enabled
  or required by the VPP backend.
- Patch 6: 27048 PS51, direct in-capsule receive buffers.
- Patch 7: 27049 PS52, direct H2C receive buffers.
- Patch 8: 29255 PS14, copied fallback accounting and DMA-compatible storage.
- Patch 9: 29258 PS16, dynamically grown receive vectors and request reuse.
- Patch 10: 29602 PS1, receive-stream descriptor exhaustion/backpressure.

Patches 8-10 are clean cherry-picks onto the current Ben Walker review stack.
Their local commit hashes differ from the public Gerrit patchsets; this is not
a replacement for the upstream reviews. The tracker-pool correction is kept
separate from the VPP socket binding and HostStack implementation.

The matching VPP candidate uses 46940 PS20 on top of the merged plugin
baseline. The binding carries no additional HostStack or TCP changes. No TX
reservations, C2H direct placement or TX-vlib prototype are included. This
remains optional experimental RX work, not the merged minimal plugin.
