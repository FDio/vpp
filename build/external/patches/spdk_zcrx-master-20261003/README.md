# SPDK RX zero-copy integration stack

This experimental package is based on SPDK master commit
`d912280586e358f2db3cbe4b4a92a252f8f40215` (`v27.01-pre`). The source
archive is pinned by commit and SHA-256; it does not track master at build time.

Patches 0001 through 0012 carry Ben Walker's socket RX zero-copy review
series through changes 27033 PS46, 27037 PS45, 27048 PS45 and 27049 PS46.
They are still under review and are not part of the upstream base. The old
review-series release-documentation patch is omitted: the new base already
documents the v26.09 socket API, and that historical documentation is kept.
Rebase conflicts remove obsolete deprecation logs for APIs replaced by the
review series; no receive ownership or TCP data-path behavior is changed.

Patches 0013 through 0015 carry changes 29255 PS11, 29257 PS12 and
29258 PS12. Patch 0014 advances the nvmf library major SO version to 25
because the extended request iovec changes the public request structure.
Change 29257 is reviewed directly on SPDK master; its import includes the
generic vector-selection and fragmented request-copy unit tests from PS12.
Change 29254 (`--without-isal`) is now upstream and is no longer carried
as a patch. The configure option is still used by the VPP build.

VPP change 46734 includes the matching socket API adaptation, so the
intermediate commit builds and runs using copied RX. Change 46736 adds
FIFO-backed deferred RX acquisition and release using change 46940 PS7.
The binding embeds the SPDK buffer token in its backend token and records
the owning socket group. Returned buffers must be released before that
group is closed.

This is a public WIP/RFC reproducibility dependency, not a permanent
downstream patch queue. The separate RX stream-tracker pool forward-progress
fix is not included. Many-session tests exposed exhaustion of the fixed
SPDK tracker pool while requests retained receive segments; that correction
will be reviewed separately. The experimental TX-vlib-buffer prototype is
also excluded, and this RX stack does not enable the optional VPP TX
reservation API.
