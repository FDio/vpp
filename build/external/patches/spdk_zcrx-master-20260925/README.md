# SPDK RX zero-copy integration stack

This experimental package is based on SPDK commit
`d821b41883d5c30b66a9f543833aaac3cc3d7676` (`v27.01-pre`).

Patches 0001 through 0013 are Ben Walker's RX zero-copy review series
through changes 27033 PS46, 27037 PS45, 27048 PS45 and 27049 PS46.
Patches 0014 through 0016 are changes 29255 PS11, 29257 PS11 and
29258 PS12. Patch 0015 also advances the nvmf library major SO version to
25 because the extended request iovec changes the public request structure.
Patch 0017 adds the `--without-isal` build option from 29254.

The VPP socket backend implements `recv_next`, embeds the SPDK buffer token
in each backend token and records the owning `spdk_sock_group_impl`. All
buffers must be released before their socket group is closed.

This stack is carried by VPP Gerrit change 46734 as a public WIP/RFC to keep
the SPDK/VPP integration reproducible while the SPDK changes are under review.
Its VPP base includes the FIFO-backed deferred RX API from change 46940 PS7;
change 46736 supplies the corresponding socket binding. The source revision
and the 17 imported patches remain those used in the ARM/x86 validation.
This package is not intended to become a permanent downstream patch queue.

The separate RX stream-tracker pool forward-progress fix is not included.
Many-session tests exposed exhaustion of the fixed SPDK tracker pool while
requests retained receive segments; that correction will be reviewed
separately. The experimental TX-vlib-buffer prototype is also excluded, and
this RX stack does not enable the optional VPP TX reservation API.
