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

This stack is carried by a private VPP Gerrit WIP only to keep the SPDK/VPP
integration reproducible while the referenced SPDK changes are under review.
It is not intended to be merged as a permanent downstream patch queue.
