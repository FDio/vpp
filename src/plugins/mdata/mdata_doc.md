# Buffer metadata change tracker {#mdata_doc}

## Introduction

The mdata plugin uses the vlib main loop "before" performance counter
hook to snapshoot buffer metadata before calling the node dispatch
function. Similarly, the plugin uses the main loop "after" hook to
compare a vectors' worth of buffer metadata after the fact.

The comparison function is a simple octet-by-octet A != B check. We
accumulate changed octets per-node across the entire run, using a
single spinlock-protected accumulator.

The "show buffer metadata" command produces a report of all fields
whose values are changed by nodes visited during a given run.

Since many fields in the vnet_buffer_opaque_t are union members,
it may appear that a certain node changes numerous fields. The entire
point of the exercise is to warn developers that if a packet visits
node N, data placed into opaque union field F *will* be affected.

One should never assume much about buffer metadata immutability across
arbitrary subgraphs. This tool generates accurate reports, to the
extent that one exercises the required subgraph trajectories.
