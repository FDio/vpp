.. _missing:

Missing Functionality
---------------------

A list of functionality that the FIB does not currently provide.


PIC Edge Backup Paths
^^^^^^^^^^^^^^^^^^^^^

FIB supports the concept of path 'preference'. Only paths that have
the best preference contribute to forwarding. Only once all the paths with
the best preference go down do the paths with the next best preference
contribute.

In BGP PIC edge, BGP would install the primary paths and the backup
paths. With expectation that backups are only used once all primaries
fail; this is the same behaviour that FIB's preference sets provide.

However, in order to get prefix independent convergence, one must be
able to only modify the path-list's load-balance map (LBM) to choose the
paths to use. Hence the paths must already be in the map, and
conversely must be in the fib_entry's load-balance (LB). In other
words, to use backup paths with PIC, the fib_entry's LB must include
the backup paths, and the path-lists LBM must map from the backups to
the primaries.

This is change that is reasonably easy w.r.t. to knowing what to
change, but hard to get right and hard to test.


Loop Free Alternate Paths
^^^^^^^^^^^^^^^^^^^^^^^^^^

Contrary to the BGP approach for path backups, an IGP could install a
loop free alternate (LFA) path to achieve fast re-route (FRR).

Because of the way the LFA paths are calculated by the IGP an LFA backup
path is always paired with a primary. VPP FIB does not support this
primary-backup pair relationship.

In intent of LFA FRR is/was to get below the magic 50ms mark. To do
this the expectation is/was that one would need in the forwarding
graph an object that represents a path's state. This object would be
checked for each packet being sent. If the path is up, the graph (an
adjacency since it's the IGP) for the primary path is taken, if it's
down the graph for the backup is taken. When a path goes down only
this indirection object needs to be updated to affect all
routes. Naturally, the indirection would incur a performance cost, but
we know that there are many performance-convergence trade-offs in a
FIB design.

Should VPP's FIB support this feature? It all depends on the
50ms. LFA FRR comes from the era when routers ran on lower performance
CPUs and interface down was an interrupt. VPP typically has plenty of
gas but runs as a user space process. So, can it update all routes in
under 50ms on a meaty CPU and can the OS deliver the interface down
within the time requirements? I don't have the answers to either
question.


Extranets for Multicast
^^^^^^^^^^^^^^^^^^^^^^^

When a unicast prefix is present in two different tables, then it
refers to a different set of devices. When the prefix is imported it
refers to the same set of devices. If the set of paths to reach the
prefix is different in the import and export table, it doesn't matter,
since they both refer to the same devices, so either set can be
used. Therefore, FIB's usual source preference rules can apply. The
'import' source is lower priority.

When a multicast prefix is present in two different tables, then it's
two different flows referring to two different set of receivers. When
the prefix is imported, then it refers to the same flow and two
different sets of receivers. In other words, the receiver set in the
import table needs to be the super set of receivers.

There are two ways one might consider doing this; merging the
path-lists or replicating the packet first into each table.


Collapsing
^^^^^^^^^^

Read :ref:`fastconvergence`

Collapsing the DPO graph for recursive routes doesn't have to be an
all or nothing. Easy cases:


- A recursive prefix with only one path and a path-list that is not
  popular, could stack directly on the LB of the via entry. 
- A recursive prefix with only multiple paths and a path-list that is not
  popular, could construct a new load balance using the choices
  present in each bucket of its via entries. The choices in the new LB
  though would need to reflect the relative weighting.


The condition of an non-popular path-list means that the LB doesn't
have an LB map and hence it needs to be updated for convergence to
occur.

The more difficult cases come when the recursive prefix has labels
which need to be stack on the via entries' choices.

You might also envision a global configuration that always collapses all
chains, which could be used in deployments where convergence is not a
priority.
