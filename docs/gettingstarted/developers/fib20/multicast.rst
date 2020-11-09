.. _mfib:

IP Multicast FIB
----------------

The two principal differences between multicast and unicast forwarding
are:

* there is no load-balancing among paths, there is only replication
  across paths.
* multicast forwarding has an explicit reverse path forwarding (RPF)
  check. It will only forward a packet if it arrives from a peer for
  which it has been explicitly configured to accept.

The other factor that influences the design of the mFIB is that the
match criteria (the prefix) is different. For multicast it is 
necessary to be able to match on source and destination/group
addresses (termed an (S,G)) and only on a destination prefix (a (\*,
G/m)). This prefix is much bigger than a unicast prefix, and since
unicast scale is almost always greater than multicast scale, it is not
a good idea to have a single definition of a prefix. Therefore,
there is a fib_prefix_t (and hence a fib_entry_t) and an
mfib_prefix_t (and hence a mfib_entry_t).

The fib_path_t and fib_path_list_t are reused. A path can represent
either a peer from which to accept packets or a peer to which to send
packets. A path-extension is added to the fib_path_t/mfib_entry_t to
describe the role the path plays. Logically the path-list is split
into two sets; an accepting set and a forwarding set. The forwarding set
contributes a replicate DPO for forwarding and the accepting set
contributes a list of interfaces (an mfib_itf_t) for the RPF check.

An IP multicast FIB (mFIB) is a data-structure that holds entries that
represent a (S,G) or a (\*,G/m) multicast group. There is one IPv4 and
one IPv6 mFIB per IP table, i.e. each time the user calls 'ip[6] table
add X' an mFIB is created.

Usage
^^^^^

To add an entry to the default mFIB for the group (1.1.1.1, 239.1.1.1)
that will replicate packets to GigEthernet0/0/0 and GigEthernet0/0/1, do:

.. code-block:: console

   $ ip mroute add 1.1.1.1 239.1.1.1 via GigEthernet0/0/0 Forward
   $ ip mroute add 1.1.1.1 239.1.1.1 via GigEthernet0/0/1 Forward

the flag 'Forward' passed with the path specifies this path to be part of the replication set.
To add a path from GigEthernet0/0/2 to the accepting (RPF) set do:

.. code-block:: console

   $ ip mroute add 1.1.1.1 239.1.1.1 via GigEthernet0/0/2 Accept

A (\*,G) entry is added by not specifying a source address:

.. code-block:: console

   $ ip mroute add 232.2.2.2 via GigEthernet0/0/2 Forward

A (\*,G/m) entry is added by not specifying a source address and giving
the group address a mask:

.. code-block:: console

   $ ip mroute add 232.2.2.0/24 via GigEthernet0/0/2 Forward

Entries are deleted when all paths have been removed and all entry flags (see below) are also removed.

Advanced
^^^^^^^^

There are a set of flags associated only with an entry, see:

.. code-block:: console

   $ show mfib route flags

only some of these are relevant over the API/CLI:

#. Signal - packets that match this entry will generate an event that
   is sent to the control plane (which can be retrieved via the signal
   dump API)
#. Connected - indicates that the control plane should be informed of
   connected sources (also retrieved via the signal dump API)
#. Accept-all-itf - the entry shall accept packets from all
   interfaces, thus eliminating the RPF check
#. Drop - Drop all packet matching this entry.

flags on an entry can be changed with:

.. code-block:: console

   $ ip mroute <PREFIX> <FLAG>

An alternative approach to the RPF check, that does check the
accepting path set, is to give the entry and RPF-ID:

.. code-block:: console

   $ ip mroute <PREFIX> rpf-id X

the RPF-ID is an attribute of a received packet's meta-data and is
added to the packet when it ingresses on a given entity such as an
MPLS-tunnel or a BIER table disposition entry.
