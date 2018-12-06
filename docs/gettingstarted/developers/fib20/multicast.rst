.. _mfib:

IP Multicast FIB
----------------

Basics
^^^^^^

An IP multicast FIB (mFIB) is a data-structure that holds entries that
represent a (S,G) or a (\*,G) multicast group. There is one IPv4 and
one IPv6 mFIB per IP table, i.e. each time the user calls 'ip[6] table
add X' an mFIB is created.


A path describes either where a packet is sent to or where a packet is
received from. mFIB entries maintain two sets of 'paths'; the
forwarding set and the accepting set. Each path in the forwarding set
will output a replica of a received packet. A received packet is only
accepted for forwarding if it ingresses on a path that matches in the
accepting set - this is the RPF check.


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
