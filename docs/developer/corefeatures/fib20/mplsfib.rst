.. _mplsfib:

MPLS FIB
--------

Implementation
^^^^^^^^^^^^^^^

The MPLS FIB is implemented using exactly the same data structures as
the IP FIB.  The only difference is the implementation of the
table. Whereas for IPv4 this is an mtrie and for IPv6 a hash table,
for MPLS it is a flat array indexed by a 21 bit key (label & EOS
bit). This implementation is chosen to favour packet forwarding speed.

It can be the case in MPLS forwarding that packets received with the
EOS bit set in the MPLS label need to be forwarded differently from
those without. The most common example of this is if the path set
contains a path that does not have an output label. In this case the
non-EOS packets cannot take this path, because to do so would expose
the neighbouring router to a label that it did not allocate.

The desgin choice to make with an MPLS FIB table is therefore:
- 20 bit key: label only. When the EOS and non-EOS actions differ the result is a 'EOS-choice' object.
- 21 bit key: label and EOS-bit. The result is then the specific action based on EOS-bit.

20 bit key
  - Advantages:lower memory overhead, since there are few DB entries.
  - Disadvantages: slower DP performance in the case the path-lists
    differ, as more objects are encounterd in the switch path

21 bit key
  - Advantages: faster DP performance
    Disadvantages: increased memory footprint.

Switching between schemes based on observed/measured action similarity
is not considered on the grounds of complexity and flip-flopping.

VPP mantra - favour performance over memory. We choose a 21 bit key.

Basics
^^^^^^

MPLS is not enabled by default. There are two steps to get
started. First, create the default MPLS FIB:

.. code-block:: console

   $ mpls table add 0

With '0' being the magic number for the 'default' table (just like it
is for IPv[46]). One can create other MPLS tables, but, unlike IP
tables, one cannot 'bind' non-default MPLS tables to interfaces, in
other words all MPLS packets received on an interface will always
result in a lookup in the default table. One has to be more inventive
to use the non-default tables...

Secondly, for *each* interface on which you wish to *receive* MPLS
packets, that interface must be MPLS 'enabled'

.. code-block:: console

   $ set interface mpls GigEthernet0/0/0 enable

there is no equivalent enable for transmit, all that is required is to
use an interface as an egress path.

Entries in the MPLS FIB can be displayed with:

.. code-block:: console

   $ sh mpls fib [table X] [label]

There is a tight coupling between IP and MPLS forwarding. MPLS
forwarding equivalence classes (FECs) are often an IP prefix – that is
to say that traffic matching a given IP prefix is routed into a MPLS
label switch path (LSP). It is thus necessary to be able to associate
a given prefix/route with an [out-going] MPLS label that will be
imposed when the packet is forwarded. This is configured as:

.. code-block:: console

   $ ip route add 1.1.1.1/32 via 10.10.10.10 GigEthernet0/0/0 out-labels 33

packets matching 1.1.1.1/32 will be forwarded out GigEthernet0/0/0 and have
MPLS label 33 imposed. More than one out-going label can be
specified. Out-going MPLS labels can be applied to recursive and
non-recursive routes, e.g;

.. code-block:: console

   $ ip route add 2.2.2.0/24 via 1.1.1.1 out-labels 34

packets matching 2.2.2.0/24 will thus have two MPLS labels imposed; 34
and 33. This is the realisation of, e,g, an MPLS BGP VPNv4.

To associate/allocate a local-label for a prefix, and thus have
packets to that local-label forwarded equivalently to the prefix do;

.. code-block:: console

   $ mpls local-label 99 2.2.2.0/24

In the API this action is called a ‘bind’.
The router receiving the MPLS encapsulated packets needs to be
programmed with actions associated which each label value – this is
the role of the MPLS FIB. The MPLS FIB is a table, whose key is the
MPLS label value and end-of-stack (EOS) bit, which stores the action
to perform on packets with matching encapsulation. Currently supported
actions are:

#. Pop the label and perform an IPv[46] lookup in a specified table
#. Pop the label and forward via a specified next-hop (this is penultimate-hop-pop, PHP)
#. Swap the label and forward via a specified next-hop.

These can be programmed respectively by:	

.. code-block:: console

   $ mpls local-label 33 eos ip4-lookup-in-table X
   $ mpls local-label 33 [eos] via 10.10.10.10 GigEthernet0/0/0
   $ mpls local-label 33 [eos] via 10.10.10.10 GigEthernet0/0/0 out-labels 66

the latter is an example of an MPLS cross connect. Any description of
a next-hop, recursive, non-recursive, labelled, non-labelled, etc,
that is valid for an IP prefix, is also valid for an MPLS
local-label. Note the use of the 'eos' keyword which indicates the
programming is for the case when the label is end-of-stack. The last
two operations can apply to both eos and non-eos packets, but the pop
and IP lookup only to an eos packet.


MPLS VPN
^^^^^^^^

To configure an MPLS VPN for a PE the following example can be used.

Step 1; Configure routes to the iBGP peers - note these route MUST
have out-going labels;

.. code-block:: console

   $ ip route add 10.0.0.1/32 via 192.168.1.2 Eth0 out-labels 33
   $ ip route add 10.0.0.2/32 via 192.168.2.2 Eth0 out-labels 34

Step 2; Configure the customer 'VRF'

.. code-block:: console

   $ ip table add 2

Step 3; add a route via the iBGP peer[s] with the MPLS label
advertised by that peer

.. code-block:: console

   $ ip route add table 2 10.10.10.0/24 via 10.0.0.2 next-hop-table 0 out-label 122
   $ ip route add table 2 10.10.10.0/24 via 10.0.0.1 next-hop-table 0 out-label 121

Step 4; add a route via the eBGP peer

.. code-block:: console

   $ ip route add table 2 10.10.20.0/24 via 172.16.0.1 next-hop-table 2

Step 5; depending on the label allocation scheme used, add routes to
the MPLS FIB to accept incoming labelled packets:

#. per-prefix label scheme - this command 'binds' the label to the same
   forwarding as the IP route

   .. code-block:: console

      $ mpls local-label 99 10.10.20.0/24

#. per-CE label scheme - this pops the incoming label and forwards via
   the next-hop provided. Append config for 'out-labels' if so desired.

   .. code-block:: console

      $ mpls local-label 99 via 172.16.0.1 next-hop-table 2

#. per-VRF label scheme

   .. code-block:: console

      $ mpls local-label 99 via ip4-lookup-in-table 2

MPLS Tunnels
^^^^^^^^^^^^

MPLS tunnels are unidirectional and can impose a stack of labels. They
are 'normal' interfaces and thus can be used, for example, as the
target for IP routes and L2 cross-connects. To construct a tunnel:

.. code-block:: console

   $ mpls tunnel add via 10.10.10.10 GigEthernet0/0/0 out-labels 33 44 55

and to then have that created tunnel to perform ECMP:

.. code-block:: console

   $ mpls tunnel add mpls-tunnel0 via 10.10.10.11 GigEthernet0/0/0 out-labels 66 77 88

use

.. code-block:: console

   $ sh mpls tunnel [X]

to see the monster you have created.

An MPLS tunnel interface is an interface like any other and now ready
for use with the usual set of interface commands, e.g.:

.. code-block:: console

   $ set interface state mpls-tunnel0 up
   $ set interface ip address mpls-tunnel0 192.168.1.1/30
   $ ip route 1.1.1.1/32 via mpls-tunnel0
