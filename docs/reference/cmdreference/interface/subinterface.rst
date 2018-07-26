.. _subinterfacecommands:

.. toctree::

Create Sub-Interfaces
=====================
This command is used to add VLAN IDs to interfaces, also known as
subinterfaces. The primary input to this command is the '*interface*'
and '*subId*' (subinterface Id) parameters. If no additional VLAN ID is
provide, the VLAN ID is assumed to be the '*subId*'. The VLAN ID and
'*subId*' can be different, but this is not recommended.

This command has several variations:

-  **create sub-interfaces <interface> <subId>** - Create a subinterface
   to process packets with a given 802.1q VLAN ID (same value as the
   '*subId*').
-  **create sub-interfaces <interface> <subId> default** - Adding the
   '*default*' parameter indicates that packets with VLAN IDs that do
   not match any other subinterfaces should be sent to this
   subinterface.
-  **create sub-interfaces <interface> <subId> untagged** - Adding the
   '*untagged*' parameter indicates that packets no VLAN IDs should be
   sent to this subinterface.
-  **create sub-interfaces <interface> <subId>-<subId>** - Create a
   range of subinterfaces to handle a range of VLAN IDs.
-  **create sub-interfaces <interface> <subId> dot1q|dot1ad <vlanId>|any
   [exact-match]** - Use this command to specify the outer VLAN ID, to
   either be explicited or to make the VLAN ID different from the
   '*subId*'.
-  **create sub-interfaces <interface> <subId> dot1q|dot1ad <vlanId>|any
   inner-dot1q <vlanId>|any [exact-match]** - Use this command to
   specify the outer VLAN ID and the innner VLAN ID.

When '*dot1q*' or '*dot1ad*' is explictly entered, subinterfaces can be
configured as either exact-match or non-exact match. Non-exact match is
the CLI default. If '*exact-match*' is specified, packets must have the
same number of VLAN tags as the configuration. For non-exact-match,
packets must at least that number of tags. L3 (routed) interfaces must
be configured as exact-match. L2 interfaces are typically configured as
non-exact-match. If '*dot1q*' or '*dot1ad*' is NOT entered, then the
default behavior is exact-match.

Use the '*show interface*' command to display all subinterfaces.

Summary/Usage
-------------

.. code-block:: shell

    create sub-interfaces <interface> {<subId> [default|untagged]} | {<subId>-<subId>} | {<subId> dot1q|dot1ad <vlanId>|any [inner-dot1q <vlanId>|any] [exact-match]}.

Examples
--------

Example of how to create a VLAN subinterface 11 to process packets on 802.1q VLAN ID 11:

.. code-block:: console

    vpp# create sub-interfaces GigabitEthernet2/0/0 11

The previous example is shorthand and is equivalent to:

.. code-block:: console

    vpp# create sub-interfaces GigabitEthernet2/0/0 11 dot1q 11 exact-match

Example of how to create a subinterface number that is different from the VLAN ID:

.. code-block:: console

    vpp# create sub-interfaces GigabitEthernet2/0/0 11 dot1q 100

Examples of how to create q-in-q and q-in-any subinterfaces:

.. code-block:: console

    vpp# create sub-interfaces GigabitEthernet2/0/0 11 dot1q 100 inner-dot1q 200
    vpp# create sub-interfaces GigabitEthernet2/0/0 12 dot1q 100 inner-dot1q any

Examples of how to create dot1ad interfaces:

.. code-block:: console

    vpp# create sub-interfaces GigabitEthernet2/0/0 11 dot1ad 11
    vpp# create sub-interfaces GigabitEthernet2/0/0 12 dot1ad 100 inner-dot1q 200

Examples of '*exact-match*' versus non-exact match. A packet with outer VLAN 100 and inner VLAN 200 would match this interface, because the default is non-exact match:

.. code-block:: console

    vpp# create sub-interfaces GigabitEthernet2/0/0 5 dot1q 100

However, the same packet would NOT match this interface because '*exact-match*' is specified and only one VLAN is configured, but packet contains two VLANs:

.. code-block:: console

    vpp# create sub-interfaces GigabitEthernet2/0/0 5 dot1q 100 exact-match

Example of how to created a subinterface to process untagged packets:

.. code-block:: console

   vpp# create sub-interfaces GigabitEthernet2/0/0 5 untagged

Example of how to created a subinterface to process any packet with a VLAN ID that does not match any other subinterface:

.. code-block:: console

    vpp# create sub-interfaces GigabitEthernet2/0/0 7 default

When subinterfaces are created, they are in the down state. Example of how to enable a newly created subinterface:

.. code-block:: console

    vpp# set interface GigabitEthernet2/0/0.7 up
        
