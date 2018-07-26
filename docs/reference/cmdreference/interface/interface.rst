.. _intcommands:

Interface Commands
==================

.. toctree::

.. _showintcommand:

Show Interface
==============
Shows software interface information including counters and features

Summary/Usage
-------------

.. code-block:: shell

    show interface [address|addr|features|feat] [<interface> [<interface> [..]]]

Examples
--------

Example of how to show the interface counters:

.. code-block:: console

    vpp# show int
                  Name               Idx       State          Counter          Count     
    TenGigabitEthernet86/0/0          1         up       rx packets               6569213
                                                         rx bytes              9928352943
                                                         tx packets                 50384
                                                         tx bytes                 3329279
    TenGigabitEthernet86/0/1          2        down      
    VirtualEthernet0/0/0              3         up       rx packets                 50384
                                                         rx bytes                 3329279
                                                         tx packets               6569213
                                                         tx bytes              9928352943
                                                         drops                       1498
    local0                            0        down      

Example of how to display the interface placement:

.. code-block:: console

    vpp# show interface rx-placement
    Thread 1 (vpp_wk_0):
      node dpdk-input:
        GigabitEthernet7/0/0 queue 0 (polling)
      node vhost-user-input:
        VirtualEthernet0/0/12 queue 0 (polling)
        VirtualEthernet0/0/12 queue 2 (polling)
        VirtualEthernet0/0/13 queue 0 (polling)
        VirtualEthernet0/0/13 queue 2 (polling)
    Thread 2 (vpp_wk_1):
      node dpdk-input:
        GigabitEthernet7/0/1 queue 0 (polling)
      node vhost-user-input:
        VirtualEthernet0/0/12 queue 1 (polling)
        VirtualEthernet0/0/12 queue 3 (polling)
        VirtualEthernet0/0/13 queue 1 (polling)
        VirtualEthernet0/0/13 queue 3 (polling)

Clear Interfaces
================
Clear the statistics for all interfaces (statistics associated with the
'*show interface*' command).

Summary/Usage
-------------

.. code-block:: shell

    clear interfaces

Example
-------
Example of how to clear the statistics for all interfaces:

.. code-block:: console

    vpp# clear interfaces

Set Interface Mac Address
=========================
The '*set interface mac address* ' command allows to set MAC address of
given interface. In case of NIC interfaces the one has to support MAC
address change. A side effect of MAC address change are changes of MAC
addresses in FIB tables (ipv4 and ipv6).


Summary/Usage
-------------

.. code-block:: shell

    set interface mac address <interface> <mac-address>.

Examples
--------

Examples of how to change MAC Address of interface:

.. code-block:: console

    vpp# set interface mac address GigabitEthernet0/8/0 aa:bb:cc:dd:ee:01
    vpp# set interface mac address host-vpp0 aa:bb:cc:dd:ee:02
    vpp# set interface mac address tap-0 aa:bb:cc:dd:ee:03
    vpp# set interface mac address pg0 aa:bb:cc:dd:ee:04

Set Interface Mtu
=================

.. toctree::

Summary/Usage
-------------

.. code-block:: shell

    set interface mtu [packet|ip4|ip6|mpls] <value> <interface>.

Set Interface Promiscuous
=========================

Summary/Usage
-------------

.. code-block:: shell

    set interface promiscuous [on|off] <interface>.

.. _setintstate:

Set Interface State
===================
This command is used to change the admin state (up/down) of an
interface.

If an interface is down, the optional '*punt*' flag can also be set. The
'*punt*' flag implies the interface is disabled for forwarding but punt
all traffic to slow-path. Use the '*enable*' flag to clear '*punt*' flag
(interface is still down).

Summary/Usage
-------------

.. code-block:: shell

    set interface state <interface> [up|down|punt|enable].

Examples
--------

Example of how to configure the admin state of an interface to **up**:

.. code-block:: console

    vpp# set interface state GigabitEthernet2/0/0 up

Example of how to configure the admin state of an interface to **down**:

.. code-block:: console

    vpp# set interface state GigabitEthernet2/0/0 down
