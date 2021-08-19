.. _interface:

.. toctree::

Set Interface Commands
=======================
This section covers those commands that are related to setting an interface:

* `Set Interface`_
* `Set Interface IP Address`_
* `Set Interface L2 Bridge`_
* `Set Interface MTU`_
* `Set Interface Promiscuous`_
* `Set Interface State`_

.. note:: For a complete list of CLI Debug commands refer to the Debug CLI section of the `Source Code Documents <https://docs.fd.io/vpp/18.07/clicmd.html>`_ .

Set Interface
++++++++++++++++

Summary/Usage
-------------

Interface commands.

Declaration and Implementation
-------------------------------

**Declaration:** vnet_cli_set_interface_command (src/vnet/interface_cli.c line 484)

Set Interface IP Address
+++++++++++++++++++++++++

Summary/Usage
-------------

set interface ip address [del] <*interface*> <*ip-addr*>/<*mask*> | [all]

Description
-------------

Add an IP Address to an interface or remove and IP Address from an interface. 
The IP Address can be an IPv4 or an IPv6 address. Interfaces may have multiple IPv4 and IPv6
addresses. There is no concept of primary vs. secondary interface addresses; they're just addresses.

To display the addresses associated with a given interface, use the command **show interface address** <*interface*>.

.. note:: 
	The debug CLI does not enforce classful mask-width / addressing constraints.

Example Usage
--------------

An example of how to add an IPv4 address to an interface:

.. code-block:: console

	vpp# set interface ip address GigabitEthernet2/0/0 172.16.2.12/24

An example of how to add an IPv6 address to an interface:

.. code-block:: console

	vpp# set interface ip address GigabitEthernet2/0/0 ::a:1:1:0:7/126

To delete a specific interface ip address:

.. code-block:: console

	vpp# set interface ip address GigabitEthernet2/0/0 172.16.2.12/24 del

To delete all interfaces addresses (IPv4 and IPv6):

.. code-block:: console

	vpp# set interface ip address GigabitEthernet2/0/0 del all

Declaration and Implementation
-------------------------------

**Declaration:** set_interface_ip_address_command (src/vnet/ip/ip46_cli.c line 216)

**Implementation:** add_del_ip_address


Set Interface L2 Bridge	
+++++++++++++++++++++++++

Summary/Usage
-------------

set interface l2 bridge <*interface*> <*bridge-domain-id*> [bvi|uu-fwd] [shg]

Description
-------------

Use this command put an interface into Layer 2 bridge domain. If a bridge-domain with the provided
bridge-domain-id does not exist, it will be created. Interfaces in a bridge-domain forward packets
to other interfaces in the same bridge-domain based on destination mac address. To remove an interface
from a the Layer 2 bridge domain, put the interface in a different mode, for example Layer 3 mode.

Optionally, an interface can be added to a Layer 2 bridge-domain as a Bridged Virtual Interface (bvi).
Only one interface in a Layer 2 bridge-domain can be a bvi.

Optionally, a split-horizon group can also be specified. This defaults to 0 if not specified.

Example Usage
--------------
Example of how to configure a Layer 2 bridge-domain with three interfaces (where 200 is the bridge-domain-id):

.. code-block:: console

	vpp# set interface l2 bridge GigabitEthernet0/8/0.200 200

This interface is added a BVI interface:

.. code-block:: console

	vpp# set interface l2 bridge GigabitEthernet0/9/0.200 200 bvi

This interface also has a split-horizon group of 1 specified:

.. code-block:: console

	vpp# set interface l2 bridge GigabitEthernet0/a/0.200 200 1

Example of how to remove an interface from a Layer2 bridge-domain:

.. code-block:: console

	vpp# set interface l3 GigabitEthernet0/a/0.200

Declaration and Implementation
-------------------------------

**Declaration:** int_l2_bridge_cli (src/vnet/l2/l2_input.c line 949)

**Implementation:** int_l2_bridge

Set Interface MTU
++++++++++++++++++

Summary/Usage
-------------

.. code-block:: shell

    set interface mtu [packet|ip4|ip6|mpls] <value> <interface>

Set Interface Promiscuous
++++++++++++++++++++++++++

Summary/Usage
-------------

.. code-block:: shell

    set interface promiscuous [on|off] <interface>.

.. _setintstate:

Set Interface State
++++++++++++++++++++
This command is used to change the admin state (up/down) of an
interface.

If an interface is down, the optional *punt* flag can also be set. The
*punt* flag implies the interface is disabled for forwarding but punt
all traffic to slow-path. Use the *enable* flag to clear *punt* flag
(interface is still down).

Summary/Usage
-------------

.. code-block:: shell

    set interface state <interface> [up|down|punt|enable].

Example Usage
----------------

Example of how to configure the admin state of an interface to **up**:

.. code-block:: console

    vpp# set interface state GigabitEthernet2/0/0 up

Example of how to configure the admin state of an interface to **down**:

.. code-block:: console

    vpp# set interface state GigabitEthernet2/0/0 down

