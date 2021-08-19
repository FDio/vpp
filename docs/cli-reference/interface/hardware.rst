.. _interface:

.. toctree::

Hardware-Interfaces Commands
============================
This section contains those interface commands that are related to hardware-interfaces: 


* `Show Bridge-Domain`_
* `Show Hardware-Interfaces`_
* `Clear Hardware-Interfaces`_

.. note:: For a complete list of CLI Debug commands refer to the Debug CLI section of the `Source Code Documents <https://docs.fd.io/vpp/18.07/clicmd.html>`_ .

Show Bridge-Domain
+++++++++++++++++++

Summary/Usage
-------------

show bridge-domain [*bridge-domain-id* [detail|int|arp| *bd-tag* ]]

Description
-----------

Show a summary of all the bridge-domain instances or detailed view of a single bridge-domain.
Bridge-domains are created by adding an interface to a bridge using the **set interface l2 bridge** command.

Example Usage
-------------
.. code-block:: console

    Example of displaying all bridge-domains:

    vpp# show bridge-domain

     ID   Index   Learning   U-Forwrd   UU-Flood   Flooding   ARP-Term     BVI-Intf
     0      0        off        off        off        off        off        local0
    200     1        on         on         on         on         off          N/A

    Example of displaying details of a single bridge-domains:

    vpp# show bridge-domain 200 detail

     ID   Index   Learning   U-Forwrd   UU-Flood   Flooding   ARP-Term     BVI-Intf
    200     1        on         on         on         on         off          N/A

             Interface           Index  SHG  BVI        VLAN-Tag-Rewrite
     GigabitEthernet0/8/0.200      3     0    -               none
     GigabitEthernet0/9/0.200      4     0    -               none

Declaration and Implementation
------------------------------

**Declaration:** bd_show_cli (src/vnet/l2/l2_bd.c line 1151)

**Implementation:** bd_show

Show Hardware-Interfaces
+++++++++++++++++++++++++
Display more detailed information about all or a list of given
interfaces. The verboseness of the output can be controlled by the
following optional parameters:

-  **brief**: Only show name, index and state (default for bonded
   interfaces).
-  **verbose**: Also display additional attributes (default for all other
   interfaces).
-  **detail**: Also display all remaining attributes and extended
   statistics.

.. note:: 
	To limit the output of the command to bonded interfaces and their
	slave interfaces, use the '*bond*' optional parameter.

Summary/Usage
-------------

.. code-block:: shell

    show hardware-interfaces [brief|verbose|detail] [bond] [<interface> [<interface> [..]]] [<sw_idx> [<sw_idx> [..]]].

Examples
--------
Example of how to display default data for all interfaces:

.. code-block:: console

    vpp# show hardware-interfaces
                  Name                Idx   Link  Hardware
    GigabitEthernet7/0/0               1     up   GigabitEthernet7/0/0
      Ethernet address ec:f4:bb:c0:bc:fc
      Intel e1000
        carrier up full duplex speed 1000 mtu 9216
        rx queues 1, rx desc 1024, tx queues 3, tx desc 1024
        cpu socket 0
    GigabitEthernet7/0/1               2     up   GigabitEthernet7/0/1
      Ethernet address ec:f4:bb:c0:bc:fd
      Intel e1000
        carrier up full duplex speed 1000 mtu 9216
        rx queues 1, rx desc 1024, tx queues 3, tx desc 1024
        cpu socket 0
    VirtualEthernet0/0/0               3     up   VirtualEthernet0/0/0
      Ethernet address 02:fe:a5:a9:8b:8e
    VirtualEthernet0/0/1               4     up   VirtualEthernet0/0/1
      Ethernet address 02:fe:c0:4e:3b:b0
    VirtualEthernet0/0/2               5     up   VirtualEthernet0/0/2
      Ethernet address 02:fe:1f:73:92:81
    VirtualEthernet0/0/3               6     up   VirtualEthernet0/0/3
      Ethernet address 02:fe:f2:25:c4:68
    local0                             0    down  local0
      local

Example of how to display *verbose* data for an interface by name and software index
(where 2 is the software index):

.. code-block:: console

    vpp# show hardware-interfaces GigabitEthernet7/0/0 2 verbose
                   Name                Idx   Link  Hardware
    GigabitEthernet7/0/0               1     up   GigabitEthernet7/0/0
      Ethernet address ec:f4:bb:c0:bc:fc
      Intel e1000
        carrier up full duplex speed 1000 mtu 9216
        rx queues 1, rx desc 1024, tx queues 3, tx desc 1024
        cpu socket 0
    GigabitEthernet7/0/1               2    down  GigabitEthernet7/0/1
      Ethernet address ec:f4:bb:c0:bc:fd
      Intel e1000
        carrier up full duplex speed 1000 mtu 9216
        rx queues 1, rx desc 1024, tx queues 3, tx desc 1024
        cpu socket 0

Clear Hardware-Interfaces
+++++++++++++++++++++++++

Clear the extended statistics for all or a list of given interfaces
(statistics associated with the **show hardware-interfaces** command).


Summary/Usage
-------------

.. code-block:: shell

    clear hardware-interfaces [<interface> [<interface> [..]]] [<sw_idx> [<sw_idx> [..]]].
                

Examples
--------

Example of how to clear the extended statistics for all interfaces:


.. code-block:: console

        vpp# clear hardware-interfaces

Example of how to clear the extended statistics for an interface by name and software index
(where 2 is the software index): 

.. code-block:: console

        vpp# clear hardware-interfaces GigabitEthernet7/0/0 2


