.. _hardwarecommands:

.. toctree::

Show Hardware-Interfaces
========================
Display more detailed information about all or a list of given
interfaces. The verboseness of the output can be controlled by the
following optional parameters:

-  brief: Only show name, index and state (default for bonded
   interfaces).
-  verbose: Also display additional attributes (default for all other
   interfaces).
-  detail: Also display all remaining attributes and extended
   statistics.

**To limit the output of the command to bonded interfaces and their
slave interfaces, use the '*bond*' optional parameter.**

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

Example of how to display '*verbose*' data for an interface by name and software index (where 2 is the software index):

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
=========================

Clear the extended statistics for all or a list of given interfaces
(statistics associated with the '*show hardware-interfaces*' command).


Summary/Usage
-------------

.. code-block:: shell

    clear hardware-interfaces [<interface> [<interface> [..]]] [<sw_idx> [<sw_idx> [..]]].
                

Examples
--------

Example of how to clear the extended statistics for all interfaces:


.. code-block:: console

        vpp# clear hardware-interfaces

Example of how to clear the extended statistics for an interface by name and software index (where 2 is the software index): 

.. code-block:: console

        vpp# clear hardware-interfaces GigabitEthernet7/0/0 2


