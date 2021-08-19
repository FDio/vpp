.. _interface:

.. toctree::

Basic Interface Commands
=========================

There are several commands that are associated to Basic Interface:

* `Show Interface`_
* `Clear Interfaces`_

.. note:: For a complete list of CLI Debug commands refer to the Debug CLI section of the `Source Code Documents <https://docs.fd.io/vpp/18.07/clicmd.html>`_ .

.. _showintcommand:

Show Interface
++++++++++++++++
Shows software interface information including counters and features.

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
+++++++++++++++++
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
