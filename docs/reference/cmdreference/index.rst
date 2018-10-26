.. _cmdreference:


Useful Debug CLI
==================

This is a reference guide for the vpp debug commands that are referenced within these documents. This is **NOT** a complete list. For a complete list refer to the Debug CLI section of the
`Source Code Documents <https://docs.fd.io/vpp/18.07/clicmd.html>`_.

The debug CLI can be executed from a su (superuser) shell using the vppctl command.

.. code-block:: console

    # sudo bash
    # vppctl show interface
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

Commands can also be executed from the vppct shell.

.. code-block:: console

    # vppctl

     __/ __/ _ \  (_)__    | | / / _ \/ _ \
     _/ _// // / / / _ \   | |/ / ___/ ___/
     /_/ /____(_)_/\___/   |___/_/  /_/
    
    vpp# show interface
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

.. toctree::
   :maxdepth: 3

   interface/index.rst
   ip/index.rst
   show/index.rst
   trace/index.rst
   vhost/index.rst