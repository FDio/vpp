.. _twovppinstances:

.. toctree::

Connecting Two FD.io VPP Instances
==================================

.. _background-1:

memif is a very high performance, direct memory interface type which can
be used between FD.io VPP instances. It uses a file socket for a control channel
to set up shared memory.

.. _skills-to-be-learned-1:

Skills to be Learned
---------------------

You will learn the following new skill in this exercise:

#. Create a memif interface between two FD.io VPP instances

You should be able to perform this exercise with the following skills
learned in previous exercises:

#. Run a second FD.io VPP instance
#. Add an ip address to a FD.io VPP interface
#. Ping from FD.io VPP

.. _topology-1:

Topology
---------

.. figure:: /_images/Connecting_two_vpp_instances_with_memif.png
   :alt: Connect two FD.io VPP topology

   Connect two FD.io VPP topology

.. _initial-state-1:

Initial state
--------------

The initial state here is presumed to be the final state from the
exercise `Create an
Interface <VPP/Progressive_VPP_Tutorial#Exercise:_Create_an_Interface>`__

.. _action-running-a-second-vpp-instances-1:

Running a second FD.io VPP instances
-------------------------------------

You should already have a FD.io VPP instance running named: vpp1.

Run a second FD.io VPP instance named: vpp2.

.. code-block:: console

    $ sudo /usr/bin/vpp -c startup2.conf
    ....
    $ sudo vppctl -s /run/vpp/cli-vpp2.sock
        _______    _        _   _____  ___
     __/ __/ _ \  (_)__    | | / / _ \/ _ \
     _/ _// // / / / _ \   | |/ / ___/ ___/
     /_/ /____(_)_/\___/   |___/_/  /_/
    
    vpp# show version
    vpp v18.07-release built by root on c469eba2a593 at Mon Jul 30 23:27:03 UTC 2018
    vpp# quit

.. _action-create-memif-interface-on-vpp1-1:

Create memif interface on vpp1
-------------------------------

Create a memif interface on vpp1. To connect to the instance vpp1 use the
socket **/run/vpp/cli-vpp1.sock**

.. code-block:: console

   $ sudo vppctl -s /run/vpp/cli-vpp1.sock
   vpp# create interface memif id 0 master

This will create an interface on vpp1 memif0/0 using /run/vpp/memif as
its socket file. The role of vpp1 for this memif interface is 'master'.

With what you have learned:

#. Set the memif0/0 state to up.
#. Assign IP address 10.10.2.1/24 to memif0/0
#. Examine memif0/0 via show commands

.. _action-create-memif-interface-on-vpp2-1:

Create memif interface on vpp2
--------------------------------

We want vpp2 to pick up the 'slave' role using the same
run/vpp/memif-vpp1vpp2 socket file

.. code-block:: console

   vpp# create interface memif id 0 slave

This will create an interface on vpp2 memif0/0 using /run/vpp/memif as
its socket file. The role of vpp1 for this memif interface is 'slave'.

Use your previously used skills to:

#. Set the memif0/0 state to up.
#. Assign IP address 10.10.2.2/24 to memif0/0
#. Examine memif0/0 via show commands

.. _action-ping-from-vpp1-to-vpp2-1:

Ping from vpp1 to vpp2
------------------------

Ping 10.10.2.2 from vpp1

.. code-block:: console

    $ ping 10.10.2.2 

Ping 10.10.2.1 from vpp2

.. code-block:: console

    $ ping 10.10.2.1
