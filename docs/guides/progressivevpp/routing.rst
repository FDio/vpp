.. _routing:

.. toctree::

Routing
=======

Skills to be Learned
^^^^^^^^^^^^^^^^^^^^

In this exercise you will learn these new skills:

#. Add route to Linux Host routing table
#. Add route to FD.io VPP routing table

And revisit the old ones:

#. Examine FD.io VPP routing table
#. Enable trace on vpp1 and vpp2
#. ping from host to FD.io VPP
#. Examine and clear trace on vpp1 and vpp2
#. ping from FD.io VPP to host
#. Examine and clear trace on vpp1 and vpp2

FD.io VPP command learned in this exercise
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. `ip route
   add <https://docs.fd.io/vpp/17.04/clicmd_src_vnet_ip.html#clicmd_ip_route>`__

Topology
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. figure:: /_images/Connecting_two_vpp_instances_with_memif.png
   :alt: Connect two FD.io VPP topology

   Connect two FD.io VPP topology

Initial State
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The initial state here is presumed to be the final state from the
exercise `Connecting two FD.io VPP
instances <VPP/Progressive_VPP_Tutorial#Connecting_two_vpp_instances>`__

Setup host route
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   $ sudo ip route add 10.10.2.0/24 via 10.10.1.2
   $ ip route
   default via 10.0.2.2 dev enp0s3 
   10.0.2.0/24 dev enp0s3  proto kernel  scope link  src 10.0.2.15 
   10.10.1.0/24 dev vpp1host  proto kernel  scope link  src 10.10.1.1 
   10.10.2.0/24 via 10.10.1.2 dev vpp1host 

Setup return route on vpp2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    vpp# ip route add 10.10.1.0/24  via 10.10.2.1

Ping from host through vpp1 to vpp2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Setup a trace on vpp1 and vpp2
#. Ping 10.10.2.2 from the host
#. Examine the trace on vpp1 and vpp2
#. Clear the trace on vpp1 and vpp2
