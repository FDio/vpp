.. _nat:

.. toctree::

Network Address Translation
===========================

Skills to be Learned
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Abusing networks namespaces for fun and profit
#. Configuring nat address
#. Configuring nat inside and outside interfaces

FD.io VPP command learned in this exercise
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. `nat44 add interface address
   <https://fd.io/docs/vpp/master/cli-reference/clis/clicmd_src_plugins_nat_nat44-ed.html#nat44-add-interface-address>`__
#. `set interface nat44
   <https://fd.io/docs/vpp/master/cli-reference/clis/clicmd_src_plugins_nat_nat44-ed.html#set-interface-nat44>`__

Topology
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. figure:: /_images/NAT_Topology.jpg
   :alt: NAT Topology

   NAT Topology

Initial state
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Unlike previous exercises, for this one you want to start tabula rasa.

Note: You will lose all your existing config in your FD.io VPP instances!

To clear existing config from previous exercises run:

.. code-block:: console

   ps -ef | grep vpp | awk '{print $2}'| xargs sudo kill
   $ sudo ip link del dev vpp1host
   $ sudo ip link del dev vpp1vpp2

Install vpp-plugins
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

NAT is supported by a plugin, so the respective package needs to be installed

.. code-block:: console

   $ sudo apt-get install vpp-plugin-core

Create FD.io VPP  instance
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create one FD.io VPP instance named vpp1.

Confirm nat44 plugin is present:

.. code-block:: console

    # vppctl -s /run/vpp/cli-vpp1.sock show plugins | egrep nat44
    57. nat44_ei_plugin.so                       24.02-rc0~124-g2ab902f28         IPv4 Endpoint-Independent NAT (NAT44 EI)

Please note that earlier versions if VPP and this document referred to the
``snat`` plugin, which `was renamed <https://www.mail-archive.com/vpp-dev@lists.fd.io/msg03299.html>`__.

Create veth interfaces
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Create a veth interface with one end named ``vpp1outside`` and the other
   named ``vpp1outsidehost``
#. Assign IP address 10.10.1.1/24 to ``vpp1outsidehost``
#. Create a veth interface with one end named ``vpp1inside`` and the other
   named ``vpp1insidehost``
#. Assign IP address 10.10.2.1/24 to ``vpp1insidehost``

Because we'd like to be able to route \*via\* our vpp instance to an
interface on the same host, we are going to put ``vpp1insidehost`` into a
network namespace

Create a new network namespace 'inside'

.. code-block:: console

    $ sudo ip netns add inside

Move interface vpp1inside into the 'inside' namespace:

.. code-block:: console

    $ sudo ip link set dev vpp1insidehost up netns inside

Assign an ip address to ``vpp1insidehost``

.. code-block:: console

    $ sudo ip netns exec inside ip addr add 10.10.2.1/24 dev vpp1insidehost

Create a route inside the ``netns``:

.. code-block:: console

    $ sudo ip netns exec inside ip route add 10.10.1.0/24 via 10.10.2.2

Configure vpp outside interface
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Create a vpp host interface connected to vpp1outside
#. Assign ip address 10.10.1.2/24
#. Create a vpp host interface connected to vpp1inside
#. Assign ip address 10.10.2.2/24

Configure nat44
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Enable the nat44 plugin

.. code-block:: console

   vpp# nat44 plugin enable

Configure nat44 to use the address of host-vpp1outside

.. code-block:: console

   vpp# nat44 add interface address host-vpp1outside

Configure nat44 inside and outside interfaces

.. code-block:: console

   vpp# set interface nat44 in host-vpp1inside out host-vpp1outside

Prepare to Observe NAT
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Observing NAT in this configuration is interesting. To do so, vagrant
ssh a second time into your VM and run:

.. code-block:: console

   $ sudo tcpdump -s 0 -i vpp1outsidehost

Also enable tracing on vpp1

Ping via NAT
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   $ sudo ip netns exec inside ping -c 3 10.10.1.1

Confirm NAT
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Examine the ``tcpdump`` output and vpp1 trace to confirm NAT occurred.
