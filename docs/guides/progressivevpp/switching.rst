.. _switching:

.. toctree::

Switching
=========

Skills to be Learned
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Associate an interface with a bridge domain
#. Create a loopback interaface
#. Create a BVI (Bridge Virtual Interface) for a bridge domain
#. Examine a bridge domain

FD.io VPP command learned in this exercise
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. `show
   bridge <https://docs.fd.io/vpp/17.04/clicmd_src_vnet_l2.html#clicmd_show_bridge-domain>`__
#. `show bridge
   detail <https://docs.fd.io/vpp/17.04/clicmd_src_vnet_l2.html#clicmd_show_bridge-domain>`__
#. `set int l2
   bridge <https://docs.fd.io/vpp/17.04/clicmd_src_vnet_l2.html#clicmd_set_interface_l2_bridge>`__
#. `show l2fib
   verbose <https://docs.fd.io/vpp/17.04/clicmd_src_vnet_l2.html#clicmd_show_l2fib>`__

Topology
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. figure:: /_images/Switching_Topology.jpg
   :alt: Switching Topology

   Switching Topology

Initial state
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Unlike previous exercises, for this one you want to start tabula rasa.

Note: You will lose all your existing config in your FD.io VPP instances!

To clear existing config from previous exercises run:

.. code-block:: console

   $ ps -ef | grep vpp | awk '{print $2}'| xargs sudo kill
   $ sudo ip link del dev vpp1host
   $ sudo ip link del dev vpp1vpp2

Run FD.io VPP instances
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Run a vpp instance named **vpp1**
#. Run a vpp instance named **vpp2**

Connect vpp1 to host
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Create a veth with one end named vpp1host and the other named
   vpp1out.
#. Connect vpp1out to vpp1
#. Add ip address 10.10.1.1/24 on vpp1host

Connect vpp1 to vpp2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Create a veth with one end named vpp1vpp2 and the other named
   vpp2vpp1.
#. Connect vpp1vpp2 to vpp1.
#. Connect vpp2vpp1 to vpp2.

Configure Bridge Domain on vpp1
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check to see what bridge domains already exist, and select the first
bridge domain number not in use:

.. code-block:: console

   vpp# show bridge-domain
    ID   Index   Learning   U-Forwrd   UU-Flood   Flooding   ARP-Term     BVI-Intf   
    0      0        off        off        off        off        off        local0    

In the example above, there is bridge domain ID '0' already. Even though
sometimes we might get feedback as below:

.. code-block:: console

   no bridge-domains in use

the bridge domain ID '0' still exists, where no operations are
supported. For instance, if we try to add host-vpp1out and host-vpp1vpp2
to bridge domain ID 0, we will get nothing setup.

.. code-block:: console

   vpp# set int l2 bridge host-vpp1out 0
   vpp# set int l2 bridge host-vpp1vpp2 0
   vpp# show bridge-domain 0 detail
   show bridge-domain: No operations on the default bridge domain are supported

So we will create bridge domain 1 instead of playing with the default
bridge domain ID 0.

Add host-vpp1out to bridge domain ID 1

.. code-block:: console

   vpp# set int l2 bridge host-vpp1out 1

Add host-vpp1vpp2 to bridge domain ID1

.. code-block:: console

   vpp# set int l2 bridge host-vpp1vpp2  1

Examine bridge domain 1:

.. code-block:: console

    vpp# show bridge-domain 1 detail
    BD-ID   Index   BSN  Age(min)  Learning  U-Forwrd  UU-Flood  Flooding  ARP-Term  BVI-Intf
    1       1      0     off        on        on        on        on       off       N/A

            Interface           If-idx ISN  SHG  BVI  TxFlood        VLAN-Tag-Rewrite
        host-vpp1out            1     1    0    -      *                 none
        host-vpp1vpp2           2     1    0    -      *                 none

Configure loopback interface on vpp2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    vpp# create loopback interface
    loop0

Add the ip address 10.10.1.2/24 to vpp2 interface loop0. Set the state
of interface loop0 on vpp2 to 'up'

Configure bridge domain on vpp2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check to see the first available bridge domain ID (it will be 1 in this
case)

Add interface loop0 as a bridge virtual interface (bvi) to bridge domain
1

.. code-block:: console

   vpp# set int l2 bridge loop0 1 bvi

Add interface vpp2vpp1 to bridge domain 1

.. code-block:: console

   vpp# set int l2 bridge host-vpp2vpp1  1

Examine the bridge domain and interfaces.

Ping from host to vpp and vpp to host
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Add trace on vpp1 and vpp2
#. ping from host to 10.10.1.2
#. Examine and clear trace on vpp1 and vpp2
#. ping from vpp2 to 10.10.1.1
#. Examine and clear trace on vpp1 and vpp2

Examine l2 fib
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    vpp# show l2fib verbose
    Mac Address     BD Idx           Interface           Index  static  filter  bvi   Mac Age (min) 
    de:ad:00:00:00:00    1            host-vpp1vpp2           2       0       0     0      disabled    
    c2:f6:88:31:7b:8e    1            host-vpp1out            1       0       0     0      disabled    
    2 l2fib entries

.. code-block:: console

    vpp# show l2fib verbose
    Mac Address     BD Idx           Interface           Index  static  filter  bvi   Mac Age (min) 
    de:ad:00:00:00:00    1                loop0               2       1       0     1      disabled    
    c2:f6:88:31:7b:8e    1            host-vpp2vpp1           1       0       0     0      disabled    
    2 l2fib entries
