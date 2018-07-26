.. _vagrant:

.. toctree::

.. _introduction-to-vpp-vagrant:

Introduction
---------------

This tutorial is designed for you to be able to run it on a single Ubuntu 16.04 VM on your laptop.
It walks you through some very basic vpp senarios, with a focus on learning vpp commands, doing common actions,
and being able to discover common things about the state of a running vpp.

This is *not* intended to be a 'how to run in a production environment' set of instructions.

Exercise: Setting up your environment
-------------------------------------

All of these exercises are designed to be performed on an Ubuntu 16.04 (Xenial) box.

If you have an Ubuntu 16.04 box on which you have sudo, you can feel free to use that.

If you do not, a Vagrantfile is provided to setup a basic Ubuntu 16.04 box for you

.. _vagrant-set-up:

Vagrant Set Up
--------------

Action: Install Virtualbox
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you do not already have virtualbox on your laptop (or if it is not up to date), please download and install it:

https://www.virtualbox.org/wiki/Downloads

Action: Install Vagrant
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you do not already have Vagrant on your laptop (or if it is not up to date), please download it:

https://www.vagrantup.com/downloads.html

Action: Create a Vagrant Directory
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Create a directory on your laptop

.. code-block:: console

    mkdir fdio-tutorial
    cd fdio-tutorial/

.. _create-vagrant-file:

Create a Vagrantfile
^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    # -*- mode: ruby -*-
    # vi: set ft=ruby :

    Vagrant.configure(2) do |config|

    config.vm.box = "puppetlabs/ubuntu-16.04-64-nocm"
    config.vm.box_check_update = false

    vmcpu=(ENV['VPP_VAGRANT_VMCPU'] || 2)
    vmram=(ENV['VPP_VAGRANT_VMRAM'] || 4096)

    config.ssh.forward_agent = true

    config.vm.provider "virtualbox" do |vb|
        vb.customize ["modifyvm", :id, "--ioapic", "on"]
        vb.memory = "#{vmram}"
        vb.cpus = "#{vmcpu}"
        #support for the SSE4.x instruction is required in some versions of VB.
        vb.customize ["setextradata", :id, "VBoxInternal/CPUM/SSE4.1", "1"]
        vb.customize ["setextradata", :id, "VBoxInternal/CPUM/SSE4.2", "1"]
    end
    end

Action: Vagrant Up
^^^^^^^^^^^^^^^^^^

Bring up your Vagrant VM:

.. code-block:: console

    vagrant up


Action: ssh to Vagrant VM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    vagrant ssh

Exercise: Install VPP
---------------------
**Skills to be Learned**

    * Learn how to install vpp binary packges using apt-get.

Follow the instructions at :ref:`Installing VPP Binaries <install_vpp>` for installing xenial vpp packages from the release repo.  Please note, certain aspects of this tutorial require vpp 17.10 or later.

Exercise: VPP basics
---------------------
**Skills to be Learned**

By the end of the exercise you should be able to:

* Run a vpp instance in a mode which allows multiple vpp processes to run
* Issue vpp commands from the unix shell
* Run a vpp shell and issue it commands


VPP command learned in this exercise
--------------------------------------

* `show ver <https://docs.fd.io/vpp/17.04/clicmd_src_vpp_app.html#clicmd_show_version>`_

Action: Remove dpdk plugin 
--------------------------
In this tutorial, we will be running multiple vpp instances.  DPDK does not work well with multiple instances, and so to run multiple instances we will need to disable the dpdk-plugin by removing it:

.. code-block:: console
    
    sudo rm -rf /usr/lib/vpp_plugins/dpdk_plugin.so

..how-to-run-vpp:

Action: Run VPP
-----------------

VPP runs in userspace.  In a production environment you will often run it with DPDK to connect to real NICs or vhost to connect to VMs.
In those circumstances you usually run a single instance of vpp.

For purposes of this tutorial, it is going to be extremely useful to run multiple instances of vpp, and connect them to each other to form
a topology.  Fortunately, vpp supports this.

When running multiple vpp instances, each instance needs to have specified a 'name' or 'prefix'.  In the example below, the 'name' or 'prefix' is "vpp1". Note that only one instance can use the dpdk plugin, since this plugin is trying to acquire a lock on a file.

.. code-block:: console
   
    sudo vpp unix {cli-listen /run/vpp/cli-vpp1.sock} api-segment { prefix vpp1 }

**Example Output:**

.. code-block:: console
   
    vlib_plugin_early_init:230: plugin path /usr/lib/vpp_plugins

Please note:

* "api-segment {prefix vpp1}" tells vpp how to name the files in /dev/shm/ for your vpp instance differently from the default.  
* "unix {cli-listen /run/vpp/cli-vpp1.sock}" tells vpp to use a non-default socket file when being addressed by vppctl.

If you can't see the vpp process running on the host, activate the nodaemon option to better understand what is happening

.. code-block:: console
    
    sudo vpp unix {nodaemon cli-listen /run/vpp/cli-vpp1.sock} api-segment { prefix vpp1 }

**Example Output with errors from the dpdk plugin:**

.. code-block:: console

    vlib_plugin_early_init:356: plugin path /usr/lib/vpp_plugins
    load_one_plugin:184: Loaded plugin: acl_plugin.so (Access Control Lists)
    load_one_plugin:184: Loaded plugin: dpdk_plugin.so (Data Plane Development Kit (DPDK))
    load_one_plugin:184: Loaded plugin: flowprobe_plugin.so (Flow per Packet)
    load_one_plugin:184: Loaded plugin: gtpu_plugin.so (GTPv1-U)
    load_one_plugin:184: Loaded plugin: ila_plugin.so (Identifier-locator addressing for IPv6)
    load_one_plugin:184: Loaded plugin: ioam_plugin.so (Inbound OAM)
    load_one_plugin:114: Plugin disabled (default): ixge_plugin.so
    load_one_plugin:184: Loaded plugin: kubeproxy_plugin.so (kube-proxy data plane)
    load_one_plugin:184: Loaded plugin: l2e_plugin.so (L2 Emulation)
    load_one_plugin:184: Loaded plugin: lb_plugin.so (Load Balancer)
    load_one_plugin:184: Loaded plugin: libsixrd_plugin.so (IPv6 Rapid Deployment on IPv4 Infrastructure (RFC5969))
    load_one_plugin:184: Loaded plugin: memif_plugin.so (Packet Memory Interface (experimetal))
    load_one_plugin:184: Loaded plugin: nat_plugin.so (Network Address Translation)
    load_one_plugin:184: Loaded plugin: pppoe_plugin.so (PPPoE)
    load_one_plugin:184: Loaded plugin: stn_plugin.so (VPP Steals the NIC for Container integration)
    vpp[10211]: vlib_pci_bind_to_uio: Skipping PCI device 0000:00:03.0 as host interface eth0 is up
    vpp[10211]: vlib_pci_bind_to_uio: Skipping PCI device 0000:00:04.0 as host interface eth1 is up
    vpp[10211]: dpdk_config:1240: EAL init args: -c 1 -n 4 --huge-dir /run/vpp/hugepages --file-prefix vpp -b 0000:00:03.0 -b 0000:00:04.0 --master-lcore 0 --socket-mem 64
    EAL: No free hugepages reported in hugepages-1048576kB
    EAL: Error - exiting with code: 1
    Cause: Cannot create lock on '/var/run/.vpp_config'. Is another primary process running?

Action: Send commands to VPP using vppctl
---------------------------------------------------------------

You can send vpp commands with a utility called *vppctl*.

When running vppctl against a named version of vpp, you will need to run:

.. code-block:: console
   
    sudo vppctl -s /run/vpp/cli-${name}.sock ${cmd}

**Note** 

.. code-block:: console
    
    /run/vpp/cli-${name}.sock

is the particular naming convention used in this tutorial.  By default you can set vpp to use what ever socket file name you would like at startup (the default config file uses /run/vpp/cli.sock) if two different vpps are being run (as in this tutorial) you must use distinct socket files for each one.

So to run 'show ver' against the vpp instance named vpp1 you would run:

.. code-block:: console

    sudo vppctl -s /run/vpp/cli-vpp1.sock show ver

**Output:**

.. code-block:: console
    
    vpp v17.04-rc0~177-g006eb47 built by ubuntu on fdio-ubuntu1604-sevt at Mon Jan 30 18:30:12 UTC 2017

Action: Start a VPP shell using vppctl
---------------------------------------------------------------
You can also use vppctl to launch a vpp shell with which you can run multiple vpp commands interactively by running:

.. code-block:: console
    
    sudo vppctl -s /run/vpp/cli-${name}.sock

which will give you a command prompt.

Try doing show ver that way:

.. code-block:: console

    sudo vppctl -s /run/vpp/cli-vpp1.sock
    vpp# show ver

Output:

.. code-block:: console

    vpp v17.04-rc0~177-g006eb47 built by ubuntu on fdio-ubuntu1604-sevt at Mon Jan 30 18:30:12 UTC 2017

    vpp#

To exit the vppctl shell:

.. code-block:: console

    vpp# quit

Exercise: Create an interface
-----------------------------

Skills to be Learned
^^^^^^^^^^^^^^^^^^^^

#. Create a veth interface in Linux host
#. Assign an IP address to one end of the veth interface in the Linux host
#. Create a vpp host-interface that connected to one end of a veth interface via AF_PACKET
#. Add an ip address to a vpp interface
#. Setup a 'trace'
#. View a 'trace'
#. Clear a 'trace'
#. Verify using ping from host
#. Ping from vpp
#. Examine Arp Table
#. Examine ip fib

VPP command learned in this exercise
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#. `create host-interface <https://docs.fd.io/vpp/17.04/clicmd_src_vnet_devices_af_packet.html#clicmd_create_host-interface>`_
#. `set int state <https://docs.fd.io/vpp/17.04/clicmd_src_vnet.html#clicmd_set_interface_state>`_
#. `set int ip address <https://docs.fd.io/vpp/17.04/clicmd_src_vnet_ip.html#clicmd_set_interface_ip_address>`_
#. `show hardware <https://docs.fd.io/vpp/17.04/clicmd_src_vnet.html#clicmd_show_hardware-interfaces>`_
#. `show int <https://docs.fd.io/vpp/17.04/clicmd_src_vnet.html#clicmd_show_interfaces>`_
#. `show int addr <https://docs.fd.io/vpp/17.04/clicmd_src_vnet.html#clicmd_show_interfaces>`_
#. `trace add <https://docs.fd.io/vpp/17.04/clicmd_src_vlib.html#clicmd_trace_add>`_
#. `clear trace <https://docs.fd.io/vpp/17.04/clicmd_src_vlib.html#clicmd_clear_trace>`_
#. `ping <https://docs.fd.io/vpp/17.04/clicmd_src_vnet_ip.html#clicmd_ping>`_
#. `show ip arp <https://docs.fd.io/vpp/17.04/clicmd_src_vnet_ethernet.html#clicmd_show_ip_arp>`_
#. `show ip fib <https://docs.fd.io/vpp/17.04/clicmd_src_vnet_fib.html#clicmd_show_ip_fib>`_

Topology
~~~~~~~~

.. figure:: /_images/Create_Interface_Topology.jpg
  :alt: Figure: Create Interface Topology

  Figure: Create Interface Topology

Initial State
~~~~~~~~~~~~~

The initial state here is presumed to be the final state from the
exercise `VPP Basics <VPP/Progressive_VPP_Tutorial#Exercise:_vpp_basics>`__
 
Action: Create veth interfaces on host
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In Linux, there is a type of interface call 'veth'. Think of a 'veth'
interface as being an interface that has two ends to it (rather than
one).

Create a veth interface with one end named **vpp1out** and the other
named **vpp1host**

::

   sudo ip link add name vpp1out type veth peer name vpp1host

Turn up both ends:

::

   sudo ip link set dev vpp1out up
   sudo ip link set dev vpp1host up

Assign an IP address

::

   sudo ip addr add 10.10.1.1/24 dev vpp1host

Display the result:

::

   sudo ip addr show vpp1host

Example Output:

::

   10: vpp1host@vpp1out: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
       link/ether 5e:97:e3:41:aa:b8 brd ff:ff:ff:ff:ff:ff
       inet 10.10.1.1/24 scope global vpp1host
          valid_lft forever preferred_lft forever
       inet6 fe80::5c97:e3ff:fe41:aab8/64 scope link 
          valid_lft forever preferred_lft forever

Action: Create vpp host- interface
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a host interface attached to **vpp1out**.

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock create host-interface name vpp1out

Output:

::

   host-vpp1out

Confirm the interface:

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock show hardware

Example Output:

::

                 Name                Idx   Link  Hardware
   host-vpp1out                       1     up   host-vpp1out
     Ethernet address 02:fe:48:ec:d5:a7
     Linux PACKET socket interface
   local0                             0    down  local0
     local

Turn up the interface:

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock set int state host-vpp1out up

Confirm the interface is up:

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock show int

::

                 Name               Idx       State          Counter          Count     
   host-vpp1out                      1         up       
   local0                            0        down

Assign ip address 10.10.1.2/24

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock set int ip address host-vpp1out 10.10.1.2/24

Confirm the ip address is assigned:

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock show int addr

::

   host-vpp1out (up):
     10.10.1.2/24
   local0 (dn):

Action: Add trace
~~~~~~~~~~~~~~~~~

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock trace add af-packet-input 10

Action: Ping from host to vpp
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   ping -c 1 10.10.1.2

::

   PING 10.10.1.2 (10.10.1.2) 56(84) bytes of data.
   64 bytes from 10.10.1.2: icmp_seq=1 ttl=64 time=0.557 ms

   --- 10.10.1.2 ping statistics ---
   1 packets transmitted, 1 received, 0% packet loss, time 0ms
   rtt min/avg/max/mdev = 0.557/0.557/0.557/0.000 ms

Action: Examine Trace of ping from host to vpp
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock show trace

::

   ------------------- Start of thread 0 vpp_main -------------------
   Packet 1

   00:09:30:397798: af-packet-input
     af_packet: hw_if_index 1 next-index 4
       tpacket2_hdr:
         status 0x20000001 len 42 snaplen 42 mac 66 net 80
         sec 0x588fd3ac nsec 0x375abde7 vlan 0 vlan_tpid 0
   00:09:30:397906: ethernet-input
     ARP: fa:13:55:ac:d9:50 -> ff:ff:ff:ff:ff:ff
   00:09:30:397912: arp-input
     request, type ethernet/IP4, address size 6/4
     fa:13:55:ac:d9:50/10.10.1.1 -> 00:00:00:00:00:00/10.10.1.2
   00:09:30:398191: host-vpp1out-output
     host-vpp1out
     ARP: 02:fe:48:ec:d5:a7 -> fa:13:55:ac:d9:50
     reply, type ethernet/IP4, address size 6/4
     02:fe:48:ec:d5:a7/10.10.1.2 -> fa:13:55:ac:d9:50/10.10.1.1

   Packet 2

   00:09:30:398227: af-packet-input
     af_packet: hw_if_index 1 next-index 4
       tpacket2_hdr:
         status 0x20000001 len 98 snaplen 98 mac 66 net 80
         sec 0x588fd3ac nsec 0x37615060 vlan 0 vlan_tpid 0
   00:09:30:398295: ethernet-input
     IP4: fa:13:55:ac:d9:50 -> 02:fe:48:ec:d5:a7
   00:09:30:398298: ip4-input
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x9b46
       fragment id 0x894c, flags DONT_FRAGMENT
     ICMP echo_request checksum 0x83c
   00:09:30:398300: ip4-lookup
     fib 0 dpo-idx 5 flow hash: 0x00000000
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x9b46
       fragment id 0x894c, flags DONT_FRAGMENT
     ICMP echo_request checksum 0x83c
   00:09:30:398303: ip4-local
       ICMP: 10.10.1.1 -> 10.10.1.2
         tos 0x00, ttl 64, length 84, checksum 0x9b46
         fragment id 0x894c, flags DONT_FRAGMENT
       ICMP echo_request checksum 0x83c
   00:09:30:398305: ip4-icmp-input
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x9b46
       fragment id 0x894c, flags DONT_FRAGMENT
     ICMP echo_request checksum 0x83c
   00:09:30:398307: ip4-icmp-echo-request
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x9b46
       fragment id 0x894c, flags DONT_FRAGMENT
     ICMP echo_request checksum 0x83c
   00:09:30:398317: ip4-load-balance
     fib 0 dpo-idx 10 flow hash: 0x0000000e
     ICMP: 10.10.1.2 -> 10.10.1.1
       tos 0x00, ttl 64, length 84, checksum 0xbef3
       fragment id 0x659f, flags DONT_FRAGMENT
     ICMP echo_reply checksum 0x103c
   00:09:30:398318: ip4-rewrite
     tx_sw_if_index 1 dpo-idx 2 : ipv4 via 10.10.1.1 host-vpp1out: IP4: 02:fe:48:ec:d5:a7 -> fa:13:55:ac:d9:50 flow hash: 0x00000000
     IP4: 02:fe:48:ec:d5:a7 -> fa:13:55:ac:d9:50
     ICMP: 10.10.1.2 -> 10.10.1.1
       tos 0x00, ttl 64, length 84, checksum 0xbef3
       fragment id 0x659f, flags DONT_FRAGMENT
     ICMP echo_reply checksum 0x103c
   00:09:30:398320: host-vpp1out-output
     host-vpp1out
     IP4: 02:fe:48:ec:d5:a7 -> fa:13:55:ac:d9:50
     ICMP: 10.10.1.2 -> 10.10.1.1
       tos 0x00, ttl 64, length 84, checksum 0xbef3
       fragment id 0x659f, flags DONT_FRAGMENT
     ICMP echo_reply checksum 0x103c

Action: Clear trace buffer
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock clear  trace

Action: ping from vpp to host
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock ping 10.10.1.1

::

   64 bytes from 10.10.1.1: icmp_seq=1 ttl=64 time=.0865 ms
   64 bytes from 10.10.1.1: icmp_seq=2 ttl=64 time=.0914 ms
   64 bytes from 10.10.1.1: icmp_seq=3 ttl=64 time=.0943 ms
   64 bytes from 10.10.1.1: icmp_seq=4 ttl=64 time=.0959 ms
   64 bytes from 10.10.1.1: icmp_seq=5 ttl=64 time=.0858 ms

   Statistics: 5 sent, 5 received, 0% packet loss

Action: Examine Trace of ping from vpp to host
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock show trace

::

   ------------------- Start of thread 0 vpp_main -------------------
   Packet 1

   00:12:47:155326: af-packet-input
     af_packet: hw_if_index 1 next-index 4
       tpacket2_hdr:
         status 0x20000001 len 98 snaplen 98 mac 66 net 80
         sec 0x588fd471 nsec 0x161c61ad vlan 0 vlan_tpid 0
   00:12:47:155331: ethernet-input
     IP4: fa:13:55:ac:d9:50 -> 02:fe:48:ec:d5:a7
   00:12:47:155334: ip4-input
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x2604
       fragment id 0x3e8f
     ICMP echo_reply checksum 0x1a83
   00:12:47:155335: ip4-lookup
     fib 0 dpo-idx 5 flow hash: 0x00000000
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x2604
       fragment id 0x3e8f
     ICMP echo_reply checksum 0x1a83
   00:12:47:155336: ip4-local
       ICMP: 10.10.1.1 -> 10.10.1.2
         tos 0x00, ttl 64, length 84, checksum 0x2604
         fragment id 0x3e8f
       ICMP echo_reply checksum 0x1a83
   00:12:47:155339: ip4-icmp-input
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x2604
       fragment id 0x3e8f
     ICMP echo_reply checksum 0x1a83
   00:12:47:155342: ip4-icmp-echo-reply
     ICMP echo id 17572 seq 1
   00:12:47:155349: error-drop
     ip4-icmp-input: unknown type

   Packet 2

   00:12:48:155330: af-packet-input
     af_packet: hw_if_index 1 next-index 4
       tpacket2_hdr:
         status 0x20000001 len 98 snaplen 98 mac 66 net 80
         sec 0x588fd472 nsec 0x1603e95b vlan 0 vlan_tpid 0
   00:12:48:155337: ethernet-input
     IP4: fa:13:55:ac:d9:50 -> 02:fe:48:ec:d5:a7
   00:12:48:155341: ip4-input
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x2565
       fragment id 0x3f2e
     ICMP echo_reply checksum 0x7405
   00:12:48:155343: ip4-lookup
     fib 0 dpo-idx 5 flow hash: 0x00000000
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x2565
       fragment id 0x3f2e
     ICMP echo_reply checksum 0x7405
   00:12:48:155344: ip4-local
       ICMP: 10.10.1.1 -> 10.10.1.2
         tos 0x00, ttl 64, length 84, checksum 0x2565
         fragment id 0x3f2e
       ICMP echo_reply checksum 0x7405
   00:12:48:155346: ip4-icmp-input
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x2565
       fragment id 0x3f2e
     ICMP echo_reply checksum 0x7405
   00:12:48:155348: ip4-icmp-echo-reply
     ICMP echo id 17572 seq 2
   00:12:48:155351: error-drop
     ip4-icmp-input: unknown type

   Packet 3

   00:12:49:155331: af-packet-input
     af_packet: hw_if_index 1 next-index 4
       tpacket2_hdr:
         status 0x20000001 len 98 snaplen 98 mac 66 net 80
         sec 0x588fd473 nsec 0x15eb77ef vlan 0 vlan_tpid 0
   00:12:49:155337: ethernet-input
     IP4: fa:13:55:ac:d9:50 -> 02:fe:48:ec:d5:a7
   00:12:49:155341: ip4-input
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x249e
       fragment id 0x3ff5
     ICMP echo_reply checksum 0xf446
   00:12:49:155343: ip4-lookup
     fib 0 dpo-idx 5 flow hash: 0x00000000
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x249e
       fragment id 0x3ff5
     ICMP echo_reply checksum 0xf446
   00:12:49:155345: ip4-local
       ICMP: 10.10.1.1 -> 10.10.1.2
         tos 0x00, ttl 64, length 84, checksum 0x249e
         fragment id 0x3ff5
       ICMP echo_reply checksum 0xf446
   00:12:49:155349: ip4-icmp-input
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x249e
       fragment id 0x3ff5
     ICMP echo_reply checksum 0xf446
   00:12:49:155350: ip4-icmp-echo-reply
     ICMP echo id 17572 seq 3
   00:12:49:155354: error-drop
     ip4-icmp-input: unknown type

   Packet 4

   00:12:50:155335: af-packet-input
     af_packet: hw_if_index 1 next-index 4
       tpacket2_hdr:
         status 0x20000001 len 98 snaplen 98 mac 66 net 80
         sec 0x588fd474 nsec 0x15d2ffb6 vlan 0 vlan_tpid 0
   00:12:50:155341: ethernet-input
     IP4: fa:13:55:ac:d9:50 -> 02:fe:48:ec:d5:a7
   00:12:50:155346: ip4-input
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x2437
       fragment id 0x405c
     ICMP echo_reply checksum 0x5b6e
   00:12:50:155347: ip4-lookup
     fib 0 dpo-idx 5 flow hash: 0x00000000
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x2437
       fragment id 0x405c
     ICMP echo_reply checksum 0x5b6e
   00:12:50:155350: ip4-local
       ICMP: 10.10.1.1 -> 10.10.1.2
         tos 0x00, ttl 64, length 84, checksum 0x2437
         fragment id 0x405c
       ICMP echo_reply checksum 0x5b6e
   00:12:50:155351: ip4-icmp-input
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x2437
       fragment id 0x405c
     ICMP echo_reply checksum 0x5b6e
   00:12:50:155353: ip4-icmp-echo-reply
     ICMP echo id 17572 seq 4
   00:12:50:155356: error-drop
     ip4-icmp-input: unknown type

   Packet 5

   00:12:51:155324: af-packet-input
     af_packet: hw_if_index 1 next-index 4
       tpacket2_hdr:
         status 0x20000001 len 98 snaplen 98 mac 66 net 80
         sec 0x588fd475 nsec 0x15ba8726 vlan 0 vlan_tpid 0
   00:12:51:155331: ethernet-input
     IP4: fa:13:55:ac:d9:50 -> 02:fe:48:ec:d5:a7
   00:12:51:155335: ip4-input
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x23cc
       fragment id 0x40c7
     ICMP echo_reply checksum 0xedb3
   00:12:51:155337: ip4-lookup
     fib 0 dpo-idx 5 flow hash: 0x00000000
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x23cc
       fragment id 0x40c7
     ICMP echo_reply checksum 0xedb3
   00:12:51:155338: ip4-local
       ICMP: 10.10.1.1 -> 10.10.1.2
         tos 0x00, ttl 64, length 84, checksum 0x23cc
         fragment id 0x40c7
       ICMP echo_reply checksum 0xedb3
   00:12:51:155341: ip4-icmp-input
     ICMP: 10.10.1.1 -> 10.10.1.2
       tos 0x00, ttl 64, length 84, checksum 0x23cc
       fragment id 0x40c7
     ICMP echo_reply checksum 0xedb3
   00:12:51:155343: ip4-icmp-echo-reply
     ICMP echo id 17572 seq 5
   00:12:51:155346: error-drop
     ip4-icmp-input: unknown type

   Packet 6

   00:12:52:175185: af-packet-input
     af_packet: hw_if_index 1 next-index 4
       tpacket2_hdr:
         status 0x20000001 len 42 snaplen 42 mac 66 net 80
         sec 0x588fd476 nsec 0x16d05dd0 vlan 0 vlan_tpid 0
   00:12:52:175195: ethernet-input
     ARP: fa:13:55:ac:d9:50 -> 02:fe:48:ec:d5:a7
   00:12:52:175200: arp-input
     request, type ethernet/IP4, address size 6/4
     fa:13:55:ac:d9:50/10.10.1.1 -> 00:00:00:00:00:00/10.10.1.2
   00:12:52:175214: host-vpp1out-output
     host-vpp1out
     ARP: 02:fe:48:ec:d5:a7 -> fa:13:55:ac:d9:50
     reply, type ethernet/IP4, address size 6/4
     02:fe:48:ec:d5:a7/10.10.1.2 -> fa:13:55:ac:d9:50/10.10.1.1

After examinging the trace, clear it again.

Action: Examine arp tables
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock show ip arp

::

       Time           IP4       Flags      Ethernet              Interface       
       570.4092    10.10.1.1      D    fa:13:55:ac:d9:50       host-vpp1out      

Action: Examine routing table
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock show ip fib

::

   ipv4-VRF:0, fib_index 0, flow hash: src dst sport dport proto 
   0.0.0.0/0
     unicast-ip4-chain
     [@0]: dpo-load-balance: [index:0 buckets:1 uRPF:0 to:[0:0]]
       [0] [@0]: dpo-drop ip4
   0.0.0.0/32
     unicast-ip4-chain
     [@0]: dpo-load-balance: [index:1 buckets:1 uRPF:1 to:[0:0]]
       [0] [@0]: dpo-drop ip4
   10.10.1.1/32
     unicast-ip4-chain
     [@0]: dpo-load-balance: [index:10 buckets:1 uRPF:9 to:[5:420] via:[1:84]]
       [0] [@5]: ipv4 via 10.10.1.1 host-vpp1out: IP4: 02:fe:48:ec:d5:a7 -> fa:13:55:ac:d9:50
   10.10.1.0/24
     unicast-ip4-chain
     [@0]: dpo-load-balance: [index:8 buckets:1 uRPF:7 to:[0:0]]
       [0] [@4]: ipv4-glean: host-vpp1out
   10.10.1.2/32
     unicast-ip4-chain
     [@0]: dpo-load-balance: [index:9 buckets:1 uRPF:8 to:[6:504]]
       [0] [@2]: dpo-receive: 10.10.1.2 on host-vpp1out
   224.0.0.0/4
     unicast-ip4-chain
     [@0]: dpo-load-balance: [index:3 buckets:1 uRPF:3 to:[0:0]]
       [0] [@0]: dpo-drop ip4
   240.0.0.0/4
     unicast-ip4-chain
     [@0]: dpo-load-balance: [index:2 buckets:1 uRPF:2 to:[0:0]]
       [0] [@0]: dpo-drop ip4
   255.255.255.255/32
     unicast-ip4-chain
     [@0]: dpo-load-balance: [index:4 buckets:1 uRPF:4 to:[0:0]]
       [0] [@0]: dpo-drop ip4

Exercise: Connecting two vpp instances
--------------------------------------

.. _background-1:

Background
^^^^^^^^^^^^^^^^^^^^^^^^^^

memif is a very high performance, direct memory interface type which can
be used between vpp instances to form a topology. It uses a file socket
for a control channel to set up that shared memory.

.. _skills-to-be-learned-1:

Skills to be Learned
^^^^^^^^^^^^^^^^^^^^^^^^^^

You will learn the following new skill in this exercise:

#. Create a memif interface between two vpp instances

You should be able to perform this exercise with the following skills
learned in previous exercises:

#. Run a second vpp instance
#. Add an ip address to a vpp interface
#. Ping from vpp

.. _topology-1:

Topology
^^^^^^^^^^^^^

.. figure:: /_images/Connecting_two_vpp_instances_with_memif.png
   :alt: Connect two vpp topolgy

   Connect two vpp topolgy

.. _initial-state-1:

Initial state
^^^^^^^^^^^^^

The initial state here is presumed to be the final state from the
exercise `Create an
Interface <VPP/Progressive_VPP_Tutorial#Exercise:_Create_an_Interface>`__

.. _action-running-a-second-vpp-instances-1:

Action: Running a second vpp instances
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You should already have a vpp instance running named: vpp1.

Run a second vpp instance named: vpp2.

.. _action-create-memif-interface-on-vpp1-1:

Action: Create memif interface on vpp1
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create a memif interface on vpp1:

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock create memif id 0 master

This will create an interface on vpp1 memif0/0 using /run/vpp/memif as
its socket file. The role of vpp1 for this memif inteface is 'master'.

Use your previously used skills to:

#. Set the memif0/0 state to up.
#. Assign IP address 10.10.2.1/24 to memif0/0
#. Examine memif0/0 via show commands

.. _action-create-memif-interface-on-vpp2-1:

Action: Create memif interface on vpp2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We want vpp2 to pick up the 'slave' role using the same
run/vpp/memif-vpp1vpp2 socket file

::

   sudo vppctl -s /run/vpp/cli-vpp2.sock create memif id 0 slave

This will create an interface on vpp2 memif0/0 using /run/vpp/memif as
its socket file. The role of vpp1 for this memif inteface is 'slave'.

Use your previously used skills to:

#. Set the memif0/0 state to up.
#. Assign IP address 10.10.2.2/24 to memif0/0
#. Examine memif0/0 via show commands

.. _action-ping-from-vpp1-to-vpp2-1:

Action: Ping from vpp1 to vpp2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Ping 10.10.2.2 from vpp1

Ping 10.10.2.1 from vpp2

Exercise: Routing
-----------------

Skills to be Learned
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this exercise you will learn these new skills:

#. Add route to Linux Host routing table
#. Add route to vpp routing table

And revisit the old ones:

#. Examine vpp routing table
#. Enable trace on vpp1 and vpp2
#. ping from host to vpp
#. Examine and clear trace on vpp1 and vpp2
#. ping from vpp to host
#. Examine and clear trace on vpp1 and vpp2

vpp command learned in this exercise
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. `ip route
   add <https://docs.fd.io/vpp/17.04/clicmd_src_vnet_ip.html#clicmd_ip_route>`__

Topology
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. figure:: /_images/Connecting_two_vpp_instances_with_memif.png
   :alt: Connect two vpp topology

   Connect two vpp topology

Initial State
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The initial state here is presumed to be the final state from the
exercise `Connecting two vpp
instances <VPP/Progressive_VPP_Tutorial#Connecting_two_vpp_instances>`__

Action: Setup host route
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   sudo ip route add 10.10.2.0/24 via 10.10.1.2
   ip route

::

   default via 10.0.2.2 dev enp0s3 
   10.0.2.0/24 dev enp0s3  proto kernel  scope link  src 10.0.2.15 
   10.10.1.0/24 dev vpp1host  proto kernel  scope link  src 10.10.1.1 
   10.10.2.0/24 via 10.10.1.2 dev vpp1host 

Setup return route on vpp2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 10.10.1.0/24  via 10.10.2.1

Ping from host through vpp1 to vpp2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Setup a trace on vpp1 and vpp2
#. Ping 10.10.2.2 from the host
#. Examine the trace on vpp1 and vpp2
#. Clear the trace on vpp1 and vpp2

Exercise: Switching
-------------------

Skills to be Learned
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Associate an interface with a bridge domain
#. Create a loopback interaface
#. Create a BVI (Bridge Virtual Interface) for a bridge domain
#. Examine a bridge domain

vpp command learned in this exercise
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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

Note: You will lose all your existing config in your vpp instances!

To clear existing config from previous exercises run:

::

   ps -ef | grep vpp | awk '{print $2}'| xargs sudo kill
   sudo ip link del dev vpp1host
   sudo ip link del dev vpp1vpp2

Action: Run vpp instances
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Run a vpp instance named **vpp1**
#. Run a vpp instance named **vpp2**

Action: Connect vpp1 to host
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Create a veth with one end named vpp1host and the other named
   vpp1out.
#. Connect vpp1out to vpp1
#. Add ip address 10.10.1.1/24 on vpp1host

Action: Connect vpp1 to vpp2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Create a veth with one end named vpp1vpp2 and the other named
   vpp2vpp1.
#. Connect vpp1vpp2 to vpp1.
#. Connect vpp2vpp1 to vpp2.

Action: Configure Bridge Domain on vpp1
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check to see what bridge domains already exist, and select the first
bridge domain number not in use:

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock show bridge-domain

::

     ID   Index   Learning   U-Forwrd   UU-Flood   Flooding   ARP-Term     BVI-Intf   
     0      0        off        off        off        off        off        local0    

In the example above, there is bridge domain ID '0' already. Even though
sometimes we might get feedback as below:

::

   no bridge-domains in use

the bridge domain ID '0' still exists, where no operations are
supported. For instance, if we try to add host-vpp1out and host-vpp1vpp2
to bridge domain ID 0, we will get nothing setup.

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock set int l2 bridge host-vpp1out 0
   sudo vppctl -s /run/vpp/cli-vpp1.sock set int l2 bridge host-vpp1vpp2 0
   sudo vppctl -s /run/vpp/cli-vpp1.sock show bridge-domain 0 detail

::

   show bridge-domain: No operations on the default bridge domain are supported

So we will create bridge domain 1 instead of playing with the default
bridge domain ID 0.

Add host-vpp1out to bridge domain ID 1

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock set int l2 bridge host-vpp1out 1

Add host-vpp1vpp2 to bridge domain ID1

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock set int l2 bridge host-vpp1vpp2  1

Examine bridge domain 1:

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock show bridge-domain 1 detail

::

     BD-ID   Index   BSN  Age(min)  Learning  U-Forwrd  UU-Flood  Flooding  ARP-Term  BVI-Intf
       1       1      0     off        on        on        on        on       off       N/A

              Interface           If-idx ISN  SHG  BVI  TxFlood        VLAN-Tag-Rewrite
            host-vpp1out            1     1    0    -      *                 none
            host-vpp1vpp2           2     1    0    -      *                 none

Action: Configure loopback interface on vpp2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   sudo vppctl -s /run/vpp/cli-vpp2.sock create loopback interface

::

   loop0

Add the ip address 10.10.1.2/24 to vpp2 interface loop0. Set the state
of interface loop0 on vpp2 to 'up'

Action: Configure bridge domain on vpp2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check to see the first available bridge domain ID (it will be 1 in this
case)

Add interface loop0 as a bridge virtual interface (bvi) to bridge domain
1

::

   sudo vppctl -s /run/vpp/cli-vpp2.sock set int l2 bridge loop0 1 bvi

Add interface vpp2vpp1 to bridge domain 1

::

   sudo vppctl -s /run/vpp/cli-vpp2.sock set int l2 bridge host-vpp2vpp1  1

Examine the bridge domain and interfaces.

Action: Ping from host to vpp and vpp to host
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Add trace on vpp1 and vpp2
#. ping from host to 10.10.1.2
#. Examine and clear trace on vpp1 and vpp2
#. ping from vpp2 to 10.10.1.1
#. Examine and clear trace on vpp1 and vpp2

Action: Examine l2 fib
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock show l2fib verbose

::

       Mac Address     BD Idx           Interface           Index  static  filter  bvi   Mac Age (min) 
    de:ad:00:00:00:00    1            host-vpp1vpp2           2       0       0     0      disabled    
    c2:f6:88:31:7b:8e    1            host-vpp1out            1       0       0     0      disabled    
   2 l2fib entries

::

   sudo vppctl -s /run/vpp/cli-vpp2.sock show l2fib verbose

::

       Mac Address     BD Idx           Interface           Index  static  filter  bvi   Mac Age (min) 
    de:ad:00:00:00:00    1                loop0               2       1       0     1      disabled    
    c2:f6:88:31:7b:8e    1            host-vpp2vpp1           1       0       0     0      disabled    
   2 l2fib entries

Source NAT
----------

Skills to be Learned
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Abusing networks namespaces for fun and profit
#. Configuring snat address
#. Configuring snat inside and outside interfaces

vpp command learned in this exercise
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. `snat add interface
   address <https://docs.fd.io/vpp/17.04/clicmd_src_plugins_snat.html#clicmd_snat_add_interface_address>`__
#. `set interface
   snat <https://docs.fd.io/vpp/17.04/clicmd_src_plugins_snat.html#clicmd_set_interface_snat>`__

Topology
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. figure:: /_images/SNAT_Topology.jpg
   :alt: SNAT Topology

   SNAT Topology

Initial state
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Unlike previous exercises, for this one you want to start tabula rasa.

Note: You will lose all your existing config in your vpp instances!

To clear existing config from previous exercises run:

::

   ps -ef | grep vpp | awk '{print $2}'| xargs sudo kill
   sudo ip link del dev vpp1host
   sudo ip link del dev vpp1vpp2

Action: Install vpp-plugins
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Snat is supported by a plugin, so vpp-plugins need to be installed

::

   sudo apt-get install vpp-plugins

Action: Create vpp instance
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create one vpp instance named vpp1.

Confirm snat plugin is present:

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock show plugins

::

    Plugin path is: /usr/lib/vpp_plugins
    Plugins loaded: 
     1.ioam_plugin.so
     2.ila_plugin.so
     3.acl_plugin.so
     4.flowperpkt_plugin.so
     5.snat_plugin.so
     6.libsixrd_plugin.so
     7.lb_plugin.so

Action: Create veth interfaces
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Create a veth interface with one end named vpp1outside and the other
   named vpp1outsidehost
#. Assign IP address 10.10.1.1/24 to vpp1outsidehost
#. Create a veth interface with one end named vpp1inside and the other
   named vpp1insidehost
#. Assign IP address 10.10.2.1/24 to vpp1outsidehost

Because we'd like to be able to route \*via\* our vpp instance to an
interface on the same host, we are going to put vpp1insidehost into a
network namespace

Create a new network namespace 'inside'

::

   sudo ip netns add inside

Move interface vpp1inside into the 'inside' namespace:

::

   sudo ip link set dev vpp1insidehost up netns inside

Assign an ip address to vpp1insidehost

::

   sudo ip netns exec inside ip addr add 10.10.2.1/24 dev vpp1insidehost

Create a route inside the netns:

::

   sudo ip netns exec inside ip route add 10.10.1.0/24 via 10.10.2.2

Action: Configure vpp outside interface
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Create a vpp host interface connected to vpp1outside
#. Assign ip address 10.10.1.2/24
#. Create a vpp host interface connected to vpp1inside
#. Assign ip address 10.10.2.2/24

Action: Configure snat
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Configure snat to use the address of host-vpp1outside

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock snat add interface address host-vpp1outside

Configure snat inside and outside interfaces

::

   sudo vppctl -s /run/vpp/cli-vpp1.sock set interface snat in host-vpp1inside out host-vpp1outside

Action: Prepare to Observe Snat
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Observing snat in this configuration is interesting. To do so, vagrant
ssh a second time into your VM and run:

::

   sudo tcpdump -s 0 -i vpp1outsidehost

Also enable tracing on vpp1

Action: Ping via snat
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   sudo ip netns exec inside ping -c 1 10.10.1.1

Action: Confirm snat
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Examine the tcpdump output and vpp1 trace to confirm snat occurred.

