.. _trex:

Using VPP with TRex
===================

In this example we use only two systems, *csp2s22c03* and *net2s22c05*, to run
**TRex** VPP is installed on **csp2s22c03** and run as a packet forwarding
engine. On *net2s22c05*, TRex is used to generate both client and server-side
traffic. **TRex** is a high-performance traffic generator. It leverages DPDK and
run in user space. Figure 2 illustrates this configuration.

VPP is set up on *csp2s22c03* exactly as it was in the previous example. Only
the setup on *net2s22c05* is modified slightly to run TRex preconfigured traffic
files.

.. figure:: /_images/trex.png

Figure 2: The TRex traffic generator sends packages to the host that has VPP running.


First we install **TRex**.

.. code-block:: console

   NET2S22C05$ wget --no-cache http://trex-tgn.cisco.com/trex/release/latest
   NET2S22C05$ tar -xzvf latest
   NET2S22C05$ cd v2.37

Then show the devices we have.

.. code-block:: console

   NET2S22C05$ sudo ./dpdk_nic_bind.py -s

   Network devices using DPDK-compatible driver
   ============================================
   0000:87:00.0 'Ethernet Controller XL710 for 40GbE QSFP+' drv=vfio-pci unused=i40e
   0000:87:00.1 'Ethernet Controller XL710 for 40GbE QSFP+' drv=vfio-pci unused=i40e

   Network devices using kernel driver
   ===================================
   0000:03:00.0 'Ethernet Controller 10-Gigabit X540-AT2' if=enp3s0f0 drv=ixgbe unused=vfio-pci *Active*
   0000:03:00.1 'Ethernet Controller 10-Gigabit X540-AT2' if=enp3s0f1 drv=ixgbe unused=vfio-pci
   0000:81:00.0 '82599 10 Gigabit TN Network Connection' if=ens787f0 drv=ixgbe unused=vfio-pci
   0000:81:00.1 '82599 10 Gigabit TN Network Connection' if=ens787f1 drv=ixgbe unused=vfio-pci

   Other network devices
   =====================
   <none>

Create the */etc/trex_cfg.yaml* configuration file. In this configuration file,
the port should match the interfaces available in the target system, which is
*net2s22c05* in our example. The IP addresses correspond to Figure 2. For more
information on the configuration file, please refer to the `TRex Manual <http://trex-tgn.cisco.com/trex/doc/index.html>`_.

.. code-block:: console

   NET2S22C05$ cat /etc/trex_cfg.yaml
   - port_limit: 2
     version: 2
     interfaces: ['87:00.0', '87:00.1']
     port_bandwidth_gb: 40
     port_info:
         - ip: 10.10.2.2
           default_gw: 10.10.2.1
         - ip: 10.10.1.2
           default_gw: 10.10.1.1
   
     platform:
         master_thread_id: 0
         latency_thread_id: 1
         dual_if:
           - socket: 1
             threads: [22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43]

Stop the previous VPP session and start it again in order to add a route for new
IP addresses 16.0.0.0/8 and 48.0.0.0/8, according to Figure 2. Those IP addresses
are needed because TRex generates packets that use these addresses. Refer to the
`TRex Manual <http://trex-tgn.cisco.com/trex/doc/index.html>`_ for details on
these traffic templates.

.. code-block:: console

   csp2s22c03$ sudo service vpp stop
   csp2s22c03$ sudo service vpp start
   csp2s22c03$ sudo vppctl
       _______    _        _   _____  ___
    __/ __/ _ \  (_)__    | | / / _ \/ _ \
    _/ _// // / / / _ \   | |/ / ___/ ___/
    /_/ /____(_)_/\___/   |___/_/  /_/
   
   vpp# sho int
                 Name               Idx       State          Counter          Count
   FortyGigabitEthernet82/0/0        1        down
   FortyGigabitEthernet82/0/1        2        down
   local0                            0        down
   
   vpp#
   vpp# set interface ip address FortyGigabitEthernet82/0/0 10.10.1.1/24
   vpp# set interface ip address FortyGigabitEthernet82/0/1 10.10.2.1/24
   vpp# set interface state FortyGigabitEthernet82/0/0 up
   vpp# set interface state FortyGigabitEthernet82/0/1 up
   vpp# ip route add 16.0.0.0/8 via 10.10.1.2
   vpp# ip route add 48.0.0.0/8 via 10.10.2.2
   vpp# clear run

Now, you can generate a simple traffic flow from *net2s22c05* using the traffic
configuration file "cap2/dns.yaml".

.. code-block:: console

   NET2S22C05$ sudo ./t-rex-64 -f cap2/dns.yaml -d 1 -l 1000
    summary stats
    --------------
    Total-pkt-drop       : 0 pkts
    Total-tx-bytes       : 166886 bytes
    Total-tx-sw-bytes    : 166716 bytes
    Total-rx-bytes       : 166886 byte
   
    Total-tx-pkt         : 2528 pkts
    Total-rx-pkt         : 2528 pkts
    Total-sw-tx-pkt      : 2526 pkts
    Total-sw-err         : 0 pkts
    Total ARP sent       : 4 pkts
    Total ARP received   : 2 pkts
    maximum-latency   : 35 usec
    average-latency   : 8 usec
    latency-any-error : OK

On *csp2s22c03*, the *show run* command displays the graph runtime statistics.

.. figure:: /_images/build-a-fast-network-stack-terminal-2.png

