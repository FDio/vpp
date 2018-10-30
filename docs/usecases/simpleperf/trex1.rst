.. _trex1:

Using VPP with TRex Mixed Traffic Templates
===========================================

In this example, a more complicated traffic with delay profile on *net2s22c05* is
generated using the traffic configuration file "avl/sfr_delay_10_1g.yaml":

.. code-block:: console

   NET2S22C05$ sudo ./t-rex-64 -f avl/sfr_delay_10_1g.yaml -c 2 -m 20 -d 100 -l 1000
   summary stats
    --------------
    Total-pkt-drop       : 43309 pkts
    Total-tx-bytes       : 251062132504 bytes
    Total-tx-sw-bytes    : 21426636 bytes
    Total-rx-bytes       : 251040139922 byte
   
    Total-tx-pkt         : 430598064 pkts
    Total-rx-pkt         : 430554755 pkts
    Total-sw-tx-pkt      : 324646 pkts
    Total-sw-err         : 0 pkts
    Total ARP sent       : 5 pkts
    Total ARP received   : 4 pkts
    maximum-latency   : 1278 usec
    average-latency   : 9 usec
    latency-any-error : ERROR

On *csp2s22c03*, use the VCC CLI command show run to display the graph runtime statistics.
Observe that the average vector per node is 10.69 and 14.47:

.. figure:: /_images/build-a-fast-network-stack-terminal-3.png

Summary
=======

This tutorial showed how to download, compile, and install the VPP binary on an
Intel® Architecture platform. Examples of /etc/sysctl.d/80-vpp.conf and
/etc/vpp/startup.conf/startup.conf configuration files were provided to get the
user up and running with VPP. The tutorial also illustrated how to detect and bind
the network interfaces to a DPDK-compatible driver. You can use the VPP CLI to assign
IP addresses to these interfaces and bring them up. Finally, four examples using iperf3
and TRex were included, to show how VPP processes packets in batches.

