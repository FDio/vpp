.. _trex3:

Examples
========

There are many examples of how to create traffic flows in the directories below the
TRex root directory. The stateless examples are written in Python and are found in
the **./stl** directory. Examine the directories **./avl/, ./stl and ./cap2**. A few
simple examples are as follows:

* ./cap2/dns.yaml - Used in the first example
* ./avl/sfr_delay_10_1g.yaml - Used in the second example
* ./cap2/imix*.yaml - Uses some imix traffic profiles.
* ./stl/udp_1pkt.py - UDP example
* ./stl/imix.py - Simple imix example

Summary
=======

This tutorial showed how to download, compile, and install the VPP binary on an
Intel® Architecture platform. Examples of /etc/sysctl.d/80-vpp.conf and
/etc/vpp/startup.conf/startup.conf configuration files were provided to get the
user up and running with VPP. The tutorial also illustrated how to detect and bind
the network interfaces to a DPDK-compatible driver. You can use the VPP CLI to assign
IP addresses to these interfaces and bring them up. Four examples using iperf3
and TRex were included, to show how VPP processes packets in batches. We
also showed how to use TRex in stateless mode and examine traffic flow statistics.
