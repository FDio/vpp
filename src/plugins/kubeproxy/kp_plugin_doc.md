# Kube-proxy plugin for VPP    {#kp_plugin_doc}

## Overview

This plugin provides kube-proxy data plane on user space,
which is used to replace linux kernal's kube-proxy based on iptables.
The idea is largely inspired from VPP LB plugin.

Currently, kube-proxy plugin supports three service types:
1) Cluster IP plus Port: support any protocols, including TCP, UDP.
2) Node IP plus Node Port: currently only support UDP.
3) External Load Balancer.

For Cluster IP plus Port case:
kube-proxy is configured with a set of Virtual IPs (VIP, which can be
prefixes), and for each VIP, with a set of POD addresses (PODs).

For a specific session received for a given VIP (or VIP prefix), 
first packet selects a Pod according to internal load balancing algorithm, 
then does DNAT operation and sent to chosen Pod.
At the same time, will create a session entry to store Pod chosen result.
Following packets for that session will look up session table first, 
which ensures that a given session will always be routed to the same Pod.

For returned packet from Pod, it will do SNAT operation and sent out.

Please refer to below for details: 
https://schd.ws/hosted_files/ossna2017/1e/VPP_K8S_GTPU_OSSNA.pdf


## Configuration

### Global KP parameters

The kube-proxy needs to be configured with some parameters:

	ku conf [buckets <n>] [timeout <s>]

buckets: the *per-thread* established-connections-table number of buckets.

timeout: the number of seconds a connection will remain in the
         established-connections-table while no packet for this flow
         is received.

### Configure VIPs and Ports

    ku vip <prefix>  port <n> target_port <n> node_port <n> \
      [nat4|nat6)] [new_len <n>] [del]

new_len is the size of the new-connection-table. It should be 1 or 2 orders of
magnitude bigger than the number of PODs for the VIP in order to ensure a good
load balancing.

Examples:

    ku vip 90.0.0.0/8 nat44 new_len 2048
    ku vip 2003::/16 nat66 new_len 2048
    
### Configure PODs (for each VIP)

    ku pod <vip-prefix> [<address> [<address> [...]]] [del]

You can add (or delete) as many PODs at a time (for a single VIP).

Examples:

    ku pod 90.0.0.0/8 10.0.0.1
    ku pod 2002::/16 2001::2 2001::3 2001::4

### Configure SNAT

    ku set interface nat4 in <intfc> [del]

Set SNAT feature in a specific interface.


## Monitoring

The plugin provides quite a bunch of counters and information.

    show ku
    show ku vip verbose
    show node counters


## Design notes

### Multi-Threading

This implementation implement parallelism by using 
one established-connections table per thread. This is equivalent to assuming
that RSS will make a job similar to ECMP, and is pretty useful as threads don't
need to get a lock in order to write in the table.

### Hash Table

A kube-proxy requires an efficient read and write Hash table. The Hash table
used by ip6-forward is very read-efficient, but not so much for writing. In
addition, it is not a big deal if writing into the Hash table fails.

The plugin therefore uses a very specific Hash table.
	- Fixed (and power of 2) number of buckets (configured at runtime)
	- Fixed (and power of 2) elements per buckets (configured at compilation time)


