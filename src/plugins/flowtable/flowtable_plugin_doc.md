# Flowtable plugin for VPP

## Overview

This plugin provides a stateful node with flow-level API, available for consecutive nodes or external applications.

## Objective
Provides a flowtable node to do flow classification, and associate a flow context 
that can be enriched as needed by another node or an external application.
The objective is to be adaptable so as to be used for any stateful use such as load-balancing, firewall, etc.

Compared to the classifier, it stores a flow context, which changes the following:
1). A flow context (which can be updated with external information)
2). It can offload
3). Flows have a lifetime

## Current status
a).Default behavior is to connect transparently to given interface.
b).Can reroute packets to given node
c).Can receive additional information
d).Can offload sessions
e).Only support IP packets
f).if the maximum number of flows is reached, the flowtable will recycle a flow by expiring a flow 
   which was about to expire (typically the first flow found in the timer-wheel's next-slot)

## CLI
Configuration

    flowtable [max-flows <n>] [intf <name>] [next-node <name>] [disable]

The traffic from the given intf is redirected to the flowtable using vnet_hw_interface_rx_redirect_to_node()

## API
Used ~0 (or 0xff for u8) to leave configuration parameter unchanged.

flowtable configuration

    flowtable_conf(flows_max, sw_if_index, next_node_index, enable_disable)

send additional informations to the flowtable

    flowtable_update(is_ip4, ip_src, ip_dst, port_src, port_dst # used to compute flow key
                     lifetime, offloaded, infos) # additional flow informations

