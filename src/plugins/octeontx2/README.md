# Marvell® OCTEON TX2® device plugin for VPP    {#marvell_octeontx2_plugin_doc}

##Overview
This plugin provides support for [Marvell® OCTEON TX2®][1] SOC processor. Plugin
uses Marvell's DPDK library (libmarvelldpdk) which is a derivative of [DPDK][2]
library. libmarvelldpdk has been optimized for performance with VPP on the
Marvell OCTEON TX2 processor

##About Marvell OCTEON TX2 plugin
1. This plugin uses the performance optimized libmarvelldpdk. Standard [DPDK][2]
API use [struct rte_mbuf][3] which then require conversion to vlib_buffer_t for
VPP. This plugin avoids this conversion in ingress/egress path thereby reducing
one DCACHE access per packet for ingress and egress. Like a native VPP plugin,
this plugin only interacts with VPP meta data (vlib_buffer_t).

2. Marvell OCTEON TX2 network device(s) interacts with co-processor (aka NPA),
which manages packet buffers in hardware pool(s), while receiving and
transmitting packets. This OCTEON TX2 co-processor is exposed as a
rte_mempool_ops for DPDK applicatons. On other hand VPP has single VLIB buffer
pool for each NUMA node. Amid these two design requirements this plugin manages
hardware pools (rte_mempool) internally.  This plugin does following to manage
hardware pool (rte_mempool) and VLIB buffer pool.
    - Populate hardware pool from VLIB buffer pool (default-numa-0)
    - If hardware pool buffer count decreases by threshold, refill them from
      vlib buffer pool in ingress path.
    - If hardware pool buffer count exceeds by threshold, free buffers back to
      VLIB buffer pool in egress path.

3. Processing of vlib buffers happens only in PMD handlers of rte_eth_rx_burst()/
rte_eth_tx_burst() which further reduces cycles to process each packet in Rx and
Tx path.

##Pre-requisites
Cmake compiles this plugin only when it finds "libmarvelldpdk" library in
library path.

##Execution
OCTEON TX2 startup config parameters are almost same as dpdk startup config with
following differences

1. User can configure number of buffers in hardware pool by providing num-mbufs
option as follows

    octeontx2 {
        ...
        ...
      num-mbufs 16384
        ...
        ...
    }
*Note*: (i) Default count is 8192. (ii) The count should be less than
"buffers { buffers-per-numa XXX }" count

2. Plugin registers itself in disabled state. On OCTEON TX2 platform, the
dpdk_plugin should be disabled and octeontx2 plugin should be enabled to use
this plugin as follows

    plugins {
          ...
          ...
	  # Disable DPDK plugin
	  plugin dpdk_plugin.so { disable }

	  # Enable OCTEONTX2 plugin
	  plugin octeontx2_plugin.so { enable }
         ...
         ...

    }
*Note*: Sample startup.conf is placed at src/plugins/octeontx2/sample-startup.conf

##Known Issues
1. Plugin does not support multi-segment buffers.

[1]: https://www.marvell.com/embedded-processors/infrastructure-processors/
[2]: https://www.dpdk.org
[3]: https://doc.dpdk.org/api/structrte__mbuf.html
