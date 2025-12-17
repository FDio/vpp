BPF Trace Filter Function
============================
This plugin provides a trace filter function that relies on a BPF interpreter to select which packets
must be traced. This filter function can be applied to vpp traces and pcap captures.

Note that if a classifier-based filter has been specified, then it will be used
in conjunction with the BPF filter.

Setting BPF filter:
---------------------

Add filter for ICMP packets
::

   vpp# set bpf trace filter {{ip proto icmp}}

Show BPF bytecode:
::

   vpp# show bpf trace filter
   (000) ldh      [12]
   (001) jeq      #0x800           jt 2    jf 5
   (002) ldb      [23]
   (003) jeq      #0x1             jt 4    jf 5
   (004) ret      #65535
   (005) ret      #0

Applying BPF filter on trace:
-----------------------------

Enable BPF filter function for trace:
::

   vpp# set trace filter function bpf_trace_filter
   vpp# show trace filter function
   (*) name:bpf_trace_filter description: bpf based trace filter priority: 10
   name:vnet_is_packet_traced description: classifier based filter priority: 50

Add trace with filter:
::

   vpp# trace add <input-graph-node> 100 filter
   vpp# show trace

Enabling BPF filter on pcap capture:
-------------------------------------

Enable BPF filter function for pcap capture:
::

   vpp# set pcap filter function bpf_trace_filter
   vpp# show pcap filter function
   (*) name:bpf_trace_filter description: bpf based trace filter priority: 10
   name:vnet_is_packet_traced description: classifier based filter priority: 50

Enable pcap capture with filter:
::

   vpp# pcap trace rx tx max 1000 intfc <interface> filter
   vpp# pcap trace off

Enabling BPF filter on dispatch trace:
---------------------------------------

Enable BPF filter function for dispatch trace:
::

   vpp# set pcap filter function bpf_trace_filter
   vpp# show pcap filter function
   (*) name:bpf_trace_filter description: bpf based trace filter priority: 10
   name:vnet_is_packet_traced description: classifier based filter priority: 50

Enable dispatch trace with filter:
::

   vpp# pcap dispatch trace on max 1000 file dispatch.pcap filter
   vpp# pcap dispatch trace off

Additional information:
-------------------------------------

BPF syntax reference : https://www.tcpdump.org/manpages/pcap-filter.7.html

FAQ on limitations when filtering on VLAN/Geneve/MPLS packets: https://www.tcpdump.org/faq.html#q13
