IPFIX flow record plugin
========================

Introduction
------------

This plugin generates IPFIX flow records on interfaces which have the
feature enabled.

Count based sampling
----------------------

The plugin allows configuring sampling intervals using the following parameters:

- **interval_spacing**: Number of packets to skip between sampling intervals.
- **interval_length**: Number of packets to report in each interval.

Behavior:
- If `interval_spacing` is `0`, all packets are reported.
- If `interval_spacing > 0`, `interval_length` packets are reported with a wait of `interval_spacing` packets in between.
- If `interval_length` is `0`, it defaults to reporting a single packet.

Sample configuration
--------------------

::

  set ipfix exporter collector 192.168.6.2 src 192.168.6.1 template-interval 20 port 4739 path-mtu 1450

  flowprobe params record l3 active 20 passive 120
  flowprobe feature add-del GigabitEthernet2/3/0 l2
  flowprobe feature add-del GigabitEthernet2/3/0 ip4 rx spacing 100 length 10
