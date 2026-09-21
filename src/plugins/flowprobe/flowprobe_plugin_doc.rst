IPFIX flow record plugin
========================

Introduction
------------

This plugin generates ipfix flow records on interfaces which have the
feature enabled

Sample configuration
--------------------

::

  set ipfix exporter collector 192.168.6.2 src 192.168.6.1 template-interval 20 port 4739 path-mtu 1450

  flowprobe params record l3 active 20 passive 120
  flowprobe feature add-del GigabitEthernet2/3/0 l2

The ``l2`` datapath can also be enabled on a VLAN sub-interface, where it is
installed on the IPv4 and IPv6 feature arcs of that sub-interface.  When the
record includes ``l2``, it records the MAC addresses and the inner ethertype
of IPv4 and IPv6 frames of the enabled directions.  Non-IP frames are not
recorded on a sub-interface.

::

  flowprobe feature add-del GigabitEthernet2/3/0.10 l2 both
