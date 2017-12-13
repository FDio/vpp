#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppSubInterface, VppDot1QSubint, VppDot1ADSubint
from vpp_ip_route import VppIpMRoute, VppMRoutePath, VppMFibSignal, \
    MRouteItfFlags, MRouteEntryFlags, VppIpTable, DpoProto

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, getmacbyip, ICMP
from scapy.layers.inet6 import IPv6, getmacbyip6
from util import ppp

#
# The number of packets sent is set to 91 so that when we replicate more than 3
# times, which we do for some entries, we will generate more than 256 packets
# to the next node in the VLIB graph. Thus we are testing the code's
# correctness handling this over-flow.
# It's also an odd number so we hit any single loops.
#
N_PKTS_IN_STREAM = 91


class TestMFIB(VppTestCase):
    """ MFIB Test Case """

    def setUp(self):
        super(TestMFIB, self).setUp()

    def test_mfib(self):
        """ MFIB Unit Tests """
        error = self.vapi.cli("test mfib")

        if error:
            self.logger.critical(error)
        self.assertEqual(error.find("Failed"), -1)


class TestIPMcast(VppTestCase):
    """ IP Multicast Test Case """

    def setUp(self):
        super(TestIPMcast, self).setUp()

        # create 8 pg interfaces
        self.create_pg_interfaces(range(9))

        # setup interfaces
        for i in self.pg_interfaces[:8]:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.resolve_arp()
            i.resolve_ndp()

        # one more in a vrf
        tbl4 = VppIpTable(self, 10)
        tbl4.add_vpp_config()
        self.pg8.set_table_ip4(10)
        self.pg8.config_ip4()

        tbl6 = VppIpTable(self, 10, is_ip6=1)
        tbl6.add_vpp_config()
        self.pg8.set_table_ip6(10)
        self.pg8.config_ip6()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()

        self.pg8.set_table_ip4(0)
        self.pg8.set_table_ip6(0)
        super(TestIPMcast, self).tearDown()

    def create_stream_ip4(self, src_if, src_ip, dst_ip, payload_size=0):
        pkts = []
        # default to small packet sizes
        p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
             IP(src=src_ip, dst=dst_ip) /
             UDP(sport=1234, dport=1234))
        if not payload_size:
            payload_size = 64 - len(p)
            p = p / Raw('\xa5' * payload_size)

        for i in range(0, N_PKTS_IN_STREAM):
            pkts.append(p)
        return pkts

    def create_stream_ip6(self, src_if, src_ip, dst_ip):
        pkts = []
        for i in range(0, N_PKTS_IN_STREAM):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IPv6(src=src_ip, dst=dst_ip) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def verify_filter(self, capture, sent):
        if not len(capture) == len(sent):
            # filter out any IPv6 RAs from the captur
            for p in capture:
                if (p.haslayer(IPv6)):
                    capture.remove(p)
        return capture

    def verify_capture_ip4(self, rx_if, sent):
        rxd = rx_if.get_capture(len(sent))

        try:
            capture = self.verify_filter(rxd, sent)

            self.assertEqual(len(capture), len(sent))

            for i in range(len(capture)):
                tx = sent[i]
                rx = capture[i]

                eth = rx[Ether]
                self.assertEqual(eth.type, 0x800)

                tx_ip = tx[IP]
                rx_ip = rx[IP]

                # check the MAC address on the RX'd packet is correctly formed
                self.assertEqual(eth.dst, getmacbyip(rx_ip.dst))

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                # IP processing post pop has decremented the TTL
                self.assertEqual(rx_ip.ttl + 1, tx_ip.ttl)

        except:
            raise

    def verify_capture_ip6(self, rx_if, sent):
        capture = rx_if.get_capture(len(sent))

        self.assertEqual(len(capture), len(sent))

        for i in range(len(capture)):
            tx = sent[i]
            rx = capture[i]

            eth = rx[Ether]
            self.assertEqual(eth.type, 0x86DD)

            tx_ip = tx[IPv6]
            rx_ip = rx[IPv6]

            # check the MAC address on the RX'd packet is correctly formed
            self.assertEqual(eth.dst, getmacbyip6(rx_ip.dst))

            self.assertEqual(rx_ip.src, tx_ip.src)
            self.assertEqual(rx_ip.dst, tx_ip.dst)
            # IP processing post pop has decremented the TTL
            self.assertEqual(rx_ip.hlim + 1, tx_ip.hlim)

    def test_ip_mcast(self):
        """ IP Multicast Replication """

        #
        # a stream that matches the default route. gets dropped.
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "1.1.1.1", "232.1.1.1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.pg0.assert_nothing_captured(
            remark="IP multicast packets forwarded on default route")

        #
        # A (*,G).
        # one accepting interface, pg0, 7 forwarding interfaces
        #  many forwarding interfaces test the case where the replicare DPO
        #  needs to use extra cache lines for the buckets.
        #
        route_232_1_1_1 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.1", 32,
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE,
            [VppMRoutePath(self.pg0.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT),
             VppMRoutePath(self.pg1.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD),
             VppMRoutePath(self.pg2.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD),
             VppMRoutePath(self.pg3.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD),
             VppMRoutePath(self.pg4.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD),
             VppMRoutePath(self.pg5.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD),
             VppMRoutePath(self.pg6.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD),
             VppMRoutePath(self.pg7.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD)])
        route_232_1_1_1.add_vpp_config()

        #
        # An (S,G).
        # one accepting interface, pg0, 2 forwarding interfaces
        #
        route_1_1_1_1_232_1_1_1 = VppIpMRoute(
            self,
            "1.1.1.1",
            "232.1.1.1", 64,
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE,
            [VppMRoutePath(self.pg0.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT),
             VppMRoutePath(self.pg1.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD),
             VppMRoutePath(self.pg2.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD)])
        route_1_1_1_1_232_1_1_1.add_vpp_config()

        #
        # An (*,G/m).
        # one accepting interface, pg0, 1 forwarding interfaces
        #
        route_232 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.0.0.0", 8,
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE,
            [VppMRoutePath(self.pg0.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT),
             VppMRoutePath(self.pg1.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD)])
        route_232.add_vpp_config()

        #
        # a stream that matches the route for (1.1.1.1,232.1.1.1)
        #  small packets
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "1.1.1.1", "232.1.1.1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1->7
        self.verify_capture_ip4(self.pg1, tx)
        self.verify_capture_ip4(self.pg2, tx)

        # no replications on Pg0
        self.pg0.assert_nothing_captured(
            remark="IP multicast packets forwarded on PG0")
        self.pg3.assert_nothing_captured(
            remark="IP multicast packets forwarded on PG3")

        #
        # a stream that matches the route for (1.1.1.1,232.1.1.1)
        #  large packets
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "1.1.1.1", "232.1.1.1",
                                    payload_size=1024)
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1->7
        self.verify_capture_ip4(self.pg1, tx)
        self.verify_capture_ip4(self.pg2, tx)

        # no replications on Pg0
        self.pg0.assert_nothing_captured(
            remark="IP multicast packets forwarded on PG0")
        self.pg3.assert_nothing_captured(
            remark="IP multicast packets forwarded on PG3")

        #
        # a stream that matches the route for (*,232.0.0.0/8)
        # Send packets with the 9th bit set so we test the correct clearing
        # of that bit in the mac rewrite
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "1.1.1.1", "232.255.255.255")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1 only
        self.verify_capture_ip4(self.pg1, tx)

        # no replications on Pg0, Pg2 not Pg3
        self.pg0.assert_nothing_captured(
            remark="IP multicast packets forwarded on PG0")
        self.pg2.assert_nothing_captured(
            remark="IP multicast packets forwarded on PG2")
        self.pg3.assert_nothing_captured(
            remark="IP multicast packets forwarded on PG3")

        #
        # a stream that matches the route for (*,232.1.1.1)
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "1.1.1.2", "232.1.1.1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1, 2, 3.
        self.verify_capture_ip4(self.pg1, tx)
        self.verify_capture_ip4(self.pg2, tx)
        self.verify_capture_ip4(self.pg3, tx)
        self.verify_capture_ip4(self.pg4, tx)
        self.verify_capture_ip4(self.pg5, tx)
        self.verify_capture_ip4(self.pg6, tx)
        self.verify_capture_ip4(self.pg7, tx)

    def test_ip6_mcast(self):
        """ IPv6 Multicast Replication """

        #
        # a stream that matches the default route. gets dropped.
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip6(self.pg0, "2001::1", "ff01::1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.pg0.assert_nothing_captured(
            remark="IPv6 multicast packets forwarded on default route")

        #
        # A (*,G).
        # one accepting interface, pg0, 3 forwarding interfaces
        #
        route_ff01_1 = VppIpMRoute(
            self,
            "::",
            "ff01::1", 128,
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE,
            [VppMRoutePath(self.pg0.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT,
                           proto=DpoProto.DPO_PROTO_IP6),
             VppMRoutePath(self.pg1.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD,
                           proto=DpoProto.DPO_PROTO_IP6),
             VppMRoutePath(self.pg2.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD,
                           proto=DpoProto.DPO_PROTO_IP6),
             VppMRoutePath(self.pg3.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD,
                           proto=DpoProto.DPO_PROTO_IP6)],
            is_ip6=1)
        route_ff01_1.add_vpp_config()

        #
        # An (S,G).
        # one accepting interface, pg0, 2 forwarding interfaces
        #
        route_2001_ff01_1 = VppIpMRoute(
            self,
            "2001::1",
            "ff01::1", 256,
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE,
            [VppMRoutePath(self.pg0.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT,
                           proto=DpoProto.DPO_PROTO_IP6),
             VppMRoutePath(self.pg1.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD,
                           proto=DpoProto.DPO_PROTO_IP6),
             VppMRoutePath(self.pg2.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD,
                           proto=DpoProto.DPO_PROTO_IP6)],
            is_ip6=1)
        route_2001_ff01_1.add_vpp_config()

        #
        # An (*,G/m).
        # one accepting interface, pg0, 1 forwarding interface
        #
        route_ff01 = VppIpMRoute(
            self,
            "::",
            "ff01::", 16,
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE,
            [VppMRoutePath(self.pg0.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT,
                           proto=DpoProto.DPO_PROTO_IP6),
             VppMRoutePath(self.pg1.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD,
                           proto=DpoProto.DPO_PROTO_IP6)],
            is_ip6=1)
        route_ff01.add_vpp_config()

        #
        # a stream that matches the route for (*, ff01::/16)
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip6(self.pg0, "2002::1", "ff01:2::255")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1
        self.verify_capture_ip6(self.pg1, tx)

        # no replications on Pg0, Pg3
        self.pg0.assert_nothing_captured(
            remark="IP multicast packets forwarded on PG0")
        self.pg2.assert_nothing_captured(
            remark="IP multicast packets forwarded on PG2")
        self.pg3.assert_nothing_captured(
            remark="IP multicast packets forwarded on PG3")

        #
        # Bounce the interface and it should still work
        #
        self.pg1.admin_down()
        self.pg0.add_stream(tx)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured(
            remark="IP multicast packets forwarded on down PG1")

        self.pg1.admin_up()
        self.pg0.add_stream(tx)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.verify_capture_ip6(self.pg1, tx)

        #
        # a stream that matches the route for (*,ff01::1)
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip6(self.pg0, "2002::2", "ff01::1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1, 2, 3.
        self.verify_capture_ip6(self.pg1, tx)
        self.verify_capture_ip6(self.pg2, tx)
        self.verify_capture_ip6(self.pg3, tx)

        # no replications on Pg0
        self.pg0.assert_nothing_captured(
            remark="IPv6 multicast packets forwarded on PG0")

        #
        # a stream that matches the route for (2001::1, ff00::1)
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip6(self.pg0, "2001::1", "ff01::1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1, 2,
        self.verify_capture_ip6(self.pg1, tx)
        self.verify_capture_ip6(self.pg2, tx)

        # no replications on Pg0, Pg3
        self.pg0.assert_nothing_captured(
            remark="IP multicast packets forwarded on PG0")
        self.pg3.assert_nothing_captured(
            remark="IP multicast packets forwarded on PG3")

    def _mcast_connected_send_stream(self, dst_ip):
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0,
                                    self.pg0.remote_ip4,
                                    dst_ip)
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1.
        self.verify_capture_ip4(self.pg1, tx)

        return tx

    def test_ip_mcast_connected(self):
        """ IP Multicast Connected Source check """

        #
        # A (*,G).
        # one accepting interface, pg0, 1 forwarding interfaces
        #
        route_232_1_1_1 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.1", 32,
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE,
            [VppMRoutePath(self.pg0.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT),
             VppMRoutePath(self.pg1.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD)])

        route_232_1_1_1.add_vpp_config()
        route_232_1_1_1.update_entry_flags(
            MRouteEntryFlags.MFIB_ENTRY_FLAG_CONNECTED)

        #
        # Now the (*,G) is present, send from connected source
        #
        tx = self._mcast_connected_send_stream("232.1.1.1")

        #
        # Constrct a representation of the signal we expect on pg0
        #
        signal_232_1_1_1_itf_0 = VppMFibSignal(self,
                                               route_232_1_1_1,
                                               self.pg0.sw_if_index,
                                               tx[0])

        #
        # read the only expected signal
        #
        signals = self.vapi.mfib_signal_dump()

        self.assertEqual(1, len(signals))

        signal_232_1_1_1_itf_0.compare(signals[0])

        #
        # reading the signal allows for the generation of another
        # so send more packets and expect the next signal
        #
        tx = self._mcast_connected_send_stream("232.1.1.1")

        signals = self.vapi.mfib_signal_dump()
        self.assertEqual(1, len(signals))
        signal_232_1_1_1_itf_0.compare(signals[0])

        #
        # A Second entry with connected check
        # one accepting interface, pg0, 1 forwarding interfaces
        #
        route_232_1_1_2 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.2", 32,
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE,
            [VppMRoutePath(self.pg0.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT),
             VppMRoutePath(self.pg1.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD)])

        route_232_1_1_2.add_vpp_config()
        route_232_1_1_2.update_entry_flags(
            MRouteEntryFlags.MFIB_ENTRY_FLAG_CONNECTED)

        #
        # Send traffic to both entries. One read should net us two signals
        #
        signal_232_1_1_2_itf_0 = VppMFibSignal(self,
                                               route_232_1_1_2,
                                               self.pg0.sw_if_index,
                                               tx[0])
        tx = self._mcast_connected_send_stream("232.1.1.1")
        tx2 = self._mcast_connected_send_stream("232.1.1.2")

        #
        # read the only expected signal
        #
        signals = self.vapi.mfib_signal_dump()

        self.assertEqual(2, len(signals))

        signal_232_1_1_1_itf_0.compare(signals[1])
        signal_232_1_1_2_itf_0.compare(signals[0])

        route_232_1_1_1.update_entry_flags(
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE)
        route_232_1_1_2.update_entry_flags(
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE)

    def test_ip_mcast_signal(self):
        """ IP Multicast Signal """

        #
        # A (*,G).
        # one accepting interface, pg0, 1 forwarding interfaces
        #
        route_232_1_1_1 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.1", 32,
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE,
            [VppMRoutePath(self.pg0.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT),
             VppMRoutePath(self.pg1.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD)])

        route_232_1_1_1.add_vpp_config()
        route_232_1_1_1.update_entry_flags(
            MRouteEntryFlags.MFIB_ENTRY_FLAG_SIGNAL)

        #
        # Now the (*,G) is present, send from connected source
        #
        tx = self._mcast_connected_send_stream("232.1.1.1")

        #
        # Constrct a representation of the signal we expect on pg0
        #
        signal_232_1_1_1_itf_0 = VppMFibSignal(self,
                                               route_232_1_1_1,
                                               self.pg0.sw_if_index,
                                               tx[0])

        #
        # read the only expected signal
        #
        signals = self.vapi.mfib_signal_dump()

        self.assertEqual(1, len(signals))

        signal_232_1_1_1_itf_0.compare(signals[0])

        #
        # reading the signal allows for the generation of another
        # so send more packets and expect the next signal
        #
        tx = self._mcast_connected_send_stream("232.1.1.1")

        signals = self.vapi.mfib_signal_dump()
        self.assertEqual(1, len(signals))
        signal_232_1_1_1_itf_0.compare(signals[0])

        #
        # Set the negate-signal on the accepting interval - the signals
        # should stop
        #
        route_232_1_1_1.update_path_flags(
            self.pg0.sw_if_index,
            (MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT |
             MRouteItfFlags.MFIB_ITF_FLAG_NEGATE_SIGNAL))

        self.vapi.cli("clear trace")
        tx = self._mcast_connected_send_stream("232.1.1.1")

        signals = self.vapi.mfib_signal_dump()
        self.assertEqual(0, len(signals))

        #
        # Clear the SIGNAL flag on the entry and the signals should
        # come back since the interface is still NEGATE-SIGNAL
        #
        route_232_1_1_1.update_entry_flags(
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE)

        tx = self._mcast_connected_send_stream("232.1.1.1")

        signals = self.vapi.mfib_signal_dump()
        self.assertEqual(1, len(signals))
        signal_232_1_1_1_itf_0.compare(signals[0])

        #
        # Lastly remove the NEGATE-SIGNAL from the interface and the
        # signals should stop
        #
        route_232_1_1_1.update_path_flags(self.pg0.sw_if_index,
                                          MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT)

        tx = self._mcast_connected_send_stream("232.1.1.1")
        signals = self.vapi.mfib_signal_dump()
        self.assertEqual(0, len(signals))

    def test_ip_mcast_vrf(self):
        """ IP Multicast Replication in non-default table"""

        #
        # An (S,G).
        # one accepting interface, pg0, 2 forwarding interfaces
        #
        route_1_1_1_1_232_1_1_1 = VppIpMRoute(
            self,
            "1.1.1.1",
            "232.1.1.1", 64,
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE,
            [VppMRoutePath(self.pg8.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT),
             VppMRoutePath(self.pg1.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD),
             VppMRoutePath(self.pg2.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD)],
            table_id=10)
        route_1_1_1_1_232_1_1_1.add_vpp_config()

        #
        # a stream that matches the route for (1.1.1.1,232.1.1.1)
        #  small packets
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg8, "1.1.1.1", "232.1.1.1")
        self.pg8.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1 & 2
        self.verify_capture_ip4(self.pg1, tx)
        self.verify_capture_ip4(self.pg2, tx)

    def test_ip6_mcast_vrf(self):
        """ IPv6 Multicast Replication in non-default table"""

        #
        # An (S,G).
        # one accepting interface, pg0, 2 forwarding interfaces
        #
        route_2001_ff01_1 = VppIpMRoute(
            self,
            "2001::1",
            "ff01::1", 256,
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE,
            [VppMRoutePath(self.pg8.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT,
                           proto=DpoProto.DPO_PROTO_IP6),
             VppMRoutePath(self.pg1.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD,
                           proto=DpoProto.DPO_PROTO_IP6),
             VppMRoutePath(self.pg2.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD,
                           proto=DpoProto.DPO_PROTO_IP6)],
            table_id=10,
            is_ip6=1)
        route_2001_ff01_1.add_vpp_config()

        #
        # a stream that matches the route for (2001::1, ff00::1)
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip6(self.pg8, "2001::1", "ff01::1")
        self.pg8.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1, 2,
        self.verify_capture_ip6(self.pg1, tx)
        self.verify_capture_ip6(self.pg2, tx)

    def test_bidir(self):
        """ IP Multicast Bi-directional """

        #
        # A (*,G). The set of accepting interfaces matching the forwarding
        #
        route_232_1_1_1 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.1", 32,
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE,
            [VppMRoutePath(self.pg0.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT |
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD),
             VppMRoutePath(self.pg1.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT |
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD),
             VppMRoutePath(self.pg2.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT |
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD),
             VppMRoutePath(self.pg3.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT |
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD)])
        route_232_1_1_1.add_vpp_config()

        tx = self.create_stream_ip4(self.pg0, "1.1.1.1", "232.1.1.1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1, 2, 3, but not on pg0
        self.verify_capture_ip4(self.pg1, tx)
        self.verify_capture_ip4(self.pg2, tx)
        self.verify_capture_ip4(self.pg3, tx)
        self.pg0.assert_nothing_captured(
            remark="IP multicast packets forwarded on PG0")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
