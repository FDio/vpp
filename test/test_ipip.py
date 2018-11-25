#!/usr/bin/env python
"""IP{4,6} over IP{v,6} tunnel functional tests"""

import unittest
from scapy.layers.inet6 import IPv6, Ether, IP, UDP, IPv6ExtHdrFragment
from scapy.all import fragment, fragment6, RandShort, defragment6
from framework import VppTestCase, VppTestRunner
from vpp_ip import DPO_PROTO
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable
from socket import AF_INET, AF_INET6, inet_pton
from util import reassemble4


""" Testipip is a subclass of  VPPTestCase classes.

IPIP tests.

"""


class TestIPIP(VppTestCase):
    """ IPIP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPIP, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    def setUp(self):
        super(TestIPIP, self).setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()

    def tearDown(self):
        super(TestIPIP, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()

    def validate(self, rx, expected):
        self.assertEqual(rx, expected.__class__(expected))

    def generate_ip4_frags(self, payload_length, fragment_size):
        p_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
        p_payload = UDP(sport=1234, dport=1234) / self.payload(payload_length)
        p_ip4 = IP(src="1.2.3.4", dst=self.pg0.remote_ip4)
        outer_ip4 = (p_ether / IP(src=self.pg1.remote_ip4,
                                  id=RandShort(),
                                  dst=self.pg0.local_ip4) / p_ip4 / p_payload)
        frags = fragment(outer_ip4, fragment_size)
        p4_reply = (p_ip4 / p_payload)
        p4_reply.ttl -= 1
        return frags, p4_reply

    def test_ipip4(self):
        """ ip{v4,v6} over ip4 test """
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip6 = IPv6(src="1::1", dst="DEAD::1", nh='UDP', tc=42)
        p_ip4 = IP(src="1.2.3.4", dst="130.67.0.1", tos=42)
        p_payload = UDP(sport=1234, dport=1234)

        # IPv4 transport
        rv = self.vapi.ipip_add_tunnel(
            src_address=self.pg0.local_ip4n,
            dst_address=self.pg1.remote_ip4n,
            is_ipv6=0, tc_tos=0xFF)
        sw_if_index = rv.sw_if_index

        # Set interface up and enable IP on it
        self.vapi.sw_interface_set_flags(sw_if_index, 1)
        self.vapi.sw_interface_set_unnumbered(
            ip_sw_if_index=self.pg0.sw_if_index,
            sw_if_index=sw_if_index)

        # Add IPv4 and IPv6 routes via tunnel interface
        ip4_via_tunnel = VppIpRoute(
            self, "130.67.0.0", 16,
            [VppRoutePath("0.0.0.0",
                          sw_if_index,
                          proto=DPO_PROTO.IP4)], is_ip6=0)
        ip4_via_tunnel.add_vpp_config()

        ip6_via_tunnel = VppIpRoute(
            self, "dead::", 16,
            [VppRoutePath("::",
                          sw_if_index,
                          proto=DPO_PROTO.IP6)], is_ip6=1)
        ip6_via_tunnel.add_vpp_config()

        # IPv6 in to IPv4 tunnel
        p6 = (p_ether / p_ip6 / p_payload)
        p_inner_ip6 = p_ip6
        p_inner_ip6.hlim -= 1
        p6_reply = (IP(src=self.pg0.local_ip4, dst=self.pg1.remote_ip4,
                       proto='ipv6', id=0, tos=42) / p_inner_ip6 / p_payload)
        p6_reply.ttl -= 1
        rx = self.send_and_expect(self.pg0, p6*10, self.pg1)
        for p in rx:
            self.validate(p[1], p6_reply)

        # IPv4 in to IPv4 tunnel
        p4 = (p_ether / p_ip4 / p_payload)
        p_ip4_inner = p_ip4
        p_ip4_inner.ttl -= 1
        p4_reply = (IP(src=self.pg0.local_ip4, dst=self.pg1.remote_ip4,
                       tos=42) /
                    p_ip4_inner / p_payload)
        p4_reply.ttl -= 1
        p4_reply.id = 0
        rx = self.send_and_expect(self.pg0, p4*10, self.pg1)
        for p in rx:
            self.validate(p[1], p4_reply)

        # Decapsulation
        p_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)

        # IPv4 tunnel to IPv4
        p_ip4 = IP(src="1.2.3.4", dst=self.pg0.remote_ip4)
        p4 = (p_ether / IP(src=self.pg1.remote_ip4,
                           dst=self.pg0.local_ip4) / p_ip4 / p_payload)
        p4_reply = (p_ip4 / p_payload)
        p4_reply.ttl -= 1
        rx = self.send_and_expect(self.pg1, p4*10, self.pg0)
        for p in rx:
            self.validate(p[1], p4_reply)

        err = self.statistics.get_counter(
            '/err/ipip4-input/packets decapsulated')
        self.assertEqual(err, 10)

        # IPv4 tunnel to IPv6
        p_ip6 = IPv6(src="1:2:3::4", dst=self.pg0.remote_ip6)
        p6 = (p_ether / IP(src=self.pg1.remote_ip4,
                           dst=self.pg0.local_ip4) / p_ip6 / p_payload)
        p6_reply = (p_ip6 / p_payload)
        p6_reply.hlim = 63
        rx = self.send_and_expect(self.pg1, p6*10, self.pg0)
        for p in rx:
            self.validate(p[1], p6_reply)

        err = self.statistics.get_counter(
            '/err/ipip4-input/packets decapsulated')
        self.assertEqual(err, 20)

        #
        # Fragmentation / Reassembly and Re-fragmentation
        #
        rv = self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.pg1.sw_if_index,
            enable_ip4=1)

        # Send lots of fragments, verify reassembled packet
        frags, p4_reply = self.generate_ip4_frags(3131, 1400)
        f = []
        for i in range(0, 1000):
            f.extend(frags)
        self.pg1.add_stream(f)
        self.pg_enable_capture()
        self.pg_start()
        rx = self.pg0.get_capture(1000)

        for p in rx:
            self.validate(p[1], p4_reply)

        err = self.statistics.get_counter(
            '/err/ipip4-input/packets decapsulated')
        self.assertEqual(err, 1020)

        f = []
        r = []
        for i in range(1, 90):
            frags, p4_reply = self.generate_ip4_frags(i * 100, 1000)
            f.extend(frags)
            r.extend(p4_reply)
        self.pg_enable_capture()
        self.pg1.add_stream(f)
        self.pg_start()
        rx = self.pg0.get_capture(89)
        i = 0
        for p in rx:
            self.validate(p[1], r[i])
            i += 1

        # Now try with re-fragmentation
        #
        # Send fragments to tunnel head-end, for the tunnel head end
        # to reassemble and then refragment
        #
        self.vapi.sw_interface_set_mtu(self.pg0.sw_if_index, [576, 0, 0, 0])
        frags, p4_reply = self.generate_ip4_frags(3123, 1200)
        self.pg_enable_capture()
        self.pg1.add_stream(frags)
        self.pg_start()
        rx = self.pg0.get_capture(6)
        reass_pkt = reassemble4(rx)
        p4_reply.ttl -= 1
        p4_reply.id = 256
        self.validate(reass_pkt, p4_reply)

        self.vapi.sw_interface_set_mtu(self.pg0.sw_if_index, [1600, 0, 0, 0])
        frags, p4_reply = self.generate_ip4_frags(3123, 1200)
        self.pg_enable_capture()
        self.pg1.add_stream(frags)
        self.pg_start()
        rx = self.pg0.get_capture(2)
        reass_pkt = reassemble4(rx)
        p4_reply.ttl -= 1
        p4_reply.id = 512
        self.validate(reass_pkt, p4_reply)

    def test_ipip_create(self):
        """ ipip create / delete interface test """
        rv = self.vapi.ipip_add_tunnel(
            src_address=inet_pton(AF_INET, '1.2.3.4'),
            dst_address=inet_pton(AF_INET, '2.3.4.5'), is_ipv6=0)
        sw_if_index = rv.sw_if_index
        self.vapi.ipip_del_tunnel(sw_if_index)

    def test_ipip_vrf_create(self):
        """ ipip create / delete interface VRF test """

        t = VppIpTable(self, 20)
        t.add_vpp_config()
        rv = self.vapi.ipip_add_tunnel(
            src_address=inet_pton(AF_INET, '1.2.3.4'),
            dst_address=inet_pton(AF_INET, '2.3.4.5'), is_ipv6=0,
            table_id=20)
        sw_if_index = rv.sw_if_index
        self.vapi.ipip_del_tunnel(sw_if_index)

    def payload(self, len):
        return 'x' * len


class TestIPIP6(VppTestCase):
    """ IPIP6 Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPIP6, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    def setUp(self):
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()
        self.setup_tunnel()

    def tearDown(self):
        if not self.vpp_dead:
            self.destroy_tunnel()
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()
            super(TestIPIP6, self).tearDown()

    def setup_tunnel(self):
        # IPv6 transport
        rv = self.vapi.ipip_add_tunnel(
            src_address=self.pg0.local_ip6n,
            dst_address=self.pg1.remote_ip6n, tc_tos=255)

        sw_if_index = rv.sw_if_index
        self.tunnel_if_index = sw_if_index
        self.vapi.sw_interface_set_flags(sw_if_index, 1)
        self.vapi.sw_interface_set_unnumbered(
            ip_sw_if_index=self.pg0.sw_if_index, sw_if_index=sw_if_index)

        # Add IPv4 and IPv6 routes via tunnel interface
        ip4_via_tunnel = VppIpRoute(
            self, "130.67.0.0", 16,
            [VppRoutePath("0.0.0.0",
                          sw_if_index,
                          proto=DPO_PROTO.IP4)], is_ip6=0)
        ip4_via_tunnel.add_vpp_config()

        ip6_via_tunnel = VppIpRoute(
            self, "dead::", 16,
            [VppRoutePath("::",
                          sw_if_index,
                          proto=DPO_PROTO.IP6)], is_ip6=1)
        ip6_via_tunnel.add_vpp_config()

        self.tunnel_ip6_via_tunnel = ip6_via_tunnel
        self.tunnel_ip4_via_tunnel = ip4_via_tunnel

    def destroy_tunnel(self):
        # IPv6 transport
        self.tunnel_ip4_via_tunnel.remove_vpp_config()
        self.tunnel_ip6_via_tunnel.remove_vpp_config()

        rv = self.vapi.ipip_del_tunnel(sw_if_index=self.tunnel_if_index)

    def validate(self, rx, expected):
        self.assertEqual(rx, expected.__class__(expected))

    def generate_ip6_frags(self, payload_length, fragment_size):
        p_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
        p_payload = UDP(sport=1234, dport=1234) / self.payload(payload_length)
        p_ip6 = IPv6(src="1::1", dst=self.pg0.remote_ip6)
        outer_ip6 = (p_ether / IPv6(src=self.pg1.remote_ip6,
                                    dst=self.pg0.local_ip6) /
                     IPv6ExtHdrFragment() / p_ip6 / p_payload)
        frags = fragment6(outer_ip6, fragment_size)
        p6_reply = (p_ip6 / p_payload)
        p6_reply.hlim -= 1
        return frags, p6_reply

    def generate_ip6_hairpin_frags(self, payload_length, fragment_size):
        p_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
        p_payload = UDP(sport=1234, dport=1234) / self.payload(payload_length)
        p_ip6 = IPv6(src="1::1", dst="dead::1")
        outer_ip6 = (p_ether / IPv6(src=self.pg1.remote_ip6,
                                    dst=self.pg0.local_ip6) /
                     IPv6ExtHdrFragment() / p_ip6 / p_payload)
        frags = fragment6(outer_ip6, fragment_size)
        p_ip6.hlim -= 1
        p6_reply = (IPv6(src=self.pg0.local_ip6, dst=self.pg1.remote_ip6,
                         hlim=63) / p_ip6 / p_payload)

        return frags, p6_reply

    def test_encap(self):
        """ ip{v4,v6} over ip6 test encap """
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip6 = IPv6(src="1::1", dst="DEAD::1", tc=42, nh='UDP')
        p_ip4 = IP(src="1.2.3.4", dst="130.67.0.1", tos=42)
        p_payload = UDP(sport=1234, dport=1234)

        # Encapsulation
        # IPv6 in to IPv6 tunnel
        p6 = (p_ether / p_ip6 / p_payload)
        p6_reply = (IPv6(src=self.pg0.local_ip6, dst=self.pg1.remote_ip6,
                         hlim=64, tc=42) /
                    p_ip6 / p_payload)
        p6_reply[1].hlim -= 1
        rx = self.send_and_expect(self.pg0, p6*11, self.pg1)
        for p in rx:
            self.validate(p[1], p6_reply)

        # IPv4 in to IPv6 tunnel
        p4 = (p_ether / p_ip4 / p_payload)
        p4_reply = (IPv6(src=self.pg0.local_ip6,
                         dst=self.pg1.remote_ip6, hlim=64, tc=42) /
                    p_ip4 / p_payload)
        p4_reply[1].ttl -= 1
        rx = self.send_and_expect(self.pg0, p4*11, self.pg1)
        for p in rx:
            self.validate(p[1], p4_reply)

    def test_decap(self):
        """ ip{v4,v6} over ip6 test decap """

        p_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
        p_ip6 = IPv6(src="1::1", dst="DEAD::1", tc=42, nh='UDP')
        p_ip4 = IP(src="1.2.3.4", dst=self.pg0.remote_ip4)
        p_payload = UDP(sport=1234, dport=1234)

        # Decapsulation
        # IPv6 tunnel to IPv4

        p4 = (p_ether / IPv6(src=self.pg1.remote_ip6,
                             dst=self.pg0.local_ip6) / p_ip4 / p_payload)
        p4_reply = (p_ip4 / p_payload)
        p4_reply.ttl -= 1
        rx = self.send_and_expect(self.pg1, p4*11, self.pg0)
        for p in rx:
            self.validate(p[1], p4_reply)

        # IPv6 tunnel to IPv6
        p_ip6 = IPv6(src="1:2:3::4", dst=self.pg0.remote_ip6)
        p6 = (p_ether / IPv6(src=self.pg1.remote_ip6,
                             dst=self.pg0.local_ip6) / p_ip6 / p_payload)
        p6_reply = (p_ip6 / p_payload)
        p6_reply.hlim = 63
        rx = self.send_and_expect(self.pg1, p6*11, self.pg0)
        for p in rx:
            self.validate(p[1], p6_reply)

    def test_frag(self):
        """ ip{v4,v6} over ip6 test frag """

        p_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
        p_ip6 = IPv6(src="1::1", dst="DEAD::1", tc=42, nh='UDP')
        p_ip4 = IP(src="1.2.3.4", dst=self.pg0.remote_ip4)
        p_payload = UDP(sport=1234, dport=1234)

        #
        # Fragmentation / Reassembly and Re-fragmentation
        #
        rv = self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.pg1.sw_if_index,
            enable_ip6=1)

        # Send lots of fragments, verify reassembled packet
        before_cnt = self.statistics.get_counter(
            '/err/ipip6-input/packets decapsulated')
        frags, p6_reply = self.generate_ip6_frags(3131, 1400)
        f = []
        for i in range(0, 1000):
            f.extend(frags)
        self.pg1.add_stream(f)
        self.pg_enable_capture()
        self.pg_start()
        rx = self.pg0.get_capture(1000)

        for p in rx:
            self.validate(p[1], p6_reply)

        cnt = self.statistics.get_counter(
            '/err/ipip6-input/packets decapsulated')
        self.assertEqual(cnt, before_cnt + 1000)

        f = []
        r = []
        # TODO: Check out why reassembly of atomic fragments don't work
        for i in range(10, 90):
            frags, p6_reply = self.generate_ip6_frags(i * 100, 1000)
            f.extend(frags)
            r.extend(p6_reply)
        self.pg_enable_capture()
        self.pg1.add_stream(f)
        self.pg_start()
        rx = self.pg0.get_capture(80)
        i = 0
        for p in rx:
            self.validate(p[1], r[i])
            i += 1

        # Simple fragmentation
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [1280, 0, 0, 0])

        # IPv6 in to IPv6 tunnel
        p_payload = UDP(sport=1234, dport=1234) / self.payload(1300)

        p6 = (p_ether / p_ip6 / p_payload)
        p6_reply = (IPv6(src=self.pg0.local_ip6, dst=self.pg1.remote_ip6,
                         hlim=63, tc=42) /
                    p_ip6 / p_payload)
        p6_reply[1].hlim -= 1
        self.pg_enable_capture()
        self.pg0.add_stream(p6)
        self.pg_start()
        rx = self.pg1.get_capture(2)

        # Scapy defragment doesn't deal well with multiple layers
        # of samy type / Ethernet header first
        f = [p[1] for p in rx]
        reass_pkt = defragment6(f)
        self.validate(reass_pkt, p6_reply)

        # Now try with re-fragmentation
        #
        # Send large fragments to tunnel head-end, for the tunnel head end
        # to reassemble and then refragment out the tunnel again.
        # Hair-pinning
        #
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [1280, 0, 0, 0])
        frags, p6_reply = self.generate_ip6_hairpin_frags(8000, 1200)
        self.pg_enable_capture()
        self.pg1.add_stream(frags)
        self.pg_start()
        rx = self.pg1.get_capture(7)
        f = [p[1] for p in rx]
        reass_pkt = defragment6(f)
        p6_reply.id = 256
        self.validate(reass_pkt, p6_reply)

    def test_ipip_create(self):
        """ ipip create / delete interface test """
        rv = self.vapi.ipip_add_tunnel(
            src_address=inet_pton(AF_INET, '1.2.3.4'),
            dst_address=inet_pton(AF_INET, '2.3.4.5'), is_ipv6=0)
        sw_if_index = rv.sw_if_index
        self.vapi.ipip_del_tunnel(sw_if_index)

    def test_ipip_vrf_create(self):
        """ ipip create / delete interface VRF test """

        t = VppIpTable(self, 20)
        t.add_vpp_config()
        rv = self.vapi.ipip_add_tunnel(
            src_address=inet_pton(AF_INET, '1.2.3.4'),
            dst_address=inet_pton(AF_INET, '2.3.4.5'), is_ipv6=0,
            table_id=20)
        sw_if_index = rv.sw_if_index
        self.vapi.ipip_del_tunnel(sw_if_index)

    def payload(self, len):
        return 'x' * len


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
