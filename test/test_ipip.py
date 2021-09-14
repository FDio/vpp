#!/usr/bin/env python3
# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""IP{4,6} over IP{v,6} tunnel functional tests"""

import unittest
from scapy.layers.inet6 import IPv6, Ether, IP, UDP, IPv6ExtHdrFragment, Raw
from scapy.contrib.mpls import MPLS
from scapy.all import fragment, fragment6, RandShort, defragment6
from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable, FibPathProto, \
    VppMplsLabel, VppMplsRoute, VppMplsTable
from vpp_ipip_tun_interface import VppIpIpTunInterface
from vpp_teib import VppTeib
from vpp_papi import VppEnum
from socket import AF_INET, AF_INET6, inet_pton
from util import reassemble4

""" Testipip is a subclass of  VPPTestCase classes.

IPIP tests.

"""


def ipip_add_tunnel(test, src, dst, table_id=0, dscp=0x0,
                    flags=0):
    """ Add a IPIP tunnel """
    return test.vapi.ipip_add_tunnel(
        tunnel={
            'src': src,
            'dst': dst,
            'table_id': table_id,
            'instance': 0xffffffff,
            'dscp': dscp,
            'flags': flags
        }
    )

# the number of packets to send when injecting traffic.
# a multiple of 8 minus one, so we test all by 8/4/2/1 loops
N_PACKETS = 64 - 1


class TestIPIP(VppTestCase):
    """ IPIP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPIP, cls).setUpClass()
        cls.create_pg_interfaces(range(3))
        cls.interfaces = list(cls.pg_interfaces)

    @classmethod
    def tearDownClass(cls):
        super(TestIPIP, cls).tearDownClass()

    def setUp(self):
        super(TestIPIP, self).setUp()
        self.table = VppIpTable(self, 1, register=False)
        self.table.add_vpp_config()

        for i in self.interfaces:
            i.admin_up()

        self.pg2.set_table_ip4(self.table.table_id)
        for i in self.interfaces:
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
                i.set_table_ip4(0)
                i.admin_down()

        self.table.remove_vpp_config()

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

    def verify_ip4ip4_encaps(self, a, p_ip4s, p_ip4_encaps):
        for i, p_ip4 in enumerate(p_ip4s):
            p_ip4.dst = a
            p4 = (self.p_ether / p_ip4 / self.p_payload)
            p_ip4_inner = p_ip4
            p_ip4_inner.ttl -= 1
            p4_reply = (p_ip4_encaps[i] / p_ip4_inner / self.p_payload)
            p4_reply.ttl -= 1
            p4_reply.id = 0
            rx = self.send_and_expect(self.pg0, p4 * N_PACKETS, self.pg1)
            for p in rx:
                self.validate(p[1], p4_reply)
                self.assert_packet_checksums_valid(p)

    def verify_ip6ip4_encaps(self, a, p_ip6s, p_ip4_encaps):
        for i, p_ip6 in enumerate(p_ip6s):
            p_ip6.dst = a
            p6 = (self.p_ether / p_ip6 / self.p_payload)
            p_inner_ip6 = p_ip6
            p_inner_ip6.hlim -= 1
            p6_reply = (p_ip4_encaps[i] / p_inner_ip6 / self.p_payload)
            p6_reply.ttl -= 1
            rx = self.send_and_expect(self.pg0, p6 * N_PACKETS, self.pg1)
            for p in rx:
                self.validate(p[1], p6_reply)
                self.assert_packet_checksums_valid(p)

    def test_ipip4(self):
        """ ip{v4,v6} over ip4 test """

        self.pg1.generate_remote_hosts(5)
        self.pg1.configure_ipv4_neighbors()
        e = VppEnum.vl_api_tunnel_encap_decap_flags_t
        d = VppEnum.vl_api_ip_dscp_t
        self.p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        self.p_payload = UDP(sport=1234, dport=1234) / Raw(b'X' * 100)

        # create a TOS byte by shifting a DSCP code point 2 bits. those 2 bits
        # are for the ECN.
        dscp = d.IP_API_DSCP_AF31 << 2
        ecn = 3
        dscp_ecn = d.IP_API_DSCP_AF31 << 2 | ecn

        # IPv4 transport that copies the DCSP from the payload
        tun_dscp = VppIpIpTunInterface(
            self,
            self.pg0,
            self.pg0.local_ip4,
            self.pg1.remote_hosts[0].ip4,
            flags=e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP)
        tun_dscp.add_vpp_config()
        # IPv4 transport that copies the DCSP and ECN from the payload
        tun_dscp_ecn = VppIpIpTunInterface(
            self,
            self.pg0,
            self.pg0.local_ip4,
            self.pg1.remote_hosts[1].ip4,
            flags=(e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP |
                   e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN))
        tun_dscp_ecn.add_vpp_config()
        # IPv4 transport that copies the ECN from the payload and sets the
        # DF bit on encap. copies the ECN on decap
        tun_ecn = VppIpIpTunInterface(
            self,
            self.pg0,
            self.pg0.local_ip4,
            self.pg1.remote_hosts[2].ip4,
            flags=(e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN |
                   e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_SET_DF |
                   e.TUNNEL_API_ENCAP_DECAP_FLAG_DECAP_COPY_ECN))
        tun_ecn.add_vpp_config()
        # IPv4 transport that sets a fixed DSCP in the encap and copies
        # the DF bit
        tun = VppIpIpTunInterface(
            self,
            self.pg0,
            self.pg0.local_ip4,
            self.pg1.remote_hosts[3].ip4,
            dscp=d.IP_API_DSCP_AF11,
            flags=e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DF)
        tun.add_vpp_config()

        # array of all the tunnels
        tuns = [tun_dscp, tun_dscp_ecn, tun_ecn, tun]

        # addresses for prefixes routed via each tunnel
        a4s = ["" for i in range(len(tuns))]
        a6s = ["" for i in range(len(tuns))]

        # IP headers with each combination of DSCp/ECN tested
        p_ip6s = [IPv6(src="1::1", dst="DEAD::1", nh='UDP', tc=dscp),
                  IPv6(src="1::1", dst="DEAD::1", nh='UDP', tc=dscp_ecn),
                  IPv6(src="1::1", dst="DEAD::1", nh='UDP', tc=ecn),
                  IPv6(src="1::1", dst="DEAD::1", nh='UDP', tc=0xff)]
        p_ip4s = [IP(src="1.2.3.4", dst="130.67.0.1", tos=dscp, flags='DF'),
                  IP(src="1.2.3.4", dst="130.67.0.1", tos=dscp_ecn),
                  IP(src="1.2.3.4", dst="130.67.0.1", tos=ecn),
                  IP(src="1.2.3.4", dst="130.67.0.1", tos=0xff)]

        # Configure each tunnel
        for i, t in enumerate(tuns):
            # Set interface up and enable IP on it
            self.vapi.sw_interface_set_flags(t.sw_if_index, 1)
            self.vapi.sw_interface_set_unnumbered(
                sw_if_index=self.pg0.sw_if_index,
                unnumbered_sw_if_index=t.sw_if_index)

            # prefix for route / destination address for packets
            a4s[i] = "130.67.%d.0" % i
            a6s[i] = "dead:%d::" % i

            # Add IPv4 and IPv6 routes via tunnel interface
            ip4_via_tunnel = VppIpRoute(
                self, a4s[i], 24,
                [VppRoutePath("0.0.0.0",
                              t.sw_if_index,
                              proto=FibPathProto.FIB_PATH_NH_PROTO_IP4)])
            ip4_via_tunnel.add_vpp_config()

            ip6_via_tunnel = VppIpRoute(
                self, a6s[i], 64,
                [VppRoutePath("::",
                              t.sw_if_index,
                              proto=FibPathProto.FIB_PATH_NH_PROTO_IP6)])
            ip6_via_tunnel.add_vpp_config()

        #
        # Encapsulation
        #

        # tun_dscp copies only the dscp
        # expected TC values are thus only the DCSP value is present from the
        # inner
        exp_tcs = [dscp, dscp, 0, 0xfc]
        p_ip44_encaps = [IP(src=self.pg0.local_ip4,
                            dst=tun_dscp.dst,
                            tos=tc) for tc in exp_tcs]
        p_ip64_encaps = [IP(src=self.pg0.local_ip4,
                            dst=tun_dscp.dst,
                            proto='ipv6', id=0, tos=tc) for tc in exp_tcs]

        # IPv4 in to IPv4 tunnel
        self.verify_ip4ip4_encaps(a4s[0], p_ip4s, p_ip44_encaps)
        # IPv6 in to IPv4 tunnel
        self.verify_ip6ip4_encaps(a6s[0], p_ip6s, p_ip64_encaps)

        # tun_dscp_ecn copies the dscp and the ecn
        exp_tcs = [dscp, dscp_ecn, ecn, 0xff]
        p_ip44_encaps = [IP(src=self.pg0.local_ip4,
                            dst=tun_dscp_ecn.dst,
                            tos=tc) for tc in exp_tcs]
        p_ip64_encaps = [IP(src=self.pg0.local_ip4,
                            dst=tun_dscp_ecn.dst,
                            proto='ipv6', id=0, tos=tc) for tc in exp_tcs]

        self.verify_ip4ip4_encaps(a4s[1], p_ip4s, p_ip44_encaps)
        self.verify_ip6ip4_encaps(a6s[1], p_ip6s, p_ip64_encaps)

        # tun_ecn copies only the ecn and always sets DF
        exp_tcs = [0, ecn, ecn, ecn]
        p_ip44_encaps = [IP(src=self.pg0.local_ip4,
                            dst=tun_ecn.dst,
                            flags='DF', tos=tc) for tc in exp_tcs]
        p_ip64_encaps = [IP(src=self.pg0.local_ip4,
                            dst=tun_ecn.dst,
                            flags='DF', proto='ipv6', id=0, tos=tc)
                         for tc in exp_tcs]

        self.verify_ip4ip4_encaps(a4s[2], p_ip4s, p_ip44_encaps)
        self.verify_ip6ip4_encaps(a6s[2], p_ip6s, p_ip64_encaps)

        # tun sets a fixed dscp and copies DF
        fixed_dscp = tun.dscp << 2
        flags = ['DF', 0, 0, 0]
        p_ip44_encaps = [IP(src=self.pg0.local_ip4,
                            dst=tun.dst,
                            flags=f,
                            tos=fixed_dscp) for f in flags]
        p_ip64_encaps = [IP(src=self.pg0.local_ip4,
                            dst=tun.dst,
                            proto='ipv6', id=0,
                            tos=fixed_dscp) for i in range(len(p_ip4s))]

        self.verify_ip4ip4_encaps(a4s[3], p_ip4s, p_ip44_encaps)
        self.verify_ip6ip4_encaps(a6s[3], p_ip6s, p_ip64_encaps)

        #
        # Decapsulation
        #
        n_packets_decapped = 0
        self.p_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)

        # IPv4 tunnel to IPv4
        tcs = [0, dscp, dscp_ecn, ecn]

        # one overlay packet and all combinations of its encap
        p_ip4 = IP(src="1.2.3.4", dst=self.pg0.remote_ip4)
        p_ip4_encaps = [IP(src=tun.dst,
                           dst=self.pg0.local_ip4,
                           tos=tc) for tc in tcs]

        # for each encap tun will produce the same inner packet because it does
        # not copy up fields from the payload
        for p_ip4_encap in p_ip4_encaps:
            p4 = (self.p_ether / p_ip4_encap / p_ip4 / self.p_payload)
            p4_reply = (p_ip4 / self.p_payload)
            p4_reply.ttl -= 1
            rx = self.send_and_expect(self.pg1, p4 * N_PACKETS, self.pg0)
            n_packets_decapped += N_PACKETS
            for p in rx:
                self.validate(p[1], p4_reply)
                self.assert_packet_checksums_valid(p)

        err = self.statistics.get_err_counter(
            '/err/ipip4-input/packets decapsulated')
        self.assertEqual(err, n_packets_decapped)

        # tun_ecn copies the ECN bits from the encap to the inner
        p_ip4_encaps = [IP(src=tun_ecn.dst,
                           dst=self.pg0.local_ip4,
                           tos=tc) for tc in tcs]
        p_ip4_replys = [p_ip4.copy() for i in range(len(p_ip4_encaps))]
        p_ip4_replys[2].tos = ecn
        p_ip4_replys[3].tos = ecn
        for i, p_ip4_encap in enumerate(p_ip4_encaps):
            p4 = (self.p_ether / p_ip4_encap / p_ip4 / self.p_payload)
            p4_reply = (p_ip4_replys[i] / self.p_payload)
            p4_reply.ttl -= 1
            rx = self.send_and_expect(self.pg1, p4 * N_PACKETS, self.pg0)
            n_packets_decapped += N_PACKETS
            for p in rx:
                self.validate(p[1], p4_reply)
                self.assert_packet_checksums_valid(p)

        err = self.statistics.get_err_counter(
            '/err/ipip4-input/packets decapsulated')
        self.assertEqual(err, n_packets_decapped)

        # IPv4 tunnel to IPv6
        # for each encap tun will produce the same inner packet because it does
        # not copy up fields from the payload
        p_ip4_encaps = [IP(src=tun.dst,
                           dst=self.pg0.local_ip4,
                           tos=tc) for tc in tcs]
        p_ip6 = IPv6(src="1:2:3::4", dst=self.pg0.remote_ip6)
        for p_ip4_encap in p_ip4_encaps:
            p6 = (self.p_ether /
                  p_ip4_encap / p_ip6 /
                  self.p_payload)
            p6_reply = (p_ip6 / self.p_payload)
            p6_reply.hlim = 63
            rx = self.send_and_expect(self.pg1, p6 * N_PACKETS, self.pg0)
            n_packets_decapped += N_PACKETS
            for p in rx:
                self.validate(p[1], p6_reply)
                self.assert_packet_checksums_valid(p)

        err = self.statistics.get_err_counter(
            '/err/ipip4-input/packets decapsulated')
        self.assertEqual(err, n_packets_decapped)

        # IPv4 tunnel to IPv6
        # tun_ecn copies the ECN bits from the encap to the inner
        p_ip4_encaps = [IP(src=tun_ecn.dst,
                           dst=self.pg0.local_ip4,
                           tos=tc) for tc in tcs]
        p_ip6 = IPv6(src="1:2:3::4", dst=self.pg0.remote_ip6)
        p_ip6_replys = [p_ip6.copy() for i in range(len(p_ip4_encaps))]
        p_ip6_replys[2].tc = ecn
        p_ip6_replys[3].tc = ecn
        for i, p_ip4_encap in enumerate(p_ip4_encaps):
            p6 = (self.p_ether / p_ip4_encap / p_ip6 / self.p_payload)
            p6_reply = (p_ip6_replys[i] / self.p_payload)
            p6_reply.hlim = 63
            rx = self.send_and_expect(self.pg1, p6 * N_PACKETS, self.pg0)
            n_packets_decapped += N_PACKETS
            for p in rx:
                self.validate(p[1], p6_reply)
                self.assert_packet_checksums_valid(p)

        err = self.statistics.get_err_counter(
            '/err/ipip4-input/packets decapsulated')
        self.assertEqual(err, n_packets_decapped)

        #
        # Fragmentation / Reassembly and Re-fragmentation
        #
        rv = self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.pg1.sw_if_index,
            enable_ip4=1)

        self.vapi.ip_reassembly_set(timeout_ms=1000, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10000,
                                    is_ip6=0)

        # Send lots of fragments, verify reassembled packet
        frags, p4_reply = self.generate_ip4_frags(3131, 1400)
        f = []
        for i in range(0, 1000):
            f.extend(frags)
        self.pg1.add_stream(f)
        self.pg_enable_capture()
        self.pg_start()
        rx = self.pg0.get_capture(1000)
        n_packets_decapped += 1000

        for p in rx:
            self.validate(p[1], p4_reply)

        err = self.statistics.get_err_counter(
            '/err/ipip4-input/packets decapsulated')
        self.assertEqual(err, n_packets_decapped)

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
        p4_reply.id = 256
        self.validate(reass_pkt, p4_reply)

        self.vapi.sw_interface_set_mtu(self.pg0.sw_if_index, [1600, 0, 0, 0])
        frags, p4_reply = self.generate_ip4_frags(3123, 1200)
        self.pg_enable_capture()
        self.pg1.add_stream(frags)
        self.pg_start()
        rx = self.pg0.get_capture(2)
        reass_pkt = reassemble4(rx)
        p4_reply.id = 512
        self.validate(reass_pkt, p4_reply)

        # send large packets through the tunnel, expect them to be fragmented
        self.vapi.sw_interface_set_mtu(tun_dscp.sw_if_index, [600, 0, 0, 0])

        p4 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
              IP(src="1.2.3.4", dst="130.67.0.1", tos=42) /
              UDP(sport=1234, dport=1234) / Raw(b'Q' * 1000))
        rx = self.send_and_expect(self.pg0, p4 * 15, self.pg1, 30)
        inners = []
        for p in rx:
            inners.append(p[IP].payload)
        reass_pkt = reassemble4(inners)
        for p in reass_pkt:
            self.assert_packet_checksums_valid(p)
            self.assertEqual(p[IP].ttl, 63)

    def test_ipip_create(self):
        """ ipip create / delete interface test """
        rv = ipip_add_tunnel(self, '1.2.3.4', '2.3.4.5')
        sw_if_index = rv.sw_if_index
        self.vapi.ipip_del_tunnel(sw_if_index)

    def test_ipip_vrf_create(self):
        """ ipip create / delete interface VRF test """

        t = VppIpTable(self, 20)
        t.add_vpp_config()
        rv = ipip_add_tunnel(self, '1.2.3.4', '2.3.4.5', table_id=20)
        sw_if_index = rv.sw_if_index
        self.vapi.ipip_del_tunnel(sw_if_index)

    def payload(self, len):
        return 'x' * len

    def test_mipip4(self):
        """ p2mp IPv4 tunnel Tests """

        for itf in self.pg_interfaces[:2]:
            #
            # one underlay nh for each overlay/tunnel peer
            #
            itf.generate_remote_hosts(4)
            itf.configure_ipv4_neighbors()

            #
            # Create an p2mo IPIP tunnel.
            #  - set it admin up
            #  - assign an IP Addres
            #  - Add a route via the tunnel
            #
            ipip_if = VppIpIpTunInterface(self, itf,
                                          itf.local_ip4,
                                          "0.0.0.0",
                                          mode=(VppEnum.vl_api_tunnel_mode_t.
                                                TUNNEL_API_MODE_MP))
            ipip_if.add_vpp_config()
            ipip_if.admin_up()
            ipip_if.config_ip4()
            ipip_if.generate_remote_hosts(4)

            self.logger.info(self.vapi.cli("sh adj"))
            self.logger.info(self.vapi.cli("sh ip fib"))

            #
            # ensure we don't match to the tunnel if the source address
            # is all zeros
            #
            # tx = self.create_tunnel_stream_4o4(self.pg0,
            #                                    "0.0.0.0",
            #                                    itf.local_ip4,
            #                                    self.pg0.local_ip4,
            #                                    self.pg0.remote_ip4)
            # self.send_and_assert_no_replies(self.pg0, tx)

            #
            # for-each peer
            #
            for ii in range(1, 4):
                route_addr = "4.4.4.%d" % ii

                #
                # route traffic via the peer
                #
                route_via_tun = VppIpRoute(
                    self, route_addr, 32,
                    [VppRoutePath(ipip_if._remote_hosts[ii].ip4,
                                  ipip_if.sw_if_index)])
                route_via_tun.add_vpp_config()

                #
                # Add a TEIB entry resolves the peer
                #
                teib = VppTeib(self, ipip_if,
                               ipip_if._remote_hosts[ii].ip4,
                               itf._remote_hosts[ii].ip4)
                teib.add_vpp_config()
                self.logger.info(self.vapi.cli("sh adj nbr ipip0 %s" %
                                               ipip_if._remote_hosts[ii].ip4))

                #
                # Send a packet stream that is routed into the tunnel
                #  - packets are IPIP encapped
                #
                inner = (IP(dst=route_addr, src="5.5.5.5") /
                         UDP(sport=1234, dport=1234) /
                         Raw(b'0x44' * 100))
                tx_e = [(Ether(dst=self.pg0.local_mac,
                               src=self.pg0.remote_mac) /
                         inner) for x in range(63)]

                rxs = self.send_and_expect(self.pg0, tx_e, itf)

                for rx in rxs:
                    self.assertEqual(rx[IP].src, itf.local_ip4)
                    self.assertEqual(rx[IP].dst, itf._remote_hosts[ii].ip4)

                tx_i = [(Ether(dst=self.pg0.local_mac,
                               src=self.pg0.remote_mac) /
                         IP(src=itf._remote_hosts[ii].ip4,
                            dst=itf.local_ip4) /
                         IP(src=self.pg0.local_ip4, dst=self.pg0.remote_ip4) /
                         UDP(sport=1234, dport=1234) /
                         Raw(b'0x44' * 100)) for x in range(63)]

                self.logger.info(self.vapi.cli("sh ipip tunnel-hash"))
                rx = self.send_and_expect(self.pg0, tx_i, self.pg0)

                #
                # delete and re-add the TEIB
                #
                teib.remove_vpp_config()
                self.send_and_assert_no_replies(self.pg0, tx_e)
                self.send_and_assert_no_replies(self.pg0, tx_i)

                teib.add_vpp_config()
                rx = self.send_and_expect(self.pg0, tx_e, itf)
                for rx in rxs:
                    self.assertEqual(rx[IP].src, itf.local_ip4)
                    self.assertEqual(rx[IP].dst, itf._remote_hosts[ii].ip4)
                rx = self.send_and_expect(self.pg0, tx_i, self.pg0)

                #
                # we can also send to the peer's address
                #
                inner = (IP(dst=teib.peer, src="5.5.5.5") /
                         UDP(sport=1234, dport=1234) /
                         Raw(b'0x44' * 100))
                tx_e = [(Ether(dst=self.pg0.local_mac,
                               src=self.pg0.remote_mac) /
                         inner) for x in range(63)]

                rxs = self.send_and_expect(self.pg0, tx_e, itf)

            #
            # with all of the peers in place, swap the ip-table of
            # the ipip interface
            #
            table = VppIpTable(self, 2)
            table.add_vpp_config()

            ipip_if.unconfig_ip4()
            ipip_if.set_table_ip4(self.table.table_id)
            ipip_if.config_ip4()

            #
            # we should still be able to reach the peers from the new table
            #
            inner = (IP(dst=teib.peer, src="5.5.5.5") /
                     UDP(sport=1234, dport=1234) /
                     Raw(b'0x44' * 100))
            tx_e = [(Ether(dst=self.pg0.local_mac,
                           src=self.pg0.remote_mac) /
                     inner) for x in range(63)]

            rxs = self.send_and_expect(self.pg2, tx_e, itf)

            ipip_if.admin_down()
            ipip_if.unconfig_ip4()
            ipip_if.set_table_ip4(0)


class TestIPIP6(VppTestCase):
    """ IPIP6 Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPIP6, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    @classmethod
    def tearDownClass(cls):
        super(TestIPIP6, cls).tearDownClass()

    def setUp(self):
        super(TestIPIP6, self).setUp()
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
        rv = ipip_add_tunnel(self,
                             self.pg0.local_ip6,
                             self.pg1.remote_ip6)

        sw_if_index = rv.sw_if_index
        self.tunnel_if_index = sw_if_index
        self.vapi.sw_interface_set_flags(sw_if_index, 1)
        self.vapi.sw_interface_set_unnumbered(
            sw_if_index=self.pg0.sw_if_index,
            unnumbered_sw_if_index=sw_if_index)

        # Add IPv4 and IPv6 routes via tunnel interface
        ip4_via_tunnel = VppIpRoute(
            self, "130.67.0.0", 16,
            [VppRoutePath("0.0.0.0",
                          sw_if_index,
                          proto=FibPathProto.FIB_PATH_NH_PROTO_IP4)])
        ip4_via_tunnel.add_vpp_config()

        ip6_via_tunnel = VppIpRoute(
            self, "dead::", 16,
            [VppRoutePath("::",
                          sw_if_index,
                          proto=FibPathProto.FIB_PATH_NH_PROTO_IP6)])
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
                         hlim=64) /
                    p_ip6 / p_payload)
        p6_reply[1].hlim -= 1
        rx = self.send_and_expect(self.pg0, p6 * 11, self.pg1)
        for p in rx:
            self.validate(p[1], p6_reply)

        # IPv4 in to IPv6 tunnel
        p4 = (p_ether / p_ip4 / p_payload)
        p4_reply = (IPv6(src=self.pg0.local_ip6,
                         dst=self.pg1.remote_ip6, hlim=64) /
                    p_ip4 / p_payload)
        p4_reply[1].ttl -= 1
        rx = self.send_and_expect(self.pg0, p4 * 11, self.pg1)
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
        rx = self.send_and_expect(self.pg1, p4 * 11, self.pg0)
        for p in rx:
            self.validate(p[1], p4_reply)

        # IPv6 tunnel to IPv6
        p_ip6 = IPv6(src="1:2:3::4", dst=self.pg0.remote_ip6)
        p6 = (p_ether / IPv6(src=self.pg1.remote_ip6,
                             dst=self.pg0.local_ip6) / p_ip6 / p_payload)
        p6_reply = (p_ip6 / p_payload)
        p6_reply.hlim = 63
        rx = self.send_and_expect(self.pg1, p6 * 11, self.pg0)
        for p in rx:
            self.validate(p[1], p6_reply)

    def verify_ip4ip6_encaps(self, a, p_ip4s, p_ip6_encaps):
        for i, p_ip4 in enumerate(p_ip4s):
            p_ip4.dst = a
            p4 = (self.p_ether / p_ip4 / self.p_payload)
            p_ip4_inner = p_ip4
            p_ip4_inner.ttl -= 1
            p6_reply = (p_ip6_encaps[i] / p_ip4_inner / self.p_payload)
            rx = self.send_and_expect(self.pg0, p4 * N_PACKETS, self.pg1)
            for p in rx:
                self.validate(p[1], p6_reply)
                self.assert_packet_checksums_valid(p)

    def verify_ip6ip6_encaps(self, a, p_ip6s, p_ip6_encaps):
        for i, p_ip6 in enumerate(p_ip6s):
            p_ip6.dst = a
            p6 = (self.p_ether / p_ip6 / self.p_payload)
            p_inner_ip6 = p_ip6
            p_inner_ip6.hlim -= 1
            p6_reply = (p_ip6_encaps[i] / p_inner_ip6 / self.p_payload)
            rx = self.send_and_expect(self.pg0, p6 * N_PACKETS, self.pg1)
            for p in rx:
                self.validate(p[1], p6_reply)
                self.assert_packet_checksums_valid(p)

    def test_ipip6(self):
        """ ip{v4,v6} over ip6 test """

        # that's annoying
        self.destroy_tunnel()

        self.pg1.generate_remote_hosts(5)
        self.pg1.configure_ipv6_neighbors()
        e = VppEnum.vl_api_tunnel_encap_decap_flags_t
        d = VppEnum.vl_api_ip_dscp_t
        self.p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        self.p_payload = UDP(sport=1234, dport=1234) / Raw(b'X' * 100)

        # create a TOS byte by shifting a DSCP code point 2 bits. those 2 bits
        # are for the ECN.
        dscp = d.IP_API_DSCP_AF31 << 2
        ecn = 3
        dscp_ecn = d.IP_API_DSCP_AF31 << 2 | ecn

        # IPv4 transport that copies the DCSP from the payload
        tun_dscp = VppIpIpTunInterface(
            self,
            self.pg0,
            self.pg0.local_ip6,
            self.pg1.remote_hosts[0].ip6,
            flags=e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP)
        tun_dscp.add_vpp_config()
        # IPv4 transport that copies the DCSP and ECN from the payload
        tun_dscp_ecn = VppIpIpTunInterface(
            self,
            self.pg0,
            self.pg0.local_ip6,
            self.pg1.remote_hosts[1].ip6,
            flags=(e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP |
                   e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN))
        tun_dscp_ecn.add_vpp_config()
        # IPv4 transport that copies the ECN from the payload and sets the
        # DF bit on encap. copies the ECN on decap
        tun_ecn = VppIpIpTunInterface(
            self,
            self.pg0,
            self.pg0.local_ip6,
            self.pg1.remote_hosts[2].ip6,
            flags=(e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN |
                   e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_SET_DF |
                   e.TUNNEL_API_ENCAP_DECAP_FLAG_DECAP_COPY_ECN))
        tun_ecn.add_vpp_config()
        # IPv4 transport that sets a fixed DSCP in the encap and copies
        # the DF bit
        tun = VppIpIpTunInterface(
            self,
            self.pg0,
            self.pg0.local_ip6,
            self.pg1.remote_hosts[3].ip6,
            dscp=d.IP_API_DSCP_AF11,
            flags=e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DF)
        tun.add_vpp_config()

        # array of all the tunnels
        tuns = [tun_dscp, tun_dscp_ecn, tun_ecn, tun]

        # addresses for prefixes routed via each tunnel
        a4s = ["" for i in range(len(tuns))]
        a6s = ["" for i in range(len(tuns))]

        # IP headers for inner packets with each combination of DSCp/ECN tested
        p_ip6s = [IPv6(src="1::1", dst="DEAD::1", nh='UDP', tc=dscp),
                  IPv6(src="1::1", dst="DEAD::1", nh='UDP', tc=dscp_ecn),
                  IPv6(src="1::1", dst="DEAD::1", nh='UDP', tc=ecn),
                  IPv6(src="1::1", dst="DEAD::1", nh='UDP', tc=0xff)]
        p_ip4s = [IP(src="1.2.3.4", dst="130.67.0.1", tos=dscp, flags='DF'),
                  IP(src="1.2.3.4", dst="130.67.0.1", tos=dscp_ecn),
                  IP(src="1.2.3.4", dst="130.67.0.1", tos=ecn),
                  IP(src="1.2.3.4", dst="130.67.0.1", tos=0xff)]

        # Configure each tunnel
        for i, t in enumerate(tuns):
            # Set interface up and enable IP on it
            self.vapi.sw_interface_set_flags(t.sw_if_index, 1)
            self.vapi.sw_interface_set_unnumbered(
                sw_if_index=self.pg0.sw_if_index,
                unnumbered_sw_if_index=t.sw_if_index)

            # prefix for route / destination address for packets
            a4s[i] = "130.67.%d.0" % i
            a6s[i] = "dead:%d::" % i

            # Add IPv4 and IPv6 routes via tunnel interface
            ip4_via_tunnel = VppIpRoute(
                self, a4s[i], 24,
                [VppRoutePath("0.0.0.0",
                              t.sw_if_index,
                              proto=FibPathProto.FIB_PATH_NH_PROTO_IP4)])
            ip4_via_tunnel.add_vpp_config()

            ip6_via_tunnel = VppIpRoute(
                self, a6s[i], 64,
                [VppRoutePath("::",
                              t.sw_if_index,
                              proto=FibPathProto.FIB_PATH_NH_PROTO_IP6)])
            ip6_via_tunnel.add_vpp_config()

        #
        # Encapsulation
        #

        # tun_dscp copies only the dscp
        # expected TC values are thus only the DCSP value is present from the
        # inner
        exp_tcs = [dscp, dscp, 0, 0xfc]
        p_ip6_encaps = [IPv6(src=self.pg0.local_ip6,
                             dst=tun_dscp.dst,
                             tc=tc) for tc in exp_tcs]

        # IPv4 in to IPv4 tunnel
        self.verify_ip4ip6_encaps(a4s[0], p_ip4s, p_ip6_encaps)
        # IPv6 in to IPv4 tunnel
        self.verify_ip6ip6_encaps(a6s[0], p_ip6s, p_ip6_encaps)

        # tun_dscp_ecn copies the dscp and the ecn
        exp_tcs = [dscp, dscp_ecn, ecn, 0xff]
        p_ip6_encaps = [IPv6(src=self.pg0.local_ip6,
                             dst=tun_dscp_ecn.dst,
                             tc=tc) for tc in exp_tcs]

        self.verify_ip4ip6_encaps(a4s[1], p_ip4s, p_ip6_encaps)
        self.verify_ip6ip6_encaps(a6s[1], p_ip6s, p_ip6_encaps)

        # tun_ecn copies only the ecn and always sets DF
        exp_tcs = [0, ecn, ecn, ecn]
        p_ip6_encaps = [IPv6(src=self.pg0.local_ip6,
                             dst=tun_ecn.dst,
                             tc=tc) for tc in exp_tcs]

        self.verify_ip4ip6_encaps(a4s[2], p_ip4s, p_ip6_encaps)
        self.verify_ip6ip6_encaps(a6s[2], p_ip6s, p_ip6_encaps)

        # tun sets a fixed dscp
        fixed_dscp = tun.dscp << 2
        p_ip6_encaps = [IPv6(src=self.pg0.local_ip6,
                             dst=tun.dst,
                             tc=fixed_dscp) for i in range(len(p_ip4s))]

        self.verify_ip4ip6_encaps(a4s[3], p_ip4s, p_ip6_encaps)
        self.verify_ip6ip6_encaps(a6s[3], p_ip6s, p_ip6_encaps)

        #
        # Decapsulation
        #
        n_packets_decapped = self.statistics.get_err_counter(
            '/err/ipip6-input/packets decapsulated')

        self.p_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)

        # IPv6 tunnel to IPv4
        tcs = [0, dscp, dscp_ecn, ecn]

        # one overlay packet and all combinations of its encap
        p_ip4 = IP(src="1.2.3.4", dst=self.pg0.remote_ip4)
        p_ip6_encaps = [IPv6(src=tun.dst,
                             dst=self.pg0.local_ip6,
                             tc=tc) for tc in tcs]

        # for each encap tun will produce the same inner packet because it does
        # not copy up fields from the payload
        for p_ip6_encap in p_ip6_encaps:
            p6 = (self.p_ether / p_ip6_encap / p_ip4 / self.p_payload)
            p4_reply = (p_ip4 / self.p_payload)
            p4_reply.ttl -= 1
            rx = self.send_and_expect(self.pg1, p6 * N_PACKETS, self.pg0)
            n_packets_decapped += N_PACKETS
            for p in rx:
                self.validate(p[1], p4_reply)
                self.assert_packet_checksums_valid(p)

        err = self.statistics.get_err_counter(
            '/err/ipip6-input/packets decapsulated')
        self.assertEqual(err, n_packets_decapped)

        # tun_ecn copies the ECN bits from the encap to the inner
        p_ip6_encaps = [IPv6(src=tun_ecn.dst,
                             dst=self.pg0.local_ip6,
                             tc=tc) for tc in tcs]
        p_ip4_replys = [p_ip4.copy() for i in range(len(p_ip6_encaps))]
        p_ip4_replys[2].tos = ecn
        p_ip4_replys[3].tos = ecn
        for i, p_ip6_encap in enumerate(p_ip6_encaps):
            p6 = (self.p_ether / p_ip6_encap / p_ip4 / self.p_payload)
            p4_reply = (p_ip4_replys[i] / self.p_payload)
            p4_reply.ttl -= 1
            rx = self.send_and_expect(self.pg1, p6 * N_PACKETS, self.pg0)
            n_packets_decapped += N_PACKETS
            for p in rx:
                self.validate(p[1], p4_reply)
                self.assert_packet_checksums_valid(p)

        err = self.statistics.get_err_counter(
            '/err/ipip6-input/packets decapsulated')
        self.assertEqual(err, n_packets_decapped)

        # IPv6 tunnel to IPv6
        # for each encap tun will produce the same inner packet because it does
        # not copy up fields from the payload
        p_ip6_encaps = [IPv6(src=tun.dst,
                             dst=self.pg0.local_ip6,
                             tc=tc) for tc in tcs]
        p_ip6 = IPv6(src="1:2:3::4", dst=self.pg0.remote_ip6)
        for p_ip6_encap in p_ip6_encaps:
            p6 = (self.p_ether / p_ip6_encap / p_ip6 / self.p_payload)
            p6_reply = (p_ip6 / self.p_payload)
            p6_reply.hlim = 63
            rx = self.send_and_expect(self.pg1, p6 * N_PACKETS, self.pg0)
            n_packets_decapped += N_PACKETS
            for p in rx:
                self.validate(p[1], p6_reply)
                self.assert_packet_checksums_valid(p)

        err = self.statistics.get_err_counter(
            '/err/ipip6-input/packets decapsulated')
        self.assertEqual(err, n_packets_decapped)

        # IPv6 tunnel to IPv6
        # tun_ecn copies the ECN bits from the encap to the inner
        p_ip6_encaps = [IPv6(src=tun_ecn.dst,
                             dst=self.pg0.local_ip6,
                             tc=tc) for tc in tcs]
        p_ip6 = IPv6(src="1:2:3::4", dst=self.pg0.remote_ip6)
        p_ip6_replys = [p_ip6.copy() for i in range(len(p_ip6_encaps))]
        p_ip6_replys[2].tc = ecn
        p_ip6_replys[3].tc = ecn
        for i, p_ip6_encap in enumerate(p_ip6_encaps):
            p6 = (self.p_ether / p_ip6_encap / p_ip6 / self.p_payload)
            p6_reply = (p_ip6_replys[i] / self.p_payload)
            p6_reply.hlim = 63
            rx = self.send_and_expect(self.pg1, p6 * N_PACKETS, self.pg0)
            n_packets_decapped += N_PACKETS
            for p in rx:
                self.validate(p[1], p6_reply)
                self.assert_packet_checksums_valid(p)

        err = self.statistics.get_err_counter(
            '/err/ipip6-input/packets decapsulated')
        self.assertEqual(err, n_packets_decapped)

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

        self.vapi.ip_reassembly_set(timeout_ms=1000, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10000,
                                    is_ip6=1)

        # Send lots of fragments, verify reassembled packet
        before_cnt = self.statistics.get_err_counter(
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

        cnt = self.statistics.get_err_counter(
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
                         hlim=63) /
                    p_ip6 / p_payload)
        p6_reply[1].hlim -= 1
        self.pg_enable_capture()
        self.pg0.add_stream(p6)
        self.pg_start()
        rx = self.pg1.get_capture(2)

        # Scapy defragment doesn't deal well with multiple layers
        # of same type / Ethernet header first
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
        rv = ipip_add_tunnel(self, '1.2.3.4', '2.3.4.5')
        sw_if_index = rv.sw_if_index
        self.vapi.ipip_del_tunnel(sw_if_index)

    def test_ipip_vrf_create(self):
        """ ipip create / delete interface VRF test """

        t = VppIpTable(self, 20)
        t.add_vpp_config()
        rv = ipip_add_tunnel(self, '1.2.3.4', '2.3.4.5', table_id=20)
        sw_if_index = rv.sw_if_index
        self.vapi.ipip_del_tunnel(sw_if_index)

    def payload(self, len):
        return 'x' * len


class TestMPLS(VppTestCase):
    """ MPLS Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestMPLS, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    @classmethod
    def tearDownClass(cls):
        super(TestMPLS, cls).tearDownClass()

    def setUp(self):
        super(TestMPLS, self).setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()

    def tearDown(self):
        super(TestMPLS, self).tearDown()

        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()

    def test_mpls(self):
        """ MPLS over ip{6,4} test """

        tbl = VppMplsTable(self, 0)
        tbl.add_vpp_config()

        self.p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        self.p_payload = UDP(sport=1234, dport=1234) / Raw(b'X' * 100)
        f = FibPathProto

        # IPv4 transport
        tun4 = VppIpIpTunInterface(
            self,
            self.pg1,
            self.pg1.local_ip4,
            self.pg1.remote_ip4).add_vpp_config()
        tun4.admin_up()
        tun4.config_ip4()
        tun4.enable_mpls()

        # IPv6 transport
        tun6 = VppIpIpTunInterface(
            self,
            self.pg1,
            self.pg1.local_ip6,
            self.pg1.remote_ip6).add_vpp_config()
        tun6.admin_up()
        tun6.config_ip6()
        tun6.enable_mpls()

        # ip routes into the tunnels with output labels
        r4 = VppIpRoute(self, "1.1.1.1", 32,
                        [VppRoutePath(
                            tun4.remote_ip4,
                            tun4.sw_if_index,
                            labels=[VppMplsLabel(44)])]).add_vpp_config()
        r6 = VppIpRoute(self, "1::1", 128,
                        [VppRoutePath(
                            tun6.remote_ip6,
                            tun6.sw_if_index,
                            labels=[VppMplsLabel(66)])]).add_vpp_config()

        # deag MPLS routes from the tunnel
        r4 = VppMplsRoute(self, 44, 1,
                          [VppRoutePath(
                              self.pg0.remote_ip4,
                              self.pg0.sw_if_index)]).add_vpp_config()
        r6 = VppMplsRoute(self, 66, 1,
                          [VppRoutePath(
                              self.pg0.remote_ip6,
                              self.pg0.sw_if_index)],
                          eos_proto=f.FIB_PATH_NH_PROTO_IP6).add_vpp_config()

        #
        # Tunnel Encap
        #
        p4 = (self.p_ether / IP(src="2.2.2.2", dst="1.1.1.1") / self.p_payload)

        rxs = self.send_and_expect(self.pg0, p4 * N_PACKETS, self.pg1)

        for rx in rxs:
            self.assertEqual(rx[IP].src, self.pg1.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
            self.assertEqual(rx[MPLS].label, 44)
            inner = rx[MPLS].payload
            self.assertEqual(inner.src, "2.2.2.2")
            self.assertEqual(inner.dst, "1.1.1.1")

        p6 = (self.p_ether / IPv6(src="2::2", dst="1::1") / self.p_payload)

        rxs = self.send_and_expect(self.pg0, p6 * N_PACKETS, self.pg1)

        for rx in rxs:
            self.assertEqual(rx[IPv6].src, self.pg1.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg1.remote_ip6)
            self.assertEqual(rx[MPLS].label, 66)
            inner = rx[MPLS].payload
            self.assertEqual(inner.src, "2::2")
            self.assertEqual(inner.dst, "1::1")

        #
        # Tunnel Decap
        #
        p4 = (self.p_ether /
              IP(src=self.pg1.remote_ip4,
                 dst=self.pg1.local_ip4) /
              MPLS(label=44, ttl=4) /
              IP(src="1.1.1.1",
                 dst="2.2.2.2") /
              self.p_payload)

        rxs = self.send_and_expect(self.pg1, p4 * N_PACKETS, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IP].src, "1.1.1.1")
            self.assertEqual(rx[IP].dst, "2.2.2.2")

        p6 = (self.p_ether /
              IPv6(src=self.pg1.remote_ip6,
                   dst=self.pg1.local_ip6) /
              MPLS(label=66, ttl=4) /
              IPv6(src="1::1",
                   dst="2::2") /
              self.p_payload)

        rxs = self.send_and_expect(self.pg1, p6 * N_PACKETS, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IPv6].src, "1::1")
            self.assertEqual(rx[IPv6].dst, "2::2")

        tun4.disable_mpls()
        tun6.disable_mpls()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
