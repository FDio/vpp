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

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto, INVALID_INDEX
from itertools import product

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.inet6 import IPv6, IPerror6, ICMPv6DestUnreach
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply

import struct

from ipaddress import ip_address, ip_network, \
    IPv4Address, IPv6Address, IPv4Network, IPv6Network

from vpp_object import VppObject
from vpp_papi import VppEnum

N_PKTS = 15
N_REMOTE_HOSTS = 3

SRC = 0
DST = 1


class CnatCommonTestCase(VppTestCase):
    """ CNat common test class """

    #
    # turn the scanner off whilst testing otherwise sessions
    # will time out
    #
    extra_vpp_punt_config = ["cnat", "{",
                             "session-db-buckets", "64",
                             "session-cleanup-timeout", "0.1",
                             "session-max-age", "1",
                             "tcp-max-age", "1",
                             "scanner", "off", "}"]

    @classmethod
    def setUpClass(cls):
        super(CnatCommonTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(CnatCommonTestCase, cls).tearDownClass()


class Endpoint(object):
    """ CNat endpoint """

    def __init__(self, pg=None, pgi=None, port=0, is_v6=False, ip=None):
        self.port = port
        self.is_v6 = is_v6
        self.sw_if_index = INVALID_INDEX
        if pg is not None and pgi is not None:
            # pg interface specified and remote index
            self.ip = self.get_ip46(pg.remote_hosts[pgi])
        elif pg is not None:
            self.ip = None
            self.sw_if_index = pg.sw_if_index
        elif ip is not None:
            self.ip = ip
        else:
            self.ip = "::" if self.is_v6 else "0.0.0.0"

    def get_ip46(self, obj):
        if self.is_v6:
            return obj.ip6
        return obj.ip4

    def udpate(self, **kwargs):
        self.__init__(**kwargs)

    def _vpp_if_af(self):
        if self.is_v6:
            return VppEnum.vl_api_address_family_t.ADDRESS_IP6
        return VppEnum.vl_api_address_family_t.ADDRESS_IP4

    def encode(self):
        return {'addr': self.ip,
                'port': self.port,
                'sw_if_index': self.sw_if_index,
                'if_af': self._vpp_if_af()}

    def __str__(self):
        return ("%s:%d" % (self.ip, self.port))


class Translation(VppObject):

    def __init__(self, test, iproto, vip, paths):
        self._test = test
        self.vip = vip
        self.iproto = iproto
        self.paths = paths
        self.id = None

    def __str__(self):
        return ("%s %s %s" % (self.vip, self.iproto, self.paths))

    def _vl4_proto(self):
        ip_proto = VppEnum.vl_api_ip_proto_t
        return {
            UDP: ip_proto.IP_API_PROTO_UDP,
            TCP: ip_proto.IP_API_PROTO_TCP,
        }[self.iproto]

    def _encoded_paths(self):
        return [{'src_ep': src.encode(),
                 'dst_ep': dst.encode()} for (src, dst) in self.paths]

    def add_vpp_config(self):
        r = self._test.vapi.cnat_translation_update(
            {'vip': self.vip.encode(),
             'ip_proto': self._vl4_proto(),
             'n_paths': len(self.paths),
             'paths': self._encoded_paths()})
        self._test.registry.register(self, self._test.logger)
        self.id = r.id
        return self

    def remove_vpp_config(self):
        assert(self.id is not None)
        self._test.vapi.cnat_translation_del(id=self.id)
        return self

    def query_vpp_config(self):
        for t in self._test.vapi.cnat_translation_dump():
            if self.id == t.translation.id:
                return t.translation
        return None


class CnatTestContext(object):
    """
    Usage :

    ctx = CnatTestContext(self, TCP, is_v6=True)

    # send pg0.remote[0]:1234 -> pg1.remote[0]:6661
    ctx.cnat_send(self.pg0, 0, 1234, self.pg1, 0, 6661)

    # We expect this to be NATed as
    # pg2.remote[0]:<anyport> -> pg1.remote[0]:6661
    ctx.cnat_expect(self.pg2, 0, None, self.pg1, 0, 6661)

    # After running cnat_expect, we can send back the received packet
    # and expect it be 'unnated' so that we get the original packet
    ctx.cnat_send_return().cnat_expect_return()

    # same thing for ICMP errors
    ctx.cnat_send_icmp_return_error().cnat_expect_icmp_error_return()
    """

    def __init__(self, test, L4PROTO, is_v6):
        self.L4PROTO = L4PROTO
        self.is_v6 = is_v6
        self._test = test

    def get_ip46(self, obj):
        if self.is_v6:
            return obj.ip6
        return obj.ip4

    @property
    def IP46(self):
        return IPv6 if self.is_v6 else IP

    def cnat_send(self, src_pg, src_id, src_port, dst_pg, dst_id, dst_port,
                  no_replies=False):
        if isinstance(src_id, int):
            self.src_addr = self.get_ip46(src_pg.remote_hosts[src_id])
        else:
            self.dst_addr = src_id
        if isinstance(dst_id, int):
            self.dst_addr = self.get_ip46(dst_pg.remote_hosts[dst_id])
        else:
            self.dst_addr = dst_id
        self.src_port = src_port  # also ICMP id
        self.dst_port = dst_port  # also ICMP type

        if self.L4PROTO in [TCP, UDP]:
            l4 = self.L4PROTO(sport=self.src_port, dport=self.dst_port)
        elif self.L4PROTO in [ICMP] and not self.is_v6:
            l4 = self.L4PROTO(id=self.src_port, type=self.dst_port)
        elif self.L4PROTO in [ICMP] and self.is_v6:
            l4 = ICMPv6EchoRequest(id=self.src_port)
        p1 = (Ether(src=src_pg.remote_mac,
                    dst=src_pg.local_mac) /
              self.IP46(src=self.src_addr, dst=self.dst_addr) /
              l4 /
              Raw())

        if no_replies:
            self._test.send_and_assert_no_replies(src_pg, p1 * N_PKTS, dst_pg)
        else:
            self.rxs = self._test.send_and_expect(src_pg, p1 * N_PKTS, dst_pg)
        self.expected_src_pg = src_pg
        self.expected_dst_pg = dst_pg
        return self

    def cnat_expect(self, src_pg, src_id, src_port, dst_pg, dst_id, dst_port):
        if isinstance(src_id, int):
            self.expect_src_addr = self.get_ip46(src_pg.remote_hosts[src_id])
        else:
            self.expect_src_addr = src_id
        if isinstance(dst_id, int):
            self.expect_dst_addr = self.get_ip46(dst_pg.remote_hosts[dst_id])
        else:
            self.expect_dst_addr = dst_id
        self.expect_src_port = src_port
        self.expect_dst_port = dst_port

        if self.expect_src_port is None:
            if self.L4PROTO in [TCP, UDP]:
                self.expect_src_port = self.rxs[0][self.L4PROTO].sport
            elif self.L4PROTO in [ICMP] and not self.is_v6:
                self.expect_src_port = self.rxs[0][self.L4PROTO].id
            elif self.L4PROTO in [ICMP] and self.is_v6:
                self.expect_src_port = self.rxs[0][ICMPv6EchoRequest].id

        for rx in self.rxs:
            self._test.assert_packet_checksums_valid(rx)
            self._test.assertEqual(rx[self.IP46].dst, self.expect_dst_addr)
            self._test.assertEqual(rx[self.IP46].src, self.expect_src_addr)
            if self.L4PROTO in [TCP, UDP]:
                self._test.assertEqual(
                    rx[self.L4PROTO].dport, self.expect_dst_port)
                self._test.assertEqual(
                    rx[self.L4PROTO].sport, self.expect_src_port)
            elif self.L4PROTO in [ICMP] and not self.is_v6:
                self._test.assertEqual(
                    rx[self.L4PROTO].type, self.expect_dst_port)
                self._test.assertEqual(
                    rx[self.L4PROTO].id, self.expect_src_port)
            elif self.L4PROTO in [ICMP] and self.is_v6:
                self._test.assertEqual(
                    rx[ICMPv6EchoRequest].id, self.expect_src_port)
        return self

    def cnat_send_return(self):
        """This sends the return traffic"""
        if self.L4PROTO in [TCP, UDP]:
            l4 = self.L4PROTO(sport=self.expect_dst_port,
                              dport=self.expect_src_port)
        elif self.L4PROTO in [ICMP] and not self.is_v6:
            # icmp type 0 if echo reply
            l4 = self.L4PROTO(id=self.expect_src_port, type=0)
        elif self.L4PROTO in [ICMP] and self.is_v6:
            l4 = ICMPv6EchoReply(id=self.expect_src_port)
        src_mac = self.expected_dst_pg.remote_mac
        p1 = (Ether(src=src_mac, dst=self.expected_dst_pg.local_mac) /
              self.IP46(src=self.expect_dst_addr, dst=self.expect_src_addr) /
              l4 /
              Raw())

        self.return_rxs = self._test.send_and_expect(
            self.expected_dst_pg, p1 * N_PKTS, self.expected_src_pg)
        return self

    def cnat_expect_return(self):
        for rx in self.return_rxs:
            self._test.assert_packet_checksums_valid(rx)
            self._test.assertEqual(rx[self.IP46].dst, self.src_addr)
            self._test.assertEqual(rx[self.IP46].src, self.dst_addr)
            if self.L4PROTO in [TCP, UDP]:
                self._test.assertEqual(rx[self.L4PROTO].dport, self.src_port)
                self._test.assertEqual(rx[self.L4PROTO].sport, self.dst_port)
            elif self.L4PROTO in [ICMP] and not self.is_v6:
                # icmp type 0 if echo reply
                self._test.assertEqual(rx[self.L4PROTO].type, 0)
                self._test.assertEqual(rx[self.L4PROTO].id, self.src_port)
            elif self.L4PROTO in [ICMP] and self.is_v6:
                self._test.assertEqual(rx[ICMPv6EchoReply].id, self.src_port)
        return self

    def cnat_send_icmp_return_error(self):
        """
        This called after cnat_expect will send an icmp error
        on the reverse path
        """
        ICMPelem = ICMPv6DestUnreach(code=1) if self.is_v6 else ICMP(type=11)
        InnerIP = self.rxs[0][self.IP46]
        p1 = (
            Ether(src=self.expected_dst_pg.remote_mac,
                  dst=self.expected_dst_pg.local_mac) /
            self.IP46(src=self.expect_dst_addr, dst=self.expect_src_addr) /
            ICMPelem / InnerIP)
        self.return_rxs = self._test.send_and_expect(
            self.expected_dst_pg, p1 * N_PKTS, self.expected_src_pg)
        return self

    def cnat_expect_icmp_error_return(self):
        ICMP46 = ICMPv6DestUnreach if self.is_v6 else ICMP
        IP46err = IPerror6 if self.is_v6 else IPerror
        L4err = TCPerror if self.L4PROTO is TCP else UDPerror
        for rx in self.return_rxs:
            self._test.assert_packet_checksums_valid(rx)
            self._test.assertEqual(rx[self.IP46].dst, self.src_addr)
            self._test.assertEqual(rx[self.IP46].src, self.dst_addr)
            self._test.assertEqual(rx[ICMP46][IP46err].src, self.src_addr)
            self._test.assertEqual(rx[ICMP46][IP46err].dst, self.dst_addr)
            self._test.assertEqual(
                rx[ICMP46][IP46err][L4err].sport, self.src_port)
            self._test.assertEqual(
                rx[ICMP46][IP46err][L4err].dport, self.dst_port)
        return self

# -------------------------------------------------------------------
# -------------------------------------------------------------------
# -------------------------------------------------------------------
# -------------------------------------------------------------------


class TestCNatTranslation(CnatCommonTestCase):
    """ CNat Translation """

    @classmethod
    def setUpClass(cls):
        super(TestCNatTranslation, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCNatTranslation, cls).tearDownClass()

    def setUp(self):
        super(TestCNatTranslation, self).setUp()

        self.create_pg_interfaces(range(3))
        self.pg0.generate_remote_hosts(N_REMOTE_HOSTS)
        self.pg1.generate_remote_hosts(N_REMOTE_HOSTS)

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            i.configure_ipv4_neighbors()
            i.configure_ipv6_neighbors()

    def tearDown(self):
        for translation in self.translations:
            translation.remove_vpp_config()

        self.vapi.cnat_session_purge()
        self.assertFalse(self.vapi.cnat_session_dump())

        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestCNatTranslation, self).tearDown()

    def cnat_translation(self):
        """ CNat Translation """
        self.logger.info(self.vapi.cli("sh cnat client"))
        self.logger.info(self.vapi.cli("sh cnat translation"))

        for nbr, translation in enumerate(self.translations):
            vip = translation.vip

            #
            # Test Flows to the VIP
            #
            ctx = CnatTestContext(self, translation.iproto, vip.is_v6)
            for src_pgi, sport in product(range(N_REMOTE_HOSTS), [1234, 1233]):
                # from client to vip
                ctx.cnat_send(self.pg0, src_pgi, sport,
                              self.pg1, vip.ip, vip.port)
                dst_port = translation.paths[0][DST].port
                ctx.cnat_expect(self.pg0, src_pgi, sport,
                                self.pg1, nbr, dst_port)
                # from vip to client
                ctx.cnat_send_return().cnat_expect_return()

                #
                # packets to the VIP that do not match a
                # translation are dropped
                #
                ctx.cnat_send(self.pg0, src_pgi, sport, self.pg1,
                              vip.ip, 6666, no_replies=True)

                #
                # packets from the VIP that do not match a
                # session are forwarded
                #
                ctx.cnat_send(self.pg1, nbr, 6666, self.pg0, src_pgi, sport)
                ctx.cnat_expect(self.pg1, nbr, 6666, self.pg0, src_pgi, sport)

            #
            # modify the translation to use a different backend
            #
            old_dst_port = translation.paths[0][DST].port
            translation.paths[0][DST].udpate(
                pg=self.pg2, pgi=0, port=5000, is_v6=vip.is_v6)
            translation.add_vpp_config()

            #
            # existing flows follow the old path
            #
            for src_pgi in range(N_REMOTE_HOSTS):
                for sport in [1234, 1233]:
                    # from client to vip
                    ctx.cnat_send(self.pg0, src_pgi, sport,
                                  self.pg1, vip.ip, vip.port)
                    ctx.cnat_expect(self.pg0, src_pgi, sport,
                                    self.pg1, nbr, old_dst_port)
                    # from vip to client
                    ctx.cnat_send_return().cnat_expect_return()

            #
            # new flows go to the new backend
            #
            for src_pgi in range(N_REMOTE_HOSTS):
                ctx.cnat_send(self.pg0, src_pgi, 9999,
                              self.pg2, vip.ip, vip.port)
                ctx.cnat_expect(self.pg0, src_pgi, 9999, self.pg2, 0, 5000)

            self.logger.info(self.vapi.cli("sh cnat session verbose"))

        #
        # turn the scanner back on and wait until the sessions
        # all disapper
        #
        self.vapi.cli("test cnat scanner on")

        n_tries = 0
        sessions = self.vapi.cnat_session_dump()
        while (len(sessions) and n_tries < 100):
            n_tries += 1
            sessions = self.vapi.cnat_session_dump()
            self.sleep(2)
            self.logger.info(self.vapi.cli("show cnat session verbose"))

        self.assertTrue(n_tries < 100)
        self.vapi.cli("test cnat scanner off")

        #
        # load some flows again and purge
        #
        for translation in self.translations:
            vip = translation.vip
            ctx = CnatTestContext(self, translation.iproto, vip.is_v6)
            for src_pgi in range(N_REMOTE_HOSTS):
                for sport in [1234, 1233]:
                    # from client to vip
                    ctx.cnat_send(self.pg0, src_pgi, sport,
                                  self.pg2, vip.ip, vip.port)
                    ctx.cnat_expect(self.pg0, src_pgi,
                                    sport, self.pg2, 0, 5000)

    def _test_icmp(self):

        #
        # Testing ICMP
        #
        for nbr, translation in enumerate(self.translations):
            vip = translation.vip
            ctx = CnatTestContext(self, translation.iproto, vip.is_v6)

            #
            # NATing ICMP errors
            #
            ctx.cnat_send(self.pg0, 0, 1234, self.pg1, vip.ip, vip.port)
            dst_port = translation.paths[0][DST].port
            ctx.cnat_expect(self.pg0, 0, 1234, self.pg1, nbr, dst_port)
            ctx.cnat_send_icmp_return_error().cnat_expect_icmp_error_return()

            #
            # ICMP errors with no VIP associated should not be
            # modified
            #
            ctx.cnat_send(self.pg0, 0, 1234, self.pg2, 0, vip.port)
            dst_port = translation.paths[0][DST].port
            ctx.cnat_expect(self.pg0, 0, 1234, self.pg2, 0, vip.port)
            ctx.cnat_send_icmp_return_error().cnat_expect_icmp_error_return()

    def _make_translations_v4(self):
        self.translations = []
        self.translations.append(Translation(
            self, TCP, Endpoint(ip="30.0.0.1", port=5555, is_v6=False),
            [(
                Endpoint(is_v6=False),
                Endpoint(pg=self.pg1, pgi=0, port=4001, is_v6=False),
            )]
        ).add_vpp_config())
        self.translations.append(Translation(
            self, TCP, Endpoint(ip="30.0.0.2", port=5554, is_v6=False),
            [(
                Endpoint(is_v6=False),
                Endpoint(pg=self.pg1, pgi=1, port=4002, is_v6=False),
            )]
        ).add_vpp_config())
        self.translations.append(Translation(
            self, UDP, Endpoint(ip="30.0.0.2", port=5553, is_v6=False),
            [(
                Endpoint(is_v6=False),
                Endpoint(pg=self.pg1, pgi=2, port=4003, is_v6=False),
            )]
        ).add_vpp_config())

    def _make_translations_v6(self):
        self.translations = []
        self.translations.append(Translation(
            self, TCP, Endpoint(ip="30::1", port=5555, is_v6=True),
            [(
                Endpoint(is_v6=True),
                Endpoint(pg=self.pg1, pgi=0, port=4001, is_v6=True),
            )]
        ).add_vpp_config())
        self.translations.append(Translation(
            self, TCP, Endpoint(ip="30::2", port=5554, is_v6=True),
            [(
                Endpoint(is_v6=True),
                Endpoint(pg=self.pg1, pgi=1, port=4002, is_v6=True),
            )]
        ).add_vpp_config())
        self.translations.append(Translation(
            self, UDP, Endpoint(ip="30::2", port=5553, is_v6=True),
            [(
                Endpoint(is_v6=True),
                Endpoint(pg=self.pg1, pgi=2, port=4003, is_v6=True),
            )]
        ).add_vpp_config())

    def test_icmp4(self):
        # """ CNat Translation icmp v4 """
        self._make_translations_v4()
        self._test_icmp()

    def test_icmp6(self):
        # """ CNat Translation icmp v6 """
        self._make_translations_v6()
        self._test_icmp()

    def test_cnat6(self):
        # """ CNat Translation ipv6 """
        self._make_translations_v6()
        self.cnat_translation()

    def test_cnat4(self):
        # """ CNat Translation ipv4 """
        self._make_translations_v4()
        self.cnat_translation()


class TestCNatSourceNAT(CnatCommonTestCase):
    """ CNat Source NAT """

    @classmethod
    def setUpClass(cls):
        super(TestCNatSourceNAT, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCNatSourceNAT, cls).tearDownClass()

    def _enable_disable_snat(self, is_enable=True):
        self.vapi.cnat_set_snat_addresses(
            snat_ip4=self.pg2.remote_hosts[0].ip4,
            snat_ip6=self.pg2.remote_hosts[0].ip6,
            sw_if_index=INVALID_INDEX)
        self.vapi.feature_enable_disable(
            enable=1 if is_enable else 0,
            arc_name="ip6-unicast",
            feature_name="cnat-snat-ip6",
            sw_if_index=self.pg0.sw_if_index)
        self.vapi.feature_enable_disable(
            enable=1 if is_enable else 0,
            arc_name="ip4-unicast",
            feature_name="cnat-snat-ip4",
            sw_if_index=self.pg0.sw_if_index)

        policie_tbls = VppEnum.vl_api_cnat_snat_policy_table_t
        self.vapi.cnat_set_snat_policy(
            policy=VppEnum.vl_api_cnat_snat_policies_t.CNAT_POLICY_IF_PFX)
        for i in self.pg_interfaces:
            self.vapi.cnat_snat_policy_add_del_if(
                sw_if_index=i.sw_if_index, is_add=1 if is_enable else 0,
                table=policie_tbls.CNAT_POLICY_INCLUDE_V6)
            self.vapi.cnat_snat_policy_add_del_if(
                sw_if_index=i.sw_if_index, is_add=1 if is_enable else 0,
                table=policie_tbls.CNAT_POLICY_INCLUDE_V4)

    def setUp(self):
        super(TestCNatSourceNAT, self).setUp()

        self.create_pg_interfaces(range(3))
        self.pg1.generate_remote_hosts(2)

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            i.configure_ipv6_neighbors()
            i.configure_ipv4_neighbors()

        self._enable_disable_snat(is_enable=True)

    def tearDown(self):
        self._enable_disable_snat(is_enable=True)

        self.vapi.cnat_session_purge()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestCNatSourceNAT, self).tearDown()

    def test_snat_v6(self):
        # """ CNat Source Nat v6 """
        self.sourcenat_test_tcp_udp_conf(TCP, is_v6=True)
        self.sourcenat_test_tcp_udp_conf(UDP, is_v6=True)
        self.sourcenat_test_icmp_echo_conf(is_v6=True)

    def test_snat_v4(self):
        # """ CNat Source Nat v4 """
        self.sourcenat_test_tcp_udp_conf(TCP)
        self.sourcenat_test_tcp_udp_conf(UDP)
        self.sourcenat_test_icmp_echo_conf()

    def sourcenat_test_icmp_echo_conf(self, is_v6=False):
        ctx = CnatTestContext(self, ICMP, is_v6=is_v6)
        # 8 is ICMP type echo (v4 only)
        ctx.cnat_send(self.pg0, 0, 0xfeed, self.pg1, 0, 8)
        ctx.cnat_expect(self.pg2, 0, None, self.pg1, 0, 8)
        ctx.cnat_send_return().cnat_expect_return()

    def sourcenat_test_tcp_udp_conf(self, L4PROTO, is_v6=False):
        ctx = CnatTestContext(self, L4PROTO, is_v6)
        # we should source NAT
        ctx.cnat_send(self.pg0, 0, 1234, self.pg1, 0, 6661)
        ctx.cnat_expect(self.pg2, 0, None, self.pg1, 0, 6661)
        ctx.cnat_send_return().cnat_expect_return()

        # exclude dst address of pg1.1 from snat
        if is_v6:
            exclude_prefix = ip_network(
                "%s/100" % self.pg1.remote_hosts[1].ip6, strict=False)
        else:
            exclude_prefix = ip_network(
                "%s/16" % self.pg1.remote_hosts[1].ip4, strict=False)

        # add remote host to exclude list
        self.vapi.cnat_snat_policy_add_del_exclude_pfx(
            prefix=exclude_prefix, is_add=1)

        # We should not source NAT the id=1
        ctx.cnat_send(self.pg0, 0, 1234, self.pg1, 1, 6661)
        ctx.cnat_expect(self.pg0, 0, 1234, self.pg1, 1, 6661)
        ctx.cnat_send_return().cnat_expect_return()

        # But we should source NAT the id=0
        ctx.cnat_send(self.pg0, 0, 1234, self.pg1, 0, 6661)
        ctx.cnat_expect(self.pg2, 0, None, self.pg1, 0, 6661)
        ctx.cnat_send_return().cnat_expect_return()

        # remove remote host from exclude list
        self.vapi.cnat_snat_policy_add_del_exclude_pfx(
            prefix=exclude_prefix, is_add=0)
        self.vapi.cnat_session_purge()

        # We should source NAT again
        ctx.cnat_send(self.pg0, 0, 1234, self.pg1, 1, 6661)
        ctx.cnat_expect(self.pg2, 0, None, self.pg1, 1, 6661)
        ctx.cnat_send_return().cnat_expect_return()

        # test return ICMP error nating
        ctx.cnat_send(self.pg0, 0, 1234, self.pg1, 1, 6661)
        ctx.cnat_expect(self.pg2, 0, None, self.pg1, 1, 6661)
        ctx.cnat_send_icmp_return_error().cnat_expect_icmp_error_return()

        self.vapi.cnat_session_purge()


class TestCNatDHCP(CnatCommonTestCase):
    """ CNat Translation """

    @classmethod
    def setUpClass(cls):
        super(TestCNatDHCP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCNatDHCP, cls).tearDownClass()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()
        super(TestCNatDHCP, self).tearDown()

    def make_addr(self, sw_if_index, addr_id, is_v6):
        if is_v6:
            return "fd01:%x::%u" % (sw_if_index, addr_id + 1)
        return "172.16.%u.%u" % (sw_if_index, addr_id)

    def make_prefix(self, sw_if_index, addr_id, is_v6):
        if is_v6:
            return "%s/128" % self.make_addr(sw_if_index, addr_id, is_v6)
        return "%s/32" % self.make_addr(sw_if_index, addr_id, is_v6)

    def check_resolved(self, tr, addr_id, is_v6=False):
        qt = tr.query_vpp_config()
        self.assertEqual(str(qt.vip.addr), self.make_addr(
            tr.vip.sw_if_index, addr_id, is_v6))
        self.assertEqual(len(qt.paths), len(tr.paths))
        for path_tr, path_qt in zip(tr.paths, qt.paths):
            src_qt = path_qt.src_ep
            dst_qt = path_qt.dst_ep
            src_tr, dst_tr = path_tr
            self.assertEqual(str(src_qt.addr), self.make_addr(
                src_tr.sw_if_index, addr_id, is_v6))
            self.assertEqual(str(dst_qt.addr), self.make_addr(
                dst_tr.sw_if_index, addr_id, is_v6))

    def add_del_address(self, pg, addr_id, is_add=True, is_v6=False):
        self.vapi.sw_interface_add_del_address(
            sw_if_index=pg.sw_if_index,
            prefix=self.make_prefix(pg.sw_if_index, addr_id, is_v6),
            is_add=1 if is_add else 0)

    def _test_dhcp_v46(self, is_v6):
        self.create_pg_interfaces(range(4))
        for i in self.pg_interfaces:
            i.admin_up()
        paths = [
            (Endpoint(pg=self.pg1, is_v6=is_v6),
             Endpoint(pg=self.pg2, is_v6=is_v6)),
            (Endpoint(pg=self.pg1, is_v6=is_v6),
             Endpoint(pg=self.pg3, is_v6=is_v6))
        ]
        ep = Endpoint(pg=self.pg0, is_v6=is_v6)
        t = Translation(self, TCP, ep, paths).add_vpp_config()
        # Add an address on every interface
        # and check it is reflected in the cnat config
        for pg in self.pg_interfaces:
            self.add_del_address(pg, addr_id=0, is_add=True, is_v6=is_v6)
        self.check_resolved(t, addr_id=0, is_v6=is_v6)
        # Add a new address on every interface, remove the old one
        # and check it is reflected in the cnat config
        for pg in self.pg_interfaces:
            self.add_del_address(pg, addr_id=1, is_add=True, is_v6=is_v6)
            self.add_del_address(pg, addr_id=0, is_add=False, is_v6=is_v6)
        self.check_resolved(t, addr_id=1, is_v6=is_v6)
        # remove the configuration
        for pg in self.pg_interfaces:
            self.add_del_address(pg, addr_id=1, is_add=False, is_v6=is_v6)
        t.remove_vpp_config()

    def test_dhcp_v4(self):
        self._test_dhcp_v46(False)

    def test_dhcp_v6(self):
        self._test_dhcp_v46(True)

    def test_dhcp_snat(self):
        self.create_pg_interfaces(range(1))
        for i in self.pg_interfaces:
            i.admin_up()
        self.vapi.cnat_set_snat_addresses(sw_if_index=self.pg0.sw_if_index)
        # Add an address on every interface
        # and check it is reflected in the cnat config
        for pg in self.pg_interfaces:
            self.add_del_address(pg, addr_id=0, is_add=True, is_v6=False)
            self.add_del_address(pg, addr_id=0, is_add=True, is_v6=True)
        r = self.vapi.cnat_get_snat_addresses()
        self.assertEqual(str(r.snat_ip4), self.make_addr(
            self.pg0.sw_if_index, addr_id=0, is_v6=False))
        self.assertEqual(str(r.snat_ip6), self.make_addr(
            self.pg0.sw_if_index, addr_id=0, is_v6=True))
        # Add a new address on every interface, remove the old one
        # and check it is reflected in the cnat config
        for pg in self.pg_interfaces:
            self.add_del_address(pg, addr_id=1, is_add=True, is_v6=False)
            self.add_del_address(pg, addr_id=1, is_add=True, is_v6=True)
            self.add_del_address(pg, addr_id=0, is_add=False, is_v6=False)
            self.add_del_address(pg, addr_id=0, is_add=False, is_v6=True)
        r = self.vapi.cnat_get_snat_addresses()
        self.assertEqual(str(r.snat_ip4), self.make_addr(
            self.pg0.sw_if_index, addr_id=1, is_v6=False))
        self.assertEqual(str(r.snat_ip6), self.make_addr(
            self.pg0.sw_if_index, addr_id=1, is_v6=True))
        # remove the configuration
        for pg in self.pg_interfaces:
            self.add_del_address(pg, addr_id=1, is_add=False, is_v6=False)
            self.add_del_address(pg, addr_id=1, is_add=False, is_v6=True)
        self.vapi.cnat_set_snat_addresses(sw_if_index=INVALID_INDEX)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
