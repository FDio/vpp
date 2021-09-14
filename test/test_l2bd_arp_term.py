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
""" L2BD ARP term Test """

import unittest
import random
import copy

from socket import AF_INET, AF_INET6, inet_pton, inet_ntop

from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP
from scapy.utils6 import in6_getnsma, in6_getnsmac, in6_ptop, in6_islladdr, \
    in6_mactoifaceid, in6_ismaddr
from scapy.layers.inet6 import IPv6, UDP, ICMPv6ND_NS, ICMPv6ND_RS, \
    ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, getmacbyip6, ICMPv6MRD_Solicitation, \
    ICMPv6NDOptMTU, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo, \
    ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, ICMPv6DestUnreach, icmp6types

from framework import VppTestCase, VppTestRunner
from util import Host, ppp


class TestL2bdArpTerm(VppTestCase):
    """ L2BD arp termination Test Case """

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(TestL2bdArpTerm, cls).setUpClass()

        try:
            # Create pg interfaces
            n_bd = 1
            cls.ifs_per_bd = ifs_per_bd = 3
            n_ifs = n_bd * ifs_per_bd
            cls.create_pg_interfaces(range(n_ifs))

            # Set up all interfaces
            for i in cls.pg_interfaces:
                i.admin_up()

            cls.hosts = set()

        except Exception:
            super(TestL2bdArpTerm, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestL2bdArpTerm, cls).tearDownClass()

    def setUp(self):
        """
        Clear trace and packet infos before running each test.
        """
        self.reset_packet_infos()
        super(TestL2bdArpTerm, self).setUp()

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(TestL2bdArpTerm, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.ppcli("show l2fib verbose"))
        # many tests delete bridge-domain 1 as the last task.  don't output
        # the details of a non-existent bridge-domain.
        if self.vapi.l2_fib_table_dump(bd_id=1):
            self.logger.info(self.vapi.ppcli("show bridge-domain 1 detail"))

    def add_del_arp_term_hosts(self, entries, bd_id=1, is_add=1, is_ipv6=0):
        for e in entries:
            ip = e.ip4 if is_ipv6 == 0 else e.ip6
            self.vapi.bd_ip_mac_add_del(is_add=is_add,
                                        entry={
                                            'bd_id': bd_id,
                                            'ip': ip,
                                            'mac': e.mac})

    @classmethod
    def mac_list(cls, b6_range):
        return ["00:00:ca:fe:00:%02x" % b6 for b6 in b6_range]

    @classmethod
    def ip4_host(cls, subnet, host, mac):
        return Host(mac=mac,
                    ip4="172.17.1%02u.%u" % (subnet, host))

    @classmethod
    def ip4_hosts(cls, subnet, start, mac_list):
        return {cls.ip4_host(subnet, start + j, mac_list[j])
                for j in range(len(mac_list))}

    @classmethod
    def ip6_host(cls, subnet, host, mac):
        return Host(mac=mac,
                    ip6="fd01:%x::%x" % (subnet, host))

    @classmethod
    def ip6_hosts(cls, subnet, start, mac_list):
        return {cls.ip6_host(subnet, start + j, mac_list[j])
                for j in range(len(mac_list))}

    @classmethod
    def bd_swifs(cls, b):
        n = cls.ifs_per_bd
        start = (b - 1) * n
        return [cls.pg_interfaces[j] for j in range(start, start + n)]

    def bd_add_del(self, bd_id=1, is_add=1):
        if is_add:
            self.vapi.bridge_domain_add_del(bd_id=bd_id, is_add=is_add)
        for swif in self.bd_swifs(bd_id):
            swif_idx = swif.sw_if_index
            self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=swif_idx,
                                                 bd_id=bd_id, enable=is_add)
        if not is_add:
            self.vapi.bridge_domain_add_del(bd_id=bd_id, is_add=is_add)

    @classmethod
    def arp_req(cls, src_host, host):
        return (Ether(dst="ff:ff:ff:ff:ff:ff", src=src_host.mac) /
                ARP(op="who-has",
                    hwsrc=src_host.bin_mac,
                    pdst=host.ip4,
                    psrc=src_host.ip4))

    @classmethod
    def arp_reqs(cls, src_host, entries):
        return [cls.arp_req(src_host, e) for e in entries]

    @classmethod
    def garp_req(cls, host):
        return cls.arp_req(host, host)

    @classmethod
    def garp_reqs(cls, entries):
        return [cls.garp_req(e) for e in entries]

    def arp_resp_host(self, src_host, arp_resp):
        ether = arp_resp[Ether]
        self.assertEqual(ether.dst, src_host.mac)

        arp = arp_resp[ARP]
        self.assertEqual(arp.hwtype, 1)
        self.assertEqual(arp.ptype, 0x800)
        self.assertEqual(arp.hwlen, 6)
        self.assertEqual(arp.plen, 4)
        arp_opts = {"who-has": 1, "is-at": 2}
        self.assertEqual(arp.op, arp_opts["is-at"])
        self.assertEqual(arp.hwdst, src_host.mac)
        self.assertEqual(arp.pdst, src_host.ip4)
        return Host(mac=arp.hwsrc, ip4=arp.psrc)

    def arp_resp_hosts(self, src_host, pkts):
        return {self.arp_resp_host(src_host, p) for p in pkts}

    @staticmethod
    def inttoip4(ip):
        o1 = int(ip / 16777216) % 256
        o2 = int(ip / 65536) % 256
        o3 = int(ip / 256) % 256
        o4 = int(ip) % 256
        return '%s.%s.%s.%s' % (o1, o2, o3, o4)

    def arp_event_host(self, e):
        return Host(str(e.mac), ip4=str(e.ip))

    def arp_event_hosts(self, evs):
        return {self.arp_event_host(e) for e in evs}

    def nd_event_host(self, e):
        return Host(str(e.mac), ip6=str(e.ip))

    def nd_event_hosts(self, evs):
        return {self.nd_event_host(e) for e in evs}

    @classmethod
    def ns_req(cls, src_host, host):
        nsma = in6_getnsma(inet_pton(AF_INET6, "fd10::ffff"))
        d = inet_ntop(AF_INET6, nsma)
        return (Ether(dst="ff:ff:ff:ff:ff:ff", src=src_host.mac) /
                IPv6(dst=d, src=src_host.ip6) /
                ICMPv6ND_NS(tgt=host.ip6) /
                ICMPv6NDOptSrcLLAddr(lladdr=src_host.mac))

    @classmethod
    def ns_reqs_dst(cls, entries, dst_host):
        return [cls.ns_req(e, dst_host) for e in entries]

    @classmethod
    def ns_reqs_src(cls, src_host, entries):
        return [cls.ns_req(src_host, e) for e in entries]

    def na_resp_host(self, src_host, rx):
        self.assertEqual(rx[Ether].dst, src_host.mac)
        self.assertEqual(in6_ptop(rx[IPv6].dst),
                         in6_ptop(src_host.ip6))

        self.assertTrue(rx.haslayer(ICMPv6ND_NA))
        self.assertTrue(rx.haslayer(ICMPv6NDOptDstLLAddr))

        na = rx[ICMPv6ND_NA]
        return Host(mac=na.lladdr, ip6=na.tgt)

    def na_resp_hosts(self, src_host, pkts):
        return {self.na_resp_host(src_host, p) for p in pkts}

    def set_bd_flags(self, bd_id, **args):
        """
        Enable/disable defined feature(s) of the bridge domain.

        :param int bd_id: Bridge domain ID.
        :param list args: List of feature/status pairs. Allowed features: \
        learn, forward, flood, uu_flood and arp_term. Status False means \
        disable, status True means enable the feature.
        :raise: ValueError in case of unknown feature in the input.
        """
        for flag in args:
            if flag == "learn":
                feature_bitmap = 1 << 0
            elif flag == "forward":
                feature_bitmap = 1 << 1
            elif flag == "flood":
                feature_bitmap = 1 << 2
            elif flag == "uu_flood":
                feature_bitmap = 1 << 3
            elif flag == "arp_term":
                feature_bitmap = 1 << 4
            else:
                raise ValueError("Unknown feature used: %s" % flag)
            is_set = 1 if args[flag] else 0
            self.vapi.bridge_flags(bd_id=bd_id, is_set=is_set,
                                   flags=feature_bitmap)
        self.logger.info("Bridge domain ID %d updated" % bd_id)

    def verify_arp(self, src_host, req_hosts, resp_hosts, bd_id=1):
        reqs = self.arp_reqs(src_host, req_hosts)

        for swif in self.bd_swifs(bd_id):
            swif.add_stream(reqs)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for swif in self.bd_swifs(bd_id):
            resp_pkts = swif.get_capture(len(resp_hosts))
            resps = self.arp_resp_hosts(src_host, resp_pkts)
            self.assertEqual(len(resps ^ resp_hosts), 0)

    def verify_nd(self, src_host, req_hosts, resp_hosts, bd_id=1):
        reqs = self.ns_reqs_src(src_host, req_hosts)

        for swif in self.bd_swifs(bd_id):
            swif.add_stream(reqs)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for swif in self.bd_swifs(bd_id):
            resp_pkts = swif.get_capture(len(resp_hosts))
            resps = self.na_resp_hosts(src_host, resp_pkts)
            self.assertEqual(len(resps ^ resp_hosts), 0)

    def test_l2bd_arp_term_01(self):
        """ L2BD arp term - add 5 hosts, verify arp responses
        """
        src_host = self.ip4_host(50, 50, "00:00:11:22:33:44")
        self.bd_add_del(1, is_add=1)
        self.set_bd_flags(1, arp_term=True, flood=False,
                          uu_flood=False, learn=False)
        macs = self.mac_list(range(1, 5))
        hosts = self.ip4_hosts(4, 1, macs)
        self.add_del_arp_term_hosts(hosts, is_add=1)

        self.verify_arp(src_host, hosts, hosts)
        type(self).hosts = hosts

    def test_l2bd_arp_term_02(self):
        """ L2BD arp term - delete 3 hosts, verify arp responses
        """
        src_host = self.ip4_host(50, 50, "00:00:11:22:33:44")
        macs = self.mac_list(range(1, 3))
        deleted = self.ip4_hosts(4, 1, macs)
        self.add_del_arp_term_hosts(deleted, is_add=0)
        remaining = self.hosts - deleted
        self.verify_arp(src_host, self.hosts, remaining)
        type(self).hosts = remaining
        self.bd_add_del(1, is_add=0)

    def test_l2bd_arp_term_03(self):
        """ L2BD arp term - recreate BD1, readd 3 hosts, verify arp responses
        """
        src_host = self.ip4_host(50, 50, "00:00:11:22:33:44")
        self.bd_add_del(1, is_add=1)
        self.set_bd_flags(1, arp_term=True, flood=False,
                          uu_flood=False, learn=False)
        macs = self.mac_list(range(1, 3))
        readded = self.ip4_hosts(4, 1, macs)
        self.add_del_arp_term_hosts(readded, is_add=1)
        self.verify_arp(src_host, self.hosts | readded, readded)
        type(self).hosts = readded

    def test_l2bd_arp_term_04(self):
        """ L2BD arp term - 2 IP4 addrs per host
        """
        src_host = self.ip4_host(50, 50, "00:00:11:22:33:44")
        macs = self.mac_list(range(1, 3))
        sub5_hosts = self.ip4_hosts(5, 1, macs)
        self.add_del_arp_term_hosts(sub5_hosts, is_add=1)
        hosts = self.hosts | sub5_hosts
        self.verify_arp(src_host, hosts, hosts)
        type(self).hosts = hosts
        self.bd_add_del(1, is_add=0)

    def test_l2bd_arp_term_05(self):
        """ L2BD arp term - create and update 10 IP4-mac pairs
        """
        src_host = self.ip4_host(50, 50, "00:00:11:22:33:44")
        self.bd_add_del(1, is_add=1)
        self.set_bd_flags(1, arp_term=True, flood=False,
                          uu_flood=False, learn=False)
        macs1 = self.mac_list(range(10, 20))
        hosts1 = self.ip4_hosts(5, 1, macs1)
        self.add_del_arp_term_hosts(hosts1, is_add=1)
        self.verify_arp(src_host, hosts1, hosts1)
        macs2 = self.mac_list(range(20, 30))
        hosts2 = self.ip4_hosts(5, 1, macs2)
        self.add_del_arp_term_hosts(hosts2, is_add=1)
        self.verify_arp(src_host, hosts1, hosts2)
        self.bd_add_del(1, is_add=0)

    def test_l2bd_arp_term_06(self):
        """ L2BD arp/ND term - hosts with both ip4/ip6
        """
        src_host4 = self.ip4_host(50, 50, "00:00:11:22:33:44")
        src_host6 = self.ip6_host(50, 50, "00:00:11:22:33:44")
        self.bd_add_del(1, is_add=1)
        # enable flood to make sure requests are not flooded
        self.set_bd_flags(1, arp_term=True, flood=True,
                          uu_flood=False, learn=False)
        macs = self.mac_list(range(10, 20))
        hosts6 = self.ip6_hosts(5, 1, macs)
        hosts4 = self.ip4_hosts(5, 1, macs)
        self.add_del_arp_term_hosts(hosts4, is_add=1)
        self.add_del_arp_term_hosts(hosts6, is_add=1, is_ipv6=1)
        self.verify_arp(src_host4, hosts4, hosts4)
        self.verify_nd(src_host6, hosts6, hosts6)
        self.bd_add_del(1, is_add=0)

    def test_l2bd_arp_term_07(self):
        """ L2BD ND term - Add and Del hosts, verify ND replies
        """
        src_host6 = self.ip6_host(50, 50, "00:00:11:22:33:44")
        self.bd_add_del(1, is_add=1)
        self.set_bd_flags(1, arp_term=True, flood=False,
                          uu_flood=False, learn=False)
        macs = self.mac_list(range(10, 20))
        hosts6 = self.ip6_hosts(5, 1, macs)
        self.add_del_arp_term_hosts(hosts6, is_add=1, is_ipv6=1)
        self.verify_nd(src_host6, hosts6, hosts6)
        del_macs = self.mac_list(range(10, 15))
        deleted = self.ip6_hosts(5, 1, del_macs)
        self.add_del_arp_term_hosts(deleted, is_add=0, is_ipv6=1)
        self.verify_nd(src_host6, hosts6, hosts6 - deleted)
        self.bd_add_del(1, is_add=0)

    def test_l2bd_arp_term_08(self):
        """ L2BD ND term - Add and update IP+mac, verify ND replies
        """
        src_host = self.ip6_host(50, 50, "00:00:11:22:33:44")
        self.bd_add_del(1, is_add=1)
        self.set_bd_flags(1, arp_term=True, flood=False,
                          uu_flood=False, learn=False)
        macs1 = self.mac_list(range(10, 20))
        hosts = self.ip6_hosts(5, 1, macs1)
        self.add_del_arp_term_hosts(hosts, is_add=1, is_ipv6=1)
        self.verify_nd(src_host, hosts, hosts)
        macs2 = self.mac_list(range(20, 30))
        updated = self.ip6_hosts(5, 1, macs2)
        self.add_del_arp_term_hosts(updated, is_add=1, is_ipv6=1)
        self.verify_nd(src_host, hosts, updated)
        self.bd_add_del(1, is_add=0)

    def test_l2bd_arp_term_09(self):
        """ L2BD arp term - send garps, verify arp event reports
        """
        self.vapi.want_l2_arp_term_events(enable=1)
        self.bd_add_del(1, is_add=1)
        self.set_bd_flags(1, arp_term=True, flood=False,
                          uu_flood=False, learn=False)
        macs = self.mac_list(range(90, 95))
        hosts = self.ip4_hosts(5, 1, macs)

        garps = self.garp_reqs(hosts)
        self.bd_swifs(1)[0].add_stream(garps)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        evs = [self.vapi.wait_for_event(1, "l2_arp_term_event")
               for i in range(len(hosts))]
        ev_hosts = self.arp_event_hosts(evs)
        self.assertEqual(len(ev_hosts ^ hosts), 0)

    def test_l2bd_arp_term_10(self):
        """ L2BD arp term - send duplicate garps, verify suppression
        """
        macs = self.mac_list(range(70, 71))
        hosts = self.ip4_hosts(6, 1, macs)

        """ send the packet 5 times expect one event
        """
        garps = self.garp_reqs(hosts) * 5
        self.bd_swifs(1)[0].add_stream(garps)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        evs = [self.vapi.wait_for_event(1, "l2_arp_term_event")
               for i in range(len(hosts))]
        ev_hosts = self.arp_event_hosts(evs)
        self.assertEqual(len(ev_hosts ^ hosts), 0)

    def test_l2bd_arp_term_11(self):
        """ L2BD arp term - disable ip4 arp events,send garps, verify no events
        """
        self.vapi.want_l2_arp_term_events(enable=0)
        macs = self.mac_list(range(90, 95))
        hosts = self.ip4_hosts(5, 1, macs)

        garps = self.garp_reqs(hosts)
        self.bd_swifs(1)[0].add_stream(garps)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.sleep(1)
        self.assertEqual(len(self.vapi.collect_events()), 0)
        self.bd_add_del(1, is_add=0)

    def test_l2bd_arp_term_12(self):
        """ L2BD ND term - send NS packets verify reports
        """
        self.vapi.want_l2_arp_term_events(enable=1)
        dst_host = self.ip6_host(50, 50, "00:00:11:22:33:44")
        self.bd_add_del(1, is_add=1)
        self.set_bd_flags(1, arp_term=True, flood=False,
                          uu_flood=False, learn=False)
        macs = self.mac_list(range(10, 15))
        hosts = self.ip6_hosts(5, 1, macs)
        reqs = self.ns_reqs_dst(hosts, dst_host)
        self.bd_swifs(1)[0].add_stream(reqs)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        evs = [self.vapi.wait_for_event(2, "l2_arp_term_event")
               for i in range(len(hosts))]
        ev_hosts = self.nd_event_hosts(evs)
        self.assertEqual(len(ev_hosts ^ hosts), 0)

    def test_l2bd_arp_term_13(self):
        """ L2BD ND term - send duplicate ns, verify suppression
        """
        dst_host = self.ip6_host(50, 50, "00:00:11:22:33:44")
        macs = self.mac_list(range(16, 17))
        hosts = self.ip6_hosts(5, 1, macs)
        reqs = self.ns_reqs_dst(hosts, dst_host) * 5
        self.bd_swifs(1)[0].add_stream(reqs)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        evs = [self.vapi.wait_for_event(2, "l2_arp_term_event")
               for i in range(len(hosts))]
        ev_hosts = self.nd_event_hosts(evs)
        self.assertEqual(len(ev_hosts ^ hosts), 0)

    def test_l2bd_arp_term_14(self):
        """ L2BD ND term - disable ip4 arp events,send ns, verify no events
        """
        self.vapi.want_l2_arp_term_events(enable=0)
        dst_host = self.ip6_host(50, 50, "00:00:11:22:33:44")
        macs = self.mac_list(range(10, 15))
        hosts = self.ip6_hosts(5, 1, macs)
        reqs = self.ns_reqs_dst(hosts, dst_host)
        self.bd_swifs(1)[0].add_stream(reqs)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.sleep(1)
        self.assertEqual(len(self.vapi.collect_events()), 0)
        self.bd_add_del(1, is_add=0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
