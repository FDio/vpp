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
"""ACL plugin Test Case HLD:
"""

import unittest
import random

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.inet6 import IPv6ExtHdrFragment
from framework import VppTestCase, VppTestRunner
from framework import tag_fixme_vpp_workers
from util import Host, ppp
from ipaddress import IPv4Network, IPv6Network

from vpp_lo_interface import VppLoInterface
from vpp_acl import AclRule, VppAcl, VppAclInterface, VppEtypeWhitelist
from vpp_ip import INVALID_INDEX


@tag_fixme_vpp_workers
class TestACLplugin(VppTestCase):
    """ ACL plugin Test Case """

    # traffic types
    IP = 0
    ICMP = 1

    # IP version
    IPRANDOM = -1
    IPV4 = 0
    IPV6 = 1

    # rule types
    DENY = 0
    PERMIT = 1

    # supported protocols
    proto = [[6, 17], [1, 58]]
    proto_map = {1: 'ICMP', 58: 'ICMPv6EchoRequest', 6: 'TCP', 17: 'UDP'}
    ICMPv4 = 0
    ICMPv6 = 1
    TCP = 0
    UDP = 1
    PROTO_ALL = 0

    # port ranges
    PORTS_ALL = -1
    PORTS_RANGE = 0
    PORTS_RANGE_2 = 1
    udp_sport_from = 10
    udp_sport_to = udp_sport_from + 5
    udp_dport_from = 20000
    udp_dport_to = udp_dport_from + 5000
    tcp_sport_from = 30
    tcp_sport_to = tcp_sport_from + 5
    tcp_dport_from = 40000
    tcp_dport_to = tcp_dport_from + 5000

    udp_sport_from_2 = 90
    udp_sport_to_2 = udp_sport_from_2 + 5
    udp_dport_from_2 = 30000
    udp_dport_to_2 = udp_dport_from_2 + 5000
    tcp_sport_from_2 = 130
    tcp_sport_to_2 = tcp_sport_from_2 + 5
    tcp_dport_from_2 = 20000
    tcp_dport_to_2 = tcp_dport_from_2 + 5000

    icmp4_type = 8  # echo request
    icmp4_code = 3
    icmp6_type = 128  # echo request
    icmp6_code = 3

    icmp4_type_2 = 8
    icmp4_code_from_2 = 5
    icmp4_code_to_2 = 20
    icmp6_type_2 = 128
    icmp6_code_from_2 = 8
    icmp6_code_to_2 = 42

    # Test variables
    bd_id = 1

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(TestACLplugin, cls).setUpClass()

        try:
            # Create 2 pg interfaces
            cls.create_pg_interfaces(range(2))

            # Packet flows mapping pg0 -> pg1, pg2 etc.
            cls.flows = dict()
            cls.flows[cls.pg0] = [cls.pg1]

            # Packet sizes
            cls.pg_if_packet_sizes = [64, 512, 1518, 9018]

            # Create BD with MAC learning and unknown unicast flooding disabled
            # and put interfaces to this BD
            cls.vapi.bridge_domain_add_del(bd_id=cls.bd_id, uu_flood=1,
                                           learn=1)
            for pg_if in cls.pg_interfaces:
                cls.vapi.sw_interface_set_l2_bridge(
                    rx_sw_if_index=pg_if.sw_if_index, bd_id=cls.bd_id)

            # Set up all interfaces
            for i in cls.pg_interfaces:
                i.admin_up()

            # Mapping between packet-generator index and lists of test hosts
            cls.hosts_by_pg_idx = dict()
            for pg_if in cls.pg_interfaces:
                cls.hosts_by_pg_idx[pg_if.sw_if_index] = []

            # Create list of deleted hosts
            cls.deleted_hosts_by_pg_idx = dict()
            for pg_if in cls.pg_interfaces:
                cls.deleted_hosts_by_pg_idx[pg_if.sw_if_index] = []

            # warm-up the mac address tables
            # self.warmup_test()
            count = 16
            start = 0
            n_int = len(cls.pg_interfaces)
            macs_per_if = count // n_int
            i = -1
            for pg_if in cls.pg_interfaces:
                i += 1
                start_nr = macs_per_if * i + start
                end_nr = count + start if i == (n_int - 1) \
                    else macs_per_if * (i + 1) + start
                hosts = cls.hosts_by_pg_idx[pg_if.sw_if_index]
                for j in range(int(start_nr), int(end_nr)):
                    host = Host(
                        "00:00:00:ff:%02x:%02x" % (pg_if.sw_if_index, j),
                        "172.17.1%02x.%u" % (pg_if.sw_if_index, j),
                        "2017:dead:%02x::%u" % (pg_if.sw_if_index, j))
                    hosts.append(host)

        except Exception:
            super(TestACLplugin, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestACLplugin, cls).tearDownClass()

    def setUp(self):
        super(TestACLplugin, self).setUp()
        self.reset_packet_infos()

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(TestACLplugin, self).tearDown()

    def show_commands_at_teardown(self):
        cli = "show vlib graph l2-input-feat-arc"
        self.logger.info(self.vapi.ppcli(cli))
        cli = "show vlib graph l2-input-feat-arc-end"
        self.logger.info(self.vapi.ppcli(cli))
        cli = "show vlib graph l2-output-feat-arc"
        self.logger.info(self.vapi.ppcli(cli))
        cli = "show vlib graph l2-output-feat-arc-end"
        self.logger.info(self.vapi.ppcli(cli))
        self.logger.info(self.vapi.ppcli("show l2fib verbose"))
        self.logger.info(self.vapi.ppcli("show acl-plugin acl"))
        self.logger.info(self.vapi.ppcli("show acl-plugin interface"))
        self.logger.info(self.vapi.ppcli("show acl-plugin tables"))
        self.logger.info(self.vapi.ppcli("show bridge-domain %s detail"
                                         % self.bd_id))

    def create_rule(self, ip=0, permit_deny=0, ports=PORTS_ALL, proto=-1,
                    s_prefix=0, s_ip=0,
                    d_prefix=0, d_ip=0):
        if ip:
            src_prefix = IPv6Network((s_ip, s_prefix))
            dst_prefix = IPv6Network((d_ip, d_prefix))
        else:
            src_prefix = IPv4Network((s_ip, s_prefix))
            dst_prefix = IPv4Network((d_ip, d_prefix))
        return AclRule(is_permit=permit_deny, ports=ports, proto=proto,
                       src_prefix=src_prefix, dst_prefix=dst_prefix)

    def apply_rules(self, rules, tag=None):
        acl = VppAcl(self, rules, tag=tag)
        acl.add_vpp_config()
        self.logger.info("Dumped ACL: " + str(acl.dump()))
        # Apply a ACL on the interface as inbound
        for i in self.pg_interfaces:
            acl_if = VppAclInterface(
                self, sw_if_index=i.sw_if_index, n_input=1, acls=[acl])
            acl_if.add_vpp_config()
        return acl.acl_index

    def apply_rules_to(self, rules, tag=None, sw_if_index=INVALID_INDEX):
        acl = VppAcl(self, rules, tag=tag)
        acl.add_vpp_config()
        self.logger.info("Dumped ACL: " + str(acl.dump()))
        # Apply a ACL on the interface as inbound
        acl_if = VppAclInterface(self, sw_if_index=sw_if_index, n_input=1,
                                 acls=[acl])
        return acl.acl_index

    def etype_whitelist(self, whitelist, n_input, add=True):
        # Apply whitelists on all the interfaces
        if add:
            self._wl = []
            for i in self.pg_interfaces:
                self._wl.append(VppEtypeWhitelist(
                    self, sw_if_index=i.sw_if_index, whitelist=whitelist,
                    n_input=n_input).add_vpp_config())
        else:
            if hasattr(self, "_wl"):
                for wl in self._wl:
                    wl.remove_vpp_config()

    def create_upper_layer(self, packet_index, proto, ports=0):
        p = self.proto_map[proto]
        if p == 'UDP':
            if ports == 0:
                return UDP(sport=random.randint(self.udp_sport_from,
                                                self.udp_sport_to),
                           dport=random.randint(self.udp_dport_from,
                                                self.udp_dport_to))
            else:
                return UDP(sport=ports, dport=ports)
        elif p == 'TCP':
            if ports == 0:
                return TCP(sport=random.randint(self.tcp_sport_from,
                                                self.tcp_sport_to),
                           dport=random.randint(self.tcp_dport_from,
                                                self.tcp_dport_to))
            else:
                return TCP(sport=ports, dport=ports)
        return ''

    def create_stream(self, src_if, packet_sizes, traffic_type=0, ipv6=0,
                      proto=-1, ports=0, fragments=False,
                      pkt_raw=True, etype=-1):
        """
        Create input packet stream for defined interface using hosts or
        deleted_hosts list.

        :param object src_if: Interface to create packet stream for.
        :param list packet_sizes: List of required packet sizes.
        :param traffic_type: 1: ICMP packet, 2: IPv6 with EH, 0: otherwise.
        :return: Stream of packets.
        """
        pkts = []
        if self.flows.__contains__(src_if):
            src_hosts = self.hosts_by_pg_idx[src_if.sw_if_index]
            for dst_if in self.flows[src_if]:
                dst_hosts = self.hosts_by_pg_idx[dst_if.sw_if_index]
                n_int = len(dst_hosts) * len(src_hosts)
                for i in range(0, n_int):
                    dst_host = dst_hosts[int(i / len(src_hosts))]
                    src_host = src_hosts[i % len(src_hosts)]
                    pkt_info = self.create_packet_info(src_if, dst_if)
                    if ipv6 == 1:
                        pkt_info.ip = 1
                    elif ipv6 == 0:
                        pkt_info.ip = 0
                    else:
                        pkt_info.ip = random.choice([0, 1])
                    if proto == -1:
                        pkt_info.proto = random.choice(self.proto[self.IP])
                    else:
                        pkt_info.proto = proto
                    payload = self.info_to_payload(pkt_info)
                    p = Ether(dst=dst_host.mac, src=src_host.mac)
                    if etype > 0:
                        p = Ether(dst=dst_host.mac,
                                  src=src_host.mac,
                                  type=etype)
                    if pkt_info.ip:
                        p /= IPv6(dst=dst_host.ip6, src=src_host.ip6)
                        if fragments:
                            p /= IPv6ExtHdrFragment(offset=64, m=1)
                    else:
                        if fragments:
                            p /= IP(src=src_host.ip4, dst=dst_host.ip4,
                                    flags=1, frag=64)
                        else:
                            p /= IP(src=src_host.ip4, dst=dst_host.ip4)
                    if traffic_type == self.ICMP:
                        if pkt_info.ip:
                            p /= ICMPv6EchoRequest(type=self.icmp6_type,
                                                   code=self.icmp6_code)
                        else:
                            p /= ICMP(type=self.icmp4_type,
                                      code=self.icmp4_code)
                    else:
                        p /= self.create_upper_layer(i, pkt_info.proto, ports)
                    if pkt_raw:
                        p /= Raw(payload)
                        pkt_info.data = p.copy()
                    if pkt_raw:
                        size = random.choice(packet_sizes)
                        self.extend_packet(p, size)
                    pkts.append(p)
        return pkts

    def verify_capture(self, pg_if, capture,
                       traffic_type=0, ip_type=0, etype=-1):
        """
        Verify captured input packet stream for defined interface.

        :param object pg_if: Interface to verify captured packet stream for.
        :param list capture: Captured packet stream.
        :param traffic_type: 1: ICMP packet, 2: IPv6 with EH, 0: otherwise.
        """
        last_info = dict()
        for i in self.pg_interfaces:
            last_info[i.sw_if_index] = None
        dst_sw_if_index = pg_if.sw_if_index
        for packet in capture:
            if etype > 0:
                if packet[Ether].type != etype:
                    self.logger.error(ppp("Unexpected ethertype in packet:",
                                          packet))
                else:
                    continue
            try:
                # Raw data for ICMPv6 are stored in ICMPv6EchoRequest.data
                if traffic_type == self.ICMP and ip_type == self.IPV6:
                    payload_info = self.payload_to_info(
                        packet[ICMPv6EchoRequest], 'data')
                    payload = packet[ICMPv6EchoRequest]
                else:
                    payload_info = self.payload_to_info(packet[Raw])
                    payload = packet[self.proto_map[payload_info.proto]]
            except:
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(outside network):", packet))
                raise

            if ip_type != 0:
                self.assertEqual(payload_info.ip, ip_type)
            if traffic_type == self.ICMP:
                try:
                    if payload_info.ip == 0:
                        self.assertEqual(payload.type, self.icmp4_type)
                        self.assertEqual(payload.code, self.icmp4_code)
                    else:
                        self.assertEqual(payload.type, self.icmp6_type)
                        self.assertEqual(payload.code, self.icmp6_code)
                except:
                    self.logger.error(ppp("Unexpected or invalid packet "
                                          "(outside network):", packet))
                    raise
            else:
                try:
                    ip_version = IPv6 if payload_info.ip == 1 else IP

                    ip = packet[ip_version]
                    packet_index = payload_info.index

                    self.assertEqual(payload_info.dst, dst_sw_if_index)
                    self.logger.debug("Got packet on port %s: src=%u (id=%u)" %
                                      (pg_if.name, payload_info.src,
                                       packet_index))
                    next_info = self.get_next_packet_info_for_interface2(
                        payload_info.src, dst_sw_if_index,
                        last_info[payload_info.src])
                    last_info[payload_info.src] = next_info
                    self.assertTrue(next_info is not None)
                    self.assertEqual(packet_index, next_info.index)
                    saved_packet = next_info.data
                    # Check standard fields
                    self.assertEqual(ip.src, saved_packet[ip_version].src)
                    self.assertEqual(ip.dst, saved_packet[ip_version].dst)
                    p = self.proto_map[payload_info.proto]
                    if p == 'TCP':
                        tcp = packet[TCP]
                        self.assertEqual(tcp.sport, saved_packet[
                            TCP].sport)
                        self.assertEqual(tcp.dport, saved_packet[
                            TCP].dport)
                    elif p == 'UDP':
                        udp = packet[UDP]
                        self.assertEqual(udp.sport, saved_packet[
                            UDP].sport)
                        self.assertEqual(udp.dport, saved_packet[
                            UDP].dport)
                except:
                    self.logger.error(ppp("Unexpected or invalid packet:",
                                          packet))
                    raise
        for i in self.pg_interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(
                remaining_packet is None,
                "Port %u: Packet expected from source %u didn't arrive" %
                (dst_sw_if_index, i.sw_if_index))

    def run_traffic_no_check(self):
        # Test
        # Create incoming packet streams for packet-generator interfaces
        for i in self.pg_interfaces:
            if self.flows.__contains__(i):
                pkts = self.create_stream(i, self.pg_if_packet_sizes)
                if len(pkts) > 0:
                    i.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

    def run_verify_test(self, traffic_type=0, ip_type=0, proto=-1, ports=0,
                        frags=False, pkt_raw=True, etype=-1):
        # Test
        # Create incoming packet streams for packet-generator interfaces
        pkts_cnt = 0
        for i in self.pg_interfaces:
            if self.flows.__contains__(i):
                pkts = self.create_stream(i, self.pg_if_packet_sizes,
                                          traffic_type, ip_type, proto, ports,
                                          frags, pkt_raw, etype)
                if len(pkts) > 0:
                    i.add_stream(pkts)
                    pkts_cnt += len(pkts)

        # Enable packet capture and start packet sendingself.IPV
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.logger.info("sent packets count: %d" % pkts_cnt)

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for src_if in self.pg_interfaces:
            if self.flows.__contains__(src_if):
                for dst_if in self.flows[src_if]:
                    capture = dst_if.get_capture(pkts_cnt)
                    self.logger.info("Verifying capture on interface %s" %
                                     dst_if.name)
                    self.verify_capture(dst_if, capture,
                                        traffic_type, ip_type, etype)

    def run_verify_negat_test(self, traffic_type=0, ip_type=0, proto=-1,
                              ports=0, frags=False, etype=-1):
        # Test
        pkts_cnt = 0
        self.reset_packet_infos()
        for i in self.pg_interfaces:
            if self.flows.__contains__(i):
                pkts = self.create_stream(i, self.pg_if_packet_sizes,
                                          traffic_type, ip_type, proto, ports,
                                          frags, True, etype)
                if len(pkts) > 0:
                    i.add_stream(pkts)
                    pkts_cnt += len(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.logger.info("sent packets count: %d" % pkts_cnt)

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for src_if in self.pg_interfaces:
            if self.flows.__contains__(src_if):
                for dst_if in self.flows[src_if]:
                    self.logger.info("Verifying capture on interface %s" %
                                     dst_if.name)
                    capture = dst_if.get_capture(0)
                    self.assertEqual(len(capture), 0)

    def test_0000_warmup_test(self):
        """ ACL plugin version check; learn MACs
        """
        reply = self.vapi.papi.acl_plugin_get_version()
        self.assertEqual(reply.major, 1)
        self.logger.info("Working with ACL plugin version: %d.%d" % (
            reply.major, reply.minor))
        # minor version changes are non breaking
        # self.assertEqual(reply.minor, 0)

    def test_0001_acl_create(self):
        """ ACL create/delete test
        """

        self.logger.info("ACLP_TEST_START_0001")
        # Create a permit-1234 ACL
        r = [AclRule(is_permit=1, proto=17, ports=1234, sport_to=1235)]
        # Test 1: add a new ACL
        first_acl = VppAcl(self, rules=r, tag="permit 1234")
        first_acl.add_vpp_config()
        self.assertTrue(first_acl.query_vpp_config())
        # The very first ACL gets #0
        self.assertEqual(first_acl.acl_index, 0)
        rr = first_acl.dump()
        self.logger.info("Dumped ACL: " + str(rr))
        self.assertEqual(len(rr), 1)
        # We should have the same number of ACL entries as we had asked
        self.assertEqual(len(rr[0].r), len(r))
        # The rules should be the same. But because the submitted and returned
        # are different types, we need to iterate over rules and keys to get
        # to basic values.
        for i_rule in range(0, len(r) - 1):
            encoded_rule = r[i_rule].encode()
            for rule_key in encoded_rule:
                self.assertEqual(rr[0].r[i_rule][rule_key],
                                 encoded_rule[rule_key])

        # Create a deny-1234 ACL
        r_deny = [AclRule(is_permit=0, proto=17, ports=1234, sport_to=1235),
                  AclRule(is_permit=1, proto=17, ports=0)]
        second_acl = VppAcl(self, rules=r_deny, tag="deny 1234;permit all")
        second_acl.add_vpp_config()
        self.assertTrue(second_acl.query_vpp_config())
        # The second ACL gets #1
        self.assertEqual(second_acl.acl_index, 1)

        # Test 2: try to modify a nonexistent ACL
        invalid_acl = VppAcl(self, acl_index=432, rules=r, tag="FFFF:FFFF")
        reply = invalid_acl.add_vpp_config(expect_error=True)

        # apply an ACL on an interface inbound, try to delete ACL, must fail
        acl_if_list = VppAclInterface(
            self, sw_if_index=self.pg0.sw_if_index, n_input=1,
            acls=[first_acl])
        acl_if_list.add_vpp_config()
        first_acl.remove_vpp_config(expect_error=True)
        # Unapply an ACL and then try to delete it - must be ok
        acl_if_list.remove_vpp_config()
        first_acl.remove_vpp_config()

        # apply an ACL on an interface inbound, try to delete ACL, must fail
        acl_if_list = VppAclInterface(
            self, sw_if_index=self.pg0.sw_if_index, n_input=0,
            acls=[second_acl])
        acl_if_list.add_vpp_config()
        second_acl.remove_vpp_config(expect_error=True)
        # Unapply an ACL and then try to delete it - must be ok
        acl_if_list.remove_vpp_config()
        second_acl.remove_vpp_config()

        # try to apply a nonexistent ACL - must fail
        acl_if_list = VppAclInterface(
            self, sw_if_index=self.pg0.sw_if_index, n_input=0,
            acls=[invalid_acl])
        acl_if_list.add_vpp_config(expect_error=True)

        self.logger.info("ACLP_TEST_FINISH_0001")

    def test_0002_acl_permit_apply(self):
        """ permit ACL apply test
        """
        self.logger.info("ACLP_TEST_START_0002")

        rules = []
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                                      0, self.proto[self.IP][self.UDP]))
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                                      0, self.proto[self.IP][self.TCP]))

        # Apply rules
        acl_idx = self.apply_rules(rules, "permit per-flow")

        # enable counters
        reply = self.vapi.papi.acl_stats_intf_counters_enable(enable=1)

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4, -1)

        matches = self.statistics.get_counter('/acl/%d/matches' % acl_idx)
        self.logger.info("stat segment counters: %s" % repr(matches))
        cli = "show acl-plugin acl"
        self.logger.info(self.vapi.ppcli(cli))
        cli = "show acl-plugin tables"
        self.logger.info(self.vapi.ppcli(cli))

        total_hits = matches[0][0]['packets'] + matches[0][1]['packets']
        self.assertEqual(total_hits, 64)

        # disable counters
        reply = self.vapi.papi.acl_stats_intf_counters_enable(enable=0)

        self.logger.info("ACLP_TEST_FINISH_0002")

    def test_0003_acl_deny_apply(self):
        """ deny ACL apply test
        """
        self.logger.info("ACLP_TEST_START_0003")
        # Add a deny-flows ACL
        rules = []
        rules.append(self.create_rule(
            self.IPV4, self.DENY, self.PORTS_ALL,
            self.proto[self.IP][self.UDP]))
        # Permit ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        acl_idx = self.apply_rules(rules, "deny per-flow;permit all")

        # enable counters
        reply = self.vapi.papi.acl_stats_intf_counters_enable(enable=1)

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPV4,
                                   self.proto[self.IP][self.UDP])

        matches = self.statistics.get_counter('/acl/%d/matches' % acl_idx)
        self.logger.info("stat segment counters: %s" % repr(matches))
        cli = "show acl-plugin acl"
        self.logger.info(self.vapi.ppcli(cli))
        cli = "show acl-plugin tables"
        self.logger.info(self.vapi.ppcli(cli))
        self.assertEqual(matches[0][0]['packets'], 64)
        # disable counters
        reply = self.vapi.papi.acl_stats_intf_counters_enable(enable=0)
        self.logger.info("ACLP_TEST_FINISH_0003")
        # self.assertEqual(, 0)

    def test_0004_vpp624_permit_icmpv4(self):
        """ VPP_624 permit ICMPv4
        """
        self.logger.info("ACLP_TEST_START_0004")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.ICMP][self.ICMPv4]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit icmpv4")

        # Traffic should still pass
        self.run_verify_test(self.ICMP, self.IPV4,
                             self.proto[self.ICMP][self.ICMPv4])

        self.logger.info("ACLP_TEST_FINISH_0004")

    def test_0005_vpp624_permit_icmpv6(self):
        """ VPP_624 permit ICMPv6
        """
        self.logger.info("ACLP_TEST_START_0005")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.ICMP][self.ICMPv6]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit icmpv6")

        # Traffic should still pass
        self.run_verify_test(self.ICMP, self.IPV6,
                             self.proto[self.ICMP][self.ICMPv6])

        self.logger.info("ACLP_TEST_FINISH_0005")

    def test_0006_vpp624_deny_icmpv4(self):
        """ VPP_624 deny ICMPv4
        """
        self.logger.info("ACLP_TEST_START_0006")
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_RANGE,
                                      self.proto[self.ICMP][self.ICMPv4]))
        # permit ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "deny icmpv4")

        # Traffic should not pass
        self.run_verify_negat_test(self.ICMP, self.IPV4, 0)

        self.logger.info("ACLP_TEST_FINISH_0006")

    def test_0007_vpp624_deny_icmpv6(self):
        """ VPP_624 deny ICMPv6
        """
        self.logger.info("ACLP_TEST_START_0007")
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.DENY, self.PORTS_RANGE,
                                      self.proto[self.ICMP][self.ICMPv6]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "deny icmpv6")

        # Traffic should not pass
        self.run_verify_negat_test(self.ICMP, self.IPV6, 0)

        self.logger.info("ACLP_TEST_FINISH_0007")

    def test_0008_tcp_permit_v4(self):
        """ permit TCPv4
        """
        self.logger.info("ACLP_TEST_START_0008")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.IP][self.TCP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ipv4 tcp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4, self.proto[self.IP][self.TCP])

        self.logger.info("ACLP_TEST_FINISH_0008")

    def test_0009_tcp_permit_v6(self):
        """ permit TCPv6
        """
        self.logger.info("ACLP_TEST_START_0009")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.IP][self.TCP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ip6 tcp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV6, self.proto[self.IP][self.TCP])

        self.logger.info("ACLP_TEST_FINISH_0008")

    def test_0010_udp_permit_v4(self):
        """ permit UDPv4
        """
        self.logger.info("ACLP_TEST_START_0010")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.IP][self.UDP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ipv udp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4, self.proto[self.IP][self.UDP])

        self.logger.info("ACLP_TEST_FINISH_0010")

    def test_0011_udp_permit_v6(self):
        """ permit UDPv6
        """
        self.logger.info("ACLP_TEST_START_0011")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.IP][self.UDP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ip6 udp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV6, self.proto[self.IP][self.UDP])

        self.logger.info("ACLP_TEST_FINISH_0011")

    def test_0012_tcp_deny(self):
        """ deny TCPv4/v6
        """
        self.logger.info("ACLP_TEST_START_0012")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_RANGE,
                                      self.proto[self.IP][self.TCP]))
        rules.append(self.create_rule(self.IPV6, self.DENY, self.PORTS_RANGE,
                                      self.proto[self.IP][self.TCP]))
        # permit ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                                      self.PORTS_ALL, 0))
        rules.append(self.create_rule(self.IPV6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "deny ip4/ip6 tcp")

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPRANDOM,
                                   self.proto[self.IP][self.TCP])

        self.logger.info("ACLP_TEST_FINISH_0012")

    def test_0013_udp_deny(self):
        """ deny UDPv4/v6
        """
        self.logger.info("ACLP_TEST_START_0013")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_RANGE,
                                      self.proto[self.IP][self.UDP]))
        rules.append(self.create_rule(self.IPV6, self.DENY, self.PORTS_RANGE,
                                      self.proto[self.IP][self.UDP]))
        # permit ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                                      self.PORTS_ALL, 0))
        rules.append(self.create_rule(self.IPV6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "deny ip4/ip6 udp")

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPRANDOM,
                                   self.proto[self.IP][self.UDP])

        self.logger.info("ACLP_TEST_FINISH_0013")

    def test_0014_acl_dump(self):
        """ verify add/dump acls
        """
        self.logger.info("ACLP_TEST_START_0014")

        r = [[self.IPV4, self.PERMIT, 1234, self.proto[self.IP][self.TCP]],
             [self.IPV4, self.PERMIT, 2345, self.proto[self.IP][self.UDP]],
             [self.IPV4, self.PERMIT, 0, self.proto[self.IP][self.TCP]],
             [self.IPV4, self.PERMIT, 0, self.proto[self.IP][self.UDP]],
             [self.IPV4, self.PERMIT, 5, self.proto[self.ICMP][self.ICMPv4]],
             [self.IPV6, self.PERMIT, 4321, self.proto[self.IP][self.TCP]],
             [self.IPV6, self.PERMIT, 5432, self.proto[self.IP][self.UDP]],
             [self.IPV6, self.PERMIT, 0, self.proto[self.IP][self.TCP]],
             [self.IPV6, self.PERMIT, 0, self.proto[self.IP][self.UDP]],
             [self.IPV6, self.PERMIT, 6, self.proto[self.ICMP][self.ICMPv6]],
             [self.IPV4, self.DENY, self.PORTS_ALL, 0],
             [self.IPV4, self.DENY, 1234, self.proto[self.IP][self.TCP]],
             [self.IPV4, self.DENY, 2345, self.proto[self.IP][self.UDP]],
             [self.IPV4, self.DENY, 5, self.proto[self.ICMP][self.ICMPv4]],
             [self.IPV6, self.DENY, 4321, self.proto[self.IP][self.TCP]],
             [self.IPV6, self.DENY, 5432, self.proto[self.IP][self.UDP]],
             [self.IPV6, self.DENY, 6, self.proto[self.ICMP][self.ICMPv6]],
             [self.IPV6, self.DENY, self.PORTS_ALL, 0]
             ]

        # Add and verify new ACLs
        rules = []
        for i in range(len(r)):
            rules.append(self.create_rule(r[i][0], r[i][1], r[i][2], r[i][3]))

        acl = VppAcl(self, rules=rules)
        acl.add_vpp_config()
        result = acl.dump()

        i = 0
        for drules in result:
            for dr in drules.r:
                self.assertEqual(dr.is_permit, r[i][1])
                self.assertEqual(dr.proto, r[i][3])

                if r[i][2] > 0:
                    self.assertEqual(dr.srcport_or_icmptype_first, r[i][2])
                else:
                    if r[i][2] < 0:
                        self.assertEqual(dr.srcport_or_icmptype_first, 0)
                        self.assertEqual(dr.srcport_or_icmptype_last, 65535)
                    else:
                        if dr.proto == self.proto[self.IP][self.TCP]:
                            self.assertGreater(dr.srcport_or_icmptype_first,
                                               self.tcp_sport_from-1)
                            self.assertLess(dr.srcport_or_icmptype_first,
                                            self.tcp_sport_to+1)
                            self.assertGreater(dr.dstport_or_icmpcode_last,
                                               self.tcp_dport_from-1)
                            self.assertLess(dr.dstport_or_icmpcode_last,
                                            self.tcp_dport_to+1)
                        elif dr.proto == self.proto[self.IP][self.UDP]:
                            self.assertGreater(dr.srcport_or_icmptype_first,
                                               self.udp_sport_from-1)
                            self.assertLess(dr.srcport_or_icmptype_first,
                                            self.udp_sport_to+1)
                            self.assertGreater(dr.dstport_or_icmpcode_last,
                                               self.udp_dport_from-1)
                            self.assertLess(dr.dstport_or_icmpcode_last,
                                            self.udp_dport_to+1)
                i += 1

        self.logger.info("ACLP_TEST_FINISH_0014")

    def test_0015_tcp_permit_port_v4(self):
        """ permit single TCPv4
        """
        self.logger.info("ACLP_TEST_START_0015")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.PERMIT, port,
                                      self.proto[self.IP][self.TCP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ip4 tcp %d" % port)

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4,
                             self.proto[self.IP][self.TCP], port)

        self.logger.info("ACLP_TEST_FINISH_0015")

    def test_0016_udp_permit_port_v4(self):
        """ permit single UDPv4
        """
        self.logger.info("ACLP_TEST_START_0016")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.PERMIT, port,
                                      self.proto[self.IP][self.UDP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ip4 tcp %d" % port)

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4,
                             self.proto[self.IP][self.UDP], port)

        self.logger.info("ACLP_TEST_FINISH_0016")

    def test_0017_tcp_permit_port_v6(self):
        """ permit single TCPv6
        """
        self.logger.info("ACLP_TEST_START_0017")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.PERMIT, port,
                                      self.proto[self.IP][self.TCP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ip4 tcp %d" % port)

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV6,
                             self.proto[self.IP][self.TCP], port)

        self.logger.info("ACLP_TEST_FINISH_0017")

    def test_0018_udp_permit_port_v6(self):
        """ permit single UDPv6
        """
        self.logger.info("ACLP_TEST_START_0018")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.PERMIT, port,
                                      self.proto[self.IP][self.UDP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ip4 tcp %d" % port)

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV6,
                             self.proto[self.IP][self.UDP], port)

        self.logger.info("ACLP_TEST_FINISH_0018")

    def test_0019_udp_deny_port(self):
        """ deny single TCPv4/v6
        """
        self.logger.info("ACLP_TEST_START_0019")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, port,
                                      self.proto[self.IP][self.TCP]))
        rules.append(self.create_rule(self.IPV6, self.DENY, port,
                                      self.proto[self.IP][self.TCP]))
        # Permit ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                                      self.PORTS_ALL, 0))
        rules.append(self.create_rule(self.IPV6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "deny ip4/ip6 udp %d" % port)

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPRANDOM,
                                   self.proto[self.IP][self.TCP], port)

        self.logger.info("ACLP_TEST_FINISH_0019")

    def test_0020_udp_deny_port(self):
        """ deny single UDPv4/v6
        """
        self.logger.info("ACLP_TEST_START_0020")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, port,
                                      self.proto[self.IP][self.UDP]))
        rules.append(self.create_rule(self.IPV6, self.DENY, port,
                                      self.proto[self.IP][self.UDP]))
        # Permit ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                                      self.PORTS_ALL, 0))
        rules.append(self.create_rule(self.IPV6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "deny ip4/ip6 udp %d" % port)

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPRANDOM,
                                   self.proto[self.IP][self.UDP], port)

        self.logger.info("ACLP_TEST_FINISH_0020")

    def test_0021_udp_deny_port_verify_fragment_deny(self):
        """ deny single UDPv4/v6, permit ip any, verify non-initial fragment
        blocked
        """
        self.logger.info("ACLP_TEST_START_0021")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, port,
                                      self.proto[self.IP][self.UDP]))
        rules.append(self.create_rule(self.IPV6, self.DENY, port,
                                      self.proto[self.IP][self.UDP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                                      self.PORTS_ALL, 0))
        rules.append(self.create_rule(self.IPV6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "deny ip4/ip6 udp %d" % port)

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPRANDOM,
                                   self.proto[self.IP][self.UDP], port, True)

        self.logger.info("ACLP_TEST_FINISH_0021")

    def test_0022_zero_length_udp_ipv4(self):
        """ VPP-687 zero length udp ipv4 packet"""
        self.logger.info("ACLP_TEST_START_0022")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.PERMIT, port,
                                      self.proto[self.IP][self.UDP]))
        # deny ip any any in the end
        rules.append(
            self.create_rule(self.IPV4, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit empty udp ip4 %d" % port)

        # Traffic should still pass
        # Create incoming packet streams for packet-generator interfaces
        pkts_cnt = 0
        pkts = self.create_stream(self.pg0, self.pg_if_packet_sizes,
                                  self.IP, self.IPV4,
                                  self.proto[self.IP][self.UDP], port,
                                  False, False)
        if len(pkts) > 0:
            self.pg0.add_stream(pkts)
            pkts_cnt += len(pkts)

        # Enable packet capture and start packet sendingself.IPV
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.pg1.get_capture(pkts_cnt)

        self.logger.info("ACLP_TEST_FINISH_0022")

    def test_0023_zero_length_udp_ipv6(self):
        """ VPP-687 zero length udp ipv6 packet"""
        self.logger.info("ACLP_TEST_START_0023")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.PERMIT, port,
                                      self.proto[self.IP][self.UDP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit empty udp ip6 %d" % port)

        # Traffic should still pass
        # Create incoming packet streams for packet-generator interfaces
        pkts_cnt = 0
        pkts = self.create_stream(self.pg0, self.pg_if_packet_sizes,
                                  self.IP, self.IPV6,
                                  self.proto[self.IP][self.UDP], port,
                                  False, False)
        if len(pkts) > 0:
            self.pg0.add_stream(pkts)
            pkts_cnt += len(pkts)

        # Enable packet capture and start packet sendingself.IPV
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify outgoing packet streams per packet-generator interface
        self.pg1.get_capture(pkts_cnt)

        self.logger.info("ACLP_TEST_FINISH_0023")

    def test_0108_tcp_permit_v4(self):
        """ permit TCPv4 + non-match range
        """
        self.logger.info("ACLP_TEST_START_0108")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_RANGE_2,
                                      self.proto[self.IP][self.TCP]))
        rules.append(self.create_rule(self.IPV4, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.IP][self.TCP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ipv4 tcp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4, self.proto[self.IP][self.TCP])

        self.logger.info("ACLP_TEST_FINISH_0108")

    def test_0109_tcp_permit_v6(self):
        """ permit TCPv6 + non-match range
        """
        self.logger.info("ACLP_TEST_START_0109")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.DENY, self.PORTS_RANGE_2,
                                      self.proto[self.IP][self.TCP]))
        rules.append(self.create_rule(self.IPV6, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.IP][self.TCP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ip6 tcp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV6, self.proto[self.IP][self.TCP])

        self.logger.info("ACLP_TEST_FINISH_0109")

    def test_0110_udp_permit_v4(self):
        """ permit UDPv4 + non-match range
        """
        self.logger.info("ACLP_TEST_START_0110")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_RANGE_2,
                                      self.proto[self.IP][self.UDP]))
        rules.append(self.create_rule(self.IPV4, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.IP][self.UDP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ipv4 udp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4, self.proto[self.IP][self.UDP])

        self.logger.info("ACLP_TEST_FINISH_0110")

    def test_0111_udp_permit_v6(self):
        """ permit UDPv6 + non-match range
        """
        self.logger.info("ACLP_TEST_START_0111")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.DENY, self.PORTS_RANGE_2,
                                      self.proto[self.IP][self.UDP]))
        rules.append(self.create_rule(self.IPV6, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.IP][self.UDP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ip6 udp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV6, self.proto[self.IP][self.UDP])

        self.logger.info("ACLP_TEST_FINISH_0111")

    def test_0112_tcp_deny(self):
        """ deny TCPv4/v6 + non-match range
        """
        self.logger.info("ACLP_TEST_START_0112")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                                      self.PORTS_RANGE_2,
                                      self.proto[self.IP][self.TCP]))
        rules.append(self.create_rule(self.IPV6, self.PERMIT,
                                      self.PORTS_RANGE_2,
                                      self.proto[self.IP][self.TCP]))
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_RANGE,
                                      self.proto[self.IP][self.TCP]))
        rules.append(self.create_rule(self.IPV6, self.DENY, self.PORTS_RANGE,
                                      self.proto[self.IP][self.TCP]))
        # permit ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                                      self.PORTS_ALL, 0))
        rules.append(self.create_rule(self.IPV6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "deny ip4/ip6 tcp")

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPRANDOM,
                                   self.proto[self.IP][self.TCP])

        self.logger.info("ACLP_TEST_FINISH_0112")

    def test_0113_udp_deny(self):
        """ deny UDPv4/v6 + non-match range
        """
        self.logger.info("ACLP_TEST_START_0113")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                                      self.PORTS_RANGE_2,
                                      self.proto[self.IP][self.UDP]))
        rules.append(self.create_rule(self.IPV6, self.PERMIT,
                                      self.PORTS_RANGE_2,
                                      self.proto[self.IP][self.UDP]))
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_RANGE,
                                      self.proto[self.IP][self.UDP]))
        rules.append(self.create_rule(self.IPV6, self.DENY, self.PORTS_RANGE,
                                      self.proto[self.IP][self.UDP]))
        # permit ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                                      self.PORTS_ALL, 0))
        rules.append(self.create_rule(self.IPV6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "deny ip4/ip6 udp")

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPRANDOM,
                                   self.proto[self.IP][self.UDP])

        self.logger.info("ACLP_TEST_FINISH_0113")

    def test_0300_tcp_permit_v4_etype_aaaa(self):
        """ permit TCPv4, send 0xAAAA etype
        """
        self.logger.info("ACLP_TEST_START_0300")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_RANGE_2,
                                      self.proto[self.IP][self.TCP]))
        rules.append(self.create_rule(self.IPV4, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.IP][self.TCP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ipv4 tcp")

        # Traffic should still pass also for an odd ethertype
        self.run_verify_test(self.IP, self.IPV4, self.proto[self.IP][self.TCP],
                             0, False, True, 0xaaaa)
        self.logger.info("ACLP_TEST_FINISH_0300")

    def test_0305_tcp_permit_v4_etype_blacklist_aaaa(self):
        """ permit TCPv4, whitelist 0x0BBB ethertype, send 0xAAAA-blocked
        """
        self.logger.info("ACLP_TEST_START_0305")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_RANGE_2,
                                      self.proto[self.IP][self.TCP]))
        rules.append(self.create_rule(self.IPV4, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.IP][self.TCP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ipv4 tcp")
        # whitelist the 0xbbbb etype - so the 0xaaaa should be blocked
        self.etype_whitelist([0xbbb], 1)

        # The oddball ethertype should be blocked
        self.run_verify_negat_test(self.IP, self.IPV4,
                                   self.proto[self.IP][self.TCP],
                                   0, False, 0xaaaa)

        # remove the whitelist
        self.etype_whitelist([], 0, add=False)

        self.logger.info("ACLP_TEST_FINISH_0305")

    def test_0306_tcp_permit_v4_etype_blacklist_aaaa(self):
        """ permit TCPv4, whitelist 0x0BBB ethertype, send 0x0BBB - pass
        """
        self.logger.info("ACLP_TEST_START_0306")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_RANGE_2,
                                      self.proto[self.IP][self.TCP]))
        rules.append(self.create_rule(self.IPV4, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.IP][self.TCP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ipv4 tcp")
        # whitelist the 0xbbbb etype - so the 0xaaaa should be blocked
        self.etype_whitelist([0xbbb], 1)

        # The whitelisted traffic, should pass
        self.run_verify_test(self.IP, self.IPV4, self.proto[self.IP][self.TCP],
                             0, False, True, 0x0bbb)

        # remove the whitelist, the previously blocked 0xAAAA should pass now
        self.etype_whitelist([], 0, add=False)

        self.logger.info("ACLP_TEST_FINISH_0306")

    def test_0307_tcp_permit_v4_etype_blacklist_aaaa(self):
        """ permit TCPv4, whitelist 0x0BBB, remove, send 0xAAAA - pass
        """
        self.logger.info("ACLP_TEST_START_0307")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_RANGE_2,
                                      self.proto[self.IP][self.TCP]))
        rules.append(self.create_rule(self.IPV4, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.IP][self.TCP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, "permit ipv4 tcp")

        # whitelist the 0xbbbb etype - so the 0xaaaa should be blocked
        self.etype_whitelist([0xbbb], 1)
        # remove the whitelist, the previously blocked 0xAAAA should pass now
        self.etype_whitelist([], 0, add=False)

        # The whitelisted traffic, should pass
        self.run_verify_test(self.IP, self.IPV4, self.proto[self.IP][self.TCP],
                             0, False, True, 0xaaaa)

        self.logger.info("ACLP_TEST_FINISH_0306")

    def test_0315_del_intf(self):
        """ apply an acl and delete the interface
        """
        self.logger.info("ACLP_TEST_START_0315")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_RANGE_2,
                                      self.proto[self.IP][self.TCP]))
        rules.append(self.create_rule(self.IPV4, self.PERMIT, self.PORTS_RANGE,
                                      self.proto[self.IP][self.TCP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, self.PORTS_ALL, 0))

        # create an interface
        intf = []
        intf.append(VppLoInterface(self))

        # Apply rules
        self.apply_rules_to(rules, "permit ipv4 tcp", intf[0].sw_if_index)

        # Remove the interface
        intf[0].remove_vpp_config()

        self.logger.info("ACLP_TEST_FINISH_0315")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
