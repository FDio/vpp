#!/usr/bin/env python
"""ACL IRB Test Case HLD:

**config**
    - L2 MAC learning enabled in l2bd
    - 2 routed interfaces untagged, bvi (Bridge Virtual Interface)
    - 2 bridged interfaces in l2bd with bvi

**test**
    - sending ip4 eth pkts between routed interfaces
        - 2 routed interfaces
        - 2 bridged interfaces

    - 64B, 512B, 1518B, 9200B (ether_size)

    - burst of pkts per interface
        - 257pkts per burst
        - routed pkts hitting different FIB entries
        - bridged pkts hitting different MAC entries

**verify**
    - all packets received correctly

"""

import unittest
from socket import inet_pton, AF_INET, AF_INET6
from random import choice
from pprint import pprint

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, ICMP, TCP
from scapy.layers.inet6 import IPv6, ICMPv6Unknown, ICMPv6EchoRequest
from scapy.layers.inet6 import ICMPv6EchoReply, IPv6ExtHdrRouting
from scapy.layers.inet6 import IPv6ExtHdrFragment

from framework import VppTestCase, VppTestRunner
import time


class TestIpIrb(VppTestCase):
    """IRB Test Case"""

    @classmethod
    def setUpClass(cls):
        """
        #. Create BD with MAC learning enabled and put interfaces to this BD.
        #. Configure IPv4 addresses on loopback interface and routed interface.
        #. Configure MAC address binding to IPv4 neighbors on loop0.
        #. Configure MAC address on pg2.
        #. Loopback BVI interface has remote hosts, one half of hosts are
           behind pg0 second behind pg1.
        """
        super(TestIpIrb, cls).setUpClass()

        cls.pg_if_packet_sizes = [64, 512, 1518, 9018]  # packet sizes
        cls.bd_id = 10
        cls.remote_hosts_count = 250

        # create 3 pg interfaces, 1 loopback interface
        cls.create_pg_interfaces(range(3))
        cls.create_loopback_interfaces(range(1))

        cls.interfaces = list(cls.pg_interfaces)
        cls.interfaces.extend(cls.lo_interfaces)

        for i in cls.interfaces:
            i.admin_up()

        # Create BD with MAC learning enabled and put interfaces to this BD
        cls.vapi.sw_interface_set_l2_bridge(
            cls.loop0.sw_if_index, bd_id=cls.bd_id, bvi=1)
        cls.vapi.sw_interface_set_l2_bridge(
            cls.pg0.sw_if_index, bd_id=cls.bd_id)
        cls.vapi.sw_interface_set_l2_bridge(
            cls.pg1.sw_if_index, bd_id=cls.bd_id)

        # Configure IPv4 addresses on loopback interface and routed interface
        cls.loop0.config_ip4()
        cls.loop0.config_ip6()
        cls.pg2.config_ip4()
        cls.pg2.config_ip6()

        # Configure MAC address binding to IPv4 neighbors on loop0
        cls.loop0.generate_remote_hosts(cls.remote_hosts_count)
        cls.loop0.configure_ipv4_neighbors()
        cls.loop0.configure_ipv6_neighbors()
        # configure MAC address on pg2
        cls.pg2.resolve_arp()
        cls.pg2.resolve_ndp()

        cls.WITHOUT_EH = False
        cls.WITH_EH = True

        # Loopback BVI interface has remote hosts, one half of hosts are behind
        # pg0 second behind pg1
        half = cls.remote_hosts_count // 2
        cls.pg0.remote_hosts = cls.loop0.remote_hosts[:half]
        cls.pg1.remote_hosts = cls.loop0.remote_hosts[half:]

    def tearDown(self):
        """Run standard test teardown and log ``show l2patch``,
        ``show l2fib verbose``,``show bridge-domain <bd_id> detail``,
        ``show ip arp``.
        """
        super(TestIpIrb, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show l2patch"))
            self.logger.info(self.vapi.cli("show classify tables"))
            self.logger.info(self.vapi.cli("show vlib graph"))
            self.logger.info(self.vapi.cli("show l2fib verbose"))
            self.logger.info(self.vapi.cli("show bridge-domain %s detail" %
                                           self.bd_id))
            self.logger.info(self.vapi.cli("show ip arp"))
            self.logger.info(self.vapi.cli("show ip6 neighbors"))
            self.logger.info(self.vapi.cli("show acl-plugin sessions"))
            self.logger.info(self.vapi.cli("show acl-plugin acl"))
            self.logger.info(self.vapi.cli("show acl-plugin interface"))
            self.logger.info(self.vapi.cli("show acl-plugin tables"))

    def create_stream(self, src_ip_if, dst_ip_if, reverse, packet_sizes,
                      is_ip6, expect_blocked, expect_established,
                      add_extension_header):
        pkts = []
        rules = []
        permit_rules = []
        permit_and_reflect_rules = []
        total_packet_count = 8
        for i in range(0, total_packet_count):
            modulo = (i//2) % 2
            can_reflect_this_packet = (modulo == 0)
            is_permit = i % 2
            remote_dst_index = i % len(dst_ip_if.remote_hosts)
            remote_dst_host = dst_ip_if.remote_hosts[remote_dst_index]
            if is_permit == 1:
                info = self.create_packet_info(src_ip_if, dst_ip_if)
                payload = self.info_to_payload(info)
            else:
                to_be_blocked = False
                if (expect_blocked and not expect_established):
                    to_be_blocked = True
                if (not can_reflect_this_packet):
                    to_be_blocked = True
                if to_be_blocked:
                    payload = "to be blocked"
                else:
                    info = self.create_packet_info(src_ip_if, dst_ip_if)
                    payload = self.info_to_payload(info)
            if reverse:
                dst_mac = 'de:ad:00:00:00:00'
                src_mac = remote_dst_host._mac
                dst_ip6 = src_ip_if.remote_ip6
                src_ip6 = remote_dst_host.ip6
                dst_ip4 = src_ip_if.remote_ip4
                src_ip4 = remote_dst_host.ip4
                dst_l4 = 1234 + i
                src_l4 = 4321 + i
            else:
                dst_mac = src_ip_if.local_mac
                src_mac = src_ip_if.remote_mac
                src_ip6 = src_ip_if.remote_ip6
                dst_ip6 = remote_dst_host.ip6
                src_ip4 = src_ip_if.remote_ip4
                dst_ip4 = remote_dst_host.ip4
                src_l4 = 1234 + i
                dst_l4 = 4321 + i

            # default ULP should be something we do not use in tests
            ulp_l4 = TCP(sport=src_l4, dport=dst_l4)
            # potentially a chain of protocols leading to ULP
            ulp = ulp_l4

            if can_reflect_this_packet:
                if is_ip6:
                    ulp_l4 = UDP(sport=src_l4, dport=dst_l4)
                    if add_extension_header:
                        # prepend some extension headers
                        ulp = (IPv6ExtHdrRouting() / IPv6ExtHdrRouting() /
                               IPv6ExtHdrFragment(offset=0, m=1) / ulp_l4)
                        # uncomment below to test invalid ones
                        # ulp = IPv6ExtHdrRouting(len = 200) / ulp_l4
                    else:
                        ulp = ulp_l4
                    p = (Ether(dst=dst_mac, src=src_mac) /
                         IPv6(src=src_ip6, dst=dst_ip6) /
                         ulp /
                         Raw(payload))
                else:
                    ulp_l4 = UDP(sport=src_l4, dport=dst_l4)
                    # IPv4 does not allow extension headers,
                    # but we rather make it a first fragment
                    flags = 1 if add_extension_header else 0
                    ulp = ulp_l4
                    p = (Ether(dst=dst_mac, src=src_mac) /
                         IP(src=src_ip4, dst=dst_ip4, frag=0, flags=flags) /
                         ulp /
                         Raw(payload))
            elif modulo == 1:
                if is_ip6:
                    ulp_l4 = ICMPv6Unknown(type=128 + (i % 2), code=i % 2)
                    ulp = ulp_l4
                    p = (Ether(dst=dst_mac, src=src_mac) /
                         IPv6(src=src_ip6, dst=dst_ip6) /
                         ulp /
                         Raw(payload))
                else:
                    ulp_l4 = ICMP(type=8 + (i % 2), code=i % 2)
                    ulp = ulp_l4
                    p = (Ether(dst=dst_mac, src=src_mac) /
                         IP(src=src_ip4, dst=dst_ip4) /
                         ulp /
                         Raw(payload))

            if i % 2 == 1:
                info.data = p.copy()
            size = packet_sizes[(i // 2) % len(packet_sizes)]
            self.extend_packet(p, size)
            pkts.append(p)

            rule_family = AF_INET6 if p.haslayer(IPv6) else AF_INET
            rule_prefix_len = 128 if p.haslayer(IPv6) else 32
            rule_l3_layer = IPv6 if p.haslayer(IPv6) else IP

            if p.haslayer(UDP):
                rule_l4_sport = p[UDP].sport
                rule_l4_dport = p[UDP].dport
            else:
                if p.haslayer(ICMP):
                    rule_l4_sport = p[ICMP].type
                    rule_l4_dport = p[ICMP].code
                else:
                    rule_l4_sport = p[ICMPv6Unknown].type
                    rule_l4_dport = p[ICMPv6Unknown].code
            if p.haslayer(IPv6):
                rule_l4_proto = ulp_l4.overload_fields[IPv6]['nh']
            else:
                rule_l4_proto = p[IP].proto

            new_rule = {
                        'is_permit': is_permit,
                        'is_ipv6': p.haslayer(IPv6),
                        'src_ip_addr': inet_pton(rule_family,
                                                 p[rule_l3_layer].src),
                        'src_ip_prefix_len': rule_prefix_len,
                        'dst_ip_addr': inet_pton(rule_family,
                                                 p[rule_l3_layer].dst),
                        'dst_ip_prefix_len': rule_prefix_len,
                        'srcport_or_icmptype_first': rule_l4_sport,
                        'srcport_or_icmptype_last': rule_l4_sport,
                        'dstport_or_icmpcode_first': rule_l4_dport,
                        'dstport_or_icmpcode_last': rule_l4_dport,
                        'proto': rule_l4_proto,
                       }
            rules.append(new_rule)
            new_rule_permit = new_rule.copy()
            new_rule_permit['is_permit'] = 1
            permit_rules.append(new_rule_permit)

            new_rule_permit_and_reflect = new_rule.copy()
            if can_reflect_this_packet:
                new_rule_permit_and_reflect['is_permit'] = 2
            else:
                new_rule_permit_and_reflect['is_permit'] = is_permit
            permit_and_reflect_rules.append(new_rule_permit_and_reflect)

        return {'stream': pkts,
                'rules': rules,
                'permit_rules': permit_rules,
                'permit_and_reflect_rules': permit_and_reflect_rules}

    def verify_capture(self, dst_ip_if, src_ip_if, capture, reverse):
        last_info = dict()
        for i in self.interfaces:
            last_info[i.sw_if_index] = None

        dst_ip_sw_if_index = dst_ip_if.sw_if_index
        return

        for packet in capture:
            l3 = IP if packet.haslayer(IP) else IPv6
            ip = packet[l3]
            if packet.haslayer(UDP):
                l4 = UDP
            else:
                if packet.haslayer(ICMP):
                    l4 = ICMP
                else:
                    l4 = ICMPv6Unknown

            # Scapy IPv6 stuff is too smart for its own good.
            # So we do this and coerce the ICMP into unknown type
            if packet.haslayer(UDP):
                data = str(packet[UDP][Raw])
            else:
                if l3 == IP:
                    data = str(ICMP(str(packet[l3].payload))[Raw])
                else:
                    data = str(ICMPv6Unknown(str(packet[l3].payload)).msgbody)
            udp_or_icmp = packet[l3].payload
            payload_info = self.payload_to_info(data)
            packet_index = payload_info.index

            self.assertEqual(payload_info.dst, dst_ip_sw_if_index)

            next_info = self.get_next_packet_info_for_interface2(
                payload_info.src, dst_ip_sw_if_index,
                last_info[payload_info.src])
            last_info[payload_info.src] = next_info
            self.assertTrue(next_info is not None)
            self.assertEqual(packet_index, next_info.index)
            saved_packet = next_info.data
            self.assertTrue(next_info is not None)

            # MAC: src, dst
            if not reverse:
                self.assertEqual(packet.src, dst_ip_if.local_mac)
                host = dst_ip_if.host_by_mac(packet.dst)

            # IP: src, dst
            # self.assertEqual(ip.src, src_ip_if.remote_ip4)
            if saved_packet is not None:
                self.assertEqual(ip.src, saved_packet[l3].src)
                self.assertEqual(ip.dst, saved_packet[l3].dst)
                if l4 == UDP:
                    self.assertEqual(udp_or_icmp.sport, saved_packet[l4].sport)
                    self.assertEqual(udp_or_icmp.dport, saved_packet[l4].dport)
            else:
                print("Saved packet is none")
            # self.assertEqual(ip.dst, host.ip4)

            # UDP:

    def create_acls_for_a_stream(self, stream_dict,
                                 test_l2_action, is_reflect):
        r = stream_dict['rules']
        r_permit = stream_dict['permit_rules']
        r_permit_reflect = stream_dict['permit_and_reflect_rules']
        r_action = r_permit_reflect if is_reflect else r
        reply = self.vapi.acl_add_replace(acl_index=4294967295, r=r_action,
                                          tag="act. acl")
        action_acl_index = reply.acl_index
        reply = self.vapi.acl_add_replace(acl_index=4294967295, r=r_permit,
                                          tag="perm. acl")
        permit_acl_index = reply.acl_index
        return {'L2': action_acl_index if test_l2_action else permit_acl_index,
                'L3': permit_acl_index if test_l2_action else action_acl_index,
                'permit': permit_acl_index, 'action': action_acl_index}

    def apply_acl_ip46_x_to_y(self, bridged_to_routed, test_l2_deny,
                              is_ip6, is_reflect, add_eh):
        """ Apply the ACLs
        """
        self.reset_packet_infos()
        stream_dict = self.create_stream(
                                         self.pg2, self.loop0,
                                         bridged_to_routed,
                                         self.pg_if_packet_sizes, is_ip6,
                                         not is_reflect, False, add_eh)
        stream = stream_dict['stream']
        acl_idx = self.create_acls_for_a_stream(stream_dict, test_l2_deny,
                                                is_reflect)
        n_input_l3 = 0 if bridged_to_routed else 1
        n_input_l2 = 1 if bridged_to_routed else 0
        self.vapi.acl_interface_set_acl_list(sw_if_index=self.pg2.sw_if_index,
                                             n_input=n_input_l3,
                                             acls=[acl_idx['L3']])
        self.vapi.acl_interface_set_acl_list(sw_if_index=self.pg0.sw_if_index,
                                             n_input=n_input_l2,
                                             acls=[acl_idx['L2']])
        self.vapi.acl_interface_set_acl_list(sw_if_index=self.pg1.sw_if_index,
                                             n_input=n_input_l2,
                                             acls=[acl_idx['L2']])

    def apply_acl_ip46_both_directions_reflect(self,
                                               primary_is_bridged_to_routed,
                                               reflect_on_l2, is_ip6, add_eh):
        primary_is_routed_to_bridged = not primary_is_bridged_to_routed
        self.reset_packet_infos()
        stream_dict_fwd = self.create_stream(self.pg2, self.loop0,
                                             primary_is_bridged_to_routed,
                                             self.pg_if_packet_sizes, is_ip6,
                                             False, False, add_eh)
        acl_idx_fwd = self.create_acls_for_a_stream(stream_dict_fwd,
                                                    reflect_on_l2, True)

        stream_dict_rev = self.create_stream(self.pg2, self.loop0,
                                             not primary_is_bridged_to_routed,
                                             self.pg_if_packet_sizes, is_ip6,
                                             True, True, add_eh)
        # We want the primary action to be "deny" rather than reflect
        acl_idx_rev = self.create_acls_for_a_stream(stream_dict_rev,
                                                    reflect_on_l2, False)

        if primary_is_bridged_to_routed:
            inbound_l2_acl = acl_idx_fwd['L2']
        else:
            inbound_l2_acl = acl_idx_rev['L2']

        if primary_is_routed_to_bridged:
            outbound_l2_acl = acl_idx_fwd['L2']
        else:
            outbound_l2_acl = acl_idx_rev['L2']

        if primary_is_routed_to_bridged:
            inbound_l3_acl = acl_idx_fwd['L3']
        else:
            inbound_l3_acl = acl_idx_rev['L3']

        if primary_is_bridged_to_routed:
            outbound_l3_acl = acl_idx_fwd['L3']
        else:
            outbound_l3_acl = acl_idx_rev['L3']

        self.vapi.acl_interface_set_acl_list(sw_if_index=self.pg2.sw_if_index,
                                             n_input=1,
                                             acls=[inbound_l3_acl,
                                                   outbound_l3_acl])
        self.vapi.acl_interface_set_acl_list(sw_if_index=self.pg0.sw_if_index,
                                             n_input=1,
                                             acls=[inbound_l2_acl,
                                                   outbound_l2_acl])
        self.vapi.acl_interface_set_acl_list(sw_if_index=self.pg1.sw_if_index,
                                             n_input=1,
                                             acls=[inbound_l2_acl,
                                                   outbound_l2_acl])

    def apply_acl_ip46_routed_to_bridged(self, test_l2_deny, is_ip6,
                                         is_reflect, add_eh):
        self.apply_acl_ip46_x_to_y(False, test_l2_deny, is_ip6,
                                   is_reflect, add_eh)

    def apply_acl_ip46_bridged_to_routed(self, test_l2_deny, is_ip6,
                                         is_reflect, add_eh):
        self.apply_acl_ip46_x_to_y(True, test_l2_deny, is_ip6,
                                   is_reflect, add_eh)

    def run_traffic_ip46_x_to_y(self, bridged_to_routed,
                                test_l2_deny, is_ip6,
                                is_reflect, is_established, add_eh):
        self.reset_packet_infos()
        stream_dict = self.create_stream(self.pg2, self.loop0,
                                         bridged_to_routed,
                                         self.pg_if_packet_sizes, is_ip6,
                                         not is_reflect, is_established,
                                         add_eh)
        stream = stream_dict['stream']

        tx_if = self.pg0 if bridged_to_routed else self.pg2
        rx_if = self.pg2 if bridged_to_routed else self.pg0

        tx_if.add_stream(stream)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        packet_count = self.get_packet_count_for_if_idx(self.loop0.sw_if_index)
        rcvd1 = rx_if.get_capture(packet_count)
        self.verify_capture(self.loop0, self.pg2, rcvd1, bridged_to_routed)

    def run_traffic_ip46_routed_to_bridged(self, test_l2_deny, is_ip6,
                                           is_reflect, is_established, add_eh):
        self.run_traffic_ip46_x_to_y(False, test_l2_deny, is_ip6,
                                     is_reflect, is_established, add_eh)

    def run_traffic_ip46_bridged_to_routed(self, test_l2_deny, is_ip6,
                                           is_reflect, is_established, add_eh):
        self.run_traffic_ip46_x_to_y(True, test_l2_deny, is_ip6,
                                     is_reflect, is_established, add_eh)

    def run_test_ip46_routed_to_bridged(self, test_l2_deny,
                                        is_ip6, is_reflect, add_eh):
        self.apply_acl_ip46_routed_to_bridged(test_l2_deny,
                                              is_ip6, is_reflect, add_eh)
        self.run_traffic_ip46_routed_to_bridged(test_l2_deny, is_ip6,
                                                is_reflect, False, add_eh)

    def run_test_ip46_bridged_to_routed(self, test_l2_deny,
                                        is_ip6, is_reflect, add_eh):
        self.apply_acl_ip46_bridged_to_routed(test_l2_deny,
                                              is_ip6, is_reflect, add_eh)
        self.run_traffic_ip46_bridged_to_routed(test_l2_deny, is_ip6,
                                                is_reflect, False, add_eh)

    def run_test_ip46_routed_to_bridged_and_back(self, test_l2_action,
                                                 is_ip6, add_eh):
        self.apply_acl_ip46_both_directions_reflect(False, test_l2_action,
                                                    is_ip6, add_eh)
        self.run_traffic_ip46_routed_to_bridged(test_l2_action, is_ip6,
                                                True, False, add_eh)
        self.run_traffic_ip46_bridged_to_routed(test_l2_action, is_ip6,
                                                False, True, add_eh)

    def run_test_ip46_bridged_to_routed_and_back(self, test_l2_action,
                                                 is_ip6, add_eh):
        self.apply_acl_ip46_both_directions_reflect(True, test_l2_action,
                                                    is_ip6, add_eh)
        self.run_traffic_ip46_bridged_to_routed(test_l2_action, is_ip6,
                                                True, False, add_eh)
        self.run_traffic_ip46_routed_to_bridged(test_l2_action, is_ip6,
                                                False, True, add_eh)

    def test_0000_ip6_irb_1(self):
        """ ACL plugin prepare"""
        if not self.vpp_dead:
            cmd = "set acl-plugin session timeout udp idle 2000"
            self.logger.info(self.vapi.ppcli(cmd))
            # uncomment to not skip past the routing header
            # and watch the EH tests fail
            # self.logger.info(self.vapi.ppcli(
            #    "set acl-plugin skip-ipv6-extension-header 43 0"))
            # uncomment to test the session limit (stateful tests will fail)
            # self.logger.info(self.vapi.ppcli(
            #    "set acl-plugin session table max-entries 1"))
            # new datapath is the default, but just in case
            # self.logger.info(self.vapi.ppcli(
            #    "set acl-plugin l2-datapath new"))
            # If you want to see some tests fail, uncomment the next line
            # self.logger.info(self.vapi.ppcli(
            #    "set acl-plugin l2-datapath old"))

    def test_0001_ip6_irb_1(self):
        """ ACL IPv6 routed -> bridged, L2 ACL deny"""
        self.run_test_ip46_routed_to_bridged(True, True, False,
                                             self.WITHOUT_EH)

    def test_0002_ip6_irb_1(self):
        """ ACL IPv6 routed -> bridged, L3 ACL deny"""
        self.run_test_ip46_routed_to_bridged(False, True, False,
                                             self.WITHOUT_EH)

    def test_0003_ip4_irb_1(self):
        """ ACL IPv4 routed -> bridged, L2 ACL deny"""
        self.run_test_ip46_routed_to_bridged(True, False, False,
                                             self.WITHOUT_EH)

    def test_0004_ip4_irb_1(self):
        """ ACL IPv4 routed -> bridged, L3 ACL deny"""
        self.run_test_ip46_routed_to_bridged(False, False, False,
                                             self.WITHOUT_EH)

    def test_0005_ip6_irb_1(self):
        """ ACL IPv6 bridged -> routed, L2 ACL deny """
        self.run_test_ip46_bridged_to_routed(True, True, False,
                                             self.WITHOUT_EH)

    def test_0006_ip6_irb_1(self):
        """ ACL IPv6 bridged -> routed, L3 ACL deny """
        self.run_test_ip46_bridged_to_routed(False, True, False,
                                             self.WITHOUT_EH)

    def test_0007_ip6_irb_1(self):
        """ ACL IPv4 bridged -> routed, L2 ACL deny """
        self.run_test_ip46_bridged_to_routed(True, False, False,
                                             self.WITHOUT_EH)

    def test_0008_ip6_irb_1(self):
        """ ACL IPv4 bridged -> routed, L3 ACL deny """
        self.run_test_ip46_bridged_to_routed(False, False, False,
                                             self.WITHOUT_EH)

    # Stateful ACL tests
    def test_0101_ip6_irb_1(self):
        """ ACL IPv6 routed -> bridged, L2 ACL permit+reflect"""
        self.run_test_ip46_routed_to_bridged_and_back(True, True,
                                                      self.WITHOUT_EH)

    def test_0102_ip6_irb_1(self):
        """ ACL IPv6 bridged -> routed, L2 ACL permit+reflect"""
        self.run_test_ip46_bridged_to_routed_and_back(True, True,
                                                      self.WITHOUT_EH)

    def test_0103_ip6_irb_1(self):
        """ ACL IPv4 routed -> bridged, L2 ACL permit+reflect"""
        self.run_test_ip46_routed_to_bridged_and_back(True, False,
                                                      self.WITHOUT_EH)

    def test_0104_ip6_irb_1(self):
        """ ACL IPv4 bridged -> routed, L2 ACL permit+reflect"""
        self.run_test_ip46_bridged_to_routed_and_back(True, False,
                                                      self.WITHOUT_EH)

    def test_0111_ip6_irb_1(self):
        """ ACL IPv6 routed -> bridged, L3 ACL permit+reflect"""
        self.run_test_ip46_routed_to_bridged_and_back(False, True,
                                                      self.WITHOUT_EH)

    def test_0112_ip6_irb_1(self):
        """ ACL IPv6 bridged -> routed, L3 ACL permit+reflect"""
        self.run_test_ip46_bridged_to_routed_and_back(False, True,
                                                      self.WITHOUT_EH)

    def test_0113_ip6_irb_1(self):
        """ ACL IPv4 routed -> bridged, L3 ACL permit+reflect"""
        self.run_test_ip46_routed_to_bridged_and_back(False, False,
                                                      self.WITHOUT_EH)

    def test_0114_ip6_irb_1(self):
        """ ACL IPv4 bridged -> routed, L3 ACL permit+reflect"""
        self.run_test_ip46_bridged_to_routed_and_back(False, False,
                                                      self.WITHOUT_EH)

    # A block of tests with extension headers

    def test_1001_ip6_irb_1(self):
        """ ACL IPv6+EH routed -> bridged, L2 ACL deny"""
        self.run_test_ip46_routed_to_bridged(True, True, False,
                                             self.WITH_EH)

    def test_1002_ip6_irb_1(self):
        """ ACL IPv6+EH routed -> bridged, L3 ACL deny"""
        self.run_test_ip46_routed_to_bridged(False, True, False,
                                             self.WITH_EH)

    def test_1005_ip6_irb_1(self):
        """ ACL IPv6+EH bridged -> routed, L2 ACL deny """
        self.run_test_ip46_bridged_to_routed(True, True, False,
                                             self.WITH_EH)

    def test_1006_ip6_irb_1(self):
        """ ACL IPv6+EH bridged -> routed, L3 ACL deny """
        self.run_test_ip46_bridged_to_routed(False, True, False,
                                             self.WITH_EH)

    def test_1101_ip6_irb_1(self):
        """ ACL IPv6+EH routed -> bridged, L2 ACL permit+reflect"""
        self.run_test_ip46_routed_to_bridged_and_back(True, True,
                                                      self.WITH_EH)

    def test_1102_ip6_irb_1(self):
        """ ACL IPv6+EH bridged -> routed, L2 ACL permit+reflect"""
        self.run_test_ip46_bridged_to_routed_and_back(True, True,
                                                      self.WITH_EH)

    def test_1111_ip6_irb_1(self):
        """ ACL IPv6+EH routed -> bridged, L3 ACL permit+reflect"""
        self.run_test_ip46_routed_to_bridged_and_back(False, True,
                                                      self.WITH_EH)

    def test_1112_ip6_irb_1(self):
        """ ACL IPv6+EH bridged -> routed, L3 ACL permit+reflect"""
        self.run_test_ip46_bridged_to_routed_and_back(False, True,
                                                      self.WITH_EH)

    # IPv4 with "MF" bit set

    def test_1201_ip6_irb_1(self):
        """ ACL IPv4+MF routed -> bridged, L2 ACL deny"""
        self.run_test_ip46_routed_to_bridged(True, False, False,
                                             self.WITH_EH)

    def test_1202_ip6_irb_1(self):
        """ ACL IPv4+MF routed -> bridged, L3 ACL deny"""
        self.run_test_ip46_routed_to_bridged(False, False, False,
                                             self.WITH_EH)

    def test_1205_ip6_irb_1(self):
        """ ACL IPv4+MF bridged -> routed, L2 ACL deny """
        self.run_test_ip46_bridged_to_routed(True, False, False,
                                             self.WITH_EH)

    def test_1206_ip6_irb_1(self):
        """ ACL IPv4+MF bridged -> routed, L3 ACL deny """
        self.run_test_ip46_bridged_to_routed(False, False, False,
                                             self.WITH_EH)

    def test_1301_ip6_irb_1(self):
        """ ACL IPv4+MF routed -> bridged, L2 ACL permit+reflect"""
        self.run_test_ip46_routed_to_bridged_and_back(True, False,
                                                      self.WITH_EH)

    def test_1302_ip6_irb_1(self):
        """ ACL IPv4+MF bridged -> routed, L2 ACL permit+reflect"""
        self.run_test_ip46_bridged_to_routed_and_back(True, False,
                                                      self.WITH_EH)

    def test_1311_ip6_irb_1(self):
        """ ACL IPv4+MF routed -> bridged, L3 ACL permit+reflect"""
        self.run_test_ip46_routed_to_bridged_and_back(False, False,
                                                      self.WITH_EH)

    def test_1312_ip6_irb_1(self):
        """ ACL IPv4+MF bridged -> routed, L3 ACL permit+reflect"""
        self.run_test_ip46_bridged_to_routed_and_back(False, False,
                                                      self.WITH_EH)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
