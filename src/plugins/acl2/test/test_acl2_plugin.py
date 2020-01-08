#!/usr/bin/env python3
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
from util import Host, ppp

from vpp_lo_interface import VppLoInterface
from vpp_papi import VppEnum


class TestACLplugin(VppTestCase):
    """ ACL plugin Test Case """

    # traffic types
    IP = 0
    ICMP = 1

    # IP version
    IPRANDOM = -1
    IPV4 = 0
    IPV6 = 1

    P_IP4 = "0.0.0.0/0"
    P_IP6 = "::/0"

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
        # rule types
        self.DENY = VppEnum.vl_api_acl2_action_t.ACL_API_ACTION_DENY
        self.PERMIT = VppEnum.vl_api_acl2_action_t.ACL_API_ACTION_PERMIT

        self.UDP = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP
        self.TCP = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_TCP
        self.ICMP4 = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP
        self.ICMP6 = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP6

        super(TestACLplugin, self).setUp()
        self.reset_packet_infos()

        self.vapi.cli("match engine set priority 1 classifier")

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
        self.logger.info(self.vapi.ppcli("show acl2-plugin acl"))
        self.logger.info(self.vapi.ppcli("show acl2-plugin interface"))
        self.logger.info(self.vapi.ppcli("show acl2-plugin tables"))
        self.logger.info(self.vapi.ppcli("show bridge-domain %s detail"
                                         % self.bd_id))

    def create_rule(self, s_prefix, action, ports=PORTS_ALL, proto=-1,
                    d_prefix=None):
        if not d_prefix:
            d_prefix = s_prefix
        if proto == -1:
            return
        if ports == self.PORTS_ALL:
            sport_from = 0
            dport_from = 0
            if proto != self.ICMP4 and proto != self.ICMP6:
                sport_to = 65535
            else:
                sport_to = 255
            dport_to = sport_to
        elif ports == self.PORTS_RANGE:
            if proto == self.ICMP4:
                sport_from = self.icmp4_type
                sport_to = self.icmp4_type
                dport_from = self.icmp4_code
                dport_to = self.icmp4_code
            elif proto == self.ICMP6:
                sport_from = self.icmp6_type
                sport_to = self.icmp6_type
                dport_from = self.icmp6_code
                dport_to = self.icmp6_code
            elif proto == self.TCP:
                sport_from = self.tcp_sport_from
                sport_to = self.tcp_sport_to
                dport_from = self.tcp_dport_from
                dport_to = self.tcp_dport_to
            elif proto == self.UDP:
                sport_from = self.udp_sport_from
                sport_to = self.udp_sport_to
                dport_from = self.udp_dport_from
                dport_to = self.udp_dport_to
        elif ports == self.PORTS_RANGE_2:
            if proto == self.ICMP4:
                sport_from = self.icmp4_type_2
                sport_to = self.icmp4_type_2
                dport_from = self.icmp4_code_from_2
                dport_to = self.icmp4_code_to_2
            elif proto == self.ICMP6:
                sport_from = self.icmp6_type_2
                sport_to = self.icmp6_type_2
                dport_from = self.icmp6_code_from_2
                dport_to = self.icmp6_code_to_2
            elif proto == self.TCP:
                sport_from = self.tcp_sport_from_2
                sport_to = self.tcp_sport_to_2
                dport_from = self.tcp_dport_from_2
                dport_to = self.tcp_dport_to_2
            elif proto == self.UDP:
                sport_from = self.udp_sport_from_2
                sport_to = self.udp_sport_to_2
                dport_from = self.udp_dport_from_2
                dport_to = self.udp_dport_to_2
        else:
            sport_from = ports
            sport_to = ports
            dport_from = ports
            dport_to = ports

        if proto == self.TCP or proto == self.UDP:
            rule = ({'action': action,
                     'rule': {
                         'mnt_src_ip': s_prefix,
                         'mnt_dst_ip': d_prefix,
                         'mnt_proto': proto,
                         'mnt_l4':
                         {
                             'mlu_l4':
                             {
                                 'ml4_src_port':
                                 {
                                     'mpr_begin': sport_from,
                                     'mpr_end': sport_to,
                                 },
                                 'ml4_dst_port':
                                 {
                                     'mpr_begin': dport_from,
                                     'mpr_end': dport_to,
                                 },
                                 'ml4_tcp':
                                 {
                                     'mtf_flags': 0,
                                     'mtf_mask': 0,
                                 },
                             },
                         }}})
        elif proto == self.ICMP or proto == self.ICMP6:
            rule = ({'action': action,
                     'rule': {
                         'mnt_src_ip': s_prefix,
                         'mnt_dst_ip': d_prefix,
                         'mnt_proto': proto,
                         'mnt_l4':
                         {
                             'mlu_icmp':
                             {
                                 'mir_codes':
                                 {
                                     'micr_begin': dport_from,
                                     'micr_end': dport_to,
                                 },
                                 'mir_types':
                                 {
                                     'mitr_begin': sport_from,
                                     'mitr_end': sport_to,
                                 },
                             },
                         }}})
        else:
            rule = ({'action': action,
                     'rule': {
                         'mnt_src_ip': s_prefix,
                         'mnt_dst_ip': d_prefix,
                         'mnt_proto': 0
                     }})
        return rule

    def apply_rules(self, rules, tag=b''):
        reply = self.vapi.acl2_add_replace(acl_index=4294967295,
                                           r=rules,
                                           count=len(rules),
                                           tag=tag)
        self.logger.info("Dumped ACL: " + str(
            self.vapi.acl2_dump(reply.acl_index)))
        # Apply a ACL on the interface as inbound
        for i in self.pg_interfaces:
            self.vapi.acl2_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                  n_input=1,
                                                  count=1,
                                                  acls=[reply.acl_index])
        return reply.acl_index

    def apply_rules_to(self, rules, tag=b'', sw_if_index=0xFFFFFFFF):
        reply = self.vapi.acl2_add_replace(acl_index=4294967295,
                                           r=rules,
                                           count=len(rules),
                                           tag=tag)
        self.logger.info("Dumped ACL: " + str(
            self.vapi.acl2_dump(reply.acl_index)))
        # Apply a ACL on the interface as inbound
        self.vapi.acl2_interface_set_acl_list(sw_if_index=sw_if_index,
                                              n_input=1,
                                              count=1,
                                              acls=[reply.acl_index])
        return reply.acl_index

    def etype_whitelist(self, whitelist, n_input):
        # Apply whitelists on all the interfaces
        for i in self.pg_interfaces:
            # checkstyle can't read long names. Help them.
            fun = self.vapi.acl2_interface_set_etype_whitelist
            fun(sw_if_index=i.sw_if_index, n_input=n_input,
                count=len(whitelist),
                whitelist=whitelist)
        return

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

    def test_0001_acl_create(self):
        """ ACL create/delete test
        """

        self.logger.info("ACLP_TEST_START_0001")
        # Add an ACL
        r = [{'action': VppEnum.vl_api_acl2_action_t.ACL_API_ACTION_PERMIT,
              'rule': {
                  'mnt_src_ip': "0.0.0.0/0",
                  'mnt_dst_ip': "0.0.0.0/0",
                  'mnt_proto': VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                  'mnt_l4':
                  {
                      'mlu_l4':
                      {
                          'ml4_src_port':
                          {
                              'mpr_begin': 1234,
                              'mpr_end': 1234,
                          },
                          'ml4_dst_port':
                          {
                              'mpr_begin': 1234,
                              'mpr_end': 1234,
                          },
                      },
                  }
              }}]
        # Test 1: add a new ACL
        reply = self.vapi.acl2_add_replace(acl_index=4294967295,
                                           r=r,
                                           count=len(r),
                                           tag=b"permit 1234")
        self.assertEqual(reply.retval, 0)
        # The very first ACL gets #0
        self.assertEqual(reply.acl_index, 0)
        first_acl = reply.acl_index
        rr = self.vapi.acl2_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        self.assertEqual(len(rr), 1)
        # We should have the same number of ACL entries as we had asked
        self.assertEqual(len(rr[0].r), len(r))
        # The rules should be the same. But because the submitted and returned
        # are different types, we need to iterate over rules and keys to get
        # to basic values.
        for i_rule in range(0, len(r) - 1):
            for rule_key in r[i_rule]:
                self.assertEqual(rr[0].r[i_rule][rule_key],
                                 r[i_rule][rule_key])
        a = VppEnum.vl_api_acl2_action_t

        # Add a deny-1234 ACL
        r_deny = [{'action': a.ACL_API_ACTION_DENY,
                   'rule': {
                       'mnt_src_ip': "0.0.0.0/0",
                       'mnt_dst_ip': "0.0.0.0/0",
                       'mnt_proto': VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                       'mnt_l4':
                       {
                           'mlu_l4':
                           {
                               'ml4_src_port':
                               {
                                   'mpr_begin': 1234,
                                   'mpr_end': 1234,
                               },
                               'ml4_dst_port':
                               {
                                   'mpr_begin': 1234,
                                   'mpr_end': 1234,
                               },
                           },
                       }
                   }},
                  {'action': a.ACL_API_ACTION_PERMIT,
                   'rule': {
                       'mnt_src_ip': "0.0.0.0/0",
                       'mnt_dst_ip': "0.0.0.0/0",
                       'mnt_proto': VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                       'mnt_l4':
                       {
                           'mlu_l4':
                           {
                               'ml4_src_port':
                               {
                                   'mpr_begin': 0,
                                   'mpr_end': 0xffff,
                               },
                               'ml4_dst_port':
                               {
                                   'mpr_begin': 0,
                                   'mpr_end': 0xffff,
                               },
                           },
                       }
                   }}]

        reply = self.vapi.acl2_add_replace(acl_index=4294967295, r=r_deny,
                                           count=len(r_deny),
                                           tag=b"deny 1234;permit all")
        self.assertEqual(reply.retval, 0)
        # The second ACL gets #1
        self.assertEqual(reply.acl_index, 1)
        second_acl = reply.acl_index

        # Test 2: try to modify a nonexistent ACL

        reply = self.vapi.papi.acl2_add_replace(acl_index=432, r=r,
                                                count=len(r),
                                                tag=b"FFFF:FFFF")
        self.assertEqual(reply.retval, -6)
        # The ACL number should pass through
        self.assertEqual(reply.acl_index, 432)
        # apply an ACL on an interface inbound, try to delete ACL, must fail
        self.vapi.acl2_interface_set_acl_list(sw_if_index=self.pg0.sw_if_index,
                                              n_input=1,
                                              count=1,
                                              acls=[first_acl])

        reply = self.vapi.papi.acl2_del(acl_index=first_acl)
        # Unapply an ACL and then try to delete it - must be ok
        self.vapi.acl2_interface_set_acl_list(sw_if_index=self.pg0.sw_if_index,
                                              count=0,
                                              n_input=0,
                                              acls=[])
        reply = self.vapi.acl2_del(acl_index=first_acl)

        # apply an ACL on an interface outbound, try to delete ACL, must fail
        self.vapi.acl2_interface_set_acl_list(sw_if_index=self.pg0.sw_if_index,
                                              n_input=0,
                                              count=1,
                                              acls=[second_acl])

        reply = self.vapi.papi.acl2_del(acl_index=second_acl)
        # Unapply the ACL and then try to delete it - must be ok
        self.vapi.acl2_interface_set_acl_list(sw_if_index=self.pg0.sw_if_index,
                                              n_input=0,
                                              count=0,
                                              acls=[])
        reply = self.vapi.acl2_del(acl_index=second_acl)

        # try to apply a nonexistent ACL - must fail
        reply = self.vapi.papi.acl2_interface_set_acl_list(
            sw_if_index=self.pg0.sw_if_index,
            n_input=1,
            count=1,
            acls=[first_acl])
        self.assertEqual(reply.retval, -6)

        self.logger.info("ACLP_TEST_FINISH_0001")

    def test_0002_acl_permit_apply(self):
        """ permit ACL apply test
        """
        self.logger.info("ACLP_TEST_START_0002")

        rules = []
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_RANGE, self.UDP))
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_RANGE, self.TCP))

        # Apply rules
        acl_idx = self.apply_rules(rules, b"permit per-flow")

        # enable counters
        reply = self.vapi.papi.acl2_stats_intf_counters_enable(enable=1)

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4, -1)

        matches = self.statistics.get_counter('/acl2/%d/matches' % acl_idx)

        self.logger.info("stat segment counters: %s" % repr(matches))
        self.logger.info(self.vapi.ppcli("show acl2-plugin acl"))
        self.logger.info(self.vapi.ppcli("show acl2-plugin tables"))

        total_hits = matches[0][0]['packets'] + matches[0][1]['packets']
        self.assertEqual(total_hits, 64)

        # disable counters
        reply = self.vapi.papi.acl2_stats_intf_counters_enable(enable=0)

        self.logger.info("ACLP_TEST_FINISH_0002")

    def test_0003_acl_deny_apply(self):
        """ deny ACL apply test
        """
        self.logger.info("ACLP_TEST_START_0003")

        # Add a deny-flows ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                     self.PORTS_ALL, self.UDP))
        # Permit ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        acl_idx = self.apply_rules(rules, b"deny per-flow;permit all")

        # enable counters
        reply = self.vapi.papi.acl2_stats_intf_counters_enable(enable=1)

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPV4, self.UDP)

        matches = self.statistics.get_counter('/acl2/%d/matches' % acl_idx)
        self.logger.info("stat segment counters: %s" % repr(matches))
        cli = "show acl-plugin acl"
        self.logger.info(self.vapi.ppcli(cli))
        cli = "show acl-plugin tables"
        self.logger.info(self.vapi.ppcli(cli))
        self.assertEqual(matches[0][0]['packets'], 64)
        # disable counters
        reply = self.vapi.papi.acl2_stats_intf_counters_enable(enable=0)
        self.logger.info("ACLP_TEST_FINISH_0003")
        # self.assertEqual(, 0)

    def test_0004_vpp624_permit_icmpv4(self):
        """ VPP_624 permit ICMPv4
        """
        self.logger.info("ACLP_TEST_START_0004")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_RANGE, self.ICMP4))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_ALL, self.ICMP4))

        # Apply rules
        self.apply_rules(rules, b"permit icmpv4")

        # Traffic should still pass
        self.run_verify_test(self.ICMP, self.IPV4, self.ICMP4)

        self.logger.info("ACLP_TEST_FINISH_0004")

    def test_0005_vpp624_permit_icmpv6(self):
        """ VPP_624 permit ICMPv6
        """
        self.logger.info("ACLP_TEST_START_0005")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_RANGE, self.ICMP6))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_ALL, self.ICMP6))

        # Apply rules
        self.apply_rules(rules, b"permit icmpv6")

        # Traffic should still pass
        self.run_verify_test(self.ICMP, self.IPV6, self.ICMP6)

        self.logger.info("ACLP_TEST_FINISH_0005")

    def test_0006_vpp624_deny_icmpv4(self):
        """ VPP_624 deny ICMPv4
        """
        self.logger.info("ACLP_TEST_START_0006")
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_RANGE,
                                      self.ICMP4))
        # permit ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"deny icmpv4")

        # Traffic should not pass
        self.run_verify_negat_test(self.ICMP, self.IPV4, 0)

        self.logger.info("ACLP_TEST_FINISH_0006")

    def test_0007_vpp624_deny_icmpv6(self):
        """ VPP_624 deny ICMPv6
        """
        self.logger.info("ACLP_TEST_START_0007")
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_RANGE, self.ICMP6))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"deny icmpv6")

        # Traffic should not pass
        self.run_verify_negat_test(self.ICMP, self.IPV6, 0)

        self.logger.info("ACLP_TEST_FINISH_0007")

    def test_0008_tcp_permit_v4(self):
        """ permit TCPv4
        """
        self.logger.info("ACLP_TEST_START_0008")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_RANGE, self.TCP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ipv4 tcp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4, self.TCP)

        self.logger.info("ACLP_TEST_FINISH_0008")

    def test_0009_tcp_permit_v6(self):
        """ permit TCPv6
        """
        self.logger.info("ACLP_TEST_START_0009")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_RANGE, self.TCP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ip6 tcp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV6, self.TCP)

        self.logger.info("ACLP_TEST_FINISH_0008")

    def test_0010_udp_permit_v4(self):
        """ permit UDPv4
        """
        self.logger.info("ACLP_TEST_START_0010")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_RANGE, self.UDP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ipv udp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4, self.UDP)

        self.logger.info("ACLP_TEST_FINISH_0010")

    def test_0011_udp_permit_v6(self):
        """ permit UDPv6
        """
        self.logger.info("ACLP_TEST_START_0011")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_RANGE, self.UDP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ip6 udp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV6, self.UDP)

        self.logger.info("ACLP_TEST_FINISH_0011")

    def test_0012_tcp_deny(self):
        """ deny TCPv4/v6
        """
        self.logger.info("ACLP_TEST_START_0012")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_RANGE, self.TCP))
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_RANGE, self.TCP))
        # permit ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_ALL, 0))
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"deny ip4/ip6 tcp")

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPRANDOM, self.TCP)

        self.logger.info("ACLP_TEST_FINISH_0012")

    def test_0013_udp_deny(self):
        """ deny UDPv4/v6
        """
        self.logger.info("ACLP_TEST_START_0013")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_RANGE, self.UDP))
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_RANGE, self.UDP))
        # permit ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_ALL, 0))
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"deny ip4/ip6 udp")

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPRANDOM, self.UDP)

        self.logger.info("ACLP_TEST_FINISH_0013")

    def test_0014_acl_dump(self):
        """ verify add/dump acls
        """
        self.logger.info("ACLP_TEST_START_0014")

        r = [[self.P_IP4, self.PERMIT, 1234, self.TCP],
             [self.P_IP4, self.PERMIT, 2345, self.UDP],
             [self.P_IP4, self.PERMIT, 0, self.TCP],
             [self.P_IP4, self.PERMIT, 0, self.UDP],
             [self.P_IP4, self.PERMIT, 5, self.ICMPv4],
             [self.P_IP6, self.PERMIT, 4321, self.TCP],
             [self.P_IP6, self.PERMIT, 5432, self.UDP],
             [self.P_IP6, self.PERMIT, 0, self.TCP],
             [self.P_IP6, self.PERMIT, 0, self.UDP],
             [self.P_IP6, self.PERMIT, 6, self.ICMPv6],
             [self.P_IP4, self.DENY, self.PORTS_ALL, 0],
             [self.P_IP4, self.DENY, 1234, self.TCP],
             [self.P_IP4, self.DENY, 2345, self.UDP],
             [self.P_IP4, self.DENY, 5, self.ICMP4],
             [self.P_IP6, self.DENY, 4321, self.TCP],
             [self.P_IP6, self.DENY, 5432, self.UDP],
             [self.P_IP6, self.DENY, 6, self.ICMP6],
             [self.P_IP6, self.DENY, self.PORTS_ALL, 0]
             ]

        # Add and verify new ACLs
        rules = []
        for i in range(len(r)):
            rules.append(self.create_rule(r[i][0], r[i][1], r[i][2], r[i][3]))

        reply = self.vapi.acl2_add_replace(acl_index=4294967295, r=rules,
                                           count=len(rules), tag=b'')
        result = self.vapi.acl2_dump(reply.acl_index)

        for drules in result:
            for dr, rule in zip(drules.r, rules):
                self.assertEqual(dr.action, rule['action'])

                mnt = rule['rule']
                dmnt = dr.rule

                self.assertEqual(str(dmnt.mnt_src_ip), mnt['mnt_src_ip'])
                self.assertEqual(str(dmnt.mnt_dst_ip), mnt['mnt_dst_ip'])

                self.assertEqual(dmnt.mnt_proto, mnt['mnt_proto'])

                if dmnt.mnt_proto == self.TCP or \
                   dmnt.mnt_proto == self.UDP:
                    l4 = mnt['mnt_l4']['mlu_l4']
                    dl4 = dmnt.mnt_l4.mlu_l4

                    self.assertEqual(dl4.ml4_src_port.mpr_begin,
                                     l4['ml4_src_port']['mpr_begin'])
                    self.assertEqual(dl4.ml4_src_port.mpr_end,
                                     l4['ml4_src_port']['mpr_end'])
                    self.assertEqual(dl4.ml4_dst_port.mpr_begin,
                                     l4['ml4_dst_port']['mpr_begin'])
                    self.assertEqual(dl4.ml4_dst_port.mpr_end,
                                     l4['ml4_dst_port']['mpr_end'])

                    if dmnt.mnt_proto == self.TCP:
                        self.assertEqual(dl4.ml4_tcp.mtf_flags,
                                         l4['ml4_tcp']['mtf_flags'])
                        self.assertEqual(dl4.ml4_tcp.mtf_mask,
                                         l4['ml4_tcp']['mtf_mask'])
                elif (dmnt.mnt_proto == self.ICMP4 or
                      dmnt.mnt_proto == self.ICMP6):
                    ic = mnt['mnt_l4']['mlu_icmp']
                    dic = dmnt.mnt_l4.mlu_icmp

                    self.assertEqual(dic.mir_types.mitr_begin,
                                     ic['mir_types']['mitr_begin'])
                    self.assertEqual(dic.mir_types.mitr_end,
                                     ic['mir_types']['mitr_end'])
                    self.assertEqual(dic.mir_codes.micr_begin,
                                     ic['mir_codes']['micr_begin'])
                    self.assertEqual(dic.mir_codes.micr_end,
                                     ic['mir_codes']['micr_end'])

        self.logger.info("ACLP_TEST_FINISH_0014")

    def test_0015_tcp_permit_port_v4(self):
        """ permit single TCPv4
        """
        self.logger.info("ACLP_TEST_START_0015")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.PERMIT, port, self.TCP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ip4 tcp %d" % port)

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4, self.TCP, port)

        self.logger.info("ACLP_TEST_FINISH_0015")

    def test_0016_udp_permit_port_v4(self):
        """ permit single UDPv4
        """
        self.logger.info("ACLP_TEST_START_0016")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.PERMIT, port, self.UDP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ip4 tcp %d" % port)

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4, self.UDP, port)

        self.logger.info("ACLP_TEST_FINISH_0016")

    def test_0017_tcp_permit_port_v6(self):
        """ permit single TCPv6
        """
        self.logger.info("ACLP_TEST_START_0017")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP6, self.PERMIT, port, self.TCP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ip4 tcp %d" % port)

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV6, self.TCP, port)

        self.logger.info("ACLP_TEST_FINISH_0017")

    def test_0018_udp_permit_port_v6(self):
        """ permit single UPPv6
        """
        self.logger.info("ACLP_TEST_START_0018")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP6, self.PERMIT, port, self.UDP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ip4 tcp %d" % port)

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV6, self.UDP, port)

        self.logger.info("ACLP_TEST_FINISH_0018")

    def test_0019_udp_deny_port(self):
        """ deny single TCPv4/v6
        """
        self.logger.info("ACLP_TEST_START_0019")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.DENY, port, self.TCP))
        rules.append(self.create_rule(self.P_IP6, self.DENY, port, self.TCP))
        # Permit ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_ALL, 0))
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"deny ip4/ip6 udp %d" % port)

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPRANDOM, self.TCP, port)

        self.logger.info("ACLP_TEST_FINISH_0019")

    def test_0020_udp_deny_port(self):
        """ deny single UDPv4/v6
        """
        self.logger.info("ACLP_TEST_START_0020")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.DENY, port, self.UDP))
        rules.append(self.create_rule(self.P_IP6, self.DENY, port, self.UDP))
        # Permit ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_ALL, 0))
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"deny ip4/ip6 udp %d" % port)

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPRANDOM, self.UDP, port)

        self.logger.info("ACLP_TEST_FINISH_0020")

    def test_0021_udp_deny_port_verify_fragment_deny(self):
        """ deny single UDPv4/v6, permit ip any, verify non-initial fragment
        blocked
        """
        self.logger.info("ACLP_TEST_START_0021")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.DENY, port, self.UDP))
        rules.append(self.create_rule(self.P_IP6, self.DENY, port, self.UDP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_ALL, 0))
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"deny ip4/ip6 udp %d" % port)

        # print(self.vapi.cli("sh acl2-plugin acl"))
        # print(self.vapi.cli("sh acl2-plugin interface detail"))

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPRANDOM,
                                   self.UDP, port, True)

        self.logger.info("ACLP_TEST_FINISH_0021")

    def test_0022_zero_length_udp_ipv4(self):
        """ VPP-687 zero length udp ipv4 packet"""
        self.logger.info("ACLP_TEST_START_0022")

        port = random.randint(16384, 65535)
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.PERMIT, port, self.UDP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit empty udp ip4 %d" % port)

        # Traffic should still pass
        # Create incoming packet streams for packet-generator interfaces
        pkts_cnt = 0
        pkts = self.create_stream(self.pg0, self.pg_if_packet_sizes,
                                  self.IP, self.IPV4,
                                  self.UDP, port,
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
        rules.append(self.create_rule(self.P_IP6, self.PERMIT, port, self.UDP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit empty udp ip6 %d" % port)

        # Traffic should still pass
        # Create incoming packet streams for packet-generator interfaces
        pkts_cnt = 0
        pkts = self.create_stream(self.pg0, self.pg_if_packet_sizes,
                                  self.IP, self.IPV6,
                                  self.UDP, port,
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
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_RANGE_2, self.TCP))
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_RANGE, self.TCP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ipv4 tcp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4, self.TCP)

        self.logger.info("ACLP_TEST_FINISH_0108")

    def test_0109_tcp_permit_v6(self):
        """ permit TCPv6 + non-match range
        """
        self.logger.info("ACLP_TEST_START_0109")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_RANGE_2, self.TCP))
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_RANGE, self.TCP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ip6 tcp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV6, self.TCP)

        self.logger.info("ACLP_TEST_FINISH_0109")

    def test_0110_udp_permit_v4(self):
        """ permit UDPv4 + non-match range
        """
        self.logger.info("ACLP_TEST_START_0110")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_RANGE_2, self.UDP))
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_RANGE, self.UDP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ipv4 udp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4, self.UDP)

        self.logger.info("ACLP_TEST_FINISH_0110")

    def test_0111_udp_permit_v6(self):
        """ permit UDPv6 + non-match range
        """
        self.logger.info("ACLP_TEST_START_0111")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_RANGE_2, self.UDP))
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_RANGE, self.UDP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ip6 udp")

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV6, self.UDP)

        self.logger.info("ACLP_TEST_FINISH_0111")

    def test_0112_tcp_deny(self):
        """ deny TCPv4/v6 + non-match range
        """
        self.logger.info("ACLP_TEST_START_0112")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_RANGE_2, self.TCP))
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_RANGE_2, self.TCP))
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_RANGE, self.TCP))
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_RANGE, self.TCP))
        # permit ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_ALL, 0))
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"deny ip4/ip6 tcp")

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPRANDOM, self.TCP)

        self.logger.info("ACLP_TEST_FINISH_0112")

    def test_0113_udp_deny(self):
        """ deny UDPv4/v6 + non-match range
        """
        self.logger.info("ACLP_TEST_START_0113")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_RANGE_2, self.UDP))
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_RANGE_2, self.UDP))
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_RANGE, self.UDP))
        rules.append(self.create_rule(self.P_IP6, self.DENY,
                                      self.PORTS_RANGE, self.UDP))
        # permit ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_ALL, 0))
        rules.append(self.create_rule(self.P_IP6, self.PERMIT,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"deny ip4/ip6 udp")

        # Traffic should not pass
        self.run_verify_negat_test(self.IP, self.IPRANDOM, self.UDP)

        self.logger.info("ACLP_TEST_FINISH_0113")

    def test_0300_tcp_permit_v4_etype_aaaa(self):
        """ permit TCPv4, send 0xAAAA etype
        """
        self.logger.info("ACLP_TEST_START_0300")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_RANGE_2, self.TCP))
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_RANGE, self.TCP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ipv4 tcp")

        # Traffic should still pass also for an odd ethertype
        self.run_verify_test(self.IP, self.IPV4, self.TCP,
                             0, False, True, 0xaaaa)
        self.logger.info("ACLP_TEST_FINISH_0300")

    def test_0305_tcp_permit_v4_etype_blacklist_aaaa(self):
        """ permit TCPv4, whitelist 0x0BBB ethertype, send 0xAAAA-blocked
        """
        self.logger.info("ACLP_TEST_START_0305")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_RANGE_2, self.TCP))
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_RANGE, self.TCP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ipv4 tcp")

        # whitelist the 0xbbbb etype - so the 0xaaaa should be blocked
        self.etype_whitelist([0xbbb], 1)

        # The oddball ethertype should be blocked
        self.run_verify_negat_test(self.IP, self.IPV4,
                                   self.TCP, 0, False, 0xaaaa)

        # remove the whitelist
        self.etype_whitelist([], 0)

        self.logger.info("ACLP_TEST_FINISH_0305")

    def test_0306_tcp_permit_v4_etype_blacklist_aaaa(self):
        """ permit TCPv4, whitelist 0x0BBB ethertype, send 0x0BBB - pass
        """
        self.logger.info("ACLP_TEST_START_0306")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_RANGE_2, self.TCP))
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_RANGE, self.TCP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ipv4 tcp")

        # whitelist the 0xbbbb etype - so the 0xaaaa should be blocked
        self.etype_whitelist([0xbbb], 1)

        # The whitelisted traffic, should pass
        self.run_verify_test(self.IP, self.IPV4, self.TCP,
                             0, False, True, 0x0bbb)

        # remove the whitelist, the previously blocked 0xAAAA should pass now
        self.etype_whitelist([], 0)

        self.logger.info("ACLP_TEST_FINISH_0306")

    def test_0307_tcp_permit_v4_etype_blacklist_aaaa(self):
        """ permit TCPv4, whitelist 0x0BBB, remove, send 0xAAAA - pass
        """
        self.logger.info("ACLP_TEST_START_0307")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_RANGE_2, self.TCP))
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_RANGE, self.TCP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_ALL, 0))

        # Apply rules
        self.apply_rules(rules, b"permit ipv4 tcp")

        # whitelist the 0xbbbb etype - so the 0xaaaa should be blocked
        self.etype_whitelist([0xbbb], 1)
        # remove the whitelist, the previously blocked 0xAAAA should pass now
        self.etype_whitelist([], 0)

        # The whitelisted traffic, should pass
        self.run_verify_test(self.IP, self.IPV4, self.TCP,
                             0, False, True, 0xaaaa)

        self.logger.info("ACLP_TEST_FINISH_0306")

    def test_0315_del_intf(self):
        """ apply an acl and delete the interface
        """
        self.logger.info("ACLP_TEST_START_0315")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_RANGE_2, self.TCP))
        rules.append(self.create_rule(self.P_IP4, self.PERMIT,
                                      self.PORTS_RANGE, self.TCP))
        # deny ip any any in the end
        rules.append(self.create_rule(self.P_IP4, self.DENY,
                                      self.PORTS_ALL, 0))

        # create an interface
        intf = []
        intf.append(VppLoInterface(self))

        # Apply rules
        self.apply_rules_to(rules, b"permit ipv4 tcp", intf[0].sw_if_index)

        # Remove the interface
        intf[0].remove_vpp_config()

        self.logger.info("ACLP_TEST_FINISH_0315")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
