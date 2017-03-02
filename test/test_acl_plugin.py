#!/usr/bin/env python
"""ACL plugin Test Case HLD:

**config 1**
    - add 4 pg-l2 interfaces
    - configure them into l2bd

"""

import unittest
import random

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from framework import VppTestCase, VppTestRunner
from util import Host, ppp


class TestACLplugin(VppTestCase):
    """ ACL plugin Test Case """

    IP = 0
    ICMP = 1
    IPV4 = 0
    IPV6 = 1
    TCP = 0
    UDP = 1
    DENY = 0
    PERMIT = 1

    # Test variables
    bd_id = 1
    mac_entries_count = 200

    proto = [6, 17]
    proto_map = {6: 'TCP', 17: 'UDP'}

    udp_sport_from = 10000
    udp_sport_to = udp_sport_from + 5000
    udp_dport_from = 20000
    udp_dport_to = udp_dport_from + 5000
    tcp_sport_from = 30000
    tcp_sport_to = tcp_sport_from + 5000
    tcp_dport_from = 40000
    tcp_dport_to = tcp_dport_from + 5000

    icmp4_type = 8  # echo request
    icmp4_code = 3
    icmp6_type = 128  # echo request
    icmp6_code = 3

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(TestACLplugin, cls).setUpClass()

        random.seed()

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
                cls.vapi.sw_interface_set_l2_bridge(pg_if.sw_if_index,
                                                    bd_id=cls.bd_id)

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

        except Exception:
            super(TestACLplugin, cls).tearDownClass()
            raise

    def setUp(self):
        super(TestACLplugin, self).setUp()
        self.reset_packet_infos()

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(TestACLplugin, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.ppcli("show l2fib verbose"))
            self.logger.info(self.vapi.ppcli("show bridge-domain %s detail"
                                             % self.bd_id))

    def create_hosts(self, count, start=0):
        """
        Create required number of host MAC addresses and distribute them among
        interfaces. Create host IPv4 address for every host MAC address.

        :param int count: Number of hosts to create MAC/IPv4 addresses for.
        :param int start: Number to start numbering from.
        """
        n_int = len(self.pg_interfaces)
        macs_per_if = count / n_int
        i = -1
        for pg_if in self.pg_interfaces:
            i += 1
            start_nr = macs_per_if * i + start
            end_nr = count + start if i == (n_int - 1) \
                else macs_per_if * (i + 1) + start
            hosts = self.hosts_by_pg_idx[pg_if.sw_if_index]
            for j in range(start_nr, end_nr):
                host = Host(
                    "00:00:00:ff:%02x:%02x" % (pg_if.sw_if_index, j),
                    "172.17.1%02x.%u" % (pg_if.sw_if_index, j),
                    "2017:dead:%02x::%u" % (pg_if.sw_if_index, j))
                hosts.append(host)

    def create_rule(self, ip=0, permit_deny=0, ports=True, proto=-1):
        if proto == -1:
            return
        sport_from = 0
        dport_from = 0
        sport_to = 65535 if proto != 1 and proto != 58 else 255
        dport_to = sport_to
        if ports:
            if proto == 1:
                sport_from = self.icmp4_type
                sport_to = self.icmp4_type
                dport_from = self.icmp4_code
                dport_to = self.icmp4_code
            elif proto == 58:
                sport_from = self.icmp6_type
                sport_to = self.icmp6_type
                dport_from = self.icmp6_code
                dport_to = self.icmp6_code
            elif proto == self.proto[self.TCP]:
                sport_from = self.tcp_sport_from
                sport_to = self.tcp_sport_to
                dport_from = self.tcp_dport_from
                dport_to = self.tcp_dport_to
            elif proto == self.proto[self.UDP]:
                sport_from = self.udp_sport_from
                sport_to = self.udp_sport_to
                dport_from = self.udp_dport_from
                dport_to = self.udp_dport_to

        rule = ({'is_permit': permit_deny, 'is_ipv6': ip, 'proto': proto,
                 'srcport_or_icmptype_first': sport_from,
                 'srcport_or_icmptype_last': sport_to,
                 'src_ip_prefix_len': 0,
                 'src_ip_addr': '\x00\x00\x00\x00',
                 'dstport_or_icmpcode_first': dport_from,
                 'dstport_or_icmpcode_last': dport_to,
                 'dst_ip_addr': '\x00\x00\x00\x00',
                 'dst_ip_prefix_len': 0})
        return rule

    def create_upper_layer(self, packet_index, proto):
        p = self.proto_map[proto]
        if p == 'UDP':
            return UDP(sport=random.randint(self.udp_sport_from,
                                            self.udp_sport_to),
                       dport=random.randint(self.udp_dport_from,
                                            self.udp_dport_to))
        elif p == 'TCP':
            return TCP(sport=random.randint(self.tcp_sport_from,
                                            self.tcp_sport_to),
                       dport=random.randint(self.tcp_dport_from,
                                            self.tcp_dport_to))
        return ''

    def create_stream(self, src_if, packet_sizes, traffic_type=0, ipv6=0,
                      proto=-1):
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
                    dst_host = dst_hosts[i / len(src_hosts)]
                    src_host = src_hosts[i % len(src_hosts)]
                    pkt_info = self.create_packet_info(src_if, dst_if)
                    pkt_info.ip = 1 if ipv6 else 0
                    if proto == -1:
                        pkt_info.proto = random.choice(self.proto)
                    else:
                        pkt_info.proto = proto
                    payload = self.info_to_payload(pkt_info)
                    p = Ether(dst=dst_host.mac, src=src_host.mac)
                    if ipv6:
                        p /= IPv6(dst=dst_host.ip6, src=src_host.ip6)
                    else:
                        p /= IP(src=src_host.ip4, dst=dst_host.ip4)
                    if traffic_type == self.ICMP:
                        if ipv6:
                            p /= ICMPv6EchoRequest(type=self.icmp6_type,
                                                   code=self.icmp6_code)
                        else:
                            p /= ICMP(type=self.icmp4_type,
                                      code=self.icmp4_code)
                    else:
                        if traffic_type == self.IP:
                            p /= self.create_upper_layer(i, pkt_info.proto)
                            p /= Raw(payload)
                        pkt_info.data = p.copy()
                        size = random.choice(packet_sizes)
                        self.extend_packet(p, size)
                    pkts.append(p)
        return pkts

    def verify_capture(self, pg_if, capture, traffic_type=0, ip_type=0):
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
            if traffic_type == self.ICMP:
                try:
                    if packet.haslayer(ICMP):
                        self.assertEqual(packet[ICMP].type, self.icmp4_type)
                        self.assertEqual(packet[ICMP].code, self.icmp4_code)
                    elif packet.haslayer(ICMPv6EchoRequest):
                        self.assertEqual(packet[ICMPv6EchoRequest].type,
                                         self.icmp6_type)
                        self.assertEqual(packet[ICMPv6EchoRequest].code,
                                         self.icmp6_code)
                except:
                    self.logger.error(ppp("Unexpected or invalid packet "
                                          "(outside network):", packet))
                    raise
            else:
                payload_info = self.payload_to_info(str(packet[Raw]))
                try:
                    self.assertEqual(payload_info.ip, ip_type)
                    ip_version = IPv6 if payload_info.ip == 1 else IP

                    ip = packet[ip_version]
                    packet_index = payload_info.index

                    self.assertTrue(packet.haslayer(self.proto_map[
                                                        payload_info.proto]))
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
                    if packet.haslayer(self.proto_map[payload_info.proto]):
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

    def run_traffic_no_check(self, traffic_type=0, ip_type=0):
        # Test
        # Create incoming packet streams for packet-generator interfaces
        for i in self.pg_interfaces:
            if self.flows.__contains__(i):
                pkts = self.create_stream(i, self.pg_if_packet_sizes,
                                          traffic_type, ip_type)
                if len(pkts) > 0:
                    i.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

    def run_verify_test(self, traffic_type=0, ip_type=0, proto=-1):
        # Test
        # Create incoming packet streams for packet-generator interfaces
        for i in self.pg_interfaces:
            if self.flows.__contains__(i):
                pkts = self.create_stream(i, self.pg_if_packet_sizes,
                                          traffic_type, ip_type, proto)
                if len(pkts) > 0:
                    i.add_stream(pkts)

        # Enable packet capture and start packet sendingself.IPV
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for src_if in self.pg_interfaces:
            if self.flows.__contains__(src_if):
                for dst_if in self.flows[src_if]:
                    capture = dst_if.get_capture()
                    self.logger.info("Verifying capture on interface %s" %
                                     dst_if.name)
                    self.verify_capture(dst_if, capture, traffic_type, ip_type)

    def run_verify_negat_test(self, traffic_type=0, ip_type=0, proto=-1):
        # Test
        self.reset_packet_infos()
        for i in self.pg_interfaces:
            if self.flows.__contains__(i):
                pkts = self.create_stream(i, self.pg_if_packet_sizes,
                                          traffic_type, ip_type, proto)
                if len(pkts) > 0:
                    i.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for src_if in self.pg_interfaces:
            if self.flows.__contains__(src_if):
                for dst_if in self.flows[src_if]:
                    src_if.assert_nothing_captured(remark="outgoing interface")

    def api_acl_add_replace(self, acl_index, r, count, tag='',
                            expected_retval=0):
        """Add/replace an ACL

        :param int acl_index: ACL index to replace,
        4294967295 to create new ACL.
        :param acl_rule r: ACL rules array.
        :param str tag: symbolic tag (description) for this ACL.
        :param int count: number of rules.
        """
        return self.vapi.api(self.vapi.papi.acl_add_replace,
                             {'acl_index': acl_index,
                              'r': r,
                              'count': count,
                              'tag': tag},
                             expected_retval=expected_retval)

    def api_acl_interface_set_acl_list(self, sw_if_index, count, n_input, acls,
                                       expected_retval=0):
        return self.vapi.api(self.vapi.papi.acl_interface_set_acl_list,
                             {'sw_if_index': sw_if_index,
                              'count': count,
                              'n_input': n_input,
                              'acls': acls},
                             expected_retval=expected_retval)

    def api_acl_dump(self, acl_index, expected_retval=0):
        return self.vapi.api(self.vapi.papi.acl_dump,
                             {'acl_index': acl_index},
                             expected_retval=expected_retval)

    def test_0000_warmup_test(self):
        """ ACL plugin version check; learn MACs
        """
        self.create_hosts(16)
        self.run_traffic_no_check()
        reply = self.vapi.papi.acl_plugin_get_version()
        self.assertEqual(reply.major, 1)
        self.logger.info("Working with ACL plugin version: %d.%d" % (
            reply.major, reply.minor))
        # minor version changes are non breaking
        # self.assertEqual(reply.minor, 0)

    def test_0001_acl_create(self):
        """ ACL create test
        """

        self.logger.info("ACLP_TEST_START_0001")
        # Add an ACL
        r = [{'is_permit': 1, 'is_ipv6': 0, 'proto': 17,
              'srcport_or_icmptype_first': 1234,
              'srcport_or_icmptype_last': 1235,
              'src_ip_prefix_len': 0,
              'src_ip_addr': '\x00\x00\x00\x00',
              'dstport_or_icmpcode_first': 1234,
              'dstport_or_icmpcode_last': 1234,
              'dst_ip_addr': '\x00\x00\x00\x00',
              'dst_ip_prefix_len': 0}]
        # Test 1: add a new ACL
        reply = self.api_acl_add_replace(acl_index=4294967295, r=r,
                                         count=len(r), tag="permit 1234")
        self.assertEqual(reply.retval, 0)
        # The very first ACL gets #0
        self.assertEqual(reply.acl_index, 0)
        rr = self.api_acl_dump(reply.acl_index)
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

        # Add a deny-1234 ACL
        r_deny = ({'is_permit': 0, 'is_ipv6': 0, 'proto': 17,
                   'srcport_or_icmptype_first': 1234,
                   'srcport_or_icmptype_last': 1235,
                   'src_ip_prefix_len': 0,
                   'src_ip_addr': '\x00\x00\x00\x00',
                   'dstport_or_icmpcode_first': 1234,
                   'dstport_or_icmpcode_last': 1234,
                   'dst_ip_addr': '\x00\x00\x00\x00',
                   'dst_ip_prefix_len': 0},
                  {'is_permit': 1, 'is_ipv6': 0, 'proto': 17,
                   'srcport_or_icmptype_first': 0,
                   'srcport_or_icmptype_last': 0,
                   'src_ip_prefix_len': 0,
                   'src_ip_addr': '\x00\x00\x00\x00',
                   'dstport_or_icmpcode_first': 0,
                   'dstport_or_icmpcode_last': 0,
                   'dst_ip_addr': '\x00\x00\x00\x00',
                   'dst_ip_prefix_len': 0})

        reply = self.api_acl_add_replace(acl_index=4294967295, r=r_deny,
                                         count=len(r_deny),
                                         tag="deny 1234;permit all")
        self.assertEqual(reply.retval, 0)
        # The second ACL gets #1
        self.assertEqual(reply.acl_index, 1)

        # Test 2: try to modify a nonexistent ACL
        reply = self.api_acl_add_replace(acl_index=432, r=r, count=len(r),
                                         tag="FFFF:FFFF", expected_retval=-1)
        self.assertEqual(reply.retval, -1)
        # The ACL number should pass through
        self.assertEqual(reply.acl_index, 432)

        self.logger.info("ACLP_TEST_FINISH_0001")

    def test_0002_acl_permit_apply(self):
        """ permit ACL apply test
        """
        self.logger.info("ACLP_TEST_START_0002")

        rules = []
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                     True, self.proto[self.UDP]))
        rules.append(self.create_rule(self.IPV4, self.PERMIT,
                     True, self.proto[self.TCP]))

        # Test 1: add a new ACL
        reply = self.api_acl_add_replace(acl_index=4294967295, r=rules,
                                         count=len(rules),
                                         tag="permit per-flow")
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interface pg0 as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])
        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4)
        self.logger.info("ACLP_TEST_FINISH_0002")

    def test_0003_acl_deny_apply(self):
        """ deny ACL apply test
        """
        self.logger.info("ACLP_TEST_START_0003")
        # Add a deny-flows ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY,
                     True, self.proto[self.UDP]))
        # permit ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.PERMIT, True, 0))

        reply = self.api_acl_add_replace(acl_index=4294967295, r=rules,
                                         count=len(rules),
                                         tag="deny per-flow;permit all")
        self.assertEqual(reply.retval, 0)
        deny_acl_index = reply.acl_index

        # Apply a denying ACL all of interfaces as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[deny_acl_index])
        # Traffic should not pass
        self.run_verify_negat_test()
        self.logger.info("ACLP_TEST_FINISH_0003")
        # self.assertEqual(1, 0)

    def test_0004_vpp624_permit_icmpv4(self):
        """ VPP_624 permit ICMPv4
        """
        self.logger.info("ACLP_TEST_START_0004")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.PERMIT, True, 1))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, False, 0))

        reply = self.api_acl_add_replace(acl_index=4294967295, r=rules,
                                         count=len(rules))
        rr = self.api_acl_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interface as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])

        # Traffic should still pass
        self.run_verify_test(self.ICMP, self.IPV4, 1)

        self.logger.info("ACLP_TEST_FINISH_0004")

    def test_0005_vpp624_permit_icmpv6(self):
        """ VPP_624 permit ICMPv6
        """
        self.logger.info("ACLP_TEST_START_0005")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.PERMIT, True, 58))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.DENY, False, 0))

        reply = self.api_acl_add_replace(acl_index=4294967295, r=rules,
                                         count=len(rules))
        rr = self.api_acl_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interface as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])

        # Traffic should still pass
        self.run_verify_test(self.ICMP, self.IPV6, 58)

        self.logger.info("ACLP_TEST_FINISH_0005")

    def test_0006_vpp624_deny_icmpv4(self):
        """ VPP_624 deny ICMPv4
        """
        self.logger.info("ACLP_TEST_START_0006")
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, True, 1))
        # permit ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.PERMIT, False, 0))

        reply = self.api_acl_add_replace(acl_index=4294967295, r=rules,
                                         count=len(rules))
        rr = self.api_acl_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interfaces as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])

        self.run_verify_negat_test(self.ICMP, self.IPV4, 1)

        self.logger.info("ACLP_TEST_FINISH_0006")

    def test_0007_vpp624_deny_icmpv6(self):
        """ VPP_624 deny ICMPv6
        """
        self.logger.info("ACLP_TEST_START_0007")
        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.DENY, True, 58))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.PERMIT, False, 0))

        reply = self.api_acl_add_replace(acl_index=4294967295, r=rules,
                                         count=len(rules))
        rr = self.api_acl_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interfaces as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])

        self.run_verify_negat_test(self.ICMP, self.IPV6, 58)

        self.logger.info("ACLP_TEST_FINISH_0007")

    def test_0008_tcp_permit_v4(self):
        """ permit TCPv4
        """
        self.logger.info("ACLP_TEST_START_0008")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.PERMIT, True,
                     self.proto[self.TCP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, False, 0))

        reply = self.api_acl_add_replace(acl_index=4294967295, r=rules,
                                         count=len(rules))
        rr = self.api_acl_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interface as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4, self.proto[self.TCP])

        self.logger.info("ACLP_TEST_FINISH_0008")

    def test_0009_tcp_permit_v6(self):
        """ permit TCPv6
        """
        self.logger.info("ACLP_TEST_START_0009")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.PERMIT, True, self.proto[
            self.TCP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.DENY, False, 0))

        reply = self.api_acl_add_replace(acl_index=4294967295, r=rules,
                                         count=len(rules))
        rr = self.api_acl_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interface as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV6, self.proto[self.TCP])

        self.logger.info("ACLP_TEST_FINISH_0008")

    def test_0010_udp_permit_v4(self):
        """ permit UDPv4
        """
        self.logger.info("ACLP_TEST_START_0010")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.PERMIT, True, self.proto[
            self.UDP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.DENY, False, 0))

        reply = self.api_acl_add_replace(acl_index=4294967295, r=rules,
                                         count=len(rules))
        rr = self.api_acl_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interface as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV4, self.proto[self.UDP])

        self.logger.info("ACLP_TEST_FINISH_0010")

    def test_0011_udp_permit_v6(self):
        """ permit UDPv6
        """
        self.logger.info("ACLP_TEST_START_0011")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.PERMIT, True,
                                      self.proto[self.UDP]))
        # deny ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.DENY, False, 0))

        reply = self.api_acl_add_replace(acl_index=4294967295, r=rules,
                                         count=len(rules))
        rr = self.api_acl_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interface as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])

        # Traffic should still pass
        self.run_verify_test(self.IP, self.IPV6, self.proto[self.UDP])

        self.logger.info("ACLP_TEST_FINISH_0011")

    def test_0012_tcp_deny_v4(self):
        """ deny TCPv4
        """
        self.logger.info("ACLP_TEST_START_0012")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, True,
                                      self.proto[self.TCP]))
        # permit ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.PERMIT, False, 0))

        reply = self.api_acl_add_replace(acl_index=4294967295, r=rules,
                                         count=len(rules))
        rr = self.api_acl_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interface as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])

        # Traffic should still pass
        self.run_verify_negat_test(self.IP, self.IPV4, self.proto[self.TCP])

        self.logger.info("ACLP_TEST_FINISH_0012")

    def test_0013_tcp_deny_v6(self):
        """ deny TCPv6
        """
        self.logger.info("ACLP_TEST_START_0013")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.DENY, True,
                                      self.proto[self.TCP]))
        # permit ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.PERMIT, False, 0))

        reply = self.api_acl_add_replace(acl_index=4294967295, r=rules,
                                         count=len(rules))
        rr = self.api_acl_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interface as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])

        # Traffic should still pass
        self.run_verify_negat_test(self.IP, self.IPV6, self.proto[self.TCP])

        self.logger.info("ACLP_TEST_FINISH_0013")

    def test_0014_udp_deny_v4(self):
        """ deny UDPv4
        """
        self.logger.info("ACLP_TEST_START_0014")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV4, self.DENY, True,
                                      self.proto[self.UDP]))
        # permit ip any any in the end
        rules.append(self.create_rule(self.IPV4, self.PERMIT, False, 0))

        reply = self.api_acl_add_replace(acl_index=4294967295, r=rules,
                                         count=len(rules))
        rr = self.api_acl_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interface as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])

        # Traffic should still pass
        self.run_verify_negat_test(self.IP, self.IPV4, self.proto[self.UDP])

        self.logger.info("ACLP_TEST_FINISH_0014")

    def test_0015_udp_deny_v6(self):
        """ deny UDPv6
        """
        self.logger.info("ACLP_TEST_START_0015")

        # Add an ACL
        rules = []
        rules.append(self.create_rule(self.IPV6, self.DENY, True,
                                      self.proto[self.UDP]))
        # permit ip any any in the end
        rules.append(self.create_rule(self.IPV6, self.PERMIT, False, 0))

        reply = self.api_acl_add_replace(acl_index=4294967295, r=rules,
                                         count=len(rules))
        rr = self.api_acl_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interface as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])

        # Traffic should still pass
        self.run_verify_negat_test(self.IP, self.IPV6, self.proto[self.UDP])

        self.logger.info("ACLP_TEST_FINISH_0015")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
