#!/usr/bin/env python
"""ACL plugin Test Case HLD:

**config 1**
    - add 4 pg-l2 interfaces
    - configure them into l2bd

"""

import unittest
import random
import time

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest

from framework import VppTestCase, VppTestRunner
from util import Host, ppp


class TestACLplugin(VppTestCase):
    """ ACL plugin Test Case """

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.

        :var int bd_id: Bridge domain ID.
        :var int mac_entries_count: Number of MAC entries for bridge-domain.
        """
        super(TestACLplugin, cls).setUpClass()

        # Test variables
        cls.bd_id = 1
        cls.mac_entries_count = 200

        cls.icmp4_type = 8      # echo request
        cls.icmp4_code = 3
        cls.icmp6_type = 128    # echo request
        cls.icmp6_code = 3

        try:
            # Create 4 pg interfaces
            cls.create_pg_interfaces(range(4))

            # Packet flows mapping pg0 -> pg1, pg2, pg3 etc.
            cls.flows = dict()
            cls.flows[cls.pg0] = [cls.pg1, cls.pg2, cls.pg3]
            cls.flows[cls.pg1] = [cls.pg0, cls.pg2, cls.pg3]
            cls.flows[cls.pg2] = [cls.pg0, cls.pg1, cls.pg3]
            cls.flows[cls.pg3] = [cls.pg0, cls.pg1, cls.pg2]

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
                    "172.17.1%02x.%u" % (pg_if.sw_if_index, j))
                hosts.append(host)

    def create_stream(self, src_if, packet_sizes, traffic_type=0):
        """
        Create input packet stream for defined interface using hosts or
        deleted_hosts list.

        :param object src_if: Interface to create packet stream for.
        :param list packet_sizes: List of required packet sizes.
        :param traffic_type:
        :return: Stream of packets.
        """
        pkts = []
        src_hosts = self.hosts_by_pg_idx[src_if.sw_if_index]
        for dst_if in self.flows[src_if]:
            dst_hosts = self.hosts_by_pg_idx[dst_if.sw_if_index]
            n_int = len(dst_hosts) * len(src_hosts)
            for i in range(0, n_int):
                dst_host = dst_hosts[i/len(src_hosts)]
                src_host = src_hosts[i % len(src_hosts)]
                pkt_info = self.create_packet_info(src_if, dst_if)
                payload = self.info_to_payload(pkt_info)
                p = (Ether(dst=dst_host.mac, src=src_host.mac) /
                     IP(src=src_host.ip4, dst=dst_host.ip4) /
                     UDP(sport=10000 + i*(123+traffic_type),
                         dport=500+(i+2*traffic_type)) /
                     Raw(payload))
                pkt_info.data = p.copy()
                size = random.choice(packet_sizes)
                self.extend_packet(p, size)
                pkts.append(p)
        return pkts

    def create_stream_icmp(self, in_if, out_if, ip_ver):
        """
        Create packet stream for inside network

        :param in_if: Inside interface
        :param out_if: Outside interface
        """
        pkts = []
        if (ip_ver != "IPv4" and ip_ver != "IPv6"):
            return

        src_hosts = self.hosts_by_pg_idx[in_if.sw_if_index]
        dst_hosts = self.hosts_by_pg_idx[out_if.sw_if_index]
        n_int = len(dst_hosts) * len(src_hosts)
        for i in range(0, n_int):
                dst_host = dst_hosts[i/len(src_hosts)]
                src_host = src_hosts[i % len(src_hosts)]
                if (ip_ver == "IPv4"):
                    p = (Ether(dst=dst_host.mac, src=src_host.mac) /
                        IP(dst=dst_host.ip4, src=src_host.ip4) /
                        ICMP(type=self.icmp4_type, code=self.icmp4_code))
                elif (ip_ver == "IPv6"):
                    p = (Ether(dst=dst_host.mac, src=src_host.mac) /
                        IPv6(dst=dst_host.ip6, src=src_host.ip6) /
                        ICMPv6EchoRequest(code=self.icmp6_code))
                pkts.append(p)
        return pkts

    def verify_capture(self, pg_if, capture):
        """
        Verify captured input packet stream for defined interface.

        :param object pg_if: Interface to verify captured packet stream for.
        :param list capture: Captured packet stream.
        """
        last_info = dict()
        for i in self.pg_interfaces:
            last_info[i.sw_if_index] = None
        dst_sw_if_index = pg_if.sw_if_index
        for packet in capture:
            payload_info = self.payload_to_info(str(packet[Raw]))
            try:
                ip = packet[IP]
                packet_index = payload_info.index
                udp = packet[UDP]
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                self.logger.debug("Got packet on port %s: src=%u (id=%u)" %
                                  (pg_if.name, payload_info.src, packet_index))
                next_info = self.get_next_packet_info_for_interface2(
                    payload_info.src, dst_sw_if_index,
                    last_info[payload_info.src])
                last_info[payload_info.src] = next_info
                self.assertTrue(next_info is not None)
                self.assertEqual(packet_index, next_info.index)
                saved_packet = next_info.data
                # Check standard fields
                self.assertEqual(ip.src, saved_packet[IP].src)
                self.assertEqual(ip.dst, saved_packet[IP].dst)
                self.assertEqual(udp.sport, saved_packet[UDP].sport)
                self.assertEqual(udp.dport, saved_packet[UDP].dport)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for i in self.pg_interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(
                remaining_packet is None,
                "Port %u: Packet expected from source %u didn't arrive" %
                (dst_sw_if_index, i.sw_if_index))

    def run_traffic_no_check(self, traffic_type=0):
        # Test
        # Create incoming packet streams for packet-generator interfaces
        for i in self.pg_interfaces:
            pkts = self.create_stream(i, self.pg_if_packet_sizes, traffic_type)
            i.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

    def run_verify_test(self, traffic_type=0):
        # Test
        # Create incoming packet streams for packet-generator interfaces
        for i in self.pg_interfaces:
            pkts = self.create_stream(i, self.pg_if_packet_sizes, traffic_type)
            i.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for i in self.pg_interfaces:
            capture = i.get_capture()
            self.logger.info("Verifying capture on interface %s" % i.name)
            self.verify_capture(i, capture)

    def run_verify_negat_test(self):
        # Test
        self.reset_packet_infos()
        for i in self.pg_interfaces:
            pkts = self.create_stream(i, self.pg_if_packet_sizes)
            i.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for i in self.pg_interfaces:
            i.assert_nothing_captured(remark="outgoing interface")

    def api_acl_add_replace(self, acl_index, r, count, tag = "",
                            expected_retval = 0):
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
			 'tag': tag
			 }, expected_retval=expected_retval)

    def api_acl_interface_set_acl_list(self, sw_if_index, count, n_input, acls,
                                       expected_retval = 0):
        return self.vapi.api(self.vapi.papi.acl_interface_set_acl_list,
                        {'sw_if_index': sw_if_index,
			             'count': count,
			             'n_input': n_input,
			             'acls': acls },
			            expected_retval=expected_retval)

    def api_acl_dump(self, acl_index, expected_retval = 0):
        return self.vapi.api(self.vapi.papi.acl_dump, 
                        { 'acl_index': acl_index },
                        expected_retval = expected_retval );

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
        self.maxDiff = None
        self.assertEqual(len(rr), 1)
        # We should have the same number of ACL entries as we had asked
        self.assertEqual(len(rr[0].r), len(r))
        # The rules should be the same. But because the submitted and returned
        # are different types, we need to iterate over rules and keys to get
        # to basic values.
        for i_rule in range(0, len(r)-1):
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

        r = []
        for src_if in self.pg_interfaces:
            src_hosts = self.hosts_by_pg_idx[src_if.sw_if_index]
            for dst_if in self.flows[src_if]:
                dst_hosts = self.hosts_by_pg_idx[dst_if.sw_if_index]
                n_int = len(dst_hosts) * len(src_hosts)
                for i in range(0, n_int):
                    dst_host = dst_hosts[i / len(src_hosts)]
                    src_host = src_hosts[i % len(src_hosts)]
                    sport = 10000 + i*123
                    dport = 500 + i
                    new_rule = ({'is_permit': 1, 'is_ipv6': 0, 'proto': 17,
                        'srcport_or_icmptype_first': sport,
                        'srcport_or_icmptype_last': sport,
                        'src_ip_prefix_len': 0,
                        'src_ip_addr': src_host.ip4,
                        'dstport_or_icmpcode_first': dport,
                        'dstport_or_icmpcode_last': dport,
                        'dst_ip_addr': dst_host.ip4,
                        'dst_ip_prefix_len': 0})
                    r.append(new_rule)

        # Test 1: add a new ACL
        reply = self.api_acl_add_replace(acl_index=4294967295, r=r,
                                         count=len(r),
                                         tag="permit per-flow")
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interface pg0 as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index = i.sw_if_index,
                                                count=1, n_input=1,
                                                acls = [ permit_acl_index ])
        # Traffic should still pass
        self.run_verify_test()
        self.logger.info("ACLP_TEST_FINISH_0002")

    def test_0003_acl_deny_apply(self):
        """ deny ACL apply test
        """
        self.logger.info("ACLP_TEST_START_0003")
        # Add a deny-flows ACL
        r = []
        for src_if in self.pg_interfaces:
            src_hosts = self.hosts_by_pg_idx[src_if.sw_if_index]
            for dst_if in self.flows[src_if]:
                dst_hosts = self.hosts_by_pg_idx[dst_if.sw_if_index]
                n_int = len(dst_hosts) * len(src_hosts)
                for i in range(0, n_int):
                    dst_host = dst_hosts[i / len(src_hosts)]
                    src_host = src_hosts[i % len(src_hosts)]
                    sport = 10000 + i*123
                    dport = 500 + i
                    new_rule = ({'is_permit': 0, 'is_ipv6': 0, 'proto': 17,
                        'srcport_or_icmptype_first': sport,
                        'srcport_or_icmptype_last': sport,
                        'src_ip_prefix_len': 0,
                        'src_ip_addr': src_host.ip4,
                        'dstport_or_icmpcode_first': dport,
                        'dstport_or_icmpcode_last': dport,
                        'dst_ip_addr': dst_host.ip4,
                        'dst_ip_prefix_len': 0})
                    r.append(new_rule)

        # permit ip any any in the end
        r.append(
             {'is_permit': 0, 'is_ipv6': 0, 'proto': 0,
              'srcport_or_icmptype_first': 0,
              'srcport_or_icmptype_last': 0,
              'src_ip_prefix_len': 0,
              'src_ip_addr': '\x00\x00\x00\x00',
              'dstport_or_icmpcode_first': 0,
              'dstport_or_icmpcode_last': 0,
              'dst_ip_prefix_len': 0,
              'dst_ip_addr': '\x00\x00\x00\x00'
              })
            
        reply = self.api_acl_add_replace(acl_index=4294967295, r=r,
                                         count=len(r),
                                         tag="deny per-flow;permit all")
        self.assertEqual(reply.retval, 0)
        deny_acl_index = reply.acl_index

        # Apply a denying ACL all of interfaces as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index = i.sw_if_index,
                                                count=1, n_input=1,
                                                acls = [ deny_acl_index ])
        # Traffic should not pass
        self.run_verify_negat_test()
        self.logger.info("ACLP_TEST_FINISH_0003")
        # self.assertEqual(1, 0)

    def test_0004_vpp624_permit(self):
        """ VPP_624 permit ICMP
        """
        self.logger.info("ACLP_TEST_START_0004")

        # Add an ACL
        r_permit = ({'is_permit': 1, 'is_ipv6': 0, 'proto': 1,
                     'srcport_or_icmptype_first': 0,
                     'srcport_or_icmptype_last': self.icmp4_type,
                     'src_ip_prefix_len': 0,
                     'src_ip_addr': '\x00\x00\x00\x00',
                     'dstport_or_icmpcode_first': 0,
                     'dstport_or_icmpcode_last': self.icmp4_code,
                     'dst_ip_addr': '\x00\x00\x00\x00',
                     'dst_ip_prefix_len': 0},
                     {'is_permit': 1, 'is_ipv6': 1, 'proto': 58,
                     'srcport_or_icmptype_first': 0,
                     'srcport_or_icmptype_last': self.icmp6_type,
                     'src_ip_prefix_len': 0,
                     'src_ip_addr': '\x00\x00\x00\x00',
                     'dstport_or_icmpcode_first': 0,
                     'dstport_or_icmpcode_last': self.icmp6_code,
                     'dst_ip_addr': '\x00\x00\x00\x00',
                     'dst_ip_prefix_len': 0})

        reply = self.api_acl_add_replace(acl_index=4294967295, r=r_permit,
                                         count=len(r_permit))
        rr = self.api_acl_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interface pg0 as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])

        # Traffic should still pass
        pkts_pg0 = self.create_stream_icmp(self.pg0, self.pg1, "IPv4")
        self.pg0.add_stream(pkts_pg0)
        pkts_pg2 = self.create_stream_icmp(self.pg2, self.pg3, "IPv6")
        self.pg2.add_stream(pkts_pg2)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture_pg1 = self.pg1.get_capture(len(pkts_pg0))
        self.assertEqual(len(pkts_pg0), len(capture_pg1))
        capture_pg3 = self.pg3.get_capture(len(pkts_pg2))
        self.assertEqual(len(pkts_pg2), len(capture_pg3))

        for packet in capture_pg1:
            try:
                self.assertEqual(packet[ICMP].type, self.icmp4_type)
                self.assertEqual(packet[ICMP].code, self.icmp4_code)
            except:
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(outside network):", packet))
                raise
        for packet in capture_pg3:
            try:
                self.assertEqual(packet[ICMPv6EchoRequest].type,
                                 self.icmp6_type)
                self.assertEqual(packet[ICMPv6EchoRequest].code,
                                 self.icmp6_code)
            except:
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(outside network):", packet))
                raise

        self.logger.info("ACLP_TEST_FINISH_0004")

    def test_0005_vpp624_deny(self):
        """ VPP_624 deny ICMP
        """
        self.logger.info("ACLP_TEST_START_0005")
        # Add an ACL
        r_deny = ({'is_permit': 0, 'is_ipv6': 0, 'proto': 1,
                   'srcport_or_icmptype_first': 0,
                   'srcport_or_icmptype_last': self.icmp4_type,
                   'src_ip_prefix_len': 0,
                   'src_ip_addr': '\x00\x00\x00\x00',
                   'dstport_or_icmpcode_first': 0,
                   'dstport_or_icmpcode_last': self.icmp4_code,
                   'dst_ip_addr': '\x00\x00\x00\x00',
                   'dst_ip_prefix_len': 0},
                   {'is_permit': 0, 'is_ipv6': 1, 'proto': 58,
                   'srcport_or_icmptype_first': 0,
                   'srcport_or_icmptype_last': self.icmp6_type,
                   'src_ip_prefix_len': 0,
                   'src_ip_addr': '\x00\x00\x00\x00',
                   'dstport_or_icmpcode_first': 0,
                   'dstport_or_icmpcode_last': self.icmp6_code,
                   'dst_ip_addr': '\x00\x00\x00\x00',
                   'dst_ip_prefix_len': 0})

        reply = self.api_acl_add_replace(acl_index=4294967295, r=r_deny,
                                         count=len(r_deny))
        rr = self.api_acl_dump(reply.acl_index)
        self.logger.info("Dumped ACL: " + str(rr))
        permit_acl_index = reply.acl_index
        # Apply a permitting ACL on the interface pg0 as inbound
        for i in self.pg_interfaces:
            self.api_acl_interface_set_acl_list(sw_if_index=i.sw_if_index,
                                                count=1, n_input=1,
                                                acls=[permit_acl_index])

        # Traffic should be denied by type
        pkts = self.create_stream_icmp(self.pg0, self.pg1, "IPv4")
        self.pg0.add_stream(pkts)
        # Traffic should be denied by code
        pkts = self.create_stream_icmp(self.pg2, self.pg3, "IPv6")
        self.pg2.add_stream(pkts)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.pg1.assert_nothing_captured()
        self.pg3.assert_nothing_captured()

        self.logger.info("ACLP_TEST_FINISH_0005")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
