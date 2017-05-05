#!/usr/bin/env python
""" ACL plugin extended stateful tests """

import unittest
from framework import VppTestCase, VppTestRunner, running_extended_tests
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet
from socket import inet_pton, AF_INET, AF_INET6
from scapy.layers.inet6 import IPv6, ICMPv6Unknown, ICMPv6EchoRequest
from scapy.layers.inet6 import ICMPv6EchoReply, IPv6ExtHdrRouting
from scapy.layers.inet6 import IPv6ExtHdrFragment
from pprint import pprint
from random import randint


def to_acl_rule(self, is_permit, wildcard_sport=False):
    p = self
    rule_family = AF_INET6 if p.haslayer(IPv6) else AF_INET
    rule_prefix_len = 128 if p.haslayer(IPv6) else 32
    rule_l3_layer = IPv6 if p.haslayer(IPv6) else IP
    rule_l4_sport = p.sport
    rule_l4_dport = p.dport
    if p.haslayer(IPv6):
        rule_l4_proto = p[IPv6].nh
    else:
        rule_l4_proto = p[IP].proto

    if wildcard_sport:
        rule_l4_sport_first = 0
        rule_l4_sport_last = 65535
    else:
        rule_l4_sport_first = rule_l4_sport
        rule_l4_sport_last = rule_l4_sport

    new_rule = {
          'is_permit': is_permit,
          'is_ipv6': p.haslayer(IPv6),
          'src_ip_addr': inet_pton(rule_family,
                                   p[rule_l3_layer].src),
          'src_ip_prefix_len': rule_prefix_len,
          'dst_ip_addr': inet_pton(rule_family,
                                   p[rule_l3_layer].dst),
          'dst_ip_prefix_len': rule_prefix_len,
          'srcport_or_icmptype_first': rule_l4_sport_first,
          'srcport_or_icmptype_last': rule_l4_sport_last,
          'dstport_or_icmpcode_first': rule_l4_dport,
          'dstport_or_icmpcode_last': rule_l4_dport,
          'proto': rule_l4_proto,
         }
    return new_rule

Packet.to_acl_rule = to_acl_rule


class IterateWithSleep():
    def __init__(self, testcase, n_iters, description, sleep_sec):
        self.curr = 0
        self.testcase = testcase
        self.n_iters = n_iters
        self.sleep_sec = sleep_sec
        self.description = description

    def __iter__(self):
        for x in range(0, self.n_iters):
            yield x
            self.testcase.sleep(self.sleep_sec)


class Conn():
    def __init__(self, testcase, if1, if2, af, l4proto, port1, port2):
        self.testcase = testcase
        self.ifs = [None, None]
        self.ifs[0] = if1
        self.ifs[1] = if2
        self.address_family = af
        self.l4proto = l4proto
        self.ports = [None, None]
        self.ports[0] = port1
        self.ports[1] = port2
        self

    def pkt(self, side):
        is_ip6 = 1 if self.address_family == AF_INET6 else 0
        s0 = side
        s1 = 1-side
        src_if = self.ifs[s0]
        dst_if = self.ifs[s1]
        layer_3 = [IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4),
                   IPv6(src=src_if.remote_ip6, dst=dst_if.remote_ip6)]
        payload = "x"
        p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
             layer_3[is_ip6] /
             self.l4proto(sport=self.ports[s0], dport=self.ports[s1]) /
             Raw(payload))
        return p

    def apply_acls(self, reflect_side, acl_side):
        pkts = []
        pkts.append(self.pkt(0))
        pkts.append(self.pkt(1))
        pkt = pkts[reflect_side]

        r = []
        r.append(pkt.to_acl_rule(2, wildcard_sport=True))
        r.append(self.wildcard_rule(0))
        res = self.testcase.api_acl_add_replace(0xffffffff, r)
        self.testcase.assert_equal(res.retval, 0, "error adding ACL")
        reflect_acl_index = res.acl_index

        r = []
        r.append(self.wildcard_rule(0))
        res = self.testcase.api_acl_add_replace(0xffffffff, r)
        self.testcase.assert_equal(res.retval, 0, "error adding deny ACL")
        deny_acl_index = res.acl_index

        if reflect_side == acl_side:
            self.testcase.api_acl_interface_set_acl_list(
                   self.ifs[acl_side].sw_if_index, 2, 1,
                   [reflect_acl_index,
                    deny_acl_index])
            self.testcase.api_acl_interface_set_acl_list(
                   self.ifs[1-acl_side].sw_if_index, 0, 0, [])
        else:
            self.testcase.api_acl_interface_set_acl_list(
                   self.ifs[acl_side].sw_if_index, 2, 1,
                   [deny_acl_index,
                    reflect_acl_index])
            self.testcase.api_acl_interface_set_acl_list(
                   self.ifs[1-acl_side].sw_if_index, 0, 0, [])

    def wildcard_rule(self, is_permit):
        any_addr = ["0.0.0.0", "::"]
        rule_family = self.address_family
        is_ip6 = 1 if rule_family == AF_INET6 else 0
        new_rule = {
              'is_permit': is_permit,
              'is_ipv6': is_ip6,
              'src_ip_addr': inet_pton(rule_family, any_addr[is_ip6]),
              'src_ip_prefix_len': 0,
              'dst_ip_addr': inet_pton(rule_family, any_addr[is_ip6]),
              'dst_ip_prefix_len': 0,
              'srcport_or_icmptype_first': 0,
              'srcport_or_icmptype_last': 65535,
              'dstport_or_icmpcode_first': 0,
              'dstport_or_icmpcode_last': 65535,
              'proto': 0,
             }
        return new_rule

    def send(self, side):
        self.ifs[side].add_stream(self.pkt(side))
        self.ifs[1-side].enable_capture()
        self.testcase.pg_start()

    def recv(self, side):
        p = self.ifs[side].wait_for_packet(1)
        return p

    def send_through(self, side):
        self.send(side)
        p = self.recv(1-side)
        return p

    def send_pingpong(self, side):
        p1 = self.send_through(side)
        p2 = self.send_through(1-side)
        return [p1, p2]


@unittest.skipUnless(running_extended_tests(), "part of extended tests")
class ACLPluginConnTestCase(VppTestCase):
    """ ACL plugin connection-oriented extended testcases """

    @classmethod
    def setUpClass(self):
        super(ACLPluginConnTestCase, self).setUpClass()
        # create pg0 and pg1
        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.resolve_arp()
            i.resolve_ndp()

    def api_acl_add_replace(self, acl_index, r, count=-1, tag="",
                            expected_retval=0):
        """Add/replace an ACL

        :param int acl_index: ACL index to replace, 4294967295 to create new.
        :param acl_rule r: ACL rules array.
        :param str tag: symbolic tag (description) for this ACL.
        :param int count: number of rules.
        """
        if (count < 0):
            count = len(r)
        return self.vapi.api(self.vapi.papi.acl_add_replace,
                             {'acl_index': acl_index,
                              'r': r,
                              'count': count,
                              'tag': tag
                              }, expected_retval=expected_retval)

    def api_acl_interface_set_acl_list(self, sw_if_index, count, n_input, acls,
                                       expected_retval=0):
        return self.vapi.api(self.vapi.papi.acl_interface_set_acl_list,
                             {'sw_if_index': sw_if_index,
                              'count': count,
                              'n_input': n_input,
                              'acls': acls
                              }, expected_retval=expected_retval)

    def api_acl_dump(self, acl_index, expected_retval=0):
        return self.vapi.api(self.vapi.papi.acl_dump,
                             {'acl_index': acl_index},
                             expected_retval=expected_retval)

    def run_basic_conn_test(self, af, acl_side):
        """ Basic conn timeout test """
        conn1 = Conn(self, self.pg0, self.pg1, af, UDP, 42001, 4242)
        conn1.apply_acls(0, acl_side)
        conn1.send_through(0)
        # the return packets should pass
        conn1.send_through(1)
        # send some packets on conn1, ensure it doesn't go away
        for i in IterateWithSleep(self, 20, "Keep conn active", 0.3):
            conn1.send_through(1)
        # allow the conn to time out
        for i in IterateWithSleep(self, 30, "Wait for timeout", 0.1):
            pass
        # now try to send a packet on the reflected side
        try:
            p2 = conn1.send_through(1).command()
        except:
            # If we asserted while waiting, it's good.
            # the conn should have timed out.
            p2 = None
        self.assert_equal(p2, None, "packet on long-idle conn")

    def run_active_conn_test(self, af, acl_side):
        """ Idle connection behind active connection test """
        base = 10000 + 1000*acl_side
        conn1 = Conn(self, self.pg0, self.pg1, af, UDP, base + 1, 2323)
        conn2 = Conn(self, self.pg0, self.pg1, af, UDP, base + 2, 2323)
        conn3 = Conn(self, self.pg0, self.pg1, af, UDP, base + 3, 2323)
        conn1.apply_acls(0, acl_side)
        conn1.send(0)
        conn1.recv(1)
        # create and check that the conn2/3 work
        self.sleep(0.1)
        conn2.send_pingpong(0)
        self.sleep(0.1)
        conn3.send_pingpong(0)
        # send some packets on conn1, keep conn2/3 idle
        for i in IterateWithSleep(self, 20, "Keep conn active", 0.2):
            conn1.send_through(1)
        try:
            p2 = conn2.send_through(1).command()
        except:
            # If we asserted while waiting, it's good.
            # the conn should have timed out.
            p2 = None
        # We should have not received the packet on a long-idle
        # connection, because it should have timed out
        # If it didn't - it is a problem
        self.assert_equal(p2, None, "packet on long-idle conn")

    def test_0000_conn_prepare_test(self):
        """ Prepare the settings """
        self.vapi.ppcli("set acl-plugin session timeout udp idle 1")

    def test_0001_basic_conn_test(self):
        """ IPv4: Basic conn timeout test reflect on ingress """
        self.run_basic_conn_test(AF_INET, 0)

    def test_0002_basic_conn_test(self):
        """ IPv4: Basic conn timeout test reflect on egress """
        self.run_basic_conn_test(AF_INET, 1)

    def test_0011_active_conn_test(self):
        """ IPv4: Idle conn behind active conn, reflect on ingress """
        self.run_active_conn_test(AF_INET, 0)

    def test_0012_active_conn_test(self):
        """ IPv4: Idle conn behind active conn, reflect on egress """
        self.run_active_conn_test(AF_INET, 1)

    def test_1001_basic_conn_test(self):
        """ IPv6: Basic conn timeout test reflect on ingress """
        self.run_basic_conn_test(AF_INET6, 0)

    def test_1002_basic_conn_test(self):
        """ IPv6: Basic conn timeout test reflect on egress """
        self.run_basic_conn_test(AF_INET6, 1)

    def test_1011_active_conn_test(self):
        """ IPv6: Idle conn behind active conn, reflect on ingress """
        self.run_active_conn_test(AF_INET6, 0)

    def test_1012_active_conn_test(self):
        """ IPv6: Idle conn behind active conn, reflect on egress """
        self.run_active_conn_test(AF_INET6, 1)
