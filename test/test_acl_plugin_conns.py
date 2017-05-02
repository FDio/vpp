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
from time import sleep
from sys import stderr

def to_acl_rule(self, is_permit, wildcard_sport=False):
    p = self
    rule_family = AF_INET6 if p.haslayer(IPv6) else AF_INET        
    rule_prefix_len = 128 if p.haslayer(IPv6) else 32              
    rule_l3_layer = IPv6 if p.haslayer(IPv6) else IP 
    rule_l4_sport = p.sport
    rule_l4_dport = p.dport
    if p.haslayer(IPv6):                                           
        rule_l4_proto = ulp_l4.overload_fields[IPv6]['nh']         
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
        s0 = side
        s1 = 1-side
        src_if = self.ifs[s0]
        dst_if = self.ifs[s1]
        payload = "x"
        p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
             IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
             self.l4proto(sport=self.ports[s0], dport=self.ports[s1]) /
             Raw(payload))
        return p

    def apply_acls(self, reflect_side, acl_side):
        pkts = [ ]
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

        r = []
        r.append(self.wildcard_rule(1))
        res = self.testcase.api_acl_add_replace(0xffffffff, r)
        self.testcase.assert_equal(res.retval, 0, "error adding permit ACL")
        permit_acl_index = res.acl_index
        if reflect_side == acl_side:
            self.testcase.api_acl_interface_set_acl_list(
                   self.ifs[acl_side].sw_if_index, 2, 1,
                   [reflect_acl_index,
                    deny_acl_index])
        else:
            self.testcase.api_acl_interface_set_acl_list(
                   self.ifs[acl_side].sw_if_index, 2, 1,
                   [deny_acl_index,
                    reflect_acl_index])


    def pkt1(self):
        src_if = self.ifs[0]
        dst_if = self.ifs[1]
        payload = "test"
        p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
             IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
             UDP(sport=1000, dport=2000) /
             Raw(payload))
        return p

    def pkt2(self):
        src_if = self.ifs[1]
        dst_if = self.ifs[0]
        payload = "test2"
        p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
             IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
             UDP(sport=2000, dport=1000) /
             Raw(payload))
        return p

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

    def send1(self, pkt):
        self.ifs[0].add_stream(pkt)
        self.ifs[1].enable_capture()
        self.testcase.pg_start()
    def send2(self, pkt):
        self.ifs[1].add_stream(pkt)
        self.ifs[0].enable_capture()
        self.testcase.pg_start()
    def recv1(self):
        p = self.ifs[0].wait_for_packet(1)
        return p

    def recv2(self):
        p = self.ifs[1].wait_for_packet(1)
        return p

    def send_through(self, side):
        self.send(side)
        p = self.recv(1-side)
        return p

    def send_pingpong(self, side):
        p1 = self.send_through(side)
        p2 = self.send_through(1-side)
        return [p1, p2]
    
class ACLPluginConnTestCase(VppTestCase):
    """ ACL plugin connection-oriented extended testcases """

    @classmethod
    def setUpClass(self):
        super(ACLPluginConnTestCase, self).setUpClass()
        self.create_pg_interfaces(range(2))  #  create pg0 and pg1
        for i in self.pg_interfaces:
            i.admin_up()  # put the interface up
            i.config_ip4()  # configure IPv4 address on the interface
            i.config_ip6()
            i.resolve_arp()  # resolve ARP, so that we know VPP MAC
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

    @unittest.skipUnless(running_extended_tests(), "part of extended tests")
    def test_0000_conn_prepare_test(self):
        """ Prepare the settings """
        self.vapi.ppcli("set acl-plugin session timeout udp idle 1")

    @unittest.skipUnless(running_extended_tests(), "part of extended tests")
    def test_0001_basic_conn_test(self):
        """ Basic conn timeout test """
        conn1 = Conn(self, self.pg0, self.pg1, AF_INET, UDP, 42001, 4242)
        conn1.apply_acls(0, 0)
        conn1.send_through(0)
        # the return packets should pass
        conn1.send_through(1)
        # send some packets on conn1, ensure it doesn't go away
        total_packets = 20
        for i in range(total_packets):
          sleep(0.3)
          stderr.write("Test running : %d of %d\r" % (i, total_packets))
          conn1.send_through(1)
        # allow the conn to time out
        for i in range(30):
           sleep(0.1)
           stderr.write("Waiting for timeout (%d of %d)\r" % (i, 30))
        try:
            p2 = conn1.send_through(1).command()
        except:
            # If we asserted while waiting, it's good.
            # the conn should have timed out.
            p2 = None
        self.assert_equal(p2, None, "packet on long-idle conn")

    @unittest.skipUnless(running_extended_tests(), "part of extended tests")
    def test_0002_active_conn_test(self):
        """ Idle connection behind active connection test """
        conn1 = Conn(self, self.pg0, self.pg1, AF_INET, UDP, 10001, 2323)
        conn2 = Conn(self, self.pg0, self.pg1, AF_INET, UDP, 10002, 2323)
        conn3 = Conn(self, self.pg0, self.pg1, AF_INET, UDP, 10003, 2323)
        conn1.apply_acls(0, 0)
        conn1.send(0)
        conn1.recv(1)
        # create and check that the conn2 works
        sleep(0.1)
        conn2.send_pingpong(0)
        sleep(0.1)
        conn3.send_pingpong(0)
        # send some packets on conn1, keep conn2/3 idle
        total_packets = 20;
        for i in range(total_packets):
          sleep(0.2)
          stderr.write("Test running : %d of %d\r" % (i, total_packets))
          conn1.send_through(1)
        try:
            p2 = conn2.send_through(1).command()
        except:
            # If we asserted while waiting, it's good.
            # the conn should have timed out.
            p2 = None
        self.assert_equal(p2, None, "packet on long-idle conn")

