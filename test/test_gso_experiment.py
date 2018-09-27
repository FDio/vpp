
#!/usr/bin/env python
"""GSO experiment test-case
"""

import unittest
import random

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.inet6 import IPv6ExtHdrFragment
from framework import VppTestCase, VppTestRunner, running_extended_tests

from util import Host, ppp
from subprocess import call
from subprocess import check_output

from vpp_lo_interface import VppLoInterface

import os
import signal
import fnmatch
import logging
import pprint


from vpp_papi import VPP

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP, TCP
from scapy.packet import Packet
from socket import inet_pton, AF_INET, AF_INET6
from scapy.layers.inet6 import IPv6, ICMPv6Unknown, ICMPv6EchoRequest
from scapy.layers.inet6 import ICMPv6EchoReply, IPv6ExtHdrRouting
from scapy.layers.inet6 import IPv6ExtHdrFragment

import collections
import socket
import binascii

@unittest.skipUnless(running_extended_tests(), "part of extended tests")
class TestGsoExperimentTestCase(VppTestCase):
    """ GSO experiment test case """

    # Test variables
    bd_id = 1

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(TestGsoExperimentTestCase, cls).setUpClass()


        try:
            print("Setup")
        except Exception:
            super(TestGsoExperimentTestCase, cls).tearDownClass()
            raise

    def setUp(self):
        super(TestGsoExperimentTestCase, self).setUp()
        self.reset_packet_infos()

        cli = "ip netns add vpp1"
        call(cli.split())
        cli = "ip netns add vpp2"
        call(cli.split())

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        # super(TestGsoExperimentTestCase, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.ppcli("show vlib graph"))
            self.logger.info(self.vapi.ppcli("show l2fib verbose"))
            self.logger.info(self.vapi.ppcli("show acl-plugin acl"))
            self.logger.info(self.vapi.ppcli("show acl-plugin interface"))
            self.logger.info(self.vapi.ppcli("show acl-plugin tables"))
            self.logger.info(self.vapi.ppcli("show bridge-domain %s detail"
                                             % self.bd_id))
        cli = "ip netns del vpp1"
        call(cli.split())
        cli = "ip netns del vpp2"
        call(cli.split())


    def kill_iperf_server(self):
        pid = int(open("/tmp/gso_test_server.pid").read().rstrip('\x00'))
        os.kill(pid, signal.SIGKILL)

    def tap_test(self, gso_cli):
        # tweak this according to needs to tune the starting sw_if_index
        # self.create_loopback_interfaces(1)
        cli = "create tap id 1 hw-addr 00:fe:00:00:00:01 rx-ring-size 1024 tx-ring-size 1024 host-ns vpp1 host-ip4-addr 172.16.1.2/24 host-ip4-gw 172.16.1.1 host-if-name vpp" + gso_cli
        self.logger.info(self.vapi.ppcli(cli))
        cli = "create tap id 2 hw-addr 00:fe:00:00:00:02 rx-ring-size 1024 tx-ring-size 1024 host-ns vpp2 host-ip4-addr 172.16.2.2/24 host-ip4-gw 172.16.2.1 host-if-name vpp" + gso_cli
        self.logger.info(self.vapi.ppcli(cli))
        cli = "trace add virtio-input 100"
        self.logger.info(self.vapi.ppcli(cli))
        cli = "set int state tap1 up"
        self.logger.info(self.vapi.ppcli(cli))
        cli = "set int state tap2 up"
        self.logger.info(self.vapi.ppcli(cli))
        cli = "set int ip address tap1 172.16.1.1/24"
        self.logger.info(self.vapi.ppcli(cli))
        cli = "set int ip address tap2 172.16.2.1/24"
        self.logger.info(self.vapi.ppcli(cli))
        cli = "ip netns exec vpp1 ifconfig -a"
        self.logger.info(check_output(cli.split()))
        cli = "ip netns exec vpp2 ifconfig -a"
        self.logger.info(check_output(cli.split()))
        cli = "ip netns exec vpp1 iperf3 -s -D -I /tmp/gso_test_server.pid"
        self.logger.info(check_output(cli.split()))
        cli = "ip netns exec vpp2 iperf3 -c 172.16.1.2 -t 5"
        result = ""
        try:
          result = check_output(cli.split())
        except:
          self.kill_iperf_server()
          print("iperf3 ERROR")
          cli = "show trace"
          self.logger.info(self.vapi.ppcli(cli))
          raise
        self.kill_iperf_server()
        print("iperf3 test result:\n" + result)
        self.logger.info(result)
        cli = "show trace"
        self.logger.info(self.vapi.ppcli(cli))

        self.logger.info(self.vapi.ppcli("show interface"))
        cli = "delete tap tap1"
        self.logger.info(self.vapi.ppcli(cli))
        cli = "delete tap tap2"
        self.logger.info(self.vapi.ppcli(cli))

    def test_no_gso(self):
        self.tap_test("")
        self.logger.info("End of no-gso testcase")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)


