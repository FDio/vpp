#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner, running_gcov_tests
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath
from os import path, remove


class TestPcap(VppTestCase):
    """ Pcap Unit Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestPcap, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestPcap, cls).tearDownClass()

    def setUp(self):
        super(TestPcap, self).setUp()

    def tearDown(self):
        super(TestPcap, self).tearDown()

# This is a code coverage test, but it only runs for 0.3 seconds
# might as well just run it...
    def test_pcap_unittest(self):
        """ PCAP Capture Tests """
        cmds = ["loop create",
                "set int ip address loop0 11.22.33.1/24",
                "set int state loop0 up",
                "loop create",
                "set int ip address loop1 11.22.34.1/24",
                "set int state loop1 up",
                "set ip neighbor loop1 11.22.34.44 03:00:11:22:34:44",
                "packet-generator new {\n"
                "  name s0\n"
                "  limit 10\n"
                "  size 128-128\n"
                "  interface loop0\n"
                "  tx-interface loop1\n"
                "  node loop1-output\n"
                "  buffer-flags ip4 offload\n"
                "  buffer-offload-flags offload-ip-cksum offload-udp-cksum\n"
                "  data {\n"
                "    IP4: 1.2.3 -> dead.0000.0001\n"
                "    UDP: 11.22.33.44 -> 11.22.34.44\n"
                "      ttl 2 checksum 13\n"
                "    UDP: 1234 -> 2345\n"
                "      checksum 11\n"
                "    incrementing 114\n"
                "  }\n"
                "}",
                "pcap dispatch trace on max 100 buffer-trace pg-input 10",
                "pa en",
                "pcap dispatch trace off",
                "pcap trace rx tx max 1000 intfc any",
                "pa en",
                "pcap trace status",
                "pcap trace rx tx off",
                "classify filter pcap mask l3 ip4 src "
                "match l3 ip4 src 11.22.33.44",
                "pcap trace rx tx max 1000 intfc any file filt.pcap filter",
                "show cla t verbose 2",
                "show cla t verbose",
                "show cla t",
                "pa en",
                "pcap trace rx tx off",
                "classify filter pcap del mask l3 ip4 src "
                "match l3 ip4 src 11.22.33.44"]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, 'reply'):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

        self.assertTrue(path.exists('/tmp/dispatch.pcap'))
        self.assertTrue(path.exists('/tmp/rxtx.pcap'))
        self.assertTrue(path.exists('/tmp/filt.pcap'))
        os.remove('/tmp/dispatch.pcap')
        os.remove('/tmp/rxtx.pcap')
        os.remove('/tmp/filt.pcap')

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
