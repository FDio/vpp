#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath
import os


class TestMpcap(VppTestCase):
    """ Mpcap Unit Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestMpcap, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestMpcap, cls).tearDownClass()

    def setUp(self):
        super(TestMpcap, self).setUp()

    def tearDown(self):
        super(TestMpcap, self).tearDown()

    def test_mpcap_unittest(self):
        """ Mapped pcap file test """
        cmds = ["packet-generator new {\n"
                " name mpcap\n"
                " limit 15\n"
                " size 128-128\n"
                " interface local0\n"
                " node mpcap-unittest\n"
                " data {\n"
                "   IP6: 00:d0:2d:5e:86:85 -> 00:0d:ea:d0:00:00\n"
                "   ICMP: db00::1 -> db00::2\n"
                "   incrementing 30\n"
                "   }\n",
                "trace add pg-input 15",
                "pa en",
                "show trace",
                "show error"]

        for cmd in cmds:
            self.logger.info(self.vapi.cli(cmd))

        size = os.path.getsize("/tmp/mpcap_unittest.pcap")
        os.remove("/tmp/mpcap_unittest.pcap")
        if size != 2184:
            self.logger.critical("BUG: file size %d not 2184" % size)
            self.assertNotIn('WrongMPCAPFileSize', 'WrongMPCAPFileSize')

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
