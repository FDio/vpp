#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestVlib(VppTestCase):
    """ Vlib Unit Test Cases """
    worker_config = "workers 1"

    @classmethod
    def setUpClass(cls):
        super(TestVlib, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestVlib, cls).tearDownClass()

    def setUp(self):
        super(TestVlib, self).setUp()

    def tearDown(self):
        super(TestVlib, self).tearDown()

    # @unittest.skipUnless(running_extended_tests, "part of extended tests")

    def test_vlib_main_unittest(self):
        """ Vlib main.c Code Coverage Test """

        cmds = ["loopback create",
                "packet-generator new {\n"
                " name vlib\n"
                " limit 15\n"
                " size 128-128\n"
                " interface loop0\n"
                " node ethernet-input\n"
                " data {\n"
                "   IP6: 00:d0:2d:5e:86:85 -> 00:0d:ea:d0:00:00\n"
                "   ICMP: db00::1 -> db00::2\n"
                "   incrementing 30\n"
                "   }\n",
                "}\n",
                "elog trace dispatch",
                "event-logger stop",
                "event-logger clear",
                "event-logger resize 102400",
                "event-logger restart",
                "pcap dispatch trace on max 100 buffer-trace pg-input 15",
                "set pmc instructions-per-clock",
                "pa en",
                "show event-log 100 all",
                "event-log save",
                "event-log save foo",
                "pcap dispatch trace",
                "pcap dispatch trace status",
                "pcap dispatch trace off",
                "show vlib frame-allocation",
                ]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, 'reply'):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

    def test_vlib_node_cli_unittest(self):
        """ Vlib node_cli.c Code Coverage Test """

        cmds = ["loopback create",
                "packet-generator new {\n"
                " name vlib\n"
                " limit 15\n"
                " size 128-128\n"
                " interface loop0\n"
                " node ethernet-input\n"
                " data {\n"
                "   IP6: 00:d0:2d:5e:86:85 -> 00:0d:ea:d0:00:00\n"
                "   ICMP: db00::1 -> db00::2\n"
                "   incrementing 30\n"
                "   }\n",
                "}\n",
                "show vlib graph",
                "show vlib graph ethernet-input",
                "show vlib graphviz",
                "show vlib graphviz graphviz.dot",
                "pa en",
                "show runtime ethernet-input",
                "show runtime brief verbose max summary",
                "clear runtime",
                "show node index 1",
                "show node ethernet-input",
                "show node pg-input",
                "set node function",
                "set node function no-such-node",
                "set node function cdp-input default",
                "set node function ethernet-input default",
                "set node function ethernet-input bozo",
                "set node function ethernet-input",
                ]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, 'reply'):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
