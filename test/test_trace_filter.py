#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestTracefilter(VppTestCase):
    """ Packet Tracer Filter Test """

    @classmethod
    def setUpClass(cls):
        super(TestTracefilter, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestTracefilter, cls).tearDownClass()

    def setUp(self):
        super(TestTracefilter, self).setUp()

    def tearDown(self):
        super(TestTracefilter, self).tearDown()

    def test_mactime_unitTest(self):
        """ Packet Tracer Filter Test """
        cmds = ["loopback create",
                "set int ip address loop0 192.168.1.1/24",
                "set int state loop0 up",
                "packet-generator new {\n"
                " name classifyme\n"
                " limit 100\n"
                " size 300-300\n"
                " interface loop0\n"
                " node ethernet-input\n"
                " data { \n"
                "      IP4: 1.2.3 -> 4.5.6\n"
                "      UDP: 192.168.1.10 - 192.168.1.20 -> 192.168.2.10\n"
                "      UDP: 1234 -> 2345\n"
                "      incrementing 286\n"
                "     }\n"
                "}\n",
                "classify filter trace mask l3 ip4 src\n"
                " match l3 ip4 src 192.168.1.15",
                "trace add pg-input 100 filter",
                "pa en"]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, 'reply'):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

        # Check for 9 classifier hits, which is the right answer
        r = self.vapi.cli_return_response("show classify table verbose 2")
        self.assertTrue(r.retval == 0)
        self.assertTrue(hasattr(r, 'reply'))
        self.assertTrue(r.reply.find("hits 9") != -1)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
