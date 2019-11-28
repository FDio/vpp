#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestFlow(VppTestCase):
    """ Flow Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestFlow, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestFlow, cls).tearDownClass()

    def setUp(self):
        super(TestFlow, self).setUp()

    def tearDown(self):
        super(TestFlow, self).tearDown()

    def test_flow_cli_unittest(self):
        """ Flow tests """
        # Just very basic sanity tests using the debug CLI
        # all we care about is no crash
        data = "IP6: 00:00:00:00:00:01 -> 00:00:00:00:00:01 incrementing 30"
        pgtext = " data {" + data + "incrementing 30 } node ethernet-input "

        self.vapi.cli("packet-generator new { name one " + pgtext + "}")
        self.vapi.cli("packet-generator new { name two " + pgtext + "}")

        proto_and_action = "proto udp redirect-to-queue 8"

        cmds = ["test flow enable index 0 pg0",
                "test flow disable index 0 pg0",
                "test flow add src-ip 192.168.8.8" + proto_and_action
                "test flow enable index 0 pg0",
                "test flow disable index 0 pg0",
                "test flow add src-ip 192.168.8.8"
                "test flow add src-ip 192.168.8.8" + proto_and_action
                "test flow enable index 0 pg0",
                "test flow enable index 0 pg1",
                "test flow del index 0"]

        for cmd in cmds:
            # Getting a reply is good enough.
            self.vapi.cli_return_response(cmd)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
