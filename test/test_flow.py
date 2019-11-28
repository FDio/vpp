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

        # we only need those for their hw_if_index...
        pg0add = "create packet-generator interface pg0"
        pg1add = "create packet-generator interface pg1"

        proto_and_action = " proto udp redirect-to-queue 8"

        cmds = [[pg0add, 0],
                [pg1add, 0],
                ["test flow enable index 0 pg0", -1, "no such entry"],
                ["test flow disable index 0 pg0", -1, "no such entry"],
                ["test flow add src-ip 192.168.8.8" + proto_and_action, 0],
                ["test flow enable index 0 pg0", -1, "not supported"],
                ["test flow disable index 0 pg0", -1, "already done"],
                ["test flow add src-ip 192.168.8.8" + proto_and_action, 0],
                ["test flow enable index 0 pg0", -1, "not supported"], # these don't test properly.
                ["test flow enable index 0 pg1", -1, "not supported"],
                ["test flow del index 0", 0]]

        for cmd in cmds:
            # Getting a reply is good enough.
            ret = self.vapi.cli_return_response(cmd[0])
            if ret.retval != cmd[1]:
                print(cmd[0] + " : " + str(ret.retval))
            self.assertEqual(cmd[1], ret.retval)
            if len(cmd) == 3:
                self.assertIn(cmd[2], ret.reply)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
