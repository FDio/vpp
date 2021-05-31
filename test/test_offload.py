#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestOffload(VppTestCase):
    """ Offload Unit Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestOffload, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestOffload, cls).tearDownClass()

    def setUp(self):
        super(TestOffload, self).setUp()

    def tearDown(self):
        super(TestOffload, self).tearDown()

    def test_offload_unittest(self):
        """ Checksum Offload Test """
        cmds = ["loop create",
                "set int ip address loop0 11.22.33.1/24",
                "set int state loop0 up",
                "loop create",
                "set int ip address loop1 11.22.34.1/24",
                "set int state loop1 up",
                "set ip neighbor loop1 11.22.34.44 03:00:11:22:34:44",
                "packet-generator new {\n"
                "  name s0\n"
                "  limit 100\n"
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
                "trace add pg-input 1",
                "pa en",
                "show error"]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, 'reply'):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

        r = self.vapi.cli_return_response("show trace")
        self.assertTrue(r.retval == 0)
        self.assertTrue(hasattr(r, 'reply'))
        rv = r.reply
        look_here = rv.find('ethernet-input')
        self.assertFalse(look_here == -1)
        bad_checksum_index = rv[look_here:].find('should be')
        self.assertTrue(bad_checksum_index == -1)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
