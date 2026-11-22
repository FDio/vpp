#!/usr/bin/env python3

import unittest

from config import config
from asfframework import VppAsfTestCase, VppTestRunner


class TestMactime(VppAsfTestCase):
    """Mactime Unit Test Cases"""

    @classmethod
    def setUpClass(cls):
        super(TestMactime, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestMactime, cls).tearDownClass()

    def setUp(self):
        super(TestMactime, self).setUp()

    def tearDown(self):
        super(TestMactime, self).tearDown()

    def test_mactime_range_unittest(self):
        """Time Range Test"""
        error = self.vapi.cli("test time-range")

        if error:
            self.logger.critical(error)
        self.assertNotIn("FAILED", error)

    @unittest.skipUnless(config.gcov, "part of code coverage tests")
    def test_mactime_unittest(self):
        """Mactime Plugin Code Coverage Test"""
        cmds = [
            "loopback create",
            "mactime enable-disable disable",
            "mactime enable-disable loop0",
            "mactime enable-disable loop0 disable",
            "mactime enable-disable sw_if_index 9999",
            "bin mactime_enable_disable sw_if_index loop0 enable_disable on",
            "bin mactime_enable_disable sw_if_index loop0 enable_disable off",
            "bin mactime_enable_disable sw_if_index 1 enable_disable on",
            "set interface state loop0 up",
            "clear mactime",
            "set ip neighbor loop0 192.168.1.1 00:d0:2d:5e:86:85",
            "bin mactime_add_del_range is_add off device_name sallow "
            "mac_address 00:d0:2d:5e:86:85 allow on",
            "bin mactime_add_del_range is_add on device_name sallow "
            "mac_address 00:d0:2d:5e:86:85 allow on",
            "bin mactime_add_del_range is_add off device_name sallow "
            "mac_address 00:d0:2d:5e:86:85 allow on",
            "bin mactime_add_del_range is_add on device_name sallow "
            "mac_address 00:d0:2d:5e:86:85 allow on",
            "bin mactime_add_del_range is_add on device_name sblock "
            "mac_address 01:00:5e:7f:ff:fa drop on",
            "bin mactime_add_del_range is_add on device_name ddrop "
            "mac_address c8:bc:c8:5a:ba:f3 drop on "
            'json {"ranges": [{"start": 0, "end": 604740}]}',
            "bin mactime_add_del_range is_add on device_name dallow "
            "mac_address c8:bc:c8:5a:ba:f4 allow on "
            'json {"ranges": [{"start": 0, "end": 604740}]}',
            "bin mactime_add_del_range is_add on device_name multi "
            "mac_address c8:bc:c8:f0:f0:f0 allow on "
            'json {"ranges": [{"start": 0, "end": 172740}, '
            '{"start": 172800, "end": 604740}]}',
            "bin mactime_add_del_range bogus",
            "bin mactime_add_del_range is_add on "
            "mac_address 01:00:5e:7f:f0:f0 allow on",
            "bin mactime_add_del_range is_add on "
            "device_name tooloooooooooooooooooooooooooooooooooooooooooooooooo"
            "nnnnnnnnnnnnnnnnnnnnnnnnnnnng mac_address 00:00:de:ad:be:ef "
            "allow on",
            "packet-generator new {\n"
            " name allow\n"
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
            "packet-generator new {\n"
            " name deny\n"
            " limit 15\n"
            " size 128-128\n"
            " interface loop0\n"
            " node ethernet-input\n"
            " data {\n"
            "   IP6: 01:00:5e:7f:ff:fa -> 00:0d:ea:d0:00:00\n"
            "   ICMP: db00::1 -> db00::2\n"
            "   incrementing 30\n"
            "   }\n",
            "}\n",
            "packet-generator new {\n"
            " name ddrop\n"
            " limit 15\n"
            " size 128-128\n"
            " interface loop0\n"
            " node ethernet-input\n"
            " data {\n"
            "   IP6: c8:bc:c8:5a:ba:f3 -> 00:0d:ea:d0:00:00\n"
            "   ICMP: db00::1 -> db00::2\n"
            "   incrementing 30\n"
            "   }\n",
            "}\n",
            "packet-generator new {\n"
            " name dallow\n"
            " limit 15\n"
            " size 128-128\n"
            " interface loop0\n"
            " node ethernet-input\n"
            " data {\n"
            "   IP6: c8:bc:c8:5a:ba:f4 -> 00:0d:ea:d0:00:00\n"
            "   ICMP: db00::1 -> db00::2\n"
            "   incrementing 30\n"
            "   }\n"
            "}\n"
            "packet-generator new {\n"
            " name makeentry\n"
            " limit 15\n"
            " size 128-128\n"
            " interface loop0\n"
            " node ethernet-input\n"
            " data {\n"
            "   IP6: c8:bc:c8:5a:b0:0b -> 00:0d:ea:d0:00:00\n"
            "   ICMP: db00::1 -> db00::2\n"
            "   incrementing 30\n"
            "   }\n"
            "}\n"
            "packet-generator new {\n"
            " name tx\n"
            " limit 15\n"
            " size 128-128\n"
            " interface local0\n"
            " tx-interface loop0\n"
            " node loop0-output\n"
            " data {\n"
            "   hex 0x01005e7ffffa000dead000000800"
            "0102030405060708090a0b0c0d0e0f0102030405\n"
            "   }\n"
            "}\n"
            "trace add pg-input 2",
            "pa en",
            "show mactime verbose 2",
            "show trace",
            "show error",
        ]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, "reply"):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
