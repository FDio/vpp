#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_papi_provider import CliFailedCommandError


class TestMactime(VppTestCase):
    """ Mactime Unit Test Cases """

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
        """ Time Range Test """
        error = self.vapi.cli("test time-range")

        if error:
            self.logger.critical(error)
        self.assertNotIn('FAILED', error)

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_mactime_unittest(self):
        """ Mactime Plugin Code Coverage Test """
        cmds = ["loopback create",
                "mactime enable-disable loop0",
                "mactime enable-disable loop0 disable",
                "set interface state loop0 up",
                "clear mactime",
                "set ip arp loop0 192.168.1.1 00:d0:2d:5e:86:85",
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
                "   }\n"
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
                "   }\n"
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
                "   }\n"
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
                "show error"]

        # tuples of
        # ('command', 'expected output')
        invalid_commands = [
            ("mactime enable-disable disable",
             "mactime enable-disable: Please specify an interface..."),
            ("mactime enable-disable sw_if_index 9999",
             "mactime enable-disable: Invalid interface, only works on physical ports"),  # noqa
            ("bin mactime_enable_disable loop0",
             "binary-api: mactime_enable_disable error: Misc"),
            ("bin mactime_enable_disable loop0 disable",
             "binary-api: mactime_enable_disable error: Misc"),
            ("bin mactime_enable_disable sw_if_index 1",
             "binary-api: mactime_enable_disable error: Misc"),
            ("bin mactime_add_del_range name sallow mac 00:d0:2d:5e:86:85 allow-static del",  # noqa
             "binary-api: mactime_add_del_range error: Misc"),
            ("bin mactime_add_del_range name sallow mac 00:d0:2d:5e:86:85 allow-static",  # noqa
             "binary-api: mactime_add_del_range error: Misc"),
            ("bin mactime_add_del_range name sallow "
             "mac 00:d0:2d:5e:86:85 allow-static del",
             "binary-api: mactime_add_del_range error: Misc"),
            ("bin mactime_add_del_range name sallow mac 00:d0:2d:5e:86:85 allow-static",  # noqa
             "binary-api: mactime_add_del_range error: Misc"),
            ("bin mactime_add_del_range name sblock mac 01:00:5e:7f:ff:fa drop-static",  # noqa
             "binary-api: mactime_add_del_range error: Misc"),
            ("bin mactime_add_del_range name ddrop mac c8:bc:c8:5a:ba:f3 drop-range Sun - Sat 00:00 - 23:59",  # noqa
             "binary-api: mactime_add_del_range error: Misc"),
            ("bin mactime_add_del_range name dallow mac c8:bc:c8:5a:ba:f4 allow-range Sun - Sat 00:00 - 23:59",  # noqa
             "binary-api: mactime_add_del_range error: Misc"),
            ("bin mactime_add_del_range name multi mac c8:bc:c8:f0:f0:f0 allow-range Sun - Mon 00:00 - 23:59 Tue - Sat 00:00 - 23:59",  # noqa
             "binary-api: mactime_add_del_range error: Misc"),
            ("bin mactime_add_del_range bogus",
             "mac address required, not set\n"
             "binary-api: mactime_add_del_range error: Misc"),
            ("bin mactime_add_del_range mac 01:00:5e:7f:f0:f0 allow-static",
             "binary-api: mactime_add_del_range error: Misc"),
            ("bin mactime_add_del_range name tooloooooooooooooooooooooooooooooooooooooooooooooooonnnnnnnnnnnnnnnnnnnnnnnnnnnng mac 00:00:de:ad:be:ef allow-static",  # noqa
             "device name too long, max 64\n"
             "binary-api: mactime_add_del_range error: Misc")
        ]

        for cmd in cmds:
            self.logger.info(self.vapi.cli(cmd))

        for cmd in invalid_commands:
            with self.assertRaises(CliFailedCommandError) as ctx_mgr:
                self.logger.info(self.vapi.cli(cmd[0]))

            self.assertEqual(cmd[1], ctx_mgr.exception.command_output,
                             'Msg: %s, expected: %s' %
                             (ctx_mgr.exception.args, cmd[1]))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
