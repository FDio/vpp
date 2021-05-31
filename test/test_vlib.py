#!/usr/bin/env python3

import unittest
import pexpect
import time
import signal
from config import config
from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


@unittest.skipUnless(config.gcov, "part of code coverage tests")
class TestVlib(VppTestCase):
    """ Vlib Unit Test Cases """
    vpp_worker_count = 1

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
                "   }\n"
                "}\n",
                "event-logger trace dispatch",
                "event-logger stop",
                "event-logger clear",
                "event-logger resize 102400",
                "event-logger restart",
                "pcap dispatch trace on max 100 buffer-trace pg-input 15",
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
                "   }\n"
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
                "show \t",
                ]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, 'reply'):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

    def test_vlib_buffer_c_unittest(self):
        """ Vlib buffer.c Code Coverage Test """

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
                "   }\n"
                "}\n",
                "event-logger trace",
                "event-logger trace enable",
                "event-logger trace api cli barrier",
                "pa en",
                "show interface bogus",
                "event-logger trace disable api cli barrier",
                "event-logger trace circuit-node ethernet-input",
                "event-logger trace circuit-node ethernet-input disable",
                "clear interfaces",
                "test vlib",
                "test vlib2",
                "show memory api-segment stats-segment main-heap verbose",
                "leak-check { show memory }",
                "show cpu",
                "memory-trace main-heap",
                "memory-trace main-heap api-segment stats-segment",
                "leak-check { show version }",
                "show version ?",
                "comment { show version }",
                "uncomment { show version }",
                "show memory main-heap",
                "show memory bogus",
                "choices",
                "test heap-validate",
                "memory-trace main-heap disable",
                "show buffers",
                "show eve",
                "show help",
                "show ip ",
                ]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, 'reply'):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

    def test_vlib_format_unittest(self):
        """ Vlib format.c Code Coverage Test """

        cmds = ["loopback create",
                "classify filter pcap mask l2 proto match l2 proto 0x86dd",
                "classify filter pcap del",
                "test format-vlib",
                ]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, 'reply'):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

    def test_vlib_main_unittest(self):
        """ Private Binary API Segment Test (takes 70 seconds) """

        vat_path = self.vpp_bin + '_api_test'
        vat = pexpect.spawn(vat_path, ['socket-name',
                                       self.get_api_sock_path()])
        vat.expect("vat# ", timeout=10)
        vat.sendline('sock_init_shm')
        vat.expect("vat# ", timeout=10)
        vat.sendline('sh api cli')
        vat.kill(signal.SIGKILL)
        vat.wait()
        self.logger.info("vat terminated, 70 second wait for the Reaper")
        time.sleep(70)
        self.logger.info("Reaper should be complete...")

    def test_pool(self):
        """ Fixed-size Pool Test """

        cmds = ["test pool",
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
