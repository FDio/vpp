#!/usr/bin/env python3

import unittest
import pexpect
import time
import signal
from config import config
from asfframework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw


@unittest.skipUnless(config.gcov, "part of code coverage tests")
class TestVlib(VppTestCase):
    """Vlib Unit Test Cases"""

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
        """Vlib main.c Code Coverage Test"""

        cmds = [
            "loopback create",
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
                if hasattr(r, "reply"):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

    def test_vlib_node_cli_unittest(self):
        """Vlib node_cli.c Code Coverage Test"""

        cmds = [
            "loopback create",
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
                if hasattr(r, "reply"):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

    def test_vlib_buffer_c_unittest(self):
        """Vlib buffer.c Code Coverage Test"""

        cmds = [
            "loopback create",
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
                if hasattr(r, "reply"):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

    def test_vlib_format_unittest(self):
        """Vlib format.c Code Coverage Test"""

        cmds = [
            "loopback create",
            "classify filter pcap mask l2 proto match l2 proto 0x86dd",
            "classify filter pcap del",
            "test format-vlib",
        ]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, "reply"):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

    def test_vlib_main_unittest(self):
        """Private Binary API Segment Test (takes 70 seconds)"""

        vat_path = config.vpp + "_api_test"
        vat = pexpect.spawn(vat_path, ["socket-name", self.get_api_sock_path()])
        vat.expect("vat# ", timeout=10)
        vat.sendline("sock_init_shm")
        vat.expect("vat# ", timeout=10)
        vat.sendline("sh api cli")
        vat.kill(signal.SIGKILL)
        vat.wait()
        self.logger.info("vat terminated, 70 second wait for the Reaper")
        time.sleep(70)
        self.logger.info("Reaper should be complete...")

    def test_pool(self):
        """Fixed-size Pool Test"""

        cmds = [
            "test pool",
        ]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, "reply"):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))


class TestVlibCrc32c(VppTestCase):
    """Vlib CRC32C Test Cases"""

    vpp_worker_count = 1

    @classmethod
    def setUpClass(cls):
        super(TestVlibCrc32c, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestVlibCrc32c, cls).tearDownClass()

    def setUp(self):
        super(TestVlibCrc32c, self).setUp()

    def tearDown(self):
        super(TestVlibCrc32c, self).tearDown()

    def test_crc32c(self):
        """CRC32C sanity Test"""

        output = self.vapi.cli("test crc32c")
        self.logger.info(output)
        self.assertEquals(output.find("FAIL"), -1)


class TestVlibFrameLeak(VppTestCase):
    """Vlib Frame Leak Test Cases"""

    vpp_worker_count = 1

    @classmethod
    def setUpClass(cls):
        super(TestVlibFrameLeak, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestVlibFrameLeak, cls).tearDownClass()

    def setUp(self):
        super(TestVlibFrameLeak, self).setUp()
        # create 1 pg interface
        self.create_pg_interfaces(range(1))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestVlibFrameLeak, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def test_vlib_mw_refork_frame_leak(self):
        """Vlib worker thread refork leak test case"""
        icmp_id = 0xB
        icmp_seq = 5
        icmp_load = b"\x0a" * 18
        pkt = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4)
            / ICMP(id=icmp_id, seq=icmp_seq)
            / Raw(load=icmp_load)
        )

        # Send a packet
        self.pg0.add_stream(pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)

        self.assertEquals(len(rx), 1)
        rx = rx[0]
        ether = rx[Ether]
        ipv4 = rx[IP]

        self.assertEqual(ether.src, self.pg0.local_mac)
        self.assertEqual(ether.dst, self.pg0.remote_mac)

        self.assertEqual(ipv4.src, self.pg0.local_ip4)
        self.assertEqual(ipv4.dst, self.pg0.remote_ip4)

        # Save allocated frame count
        frame_allocated = {}
        for fs in self.vapi.cli("show vlib frame-allocation").splitlines()[1:]:
            spl = fs.split()
            thread = int(spl[0])
            size = int(spl[1])
            alloc = int(spl[2])
            key = (thread, size)
            frame_allocated[key] = alloc

        # cause reforks
        _ = self.create_loopback_interfaces(1)

        # send the same packet
        self.pg0.add_stream(pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)

        self.assertEquals(len(rx), 1)
        rx = rx[0]
        ether = rx[Ether]
        ipv4 = rx[IP]

        self.assertEqual(ether.src, self.pg0.local_mac)
        self.assertEqual(ether.dst, self.pg0.remote_mac)

        self.assertEqual(ipv4.src, self.pg0.local_ip4)
        self.assertEqual(ipv4.dst, self.pg0.remote_ip4)

        # Check that no frame were leaked during refork
        for fs in self.vapi.cli("show vlib frame-allocation").splitlines()[1:]:
            spl = fs.split()
            thread = int(spl[0])
            size = int(spl[1])
            alloc = int(spl[2])
            key = (thread, size)
            self.assertEqual(frame_allocated[key], alloc)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
