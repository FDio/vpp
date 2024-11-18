#!/usr/bin/env python3

import subprocess
import socket

import unittest

from asfframework import (
    VppAsfTestCase,
    VppTestRunner,
    tag_fixme_vpp_workers,
    tag_run_solo,
)
from config import config
from ipaddress import IPv4Network, IPv6Network
from vpp_acl import AclRule, VppAcl, VppAclInterface

from vpp_ip_route import (
    VppIpRoute,
    VppRoutePath,
    VppIpTable,
)

from vpp_papi import VppEnum


VPP_TAP_IP4 = "8.8.8.1"
VPP_TAP_IP6 = "2001::1"

HOST_TAP_IP4 = "8.8.8.2"
HOST_TAP_IP6 = "2001::2"
SCALE_COUNT = 10


@tag_fixme_vpp_workers
class TestAutoSDLUnitTests(VppAsfTestCase):
    """Auto SDL Unit Tests Case"""

    @classmethod
    def setUpClass(cls):
        super(TestAutoSDLUnitTests, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestAutoSDLUnitTests, cls).tearDownClass()

    def setUp(self):
        super(TestAutoSDLUnitTests, self).setUp()
        self.vapi.session_enable_disable(is_enable=1)

    def test_session(self):
        """Auto SDL Unit Tests"""
        error = self.vapi.cli("test auto-sdl all")

        if error:
            self.logger.critical(error)
        self.assertNotIn("failed", error)

    def tearDown(self):
        super(TestAutoSDLUnitTests, self).tearDown()
        self.vapi.session_enable_disable(is_enable=0)


@tag_fixme_vpp_workers
@unittest.skipUnless(config.extended, "part of extended tests")
class TestAutoSDL(VppAsfTestCase):
    """Auto SDL Baasic Test Case"""

    tcp_startup = ["syn-rcvd-time 1"]

    @classmethod
    def setUpClass(cls):
        if cls.tcp_startup:
            conf = "tcp {" + " ".join(cls.tcp_startup) + "}"
            cls.extra_vpp_config = [conf]
        super(TestAutoSDL, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestAutoSDL, cls).tearDownClass()

    def setUp(self):
        super(TestAutoSDL, self).setUp()

        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_SDL
        )

        # self.logger.info(self.vapi.cli("create tap host-ip4-addr HOST_TAP_IP/24"))
        self.tap0 = self.vapi.tap_create_v3(
            id=0,
            host_ip4_prefix=HOST_TAP_IP4 + "/24",
            host_ip4_prefix_set=True,
            host_ip6_prefix=HOST_TAP_IP6 + "/64",
            host_ip6_prefix_set=True,
        )

        # self.logger.info(self.vapi.cli("set interface state tap0 up"))
        self.vapi.sw_interface_set_flags(sw_if_index=self.tap0.sw_if_index, flags=1)

    def tearDown(self):
        self.logger.info(
            self.vapi.sw_interface_add_del_address(
                is_add=0,
                sw_if_index=self.tap0.sw_if_index,
                prefix=VPP_TAP_IP4 + "/24",
                del_all=1,
            )
        )
        # self.logger.info(self.vapi.cli("set interface ip address tap0 VPP_TAP_IP6/64"))
        self.logger.info(
            self.vapi.sw_interface_add_del_address(
                is_add=0,
                sw_if_index=self.tap0.sw_if_index,
                prefix=VPP_TAP_IP6 + "/64",
                del_all=1,
            )
        )
        self.logger.info(self.vapi.tap_delete_v2(self.tap0.sw_if_index))
        self.logger.info(
            self.vapi.session_enable_disable_v2(
                rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
            )
        )
        dump = self.vapi.session_sdl_v3_dump()
        self.assertTrue(len(dump) == 0)
        super(TestAutoSDL, self).tearDown()

    def test_auto_sdl(self):
        """Auto SDL test"""

        # self.logger.info(self.vapi.cli("set interface ip address tap0 VPP_TAP_IP/24"))
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.tap0.sw_if_index, prefix=VPP_TAP_IP4 + "/24"
        )
        # self.logger.info(self.vapi.cli("set interface ip address tap0 VPP_TAP_IP6/64"))
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.tap0.sw_if_index, prefix=VPP_TAP_IP6 + "/64"
        )

        # start the cli server
        self.logger.info("Starting cli sever")
        self.logger.info(self.vapi.cli("http cli server"))

        self.logger.info(
            self.vapi.cli("http cli server uri http://::0/80 listener add")
        )

        # Test 1. No ACL. curl should work.
        self.logger.info("Starting test 1")
        for i in range(10):
            try:
                process = subprocess.run(
                    [
                        "curl",
                        "--noproxy",
                        "'*'",
                        "http://" + VPP_TAP_IP4 + ":80/sh/version",
                    ],
                    capture_output=True,
                    timeout=2,
                )
            except:
                self.logger.info("timeout")
            else:
                break
        self.assertEqual(0, process.returncode)
        self.logger.info("Test 1 passed")

        # Test 2. Add ACL to block the source.
        rule = AclRule(
            is_permit=0,
            proto=6,
            src_prefix=IPv4Network("8.8.0.0/16"),
            dst_prefix=IPv4Network(VPP_TAP_IP4 + "/32"),
            ports=80,
        )
        acl = VppAcl(self, rules=[rule])
        acl.add_vpp_config()

        # Apply the ACL on the interface output
        # Auto SDL entry should be created and timed out accordingly
        acl_if_e = VppAclInterface(
            self, sw_if_index=self.tap0.sw_if_index, n_input=0, acls=[acl]
        )
        acl_if_e.add_vpp_config()

        self.vapi.auto_sdl_config(threshold=2, remove_timeout=3, enable=True)

        for i in range(2):
            try:
                process = subprocess.run(
                    [
                        "curl",
                        "--noproxy",
                        "'*'",
                        "http://" + VPP_TAP_IP4 + ":80/sh/version",
                    ],
                    capture_output=True,
                    timeout=2,
                )
            except:
                self.logger.info("curl timeout -- as exepcted")

        # check for the SDL entry
        for i in range(10):
            dump = self.vapi.session_sdl_v3_dump()
            if len(dump) == 0:
                self.sleep(1)
        self.assertTrue(len(dump) > 0)
        self.assertEqual(dump[0].rmt, IPv4Network(HOST_TAP_IP4 + "/32"))

        # verify entry is timed out and removed eventually
        for i in range(10):
            dump = self.vapi.session_sdl_v3_dump()
            if len(dump) > 0:
                self.sleep(1)
        self.assertTrue(len(dump) == 0)

        acl_if_e.remove_vpp_config()
        acl.remove_vpp_config()
        self.logger.info("Test 2 passed")

        # Test 3: Do the same for IPv6
        process = subprocess.run(
            [
                "curl",
                "-6",
                "--noproxy",
                "'*'",
                "http://" + "[" + VPP_TAP_IP6 + "]" + ":80/sh/version",
            ],
            capture_output=True,
        )
        self.assertEqual(0, process.returncode)

        rule = AclRule(
            is_permit=0,
            proto=6,
            src_prefix=IPv6Network(HOST_TAP_IP6 + "/128"),
            dst_prefix=IPv6Network(VPP_TAP_IP6 + "/128"),
            ports=80,
        )
        acl = VppAcl(self, rules=[rule])
        acl.add_vpp_config()

        # Apply the ACL on the interface output
        acl_if_e = VppAclInterface(
            self, sw_if_index=self.tap0.sw_if_index, n_input=0, acls=[acl]
        )
        acl_if_e.add_vpp_config()

        for i in range(2):
            try:
                process = subprocess.run(
                    [
                        "curl",
                        "-6",
                        "--noproxy",
                        "'*'",
                        "http://" + "[" + VPP_TAP_IP6 + "]" + ":80/sh/version",
                    ],
                    capture_output=True,
                    timeout=2,
                )
            except:
                self.logger.info("curl timeout -- as exepcted")

        acl_if_e.remove_vpp_config()
        acl.remove_vpp_config()

        # verify the SDL entry is added
        for i in range(5):
            dump = self.vapi.session_sdl_v3_dump()
            if len(dump) == 0:
                self.sleep(1)
        self.assertTrue(len(dump) > 0)
        self.assertEqual(dump[0].rmt, IPv6Network(HOST_TAP_IP6 + "/128"))

        # verify the entry is removed after timeout
        for i in range(10):
            dump = self.vapi.session_sdl_v3_dump()
            if len(dump) > 0:
                self.sleep(1)
        self.assertEqual(len(dump), 0)
        self.logger.info("Test 3 passed")

        self.vapi.auto_sdl_config(enable=False)

        # bring down the cli server
        self.logger.info(self.vapi.cli("http cli server listener del"))
        self.logger.info(
            self.vapi.cli("http cli server uri http://::0/80 listener del")
        )

    def test_auto_sdl_appns_ip4(self):
        """Auto SDL with appns test -- ip4"""

        # Test tap0 in appns 1
        table_id = 1
        tbl = VppIpTable(self, table_id)
        tbl.add_vpp_config()

        # place tap0 to vrf 1
        self.vapi.sw_interface_set_table(
            self.tap0.sw_if_index, is_ipv6=0, vrf_id=table_id
        )

        # place tap0 to appns 1
        self.vapi.app_namespace_add_del_v4(
            namespace_id="1", secret=1, sw_if_index=self.tap0.sw_if_index
        )
        # configure ip4 address on tap0
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.tap0.sw_if_index, prefix=VPP_TAP_IP4 + "/24"
        )

        # start http cli server in appns 1
        self.logger.info(self.vapi.cli("http cli server appns 1 secret 1"))

        process = subprocess.run(
            [
                "curl",
                "--noproxy",
                "'*'",
                "http://" + VPP_TAP_IP4 + ":80/sh/version",
            ],
            timeout=1,
            capture_output=True,
        )
        self.assertEqual(0, process.returncode)

        # Apply the ACL on the interface output
        rule = AclRule(
            is_permit=0,
            proto=6,
            src_prefix=IPv4Network("8.8.0.0/16"),
            dst_prefix=IPv4Network(VPP_TAP_IP4 + "/32"),
            ports=80,
        )
        acl = VppAcl(self, rules=[rule])
        acl.add_vpp_config()

        acl_if_e = VppAclInterface(
            self, sw_if_index=self.tap0.sw_if_index, n_input=0, acls=[acl]
        )
        acl_if_e.add_vpp_config()

        self.vapi.auto_sdl_config(threshold=1, remove_timeout=60, enable=True)
        for i in range(10):
            try:
                process = subprocess.run(
                    [
                        "curl",
                        "--noproxy",
                        "'*'",
                        "http://" + VPP_TAP_IP4 + ":80/sh/version",
                    ],
                    capture_output=True,
                    timeout=1,
                )
            except:
                self.logger.info("connect timeout -- as expected")
            else:
                dump = self.vapi.session_sdl_v3_dump()
                if len(dump) == 0:
                    self.sleep(1)
                else:
                    break

        for i in range(60):
            dump = self.vapi.session_sdl_v3_dump()
            if len(dump) != 1:
                self.sleep(1)
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0].rmt, IPv4Network(HOST_TAP_IP4 + "/32"))
        self.logger.info("Test 6 passed")

        acl_if_e.remove_vpp_config()
        acl.remove_vpp_config()

        # bring down the cli server
        self.logger.info(self.vapi.cli("http cli server listener del"))

        # delete namespace
        self.vapi.app_namespace_add_del_v4(
            namespace_id="1",
            secret=1,
            sw_if_index=self.tap0.sw_if_index,
            is_add=0,
        )

        # Disable auto sdl -- quicker than waiting the entry to timeout
        self.vapi.auto_sdl_config(enable=False)

        # disable session sdl
        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
        )

        dump = self.vapi.session_sdl_v3_dump()
        self.assertTrue(len(dump) == 0)

    def test_auto_sdl_appns_ip6(self):
        """Auto SDL with appns test -- ip6"""

        # Test tap0 in appns 1
        table_id = 1
        tbl = VppIpTable(self, table_id, is_ip6=1)
        tbl.add_vpp_config()

        # place tap0 to vrf 1
        self.vapi.sw_interface_set_table(
            self.tap0.sw_if_index, is_ipv6=1, vrf_id=table_id
        )

        # place tap0 to appns 1
        self.vapi.app_namespace_add_del_v4(
            namespace_id="1", secret=1, sw_if_index=self.tap0.sw_if_index
        )
        # configure ip6 address on tap0
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.tap0.sw_if_index, prefix=VPP_TAP_IP6 + "/64"
        )

        # start http cli server in appns 1
        self.logger.info(
            self.vapi.cli("http cli server appns 1 secret 1 uri http://::0/80")
        )

        self.sleep(3)
        process = subprocess.run(
            [
                "curl",
                "-6",
                "--noproxy",
                "'*'",
                "http://" + "[" + VPP_TAP_IP6 + "]" + ":80/sh/version",
            ],
            timeout=5,
            capture_output=True,
        )
        self.assertEqual(0, process.returncode)

        # Apply the ACL on the interface output
        rule = AclRule(
            is_permit=0,
            proto=6,
            src_prefix=IPv6Network(HOST_TAP_IP6 + "/128"),
            dst_prefix=IPv6Network(VPP_TAP_IP6 + "/128"),
            ports=80,
        )
        acl = VppAcl(self, rules=[rule])
        acl.add_vpp_config()

        acl_if_e = VppAclInterface(
            self, sw_if_index=self.tap0.sw_if_index, n_input=0, acls=[acl]
        )
        acl_if_e.add_vpp_config()

        self.vapi.auto_sdl_config(threshold=1, remove_timeout=60, enable=True)
        for i in range(10):
            try:
                process = subprocess.run(
                    [
                        "curl",
                        "-6",
                        "--noproxy",
                        "'*'",
                        "http://" + "[" + VPP_TAP_IP6 + "]" + ":80/sh/version",
                    ],
                    capture_output=True,
                    timeout=1,
                )
            except:
                self.logger.info("connect timeout -- as expected")
            else:
                dump = self.vapi.session_sdl_v3_dump()
                if len(dump) == 0:
                    self.sleep(1)
                else:
                    break

        for i in range(60):
            dump = self.vapi.session_sdl_v3_dump()
            if len(dump) != 1:
                self.sleep(1)
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0].rmt, IPv6Network(HOST_TAP_IP6 + "/128"))
        self.logger.info("Test 6 passed")

        acl_if_e.remove_vpp_config()
        acl.remove_vpp_config()

        # bring down the cli server
        self.logger.info(
            self.vapi.cli("http cli server uri http://::0/80 listener del")
        )

        # delete namespace
        self.vapi.app_namespace_add_del_v4(
            namespace_id="1",
            secret=1,
            sw_if_index=self.tap0.sw_if_index,
            is_add=0,
        )

    @unittest.skip("test disabled for auto sdl")
    def test_auto_sdl_scale(self):
        """Auto SDL scale test"""

        # Test 4: Scale
        # Send 250 packets from different sources. Should create 250 auto-SDL
        # and SDL entries
        # self.logger.info(self.vapi.cli("set interface ip address tap0 VPP_TAP_IP/24"))

        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.tap0.sw_if_index, prefix=VPP_TAP_IP4 + "/24"
        )

        # start the cli server
        self.logger.info("Starting cli sever")
        self.logger.info(self.vapi.cli("http cli server"))

        rule = AclRule(
            is_permit=0,
            proto=6,
            src_prefix=IPv4Network("8.8.0.0/16"),
            dst_prefix=IPv4Network(VPP_TAP_IP4 + "/32"),
            ports=80,
        )
        acl = VppAcl(self, rules=[rule])
        acl.add_vpp_config()

        # Apply the ACL on the interface output
        acl_if_e = VppAclInterface(
            self, sw_if_index=self.tap0.sw_if_index, n_input=0, acls=[acl]
        )
        acl_if_e.add_vpp_config()

        # set the remove_timeout to a large value. Otherwise, some entries may
        # get timed out before we accumulate all of them for verification
        self.vapi.auto_sdl_config(threshold=1, remove_timeout=300, enable=True)

        for i in range(SCALE_COUNT):
            prefix = "8.8.8.{0}".format(i + 3)
            prefix_mask = "8.8.8.{0}/24".format(i + 3)
            prefix_port = (prefix, 5000)
            process = subprocess.run(
                [
                    "ip",
                    "address",
                    "add",
                    prefix_mask,
                    "dev",
                    "tap0",
                ],
                capture_output=True,
            )
            self.assertEqual(process.returncode, 0)
            for i in range(2):
                try:
                    s = socket.create_connection(
                        (VPP_TAP_IP4, 80), timeout=0.5, source_address=prefix_port
                    )
                except:
                    self.logger.info("connect timeout -- as exepcted")

        # check for the SDL entry
        for i in range(60):
            dump = self.vapi.session_sdl_v3_dump()
            if len(dump) != SCALE_COUNT:
                self.sleep(1)

        self.assertEqual(len(dump), SCALE_COUNT)
        self.logger.info("Test 4 passed")

        # Test 5: Disable auto-sdl
        # It should clean up the Auto SDL and SDL entries immediately
        self.logger.info(self.vapi.auto_sdl_config(enable=False))
        dump = self.vapi.session_sdl_v3_dump()
        self.assertEqual(len(dump), 0)

        acl_if_e.remove_vpp_config()
        acl.remove_vpp_config()
        self.logger.info("Test 5 passed")

        # bring down the cli server
        self.vapi.cli("http cli server listener del")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
