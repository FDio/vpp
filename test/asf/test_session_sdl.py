#!/usr/bin/env python3

import subprocess
import socket

import unittest

from framework import VppTestCase
from config import config
from asfframework import VppTestRunner, tag_fixme_vpp_workers
from ipaddress import IPv4Network, IPv6Network
from vpp_acl import AclRule, VppAcl, VppAclInterface

from vpp_ip_route import (
    VppIpRoute,
    VppRoutePath,
    VppIpTable,
)

from vpp_papi import VppEnum
from vpp_session_sdl import VppSessionSdl, SessionSdl


@tag_fixme_vpp_workers
class TestSessionSDL(VppTestCase):
    """Session SDL Test Case"""

    tcp_startup = ["syn-rcvd-time 1"]

    @classmethod
    def setUpClass(cls):
        if cls.tcp_startup:
            conf = "tcp {" + " ".join(cls.tcp_startup) + "}"
            cls.extra_vpp_config = [conf]
        super(TestSessionSDL, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSessionSDL, cls).tearDownClass()

    def setUp(self):
        super(TestSessionSDL, self).setUp()
        self.create_loopback_interfaces(2)

        table_id = 0

        for i in self.lo_interfaces:
            i.admin_up()

            if table_id != 0:
                tbl = VppIpTable(self, table_id)
                tbl.add_vpp_config()
                tbl = VppIpTable(self, table_id, is_ip6=1)
                tbl.add_vpp_config()

            i.set_table_ip4(table_id)
            i.set_table_ip6(table_id)
            i.config_ip4()
            i.config_ip6()
            table_id += 1

    def tearDown(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.unconfig_ip6()
            i.set_table_ip6(0)
            i.admin_down()
        self.loop0.remove_vpp_config()
        self.loop1.remove_vpp_config()
        super(TestSessionSDL, self).tearDown()

    def create_rule(self, rmt, action_index, tag):
        return SessionSdl(rmt=rmt, action_index=action_index, tag=tag)

    def apply_rules(self, rules, is_add, appns_index):
        r = VppSessionSdl(self, rules, is_add=is_add, appns_index=appns_index)
        r.add_vpp_config()

    def test_session_sdl_ip4(self):
        """Session SDL IP4 test"""

        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_SDL
        )

        # Configure namespaces
        app0 = self.vapi.app_namespace_add_del_v4(
            namespace_id="0", sw_if_index=self.loop0.sw_if_index
        )
        app1 = self.vapi.app_namespace_add_del_v4(
            namespace_id="1", sw_if_index=self.loop1.sw_if_index
        )

        # Add inter-table routes
        uri = "tcp://" + self.loop0.local_ip4 + "/1234"
        server_cmd = "test echo server appns 0 fifo-size 4k " + "uri " + uri
        client_cmd = (
            "test echo client bytes 100000 appns 1 "
            + "fifo-size 4k "
            + "syn-timeout 2 uri "
            + uri
        )
        ip_t01 = VppIpRoute(
            self,
            self.loop1.local_ip4,
            32,
            [VppRoutePath("0.0.0.0", 0xFFFFFFFF, nh_table_id=1)],
        )
        ip_t10 = VppIpRoute(
            self,
            self.loop0.local_ip4,
            32,
            [VppRoutePath("0.0.0.0", 0xFFFFFFFF, nh_table_id=0)],
            table_id=1,
        )
        ip_t01.add_vpp_config()
        ip_t10.add_vpp_config()

        # Start builtin server for ip4 on loop0 appns 0
        self.logger.info(self.vapi.cli(server_cmd))

        # Add session filter to block loop1 (client on loop1 appns 1)
        rules = []
        rules.append(
            self.create_rule(rmt=self.loop1.local_ip4 + "/32", action_index=0, tag="")
        )
        self.apply_rules(rules, is_add=1, appns_index=0)

        filter = self.vapi.session_sdl_v3_dump()
        self.assertEqual(filter[0].rmt, IPv4Network(self.loop1.local_ip4 + "/32"))
        self.assertEqual(len(filter[0].appns_index), 2)
        self.assertEqual(filter[0].count, 2)
        self.assertEqual(filter[0].appns_index[0], 0)
        self.assertEqual(filter[0].appns_index[1], app0.appns_index)

        # irrelevant rules - add 64k entries in one API call
        rules = []
        for i in range(255):
            for j in range(255):
                prefix = "10.1.{0}.{1}/32".format(i, j)
                rules.append(self.create_rule(rmt=prefix, action_index=0, tag=""))
        self.apply_rules(rules, is_add=1, appns_index=0)

        error = self.vapi.cli_return_response(client_cmd)
        # Expecting an error because loop1 is blocked
        self.assertEqual(-1, error.retval)

        # Remove the session filter
        rules = []
        rules.append(
            self.create_rule(rmt=self.loop1.local_ip4 + "/32", action_index=0, tag="")
        )
        self.apply_rules(rules, is_add=0, appns_index=0)

        # Not expecting an error
        self.logger.info(self.vapi.cli(client_cmd))

        # Add a session filter not matching loop1
        rules = []
        rules.append(self.create_rule(rmt="172.100.1.0/24", action_index=0, tag=""))
        self.apply_rules(rules, is_add=1, appns_index=0)

        # Not expecting an error
        self.logger.info(self.vapi.cli(client_cmd))

        self.logger.info(self.vapi.cli(server_cmd + " stop"))

        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="0", sw_if_index=self.loop0.sw_if_index
        )
        filter = self.vapi.session_sdl_v3_dump()
        self.assertEqual(len(filter[0].appns_index), 1)
        self.assertEqual(filter[0].count, 1)
        self.assertEqual(filter[0].appns_index[0], 0)

        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="1", sw_if_index=self.loop1.sw_if_index
        )
        # Delete inter-table routes
        ip_t01.remove_vpp_config()
        ip_t10.remove_vpp_config()
        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
        )

    def test_session_sdl_ip6(self):
        """Session SDL IP6 test"""

        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_SDL
        )

        # Configure namespaces
        self.vapi.app_namespace_add_del_v4(
            namespace_id="0", sw_if_index=self.loop0.sw_if_index
        )
        self.vapi.app_namespace_add_del_v4(
            namespace_id="1", sw_if_index=self.loop1.sw_if_index
        )

        # IP6 Test
        # Add inter-table routes
        uri = "tcp://" + self.loop0.local_ip6 + "/1235"
        client_cmd = (
            "test echo client bytes 100000 appns 1 "
            + "fifo-size 4k "
            + "syn-timeout 2 uri "
            + uri
        )
        server_cmd = "test echo server appns 0 fifo-size 4k " + "uri " + uri

        ip_t01 = VppIpRoute(
            self,
            self.loop1.local_ip6,
            128,
            [VppRoutePath("0::0", 0xFFFFFFFF, nh_table_id=1)],
        )
        ip_t10 = VppIpRoute(
            self,
            self.loop0.local_ip6,
            128,
            [VppRoutePath("0::0", 0xFFFFFFFF, nh_table_id=0)],
            table_id=1,
        )
        ip_t01.add_vpp_config()
        ip_t10.add_vpp_config()

        # Start builtin server for ip6 on loop0 appns 0
        self.logger.info(self.vapi.cli(server_cmd))

        # case 1: No filter

        # Not expecting an error
        self.logger.info(self.vapi.cli(client_cmd))

        # case 2: filter to block
        # Add session filter to block loop1, client appns 1
        rules = []
        rules.append(
            self.create_rule(rmt=self.loop1.local_ip6 + "/128", action_index=0, tag="")
        )
        self.apply_rules(rules, is_add=1, appns_index=0)
        filter = self.vapi.session_sdl_v2_dump()
        self.assertEqual(filter[0].rmt, IPv6Network(self.loop1.local_ip6 + "/128"))

        error = self.vapi.cli_return_response(client_cmd)
        # Expecting an error because loop1 is blocked
        self.assertEqual(-1, error.retval)

        # case 3: remove filter to unblock
        rules = []
        rules.append(
            self.create_rule(rmt=self.loop1.local_ip6 + "/128", action_index=0, tag="")
        )
        self.apply_rules(rules, is_add=0, appns_index=0)
        # Not expecting an error
        self.logger.info(self.vapi.cli(client_cmd))

        # stop the server
        self.logger.info(self.vapi.cli(server_cmd + " stop"))

        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="0", sw_if_index=self.loop0.sw_if_index
        )
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="1", sw_if_index=self.loop1.sw_if_index
        )
        # Delete inter-table routes
        ip_t01.remove_vpp_config()
        ip_t10.remove_vpp_config()
        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
        )

    def test_session_enable_disable(self):
        """Session SDL enable/disable test"""

        for i in range(10):
            # Enable sdl
            self.vapi.session_enable_disable_v2(
                rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_SDL
            )

            # Disable
            self.vapi.session_enable_disable_v2(
                rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
            )

            # Enable rule-table
            self.vapi.session_enable_disable_v2(
                rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_RULE_TABLE
            )

            # Disable
            self.vapi.session_enable_disable_v2(
                rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
            )

            # Enable sdl
            self.vapi.session_enable_disable_v2(
                rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_SDL
            )

            # Disable
            self.vapi.session_enable_disable_v2(
                rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
            )


VPP_TAP_IP4 = "8.8.8.1"
VPP_TAP_IP6 = "2001::1"

HOST_TAP_IP4 = "8.8.8.2"
HOST_TAP_IP6 = "2001::2"
SCALE_COUNT = 250


@tag_fixme_vpp_workers
@unittest.skipUnless(config.extended, "part of extended tests")
class TestSessionAutoSDL(VppTestCase):
    """Session Auto SDL Baasic Test Case"""

    tcp_startup = ["syn-rcvd-time 1"]

    @classmethod
    def setUpClass(cls):
        if cls.tcp_startup:
            conf = "tcp {" + " ".join(cls.tcp_startup) + "}"
            cls.extra_vpp_config = [conf]
        super(TestSessionAutoSDL, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSessionAutoSDL, cls).tearDownClass()

    def setUp(self):
        super(TestSessionAutoSDL, self).setUp()

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
        super(TestSessionAutoSDL, self).tearDown()

    def test_session_auto_sdl(self):
        """Session Auto SDL test"""

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

        # Test 2. Add ACL to block the source. Auto SDL entry should be created
        # and timed out accordingly
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

        self.vapi.session_auto_sdl(threshold=2, remove_timeout=3, enable=True)

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
            dump = self.vapi.session_sdl_v2_dump()
            if len(dump) == 0:
                self.sleep(1)
        self.assertTrue(len(dump) > 0)
        self.assertEqual(dump[0].rmt, IPv4Network(HOST_TAP_IP4 + "/32"))

        # verify entry is timed out and removed eventually
        for i in range(10):
            dump = self.vapi.session_sdl_v2_dump()
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
            dump = self.vapi.session_sdl_v2_dump()
            if len(dump) == 0:
                self.sleep(1)
        self.assertTrue(len(dump) > 0)
        self.assertEqual(dump[0].rmt, IPv6Network(HOST_TAP_IP6 + "/128"))

        # verify the entry is removed after timeout
        for i in range(10):
            dump = self.vapi.session_sdl_v2_dump()
            if len(dump) > 0:
                self.sleep(1)
        self.assertEqual(len(dump), 0)
        self.logger.info("Test 3 passed")

        self.vapi.session_auto_sdl(enable=False)
        # bring down the cli server
        self.logger.info(self.vapi.cli("http cli server listener del"))
        self.logger.info(
            self.vapi.cli("http cli server uri http://::0/80 listener del")
        )
        self.logger.info(
            self.vapi.sw_interface_add_del_address(
                is_add=0, sw_if_index=self.tap0.sw_if_index, prefix=VPP_TAP_IP4 + "/24"
            )
        )
        # self.logger.info(self.vapi.cli("set interface ip address tap0 VPP_TAP_IP6/64"))
        self.logger.info(
            self.vapi.sw_interface_add_del_address(
                is_add=0, sw_if_index=self.tap0.sw_if_index, prefix=VPP_TAP_IP6 + "/64"
            )
        )
        self.logger.info(self.vapi.tap_delete_v2(self.tap0.sw_if_index))
        self.logger.info(
            self.vapi.session_enable_disable_v2(
                rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
            )
        )

    def test_session_auto_sdl_scale(self):
        """Session Auto SDL scale test"""

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
        self.vapi.session_auto_sdl(threshold=1, remove_timeout=60, enable=True)
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
            for j in range(1):
                try:
                    s = socket.create_connection(
                        (VPP_TAP_IP4, 80), timeout=0.05, source_address=prefix_port
                    )
                except:
                    self.logger.info("connect timeout -- as exepcted")

        # check for the SDL entry
        for i in range(60):
            dump = self.vapi.session_sdl_v2_dump()
            if len(dump) != SCALE_COUNT:
                self.sleep(1)

        self.assertEqual(len(dump), SCALE_COUNT)
        self.logger.info("Test 4 passed")

        # Test 5: Disable auto-sdl
        # It should clean up the Auto SDL and SDL entries immediately
        self.logger.info(self.vapi.session_auto_sdl(enable=False))
        dump = self.vapi.session_sdl_v2_dump()
        self.assertEqual(len(dump), 0)

        acl_if_e.remove_vpp_config()
        acl.remove_vpp_config()
        self.logger.info("Test 5 passed")

        # bring down the cli server
        self.vapi.cli("http cli server listener del")

        self.vapi.sw_interface_add_del_address(
            is_add=0, sw_if_index=self.tap0.sw_if_index, prefix=VPP_TAP_IP4 + "/24"
        )
        self.vapi.tap_delete_v2(self.tap0.sw_if_index)
        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
        )

    def test_session_auto_sdl_appns_ip4(self):
        """Session Auto SDL with appns test -- ip4"""

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

        self.logger.info(self.vapi.cli("http cli server appns 1 secret 1"))

        # start http cli server in appns 1
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

        self.vapi.session_auto_sdl(threshold=1, remove_timeout=60, enable=True)
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
                dump = self.vapi.session_sdl_v2_dump()
                if len(dump) == 0:
                    self.sleep(1)
                else:
                    break

        for i in range(60):
            dump = self.vapi.session_sdl_v2_dump()
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
        self.vapi.sw_interface_add_del_address(
            is_add=0,
            sw_if_index=self.tap0.sw_if_index,
            prefix=VPP_TAP_IP4 + "/24",
            del_all=1,
        )
        # delete tap0
        self.vapi.tap_delete_v2(self.tap0.sw_if_index)

        # Disable auto sdl -- quicker than waiting the entry to timeout
        self.vapi.session_auto_sdl(enable=False)

        # disable session sdl
        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
        )

        dump = self.vapi.session_sdl_v2_dump()
        self.assertTrue(len(dump) == 0)

    def test_session_auto_sdl_appns_ip6(self):
        """Session Auto SDL with appns test -- ip6"""

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

        self.vapi.session_auto_sdl(threshold=1, remove_timeout=60, enable=True)
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
                dump = self.vapi.session_sdl_v2_dump()
                if len(dump) == 0:
                    self.sleep(1)
                else:
                    break

        for i in range(60):
            dump = self.vapi.session_sdl_v2_dump()
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

        self.vapi.sw_interface_add_del_address(
            is_add=0,
            sw_if_index=self.tap0.sw_if_index,
            prefix=VPP_TAP_IP6 + "/64",
            del_all=1,
        )
        # delete tap0
        self.vapi.tap_delete_v2(self.tap0.sw_if_index)

        # Disable auto sdl -- quicker than waiting the entry to timeout
        self.vapi.session_auto_sdl(enable=False)

        # disable session sdl
        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
        )

        dump = self.vapi.session_sdl_v2_dump()
        self.assertTrue(len(dump) == 0)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
