#!/usr/bin/env python3

import unittest

from framework import VppTestCase
from asfframework import VppTestRunner, tag_fixme_vpp_workers, tag_fixme_asan
from ipaddress import IPv4Network, IPv6Network
from config import config

from vpp_ip_route import (
    VppIpRoute,
    VppRoutePath,
    VppIpTable,
)

from vpp_papi import VppEnum


from vpp_session_sdl import VppSessionSdl
from vpp_session_sdl import SessionSdl


@tag_fixme_vpp_workers
class TestSessionSDL(VppTestCase):
    """Session SDL Test Case"""

    @classmethod
    def setUpClass(cls):
        # increase vapi timeout, to avoid
        # failures reported on test-cov
        if config.gcov:
            cls.vapi_response_timeout = 20
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

    @tag_fixme_asan
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
        filter = self.vapi.session_sdl_v3_dump()
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


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
