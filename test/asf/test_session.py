#!/usr/bin/env python3

import unittest

from asfframework import (
    VppAsfTestCase,
    VppTestRunner,
    tag_fixme_vpp_workers,
    tag_fixme_asan,
    tag_run_solo,
)
from vpp_papi import VppEnum
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath
from ipaddress import IPv4Network
from config import config


@tag_fixme_vpp_workers
@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class TestSession(VppAsfTestCase):
    """Session Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestSession, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSession, cls).tearDownClass()

    def setUp(self):
        super(TestSession, self).setUp()

        self.vapi.session_enable_disable(is_enable=1)
        self.create_loopback_interfaces(2)

        table_id = 0

        for i in self.lo_interfaces:
            i.admin_up()

            if table_id != 0:
                tbl = VppIpTable(self, table_id)
                tbl.add_vpp_config()

            i.set_table_ip4(table_id)
            i.config_ip4()
            table_id += 1

        # Configure namespaces
        self.vapi.app_namespace_add_del_v4(
            namespace_id="0", sw_if_index=self.loop0.sw_if_index
        )
        self.vapi.app_namespace_add_del_v4(
            namespace_id="1", sw_if_index=self.loop1.sw_if_index
        )

    def tearDown(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()

        # Unconfigure namespaces - remove our locks to the vrf tables
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="0", sw_if_index=self.loop0.sw_if_index
        )
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="1", sw_if_index=self.loop1.sw_if_index
        )

        super(TestSession, self).tearDown()
        self.vapi.session_enable_disable(is_enable=0)

    def test_segment_manager_alloc(self):
        """Session Segment Manager Multiple Segment Allocation"""

        # Add inter-table routes
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

        # Start builtin server and client with small private segments
        uri = "tcp://" + self.loop0.local_ip4 + "/1234"
        error = self.vapi.cli(
            "test echo server appns 0 fifo-size 64k "
            + "private-segment-size 1m uri "
            + uri
        )
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        error = self.vapi.cli(
            "test echo client nclients 100 appns 1 "
            + "fifo-size 64k syn-timeout 2 bytes 8k "
            + "private-segment-size 1m uri "
            + uri
        )
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        if self.vpp_dead:
            self.assert_equal(0)

        # Delete inter-table routes
        ip_t01.remove_vpp_config()
        ip_t10.remove_vpp_config()


class TestApplicationNamespace(VppAsfTestCase):
    """Application Namespacee"""

    @classmethod
    def setUpClass(cls):
        super(TestApplicationNamespace, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestApplicationNamespace, cls).tearDownClass()

    def setUp(self):
        super(TestApplicationNamespace, self).setUp()
        self.create_loopback_interfaces(1)

    def tearDown(self):
        super(TestApplicationNamespace, self).tearDown()
        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
        )

    def test_application_namespace(self):
        """Application Namespace Create"""

        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_RULE_TABLE
        )

        # Configure 2 namespaces, sharing the same interface
        app0 = self.vapi.app_namespace_add_del_v4(
            namespace_id="0", sw_if_index=self.loop0.sw_if_index
        )
        app1 = self.vapi.app_namespace_add_del_v4(
            namespace_id="1", sw_if_index=self.loop0.sw_if_index
        )

        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl="172.100.1.1/32",
            rmt="172.100.1.2/32",
            lcl_port=5000,
            rmt_port=5000,
            action_index=1,
            appns_index=app0.appns_index,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            is_add=1,
        )
        dump = self.vapi.session_rules_v2_dump()
        # session table should contain 3 appns's indices (default, app0, and app1)
        self.assertEqual(len(dump[1].appns_index), 3)
        self.assertEqual(dump[1].count, 3)
        self.assertEqual(dump[1].appns_index[0], 0)
        self.assertEqual(dump[1].appns_index[1], app0.appns_index)
        self.assertEqual(dump[1].appns_index[2], app1.appns_index)

        # remove the last namespace
        self.vapi.app_namespace_add_del_v4(
            namespace_id="1", sw_if_index=self.loop0.sw_if_index, is_add=0
        )
        dump = self.vapi.session_rules_v2_dump()
        # session table should contain the remainging appns's index
        self.assertEqual(len(dump[1].appns_index), 2)
        self.assertEqual(dump[1].count, 2)
        self.assertEqual(dump[1].appns_index[0], 0)
        self.assertEqual(dump[1].appns_index[1], app0.appns_index)

        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl="172.100.1.1/32",
            rmt="172.100.1.2/32",
            lcl_port=5000,
            rmt_port=5000,
            action_index=1,
            appns_index=app0.appns_index,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            is_add=0,
        )
        self.vapi.app_namespace_add_del_v4(
            namespace_id="0", sw_if_index=self.loop0.sw_if_index, is_add=0
        )

        # test bad appns index for the API
        with self.vapi.assert_negative_api_retval():
            rv = self.vapi.session_rule_add_del(
                transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
                lcl="172.100.1.1/32",
                rmt="172.100.1.2/32",
                lcl_port=5000,
                rmt_port=5000,
                action_index=1,
                appns_index=10,
                scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
                is_add=1,
            )
        self.assertEqual(rv.retval, -1)

    def test_application_namespace_binding(self):
        """Application Namespace Interface Binding"""

        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_RULE_TABLE
        )

        table_id = 99

        # Bad ip4_fib_id
        with self.vapi.assert_negative_api_retval():
            rv = self.vapi.app_namespace_add_del_v4(
                is_add=1, namespace_id="2", ip4_fib_id=table_id, ip6_fib_id=0
            )
        self.assertEqual(rv.retval, -19)

        # Bad ip6_fib_id
        with self.vapi.assert_negative_api_retval():
            rv = self.vapi.app_namespace_add_del_v4(
                is_add=1, namespace_id="2", ip4_fib_id=0, ip6_fib_id=table_id
            )
        self.assertEqual(rv.retval, -19)

        tbl = VppIpTable(self, table_id)
        tbl.add_vpp_config()

        tbl6 = VppIpTable(self, table_id, is_ip6=1)
        tbl6.add_vpp_config()

        # Not expecting an error with valid table_id's
        self.vapi.app_namespace_add_del_v4(
            is_add=1, namespace_id="2", ip4_fib_id=table_id, ip6_fib_id=table_id
        )
        # delete
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="2", ip4_fib_id=table_id, ip6_fib_id=table_id
        )

        # ip4 only
        self.vapi.app_namespace_add_del_v4(
            is_add=1, namespace_id="2", ip4_fib_id=table_id, ip6_fib_id=0xFFFFFFFF
        )
        # delete
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="2", ip4_fib_id=table_id, ip6_fib_id=0xFFFFFFFF
        )

        # ip6 only
        self.vapi.app_namespace_add_del_v4(
            is_add=1, namespace_id="2", ip4_fib_id=0xFFFFFFFF, ip6_fib_id=table_id
        )
        # delete
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="2", ip4_fib_id=0xFFFFFFFF, ip6_fib_id=table_id
        )

        app0 = self.vapi.app_namespace_add_del_v4(
            namespace_id="0", sw_if_index=self.loop0.sw_if_index, is_add=1
        )
        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl="172.100.1.1/32",
            rmt="172.100.1.2/32",
            lcl_port=5000,
            rmt_port=5000,
            action_index=1,
            appns_index=app0.appns_index,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            is_add=1,
        )
        dump = self.vapi.session_rules_v2_dump()
        self.assertEqual(len(dump[1].appns_index), 2)
        self.assertEqual(dump[1].count, 2)

        # move the interface to vrf 99
        self.vapi.sw_interface_set_table(
            sw_if_index=self.loop0.sw_if_index,
            is_ipv6=0,
            vrf_id=table_id,
        )
        dump = self.vapi.session_rules_v2_dump()
        self.assertEqual(len(dump[1].appns_index), 1)
        self.assertEqual(dump[1].count, 1)

        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl="172.100.1.1/32",
            rmt="172.100.1.2/32",
            lcl_port=5000,
            rmt_port=5000,
            action_index=1,
            appns_index=0,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            is_add=0,
        )

        # move the interface to vrf 0
        self.vapi.sw_interface_set_table(
            sw_if_index=self.loop0.sw_if_index,
            is_ipv6=0,
            vrf_id=0,
        )

        # try it with ip6
        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl="2001::1/128",
            rmt="2002::1/128",
            lcl_port=5000,
            rmt_port=5000,
            action_index=1,
            appns_index=app0.appns_index,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            is_add=1,
        )
        dump = self.vapi.session_rules_v2_dump()
        self.assertEqual(len(dump[1].appns_index), 2)
        self.assertEqual(dump[1].count, 2)

        self.vapi.sw_interface_set_table(
            sw_if_index=self.loop0.sw_if_index,
            is_ipv6=1,
            vrf_id=table_id,
        )
        dump = self.vapi.session_rules_v2_dump()
        self.assertEqual(len(dump[1].appns_index), 2)
        self.assertEqual(dump[1].count, 2)

        # move back to 0
        self.vapi.sw_interface_set_table(
            sw_if_index=self.loop0.sw_if_index,
            is_ipv6=1,
            vrf_id=0,
        )

        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl="2001::1/128",
            rmt="2002::1/128",
            lcl_port=5000,
            rmt_port=5000,
            action_index=1,
            appns_index=0,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            is_add=0,
        )

        self.vapi.app_namespace_add_del_v4(
            namespace_id="0", sw_if_index=self.loop0.sw_if_index, is_add=0
        )

        tbl.remove_vpp_config()
        tbl6.remove_vpp_config()


@tag_fixme_vpp_workers
@tag_fixme_asan
class TestSessionUnitTests(VppAsfTestCase):
    """Session Unit Tests Case"""

    @classmethod
    def setUpClass(cls):
        super(TestSessionUnitTests, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSessionUnitTests, cls).tearDownClass()

    def setUp(self):
        super(TestSessionUnitTests, self).setUp()
        self.vapi.session_enable_disable(is_enable=1)

    def test_session(self):
        """Session Unit Tests"""
        error = self.vapi.cli("test session all")

        if error:
            self.logger.critical(error)
        self.assertNotIn("failed", error)

    def tearDown(self):
        super(TestSessionUnitTests, self).tearDown()
        self.vapi.session_enable_disable(is_enable=0)


@tag_fixme_vpp_workers
class TestSessionRuleTableTests(VppAsfTestCase):
    """Session Rule Table Tests Case"""

    @classmethod
    def setUpClass(cls):
        super(TestSessionRuleTableTests, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSessionRuleTableTests, cls).tearDownClass()

    def setUp(self):
        super(TestSessionRuleTableTests, self).setUp()
        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_RULE_TABLE
        )

    def test_session_rule_table(self):
        """Session Rule Table Tests"""

        LCL_IP = "172.100.1.1/32"
        RMT_IP = "172.100.1.2/32"
        LCL_PORT = 5000
        RMT_PORT = 80

        # Add a rule table entry
        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl=LCL_IP,
            rmt=RMT_IP,
            lcl_port=LCL_PORT,
            rmt_port=RMT_PORT,
            action_index=1,
            is_add=1,
            appns_index=0,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            tag="rule-1",
        )

        # Verify it is correctly injected
        dump = self.vapi.session_rules_dump()
        self.assertTrue(len(dump) > 1)
        self.assertEqual(dump[1].rmt_port, RMT_PORT)
        self.assertEqual(dump[1].lcl_port, LCL_PORT)
        self.assertEqual(dump[1].lcl, IPv4Network(LCL_IP))
        self.assertEqual(dump[1].rmt, IPv4Network(RMT_IP))
        self.assertEqual(dump[1].action_index, 1)
        self.assertEqual(dump[1].appns_index, 0)
        self.assertEqual(
            dump[1].scope,
            VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
        )

        # Delete the entry
        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl=LCL_IP,
            rmt=RMT_IP,
            lcl_port=LCL_PORT,
            rmt_port=RMT_PORT,
            action_index=1,
            is_add=0,
            appns_index=0,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            tag="rule-1",
        )
        dump2 = self.vapi.session_rules_dump()

        # Verify it is removed
        self.assertTrue((len(dump) - 1) == len(dump2))

    def tearDown(self):
        super(TestSessionRuleTableTests, self).tearDown()
        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
        )


@tag_run_solo
class TestSegmentManagerTests(VppAsfTestCase):
    """SVM Fifo Unit Tests Case"""

    @classmethod
    def setUpClass(cls):
        super(TestSegmentManagerTests, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSegmentManagerTests, cls).tearDownClass()

    def setUp(self):
        super(TestSegmentManagerTests, self).setUp()

    def test_segment_manager(self):
        """Segment manager Tests"""
        error = self.vapi.cli("test segment-manager all")

        if error:
            self.logger.critical(error)
        self.assertNotIn("failed", error)

    def tearDown(self):
        super(TestSegmentManagerTests, self).tearDown()


@tag_run_solo
class TestSvmFifoUnitTests(VppAsfTestCase):
    """SVM Fifo Unit Tests Case"""

    @classmethod
    def setUpClass(cls):
        super(TestSvmFifoUnitTests, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSvmFifoUnitTests, cls).tearDownClass()

    def setUp(self):
        super(TestSvmFifoUnitTests, self).setUp()

    def test_svm_fifo(self):
        """SVM Fifo Unit Tests"""
        error = self.vapi.cli("test svm fifo all")

        if error:
            self.logger.critical(error)
        self.assertNotIn("failed", error)

    def tearDown(self):
        super(TestSvmFifoUnitTests, self).tearDown()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
