#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestSession(VppTestCase):
    """ Session Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestSession, cls).setUpClass()

    def setUp(self):
        super(TestSession, self).setUp()

        self.vapi.session_enable_disable(is_enabled=1)
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
        self.vapi.app_namespace_add(namespace_id="0",
                                    sw_if_index=self.loop0.sw_if_index)
        self.vapi.app_namespace_add(namespace_id="1",
                                    sw_if_index=self.loop1.sw_if_index)

    def tearDown(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()

        super(TestSession, self).tearDown()
        self.vapi.session_enable_disable(is_enabled=1)

    def test_segment_manager_alloc(self):
        """ Session Segment Manager Multiple Segment Allocation """

        # Add inter-table routes
        ip_t01 = VppIpRoute(self, self.loop1.local_ip4, 32,
                            [VppRoutePath("0.0.0.0",
                                          0xffffffff,
                                          nh_table_id=1)])
        ip_t10 = VppIpRoute(self, self.loop0.local_ip4, 32,
                            [VppRoutePath("0.0.0.0",
                                          0xffffffff,
                                          nh_table_id=0)], table_id=1)
        ip_t01.add_vpp_config()
        ip_t10.add_vpp_config()

        # Start builtin server and client with small private segments
        uri = "tcp://" + self.loop0.local_ip4 + "/1234"
        error = self.vapi.cli("test echo server appns 0 fifo-size 64 " +
                              "private-segment-size 1m uri " + uri)
        if error:
            self.logger.critical(error)
            self.assertEqual(error.find("failed"), -1)

        error = self.vapi.cli("test echo client nclients 100 appns 1 " +
                              "no-output fifo-size 64 syn-timeout 2 " +
                              "private-segment-size 1m uri " + uri)
        if error:
            self.logger.critical(error)
            self.assertEqual(error.find("failed"), -1)

        if self.vpp_dead:
            self.assert_equal(0)

        # Delete inter-table routes
        ip_t01.remove_vpp_config()
        ip_t10.remove_vpp_config()

class TestSessionUnitTests(VppTestCase):
    """ Session Unit Tests Case """

    def setUp(self):
        super(TestSessionUnitTests, self).setUp()
        self.vapi.session_enable_disable(is_enabled=1)

    def test_session(self):
        """ Session Unit Tests """
        error = self.vapi.cli("test session all")

        if error:
            self.logger.critical(error)
        self.assertEqual(error.find("failed"), -1)

    def tearDown(self):
        super(TestSessionUnitTests, self).tearDown()
        self.vapi.session_enable_disable(is_enabled=0)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
