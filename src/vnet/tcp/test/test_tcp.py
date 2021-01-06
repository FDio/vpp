#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestTCP(VppTestCase):
    """ TCP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestTCP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestTCP, cls).tearDownClass()

    def setUp(self):
        super(TestTCP, self).setUp()
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
        self.vapi.app_namespace_add_del(namespace_id="0",
                                        sw_if_index=self.loop0.sw_if_index)
        self.vapi.app_namespace_add_del(namespace_id="1",
                                        sw_if_index=self.loop1.sw_if_index)

    def tearDown(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
        self.vapi.session_enable_disable(is_enable=0)
        super(TestTCP, self).tearDown()

    def test_tcp_transfer(self):
        """ TCP echo client/server transfer """

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

        # Start builtin server and client
        uri = "tcp://" + self.loop0.local_ip4 + "/1234"
        error = self.vapi.cli("test echo server appns 0 fifo-size 4 uri " +
                              uri)
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        error = self.vapi.cli("test echo client mbytes 10 appns 1 " +
                              "fifo-size 4 no-output test-bytes " +
                              "syn-timeout 2 uri " + uri)
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        # Delete inter-table routes
        ip_t01.remove_vpp_config()
        ip_t10.remove_vpp_config()


class TestTCPUnitTests(VppTestCase):
    "TCP Unit Tests"

    @classmethod
    def setUpClass(cls):
        super(TestTCPUnitTests, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestTCPUnitTests, cls).tearDownClass()

    def setUp(self):
        super(TestTCPUnitTests, self).setUp()
        self.vapi.session_enable_disable(is_enable=1)

    def tearDown(self):
        super(TestTCPUnitTests, self).tearDown()
        self.vapi.session_enable_disable(is_enable=0)

    def test_tcp_unittest(self):
        """ TCP Unit Tests """
        error = self.vapi.cli("test tcp all")

        if error:
            self.logger.critical(error)
        self.assertNotIn("failed", error)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
