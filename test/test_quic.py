#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestQUIC(VppTestCase):
    """ QUIC Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestQUIC, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestQUIC, cls).tearDownClass()

    def setUp(self):
        super(TestQUIC, self).setUp()
        self.vapi.session_enable_disable(is_enabled=1)
        self.create_loopback_interfaces(2)

        table_id = 1

        for i in self.lo_interfaces:
            i.admin_up()

            if table_id != 0:
                tbl = VppIpTable(self, table_id)
                tbl.add_vpp_config()

            i.set_table_ip4(table_id)
            i.config_ip4()
            table_id += 1

        # Configure namespaces
        self.vapi.app_namespace_add_del(namespace_id=b"1",
                                        sw_if_index=self.loop0.sw_if_index)
        self.vapi.app_namespace_add_del(namespace_id=b"2",
                                        sw_if_index=self.loop1.sw_if_index)

    def tearDown(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
        self.vapi.session_enable_disable(is_enabled=0)
        super(TestQUIC, self).tearDown()

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_transfer(self):
        """ QUIC echo client/server transfer """

        # Add inter-table routes
        ip_t01 = VppIpRoute(self, self.loop1.local_ip4, 32,
                            [VppRoutePath("0.0.0.0",
                                          0xffffffff,
                                          nh_table_id=2)], table_id=1)
        ip_t10 = VppIpRoute(self, self.loop0.local_ip4, 32,
                            [VppRoutePath("0.0.0.0",
                                          0xffffffff,
                                          nh_table_id=1)], table_id=2)
        ip_t01.add_vpp_config()
        ip_t10.add_vpp_config()
        self.logger.debug(self.vapi.cli("show ip fib"))

        # Start builtin server and client
        uri = "quic://%s/1234" % self.loop0.local_ip4
        error = self.vapi.cli("test echo server appns 1 fifo-size 4 uri %s" %
                              uri)
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)
        error = self.vapi.cli("test echo client bytes 1024 appns 2 " +
                              "fifo-size 4 test-bytes no-output " +
                              "uri %s" % uri)
        self.logger.critical(error)
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        # Delete inter-table routes
        ip_t01.remove_vpp_config()
        ip_t10.remove_vpp_config()

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
