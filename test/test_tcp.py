#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable

class TestTCP(VppTestCase):
    """ TCP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestTCP, cls).setUpClass()

    def setUp(self):
        super(TestTCP, self).setUp()
        self.vapi.session_enable_disable(is_enabled=1)
        self.create_loopback_interfaces(range(2))

        table_id = 0
        self.tables = []

        for i in self.lo_interfaces:
            i.admin_up()

            if table_id != 0:
                tbl = VppIpTable(self, table_id)
                tbl.add_vpp_config()
                self.tables.append(tbl)

            i.set_table_ip4(table_id)
            i.config_ip4()
            table_id += 1

        # Configure namespaces
        self.vapi.cli("app ns add id 0 secret 0 sw_if_index "
                      + str(self.loop0.sw_if_index))
        self.vapi.cli("app ns add id 1 secret 0 sw_if_index "
                      + str(self.loop1.sw_if_index))


    def tearDown(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
        self.vapi.session_enable_disable(is_enabled=0)
        super(TestTCP, self).tearDown()

    def test_tcp_unittest(self):
        """ TCP Unit Tests """
        error = self.vapi.cli("test tcp all")

        if error:
            self.logger.critical(error)
        self.assertEqual(error.find("Failed"), -1)

    def test_tcp_transfer(self):
        """ TCP builtin client/server transfer """

        # Add inter-table routes
        self.vapi.cli("ip route add " + self.loop1.local_ip4
                     + "/32 table 0 via lookup in table 1")
        self.vapi.cli("ip route add " + self.loop0.local_ip4
                     + "/32 table 1 via lookup in table 0")

        # Start builtin server and client
        uri = "tcp://" + self.loop0.local_ip4 + "/1234"
        error = self.vapi.cli("test tcp server appns 0 fifo-size 4 uri " + uri)
        if error:
            self.logger.critical(error)

        error = self.vapi.cli("test tcp client mbytes 10 appns 1 fifo-size 4"
                              + " uri " + uri + " no-output test-bytes")
        if error:
            self.logger.critical(error)

        # Delete inter-table routes
        self.vapi.cli("ip route del " + self.loop1.local_ip4
                     + "/32 table 0 via lookup in table 1")
        self.vapi.cli("ip route del " + self.loop0.local_ip4
                     + "/32 table 1 via lookup in table 0")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)