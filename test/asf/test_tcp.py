#!/usr/bin/env python3

import unittest

from asfframework import VppAsfTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath
from config import config


@unittest.skipIf(
    "vperf" in config.excluded_plugins, "Exclude tests requiring vperf plugin"
)
class TestTCP(VppAsfTestCase):
    """TCP Test Case"""

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
        self.vapi.app_namespace_add_del_v4(
            namespace_id="0", sw_if_index=self.loop0.sw_if_index
        )
        self.vapi.app_namespace_add_del_v4(
            namespace_id="1", sw_if_index=self.loop1.sw_if_index
        )

    def tearDown(self):
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="0", sw_if_index=self.loop0.sw_if_index
        )
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="1", sw_if_index=self.loop1.sw_if_index
        )
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
        self.vapi.session_enable_disable(is_enable=0)
        super(TestTCP, self).tearDown()

    def test_tcp_transfer(self):
        """TCP echo client/server transfer"""

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

        # Start builtin server and client
        uri = "tcp://" + self.loop0.local_ip4 + "/1234"
        error = self.vapi.cli("vperf server appns 0 fifo-size 4k uri " + uri)
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        error = self.vapi.cli(
            "vperf client bytes 10m appns 1 "
            + "fifo-size 4k test-bytes "
            + "syn-timeout 2 uri "
            + uri
        )
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        # Delete inter-table routes
        ip_t01.remove_vpp_config()
        ip_t10.remove_vpp_config()


@unittest.skipIf(
    "vperf" in config.excluded_plugins, "Exclude tests requiring vperf plugin"
)
class TestTCPFastOpen(VppAsfTestCase):
    """TCP Fast Open Test Cases (RFC 7413)"""

    @classmethod
    def setUpClass(cls):
        super(TestTCPFastOpen, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestTCPFastOpen, cls).tearDownClass()

    def setUp(self):
        super(TestTCPFastOpen, self).setUp()
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

        self.vapi.app_namespace_add_del_v4(
            namespace_id="0", sw_if_index=self.loop0.sw_if_index
        )
        self.vapi.app_namespace_add_del_v4(
            namespace_id="1", sw_if_index=self.loop1.sw_if_index
        )

        # Add inter-table routes
        self.ip_t01 = VppIpRoute(
            self,
            self.loop1.local_ip4,
            32,
            [VppRoutePath("0.0.0.0", 0xFFFFFFFF, nh_table_id=1)],
        )
        self.ip_t10 = VppIpRoute(
            self,
            self.loop0.local_ip4,
            32,
            [VppRoutePath("0.0.0.0", 0xFFFFFFFF, nh_table_id=0)],
            table_id=1,
        )
        self.ip_t01.add_vpp_config()
        self.ip_t10.add_vpp_config()

    def tearDown(self):
        self.ip_t01.remove_vpp_config()
        self.ip_t10.remove_vpp_config()
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="0", sw_if_index=self.loop0.sw_if_index
        )
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="1", sw_if_index=self.loop1.sw_if_index
        )
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
            self.vapi.delete_loopback(sw_if_index=i.sw_if_index)
        # Disable TFO after each test
        self.vapi.cli("tcp fast-open off")
        self.vapi.session_enable_disable(is_enable=0)
        super(TestTCPFastOpen, self).tearDown()

    def test_tfo_cookie_exchange(self):
        """TFO cookie request and response (RFC 7413 Sec 3)

        Client connects with empty TFO option (cookie request).
        Server responds with SYN-ACK containing a TFO cookie.
        Subsequent connection uses the cookie to fast-open.
        """
        # Enable TFO globally
        self.vapi.cli("tcp fast-open on")

        uri = "tcp://" + self.loop0.local_ip4 + "/1235"
        error = self.vapi.cli("vperf server appns 0 fifo-size 4k uri " + uri)
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        # First connection: cookie request exchange
        error = self.vapi.cli(
            "vperf client bytes 1m appns 1 "
            + "fifo-size 4k test-bytes "
            + "syn-timeout 2 uri "
            + uri
        )
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

    def test_tfo_fast_open(self):
        """TFO fast-open transfer with cookie (RFC 7413 Sec 4)

        After a cookie exchange, subsequent connections use the cookie
        to deliver data with the SYN, reducing connection latency.
        """
        # Enable TFO globally
        self.vapi.cli("tcp fast-open on")

        uri = "tcp://" + self.loop0.local_ip4 + "/1236"
        error = self.vapi.cli("vperf server appns 0 fifo-size 4k uri " + uri)
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        # Run two back-to-back transfers: first gets cookie, second uses it
        for _ in range(2):
            error = self.vapi.cli(
                "vperf client bytes 2m appns 1 "
                + "fifo-size 4k test-bytes "
                + "syn-timeout 2 uri "
                + uri
            )
            if error:
                self.logger.critical(error)
                self.assertNotIn("failed", error)

    def test_tfo_disabled_fallback(self):
        """TFO disabled: regular TCP handshake proceeds normally"""
        # Ensure TFO is off (default)
        self.vapi.cli("tcp fast-open off")

        uri = "tcp://" + self.loop0.local_ip4 + "/1237"
        error = self.vapi.cli("vperf server appns 0 fifo-size 4k uri " + uri)
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        error = self.vapi.cli(
            "vperf client bytes 1m appns 1 "
            + "fifo-size 4k test-bytes "
            + "syn-timeout 2 uri "
            + uri
        )
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)


class TestTCPUnitTests(VppAsfTestCase):
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
        """TCP Unit Tests"""
        error = self.vapi.cli("test tcp all")

        if error:
            self.logger.critical(error)
        self.assertNotIn("failed", error)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
