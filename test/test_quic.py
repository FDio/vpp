#!/usr/bin/env python

import unittest
import os
from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class QUICTestCase(VppTestCase):
    """ QUIC Test Case """

    @classmethod
    def setUpClass(cls):
        super(QUICTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(QUICTestCase, cls).tearDownClass()

    def setUp(self):
        var = "VPP_BUILD_DIR"
        self.build_dir = os.getenv(var, None)
        if self.build_dir is None:
            raise Exception("Environment variable `%s' not set" % var)
        self.vppDebug = 'vpp_debug' in self.build_dir
        self.timeout = 20
        self.pre_test_sleep = 0.3
        self.post_test_sleep = 0.3
        self.vapi.session_enable_disable(is_enabled=1)

    def tearDown(self):
        self.vapi.session_enable_disable(is_enabled=0)

    def thru_host_stack_ipv4_setup(self):
        super(QUICTestCase, self).setUp()

        self.create_loopback_interfaces(2)
        self.uri = "quic://%s/1234" % self.loop0.local_ip4
        common_args = ["uri", self.uri, "fifo-size", "4"]
        self.server_echo_test_args = common_args + ["appns", "server"]
        self.client_echo_test_args = common_args + ["appns", "client",
                                                    "bytes", "1024",
                                                    "test-bytes",
                                                    "no-output"]
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
        self.vapi.app_namespace_add_del(namespace_id=b"server",
                                        sw_if_index=self.loop0.sw_if_index)
        self.vapi.app_namespace_add_del(namespace_id=b"client",
                                        sw_if_index=self.loop1.sw_if_index)

        # Add inter-table routes
        self.ip_t01 = VppIpRoute(self, self.loop1.local_ip4, 32,
                                 [VppRoutePath("0.0.0.0",
                                               0xffffffff,
                                               nh_table_id=2)], table_id=1)
        self.ip_t10 = VppIpRoute(self, self.loop0.local_ip4, 32,
                                 [VppRoutePath("0.0.0.0",
                                               0xffffffff,
                                               nh_table_id=1)], table_id=2)
        self.ip_t01.add_vpp_config()
        self.ip_t10.add_vpp_config()
        self.logger.debug(self.vapi.cli("show ip fib"))

    def thru_host_stack_ipv4_tear_down(self):
        # Delete inter-table routes
        self.ip_t01.remove_vpp_config()
        self.ip_t10.remove_vpp_config()

        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
        self.vapi.session_enable_disable(is_enabled=0)
        super(QUICTestCase, self).tearDown()

    def start_internal_echo_server(self, args):
        error = self.vapi.cli("test echo server %s" % ' '.join(args))
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

    def start_internal_echo_client(self, args):
        error = self.vapi.cli("test echo client %s" % ' '.join(args))
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

    def internal_ipv4_transfer_test(self, server_args, client_args):
        self.start_internal_echo_server(server_args)
        self.sleep(self.pre_test_sleep)
        self.start_internal_echo_client(client_args)
        self.sleep(self.post_test_sleep)


class QUICInternalEchoIPv4TestCase(QUICTestCase):
    """ QUIC Internal Echo IPv4 Transfer Test Cases """

    @classmethod
    def setUpClass(cls):
        super(QUICInternalEchoIPv4TestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(QUICInternalEchoIPv4TestCase, cls).tearDownClass()

    def setUp(self):
        super(QUICInternalEchoIPv4TestCase, self).setUp()
        self.thru_host_stack_ipv4_setup()

    def tearDown(self):
        self.thru_host_stack_ipv4_tear_down()
        super(QUICInternalEchoIPv4TestCase, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_internal_transfer(self):
        """ QUIC internal echo client/server transfer """

        self.internal_ipv4_transfer_test(self.server_echo_test_args,
                                         self.client_echo_test_args)


class QUICInternalEchoIPv4MultiStreamTestCase(QUICTestCase):
    """ QUIC Internal Echo IPv4 Transfer Test Cases """

    @classmethod
    def setUpClass(cls):
        super(QUICInternalEchoIPv4MultiStreamTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(QUICInternalEchoIPv4MultiStreamTestCase, cls).tearDownClass()

    def setUp(self):
        super(QUICInternalEchoIPv4MultiStreamTestCase, self).setUp()
        self.thru_host_stack_ipv4_setup()

    def tearDown(self):
        self.thru_host_stack_ipv4_tear_down()
        super(QUICInternalEchoIPv4MultiStreamTestCase, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_internal_multistream_transfer(self):
        """ QUIC internal echo client/server multi-stream transfer """

        self.internal_ipv4_transfer_test(self.server_echo_test_args,
                                         self.client_echo_test_args +
                                         ["quic-streams", "10"])


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
