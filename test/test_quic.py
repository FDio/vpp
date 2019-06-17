#!/usr/bin/env python
""" Vpp QUIC tests """

import unittest
import os
import subprocess
import signal
from framework import VppTestCase, VppTestRunner, running_extended_tests, \
    Worker
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class QUICAppWorker(Worker):
    """ QUIC Test Application Worker """

    def __init__(self, build_dir, appname, args, logger, env={}):
        app = "%s/vpp/bin/%s" % (build_dir, appname)
        self.args = [app] + args
        super(QUICAppWorker, self).__init__(self.args, logger, env)


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
        common_args = ["uri", self.uri, "fifo-size", "64"]
        self.server_echo_test_args = common_args + ["appns", "server"]
        self.client_echo_test_args = common_args + ["appns", "client",
                                                    "test-bytes"]
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
        self.start_internal_echo_client(client_args)

    def start_external_echo_server(self, args):
        self.worker_server = QUICAppWorker(self.build_dir, "quic_echo",
                                           args, self.logger)
        self.worker_server.start()

    def start_external_echo_client(self, args):
        self.client_echo_test_args += "use-svm-api"
        self.worker_client = QUICAppWorker(self.build_dir, "quic_echo",
                                           args, self.logger)
        self.worker_client.start()
        self.worker_client.join(self.timeout)
        try:
            self.validateExternalTestResults()
        except Exception as error:
            self.fail("Failed with %s" % error)

    def external_ipv4_transfer_test(self, server_args, client_args):
        self.start_external_echo_server(server_args)
        self.sleep(self.pre_test_sleep)
        self.start_external_echo_client(client_args)
        self.sleep(self.post_test_sleep)

    def validateExternalTestResults(self):
        if os.path.isdir('/proc/{}'.format(self.worker_server.process.pid)):
            self.logger.info("Killing server worker process (pid %d)" %
                             self.worker_server.process.pid)
            os.killpg(os.getpgid(self.worker_server.process.pid),
                      signal.SIGTERM)
            self.worker_server.join()
        self.logger.info("Client worker result is `%s'" %
                         self.worker_client.result)
        error = False
        if self.worker_client.result is None:
            try:
                error = True
                self.logger.error(
                    "Timeout: %ss! Killing client worker process (pid %d)" %
                    (self.timeout, self.worker_client.process.pid))
                os.killpg(os.getpgid(self.worker_client.process.pid),
                          signal.SIGKILL)
                self.worker_client.join()
            except OSError:
                self.logger.debug(
                    "Couldn't kill client worker process")
                raise
        if error:
            raise Exception(
                "Timeout! Client worker did not finish in %ss" % self.timeout)
        self.assert_equal(self.worker_client.result, 0,
                          "Binary test return code")


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
        super(QUICInternalEchoIPv4TestCase, self).tearDown()
        self.thru_host_stack_ipv4_tear_down()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_internal_transfer(self):
        """ QUIC internal echo client/server transfer """

        self.internal_ipv4_transfer_test(self.server_echo_test_args,
                                         self.client_echo_test_args +
                                         ["no-output", "mbytes", "10"])


class QUICInternalSerialEchoIPv4TestCase(QUICTestCase):
    """ QUIC Internal Serial Echo IPv4 Transfer Test Cases """

    @classmethod
    def setUpClass(cls):
        super(QUICInternalSerialEchoIPv4TestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(QUICInternalSerialEchoIPv4TestCase, cls).tearDownClass()

    def setUp(self):
        super(QUICInternalSerialEchoIPv4TestCase, self).setUp()
        self.thru_host_stack_ipv4_setup()

    def tearDown(self):
        super(QUICInternalSerialEchoIPv4TestCase, self).tearDown()
        self.thru_host_stack_ipv4_tear_down()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_serial_internal_transfer(self):
        """ QUIC serial internal echo client/server transfer """

        client_args = (self.client_echo_test_args +
                       ["no-output", "mbytes", "10"])
        self.internal_ipv4_transfer_test(self.server_echo_test_args,
                                         client_args)
        self.start_internal_echo_client(client_args)
        self.start_internal_echo_client(client_args)
        self.start_internal_echo_client(client_args)
        self.start_internal_echo_client(client_args)


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
        super(QUICInternalEchoIPv4MultiStreamTestCase, self).tearDown()
        self.thru_host_stack_ipv4_tear_down()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_internal_multistream_transfer(self):
        """ QUIC internal echo client/server multi-stream transfer """

        self.internal_ipv4_transfer_test(self.server_echo_test_args,
                                         self.client_echo_test_args +
                                         ["quic-streams", "10",
                                          "mbytes", "1",
                                          "no-output"])


class QUICExternalEchoIPv4TestCase(QUICTestCase):
    """ QUIC External Echo IPv4 Transfer Test Cases """

    @classmethod
    def setUpConstants(cls):
        super(QUICExternalEchoIPv4TestCase, cls).setUpConstants()
        cls.vpp_cmdline.extend(["session", "{", "evt_qs_memfd_seg", "}"])

    @classmethod
    def setUpClass(cls):
        super(QUICExternalEchoIPv4TestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(QUICExternalEchoIPv4TestCase, cls).tearDownClass()

    def setUp(self):
        super(QUICExternalEchoIPv4TestCase, self).setUp()
        self.thru_host_stack_ipv4_setup()

    def tearDown(self):
        super(QUICExternalEchoIPv4TestCase, self).tearDown()
        self.thru_host_stack_ipv4_tear_down()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_external_transfer(self):
        """ QUIC external echo client/server transfer """

        self.external_ipv4_transfer_test(self.server_echo_test_args +
                                         ["socket-name", self.api_sock,
                                          "server"],
                                         self.client_echo_test_args +
                                         ["socket-name", self.api_sock,
                                          "client", "mbytes", "10"])


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
