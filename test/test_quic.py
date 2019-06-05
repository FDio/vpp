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
        super(QUICTestCase, self).setUp()
        var = "VPP_BUILD_DIR"
        self.build_dir = os.getenv(var, None)
        if self.build_dir is None:
            raise Exception("Environment variable `%s' not set" % var)
        self.vppDebug = 'vpp_debug' in self.build_dir
        self.timeout = 20
        self.pre_test_sleep = 0.3
        self.post_test_sleep = 0.3
        self.vapi.session_enable_disable(is_enabled=1)

        self.create_loopback_interfaces(2)
        self.uri = "quic://%s/1234" % self.loop0.local_ip4
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

    def tearDown(self):
        # super(QUICTestCase, self).tearDown()
        self.vapi.session_enable_disable(is_enabled=0)
        # Delete inter-table routes
        self.ip_t01.remove_vpp_config()
        self.ip_t10.remove_vpp_config()

        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()

    # def show_commands_at_teardown(self):
    #     self.logger.debug(self.vapi.cli("show session verbose 2"))


class QUICEchoInternalTestCase(QUICTestCase):
    """QUIC Echo Internal Test Case"""
    def setUp(self):
        super(QUICEchoInternalTestCase, self).setUp()
        self.client_args = "uri %s fifo-size 64 test-bytes appns client" % self.uri
        self.server_args = "uri %s fifo-size 64 appns server" % self.uri

    def server(self, *args):
        error = self.vapi.cli("test echo server %s %s" % (self.server_args, ' '.join(args)))
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

    def client(self, *args):
        error = self.vapi.cli("test echo client %s %s" % (self.client_args, ' '.join(args)))
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

class QUICEchoInternalTransferTestCase(QUICEchoInternalTestCase):
    """QUIC Echo Internal Transfer Test Case"""
    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_internal_transfer(self):
        self.server()
	self.client("no-output", "mbytes", "10")

class QUICEchoInternalSerialTestCase(QUICEchoInternalTestCase):
    """QUIC Echo Internal Serial Transfer Test Case"""
    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_serial_internal_transfer(self):
        self.server()
	self.client("no-output", "mbytes", "10")
        self.client("no-output", "mbytes", "10")
        self.client("no-output", "mbytes", "10")
        self.client("no-output", "mbytes", "10")
        self.client("no-output", "mbytes", "10")

class QUICEchoInternalMStreamTestCase(QUICEchoInternalTestCase):
    """QUIC Echo Internal MultiStream Test Case"""
    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_internal_multistream_transfer(self):
        self.server()
        self.client("nclients", "10", "mbytes", "1", "no-output")


class QUICEchoExternalTestCase(QUICTestCase):
    def setUp(self):
        super(QUICEchoExternalTestCase, self).setUp()
        common_args = ["uri", self.uri, "fifo-size", "64", "test-bytes", "socket-name", self.api_sock]
        self.server_echo_test_args = common_args + ["server", "appns", "server"]
        self.client_echo_test_args = common_args + ["client", "appns", "client"]

    def server(self, *args):
    	_args = self.server_echo_test_args + list(args)
        self.worker_server = QUICAppWorker(self.build_dir, "quic_echo",
                                           _args, self.logger)
        self.worker_server.start()
        self.sleep(self.pre_test_sleep)

    def client(self, *args):
    	_args = self.client_echo_test_args + list(args)
        # self.client_echo_test_args += "use-svm-api"
        self.worker_client = QUICAppWorker(self.build_dir, "quic_echo",
                                           _args, self.logger)
        self.worker_client.start()
        self.worker_client.join(self.timeout)
        try:
            self.validate_external_test_results()
        except Exception as error:
            self.fail("Failed with %s" % error)
        self.sleep(self.post_test_sleep)


    def validate_external_test_results(self):
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


class QUICEchoExternalTransferTestCase(QUICEchoExternalTestCase):
    """QUIC Echo External Transfer Test Case"""
    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_external_transfer(self):
        self.server()
        self.client("mbytes", "10")

class QUICEchoExternalServerStreamTestCase(QUICEchoExternalTestCase):
    """QUIC Echo External Transfer Server Stream Test Case"""
    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_external_transfer_server_stream(self):
        self.server("mbytes", "1", "quic-setup", "serverstream")
	self.client("mbytes", "1", "quic-setup", "serverstream")

class QUICEchoExternalServerStreamWorkersTestCase(QUICEchoExternalTestCase):
    """QUIC Echo External Transfer Server Stream MultiWorker Test Case"""
    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_external_transfer_server_stream_multi_workers(self):
	self.server("nclients", "3", "mbytes", "1", "quic-setup", "serverstream")
        self.client("nclients", "3", "mbytes", "1", "quic-setup", "serverstream")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
