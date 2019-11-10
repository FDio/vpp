#!/usr/bin/env python3
""" Vpp QUIC tests """

import os
import signal
import subprocess
import unittest

from framework import (
    VppTestCase,
    VppTestRunner,
    Worker,
    running_extended_tests,
)
from vpp_ip_route import (
    VppIpRoute,
    VppIpTable,
    VppRoutePath,
)


class QUICAppWorker(Worker):
    """ QUIC Test Application Worker """
    process = None

    def __init__(self, build_dir, appname, args, logger, role, testcase,
                 env={}):
        app = "%s/vpp/bin/%s" % (build_dir, appname)
        self.args = [app] + args
        self.role = role
        self.wait_for_gdb = 'wait-for-gdb'
        self.testcase = testcase
        super(QUICAppWorker, self).__init__(self.args, logger, env)

    def run(self):
        super(QUICAppWorker, self).run()

    def teardown(self, logger, timeout):
        if self.process is None:
            return False
        try:
            logger.debug("Killing worker process (pid %d)" % self.process.pid)
            os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
            self.join(timeout)
        except OSError as e:
            logger.debug("Couldn't kill worker process")
            return True
        return False


class QUICTestCase(VppTestCase):
    """ QUIC Test Case """
    @classmethod
    def setUpClass(cls):
        cls.extra_vpp_plugin_config.append("plugin quic_plugin.so { enable }")
        super(QUICTestCase, cls).setUpClass()

    def setUp(self):
        super(QUICTestCase, self).setUp()
        var = "VPP_BUILD_DIR"
        self.build_dir = os.getenv(var, None)
        if self.build_dir is None:
            raise Exception("Environment variable `%s' not set" % var)
        self.vppDebug = 'vpp_debug' in self.build_dir
        self.timeout = 20
        self.vapi.session_enable_disable(is_enabled=1)
        self.pre_test_sleep = 0.3
        self.post_test_sleep = 0.2

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
        self.vapi.session_enable_disable(is_enabled=0)
        # Delete inter-table routes
        self.ip_t01.remove_vpp_config()
        self.ip_t10.remove_vpp_config()

        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
        super(QUICTestCase, self).tearDown()


class QUICEchoIntTestCase(QUICTestCase):
    """QUIC Echo Internal Test Case"""
    test_bytes = ' test-bytes'

    def setUp(self):
        super(QUICEchoIntTestCase, self).setUp()
        self.client_args = 'uri {uri} fifo-size 64{testbytes} appns client' \
            .format(uri=self.uri, testbytes=self.test_bytes)
        self.server_args = "uri %s fifo-size 64 appns server" % self.uri

    def server(self, *args):
        error = self.vapi.cli(
            "test echo server %s %s" %
            (self.server_args, ' '.join(args)))
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

    def client(self, *args):
        error = self.vapi.cli(
            "test echo client %s %s" %
            (self.client_args, ' '.join(args)))
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)


class QUICEchoIntTransferTestCase(QUICEchoIntTestCase):
    """QUIC Echo Internal Transfer Test Case"""
    def test_quic_int_transfer(self):
        self.server()
        self.client("no-output", "mbytes", "2")


class QUICEchoIntTransferBigTestCase(QUICEchoIntTestCase):
    """QUIC Echo Internal Transfer Big Test Case"""
    test_bytes = ''

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_int_transfer_big(self):
        self.server()
        self.client("no-output", "gbytes", "10")


class QUICEchoIntSerialTestCase(QUICEchoIntTestCase):
    """QUIC Echo Internal Serial Transfer Test Case"""
    def test_quic_serial_int_transfer(self):
        self.server()
        self.client("no-output", "mbytes", "2")
        self.client("no-output", "mbytes", "2")
        self.client("no-output", "mbytes", "2")
        self.client("no-output", "mbytes", "2")
        self.client("no-output", "mbytes", "2")


class QUICEchoIntSerialBigTestCase(QUICEchoIntTestCase):
    """QUIC Echo Internal Serial Transfer Big Test Case"""

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_serial_int_transfer_big(self):
        self.server()
        self.client("no-output", "gbytes", "5")
        self.client("no-output", "gbytes", "5")
        self.client("no-output", "gbytes", "5")
        self.client("no-output", "gbytes", "5")
        self.client("no-output", "gbytes", "5")


class QUICEchoIntMStreamTestCase(QUICEchoIntTestCase):
    """QUIC Echo Internal MultiStream Test Case"""
    def test_quic_int_multistream_transfer(self):
        self.server()
        self.client("nclients", "10", "mbytes", "1", "no-output")


class QUICEchoIntMStreamBigTestCase(QUICEchoIntTestCase):
    """QUIC Echo Internal MultiStream Big Test Case"""

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_int_multistream_transfer(self):
        self.server()
        self.client("nclients", "10", "gbytes", "5", "no-output")


class QUICEchoExtTestCase(QUICTestCase):
    extra_vpp_punt_config = ["session", "{", "evt_qs_memfd_seg", "}"]
    quic_setup = "default"
    test_bytes = "test-bytes:assert"
    app = "vpp_echo"

    def setUp(self):
        super(QUICEchoExtTestCase, self).setUp()
        common_args = [
            "uri",
            self.uri,
            "json",
            self.test_bytes,
            "socket-name", self.api_sock,
            "quic-setup", self.quic_setup]
        self.server_echo_test_args = common_args + \
            ["server", "appns", "server"]  # use default fifo-size
        self.client_echo_test_args = common_args + \
            ["client", "appns", "client", "fifo-size", "4M"]
        error = self.vapi.cli("quic set fifo-size 2M")
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

    def server(self, *args):
        _args = self.server_echo_test_args + list(args)
        self.worker_server = QUICAppWorker(
            self.build_dir,
            self.app,
            _args,
            self.logger,
            'server',
            self)
        self.worker_server.start()
        self.sleep(self.pre_test_sleep)

    def client(self, *args):
        _args = self.client_echo_test_args + list(args)
        self.worker_client = QUICAppWorker(
            self.build_dir,
            self.app,
            _args,
            self.logger,
            'client',
            self)
        self.worker_client.start()
        timeout = None if self.debug_all else self.timeout
        self.worker_client.join(timeout)
        self.worker_server.join(timeout)
        self.sleep(self.post_test_sleep)

    def validate_ext_test_results(self):
        server_result = self.worker_server.result
        client_result = self.worker_client.result
        self.logger.info("Server worker result is `%s'" %
                         server_result)
        self.logger.info("Client worker result is `%s'" %
                         client_result)
        server_kill_error = False
        if self.worker_server.result is None:
            server_kill_error = self.worker_server.teardown(
                self.logger, self.timeout)
        if self.worker_client.result is None:
            self.worker_client.teardown(self.logger, self.timeout)
        err_msg = "Wrong server worker return code (%s)" % server_result
        self.assertEqual(server_result, 0, err_msg)
        self.assertIsNotNone(
            client_result,
            "Timeout! Client worker did not finish in %ss" %
            self.timeout)
        err_msg = "Wrong client worker return code (%s)" % client_result
        self.assertEqual(client_result, 0, err_msg)
        self.assertFalse(server_kill_error, "Server kill errored")


class QUICEchoExtTransferTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Test Case"""
    def test_quic_ext_transfer(self):
        self.server()
        self.client()
        self.validate_ext_test_results()


class QUICEchoExtTransferBigTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Big Test Case"""
    test_bytes = ''

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_transfer_big(self):
        self.server("TX=0", "RX=10Gb")
        self.client("TX=10Gb", "RX=0")
        self.validate_ext_test_results()


class QUICEchoExtQcloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Qclose Rx Test Case"""

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_qclose_rx(self):
        self.server("TX=0", "RX=10Mb", "qclose=Y", "sclose=N")
        self.client("TX=10Mb", "RX=0", "qclose=W", "sclose=W")
        self.validate_ext_test_results()


class QUICEchoExtQcloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Qclose Tx Test Case"""

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_qclose_tx(self):
        self.server("TX=0", "RX=10Mb", "qclose=W", "sclose=W",
                    "rx-results-diff")
        self.client("TX=10Mb", "RX=0", "qclose=Y", "sclose=N")
        self.validate_ext_test_results()


class QUICEchoExtEarlyQcloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Early Qclose Rx Test Case"""

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_early_qclose_rx(self):
        self.server("TX=0", "RX=10Mb", "qclose=Y", "sclose=N")
        self.client("TX=20Mb", "RX=0", "qclose=W", "sclose=W",
                    "tx-results-diff")
        self.validate_ext_test_results()


class QUICEchoExtEarlyQcloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Early Qclose Tx Test Case"""

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_early_qclose_tx(self):
        self.server("TX=0", "RX=20Mb", "qclose=W", "sclose=W",
                    "rx-results-diff")
        self.client("TX=10Mb", "RX=0", "qclose=Y", "sclose=N")
        self.validate_ext_test_results()


class QUICEchoExtScloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Sclose Rx Test Case"""

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_sclose_rx(self):
        self.server("TX=0", "RX=10Mb", "qclose=N", "sclose=Y")
        self.client("TX=10Mb", "RX=0", "qclose=W", "sclose=W")
        self.validate_ext_test_results()


class QUICEchoExtScloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Sclose Tx Test Case"""

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_sclose_tx(self):
        self.server("TX=0", "RX=10Mb", "qclose=W", "sclose=W")
        self.client("TX=10Mb", "RX=0", "qclose=Y", "sclose=Y")
        self.validate_ext_test_results()


class QUICEchoExtEarlyScloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Early Sclose Rx Test Case"""

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_early_sclose_rx(self):
        self.server("TX=0", "RX=10Mb", "qclose=N", "sclose=Y")
        self.client("TX=20Mb", "RX=0", "qclose=W", "sclose=W",
                    "tx-results-diff")
        self.validate_ext_test_results()


class QUICEchoExtEarlyScloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Early Sclose Tx Test Case"""

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_early_sclose_tx(self):
        self.server("TX=0", "RX=20Mb", "qclose=W", "sclose=W",
                    "rx-results-diff")
        self.client("TX=10Mb", "RX=0", "qclose=Y", "sclose=Y")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Test Case"""
    quic_setup = "serverstream"

    def test_quic_ext_transfer_server_stream(self):
        self.server("TX=10Mb", "RX=0")
        self.client("TX=0", "RX=10Mb")
        self.validate_ext_test_results()


class QUICEchoExtBigServerStreamTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Big Server Stream Test Case"""
    quic_setup = "serverstream"
    test_bytes = ''

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_transfer_big_server_stream(self):
        self.server("TX=10Gb", "RX=0")
        self.client("TX=0", "RX=10Gb")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamQcloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Qclose Rx Test Case"""
    quic_setup = "serverstream"

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_server_stream_qclose_rx(self):
        self.server("TX=10Mb", "RX=0", "qclose=W", "sclose=W")
        self.client("TX=0", "RX=10Mb", "qclose=Y", "sclose=N")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamQcloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Qclose Tx Test Case"""
    quic_setup = "serverstream"

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_server_stream_qclose_tx(self):
        self.server("TX=10Mb", "RX=0", "qclose=Y", "sclose=N")
        self.client("TX=0", "RX=10Mb", "qclose=W", "sclose=W",
                    "rx-results-diff")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamEarlyQcloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Early Qclose Rx Test Case"""
    quic_setup = "serverstream"

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_server_stream_early_qclose_rx(self):
        self.server("TX=20Mb", "RX=0", "qclose=W", "sclose=W",
                    "tx-results-diff")
        self.client("TX=0", "RX=10Mb", "qclose=Y", "sclose=N")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamEarlyQcloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Early Qclose Tx Test Case"""
    quic_setup = "serverstream"

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_server_stream_early_qclose_tx(self):
        self.server("TX=10Mb", "RX=0", "qclose=Y", "sclose=N")
        self.client("TX=0", "RX=20Mb", "qclose=W", "sclose=W",
                    "rx-results-diff")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamScloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Sclose Rx Test Case"""
    quic_setup = "serverstream"

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_server_stream_sclose_rx(self):
        self.server("TX=10Mb", "RX=0", "qclose=W", "sclose=W")
        self.client("TX=0", "RX=10Mb", "qclose=N", "sclose=Y")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamScloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Sclose Tx Test Case"""
    quic_setup = "serverstream"

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_server_stream_sclose_tx(self):
        self.server("TX=10Mb", "RX=0", "qclose=Y", "sclose=Y")
        self.client("TX=0", "RX=10Mb", "qclose=W", "sclose=W")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamEarlyScloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Early Sclose Rx Test Case"""
    quic_setup = "serverstream"

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_server_stream_early_sclose_rx(self):
        self.server("TX=20Mb", "RX=0", "qclose=W", "sclose=W",
                    "tx-results-diff")
        self.client("TX=0", "RX=10Mb", "qclose=N", "sclose=Y")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamEarlyScloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo Ext Transfer Server Stream Early Sclose Tx Test Case"""
    quic_setup = "serverstream"

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_server_stream_early_sclose_tx(self):
        self.server("TX=10Mb", "RX=0", "qclose=Y", "sclose=Y")
        self.client("TX=0", "RX=20Mb", "qclose=W", "sclose=W",
                    "rx-results-diff")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamWorkersTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream MultiWorker Test Case"""
    quic_setup = "serverstream"

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_quic_ext_transfer_server_stream_multi_workers(self):
        self.server("nclients", "4", "quic-streams", "4", "TX=10Mb", "RX=0")
        self.client("nclients", "4", "quic-streams", "4", "TX=0", "RX=10Mb")
        self.validate_ext_test_results()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
