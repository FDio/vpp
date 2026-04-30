#!/usr/bin/env python3
"""Vpp QUIC tests"""

import unittest
import os
import signal
from config import config
from asfframework import VppAsfTestCase, VppTestRunner, Worker, tag_fixme_vpp_workers
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class QUICAppWorker(Worker):
    """QUIC Test Application Worker"""

    process = None

    def __init__(
        self,
        appname,
        executable_args,
        logger,
        role,
        testcase,
        env=None,
        *args,
        **kwargs,
    ):
        if env is None:
            env = {}
        app = f"{config.vpp_build_dir}/vpp/bin/{appname}"
        self.args = [app] + executable_args
        self.role = role
        self.wait_for_gdb = "wait-for-gdb"
        self.testcase = testcase
        super(QUICAppWorker, self).__init__(self.args, logger, env, *args, **kwargs)

    def run(self):
        super(QUICAppWorker, self).run()

    def teardown(self, logger, timeout):
        if self.process is None:
            return False
        try:
            logger.debug(f"Killing worker process (pid {self.process.pid})")
            os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
            self.join(timeout)
        except OSError as e:
            logger.debug("Couldn't kill worker process")
            return True
        return False


@unittest.skipIf("quic" in config.excluded_plugins, "Exclude QUIC plugin tests")
class QUICTestCase(VppAsfTestCase):
    """QUIC Test Case"""

    timeout = 20
    pre_test_sleep = 0.3
    post_test_sleep = 0.3
    server_appns = "server"
    server_appns_secret = None
    client_appns = "client"
    client_appns_secret = None
    # Crypto engine: "vpp" (vnet_crypto) or "engine-lib" (picotls)
    crypto_engine = "vpp"
    # vnet_crypto handler (only used when crypto_engine == "vpp"):
    # None  -> leave the current handler unchanged
    # "native", "ipsecmb", "openssl" -> set via "set crypto handler all <handler>"
    crypto_handler = None

    @classmethod
    def setUpClass(cls):
        cls.extra_vpp_plugin_config.append("plugin quic_plugin.so { enable }")
        cls.extra_vpp_plugin_config.append("plugin quic_quicly_plugin.so { enable }")
        cls.extra_vpp_config = list(cls.extra_vpp_config) + [
            "quic",
            "{",
            "enable-vnet-crypto",
            "}",
        ]
        super(QUICTestCase, cls).setUpClass()

    def setUp(self):
        super(QUICTestCase, self).setUp()
        self.vppDebug = "vpp_debug" in config.vpp_build_dir

        self.create_loopback_interfaces(2)
        self.uri = f"quic://{self.loop0.local_ip4}/1234"
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
        self.vapi.app_namespace_add_del_v4(
            namespace_id=self.server_appns,
            secret=self.server_appns_secret,
            sw_if_index=self.loop0.sw_if_index,
        )
        self.vapi.app_namespace_add_del_v4(
            namespace_id=self.client_appns,
            secret=self.client_appns_secret,
            sw_if_index=self.loop1.sw_if_index,
        )

        # Add inter-table routes
        self.ip_t01 = VppIpRoute(
            self,
            self.loop1.local_ip4,
            32,
            [VppRoutePath("0.0.0.0", 0xFFFFFFFF, nh_table_id=2)],
            table_id=1,
        )
        self.ip_t10 = VppIpRoute(
            self,
            self.loop0.local_ip4,
            32,
            [VppRoutePath("0.0.0.0", 0xFFFFFFFF, nh_table_id=1)],
            table_id=2,
        )
        self.ip_t01.add_vpp_config()
        self.ip_t10.add_vpp_config()
        self.logger.debug(self.vapi.cli("show ip fib"))
        self.vapi.cli(f"quic set crypto api {self.crypto_engine}")
        # self.vapi.cli("quic set crypto api engine-lib")
        if self.crypto_handler is not None:
            self.vapi.cli(f"set crypto handler all {self.crypto_handler}")
        self.logger.debug(self.vapi.cli("show quic"))

    def tearDown(self):
        self.logger.debug(self.vapi.cli("show quic"))
        self.vapi.app_namespace_add_del_v4(
            is_add=0,
            namespace_id=self.server_appns,
            secret=self.server_appns_secret,
            sw_if_index=self.loop0.sw_if_index,
        )
        self.vapi.app_namespace_add_del_v4(
            is_add=0,
            namespace_id=self.client_appns,
            secret=self.client_appns_secret,
            sw_if_index=self.loop1.sw_if_index,
        )
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

    test_bytes = " test-bytes"
    extra_vpp_config = ["session", "{", "enable", "poll-main", "}"]
    vpp_worker_count = 2

    def setUp(self):
        super(QUICEchoIntTestCase, self).setUp()
        self.client_args = (
            f"uri {self.uri} fifo-size 64k{self.test_bytes} appns {self.client_appns} "
        )
        self.server_args = f"uri {self.uri} fifo-size 64k appns {self.server_appns} "

    def tearDown(self):
        super(QUICEchoIntTestCase, self).tearDown()

    def server(self, *args):
        _args = self.server_args + " ".join(args)
        error = self.vapi.cli(f"test echo server {_args}")
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

    def client(self, *args):
        _args = self.client_args + " ".join(args)
        error = self.vapi.cli(f"test echo client {_args}")
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)


class QUICEchoIntTransferTestCase(QUICEchoIntTestCase):
    """QUIC Echo Internal Transfer Test Case"""

    def test_quic_int_transfer(self):
        """QUIC internal transfer"""
        self.server()
        self.client("bytes", "2m")


class QUICEchoIntSerialTestCase(QUICEchoIntTestCase):
    """QUIC Echo Internal Serial Transfer Test Case"""

    def test_quic_serial_int_transfer(self):
        """QUIC serial internal transfer"""
        self.server()
        self.client("bytes", "2m")
        self.client("bytes", "2m")
        self.client("bytes", "2m")
        self.client("bytes", "2m")
        self.client("bytes", "2m")


class QUICEchoIntMStreamTestCase(QUICEchoIntTestCase):
    """QUIC Echo Internal MultiStream Test Case"""

    def test_quic_int_multistream_transfer(self):
        """QUIC internal multi-stream transfer"""
        self.server()
        self.client("nclients", "10", "bytes", "1m")


class QUICEchoExtTestCase(QUICTestCase):
    quic_setup = "default"
    test_bytes = "test-bytes:assert"
    pre_test_sleep = 1
    post_test_sleep = 1
    app = "vpp_echo"
    evt_q_len = 16384
    vpp_worker_count = 1
    server_fifo_size = "1M"
    client_fifo_size = "4M"
    extra_vpp_config = [
        "session",
        "{",
        "enable",
        "poll-main",
        "use-app-socket-api",
        "wrk-mqs-segment-size",
        "64M",
        "event-queue-length",
        f"{evt_q_len}",
        "preallocated-sessions",
        "1024",
        "v4-session-table-buckets",
        "20000",
        "v4-session-table-memory",
        "64M",
        "v4-halfopen-table-buckets",
        "20000",
        "v4-halfopen-table-memory",
        "64M",
        "local-endpoints-table-buckets",
        "250000",
        "local-endpoints-table-memory",
        "512M",
        "}",
    ]

    def setUp(self):
        self.server_appns_secret = 1234
        self.client_appns_secret = 5678
        super(QUICEchoExtTestCase, self).setUp()
        common_args = [
            "uri",
            self.uri,
            "json",
            self.test_bytes,
            "quic-setup",
            self.quic_setup,
            "nthreads",
            "1",
            "mq-size",
            f"{self.evt_q_len}",
            "use-app-socket-api",
        ]
        self.server_echo_test_args = common_args + [
            "server",
            "appns",
            f"{self.server_appns}",
            "fifo-size",
            f"{self.server_fifo_size}",
            "socket-name",
            f"{self.tempdir}/app_ns_sockets/{self.server_appns}",
        ]
        self.client_echo_test_args = common_args + [
            "client",
            "appns",
            f"{self.client_appns}",
            "fifo-size",
            f"{self.client_fifo_size}",
            "socket-name",
            f"{self.tempdir}/app_ns_sockets/{self.client_appns}",
        ]
        error = self.vapi.cli("quic set fifo-size 2M")
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

    def server(self, *args):
        _args = self.server_echo_test_args + list(args)
        self.worker_server = QUICAppWorker(
            self.app, _args, self.logger, self.server_appns, self
        )
        self.worker_server.start()
        self.sleep(self.pre_test_sleep)

    def client(self, *args):
        _args = self.client_echo_test_args + list(args)
        self.worker_client = QUICAppWorker(
            self.app, _args, self.logger, self.client_appns, self
        )
        self.worker_client.start()
        timeout = None if self.debug_all else self.timeout
        self.worker_client.join(timeout)
        if self.worker_client.is_alive():
            error = f"Client failed to complete in {timeout} seconds!"
            self.logger.critical(error)
            return
        self.worker_server.join(timeout)
        if self.worker_server.is_alive():
            error = f"Server failed to complete in {timeout} seconds!"
            self.logger.critical(error)
        self.sleep(self.post_test_sleep)

    def validate_ext_test_results(self):
        server_result = self.worker_server.result
        self.logger.debug(self.vapi.cli(f"show session verbose 2"))
        client_result = self.worker_client.result
        self.logger.info(f"Server worker result is `{server_result}'")
        self.logger.info(f"Client worker result is `{client_result}'")
        server_kill_error = False
        if self.worker_server.result is None:
            server_kill_error = self.worker_server.teardown(self.logger, self.timeout)
        if self.worker_client.result is None:
            self.worker_client.teardown(self.logger, self.timeout)
        err_msg = f"Wrong server worker return code ({server_result})"
        self.assertEqual(server_result, 0, err_msg)
        self.assertIsNotNone(
            client_result, f"Timeout! Client worker did not finish in {self.timeout}s"
        )
        err_msg = f"Wrong client worker return code ({client_result})"
        self.assertEqual(client_result, 0, err_msg)
        self.assertFalse(server_kill_error, "Server kill errored")


class QUICEchoExtTransferTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Test Case"""

    timeout = 60

    def test_quic_ext_transfer(self):
        """QUIC external transfer"""
        self.server()
        self.client()
        self.validate_ext_test_results()


class QUICEchoExtTransferBigTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Big Test Case"""

    server_fifo_size = "4M"
    client_fifo_size = "4M"
    test_bytes = ""
    timeout = 60

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_quic_ext_transfer_big(self):
        """QUIC external transfer, big stream"""
        self.server("TX=0", "RX=2G")
        self.client("TX=2G", "RX=0")
        self.validate_ext_test_results()


class QUICEchoExtQcloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Qclose Rx Test Case"""

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_qclose_rx(self):
        """QUIC external transfer, rx close"""
        self.server("TX=0", "RX=10M", "qclose=Y", "sclose=N")
        self.client("TX=10M", "RX=0", "qclose=W", "sclose=W")
        self.validate_ext_test_results()


class QUICEchoExtQcloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Qclose Tx Test Case"""

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_qclose_tx(self):
        """QUIC external transfer, tx close"""
        self.server("TX=0", "RX=10M", "qclose=W", "sclose=W", "rx-results-diff")
        self.client("TX=10M", "RX=0", "qclose=Y", "sclose=N")
        self.validate_ext_test_results()


class QUICEchoExtEarlyQcloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Early Qclose Rx Test Case"""

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_early_qclose_rx(self):
        """QUIC external transfer, early rx close"""
        self.server("TX=0", "RX=10M", "qclose=Y", "sclose=N")
        self.client("TX=20M", "RX=0", "qclose=W", "sclose=W", "tx-results-diff")
        self.validate_ext_test_results()


class QUICEchoExtEarlyQcloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Early Qclose Tx Test Case"""

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_early_qclose_tx(self):
        """QUIC external transfer, early tx close"""
        self.server("TX=0", "RX=20M", "qclose=W", "sclose=W", "rx-results-diff")
        self.client("TX=10M", "RX=0", "qclose=Y", "sclose=N")
        self.validate_ext_test_results()


class QUICEchoExtScloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Sclose Rx Test Case"""

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_sclose_rx(self):
        """QUIC external transfer, rx stream close"""
        self.server("TX=0", "RX=10M", "qclose=N", "sclose=Y")
        self.client("TX=10M", "RX=0", "qclose=W", "sclose=W")
        self.validate_ext_test_results()


class QUICEchoExtScloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Sclose Tx Test Case"""

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_sclose_tx(self):
        """QUIC external transfer, tx stream close"""
        self.server("TX=0", "RX=10M", "qclose=W", "sclose=W")
        self.client("TX=10M", "RX=0", "qclose=Y", "sclose=Y")
        self.validate_ext_test_results()


class QUICEchoExtEarlyScloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Early Sclose Rx Test Case"""

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_early_sclose_rx(self):
        """QUIC external transfer, early rx stream close"""
        self.server("TX=0", "RX=10M", "qclose=N", "sclose=Y")
        self.client("TX=20M", "RX=0", "qclose=W", "sclose=W", "tx-results-diff")
        self.validate_ext_test_results()


class QUICEchoExtEarlyScloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Early Sclose Tx Test Case"""

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_early_sclose_tx(self):
        """QUIC external transfer, early tx stream close"""
        self.server("TX=0", "RX=20M", "qclose=W", "sclose=W", "rx-results-diff")
        self.client("TX=10M", "RX=0", "qclose=Y", "sclose=Y")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Test Case"""

    quic_setup = "serverstream"
    timeout = 60

    def test_quic_ext_transfer_server_stream(self):
        """QUIC external server transfer"""
        self.server("TX=10M", "RX=0")
        self.client("TX=0", "RX=10M")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamBigTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Big Test Case"""

    quic_setup = "serverstream"
    server_fifo_size = "4M"
    client_fifo_size = "4M"
    test_bytes = ""
    timeout = 60

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_quic_ext_transfer_server_stream_big(self):
        """QUIC external server transfer, big stream"""
        self.server("TX=2G", "RX=0")
        self.client("TX=0", "RX=2G")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamQcloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Qclose Rx Test Case"""

    quic_setup = "serverstream"

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_server_stream_qclose_rx(self):
        """QUIC external server transfer, rx close"""
        self.server("TX=10M", "RX=0", "qclose=W", "sclose=W")
        self.client("TX=0", "RX=10M", "qclose=Y", "sclose=N")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamQcloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Qclose Tx Test Case"""

    quic_setup = "serverstream"

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_server_stream_qclose_tx(self):
        """QUIC external server transfer, tx close"""
        self.server("TX=10M", "RX=0", "qclose=Y", "sclose=N")
        self.client("TX=0", "RX=10M", "qclose=W", "sclose=W", "rx-results-diff")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamEarlyQcloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Early Qclose Rx Test Case"""

    quic_setup = "serverstream"

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_server_stream_early_qclose_rx(self):
        """QUIC external server transfer, early rx close"""
        self.server("TX=20M", "RX=0", "qclose=W", "sclose=W", "tx-results-diff")
        self.client("TX=0", "RX=10M", "qclose=Y", "sclose=N")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamEarlyQcloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Early Qclose Tx Test Case"""

    quic_setup = "serverstream"

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_server_stream_early_qclose_tx(self):
        """QUIC external server transfer, early tx close"""
        self.server("TX=10M", "RX=0", "qclose=Y", "sclose=N")
        self.client("TX=0", "RX=20M", "qclose=W", "sclose=W", "rx-results-diff")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamScloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Sclose Rx Test Case"""

    quic_setup = "serverstream"

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_server_stream_sclose_rx(self):
        """QUIC external server transfer, rx stream close"""
        self.server("TX=10M", "RX=0", "qclose=W", "sclose=W")
        self.client("TX=0", "RX=10M", "qclose=N", "sclose=Y")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamScloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Sclose Tx Test Case"""

    quic_setup = "serverstream"

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_server_stream_sclose_tx(self):
        """QUIC external server transfer, tx stream close"""
        self.server("TX=10M", "RX=0", "qclose=Y", "sclose=Y")
        self.client("TX=0", "RX=10M", "qclose=W", "sclose=W")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamEarlyScloseRxTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream Early Sclose Rx Test Case"""

    quic_setup = "serverstream"

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_server_stream_early_sclose_rx(self):
        """QUIC external server transfer, early rx stream close"""
        self.server("TX=20M", "RX=0", "qclose=W", "sclose=W", "tx-results-diff")
        self.client("TX=0", "RX=10M", "qclose=N", "sclose=Y")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamEarlyScloseTxTestCase(QUICEchoExtTestCase):
    """QUIC Echo Ext Transfer Server Stream Early Sclose Tx Test Case"""

    quic_setup = "serverstream"

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_server_stream_early_sclose_tx(self):
        """QUIC external server transfer, early tx stream close"""
        self.server("TX=10M", "RX=0", "qclose=Y", "sclose=Y")
        self.client("TX=0", "RX=20M", "qclose=W", "sclose=W", "rx-results-diff")
        self.validate_ext_test_results()


class QUICEchoExtServerStreamWorkersTestCase(QUICEchoExtTestCase):
    """QUIC Echo External Transfer Server Stream MultiWorker Test Case"""

    quic_setup = "serverstream"

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("testcase under development")
    def test_quic_ext_transfer_server_stream_multi_workers(self):
        """QUIC external server transfer, multi-worker"""
        self.server("nclients", "4", "quic-streams", "4", "TX=10M", "RX=0")
        self.client("nclients", "4", "quic-streams", "4", "TX=0", "RX=10M")
        self.validate_ext_test_results()


# ---------------------------------------------------------------------------
# Picotls (engine-lib) variants of the actively-run test cases
# ---------------------------------------------------------------------------


class QUICEchoIntTransferPicotlsTestCase(QUICEchoIntTransferTestCase):
    """QUIC Echo Internal Transfer Test Case (picotls/engine-lib)"""

    crypto_engine = "engine-lib"


class QUICEchoIntSerialPicotlsTestCase(QUICEchoIntSerialTestCase):
    """QUIC Echo Internal Serial Transfer Test Case (picotls/engine-lib)"""

    crypto_engine = "engine-lib"


class QUICEchoIntMStreamPicotlsTestCase(QUICEchoIntMStreamTestCase):
    """QUIC Echo Internal MultiStream Test Case (picotls/engine-lib)"""

    crypto_engine = "engine-lib"


class QUICEchoExtTransferPicotlsTestCase(QUICEchoExtTransferTestCase):
    """QUIC Echo External Transfer Test Case (picotls/engine-lib)"""

    crypto_engine = "engine-lib"


class QUICEchoExtServerStreamPicotlsTestCase(QUICEchoExtServerStreamTestCase):
    """QUIC Echo External Transfer Server Stream Test Case (picotls/engine-lib)"""

    crypto_engine = "engine-lib"


# ---------------------------------------------------------------------------
# Key-update tests: max_packets_per_key is set small so that multiple key
# updates are triggered during a normal 2 MB transfer.  Tested with both
# the vnet_crypto (vpp) and picotls (engine-lib) backends.
# ---------------------------------------------------------------------------


class QUICKeyUpdateVppTestCase(QUICEchoIntTestCase):
    """QUIC Key Update Test Case (vpp/vnet_crypto)"""

    # Force a key update every 16 packets (default is 16 777 216)
    max_packets_per_key = 16

    def setUp(self):
        super().setUp()
        self.vapi.cli(f"set quic max_packets_per_key {self.max_packets_per_key}")

    def test_quic_key_update(self):
        """QUIC internal transfer with frequent key updates (vpp crypto)"""
        self.server()
        self.client("bytes", "2m")


class QUICKeyUpdatePicotlsTestCase(QUICEchoIntTestCase):
    """QUIC Key Update Test Case (picotls/engine-lib)"""

    crypto_engine = "engine-lib"
    max_packets_per_key = 16

    def setUp(self):
        super().setUp()
        self.vapi.cli(f"set quic max_packets_per_key {self.max_packets_per_key}")

    def test_quic_key_update_picotls(self):
        """QUIC internal transfer with frequent key updates (picotls)"""
        self.server()
        self.client("bytes", "2m")


# ---------------------------------------------------------------------------
# Nsim tests: packet loss and reordering applied to both loopback interfaces
# so that QUIC exercises its loss-recovery and reorder-handling paths.
# ---------------------------------------------------------------------------


@unittest.skipIf("nsim" in config.excluded_plugins, "Exclude NSIM plugin tests")
class QUICNsimTestCase(QUICEchoIntTestCase):
    """QUIC Echo Internal Transfer with Loss and Reordering (nsim)"""

    # Increase timeout to accommodate extra latency / retransmissions
    timeout = 60

    def _nsim_enable(self):
        # 0.1 ms delay, 10 Gbps bandwidth, 1460-byte packets,
        # 1-in-100 drop rate, 1-in-5 reorder rate; poll-main-thread is
        # required for loopback interfaces that run on the main thread.
        self.vapi.cli(
            "set nsim poll-main-thread delay 0.1 ms bandwidth 10 gbit "
            "packet-size 1460 packets-per-drop 100 packets-per-reorder 5"
        )
        self.vapi.cli(f"nsim output-feature enable-disable {self.loop0.name}")
        self.vapi.cli(f"nsim output-feature enable-disable {self.loop1.name}")
        self.logger.debug(self.vapi.cli("show nsim"))

    def _nsim_disable(self):
        self.vapi.cli(f"nsim output-feature enable-disable {self.loop0.name} disable")
        self.vapi.cli(f"nsim output-feature enable-disable {self.loop1.name} disable")

    def test_quic_int_transfer_nsim(self):
        """QUIC internal transfer under packet loss and reordering"""
        self._nsim_enable()
        try:
            self.server()
            self.client("bytes", "2m")
        finally:
            self._nsim_disable()


class _QUICNsimMixin:
    """Mixin providing nsim enable/disable helpers without contributing tests."""

    timeout = 60

    def _nsim_enable(self):
        self.vapi.cli(
            "set nsim poll-main-thread delay 0.1 ms bandwidth 10 gbit "
            "packet-size 1460 packets-per-drop 100 packets-per-reorder 5"
        )
        self.vapi.cli(f"nsim output-feature enable-disable {self.loop0.name}")
        self.vapi.cli(f"nsim output-feature enable-disable {self.loop1.name}")
        self.logger.debug(self.vapi.cli("show nsim"))

    def _nsim_disable(self):
        self.vapi.cli(f"nsim output-feature enable-disable {self.loop0.name} disable")
        self.vapi.cli(f"nsim output-feature enable-disable {self.loop1.name} disable")


@unittest.skipIf("nsim" in config.excluded_plugins, "Exclude NSIM plugin tests")
class QUICNsimKeyUpdateTestCase(_QUICNsimMixin, QUICEchoIntTestCase):
    """QUIC Key Update under Loss and Reordering (vpp crypto, nsim)"""

    max_packets_per_key = 16

    def setUp(self):
        super().setUp()
        self.vapi.cli(f"set quic max_packets_per_key {self.max_packets_per_key}")

    def test_quic_key_update_nsim(self):
        """QUIC internal transfer with key updates under loss and reordering"""
        self._nsim_enable()
        try:
            self.server()
            self.client("bytes", "2m")
        finally:
            self._nsim_disable()


# ---------------------------------------------------------------------------
# Runtime crypto handler switch tests
# Verify that QUIC connections keep working when the vnet_crypto handler is
# changed at runtime via "set crypto handler all <engine>".
# ---------------------------------------------------------------------------


class QUICCryptoHandlerSwitchTestCase(QUICEchoIntTestCase):
    """QUIC Crypto Handler Runtime Switch Between Connections"""

    # Handlers to cycle through; the test switches to each one in sequence
    # between consecutive QUIC connections to the same server.
    _switch_handlers = ("native", "ipsecmb", "openssl")

    def test_quic_handler_switch_between_connections(self):
        """QUIC: switch vnet_crypto handler between consecutive connections"""
        self.server()
        for handler in self._switch_handlers:
            self.vapi.cli(f"set crypto handler all {handler}")
            self.logger.debug(self.vapi.cli("show crypto handlers"))
            self.client("bytes", "2m")


class QUICCryptoHandlerMidTransferSwitchTestCase(QUICEchoExtTestCase):
    """QUIC Crypto Handler Runtime Switch During Active Transfer"""

    # Disable byte-assertion so TX=200M / RX=0 args are accepted cleanly
    test_bytes = ""
    timeout = 60

    def test_quic_handler_switch_mid_transfer(self):
        """QUIC: cycle vnet_crypto handler while a large transfer is in flight"""
        # 200 MB gives enough wall time to cycle through all three handlers
        # before the transfer completes.
        self.server("TX=0", "RX=200M")
        _args = self.client_echo_test_args + ["TX=200M", "RX=0"]
        self.worker_client = QUICAppWorker(
            self.app, _args, self.logger, self.client_appns, self
        )
        self.worker_client.start()
        # Let the connection establish and data start flowing
        self.sleep(1)
        # Cycle through handlers while the transfer is active
        for handler in ("native", "ipsecmb", "openssl"):
            self.vapi.cli(f"set crypto handler all {handler}")
            self.logger.debug(self.vapi.cli("show crypto handlers"))
            self.sleep(0.5)
        # Collect results
        timeout = None if self.debug_all else self.timeout
        self.worker_client.join(timeout)
        if self.worker_client.is_alive():
            self.logger.critical(f"Client failed to complete in {timeout} seconds!")
        self.worker_server.join(timeout)
        if self.worker_server.is_alive():
            self.logger.critical(f"Server failed to complete in {timeout} seconds!")
        self.sleep(self.post_test_sleep)
        self.validate_ext_test_results()


class QUICCryptoHandlerMidTransferWithKeyUpdateTestCase(QUICEchoExtTestCase):
    """QUIC Crypto Handler Switch Mid-Transfer with Frequent Key Updates

    Forces a key update every 16 packets so that both the data-path and
    key-update crypto operations are processed by each handler during the
    handler rotation.  This guarantees that each handler is exercised
    within the same QUIC connection.
    """

    test_bytes = ""
    timeout = 60
    # Small value ensures many key updates occur during the transfer
    max_packets_per_key = 16

    def setUp(self):
        super().setUp()
        self.vapi.cli(f"set quic max_packets_per_key {self.max_packets_per_key}")

    def test_quic_handler_switch_mid_transfer_with_key_update(self):
        """QUIC: switch handler mid-connection combined with frequent key updates"""
        self.server("TX=0", "RX=200M")
        _args = self.client_echo_test_args + ["TX=200M", "RX=0"]
        self.worker_client = QUICAppWorker(
            self.app, _args, self.logger, self.client_appns, self
        )
        self.worker_client.start()
        # Wait for connection establishment
        self.sleep(1)
        # Switch handler every 0.5 s; with max_packets_per_key=16 many key
        # updates will be issued within each handler's active window.
        for handler in ("native", "ipsecmb", "openssl", "native"):
            self.vapi.cli(f"set crypto handler all {handler}")
            self.logger.debug(self.vapi.cli("show crypto handlers"))
            self.sleep(0.5)
        timeout = None if self.debug_all else self.timeout
        self.worker_client.join(timeout)
        if self.worker_client.is_alive():
            self.logger.critical(f"Client failed to complete in {timeout} seconds!")
        self.worker_server.join(timeout)
        if self.worker_server.is_alive():
            self.logger.critical(f"Server failed to complete in {timeout} seconds!")
        self.sleep(self.post_test_sleep)
        self.validate_ext_test_results()


# ---------------------------------------------------------------------------
# vnet_crypto handler variants: native, ipsecmb, openssl
# Each group sets crypto_handler so QUICTestCase.setUp issues
# "set crypto handler all <handler>" before running the test.
# ---------------------------------------------------------------------------


# -- native -----------------------------------------------------------------


class QUICEchoIntTransferNativeTestCase(QUICEchoIntTransferTestCase):
    """QUIC Echo Internal Transfer Test Case (vpp/native)"""

    crypto_handler = "native"


class QUICEchoIntSerialNativeTestCase(QUICEchoIntSerialTestCase):
    """QUIC Echo Internal Serial Transfer Test Case (vpp/native)"""

    crypto_handler = "native"


class QUICEchoIntMStreamNativeTestCase(QUICEchoIntMStreamTestCase):
    """QUIC Echo Internal MultiStream Test Case (vpp/native)"""

    crypto_handler = "native"


class QUICEchoExtTransferNativeTestCase(QUICEchoExtTransferTestCase):
    """QUIC Echo External Transfer Test Case (vpp/native)"""

    crypto_handler = "native"


class QUICEchoExtServerStreamNativeTestCase(QUICEchoExtServerStreamTestCase):
    """QUIC Echo External Transfer Server Stream Test Case (vpp/native)"""

    crypto_handler = "native"


class QUICKeyUpdateNativeTestCase(QUICKeyUpdateVppTestCase):
    """QUIC Key Update Test Case (vpp/native)"""

    crypto_handler = "native"


@unittest.skipIf("nsim" in config.excluded_plugins, "Exclude NSIM plugin tests")
class QUICNsimTransferNativeTestCase(QUICNsimTestCase):
    """QUIC Nsim Transfer Test Case (vpp/native)"""

    crypto_handler = "native"


@unittest.skipIf("nsim" in config.excluded_plugins, "Exclude NSIM plugin tests")
class QUICNsimKeyUpdateNativeTestCase(QUICNsimKeyUpdateTestCase):
    """QUIC Nsim Key Update Test Case (vpp/native)"""

    crypto_handler = "native"


# -- ipsecmb ----------------------------------------------------------------


class QUICEchoIntTransferIpsecmbTestCase(QUICEchoIntTransferTestCase):
    """QUIC Echo Internal Transfer Test Case (vpp/ipsecmb)"""

    crypto_handler = "ipsecmb"


@unittest.skipUnless(config.extended, "part of extended tests")
class QUICEchoIntSerialIpsecmbTestCase(QUICEchoIntSerialTestCase):
    """QUIC Echo Internal Serial Transfer Test Case (vpp/ipsecmb)"""

    crypto_handler = "ipsecmb"


@unittest.skipUnless(config.extended, "part of extended tests")
class QUICEchoIntMStreamIpsecmbTestCase(QUICEchoIntMStreamTestCase):
    """QUIC Echo Internal MultiStream Test Case (vpp/ipsecmb)"""

    crypto_handler = "ipsecmb"


@unittest.skipUnless(config.extended, "part of extended tests")
class QUICEchoExtTransferIpsecmbTestCase(QUICEchoExtTransferTestCase):
    """QUIC Echo External Transfer Test Case (vpp/ipsecmb)"""

    crypto_handler = "ipsecmb"


@unittest.skipUnless(config.extended, "part of extended tests")
class QUICEchoExtServerStreamIpsecmbTestCase(QUICEchoExtServerStreamTestCase):
    """QUIC Echo External Transfer Server Stream Test Case (vpp/ipsecmb)"""

    crypto_handler = "ipsecmb"


@unittest.skipUnless(config.extended, "part of extended tests")
class QUICKeyUpdateIpsecmbTestCase(QUICKeyUpdateVppTestCase):
    """QUIC Key Update Test Case (vpp/ipsecmb)"""

    crypto_handler = "ipsecmb"


@unittest.skipUnless(config.extended, "part of extended tests")
@unittest.skipIf("nsim" in config.excluded_plugins, "Exclude NSIM plugin tests")
class QUICNsimTransferIpsecmbTestCase(QUICNsimTestCase):
    """QUIC Nsim Transfer Test Case (vpp/ipsecmb)"""

    crypto_handler = "ipsecmb"


@unittest.skipUnless(config.extended, "part of extended tests")
@unittest.skipIf("nsim" in config.excluded_plugins, "Exclude NSIM plugin tests")
class QUICNsimKeyUpdateIpsecmbTestCase(QUICNsimKeyUpdateTestCase):
    """QUIC Nsim Key Update Test Case (vpp/ipsecmb)"""

    crypto_handler = "ipsecmb"


# -- openssl ----------------------------------------------------------------


class QUICEchoIntTransferOpensslTestCase(QUICEchoIntTransferTestCase):
    """QUIC Echo Internal Transfer Test Case (vpp/openssl)"""

    crypto_handler = "openssl"


@unittest.skipUnless(config.extended, "part of extended tests")
class QUICEchoIntSerialOpensslTestCase(QUICEchoIntSerialTestCase):
    """QUIC Echo Internal Serial Transfer Test Case (vpp/openssl)"""

    crypto_handler = "openssl"


@unittest.skipUnless(config.extended, "part of extended tests")
class QUICEchoIntMStreamOpensslTestCase(QUICEchoIntMStreamTestCase):
    """QUIC Echo Internal MultiStream Test Case (vpp/openssl)"""

    crypto_handler = "openssl"


@unittest.skipUnless(config.extended, "part of extended tests")
class QUICEchoExtTransferOpensslTestCase(QUICEchoExtTransferTestCase):
    """QUIC Echo External Transfer Test Case (vpp/openssl)"""

    crypto_handler = "openssl"


@unittest.skipUnless(config.extended, "part of extended tests")
class QUICEchoExtServerStreamOpensslTestCase(QUICEchoExtServerStreamTestCase):
    """QUIC Echo External Transfer Server Stream Test Case (vpp/openssl)"""

    crypto_handler = "openssl"


@unittest.skipUnless(config.extended, "part of extended tests")
class QUICKeyUpdateOpensslTestCase(QUICKeyUpdateVppTestCase):
    """QUIC Key Update Test Case (vpp/openssl)"""

    crypto_handler = "openssl"


@unittest.skipUnless(config.extended, "part of extended tests")
@unittest.skipIf("nsim" in config.excluded_plugins, "Exclude NSIM plugin tests")
class QUICNsimTransferOpensslTestCase(QUICNsimTestCase):
    """QUIC Nsim Transfer Test Case (vpp/openssl)"""

    crypto_handler = "openssl"


@unittest.skipUnless(config.extended, "part of extended tests")
@unittest.skipIf("nsim" in config.excluded_plugins, "Exclude NSIM plugin tests")
class QUICNsimKeyUpdateOpensslTestCase(QUICNsimKeyUpdateTestCase):
    """QUIC Nsim Key Update Test Case (vpp/openssl)"""

    crypto_handler = "openssl"


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
