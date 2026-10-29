#!/usr/bin/env python3

import unittest
import select
import socket
import struct

from asfframework import (
    VppAsfTestCase,
    VppTestRunner,
    tag_fixme_vpp_workers,
    tag_run_solo,
)
from vpp_papi import VppEnum
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath
from ipaddress import IPv4Network
from config import config


class TestSessionSocketAPI(VppAsfTestCase):
    """Session socket API certificate messages"""

    extra_vpp_config = ["session { enable use-app-socket-api }"]

    # app_sapi_msg_t uses a packed type byte and a union whose largest member
    # is the attach message (name[64], options[18]). Fields use native endian.
    msg_len = struct.calcsize("=B64s18Q")
    cert_key_msg_type = 6
    cert_key_reply_type = 7
    context = 123

    def setUp(self):
        super().setUp()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(self.sock.close)
        self.sock.settimeout(2)
        self.sock.connect(f"{self.tempdir}/app_ns_sockets/default")
        self.sock.sendall(
            struct.pack("=B64s18Q", 1, b"session-socket-api-test", *([0] * 18))
        )
        reply = self.sock.recv(self.msg_len)
        self.assertEqual(len(reply), self.msg_len)
        self.assertEqual(struct.unpack_from("=Bi", reply), (2, 0))

    def cert_key_msg(self, cert_len=0, data_len=0, index=0, is_add=1):
        return struct.pack(
            "=BIIHHB",
            self.cert_key_msg_type,
            self.context,
            index,
            cert_len,
            data_len,
            is_add,
        ).ljust(self.msg_len, b"\0")

    def cert_key_reply(self):
        reply = self.sock.recv(self.msg_len)
        self.assertEqual(len(reply), self.msg_len)
        msg_type, context, retval, index = struct.unpack_from("=BIiI", reply)
        self.assertEqual(msg_type, self.cert_key_reply_type)
        self.assertEqual(context, self.context)
        return retval, index

    def assert_no_reply(self):
        self.assertFalse(select.select([self.sock], [], [], 0.05)[0])

    def test_cert_key_fragments(self):
        """Accumulate delayed certificate payloads across seqpackets"""
        cases = [
            (4, b"certkey", [7]),
            (4, b"certkey", list(range(1, 8))),
            (10000, b"c" * 10000 + b"k" * 10000, [20000]),
            (10000, b"c" * 10000 + b"k" * 10000, [1, 4097, 11097, 19999, 20000]),
        ]
        for cert_len, data, ends in cases:
            with self.subTest(cert_len=cert_len, fragments=len(ends)):
                self.sock.sendall(self.cert_key_msg(cert_len, len(data)))
                self.assert_no_reply()
                start = 0
                for end in ends:
                    self.sock.sendall(data[start:end])
                    if end < len(data):
                        self.assert_no_reply()
                    start = end
                retval, index = self.cert_key_reply()
                self.assertEqual(retval, 0)
                self.assertIn(
                    f"{index} (cert:{cert_len}, key:{len(data) - cert_len})",
                    self.vapi.cli("show app certificate"),
                )
                self.sock.sendall(self.cert_key_msg(index=index, is_add=0))
                retval, _ = self.cert_key_reply()
                self.assertEqual(retval, 0)

    def test_cert_key_invalid_lengths(self):
        """Discard invalid certificate bodies and preserve request framing"""
        for cert_len, data_len in [
            (0, 0),
            (1, 0),
            (0, 1),
            (1, 1),
            (2, 1),
            (10001, 10002),
            (1, 10002),
            (10000, 20001),
            (1, 65535),
        ]:
            with self.subTest(cert_len=cert_len, data_len=data_len):
                self.sock.sendall(self.cert_key_msg(cert_len, data_len))
                if data_len:
                    self.sock.sendall(b"x" * data_len)
                retval, _ = self.cert_key_reply()
                self.assertLess(retval, 0)

                # A rejected body must not detach the worker or consume the
                # next request. Exercise another complete add/delete pair.
                self.sock.sendall(self.cert_key_msg(4, 7))
                self.sock.sendall(b"certkey")
                retval, index = self.cert_key_reply()
                self.assertEqual(retval, 0)
                self.sock.sendall(self.cert_key_msg(index=index, is_add=0))
                retval, _ = self.cert_key_reply()
                self.assertEqual(retval, 0)

    def test_cert_key_queued_payload(self):
        """Read queued certificate fragments without consuming the next command"""
        cases = [
            (4, b"certkey", [7]),
            (4, b"certkey", list(range(1, 8))),
            (10000, b"c" * 10000 + b"k" * 10000, [20000]),
            (10000, b"c" * 10000 + b"k" * 10000, [1, 4097, 11097, 19999, 20000]),
        ]
        for cert_len, data, ends in cases:
            with self.subTest(cert_len=cert_len, fragments=len(ends)):
                saved = self.vapi.app_add_cert_key_pair(
                    cert_len=4, certkey_len=7, certkey=b"certkey"
                )
                self.sock.sendall(self.cert_key_msg(cert_len, len(data)))
                start = 0
                for end in ends:
                    self.sock.sendall(data[start:end])
                    start = end
                # Queue a command immediately after the payload. The receive
                # loop must stop at the advertised length and preserve it.
                self.sock.sendall(self.cert_key_msg(index=saved.index, is_add=0))
                retval, index = self.cert_key_reply()
                self.assertEqual(retval, 0)
                retval, _ = self.cert_key_reply()
                self.assertEqual(retval, 0)
                self.assertIn(
                    f"{index} (cert:{cert_len}, key:{len(data) - cert_len})",
                    self.vapi.cli("show app certificate"),
                )
                self.sock.sendall(self.cert_key_msg(index=index, is_add=0))
                retval, _ = self.cert_key_reply()
                self.assertEqual(retval, 0)

    def assert_incomplete_payload_eof(self, prefix=b""):
        self.sock.sendall(self.cert_key_msg(4, 7))
        if prefix:
            self.sock.sendall(prefix)
        self.assert_no_reply()
        self.sock.shutdown(socket.SHUT_WR)
        self.assertEqual(self.sock.recv(self.msg_len), b"")
        self.assertTrue(self.vapi.cli("show version"))

    def test_cert_key_eof_before_payload(self):
        """Detach when the peer closes before sending the certificate payload"""
        self.assert_incomplete_payload_eof()

    def test_cert_key_eof_after_fragment(self):
        """Detach when the peer closes after sending an incomplete payload"""
        self.assert_incomplete_payload_eof(b"cert")

    def test_cert_key_invalid_body_command(self):
        """Never dispatch a rejected certificate body as an API command"""
        reply = self.vapi.app_add_cert_key_pair(
            cert_len=4, certkey_len=7, certkey=b"certkey"
        )
        index = reply.index
        body = self.cert_key_msg(index=index, is_add=0)

        for fragments in ([body], [body[:1], body[1:100], body[100:]]):
            with self.subTest(fragments=len(fragments)):
                self.sock.sendall(self.cert_key_msg(0, len(body)))
                if len(fragments) > 1:
                    self.assert_no_reply()
                for fragment in fragments[:-1]:
                    self.sock.sendall(fragment)
                    self.assert_no_reply()
                self.sock.sendall(fragments[-1])
                retval, _ = self.cert_key_reply()
                self.assertLess(retval, 0)
                self.assert_no_reply()
                self.assertIn(
                    f"{index} (cert:4, key:3)",
                    self.vapi.cli("show app certificate"),
                )

        self.sock.sendall(self.cert_key_msg(index=index, is_add=0))
        retval, _ = self.cert_key_reply()
        self.assertEqual(retval, 0)


@tag_fixme_vpp_workers
@unittest.skipIf(
    "vperf" in config.excluded_plugins, "Exclude tests requiring vperf plugin"
)
class TestSession(VppAsfTestCase):
    """Session Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestSession, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSession, cls).tearDownClass()

    def setUp(self):
        super(TestSession, self).setUp()

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
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()

        # Unconfigure namespaces - remove our locks to the vrf tables
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="0", sw_if_index=self.loop0.sw_if_index
        )
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="1", sw_if_index=self.loop1.sw_if_index
        )

        super(TestSession, self).tearDown()
        self.vapi.session_enable_disable(is_enable=0)

    def test_segment_manager_alloc(self):
        """Session Segment Manager Multiple Segment Allocation"""

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

        # Start builtin server and client with small private segments
        uri = "tcp://" + self.loop0.local_ip4 + "/1234"
        error = self.vapi.cli(
            "vperf server appns 0 fifo-size 64k " + "private-segment-size 1m uri " + uri
        )
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        error = self.vapi.cli(
            "vperf client nclients 100 appns 1 "
            + "fifo-size 64k syn-timeout 2 bytes 8k "
            + "private-segment-size 1m uri "
            + uri
        )
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        if self.vpp_dead:
            self.assert_equal(0)

        # Delete inter-table routes
        ip_t01.remove_vpp_config()
        ip_t10.remove_vpp_config()


class TestApplicationNamespace(VppAsfTestCase):
    """Application Namespacee"""

    @classmethod
    def setUpClass(cls):
        super(TestApplicationNamespace, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestApplicationNamespace, cls).tearDownClass()

    def setUp(self):
        super(TestApplicationNamespace, self).setUp()
        self.create_loopback_interfaces(1)

    def tearDown(self):
        super(TestApplicationNamespace, self).tearDown()
        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
        )

    def test_application_namespace(self):
        """Application Namespace Create"""

        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_RULE_TABLE
        )

        # Configure 2 namespaces, sharing the same interface
        app0 = self.vapi.app_namespace_add_del_v4(
            namespace_id="0", sw_if_index=self.loop0.sw_if_index
        )
        app1 = self.vapi.app_namespace_add_del_v4(
            namespace_id="1", sw_if_index=self.loop0.sw_if_index
        )

        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl="172.100.1.1/32",
            rmt="172.100.1.2/32",
            lcl_port=5000,
            rmt_port=5000,
            action_index=1,
            appns_index=app0.appns_index,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            is_add=1,
        )
        dump = self.vapi.session_rules_v2_dump()
        # session table should contain 3 appns's indices (default, app0, and app1)
        self.assertEqual(len(dump[1].appns_index), 3)
        self.assertEqual(dump[1].count, 3)
        self.assertEqual(dump[1].appns_index[0], 0)
        self.assertEqual(dump[1].appns_index[1], app0.appns_index)
        self.assertEqual(dump[1].appns_index[2], app1.appns_index)

        # remove the last namespace
        self.vapi.app_namespace_add_del_v4(
            namespace_id="1", sw_if_index=self.loop0.sw_if_index, is_add=0
        )
        dump = self.vapi.session_rules_v2_dump()
        # session table should contain the remainging appns's index
        self.assertEqual(len(dump[1].appns_index), 2)
        self.assertEqual(dump[1].count, 2)
        self.assertEqual(dump[1].appns_index[0], 0)
        self.assertEqual(dump[1].appns_index[1], app0.appns_index)

        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl="172.100.1.1/32",
            rmt="172.100.1.2/32",
            lcl_port=5000,
            rmt_port=5000,
            action_index=1,
            appns_index=app0.appns_index,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            is_add=0,
        )
        self.vapi.app_namespace_add_del_v4(
            namespace_id="0", sw_if_index=self.loop0.sw_if_index, is_add=0
        )

        # test bad appns index for the API
        with self.vapi.assert_negative_api_retval():
            rv = self.vapi.session_rule_add_del(
                transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
                lcl="172.100.1.1/32",
                rmt="172.100.1.2/32",
                lcl_port=5000,
                rmt_port=5000,
                action_index=1,
                appns_index=10,
                scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
                is_add=1,
            )
        self.assertEqual(rv.retval, -1)

    def test_application_namespace_binding(self):
        """Application Namespace Interface Binding"""

        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_RULE_TABLE
        )

        table_id = 99

        # Bad ip4_fib_id
        with self.vapi.assert_negative_api_retval():
            rv = self.vapi.app_namespace_add_del_v4(
                is_add=1, namespace_id="2", ip4_fib_id=table_id, ip6_fib_id=0
            )
        self.assertEqual(rv.retval, -19)

        # Bad ip6_fib_id
        with self.vapi.assert_negative_api_retval():
            rv = self.vapi.app_namespace_add_del_v4(
                is_add=1, namespace_id="2", ip4_fib_id=0, ip6_fib_id=table_id
            )
        self.assertEqual(rv.retval, -19)

        tbl = VppIpTable(self, table_id)
        tbl.add_vpp_config()

        tbl6 = VppIpTable(self, table_id, is_ip6=1)
        tbl6.add_vpp_config()

        # Not expecting an error with valid table_id's
        self.vapi.app_namespace_add_del_v4(
            is_add=1, namespace_id="2", ip4_fib_id=table_id, ip6_fib_id=table_id
        )
        # delete
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="2", ip4_fib_id=table_id, ip6_fib_id=table_id
        )

        # ip4 only
        self.vapi.app_namespace_add_del_v4(
            is_add=1, namespace_id="2", ip4_fib_id=table_id, ip6_fib_id=0xFFFFFFFF
        )
        # delete
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="2", ip4_fib_id=table_id, ip6_fib_id=0xFFFFFFFF
        )

        # ip6 only
        self.vapi.app_namespace_add_del_v4(
            is_add=1, namespace_id="2", ip4_fib_id=0xFFFFFFFF, ip6_fib_id=table_id
        )
        # delete
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="2", ip4_fib_id=0xFFFFFFFF, ip6_fib_id=table_id
        )

        app0 = self.vapi.app_namespace_add_del_v4(
            namespace_id="0", sw_if_index=self.loop0.sw_if_index, is_add=1
        )
        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl="172.100.1.1/32",
            rmt="172.100.1.2/32",
            lcl_port=5000,
            rmt_port=5000,
            action_index=1,
            appns_index=app0.appns_index,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            is_add=1,
        )
        dump = self.vapi.session_rules_v2_dump()
        self.assertEqual(len(dump[1].appns_index), 2)
        self.assertEqual(dump[1].count, 2)

        # move the interface to vrf 99
        self.vapi.sw_interface_set_table(
            sw_if_index=self.loop0.sw_if_index,
            is_ipv6=0,
            vrf_id=table_id,
        )
        dump = self.vapi.session_rules_v2_dump()
        self.assertEqual(len(dump[1].appns_index), 1)
        self.assertEqual(dump[1].count, 1)

        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl="172.100.1.1/32",
            rmt="172.100.1.2/32",
            lcl_port=5000,
            rmt_port=5000,
            action_index=1,
            appns_index=0,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            is_add=0,
        )

        # move the interface to vrf 0
        self.vapi.sw_interface_set_table(
            sw_if_index=self.loop0.sw_if_index,
            is_ipv6=0,
            vrf_id=0,
        )

        # try it with ip6
        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl="2001::1/128",
            rmt="2002::1/128",
            lcl_port=5000,
            rmt_port=5000,
            action_index=1,
            appns_index=app0.appns_index,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            is_add=1,
        )
        dump = self.vapi.session_rules_v2_dump()
        self.assertEqual(len(dump[1].appns_index), 2)
        self.assertEqual(dump[1].count, 2)

        self.vapi.sw_interface_set_table(
            sw_if_index=self.loop0.sw_if_index,
            is_ipv6=1,
            vrf_id=table_id,
        )
        dump = self.vapi.session_rules_v2_dump()
        self.assertEqual(len(dump[1].appns_index), 2)
        self.assertEqual(dump[1].count, 2)

        # move back to 0
        self.vapi.sw_interface_set_table(
            sw_if_index=self.loop0.sw_if_index,
            is_ipv6=1,
            vrf_id=0,
        )

        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl="2001::1/128",
            rmt="2002::1/128",
            lcl_port=5000,
            rmt_port=5000,
            action_index=1,
            appns_index=0,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            is_add=0,
        )

        self.vapi.app_namespace_add_del_v4(
            namespace_id="0", sw_if_index=self.loop0.sw_if_index, is_add=0
        )

        tbl.remove_vpp_config()
        tbl6.remove_vpp_config()


@tag_fixme_vpp_workers
class TestSessionUnitTests(VppAsfTestCase):
    """Session Unit Tests Case"""

    @classmethod
    def setUpClass(cls):
        super(TestSessionUnitTests, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSessionUnitTests, cls).tearDownClass()

    def setUp(self):
        super(TestSessionUnitTests, self).setUp()
        self.vapi.session_enable_disable(is_enable=1)

    def test_session(self):
        """Session Unit Tests"""
        error = self.vapi.cli("test session all")

        if error:
            self.logger.critical(error)
        self.assertNotIn("failed", error)

    def tearDown(self):
        super(TestSessionUnitTests, self).tearDown()
        self.vapi.session_enable_disable(is_enable=0)


@tag_fixme_vpp_workers
class TestSessionRuleTableTests(VppAsfTestCase):
    """Session Rule Table Tests Case"""

    @classmethod
    def setUpClass(cls):
        super(TestSessionRuleTableTests, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSessionRuleTableTests, cls).tearDownClass()

    def setUp(self):
        super(TestSessionRuleTableTests, self).setUp()
        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_RULE_TABLE
        )

    def test_session_rule_table(self):
        """Session Rule Table Tests"""

        LCL_IP = "172.100.1.1/32"
        RMT_IP = "172.100.1.2/32"
        LCL_PORT = 5000
        RMT_PORT = 80

        # Add a rule table entry
        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl=LCL_IP,
            rmt=RMT_IP,
            lcl_port=LCL_PORT,
            rmt_port=RMT_PORT,
            action_index=1,
            is_add=1,
            appns_index=0,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            tag="rule-1",
        )

        # Verify it is correctly injected
        dump = self.vapi.session_rules_dump()
        self.assertTrue(len(dump) > 1)
        self.assertEqual(dump[1].rmt_port, RMT_PORT)
        self.assertEqual(dump[1].lcl_port, LCL_PORT)
        self.assertEqual(dump[1].lcl, IPv4Network(LCL_IP))
        self.assertEqual(dump[1].rmt, IPv4Network(RMT_IP))
        self.assertEqual(dump[1].action_index, 1)
        self.assertEqual(dump[1].appns_index, 0)
        self.assertEqual(
            dump[1].scope,
            VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
        )

        # Delete the entry
        self.vapi.session_rule_add_del(
            transport_proto=VppEnum.vl_api_transport_proto_t.TRANSPORT_PROTO_API_TCP,
            lcl=LCL_IP,
            rmt=RMT_IP,
            lcl_port=LCL_PORT,
            rmt_port=RMT_PORT,
            action_index=1,
            is_add=0,
            appns_index=0,
            scope=VppEnum.vl_api_session_rule_scope_t.SESSION_RULE_SCOPE_API_GLOBAL,
            tag="rule-1",
        )
        dump2 = self.vapi.session_rules_dump()

        # Verify it is removed
        self.assertTrue((len(dump) - 1) == len(dump2))

    def tearDown(self):
        super(TestSessionRuleTableTests, self).tearDown()
        self.vapi.session_enable_disable_v2(
            rt_engine_type=VppEnum.vl_api_rt_backend_engine_t.RT_BACKEND_ENGINE_API_DISABLE
        )


@tag_run_solo
class TestSegmentManagerTests(VppAsfTestCase):
    """SVM Fifo Unit Tests Case"""

    @classmethod
    def setUpClass(cls):
        super(TestSegmentManagerTests, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSegmentManagerTests, cls).tearDownClass()

    def setUp(self):
        super(TestSegmentManagerTests, self).setUp()

    def test_segment_manager(self):
        """Segment manager Tests"""
        error = self.vapi.cli("test segment-manager all")

        if error:
            self.logger.critical(error)
        self.assertNotIn("failed", error)

    def tearDown(self):
        super(TestSegmentManagerTests, self).tearDown()


@tag_run_solo
class TestSvmFifoUnitTests(VppAsfTestCase):
    """SVM Fifo Unit Tests Case"""

    @classmethod
    def setUpClass(cls):
        super(TestSvmFifoUnitTests, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSvmFifoUnitTests, cls).tearDownClass()

    def setUp(self):
        super(TestSvmFifoUnitTests, self).setUp()

    def test_svm_fifo(self):
        """SVM Fifo Unit Tests"""
        error = self.vapi.cli("test svm fifo all")

        if error:
            self.logger.critical(error)
        self.assertNotIn("failed", error)

    def tearDown(self):
        super(TestSvmFifoUnitTests, self).tearDown()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
