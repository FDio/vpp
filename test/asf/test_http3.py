#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.
"""VPP HTTP/3 malformed-frame tests.

This test sends one complete unknown frame on a fresh client-initiated
bidirectional (request) stream and then checks that VPP is still responsive
"""

import unittest
import asyncio
import socket
import ssl
import os
import tempfile

from config import config
from asfframework import VppAsfTestCase, VppTestRunner

try:
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection

    _HAVE_AIOQUIC = True
except ImportError:
    _HAVE_AIOQUIC = False


def encode_h3_varint(value):
    """Encode a QUIC/HTTP3 variable-length integer (RFC 9000 section 16)."""
    if value <= 0x3F:
        return bytes([value])
    if value <= 0x3FFF:
        return (0x4000 | value).to_bytes(2, "big")
    if value <= 0x3FFFFFFF:
        return (0x80000000 | value).to_bytes(4, "big")
    if value <= 0x3FFFFFFFFFFFFFFF:
        return (0xC000000000000000 | value).to_bytes(8, "big")
    raise ValueError("varint out of range")


@unittest.skipIf(
    "http_static" in config.excluded_plugins, "Exclude HTTP Static Server plugin tests"
)
@unittest.skipIf("quic" in config.excluded_plugins, "Exclude QUIC plugin tests")
@unittest.skipUnless(_HAVE_AIOQUIC, "aioquic is required for HTTP/3 client tests")
class TestHttp3MalformedFrame(VppAsfTestCase):
    """Malformed HTTP/3 request frame"""

    @classmethod
    def setUpClass(cls):
        super(TestHttp3MalformedFrame, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestHttp3MalformedFrame, cls).tearDownClass()

    def setUp(self):
        super(TestHttp3MalformedFrame, self).setUp()
        self.server_ip4 = "172.0.0.1"
        self.client_ip4 = "172.0.0.2"
        self.server_port = 443

        # www-root is required by the static server; give it an index file
        self.www_root = tempfile.mkdtemp()
        with open(os.path.join(self.www_root, "index.html"), "wb") as f:
            f.write(b"hello h3")

        # TAP interface: VPP owns server_ip4, the host (test process) owns client_ip4.
        # Creating a tap needs CAP_NET_ADMIN; skip (don't error) when unprivileged.
        try:
            self.vapi.cli(f"create tap id 0 host-ip4-addr {self.client_ip4}/24")
        except Exception as e:
            raise unittest.SkipTest(
                f"cannot create tap (needs root/CAP_NET_ADMIN): {e}"
            )
        self.vapi.cli(f"set int ip addr tap0 {self.server_ip4}/24")
        self.vapi.cli("set int state tap0 up")
        self.vapi.session_enable_disable(is_enable=1)
        self.vapi.cli(
            f"http static server http3 www-root {self.www_root} "
            f"uri https://0.0.0.0/{self.server_port}"
        )

    def tearDown(self):
        try:
            self.vapi.cli("session disable")
            self.vapi.cli("delete tap id 0")
        except Exception:
            pass
        super(TestHttp3MalformedFrame, self).tearDown()

    async def _connect_ipv4(self, cfg):
        # aioquic's high-level connect() forces an AF_INET6 socket; this host has
        # IPv6 disabled, so build the endpoint over an explicit IPv4 socket.
        if cfg.server_name is None:
            cfg.server_name = self.server_ip4
        loop = asyncio.get_running_loop()
        connection = QuicConnection(configuration=cfg)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", 0))
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: QuicConnectionProtocol(connection), sock=sock
        )
        protocol.connect((self.server_ip4, self.server_port), transmit=True)
        await protocol.wait_connected()
        return transport, protocol

    async def _send_unknown_frame(self):
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        # VPP presents a self-signed cert; the client does not verify it
        cfg.verify_mode = ssl.CERT_NONE
        transport, protocol = await self._connect_ipv4(cfg)
        try:
            quic = protocol._quic
            # A complete unknown HTTP/3 frame as the only data on a fresh
            # client-initiated bidirectional (request) stream:
            #   Type   = 0x21  (reserved/grease type, unknown to the server)
            #   Length = 16, Payload = 16 bytes
            unknown_type = 0x21
            payload = b"\x00" * 16
            frame = (
                encode_h3_varint(unknown_type)
                + encode_h3_varint(len(payload))
                + payload
            )
            stream_id = quic.get_next_available_stream_id(is_unidirectional=False)
            quic.send_stream_data(stream_id, frame, end_stream=True)
            protocol.transmit()
            # give the server time to process the frame (and crash/hang if buggy)
            await asyncio.sleep(2)
        finally:
            protocol.close()
            await protocol.wait_closed()
            transport.close()

    def test_http3_unknown_frame_does_not_crash_vpp(self):
        """Unknown HTTP/3 frame on a request stream keeps VPP alive"""
        asyncio.run(asyncio.wait_for(self._send_unknown_frame(), timeout=20))
        # A crashed main thread makes the API unreachable; a wedged main thread
        # (release-build hang) makes it time out. The framework's post-test
        # core-dump check is a second guard.
        self.assertIn("vpp", self.vapi.cli("show version").lower())


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
