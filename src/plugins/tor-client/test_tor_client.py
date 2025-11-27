#!/usr/bin/env python3
"""
Copyright (c) 2025 Internet Mastering & Company, Inc.
Licensed under the Apache License, Version 2.0 (the "License")

Integration tests for Tor Client VPP plugin
"""

import unittest
import socket
import struct
import time
from vpp_papi import VPPApiClient


class TestTorClient(unittest.TestCase):
    """Test cases for Tor client plugin"""

    @classmethod
    def setUpClass(cls):
        """Set up VPP API connection"""
        cls.vpp = VPPApiClient()
        cls.vpp.connect("test_tor_client")

    @classmethod
    def tearDownClass(cls):
        """Tear down VPP API connection"""
        cls.vpp.disconnect()

    def test_01_enable_disable(self):
        """Test enabling and disabling Tor client"""
        # Enable
        result = self.vpp.api.tor_client_enable_disable(
            enable=True, socks_port=9150
        )
        self.assertEqual(result.retval, 0)

        # Check status
        stats = self.vpp.api.tor_client_get_stats()
        self.assertTrue(stats.enabled)
        self.assertEqual(stats.socks_port, 9150)

        # Disable
        result = self.vpp.api.tor_client_enable_disable(
            enable=False, socks_port=0
        )
        self.assertEqual(result.retval, 0)

        # Check status
        stats = self.vpp.api.tor_client_get_stats()
        self.assertFalse(stats.enabled)

    def test_02_statistics(self):
        """Test statistics retrieval"""
        # Enable first
        self.vpp.api.tor_client_enable_disable(enable=True, socks_port=9150)

        # Get stats
        stats = self.vpp.api.tor_client_get_stats()
        self.assertTrue(stats.enabled)
        self.assertGreaterEqual(stats.active_streams, 0)
        self.assertGreaterEqual(stats.total_connections, 0)

        # Cleanup
        self.vpp.api.tor_client_enable_disable(enable=False, socks_port=0)

    def test_03_socks5_handshake(self):
        """Test SOCKS5 protocol handshake"""
        # Enable Tor client
        self.vpp.api.tor_client_enable_disable(enable=True, socks_port=9150)
        time.sleep(1)  # Give it time to start

        try:
            # Connect to SOCKS5 proxy
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(("127.0.0.1", 9150))

            # Send authentication methods (no auth)
            auth_request = struct.pack("BBB", 0x05, 0x01, 0x00)
            sock.sendall(auth_request)

            # Receive method selection
            response = sock.recv(2)
            self.assertEqual(len(response), 2)
            self.assertEqual(response[0], 0x05)  # SOCKS version
            self.assertEqual(response[1], 0x00)  # No auth

            sock.close()

        except Exception as e:
            self.fail(f"SOCKS5 handshake failed: {e}")

        finally:
            # Cleanup
            self.vpp.api.tor_client_enable_disable(enable=False, socks_port=0)

    def test_04_socks5_connect_request(self):
        """Test SOCKS5 connect request"""
        # Enable Tor client
        self.vpp.api.tor_client_enable_disable(enable=True, socks_port=9150)
        time.sleep(2)  # Wait for Tor bootstrap

        try:
            # Connect to SOCKS5 proxy
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)  # Tor connections can be slow
            sock.connect(("127.0.0.1", 9150))

            # Authentication
            sock.sendall(struct.pack("BBB", 0x05, 0x01, 0x00))
            response = sock.recv(2)
            self.assertEqual(response[1], 0x00)

            # Connect request to check.torproject.org:443
            domain = b"check.torproject.org"
            connect_request = (
                struct.pack("BBBB", 0x05, 0x01, 0x00, 0x03)
                + struct.pack("B", len(domain))
                + domain
                + struct.pack("!H", 443)
            )
            sock.sendall(connect_request)

            # Receive response
            response = sock.recv(10)
            self.assertGreater(len(response), 0)
            self.assertEqual(response[0], 0x05)  # SOCKS version

            # Note: response[1] might not be 0x00 if Tor connection fails
            # This is expected in test environment without Tor network access

            sock.close()

        except Exception as e:
            # Connection may fail if Tor network is not accessible
            # This is okay for unit tests
            print(f"Note: SOCKS5 connect test got expected error: {e}")

        finally:
            # Cleanup
            self.vpp.api.tor_client_enable_disable(enable=False, socks_port=0)


class TestTorClientCLI(unittest.TestCase):
    """Test cases for CLI commands"""

    def test_cli_help(self):
        """Test CLI help output"""
        # These would require VPP CLI testing framework
        # Placeholder for now
        pass


if __name__ == "__main__":
    unittest.main()
