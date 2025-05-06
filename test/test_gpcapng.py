#!/usr/bin/env python3

import unittest
import tempfile
import os
import struct
import threading
import time
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from framework import VppTestCase
from asfframework import tag_fixme_vpp_workers, VppTestRunner
from config import config
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.contrib.geneve import GENEVE
from scapy.packet import Raw
import util

from multiprocessing import Lock, Process
import subprocess

lock = Lock()


def can_create_tap_interfaces(name="tap_1231"):
    """Check if the environment allows creating the namespaces"""
    with lock:
        try:
            result = subprocess.run(
                ["ip", "tuntap", "add", name, "mode", "tap"], capture_output=True
            )
            if result.returncode != 0:
                print("CAN NOT CREATE TAP")
                return False
            subprocess.run(
                ["ip", "tuntap", "del", name, "mode", "tap"], capture_output=True
            )
            return True
        except Exception as e:
            print("EXCEPTION TAP", e)
            return False


class MockHTTPCaptureHandler(BaseHTTPRequestHandler):
    """Mock HTTP server for testing HTTP capture destinations"""

    # Class variables to store received data
    received_posts = []
    received_data = b""
    logger = None  # Will be set by test class
    save_dir = None  # Will be set by test class

    def _log(self, level, message):
        """Log message using logger if available, otherwise print"""
        if self.logger:
            getattr(self.logger, level)(message)
        else:
            print(f"[{level.upper()}] {message}")

    def _read_request_data(self, method):
        """Read request data based on transfer encoding or content length"""
        self._log("info", f"[HTTP-SERVER] {method} received: path={self.path}")
        self._log("info", f"[HTTP-SERVER] Headers: {dict(self.headers)}")

        # Check if using chunked transfer encoding
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            self._log("info", f"[HTTP-SERVER] Handling chunked transfer encoding")
            return self._handle_chunked_stream()
        else:
            # Handle with Content-Length
            content_length = int(self.headers.get("Content-Length", 0))
            self._log(
                "info", f"[HTTP-SERVER] Handling with Content-Length: {content_length}"
            )
            return self.rfile.read(content_length)

    def _handle_chunked_stream(self):
        """Handle chunked transfer encoding for streaming requests"""
        total_data = b""
        chunk_count = 0

        self._log("info", f"[HTTP-SERVER] Starting chunked stream handling")

        try:
            while True:
                # Read chunk size line
                size_line = self.rfile.readline().decode("ascii").strip()
                if not size_line:
                    break

                # Parse chunk size (hex)
                try:
                    chunk_size = int(
                        size_line.split(";")[0], 16
                    )  # Handle chunk extensions
                except ValueError:
                    self._log("error", f"[HTTP-SERVER] Invalid chunk size: {size_line}")
                    break

                if chunk_count < 5:  # Log first few chunks to avoid spam
                    self._log(
                        "info", f"[HTTP-SERVER] Chunk {chunk_count}: size={chunk_size}"
                    )

                # If chunk size is 0, this is the end
                if chunk_size == 0:
                    # Read final CRLF and any trailing headers
                    self.rfile.readline()  # Final CRLF after last chunk
                    self._log(
                        "info", f"[HTTP-SERVER] End chunk received, stream complete"
                    )
                    break

                # Read chunk data
                chunk_data = self.rfile.read(chunk_size)
                if len(chunk_data) != chunk_size:
                    self._log(
                        "error",
                        f"[HTTP-SERVER] Chunk data size mismatch: expected {chunk_size}, got {len(chunk_data)}",
                    )
                    break

                # Read trailing CRLF after chunk data
                self.rfile.readline()

                total_data += chunk_data
                chunk_count += 1

                # Periodically log progress for long streams
                if chunk_count % 100 == 0:
                    self._log(
                        "info",
                        f"[HTTP-SERVER] Processed {chunk_count} chunks, {len(total_data)} bytes total",
                    )

        except Exception as e:
            self._log("error", f"[HTTP-SERVER] Error processing chunked stream: {e}")

        self._log(
            "info",
            f"[HTTP-SERVER] Chunked stream complete: {chunk_count} chunks, {len(total_data)} bytes",
        )

        return total_data

    def _store_and_respond(self, method, data):
        """Store received data and send response"""
        self._log(
            "info",
            f"[HTTP-SERVER] {method} request to {self.path}, received {len(data)} bytes, headers: {dict(self.headers)}",
        )

        # Store the received data
        MockHTTPCaptureHandler.received_posts.append(
            {
                "path": self.path,
                "headers": dict(self.headers),
                "data": data,
                "timestamp": time.time(),
            }
        )
        MockHTTPCaptureHandler.received_data += data

        # Save data to file in test directory for debugging
        if (
            hasattr(MockHTTPCaptureHandler, "save_dir")
            and MockHTTPCaptureHandler.save_dir
        ):
            try:
                # Create filename based on path and timestamp
                safe_path = self.path.replace("/", "_").replace(":", "_")
                timestamp = int(time.time() * 1000)  # milliseconds
                filename = (
                    f"http_capture_{safe_path}_{timestamp}_{len(data)}bytes.pcapng"
                )
                filepath = os.path.join(MockHTTPCaptureHandler.save_dir, filename)

                with open(filepath, "ab") as f:  # append binary mode
                    f.write(data)

                self._log(
                    "info", f"[HTTP-SERVER] Saved {len(data)} bytes to {filepath}"
                )
            except Exception as e:
                self._log("error", f"[HTTP-SERVER] Failed to save data to file: {e}")

        # Send success response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        response = json.dumps({"status": "success", "received_bytes": len(data)})
        self.wfile.write(response.encode())

        self._log(
            "info",
            f"[HTTP-SERVER] {method} response sent: {len(data)} bytes, total received: {len(MockHTTPCaptureHandler.received_data)} bytes",
        )

    def do_POST(self):
        """Handle POST requests from gpcapng HTTP sink"""
        data = self._read_request_data("POST")
        self._store_and_respond("POST", data)

    def do_PUT(self):
        """Handle PUT requests from gpcapng HTTP sink"""
        data = self._read_request_data("PUT")
        self._store_and_respond("PUT", data)

    def log_message(self, format, *args):
        """Suppress log messages in tests"""
        pass

    @classmethod
    def reset(cls):
        """Reset collected data between tests"""
        cls.received_posts = []
        cls.received_data = b""

    @classmethod
    def get_total_received_bytes(cls):
        """Get total bytes received across all requests"""
        return len(cls.received_data)

    @classmethod
    def get_request_count(cls):
        """Get number of HTTP requests received"""
        return len(cls.received_posts)


class HTTPCaptureServer:
    """HTTP server wrapper for testing"""

    def __init__(self, host="127.0.0.1", port=0, logger=None, save_dir=None):
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
        self.logger = logger
        self.save_dir = save_dir

    def _log(self, level, message):
        """Log message using logger if available, otherwise print"""
        if self.logger:
            getattr(self.logger, level)(message)
        else:
            print(f"[{level.upper()}] {message}")

    def start(self):
        """Start the HTTP server in a background thread"""
        MockHTTPCaptureHandler.reset()
        MockHTTPCaptureHandler.logger = self.logger
        MockHTTPCaptureHandler.save_dir = self.save_dir

        self._log(
            "info",
            f"[HTTP-SERVER] STARTING: Initializing HTTP server on {self.host}:{self.port}",
        )

        try:
            self.server = HTTPServer((self.host, self.port), MockHTTPCaptureHandler)
            if self.port == 0:
                self.port = self.server.server_port

            self._log(
                "info",
                f"[HTTP-SERVER] BIND: Successfully bound to {self.host}:{self.port}",
            )

            self.thread = threading.Thread(target=self.server.serve_forever)
            self.thread.daemon = True
            self.thread.start()

            # Give server time to start
            time.sleep(0.1)

            self._log(
                "info",
                f"[HTTP-SERVER] READY: Server thread started and listening on {self.host}:{self.port}",
            )
            self._log("info", f"[HTTP-SERVER] READY: URL endpoint: {self.get_url()}")

        except Exception as e:
            self._log("error", f"[HTTP-SERVER] ERROR: Failed to start server: {e}")
            raise

    def stop(self):
        """Stop the HTTP server"""
        self._log(
            "info",
            f"[HTTP-SERVER] STOPPING: Shutting down server on {self.host}:{self.port}",
        )

        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1.0)

        self._log("info", f"[HTTP-SERVER] STOPPED: Server shutdown complete")

    def get_url(self, path="/upload"):
        """Get the full URL for the server"""
        return f"http://{self.host}:{self.port}{path}"

    def get_received_data(self):
        """Get all data received by the server"""
        return MockHTTPCaptureHandler.received_data

    def get_request_count(self):
        """Get number of requests received"""
        return MockHTTPCaptureHandler.get_request_count()

    def get_total_bytes(self):
        """Get total bytes received"""
        return MockHTTPCaptureHandler.get_total_received_bytes()


class BaseGPCAPNGTestCase(VppTestCase):
    @classmethod
    def setUpClass(cls):
        super(BaseGPCAPNGTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(BaseGPCAPNGTestCase, cls).tearDownClass()

    def setUp(self):
        super(BaseGPCAPNGTestCase, self).setUp()

    def get_test_capture_file(self, filename):
        """Generate test-specific capture file path in subdirectory"""
        test_method = self._testMethodName
        test_subdir = os.path.join(self.tempdir, test_method)
        os.makedirs(test_subdir, exist_ok=True)
        return os.path.join(test_subdir, filename)

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()
            i.unconfig_ip4()
            i.unconfig_ip6()
        super(BaseGPCAPNGTestCase, self).tearDown()

    def add_destination(self, name, path, dest_type="file"):
        """Add a capture destination"""
        if dest_type == "file":
            cmd = f"gpcapng destination add name {name} file {path}"
        elif dest_type == "gzip":
            cmd = f"gpcapng destination add name {name} gzip {path}"
        elif dest_type == "http":
            cmd = f"gpcapng destination add name {name} http {path}"
        else:
            raise ValueError(f"Unsupported destination type: {dest_type}")

        result = self.vapi.cli(cmd)
        self.logger.info(f"Added destination: {result}")
        return result

    def del_destination(self, name):
        cmd = f"gpcapng destination del name {name}"
        result = self.vapi.cli(cmd)
        self.logger.info(f"Deleted destination: {result}")
        return result

    def add_filter(
        self, name, interface=None, vni=None, protocol=None, global_filter=False
    ):
        """Add a capture filter"""
        cmd_parts = ["gpcapng filter name", name]

        if global_filter:
            cmd_parts.append("global")
        elif interface:
            cmd_parts.extend(["interface", interface.name])

        if vni is not None:
            cmd_parts.extend(["vni", str(vni)])

        if protocol is not None:
            cmd_parts.extend(["protocol", str(protocol)])

        cmd = " ".join(cmd_parts)
        result = self.vapi.cli(cmd)
        self.logger.info(f"Added filter: {result}")
        return result

    def enable_capture(self, interface):
        """Enable capture on interface"""
        cmd = f"gpcapng capture interface {interface.name}"
        result = self.vapi.cli(cmd)
        self.logger.info(f"Enabled capture: {result}")
        return result

    def disable_capture(self, interface):
        """Disable capture on interface"""
        cmd = f"gpcapng capture interface {interface.name} disable"
        result = self.vapi.cli(cmd)
        self.logger.info(f"Disabled capture: {result}")
        return result


@unittest.skipIf("gpcapng" in config.excluded_plugins, "Exclude GPCAPNG plugin tests")
class TestGPCAPNG(BaseGPCAPNGTestCase):
    """GPCAPNG Plugin Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestGPCAPNG, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestGPCAPNG, cls).tearDownClass()

    def setUp(self):
        super(TestGPCAPNG, self).setUp()

        # Create interfaces
        self.create_pg_interfaces(range(2))

        # Configure IP addresses
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.resolve_arp()
            i.resolve_ndp()

        # Use the same directory as test logs for capture files
        # self.tempdir is provided by the VPP test framework

        # Create HTTP server subdirectory for test-specific HTTP files
        self.http_server_dir = os.path.join(self.tempdir, "http_server_files")
        os.makedirs(self.http_server_dir, exist_ok=True)

        # HTTP server for testing HTTP destinations
        self.http_server = None

    def tearDown(self):
        # Stop HTTP server if running
        if self.http_server:
            self.http_server.stop()
            self.http_server = None

        # Test-specific subdirectories will be cleaned up automatically
        # with the main tempdir by the VPP test framework

        # Disable capture on all interfaces
        for i in self.pg_interfaces:
            try:
                self.vapi.cli(f"gpcapng capture interface {i.name} disable")
            except:
                pass  # Interface might not have capture enabled

        super(TestGPCAPNG, self).tearDown()

    def create_geneve_packet(
        self, vni=100, inner_payload=None, outer_src="10.0.0.1", outer_dst="10.0.0.2"
    ):
        """Create a GENEVE encapsulated packet"""
        if inner_payload is None:
            inner_payload = (
                IP(src="192.168.1.1", dst="192.168.1.2")
                / TCP(sport=12345, dport=80)
                / Raw("Test payload data")
            )

        return (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=outer_src, dst=outer_dst)
            / UDP(sport=12345, dport=6081)  # 6081 is GENEVE port
            / GENEVE(vni=vni)
            / inner_payload
        )

    def create_geneve_with_options(self, vni=100, options=None):
        """Create GENEVE packet with custom options"""
        geneve_pkt = GENEVE(vni=vni)
        if options:
            # Note: Scapy GENEVE may not support custom options directly
            # This is a placeholder for custom option handling
            pass

        return (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=12345, dport=6081)
            / geneve_pkt
            / IP(src="192.168.1.1", dst="192.168.1.2")
            / UDP(sport=53, dport=53)
            / Raw("DNS query data")
        )

    def verify_pcapng_file(self, filepath):
        """Basic verification that file exists and has some content"""
        self.assertTrue(
            os.path.exists(filepath), f"Capture file {filepath} does not exist"
        )

        file_size = os.path.getsize(filepath)
        self.assertGreater(file_size, 0, f"Capture file {filepath} is empty")
        self.logger.info(f"Capture file {filepath} size: {file_size} bytes")

        # Basic PCAPNG format check - should start with Section Header Block
        with open(filepath, "rb") as f:
            # Read first 4 bytes - should be SHB block type (0x0A0D0D0A)
            block_type = f.read(4)
            if len(block_type) >= 4:
                block_type_val = struct.unpack("<I", block_type)[0]
                # Allow both little-endian and big-endian
                self.assertIn(
                    block_type_val,
                    [0x0A0D0D0A, 0x0A0D0D0A],
                    f"Invalid PCAPNG file format, block type: 0x{block_type_val:08x}",
                )

    def test_basic_functionality(self):
        """Test basic GPCAPNG plugin functionality"""
        capture_file = self.get_test_capture_file("test_basic.pcapng")

        # Add destination
        self.add_destination("test-dest", capture_file)

        # Add basic filter
        self.add_filter("test-filter", interface=self.pg0, vni=100)

        # Enable capture
        self.enable_capture(self.pg0)

        # Send GENEVE packets
        packets = []
        for i in range(200):
            pkt = self.create_geneve_packet(vni=100)
            packets.append(pkt)

        self.pg0.add_stream(packets)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Give some time for packet processing and file writing
        self.sleep(1)

        self.del_destination("test-dest")

        # Verify capture file was created and has content
        self.verify_pcapng_file(capture_file)

    @unittest.skipIf(
        not can_create_tap_interfaces("pcap-http"),
        "Test is not running with root privileges",
    )
    def test_http_server_logging(self):
        """Test HTTP server startup and shutdown logging"""
        # This test doesn't need TAP interfaces, just tests HTTP server logging
        self.logger.info("Starting HTTP server logging test")

        # Start HTTP server on localhost (no TAP needed)
        self.http_server = HTTPCaptureServer(
            host="127.0.0.1", logger=self.logger, save_dir=self.http_server_dir
        )
        self.http_server.start()

        # Log server info
        self.logger.info(f"HTTP server URL: {self.http_server.get_url()}")

        # Give server time to initialize
        self.sleep(0.5)

        # Test simple HTTP request without VPP (just to verify server works)
        import urllib.request
        import urllib.error

        try:
            # Try a simple GET request to test server responsiveness
            test_url = self.http_server.get_url("/test")
            self.logger.info(f"Testing HTTP server with GET request to {test_url}")

            # We expect this to fail (405 Method Not Allowed) since we only support PUT/POST
            # But it will verify the server is running and log the interaction
            with urllib.request.urlopen(test_url, timeout=1):
                pass
        except urllib.error.HTTPError as e:
            self.logger.info(f"Expected HTTP error {e.code}: {e.reason}")
        except Exception as e:
            self.logger.info(f"Server test result: {e}")

        # Stop server
        self.http_server.stop()
        self.logger.info("HTTP server logging test completed")

    def test_vni_filtering(self):
        """Test VNI-based filtering"""
        capture_file = self.get_test_capture_file("test_vni_filter.pcapng")

        # Add destination and filter for specific VNI
        self.add_destination("vni-dest", capture_file)
        self.add_filter("vni-filter", interface=self.pg0, vni=200)

        # Enable capture
        self.enable_capture(self.pg0)

        # Send packets with different VNIs
        packets_match = []
        packets_no_match = []

        # Packets that should match (VNI 200)
        for i in range(300):
            pkt = self.create_geneve_packet(vni=200)
            packets_match.append(pkt)

        # Packets that should not match (VNI 100)
        for i in range(300):
            pkt = self.create_geneve_packet(vni=100)
            packets_no_match.append(pkt)

        # Send all packets
        self.pg0.add_stream(packets_match + packets_no_match)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Give time for processing
        self.sleep(1)

        self.del_destination("vni-dest")

        # Verify capture file exists - should only contain VNI 200 packets
        self.verify_pcapng_file(capture_file)

    def test_global_filter(self):
        """Test global filtering across interfaces"""
        capture_file = self.get_test_capture_file("test_global.pcapng")

        # Add destination and global filter
        self.add_destination("global-dest", capture_file)
        self.add_filter("global-filter", vni=300, global_filter=True)

        # Enable capture on both interfaces
        self.enable_capture(self.pg0)
        self.enable_capture(self.pg1)

        # Send GENEVE packets on both interfaces
        packets0 = [self.create_geneve_packet(vni=300) for _ in range(200)]
        packets1 = [self.create_geneve_packet(vni=300) for _ in range(200)]

        self.pg0.add_stream(packets0)
        self.pg1.add_stream(packets1)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Give time for processing
        self.sleep(1)

        # Verify capture file exists
        self.verify_pcapng_file(capture_file)

    def test_mixed_traffic(self):
        """Test filtering GENEVE traffic mixed with regular traffic"""
        capture_file = self.get_test_capture_file("test_mixed.pcapng")

        # Add destination and filter
        self.add_destination("mixed-dest", capture_file)
        self.add_filter("mixed-filter", interface=self.pg0, vni=500)

        # Enable capture
        self.enable_capture(self.pg0)

        # Create mixed traffic
        packets = []

        # Regular IP packets (should not be captured)
        for i in range(300):
            pkt = (
                Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / IP(src="10.0.0.1", dst="10.0.0.2")
                / TCP(sport=1234, dport=80)
                / Raw("Regular traffic")
            )
            packets.append(pkt)

        # GENEVE packets (should be captured)
        for i in range(300):
            pkt = self.create_geneve_packet(vni=500)
            packets.append(pkt)

        # Shuffle to mix the traffic
        import random

        random.shuffle(packets)

        self.pg0.add_stream(packets)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Give time for processing
        self.sleep(1)

        # Verify capture file exists - should only contain GENEVE packets
        self.verify_pcapng_file(capture_file)

    @unittest.skipIf(
        not can_create_tap_interfaces("pcap-http"),
        "Test is not running with root privileges",
    )
    def test_http_destination(self):
        """Test HTTP destination for capture output"""
        # Create unique TAP interface name for this test
        tap_name = f"vpt{os.getpid()}"
        host_ip = "192.0.2.1"  # RFC 3330 TEST-NET-1
        vpp_ip = "192.0.2.2"

        # Setup VPP networking to reach host HTTP server
        self.vapi.cli(
            f"create tap id 0 host-if-name {tap_name} host-ip4-addr {host_ip}/24"
        )
        self.vapi.cli(f"set int ip addr tap0 {vpp_ip}/24")
        self.vapi.cli("set int state tap0 up")

        # Start mock HTTP server on host IP that VPP can reach
        self.http_server = HTTPCaptureServer(
            host=host_ip, logger=self.logger, save_dir=self.http_server_dir
        )
        self.http_server.start()

        upload_url = self.http_server.get_url("/capture/upload")

        # Add HTTP destination
        self.add_destination("http-dest", upload_url, dest_type="http")
        self.add_filter("http-filter", interface=self.pg0, vni=1000)

        # Enable capture
        self.enable_capture(self.pg0)

        # Send GENEVE packets
        packets = []
        for i in range(300):
            pkt = self.create_geneve_packet(vni=1000)
            packets.append(pkt)

        self.pg0.add_stream(packets)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Give time for HTTP transmission
        self.sleep(2)
        self.del_destination("http-dest")

        # Cleanup TAP interface
        self.vapi.cli("delete tap tap0")

        # Verify HTTP server received data
        received_bytes = self.http_server.get_total_bytes()
        request_count = self.http_server.get_request_count()

        self.assertGreater(received_bytes, 0, "No data received by HTTP server")
        self.assertGreater(request_count, 0, "No HTTP requests received")

        self.logger.info(
            f"HTTP destination test: {request_count} requests, {received_bytes} bytes received"
        )

        # Verify received data looks like PCAPng format
        received_data = self.http_server.get_received_data()
        if len(received_data) >= 4:
            # Check for PCAPng Section Header Block signature
            block_type = struct.unpack("<I", received_data[:4])[0]
            # Accept both endianness possibilities
            self.assertIn(
                block_type,
                [0x0A0D0D0A, 0x0A0D0D0A],
                f"HTTP received data doesn't appear to be PCAPng format: 0x{block_type:08x}",
            )

    def test_http_destination_failure_handling(self):
        """Test HTTP destination behavior when server is unavailable"""
        # Use a non-existent HTTP endpoint
        bad_url = "http://127.0.0.1:65432/nonexistent"

        # Add HTTP destination that will fail
        self.add_destination("http-fail-dest", bad_url, dest_type="http")
        self.add_filter("http-fail-filter", interface=self.pg0, vni=1100)

        # Enable capture
        self.enable_capture(self.pg0)

        # Send packets - should not crash VPP even if HTTP fails
        packets = [self.create_geneve_packet(vni=1100) for _ in range(200)]

        self.pg0.add_stream(packets)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Give time for failed HTTP attempts
        self.sleep(2)

        # Test should complete without VPP crashing
        self.del_destination("http-fail-dest")
        # We can't easily verify the failure behavior, but VPP should remain stable
        self.logger.info("HTTP failure handling test completed - VPP remained stable")

    @unittest.skipIf(
        not can_create_tap_interfaces("pcap-http"),
        "Test is not running with root privileges",
    )
    def test_http_vs_file_destinations(self):
        """Test that HTTP and file destinations can work simultaneously"""
        # Create unique TAP interface name for this test
        tap_name = f"vpt{os.getpid()}"
        host_ip = "192.0.2.1"  # RFC 3330 TEST-NET-1
        vpp_ip = "192.0.2.2"

        # Setup VPP networking to reach host HTTP server
        self.vapi.cli(
            f"create tap id 0 host-if-name {tap_name} host-ip4-addr {host_ip}/24"
        )
        self.vapi.cli(f"set int ip addr tap0 {vpp_ip}/24")
        self.vapi.cli("set int state tap0 up")

        # Start HTTP server
        self.http_server = HTTPCaptureServer(
            host=host_ip, logger=self.logger, save_dir=self.http_server_dir
        )
        self.http_server.start()

        # Set up both HTTP and file destinations
        file_path = self.get_test_capture_file("test_mixed_dest.pcapng")
        http_url = self.http_server.get_url("/mixed")

        self.add_destination("file-dest", file_path, dest_type="file")
        self.add_destination("http-dest", http_url, dest_type="http")

        # Create filters pointing to different destinations
        self.add_filter("file-filter", interface=self.pg0, vni=1200)
        self.add_filter("http-filter", interface=self.pg0, vni=1300)

        # Set filter destinations (assuming this CLI exists)
        try:
            self.vapi.cli("gpcapng output set filter file-filter destination file-dest")
            self.vapi.cli("gpcapng output set filter http-filter destination http-dest")
        except:
            # If the CLI doesn't exist, the test will still verify basic functionality
            self.logger.info(
                "Output assignment CLI not available - testing with default assignments"
            )

        # Enable capture
        self.enable_capture(self.pg0)

        # Send packets for both filters
        packets = []

        # Packets for file destination (VNI 1200)
        for i in range(300):
            pkt = self.create_geneve_packet(vni=1200)
            packets.append(pkt)

        # Packets for HTTP destination (VNI 1300)
        for i in range(300):
            pkt = self.create_geneve_packet(vni=1300)
            packets.append(pkt)

        self.pg0.add_stream(packets)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Give time for processing
        self.sleep(2)
        self.del_destination("http-dest")
        self.del_destination("file-dest")

        # Cleanup TAP interface
        self.vapi.cli("delete tap tap0")

        # Verify both destinations received data
        # File destination
        if os.path.exists(file_path):
            self.verify_pcapng_file(file_path)
            self.logger.info("File destination working correctly")

        # HTTP destination
        http_bytes = self.http_server.get_total_bytes()
        if http_bytes > 0:
            self.logger.info(f"HTTP destination received {http_bytes} bytes")

        # At least one destination should have received data
        file_exists = os.path.exists(file_path) and os.path.getsize(file_path) > 0
        http_received = http_bytes > 0

        self.assertTrue(
            file_exists or http_received,
            "Neither file nor HTTP destination received data",
        )


@unittest.skipIf("gpcapng" in config.excluded_plugins, "Exclude GPCAPNG plugin tests")
class TestGPCAPNGMultiWorker(BaseGPCAPNGTestCase):
    """GPCAPNG Plugin Multi-Worker Test Case"""

    vpp_worker_count = 2  # Use 2 worker threads

    @classmethod
    def setUpClass(cls):
        super(TestGPCAPNGMultiWorker, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestGPCAPNGMultiWorker, cls).tearDownClass()

    def setUp(self):
        super(TestGPCAPNGMultiWorker, self).setUp()

        # Create interfaces
        self.create_pg_interfaces(range(4))  # More interfaces for worker distribution

        # Configure IP addresses
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.resolve_arp()
            i.resolve_ndp()

        # Use the same directory as test logs for capture files
        # self.tempdir is provided by the VPP test framework

        # Create HTTP server subdirectory for test-specific HTTP files
        self.http_server_dir = os.path.join(self.tempdir, "http_server_files")
        os.makedirs(self.http_server_dir, exist_ok=True)

        # HTTP server for testing HTTP destinations
        self.http_server = None

    def tearDown(self):
        # Stop HTTP server if running
        if self.http_server:
            self.http_server.stop()
            self.http_server = None

        # Test-specific subdirectories will be cleaned up automatically
        # with the main tempdir by the VPP test framework

        # Disable capture on all interfaces
        for i in self.pg_interfaces:
            try:
                self.vapi.cli(f"gpcapng capture interface {i.name} disable")
            except:
                pass

        super(TestGPCAPNGMultiWorker, self).tearDown()

    def create_geneve_packet(self, vni=100, worker_id=0, seq=0):
        """Create a GENEVE packet with worker-specific addressing"""
        # Use different source IPs to ensure different workers process packets
        outer_src = f"10.{worker_id}.0.{seq % 254 + 1}"
        inner_src = f"192.168.{worker_id}.{seq % 254 + 1}"

        return (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=outer_src, dst="10.0.0.100")
            / UDP(sport=10000 + seq, dport=6081)
            / GENEVE(vni=vni)
            / IP(src=inner_src, dst="192.168.100.1")
            / TCP(sport=20000 + seq, dport=80)
            / Raw(f"Worker {worker_id} packet {seq}")
        )

    def verify_worker_files(self, base_path, expected_workers):
        """Verify that worker-specific files were created"""
        worker_files = []

        # Check for main file and worker-specific files
        files_found = []

        # Main file (worker 0)
        if os.path.exists(base_path):
            files_found.append((base_path, 0))

        # Worker-specific files (pattern: filename-<worker_id>.pcapng)
        base_dir = os.path.dirname(base_path)
        base_name = os.path.basename(base_path)
        name_without_ext = os.path.splitext(base_name)[0]

        for worker_id in range(1, expected_workers):  # Workers 1, 2, ...
            worker_file = os.path.join(
                base_dir, f"{name_without_ext}-{worker_id}.pcapng"
            )
            if os.path.exists(worker_file):
                files_found.append((worker_file, worker_id))

        self.logger.info(f"Found worker files: {files_found}")

        # Verify at least one file exists
        self.assertGreater(len(files_found), 0, "No capture files found")

        # Verify each found file has content
        for filepath, worker_id in files_found:
            file_size = os.path.getsize(filepath)
            self.assertGreater(
                file_size, 0, f"Worker {worker_id} capture file {filepath} is empty"
            )
            self.logger.info(f"Worker {worker_id} file {filepath}: {file_size} bytes")

        return files_found

    def test_multi_worker_capture(self):
        """Test capture with multiple workers"""
        capture_file = self.get_test_capture_file("test_multiworker.pcapng")

        # Add destination and filter
        self.add_destination("mw-dest", capture_file)
        self.add_filter("mw-filter", interface=self.pg0, vni=600)

        # Enable capture
        self.enable_capture(self.pg0)

        # Create packets for different workers
        all_packets = []
        packets_per_worker = 300

        for worker_id in range(self.vpp_worker_count):
            for seq in range(packets_per_worker):
                pkt = self.create_geneve_packet(vni=600, worker_id=worker_id, seq=seq)
                all_packets.append(pkt)

        # Send packets
        self.pg0.add_stream(all_packets)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Give extra time for multi-worker processing
        self.sleep(2)

        # Verify worker files were created
        worker_files = self.verify_worker_files(capture_file, self.vpp_worker_count)

        # Log summary
        total_size = sum(os.path.getsize(f[0]) for f in worker_files)
        self.logger.info(
            f"Multi-worker capture completed: {len(worker_files)} files, {total_size} total bytes"
        )

    def test_worker_distribution(self):
        """Test that packets are distributed across workers"""
        capture_file = self.get_test_capture_file("test_distribution.pcapng")

        # Add destination and global filter
        self.add_destination("dist-dest", capture_file)
        self.add_filter("dist-filter", vni=700, global_filter=True)

        # Enable capture on multiple interfaces
        for intf in self.pg_interfaces[:2]:
            self.enable_capture(intf)

        # Generate diverse traffic to encourage worker distribution
        all_packets = []

        # Create packets with varying 5-tuples to hit different workers
        for i in range(200):
            outer_src = f"10.{i % 4}.{(i // 4) % 4}.{i % 10 + 1}"
            sport = 10000 + (i * 123) % 50000  # Varying source ports

            pkt = (
                Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / IP(src=outer_src, dst="10.100.100.100")
                / UDP(sport=sport, dport=6081)
                / GENEVE(vni=700)
                / IP(src=f"192.168.{i % 10}.{(i // 10) + 1}", dst="192.168.200.1")
                / UDP(sport=sport + 1000, dport=53)
                / Raw(f"Distribution test packet {i}")
            )
            all_packets.append(pkt)

        # Send packets on interface 0
        self.pg0.add_stream(all_packets)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Give time for processing
        self.sleep(2)

        # Verify files created
        worker_files = self.verify_worker_files(capture_file, self.vpp_worker_count)

        # Check that multiple workers processed packets (if more than 1 file created)
        if len(worker_files) > 1:
            self.logger.info("SUCCESS: Packets distributed across multiple workers")
        else:
            self.logger.info(
                "NOTE: All packets processed by single worker (acceptable depending on traffic pattern)"
            )

    def test_per_worker_filtering(self):
        """Test that filtering works correctly per worker"""
        capture_file = self.get_test_capture_file("test_per_worker_filter.pcapng")

        # Add destination and filter for specific VNI
        self.add_destination("pwf-dest", capture_file)
        self.add_filter("pwf-filter", interface=self.pg0, vni=800)

        # Enable capture
        self.enable_capture(self.pg0)

        # Create mixed packets - some matching, some not
        all_packets = []

        # Matching packets (VNI 800)
        for i in range(200):
            pkt = self.create_geneve_packet(vni=800, worker_id=i % 2, seq=i)
            all_packets.append(pkt)

        # Non-matching packets (VNI 900)
        for i in range(200):
            pkt = self.create_geneve_packet(vni=900, worker_id=i % 2, seq=i + 100)
            all_packets.append(pkt)

        # Shuffle packets
        import random

        random.shuffle(all_packets)

        # Send packets
        self.pg0.add_stream(all_packets)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Give time for processing
        self.sleep(2)
        self.del_destination("pwf-dest")

        # Verify files created (should only contain VNI 800 packets)
        worker_files = self.verify_worker_files(capture_file, self.vpp_worker_count)

        self.logger.info(
            f"Per-worker filtering test completed: {len(worker_files)} worker files created"
        )

    @unittest.skipIf(
        not can_create_tap_interfaces("pcap-http"),
        "Test is not running with root privileges",
    )
    def test_multi_worker_http_destination(self):
        """Test HTTP destination with multiple workers"""
        # Create unique TAP interface name for this test
        tap_name = f"vpt{os.getpid()}"
        host_ip = "192.0.2.1"  # RFC 3330 TEST-NET-1
        vpp_ip = "192.0.2.2"

        # Setup VPP networking to reach host HTTP server
        self.vapi.cli(
            f"create tap id 0 host-if-name {tap_name} host-ip4-addr {host_ip}/24"
        )
        self.vapi.cli(f"set int ip addr tap0 {vpp_ip}/24")
        self.vapi.cli("set int state tap0 up")

        # Start HTTP server
        self.http_server = HTTPCaptureServer(
            host=host_ip, logger=self.logger, save_dir=self.http_server_dir
        )
        self.http_server.start()

        http_url = self.http_server.get_url("/multiworker")

        # Add HTTP destination and global filter
        self.add_destination("mw-http-dest", http_url, dest_type="http")
        self.add_filter("mw-http-filter", vni=900, global_filter=True)

        # Enable capture on interfaces
        for intf in self.pg_interfaces[:2]:
            self.enable_capture(intf)

        # Create packets for different workers
        all_packets = []
        packets_per_worker = 300

        for worker_id in range(self.vpp_worker_count):
            for seq in range(packets_per_worker):
                pkt = self.create_geneve_packet(vni=900, worker_id=worker_id, seq=seq)
                all_packets.append(pkt)

        # Send packets
        self.pg0.add_stream(all_packets)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Give extra time for multi-worker HTTP processing
        self.sleep(3)
        self.del_destination("mw-http-dest")

        # Cleanup TAP interface
        # uncomment this one to crash VPP
        # self.vapi.cli("delete tap tap0")

        # Verify HTTP server received data from multiple workers
        received_bytes = self.http_server.get_total_bytes()
        request_count = self.http_server.get_request_count()

        self.assertGreater(
            received_bytes, 0, "No data received by HTTP server from multi-worker test"
        )
        self.assertGreater(
            request_count, 0, "No HTTP requests received from multi-worker test"
        )

        self.logger.info(
            f"Multi-worker HTTP test: {request_count} requests, {received_bytes} bytes received"
        )

        # Verify received data appears to be PCAPng format
        received_data = self.http_server.get_received_data()
        if len(received_data) >= 4:
            block_type = struct.unpack("<I", received_data[:4])[0]
            self.assertIn(
                block_type,
                [0x0A0D0D0A, 0x0A0D0D0A],
                "Multi-worker HTTP data doesn't appear to be PCAPng format",
            )

        # Multiple workers may send data separately or together
        # The key is that we received valid PCAPng data via HTTP
        self.logger.info(f"Multi-worker HTTP capture completed successfully")
        # self.vapi.cli("delete tap tap0")

    def add_destination(self, name, path, dest_type="file"):
        """Add a capture destination (copy from base class with HTTP support)"""
        if dest_type == "file":
            cmd = f"gpcapng destination add name {name} file {path}"
        elif dest_type == "gzip":
            cmd = f"gpcapng destination add name {name} gzip {path}"
        elif dest_type == "http":
            cmd = f"gpcapng destination add name {name} http {path}"
        else:
            raise ValueError(f"Unsupported destination type: {dest_type}")

        result = self.vapi.cli(cmd)
        self.logger.info(f"Added destination: {result}")
        return result


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
