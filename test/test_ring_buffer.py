import time
import unittest
from vpp_papi.vpp_stats import VPPStats
import struct
from framework import VppTestCase

RING_NAME = "/test/ring_buffer_pytest"
RING_SIZE = 1024
COUNT = 100
INTERVAL_USEC = 1000  # 1ms


class TestRingBuffer(VppTestCase):
    """Ring Buffer Test Case"""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super(TestRingBuffer, cls).setUpClass()

    def setUp(self):
        super(TestRingBuffer, self).setUp()

    def tearDown(self):
        super(TestRingBuffer, self).tearDown()

    def test_ring_buffer_generation(self):
        """Test ring buffer generation"""

        # Step 1: Generate messages using the VPPApiClient CLI
        cli_cmd = f"test stats ring-buffer-gen {RING_NAME} {COUNT} {INTERVAL_USEC} {RING_SIZE}"
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Connect to stats segment and get the ring buffer
        ring_buffer = self.statistics.get_ring_buffer(f"{RING_NAME}")

        # Step 3: Poll for all messages
        received = []
        start = time.time()
        while len(received) < COUNT and (time.time() - start) < 10:
            data = ring_buffer.poll_for_data(thread_index=0, timeout=0.5)
            for entry in data:
                # Unpack the struct: u64 seq, f64 timestamp
                seq, ts = struct.unpack("<Qd", entry)
                received.append((seq, ts))
            time.sleep(0.01)

        # Step 4: Validate
        assert len(received) == COUNT, f"Expected {COUNT} messages, got {len(received)}"
        for i, (seq, ts) in enumerate(received):
            assert seq == i, f"Sequence mismatch at {i}: got {seq}"
            assert ts > 0, f"Timestamp should be positive, got {ts}"

        # print(f"Received {len(received)} messages from ring buffer '{RING_NAME}'")

    def test_ring_buffer_overwrite(self):
        """Test ring buffer overwrite behavior"""
        ring_size = 16
        total_messages = 3 * ring_size
        interval_usec = 100  # Fast, to fill quickly
        ring_name = "/test/ring_buffer_overwrite"

        # Step 1: Generate more messages than the ring size
        cli_cmd = f"test stats ring-buffer-gen {ring_name} {total_messages} {interval_usec} {ring_size}"
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Ensure all messages are written before polling
        time.sleep(0.1)

        # Step 2: Connect to stats segment and get the ring buffer
        ring_buffer = self.statistics.get_ring_buffer(f"{ring_name}")

        # Step 3: Poll for all messages (should only get the last 'ring_size' messages)
        received = {}
        start = time.time()
        while len(received) < ring_size and (time.time() - start) < 10:
            data = ring_buffer.poll_for_data(thread_index=0, timeout=0.5)
            for entry in data:
                seq, ts = struct.unpack("<Qd", entry)
                if seq not in received:
                    received[seq] = ts
            time.sleep(0.01)

        # Debug: print the received sequence numbers
        print(f"Received sequence numbers: {sorted(received.keys())}")

        # Step 4: Validate
        assert (
            len(received) == ring_size
        ), f"Expected {ring_size} messages, got {len(received)}"
        expected_start = total_messages - ring_size
        for i, seq in enumerate(sorted(received)):
            ts = received[seq]
            assert (
                seq == expected_start + i
            ), f"Sequence mismatch at {i}: got {seq}, expected {expected_start + i}"
            assert ts > 0, f"Timestamp should be positive, got {ts}"
