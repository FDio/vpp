#!/usr/bin/env python3
"""
Simple Ring Buffer Test Runner

This script provides a simple way to test ring buffer functionality
using the existing VPP make test infrastructure.

Usage:
    python3 test/test_ring_buffer_simple.py

This script can be run as part of the VPP test suite or standalone.
"""

import sys
import time
import struct
from framework import VppTestCase


class TestRingBufferSimple(VppTestCase):
    """Simple Ring Buffer Test Case for Make Test Infrastructure"""

    def test_ring_buffer_basic_functionality(self):
        """Test basic ring buffer functionality"""
        import time
        import struct

        # Use a unique name for each test run to avoid reading old data
        ring_name = f"/test/ring_buffer_simple_{int(time.time())}"
        count = 50
        interval_usec = 1000
        ring_size = 64

        # Step 1: Generate messages using VPP CLI
        cli_cmd = f"test stats ring-buffer-gen {ring_name} {count} {interval_usec} {ring_size}"
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer from stats segment
        ring_buffer = self.statistics.get_ring_buffer(ring_name)

        # Step 3: Consume all messages
        received = []
        start = time.time()

        # Debug: Check initial state
        metadata = ring_buffer._get_thread_metadata(0)
        print(
            f"DEBUG: Initial metadata - head: {metadata['head']}, sequence: {metadata['sequence']}"
        )
        print(f"DEBUG: Ring size: {ring_buffer.get_config()['ring_size']}")

        while len(received) < count and (time.time() - start) < 10:
            data = ring_buffer.consume_data(thread_index=0, max_entries=10)
            print(f"DEBUG: Consumed {len(data)} entries")
            for entry in data:
                seq, ts = struct.unpack("<Qd", entry)
                received.append((seq, ts))
                if len(received) <= 5:  # Print first few entries
                    print(f"DEBUG: Entry {len(received)-1}: seq={seq}, ts={ts}")
            time.sleep(0.01)

        # Step 4: Validate results
        assert len(received) == count, f"Expected {count} messages, got {len(received)}"

        # Check sequence numbers are consecutive
        for i, (seq, ts) in enumerate(received):
            assert seq == i, f"Sequence mismatch at {i}: got {seq}, expected {i}"
            assert ts > 0, f"Timestamp should be positive, got {ts}"

        print(f"✓ Successfully received {len(received)} messages from ring buffer")

    def test_ring_buffer_batch_operations(self):
        """Test ring buffer batch operations"""
        ring_name = "/test/ring_buffer_batch_simple"
        count = 30
        interval_usec = 1000
        ring_size = 64

        # Step 1: Generate messages
        cli_cmd = f"test stats ring-buffer-gen {ring_name} {count} {interval_usec} {ring_size}"
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer
        ring_buffer = self.statistics.get_ring_buffer(ring_name)

        # Step 3: Test batch consume
        data = ring_buffer.consume_data_batch(thread_index=0, max_entries=count)

        # Step 4: Validate results
        assert len(data) == count, f"Expected {count} entries, got {len(data)}"

        # Check data format
        for i, entry in enumerate(data):
            seq, ts = struct.unpack("<Qd", entry)
            assert seq == i, f"Sequence mismatch at {i}: got {seq}, expected {i}"
            assert ts > 0, f"Timestamp should be positive, got {ts}"

        print(f"✓ Successfully received {len(data)} messages using batch operations")

    def test_ring_buffer_configuration(self):
        """Test ring buffer configuration access"""
        ring_name = "/test/ring_buffer_config_simple"
        count = 10
        interval_usec = 1000
        ring_size = 32

        # Step 1: Create ring buffer
        cli_cmd = f"test stats ring-buffer-gen {ring_name} {count} {interval_usec} {ring_size}"
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer and check configuration
        ring_buffer = self.statistics.get_ring_buffer(ring_name)
        config = ring_buffer.get_config()

        # Step 3: Validate configuration
        assert (
            config["entry_size"] == 16
        ), f"Expected entry_size 16, got {config['entry_size']}"
        assert (
            config["ring_size"] == ring_size
        ), f"Expected ring_size {ring_size}, got {config['ring_size']}"
        assert (
            config["n_threads"] == 1
        ), f"Expected n_threads 1, got {config['n_threads']}"

        # Step 4: Check metadata
        metadata = ring_buffer._get_thread_metadata(0)
        assert "head" in metadata, "Metadata should contain head"
        assert "sequence" in metadata, "Metadata should contain sequence"
        assert (
            metadata["sequence"] >= count
        ), f"Sequence should be >= {count}, got {metadata['sequence']}"

        print(f"✓ Ring buffer configuration validated: {config}")

    def test_ring_buffer_empty_operations(self):
        """Test ring buffer operations on empty buffer"""
        ring_name = "/test/ring_buffer_empty_simple"

        # Step 1: Create ring buffer without generating data
        cli_cmd = f"test stats ring-buffer-gen {ring_name} 0 1000 32"
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer
        ring_buffer = self.statistics.get_ring_buffer(ring_name)

        # Step 3: Test various operations on empty buffer
        data = ring_buffer.consume_data(thread_index=0)
        assert data == [], "Empty buffer should return empty list"

        data = ring_buffer.consume_data_batch(thread_index=0)
        assert data == [], "Empty buffer should return empty list for batch"

        data = ring_buffer.poll_for_data(thread_index=0, timeout=0.1)
        assert data == [], "Empty buffer should return empty list for poll"

        # Step 4: Check API compatibility methods
        count = ring_buffer.get_count(thread_index=0)
        is_empty = ring_buffer.is_empty(thread_index=0)
        is_full = ring_buffer.is_full(thread_index=0)

        assert count == 0, "Count should be 0 for empty buffer"
        assert is_empty == True, "Is empty should be True for empty buffer"
        assert is_full == False, "Is full should be False for empty buffer"

        print("✓ Empty buffer operations validated")

    def test_ring_buffer_error_handling(self):
        """Test ring buffer error handling"""
        ring_name = "/test/ring_buffer_error_simple"

        # Step 1: Create ring buffer
        cli_cmd = f"test stats ring-buffer-gen {ring_name} 5 1000 32"
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer
        ring_buffer = self.statistics.get_ring_buffer(ring_name)

        # Step 3: Test invalid thread index
        try:
            ring_buffer._get_thread_metadata(999)  # Invalid thread
            assert False, "Should have raised IndexError for invalid thread"
        except IndexError:
            pass  # Expected

        # Step 4: Test invalid parameters
        data = ring_buffer.consume_data(thread_index=0, max_entries=0)
        assert data == [], "Zero max_entries should return empty list"

        data = ring_buffer.consume_data(thread_index=0, max_entries=-1)
        assert data == [], "Negative max_entries should return empty list"

        print("✓ Error handling validated")


def main():
    """Main function for standalone execution"""
    import unittest

    # Create test suite
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestRingBufferSimple))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Return appropriate exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
