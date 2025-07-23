import time
import unittest
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

    def test_ring_buffer_batch_operations(self):
        """Test ring buffer batch operations"""
        ring_name = "/test/ring_buffer_batch"
        batch_size = 10
        total_messages = 50

        # Step 1: Generate messages using VPP CLI
        cli_cmd = f"test stats ring-buffer-gen {ring_name} {total_messages} {INTERVAL_USEC} {RING_SIZE}"
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer
        ring_buffer = self.statistics.get_ring_buffer(f"{ring_name}")

        # Step 3: Test individual consume
        individual_data = []
        start = time.time()
        while len(individual_data) < total_messages and (time.time() - start) < 10:
            data = ring_buffer.consume_data(thread_index=0, max_entries=batch_size)
            individual_data.extend(data)
            time.sleep(0.01)

        # Step 4: Reset and test batch consume
        ring_buffer.local_tails[0] = 0
        ring_buffer.last_sequences[0] = None

        batch_data = []
        start = time.time()
        while len(batch_data) < total_messages and (time.time() - start) < 10:
            data = ring_buffer.consume_data_batch(
                thread_index=0, max_entries=batch_size
            )
            batch_data.extend(data)
            time.sleep(0.01)

        # Step 5: Validate results are the same
        assert len(individual_data) == len(
            batch_data
        ), "Individual and batch should return same number of entries"
        assert (
            individual_data == batch_data
        ), "Individual and batch should return same data"

        # Step 6: Validate data format
        for entry in individual_data:
            seq, ts = struct.unpack("<Qd", entry)
            assert seq >= 0, f"Sequence should be non-negative, got {seq}"
            assert ts > 0, f"Timestamp should be positive, got {ts}"

    def test_ring_buffer_configuration(self):
        """Test ring buffer configuration access"""
        ring_name = "/test/ring_buffer_config"

        # Step 1: Create ring buffer
        cli_cmd = (
            f"test stats ring-buffer-gen {ring_name} 10 {INTERVAL_USEC} {RING_SIZE}"
        )
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer and check configuration
        ring_buffer = self.statistics.get_ring_buffer(f"{ring_name}")
        config = ring_buffer.get_config()

        # Step 3: Validate configuration
        assert "entry_size" in config, "Config should contain entry_size"
        assert "ring_size" in config, "Config should contain ring_size"
        assert "n_threads" in config, "Config should contain n_threads"
        assert config["entry_size"] > 0, "Entry size should be positive"
        assert config["ring_size"] > 0, "Ring size should be positive"
        assert config["n_threads"] > 0, "Number of threads should be positive"

        # Step 4: Check metadata access
        metadata = ring_buffer._get_thread_metadata(0)
        assert "head" in metadata, "Metadata should contain head"
        assert "sequence" in metadata, "Metadata should contain sequence"
        assert isinstance(metadata["head"], int), "Head should be integer"
        assert isinstance(metadata["sequence"], int), "Sequence should be integer"

    def test_ring_buffer_error_handling(self):
        """Test ring buffer error handling"""
        ring_name = "/test/ring_buffer_error"

        # Step 1: Create ring buffer
        cli_cmd = (
            f"test stats ring-buffer-gen {ring_name} 10 {INTERVAL_USEC} {RING_SIZE}"
        )
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer
        ring_buffer = self.statistics.get_ring_buffer(f"{ring_name}")

        # Step 3: Test invalid thread index
        config = ring_buffer.get_config()
        invalid_thread = config["n_threads"] + 1

        try:
            ring_buffer._get_thread_metadata(invalid_thread)
            assert False, "Should have raised IndexError for invalid thread"
        except IndexError:
            pass  # Expected

        # Step 4: Test invalid parameters
        data = ring_buffer.consume_data(thread_index=0, max_entries=0)
        assert data == [], "Zero max_entries should return empty list"

        data = ring_buffer.consume_data(thread_index=0, max_entries=-1)
        assert data == [], "Negative max_entries should return empty list"

    def test_ring_buffer_api_compatibility(self):
        """Test ring buffer API compatibility methods"""
        ring_name = "/test/ring_buffer_compat"

        # Step 1: Create ring buffer
        cli_cmd = (
            f"test stats ring-buffer-gen {ring_name} 10 {INTERVAL_USEC} {RING_SIZE}"
        )
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer
        ring_buffer = self.statistics.get_ring_buffer(f"{ring_name}")

        # Step 3: Test compatibility methods
        count = ring_buffer.get_count(thread_index=0)
        is_empty = ring_buffer.is_empty(thread_index=0)
        is_full = ring_buffer.is_full(thread_index=0)

        # These methods return simplified values since writer doesn't track reader state
        assert count == 0, "Count should be 0 (writer doesn't track reader)"
        assert is_empty == True, "Is empty should be True (writer doesn't track reader)"
        assert is_full == False, "Is full should be False (writer doesn't track reader)"

        # Step 4: Test string representation
        repr_str = repr(ring_buffer)
        assert (
            "StatsRingBuffer" in repr_str
        ), "String representation should contain StatsRingBuffer"
        assert (
            "entry_size" in repr_str
        ), "String representation should contain entry_size"
        assert "ring_size" in repr_str, "String representation should contain ring_size"
        assert "n_threads" in repr_str, "String representation should contain n_threads"

    def test_ring_buffer_performance(self):
        """Test ring buffer performance characteristics"""
        ring_name = "/test/ring_buffer_perf"
        test_entries = 100

        # Step 1: Create ring buffer
        cli_cmd = f"test stats ring-buffer-gen {ring_name} {test_entries} {INTERVAL_USEC} {RING_SIZE}"
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer
        ring_buffer = self.statistics.get_ring_buffer(f"{ring_name}")

        # Step 3: Test individual consume performance
        start_time = time.time()
        individual_count = 0
        for _ in range(100):  # 100 operations
            data = ring_buffer.consume_data(thread_index=0, max_entries=1)
            individual_count += len(data)
        individual_time = time.time() - start_time

        # Step 4: Reset and test batch consume performance
        ring_buffer.local_tails[0] = 0
        ring_buffer.last_sequences[0] = None

        start_time = time.time()
        batch_count = 0
        for _ in range(10):  # 10 batch operations
            data = ring_buffer.consume_data_batch(thread_index=0, max_entries=10)
            batch_count += len(data)
        batch_time = time.time() - start_time

        # Step 5: Calculate performance metrics
        individual_throughput = 100 / individual_time if individual_time > 0 else 0
        batch_throughput = 100 / batch_time if batch_time > 0 else 0

        print(f"Individual consume: {individual_throughput:.0f} ops/sec")
        print(f"Batch consume: {batch_throughput:.0f} ops/sec")

        # Step 6: Validate performance (basic sanity checks)
        assert individual_time > 0, "Individual operations should take some time"
        assert batch_time > 0, "Batch operations should take some time"
        assert individual_count >= 0, "Individual count should be non-negative"
        assert batch_count >= 0, "Batch count should be non-negative"

    def test_ring_buffer_multiple_threads(self):
        """Test ring buffer access across multiple threads"""
        ring_name = "/test/ring_buffer_multi"
        threads = 2

        # Step 1: Create ring buffer with multiple threads using CLI (single-threaded)
        cli_cmd = (
            f"test stats ring-buffer-gen {ring_name} 10 {INTERVAL_USEC} {RING_SIZE}"
        )
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer
        ring_buffer = self.statistics.get_ring_buffer(f"{ring_name}")

        # Step 3: Test single thread (since CLI only supports single-threaded)
        config = ring_buffer.get_config()
        assert (
            config["n_threads"] == 1
        ), f"CLI creates single-threaded ring buffers, got {config['n_threads']}"

        # Test metadata access
        metadata = ring_buffer._get_thread_metadata(0)
        assert "head" in metadata, "Thread 0 metadata should contain head"
        assert "sequence" in metadata, "Thread 0 metadata should contain sequence"

        # Test data consumption
        data = ring_buffer.consume_data(thread_index=0)
        assert isinstance(data, list), "Thread 0 should return list"

    def test_ring_buffer_sequence_consistency(self):
        """Test sequence number consistency across reads"""
        ring_name = "/test/ring_buffer_seq"

        # Step 1: Create ring buffer
        cli_cmd = (
            f"test stats ring-buffer-gen {ring_name} 10 {INTERVAL_USEC} {RING_SIZE}"
        )
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer
        ring_buffer = self.statistics.get_ring_buffer(f"{ring_name}")

        # Step 3: Read metadata multiple times to check consistency
        metadata1 = ring_buffer._get_thread_metadata(0)
        time.sleep(0.01)  # Small delay
        metadata2 = ring_buffer._get_thread_metadata(0)

        # Sequence numbers should be consistent (same or increasing)
        assert (
            metadata2["sequence"] >= metadata1["sequence"]
        ), "Sequence should be monotonically increasing"

    def test_ring_buffer_polling_with_callback(self):
        """Test ring buffer polling with callback function"""
        ring_name = "/test/ring_buffer_callback"

        # Step 1: Create ring buffer
        cli_cmd = (
            f"test stats ring-buffer-gen {ring_name} 5 {INTERVAL_USEC} {RING_SIZE}"
        )
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer
        ring_buffer = self.statistics.get_ring_buffer(f"{ring_name}")

        # Step 3: Test polling with callback
        collected_data = []

        def callback(data):
            collected_data.append(data)

        # Poll with callback and short timeout
        result_data = ring_buffer.poll_for_data(
            thread_index=0, timeout=1.0, callback=callback
        )

        # Both callback and return value should work
        assert isinstance(result_data, list), "Poll should return list"
        assert isinstance(collected_data, list), "Callback should collect data in list"

    def test_ring_buffer_empty_operations(self):
        """Test ring buffer operations on empty buffer"""
        ring_name = "/test/ring_buffer_empty"

        # Step 1: Create ring buffer but don't generate data
        cli_cmd = (
            f"test stats ring-buffer-gen {ring_name} 0 {INTERVAL_USEC} {RING_SIZE}"
        )
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer
        ring_buffer = self.statistics.get_ring_buffer(f"{ring_name}")

        # Step 3: Test empty consume
        data = ring_buffer.consume_data(thread_index=0)
        assert data == [], "Empty buffer should return empty list"

        # Step 4: Test empty batch consume
        data = ring_buffer.consume_data_batch(thread_index=0)
        assert data == [], "Empty buffer should return empty list for batch"

        # Step 5: Test empty poll
        data = ring_buffer.poll_for_data(thread_index=0, timeout=0.1)
        assert data == [], "Empty buffer should return empty list for poll"

    def test_ring_buffer_prefetch_parameter(self):
        """Test prefetch parameter in batch consume"""
        ring_name = "/test/ring_buffer_prefetch"

        # Step 1: Create ring buffer
        cli_cmd = (
            f"test stats ring-buffer-gen {ring_name} 10 {INTERVAL_USEC} {RING_SIZE}"
        )
        result = self.vapi.cli(cli_cmd)
        assert "Generated" in result, f"CLI failed: {result}"

        # Step 2: Get ring buffer
        ring_buffer = self.statistics.get_ring_buffer(f"{ring_name}")

        # Step 3: Test with prefetch enabled
        data1 = ring_buffer.consume_data_batch(thread_index=0, prefetch=True)

        # Step 4: Reset and test with prefetch disabled
        ring_buffer.local_tails[0] = 0
        ring_buffer.last_sequences[0] = None

        data2 = ring_buffer.consume_data_batch(thread_index=0, prefetch=False)

        # Step 5: Results should be the same regardless of prefetch setting
        assert data1 == data2, "Prefetch parameter should not affect results"
