# SPDX-License-Identifier: Apache-2.0

import struct
import unittest

from vpp_papi.vpp_stats import StatsRingBuffer

# vlib_stats_ring_config_t, then metadata_offset and data_offset: the head of
# vlib_stats_ring_buffer_t in src/vlib/stats/stats.h.
RING_HEADER = struct.Struct("=IIIIIII")
# The fields of vlib_stats_ring_metadata_t ahead of its cache line padding.
THREAD_METADATA = struct.Struct("=IIQII")

SCHEMA = b"ring-schema"


class FakeStats:
    """The two members of VPPStats the ring reader touches."""

    def __init__(self, statseg):
        self.statseg = statseg
        self.base = 0


def make_ring(n_threads, cache_line, schema=SCHEMA, ring_at=4096):
    """Lay a ring out as vlib_stats_add_ring_buffer() does on a target with
    the given cache line size. Thread t gets head t and sequence (t + 1) * 10."""
    entry_size, ring_size = 8, 4
    data_offset = cache_line
    data_size = n_threads * ring_size * entry_size
    metadata_offset = -(-(data_offset + data_size) // cache_line) * cache_line
    metadata_size = n_threads * cache_line
    schema_offset = metadata_offset + metadata_size if schema else 0

    seg = bytearray(ring_at + metadata_offset + metadata_size + len(schema))
    RING_HEADER.pack_into(
        seg,
        ring_at,
        entry_size,
        ring_size,
        n_threads,
        len(schema),
        1,  # schema_version
        metadata_offset,
        data_offset,
    )
    for t in range(n_threads):
        THREAD_METADATA.pack_into(
            seg,
            ring_at + metadata_offset + t * cache_line,
            t,  # head
            1,  # schema_version
            (t + 1) * 10,  # sequence
            schema_offset,
            len(schema),
        )
    if schema:
        start = ring_at + schema_offset
        seg[start : start + len(schema)] = schema
    return StatsRingBuffer(FakeStats(bytes(seg)), ring_at)


class TestStatsRingBuffer(unittest.TestCase):
    def assert_reads_every_thread(self, ring, n_threads):
        for t in range(n_threads):
            metadata = ring._get_thread_metadata(t)
            self.assertEqual(metadata["head"], t, f"thread {t}")
            self.assertEqual(metadata["sequence"], (t + 1) * 10, f"thread {t}")

    def test_metadata_stride_64(self):
        """Default build: vlib_stats_ring_metadata_t is one 64 byte cache line"""
        ring = make_ring(n_threads=3, cache_line=64)
        self.assert_reads_every_thread(ring, 3)
        self.assertEqual(ring.metadata_stride, 64)

    def test_metadata_stride_128(self):
        """A 128 byte cache line build pads the same struct out to 128 bytes"""
        ring = make_ring(n_threads=3, cache_line=128)
        self.assert_reads_every_thread(ring, 3)
        self.assertEqual(ring.metadata_stride, 128)

    def test_metadata_stride_single_thread(self):
        ring = make_ring(n_threads=1, cache_line=128)
        self.assert_reads_every_thread(ring, 1)
        self.assertEqual(ring.metadata_stride, 128)

    def test_metadata_stride_without_schema(self):
        """No schema, nothing to derive the stride from: assume 64 bytes"""
        ring = make_ring(n_threads=3, cache_line=64, schema=b"")
        self.assert_reads_every_thread(ring, 3)
        self.assertEqual(ring.metadata_stride, 64)


if __name__ == "__main__":
    unittest.main()
