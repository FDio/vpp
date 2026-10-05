import contextlib
import unittest
from struct import Struct

from vpp_papi.vpp_stats import StatsEntry, StatsVector, VPPStats


class FakeStats:
    """A stats segment holding one VPP vector of u64 values at offset 8."""

    def __init__(self, values):
        self.statseg = bytearray(16 + 8 * len(values))
        Struct("I").pack_into(self.statseg, 0, len(values))
        for i, v in enumerate(values):
            Struct("Q").pack_into(self.statseg, 8 + 8 * i, v)
        self.base = 0
        self.size = len(self.statseg)
        self.lock = contextlib.nullcontext()


class TestStatsVector(unittest.TestCase):
    def test_index(self):
        v = StatsVector(FakeStats([10, 11, 12]), 8, "Q")
        self.assertEqual([v[0], v[1], v[2]], [10, 11, 12])

    def test_index_past_end(self):
        v = StatsVector(FakeStats([10, 11, 12]), 8, "Q")
        with self.assertRaises(IOError):
            v[3]


class FakeDirectory:
    """A stats segment whose directory holds one gauge at offset 8."""

    elementfmt = VPPStats.elementfmt
    directory_vector = 8

    def __init__(self, value):
        entry = Struct(self.elementfmt)
        self.statseg = bytearray(16 + entry.size)
        Struct("I").pack_into(self.statseg, 0, 1)
        entry.pack_into(self.statseg, 8, 9, value, b"/test/gauge")
        self.base = 0
        self.size = len(self.statseg)
        self.lock = contextlib.nullcontext()

    def set(self, value):
        Struct(self.elementfmt).pack_into(self.statseg, 8, 9, value, b"/test/gauge")


class TestStatsEntry(unittest.TestCase):
    def test_gauge_read_when_accessed(self):
        stats = FakeDirectory(1)
        gauge = StatsEntry(9, 1, 0)
        stats.set(2)
        self.assertEqual(gauge.get_counter(stats), 2)


if __name__ == "__main__":
    unittest.main()
