#!/usr/bin/env python2.7

import unittest

import psutil
from vpp_papi.vpp_stats import VPPStats

from framework import VppTestCase, VppTestRunner


class StatsClientTestCase(VppTestCase):
    """Test Stats Client"""

    @classmethod
    def setUpClass(cls):
        super(StatsClientTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(StatsClientTestCase, cls).tearDownClass()

    def test_set_errors(self):
        """Test set errors"""
        self.assertEqual(self.statistics.set_errors(), {})
        self.assertEqual(self.statistics.get_counter('/err/ethernet-input/no'),
                         [0])

    def test_client_fd_leak(self):
        """Test file descriptor count - VPP-1486"""

        cls = self.__class__
        p = psutil.Process()
        initial_fds = p.num_fds()

        for _ in range(100):
            stats = VPPStats(socketname=cls.stats_sock)
            stats.disconnect()

        ending_fds = p.num_fds()
        self.assertEqual(initial_fds, ending_fds,
                         "initial client side file descriptor count: %s "
                         "is not equal to "
                         "ending client side file descriptor count: %s" % (
                             initial_fds, ending_fds))

    def test_mem_leak(self):
        used = []
        used.append(self.statistics.get_counter('/mem/statseg/used'))

        def loop():
            for i in range(10):
                rv = self.vapi.papi.tap_create_v2(id=i, use_random_mac=1)
                self.assertEqual(rv.retval, 0)
                used.append(self.statistics.get_counter('/mem/statseg/used'))
                rv = self.vapi.papi.tap_delete_v2(sw_if_index=rv.sw_if_index)
                self.assertEqual(rv.retval, 0)
                used.append(self.statistics.get_counter('/mem/statseg/used'))

        before = self.statistics.get_counter('/mem/statseg/used')
        loop()
        after = self.statistics.get_counter('/mem/statseg/used')

        print(self.vapi.cli("memory-trace on stats-segment"))
        for j in range(10):
            loop()

        print('USED', used)
        print('INTERFACES', self.statistics.get_counter('/if/names'))
        print('BEFORE, AFTER', before, after)
        print(self.vapi.cli("show memory stats-segment verbose"))
if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
