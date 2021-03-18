#!/usr/bin/env python3

import unittest
import psutil
from vpp_papi.vpp_stats import VPPStats

from framework import tag_fixme_vpp_workers
from framework import VppTestCase, VppTestRunner


@tag_fixme_vpp_workers
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
        self.assertEqual(
            self.statistics.get_counter('/err/ethernet-input/no error'), [0])

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

    @unittest.skip("Manual only")
    def test_mem_leak(self):
        def loop():
            print('Running loop')
            for i in range(50):
                rv = self.vapi.papi.tap_create_v2(id=i, use_random_mac=1)
                self.assertEqual(rv.retval, 0)
                rv = self.vapi.papi.tap_delete_v2(sw_if_index=rv.sw_if_index)
                self.assertEqual(rv.retval, 0)

        before = self.statistics.get_counter('/mem/statseg/used')
        loop()
        self.vapi.cli("memory-trace on stats-segment")
        for j in range(100):
            loop()
        print(self.vapi.cli("show memory stats-segment verbose"))
        print('AFTER', before,
              self.statistics.get_counter('/mem/statseg/used'))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
