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
        self.assertEqual(self.statistics.get_counter('/err/ethernet-input/no'), [0])

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

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
