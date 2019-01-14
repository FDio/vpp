#!/usr/bin/env python
"""Test framework utility functions tests"""

import unittest
import main
from framework import VppTestRunner
from vpp_papi import mac_pton, mac_ntop


class TestUtil (unittest.TestCase):
    """ MAC to binary and back """
    def test_mac_to_binary(self):
        mac = 'aa:bb:cc:dd:ee:ff'
        b = mac_pton(mac)
        mac2 = mac_ntop(b)
        self.assertEqual(type(mac), type(mac2))
        self.assertEqual(mac2, mac)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
