#!/usr/bin/env python
"""Test framework utilitty functions tests"""

import unittest
from framework import VppTestCase, VppTestRunner
from vpp_papi import mac_pton, mac_ntop


class TestUtil (VppTestCase):
    """ MAC to binary and back """
    def test_mac_to_binary(self):
        mac = 'aa:bb:cc:dd:ee:ff'
        b = mac_pton(mac)
        mac2 = mac_ntop(b)
        self.assertEqual(type(mac), type(mac2))
        self.assertEqual(mac2, mac)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
