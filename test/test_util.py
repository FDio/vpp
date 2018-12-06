#!/usr/bin/env python
"""Test framework utilitty functions tests"""

import unittest
from framework import VppTestCase, VppTestRunner
from util import mactobinary, binarytomac


class TestUtil (VppTestCase):
    """ MAC to binary and back """
    def test_mac_to_binary(self):
        mac = 'aa:bb:cc:dd:ee:ff'
        b = mactobinary(mac)
        mac2 = binarytomac(b)
        self.assertEqual(type(mac), type(mac2))
        self.assertEqual(mac2, mac)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
