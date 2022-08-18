#!/usr/bin/env python3
"""Test framework utility functions tests"""

import unittest
from asfframework import VppTestRunner, CPUInterface
from vpp_papi import mac_pton, mac_ntop


class TestUtil(CPUInterface, unittest.TestCase):
    """Test framework utility tests"""

    @classmethod
    def is_tagged_run_solo(cls):
        """if the test case class is timing-sensitive - return true"""
        return False

    @classmethod
    def has_tag(cls, tag):
        """if the test case has a given tag - return true"""
        try:
            return tag in cls.test_tags
        except AttributeError:
            pass
        return False

    @classmethod
    def get_cpus_required(cls):
        return 0

    def test_mac_to_binary(self):
        """MAC to binary and back"""
        mac = "aa:bb:cc:dd:ee:ff"
        b = mac_pton(mac)
        mac2 = mac_ntop(b)
        self.assertEqual(type(mac), type(mac2))
        self.assertEqual(mac2, mac)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
