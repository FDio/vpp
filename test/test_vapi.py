#!/usr/bin/env python
""" VAPI test """

from __future__ import division
import unittest
from framework import VppTestCase, running_extended_tests, VppTestRunner


@unittest.skipUnless(running_extended_tests(), "part of extended tests")
class VAPITestCase(VppTestCase):
    """ VAPI test """

    def test_vapi(self):
        """ run VAPI tests """
        pass


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
