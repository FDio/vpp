from __future__ import print_function
import unittest, sys, time, threading, struct

import vpp_papi
from ipaddress import *
import glob, subprocess
class TestPAPI(unittest.TestCase):
    def setUp(self):
        print("Connecting API")
        r = vpp_papi.connect("test_papi")
        self.assertEqual(r, 0)

    def tearDown(self):
        r = vpp_papi.disconnect()
        self.assertEqual(r, 0)

    #
    # The tests themselves
    #

    #
    # Basic request / reply
    #
    def test_show_version(self):
        print(vpp_papi.show_version())

    #
    # Details / Dump
    #
    def test_details_dump(self):
        t = vpp_papi.sw_interface_dump(0, b'')
        print('Dump/details T', t)

if __name__ == '__main__':
    unittest.main()
