#!/usr/bin/env python

from __future__ import print_function
import unittest, sys, time, threading, struct
import test_base
import vpp_papi
from ipaddress import *

import glob, subprocess
class TestPAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        #
        # Start main VPP process
        cls.vpp_bin = glob.glob(test_base.scriptdir+'/../../../build-root/install-vpp*-native/vpp/bin/vpp')[0]
        print("VPP BIN:", cls.vpp_bin)
        cls.vpp = subprocess.Popen([cls.vpp_bin, "unix", "nodaemon"], stderr=subprocess.PIPE)
        print('Started VPP')
        # For some reason unless we let VPP start up the API cannot connect.
        time.sleep(0.3)
    @classmethod
    def tearDownClass(cls):
        cls.vpp.terminate()

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
    def test_cli_request(self):
        print(vpp_papi.cli_exec('show version verbose'))
        #t = vpp_papi.cli_inband_request(len(cmd), cmd)
        #print('T:',t)
        #reply = t.reply[0].decode().rstrip('\x00')
        #print(reply)
        #program = t.program.decode().rstrip('\x00')
        #self.assertEqual('vpe', program)


if __name__ == '__main__':
    unittest.main()
