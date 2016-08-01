#!/usr/bin/env python

from __future__ import print_function
import unittest, sys, time, threading, struct, logging
import test_base
import vpp_papi
from ipaddress import *

papi_event = threading.Event()

def papi_event_handler(result):
    if result.vl_msg_id == vpp_papi.VL_API_SW_INTERFACE_SET_FLAGS:
        papi_event.set()
        return
    if result.vl_msg_id == vpp_papi.VL_API_VNET_INTERFACE_COUNTERS:
        print('Result', result)
        format = '>' + str(int(len(result.data) / 8)) + 'Q'
        counters = struct.unpack(format, result.data)
        print('Counters:', counters)
        return
    if result.vl_msg_id == vpp_papi.VL_API_VNET_IP6_FIB_COUNTERS:
        print('Result', result)
        print('IP6 FIB Counters:', result.count, len(result.c), len(result))
        i = 0
        # FIB counters allocate a large (1000 bytes) block so message length does not match reality
        for c in struct.iter_unpack('>16sBQQ', result.c):
            # In Python 3.5 we can use a tuple for prefix, length
            print(str(IPv6Address(c[0])) + '/' + str(c[1]), str(c[2]), str(c[3]))
            i += 1
            if i >= result.count:
                break
        return

    print('Unknown message id:', result.vl_msg_id)

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
    def test_show_version(self):
        t = vpp_papi.show_version()
        print('T', t);
        program = t.program.decode().rstrip('\x00')
        self.assertEqual('vpe', program)

    #
    # Details / Dump
    #
    def test_details_dump(self):
        t = vpp_papi.sw_interface_dump(0, b'')
        print('Dump/details T', t)


    #
    # Events
    #

    #
    # Variable sized arrays and counters
    #
    def test_want_stats(self):
        pid = 123
        vpp_papi.register_event_callback(papi_event_handler)
        papi_event.clear()

        # Need to configure IPv6 to get som IPv6 FIB stats
        t = vpp_papi.create_loopback('')
        print(t)
        self.assertEqual(t.retval, 0)

        ifindex = t.sw_if_index
        addr = str(IPv6Address('1::1').packed)
        t = vpp_papi.sw_interface_add_del_address(ifindex, 1, 1, 0, 16, addr)
        print(t)
        self.assertEqual(t.retval, 0)

        # Check if interface is up
        # XXX: Add new API to query interface state based on ifindex, instead of dump all.
        t = vpp_papi.sw_interface_set_flags(ifindex, 1, 1, 0)
        self.assertEqual(t.retval, 0)

        t = vpp_papi.want_stats(True, pid)

        print (t)

        #
        # Wait for some stats
        #
        self.assertEqual(papi_event.wait(30), True)
        t = vpp_papi.want_stats(False, pid)
        print (t)


    #
    # Shared memory APIs
    #

    #
    # Plugins?
    #

if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    unittest.main()
def test_papi():
    print('test')
