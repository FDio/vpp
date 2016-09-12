from __future__ import print_function
import unittest, sys, time, threading, struct, logging, os
import vpp_papi
from ipaddress import *
scriptdir = os.path.dirname(os.path.realpath(__file__))
papi_event = threading.Event()
print(vpp_papi.vpe.VL_API_SW_INTERFACE_SET_FLAGS)
def papi_event_handler(result):
    if result.vl_msg_id == vpp_papi.vpe.VL_API_SW_INTERFACE_SET_FLAGS:
        return
    if result.vl_msg_id == vpp_papi.vpe.VL_API_VNET_INTERFACE_COUNTERS:
        print('Interface counters', result)
        return
    if result.vl_msg_id == vpp_papi.vpe.VL_API_VNET_IP6_FIB_COUNTERS:
        print('IPv6 FIB counters', result)
        papi_event.set()
        return

    print('Unknown message id:', result.vl_msg_id)

import glob, subprocess
class TestPAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        #
        # Start main VPP process
        cls.vpp_bin = glob.glob(scriptdir+'/../../../build-root/install-vpp*-native/vpp/bin/vpp')[0]
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
    # Arrays
    #
    def test_arrays(self):
        t = vpp_papi.vnet_get_summary_stats()
        print('Summary stats', t)
        print('Packets:', t.total_pkts[0])
        print('Packets:', t.total_pkts[1])
    #
    # Variable sized arrays and counters
    #
    #@unittest.skip("stats")
    def test_want_stats(self):
        pid = 123
        vpp_papi.register_event_callback(papi_event_handler)
        papi_event.clear()

        # Need to configure IPv6 to get som IPv6 FIB stats
        t = vpp_papi.create_loopback('')
        print(t)
        self.assertEqual(t.retval, 0)

        ifindex = t.sw_if_index
        addr = str(IPv6Address(u'1::1').packed)
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
        self.assertEqual(papi_event.wait(15), True)
        t = vpp_papi.want_stats(False, pid)
        print (t)


    #
    # Plugins?
    #

if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    unittest.main()
def test_papi():
    print('test')
