#!/usr/bin/env python3

import vpp_papi
import unittest, sys, time, threading, struct, logging
from ipaddress import *

papi_event = threading.Event()
def papi_event_handler(result):
    if result.vl_msg_id == vpp_papi.VL_API_SW_INTERFACE_SET_FLAGS:
        papi_event.set()
        return
    if result.vl_msg_id == vpp_papi.VL_API_VNET_INTERFACE_COUNTERS:
        format = '>' + str(int(len(result.data) / 8)) + 'Q'
        counters = struct.unpack(format, result.data)
        print('Counters:', counters)
        return
    if result.vl_msg_id == vpp_papi.VL_API_VNET_IP6_FIB_COUNTERS:
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

class TestPAPI(unittest.TestCase):

    def setUp(self):
        r = vpp_papi.connect("test_papi")
        self.assertEqual(r, 0)

    def tearDown(self):
        r = vpp_papi.disconnect()
        self.assertEqual(r, 0)
        
    def test_show_version(self):
        t = vpp_papi.show_version()
        program = t.program.decode().rstrip('\x00')
        self.assertEqual('vpe', program)

    #
    # Add a few MAP domains, then dump them later
    #
    def test_map(self):
        t = vpp_papi.map_summary_stats()
        print(t)
        ip6 = IPv6Address(u'2001:db8::1').packed
        ip4 = IPv4Address(u'10.0.0.0').packed
        ip6_src = IPv6Address(u'2001:db9::1').packed
        t = vpp_papi.map_add_domain(ip6, ip4, ip6_src, 32, 24, 128, 0, 0, 6, 0, 0)
        print(t)
        self.assertEqual(t.retval, 0)

        ip4 = IPv4Address(u'10.0.1.0').packed
        t = vpp_papi.map_add_domain(ip6, ip4, ip6_src, 32, 24, 128, 0, 0, 6, 0, 0)
        print(t)
        self.assertEqual(t.retval, 0)

        t = vpp_papi.map_summary_stats()
        print(t)
        self.assertEqual(t.total_bindings, 2)

        t = vpp_papi.map_domain_dump()
        print (t)
        self.assertEqual(len(t), 2)

    def test_sw_interface_dump(self):
        #
        # Dump interfaces
        #
        t = vpp_papi.sw_interface_dump(0, b'ignored')
        for interface in t:
            if interface.vl_msg_id == vpp_papi.VL_API_SW_INTERFACE_DETAILS:
                print(interface.interface_name.decode())

    def test_want_interface_events(self):
        pid = 123
        vpp_papi.register_event_callback(papi_event_handler)
        papi_event.clear()
        t = vpp_papi.want_interface_events(True, pid)
        print (t)
        print('Setting interface up')
        t = vpp_papi.sw_interface_set_flags(0, 1, 1, 0)
        print (t)
        self.assertEqual(papi_event.wait(5), True)
        t = vpp_papi.sw_interface_set_flags(0, 0, 0, 0)
        print (t)
        self.assertEqual(papi_event.wait(5), True)

    @unittest.skip("not quite ready yet")
    def test_want_stats(self):
        pid = 123
        vpp_papi.register_event_callback(papi_event_handler)
        papi_event.clear()
        t = vpp_papi.want_stats(True, pid)

        print (t)

        #
        # Wait for some stats
        #
        self.assertEqual(papi_event.wait(30), True)
        t = vpp_papi.want_stats(False, pid)
        print (t)

    def test_tap(self):
        pid = 123
        vpp_papi.register_event_callback(papi_event_handler)
        papi_event.clear()
        t = vpp_papi.want_stats(True, pid)

        print (t)

        t = vpp_papi.tap_connect(1, b'tap', b'foo', 1, 0)
        print (t)
        self.assertEqual(t.retval, 0)
        swifindex = t.sw_if_index

        t = vpp_papi.sw_interface_set_flags(swifindex, 1, 1, 0)
        print (t)
        self.assertEqual(t.retval, 0)        

        ip6 = IPv6Address(u'2001:db8::1').packed
        t = vpp_papi.sw_interface_add_del_address(swifindex, 1, 1, 0, 16, ip6)
        print (t)
        time.sleep(40)


if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    unittest.main()
