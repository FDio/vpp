#!/usr/bin/env python

from __future__ import print_function
import unittest, sys, threading, struct, logging, os
from vpp_papi import VPP
from ipaddress import *
import glob, json

papi_event = threading.Event()
import glob

import fnmatch
import os

jsonfiles = []
for root, dirnames, filenames in os.walk('../../../build-root/'):
    if root.find('install-') == -1: continue
    for filename in fnmatch.filter(filenames, '*.api.json'):
        jsonfiles.append(os.path.join(root, filename))

class TestPAPI(unittest.TestCase):
    show_version_msg = '''["show_version",
              ["u16", "_vl_msg_id"],
              ["u32", "client_index"],
              ["u32", "context"],
              {"crc" : "0xf18f9480"}
        ]'''

    ip_address_details_msg = '''["ip_address_details",
            ["u16", "_vl_msg_id"],
            ["u32", "client_index"],
            ["u32", "context"],
            ["u8", "ip", 16],
            ["u8", "prefix_length"],
            {"crc" : "0x87d522a1"}
        ]'''

    cli_inband_msg = '''["cli_inband",
            ["u16", "_vl_msg_id"],
            ["u32", "client_index"],
            ["u32", "context"],
            ["u32", "length"],
            ["u8", "cmd", 0, "length"],
            {"crc" : "0x22345937"}
        ]'''

    def test_adding_new_message_object(self):
        p = json.loads(TestPAPI.show_version_msg)
        msglist = VPP(testmode=json)
        msgdef = msglist.add_message(p[0], p[1:])

        # Verify that message can be retrieved
        self.assertTrue(msglist['show_version'])
        self.assertFalse(msglist['foobar'])

        # Test duplicate
        self.assertRaises(ValueError, msglist.add_message, p[0], p[1:])

        # Look at return tuple
        self.assertTrue(msglist.ret_tup('show_version'))

    def test_adding_new_message_object_with_array(self):
        p = json.loads(TestPAPI.ip_address_details_msg)
        msglist = VPP(testmode=True)
        msglist.add_message(p[0], p[1:])

        self.assertTrue(msglist['ip_address_details'])

    def test_message_to_bytes(self):
        msglist = VPP(testmode=True)
        p = json.loads(TestPAPI.show_version_msg)
        msgdef = msglist.add_message(p[0], p[1:])

        # Give me a byte string for given message and given arguments

        b = msglist.encode(msgdef, {'_vl_msg_id' : 50, 'context' : 123 })
        self.assertEqual(10, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(rv._0, 50)
        self.assertEqual(rv.context, 123)


        p = json.loads(TestPAPI.ip_address_details_msg)
        msgdef = msglist.add_message(p[0], p[1:])

        # Give me a byte string for given message and given arguments
        b = msglist.encode(msgdef, {'_vl_msg_id' : 50, 'context' : 123,
                                    'ip' : b'\xf0\xf1\xf2',
                                    'prefix_length' :  12})
        self.assertEqual(27, len(b))
        rv = msglist.decode(msgdef, b)

        self.assertEqual(rv.context, 123)
        self.assertEqual(rv.ip, b'\xf0\xf1\xf2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(rv.prefix_length, 12)

        p = json.loads(TestPAPI.cli_inband_msg)
        msgdef = msglist.add_message(p[0], p[1:])

        # Give me a byte string for given message and given arguments
        b = msglist.encode(msgdef, { '_vl_msg_id' : 50, 'context' : 123,
                                     'length' : 20, 'cmd' : 'show version verbose'})
        self.assertEqual(34, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(rv._0, 50)
        self.assertEqual(rv.context, 123)
        self.assertEqual(rv.cmd.decode('ascii'), 'show version verbose')

        variable_array_16_msg = '''["variable_array_16",
            ["u32", "length"],
            ["u16", "list", 0, "length"]
        ]'''

        p = json.loads(variable_array_16_msg)
        msgdef = msglist.add_message(p[0], p[1:])

        # Give me a byte string for given message and given arguments
        b = msglist.encode(msgdef, { 'list' : [1, 2], 'length' :2})
        self.assertEqual(8, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(2, rv.length)
        self.assertEqual([1,2], rv.list)

    def test_add_new_types(self):
        counter_type = '''["ip4_fib_counter",
            ["u32", "address"],
            ["u8", "address_length"],
            ["u64", "packets"],
            ["u64", "bytes"],
            {"crc" : "0xb2739495"}
        ]'''

        with_type_msg = '''["with_type_msg",
            ["u32", "length"],
            ["u16", "list", 0, "length"],
            ["vl_api_ip4_fib_counter_t", "counter"]
        ]'''

        # Add new type
        msglist = VPP(testmode=True)
        p = json.loads(counter_type)
        msglist.add_type(p[0], p[1:])
        p = json.loads(with_type_msg)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'length' : 2, 'list' : [1,2],
                           'counter' : { 'address' : 4, 'address_length' : 12,
                                       'packets': 1235, 'bytes' : 5678}})
        self.assertEqual(29, len(b)) # feil
        rv = msglist.decode(msgdef, b)
        self.assertEqual(2, rv.length)
        self.assertEqual(5678, rv.counter.bytes)

    def test_add_new_compound_type_with_array(self):
        counter_type = '''["ip4_fib_counter",
            ["u32", "address"],
            ["u8", "address_length"],
            ["u64", "packets"],
            ["u64", "bytes"],
            {"crc" : "0xb2739495"}
        ]'''

        with_type_msg = '''["with_type_msg",
            ["u32", "length"],
            ["u16", "list", 0, "length"],
            ["vl_api_ip4_fib_counter_t", "counter", 2]

        ]'''

        # Add new type
        msglist = VPP(testmode=True)
        p = json.loads(counter_type)
        msglist.add_type(p[0], p[1:])
        p = json.loads(with_type_msg)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'length' : 2, 'list' : [1,2],
                           'counter' : [{ 'address' : 4, 'address_length' : 12,
                                        'packets': 1235, 'bytes' : 5678},
                                      { 'address' : 111, 'address_length' : 222,
                                        'packets': 333, 'bytes' : 444}]})
        self.assertEqual(50, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual([1,2], rv.list)
        self.assertEqual(1235, rv.counter[0].packets)

        with_type_variable_msg = '''["with_type_variable_msg",
            ["u32", "length"],
            ["vl_api_ip4_fib_counter_t", "counter", 0, "length"]

        ]'''

        p = json.loads(with_type_variable_msg)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'length' : 2,
                           'counter' : [{ 'address' : 4, 'address_length' : 12,
                                        'packets': 1235, 'bytes' : 5678},
                                      { 'address' : 111, 'address_length' : 222,
                                        'packets': 333, 'bytes' : 444}]})
        self.assertEqual(46, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(2, rv.length)
        self.assertEqual(1235, rv.counter[0].packets)
        self.assertEqual(333, rv.counter[1].packets)

    def test_simple_array(self):
        msglist = VPP(testmode=True)

        simple_byte_array = '''["simple_byte_array",
            ["u32", "length"],
            ["u8", "namecommand", 64]

        ]'''
        p = json.loads(simple_byte_array)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'length': 2, 'namecommand': 'foobar'})
        self.assertEqual(68, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(2, rv.length)

        simple_array = '''["simple_array",
            ["u32", "length"],
            ["u32", "list", 2]

        ]'''
        p = json.loads(simple_array)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'length': 2, 'list': [1,2]})
        self.assertEqual(12, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(2, rv.length)
        self.assertEqual([1,2], rv.list)

        simple_variable_array = '''["simple_variable_array",
            ["u32", "length"],
            ["u32", "list", 0, "length"]

        ]'''
        p = json.loads(simple_variable_array)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'length':2, 'list': [1,2]})
        self.assertEqual(12, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(2, rv.length)
        self.assertEqual([1,2], rv.list)

        simple_variable_byte_array = '''["simple_variable_byte_array",
            ["u32", "length"],
            ["u8", "list", 0, "length"]
        ]'''
        p = json.loads(simple_variable_byte_array)
        msgdef =msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'length': 6, 'list' : 'foobar'})
        self.assertEqual(10, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(6, rv.length)
        self.assertEqual('foobar', rv.list)

    def test_old_vla_array(self):
        msglist = VPP(testmode = True)

        # VLA
        vla_byte_array = '''["vla_byte_array",
            ["u32", "foobar"],
            ["u32", "list", 2],
            ["u32", "propercount"],
            ["u8", "propermask", 0, "propercount"],
            ["u8", "oldmask", 0],
            {"crc" : "0xb2739495"}
        ]'''
        p = json.loads(vla_byte_array)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'list' : [123, 456], 'oldmask': b'foobar',
                                    'propercount' : 2,
                                    'propermask' : [8,9]})
        self.assertEqual(24, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(b'foobar', rv.oldmask)

    def test_old_vla_array_not_last_member(self):
        msglist = VPP(testmode = True)

        # VLA
        vla_byte_array = '''["vla_byte_array",
            ["u8", "oldmask", 0],
            ["u32", "foobar"],
            {"crc" : "0xb2739495"}
        ]'''
        p = json.loads(vla_byte_array)
        self.assertRaises(ValueError, msglist.add_message, p[0], p[1:])

    def test_old_vla_array_u32(self):
        msglist = VPP(testmode = True)

        # VLA
        vla_byte_array = '''["vla_byte_array",
            ["u32", "foobar"],
            ["u32", "oldmask", 0],
            {"crc" : "0xb2739495"}
        ]'''
        p = json.loads(vla_byte_array)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'foobar' : 123, 'oldmask': [123, 456, 789]})
        self.assertEqual(16, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual([123, 456, 789], rv.oldmask)

    def test_old_vla_array_compound(self):
        msglist = VPP(testmode = True)

        # VLA
        counter_type = '''["ip4_fib_counter",
            ["u32", "address"],
            ["u8", "address_length"],
            ["u64", "packets"],
            ["u64", "bytes"],
            {"crc" : "0xb2739495"}
        ]'''

        vla_byte_array = '''["vla_byte_array",
            ["vl_api_ip4_fib_counter_t", "counter", 0],
            {"crc" : "0xb2739495"}
        ]'''

        p = json.loads(counter_type)
        msglist.add_type(p[0], p[1:])

        p = json.loads(vla_byte_array)
        with self.assertRaises(NotImplementedError):
            msgdef = msglist.add_message(p[0], p[1:])

    def test_array_count_not_previous(self):
        msglist = VPP(testmode = True)

        # VLA
        vla_byte_array = '''["vla_byte_array",
            ["u32", "count"],
            ["u32", "filler"],
            ["u32", "lst", 0, "count"],
            {"crc" : "0xb2739495"}
        ]'''

        p = json.loads(vla_byte_array)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'count': 3, 'lst': [1,2,3], 'filler' : 1 })
        rv = msglist.decode(msgdef, b)
        self.assertEqual(rv.lst, [1,2,3])

    def test_argument_name(self):
        msglist = VPP(testmode=True)


        simple_name = '''["simple_name",
            ["u32", "length"],
            ["u8", "name"]
        ]'''
        p = json.loads(simple_name)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'length': 6, 'name': 1})
        self.assertEqual(5, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(6, rv.length)
        self.assertEqual(1, rv.name)

class TestConnectedPAPI(unittest.TestCase):
    def test_request_reply_function(self):
        vpp = VPP(jsonfiles)

        vpp.connect('test_vpp_papi2')

        rv = vpp.show_version()
        self.assertEqual(0, rv.retval)
        self.assertEqual('vpe', rv.program.decode().rstrip('\0x00'))
        vpp.disconnect()


    def test_dump_details_function(self):
        vpp = VPP(jsonfiles)
        vpp.connect('test_vpp_papi3')

        rv = vpp.sw_interface_dump()
        #self.assertEqual(0, rv.retval)
        print('RV', rv)
        vpp.disconnect()

    def test_vla(self):
        vpp = VPP(jsonfiles)

        vpp.connect('test_vpp_papi3')

        cmd = 'show version verbose'
        rv = vpp.cli_inband(length=len(cmd), cmd=cmd)
        self.assertEqual(0, rv.retval)
        print('RV', rv.reply)

        cmd = 'show vlib graph'
        rv = vpp.cli_inband(length=len(cmd), cmd=cmd)
        self.assertEqual(0, rv.retval)
        print('RV', rv.reply)
        vpp.disconnect()

    def test_events(self):
        vpp = VPP(jsonfiles)

        vpp.connect('test_vpp_papi3')

        vpp.register_event_callback(event_handler)

        rv = vpp.want_interface_events(enable_disable = True)
        self.assertEqual(0, rv.retval)
        print('RV', rv)

        rv = vpp.create_loopback()
        print('RV', rv)
        self.assertEqual(0, rv.retval)

        rv = vpp.sw_interface_set_flags(sw_if_index = 1, admin_up_down = 1)
        print('RV', rv)
        self.assertEqual(0, rv.retval)
        rv = vpp.sw_interface_set_flags(sw_if_index = 1, admin_up_down = 0)
        print('RV', rv)
        self.assertEqual(0, rv.retval)
        self.assertEqual(papi_event.wait(10), True)

        vpp.disconnect()

def event_handler(msgname, result):
    print('IN EVENT HANDLER:', msgname, result)
    papi_event.set()

class TestACL(unittest.TestCase):
    def test_acl_create(self):
        vpp = VPP(jsonfiles)

        vpp.connect('acl-test')

        rv = vpp.acl_plugin_get_version()
        print('RV', rv)
        self.assertEqual(rv.major, 1)
        self.assertEqual(rv.minor, 1)

        rv = vpp.acl_add_replace(acl_index = 0xFFFFFFFF,
            r = [{
                "is_permit" : 1,
                "is_ipv6" : 0,
                "proto" : 6,
                "srcport_or_icmptype_first" : 80,
                }],
            count = 1)
        print ('RV', rv)
        rv = vpp.acl_add_replace(acl_index = 0xFFFFFFFF,
            r = [{
                "is_permit" : 1,
                "is_ipv6" : 0,
                "proto" : 6,
                "srcport_or_icmptype_first" : 81,
                }],
            count = 1)
        self.assertEqual(rv.retval, 0)
        print ('RV', rv)
        ai = rv.acl_index
        rv = vpp.acl_dump()
        print ('RV', rv)

        #rv = vpp.acl_del(acl_index = ai)
        #self.assertEqual(rv.retval, 0)

        #rv = vpp.acl_dump()
        #self.assertEqual([], vpp.acl_dump())

        vpp.disconnect()

    def test_status(self):
        vpp = VPP(jsonfiles)
        vpp.status()

    def test_acl_interface_get(self):
        vpp = VPP(jsonfiles)

        vpp.connect('test_vpp_papi2')

        rv = vpp.macip_acl_interface_get()

        print('RV', rv)

        vpp.disconnect()

if __name__ == '__main__':
    unittest.main()
