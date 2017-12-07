import binascii
from framework import VppTestCase
from vpp_papi import VPP
import json

""" TestPAPI is a subclass of  VPPTestCase classes.

Basic test for sanity check of the Python API binding.

"""


class TestPAPI(VppTestCase):
    """ PAPI Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestPAPI, cls).setUpClass()
        cls.v = cls.vapi.papi

    def test_show_version(self):
        rv = self.v.show_version()
        self.assertEqual(rv.retval, 0)

    def test_show_version_invalid_param(self):
        self.assertRaises(ValueError, self.v.show_version, foobar='foo')

    def test_u8_array(self):
        rv = self.v.get_node_index(node_name='ip4-lookup')
        self.assertEqual(rv.retval, 0)
        node_name = 'X' * 100
        self.assertRaises(ValueError, self.v.get_node_index,
                          node_name=node_name)


class TestPAPIMessageParsing(VppTestCase):
    """ PAPI Message parsing Test Case """

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
        p = json.loads(TestPAPIMessageParsing.show_version_msg)
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
        p = json.loads(TestPAPIMessageParsing.ip_address_details_msg)
        msglist = VPP(testmode=True)
        msglist.add_message(p[0], p[1:])

        self.assertTrue(msglist['ip_address_details'])

    def test_message_to_bytes(self):
        msglist = VPP(testmode=True)
        p = json.loads(TestPAPIMessageParsing.show_version_msg)
        msgdef = msglist.add_message(p[0], p[1:])

        # Give me a byte string for given message and given arguments

        b = msglist.encode(msgdef, {'_vl_msg_id': 50, 'context': 123})
        self.assertEqual(10, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(rv._0, 50)
        self.assertEqual(rv.context, 123)

        p = json.loads(TestPAPIMessageParsing.ip_address_details_msg)
        msgdef = msglist.add_message(p[0], p[1:])

        # Give me a byte string for given message and given arguments
        b = msglist.encode(msgdef, {'_vl_msg_id': 50, 'context': 123,
                                    'ip': b'\xf0\xf1\xf2',
                                    'prefix_length': 12})
        self.assertEqual(27, len(b))
        rv = msglist.decode(msgdef, b)

        self.assertEqual(rv.context, 123)
        self.assertEqual(rv.ip, b'\xf0\xf1\xf2\x00\x00\x00' +
                         '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(rv.prefix_length, 12)

        p = json.loads(TestPAPIMessageParsing.cli_inband_msg)
        msgdef = msglist.add_message(p[0], p[1:])

        # Give me a byte string for given message and given arguments
        b = msglist.encode(msgdef, {'_vl_msg_id': 50, 'context': 123,
                                    'length': 20,
                                    'cmd': 'show version verbose'})
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
        b = msglist.encode(msgdef, {'list': [1, 2], 'length': 2})
        self.assertEqual(8, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(2, rv.length)
        self.assertEqual([1, 2], rv.list)

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
        b = msglist.encode(msgdef, {'length': 2, 'list': [1, 2],
                                    'counter': {'address': 4,
                                                'address_length': 12,
                                                'packets': 1235,
                                                'bytes': 5678}})
        self.assertEqual(29, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(2, rv.length)
        self.assertEqual(5678, rv.counter.bytes)

    def test_add_two_new_types(self):
        mock_r1 = '''["mock_r1",
            ["u32", "a1"],
            {"crc" : "0xb2739495"}
        ]'''
        mock_r2 = '''["mock_r2",
            ["u32", "a1"],
            {"crc" : "0xb2739495"}
        ]'''

        mock_msg = '''["mock_msg",
            ["u32", "context"],
            ["i32", "retval"],
            ["vl_api_mock_r1_t", "r1"],
            ["vl_api_mock_r2_t", "r2"],
            {"crc" : "0xb2739495"}
        ]'''

        # Add new type
        msglist = VPP(testmode=True)
        p = json.loads(mock_r1)
        msglist.add_type(p[0], p[1:])
        p = json.loads(mock_r2)
        msglist.add_type(p[0], p[1:])
        p = json.loads(mock_msg)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'context': 2, 'retval': 0,
                                    'r1': {'a1': 4}, 'r2': {'a1': 12}})

        self.assertEqual(16, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(4, rv.r1.a1)

    def test_nested_array_type(self):
        bier_type = '''["bier_table_id",
            ["u8", "bt_set"],
            ["u8", "bt_sub_domain"],
            ["u8", "bt_hdr_len_id"],
            {"crc" : "0xb2739495"}
        ]'''
        fib_path3 = '''["fib_path3",
            ["u32", "sw_if_index"],
            ["u8", "n_labels"],
            ["u32", "label_stack", 0, "n_labels"],
            {"crc" : "0xb2739495"}
        ]'''

        bier_route_details = '''["bier_route_details",
            ["u32", "client_index"],
            ["vl_api_bier_table_id_t", "br_tbl_id"],
            ["u32", "br_n_paths"],
            ["vl_api_fib_path3_t", "br_paths", 0, "br_n_paths"],
            {"crc" : "0xb2739495"}
        ]'''

        # Add new type
        msglist = VPP(testmode=True)

        p = json.loads(bier_type)
        msglist.add_type(p[0], p[1:])
        p = json.loads(fib_path3)
        msglist.add_type(p[0], p[1:])

        p = json.loads(bier_route_details)
        msgdef = msglist.add_message(p[0], p[1:])

        bt_tbl_id = {'bt_set': 1, 'bt_sub_domain': 2, 'bt_hdr_len_id': 3}
        fib_path = {'sw_if_index': 1, 'n_labels': 2,
                    'label_stack': [123, 456]}

        b = msglist.encode(msgdef, {'client_index': 2,
                                    'br_tbl_id': bt_tbl_id,
                                    'br_n_paths': 2,
                                    'br_paths': [fib_path, fib_path]})
        self.assertEqual(37, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual([123, 456], rv.br_paths[1].label_stack)
        self.assertEqual(bt_tbl_id['bt_set'], rv.br_tbl_id.bt_set)

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
        b = msglist.encode(msgdef, {'length': 2, 'list': [1, 2],
                                    'counter': [{'address': 4,
                                                 'address_length': 12,
                                                 'packets': 1235,
                                                 'bytes': 5678},
                                                {'address': 111,
                                                 'address_length': 222,
                                                 'packets': 333,
                                                 'bytes': 444}]})
        self.assertEqual(50, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual([1, 2], rv.list)
        self.assertEqual(1235, rv.counter[0].packets)

        with_type_variable_msg = '''["with_type_variable_msg",
            ["u32", "length"],
            ["vl_api_ip4_fib_counter_t", "counter", 0, "length"]

        ]'''

        p = json.loads(with_type_variable_msg)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'length': 2,
                                    'counter': [{'address': 4,
                                                 'address_length': 12,
                                                 'packets': 1235,
                                                 'bytes': 5678},
                                                {'address': 111,
                                                 'address_length': 222,
                                                 'packets': 333,
                                                 'bytes': 444}]})
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
        b = msglist.encode(msgdef, {'length': 2, 'list': [1, 2]})
        self.assertEqual(12, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(2, rv.length)
        self.assertEqual([1, 2], rv.list)

        simple_variable_array = '''["simple_variable_array",
            ["u32", "length"],
            ["u32", "list", 0, "length"]

        ]'''
        p = json.loads(simple_variable_array)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'length': 2, 'list': [1, 2]})
        self.assertEqual(12, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(2, rv.length)
        self.assertEqual([1, 2], rv.list)

        simple_variable_byte_array = '''["simple_variable_byte_array",
            ["u32", "length"],
            ["u8", "list", 0, "length"]
        ]'''
        p = json.loads(simple_variable_byte_array)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'length': 6, 'list': 'foobar'})
        self.assertEqual(10, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(6, rv.length)
        self.assertEqual('foobar', rv.list)

    def test_old_vla_array(self):
        msglist = VPP(testmode=True)

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
        b = msglist.encode(msgdef, {'list': [123, 456], 'oldmask': b'foobar',
                                    'propercount': 2,
                                    'propermask': [8, 9]})
        self.assertEqual(24, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual(b'foobar', rv.oldmask)

    def test_old_vla_array_not_last_member(self):
        msglist = VPP(testmode=True)

        # VLA
        vla_byte_array = '''["vla_byte_array",
            ["u8", "oldmask", 0],
            ["u32", "foobar"],
            {"crc" : "0xb2739495"}
        ]'''
        p = json.loads(vla_byte_array)
        self.assertRaises(ValueError, msglist.add_message, p[0], p[1:])

    def test_old_vla_array_u32(self):
        msglist = VPP(testmode=True)

        # VLA
        vla_byte_array = '''["vla_byte_array",
            ["u32", "foobar"],
            ["u32", "oldmask", 0],
            {"crc" : "0xb2739495"}
        ]'''
        p = json.loads(vla_byte_array)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'foobar': 123,
                                    'oldmask': [123, 456, 789]})
        self.assertEqual(16, len(b))
        rv = msglist.decode(msgdef, b)
        self.assertEqual([123, 456, 789], rv.oldmask)

    def test_old_vla_array_compound(self):
        msglist = VPP(testmode=True)

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
        msglist = VPP(testmode=True)

        # VLA
        vla_byte_array = '''["vla_byte_array",
            ["u32", "count"],
            ["u32", "filler"],
            ["u32", "lst", 0, "count"],
            {"crc" : "0xb2739495"}
        ]'''

        p = json.loads(vla_byte_array)
        msgdef = msglist.add_message(p[0], p[1:])
        b = msglist.encode(msgdef, {'count': 3, 'lst': [1, 2, 3],
                                    'filler': 1})
        rv = msglist.decode(msgdef, b)
        self.assertEqual(rv.lst, [1, 2, 3])

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
