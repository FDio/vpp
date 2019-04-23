#!/usr/bin/env python

import unittest
from vpp_papi.vpp_serializer import VPPType, VPPEnumType
from vpp_papi.vpp_serializer import VPPUnionType, VPPMessage
from vpp_papi.vpp_serializer import VPPTypeAlias, VPPSerializerValueError
from socket import inet_pton, AF_INET, AF_INET6
import logging
import sys
from ipaddress import *

class TestLimits(unittest.TestCase):
    def test_limit(self):
        limited_type = VPPType('limited_type_t',
                               [['string', 'name', {'limit': 16}]])
        unlimited_type = VPPType('limited_type_t',
                                 [['string', 'name']])


        b = limited_type.pack({'name':'foobar'})
        self.assertEqual(len(b), 10)
        b = unlimited_type.pack({'name':'foobar'})
        self.assertEqual(len(b), 10)

        with self.assertRaises(VPPSerializerValueError):
            b = limited_type.pack({'name':'foobar'*3})

class TestAddType(unittest.TestCase):

    def test_union(self):
        un = VPPUnionType('test_union',
                          [['u8', 'is_bool'],
                           ['u32', 'is_int']])

        b = un.pack({'is_int': 0x12345678})
        nt, size = un.unpack(b)
        self.assertEqual(len(b), size)
        self.assertEqual(nt.is_bool, 0x12)
        self.assertEqual(nt.is_int, 0x12345678)

    def test_address(self):
        af = VPPEnumType('vl_api_address_family_t', [["ADDRESS_IP4", 0],
                                                     ["ADDRESS_IP6", 1],
                                                     {"enumtype": "u32"}])
        ip4 = VPPTypeAlias('vl_api_ip4_address_t', {'type': 'u8',
                                                    'length': 4})
        ip6 = VPPTypeAlias('vl_api_ip6_address_t', {'type': 'u8',
                                                    'length': 16})
        VPPUnionType('vl_api_address_union_t',
                     [["vl_api_ip4_address_t", "ip4"],
                      ["vl_api_ip6_address_t", "ip6"]])

        address = VPPType('vl_api_address_t',
                          [['vl_api_address_family_t', 'af'],
                           ['vl_api_address_union_t', 'un']])

        va_address_list = VPPType('list_addresses',
                                  [['u8', 'count'],
                                   ['vl_api_address_t', 'addresses',
                                    0, 'count']])

        message_with_va_address_list = VPPType('msg_with_vla',
                                               [['list_addresses',
                                                 'vla_address'],
                                                ['u8', 'is_cool']])

        b = ip4.pack(inet_pton(AF_INET, '1.1.1.1'))
        self.assertEqual(len(b), 4)
        nt, size = ip4.unpack(b)
        self.assertEqual(str(nt), '1.1.1.1')

        b = ip6.pack(inet_pton(AF_INET6, '1::1'))
        self.assertEqual(len(b), 16)

        b = address.pack({'af': af.ADDRESS_IP4,
                          'un':
                          {'ip4': inet_pton(AF_INET, '2.2.2.2')}})
        self.assertEqual(len(b), 20)

        nt, size = address.unpack(b)
        self.assertEqual(str(nt), '2.2.2.2')

        # List of addresses
        address_list = []
        for i in range(4):
            address_list.append({'af': af.ADDRESS_IP4,
                                 'un':
                                 {'ip4': inet_pton(AF_INET, '2.2.2.2')}})
        b = va_address_list.pack({'count': len(address_list),
                                  'addresses': address_list})
        self.assertEqual(len(b), 81)

        nt, size = va_address_list.unpack(b)
        self.assertEqual(str(nt.addresses[0]), '2.2.2.2')

        b = message_with_va_address_list.pack({'vla_address':
                                               {'count': len(address_list),
                                                'addresses': address_list},
                                               'is_cool': 100})
        self.assertEqual(len(b), 82)
        nt, size = message_with_va_address_list.unpack(b)
        self.assertEqual(nt.is_cool, 100)

    def test_recursive_address(self):
        af = VPPEnumType('vl_api_address_family_t', [["ADDRESS_IP4", 0],
                                                     ["ADDRESS_IP6", 1],
                                                     {"enumtype": "u32"}])
        ip4 = VPPTypeAlias('vl_api_ip4_address_t', {'type': 'u8',
                                                    'length': 4})
        b = ip4.pack('1.1.1.1')
        self.assertEqual(len(b), 4)
        nt, size = ip4.unpack(b)

        self.assertEqual(str(nt), '1.1.1.1')

        ip6 = VPPTypeAlias('vl_api_ip6_address_t', {'type': 'u8',
                                                    'length': 16})
        VPPUnionType('vl_api_address_union_t',
                     [["vl_api_ip4_address_t", "ip4"],
                      ["vl_api_ip6_address_t", "ip6"]])

        address = VPPType('vl_api_address_t',
                          [['vl_api_address_family_t', 'af'],
                           ['vl_api_address_union_t', 'un']])

        prefix = VPPType('vl_api_prefix_t',
                         [['vl_api_address_t', 'address'],
                          ['u8', 'address_length']])
        message = VPPMessage('svs',
                             [['vl_api_prefix_t', 'prefix']])
        message_addr = VPPMessage('svs_address',
                                  [['vl_api_address_t', 'address']])

        b = message_addr.pack({'address': "1::1"})
        self.assertEqual(len(b), 20)
        nt, size = message_addr.unpack(b)
        self.assertEqual("1::1", str(nt.address))
        b = message_addr.pack({'address': "1.1.1.1"})
        self.assertEqual(len(b), 20)
        nt, size = message_addr.unpack(b)
        self.assertEqual("1.1.1.1", str(nt.address))

        b = message.pack({'prefix': "1.1.1.0/24"})
        self.assertEqual(len(b), 21)
        nt, size = message.unpack(b)
        self.assertEqual("1.1.1.0/24", str(nt.prefix))

        message_array = VPPMessage('address_array',
                                   [['vl_api_ip6_address_t',
                                     'addresses', 2]])
        b = message_array.pack({'addresses': [IPv6Address(u"1::1"), "2::2"]})
        self.assertEqual(len(b), 32)
        message_array_vla = VPPMessage('address_array_vla',
                                       [['u32', 'num'],
                                        ['vl_api_ip6_address_t',
                                         'addresses', 0, 'num']])
        b = message_array_vla.pack({'addresses': ["1::1", "2::2"], 'num': 2})
        self.assertEqual(len(b), 36)

        message_array4 = VPPMessage('address_array4',
                                    [['vl_api_ip4_address_t',
                                      'addresses', 2]])
        b = message_array4.pack({'addresses': ["1.1.1.1", "2.2.2.2"]})
        self.assertEqual(len(b), 8)
        b = message_array4.pack({'addresses': [IPv4Address(u"1.1.1.1"),
                                               "2.2.2.2"]})
        self.assertEqual(len(b), 8)

        message = VPPMessage('address', [['vl_api_address_t', 'address']])
        b = message.pack({'address': '1::1'})
        self.assertEqual(len(b), 20)
        b = message.pack({'address': '1.1.1.1'})
        self.assertEqual(len(b), 20)
        message = VPPMessage('prefix', [['vl_api_prefix_t', 'prefix']])
        b = message.pack({'prefix': '1::1/130'})
        self.assertEqual(len(b), 21)
        b = message.pack({'prefix': IPv6Network(u'1::/119')})
        self.assertEqual(len(b), 21)
        b = message.pack({'prefix': IPv4Network(u'1.1.0.0/16')})
        self.assertEqual(len(b), 21)

    def test_zero_vla(self):
        '''Default zero'ed out for VLAs'''
        list = VPPType('vl_api_list_t',
                       [['u8', 'count', 10]])

        # Define an embedded VLA type
        valist = VPPType('vl_api_valist_t',
                         [['u8', 'count'],
                          ['u8', 'string', 0, 'count']])
        # Define a message
        vamessage = VPPMessage('vamsg',
                               [['vl_api_valist_t', 'valist'],
                                ['u8', 'is_something']])

        message = VPPMessage('msg',
                             [['vl_api_list_t', 'list'],
                              ['u8', 'is_something']])

        # Pack message without VLA specified
        b = message.pack({'is_something': 1})
        b = vamessage.pack({'is_something': 1})

    def test_arrays(self):
        # Test cases
        # 1. Fixed list
        # 2. Fixed list of variable length sub type
        # 3. Variable length type
        #
        s = VPPType('str', [['u32', 'length'],
                            ['u8', 'string', 0, 'length']])

        ip4 = VPPType('ip4_address', [['u8', 'address', 4]])
        listip4 = VPPType('list_ip4_t', [['ip4_address', 'addresses', 4]])
        valistip4 = VPPType('list_ip4_t',
                            [['u8', 'count'],
                             ['ip4_address', 'addresses', 0, 'count']])

        valistip4_legacy = VPPType('list_ip4_t',
                                   [['u8', 'foo'],
                                    ['ip4_address', 'addresses', 0]])

        addresses = []
        for i in range(4):
            addresses.append({'address': inet_pton(AF_INET, '2.2.2.2')})
        b = listip4.pack({'addresses': addresses})
        self.assertEqual(len(b), 16)
        nt, size = listip4.unpack(b)
        self.assertEqual(nt.addresses[0].address,
                         inet_pton(AF_INET, '2.2.2.2'))

        b = valistip4.pack({'count': len(addresses), 'addresses': addresses})
        self.assertEqual(len(b), 17)

        nt, size = valistip4.unpack(b)
        self.assertEqual(nt.count, 4)
        self.assertEqual(nt.addresses[0].address,
                         inet_pton(AF_INET, '2.2.2.2'))

        b = valistip4_legacy.pack({'foo': 1, 'addresses': addresses})
        self.assertEqual(len(b), 17)
        nt, size = valistip4_legacy.unpack(b)
        self.assertEqual(len(nt.addresses), 4)
        self.assertEqual(nt.addresses[0].address,
                         inet_pton(AF_INET, '2.2.2.2'))

        string = 'foobar foobar'
        b = s.pack({'length': len(string), 'string': string.encode('utf-8')})
        nt, size = s.unpack(b)
        self.assertEqual(len(b), size)

    def test_string(self):
        s = VPPType('str', [['u32', 'length'],
                            ['u8', 'string', 0, 'length']])

        string = ''
        b = s.pack({'length': len(string), 'string': string.encode('utf-8')})
        nt, size = s.unpack(b)
        self.assertEqual(len(b), size)

    def test_message(self):
        foo = VPPMessage('foo', [['u16', '_vl_msg_id'],
                                 ['u8', 'client_index'],
                                 ['u8', 'something'],
                                 {"crc": "0x559b9f3c"}])
        b = foo.pack({'_vl_msg_id': 1, 'client_index': 5,
                      'something': 200})
        nt, size = foo.unpack(b)
        self.assertEqual(len(b), size)
        self.assertEqual(nt.something, 200)

    def test_abf(self):

        fib_mpls_label = VPPType('vl_api_fib_mpls_label_t',
                                 [['u8', 'is_uniform'],
                                  ['u32', 'label'],
                                  ['u8', 'ttl'],
                                  ['u8', 'exp']])

        label_stack = {'is_uniform': 0,
                       'label': 0,
                       'ttl': 0,
                       'exp': 0}

        b = fib_mpls_label.pack(label_stack)
        self.assertEqual(len(b), 7)

        fib_path = VPPType('vl_api_fib_path_t',
                           [['u32', 'sw_if_index'],
                            ['u32', 'table_id'],
                            ['u8', 'weight'],
                            ['u8', 'preference'],
                            ['u8', 'is_local'],
                            ['u8', 'is_drop'],
                            ['u8', 'is_udp_encap'],
                            ['u8', 'is_unreach'],
                            ['u8', 'is_prohibit'],
                            ['u8', 'is_resolve_host'],
                            ['u8', 'is_resolve_attached'],
                            ['u8', 'is_dvr'],
                            ['u8', 'is_source_lookup'],
                            ['u8', 'afi'],
                            ['u8', 'next_hop', 16],
                            ['u32', 'next_hop_id'],
                            ['u32', 'rpf_id'],
                            ['u32', 'via_label'],
                            ['u8', 'n_labels'],
                            ['vl_api_fib_mpls_label_t', 'label_stack', 16]])
        label_stack_list = []
        for i in range(16):
            label_stack_list.append(label_stack)

        paths = {'is_udp_encap': 0,
                 'next_hop': b'\x10\x02\x02\xac',
                 'table_id': 0,
                 'afi': 0,
                 'weight': 1,
                 'next_hop_id': 4294967295,
                 'label_stack': label_stack_list,
                 'n_labels': 0,
                 'sw_if_index': 4294967295,
                 'preference': 0}

        b = fib_path.pack(paths)
        self.assertEqual(len(b), (7*16) + 49)

        abf_policy = VPPType('vl_api_abf_policy_t',
                             [['u32', 'policy_id'],
                              ['u32', 'acl_index'],
                              ['u8', 'n_paths'],
                              ['vl_api_fib_path_t', 'paths', 0, 'n_paths']])

        policy = {
            'n_paths': 1,
            'paths': [paths],
            'acl_index': 0,
            'policy_id': 10}

        b = abf_policy.pack(policy)
        self.assertEqual(len(b), (7*16) + 49 + 9)

        abf_policy_add_del = VPPMessage('abf_policy_add_del',
                                        [['u16', '_vl_msg_id'],
                                         ['u32', 'client_index'],
                                         ['u32', 'context'],
                                         ['u8', 'is_add'],
                                         ['vl_api_abf_policy_t', 'policy']])

        b = abf_policy_add_del.pack({'is_add': 1,
                                     'context': 66,
                                     '_vl_msg_id': 1066,
                                     'policy': policy})

        nt, size = abf_policy_add_del.unpack(b)
        self.assertEqual(nt.policy.paths[0].next_hop,
                         b'\x10\x02\x02\xac\x00\x00\x00\x00'
                         b'\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_bier(self):

        bier_table_id = VPPType('vl_api_bier_table_id_t',
                                [['u8', 'bt_set'],
                                 ['u8', 'bt_sub_domain'],
                                 ['u8', 'bt_hdr_len_id']])

        bier_imp_add = VPPMessage('bier_imp_add',
                                  [['u32', 'client_index'],
                                   ['u32', 'context'],
                                   ['vl_api_bier_table_id_t', 'bi_tbl_id'],
                                   ['u16', 'bi_src'],
                                   ['u8', 'bi_n_bytes'],
                                   ['u8', 'bi_bytes', 0, 'bi_n_bytes']])

        table_id = {'bt_set': 0,
                    'bt_sub_domain': 0,
                    'bt_hdr_len_id': 0}

        bibytes = b'foobar'

        b = bier_imp_add.pack({'bi_tbl_id': table_id,
                               'bi_n_bytes': len(bibytes),
                               'bi_bytes': bibytes})

        self.assertEqual(len(b), 20)


if __name__ == '__main__':
    unittest.main()
