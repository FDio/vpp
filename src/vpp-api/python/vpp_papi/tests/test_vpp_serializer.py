#!/usr/bin/env python3

import unittest
from vpp_papi.vpp_serializer import VPPType, VPPEnumType, VPPEnumFlagType
from vpp_papi.vpp_serializer import VPPUnionType, VPPMessage
from vpp_papi.vpp_serializer import VPPTypeAlias, VPPSerializerValueError
from vpp_papi import MACAddress
from socket import inet_pton, AF_INET, AF_INET6
import logging
import sys
from ipaddress import *


class TestLimits(unittest.TestCase):
    def test_string(self):
        fixed_string = VPPType('fixed_string',
                               [['string', 'name', 16]])

        b = fixed_string.pack({'name': 'foobar'})
        self.assertEqual(len(b), 16)

        # Ensure string is nul terminated
        self.assertEqual(b.decode('ascii')[6], '\x00')

        nt, size = fixed_string.unpack(b)
        self.assertEqual(size, 16)
        self.assertEqual(nt.name, 'foobar')

        # Empty string
        b = fixed_string.pack({'name': ''})
        self.assertEqual(len(b), 16)
        nt, size = fixed_string.unpack(b)
        self.assertEqual(size, 16)
        self.assertEqual(nt.name, '')

        # String too long
        with self.assertRaises(VPPSerializerValueError):
            b = fixed_string.pack({'name': 'foobarfoobar1234'})

        variable_string = VPPType('variable_string',
                                  [['string', 'name', 0]])
        b = variable_string.pack({'name': 'foobar'})
        self.assertEqual(len(b), 4 + len('foobar'))

        nt, size = variable_string.unpack(b)
        self.assertEqual(size, 4 + len('foobar'))
        self.assertEqual(nt.name, 'foobar')
        self.assertEqual(len(nt.name), len('foobar'))

    def test_limit(self):
        limited_type = VPPType('limited_type_t',
                               [['string', 'name', 0, {'limit': 16}]])
        unlimited_type = VPPType('limited_type_t',
                                 [['string', 'name', 0]])

        b = limited_type.pack({'name': 'foobar'})
        self.assertEqual(len(b), 10)
        b = unlimited_type.pack({'name': 'foobar'})
        self.assertEqual(len(b), 10)

        with self.assertRaises(VPPSerializerValueError):
            b = limited_type.pack({'name': 'foobar'*3})


class TestDefaults(unittest.TestCase):
    def test_defaults(self):
        default_type = VPPType('default_type_t',
                               [['u16', 'mtu', {'default': 1500, 'limit': 0}]])
        without_default_type = VPPType('without_default_type_t',
                                       [['u16', 'mtu']])

        b = default_type.pack({})
        self.assertEqual(len(b), 2)
        nt, size = default_type.unpack(b)
        self.assertEqual(len(b), size)
        self.assertEqual(nt.mtu, 1500)

        # distinguish between parameter 0 and parameter not passed
        b = default_type.pack({'mtu': 0})
        self.assertEqual(len(b), 2)
        nt, size = default_type.unpack(b)
        self.assertEqual(len(b), size)
        self.assertEqual(nt.mtu, 0)

        # Ensure that basetypes does not inherit default
        b = without_default_type.pack({})
        self.assertEqual(len(b), 2)
        nt, size = default_type.unpack(b)
        self.assertEqual(len(b), size)
        self.assertEqual(nt.mtu, 0)

        # default enum type
        VPPEnumType('vl_api_enum_t', [["ADDRESS_IP4", 0],
                                      ["ADDRESS_IP6", 1],
                                      {"enumtype": "u32"}])

        default_with_enum = VPPType('default_enum_type_t',
                                    [['u16', 'mtu'], ['vl_api_enum_t',
                                                      'e', {'default': 1}]])

        b = default_with_enum.pack({})
        self.assertEqual(len(b), 6)
        nt, size = default_with_enum.unpack(b)
        self.assertEqual(len(b), size)
        self.assertEqual(nt.e, 1)


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
        aff = VPPEnumFlagType('vl_api_address_family_flag_t', [["ADDRESS_IP4", 0],
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

        prefix = VPPType('vl_api_prefix_t',
                         [['vl_api_address_t', 'address'],
                          ['u8', 'len']])

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

    def test_address_with_prefix(self):
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

        prefix = VPPType('vl_api_prefix_t',
                         [['vl_api_address_t', 'address'],
                          ['u8', 'len']])
        prefix4 = VPPType('vl_api_ip4_prefix_t',
                          [['vl_api_ip4_address_t', 'address'],
                          ['u8', 'len']])
        prefix6 = VPPType('vl_api_ip6_prefix_t',
                          [['vl_api_ip6_address_t', 'address'],
                          ['u8', 'len']])

        address_with_prefix = VPPTypeAlias('vl_api_address_with_prefix_t', {'type': 'vl_api_prefix_t' })
        address4_with_prefix = VPPTypeAlias('vl_api_ip4_address_with_prefix_t',
                                            {'type': 'vl_api_ip4_prefix_t' })
        address6_with_prefix = VPPTypeAlias('vl_api_ip6_address_with_prefix_t',
                                            {'type': 'vl_api_ip6_prefix_t' })

        awp_type = VPPType('foobar_t',
                           [['vl_api_address_with_prefix_t', 'address']])

        # address with prefix
        b = address_with_prefix.pack(IPv4Interface('2.2.2.2/24'))
        self.assertEqual(len(b), 21)
        nt, size = address_with_prefix.unpack(b)
        self.assertTrue(isinstance(nt, IPv4Interface))
        self.assertEqual(str(nt), '2.2.2.2/24')

        b = address_with_prefix.pack(IPv6Interface('2::2/64'))
        self.assertEqual(len(b), 21)
        nt, size = address_with_prefix.unpack(b)
        self.assertTrue(isinstance(nt, IPv6Interface))
        self.assertEqual(str(nt), '2::2/64')

        b = address_with_prefix.pack(IPv4Network('2.2.2.2/24', strict=False))
        self.assertEqual(len(b), 21)
        nt, size = address_with_prefix.unpack(b)
        self.assertTrue(isinstance(nt, IPv4Interface))
        self.assertEqual(str(nt), '2.2.2.0/24')

        b = address4_with_prefix.pack('2.2.2.2/24')
        self.assertEqual(len(b), 5)
        nt, size = address4_with_prefix.unpack(b)
        self.assertTrue(isinstance(nt, IPv4Interface))
        self.assertEqual(str(nt), '2.2.2.2/24')
        b = address4_with_prefix.pack(IPv4Interface('2.2.2.2/24'))
        self.assertEqual(len(b), 5)

        b = address6_with_prefix.pack('2::2/64')
        self.assertEqual(len(b), 17)
        nt, size = address6_with_prefix.unpack(b)
        self.assertTrue(isinstance(nt, IPv6Interface))
        self.assertEqual(str(nt), '2::2/64')
        b = address6_with_prefix.pack(IPv6Interface('2::2/64'))
        self.assertEqual(len(b), 17)

        b = prefix.pack('192.168.10.0/24')
        self.assertEqual(len(b), 21)
        nt, size = prefix.unpack(b)
        self.assertTrue(isinstance(nt, IPv4Network))
        self.assertEqual(str(nt), '192.168.10.0/24')

        b = awp_type.pack({'address': '1.2.3.4/24'})
        self.assertEqual(len(b), 21)
        nt, size = awp_type.unpack(b)
        self.assertTrue(isinstance(nt.address, IPv4Interface))
        self.assertEqual(str(nt.address), '1.2.3.4/24')

        b = awp_type.pack({'address': IPv4Interface('1.2.3.4/24')})
        self.assertEqual(len(b), 21)
        nt, size = awp_type.unpack(b)
        self.assertTrue(isinstance(nt.address, IPv4Interface))
        self.assertEqual(str(nt.address), '1.2.3.4/24')

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
                          ['u8', 'len']])
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

    def test_lisp(self):
        VPPEnumType('vl_api_eid_type_t',
                    [["EID_TYPE_API_PREFIX", 0],
                     ["EID_TYPE_API_MAC", 1],
                     ["EID_TYPE_API_NSH", 2],
                     {"enumtype": "u32"}])

        VPPTypeAlias('vl_api_mac_address_t', {'type': 'u8',
                                              'length': 6})

        VPPType('vl_api_nsh_t',
                [["u32", "spi"],
                 ["u8", "si"]])

        VPPEnumType('vl_api_address_family_t', [["ADDRESS_IP4", 0],
                                                ["ADDRESS_IP6", 1],
                                                {"enumtype": "u32"}])
        VPPTypeAlias('vl_api_ip4_address_t', {'type': 'u8',
                                              'length': 4})
        VPPTypeAlias('vl_api_ip6_address_t', {'type': 'u8',
                                              'length': 16})
        VPPUnionType('vl_api_address_union_t',
                     [["vl_api_ip4_address_t", "ip4"],
                      ["vl_api_ip6_address_t", "ip6"]])

        VPPType('vl_api_address_t',
                [['vl_api_address_family_t', 'af'],
                 ['vl_api_address_union_t', 'un']])

        VPPType('vl_api_prefix_t',
                [['vl_api_address_t', 'address'],
                 ['u8', 'len']])

        VPPUnionType('vl_api_eid_address_t',
                     [["vl_api_prefix_t", "prefix"],
                      ["vl_api_mac_address_t", "mac"],
                      ["vl_api_nsh_t", "nsh"]])

        eid = VPPType('vl_api_eid_t',
                      [["vl_api_eid_type_t", "type"],
                       ["vl_api_eid_address_t", "address"]])

        b = eid.pack({'type':1,
                      'address': {
                          'mac': MACAddress('aa:bb:cc:dd:ee:ff')}})
        self.assertEqual(len(b), 25)
        nt, size = eid.unpack(b)
        self.assertEqual(str(nt.address.mac), 'aa:bb:cc:dd:ee:ff')
        self.assertIsNone(nt.address.prefix)


class TestVppSerializerLogging(unittest.TestCase):

    def test_logger(self):
        # test logger name 'vpp_papi.serializer'
        with self.assertRaises(VPPSerializerValueError) as ctx:
            with self.assertLogs('vpp_papi.serializer', level='DEBUG') as cm:
                u = VPPUnionType('vl_api_eid_address_t',
                                 [["vl_api_prefix_t", "prefix"],
                                  ["vl_api_mac_address_t", "mac"],
                                  ["vl_api_nsh_t", "nsh"]])
        self.assertEqual(cm.output, ["DEBUG:vpp_papi.serializer:Unknown union type vl_api_prefix_t"])

        # test parent logger name 'vpp_papi'
        with self.assertRaises(VPPSerializerValueError) as ctx:
            with self.assertLogs('vpp_papi', level='DEBUG') as cm:
                u = VPPUnionType('vl_api_eid_address_t',
                                 [["vl_api_prefix_t", "prefix"],
                                  ["vl_api_mac_address_t", "mac"],
                                  ["vl_api_nsh_t", "nsh"]])
        self.assertEqual(cm.output, ["DEBUG:vpp_papi.serializer:Unknown union type vl_api_prefix_t"])


if __name__ == '__main__':
    unittest.main()
