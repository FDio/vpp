import binascii
from framework import VppTestCase
from vpp_papi import VPP
from vpp_serializer import VPPType, VPPEnumType, VPPUnionType
from socket import inet_pton, AF_INET, AF_INET6

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
        """ show version """
        rv = self.v.show_version()
        self.assertEqual(rv.retval, 0)

    def test_show_version_invalid_param(self):
        """ show version - invalid parameters"""
        self.assertRaises(ValueError, self.v.show_version, foobar='foo')

    def test_u8_array(self):
        """ u8 array """
        rv = self.v.get_node_index(node_name='ip4-lookup')
        self.assertEqual(rv.retval, 0)
        node_name = 'X' * 100
        self.assertRaises(ValueError, self.v.get_node_index,
                          node_name=node_name)


class TestPAPIMessageParsing(VppTestCase):
    """ PAPI Message parsing Test Case """

    def test_union(self):
        un = VPPUnionType('test_union',
                          [['u8', 'is_bool'],
                           ['u32', 'is_int']])

        b = un.pack({'is_int': 0x1234})
        self.assertEqual(len(b), 4)
        nt = un.unpack(b)
        self.assertEqual(nt.is_bool, 52)
        self.assertEqual(nt.is_int, 0x1234)

    def test_address(self):
        af = VPPEnumType('vl_api_address_family_t', [["ADDRESS_IP4", 0],
                                                     ["ADDRESS_IP6", 1],
                                                     {"enumtype": "u32"}])
        ip4 = VPPType('vl_api_ip4_address_t', [['u8', 'address', 4]])
        ip6 = VPPType('vl_api_ip6_address_t', [['u8', 'address', 16]])
        VPPUnionType('vl_api_address_union_t',
                     [["vl_api_ip4_address_t", "ip4"],
                      ["vl_api_ip6_address_t", "ip6"]])

        address = VPPType('address', [['vl_api_address_family_t', 'af'],
                                      ['vl_api_address_union_t', 'un']])

        b = ip4.pack({'address': inet_pton(AF_INET, '1.1.1.1')})
        self.assertEqual(len(b), 4)
        nt = ip4.unpack(b)
        self.assertEqual(nt.address, inet_pton(AF_INET, '1.1.1.1'))

        b = ip6.pack({'address': inet_pton(AF_INET6, '1::1')})
        self.assertEqual(len(b), 16)

        b = address.pack({'af': af.ADDRESS_IP4,
                          'un':
                          {'ip4':
                           {'address': inet_pton(AF_INET, '2.2.2.2')}}})
        self.assertEqual(len(b), 20)

        nt = address.unpack(b)
        self.assertEqual(nt.af, af.ADDRESS_IP4)
        self.assertEqual(nt.un.ip4.address,
                         inet_pton(AF_INET, '2.2.2.2'))
        self.assertEqual(nt.un.ip6.address,
                         inet_pton(AF_INET6, '::0202:0202'))

    def test_arrays(self):
        # Test cases
        # 1. Fixed list
        # 2. Fixed list of variable length sub type
        # 3. Variable length type
        #
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
        nt = listip4.unpack(b)

        self.assertEqual(nt.addresses[0].address,
                         inet_pton(AF_INET, '2.2.2.2'))

        b = valistip4.pack({'count': len(addresses), 'addresses': addresses})
        self.assertEqual(len(b), 17)

        nt = valistip4.unpack(b)

        b = valistip4_legacy.pack({'foo': 1, 'addresses': addresses})
        self.assertEqual(len(b), 17)
        nt = valistip4_legacy.unpack(b)

    def test_message(self):
        foo = VPPType('foo', [['u16', '_vl_msg_id'],
                              ['u8', 'client_index'],
                              ['u8', 'something'],
                              {"crc": "0x559b9f3c"}])
        b = foo.pack({'_vl_msg_id': 1, 'client_index': 5,
                      'something': 200})
        self.assertEqual(len(b), 4)
        nt = foo.unpack(b)
