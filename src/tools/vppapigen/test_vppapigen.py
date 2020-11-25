#!/usr/bin/env python3

import unittest
from vppapigen import VPPAPI, Option, ParseError, Union, foldup_crcs, \
    global_types
import vppapigen


# TODO
# - test parsing of options, typedefs, enums, defines
# - test JSON, C output


class TestVersion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = VPPAPI()

    def test_version(self):
        version_string = 'option version = "1.0.0";'
        r = self.parser.parse_string(version_string)
        self.assertTrue(isinstance(r[0], Option))


class TestUnion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = VPPAPI()

    def test_union(self):
        test_string = '''
        union foo_union {
        u32 a;
        u8 b;
        };
        '''
        r = self.parser.parse_string(test_string)
        self.assertTrue(isinstance(r[0], Union))

    def test_union_vla(self):
        test_string = '''
        union foo_union_vla {
        u32 a;
        u8 b[a];
        };
        autoreply define foo {
        vl_api_foo_union_vla_t v;
        };
        '''
        r = self.parser.parse_string(test_string)
        self.assertTrue(isinstance(r[0], Union))
        self.assertTrue(r[0].vla)
        s = self.parser.process(r)

        test_string2 = '''
        union foo_union_vla2 {
        u32 a;
        u8 b[a];
        u32 c;
        };
        autoreply define foo2 {
        vl_api_foo_union_vla2_t v;
        };
        '''
        self.assertRaises(ValueError, self.parser.parse_string, test_string2)

        test_string3 = '''
        union foo_union_vla3 {
        u32 a;
        u8 b[a];
        };
        autoreply define foo3 {
        vl_api_foo_union_vla3_t v;
        u32 x;
        };
        '''
        self.assertRaises(ValueError, self.parser.parse_string, test_string3)


class TestTypedef(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = VPPAPI()

    def test_duplicatetype(self):
        test_string = '''
        typedef foo1 { u8 dummy; };
        typedef foo1 { u8 dummy; };
        '''
        self.assertRaises(KeyError, self.parser.parse_string, test_string)


class TestDefine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = VPPAPI()

    def test_unknowntype(self):
        test_string = 'define foo { foobar foo;};'
        with self.assertRaises(ParseError) as ctx:
            self.parser.parse_string(test_string)
        self.assertIn('Undefined type: foobar', str(ctx.exception))

        test_string = 'define { u8 foo;};'
        with self.assertRaises(ParseError) as ctx:
            self.parser.parse_string(test_string)

    def test_flags(self):
        test_string = '''
          manual_print dont_trace manual_endian define foo { u8 foo; };
          define foo_reply {u32 context; i32 retval; };
        '''
        r = self.parser.parse_string(test_string)
        self.assertIsNotNone(r)
        s = self.parser.process(r)
        self.assertIsNotNone(s)
        for d in s['Define']:
            if d.name == 'foo':
                self.assertTrue(d.dont_trace)
                self.assertTrue(d.manual_endian)
                self.assertTrue(d.manual_print)
                self.assertFalse(d.autoreply)

        test_string = '''
          nonexisting_flag define foo { u8 foo; };
        '''
        with self.assertRaises(ParseError):
            self.parser.parse_string(test_string)

    def test_options(self):
        test_string = '''
          define foo { option deprecated; u8 foo; };
          define foo_reply {u32 context; i32 retval; };
        '''
        r = self.parser.parse_string(test_string)
        self.assertIsNotNone(r)
        s = self.parser.process(r)
        self.assertIsNotNone(s)


class TestService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = VPPAPI()

    def test_service(self):
        test_string = '''
         autoreply define show_version { u8 foo;};
         service { rpc show_version returns show_version_reply; };
        '''
        r = self.parser.parse_string(test_string)
        s = self.parser.process(r)
        self.assertEqual(s['Service'][0].caller, 'show_version')
        self.assertEqual(s['Service'][0].reply, 'show_version_reply')


def get_crc(apistring, name):
    vppapigen.global_types = {}
    parser = vppapigen.VPPAPI()
    r = parser.parse_string(apistring)
    s = parser.process(r)
    foldup_crcs(s['Define'])
    d = [f for f in s['Define'] if f.name == name]
    return d[0].crc


class TestCRC(unittest.TestCase):
    def test_crc(self):
        test_string = '''
         typedef list { u8 foo; };
         autoreply define foo { u8 foo; vl_api_list_t l;};
        '''
        crc = get_crc(test_string, 'foo')

        # modify underlying type
        test_string = '''
         typedef list { u8 foo2; };
         autoreply define foo { u8 foo;  vl_api_list_t l;};
        '''
        crc2 = get_crc(test_string, 'foo')
        self.assertNotEqual(crc, crc2)

        # two user-defined types
        test_string = '''
         typedef address { u8 foo2; };
         typedef list { u8 foo2; vl_api_address_t add; };
         autoreply define foo { u8 foo;  vl_api_list_t l;};
        '''
        crc3 = get_crc(test_string, 'foo')

        test_string = '''
         typedef address { u8 foo3; };
         typedef list { u8 foo2; vl_api_address_t add; };
         autoreply define foo { u8 foo;  vl_api_list_t l;};
        '''
        crc4 = get_crc(test_string, 'foo')
        self.assertNotEqual(crc3, crc4)

        test_string = '''
         typedef address { u8 foo3; };
         typedef list { u8 foo2; vl_api_address_t add; u8 foo3; };
         autoreply define foo { u8 foo;  vl_api_list_t l;};
        '''
        crc5 = get_crc(test_string, 'foo')
        self.assertNotEqual(crc4, crc5)

        test_string = '''
typedef ip6_address
{
  u8 foo;
};
typedef srv6_sid_list
{
  u8 num_sids;
  u32 weight;
  u32 sl_index;
  vl_api_ip6_address_t sids[16];
};
autoreply define sr_policy_add
{
  u32 client_index;
  u32 context;
  vl_api_ip6_address_t bsid_addr;
  u32 weight;
  bool is_encap;
  bool is_spray;
  u32 fib_table;
  vl_api_srv6_sid_list_t sids;
};
'''

        crc = get_crc(test_string, 'sr_policy_add')

        test_string = '''
typedef ip6_address
{
  u8 foo;
};
typedef srv6_sid_list
{
  u8 num_sids;
  u32 weight;
  vl_api_ip6_address_t sids[16];
};
autoreply define sr_policy_add
{
  u32 client_index;
  u32 context;
  vl_api_ip6_address_t bsid_addr;
  u32 weight;
  bool is_encap;
  bool is_spray;
  u32 fib_table;
  vl_api_srv6_sid_list_t sids;
};
'''
        crc2 = get_crc(test_string, 'sr_policy_add')

        self.assertNotEqual(crc, crc2)


class TestEnum(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.parser = VPPAPI()

    def test_enum_as_enum(self):
        test_string = """\
enum tunnel_mode : u8
{
  /** point-to-point */
  TUNNEL_API_MODE_P2P = 0,
  /** multi-point */
  TUNNEL_API_MODE_MP,
};
"""
        r = self.parser.parse_string(test_string)
        self.assertIsNotNone(r)
        s = self.parser.process(r)
        for o in s['types']:
            if o.type == 'Enum':
                self.assertEqual(o.name, "tunnel_mode")
                break
        else:
            self.fail()

    def test_enumflag_as_enum(self):
        test_string = """\
enum virtio_flags {
        VIRTIO_API_FLAG_GSO = 1, /* enable gso on the interface */
        VIRTIO_API_FLAG_CSUM_OFFLOAD = 2, /* enable checksum offload without gso on the interface */
        VIRTIO_API_FLAG_GRO_COALESCE = 4, /* enable packet coalescing on tx side, provided gso enabled */
        VIRTIO_API_FLAG_PACKED = 8, /* enable packed ring support, provided it is available from backend */
        VIRTIO_API_FLAG_IN_ORDER = 16, /* enable in order support, provided it is available from backend */
        VIRTIO_API_FLAG_BUFFERING = 32 [backwards_compatible], /* enable buffering to handle backend jitter/delays */
};"""
        r = self.parser.parse_string(test_string)
        self.assertIsNotNone(r)
        s = self.parser.process(r)
        for o in s['types']:
            if o.type == 'Enum':
                self.assertEqual(o.name, "virtio_flags")
                break
        else:
            self.fail()


class TestEnumFlag(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.parser = VPPAPI()

    def test_enum_as_enumflag(self):
        test_string = """\
enumflag tunnel_mode_ef : u8
{
  /** point-to-point */
  TUNNEL_API_MODE_P2P = 0,
  /** multi-point */
  TUNNEL_API_MODE_MP,
};"""
        r = self.parser.parse_string(test_string)
        self.assertIsNotNone(r)
        s = self.parser.process(r)
        for o in s['types']:
            if o.type == 'EnumFlag':
                self.assertEqual(o.name, "tunnel_mode_ef")
                break
        else:
            self.fail()

    def test_enumflag_as_enumflag(self):
        test_string = """\
enumflag virtio_flags_ef {
        VIRTIO_API_FLAG_GSO = 1, /* enable gso on the interface */
        VIRTIO_API_FLAG_CSUM_OFFLOAD = 2, /* enable checksum offload without gso on the interface */
        VIRTIO_API_FLAG_GRO_COALESCE = 4, /* enable packet coalescing on tx side, provided gso enabled */
        VIRTIO_API_FLAG_PACKED = 8, /* enable packed ring support, provided it is available from backend */
        VIRTIO_API_FLAG_IN_ORDER = 16, /* enable in order support, provided it is available from backend */
        VIRTIO_API_FLAG_BUFFERING = 32 [backwards_compatible], /* enable buffering to handle backend jitter/delays */
};"""
        r = self.parser.parse_string(test_string)
        self.assertIsNotNone(r)
        s = self.parser.process(r)
        for o in s['types']:
            if o.type == 'EnumFlag':
                self.assertEqual(o.name, "virtio_flags_ef")
                break
        else:
            self.fail()


if __name__ == '__main__':
    unittest.main(verbosity=2)
