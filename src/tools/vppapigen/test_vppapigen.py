#!/usr/bin/env python3

import unittest

from vppapigen import VPPAPI, Option, ParseError, Union

# TODO
# - test parsing of options, typedefs, enums, defines, CRC
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
