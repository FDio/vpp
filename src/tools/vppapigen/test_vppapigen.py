#!/usr/bin/env python

import unittest
from vppapigen import VPPAPI, Option, ParseError

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


class TestTypedef(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = VPPAPI()

    def test_duplicatetype(self):
        test_string = '''
        typeonly define foo1 { u8 dummy; };
        typeonly define foo1 { u8 dummy; };
        '''
        self.assertRaises(KeyError, self.parser.parse_string, test_string)


class TestDefine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = VPPAPI()

    def test_unknowntype(self):
        test_string = 'define foo { foobar foo;};'
        self.assertRaises(ParseError, self.parser.parse_string, test_string)
        test_string = 'define { u8 foo;};'
        self.assertRaises(ParseError, self.parser.parse_string, test_string)

    def test_flags(self):
        test_string = '''
          manual_print dont_trace manual_endian define foo { u8 foo; };
        '''
        r = self.parser.parse_string(test_string)
        self.assertIsNotNone(r)
        s = self.parser.process(r)
        self.assertIsNotNone(s)
        for d in s['defines']:
            self.assertTrue(d.dont_trace)
            self.assertTrue(d.manual_endian)
            self.assertTrue(d.manual_print)
            self.assertFalse(d.autoreply)

        test_string = '''
          nonexisting_flag define foo { u8 foo; };
        '''
        self.assertRaises(ParseError, self.parser.parse_string, test_string)


class TestService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = VPPAPI()

    def test_service(self):
        test_string = '''
         service foo { rpc foo (show_version) returns (show_version) };
        '''
        r = self.parser.parse_string(test_string)
        print('R', r)


if __name__ == '__main__':
    unittest.main()
