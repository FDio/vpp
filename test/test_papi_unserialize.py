import struct
from unittest import TestCase
from vpp_papi_unserialize import VPPUnserialize
from vpp_papi_unserialize import VPPUnserializeBuffer

""" TestPAPIUnserialize is a subclass of VPPTestCase classes.

Basic tests for the VPP Unserializer. This decodes data delivered
by means other than in an API message directly, such as the indirect
reply_in_shmem method.

"""


class DummySuint(VPPUnserialize):
    suint = 0

    struct = [
            ['suint', 'suint'],
    ]


class DummyString(VPPUnserialize):
    string = None

    struct = [
            ['string', 'cstring'],
    ]


class DummyNested(VPPUnserialize):
    nested_suint = None
    nested_string = None

    struct = [
            ['nested_suint', DummySuint],
            ['nested_string', DummyString],
    ]


class DummyList(VPPUnserialize):
    _nitems = 0
    items = None

    struct = [
            ['_nitems', 'suint'],
            ['items', 'list', '_nitems', 'suint'],
    ]

    def __init__(self, buf=None):
        self.items = []
        super(DummyList, self).__init__(buf)


class TestPAPIUnserialize(TestCase):
    """ PAPI VPP Unserialize Test Case """

    def encode_suint(self, x):
        r = x
        if r < (1 << 7):
            return bytes(struct.pack('B', (r << 1) | 1))

        r -= (1 << 7)
        if r < (1 << 14):
            return bytes(struct.pack('<H', (r << 2) | 2))

        r -= (1 << 14)
        if r < (1 << 29):
            return bytes(struct.pack('<I', (r << 3) | 4))

        return bytes(struct.pack('<BQ', 0, x))

    def test_basic_int(self):
        for v in (0, 1,
                  127, 128,
                  16255, 16256,
                  536854655, 536854656,
                  1 << 32, 1 << 63):
            b = VPPUnserializeBuffer(self.encode_suint(v))
            t = DummySuint(b)
            self.assertEqual(t.suint, v,
                             "decoded value '%x' should equal '%x'" %
                             (t.suint, v))
            self.assertEqual(b.offset, len(b.data),
                             "buffer offset should equal its length")

    def test_basic_string(self):
        string = "This is a test string"
        buf = self.encode_suint(len(string)) + bytes(string)
        b = VPPUnserializeBuffer(buf)
        t = DummyString(b)
        self.assertEqual(t.string, string,
                         "decoded string '%s' should equal '%s'" %
                         (t.string, string))
        self.assertEqual(b.offset, len(b.data),
                         "buffer offset should equal its length")

    def test_types_nested(self):
        val = 0xaa55
        string = "This is our super special string"
        buf = self.encode_suint(val)
        buf += self.encode_suint(len(string)) + bytes(string)
        b = VPPUnserializeBuffer(buf)
        t = DummyNested(b)
        self.assertIsInstance(t.nested_suint, DummySuint)
        self.assertIsInstance(t.nested_string, DummyString)
        self.assertEqual(t.nested_suint.suint, val)
        self.assertEqual(t.nested_string.string, string)
        self.assertEqual(b.offset, len(b.data),
                         "buffer offset should equal its length")

    def test_types_list(self):
        vals = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
        buf = self.encode_suint(len(vals))
        for val in vals:
            buf += self.encode_suint(val)
        b = VPPUnserializeBuffer(buf)
        t = DummyList(b)
        self.assertIsInstance(t.items, list,
                              "Decoded items should be of type 'list'")
        self.assertEqual(len(t.items), len(vals),
                         "Decoded list of '%s' items should have '%d' items" %
                         (len(t.items), len(vals)))
        self.assertEqual(t.items, vals,
                         "Decoded list %s should equal %s" %
                         (repr(t.items), vals))
        self.assertEqual(b.offset, len(b.data),
                         "buffer offset should equal its length")
