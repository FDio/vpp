import binascii
from framework import VppTestCase

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
