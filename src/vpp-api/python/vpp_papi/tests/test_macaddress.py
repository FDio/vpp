import unittest
from vpp_papi import MACAddress


class TestMacAddress(unittest.TestCase):

    def test_eq(self):
        mac = '11:22:33:44:55:66'
        self.assertEqual(MACAddress(mac),
                         MACAddress(mac))
