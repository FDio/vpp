# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Bo Xu <i@186526.xyz>

import ipaddress
import unittest

from vpp_papi import vpp_papi
from vpp_papi import vpp_papi_async

JSON_API = """\
{
    "enums": [
        [
            "address_family",
            [
                "ADDRESS_IP4",
                0
            ],
            [
                "ADDRESS_IP6",
                1
            ],
            {
                "enumtype": "u8"
            }
        ]
    ]
}
"""


class TestVapiAf(unittest.TestCase):
    """The vapi_af and vapi_af_name properties of an IP address."""

    def setUp(self):
        # The properties resolve the address_family enum through the type
        # table, so make sure that enum is known.
        vpp_papi.VPPApiJSONFiles().process_json_str(JSON_API)

    def test_vapi_af_and_name_of_ip_address(self):
        af = vpp_papi.VppEnum.vl_api_address_family_t

        # Both modules install the properties on the same base class, so
        # install one at a time to exercise both implementations.
        for module in (vpp_papi, vpp_papi_async):
            with self.subTest(module=module.__name__):
                module.add_convenience_methods()
                ip4 = ipaddress.ip_address("1.2.3.4")
                ip6 = ipaddress.ip_address("::1")
                self.assertEqual(af.ADDRESS_IP4.value, ip4.vapi_af)
                self.assertEqual(af.ADDRESS_IP6.value, ip6.vapi_af)
                self.assertEqual("ip4", ip4.vapi_af_name)
                self.assertEqual("ip6", ip6.vapi_af_name)

    def test_vapi_af_rejects_other_versions(self):
        class NotAnIpAddress(ipaddress.IPv4Address):
            version = 5

        for module in (vpp_papi, vpp_papi_async):
            with self.subTest(module=module.__name__):
                module.add_convenience_methods()
                addr = NotAnIpAddress("1.2.3.4")
                for attr in ("vapi_af", "vapi_af_name"):
                    with self.assertRaises(ValueError) as cm:
                        getattr(addr, attr)
                    self.assertIn("Invalid version", str(cm.exception))
