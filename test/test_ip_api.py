#!/usr/bin/env python3
#  Copyright (c) 2020. Vinci Consulting Corp. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

""" Tests against src/vnet/ip/ip.api """

import unittest

import framework


class TestIpApiDumpFields(framework.VppTestCase):
    """Test ip.api.ip_address_dump"""

    def test_ip_address_dump_details(self):
        # use if addresses with non-zero host bits.
        if_v4_addrs = ['10.0.0.1/8', '192.168.10.1/24']
        if_v6_addrs = ['2601:1f00::1/64', 'db01::1234/128']

        self.vapi.cli("comment {Test that the api returns the proper values.}")
        self.vapi.create_loopback_instance(is_specified=1,
                                           user_instance=10)
        self.vapi.cli(
            "comment {Add two v4 addresses to the interface(via cli).}")
        for if_addr in if_v4_addrs:
            self.vapi.cli(f"set interface ip address loop10 {if_addr}")
        for if_addr in if_v4_addrs:
            rv = self.vapi.cli("sho int addr")
            self.assertIn(if_addr, rv, f"{if_addr} not in sho int addr.")
        for if_addr in if_v4_addrs:
            rv = [str(x.prefix) for x in
                  self.vapi.ip_address_dump(sw_if_index=1)]
            self.assertIn(if_addr, rv, f"{if_addr} not in ip_address_dump().")

        self.vapi.cli(
            "comment {Add two v6 addresses to the interface(via cli).}")
        for if_addr in if_v6_addrs:
            self.vapi.cli(f"set interface ip address loop10 {if_addr}")
        for if_addr in if_v6_addrs:
            rv = self.vapi.cli("sho int addr")
            self.assertIn(if_addr, rv, f"{if_addr} not in sho int addr.")
        for if_addr in if_v6_addrs:
            rv = [str(x.prefix) for x in
                  self.vapi.ip_address_dump(sw_if_index=1, is_ipv6=True)]
            self.assertIn(if_addr, rv, f"{if_addr} not in "
                                       f"ip_address_dump(is_ipv6=True).")

        self.vapi.cli("comment {Add an unnumbered interface.}")
        self.vapi.create_loopback_instance(is_specified=1,
                                           user_instance=20)
        self.vapi.cli(f"set interface unnumbered loop20 use loop10")

        for if_addr in if_v4_addrs:
            rv = [str(x.prefix) for x in
                  self.vapi.ip_address_dump(
                      self.vapi.ip_unnumbered_dump(
                          sw_if_index=2)[0].ip_sw_if_index)]
            self.assertIn(if_addr, rv, f"{if_addr} not in "
                                       f"ip_unnumbered_dump().")

        for if_addr in if_v6_addrs:
            rv = [str(x.prefix) for x in
                  self.vapi.ip_address_dump(
                      self.vapi.ip_unnumbered_dump(
                          sw_if_index=2)[0].ip_sw_if_index,
                      is_ipv6=True)]
            self.assertIn(if_addr, rv, f"{if_addr} not in "
                                       f"ip_unnumbered_dump(is_ipv6=True).")


# in case someone want's to run the test via the test shell...
if __name__ == '__main__':
    unittest.main(testRunner=framework.VppTestRunner)
