#!/usr/bin/env python3
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco and/or its affiliates.
#

import unittest

from asfframework import VppAsfTestCase, VppTestRunner


class TestVirtioInterface(VppAsfTestCase):
    """Virtio interface tests"""

    @staticmethod
    def _interface_name(sw_if):
        return str(sw_if.interface_name).rstrip("\x00")

    def _find_virtio_interfaces(self):
        return [
            sw_if
            for sw_if in self.vapi.sw_interface_dump()
            if self._interface_name(sw_if).startswith("VirtioEthernet")
        ]

    def test_virtio_interface_mac_addr_change(self):
        """Virtio interface MAC address change test"""

        virtio_ifs = self._find_virtio_interfaces()
        if not virtio_ifs:
            self.skipTest("No virtio interface is present")

        virtio_if = virtio_ifs[0]
        sw_if_index = virtio_if.sw_if_index
        original_mac = str(virtio_if.l2_address)
        new_mac = "02:fe:%02x:%02x:%02x:%02x" % (
            (sw_if_index >> 24) & 0xFF,
            (sw_if_index >> 16) & 0xFF,
            (sw_if_index >> 8) & 0xFF,
            sw_if_index & 0xFF,
        )

        if new_mac == original_mac:
            new_mac = "02:fe:00:11:22:33"

        try:
            self.vapi.sw_interface_set_mac_address(sw_if_index, new_mac)

            if_dump = self.vapi.sw_interface_dump(sw_if_index=sw_if_index)
            self.assertEqual(len(if_dump), 1, "interface dump length")
            self.assertEqual(str(if_dump[0].l2_address), new_mac, "updated MAC")
        finally:
            if_dump = self.vapi.sw_interface_dump(sw_if_index=sw_if_index)
            if len(if_dump) == 1 and str(if_dump[0].l2_address) != original_mac:
                self.vapi.sw_interface_set_mac_address(sw_if_index, original_mac)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
