#!/usr/bin/env python3
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco and/or its affiliates.
#

import unittest

from asfframework import VppAsfTestCase, VppTestRunner
from vpp_papi_exceptions import CliFailedCommandError


class TestVirtioInterface(VppAsfTestCase):
    """Virtio interface tests"""

    @staticmethod
    def _interface_name(sw_if):
        return str(sw_if.interface_name).rstrip("\x00")

    @staticmethod
    def _is_virtio_interface(interface_name):
        return interface_name.startswith("virtio-") or interface_name.startswith(
            "VirtioEthernet"
        )

    @staticmethod
    def _filter_mac(sw_if_index, salt):
        return "02:fd:%02x:%02x:%02x:%02x" % (
            salt & 0xFF,
            (sw_if_index >> 16) & 0xFF,
            (sw_if_index >> 8) & 0xFF,
            sw_if_index & 0xFF,
        )

    def _find_virtio_interfaces(self):
        return [
            sw_if
            for sw_if in self.vapi.sw_interface_dump()
            if self._is_virtio_interface(self._interface_name(sw_if))
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

    def test_virtio_interface_mac_filtering(self):
        """Virtio interface MAC filtering test"""

        virtio_ifs = self._find_virtio_interfaces()
        if not virtio_ifs:
            self.skipTest("No virtio interface is present")

        virtio_if = None
        interface_name = None
        for sw_if in virtio_ifs:
            name = self._interface_name(sw_if)
            show = self.vapi.cli(f"show virtio pci {name}")
            if "mac-table-filtering 1" in show:
                virtio_if = sw_if
                interface_name = name
                break

        if not virtio_if:
            self.skipTest("No virtio interface with MAC filtering enabled")

        sw_if_index = virtio_if.sw_if_index
        added_macs = []

        unicast_mac = None
        for salt in (0x11, 0x22):
            candidate = self._filter_mac(sw_if_index, salt)
            try:
                self.vapi.cli(
                    f"set interface secondary-mac-address {interface_name} "
                    f"{candidate} add"
                )
                unicast_mac = candidate
                added_macs.append(candidate)
                break
            except CliFailedCommandError:
                continue

        if not unicast_mac:
            self.skipTest("Unable to add a unicast test MAC filter on virtio interface")

        multicast_mac = "01:00:5e:%02x:%02x:%02x" % (
            (sw_if_index >> 16) & 0x7F,
            (sw_if_index >> 8) & 0xFF,
            sw_if_index & 0xFF,
        )
        try:
            self.vapi.cli(
                f"set interface secondary-mac-address {interface_name} "
                f"{multicast_mac} add"
            )
            added_macs.append(multicast_mac)
        except CliFailedCommandError:
            self.skipTest(
                "Unable to add a multicast test MAC filter on virtio interface"
            )

        try:
            show = self.vapi.cli(f"show virtio pci {interface_name}")
            self.assertIn("MAC Filters:", show, "MAC filter section")
            self.assertIn(unicast_mac, show, "added unicast MAC in virtio dump")
            self.assertIn(multicast_mac, show, "added multicast MAC in virtio dump")

            show = self.vapi.cli(
                f"show interface secondary-mac-address {interface_name}"
            )
            self.assertIn(
                unicast_mac, show, "added unicast MAC in interface secondary list"
            )
            self.assertIn(
                multicast_mac, show, "added multicast MAC in interface secondary list"
            )

            for candidate in list(added_macs):
                self.vapi.cli(
                    f"set interface secondary-mac-address {interface_name} "
                    f"{candidate} del"
                )
                added_macs.remove(candidate)

            show = self.vapi.cli(f"show virtio pci {interface_name}")
            self.assertNotIn(
                unicast_mac, show, "removed unicast MAC absent in virtio dump"
            )
            self.assertNotIn(
                multicast_mac, show, "removed multicast MAC absent in virtio dump"
            )
        finally:
            for candidate in list(added_macs):
                try:
                    self.vapi.cli(
                        f"set interface secondary-mac-address {interface_name} "
                        f"{candidate} del"
                    )
                except CliFailedCommandError:
                    pass


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
