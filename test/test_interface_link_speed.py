#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Cisco and/or its affiliates.
"""Interface link speed API tests"""

import unittest

from framework import VppTestCase
from asfframework import VppTestRunner


class TestInterfaceLinkSpeed(VppTestCase):
    """Interface Link Speed Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestInterfaceLinkSpeed, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestInterfaceLinkSpeed, cls).tearDownClass()

    def setUp(self):
        super(TestInterfaceLinkSpeed, self).setUp()
        self.loopbacks = self.create_loopback_interfaces(1)
        for i in self.loopbacks:
            i.admin_up()

    def tearDown(self):
        for i in self.loopbacks:
            i.admin_down()
            i.remove_vpp_config()
        super(TestInterfaceLinkSpeed, self).tearDown()

    def test_set_link_speed_unimplemented(self):
        """set_link_speed returns UNIMPLEMENTED on loopback (no driver)"""
        lo = self.loopbacks[0]
        with self.vapi.assert_negative_api_retval():
            self.vapi.sw_interface_set_link_speed(
                sw_if_index=lo.sw_if_index, link_speed=10000000
            )

    def test_set_link_speed_invalid_sw_if_index(self):
        """set_link_speed returns error for invalid sw_if_index"""
        with self.vapi.assert_negative_api_retval():
            self.vapi.sw_interface_set_link_speed(
                sw_if_index=0xFFFFFFFF, link_speed=10000000
            )

    def test_get_speed_capa_empty(self):
        """get_speed_capa returns empty list for loopback"""
        lo = self.loopbacks[0]
        rv = self.vapi.sw_interface_get_speed_capa(sw_if_index=lo.sw_if_index)
        self.assertEqual(rv.count, 0)
        self.assertEqual(len(rv.speeds), 0)

    def test_get_speed_capa_invalid_sw_if_index(self):
        """get_speed_capa returns error for invalid sw_if_index"""
        with self.vapi.assert_negative_api_retval():
            self.vapi.sw_interface_get_speed_capa(sw_if_index=0xFFFFFFFF)


class TestInterfaceLinkSpeedWithDriver(VppTestCase):
    """Interface Link Speed Test Case with stub driver (via CLI)"""

    @classmethod
    def setUpClass(cls):
        super(TestInterfaceLinkSpeedWithDriver, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestInterfaceLinkSpeedWithDriver, cls).tearDownClass()

    def test_set_link_speed_via_cli(self):
        """set interface link-speed on loopback returns error via CLI"""
        self.create_loopback_interfaces(1)
        lo = self.lo_interfaces[0]
        lo.admin_up()

        # Loopback has no set_link_speed_function, CLI should report error
        reply = self.vapi.cli_return_response(
            "set interface link-speed loop0 10000000"
        )
        self.assertIn("not support", reply.reply.lower())

        lo.admin_down()
        lo.remove_vpp_config()

    def test_show_link_speed_capa_via_cli(self):
        """show interface link-speed-capa on loopback shows no caps"""
        self.create_loopback_interfaces(1)
        lo = self.lo_interfaces[0]
        lo.admin_up()

        reply = self.vapi.cli_return_response(
            "show interface link-speed-capa loop0"
        )
        self.assertIn("no speed capabilities", reply.reply.lower())

        lo.admin_down()
        lo.remove_vpp_config()

    def test_link_speed_unit(self):
        """Link Speed Unit Tests"""
        error = self.vapi.cli("test link-speed")

        if error:
            self.logger.critical(error)
        self.assertNotIn("FAIL", error)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
