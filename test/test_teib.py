#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco and/or its affiliates.

import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_ip_route import VppIpTable
from vpp_teib import VppTeib


class TestTeib(VppTestCase):
    """TEIB Test Case"""

    VNET_API_ERROR_NO_SUCH_FIB = -3
    VNET_API_ERROR_NO_SUCH_ENTRY = -6
    VNET_API_ERROR_ENTRY_ALREADY_EXISTS = -116

    def setUp(self):
        super(TestTeib, self).setUp()

        self.create_loopback_interfaces(2)

        for i in self.lo_interfaces:
            i.generate_remote_hosts(2)
            i.admin_up()
            i.config_ip4()
            i.config_ip6()

    def tearDown(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestTeib, self).tearDown()

    def test_ipv4_add_dump_del(self):
        """IPv4 TEIB entry add, dump and delete"""

        peer = self.loop0.remote_ip4
        nh = "10.0.0.1"

        self.assertEqual(len(self.vapi.teib_dump()), 0)

        ne = VppTeib(self, self.loop0, peer, nh)
        ne.add_vpp_config()

        dump = self.vapi.teib_dump()
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0].entry.sw_if_index, self.loop0.sw_if_index)
        self.assertEqual(str(dump[0].entry.peer), peer)
        self.assertEqual(str(dump[0].entry.nh), nh)
        self.assertEqual(dump[0].entry.nh_table_id, 0)
        self.assertTrue(ne.query_vpp_config())

        # find_teib() compares the whole snapshot and not just the key, so an
        # entry that differs only in its next-hop is not this entry
        other = VppTeib(self, self.loop0, peer, "10.0.0.9")
        self.assertFalse(other.query_vpp_config())

        ne.remove_vpp_config()
        self.assertEqual(len(self.vapi.teib_dump()), 0)
        self.assertFalse(ne.query_vpp_config())

    def test_ipv6_add_dump_del(self):
        """IPv6 TEIB entry add, dump and delete"""

        peer = self.loop0.remote_ip6
        nh = "2001:2::1"

        ne = VppTeib(self, self.loop0, peer, nh)
        ne.add_vpp_config()

        dump = self.vapi.teib_dump()
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0].entry.sw_if_index, self.loop0.sw_if_index)
        self.assertEqual(str(dump[0].entry.peer), peer)
        self.assertEqual(str(dump[0].entry.nh), nh)
        self.assertEqual(dump[0].entry.nh_table_id, 0)
        self.assertTrue(ne.query_vpp_config())

        ne.remove_vpp_config()
        self.assertEqual(len(self.vapi.teib_dump()), 0)
        self.assertFalse(ne.query_vpp_config())

    def test_two_interfaces(self):
        """Entries on two overlay interfaces stay distinct"""

        #
        # The overlay interface is part of an entry's key. With every entry on
        # one interface, an entry that lost its interface would still look
        # right, because there is only one value it could hold.
        #
        ne0 = VppTeib(self, self.loop0, self.loop0.remote_ip4, "10.0.0.1")
        ne0.add_vpp_config()
        ne1 = VppTeib(self, self.loop1, self.loop1.remote_ip4, "10.0.0.2")
        ne1.add_vpp_config()

        dump = self.vapi.teib_dump()
        self.assertEqual(len(dump), 2)
        self.assertTrue(ne0.query_vpp_config())
        self.assertTrue(ne1.query_vpp_config())

        # each next-hop is reported against the interface it was added on
        nhs = {e.entry.sw_if_index: str(e.entry.nh) for e in dump}
        self.assertEqual(nhs[self.loop0.sw_if_index], "10.0.0.1")
        self.assertEqual(nhs[self.loop1.sw_if_index], "10.0.0.2")

        # and the CLI walk names both interfaces
        out = self.vapi.cli("show teib")
        self.assertIn("%s:%s" % (self.loop0.name, self.loop0.remote_ip4), out)
        self.assertIn("%s:%s" % (self.loop1.name, self.loop1.remote_ip4), out)

        # deleting one leaves the other
        ne0.remove_vpp_config()
        self.assertFalse(ne0.query_vpp_config())
        self.assertTrue(ne1.query_vpp_config())
        self.assertEqual(len(self.vapi.teib_dump()), 1)

        ne1.remove_vpp_config()
        self.assertEqual(len(self.vapi.teib_dump()), 0)

    def test_nh_table_id(self):
        """TEIB entry with a next-hop in a non-default table"""

        peer = self.loop0.remote_ip4
        nh = "10.0.0.1"

        VppIpTable(self, 10).add_vpp_config()

        ne = VppTeib(self, self.loop0, peer, nh, table_id=10)
        ne.add_vpp_config()

        # the API reports the next-hop table id, not the FIB index
        dump = self.vapi.teib_dump()
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0].entry.nh_table_id, 10)
        self.assertTrue(ne.query_vpp_config())

        # and so does the CLI, from the same field
        self.assertIn("via [10]:%s/32" % nh, self.vapi.cli("show teib"))

        ne.remove_vpp_config()
        self.assertEqual(len(self.vapi.teib_dump()), 0)

    def test_duplicate_add(self):
        """Adding a TEIB entry twice does not update it"""

        peer = self.loop0.remote_ip4
        nh = "10.0.0.1"

        ne = VppTeib(self, self.loop0, peer, nh)
        ne.add_vpp_config()

        with self.vapi.assert_negative_api_retval():
            r = self.vapi.teib_entry_add_del(
                is_add=1,
                entry={
                    "nh_table_id": 0,
                    "sw_if_index": self.loop0.sw_if_index,
                    "peer": peer,
                    "nh": "10.0.0.9",
                },
            )
        self.assertEqual(r.retval, self.VNET_API_ERROR_ENTRY_ALREADY_EXISTS)

        # the rejected add did not overwrite the underlay next-hop
        dump = self.vapi.teib_dump()
        self.assertEqual(len(dump), 1)
        self.assertEqual(str(dump[0].entry.nh), nh)

    def test_delete_missing(self):
        """Deleting a TEIB entry that does not exist is refused"""

        self.assertEqual(len(self.vapi.teib_dump()), 0)

        with self.vapi.assert_negative_api_retval():
            r = self.vapi.teib_entry_add_del(
                is_add=0,
                entry={
                    "nh_table_id": 0,
                    "sw_if_index": self.loop0.sw_if_index,
                    "peer": self.loop0.remote_ip4,
                },
            )
        self.assertEqual(r.retval, self.VNET_API_ERROR_NO_SUCH_ENTRY)
        self.assertEqual(len(self.vapi.teib_dump()), 0)

    def test_no_such_fib(self):
        """A TEIB entry with a next-hop in a missing table is refused"""

        with self.vapi.assert_negative_api_retval():
            r = self.vapi.teib_entry_add_del(
                is_add=1,
                entry={
                    "nh_table_id": 99,
                    "sw_if_index": self.loop0.sw_if_index,
                    "peer": self.loop0.remote_ip4,
                    "nh": "10.0.0.1",
                },
            )
        self.assertEqual(r.retval, self.VNET_API_ERROR_NO_SUCH_FIB)

        # refused before anything was allocated for it
        self.assertEqual(len(self.vapi.teib_dump()), 0)

    def test_cli_create_show_delete(self):
        """TEIB entries can be managed from the CLI"""

        peer = self.loop0.remote_ip4
        nh = "10.0.0.1"

        out = self.vapi.cli(
            "create teib %s peer %s nh %s" % (self.loop0.name, peer, nh)
        )
        self.assertEqual(out.strip(), "")

        # the CLI walk of the pool reports the entry that the API walk does
        self.assertIn(
            "%s:%s via [0]:%s/32" % (self.loop0.name, peer, nh),
            self.vapi.cli("show teib"),
        )

        dump = self.vapi.teib_dump()
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0].entry.sw_if_index, self.loop0.sw_if_index)
        self.assertEqual(str(dump[0].entry.peer), peer)
        self.assertEqual(str(dump[0].entry.nh), nh)

        self.vapi.cli("delete teib %s peer %s" % (self.loop0.name, peer))

        self.assertEqual(len(self.vapi.teib_dump()), 0)
        self.assertNotIn(peer, self.vapi.cli("show teib"))

    def test_c_api(self):
        """TEIB in-process C API unit tests"""

        # the interfaces and the next-hop table are created here and handed to
        # the tests, so that the C side owns nothing but the TEIB entries
        VppIpTable(self, 10).add_vpp_config()

        # vapi.cli() raises on a non-zero retval, so a failure of any case
        # fails this test; the FAIL:<line> detail lands in the run's log.txt
        self.vapi.cli(
            "test teib %s %s nh-table-id 10" % (self.loop0.name, self.loop1.name)
        )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
