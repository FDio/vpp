#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco and/or its affiliates.

import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_gre_interface import VppGreInterface
from vpp_ip_route import VppIpTable
from vpp_ipip_tun_interface import VppIpIpTunInterface
from vpp_ipsec import VppIpsecSA, VppIpsecTunProtect
from vpp_papi import VppEnum
from vpp_teib import VppTeib
from config import config

NO_SUCH_INTERFACE = 0xFFFFFFFF


@unittest.skipIf(
    "teib" in config.excluded_plugins,
    "Exclude tests requiring TEIB plugin",
)
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


class TestTeibServiceUnavailable(VppTestCase):
    """TEIB service API with the TEIB plugin unavailable"""

    extra_vpp_plugin_config = [
        "plugin teib_plugin.so { disable }",
    ]

    def setUp(self):
        super(TestTeibServiceUnavailable, self).setUp()

        self.create_loopback_interfaces(1)
        self.loop0.admin_up()
        self.loop0.config_ip4()

    def tearDown(self):
        self.loop0.unconfig_ip4()
        self.loop0.admin_down()
        super(TestTeibServiceUnavailable, self).tearDown()

    def test_c_api(self):
        """TEIB in-process C API unit tests with TEIB unavailable"""

        # The refusal is only visible from C: with the plugin disabled there is
        # no TEIB binary API and no TEIB CLI to ask.
        self.vapi.cli("test teib unavailable %s" % self.loop0.name)


@unittest.skipIf(
    "gre" in config.excluded_plugins and "ipip" in config.excluded_plugins,
    "Exclude tests requiring GRE or IPIP plugins",
)
class TestTunnelConsumersWithoutTeib(VppTestCase):
    """Tunnel consumer behaviour with the TEIB plugin unavailable"""

    # The TEIB database lives in this plugin. Disabling it leaves the service
    # TEIB API in VNET unavailable, which is what this test exercises: tunnel
    # consumers must still load and reject only configuration that could never
    # work.
    extra_vpp_plugin_config = [
        "plugin teib_plugin.so { disable }",
    ]

    VNET_API_ERROR_FEATURE_DISABLED = -30

    MP = VppEnum.vl_api_tunnel_mode_t.TUNNEL_API_MODE_MP

    def setUp(self):
        super(TestTunnelConsumersWithoutTeib, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        self.pg1.generate_remote_hosts(2)
        self.pg1.configure_ipv4_neighbors()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestTunnelConsumersWithoutTeib, self).tearDown()

    @unittest.skipIf(
        "gre" in config.excluded_plugins or "ipip" in config.excluded_plugins,
        "Exclude test requiring GRE and IPIP plugins",
    )
    def test_startup(self):
        """VPP and the tunnel consumers start when TEIB is unavailable"""

        #
        # The plugin that provides the database is disabled, while the tunnel
        # consumers, which only use the service boundary in VNET, are not.
        #
        plugins = self.vapi.cli("show plugins")
        self.assertNotIn("teib_plugin.so", plugins)
        self.assertIn("gre_plugin.so", plugins)
        self.assertIn("ipip_plugin.so", plugins)

        #
        # An init function that returned an error would have taken the whole
        # process down, so reaching here already says that GRE, IPIP and IPsec
        # initialised. Their control planes answer too.
        #
        self.assertEqual(len(self.vapi.gre_tunnel_v2_dump(NO_SUCH_INTERFACE)), 0)
        self.assertEqual(len(self.vapi.ipip_tunnel_dump(NO_SUCH_INTERFACE)), 0)
        self.assertEqual(len(self.vapi.ipsec_sa_v5_dump()), 0)

    @unittest.skipIf(
        "gre" in config.excluded_plugins or "ipip" in config.excluded_plugins,
        "Exclude test requiring GRE and IPIP plugins",
    )
    def test_p2p_tunnels(self):
        """Point-to-point tunnels do not need TEIB"""

        gre_if = VppGreInterface(self, self.pg1.local_ip4, self.pg1.remote_ip4)
        gre_if.add_vpp_config()
        gre_if.admin_up()
        gre_if.config_ip4()
        self.assertTrue(gre_if.query_vpp_config())

        ipip_if = VppIpIpTunInterface(
            self, self.pg1, self.pg1.local_ip4, self.pg1.remote_ip4
        )
        ipip_if.add_vpp_config()
        ipip_if.admin_up()
        ipip_if.config_ip4()
        self.assertTrue(ipip_if.query_vpp_config())

        #
        # 6rd is an IPIP tunnel that maps the peer's underlay address out of
        # the overlay one, so it has no use for the TEIB either.
        #
        sixrd = self.vapi.ipip_6rd_add_tunnel(
            ip6_table_id=0,
            ip4_table_id=0,
            ip6_prefix="2002::/16",
            ip4_prefix="0.0.0.0/0",
            ip4_src=self.pg1.local_ip4,
            security_check=True,
        )
        self.vapi.ipip_6rd_del_tunnel(sixrd.sw_if_index)

        ipip_if.remove_vpp_config()
        gre_if.remove_vpp_config()

    @unittest.skipIf(
        "gre" in config.excluded_plugins,
        "Exclude test requiring GRE plugin",
    )
    def test_mgre_rejected(self):
        """Multipoint GRE creation needs TEIB"""

        with self.vapi.assert_negative_api_retval():
            r = self.vapi.gre_tunnel_add_del_v2(
                is_add=1,
                tunnel={
                    "src": self.pg1.local_ip4,
                    "dst": "0.0.0.0",
                    "outer_table_id": 0,
                    "instance": NO_SUCH_INTERFACE,
                    "type": VppEnum.vl_api_gre_tunnel_type_t.GRE_API_TUNNEL_TYPE_L3,
                    "mode": self.MP,
                    "flags": 0,
                    "session_id": 0,
                    "key": 0,
                },
            )
        self.assertEqual(r.retval, self.VNET_API_ERROR_FEATURE_DISABLED)

        # the tunnel was refused before anything was allocated for it
        self.assertEqual(len(self.vapi.gre_tunnel_v2_dump(NO_SUCH_INTERFACE)), 0)

    @unittest.skipIf(
        "ipip" in config.excluded_plugins,
        "Exclude test requiring IPIP plugin",
    )
    def test_mipip_rejected(self):
        """Multipoint IPIP creation needs TEIB"""

        with self.vapi.assert_negative_api_retval():
            r = self.vapi.ipip_add_tunnel(
                tunnel={
                    "src": self.pg1.local_ip4,
                    "dst": "0.0.0.0",
                    "table_id": 0,
                    "flags": 0,
                    "dscp": 0,
                    "instance": NO_SUCH_INTERFACE,
                    "mode": self.MP,
                }
            )
        self.assertEqual(r.retval, self.VNET_API_ERROR_FEATURE_DISABLED)

        # the tunnel was refused before anything was allocated for it
        self.assertEqual(len(self.vapi.ipip_tunnel_dump(NO_SUCH_INTERFACE)), 0)

    @unittest.skipIf(
        "gre" in config.excluded_plugins,
        "Exclude test requiring GRE plugin",
    )
    def test_ipsec_protect_rejected(self):
        """Protecting a destination-less tunnel needs TEIB"""

        #
        # A tunnel with a source but no destination takes its peer's underlay
        # address from the TEIB, which is what makes protecting it depend on a
        # service. Ordinary IPsec, and IPsec over a tunnel that knows its own
        # destination, do not.
        #
        tun = VppGreInterface(self, self.pg1.local_ip4, "0.0.0.0")
        tun.add_vpp_config()
        tun.admin_up()

        esp = VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_ESP
        integ = VppEnum.vl_api_ipsec_integ_alg_t.IPSEC_API_INTEG_ALG_SHA1_96
        crypto = VppEnum.vl_api_ipsec_crypto_alg_t.IPSEC_API_CRYPTO_ALG_AES_CBC_128
        auth_key = b"C91KUR9GYMm5GfkEvNjX"
        crypt_key = b"JPjyOWBeVEQiMe7h"

        sa_in = VppIpsecSA(self, 10, 1000, integ, auth_key, crypto, crypt_key, esp)
        sa_in.add_vpp_config()
        sa_out = VppIpsecSA(self, 20, 2000, integ, auth_key, crypto, crypt_key, esp)
        sa_out.add_vpp_config()

        with self.vapi.assert_negative_api_retval():
            r = self.vapi.ipsec_tunnel_protect_update(
                tunnel={
                    "sw_if_index": tun.sw_if_index,
                    "n_sa_in": 1,
                    "sa_out": sa_out.id,
                    "sa_in": [sa_in.id],
                    "nh": self.pg1.remote_hosts[1].ip4,
                }
            )
        self.assertEqual(r.retval, self.VNET_API_ERROR_FEATURE_DISABLED)

        # no protection object survived the failure
        self.assertEqual(
            len(self.vapi.ipsec_tunnel_protect_dump(sw_if_index=tun.sw_if_index)), 0
        )

        # nor did a reference to either SA: both go when their config does
        sa_out.remove_vpp_config()
        sa_in.remove_vpp_config()
        self.assertFalse(sa_out.query_vpp_config())
        self.assertFalse(sa_in.query_vpp_config())

        tun.remove_vpp_config()

    @unittest.skipIf(
        "gre" in config.excluded_plugins,
        "Exclude test requiring GRE plugin",
    )
    def test_ipsec_protect_p2p_allowed(self):
        """Protecting a tunnel that knows its destination does not need TEIB"""

        #
        # The counterpart of the test above. This tunnel carries its own
        # destination, so there is nothing to look up and protecting it has to
        # keep working. Without this case, refusing IPsec protection outright
        # would still satisfy the rejection test.
        #
        tun = VppGreInterface(self, self.pg1.local_ip4, self.pg1.remote_ip4)
        tun.add_vpp_config()
        tun.admin_up()

        esp = VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_ESP
        integ = VppEnum.vl_api_ipsec_integ_alg_t.IPSEC_API_INTEG_ALG_SHA1_96
        crypto = VppEnum.vl_api_ipsec_crypto_alg_t.IPSEC_API_CRYPTO_ALG_AES_CBC_128
        auth_key = b"C91KUR9GYMm5GfkEvNjX"
        crypt_key = b"JPjyOWBeVEQiMe7h"

        sa_in = VppIpsecSA(self, 30, 3000, integ, auth_key, crypto, crypt_key, esp)
        sa_in.add_vpp_config()
        sa_out = VppIpsecSA(self, 40, 4000, integ, auth_key, crypto, crypt_key, esp)
        sa_out.add_vpp_config()

        protect = VppIpsecTunProtect(self, tun, sa_out, [sa_in])
        protect.add_vpp_config()
        self.assertTrue(protect.query_vpp_config())

        protect.remove_vpp_config()
        self.assertFalse(protect.query_vpp_config())

        sa_out.remove_vpp_config()
        sa_in.remove_vpp_config()
        tun.remove_vpp_config()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
