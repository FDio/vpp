#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco and/or its affiliates.

import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_gre_interface import VppGreInterface
from vpp_ipip_tun_interface import VppIpIpTunInterface
from vpp_ipsec import VppIpsecSA
from vpp_papi import VppEnum
from config import config

NO_SUCH_INTERFACE = 0xFFFFFFFF


@unittest.skipIf(
    "gre" in config.excluded_plugins or "ipip" in config.excluded_plugins,
    "Exclude test requiring GRE and IPIP plugins",
)
class TestTeibUnavailable(VppTestCase):
    """TEIB Unavailable Test Case"""

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
        super(TestTeibUnavailable, self).setUp()

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
        super(TestTeibUnavailable, self).tearDown()

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


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
