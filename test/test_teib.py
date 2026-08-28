#!/usr/bin/env python3

import unittest

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_gre_interface import VppGreInterface
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_papi import VppEnum
from config import config


@unittest.skipIf(
    "gre" in config.excluded_plugins or "ipip" in config.excluded_plugins,
    "Exclude test requiring GRE and IPIP plugins",
)
class TestTeibNoProvider(VppTestCase):
    """TEIB No Provider Test Case"""

    # The TEIB database lives in this plugin. Disabling it leaves the service
    # boundary in VNET without a backend, which is what this test exercises.
    extra_vpp_plugin_config = [
        "plugin teib_plugin.so { disable }",
    ]

    def setUp(self):
        super(TestTeibNoProvider, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestTeibNoProvider, self).tearDown()

    def create_stream_ip4(self, src_if, src_ip, dst_ip):
        pkts = []
        for i in range(0, 4):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = (
                Ether(dst=src_if.local_mac, src=src_if.remote_mac)
                / IP(src=src_ip, dst=dst_ip)
                / UDP(sport=1234, dport=1234)
                / Raw(payload)
            )
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def test_teib_no_provider(self):
        """Multipoint tunnels without a TEIB provider"""

        #
        # The plugin that provides the database is disabled, while the tunnel
        # consumers, which only use the lookup API in VNET, are not.
        #
        plugins = self.vapi.cli("show plugins")
        self.assertNotIn("teib_plugin.so", plugins)
        self.assertIn("gre_plugin.so", plugins)
        self.assertIn("ipip_plugin.so", plugins)

        itf = self.pg1
        itf.generate_remote_hosts(2)
        itf.configure_ipv4_neighbors()

        #
        # Creating a multipoint tunnel walks the TEIB entries of the interface.
        # Without a provider the walk is a no-op.
        #
        gre_if = VppGreInterface(
            self,
            itf.local_ip4,
            "0.0.0.0",
            mode=(VppEnum.vl_api_tunnel_mode_t.TUNNEL_API_MODE_MP),
        )
        gre_if.add_vpp_config()
        gre_if.admin_up()
        gre_if.config_ip4()
        gre_if.generate_remote_hosts(2)

        #
        # Routing via an overlay peer looks the peer up in the TEIB. Without a
        # provider the lookup misses, so the adjacency stays unresolved.
        #
        route_via_tun = VppIpRoute(
            self,
            "4.4.4.1",
            32,
            [VppRoutePath(gre_if._remote_hosts[1].ip4, gre_if.sw_if_index)],
        )
        route_via_tun.add_vpp_config()

        tx = self.create_stream_ip4(self.pg0, "5.5.5.5", "4.4.4.1")
        self.send_and_assert_no_replies(self.pg0, tx)

        #
        # The unresolved adjacency drops the traffic rather than taking VPP
        # down with it.
        #
        self.assertIn("local0", self.vapi.cli("show interface"))

        route_via_tun.remove_vpp_config()
        gre_if.remove_vpp_config()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
