#!/usr/bin/env python3

from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6

from asfframework import tag_fixme_vpp_workers
from framework import VppTestCase


@tag_fixme_vpp_workers
class TestL2tp(VppTestCase):
    """L2TP Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestL2tp, cls).setUpClass()
        cls.create_pg_interfaces(range(1))
        cls.pg0.admin_up()
        cls.pg0.config_ip6()

    @classmethod
    def tearDownClass(cls):
        cls.pg0.admin_down()
        cls.pg0.unconfig_ip6()
        super(TestL2tp, cls).tearDownClass()

    def test_l2tp_decap_local(self):
        """L2TP don't accept packets unless configured"""

        pkt = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / IPv6(
            src=self.pg0.remote_ip6, dst=self.pg0.local_ip6, nh=115
        )

        self.pg0.add_stream(pkt)
        self.pg_start()

        # l2tp should not accept packets
        err = self.statistics.get_counter(
            "/err/l2tp-decap-local/l2tpv3 session not found"
        )[0]
        self.assertEqual(err, 0)

        self.vapi.l2tpv3_create_tunnel(
            client_address=self.pg0.local_ip6, our_address=self.pg0.remote_ip6
        )

        sw_if_index = self.vapi.sw_if_l2tpv3_tunnel_dump()[0].sw_if_index
        self.vapi.l2tpv3_set_tunnel_cookies(
            sw_if_index=sw_if_index, new_local_cookie=128, new_remote_cookie=255
        )
        remote_cookie = self.vapi.sw_if_l2tpv3_tunnel_dump()[0].remote_cookie
        self.assertEqual(remote_cookie, 255)

        self.pg0.add_stream(pkt)
        self.pg_start()

        # l2tp accepts packets
        err = self.statistics.get_counter(
            "/err/l2tp-decap-local/l2tpv3 session not found"
        )[0]
        self.assertEqual(err, 1)

        # this doesn't seem to do anything?
        self.vapi.l2tpv3_interface_enable_disable(
            enable_disable=False, sw_if_index=sw_if_index
        )


class TestL2tpCli(VppTestCase):
    """L2TP Test Case [CLI]"""

    @classmethod
    def setUpClass(cls):
        super(TestL2tpCli, cls).setUpClass()
        cls.create_pg_interfaces(range(1))
        cls.pg0.admin_up()
        cls.pg0.config_ip6()

    @classmethod
    def tearDownClass(cls):
        cls.pg0.admin_down()
        cls.pg0.unconfig_ip6()
        super(TestL2tpCli, cls).tearDownClass()

    def test_l2tp_cli(self):
        """Enable L2TP and check outputs"""
        reply = self.vapi.cli("show l2tpv3 verbose")
        self.assertIn(r"No l2tp sessions", reply)

        l2tp_if = self.vapi.cli(
            f"create l2tpv3 tunnel client {self.pg0.local_ip6} our {self.pg0.remote_ip6} local-cookie 10 remote-cookie 20"
        )
        self.assertIn("l2tpv3_tunnel", l2tp_if)
        reply = self.vapi.cli("test lt2p counters")
        self.assertIn("Incremented", reply)

        reply = self.vapi.cli("clear l2tp counters")
        self.assertIn("Cleared", reply)

        reply = self.vapi.cli("show l2tpv3 verbose")
        self.assertIn("1 l2tp sessions", reply)

        # this also doesn't seem to do anything
        self.vapi.cli(f"set interface ip6 l2tpv3 {l2tp_if} del")
