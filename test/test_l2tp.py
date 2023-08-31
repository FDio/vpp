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
        err_count = err

        self.vapi.l2tpv3_create_tunnel(
            client_address=self.pg0.local_ip6, our_address=self.pg0.remote_ip6
        )

        self.pg0.add_stream(pkt)
        self.pg_start()

        # l2tp accepts packets
        err = self.statistics.get_counter(
            "/err/l2tp-decap-local/l2tpv3 session not found"
        )[0]
        self.assertEqual(err, 1)
        err_count = err
