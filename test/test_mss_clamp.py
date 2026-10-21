#!/usr/bin/env python3

import socket
import struct
import unittest

from framework import VppTestCase
from asfframework import VppTestRunner

from scapy.layers.inet import IP, TCP, checksum
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from vpp_ip import INVALID_INDEX
from vpp_papi import VppEnum
from vpp_sub_interface import VppDot1QSubint


class TestMSSClamp(VppTestCase):
    """TCP MSS Clamping Test Case"""

    def setUp(self):
        super(TestMSSClamp, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestMSSClamp, self).tearDown()

    def verify_pkt(self, rx, expected_mss):
        # check that the MSS size equals the expected value
        # and the IP and TCP checksums are correct
        tcp = rx[TCP]
        tcp_csum = tcp.chksum
        del tcp.chksum
        ip_csum = 0
        if rx.haslayer(IP):
            ip_csum = rx[IP].chksum
            del rx[IP].chksum

        opt = tcp.options
        self.assertEqual(opt[0][0], "MSS")
        self.assertEqual(opt[0][1], expected_mss)
        # recalculate checksums
        rx = rx.__class__(bytes(rx))
        tcp = rx[TCP]
        self.assertEqual(tcp_csum, tcp.chksum)
        if rx.haslayer(IP):
            self.assertEqual(ip_csum, rx[IP].chksum)

    def send_and_verify_ip4(self, src_pg, dst_pg, mss, expected_mss):
        # IPv4 TCP packet with the requested MSS option.
        # from a host on src_pg to a host on dst_pg.
        p = (
            Ether(dst=src_pg.local_mac, src=src_pg.remote_mac)
            / IP(src=src_pg.remote_ip4, dst=dst_pg.remote_ip4)
            / TCP(
                sport=1234,
                dport=1234,
                flags="S",
                options=[("MSS", (mss)), ("EOL", None)],
            )
            / Raw("\xa5" * 100)
        )

        rxs = self.send_and_expect(src_pg, p * 65, dst_pg)

        for rx in rxs:
            self.verify_pkt(rx, expected_mss)

    def send_and_verify_ip6(self, src_pg, dst_pg, mss, expected_mss):
        #
        # IPv6 TCP packet with the requested MSS option.
        # from a host on src_pg to a host on dst_pg.
        #
        p = (
            Ether(dst=src_pg.local_mac, src=src_pg.remote_mac)
            / IPv6(src=src_pg.remote_ip6, dst=dst_pg.remote_ip6)
            / TCP(
                sport=1234,
                dport=1234,
                flags="S",
                options=[("MSS", (mss)), ("EOL", None)],
            )
            / Raw("\xa5" * 100)
        )

        rxs = self.send_and_expect(src_pg, p * 65, dst_pg)

        for rx in rxs:
            self.verify_pkt(rx, expected_mss)

    def send_and_expect_ip4_syn_invalid_doff(self, src_pg, dst_pg):
        # IPv4 TCP SYN packet with an invalid data offset
        # from a host on src_pg to a host on dst_pg.
        p = (
            Ether(dst=src_pg.local_mac, src=src_pg.remote_mac)
            / IP(src=src_pg.remote_ip4, dst=dst_pg.remote_ip4)
            / TCP(
                sport=1234,
                dport=1234,
                flags="S",
                dataofs=0,
                options=[("MSS", (1460)), ("EOL", None)],
            )
        )

        self.send_and_expect(src_pg, p, dst_pg)

    def send_and_expect_ip6_syn_invalid_doff(self, src_pg, dst_pg):
        #
        # IPv6 TCP SYN packet with an invalid data offset
        # from a host on src_pg to a host on dst_pg.
        #
        p = (
            Ether(dst=src_pg.local_mac, src=src_pg.remote_mac)
            / IPv6(src=src_pg.remote_ip6, dst=dst_pg.remote_ip6, nh=6)
            / TCP(
                sport=1234,
                dport=1234,
                flags="S",
                dataofs=0,
                options=[("MSS", (1460)), ("EOL", None)],
            )
        )

        self.send_and_expect(src_pg, p, dst_pg)

    def test_tcp_mss_clamping_ip4_tx(self):
        """IP4 TCP MSS Clamping TX"""

        # enable the TCP MSS clamping feature to lower the MSS to 1424.
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=1424,
            ipv6_mss=0,
            ipv4_direction=3,
            ipv6_direction=0,
        )

        # Verify that the feature is enabled.
        rv, reply = self.vapi.mss_clamp_get(sw_if_index=self.pg1.sw_if_index)
        self.assertEqual(reply[0].ipv4_mss, 1424)
        self.assertEqual(reply[0].ipv4_direction, 3)

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip4(self.pg0, self.pg1, 1460, 1424)

        # check the stats
        stats = self.statistics.get_counter("/err/tcp-mss-clamping-ip4-out/clamped")
        self.assertEqual(sum(stats), 65)

        # Send syn packets with small enough MSS values and verify they are
        # unchanged.
        self.send_and_verify_ip4(self.pg0, self.pg1, 1400, 1400)

        stats = self.statistics.get_counter("/err/tcp-mss-clamping-ip4-out/clamped")
        self.assertEqual(sum(stats), 65)

        # Send malformed SYN and verify that the MSS clamp success counter is not incremented.
        self.send_and_expect_ip4_syn_invalid_doff(self.pg0, self.pg1)

        stats = self.statistics.get_counter("/err/tcp-mss-clamping-ip4-out/clamped")
        self.assertEqual(
            sum(stats),
            65,
            "malformed SYN must not increment MSS clamp success counter",
        )

        # enable the the feature only in TX direction
        # and change the max MSS value
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=1420,
            ipv6_mss=0,
            ipv4_direction=2,
            ipv6_direction=0,
        )

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip4(self.pg0, self.pg1, 1460, 1420)

        # enable the the feature only in RX direction
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=1424,
            ipv6_mss=0,
            ipv4_direction=1,
            ipv6_direction=0,
        )

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip4(self.pg0, self.pg1, 1460, 1460)

        # disable the feature
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=0,
            ipv6_mss=0,
            ipv4_direction=0,
            ipv6_direction=0,
        )

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip4(self.pg0, self.pg1, 1460, 1460)

    def test_tcp_mss_clamping_ip4_rx(self):
        """IP4 TCP MSS Clamping RX"""

        # enable the TCP MSS clamping feature to lower the MSS to 1424.
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=1424,
            ipv6_mss=0,
            ipv4_direction=3,
            ipv6_direction=0,
        )

        # Verify that the feature is enabled.
        rv, reply = self.vapi.mss_clamp_get(sw_if_index=self.pg1.sw_if_index)
        self.assertEqual(reply[0].ipv4_mss, 1424)
        self.assertEqual(reply[0].ipv4_direction, 3)

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip4(self.pg1, self.pg0, 1460, 1424)

        # check the stats
        stats = self.statistics.get_counter("/err/tcp-mss-clamping-ip4-in/clamped")
        self.assertEqual(sum(stats), 65)

        # Send syn packets with small enough MSS values and verify they are
        # unchanged.
        self.send_and_verify_ip4(self.pg1, self.pg0, 1400, 1400)

        stats = self.statistics.get_counter("/err/tcp-mss-clamping-ip4-in/clamped")
        self.assertEqual(sum(stats), 65)

        # Send malformed SYN and verify that the MSS clamp success counter is not incremented.
        self.send_and_expect_ip4_syn_invalid_doff(self.pg1, self.pg0)

        stats = self.statistics.get_counter("/err/tcp-mss-clamping-ip4-in/clamped")
        self.assertEqual(
            sum(stats),
            65,
            "malformed SYN must not increment MSS clamp success counter",
        )

        # enable the the feature only in RX direction
        # and change the max MSS value
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=1420,
            ipv6_mss=0,
            ipv4_direction=1,
            ipv6_direction=0,
        )

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip4(self.pg1, self.pg0, 1460, 1420)

        # enable the the feature only in TX direction
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=1424,
            ipv6_mss=0,
            ipv4_direction=2,
            ipv6_direction=0,
        )

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip4(self.pg1, self.pg0, 1460, 1460)

        # disable the feature
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=0,
            ipv6_mss=0,
            ipv4_direction=0,
            ipv6_direction=0,
        )

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip4(self.pg1, self.pg0, 1460, 1460)

    def test_tcp_mss_clamping_ip6_tx(self):
        """IP6 TCP MSS Clamping TX"""

        # enable the TCP MSS clamping feature to lower the MSS to 1424.
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=0,
            ipv6_mss=1424,
            ipv4_direction=0,
            ipv6_direction=3,
        )

        # Verify that the feature is enabled.
        rv, reply = self.vapi.mss_clamp_get(sw_if_index=self.pg1.sw_if_index)
        self.assertEqual(reply[0].ipv6_mss, 1424)
        self.assertEqual(reply[0].ipv6_direction, 3)

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip6(self.pg0, self.pg1, 1460, 1424)

        # check the stats
        stats = self.statistics.get_counter("/err/tcp-mss-clamping-ip6-out/clamped")
        self.assertEqual(sum(stats), 65)

        # Send syn packets with small enough MSS values and verify they are
        # unchanged.
        self.send_and_verify_ip6(self.pg0, self.pg1, 1400, 1400)

        stats = self.statistics.get_counter("/err/tcp-mss-clamping-ip6-out/clamped")
        self.assertEqual(sum(stats), 65)

        # Send malformed SYN and verify that the MSS clamp success counter is not incremented.
        self.send_and_expect_ip6_syn_invalid_doff(self.pg0, self.pg1)

        stats = self.statistics.get_counter("/err/tcp-mss-clamping-ip6-out/clamped")
        self.assertEqual(
            sum(stats),
            65,
            "malformed SYN must not increment MSS clamp success counter",
        )

        # enable the the feature only in TX direction
        # and change the max MSS value
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=0,
            ipv6_mss=1420,
            ipv4_direction=0,
            ipv6_direction=2,
        )

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip6(self.pg0, self.pg1, 1460, 1420)

        # enable the the feature only in RX direction
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=0,
            ipv6_mss=1424,
            ipv4_direction=0,
            ipv6_direction=1,
        )

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip6(self.pg0, self.pg1, 1460, 1460)

        # disable the feature
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=0,
            ipv6_mss=0,
            ipv4_direction=0,
            ipv6_direction=0,
        )

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip6(self.pg0, self.pg1, 1460, 1460)

    def test_tcp_mss_clamping_ip6_rx(self):
        """IP6 TCP MSS Clamping RX"""

        # enable the TCP MSS clamping feature to lower the MSS to 1424.
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=0,
            ipv6_mss=1424,
            ipv4_direction=0,
            ipv6_direction=3,
        )

        # Verify that the feature is enabled.
        rv, reply = self.vapi.mss_clamp_get(sw_if_index=self.pg1.sw_if_index)
        self.assertEqual(reply[0].ipv6_mss, 1424)
        self.assertEqual(reply[0].ipv6_direction, 3)

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip6(self.pg1, self.pg0, 1460, 1424)

        # check the stats
        stats = self.statistics.get_counter("/err/tcp-mss-clamping-ip6-in/clamped")
        self.assertEqual(sum(stats), 65)

        # Send syn packets with small enough MSS values and verify they are
        # unchanged.
        self.send_and_verify_ip6(self.pg1, self.pg0, 1400, 1400)

        stats = self.statistics.get_counter("/err/tcp-mss-clamping-ip6-in/clamped")
        self.assertEqual(sum(stats), 65)

        # Send malformed SYN and verify that the MSS clamp success counter is not incremented.
        self.send_and_expect_ip6_syn_invalid_doff(self.pg1, self.pg0)

        stats = self.statistics.get_counter("/err/tcp-mss-clamping-ip6-in/clamped")
        self.assertEqual(
            sum(stats),
            65,
            "malformed SYN must not increment MSS clamp success counter",
        )

        # enable the the feature only in RX direction
        # and change the max MSS value
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=0,
            ipv6_mss=1420,
            ipv4_direction=0,
            ipv6_direction=1,
        )

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip6(self.pg1, self.pg0, 1460, 1420)

        # enable the the feature only in TX direction
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=0,
            ipv6_mss=1424,
            ipv4_direction=0,
            ipv6_direction=2,
        )

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip6(self.pg1, self.pg0, 1460, 1460)

        # disable the feature
        self.vapi.mss_clamp_enable_disable(
            self.pg1.sw_if_index,
            ipv4_mss=0,
            ipv6_mss=0,
            ipv4_direction=0,
            ipv6_direction=0,
        )

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip6(self.pg1, self.pg0, 1460, 1460)


class TestMSSClampIfaceDelete(VppTestCase):
    """TCP MSS Clamping - interface delete and sw_if_index reuse"""

    def setUp(self):
        super(TestMSSClampIfaceDelete, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestMSSClampIfaceDelete, self).tearDown()

    def clamp_dump(self):
        # get the clamp state of all interfaces
        _, details = self.vapi.mss_clamp_get(sw_if_index=INVALID_INDEX)
        return details

    def enable_clamp(self, sw_if_index, mss=1424, direction=None):
        if direction is None:
            direction = (
                VppEnum.vl_api_mss_clamp_dir_t.MSS_CLAMP_DIR_RX
                | VppEnum.vl_api_mss_clamp_dir_t.MSS_CLAMP_DIR_TX
            )
        self.vapi.mss_clamp_enable_disable(
            sw_if_index,
            ipv4_mss=mss,
            ipv6_mss=mss,
            ipv4_direction=direction,
            ipv6_direction=direction,
        )

    def verify_features(self, itf, present):
        feats = self.vapi.cli("show interface features %s" % itf.name)
        for node in (
            "tcp-mss-clamping-ip4-in",
            "tcp-mss-clamping-ip4-out",
            "tcp-mss-clamping-ip6-in",
            "tcp-mss-clamping-ip6-out",
        ):
            if present:
                self.assertIn(node, feats)
            else:
                self.assertNotIn(node, feats)

    def send_syn_and_verify(self, dst, mss, expected_mss):
        syn = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst=dst.remote_ip4)
            / TCP(sport=1234, dport=1234, flags="S", options=[("MSS", mss)])
            / Raw(b"\xa5" * 100)
        )
        rxs = self.send_and_expect(self.pg0, syn * 5, self.pg1)
        for rx in rxs:
            self.assertEqual(rx[TCP].options[0], ("MSS", expected_mss))

    def test_loopback_delete(self):
        """Clamp state is reset when an interface is deleted"""

        (lo,) = self.create_loopback_interfaces(1)
        sw_if_index = lo.sw_if_index
        try:
            self.enable_clamp(sw_if_index)
            self.verify_features(lo, True)
            self.assertEqual([d.sw_if_index for d in self.clamp_dump()], [sw_if_index])

            lo.remove_vpp_config()

            # Verify that no clamp state is left for the deleted interface.
            self.assertEqual(self.clamp_dump(), [])

            # Create the interface again and verify that it gets the same sw_if_index
            # and has no clamp state.
            (lo,) = self.create_loopback_interfaces(1)
            self.assertEqual(lo.sw_if_index, sw_if_index)
            self.assertEqual(self.clamp_dump(), [])
            self.verify_features(lo, False)

            # Enable the feature again with the same parameters and verify that it
            # is enabled.
            self.enable_clamp(sw_if_index)
            self.verify_features(lo, True)
        finally:
            if lo.query_vpp_config():
                self.enable_clamp(lo.sw_if_index, mss=0, direction=0)
                lo.remove_vpp_config()

    def test_subif_delete(self):
        """A re-created sub-interface does not inherit clamping"""

        tx = VppEnum.vl_api_mss_clamp_dir_t.MSS_CLAMP_DIR_TX
        sub = VppDot1QSubint(self, self.pg1, 10)
        try:
            sub.admin_up()
            sub.config_ip4()
            sub.resolve_arp()
            sw_if_index = sub.sw_if_index
            self.enable_clamp(sw_if_index, direction=tx)
            self.send_syn_and_verify(sub, 1460, 1424)

            sub.unconfig_ip4()
            sub.admin_down()
            sub.remove_vpp_config()

            sub = VppDot1QSubint(self, self.pg1, 10)
            self.assertEqual(sub.sw_if_index, sw_if_index)
            sub.admin_up()
            sub.config_ip4()
            sub.resolve_arp()

            # Send syn packets and verify that the MSS value is unchanged.
            self.send_syn_and_verify(sub, 1460, 1460)

            # Enable the feature again with the same parameters and verify that
            # the MSS value is lowered.
            self.enable_clamp(sw_if_index, direction=tx)
            self.send_syn_and_verify(sub, 1460, 1424)
        finally:
            if sub.query_vpp_config():
                self.enable_clamp(sub.sw_if_index, mss=0, direction=0)
                sub.unconfig_ip4()
                sub.admin_down()
                sub.remove_vpp_config()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
