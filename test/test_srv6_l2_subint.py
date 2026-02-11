#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_sub_interface import VppDot1QSubint
from vpp_srv6 import (
    SRv6LocalSIDBehaviors,
    VppSRv6LocalSID,
    VppSRv6PolicyV2,
    SRv6PolicyType,
    VppSRv6Steering,
    SRv6PolicySteeringTypes,
)

import scapy.compat
from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet6 import IPv6, UDP, IPv6ExtHdrSegmentRouting

from util import ppp


class TestSRv6L2Subint(VppTestCase):
    """SRv6 L2 Sub-Interface Steering Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestSRv6L2Subint, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSRv6L2Subint, cls).tearDownClass()

    def setUp(self):
        super(TestSRv6L2Subint, self).setUp()
        self.pg_packet_sizes = [64, 512, 1518, 9018]
        self.reset_packet_infos()

    def tearDown(self):
        self.teardown_interfaces()
        super(TestSRv6L2Subint, self).tearDown()

    def teardown_interfaces(self):
        for i in self.pg_interfaces:
            self.logger.debug("Tear down interface %s" % (i.name))
            i.admin_down()
            i.unconfig()
            i.set_table_ip4(0)
            i.set_table_ip6(0)

    def create_packet_header_L2(self, vlan=0):
        """Create an L2 packet header, optionally with a VLAN tag."""
        p = Ether(src="00:11:22:33:44:55", dst="00:55:44:33:22:11")
        etype = 0x8137  # IPX
        if vlan:
            p /= Dot1Q(vlan=vlan, type=etype)
        else:
            p.type = etype
        return p

    def create_packet_header_IPv6_SRH_L2(self, sidlist, segleft, vlan=0):
        """Create an IPv6+SRH encapsulated L2 packet header."""
        eth = Ether(src="00:11:22:33:44:55", dst="00:55:44:33:22:11")
        etype = 0x8137  # IPX
        if vlan:
            eth /= Dot1Q(vlan=vlan, type=etype)
        else:
            eth.type = etype

        p = (
            IPv6(src="1234::1", dst=sidlist[segleft])
            / IPv6ExtHdrSegmentRouting(addresses=sidlist, segleft=segleft, nh=143)
            / eth
        )
        return p

    def create_packet_header_IPv6_L2(self, dst_outer, vlan=0):
        """Create an IPv6-encapsulated L2 packet header (no SRH)."""
        eth = Ether(src="00:11:22:33:44:55", dst="00:55:44:33:22:11")
        etype = 0x8137  # IPX
        if vlan:
            eth /= Dot1Q(vlan=vlan, type=etype)
        else:
            eth.type = etype

        p = IPv6(src="1234::1", dst=dst_outer, nh=143) / eth
        return p

    def create_stream(self, src_if, dst_if, packet_header, packet_sizes, count):
        """Create a packet stream with payload info for tracking."""
        self.logger.info("Creating packets")
        pkts = []
        for i in range(0, count - 1):
            payload_info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(payload_info)
            if packet_header.getlayer(0).name == "Ethernet":
                p = packet_header / Raw(payload)
            else:
                p = (
                    Ether(dst=src_if.local_mac, src=src_if.remote_mac)
                    / packet_header
                    / Raw(payload)
                )
            size = packet_sizes[i % len(packet_sizes)]
            self.extend_packet(p, size)
            p = Ether(scapy.compat.raw(p))
            payload_info.data = p.copy()
            pkts.append(p)
        self.logger.info("Done creating packets")
        return pkts

    def send_and_verify_pkts(
        self, input, pkts, output, compare_func, expected_count=None
    ):
        """Send packets and verify received packets."""
        input.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = output.get_capture(expected_count=expected_count)
        input.assert_nothing_captured()
        self.verify_captured_pkts(output, capture, compare_func)

    def get_payload_info(self, packet):
        """Extract the payload_info from the packet."""
        try:
            payload_info = self.payload_to_info(packet[Raw])
        except Exception:
            payload_info = self.payload_to_info(
                Ether(scapy.compat.raw(packet[Raw]))[Raw]
            )
        return payload_info

    def verify_captured_pkts(self, dst_if, capture, compare_func):
        """Verify captured packet stream."""
        last_info = dict()
        for i in self.pg_interfaces:
            last_info[i.sw_if_index] = None
        dst_sw_if_index = dst_if.sw_if_index

        for packet in capture:
            try:
                payload_info = self.get_payload_info(packet)
                packet_index = payload_info.index
                self.assertEqual(payload_info.dst, dst_sw_if_index)

                next_info = self.get_next_packet_info_for_interface2(
                    payload_info.src,
                    dst_sw_if_index,
                    last_info[payload_info.src],
                )
                last_info[payload_info.src] = next_info
                self.assertTrue(next_info is not None)
                self.assertEqual(packet_index, next_info.index)
                txed_packet = next_info.data

                compare_func(txed_packet, packet)

            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

    def compare_rx_tx_packet_T_Encaps_L2(self, tx_pkt, rx_pkt):
        """Compare input and output after T.Encaps for L2.

        Expected: in: L2 -> out: IPv6(C, S1)SRH(S3,S2,S1; SL=2)L2
        """
        rx_ip = rx_pkt.getlayer(IPv6)
        tx_ether = tx_pkt.getlayer(Ether)

        sr_policy_source = self.sr_policy.source

        # rx should have SRH
        self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))
        rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)

        # source should be SR policy source
        self.assertEqual(rx_ip.src, sr_policy_source)

        hit = None
        for seglist in self.sr_policy.seg_lists:
            tx_seglist = seglist[::-1]
            if rx_ip.dst == tx_seglist[-1]:
                hit = True
                self.assertEqual(rx_srh.addresses, tx_seglist)
                self.assertEqual(rx_srh.segleft, len(tx_seglist) - 1)
                break

        self.assertTrue(hit)
        self.assertEqual(rx_srh.segleft, rx_srh.lastentry)
        # nh should be "No Next Header" (143) = Ethernet
        self.assertEqual(rx_srh.nh, 143)

        # the payload beyond SRH should equal the original L2 frame
        self.assertEqual(Ether(scapy.compat.raw(rx_srh.payload)), tx_ether)
        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_End_DX2(self, tx_pkt, rx_pkt):
        """Compare input and output after End.DX2.

        Expected: in: IPv6(A,S3)SRH(S3,S2,S1;SL=0)L2 -> out: L2
        """
        rx_eth = rx_pkt.getlayer(Ether)
        tx_eth1 = Ether(scapy.compat.raw(tx_pkt[Raw]))

        self.assertFalse(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))
        self.assertEqual(rx_eth, tx_eth1)
        self.logger.debug("packet verification: SUCCESS")

    def test_SRv6_T_Encaps_L2_HW(self):
        """Test SRv6 L2 encapsulation on a hardware (phy) interface."""
        # pg0: ingress L2, pg1: egress IPv6
        self.create_pg_interfaces(range(2))
        self.pg_interfaces[1].set_table_ip6(0)
        self.pg_interfaces[1].config_ip6()
        self.pg_interfaces[1].resolve_ndp(timeout=5)
        self.pg_interfaces[1].admin_up()
        # pg0 does NOT get IP config — it's used for raw L2
        self.pg_interfaces[0].admin_up()

        # route for SR policy next-hop
        route = VppIpRoute(
            self,
            "a4::",
            64,
            [VppRoutePath(self.pg1.remote_ip6, self.pg1.sw_if_index)],
        )
        route.add_vpp_config()

        # configure SR policy
        bsid = "a3::9999:1"
        sr_policy = VppSRv6PolicyV2(
            self,
            bsid=bsid,
            is_encap=1,
            sr_type=SRv6PolicyType.SR_POLICY_TYPE_DEFAULT,
            weight=1,
            fib_table=0,
            source="a3::",
            encap_src="a3::",
        )
        sr_policy.add_vpp_config(segments=["a4::", "a5::", "a6::c7"])
        self.sr_policy = sr_policy

        self.logger.info(self.vapi.cli("show sr policies"))

        # steer L2 traffic on pg0 (hardware interface)
        pol_steering = VppSRv6Steering(
            self,
            bsid=self.sr_policy.bsid,
            prefix="::",
            mask_width=0,
            traffic_type=SRv6PolicySteeringTypes.SR_STEER_L2,
            sr_policy_index=0,
            table_id=0,
            sw_if_index=self.pg0.sw_if_index,
        )
        pol_steering.add_vpp_config()

        self.logger.info(self.vapi.cli("show sr steering-policies"))

        count = len(self.pg_packet_sizes)
        pkts = []

        # L2 packets without VLAN
        packet_header = self.create_packet_header_L2()
        pkts.extend(
            self.create_stream(
                self.pg0,
                self.pg1,
                packet_header,
                self.pg_packet_sizes,
                count,
            )
        )

        # L2 packets with VLAN
        packet_header = self.create_packet_header_L2(vlan=123)
        pkts.extend(
            self.create_stream(
                self.pg0,
                self.pg1,
                packet_header,
                self.pg_packet_sizes,
                count,
            )
        )

        self.send_and_verify_pkts(
            self.pg0,
            pkts,
            self.pg1,
            self.compare_rx_tx_packet_T_Encaps_L2,
        )

        self.logger.info(self.vapi.cli("show sr localsid"))

        # cleanup
        pol_steering.remove_vpp_config()
        self.sr_policy.remove_vpp_config()
        self.teardown_interfaces()

    def test_SRv6_T_Encaps_L2_Subint(self):
        """Test SRv6 L2 encapsulation on a sub-interface (VLAN)."""
        # pg0: ingress (parent for sub-interface), pg1: egress IPv6
        self.create_pg_interfaces(range(2))
        self.pg_interfaces[1].set_table_ip6(0)
        self.pg_interfaces[1].config_ip6()
        self.pg_interfaces[1].resolve_ndp(timeout=5)
        self.pg_interfaces[1].admin_up()
        self.pg_interfaces[0].admin_up()

        # create VLAN 100 sub-interface on pg0
        subif = VppDot1QSubint(self, self.pg0, 100)
        subif.admin_up()

        # route for SR policy next-hop
        route = VppIpRoute(
            self,
            "a4::",
            64,
            [VppRoutePath(self.pg1.remote_ip6, self.pg1.sw_if_index)],
        )
        route.add_vpp_config()

        # configure SR policy
        bsid = "a3::9999:1"
        sr_policy = VppSRv6PolicyV2(
            self,
            bsid=bsid,
            is_encap=1,
            sr_type=SRv6PolicyType.SR_POLICY_TYPE_DEFAULT,
            weight=1,
            fib_table=0,
            source="a3::",
            encap_src="a3::",
        )
        sr_policy.add_vpp_config(segments=["a4::", "a5::", "a6::c7"])
        self.sr_policy = sr_policy

        self.logger.info(self.vapi.cli("show sr policies"))

        # steer L2 traffic on the sub-interface
        pol_steering = VppSRv6Steering(
            self,
            bsid=self.sr_policy.bsid,
            prefix="::",
            mask_width=0,
            traffic_type=SRv6PolicySteeringTypes.SR_STEER_L2,
            sr_policy_index=0,
            table_id=0,
            sw_if_index=subif.sw_if_index,
        )
        pol_steering.add_vpp_config()

        self.logger.info(self.vapi.cli("show sr steering-policies"))
        self.logger.info(self.vapi.cli("show interface %s" % subif.name))

        count = len(self.pg_packet_sizes)
        pkts = []

        # L2 packets with VLAN 100 tag (matching the sub-interface)
        # These are sent on pg0 (the parent) with a VLAN 100 tag.
        # ethernet-input will classify them to the sub-interface,
        # l2input will dispatch via the SRV6 feature bit.
        packet_header = self.create_packet_header_L2(vlan=100)
        pkts.extend(
            self.create_stream(
                self.pg0,
                self.pg1,
                packet_header,
                self.pg_packet_sizes,
                count,
            )
        )

        self.send_and_verify_pkts(
            self.pg0,
            pkts,
            self.pg1,
            self.compare_rx_tx_packet_T_Encaps_L2,
        )

        self.logger.info(self.vapi.cli("show sr localsid"))

        # cleanup
        pol_steering.remove_vpp_config()
        self.sr_policy.remove_vpp_config()
        subif.remove_vpp_config()
        self.teardown_interfaces()

    def test_SRv6_End_DX2_HW(self):
        """Test SRv6 End.DX2 decapsulation to a hardware (phy) interface."""
        # pg0: ingress IPv6, pg1: egress L2
        self.create_pg_interfaces(range(2))
        self.pg_interfaces[0].set_table_ip6(0)
        self.pg_interfaces[0].config_ip6()
        self.pg_interfaces[0].resolve_ndp(timeout=5)
        self.pg_interfaces[0].admin_up()
        # pg1 does NOT get IP config — it's used for raw L2 output
        self.pg_interfaces[1].admin_up()

        # configure End.DX2 localSID → output to pg1 (hw interface)
        localsid = VppSRv6LocalSID(
            self,
            localsid="A3::C4",
            behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_DX2,
            nh_addr=0,
            end_psp=0,
            sw_if_index=self.pg1.sw_if_index,
            fib_table=0,
        )
        localsid.add_vpp_config()
        self.logger.debug(self.vapi.cli("show sr localsid"))

        count = len(self.pg_packet_sizes)
        pkts = []

        # IPv6 + SRH with L2 payload (no VLAN)
        packet_header = self.create_packet_header_IPv6_SRH_L2(
            sidlist=["a3::c4", "a2::", "a1::"], segleft=0, vlan=0
        )
        pkts.extend(
            self.create_stream(
                self.pg0,
                self.pg1,
                packet_header,
                self.pg_packet_sizes,
                count,
            )
        )

        # IPv6 + SRH with L2 payload (with VLAN)
        packet_header = self.create_packet_header_IPv6_SRH_L2(
            sidlist=["a3::c4", "a2::", "a1::"], segleft=0, vlan=123
        )
        pkts.extend(
            self.create_stream(
                self.pg0,
                self.pg1,
                packet_header,
                self.pg_packet_sizes,
                count,
            )
        )

        # IPv6 (no SRH) with L2 payload (no VLAN)
        packet_header = self.create_packet_header_IPv6_L2(dst_outer="a3::c4", vlan=0)
        pkts.extend(
            self.create_stream(
                self.pg0,
                self.pg1,
                packet_header,
                self.pg_packet_sizes,
                count,
            )
        )

        # IPv6 (no SRH) with L2 payload (with VLAN)
        packet_header = self.create_packet_header_IPv6_L2(dst_outer="a3::c4", vlan=123)
        pkts.extend(
            self.create_stream(
                self.pg0,
                self.pg1,
                packet_header,
                self.pg_packet_sizes,
                count,
            )
        )

        self.send_and_verify_pkts(
            self.pg0,
            pkts,
            self.pg1,
            self.compare_rx_tx_packet_End_DX2,
        )

        self.logger.info(self.vapi.cli("show sr localsid"))

        # cleanup
        localsid.remove_vpp_config()
        self.teardown_interfaces()

    def test_SRv6_End_DX2_Subint(self):
        """Test SRv6 End.DX2 decapsulation to a sub-interface (VLAN)."""
        # pg0: ingress IPv6, pg1: egress (parent for sub-interface)
        self.create_pg_interfaces(range(2))
        self.pg_interfaces[0].set_table_ip6(0)
        self.pg_interfaces[0].config_ip6()
        self.pg_interfaces[0].resolve_ndp(timeout=5)
        self.pg_interfaces[0].admin_up()
        self.pg_interfaces[1].admin_up()

        # create VLAN 200 sub-interface on pg1
        subif = VppDot1QSubint(self, self.pg1, 200)
        subif.admin_up()

        # configure End.DX2 localSID -> output to sub-interface
        localsid = VppSRv6LocalSID(
            self,
            localsid="A3::C4",
            behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_DX2,
            nh_addr=0,
            end_psp=0,
            sw_if_index=subif.sw_if_index,
            fib_table=0,
        )
        localsid.add_vpp_config()
        self.logger.debug(self.vapi.cli("show sr localsid"))

        count = len(self.pg_packet_sizes)
        pkts = []

        # IPv6 + SRH with L2 payload (no inner VLAN)
        packet_header = self.create_packet_header_IPv6_SRH_L2(
            sidlist=["a3::c4", "a2::", "a1::"], segleft=0, vlan=0
        )
        pkts.extend(
            self.create_stream(
                self.pg0,
                self.pg1,
                packet_header,
                self.pg_packet_sizes,
                count,
            )
        )

        # IPv6 + SRH with L2 payload (with inner VLAN)
        packet_header = self.create_packet_header_IPv6_SRH_L2(
            sidlist=["a3::c4", "a2::", "a1::"], segleft=0, vlan=123
        )
        pkts.extend(
            self.create_stream(
                self.pg0,
                self.pg1,
                packet_header,
                self.pg_packet_sizes,
                count,
            )
        )

        # IPv6 (no SRH) with L2 payload (no inner VLAN)
        packet_header = self.create_packet_header_IPv6_L2(dst_outer="a3::c4", vlan=0)
        pkts.extend(
            self.create_stream(
                self.pg0,
                self.pg1,
                packet_header,
                self.pg_packet_sizes,
                count,
            )
        )

        # IPv6 (no SRH) with L2 payload (with inner VLAN)
        packet_header = self.create_packet_header_IPv6_L2(dst_outer="a3::c4", vlan=123)
        pkts.extend(
            self.create_stream(
                self.pg0,
                self.pg1,
                packet_header,
                self.pg_packet_sizes,
                count,
            )
        )

        # End.DX2 decapsulates and outputs the raw L2 frame via the
        # sub-interface. We capture on the parent pg1.
        self.send_and_verify_pkts(
            self.pg0,
            pkts,
            self.pg1,
            self.compare_rx_tx_packet_End_DX2,
        )

        self.logger.info(self.vapi.cli("show sr localsid"))

        # cleanup
        localsid.remove_vpp_config()
        subif.remove_vpp_config()
        self.teardown_interfaces()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
