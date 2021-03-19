import socket
import unittest

from framework import VppTestRunner
from framework import VppTestCase
from util import ppp
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP
from random import randint
from vpp_ipsec import VppIpsecSpd, VppIpsecSpdEntry, \
    VppIpsecSpdItfBinding
from vpp_papi import VppEnum


class IPSec4SpdTestCase(VppTestCase):
    """ IPSec/IPv4 outbound: Policy mode test case with flow cache"""

    # Add flow cache field parameter to startup.conf
    @classmethod
    def setUpConstants(cls):
        super(IPSec4SpdTestCase, cls).setUpConstants()
        cls.vpp_cmdline.extend(["ipsec",
                                "{", "ipv4-out-spd-flow-cache on", "}"])
        cls.logger.info("VPP modified cmdline is %s" %
                        " ".join(cls.vpp_cmdline))

    @classmethod
    def setUpClass(self):
        super(IPSec4SpdTestCase, self).setUpClass()
        # create pg0 and pg1
        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            # put the interface up
            i.admin_up()
            # configure IPv4 address on the interface
            i.config_ip4()
            # resolve ARP, so that we know VPP MAC
            i.resolve_arp()

    def spd_create_and_intf_add(self, spd_id, pg):
        spd = VppIpsecSpd(self, spd_id)
        spd.add_vpp_config()
        spdItf = VppIpsecSpdItfBinding(self, spd, pg)
        spdItf.add_vpp_config()

    def spd_add(self, spd_id, pg0, pg1, proto, num_rules, is_out):
        spd = VppIpsecSpd(self, spd_id)
        e = VppEnum.vl_api_ipsec_spd_action_t
        # Low priority DISCARD rule
        for x in range(num_rules):
            spdEntry = VppIpsecSpdEntry(self, spd, 0,
                                        pg0.remote_ip4,
                                        pg0.remote_ip4,
                                        pg1.remote_ip4,
                                        pg1.remote_ip4,
                                        x,
                                        priority=5,
                                        policy=e.IPSEC_API_SPD_ACTION_DISCARD,
                                        is_outbound=is_out)
            spdEntry.add_vpp_config()
        # High Priority BYPASS rule
        spdEntry = VppIpsecSpdEntry(self, spd, 0,
                                    pg0.remote_ip4,
                                    pg0.remote_ip4,
                                    pg1.remote_ip4,
                                    pg1.remote_ip4,
                                    proto,
                                    priority=10,
                                    policy=e.IPSEC_API_SPD_ACTION_BYPASS,
                                    is_outbound=is_out)
        spdEntry.add_vpp_config()
        self.logger.info(self.vapi.ppcli("show ipsec all"))

    def spd_remove(self, spd_id, pg0, pg1, proto, num_rules, is_out):
        spd = VppIpsecSpd(self, spd_id)
        e = VppEnum.vl_api_ipsec_spd_action_t
        # Remove high priorioty BYPASS rule
        spdEntry = VppIpsecSpdEntry(self, spd, 0,
                                    pg0.remote_ip4,
                                    pg0.remote_ip4,
                                    pg1.remote_ip4,
                                    pg1.remote_ip4,
                                    proto,
                                    priority=10,
                                    policy=e.IPSEC_API_SPD_ACTION_BYPASS,
                                    is_outbound=is_out)
        spdEntry.remove_vpp_config()
        self.logger.info(self.vapi.ppcli("show ipsec all"))

    def create_stream(self, src_if, dst_if, count):
        packets = []
        for i in range(count):
            # create packet info stored in the test case instance
            info = self.create_packet_info(src_if, dst_if)
            # convert the info into packet payload
            payload = self.info_to_payload(info)
            # create the packet itself
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                 UDP(sport=1234, dport=5678) /
                 Raw(payload))
            # store a copy of the packet in the packet info
            info.data = p.copy()
            # append the packet to the list
            packets.append(p)

        # return the created packet list
        return packets

    def verify_capture(self, src_if, dst_if, capture):
        packet_info = None
        for packet in capture:
            try:
                ip = packet[IP]
                udp = packet[UDP]
                # convert the payload to packet info object
                payload_info = self.payload_to_info(packet)
                # make sure the indexes match
                self.assert_equal(payload_info.src, src_if.sw_if_index,
                                  "source sw_if_index")
                self.assert_equal(payload_info.dst, dst_if.sw_if_index,
                                  "destination sw_if_index")
                packet_info = self.get_next_packet_info_for_interface2(
                                src_if.sw_if_index,
                                dst_if.sw_if_index,
                                packet_info)
                # make sure we didn't run out of saved packets
                self.assertIsNotNone(packet_info)
                self.assert_equal(payload_info.index, packet_info.index,
                                  "packet info index")
                saved_packet = packet_info.data  # fetch the saved packet
                # assert the values match
                self.assert_equal(ip.src, saved_packet[IP].src,
                                  "IP source address")
                # ... more assertions here
                self.assert_equal(udp.sport, saved_packet[UDP].sport,
                                  "UDP source port")
            except:
                self.logger.error(ppp("Unexpected or invalid packet:",
                                  packet))
                raise
        remaining_packet = self.get_next_packet_info_for_interface2(
                src_if.sw_if_index,
                dst_if.sw_if_index,
                packet_info)
        self.assertIsNone(remaining_packet,
                          "Interface %s: Packet expected from interface "
                          "%s didn't arrive" % (dst_if.name, src_if.name))

    def test_ipsec_spd_outbound_add(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec outbound SPD policy lookup.
        # 2 SPD rules (1 HIGH and 1 LOW) are added.
        # High priority rule action is set to BYPASS.
        # Low priority rule action is set to DISCARD.
        # Traffic sent on pg0 interface should match high priority
        # rule and should be sent out on pg1 interface.
        count = 5
        self.spd_create_and_intf_add(1, self.pg1)
        self.spd_add(1, self.pg0, self.pg1, socket.IPPROTO_UDP, 1, 1)
        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, count)
        # add the stream to the source interface
        self.pg0.add_stream(packets)
        # enable capture on both interfaces
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        # start the packet generator
        self.pg_start()
        # get capture - the proper count of packets was saved by
        # create_packet_info() based on dst_if parameter
        capture = self.pg1.get_capture()
        for packet in capture:
            try:
                self.logger.debug(ppp("SPD Add - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        # assert nothing captured on pg0 (always do this last, so that
        # some time has already passed since pg_start())
        self.pg0.assert_nothing_captured()
        # verify capture
        num_pkts = len(capture.res)
        self.logger.debug("SPD Add: Num packets: %s", num_pkts)
        self.verify_capture(self.pg0, self.pg1, capture)

    def test_ipsec_spd_outbound_remove(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec outbound SPD policy lookup.
        # 2 SPD rules (1 HIGH and 1 LOW) are added.
        # High priority rule action is set to BYPASS.
        # Low priority rule action is set to DISCARD.
        # High priority rule is then removed.
        # Traffic sent on pg0 interface should match low priority
        # rule and should be discarded after SPD lookup.
        count = 5
        self.spd_create_and_intf_add(1, self.pg1)
        self.spd_add(1, self.pg0, self.pg1, socket.IPPROTO_UDP, 1, 1)
        self.spd_remove(1, self.pg0, self.pg1, socket.IPPROTO_UDP, 1, 1)
        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, count)
        # add the stream to the source interface
        self.pg0.add_stream(packets)
        # enable capture on both interfaces
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        # start the packet generator
        self.pg_start()
        # assert nothing captured on pg0 (always do this last, so that
        # some time has already passed since pg_start())
        self.pg0.assert_nothing_captured()
        # All packets will be dropped by SPD rule
        self.pg1.assert_nothing_captured()

    def test_ipsec_spd_outbound_readd(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec outbound SPD policy lookup.
        # 2 SPD rules (1 HIGH and 1 LOW) are added.
        # High priority rule action is set to BYPASS.
        # Low priority rule action is set to DISCARD.
        # Traffic sent on pg0 interface should match high priority
        # rule and should be sent out on pg1 interface.
        # High priority rule is then removed.
        # Traffic sent on pg0 interface should match low priority
        # rule and should be discarded after SPD lookup.
        # Readd high priority rule.
        # Traffic sent on pg0 interface should match high priority
        # rule and should be sent out on pg1 interface.
        count = 5
        self.spd_create_and_intf_add(1, self.pg1)
        self.spd_add(1, self.pg0, self.pg1, socket.IPPROTO_UDP, 1, 1)
        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, count)
        # add the stream to the source interface
        self.pg0.add_stream(packets)
        # enable capture on both interfaces
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        # start the packet generator
        self.pg_start()
        # get capture - the proper count of packets was saved by
        # create_packet_info() based on dst_if parameter
        capture = self.pg1.get_capture(count)
        for packet in capture:
            try:
                self.logger.debug(ppp("SPD Readd/add - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        # assert nothing captured on pg0 (always do this last, so that
        # some time has already passed since pg_start())
        self.pg0.assert_nothing_captured()
        # verify capture
        num_pkts = len(capture.res)
        self.logger.debug("SPD Readd/After add: Num packets: %s", num_pkts)
        self.assertEqual(num_pkts, count,
                         "incorrect spd out counts: expected %d != %d" %
                         (count, num_pkts))

        # Remove high priority SPD rule
        self.spd_remove(1, self.pg0, self.pg1, socket.IPPROTO_UDP, 1, 1)
        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, count)
        # add the stream to the source interface
        self.pg0.add_stream(packets)
        # enable capture on both interfaces
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        # start the packet generator
        self.pg_start()
        # assert nothing captured on pg0 (always do this last, so that
        # some time has already passed since pg_start())
        self.pg0.assert_nothing_captured()
        # All packets will be dropped by SPD rule on pg1
        self.pg1.assert_nothing_captured()

        # Readd high priority SPD rule
        self.spd_add(1, self.pg0, self.pg1, socket.IPPROTO_UDP, 0, 1)
        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, count)
        # add the stream to the source interface
        self.pg0.add_stream(packets)
        # enable capture on both interfaces
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        # start the packet generator
        self.pg_start()
        # get capture - the proper count of packets was saved by
        # create_packet_info() based on dst_if parameter
        capture = self.pg1.get_capture(count)
        for packet in capture:
            try:
                self.logger.debug(ppp("SPD Readd/readd - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        # assert nothing captured on pg0 (always do this last, so that
        # some time has already passed since pg_start())
        self.pg0.assert_nothing_captured()
        # verify capture
        num_pkts = len(capture.res)
        self.logger.debug("SPD Readd/After readd: Num packets: %s", num_pkts)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
