import socket
import unittest

from framework import VppTestRunner
from framework import VppTestCase
from util import ppp
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP
from vpp_ipsec import VppIpsecSpd, VppIpsecSpdEntry, \
    VppIpsecSpdItfBinding
from vpp_papi import VppEnum
from re import search


class IPSec4SpdCommonMethods(VppTestCase):
    # Add flow cache field parameter to startup.conf
    @classmethod
    def setUpConstants(cls):
        super(IPSec4SpdCommonMethods, cls).setUpConstants()
        cls.vpp_cmdline.extend(["ipsec", "{",
                                "ipv4-out-spd-flow-cache on",
                                "}"])
        cls.logger.info("VPP modified cmdline is %s" % " "
                        .join(cls.vpp_cmdline))

    @classmethod
    def setUpClass(cls):
        super(IPSec4SpdCommonMethods, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(IPSec4SpdCommonMethods, cls).tearDownClass()

    def setUp(self):
        super(IPSec4SpdCommonMethods, self).setUp()
        # store SPD objects so we can remove configs on tear down
        self.spd_objs = []

    def tearDown(self):
        # remove spd items
        for obj in reversed(self.spd_objs):
            obj.remove_vpp_config()
        self.spd_objs = []
        # close down pg intfs
        for pg in self.pg_interfaces:
            pg.unconfig_ip4()
            pg.admin_down()
        super(IPSec4SpdCommonMethods, self).tearDown()

    def create_interfaces(self, num_ifs=2):
        # create interfaces pg0 ... pg<num_ifs>
        self.create_pg_interfaces(range(num_ifs))
        for pg in self.pg_interfaces:
            # put the interface up
            pg.admin_up()
            # configure IPv4 address on the interface
            pg.config_ip4()
            # resolve ARP, so that we know VPP MAC
            pg.resolve_arp()
        self.logger.info(self.vapi.ppcli("show int addr"))

    def spd_create_and_intf_add(self, spd_id, pg_list):
        spd = VppIpsecSpd(self, spd_id)
        spd.add_vpp_config()
        self.spd_objs.append(spd)
        for pg in pg_list:
            spdItf = VppIpsecSpdItfBinding(self, spd, pg)
            spdItf.add_vpp_config()
            self.spd_objs.append(spdItf)

    def spd_add_low_discard_high_bypass(self, spd_id, src_if, dst_if,
                                        proto, num_rules, is_out):
        spd = VppIpsecSpd(self, spd_id)
        e = VppEnum.vl_api_ipsec_spd_action_t
        # Low priority DISCARD rule
        for x in range(num_rules):
            spdEntry = VppIpsecSpdEntry(self, spd, 0,
                                        src_if.remote_ip4,
                                        src_if.remote_ip4,
                                        dst_if.remote_ip4,
                                        dst_if.remote_ip4,
                                        proto,
                                        priority=x,
                                        policy=e.IPSEC_API_SPD_ACTION_DISCARD,
                                        is_outbound=is_out)
            spdEntry.add_vpp_config()
            self.spd_objs.append(spdEntry)
        # High Priority BYPASS rule
        spdEntry = VppIpsecSpdEntry(self, spd, 0,
                                    src_if.remote_ip4,
                                    src_if.remote_ip4,
                                    dst_if.remote_ip4,
                                    dst_if.remote_ip4,
                                    proto,
                                    priority=num_rules+1,
                                    policy=e.IPSEC_API_SPD_ACTION_BYPASS,
                                    is_outbound=is_out)
        spdEntry.add_vpp_config()
        self.spd_objs.append(spdEntry)
        self.logger.info(self.vapi.ppcli("show ipsec all"))

    def spd_remove_high_bypass(self, spd_id, src_if, dst_if,
                               proto, num_rules, is_out):
        spd = VppIpsecSpd(self, spd_id)
        e = VppEnum.vl_api_ipsec_spd_action_t
        # Remove high priority BYPASS rule
        spdEntry = VppIpsecSpdEntry(self, spd, 0,
                                    src_if.remote_ip4,
                                    src_if.remote_ip4,
                                    dst_if.remote_ip4,
                                    dst_if.remote_ip4,
                                    proto,
                                    priority=num_rules+1,
                                    policy=e.IPSEC_API_SPD_ACTION_BYPASS,
                                    is_outbound=is_out)
        spdEntry.remove_vpp_config()
        self.logger.info(self.vapi.ppcli("show ipsec all"))

    def create_stream(self, src_if, dst_if, count, src_prt=1234, dst_prt=5678):
        packets = []
        for i in range(count):
            # create packet info stored in the test case instance
            info = self.create_packet_info(src_if, dst_if)
            # convert the info into packet payload
            payload = self.info_to_payload(info)
            # create the packet itself
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                 UDP(sport=src_prt, dport=dst_prt) /
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
            except Exception as e:
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

    def get_spd_bihash_values(self):
        """ 'show bihash' output:
        Hash table 'IPSec IPv4 OUTBOUND SPD Flow cache'
            0 active elements 0 active buckets
            0 free lists
            0 linear search buckets
            heap: 1 chunk(s) allocated
                bytes: used 128m, scrap 0
        """
        bihash_reply = self.vapi.cli("show bihash")
        # match the relevant section of 'show bihash' output
        regex_match = re.search(
            'Hash table \'IPSec IPv4 OUTBOUND SPD Flow cache\'(.*)scrap',
            bihash_reply, re.DOTALL)
        if regex_match is None:
            raise Exception("Unable to find spd flow cache bihash table \
                in \'show bihash\' CLI output")
        else:
            bihash_str = regex_match.group(0)
            # scrape all positive integer numbers from CLI and return to a list
            bihash_values = [int(s) for s in bihash_str.split() if s.isdigit()]
            # bihash_values[0] = active elements
            # bihash_values[1] = active buckets
            # bihash_values[2] = free lists
            # bihash_values[3] = linear search buckets
            # bihash_values[4] = heap chunk(s) allocated
            key = ["active elements", "active buckets", "free lists",
                   "linear search buckets", "heap chunk(s) allocated"]
            for i in range(len(bihash_values)):
                self.logger.info("bihash contents: " + key[i] +
                                 ": " + str(bihash_values[i]))
        return bihash_values

    def check_spd_bihash_active_elements(self, expected_elements):
        bihash_values = self.get_spd_bihash_values()
        # bihash_values[0] = active elements
        self.assertEqual(bihash_values[0], expected_elements)


class IPSec4SpdTestCaseAdd(IPSec4SpdCommonMethods):
    """ IPSec/IPv4 outbound: Policy mode test case with flow cache \
        (add rule)"""
    def test_ipsec_spd_outbound_add(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec outbound SPD policy lookup.
        # 2 SPD rules (1 HIGH and 1 LOW) are added.
        # High priority rule action is set to BYPASS.
        # Low priority rule action is set to DISCARD.
        # Traffic sent on pg0 interface should match high priority
        # rule and should be sent out on pg1 interface.
        self.create_interfaces(2)
        count = 2
        num_discard_rules = 1
        self.spd_create_and_intf_add(1, [self.pg1])
        self.spd_add_low_discard_high_bypass(
            1, self.pg0, self.pg1, socket.IPPROTO_UDP, num_discard_rules, 1)
        # check flow cache is empty before sending traffic
        self.check_spd_bihash_active_elements(0)
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
        self.logger.debug("SPD Add: Num packets: %s", len(capture.res))
        self.verify_capture(self.pg0, self.pg1, capture)
        # check policy in SPD has been cached after traffic
        # matched BYPASS rule in SPD
        self.check_spd_bihash_active_elements(1)


class IPSec4SpdTestCaseRemove(IPSec4SpdCommonMethods):
    """ IPSec/IPv4 outbound: Policy mode test case with flow cache \
        (remove rule)"""
    def test_ipsec_spd_outbound_remove(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec outbound SPD policy lookup.
        # 2 SPD rules (1 HIGH and 1 LOW) are added.
        # High priority rule action is set to BYPASS.
        # Low priority rule action is set to DISCARD.
        # High priority rule is then removed.
        # Traffic sent on pg0 interface should match low priority
        # rule and should be discarded after SPD lookup.
        self.create_interfaces(2)
        count = 2
        num_discard_rules = 1
        self.spd_create_and_intf_add(1, [self.pg1])
        self.spd_add_low_discard_high_bypass(
            1, self.pg0, self.pg1, socket.IPPROTO_UDP, num_discard_rules, 1)
        self.spd_remove_high_bypass(
            1, self.pg0, self.pg1, socket.IPPROTO_UDP, num_discard_rules, 1)

        # check flow cache is empty before sending traffic
        self.check_spd_bihash_active_elements(0)

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
        # check policy in SPD has been cached after traffic matched rule in SPD
        self.check_spd_bihash_active_elements(1)


class IPSec4SpdTestCaseReadd(IPSec4SpdCommonMethods):
    """ IPSec/IPv4 outbound: Policy mode test case with flow cache \
        (add, remove, re-add)"""
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
        self.create_interfaces(2)
        count = 2
        num_discard_rules = 1
        self.spd_create_and_intf_add(1, [self.pg1])
        self.spd_add_low_discard_high_bypass(
            1, self.pg0, self.pg1, socket.IPPROTO_UDP, num_discard_rules, 1)

        # check flow cache is empty before sending traffic
        self.check_spd_bihash_active_elements(0)

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

        # check policy in SPD has been cached after traffic matched BYPASS
        # rule in SPD
        self.check_spd_bihash_active_elements(1)

        # remove high priority SPD rules
        self.spd_remove_high_bypass(
            1, self.pg0, self.pg1, socket.IPPROTO_UDP, num_discard_rules, 1)
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
        # all packets will be dropped by SPD rule on pg1
        self.pg1.assert_nothing_captured()

        # by removing the BYPASS rule, we invalidated the corresponding
        # bihash entry when the same IP tuple hash is searched again,
        # bihash lookup fails and we overwrite the entry with the updated
        # policy (DISCARD) matched in the linear search we should therefore
        # still expect a single (1) active element with the hash of the
        # IP tuple
        self.check_spd_bihash_active_elements(1)

        # Readd high priority bypass rule, but don't add any more discard rules
        self.spd_add_low_discard_high_bypass(
            1, self.pg0, self.pg1, socket.IPPROTO_UDP, 0, 1)
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
        self.logger.debug(
            "SPD Readd/After readd: Num packets: %s", len(capture.res))

        # as above, we overwrote the previous bihash entry, so should still
        # expect a single active element in the table matching the IP tuple
        self.check_spd_bihash_active_elements(1)


class IPSec4SpdTestCaseMultiple(IPSec4SpdCommonMethods):
    """ IPSec/IPv4 outbound: Policy mode test case with flow cache \
        (multiple interfaces, multiple rules)"""
    def test_ipsec_spd_outbound_multiple(self):
        # In this test case, packets in IPv4 FWD path are configured to go
        # through IPSec outbound SPD policy lookup.
        # Multiples rules on multiple interfaces are tested at the same time.
        # 3x interfaces are configured, binding the same SPD to each.
        # Each interface has 4 SPD rules (1 HIGH and 3 LOW).
        # High priority rule action is set to BYPASS.
        # Low priority rule action is set to DISCARD.
        # On pg0 & pg1, the BYPASS rule is matched.
        # On pg2, the bypass rule is removed, matching the DISCARD rule.
        # Traffic should be received on pg0 & pg1 and dropped on pg2.
        self.create_interfaces(3)
        count = 2
        num_discard_rules = 3
        # bind SPD to all interfaces
        self.spd_create_and_intf_add(1, self.pg_interfaces)
        # add rules on all interfaces
        self.spd_add_low_discard_high_bypass(
            1, self.pg0, self.pg1, socket.IPPROTO_UDP, num_discard_rules, 1)
        self.spd_add_low_discard_high_bypass(
            1, self.pg1, self.pg2, socket.IPPROTO_UDP, num_discard_rules, 1)
        self.spd_add_low_discard_high_bypass(
            1, self.pg2, self.pg0, socket.IPPROTO_UDP, num_discard_rules, 1)
        # remove bypass rule on traffic to pg0 - leaving discard rule
        self.spd_remove_high_bypass(
            1, self.pg2, self.pg0, socket.IPPROTO_UDP, num_discard_rules, 1)
        # check flow cache is empty (0 active elements) before sending traffic
        self.check_spd_bihash_active_elements(0)
        # create the packet streams
        packets0 = self.create_stream(self.pg0, self.pg1, count)
        packets1 = self.create_stream(self.pg1, self.pg2, count)
        packets2 = self.create_stream(self.pg2, self.pg0, count)
        # add the streams to the source interfaces
        self.pg0.add_stream(packets0)
        self.pg1.add_stream(packets1)
        self.pg2.add_stream(packets2)
        # enable capture on all interfaces
        for pg in self.pg_interfaces:
            pg.enable_capture()
        # start the packet generator
        self.pg_start()

        # get captures from ifs - the proper count of packets was saved by
        # create_packet_info() based on dst_if parameter
        if_caps = []
        for pg in [self.pg1, self.pg2]:  # we are expecting captures on pg1/pg2
            if_caps.append(pg.get_capture())
            for packet in if_caps[-1]:
                try:
                    self.logger.debug(ppp("SPD Add - Got packet:", packet))
                except Exception:
                    self.logger.error(
                        ppp("Unexpected or invalid packet:", packet))
                    raise

        # verify captures that matched BYPASS rule
        self.logger.debug("SPD Add: Num packets: %s", len(if_caps[0].res))
        self.verify_capture(self.pg0, self.pg1, if_caps[0])

        self.logger.debug("SPD Add: Num packets: %s", len(if_caps[1].res))
        self.verify_capture(self.pg1, self.pg2, if_caps[1])

        # verify that traffic to pg0 matched DISCARD rule and was dropped
        self.pg0.assert_nothing_captured()

        # check that 3 matching policies in SPD have been cached
        self.check_spd_bihash_active_elements(3)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
