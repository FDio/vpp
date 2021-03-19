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
from os import popen
from ipaddress import ip_address


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

    def setUp(self):
        super(IPSec4SpdCommonMethods, self).setUp()
        # store SPD objects so we can remove configs on tear down
        self.spd_objs = []
        self.spd_policies = []

    def tearDown(self):
        # remove SPD policies
        for obj in self.spd_policies:
            obj.remove_vpp_config()
        self.spd_policies = []
        # remove SPD items (interface bindings first, then SPD)
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

    def get_policy(self, policy_type):
        e = VppEnum.vl_api_ipsec_spd_action_t
        if policy_type == "protect":
            return e.IPSEC_API_SPD_ACTION_PROTECT
        elif policy_type == "bypass":
            return e.IPSEC_API_SPD_ACTION_BYPASS
        elif policy_type == "discard":
            return e.IPSEC_API_SPD_ACTION_DISCARD
        else:
            raise Exception("Invalid policy type: %s", policy_type)

    def spd_add_rem_policy(self, spd_id, src_if, dst_if,
                           proto, is_out, priority, policy_type,
                           remove=False, all_ips=False):
        spd = VppIpsecSpd(self, spd_id)

        if all_ips:
            src_range_low = ip_address("0.0.0.0")
            src_range_high = ip_address("255.255.255.255")
            dst_range_low = ip_address("0.0.0.0")
            dst_range_high = ip_address("255.255.255.255")
        else:
            src_range_low = src_if.remote_ip4
            src_range_high = src_if.remote_ip4
            dst_range_low = dst_if.remote_ip4
            dst_range_high = dst_if.remote_ip4

        spdEntry = VppIpsecSpdEntry(self, spd, 0,
                                    src_range_low,
                                    src_range_high,
                                    dst_range_low,
                                    dst_range_high,
                                    proto,
                                    priority=priority,
                                    policy=self.get_policy(policy_type),
                                    is_outbound=is_out)

        if(remove is False):
            spdEntry.add_vpp_config()
            self.spd_policies.append(spdEntry)
        else:
            spdEntry.remove_vpp_config()
            self.spd_policies.remove(spdEntry)
        self.logger.info(self.vapi.ppcli("show ipsec all"))
        return spdEntry

    def create_stream(self, src_if, dst_if, pkt_count,
                      src_prt=1234, dst_prt=5678):
        packets = []
        for i in range(pkt_count):
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

    def verify_policy_match(self, pkt_count, spdEntry):
        matched_pkts = spdEntry.get_stats().get('packets')
        self.logger.info(
            "Policy %s matched: %d pkts", str(spdEntry), matched_pkts)
        self.assert_equal(pkt_count, matched_pkts)

    def get_spd_flow_cache_entries(self):
        """ 'show ipsec spd' output:
        ip4-outbound-spd-flow-cache-entries: 0
        """
        show_ipsec_reply = self.vapi.cli("show ipsec spd")
        # match the relevant section of 'show bihash' output
        regex_match = re.search(
            'ip4-outbound-spd-flow-cache-entries: (.*)',
            show_ipsec_reply, re.DOTALL)
        if regex_match is None:
            raise Exception("Unable to find spd flow cache entries \
                in \'show ipsec spd\' CLI output - regex failed to match")
        else:
            try:
                num_entries = int(regex_match.group(1))
            except ValueError:
                raise Exception("Unable to get spd flow cache entries \
                from \'show ipsec spd\' string: %s", regex_match.group(0))
            self.logger.info("%s", regex_match.group(0))
        return num_entries

    def verify_num_flow_cache_entries(self, expected_elements):
        self.assertEqual(self.get_spd_flow_cache_entries(), expected_elements)

    def crc32_supported(self):
        # lscpu is part of util-linux package, available on all Linux Distros
        stream = os.popen('lscpu')
        cpu_info = stream.read()
        # feature/flag "crc32" on Aarch64 and "sse4_2" on x86
        # see vppinfra/crc32.h
        if "crc32" or "sse4_2" in cpu_info:
            self.logger.info("\ncrc32 supported: " + cpu_info)
            return True
        else:
            self.logger.info("\ncrc32 NOT supported: " + cpu_info)
            return False


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
        pkt_count = 5
        self.spd_create_and_intf_add(1, [self.pg1])
        policy_0 = self.spd_add_rem_policy(  # outbound, priority 10
            1, self.pg0, self.pg1, socket.IPPROTO_UDP,
            is_out=1, priority=10, policy_type="bypass")
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1, self.pg0, self.pg1, socket.IPPROTO_UDP,
            is_out=1, priority=5, policy_type="discard")

        # check flow cache is empty before sending traffic
        self.verify_num_flow_cache_entries(0)

        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, pkt_count)
        # add the stream to the source interface + enable capture
        self.pg0.add_stream(packets)
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        # start the packet generator
        self.pg_start()
        # get capture
        capture = self.pg1.get_capture()
        for packet in capture:
            try:
                self.logger.debug(ppp("SPD - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        self.logger.debug("SPD: Num packets: %s", len(capture.res))

        # assert nothing captured on pg0
        self.pg0.assert_nothing_captured()
        # verify captured packets
        self.verify_capture(self.pg0, self.pg1, capture)
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(0, policy_1)
        # check policy in SPD has been cached after traffic
        # matched BYPASS rule in SPD
        self.verify_num_flow_cache_entries(1)


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
        pkt_count = 5
        self.spd_create_and_intf_add(1, [self.pg1])
        policy_0 = self.spd_add_rem_policy(  # outbound, priority 10
            1, self.pg0, self.pg1, socket.IPPROTO_UDP,
            is_out=1, priority=10, policy_type="bypass")
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1, self.pg0, self.pg1, socket.IPPROTO_UDP,
            is_out=1, priority=5, policy_type="discard")

        # check flow cache is empty before sending traffic
        self.verify_num_flow_cache_entries(0)

        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, pkt_count)
        # add the stream to the source interface + enable capture
        self.pg0.add_stream(packets)
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        # start the packet generator
        self.pg_start()
        # get capture
        capture = self.pg1.get_capture()
        for packet in capture:
            try:
                self.logger.debug(ppp("SPD - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        # assert nothing captured on pg0
        self.pg0.assert_nothing_captured()
        # verify capture on pg1
        self.logger.debug("SPD: Num packets: %s", len(capture.res))
        self.verify_capture(self.pg0, self.pg1, capture)
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(0, policy_1)
        # check policy in SPD has been cached after traffic
        # matched BYPASS rule in SPD
        self.verify_num_flow_cache_entries(1)

        # now remove the bypass rule
        self.spd_add_rem_policy(  # outbound, priority 10
            1, self.pg0, self.pg1, socket.IPPROTO_UDP,
            is_out=1, priority=10, policy_type="bypass",
            remove=True)

        # resend the same packets
        self.pg0.add_stream(packets)
        self.pg0.enable_capture()  # flush the old captures
        self.pg1.enable_capture()
        self.pg_start()
        # assert nothing captured on pg0
        self.pg0.assert_nothing_captured()
        # all packets will be dropped by SPD rule
        self.pg1.assert_nothing_captured()
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(pkt_count, policy_1)
        # previous entry in flow cache should have been overwritten
        # flow cache entries should still be 1
        self.verify_num_flow_cache_entries(1)


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
        pkt_count = 5
        self.spd_create_and_intf_add(1, [self.pg1])
        policy_0 = self.spd_add_rem_policy(  # outbound, priority 10
            1, self.pg0, self.pg1, socket.IPPROTO_UDP,
            is_out=1, priority=10, policy_type="bypass")
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1, self.pg0, self.pg1, socket.IPPROTO_UDP,
            is_out=1, priority=5, policy_type="discard")

        # check flow cache is empty before sending traffic
        self.verify_num_flow_cache_entries(0)

        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, pkt_count)
        # add the stream to the source interface + enable capture
        self.pg0.add_stream(packets)
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        # start the packet generator
        self.pg_start()
        # get capture
        capture = self.pg1.get_capture()
        for packet in capture:
            try:
                self.logger.debug(ppp("SPD - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        self.logger.debug("SPD: Num packets: %s", len(capture.res))

        # assert nothing captured on pg0
        self.pg0.assert_nothing_captured()
        # verify capture on pg1
        self.verify_capture(self.pg0, self.pg1, capture)
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(0, policy_1)
        # check policy in SPD has been cached after traffic
        # matched BYPASS rule in SPD
        self.verify_num_flow_cache_entries(1)

        # now remove the bypass rule, leaving only the discard rule
        self.spd_add_rem_policy(  # outbound, priority 10
            1, self.pg0, self.pg1, socket.IPPROTO_UDP,
            is_out=1, priority=10, policy_type="bypass",
            remove=True)

        # resend the same packets
        self.pg0.add_stream(packets)
        self.pg0.enable_capture()  # flush the old captures
        self.pg1.enable_capture()
        self.pg_start()

        # assert nothing captured on pg0
        self.pg0.assert_nothing_captured()
        # all packets will be dropped by SPD rule
        self.pg1.assert_nothing_captured()
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(pkt_count, policy_1)
        # previous entry in flow cache should have been overwritten
        # flow cache entries should still be 1
        self.verify_num_flow_cache_entries(1)

        # now readd the bypass rule
        policy_0 = self.spd_add_rem_policy(  # outbound, priority 10
            1, self.pg0, self.pg1, socket.IPPROTO_UDP,
            is_out=1, priority=10, policy_type="bypass")

        # resend the same packets
        self.pg0.add_stream(packets)
        self.pg0.enable_capture()  # flush the old captures
        self.pg1.enable_capture()
        self.pg_start()

        # get capture
        capture = self.pg1.get_capture(pkt_count)
        for packet in capture:
            try:
                self.logger.debug(ppp("SPD - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        self.logger.debug("SPD: Num packets: %s", len(capture.res))

        # assert nothing captured on pg0
        self.pg0.assert_nothing_captured()
        # verify captured packets
        self.verify_capture(self.pg0, self.pg1, capture)
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(pkt_count, policy_1)
        # previous entry in flow cache should have been overwritten
        # flow cache entries should still be 1
        self.verify_num_flow_cache_entries(1)


class IPSec4SpdTestCaseMultiple(IPSec4SpdCommonMethods):
    """ IPSec/IPv4 outbound: Policy mode test case with flow cache \
        (multiple interfaces, multiple rules)"""
    def test_ipsec_spd_outbound_multiple(self):
        # In this test case, packets in IPv4 FWD path are configured to go
        # through IPSec outbound SPD policy lookup.
        # Multiples rules on multiple interfaces are tested at the same time.
        # 3x interfaces are configured, binding the same SPD to each.
        # Each interface has 2 SPD rules (1 BYPASS and 1 DISCARD).
        # On pg0 & pg1, the BYPASS rule is HIGH priority
        # On pg2, the DISCARD rule is HIGH priority
        # Traffic should be received on pg0 & pg1 and dropped on pg2.
        self.create_interfaces(3)
        pkt_count = 5
        # bind SPD to all interfaces
        self.spd_create_and_intf_add(1, self.pg_interfaces)
        # add rules on all interfaces
        policy_01 = self.spd_add_rem_policy(  # outbound, priority 10
            1, self.pg0, self.pg1, socket.IPPROTO_UDP,
            is_out=1, priority=10, policy_type="bypass")
        policy_02 = self.spd_add_rem_policy(  # outbound, priority 5
            1, self.pg0, self.pg1, socket.IPPROTO_UDP,
            is_out=1, priority=5, policy_type="discard")

        policy_11 = self.spd_add_rem_policy(  # outbound, priority 10
            1, self.pg1, self.pg2, socket.IPPROTO_UDP,
            is_out=1, priority=10, policy_type="bypass")
        policy_12 = self.spd_add_rem_policy(  # outbound, priority 5
            1, self.pg1, self.pg2, socket.IPPROTO_UDP,
            is_out=1, priority=5, policy_type="discard")

        policy_21 = self.spd_add_rem_policy(  # outbound, priority 5
            1, self.pg2, self.pg0, socket.IPPROTO_UDP,
            is_out=1, priority=5, policy_type="bypass")
        policy_22 = self.spd_add_rem_policy(  # outbound, priority 10
            1, self.pg2, self.pg0, socket.IPPROTO_UDP,
            is_out=1, priority=10, policy_type="discard")

        # check flow cache is empty (0 active elements) before sending traffic
        self.verify_num_flow_cache_entries(0)

        # create the packet streams
        packets0 = self.create_stream(self.pg0, self.pg1, pkt_count)
        packets1 = self.create_stream(self.pg1, self.pg2, pkt_count)
        packets2 = self.create_stream(self.pg2, self.pg0, pkt_count)
        # add the streams to the source interfaces
        self.pg0.add_stream(packets0)
        self.pg1.add_stream(packets1)
        self.pg2.add_stream(packets2)
        # enable capture on all interfaces
        for pg in self.pg_interfaces:
            pg.enable_capture()
        # start the packet generator
        self.pg_start()

        # get captures
        if_caps = []
        for pg in [self.pg1, self.pg2]:  # we are expecting captures on pg1/pg2
            if_caps.append(pg.get_capture())
            for packet in if_caps[-1]:
                try:
                    self.logger.debug(ppp("SPD - Got packet:", packet))
                except Exception:
                    self.logger.error(
                        ppp("Unexpected or invalid packet:", packet))
                    raise
        self.logger.debug("SPD: Num packets: %s", len(if_caps[0].res))
        self.logger.debug("SPD: Num packets: %s", len(if_caps[1].res))

        # verify captures that matched BYPASS rule
        self.verify_capture(self.pg0, self.pg1, if_caps[0])
        self.verify_capture(self.pg1, self.pg2, if_caps[1])
        # verify that traffic to pg0 matched DISCARD rule and was dropped
        self.pg0.assert_nothing_captured()
        # verify all packets that were expected to match rules, matched
        # pg0 -> pg1
        self.verify_policy_match(pkt_count, policy_01)
        self.verify_policy_match(0, policy_02)
        # pg1 -> pg2
        self.verify_policy_match(pkt_count, policy_11)
        self.verify_policy_match(0, policy_12)
        # pg2 -> pg0
        self.verify_policy_match(0, policy_21)
        self.verify_policy_match(pkt_count, policy_22)
        # check that 3 matching policies in SPD have been cached
        self.verify_num_flow_cache_entries(3)


class IPSec4SpdTestCaseCollision(IPSec4SpdCommonMethods):
    """ IPSec/IPv4 outbound: Policy mode test case with flow cache \
        (hash collision)"""
    # Override class setup to restrict vector size to 16 elements.
    # This forces using only the lower 4 bits of the hash as a key,
    # making hash collisions easy to find.
    @classmethod
    def setUpConstants(cls):
        super(IPSec4SpdCommonMethods, cls).setUpConstants()
        cls.vpp_cmdline.extend(["ipsec", "{",
                                "ipv4-out-spd-flow-cache on",
                                "ipv4 outbound spd hash buckets 16",
                                "}"])
        cls.logger.info("VPP modified cmdline is %s" % " "
                        .join(cls.vpp_cmdline))

    def test_ipsec_spd_outbound_collision(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec outbound SPD policy lookup.
        # 2 packets are configured that result in a hash with the
        # same lower 4 bits.
        # After the first packet is received, there should be one
        # active entry in the flow cache.
        # After the second packet with the same lower 4 bit hash
        # is received, this should overwrite the same entry.
        # Therefore there will still be a total of one (1) entry,
        # in the flow cache with two matching policies.
        # crc32_supported() method is used to check cpu for crc32
        # intrinsic support for hashing.
        # If crc32 is not supported, we fall back to clib_xxhash()

        self.create_interfaces(3)
        pkt_count = 5
        # bind SPD to all interfaces
        self.spd_create_and_intf_add(1, self.pg_interfaces)
        # add rules
        policy_0 = self.spd_add_rem_policy(  # outbound, priority 10
            1, self.pg1, self.pg2, socket.IPPROTO_UDP,
            is_out=1, priority=10, policy_type="bypass")
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 10
            1, self.pg2, self.pg0, socket.IPPROTO_UDP,
            is_out=1, priority=10, policy_type="bypass")

        # check flow cache is empty (0 active elements) before sending traffic
        self.verify_num_flow_cache_entries(0)

        # create the packet streams generating collision on last 4 bits
        if self.crc32_supported():
            # packet hashes to:
            # 432c99c2
            packets1 = self.create_stream(self.pg1, self.pg2, pkt_count, 1, 1)
            # 31f8f3f2
            packets2 = self.create_stream(self.pg2, self.pg0, pkt_count, 6, 6)
        else:  # clib_xxhash
            # ec3a258551bc0306
            packets1 = self.create_stream(self.pg1, self.pg2, pkt_count, 2, 2)
            # 61fee526d18d7a6
            packets2 = self.create_stream(self.pg2, self.pg0, pkt_count, 3, 3)

        # add the streams to the source interfaces
        self.pg1.add_stream(packets1)
        self.pg2.add_stream(packets2)
        # enable capture on all interfaces
        for pg in self.pg_interfaces:
            pg.enable_capture()
        # start the packet generator
        self.pg_start()

        # get captures from ifs - the proper pkt_count of packets was saved by
        # create_packet_info() based on dst_if parameter
        if_caps = []
        for pg in [self.pg2, self.pg0]:  # we are expecting captures on pg2/pg0
            if_caps.append(pg.get_capture())
            for packet in if_caps[-1]:
                try:
                    self.logger.debug(ppp(
                        "SPD - Got packet:", packet))
                except Exception:
                    self.logger.error(ppp(
                        "Unexpected or invalid packet:", packet))
                    raise
        self.logger.debug("SPD: Num packets: %s", len(if_caps[0].res))
        self.logger.debug("SPD: Num packets: %s", len(if_caps[1].res))

        # verify captures that matched BYPASS rule
        self.verify_capture(self.pg1, self.pg2, if_caps[0])
        self.verify_capture(self.pg2, self.pg0, if_caps[1])
        # verify all packets that were expected to match rules, matched
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(pkt_count, policy_1)
        # we have matched 2 policies, but due to the hash collision
        # one active entry is expected
        self.verify_num_flow_cache_entries(1)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
