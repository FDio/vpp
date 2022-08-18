import socket
import unittest

from util import ppp
from asfframework import VppTestRunner
from template_ipsec import SpdFlowCacheTemplate


class SpdFlowCacheOutbound(SpdFlowCacheTemplate):
    # Override setUpConstants to enable outbound flow cache in config
    @classmethod
    def setUpConstants(cls):
        super(SpdFlowCacheOutbound, cls).setUpConstants()
        cls.vpp_cmdline.extend(["ipsec", "{", "ipv4-outbound-spd-flow-cache on", "}"])
        cls.logger.info("VPP modified cmdline is %s" % " ".join(cls.vpp_cmdline))


class IPSec4SpdTestCaseAdd(SpdFlowCacheOutbound):
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
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="discard",
        )

        # check flow cache is empty before sending traffic
        self.verify_num_outbound_flow_cache_entries(0)

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
        self.verify_num_outbound_flow_cache_entries(1)


class IPSec4SpdTestCaseRemoveOutbound(SpdFlowCacheOutbound):
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
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="discard",
        )

        # check flow cache is empty before sending traffic
        self.verify_num_outbound_flow_cache_entries(0)

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
        self.verify_num_outbound_flow_cache_entries(1)

        # now remove the bypass rule
        self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            remove=True,
        )
        # verify flow cache counter has been reset by rule removal
        self.verify_num_outbound_flow_cache_entries(0)

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
        # previous stale entry in flow cache should have been overwritten,
        # with one active entry
        self.verify_num_outbound_flow_cache_entries(1)


class IPSec4SpdTestCaseReaddOutbound(SpdFlowCacheOutbound):
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
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="discard",
        )

        # check flow cache is empty before sending traffic
        self.verify_num_outbound_flow_cache_entries(0)

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
        self.verify_num_outbound_flow_cache_entries(1)

        # now remove the bypass rule, leaving only the discard rule
        self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            remove=True,
        )
        # verify flow cache counter has been reset by rule removal
        self.verify_num_outbound_flow_cache_entries(0)

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
        # previous stale entry in flow cache should have been overwritten
        self.verify_num_outbound_flow_cache_entries(1)

        # now readd the bypass rule
        policy_0 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )
        # verify flow cache counter has been reset by rule addition
        self.verify_num_outbound_flow_cache_entries(0)

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
        # previous stale entry in flow cache should have been overwritten
        self.verify_num_outbound_flow_cache_entries(1)


class IPSec4SpdTestCaseMultipleOutbound(SpdFlowCacheOutbound):
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
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )
        policy_02 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="discard",
        )

        policy_11 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg1,
            self.pg2,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )
        policy_12 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg1,
            self.pg2,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="discard",
        )

        policy_21 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg2,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="bypass",
        )
        policy_22 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg2,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="discard",
        )

        # interfaces bound to an SPD, will by default drop inbound
        # traffic with no matching policies. add catch-all inbound
        # bypass rule to SPD:
        self.spd_add_rem_policy(  # inbound, all interfaces
            1,
            None,
            None,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
            all_ips=True,
        )

        # check flow cache is empty (0 active elements) before sending traffic
        self.verify_num_outbound_flow_cache_entries(0)

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
                    self.logger.error(ppp("Unexpected or invalid packet:", packet))
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
        self.verify_num_outbound_flow_cache_entries(3)


class IPSec4SpdTestCaseOverwriteStaleOutbound(SpdFlowCacheOutbound):
    """ IPSec/IPv4 outbound: Policy mode test case with flow cache \
        (overwrite stale entries)"""

    def test_ipsec_spd_outbound_overwrite(self):
        # The operation of the flow cache is setup so that the entire cache
        # is invalidated when adding or removing an SPD policy rule.
        # For performance, old cache entries are not zero'd, but remain
        # in the table as "stale" entries. If a flow matches a stale entry,
        # and the epoch count does NOT match the current count, the entry
        # is overwritten.
        # In this test, 3 active rules are created and matched to enter
        # them into the flow cache.
        # A single entry is removed to invalidate the entire cache.
        # We then readd the rule and test that overwriting of the previous
        # stale entries occurs as expected, and that the flow cache entry
        # counter is updated correctly.
        self.create_interfaces(3)
        pkt_count = 2
        # bind SPD to all interfaces
        self.spd_create_and_intf_add(1, self.pg_interfaces)
        # add output rules on all interfaces
        # pg0 -> pg1
        policy_0 = self.spd_add_rem_policy(  # outbound
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )
        # pg1 -> pg2
        policy_1 = self.spd_add_rem_policy(  # outbound
            1,
            self.pg1,
            self.pg2,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )
        # pg2 -> pg0
        policy_2 = self.spd_add_rem_policy(  # outbound
            1,
            self.pg2,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="discard",
        )

        # interfaces bound to an SPD, will by default drop inbound
        # traffic with no matching policies. add catch-all inbound
        # bypass rule to SPD:
        self.spd_add_rem_policy(  # inbound, all interfaces
            1,
            None,
            None,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
            all_ips=True,
        )

        # check flow cache is empty (0 active elements) before sending traffic
        self.verify_num_outbound_flow_cache_entries(0)

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

        # get captures from ifs
        if_caps = []
        for pg in [self.pg1, self.pg2]:  # we are expecting captures on pg1/pg2
            if_caps.append(pg.get_capture())
            for packet in if_caps[-1]:
                try:
                    self.logger.debug(ppp("SPD Add - Got packet:", packet))
                except Exception:
                    self.logger.error(ppp("Unexpected or invalid packet:", packet))
                    raise

        # verify captures that matched BYPASS rules
        self.verify_capture(self.pg0, self.pg1, if_caps[0])
        self.verify_capture(self.pg1, self.pg2, if_caps[1])
        # verify that traffic to pg0 matched DISCARD rule and was dropped
        self.pg0.assert_nothing_captured()
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(pkt_count, policy_1)
        self.verify_policy_match(pkt_count, policy_2)
        # check flow/policy match was cached for: 3x output policies
        self.verify_num_outbound_flow_cache_entries(3)

        # adding an inbound policy should not invalidate output flow cache
        self.spd_add_rem_policy(  # inbound
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
        )
        # check flow cache counter has not been reset
        self.verify_num_outbound_flow_cache_entries(3)

        # remove a bypass policy - flow cache counter will be reset, and
        # there will be 3x stale entries in flow cache
        self.spd_add_rem_policy(  # outbound
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            remove=True,
        )
        # readd policy
        policy_0 = self.spd_add_rem_policy(  # outbound
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )
        # check counter was reset with flow cache invalidation
        self.verify_num_outbound_flow_cache_entries(0)

        # resend the same packets
        self.pg0.add_stream(packets0)
        self.pg1.add_stream(packets1)
        self.pg2.add_stream(packets2)
        for pg in self.pg_interfaces:
            pg.enable_capture()  # flush previous captures
        self.pg_start()

        # get captures from ifs
        if_caps = []
        for pg in [self.pg1, self.pg2]:  # we are expecting captures on pg1/pg2
            if_caps.append(pg.get_capture())
            for packet in if_caps[-1]:
                try:
                    self.logger.debug(ppp("SPD Add - Got packet:", packet))
                except Exception:
                    self.logger.error(ppp("Unexpected or invalid packet:", packet))
                    raise

        # verify captures that matched BYPASS rules
        self.verify_capture(self.pg0, self.pg1, if_caps[0])
        self.verify_capture(self.pg1, self.pg2, if_caps[1])
        # verify that traffic to pg0 matched DISCARD rule and was dropped
        self.pg0.assert_nothing_captured()
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(pkt_count * 2, policy_1)
        self.verify_policy_match(pkt_count * 2, policy_2)
        # we are overwriting 3x stale entries - check flow cache counter
        # is correct
        self.verify_num_outbound_flow_cache_entries(3)


class IPSec4SpdTestCaseCollisionOutbound(SpdFlowCacheOutbound):
    """ IPSec/IPv4 outbound: Policy mode test case with flow cache \
        (hash collision)"""

    # Override class setup to restrict vector size to 16 elements.
    # This forces using only the lower 4 bits of the hash as a key,
    # making hash collisions easy to find.
    @classmethod
    def setUpConstants(cls):
        super(SpdFlowCacheOutbound, cls).setUpConstants()
        cls.vpp_cmdline.extend(
            [
                "ipsec",
                "{",
                "ipv4-outbound-spd-flow-cache on",
                "ipv4-outbound-spd-hash-buckets 16",
                "}",
            ]
        )
        cls.logger.info("VPP modified cmdline is %s" % " ".join(cls.vpp_cmdline))

    def test_ipsec_spd_outbound_collision(self):
        # The flow cache operation is setup to overwrite an entry
        # if a hash collision occurs.
        # In this test, 2 packets are configured that result in a
        # hash with the same lower 4 bits.
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
            1,
            self.pg1,
            self.pg2,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg2,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )

        # interfaces bound to an SPD, will by default drop inbound
        # traffic with no matching policies. add catch-all inbound
        # bypass rule to SPD:
        self.spd_add_rem_policy(  # inbound, all interfaces
            1,
            None,
            None,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
            all_ips=True,
        )

        # check flow cache is empty (0 active elements) before sending traffic
        self.verify_num_outbound_flow_cache_entries(0)

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
                    self.logger.debug(ppp("SPD - Got packet:", packet))
                except Exception:
                    self.logger.error(ppp("Unexpected or invalid packet:", packet))
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
        self.verify_num_outbound_flow_cache_entries(1)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
