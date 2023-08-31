import socket
import unittest

from util import ppp
from asfframework import VppTestRunner
from template_ipsec import SpdFlowCacheTemplate


class SpdFlowCacheInbound(SpdFlowCacheTemplate):
    # Override setUpConstants to enable inbound flow cache in config
    @classmethod
    def setUpConstants(cls):
        super(SpdFlowCacheInbound, cls).setUpConstants()
        cls.vpp_cmdline.extend(["ipsec", "{", "ipv4-inbound-spd-flow-cache on", "}"])
        cls.logger.info("VPP modified cmdline is %s" % " ".join(cls.vpp_cmdline))


class IPSec4SpdTestCaseBypass(SpdFlowCacheInbound):
    """ IPSec/IPv4 inbound: Policy mode test case with flow cache \
        (add bypass)"""

    def test_ipsec_spd_inbound_bypass(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec inbound SPD policy lookup.
        #
        # 2 inbound SPD rules (1 HIGH and 1 LOW) are added.
        # - High priority rule action is set to DISCARD.
        # - Low priority rule action is set to BYPASS.
        #
        # Since BYPASS rules take precedence over DISCARD
        # (the order being PROTECT, BYPASS, DISCARD) we expect the
        # BYPASS rule to match and traffic to be correctly forwarded.
        self.create_interfaces(2)
        pkt_count = 5

        self.spd_create_and_intf_add(1, [self.pg1, self.pg0])

        # create input rules
        # bypass rule should take precedence over discard rule,
        # even though it's lower priority
        policy_0 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
        )
        policy_1 = self.spd_add_rem_policy(  # inbound, priority 15
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=15,
            policy_type="discard",
        )

        # create output rule so we can capture forwarded packets
        policy_2 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )

        # check flow cache is empty before sending traffic
        self.verify_num_inbound_flow_cache_entries(0)
        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, pkt_count)
        # add the stream to the source interface
        self.pg0.add_stream(packets)
        self.pg1.enable_capture()
        self.pg_start()

        # check capture on pg1
        capture = self.pg1.get_capture()
        for packet in capture:
            try:
                self.logger.debug(ppp("SPD Add - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        self.logger.debug("SPD: Num packets: %s", len(capture.res))

        # verify captured packets
        self.verify_capture(self.pg0, self.pg1, capture)
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(0, policy_1)
        self.verify_policy_match(pkt_count, policy_2)
        # check input policy has been cached
        self.verify_num_inbound_flow_cache_entries(1)


class IPSec4SpdTestCaseDiscard(SpdFlowCacheInbound):
    """ IPSec/IPv4 inbound: Policy mode test case with flow cache \
        (add discard)"""

    def test_ipsec_spd_inbound_discard(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec inbound SPD policy lookup.
        # 1 DISCARD rule is added, so all traffic should be dropped.
        self.create_interfaces(2)
        pkt_count = 5

        self.spd_create_and_intf_add(1, [self.pg1, self.pg0])

        # create input rule
        policy_0 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="discard",
        )

        # create output rule so we can capture forwarded packets
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )

        # check flow cache is empty before sending traffic
        self.verify_num_inbound_flow_cache_entries(0)
        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, pkt_count)
        # add the stream to the source interface
        self.pg0.add_stream(packets)
        self.pg1.enable_capture()
        self.pg_start()
        # inbound discard rule should have dropped traffic
        self.pg1.assert_nothing_captured()
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(0, policy_1)
        # only inbound discard rule should have been cached
        self.verify_num_inbound_flow_cache_entries(1)


class IPSec4SpdTestCaseRemoveInbound(SpdFlowCacheInbound):
    """ IPSec/IPv4 inbound: Policy mode test case with flow cache \
        (remove bypass)"""

    def test_ipsec_spd_inbound_remove(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec inbound SPD policy lookup.
        #
        # 2 inbound SPD rules (1 HIGH and 1 LOW) are added.
        # - High priority rule action is set to DISCARD.
        # - Low priority rule action is set to BYPASS.
        #
        # Since BYPASS rules take precedence over DISCARD
        # (the order being PROTECT, BYPASS, DISCARD) we expect the
        # BYPASS rule to match and traffic to be correctly forwarded.
        #
        # The BYPASS rules is then removed, and we check that all traffic
        # is now correctly dropped.
        self.create_interfaces(2)
        pkt_count = 5

        self.spd_create_and_intf_add(1, [self.pg1, self.pg0])

        # create input rules
        # bypass rule should take precedence over discard rule,
        # even though it's lower priority
        policy_0 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
        )
        policy_1 = self.spd_add_rem_policy(  # inbound, priority 15
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=15,
            policy_type="discard",
        )

        # create output rule so we can capture forwarded packets
        policy_2 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )

        # check flow cache is empty before sending traffic
        self.verify_num_inbound_flow_cache_entries(0)
        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, pkt_count)
        # add the stream to the source interface
        self.pg0.add_stream(packets)
        self.pg1.enable_capture()
        self.pg_start()

        # check capture on pg1
        capture = self.pg1.get_capture()
        for packet in capture:
            try:
                self.logger.debug(ppp("SPD Add - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        self.logger.debug("SPD: Num packets: %s", len(capture.res))

        # verify captured packets
        self.verify_capture(self.pg0, self.pg1, capture)
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(0, policy_1)
        self.verify_policy_match(pkt_count, policy_2)
        # check input policy has been cached
        self.verify_num_inbound_flow_cache_entries(1)

        # remove the input bypass rule
        self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
            remove=True,
        )
        # verify flow cache counter has been reset by rule removal
        self.verify_num_inbound_flow_cache_entries(0)

        # resend the same packets
        self.pg0.add_stream(packets)
        self.pg1.enable_capture()  # flush the old capture
        self.pg_start()

        # inbound discard rule should have dropped traffic
        self.pg1.assert_nothing_captured()
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(pkt_count, policy_1)
        self.verify_policy_match(pkt_count, policy_2)
        # by removing the bypass rule, we should have reset the flow cache
        # we only expect the discard rule to now be in the flow cache
        self.verify_num_inbound_flow_cache_entries(1)


class IPSec4SpdTestCaseReaddInbound(SpdFlowCacheInbound):
    """ IPSec/IPv4 inbound: Policy mode test case with flow cache \
        (add, remove, re-add bypass)"""

    def test_ipsec_spd_inbound_readd(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec inbound SPD policy lookup.
        #
        # 2 inbound SPD rules (1 HIGH and 1 LOW) are added.
        # - High priority rule action is set to DISCARD.
        # - Low priority rule action is set to BYPASS.
        #
        # Since BYPASS rules take precedence over DISCARD
        # (the order being PROTECT, BYPASS, DISCARD) we expect the
        # BYPASS rule to match and traffic to be correctly forwarded.
        #
        # The BYPASS rules is then removed, and we check that all traffic
        # is now correctly dropped.
        #
        # The BYPASS rule is then readded, checking traffic is not forwarded
        # correctly again
        self.create_interfaces(2)
        pkt_count = 5

        self.spd_create_and_intf_add(1, [self.pg1, self.pg0])

        # create input rules
        # bypass rule should take precedence over discard rule,
        # even though it's lower priority
        policy_0 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
        )
        policy_1 = self.spd_add_rem_policy(  # inbound, priority 15
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=15,
            policy_type="discard",
        )

        # create output rule so we can capture forwarded packets
        policy_2 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )

        # check flow cache is empty before sending traffic
        self.verify_num_inbound_flow_cache_entries(0)
        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, pkt_count)
        # add the stream to the source interface
        self.pg0.add_stream(packets)
        self.pg1.enable_capture()
        self.pg_start()

        # check capture on pg1
        capture = self.pg1.get_capture()
        for packet in capture:
            try:
                self.logger.debug(ppp("SPD Add - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        self.logger.debug("SPD: Num packets: %s", len(capture.res))

        # verify captured packets
        self.verify_capture(self.pg0, self.pg1, capture)
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(0, policy_1)
        self.verify_policy_match(pkt_count, policy_2)
        # check input policy has been cached
        self.verify_num_inbound_flow_cache_entries(1)

        # remove the input bypass rule
        self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
            remove=True,
        )
        # verify flow cache counter has been reset by rule removal
        self.verify_num_inbound_flow_cache_entries(0)

        # resend the same packets
        self.pg0.add_stream(packets)
        self.pg1.enable_capture()  # flush the old capture
        self.pg_start()

        # inbound discard rule should have dropped traffic
        self.pg1.assert_nothing_captured()
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(pkt_count, policy_1)
        self.verify_policy_match(pkt_count, policy_2)
        # by removing the bypass rule, flow cache was reset
        # we only expect the discard rule to now be in the flow cache
        self.verify_num_inbound_flow_cache_entries(1)

        # readd the input bypass rule
        policy_0 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
        )
        # verify flow cache counter has been reset by rule addition
        self.verify_num_inbound_flow_cache_entries(0)

        # resend the same packets
        self.pg0.add_stream(packets)
        self.pg1.enable_capture()  # flush the old capture
        self.pg_start()

        # check capture on pg1
        capture = self.pg1.get_capture()
        for packet in capture:
            try:
                self.logger.debug(ppp("SPD Add - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        # verify captured packets
        self.verify_capture(self.pg0, self.pg1, capture)
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(pkt_count, policy_1)
        self.verify_policy_match(pkt_count * 2, policy_2)
        # by readding the bypass rule, we reset the flow cache
        # we only expect the bypass rule to now be in the flow cache
        self.verify_num_inbound_flow_cache_entries(1)


class IPSec4SpdTestCaseMultipleInbound(SpdFlowCacheInbound):
    """ IPSec/IPv4 inbound: Policy mode test case with flow cache \
        (multiple interfaces, multiple rules)"""

    def test_ipsec_spd_inbound_multiple(self):
        # In this test case, packets in IPv4 FWD path are configured to go
        # through IPSec outbound SPD policy lookup.
        #
        # Multiples rules on multiple interfaces are tested at the same time.
        # 3x interfaces are configured, binding the same SPD to each.
        # Each interface has 1 SPD rule- 2x BYPASS and 1x DISCARD
        #
        # Traffic should be forwarded with destinations pg1 & pg2
        # and dropped to pg0.
        self.create_interfaces(3)
        pkt_count = 5
        # bind SPD to all interfaces
        self.spd_create_and_intf_add(1, self.pg_interfaces)
        # add input rules on all interfaces
        # pg0 -> pg1
        policy_0 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
        )
        # pg1 -> pg2
        policy_1 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg2,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
        )
        # pg2 -> pg0
        policy_2 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg0,
            self.pg2,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="discard",
        )

        # create output rules covering the the full ip range
        # 0.0.0.0 -> 255.255.255.255, so we can capture forwarded packets
        policy_3 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            all_ips=True,
        )

        # check flow cache is empty (0 active elements) before sending traffic
        self.verify_num_inbound_flow_cache_entries(0)

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
        # check flow/policy match was cached for: 3x input policies
        self.verify_num_inbound_flow_cache_entries(3)


class IPSec4SpdTestCaseOverwriteStaleInbound(SpdFlowCacheInbound):
    """ IPSec/IPv4 inbound: Policy mode test case with flow cache \
        (overwrite stale entries)"""

    def test_ipsec_spd_inbound_overwrite(self):
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
        pkt_count = 5
        # bind SPD to all interfaces
        self.spd_create_and_intf_add(1, self.pg_interfaces)
        # add input rules on all interfaces
        # pg0 -> pg1
        policy_0 = self.spd_add_rem_policy(  # inbound
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
        )
        # pg1 -> pg2
        policy_1 = self.spd_add_rem_policy(  # inbound
            1,
            self.pg2,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
        )
        # pg2 -> pg0
        policy_2 = self.spd_add_rem_policy(  # inbound
            1,
            self.pg0,
            self.pg2,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="discard",
        )

        # create output rules covering the the full ip range
        # 0.0.0.0 -> 255.255.255.255, so we can capture forwarded packets
        policy_3 = self.spd_add_rem_policy(  # outbound
            1,
            self.pg0,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            all_ips=True,
        )

        # check flow cache is empty (0 active elements) before sending traffic
        self.verify_num_inbound_flow_cache_entries(0)

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
        # check flow/policy match was cached for: 3x input policies
        self.verify_num_inbound_flow_cache_entries(3)

        # adding an outbound policy should not invalidate output flow cache
        self.spd_add_rem_policy(  # outbound
            1,
            self.pg0,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=1,
            policy_type="bypass",
            all_ips=True,
        )
        # check inbound flow cache counter has not been reset
        self.verify_num_inbound_flow_cache_entries(3)

        # remove + readd bypass policy - flow cache counter will be reset,
        # and there will be 3x stale entries in flow cache
        self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
            remove=True,
        )
        # readd policy
        policy_0 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
        )
        # check counter was reset
        self.verify_num_inbound_flow_cache_entries(0)

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
        self.verify_num_inbound_flow_cache_entries(3)


class IPSec4SpdTestCaseCollisionInbound(SpdFlowCacheInbound):
    """ IPSec/IPv4 inbound: Policy mode test case with flow cache \
        (hash collision)"""

    # Override class setup to restrict hash table size to 16 buckets.
    # This forces using only the lower 4 bits of the hash as a key,
    # making hash collisions easy to find.
    @classmethod
    def setUpConstants(cls):
        super(SpdFlowCacheInbound, cls).setUpConstants()
        cls.vpp_cmdline.extend(
            [
                "ipsec",
                "{",
                "ipv4-inbound-spd-flow-cache on",
                "ipv4-inbound-spd-hash-buckets 16",
                "}",
            ]
        )
        cls.logger.info("VPP modified cmdline is %s" % " ".join(cls.vpp_cmdline))

    def test_ipsec_spd_inbound_collision(self):
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
        self.create_interfaces(4)
        pkt_count = 5
        # bind SPD to all interfaces
        self.spd_create_and_intf_add(1, self.pg_interfaces)

        # create output rules covering the the full ip range
        # 0.0.0.0 -> 255.255.255.255, so we can capture forwarded packets
        policy_0 = self.spd_add_rem_policy(  # outbound
            1,
            self.pg0,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            all_ips=True,
        )

        capture_intfs = []
        if self.crc32_supported():  # create crc32 collision on last 4 bits
            hashed_with_crc32 = True
            # add matching rules
            policy_1 = self.spd_add_rem_policy(  # inbound, priority 10
                1,
                self.pg1,
                self.pg2,
                socket.IPPROTO_UDP,
                is_out=0,
                priority=10,
                policy_type="bypass",
            )
            policy_2 = self.spd_add_rem_policy(  # inbound, priority 10
                1,
                self.pg3,
                self.pg0,
                socket.IPPROTO_UDP,
                is_out=0,
                priority=10,
                policy_type="bypass",
            )

            # we expect to get captures on pg1 + pg3
            capture_intfs.append(self.pg1)
            capture_intfs.append(self.pg3)

            # check flow cache is empty before sending traffic
            self.verify_num_inbound_flow_cache_entries(0)

            # create the packet streams
            # packet hashes to:
            # ad727628
            packets1 = self.create_stream(self.pg2, self.pg1, pkt_count, 1, 1)
            # b5512898
            packets2 = self.create_stream(self.pg0, self.pg3, pkt_count, 1, 1)
            # add the streams to the source interfaces
            self.pg2.add_stream(packets1)
            self.pg0.add_stream(packets2)
        else:  # create xxhash collision on last 4 bits
            hashed_with_crc32 = False
            # add matching rules
            policy_1 = self.spd_add_rem_policy(  # inbound, priority 10
                1,
                self.pg1,
                self.pg2,
                socket.IPPROTO_UDP,
                is_out=0,
                priority=10,
                policy_type="bypass",
            )
            policy_2 = self.spd_add_rem_policy(  # inbound, priority 10
                1,
                self.pg2,
                self.pg3,
                socket.IPPROTO_UDP,
                is_out=0,
                priority=10,
                policy_type="bypass",
            )

            capture_intfs.append(self.pg1)
            capture_intfs.append(self.pg2)

            # check flow cache is empty before sending traffic
            self.verify_num_inbound_flow_cache_entries(0)

            # create the packet streams
            # 2f8f90f557eef12c
            packets1 = self.create_stream(self.pg2, self.pg1, pkt_count, 1, 1)
            # 6b7f9987719ffc1c
            packets2 = self.create_stream(self.pg3, self.pg2, pkt_count, 1, 1)
            # add the streams to the source interfaces
            self.pg2.add_stream(packets1)
            self.pg3.add_stream(packets2)

        # enable capture on interfaces we expect capture on & send pkts
        for pg in capture_intfs:
            pg.enable_capture()
        self.pg_start()

        # get captures
        if_caps = []
        for pg in capture_intfs:
            if_caps.append(pg.get_capture())
            for packet in if_caps[-1]:
                try:
                    self.logger.debug(ppp("SPD Add - Got packet:", packet))
                except Exception:
                    self.logger.error(ppp("Unexpected or invalid packet:", packet))
                    raise

        # verify captures that matched BYPASS rule
        if hashed_with_crc32:
            self.verify_capture(self.pg2, self.pg1, if_caps[0])
            self.verify_capture(self.pg0, self.pg3, if_caps[1])
        else:  # hashed with xxhash
            self.verify_capture(self.pg2, self.pg1, if_caps[0])
            self.verify_capture(self.pg3, self.pg2, if_caps[1])

        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_1)
        self.verify_policy_match(pkt_count, policy_2)
        self.verify_policy_match(pkt_count * 2, policy_0)  # output policy
        # we have matched 2 policies, but due to the hash collision
        # one active entry is expected
        self.verify_num_inbound_flow_cache_entries(1)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
