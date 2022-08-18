import socket
import unittest
import ipaddress

from util import ppp
from asfframework import VppTestRunner
from template_ipsec import IPSecIPv4Fwd
from template_ipsec import IPSecIPv6Fwd


class SpdFastPathOutbound(IPSecIPv4Fwd):
    # Override setUpConstants to enable outbound fast path in config
    @classmethod
    def setUpConstants(cls):
        super(SpdFastPathOutbound, cls).setUpConstants()
        cls.vpp_cmdline.extend(["ipsec", "{", "ipv4-outbound-spd-fast-path on", "}"])
        cls.logger.info("VPP modified cmdline is %s" % " ".join(cls.vpp_cmdline))


class SpdFastPathIPv6Outbound(IPSecIPv6Fwd):
    # Override setUpConstants to enable outbound fast path in config
    @classmethod
    def setUpConstants(cls):
        super(SpdFastPathIPv6Outbound, cls).setUpConstants()
        cls.vpp_cmdline.extend(["ipsec", "{", "ipv6-outbound-spd-fast-path on", "}"])
        cls.logger.info("VPP modified cmdline is %s" % " ".join(cls.vpp_cmdline))


class IPSec4SpdTestCaseAdd(SpdFastPathOutbound):
    """ IPSec/IPv4 outbound: Policy mode test case with fast path \
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
        s_port_s = 1111
        s_port_e = 1111
        d_port_s = 2222
        d_port_e = 2222
        self.spd_create_and_intf_add(1, [self.pg1])
        policy_0 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            local_port_start=s_port_s,
            local_port_stop=s_port_e,
            remote_port_start=d_port_s,
            remote_port_stop=d_port_e,
        )
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="discard",
            local_port_start=s_port_s,
            local_port_stop=s_port_e,
            remote_port_start=d_port_s,
            remote_port_stop=d_port_e,
        )

        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, pkt_count, s_port_s, d_port_s)
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


class IPSec4SpdTestCaseAddPortRange(SpdFastPathOutbound):
    """ IPSec/IPv4 outbound: Policy mode test case with fast path \
        (add all ips port range rule)"""

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
        s_port_s = 1000
        s_port_e = 2023
        d_port_s = 5000
        d_port_e = 6023
        self.spd_create_and_intf_add(1, [self.pg1])
        policy_0 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            all_ips=True,
            local_port_start=s_port_s,
            local_port_stop=s_port_e,
            remote_port_start=d_port_s,
            remote_port_stop=d_port_e,
        )
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="discard",
            all_ips=True,
            local_port_start=s_port_s,
            local_port_stop=s_port_e,
            remote_port_start=d_port_s,
            remote_port_stop=d_port_e,
        )

        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, pkt_count, 1333, 5444)
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


class IPSec4SpdTestCaseAddIPRange(SpdFastPathOutbound):
    """ IPSec/IPv4 outbound: Policy mode test case with fast path \
        (add  ips  range with any port rule)"""

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
        s_ip_s = ipaddress.ip_address(self.pg0.remote_ip4)
        s_ip_e = ipaddress.ip_address(int(s_ip_s) + 5)
        d_ip_s = ipaddress.ip_address(self.pg1.remote_ip4)
        d_ip_e = ipaddress.ip_address(int(d_ip_s) + 0)
        self.spd_create_and_intf_add(1, [self.pg1])
        policy_0 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            ip_range=True,
            local_ip_start=s_ip_s,
            local_ip_stop=s_ip_e,
            remote_ip_start=d_ip_s,
            remote_ip_stop=d_ip_e,
        )
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="discard",
            ip_range=True,
            local_ip_start=s_ip_s,
            local_ip_stop=s_ip_e,
            remote_ip_start=d_ip_s,
            remote_ip_stop=d_ip_e,
        )

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


class IPSec4SpdTestCaseAddIPAndPortRange(SpdFastPathOutbound):
    """ IPSec/IPv4 outbound: Policy mode test case with fast path \
        (add all ips  range rule)"""

    def test_ipsec_spd_outbound_add(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec outbound SPD policy lookup.
        # 2 SPD rules (1 HIGH and 1 LOW) are added.
        # High priority rule action is set to BYPASS.
        # Low priority rule action is set to DISCARD.
        # Traffic sent on pg0 interface should match high priority
        # rule and should be sent out on pg1 interface.
        # in this test we define ranges of ports and ip addresses.
        self.create_interfaces(2)
        pkt_count = 5
        s_port_s = 1000
        s_port_e = 1000 + 1023
        d_port_s = 5000
        d_port_e = 5000 + 1023

        s_ip_s = ipaddress.ip_address(
            int(ipaddress.ip_address(self.pg0.remote_ip4)) - 24
        )
        s_ip_e = ipaddress.ip_address(int(s_ip_s) + 255)
        d_ip_s = ipaddress.ip_address(self.pg1.remote_ip4)
        d_ip_e = ipaddress.ip_address(int(d_ip_s) + 255)
        self.spd_create_and_intf_add(1, [self.pg1])
        policy_0 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            ip_range=True,
            local_ip_start=s_ip_s,
            local_ip_stop=s_ip_e,
            remote_ip_start=d_ip_s,
            remote_ip_stop=d_ip_e,
            local_port_start=s_port_s,
            local_port_stop=s_port_e,
            remote_port_start=d_port_s,
            remote_port_stop=d_port_e,
        )
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="discard",
            ip_range=True,
            local_ip_start=s_ip_s,
            local_ip_stop=s_ip_e,
            remote_ip_start=d_ip_s,
            remote_ip_stop=d_ip_e,
            local_port_start=s_port_s,
            local_port_stop=s_port_e,
            remote_port_start=d_port_s,
            remote_port_stop=d_port_e,
        )

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


class IPSec4SpdTestCaseAddAll(SpdFastPathOutbound):
    """ IPSec/IPv4 outbound: Policy mode test case with fast path \
        (add all ips ports rule)"""

    def test_ipsec_spd_outbound_add(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec outbound SPD policy lookup.
        # 2 SPD rules (1 HIGH and 1 LOW) are added.
        # Low priority rule action is set to BYPASS all ips.
        # High priority rule action is set to DISCARD all ips.
        # Traffic sent on pg0 interface when LOW priority rule is added,
        # expect the packet is being sent out to pg1. Then HIGH priority
        # rule is added and send the same traffic to pg0, this time expect
        # the traffic is dropped.
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
            all_ips=True,
        )

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

        policy_1 = self.spd_add_rem_policy(  # outbound, priority 20
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=20,
            policy_type="discard",
            all_ips=True,
        )

        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, pkt_count)
        # add the stream to the source interface + enable capture
        self.pg0.add_stream(packets)
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        # start the packet generator
        self.pg_start()
        # assert nothing captured on pg0 and pg1
        self.pg0.assert_nothing_captured()
        self.pg1.assert_nothing_captured()


class IPSec4SpdTestCaseRemove(SpdFastPathOutbound):
    """ IPSec/IPv4 outbound: Policy mode test case with fast path \
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


class IPSec4SpdTestCaseReadd(SpdFastPathOutbound):
    """ IPSec/IPv4 outbound: Policy mode test case with fast path \
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
        # remove the bypass rule, leaving only the discard rule
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


class IPSec4SpdTestCaseMultiple(SpdFastPathOutbound):
    """ IPSec/IPv4 outbound: Policy mode test case with fast path \
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


class IPSec6SpdTestCaseAdd(SpdFastPathIPv6Outbound):
    """ IPSec/IPv6 outbound: Policy mode test case with fast path \
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
        s_port_s = 1111
        s_port_e = 1111
        d_port_s = 2222
        d_port_e = 2222
        self.spd_create_and_intf_add(1, [self.pg1])
        policy_0 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            local_port_start=s_port_s,
            local_port_stop=s_port_e,
            remote_port_start=d_port_s,
            remote_port_stop=d_port_e,
        )
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="discard",
            local_port_start=s_port_s,
            local_port_stop=s_port_e,
            remote_port_start=d_port_s,
            remote_port_stop=d_port_e,
        )

        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, pkt_count, s_port_s, d_port_s)
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


class IPSec6SpdTestCaseAddAll(SpdFastPathIPv6Outbound):
    """ IPSec/IPv6 outbound: Policy mode test case with fast path \
        (add all ips ports rule)"""

    def test_ipsec_spd_outbound_add(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec outbound SPD policy lookup.
        # 2 SPD rules (1 HIGH and 1 LOW) are added.
        # Low priority rule action is set to BYPASS all ips.
        # High priority rule action is set to DISCARD all ips.
        # Traffic sent on pg0 interface when LOW priority rule is added,
        # expect the packet is being sent out to pg1. Then HIGH priority
        # rule is added and send the same traffic to pg0, this time expect
        # the traffic is dropped.
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
            all_ips=True,
        )

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

        policy_1 = self.spd_add_rem_policy(  # outbound, priority 20
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=20,
            policy_type="discard",
            all_ips=True,
        )

        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, pkt_count)
        # add the stream to the source interface + enable capture
        self.pg0.add_stream(packets)
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        # start the packet generator
        self.pg_start()
        # assert nothing captured on pg0 and pg1
        self.pg0.assert_nothing_captured()
        self.pg1.assert_nothing_captured()


class IPSec6SpdTestCaseAddPortRange(SpdFastPathIPv6Outbound):
    """ IPSec/IPv6 outbound: Policy mode test case with fast path \
        (add all ips port range rule)"""

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
        s_port_s = 1000
        s_port_e = 2023
        d_port_s = 5000
        d_port_e = 6023
        self.spd_create_and_intf_add(1, [self.pg1])
        policy_0 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            all_ips=True,
            local_port_start=s_port_s,
            local_port_stop=s_port_e,
            remote_port_start=d_port_s,
            remote_port_stop=d_port_e,
        )
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="discard",
            all_ips=True,
            local_port_start=s_port_s,
            local_port_stop=s_port_e,
            remote_port_start=d_port_s,
            remote_port_stop=d_port_e,
        )

        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, pkt_count, 1333, 5444)
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


class IPSec6SpdTestCaseAddIPRange(SpdFastPathIPv6Outbound):
    """ IPSec/IPv6 outbound: Policy mode test case with fast path \
        (add ips range with any port rule)"""

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
        s_ip_s = ipaddress.ip_address(self.pg0.remote_ip6)
        s_ip_e = ipaddress.ip_address(int(s_ip_s) + 5)
        d_ip_s = ipaddress.ip_address(self.pg1.remote_ip6)
        d_ip_e = ipaddress.ip_address(int(d_ip_s) + 0)
        self.spd_create_and_intf_add(1, [self.pg1])
        policy_0 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            ip_range=True,
            local_ip_start=s_ip_s,
            local_ip_stop=s_ip_e,
            remote_ip_start=d_ip_s,
            remote_ip_stop=d_ip_e,
        )
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="discard",
            ip_range=True,
            local_ip_start=s_ip_s,
            local_ip_stop=s_ip_e,
            remote_ip_start=d_ip_s,
            remote_ip_stop=d_ip_e,
        )

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


class IPSec6SpdTestCaseAddIPAndPortRange(SpdFastPathIPv6Outbound):
    """ IPSec/IPvr6 outbound: Policy mode test case with fast path \
             (add all ips  range rule)"""

    def test_ipsec_spd_outbound_add(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec outbound SPD policy lookup.
        # 2 SPD rules (1 HIGH and 1 LOW) are added.
        # High priority rule action is set to BYPASS.
        # Low priority rule action is set to DISCARD.
        # Traffic sent on pg0 interface should match high priority
        # rule and should be sent out on pg1 interface.
        # in this test we define ranges of ports and ip addresses.
        self.create_interfaces(2)
        pkt_count = 5
        s_port_s = 1000
        s_port_e = 1000 + 1023
        d_port_s = 5000
        d_port_e = 5000 + 1023

        s_ip_s = ipaddress.ip_address(
            int(ipaddress.ip_address(self.pg0.remote_ip6)) - 24
        )
        s_ip_e = ipaddress.ip_address(int(s_ip_s) + 255)
        d_ip_s = ipaddress.ip_address(self.pg1.remote_ip6)
        d_ip_e = ipaddress.ip_address(int(d_ip_s) + 255)
        self.spd_create_and_intf_add(1, [self.pg1])
        policy_0 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            ip_range=True,
            local_ip_start=s_ip_s,
            local_ip_stop=s_ip_e,
            remote_ip_start=d_ip_s,
            remote_ip_stop=d_ip_e,
            local_port_start=s_port_s,
            local_port_stop=s_port_e,
            remote_port_start=d_port_s,
            remote_port_stop=d_port_e,
        )
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="discard",
            ip_range=True,
            local_ip_start=s_ip_s,
            local_ip_stop=s_ip_e,
            remote_ip_start=d_ip_s,
            remote_ip_stop=d_ip_e,
            local_port_start=s_port_s,
            local_port_stop=s_port_e,
            remote_port_start=d_port_s,
            remote_port_stop=d_port_e,
        )

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


class IPSec6SpdTestCaseReadd(SpdFastPathIPv6Outbound):
    """ IPSec/IPv6 outbound: Policy mode test case with fast path \
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
        # remove the bypass rule, leaving only the discard rule
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


class IPSec6SpdTestCaseMultiple(SpdFastPathIPv6Outbound):
    """ IPSec/IPv6 outbound: Policy mode test case with fast path \
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


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
