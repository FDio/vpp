import socket
import unittest
import ipaddress

from util import ppp
from framework import VppTestRunner
from template_ipsec import IPSecIPv4Fwd
from template_ipsec import IPSecIPv6Fwd
from test_ipsec_esp import TemplateIpsecEsp


def debug_signal_handler(signal, frame):
    import pdb

    pdb.set_trace()


import signal

signal.signal(signal.SIGINT, debug_signal_handler)


class SpdFastPathInbound(IPSecIPv4Fwd):
    # In test cases derived from this class, packets in IPv4 FWD path
    # are configured to go through IPSec inbound SPD policy lookup.
    # Note that order in which the rules are applied is
    # PROTECT, BYPASS, DISCARD. Therefore BYPASS rules take
    # precedence over DISCARD.
    #
    # Override setUpConstants to enable inbound fast path in config
    @classmethod
    def setUpConstants(cls):
        super(SpdFastPathInbound, cls).setUpConstants()
        cls.vpp_cmdline.extend(["ipsec", "{", "ipv4-inbound-spd-fast-path on", "}"])
        cls.logger.info("VPP modified cmdline is %s" % " ".join(cls.vpp_cmdline))


class SpdFastPathInboundProtect(TemplateIpsecEsp):
    @classmethod
    def setUpConstants(cls):
        super(SpdFastPathInboundProtect, cls).setUpConstants()
        cls.vpp_cmdline.extend(["ipsec", "{", "ipv4-inbound-spd-fast-path on", "}"])
        cls.logger.info("VPP modified cmdline is %s" % " ".join(cls.vpp_cmdline))

    @classmethod
    def setUpClass(cls):
        super(SpdFastPathInboundProtect, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(SpdFastPathInboundProtect, cls).tearDownClass()

    def setUp(self):
        super(SpdFastPathInboundProtect, self).setUp()

    def tearDown(self):
        self.unconfig_network()
        super(SpdFastPathInboundProtect, self).tearDown()


class SpdFastPathIPv6Inbound(IPSecIPv6Fwd):
    # In test cases derived from this class, packets in IPvr6 FWD path
    # are configured to go through IPSec inbound SPD policy lookup.
    # Note that order in which the rules are applied is
    # PROTECT, BYPASS, DISCARD. Therefore BYPASS rules take
    # precedence over DISCARDi.

    # Override setUpConstants to enable inbound fast path in config
    @classmethod
    def setUpConstants(cls):
        super(SpdFastPathIPv6Inbound, cls).setUpConstants()
        cls.vpp_cmdline.extend(["ipsec", "{", "ipv6-inbound-spd-fast-path on", "}"])
        cls.logger.info("VPP modified cmdline is %s" % " ".join(cls.vpp_cmdline))


class SpdFastPathIPv6InboundProtect(TemplateIpsecEsp):
    @classmethod
    def setUpConstants(cls):
        super(SpdFastPathIPv6InboundProtect, cls).setUpConstants()
        cls.vpp_cmdline.extend(["ipsec", "{", "ipv6-inbound-spd-fast-path on", "}"])
        cls.logger.info("VPP modified cmdline is %s" % " ".join(cls.vpp_cmdline))

    @classmethod
    def setUpClass(cls):
        super(SpdFastPathIPv6InboundProtect, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(SpdFastPathIPv6InboundProtect, cls).tearDownClass()

    def setUp(self):
        super(SpdFastPathIPv6InboundProtect, self).setUp()

    def tearDown(self):
        self.unconfig_network()
        super(SpdFastPathIPv6InboundProtect, self).tearDown()


class IPSec4SpdTestCaseBypass(SpdFastPathInbound):
    """ IPSec/IPv4 inbound: Policy mode test case with fast path \
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
        # even though it's lower priority, because for input policies
        # matching PROTECT policies precedes matching BYPASS policies
        # which preceeds matching for DISCARD policies.
        # Any hit stops the process.
        policy_0 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
            ip_range=True,
            local_ip_start=self.pg1.remote_ip4,
            local_ip_stop=self.pg1.remote_ip4,
            remote_ip_start=self.pg0.remote_ip4,
            remote_ip_stop=self.pg0.remote_ip4,
        )
        policy_1 = self.spd_add_rem_policy(  # inbound, priority 15
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=15,
            policy_type="discard",
            ip_range=True,
            local_ip_start=self.pg1.remote_ip4,
            local_ip_stop=self.pg1.remote_ip4,
            remote_ip_start=self.pg0.remote_ip4,
            remote_ip_stop=self.pg0.remote_ip4,
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


class IPSec4SpdTestCaseDiscard(SpdFastPathInbound):
    """ IPSec/IPv4 inbound: Policy mode test case with fast path \
            (add discard)"""

    def test_ipsec_spd_inbound_discard(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec inbound SPD policy lookup.
        #
        #  Rule action is set to DISCARD.

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
            policy_type="discard",
        )

        # create output rule so we can capture forwarded packets
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )

        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, pkt_count)
        # add the stream to the source interface
        self.pg0.add_stream(packets)
        self.pg1.enable_capture()
        self.pg_start()

        # check capture on pg1
        capture = self.pg1.assert_nothing_captured()

        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_0)
        self.verify_policy_match(0, policy_1)


class IPSec4SpdTestCaseProtect(SpdFastPathInboundProtect):
    """ IPSec/IPv4 inbound: Policy mode test case with fast path \
    (add protect)"""

    @classmethod
    def setUpClass(cls):
        super(IPSec4SpdTestCaseProtect, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(IPSec4SpdTestCaseProtect, cls).tearDownClass()

    def setUp(self):
        super(IPSec4SpdTestCaseProtect, self).setUp()

    def tearDown(self):
        super(IPSec4SpdTestCaseProtect, self).tearDown()

    def test_ipsec_spd_inbound_protect(self):
        # In this test case, encrypted packets in IPv4
        # PROTECT path are configured
        # to go through IPSec inbound SPD policy lookup.

        pkt_count = 5
        payload_size = 64
        p = self.params[socket.AF_INET]
        send_pkts = self.gen_encrypt_pkts(
            p,
            p.scapy_tra_sa,
            self.tra_if,
            src=self.tra_if.remote_ip4,
            dst=self.tra_if.local_ip4,
            count=pkt_count,
            payload_size=payload_size,
        )
        recv_pkts = self.send_and_expect(self.tra_if, send_pkts, self.tra_if)

        self.logger.info(self.vapi.ppcli("show error"))
        self.logger.info(self.vapi.ppcli("show ipsec all"))

        pkts = p.tra_sa_in.get_stats()["packets"]
        self.assertEqual(
            pkts,
            pkt_count,
            "incorrect SA in counts: expected %d != %d" % (pkt_count, pkts),
        )
        pkts = p.tra_sa_out.get_stats()["packets"]
        self.assertEqual(
            pkts,
            pkt_count,
            "incorrect SA out counts: expected %d != %d" % (pkt_count, pkts),
        )
        self.assertEqual(p.tra_sa_out.get_lost(), 0)
        self.assertEqual(p.tra_sa_in.get_lost(), 0)


class IPSec4SpdTestCaseAddIPRange(SpdFastPathInbound):
    """ IPSec/IPv4 inbound: Policy mode test case with fast path \
        (add  ips  range with any port rule)"""

    def test_ipsec_spd_inbound_add(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec inbound SPD policy lookup.
        # 2 SPD bypass rules (1 for inbound and 1 for outbound) are added.
        # Traffic sent on pg0 interface should match fast path priority
        # rule and should be sent out on pg1 interface.
        self.create_interfaces(2)
        pkt_count = 5
        s_ip_s1 = ipaddress.ip_address(self.pg0.remote_ip4)
        s_ip_e1 = ipaddress.ip_address(int(s_ip_s1) + 5)
        d_ip_s1 = ipaddress.ip_address(self.pg1.remote_ip4)
        d_ip_e1 = ipaddress.ip_address(int(d_ip_s1) + 0)

        s_ip_s0 = ipaddress.ip_address(self.pg0.remote_ip4)
        s_ip_e0 = ipaddress.ip_address(int(s_ip_s0) + 6)
        d_ip_s0 = ipaddress.ip_address(self.pg1.remote_ip4)
        d_ip_e0 = ipaddress.ip_address(int(d_ip_s0) + 0)
        self.spd_create_and_intf_add(1, [self.pg1, self.pg0])

        policy_0 = self.spd_add_rem_policy(  # inbound fast path, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
            ip_range=True,
            local_ip_start=d_ip_s0,
            local_ip_stop=d_ip_e0,
            remote_ip_start=s_ip_s0,
            remote_ip_stop=s_ip_e0,
        )
        policy_1 = self.spd_add_rem_policy(  # outbound, priority 5
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=5,
            policy_type="bypass",
            ip_range=True,
            local_ip_start=s_ip_s1,
            local_ip_stop=s_ip_e1,
            remote_ip_start=d_ip_s1,
            remote_ip_stop=d_ip_e1,
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
        self.verify_policy_match(pkt_count, policy_1)


class IPSec4SpdTestCaseAddAll(SpdFastPathInbound):
    """ IPSec/IPv4 inbound: Policy mode test case with fast path \
        (add all ips ports rule)"""

    def test_ipsec_spd_inbound_add(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec inbound SPD policy lookup.
        # 2 SPD rules (1 HIGH and 1 LOW) are added.
        # Low priority rule action is set to BYPASS all ips.
        # High priority rule action is set to DISCARD all ips.
        # Traffic not sent on pg0 interface when HIGH discard priority rule is added.
        # Then LOW priority
        # rule is added and send the same traffic to pg0, this time expect
        # the traffic is bypassed as bypass takes priority over discard.
        self.create_interfaces(2)
        pkt_count = 5
        self.spd_create_and_intf_add(1, [self.pg0, self.pg1])

        policy_0 = self.spd_add_rem_policy(  # inbound, priority 20
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=20,
            policy_type="discard",
            all_ips=True,
        )

        policy_1 = self.spd_add_rem_policy(  # inbound, priority 20
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=True,
            priority=5,
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
        # assert nothing captured on pg0 and pg1
        self.pg0.assert_nothing_captured()
        self.pg1.assert_nothing_captured()

        policy_2 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=0,
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
        capture = self.pg1.get_capture(expected_count=pkt_count)
        for packet in capture:
            try:
                self.logger.debug(ppp("SPD - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        self.logger.debug("SPD: Num packets: %s", len(capture.res))

        # assert nothing captured on pg0
        self.pg0.assert_nothing_captured()
        # verify all policies matched the expected number of times
        self.verify_policy_match(pkt_count, policy_2)


class IPSec4SpdTestCaseRemove(SpdFastPathInbound):
    """ IPSec/IPv4 inbound: Policy mode test case with fast path \
        (remove rule)"""

    def test_ipsec_spd_inbound_remove(self):
        # In this test case, packets in IPv4 FWD path are configured
        # to go through IPSec inbound SPD policy lookup.
        # 2 SPD rules (1 HIGH and 1 LOW) are added.
        # High priority rule action is set to BYPASS.
        # Low priority rule action is set to DISCARD.
        # High priority rule is then removed.
        # Traffic sent on pg0 interface should match low priority
        # rule and should be discarded after SPD lookup.
        self.create_interfaces(2)
        pkt_count = 5
        self.spd_create_and_intf_add(1, [self.pg0, self.pg1])
        policy_0 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
        )
        policy_1 = self.spd_add_rem_policy(  # inbound, priority 5
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=5,
            policy_type="discard",
        )

        policy_out = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
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
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
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


class IPSec4SpdTestCaseReadd(SpdFastPathInbound):
    """ IPSec/IPv4 inbound: Policy mode test case with fast path \
        (add, remove, re-add)"""

    def test_ipsec_spd_inbound_readd(self):
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
        self.spd_create_and_intf_add(1, [self.pg0, self.pg1])
        policy_0 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
        )
        policy_1 = self.spd_add_rem_policy(  # inbound, priority 5
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=5,
            policy_type="discard",
        )
        policy_2 = self.spd_add_rem_policy(  # outbound, priority 10
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
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
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
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


class IPSec4SpdTestCaseMultiple(SpdFastPathInbound):
    """ IPSec/IPv4 inbound: Policy mode test case with fast path \
        (multiple interfaces, multiple rules)"""

    def test_ipsec_spd_inbound_multiple(self):
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
        policy_01 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
        )
        policy_02 = self.spd_add_rem_policy(  # inbound, priority 5
            1,
            self.pg1,
            self.pg0,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=5,
            policy_type="discard",
        )

        policy_11 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg2,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
        )
        policy_12 = self.spd_add_rem_policy(  # inbound, priority 5
            1,
            self.pg2,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=5,
            policy_type="discard",
        )

        policy_21 = self.spd_add_rem_policy(  # inbound, priority 5
            1,
            self.pg0,
            self.pg2,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=5,
            policy_type="bypass",
        )
        policy_22 = self.spd_add_rem_policy(  # inbound, priority 10
            1,
            self.pg0,
            self.pg2,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="discard",
        )

        # interfaces bound to an SPD, will by default drop outbound
        # traffic with no matching policies. add catch-all outbound
        # bypass rule to SPD:
        self.spd_add_rem_policy(  # outbound, all interfaces
            1,
            None,
            None,
            socket.IPPROTO_UDP,
            is_out=1,
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
        # verify that traffic to pg0 matched BYPASS rule
        # although DISCARD rule had higher prioriy and was not dropped
        self.verify_policy_match(pkt_count, policy_21)

        # verify all packets that were expected to match rules, matched
        # pg0 -> pg1
        self.verify_policy_match(pkt_count, policy_01)
        self.verify_policy_match(0, policy_02)
        # pg1 -> pg2
        self.verify_policy_match(pkt_count, policy_11)
        self.verify_policy_match(0, policy_12)
        # pg2 -> pg0
        self.verify_policy_match(0, policy_22)


class IPSec6SpdTestCaseProtect(SpdFastPathIPv6InboundProtect):
    """ IPSec/IPv6 inbound: Policy mode test case with fast path \
    (add protect)"""

    @classmethod
    def setUpClass(cls):
        super(IPSec6SpdTestCaseProtect, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(IPSec6SpdTestCaseProtect, cls).tearDownClass()

    def setUp(self):
        super(IPSec6SpdTestCaseProtect, self).setUp()

    def tearDown(self):
        super(IPSec6SpdTestCaseProtect, self).tearDown()

    def test_ipsec6_spd_inbound_protect(self):
        pkt_count = 5
        payload_size = 64
        p = self.params[socket.AF_INET6]
        send_pkts = self.gen_encrypt_pkts6(
            p,
            p.scapy_tra_sa,
            self.tra_if,
            src=self.tra_if.remote_ip6,
            dst=self.tra_if.local_ip6,
            count=pkt_count,
            payload_size=payload_size,
        )
        recv_pkts = self.send_and_expect(self.tra_if, send_pkts, self.tra_if)

        self.logger.info(self.vapi.ppcli("show error"))
        self.logger.info(self.vapi.ppcli("show ipsec all"))
        pkts = p.tra_sa_in.get_stats()["packets"]
        self.assertEqual(
            pkts,
            pkt_count,
            "incorrect SA in counts: expected %d != %d" % (pkt_count, pkts),
        )
        pkts = p.tra_sa_out.get_stats()["packets"]
        self.assertEqual(
            pkts,
            pkt_count,
            "incorrect SA out counts: expected %d != %d" % (pkt_count, pkts),
        )
        self.assertEqual(p.tra_sa_out.get_lost(), 0)
        self.assertEqual(p.tra_sa_in.get_lost(), 0)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
