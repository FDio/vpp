import socket
import unittest

from util import ppp
from framework import VppTestRunner
from template_ipsec import IPSecIPv4Fwd

"""
When an IPSec SPD is configured on an interface, any inbound packets
not matching inbound policies, or outbound packets not matching outbound
policies, must be dropped by default as per RFC4301.

This test uses simple IPv4 forwarding on interfaces with IPSec enabled
to check if packets with no matching rules are dropped by default.

The basic setup is a single SPD bound to two interfaces, pg0 and pg1.

                    ┌────┐        ┌────┐
                    │SPD1│        │SPD1│
                    ├────┤ ─────> ├────┤
                    │PG0 │        │PG1 │
                    └────┘        └────┘

First, both inbound and outbound BYPASS policies are configured allowing
traffic to pass from pg0 -> pg1.

Packets are captured and verified at pg1.

Then either the inbound or outbound policies are removed and we verify
packets are dropped as expected.

"""


class IPSecInboundDefaultDrop(IPSecIPv4Fwd):
    """IPSec: inbound packets drop by default with no matching rule"""

    def test_ipsec_inbound_default_drop(self):
        # configure two interfaces and bind the same SPD to both
        self.create_interfaces(2)
        self.spd_create_and_intf_add(1, self.pg_interfaces)
        pkt_count = 5

        # catch-all inbound BYPASS policy, all interfaces
        inbound_policy = self.spd_add_rem_policy(
            1,
            None,
            None,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
            all_ips=True,
        )

        # outbound BYPASS policy allowing traffic from pg0->pg1
        outbound_policy = self.spd_add_rem_policy(
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )

        # create a packet stream pg0->pg1 + add to pg0
        packets0 = self.create_stream(self.pg0, self.pg1, pkt_count)
        self.pg0.add_stream(packets0)

        # with inbound BYPASS rule at pg0, we expect to see forwarded
        # packets on pg1
        self.pg_interfaces[1].enable_capture()
        self.pg_start()
        cap1 = self.pg1.get_capture()
        for packet in cap1:
            try:
                self.logger.debug(ppp("SPD - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        self.logger.debug("SPD: Num packets: %s", len(cap1.res))
        # verify captures on pg1
        self.verify_capture(self.pg0, self.pg1, cap1)
        # verify policies matched correct number of times
        self.verify_policy_match(pkt_count, inbound_policy)
        self.verify_policy_match(pkt_count, outbound_policy)

        # remove inbound catch-all BYPASS rule, traffic should now be dropped
        self.spd_add_rem_policy(  # inbound, all interfaces
            1,
            None,
            None,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
            all_ips=True,
            remove=True,
        )

        # create another packet stream pg0->pg1 + add to pg0
        packets1 = self.create_stream(self.pg0, self.pg1, pkt_count)
        self.pg0.add_stream(packets1)
        self.pg_interfaces[1].enable_capture()
        self.pg_start()
        # confirm traffic has now been dropped
        self.pg1.assert_nothing_captured(
            remark="inbound pkts with no matching" "rules NOT dropped by default"
        )
        # both policies should not have matched any further packets
        # since we've dropped at input stage
        self.verify_policy_match(pkt_count, outbound_policy)
        self.verify_policy_match(pkt_count, inbound_policy)


class IPSecOutboundDefaultDrop(IPSecIPv4Fwd):
    """IPSec: outbound packets drop by default with no matching rule"""

    def test_ipsec_inbound_default_drop(self):
        # configure two interfaces and bind the same SPD to both
        self.create_interfaces(2)
        self.spd_create_and_intf_add(1, self.pg_interfaces)
        pkt_count = 5

        # catch-all inbound BYPASS policy, all interfaces
        inbound_policy = self.spd_add_rem_policy(
            1,
            None,
            None,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
            all_ips=True,
        )

        # outbound BYPASS policy allowing traffic from pg0->pg1
        outbound_policy = self.spd_add_rem_policy(
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
        )

        # create a packet stream pg0->pg1 + add to pg0
        packets0 = self.create_stream(self.pg0, self.pg1, pkt_count)
        self.pg0.add_stream(packets0)

        # with outbound BYPASS rule allowing pg0->pg1, we expect to see
        # forwarded packets on pg1
        self.pg_interfaces[1].enable_capture()
        self.pg_start()
        cap1 = self.pg1.get_capture()
        for packet in cap1:
            try:
                self.logger.debug(ppp("SPD - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        self.logger.debug("SPD: Num packets: %s", len(cap1.res))
        # verify captures on pg1
        self.verify_capture(self.pg0, self.pg1, cap1)
        # verify policies matched correct number of times
        self.verify_policy_match(pkt_count, inbound_policy)
        self.verify_policy_match(pkt_count, outbound_policy)

        # remove outbound rule
        self.spd_add_rem_policy(
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=1,
            priority=10,
            policy_type="bypass",
            remove=True,
        )

        # create another packet stream pg0->pg1 + add to pg0
        packets1 = self.create_stream(self.pg0, self.pg1, pkt_count)
        self.pg0.add_stream(packets1)
        self.pg_interfaces[1].enable_capture()
        self.pg_start()
        # confirm traffic was dropped and not forwarded
        self.pg1.assert_nothing_captured(
            remark="outbound pkts with no matching rules NOT dropped " "by default"
        )
        # inbound rule should have matched twice the # of pkts now
        self.verify_policy_match(pkt_count * 2, inbound_policy)
        # as dropped at outbound, outbound policy is the same
        self.verify_policy_match(pkt_count, outbound_policy)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
