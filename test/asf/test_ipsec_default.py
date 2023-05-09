import socket
import unittest
from scapy.layers.l2 import Ether
from scapy.layers.inet import ICMP, IP, TCP, UDP
import scapy.compat

from util import ppp
from asfframework import VppTestRunner
from template_ipsec import IPSecIPv4Fwd
from scapy.layers.ipsec import SecurityAssociation, ESP
from template_ipsec import TemplateIpsec
from vpp_ipsec import VppIpsecSA, VppIpsecSpd, VppIpsecSpdEntry, VppIpsecSpdItfBinding
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import DpoProto
from vpp_papi import VppEnum


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
packets are dropped as expected.This test cover IPsec traffic like ESP 
UDP ENCAP ESP not normal UDP traffic.

"""


class IPSecInboundAndOutboundDefaultDrop(IPSecIPv4Fwd):
    """IPSec: inbound/Outbound packets drop by default with no matching rule"""

    tcp_port_in = 6303
    tcp_port_out = 6303
    udp_port_in = 6304
    udp_port_out = 6304
    icmp_id_in = 6305
    icmp_id_out = 6305
    is_ipv6 = 0
    # pkt_count = 3

    @classmethod
    def setUpClass(cls):
        super(IPSecInboundAndOutboundDefaultDrop, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(IPSecInboundAndOutboundDefaultDrop, cls).tearDownClass()

    def setUp(self):
        super(IPSecInboundAndOutboundDefaultDrop, self).setUp()
        self.create_interfaces(2)
        self.spd_create_and_intf_add(1, self.pg_interfaces)
        # self.config_network(self.params.values())

    def tearDown(self):
        # self.unconfig_network()
        super(IPSecInboundAndOutboundDefaultDrop, self).tearDown()

    def test_ipsec_inbound_default_drop(self):
        """IPSec: inbound packets drop by default with no matching rule"""
        pkt_count = 3

        # catch-all inbound BYPASS policy, all interfaces
        inbound_policy = self.spd_add_rem_policy(
            1,
            self.pg0,
            self.pg1,
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
        vpp_tun_sa = SecurityAssociation(
            ESP,
            spi=1000,
            crypt_algo="AES-CBC",
            crypt_key=b"JPjyOWBeVEQiMe7h",
            auth_algo="HMAC-SHA1-96",
            auth_key=b"C91KUR9GYMm5GfkEvNjX",
            tunnel_header=IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4),
            nat_t_header=UDP(sport=4500, dport=4500),
        )

        # out2in - from public network to private
        pkts = self.create_stream_encrypted(
            self.pg0.remote_mac,
            self.pg0.local_mac,
            self.pg0.remote_ip4,
            self.pg1.remote_ip4,
            vpp_tun_sa,
        )
        # packets0 = self.create_stream(self.pg0, self.pg1, pkt_count)
        self.pg0.add_stream(pkts)

        # with inbound BYPASS rule at pg0, we expect to see forwarded
        # packets on pg1
        self.pg_interfaces[1].enable_capture()
        self.pg_start()
        cap1 = self.pg1.get_capture(3)
        for packet in cap1:
            try:
                self.logger.debug(ppp("SPD - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        self.logger.debug("SPD: Num packets: %s", len(cap1.res))
        # verify captures on pg1
        # verify policies matched correct number of times
        self.verify_policy_match(pkt_count, inbound_policy)
        self.verify_policy_match(pkt_count, outbound_policy)

        # remove inbound catch-all BYPASS rule, traffic should now be dropped
        self.spd_add_rem_policy(  # inbound, all interfaces
            1,
            self.pg0,
            self.pg1,
            socket.IPPROTO_UDP,
            is_out=0,
            priority=10,
            policy_type="bypass",
            all_ips=True,
            remove=True,
        )
        self.logger.info(self.vapi.cli("show ipsec all"))
        # create another packet stream pg0->pg1 + add to pg0
        vpp_tun_sa = SecurityAssociation(
            ESP,
            spi=1000,
            crypt_algo="AES-CBC",
            crypt_key=b"JPjyOWBeVEQiMe7h",
            auth_algo="HMAC-SHA1-96",
            auth_key=b"C91KUR9GYMm5GfkEvNjX",
            tunnel_header=IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4),
            nat_t_header=UDP(sport=4600, dport=4600),
        )

        # out2in - from public network to private
        pkts1 = self.create_stream_encrypted(
            self.pg0.remote_mac,
            self.pg0.local_mac,
            self.pg0.remote_ip4,
            self.pg1.remote_ip4,
            vpp_tun_sa,
        )
        # packets1 = self.create_stream(self.pg0, self.pg1, pkt_count)
        self.pg0.add_stream(pkts1)
        self.pg_interfaces[1].disable_capture()
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

    def test_ipsec_outbound_default_drop(self):
        """IPSec: outbound packets drop by default with no matching rule"""

        # catch-all inbound BYPASS policy, all interfaces
        inbound_policy = self.spd_add_rem_policy(
            1,
            self.pg0,
            self.pg1,
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

        # p = self.ipv4_params
        # create a packet stream pg0->pg1 + add to pg0
        vpp_tun_sa = SecurityAssociation(
            ESP,
            spi=1000,
            crypt_algo="AES-CBC",
            crypt_key=b"JPjyOWBeVEQiMe7h",
            auth_algo="HMAC-SHA1-96",
            auth_key=b"C91KUR9GYMm5GfkEvNjX",
            tunnel_header=IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4),
            nat_t_header=UDP(sport=4500, dport=4500),
        )

        # out2in - from public network to private
        pkts = self.create_stream_encrypted(
            self.pg0.remote_mac,
            self.pg0.local_mac,
            self.pg0.remote_ip4,
            self.pg1.remote_ip4,
            vpp_tun_sa,
        )
        # packets0 = self.create_stream(self.pg0, self.pg1, pkt_count)
        self.pg0.add_stream(pkts)

        # with outbound BYPASS rule allowing pg0->pg1, we expect to see
        # forwarded packets on pg1
        self.pg_interfaces[1].enable_capture()
        self.pg_start()
        cap1 = self.pg1.get_capture(3)
        for packet in cap1:
            try:
                self.logger.debug(ppp("SPD - Got packet:", packet))
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        self.logger.debug("SPD: Num packets: %s", len(cap1.res))
        # verify captures on pg1
        # self.verify_capture(self.pg0, self.pg1, cap1)
        # verify policies matched correct number of times
        self.verify_policy_match(3, inbound_policy)
        self.verify_policy_match(3, outbound_policy)

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
        self.logger.info(self.vapi.cli("show ipsec all"))

        self.sleep(2)
        vpp_tun_sa = SecurityAssociation(
            ESP,
            spi=1000,
            crypt_algo="AES-CBC",
            crypt_key=b"JPjyOWBeVEQiMe7h",
            auth_algo="HMAC-SHA1-96",
            auth_key=b"C91KUR9GYMm5GfkEvNjX",
            tunnel_header=IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4),
            nat_t_header=UDP(sport=4500, dport=4500),
        )

        # out2in - from public network to private
        pkts = self.create_stream_encrypted(
            self.pg0.remote_mac,
            self.pg0.local_mac,
            self.pg0.remote_ip4,
            self.pg1.remote_ip4,
            vpp_tun_sa,
        )

        # packets1 = self.create_stream(self.pg0, self.pg1, pkt_count)
        self.pg0.add_stream(pkts)
        self.pg_interfaces[1].enable_capture()
        self.pg_start()
        # confirm traffic was dropped and not forwarded
        self.pg1.assert_nothing_captured(
            remark="outbound pkts with no matching rules NOT dropped " "by default"
        )
        # inbound rule should have matched twice the # of pkts now
        self.verify_policy_match(3 * 2, inbound_policy)
        # as dropped at outbound, outbound policy is the same
        self.verify_policy_match(3, outbound_policy)

    def create_stream_encrypted(self, src_mac, dst_mac, src_ip, dst_ip, sa):
        return [
            # TCP
            Ether(src=src_mac, dst=dst_mac)
            / sa.encrypt(
                IP(src=src_ip, dst=dst_ip) / TCP(dport=self.tcp_port_out, sport=20)
            ),
            # UDP
            Ether(src=src_mac, dst=dst_mac)
            / sa.encrypt(
                IP(src=src_ip, dst=dst_ip) / UDP(dport=self.udp_port_out, sport=20)
            ),
            # ICMP
            Ether(src=src_mac, dst=dst_mac)
            / sa.encrypt(
                IP(src=src_ip, dst=dst_ip)
                / ICMP(id=self.icmp_id_out, type="echo-request")
            ),
        ]


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
