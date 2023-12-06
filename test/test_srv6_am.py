import unittest
from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, IPv6ExtHdrSegmentRouting, UDP, Raw
import scapy
from util import ppp


class TestSRv6Am(VppTestCase):
    """SRv6-Am test"""

    # based on "test_srv6.TestSRv6.test_SRv6_End"
    @classmethod
    def setUpClass(cls):
        super(TestSRv6Am, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip6()
                i.resolve_ndp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip6()
            i.admin_down()
        super(TestSRv6Am, cls).tearDownClass()

    def create_stream(self, src_if, dst_if, packet_header, packet_sizes, count):
        """Create SRv6 input packet stream for defined interface.

        :param VppInterface src_if: Interface to create packet stream for
        :param VppInterface dst_if: destination interface of packet stream
        :param packet_header: Layer3 scapy packet headers,
                L2 is added when not provided,
                Raw(payload) with packet_info is added
        :param list packet_sizes: packet stream pckt sizes,sequentially applied
               to packets in stream have
        :param int count: number of packets in packet stream
        :return: list of packets
        """
        self.logger.info("Creating packets")
        pkts = []
        for i in range(0, count - 1):
            payload_info = self.create_packet_info(src_if, dst_if)
            self.logger.debug("Creating packet with index %d" % (payload_info.index))
            payload = self.info_to_payload(payload_info)
            # add L2 header if not yet provided in packet_header
            if packet_header.getlayer(0).name == "Ethernet":
                p = packet_header / Raw(payload)
            else:
                p = (
                    Ether(dst=src_if.local_mac, src=src_if.remote_mac)
                    / packet_header
                    / Raw(payload)
                )
            size = packet_sizes[i % len(packet_sizes)]
            self.logger.debug("Packet size %d" % (size))
            self.extend_packet(p, size)
            # we need to store the packet with the automatic fields computed
            # read back the dumped packet (with str())
            # to force computing these fields
            # probably other ways are possible
            p = Ether(scapy.compat.raw(p))
            payload_info.data = p.copy()
            self.logger.debug(ppp("Created packet:", p))
            pkts.append(p)
        self.logger.info("Done creating packets")
        return pkts

    def create_packet_header_IPv6_SRH_IPv6(self, dst, sidlist, segleft):
        """Create packet header: IPv6 encapsulated in SRv6:
        IPv6 header with SRH, IPv6 header, UDP header

        :param ipv6address dst: inner IPv6 destination address
        :param list sidlist: segment list of outer IPv6 SRH
        :param int segleft: segments-left field of outer IPv6 SRH

        Outer IPv6 destination address is set to sidlist[segleft]
        IPv6 source addresses are 1234::1 and 4321::1
        UDP source port and destination port are 1234
        """

        p = (
            IPv6(src="1234::1", dst=sidlist[segleft])
            / IPv6ExtHdrSegmentRouting(addresses=sidlist, segleft=segleft, nh=41)
            / IPv6(src="4321::1", dst=dst)
            / UDP(sport=1234, dport=1234)
        )
        return p

    def test_srv6am(self):
        """SRv6 End.AM behaviour test"""
        pg_packet_sizes = [64, 512, 1518, 9018]
        count = len(pg_packet_sizes)
        dst_inner = "a4::1234"
        pkts = []

        self.vapi.cli(
            "sr localsid address A3::0 behavior end.am nh A3::0 oif pg1 iif pg1"
        )
        route = VppIpRoute(
            self, "a4::", 64, [VppRoutePath(self.pg1.remote_ip6, self.pg1.sw_if_index)]
        )
        route.add_vpp_config()

        # packets with segments-left 2, active segment a3::
        packet_header = self.create_packet_header_IPv6_SRH_IPv6(
            dst_inner, sidlist=["a5::", "a4::", "a3::"], segleft=2
        )
        # create traffic stream pg0->pg1
        pkts.extend(
            self.create_stream(
                self.pg0, self.pg1, packet_header, pg_packet_sizes, count
            )
        )

        # packets with segments-left 1, active segment a3::
        packet_header = self.create_packet_header_IPv6_SRH_IPv6(
            dst_inner, sidlist=["a4::", "a3::", "a2::"], segleft=1
        )
        # add to traffic stream pg0->pg1
        pkts.extend(
            self.create_stream(
                self.pg0, self.pg1, packet_header, pg_packet_sizes, count
            )
        )

        self.pg0.add_stream(pkts)
        self.pg_start()
        self.assertIn("SRv6-AM-localsid", self.vapi.cli("show trace"))
        self.assertIn("6 packets", self.vapi.cli("show sr localsid"))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
