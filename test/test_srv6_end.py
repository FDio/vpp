#!/usr/bin/env python

from framework import VppTestCase
from ipaddress import IPv4Address
from ipaddress import IPv6Address
from scapy.contrib.gtp import *
from scapy.all import *


class TestSRv6EndMGTP4E(VppTestCase):
    """ SRv6 End.M.GTP4.E (SRv6 -> GTP-U) """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6EndMGTP4E, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip6()
            cls.pg_if_o.config_ip4()

            cls.ip4_dst = cls.pg_if_o.remote_ip4
            # cls.ip4_src = cls.pg_if_o.local_ip4
            cls.ip4_src = "192.168.192.10"

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_arp()

        except Exception:
            super(TestSRv6EndMGTP4E, cls).tearDownClass()
            raise

    def create_packets(self, inner):

        ip4_dst = IPv4Address(str(self.ip4_dst))
        # 32bit prefix + 32bit IPv4 DA + 8bit + 32bit TEID + 24bit
        dst = b'\xaa' * 4 + ip4_dst.packed + \
            b'\x11' + b'\xbb' * 4 + b'\x11' * 3
        ip6_dst = IPv6Address(dst)

        ip4_src = IPv4Address(str(self.ip4_src))
        # 64bit prefix + 32bit IPv4 SA + 16 bit port + 16bit
        src = b'\xcc' * 8 + ip4_src.packed + \
            b'\xdd' * 2 + b'\x11' * 2
        ip6_src = IPv6Address(src)

        print("ip4 dst: {}".format(ip4_dst))
        print("ip4 src: {}".format(ip4_src))
        print("ip6 dst (remote srgw): {}".format(ip6_dst))
        print("ip6 src (local  srgw): {}".format(ip6_src))

        pkts = list()
        for d, s in inner:
            pkt = (Ether() /
                   IPv6(dst=str(ip6_dst), src=str(ip6_src)) /
                   IPv6ExtHdrSegmentRouting() /
                   IPv6(dst=d, src=s) /
                   UDP(sport=1000, dport=23))

            print(pkt.show2())
            pkts.append(pkt)

        return pkts

    def test_srv6_end(self):
        """ test_srv6_end """
        pkts = self.create_packets([("A::1", "B::1"), ("C::1", "D::1")])

        self.vapi.cli(
            "sr localsid address {} behavior end.m.gtp4.e v4src_position 64"
            .format(pkts[0]['IPv6'].dst))
        print(self.vapi.cli("show sr localsids"))

        self.vapi.cli("clear errors")

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        print(self.vapi.cli("show errors"))
        print(self.vapi.cli("show int address"))

        capture = self.pg1.get_capture(len(pkts))

        for pkt in capture:
            print(pkt.show2())


class TestSRv6TMTmap(VppTestCase):
    """ SRv6 T.M.Tmap (GTP-U -> SRv6) """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6TMTmap, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip4()
            cls.pg_if_o.config_ip6()

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_arp()

        except Exception:
            super(TestSRv6TMTmap, cls).tearDownClass()
            raise


class TestSRv6EndMGTP6E(VppTestCase):
    """ SRv6 End.M.GTP6.E """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6EndMGTP6E, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip4()
            cls.pg_if_o.config_ip6()

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_arp()

        except Exception:
            super(TestSRv6EndMGTP6E, cls).tearDownClass()
            raise


class TestSRv6EndMGTP6D(VppTestCase):
    """ SRv6 End.M.GTP6.D """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6EndMGTP6D, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip4()
            cls.pg_if_o.config_ip6()

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_arp()

        except Exception:
            super(TestSRv6EndMGTP6D, cls).tearDownClass()
            raise
