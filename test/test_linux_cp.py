#!/usr/bin/env python3

import unittest
import socket

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, Raw
from scapy.layers.l2 import Ether, ARP, Dot3, LLC
from scapy.contrib.lacp import LACP
from scapy.contrib.lldp import (
    LLDPDUChassisID,
    LLDPDUPortID,
    LLDPDUTimeToLive,
    LLDPDUEndOfLLDPDU,
    LLDPDU,
)
from scapy.contrib.isis import *

from util import reassemble4
from vpp_object import VppObject
from framework import VppTestCase
from asfframework import (
    VppTestRunner,
    get_testcase_dirname,
)
from vpp_ipip_tun_interface import VppIpIpTunInterface
from template_ipsec import (
    TemplateIpsec,
    IpsecTun4,
)
from template_ipsec import (
    TemplateIpsec,
    IpsecTun4,
)
from test_ipsec_tun_if_esp import TemplateIpsecItf4
from config import config
from vpp_ip_route import FibPathType
from vpp_qemu_utils import (
    add_namespace_route,
    add_namespace_multipath_route,
    NextHop,
    create_namespace,
    delete_all_namespaces,
    set_interface_up,
    set_interface_down,
)


class VppLcpPair(VppObject):
    def __init__(self, test, phy, host):
        self._test = test
        self.phy = phy
        self.host = host

    def add_vpp_config(self):
        self._test.vapi.cli("test lcp add phy %s host %s" % (self.phy, self.host))
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        self._test.vapi.cli("test lcp del phy %s host %s" % (self.phy, self.host))

    def object_id(self):
        return "lcp:%d:%d" % (self.phy.sw_if_index, self.host.sw_if_index)

    def query_vpp_config(self):
        pairs = list(self._test.vapi.vpp.details_iter(self._test.vapi.lcp_itf_pair_get))

        for p in pairs:
            if (
                p.phy_sw_if_index == self.phy.sw_if_index
                and p.host_sw_if_index == self.host.sw_if_index
            ):
                return True
        return False


@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCP(VppTestCase):
    """Linux Control Plane"""

    extra_vpp_plugin_config = [
        "plugin",
        "linux_cp_plugin.so",
        "{",
        "enable",
        "}",
        "plugin",
        "linux_cp_unittest_plugin.so",
        "{",
        "enable",
        "}",
    ]

    @classmethod
    def setUpClass(cls):
        super(TestLinuxCP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestLinuxCP, cls).tearDownClass()

    def setUp(self):
        super(TestLinuxCP, self).setUp()

        # create 4 pg interfaces so we can create two pairs
        self.create_pg_interfaces(range(4))

        # create on ip4 and one ip6 pg tun
        self.pg_interfaces += self.create_pg_ip4_interfaces(range(4, 5))
        self.pg_interfaces += self.create_pg_ip6_interfaces(range(5, 6))

        for i in self.pg_interfaces:
            i.admin_up()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()
        super(TestLinuxCP, self).tearDown()

    def test_linux_cp_tap(self):
        """Linux CP TAP"""

        #
        # Setup
        #

        arp_opts = {"who-has": 1, "is-at": 2}

        # create two pairs, wihch a bunch of hots on the phys
        hosts = [self.pg0, self.pg1]
        phys = [self.pg2, self.pg3]
        N_HOSTS = 4

        for phy in phys:
            phy.config_ip4()
            phy.generate_remote_hosts(4)
            phy.configure_ipv4_neighbors()

        pair1 = VppLcpPair(self, phys[0], hosts[0]).add_vpp_config()
        pair2 = VppLcpPair(self, phys[1], hosts[1]).add_vpp_config()

        self.logger.info(self.vapi.cli("sh lcp adj verbose"))
        self.logger.info(self.vapi.cli("sh lcp"))

        #
        # Traffic Tests
        #

        # hosts to phys
        for phy, host in zip(phys, hosts):
            for j in range(N_HOSTS):
                p = (
                    Ether(src=phy.local_mac, dst=host.local_mac)
                    / IP(src=phy.local_ip4, dst=phy.remote_hosts[j].ip4)
                    / UDP(sport=1234, dport=1234)
                    / Raw()
                )

                rxs = self.send_and_expect(host, [p], phy)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

                # ARPs x-connect to phy
                p = Ether(dst="ff:ff:ff:ff:ff:ff", src=phy.remote_hosts[j].mac) / ARP(
                    op="who-has",
                    hwdst=phy.remote_hosts[j].mac,
                    hwsrc=phy.local_mac,
                    psrc=phy.local_ip4,
                    pdst=phy.remote_hosts[j].ip4,
                )

                rxs = self.send_and_expect(host, [p], phy)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

        # phy to host
        for phy, host in zip(phys, hosts):
            for j in range(N_HOSTS):
                p = (
                    Ether(dst=phy.local_mac, src=phy.remote_hosts[j].mac)
                    / IP(dst=phy.local_ip4, src=phy.remote_hosts[j].ip4)
                    / UDP(sport=1234, dport=1234)
                    / Raw()
                )

                rxs = self.send_and_expect(phy, [p], host)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

                # ARPs rx'd on the phy are sent to the host
                p = Ether(dst="ff:ff:ff:ff:ff:ff", src=phy.remote_hosts[j].mac) / ARP(
                    op="is-at",
                    hwsrc=phy.remote_hosts[j].mac,
                    hwdst=phy.local_mac,
                    pdst=phy.local_ip4,
                    psrc=phy.remote_hosts[j].ip4,
                )

                rxs = self.send_and_expect(phy, [p], host)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

        # cleanup
        for phy in phys:
            phy.unconfig_ip4()

    def test_linux_cp_sync_unnumbered(self):
        """Linux CP Sync Unnumbered"""

        # default should be enabled
        reply = self.vapi.lcp_sync_unnumbered_get()
        self.assertTrue(reply.is_enable)

        # disable it
        self.vapi.lcp_sync_unnumbered_set(is_enable=False)

        # verify it is now disabled
        reply = self.vapi.lcp_sync_unnumbered_get()
        self.assertFalse(reply.is_enable)

        # re-enable for clean state
        self.vapi.lcp_sync_unnumbered_set(is_enable=True)

    def test_linux_cp_tun(self):
        """Linux CP TUN"""

        #
        # Setup
        #
        N_PKTS = 31

        # create two pairs, wihch a bunch of hots on the phys
        hosts = [self.pg4, self.pg5]
        phy = self.pg2

        phy.config_ip4()
        phy.config_ip6()
        phy.resolve_arp()
        phy.resolve_ndp()

        tun4 = VppIpIpTunInterface(
            self, phy, phy.local_ip4, phy.remote_ip4
        ).add_vpp_config()
        tun6 = VppIpIpTunInterface(
            self, phy, phy.local_ip6, phy.remote_ip6
        ).add_vpp_config()
        tuns = [tun4, tun6]

        tun4.admin_up()
        tun4.config_ip4()
        tun6.admin_up()
        tun6.config_ip6()

        pair1 = VppLcpPair(self, tuns[0], hosts[0]).add_vpp_config()
        pair2 = VppLcpPair(self, tuns[1], hosts[1]).add_vpp_config()

        self.logger.info(self.vapi.cli("sh lcp adj verbose"))
        self.logger.info(self.vapi.cli("sh lcp"))
        self.logger.info(self.vapi.cli("sh ip punt redirect"))

        #
        # Traffic Tests
        #

        # host to phy for v4
        p = IP(src=tun4.local_ip4, dst="2.2.2.2") / UDP(sport=1234, dport=1234) / Raw()

        rxs = self.send_and_expect(self.pg4, p * N_PKTS, phy)

        # verify inner packet is unchanged and has the tunnel encap
        for rx in rxs:
            self.assertEqual(rx[Ether].dst, phy.remote_mac)
            self.assertEqual(rx[IP].dst, phy.remote_ip4)
            self.assertEqual(rx[IP].src, phy.local_ip4)
            inner = IP(bytes(rx[IP].payload))
            self.assertEqual(inner.src, tun4.local_ip4)
            self.assertEqual(inner.dst, "2.2.2.2")

        # host to phy for v6
        p = IPv6(src=tun6.local_ip6, dst="2::2") / UDP(sport=1234, dport=1234) / Raw()

        rxs = self.send_and_expect(self.pg5, p * N_PKTS, phy)

        # verify inner packet is unchanged and has the tunnel encap
        for rx in rxs:
            self.assertEqual(rx[IPv6].dst, phy.remote_ip6)
            self.assertEqual(rx[IPv6].src, phy.local_ip6)
            inner = IPv6(bytes(rx[IPv6].payload))
            self.assertEqual(inner.src, tun6.local_ip6)
            self.assertEqual(inner.dst, "2::2")

        # phy to host v4
        p = (
            Ether(dst=phy.local_mac, src=phy.remote_mac)
            / IP(dst=phy.local_ip4, src=phy.remote_ip4)
            / IP(dst=tun4.local_ip4, src=tun4.remote_ip4)
            / UDP(sport=1234, dport=1234)
            / Raw()
        )

        rxs = self.send_and_expect(phy, p * N_PKTS, self.pg4)
        for rx in rxs:
            rx = IP(bytes(rx))
            self.assertEqual(rx[IP].dst, tun4.local_ip4)
            self.assertEqual(rx[IP].src, tun4.remote_ip4)

        # phy to host v6
        p = (
            Ether(dst=phy.local_mac, src=phy.remote_mac)
            / IPv6(dst=phy.local_ip6, src=phy.remote_ip6)
            / IPv6(dst=tun6.local_ip6, src=tun6.remote_ip6)
            / UDP(sport=1234, dport=1234)
            / Raw()
        )

        rxs = self.send_and_expect(phy, p * N_PKTS, self.pg5)
        for rx in rxs:
            rx = IPv6(bytes(rx))
            self.assertEqual(rx[IPv6].dst, tun6.local_ip6)
            self.assertEqual(rx[IPv6].src, tun6.remote_ip6)

        # cleanup
        phy.unconfig_ip4()
        phy.unconfig_ip6()

        tun4.unconfig_ip4()
        tun6.unconfig_ip6()


@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCPIpsec(TemplateIpsec, TemplateIpsecItf4, IpsecTun4):
    """IPsec Interface IPv4"""

    extra_vpp_plugin_config = [
        "plugin",
        "linux_cp_plugin.so",
        "{",
        "enable",
        "}",
        "plugin",
        "linux_cp_unittest_plugin.so",
        "{",
        "enable",
        "}",
    ]

    def setUp(self):
        super(TestLinuxCPIpsec, self).setUp()

        self.tun_if = self.pg0
        self.pg_interfaces += self.create_pg_ip4_interfaces(range(3, 4))
        self.pg_interfaces += self.create_pg_ip6_interfaces(range(4, 5))

    def tearDown(self):
        super(TestLinuxCPIpsec, self).tearDown()

    def verify_encrypted(self, p, sa, rxs):
        decrypt_pkts = []
        for rx in rxs:
            if p.nat_header:
                self.assertEqual(rx[UDP].dport, 4500)
            self.assert_packet_checksums_valid(rx)
            self.assertEqual(len(rx) - len(Ether()), rx[IP].len)
            try:
                rx_ip = rx[IP]
                decrypt_pkt = p.vpp_tun_sa.decrypt(rx_ip)
                if not decrypt_pkt.haslayer(IP):
                    decrypt_pkt = IP(decrypt_pkt[Raw].load)
                if rx_ip.proto == socket.IPPROTO_ESP:
                    self.verify_esp_padding(sa, rx_ip[ESP].data, decrypt_pkt)
                decrypt_pkts.append(decrypt_pkt)
                self.assert_equal(decrypt_pkt.src, p.tun_if.local_ip4)
                self.assert_equal(decrypt_pkt.dst, p.tun_if.remote_ip4)
            except:
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", decrypt_pkt))
                except:
                    pass
                raise
        pkts = reassemble4(decrypt_pkts)
        for pkt in pkts:
            self.assert_packet_checksums_valid(pkt)

    def verify_decrypted(self, p, rxs):
        for rx in rxs:
            rx = IP(bytes(rx))
            self.assert_equal(rx[IP].src, p.tun_if.remote_ip4)
            self.assert_equal(rx[IP].dst, p.tun_if.local_ip4)
            self.assert_packet_checksums_valid(rx)

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1, payload_size=54):
        return [
            Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac)
            / sa.encrypt(
                IP(src=src, dst=dst)
                / UDP(sport=1111, dport=2222)
                / Raw(b"X" * payload_size)
            )
            for i in range(count)
        ]

    def test_linux_cp_ipsec4_tun(self):
        """Linux CP Ipsec TUN"""

        #
        # Setup
        #
        N_PKTS = 31

        # the pg that paris with the tunnel
        self.host = self.pg3

        # tunnel and protection setup
        p = self.ipv4_params

        self.config_network(p)
        self.config_sa_tun(p, self.pg0.local_ip4, self.pg0.remote_ip4)
        self.config_protect(p)

        pair = VppLcpPair(self, p.tun_if, self.host).add_vpp_config()

        self.logger.info(self.vapi.cli("sh int addr"))
        self.logger.info(self.vapi.cli("sh lcp"))
        self.logger.info(self.vapi.cli("sh ip punt redirect"))

        #
        # Traffic Tests
        #

        # host to phy for v4
        pkt = (
            IP(src=p.tun_if.local_ip4, dst=p.tun_if.remote_ip4)
            / UDP(sport=1234, dport=1234)
            / Raw()
        )

        rxs = self.send_and_expect(self.host, pkt * N_PKTS, self.tun_if)
        self.verify_encrypted(p, p.vpp_tun_sa, rxs)

        # phy to host for v4
        pkts = self.gen_encrypt_pkts(
            p,
            p.scapy_tun_sa,
            self.tun_if,
            src=p.tun_if.remote_ip4,
            dst=p.tun_if.local_ip4,
            count=N_PKTS,
        )
        rxs = self.send_and_expect(self.tun_if, pkts, self.host)
        self.verify_decrypted(p, rxs)

        # cleanup
        pair.remove_vpp_config()
        self.unconfig_protect(p)
        self.unconfig_sa(p)
        self.unconfig_network(p)


@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCPEthertype(VppTestCase):
    """Linux CP Ethertype"""

    extra_vpp_plugin_config = [
        "plugin",
        "linux_cp_plugin.so",
        "{",
        "enable",
        "}",
        "plugin",
        "linux_cp_unittest_plugin.so",
        "{",
        "enable",
        "}",
        "plugin",
        "lldp_plugin.so",
        "{",
        "disable",
        "}",
    ]

    LACP_ETHERTYPE = 0x8809
    LLDP_ETHERTYPE = 0x88CC

    @classmethod
    def setUpClass(cls):
        super(TestLinuxCPEthertype, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestLinuxCPEthertype, cls).tearDownClass()

    def setUp(self):
        super(TestLinuxCPEthertype, self).setUp()
        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            i.admin_up()

        self.host = self.pg0
        self.phy = self.pg1

        self.pair = VppLcpPair(self, self.phy, self.host).add_vpp_config()
        self.logger.info(self.vapi.cli("sh lcp"))

    def tearDown(self):
        self.pair.remove_vpp_config()

        for i in self.pg_interfaces:
            i.admin_down()
        super(TestLinuxCPEthertype, self).tearDown()

    def send_packet(self, sender, receiver, ethertype, dst, data, expect_copy=True):
        packet = Ether(src=sender.remote_mac, dst=dst, type=ethertype) / data
        if expect_copy:
            rxs = self.send_and_expect(sender, [packet], receiver)
            for rx in rxs:
                self.assertEqual(packet.show2(True), rx.show2(True))
        else:
            self.send_and_assert_no_replies(sender, [packet])

    def send_lacp_packet(self, sender, receiver, expect_copy=True):
        data = LACP(
            actor_system="00:00:00:00:00:01", partner_system="00:00:00:00:00:02"
        )
        self.send_packet(
            sender,
            receiver,
            self.LACP_ETHERTYPE,
            "01:80:c2:00:00:02",
            data,
            expect_copy,
        )

    def send_lldp_packet(self, sender, receiver, expect_copy=True):
        data = (
            LLDPDUChassisID(subtype=4, id="01:02:03:04:05:06")
            / LLDPDUPortID(subtype=3, id="07:08:09:0a:0b:0c")
            / LLDPDUTimeToLive(ttl=120)
            / LLDPDUEndOfLLDPDU()
        )
        self.send_packet(
            sender,
            receiver,
            self.LLDP_ETHERTYPE,
            "01:80:c2:00:00:0e",
            data,
            expect_copy,
        )

    def check_ethertype_enabled(self, ethertype, enabled=True):
        reply = self.vapi.lcp_ethertype_get()
        output = self.vapi.cli("show lcp ethertype")

        if enabled:
            self.assertIn(ethertype, reply.ethertypes)
            self.assertIn(hex(ethertype), output)
        else:
            self.assertNotIn(ethertype, reply.ethertypes)
            self.assertNotIn(hex(ethertype), output)

    def test_linux_cp_lacp(self):
        """Linux CP LACP Test"""
        self.check_ethertype_enabled(self.LACP_ETHERTYPE, enabled=False)
        self.send_lacp_packet(self.phy, self.host, expect_copy=False)
        self.send_lacp_packet(self.host, self.phy, expect_copy=False)

        self.vapi.cli("lcp ethertype enable " + str(self.LACP_ETHERTYPE))

        self.check_ethertype_enabled(self.LACP_ETHERTYPE, enabled=True)
        self.send_lacp_packet(self.phy, self.host, expect_copy=True)
        self.send_lacp_packet(self.host, self.phy, expect_copy=True)

    def test_linux_cp_lldp(self):
        """Linux CP LLDP Test"""
        self.check_ethertype_enabled(self.LLDP_ETHERTYPE, enabled=False)
        self.send_lldp_packet(self.phy, self.host, expect_copy=False)
        self.send_lldp_packet(self.host, self.phy, expect_copy=False)

        self.vapi.cli("lcp ethertype enable " + str(self.LLDP_ETHERTYPE))

        self.check_ethertype_enabled(self.LLDP_ETHERTYPE, enabled=True)
        self.send_lldp_packet(self.phy, self.host, expect_copy=True)
        self.send_lldp_packet(self.host, self.phy, expect_copy=True)


CLIB_U32_MAX = 4294967295


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestLinuxCPRoutes(VppTestCase):
    """Linux CP Routes"""

    extra_vpp_plugin_config = [
        "plugin",
        "linux_cp_plugin.so",
        "{",
        "enable",
        "}",
        "plugin",
        "linux_nl_plugin.so",
        "{",
        "enable",
        "}",
    ]

    @classmethod
    def setUpNetNS(cls):
        # The namespace must be set up before VPP starts
        cls.ns_history_name = (
            f"{config.tmp_dir}/{get_testcase_dirname(cls.__name__)}/history_ns.txt"
        )
        delete_all_namespaces(cls.ns_history_name)

        cls.ns_name = create_namespace(cls.ns_history_name)
        cls.vpp_cmdline.extend(
            [
                "linux-cp",
                "{",
                "default",
                "netns",
                cls.ns_name,
                "lcp-sync",
                "}",
            ]
        )

    @classmethod
    def attach_vpp(cls):
        cls.setUpNetNS()
        super(TestLinuxCPRoutes, cls).attach_vpp()

    @classmethod
    def run_vpp(cls):
        cls.setUpNetNS()
        super(TestLinuxCPRoutes, cls).run_vpp()

    @classmethod
    def setUpClass(cls):
        super(TestLinuxCPRoutes, cls).setUpClass()
        cls.create_loopback_interfaces(2)

        cls.vapi.cli(f"lcp create loop0 host-if hloop0 netns {cls.ns_name}")
        cls.vapi.cli(f"lcp create loop1 host-if hloop1 netns {cls.ns_name}")

        cls.vapi.cli("set int ip address loop0 10.10.1.2/24")
        cls.vapi.cli("set int ip address loop1 10.20.1.2/24")

        for lo in cls.lo_interfaces:
            lo.admin_up()

    @classmethod
    def tearDownClass(cls):
        delete_all_namespaces(cls.ns_history_name)
        super(TestLinuxCPRoutes, cls).tearDownClass()

    def route_lookup(self, prefix):
        return self.vapi.api(
            self.vapi.papi.ip_route_lookup,
            {
                "table_id": 0,
                "exact": False,
                "prefix": prefix,
            },
        )

    def get_paths(self, prefix):
        result = []
        route = self.route_lookup(prefix).route
        for path in route.paths:
            d = dict(type=path.type)
            if path.sw_if_index != CLIB_U32_MAX:
                d["sw_if_index"] = path.sw_if_index
            if str(path.nh.address.ip4) != "0.0.0.0":
                d["ip4"] = str(path.nh.address.ip4)
            result.append(d)
        return result

    def verify_paths(self, prefix, *expected_paths):
        for i in range(0, 20):
            paths = self.get_paths(prefix)
            if paths == list(expected_paths):
                break
            self.sleep(0.1)
        else:
            self.assertEqual(paths, expected_paths)

    def test_linux_cp_route(self):
        """Linux CP Route"""
        add_namespace_route(self.ns_name, "default", dev="hloop0", gw_ip="10.10.1.1")
        add_namespace_route(
            self.ns_name, "192.168.100.0/24", dev="hloop1", gw_ip="10.20.1.1"
        )

        self.verify_paths(
            "192.168.1.1/32",
            dict(
                type=FibPathType.FIB_PATH_TYPE_NORMAL,
                sw_if_index=self.lo_interfaces[0].sw_if_index,
                ip4="10.10.1.1",
            ),
        )
        self.verify_paths(
            "192.168.100.1/32",
            dict(
                type=FibPathType.FIB_PATH_TYPE_NORMAL,
                sw_if_index=self.lo_interfaces[1].sw_if_index,
                ip4="10.20.1.1",
            ),
        )

        set_interface_down(self.ns_name, "hloop0")

        self.verify_paths("192.168.1.1/32", dict(type=FibPathType.FIB_PATH_TYPE_DROP))
        self.verify_paths(
            "192.168.100.1/32",
            dict(
                type=FibPathType.FIB_PATH_TYPE_NORMAL,
                sw_if_index=self.lo_interfaces[1].sw_if_index,
                ip4="10.20.1.1",
            ),
        )

        set_interface_down(self.ns_name, "hloop1")

        self.verify_paths("192.168.1.1/32", dict(type=FibPathType.FIB_PATH_TYPE_DROP))
        self.verify_paths("192.168.100.1/32", dict(type=FibPathType.FIB_PATH_TYPE_DROP))

        set_interface_up(self.ns_name, "hloop0")
        set_interface_up(self.ns_name, "hloop1")

    def test_linux_cp_multipath_route(self):
        """Linux CP Multipath Route"""
        add_namespace_multipath_route(
            self.ns_name,
            "default",
            NextHop(gw_ip="10.10.1.1", dev="hloop0"),
            NextHop(gw_ip="10.20.1.1", dev="hloop1"),
        )
        self.verify_paths(
            "192.168.1.1/32",
            dict(
                type=FibPathType.FIB_PATH_TYPE_NORMAL,
                sw_if_index=self.lo_interfaces[0].sw_if_index,
                ip4="10.10.1.1",
            ),
            dict(
                type=FibPathType.FIB_PATH_TYPE_NORMAL,
                sw_if_index=self.lo_interfaces[1].sw_if_index,
                ip4="10.20.1.1",
            ),
        )
        set_interface_down(self.ns_name, "hloop0")
        self.verify_paths(
            "192.168.1.1/32",
            dict(
                type=FibPathType.FIB_PATH_TYPE_NORMAL,
                sw_if_index=self.lo_interfaces[1].sw_if_index,
                ip4="10.20.1.1",
            ),
        )
        set_interface_down(self.ns_name, "hloop1")
        self.verify_paths("192.168.1.1/32", dict(type=FibPathType.FIB_PATH_TYPE_DROP))
        set_interface_up(self.ns_name, "hloop0")
        set_interface_up(self.ns_name, "hloop1")


ISIS_PROTO = 0x83


@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCPOSI(VppTestCase):
    """Linux CP OSI registration and passthrough"""

    extra_vpp_plugin_config = [
        "plugin linux_cp_plugin.so { enable }",
        "plugin linux_cp_unittest_plugin.so { enable }",
    ]

    @classmethod
    def setUpClass(cls):
        super(TestLinuxCPOSI, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestLinuxCPOSI, cls).tearDownClass()

    def tearDown(self):
        self.pair.remove_vpp_config()

        for i in self.pg_interfaces:
            i.admin_down()
        super(TestLinuxCPOSI, self).tearDown()

    def setUp(self):
        super(TestLinuxCPOSI, self).setUp()
        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            i.admin_up()

        self.host = self.pg0
        self.phy = self.pg1

        self.pair = VppLcpPair(self, self.phy, self.host).add_vpp_config()
        self.logger.info(self.vapi.cli("sh lcp"))

    def num_osi_protos_enabled(self):
        reply = self.vapi.lcp_osi_proto_get()
        return reply.count

    def osi_proto_is_enabled(self, proto, expected=True):
        reply = self.vapi.lcp_osi_proto_get()
        self.assertEqual(expected, (proto in reply.osi_protos))
        return reply.count

    def test_linux_cp_osi_registration(self):
        """Linux CP OSI proto registration"""

        VNET_API_ERROR_INVALID_REGISTRATION = -31
        CLNP_PROTO = 0x81
        BAD_OSI_PROTO = 0xFF

        # verify that CLNP is not registered
        count_before = self.osi_proto_is_enabled(CLNP_PROTO, expected=False)

        # register CLNP, verify that it was enabled
        self.vapi.lcp_osi_proto_enable(osi_proto=CLNP_PROTO)
        count_after = self.osi_proto_is_enabled(CLNP_PROTO, expected=True)
        self.assertEqual(count_after, count_before + 1)
        count_before = count_after

        # register an unknown proto, verify that its not enabled
        with self.vapi.assert_negative_api_retval():
            reply = self.vapi.lcp_osi_proto_enable(osi_proto=BAD_OSI_PROTO)
        self.assertEqual(reply.retval, VNET_API_ERROR_INVALID_REGISTRATION)
        count_after = self.osi_proto_is_enabled(BAD_OSI_PROTO, expected=False)
        self.assertEqual(count_before, count_after)

    def send_isis_packets(self, sender, receiver, expect_copy=True):
        # Two cases:
        # - Original ethernet framing (size instead of ethertype)
        # - Ethernet II framing (ethertype containing LLC-Encap ethertype)
        ISIS_ALL_L1 = "01:80:c2:00:00:14"
        LLC_ETHERTYPE = 0x8870
        no_encap = (
            Dot3(src=sender.remote_mac, dst=ISIS_ALL_L1)
            / LLC()
            / ISIS_CommonHdr()
            / ISIS_L1_LAN_Hello(circuittype="L1")
        )
        encap = (
            Ether(src=sender.remote_mac, dst=ISIS_ALL_L1, type=LLC_ETHERTYPE)
            / LLC()
            / ISIS_CommonHdr()
            / ISIS_L1_LAN_Hello(circuittype="L1")
        )
        packets = [no_encap, encap]

        if expect_copy:
            rxs = self.send_and_expect(sender, packets, receiver)
            for rx in rxs:
                if Ether in rx:
                    self.assertEqual(encap.show2(True), rx.show2(True))
                else:
                    self.assertEqual(no_encap.show2(True), rx.show2(True))
        else:
            self.send_and_assert_no_replies(sender, packets)

    def test_linux_cp_osi_passthrough(self):
        """Linux CP OSI proto passthrough"""

        # IS-IS should not be registered yet
        count_before = self.osi_proto_is_enabled(ISIS_PROTO, expected=False)

        # send IS-IS packets in both directions, they should not be forwarded
        self.send_isis_packets(self.phy, self.host, expect_copy=False)
        self.send_isis_packets(self.host, self.phy, expect_copy=False)

        # register IS-IS, verify success
        reply = self.vapi.lcp_osi_proto_enable(osi_proto=ISIS_PROTO)
        count_after = self.osi_proto_is_enabled(ISIS_PROTO, expected=True)
        self.assertEqual(count_after, count_before + 1)

        # re-send IS-IS packets, they should be forwarded now
        self.send_isis_packets(self.phy, self.host, expect_copy=True)
        self.send_isis_packets(self.host, self.phy, expect_copy=True)


@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCPOSINotLoaded(VppTestCase):
    """Linux CP OSI registration without osi_plugin"""

    extra_vpp_plugin_config = [
        "plugin linux_cp_plugin.so { enable }",
        "plugin osi_plugin.so { disable }",
    ]

    VNET_API_ERROR_FEATURE_DISABLED = -30

    @classmethod
    def setUpClass(cls):
        super(TestLinuxCPOSINotLoaded, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestLinuxCPOSINotLoaded, cls).tearDownClass()

    def setUp(self):
        super(TestLinuxCPOSINotLoaded, self).setUp()

    def tearDown(self):
        super(TestLinuxCPOSINotLoaded, self).tearDown()

    def test_linux_cp_osi_not_loaded(self):
        """Linux CP OSI proto registration without osi_plugin"""

        with self.vapi.assert_negative_api_retval():
            reply = self.vapi.lcp_osi_proto_enable(osi_proto=ISIS_PROTO)

        self.assertEqual(reply.retval, self.VNET_API_ERROR_FEATURE_DISABLED)
