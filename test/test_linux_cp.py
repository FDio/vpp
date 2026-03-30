#!/usr/bin/env python3

import unittest
import socket
from ipaddress import ip_address, ip_interface

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
from scapy.contrib.isis import ISIS_CommonHdr, ISIS_L1_LAN_Hello

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
    del_namespace_route,
    add_namespace_address,
    del_namespace_address,
    add_namespace_neighbor,
    del_namespace_neighbor,
    NextHop,
    create_namespace,
    delete_all_namespaces,
    set_interface_up,
    set_interface_down,
    get_interface_addresses,
    interface_exists,
    is_interface_up,
    get_interface_mtu,
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


class TestLinuxCPNetNSBase(VppTestCase):
    """Base class for LCP tests that use real Linux namespaces."""

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
        super().attach_vpp()

    @classmethod
    def run_vpp(cls):
        cls.setUpNetNS()
        super().run_vpp()

    @classmethod
    def tearDownClass(cls):
        delete_all_namespaces(cls.ns_history_name)
        super().tearDownClass()

    def poll_for(self, description, fn, expected, timeout=2.0, interval=0.1):
        """Poll fn() until it returns expected, or fail after timeout."""
        iterations = int(timeout / interval)
        actual = None
        for i in range(iterations):
            actual = fn()
            if actual == expected:
                return
            self.sleep(interval)
        self.assertEqual(actual, expected, description)

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


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestLinuxCPRoutes(TestLinuxCPNetNSBase):
    """Linux CP Routes"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_loopback_interfaces(2)

        cls.vapi.cli(f"lcp create loop0 host-if hloop0 netns {cls.ns_name}")
        cls.vapi.cli(f"lcp create loop1 host-if hloop1 netns {cls.ns_name}")

        cls.vapi.cli("set int ip address loop0 10.10.1.2/24")
        cls.vapi.cli("set int ip address loop1 10.20.1.2/24")

        for lo in cls.lo_interfaces:
            lo.admin_up()

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


def _prefix_tuple(prefix):
    """Split a prefix string like "10.10.1.2/24" into ("10.10.1.2", 24)."""
    iface = ip_interface(prefix)
    return (str(iface.ip), iface.network.prefixlen)


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestLinuxCPSync(TestLinuxCPNetNSBase):
    """Linux CP VPP-to-Linux State Sync"""

    # Addresses assigned to loop0 in the IPv4/IPv6 address sync tests.
    loop0_prefixes_v4 = ["10.10.1.2/24", "10.10.2.2/24"]
    loop0_prefixes_v6 = ["2001:db8:1::2/64", "2001:db8:2::2/64"]
    # State applied to loop0 in the lcp-sync toggle test.
    loop0_toggle_prefix_v4 = "10.30.1.2/24"
    loop0_toggle_mtu = 3000

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_loopback_interfaces(2)
        cls.vapi.cli(f"lcp create loop0 host-if hloop0 netns {cls.ns_name}")
        cls.vapi.cli(f"lcp create loop1 host-if hloop1 netns {cls.ns_name}")

    def _get_ipv6_global_addresses(self, ifname):
        """Get non-link-local IPv6 addresses."""
        addrs = get_interface_addresses(self.ns_name, ifname, family="inet6")
        return sorted(
            [(addr, plen) for addr, plen in addrs if not addr.startswith("fe80:")]
        )

    def _add_addr(self, sw_if_index, prefix):
        self.vapi.sw_interface_add_del_address(sw_if_index=sw_if_index, prefix=prefix)

    def _del_addr(self, sw_if_index, prefix):
        self.vapi.sw_interface_add_del_address(
            sw_if_index=sw_if_index, prefix=prefix, is_add=0
        )

    def test_lcp_sync_admin_state(self):
        """VPP admin state changes sync to Linux"""
        # Loopbacks default to admin-down, so the host side should already
        # be down without waiting.
        self.assertFalse(is_interface_up(self.ns_name, "hloop0"))
        self.assertFalse(is_interface_up(self.ns_name, "hloop1"))

        # Bring loop0 up in VPP, verify Linux side
        self.lo_interfaces[0].admin_up()
        self.poll_for(
            "hloop0 up after VPP admin_up",
            lambda: is_interface_up(self.ns_name, "hloop0"),
            True,
        )
        self.assertFalse(is_interface_up(self.ns_name, "hloop1"))

        # Bring loop0 down in VPP, verify Linux side
        self.lo_interfaces[0].admin_down()
        self.poll_for(
            "hloop0 down after VPP admin_down",
            lambda: is_interface_up(self.ns_name, "hloop0"),
            False,
        )

        # Bring both up
        for lo in self.lo_interfaces:
            lo.admin_up()
        self.poll_for(
            "hloop0 up", lambda: is_interface_up(self.ns_name, "hloop0"), True
        )
        self.poll_for(
            "hloop1 up", lambda: is_interface_up(self.ns_name, "hloop1"), True
        )

        # Bring both down (cleanup)
        for lo in self.lo_interfaces:
            lo.admin_down()
        self.poll_for(
            "hloop0 down", lambda: is_interface_up(self.ns_name, "hloop0"), False
        )
        self.poll_for(
            "hloop1 down", lambda: is_interface_up(self.ns_name, "hloop1"), False
        )

    def test_lcp_sync_mtu(self):
        """VPP MTU changes sync to Linux"""
        loop0 = self.lo_interfaces[0]
        loop0.admin_up()
        self.poll_for(
            "hloop0 up", lambda: is_interface_up(self.ns_name, "hloop0"), True
        )

        for mtu in (4000, 1500, 9000):
            loop0.set_l3_mtu(mtu)
            self.poll_for(
                f"hloop0 mtu {mtu}",
                lambda: get_interface_mtu(self.ns_name, "hloop0"),
                mtu,
            )

        # Cleanup
        loop0.admin_down()

    def test_lcp_sync_ipv4_addr(self):
        """VPP IPv4 address changes sync to Linux"""
        loop0 = self.lo_interfaces[0]
        prefix_a, prefix_b = self.loop0_prefixes_v4
        tuple_a = _prefix_tuple(prefix_a)
        tuple_b = _prefix_tuple(prefix_b)

        loop0.admin_up()
        self.poll_for(
            "hloop0 up", lambda: is_interface_up(self.ns_name, "hloop0"), True
        )

        # Initially no IPv4 addresses
        self.poll_for(
            "hloop0 no initial ipv4",
            lambda: get_interface_addresses(self.ns_name, "hloop0", family="inet"),
            [],
        )

        # Add first IPv4 address
        self._add_addr(loop0.sw_if_index, prefix_a)
        self.poll_for(
            f"hloop0 has {prefix_a}",
            lambda: sorted(
                get_interface_addresses(self.ns_name, "hloop0", family="inet")
            ),
            [tuple_a],
        )

        # Add second IPv4 address
        self._add_addr(loop0.sw_if_index, prefix_b)
        self.poll_for(
            "hloop0 has both ipv4",
            lambda: sorted(
                get_interface_addresses(self.ns_name, "hloop0", family="inet")
            ),
            sorted([tuple_a, tuple_b]),
        )

        # Delete first address
        self._del_addr(loop0.sw_if_index, prefix_a)
        self.poll_for(
            f"hloop0 only {prefix_b}",
            lambda: sorted(
                get_interface_addresses(self.ns_name, "hloop0", family="inet")
            ),
            [tuple_b],
        )

        # Delete second address
        self._del_addr(loop0.sw_if_index, prefix_b)
        self.poll_for(
            "hloop0 no ipv4",
            lambda: get_interface_addresses(self.ns_name, "hloop0", family="inet"),
            [],
        )

        # Cleanup
        loop0.admin_down()

    def test_lcp_sync_ipv6_addr(self):
        """VPP IPv6 address changes sync to Linux"""
        loop0 = self.lo_interfaces[0]
        prefix_a, prefix_b = self.loop0_prefixes_v6
        tuple_a = _prefix_tuple(prefix_a)
        tuple_b = _prefix_tuple(prefix_b)

        loop0.admin_up()
        self.poll_for(
            "hloop0 up", lambda: is_interface_up(self.ns_name, "hloop0"), True
        )

        # Initially no global IPv6 addresses (link-local may exist)
        self.poll_for(
            "hloop0 no initial global ipv6",
            lambda: self._get_ipv6_global_addresses("hloop0"),
            [],
        )

        # Add first IPv6 address
        self._add_addr(loop0.sw_if_index, prefix_a)
        self.poll_for(
            f"hloop0 has {prefix_a}",
            lambda: self._get_ipv6_global_addresses("hloop0"),
            [tuple_a],
        )

        # Add second IPv6 address
        self._add_addr(loop0.sw_if_index, prefix_b)
        self.poll_for(
            "hloop0 has both ipv6",
            lambda: self._get_ipv6_global_addresses("hloop0"),
            sorted([tuple_a, tuple_b]),
        )

        # Delete first address
        self._del_addr(loop0.sw_if_index, prefix_a)
        self.poll_for(
            f"hloop0 only {prefix_b}",
            lambda: self._get_ipv6_global_addresses("hloop0"),
            [tuple_b],
        )

        # Delete second address
        self._del_addr(loop0.sw_if_index, prefix_b)
        self.poll_for(
            "hloop0 no global ipv6",
            lambda: self._get_ipv6_global_addresses("hloop0"),
            [],
        )

        # Cleanup
        loop0.admin_down()

    def test_lcp_sync_toggle(self):
        """Disabling and re-enabling lcp-sync triggers full state push"""
        loop0 = self.lo_interfaces[0]
        prefix = self.loop0_toggle_prefix_v4
        prefix_tuple = _prefix_tuple(prefix)
        mtu = self.loop0_toggle_mtu

        # Disable sync
        self.vapi.cli("lcp lcp-sync off")
        try:
            # Make changes while sync is off
            loop0.admin_up()
            loop0.set_l3_mtu(mtu)
            self._add_addr(loop0.sw_if_index, prefix)

            # Give time for any spurious sync
            self.sleep(0.5)

            # Verify Linux side did NOT get the changes
            self.assertFalse(is_interface_up(self.ns_name, "hloop0"))
            self.assertNotEqual(get_interface_mtu(self.ns_name, "hloop0"), mtu)
            ipv4_addrs = get_interface_addresses(self.ns_name, "hloop0", family="inet")
            self.assertNotIn(prefix_tuple, ipv4_addrs)

            # Re-enable sync (triggers lcp_itf_pair_sync_state_all)
            self.vapi.cli("lcp lcp-sync on")

            # Now poll for the state to appear
            self.poll_for(
                "hloop0 up after re-sync",
                lambda: is_interface_up(self.ns_name, "hloop0"),
                True,
            )
            self.poll_for(
                f"hloop0 mtu {mtu} after re-sync",
                lambda: get_interface_mtu(self.ns_name, "hloop0"),
                mtu,
            )
            self.poll_for(
                f"hloop0 has {prefix} after re-sync",
                lambda: get_interface_addresses(self.ns_name, "hloop0", family="inet"),
                [prefix_tuple],
            )

            # Cleanup VPP state
            self._del_addr(loop0.sw_if_index, prefix)
            loop0.admin_down()
        finally:
            self.vapi.cli("lcp lcp-sync on")


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestLinuxCPLinuxToVPP(TestLinuxCPNetNSBase):
    """Linux CP Linux-to-VPP Sync"""

    # Initial IPv4 assignments so routes/neighbors can be added on the Linux side.
    loop0_prefix_v4 = "10.10.1.2/24"
    loop1_prefix_v4 = "10.20.1.2/24"
    # IPv6 address needed on loop0 for the NDP neighbor test.
    loop0_prefix_v6 = "2001:db8:10::2/64"
    # Neighbors added from the Linux side to verify they sync to VPP.
    loop0_neighbor_v4 = "10.10.1.100"
    loop0_neighbor_v4_mac = "02:01:02:03:04:05"
    loop0_neighbor_v6 = "2001:db8:10::100"
    loop0_neighbor_v6_mac = "02:01:02:03:04:06"
    # Addresses added on the Linux side to verify they sync to VPP.
    loop0_linux_added_v4 = "10.10.5.1/24"
    loop0_linux_added_v6 = "2001:db8:20::1/64"
    # Special route types synced from Linux to VPP.
    route_blackhole = "192.168.50.0/24"
    route_unreachable = "192.168.51.0/24"
    route_prohibit = "192.168.52.0/24"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_loopback_interfaces(2)
        cls.vapi.cli(f"lcp create loop0 host-if hloop0 netns {cls.ns_name}")
        cls.vapi.cli(f"lcp create loop1 host-if hloop1 netns {cls.ns_name}")

        # Configure IPs and bring up so routes/neighbors can be added
        cls.vapi.sw_interface_add_del_address(
            sw_if_index=cls.lo_interfaces[0].sw_if_index, prefix=cls.loop0_prefix_v4
        )
        cls.vapi.sw_interface_add_del_address(
            sw_if_index=cls.lo_interfaces[1].sw_if_index, prefix=cls.loop1_prefix_v4
        )
        for lo in cls.lo_interfaces:
            lo.admin_up()

    def _route_exists(self, prefix):
        """Check if an exact route exists in VPP FIB."""
        try:
            self.vapi.api(
                self.vapi.papi.ip_route_lookup,
                {"table_id": 0, "exact": True, "prefix": prefix},
            )
            return True
        except Exception:
            return False

    def test_linux_to_vpp_route_blackhole(self):
        """Linux blackhole route syncs to VPP as DROP"""
        add_namespace_route(self.ns_name, self.route_blackhole, route_type="blackhole")

        lookup_addr = str(ip_interface(self.route_blackhole).network[1]) + "/32"
        self.verify_paths(lookup_addr, dict(type=FibPathType.FIB_PATH_TYPE_DROP))

        # Verify delete is also synced
        del_namespace_route(self.ns_name, self.route_blackhole)
        self.poll_for(
            "blackhole route removed from VPP",
            lambda: self._route_exists(self.route_blackhole),
            False,
        )

    def test_linux_to_vpp_route_unreachable(self):
        """Linux unreachable route syncs to VPP as ICMP_UNREACH"""
        add_namespace_route(
            self.ns_name, self.route_unreachable, route_type="unreachable"
        )

        lookup_addr = str(ip_interface(self.route_unreachable).network[1]) + "/32"
        self.verify_paths(
            lookup_addr, dict(type=FibPathType.FIB_PATH_TYPE_ICMP_UNREACH)
        )

        # Verify delete is also synced
        del_namespace_route(self.ns_name, self.route_unreachable)
        self.poll_for(
            "unreachable route removed from VPP",
            lambda: self._route_exists(self.route_unreachable),
            False,
        )

    def test_linux_to_vpp_route_prohibit(self):
        """Linux prohibit route syncs to VPP as ICMP_PROHIBIT"""
        add_namespace_route(self.ns_name, self.route_prohibit, route_type="prohibit")

        lookup_addr = str(ip_interface(self.route_prohibit).network[1]) + "/32"
        self.verify_paths(
            lookup_addr, dict(type=FibPathType.FIB_PATH_TYPE_ICMP_PROHIBIT)
        )

        # Verify delete is also synced
        del_namespace_route(self.ns_name, self.route_prohibit)
        self.poll_for(
            "prohibit route removed from VPP",
            lambda: self._route_exists(self.route_prohibit),
            False,
        )

    def _find_neighbor(self, sw_if_index, nbr_addr, mac=None):
        """Find a neighbor entry in VPP regardless of static/dynamic flag."""
        ip_addr = ip_address(nbr_addr)
        nbrs = self.vapi.ip_neighbor_dump(sw_if_index=sw_if_index, af=ip_addr.vapi_af)
        for n in nbrs:
            if (
                sw_if_index == n.neighbor.sw_if_index
                and ip_addr == n.neighbor.ip_address
            ):
                if mac is None or mac == str(n.neighbor.mac_address):
                    return True
        return False

    def test_linux_to_vpp_neighbor_ipv4(self):
        """Linux ARP neighbor entries sync to VPP"""
        lo0_idx = self.lo_interfaces[0].sw_if_index
        nbr = self.loop0_neighbor_v4

        # Add static ARP entry in namespace
        add_namespace_neighbor(self.ns_name, "hloop0", nbr, self.loop0_neighbor_v4_mac)

        self.poll_for(
            f"neighbor {nbr} in VPP",
            lambda: self._find_neighbor(lo0_idx, nbr, mac=self.loop0_neighbor_v4_mac),
            True,
        )

        # Delete the neighbor
        del_namespace_neighbor(self.ns_name, "hloop0", nbr)

        self.poll_for(
            f"neighbor {nbr} removed from VPP",
            lambda: self._find_neighbor(lo0_idx, nbr),
            False,
        )

    def test_linux_to_vpp_neighbor_ipv6(self):
        """Linux NDP neighbor entries sync to VPP"""
        loop0 = self.lo_interfaces[0]
        nbr = self.loop0_neighbor_v6

        # Need an IPv6 address on the interface for NDP
        self.vapi.sw_interface_add_del_address(
            sw_if_index=loop0.sw_if_index, prefix=self.loop0_prefix_v6
        )

        add_namespace_neighbor(self.ns_name, "hloop0", nbr, self.loop0_neighbor_v6_mac)

        self.poll_for(
            f"neighbor {nbr} in VPP",
            lambda: self._find_neighbor(
                loop0.sw_if_index, nbr, mac=self.loop0_neighbor_v6_mac
            ),
            True,
        )

        del_namespace_neighbor(self.ns_name, "hloop0", nbr)

        self.poll_for(
            f"neighbor {nbr} removed from VPP",
            lambda: self._find_neighbor(loop0.sw_if_index, nbr),
            False,
        )

        # Cleanup
        self.vapi.sw_interface_add_del_address(
            sw_if_index=loop0.sw_if_index, prefix=self.loop0_prefix_v6, is_add=0
        )

    def test_linux_to_vpp_ipv4_addr(self):
        """Linux IPv4 address changes sync to VPP"""
        lo0_idx = self.lo_interfaces[0].sw_if_index
        prefix = self.loop0_linux_added_v4

        # Add an address from the Linux side
        add_namespace_address(self.ns_name, "hloop0", prefix)

        self.poll_for(
            f"{prefix} on loop0 in VPP",
            lambda: any(
                str(a.prefix) == prefix
                for a in self.vapi.ip_address_dump(lo0_idx, is_ipv6=False)
            ),
            True,
        )

        # Delete the address from Linux side
        del_namespace_address(self.ns_name, "hloop0", prefix)

        self.poll_for(
            f"{prefix} removed from loop0 in VPP",
            lambda: any(
                str(a.prefix) == prefix
                for a in self.vapi.ip_address_dump(lo0_idx, is_ipv6=False)
            ),
            False,
        )

    def test_linux_to_vpp_ipv6_addr(self):
        """Linux IPv6 address changes sync to VPP"""
        lo0_idx = self.lo_interfaces[0].sw_if_index
        prefix = self.loop0_linux_added_v6

        # Add an IPv6 address from the Linux side
        add_namespace_address(self.ns_name, "hloop0", prefix)

        self.poll_for(
            f"{prefix} on loop0 in VPP",
            lambda: any(
                str(a.prefix) == prefix
                for a in self.vapi.ip_address_dump(lo0_idx, is_ipv6=True)
            ),
            True,
        )

        # Delete the address from Linux side
        del_namespace_address(self.ns_name, "hloop0", prefix)

        self.poll_for(
            f"{prefix} removed from loop0 in VPP",
            lambda: any(
                str(a.prefix) == prefix
                for a in self.vapi.ip_address_dump(lo0_idx, is_ipv6=True)
            ),
            False,
        )


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestLinuxCPPairManagement(TestLinuxCPNetNSBase):
    """Linux CP Interface Pair Management"""

    def _get_lcp_pairs(self):
        """Get all LCP pairs as a list of dicts."""
        return list(self.vapi.vpp.details_iter(self.vapi.lcp_itf_pair_get))

    def _find_lcp_pair(self, phy_sw_if_index):
        """Find an LCP pair by phy sw_if_index."""
        for p in self._get_lcp_pairs():
            if p.phy_sw_if_index == phy_sw_if_index:
                return p
        return None

    def test_pair_create_delete_tun(self):
        """Create and delete TUN LCP pair on loopback"""
        self.create_loopback_interfaces(1)
        lo = self.lo_interfaces[0]

        # Create LCP pair in TUN mode
        self.vapi.cli(f"lcp create {lo.name} host-if htun0 netns {self.ns_name} tun")

        # Verify pair exists in API with correct type
        pair = self._find_lcp_pair(lo.sw_if_index)
        self.assertIsNotNone(pair, "LCP pair should exist")
        self.assertEqual(pair.host_if_name, "htun0")
        self.assertEqual(pair.host_if_type, 1, "host_if_type should be TUN (1)")

        # Verify host interface exists in namespace
        self.assertTrue(
            interface_exists(self.ns_name, "htun0"),
            "htun0 should exist in namespace",
        )

        # Delete the pair
        self.vapi.cli(f"lcp delete {lo.name}")

        # Verify pair is gone
        self.assertIsNone(
            self._find_lcp_pair(lo.sw_if_index),
            "LCP pair should be gone after delete",
        )

        # Verify host interface is gone
        self.poll_for(
            "htun0 gone from namespace",
            lambda: interface_exists(self.ns_name, "htun0"),
            False,
        )

    def test_pair_create_delete_tap(self):
        """Create and delete TAP LCP pair on pg interface"""
        self.create_pg_interfaces(range(1))
        pg = self.pg_interfaces[0]

        # Create LCP pair (TAP mode, default for ethernet)
        self.vapi.cli(f"lcp create {pg.name} host-if htap0 netns {self.ns_name}")

        # Verify pair exists in API with correct type
        pair = self._find_lcp_pair(pg.sw_if_index)
        self.assertIsNotNone(pair, "LCP pair should exist")
        self.assertEqual(pair.host_if_name, "htap0")
        self.assertEqual(pair.host_if_type, 0, "host_if_type should be TAP (0)")

        # Verify host interface exists in namespace
        self.assertTrue(
            interface_exists(self.ns_name, "htap0"),
            "htap0 should exist in namespace",
        )

        # Delete the pair
        self.vapi.cli(f"lcp delete {pg.name}")

        # Verify pair is gone
        self.assertIsNone(
            self._find_lcp_pair(pg.sw_if_index),
            "LCP pair should be gone after delete",
        )

        # Verify host interface is gone
        self.poll_for(
            "htap0 gone from namespace",
            lambda: interface_exists(self.ns_name, "htap0"),
            False,
        )

    def test_pair_vlan_subinterface(self):
        """Create LCP pairs for VLAN sub-interfaces"""
        self.create_pg_interfaces(range(1))
        pg = self.pg_interfaces[0]

        # Create parent LCP pair
        self.vapi.cli(f"lcp create {pg.name} host-if hpg0 netns {self.ns_name}")
        self.assertTrue(interface_exists(self.ns_name, "hpg0"))

        # Create VLAN sub-interface via API (sets exact-match)
        r = self.vapi.create_vlan_subif(pg.sw_if_index, 100)
        sub_sw_if_index = r.sw_if_index

        # Create LCP pair for the sub-interface
        self.vapi.cli(f"lcp create pg0.100 host-if hpg0.100 netns {self.ns_name}")

        # Verify sub-interface pair exists
        pair = self._find_lcp_pair(sub_sw_if_index)
        self.assertIsNotNone(pair, "sub-interface LCP pair should exist")

        # Verify VLAN host interface exists in namespace
        self.poll_for(
            "hpg0.100 exists in namespace",
            lambda: interface_exists(self.ns_name, "hpg0.100"),
            True,
        )

        # Delete sub-interface pair
        self.vapi.cli("lcp delete pg0.100")
        self.assertIsNone(self._find_lcp_pair(sub_sw_if_index))
        self.poll_for(
            "hpg0.100 gone from namespace",
            lambda: interface_exists(self.ns_name, "hpg0.100"),
            False,
        )

        # Clean up
        self.vapi.delete_subif(sub_sw_if_index)
        self.vapi.cli(f"lcp delete {pg.name}")

    def test_pair_auto_subinterface(self):
        """lcp-auto-subint creates pairs automatically for new sub-interfaces"""
        self.create_pg_interfaces(range(1))
        pg = self.pg_interfaces[0]

        # Enable auto sub-interface creation
        self.vapi.cli("lcp lcp-auto-subint on")
        try:
            # Create parent LCP pair
            self.vapi.cli(f"lcp create {pg.name} host-if hauto0 netns {self.ns_name}")
            self.assertTrue(interface_exists(self.ns_name, "hauto0"))

            # Create VLAN sub-interface — LCP pair should be auto-created
            r = self.vapi.create_vlan_subif(pg.sw_if_index, 200)
            sub_sw_if_index = r.sw_if_index

            # Poll for the auto-created LCP pair
            self.poll_for(
                "auto sub-interface LCP pair exists",
                lambda: self._find_lcp_pair(sub_sw_if_index) is not None,
                True,
            )

            # Verify the auto-created host interface name is hauto0.200
            pair = self._find_lcp_pair(sub_sw_if_index)
            self.assertIsNotNone(pair)
            self.assertEqual(
                pair.host_if_name,
                "hauto0.200",
                "auto-created host interface should be named hauto0.200",
            )

            # Verify the VLAN interface exists in namespace
            self.poll_for(
                "hauto0.200 exists in namespace",
                lambda: interface_exists(self.ns_name, "hauto0.200"),
                True,
            )

            # Delete the VPP sub-interface — auto pair should be cleaned up
            self.vapi.delete_subif(sub_sw_if_index)

            self.poll_for(
                "auto sub-interface LCP pair removed",
                lambda: self._find_lcp_pair(sub_sw_if_index) is not None,
                False,
            )

            # Verify the Linux VLAN interface is also removed
            self.poll_for(
                "hauto0.200 gone from namespace",
                lambda: interface_exists(self.ns_name, "hauto0.200"),
                False,
            )

            self.vapi.cli(f"lcp delete {pg.name}")
        finally:
            self.vapi.cli("lcp lcp-auto-subint off")
