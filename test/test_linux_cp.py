#!/usr/bin/env python3
# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, Raw
from scapy.layers.l2 import Ether, ARP, Dot1Q

from util import reassemble4
from vpp_object import VppObject
from framework import VppTestCase, VppTestRunner
from vpp_ipip_tun_interface import VppIpIpTunInterface
from template_ipsec import TemplateIpsec, IpsecTun4Tests, \
    IpsecTun4, mk_scapy_crypt_key, config_tun_params
from template_ipsec import TemplateIpsec, IpsecTun4Tests, \
    IpsecTun4, mk_scapy_crypt_key, config_tun_params
from test_ipsec_tun_if_esp import TemplateIpsecItf4
from vpp_ipsec import VppIpsecSA, VppIpsecTunProtect, VppIpsecInterface


class VppLcpPair(VppObject):
    def __init__(self, test, phy, host):
        self._test = test
        self.phy = phy
        self.host = host

    def add_vpp_config(self):
        self._test.vapi.cli("test lcp add phy %s host %s" %
                            (self.phy, self.host))
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        self._test.vapi.cli("test lcp del phy %s host %s" %
                            (self.phy, self.host))

    def object_id(self):
        return "lcp:%d:%d" % (self.phy.sw_if_index,
                              self.host.sw_if_index)

    def query_vpp_config(self):
        pairs = list(self._test.vapi.vpp.details_iter(
            self._test.vapi.lcp_itf_pair_get))

        for p in pairs:
            if p.phy_sw_if_index == self.phy.sw_if_index and \
               p.host_sw_if_index == self.host.sw_if_index:
                return True
        return False


class TestLinuxCP(VppTestCase):
    """ Linux Control Plane """

    extra_vpp_plugin_config = ["plugin",
                               "linux_cp_plugin.so",
                               "{", "enable", "}",
                               "plugin",
                               "linux_cp_unittest_plugin.so",
                               "{", "enable", "}"]

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
        """ Linux CP TAP """

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
                p = (Ether(src=phy.local_mac,
                           dst=phy.remote_hosts[j].mac) /
                     IP(src=phy.local_ip4,
                        dst=phy.remote_hosts[j].ip4) /
                     UDP(sport=1234, dport=1234) /
                     Raw())

                rxs = self.send_and_expect(host, [p], phy)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

                # ARPs x-connect to phy
                p = (Ether(dst="ff:ff:ff:ff:ff:ff",
                           src=phy.remote_hosts[j].mac) /
                     ARP(op="who-has",
                         hwdst=phy.remote_hosts[j].mac,
                         hwsrc=phy.local_mac,
                         psrc=phy.local_ip4,
                         pdst=phy.remote_hosts[j].ip4))

                rxs = self.send_and_expect(host, [p], phy)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

        # phy to host
        for phy, host in zip(phys, hosts):
            for j in range(N_HOSTS):
                p = (Ether(dst=phy.local_mac,
                           src=phy.remote_hosts[j].mac) /
                     IP(dst=phy.local_ip4,
                        src=phy.remote_hosts[j].ip4) /
                     UDP(sport=1234, dport=1234) /
                     Raw())

                rxs = self.send_and_expect(phy, [p], host)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

                # ARPs rx'd on the phy are sent to the host
                p = (Ether(dst="ff:ff:ff:ff:ff:ff",
                           src=phy.remote_hosts[j].mac) /
                     ARP(op="is-at",
                         hwsrc=phy.remote_hosts[j].mac,
                         hwdst=phy.local_mac,
                         pdst=phy.local_ip4,
                         psrc=phy.remote_hosts[j].ip4))

                rxs = self.send_and_expect(phy, [p], host)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

        # cleanup
        for phy in phys:
            phy.unconfig_ip4()

    def test_linux_cp_tun(self):
        """ Linux CP TUN """

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
            self,
            phy,
            phy.local_ip4,
            phy.remote_ip4).add_vpp_config()
        tun6 = VppIpIpTunInterface(
            self,
            phy,
            phy.local_ip6,
            phy.remote_ip6).add_vpp_config()
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
        p = (IP(src=tun4.local_ip4, dst="2.2.2.2") /
             UDP(sport=1234, dport=1234) /
             Raw())

        rxs = self.send_and_expect(self.pg4, p * N_PKTS, phy)

        # verify inner packet is unchanged and has the tunnel encap
        for rx in rxs:
            self.assertEqual(rx[Ether].dst, phy.remote_mac)
            self.assertEqual(rx[IP].dst, phy.remote_ip4)
            self.assertEqual(rx[IP].src, phy.local_ip4)
            inner = IP(rx[IP].payload)
            self.assertEqual(inner.src, tun4.local_ip4)
            self.assertEqual(inner.dst, "2.2.2.2")

        # host to phy for v6
        p = (IPv6(src=tun6.local_ip6, dst="2::2") /
             UDP(sport=1234, dport=1234) /
             Raw())

        rxs = self.send_and_expect(self.pg5, p * N_PKTS, phy)

        # verify inner packet is unchanged and has the tunnel encap
        for rx in rxs:
            self.assertEqual(rx[IPv6].dst, phy.remote_ip6)
            self.assertEqual(rx[IPv6].src, phy.local_ip6)
            inner = IPv6(rx[IPv6].payload)
            self.assertEqual(inner.src, tun6.local_ip6)
            self.assertEqual(inner.dst, "2::2")

        # phy to host v4
        p = (Ether(dst=phy.local_mac, src=phy.remote_mac) /
             IP(dst=phy.local_ip4, src=phy.remote_ip4) /
             IP(dst=tun4.local_ip4, src=tun4.remote_ip4) /
             UDP(sport=1234, dport=1234) /
             Raw())

        rxs = self.send_and_expect(phy, p * N_PKTS, self.pg4)
        for rx in rxs:
            rx = IP(rx)
            self.assertEqual(rx[IP].dst, tun4.local_ip4)
            self.assertEqual(rx[IP].src, tun4.remote_ip4)

        # phy to host v6
        p = (Ether(dst=phy.local_mac, src=phy.remote_mac) /
             IPv6(dst=phy.local_ip6, src=phy.remote_ip6) /
             IPv6(dst=tun6.local_ip6, src=tun6.remote_ip6) /
             UDP(sport=1234, dport=1234) /
             Raw())

        rxs = self.send_and_expect(phy, p * N_PKTS, self.pg5)
        for rx in rxs:
            rx = IPv6(rx)
            self.assertEqual(rx[IPv6].dst, tun6.local_ip6)
            self.assertEqual(rx[IPv6].src, tun6.remote_ip6)

        # cleanup
        phy.unconfig_ip4()
        phy.unconfig_ip6()

        tun4.unconfig_ip4()
        tun6.unconfig_ip6()


class TestLinuxCPIpsec(TemplateIpsec,
                       TemplateIpsecItf4,
                       IpsecTun4):
    """ IPsec Interface IPv4 """

    extra_vpp_plugin_config = ["plugin",
                               "linux_cp_plugin.so",
                               "{", "enable", "}",
                               "plugin",
                               "linux_cp_unittest_plugin.so",
                               "{", "enable", "}"]

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
            rx = IP(rx)
            self.assert_equal(rx[IP].src, p.tun_if.remote_ip4)
            self.assert_equal(rx[IP].dst, p.tun_if.local_ip4)
            self.assert_packet_checksums_valid(rx)

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1,
                         payload_size=54):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=src, dst=dst) /
                           UDP(sport=1111, dport=2222) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def test_linux_cp_ipsec4_tun(self):
        """ Linux CP Ipsec TUN """

        #
        # Setup
        #
        N_PKTS = 31

        # the pg that paris with the tunnel
        self.host = self.pg3

        # tunnel and protection setup
        p = self.ipv4_params

        self.config_network(p)
        self.config_sa_tun(p,
                           self.pg0.local_ip4,
                           self.pg0.remote_ip4)
        self.config_protect(p)

        pair = VppLcpPair(self, p.tun_if, self.host).add_vpp_config()

        self.logger.error(self.vapi.cli("sh int addr"))
        self.logger.info(self.vapi.cli("sh lcp"))
        self.logger.info(self.vapi.cli("sh ip punt redirect"))

        #
        # Traffic Tests
        #

        # host to phy for v4
        pkt = (IP(src=p.tun_if.local_ip4,
                  dst=p.tun_if.remote_ip4) /
               UDP(sport=1234, dport=1234) /
               Raw())

        rxs = self.send_and_expect(self.host, pkt * N_PKTS, self.tun_if)
        self.verify_encrypted(p, p.vpp_tun_sa, rxs)

        # phy to host for v4
        pkts = self.gen_encrypt_pkts(p, p.scapy_tun_sa, self.tun_if,
                                     src=p.tun_if.remote_ip4,
                                     dst=p.tun_if.local_ip4,
                                     count=N_PKTS)
        try:
            rxs = self.send_and_expect(self.tun_if, pkts, self.host)
            self.verify_decrypted(p, rxs)
        finally:
            self.logger.error(self.vapi.cli("sh trace"))

        # cleanup
        pair.remove_vpp_config()
        self.unconfig_protect(p)
        self.unconfig_sa(p)
        self.unconfig_network(p)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
