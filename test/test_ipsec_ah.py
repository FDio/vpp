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
import socket
import unittest

from scapy.layers.ipsec import AH
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from framework import VppTestRunner
from template_ipsec import TemplateIpsec, IpsecTra46Tests, IpsecTun46Tests, \
    config_tun_params, config_tra_params, IPsecIPv4Params, IPsecIPv6Params, \
    IpsecTra4, IpsecTun4, IpsecTra6, IpsecTun6, \
    IpsecTun6HandoffTests, IpsecTun4HandoffTests
from template_ipsec import IpsecTcpTests
from vpp_ipsec import VppIpsecSA, VppIpsecSpd, VppIpsecSpdEntry,\
        VppIpsecSpdItfBinding
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import DpoProto
from vpp_papi import VppEnum


class ConfigIpsecAH(TemplateIpsec):
    """
    Basic test for IPSEC using AH transport and Tunnel mode

    TRANSPORT MODE::

         ---   encrypt   ---
        |pg2| <-------> |VPP|
         ---   decrypt   ---

    TUNNEL MODE::

         ---   encrypt   ---   plain   ---
        |pg0| <-------  |VPP| <------ |pg1|
         ---             ---           ---

         ---   decrypt   ---   plain   ---
        |pg0| ------->  |VPP| ------> |pg1|
         ---             ---           ---

    """
    encryption_type = AH
    net_objs = []
    tra4_encrypt_node_name = "ah4-encrypt"
    tra4_decrypt_node_name = ["ah4-decrypt", "ah4-decrypt"]
    tra6_encrypt_node_name = "ah6-encrypt"
    tra6_decrypt_node_name = ["ah6-decrypt", "ah6-decrypt"]
    tun4_encrypt_node_name = "ah4-encrypt"
    tun4_decrypt_node_name = ["ah4-decrypt", "ah4-decrypt"]
    tun6_encrypt_node_name = "ah6-encrypt"
    tun6_decrypt_node_name = ["ah6-decrypt", "ah6-decrypt"]

    @classmethod
    def setUpClass(cls):
        super(ConfigIpsecAH, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(ConfigIpsecAH, cls).tearDownClass()

    def setUp(self):
        super(ConfigIpsecAH, self).setUp()

    def tearDown(self):
        super(ConfigIpsecAH, self).tearDown()

    def config_network(self, params):
        self.net_objs = []
        self.tun_if = self.pg0
        self.tra_if = self.pg2
        self.logger.info(self.vapi.ppcli("show int addr"))

        self.tra_spd = VppIpsecSpd(self, self.tra_spd_id)
        self.tra_spd.add_vpp_config()
        self.net_objs.append(self.tra_spd)
        self.tun_spd = VppIpsecSpd(self, self.tun_spd_id)
        self.tun_spd.add_vpp_config()
        self.net_objs.append(self.tun_spd)

        b = VppIpsecSpdItfBinding(self, self.tra_spd,
                                  self.tra_if)
        b.add_vpp_config()
        self.net_objs.append(b)

        b = VppIpsecSpdItfBinding(self, self.tun_spd,
                                  self.tun_if)
        b.add_vpp_config()
        self.net_objs.append(b)

        for p in params:
            self.config_ah_tra(p)
            config_tra_params(p, self.encryption_type)
        for p in params:
            self.config_ah_tun(p)
            config_tun_params(p, self.encryption_type, self.tun_if)
        for p in params:
            d = DpoProto.DPO_PROTO_IP6 if p.is_ipv6 else DpoProto.DPO_PROTO_IP4
            r = VppIpRoute(self,  p.remote_tun_if_host, p.addr_len,
                           [VppRoutePath(self.tun_if.remote_addr[p.addr_type],
                                         0xffffffff,
                                         proto=d)])
            r.add_vpp_config()
            self.net_objs.append(r)
        self.logger.info(self.vapi.ppcli("show ipsec all"))

    def unconfig_network(self):
        for o in reversed(self.net_objs):
            o.remove_vpp_config()
        self.net_objs = []

    def config_ah_tun(self, params):
        addr_type = params.addr_type
        scapy_tun_sa_id = params.scapy_tun_sa_id
        scapy_tun_spi = params.scapy_tun_spi
        vpp_tun_sa_id = params.vpp_tun_sa_id
        vpp_tun_spi = params.vpp_tun_spi
        auth_algo_vpp_id = params.auth_algo_vpp_id
        auth_key = params.auth_key
        crypt_algo_vpp_id = params.crypt_algo_vpp_id
        crypt_key = params.crypt_key
        remote_tun_if_host = params.remote_tun_if_host
        addr_any = params.addr_any
        addr_bcast = params.addr_bcast
        flags = params.flags
        tun_flags = params.tun_flags
        e = VppEnum.vl_api_ipsec_spd_action_t
        objs = []
        params.outer_hop_limit = 253
        params.outer_flow_label = 0x12345

        params.tun_sa_in = VppIpsecSA(self, scapy_tun_sa_id, scapy_tun_spi,
                                      auth_algo_vpp_id, auth_key,
                                      crypt_algo_vpp_id, crypt_key,
                                      self.vpp_ah_protocol,
                                      self.tun_if.local_addr[addr_type],
                                      self.tun_if.remote_addr[addr_type],
                                      tun_flags=tun_flags,
                                      flags=flags,
                                      dscp=params.dscp)

        params.tun_sa_out = VppIpsecSA(self, vpp_tun_sa_id, vpp_tun_spi,
                                       auth_algo_vpp_id, auth_key,
                                       crypt_algo_vpp_id, crypt_key,
                                       self.vpp_ah_protocol,
                                       self.tun_if.remote_addr[addr_type],
                                       self.tun_if.local_addr[addr_type],
                                       tun_flags=tun_flags,
                                       flags=flags,
                                       dscp=params.dscp)

        objs.append(params.tun_sa_in)
        objs.append(params.tun_sa_out)

        params.spd_policy_in_any = VppIpsecSpdEntry(self, self.tun_spd,
                                                    vpp_tun_sa_id,
                                                    addr_any, addr_bcast,
                                                    addr_any, addr_bcast,
                                                    socket.IPPROTO_AH)
        params.spd_policy_out_any = VppIpsecSpdEntry(self, self.tun_spd,
                                                     vpp_tun_sa_id,
                                                     addr_any, addr_bcast,
                                                     addr_any, addr_bcast,
                                                     socket.IPPROTO_AH,
                                                     is_outbound=0)

        objs.append(params.spd_policy_out_any)
        objs.append(params.spd_policy_in_any)

        e1 = VppIpsecSpdEntry(self, self.tun_spd, vpp_tun_sa_id,
                              remote_tun_if_host,
                              remote_tun_if_host,
                              self.pg1.remote_addr[addr_type],
                              self.pg1.remote_addr[addr_type],
                              0, priority=10,
                              policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                              is_outbound=0)
        e2 = VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                              self.pg1.remote_addr[addr_type],
                              self.pg1.remote_addr[addr_type],
                              remote_tun_if_host,
                              remote_tun_if_host,
                              0, policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                              priority=10)
        e3 = VppIpsecSpdEntry(self, self.tun_spd, vpp_tun_sa_id,
                              remote_tun_if_host,
                              remote_tun_if_host,
                              self.pg0.local_addr[addr_type],
                              self.pg0.local_addr[addr_type],
                              0, priority=20,
                              policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                              is_outbound=0)
        e4 = VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                              self.pg0.local_addr[addr_type],
                              self.pg0.local_addr[addr_type],
                              remote_tun_if_host,
                              remote_tun_if_host,
                              0, policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                              priority=20)

        objs = objs + [e1, e2, e3, e4]

        for o in objs:
            o.add_vpp_config()

        self.net_objs = self.net_objs + objs

    def config_ah_tra(self, params):
        addr_type = params.addr_type
        scapy_tra_sa_id = params.scapy_tra_sa_id
        scapy_tra_spi = params.scapy_tra_spi
        vpp_tra_sa_id = params.vpp_tra_sa_id
        vpp_tra_spi = params.vpp_tra_spi
        auth_algo_vpp_id = params.auth_algo_vpp_id
        auth_key = params.auth_key
        crypt_algo_vpp_id = params.crypt_algo_vpp_id
        crypt_key = params.crypt_key
        addr_any = params.addr_any
        addr_bcast = params.addr_bcast
        flags = params.flags | (VppEnum.vl_api_ipsec_sad_flags_t.
                                IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY)
        e = VppEnum.vl_api_ipsec_spd_action_t
        objs = []

        params.tra_sa_in = VppIpsecSA(self, scapy_tra_sa_id, scapy_tra_spi,
                                      auth_algo_vpp_id, auth_key,
                                      crypt_algo_vpp_id, crypt_key,
                                      self.vpp_ah_protocol,
                                      flags=flags)
        params.tra_sa_out = VppIpsecSA(self, vpp_tra_sa_id, vpp_tra_spi,
                                       auth_algo_vpp_id, auth_key,
                                       crypt_algo_vpp_id, crypt_key,
                                       self.vpp_ah_protocol,
                                       flags=flags)

        objs.append(params.tra_sa_in)
        objs.append(params.tra_sa_out)

        objs.append(VppIpsecSpdEntry(self, self.tra_spd, vpp_tra_sa_id,
                                     addr_any, addr_bcast,
                                     addr_any, addr_bcast,
                                     socket.IPPROTO_AH))
        objs.append(VppIpsecSpdEntry(self, self.tra_spd, scapy_tra_sa_id,
                                     addr_any, addr_bcast,
                                     addr_any, addr_bcast,
                                     socket.IPPROTO_AH,
                                     is_outbound=0))
        objs.append(VppIpsecSpdEntry(self, self.tra_spd, vpp_tra_sa_id,
                                     self.tra_if.local_addr[addr_type],
                                     self.tra_if.local_addr[addr_type],
                                     self.tra_if.remote_addr[addr_type],
                                     self.tra_if.remote_addr[addr_type],
                                     0, priority=10,
                                     policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                                     is_outbound=0))
        objs.append(VppIpsecSpdEntry(self, self.tra_spd, scapy_tra_sa_id,
                                     self.tra_if.local_addr[addr_type],
                                     self.tra_if.local_addr[addr_type],
                                     self.tra_if.remote_addr[addr_type],
                                     self.tra_if.remote_addr[addr_type],
                                     0, policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                                     priority=10))

        for o in objs:
            o.add_vpp_config()
        self.net_objs = self.net_objs + objs


class TemplateIpsecAh(ConfigIpsecAH):
    """
    Basic test for IPSEC using AH transport and Tunnel mode

    TRANSPORT MODE::

         ---   encrypt   ---
        |pg2| <-------> |VPP|
         ---   decrypt   ---

    TUNNEL MODE::

         ---   encrypt   ---   plain   ---
        |pg0| <-------  |VPP| <------ |pg1|
         ---             ---           ---

         ---   decrypt   ---   plain   ---
        |pg0| ------->  |VPP| ------> |pg1|
         ---             ---           ---

    """
    @classmethod
    def setUpClass(cls):
        super(TemplateIpsecAh, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TemplateIpsecAh, cls).tearDownClass()

    def setUp(self):
        super(TemplateIpsecAh, self).setUp()
        self.config_network(self.params.values())

    def tearDown(self):
        self.unconfig_network()
        super(TemplateIpsecAh, self).tearDown()


class TestIpsecAh1(TemplateIpsecAh, IpsecTcpTests):
    """ Ipsec AH - TCP tests """
    pass


class TestIpsecAh2(TemplateIpsecAh, IpsecTra46Tests, IpsecTun46Tests):
    """ Ipsec AH w/ SHA1 """
    pass


class TestIpsecAhTun(TemplateIpsecAh, IpsecTun46Tests):
    """ Ipsec AH - TUN encap tests """

    def setUp(self):
        self.ipv4_params = IPsecIPv4Params()
        self.ipv6_params = IPsecIPv6Params()

        c = (VppEnum.vl_api_tunnel_encap_decap_flags_t.
             TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP)
        c1 = c | (VppEnum.vl_api_tunnel_encap_decap_flags_t.
                  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN)

        self.ipv4_params.tun_flags = c
        self.ipv6_params.tun_flags = c1

        super(TestIpsecAhTun, self).setUp()

    def gen_pkts(self, sw_intf, src, dst, count=1, payload_size=54):
        # set the DSCP + ECN - flags are set to copy only DSCP
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IP(src=src, dst=dst, tos=5) /
                UDP(sport=4444, dport=4444) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def gen_pkts6(self, p, sw_intf, src, dst, count=1, payload_size=54):
        # set the DSCP + ECN - flags are set to copy both
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IPv6(src=src, dst=dst, tc=5) /
                UDP(sport=4444, dport=4444) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_encrypted(self, p, sa, rxs):
        # just check that only the DSCP is copied
        for rx in rxs:
            self.assertEqual(rx[IP].tos, 4)

    def verify_encrypted6(self, p, sa, rxs):
        # just check that the DSCP & ECN are copied
        for rx in rxs:
            self.assertEqual(rx[IPv6].tc, 5)


class TestIpsecAhTun2(TemplateIpsecAh, IpsecTun46Tests):
    """ Ipsec AH - TUN encap tests """

    def setUp(self):
        self.ipv4_params = IPsecIPv4Params()
        self.ipv6_params = IPsecIPv6Params()

        self.ipv4_params.dscp = 3
        self.ipv6_params.dscp = 4

        super(TestIpsecAhTun2, self).setUp()

    def gen_pkts(self, sw_intf, src, dst, count=1, payload_size=54):
        # set the DSCP + ECN - flags are set to copy only DSCP
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IP(src=src, dst=dst, tos=0) /
                UDP(sport=4444, dport=4444) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def gen_pkts6(self, p, sw_intf, src, dst, count=1, payload_size=54):
        # set the DSCP + ECN - flags are set to copy both
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IPv6(src=src, dst=dst, tc=0) /
                UDP(sport=4444, dport=4444) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_encrypted(self, p, sa, rxs):
        # just check that only the DSCP is copied
        for rx in rxs:
            self.assertEqual(rx[IP].tos, 0xc)

    def verify_encrypted6(self, p, sa, rxs):
        # just check that the DSCP & ECN are copied
        for rx in rxs:
            self.assertEqual(rx[IPv6].tc, 0x10)


class TestIpsecAhHandoff(TemplateIpsecAh,
                         IpsecTun6HandoffTests,
                         IpsecTun4HandoffTests):
    """ Ipsec AH Handoff """
    pass


class TestIpsecAhAll(ConfigIpsecAH,
                     IpsecTra4, IpsecTra6,
                     IpsecTun4, IpsecTun6):
    """ Ipsec AH all Algos """

    def setUp(self):
        super(TestIpsecAhAll, self).setUp()

    def tearDown(self):
        super(TestIpsecAhAll, self).tearDown()

    def test_integ_algs(self):
        """All Engines SHA[1_96, 256, 384, 512] w/ & w/o ESN"""
        # foreach VPP crypto engine
        engines = ["ia32", "ipsecmb", "openssl"]

        algos = [{'vpp': VppEnum.vl_api_ipsec_integ_alg_t.
                  IPSEC_API_INTEG_ALG_SHA1_96,
                  'scapy': "HMAC-SHA1-96"},
                 {'vpp': VppEnum.vl_api_ipsec_integ_alg_t.
                  IPSEC_API_INTEG_ALG_SHA_256_128,
                  'scapy': "SHA2-256-128"},
                 {'vpp': VppEnum.vl_api_ipsec_integ_alg_t.
                  IPSEC_API_INTEG_ALG_SHA_384_192,
                  'scapy': "SHA2-384-192"},
                 {'vpp': VppEnum.vl_api_ipsec_integ_alg_t.
                  IPSEC_API_INTEG_ALG_SHA_512_256,
                  'scapy': "SHA2-512-256"}]

        flags = [0, (VppEnum.vl_api_ipsec_sad_flags_t.
                     IPSEC_API_SAD_FLAG_USE_ESN)]

        #
        # loop through the VPP engines
        #
        for engine in engines:
            self.vapi.cli("set crypto handler all %s" % engine)
            #
            # loop through each of the algorithms
            #
            for algo in algos:
                # with self.subTest(algo=algo['scapy']):
                for flag in flags:
                    #
                    # setup up the config paramters
                    #
                    self.ipv4_params = IPsecIPv4Params()
                    self.ipv6_params = IPsecIPv6Params()

                    self.params = {self.ipv4_params.addr_type:
                                   self.ipv4_params,
                                   self.ipv6_params.addr_type:
                                   self.ipv6_params}

                    for _, p in self.params.items():
                        p.auth_algo_vpp_id = algo['vpp']
                        p.auth_algo = algo['scapy']
                        p.flags = p.flags | flag

                    #
                    # configure the SPDs. SAs, etc
                    #
                    self.config_network(self.params.values())

                    #
                    # run some traffic.
                    #  An exhautsive 4o6, 6o4 is not necessary for each algo
                    #
                    self.verify_tra_basic6(count=17)
                    self.verify_tra_basic4(count=17)
                    self.verify_tun_66(self.params[socket.AF_INET6], count=17)
                    self.verify_tun_44(self.params[socket.AF_INET], count=17)

                    #
                    # remove the SPDs, SAs, etc
                    #
                    self.unconfig_network()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
