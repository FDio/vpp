#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner, is_skip_aarch64_set, \
    is_platform_aarch64
from vpp_object import VppObject
from vpp_neighbor import VppNeighbor
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable, \
    VppIpInterfaceAddress, VppIpInterfaceBind, find_route
from vpp_l2 import VppBridgeDomain, VppBridgeDomainPort, \
    VppBridgeDomainArpEntry, VppL2FibEntry, find_bridge_domain_port
from vpp_vxlan_gbp_tunnel import *
from vpp_sub_interface import VppDot1QSubint

from vpp_ip import *
from vpp_papi_provider import L2_PORT_TYPE
from vpp_papi import VppEnum, MACAddress

from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP, Dot1Q
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS,  ICMPv6NDOptSrcLLAddr, \
    ICMPv6ND_NA
from scapy.utils6 import in6_getnsma, in6_getnsmac
from scapy.layers.vxlan import VXLAN
from scapy.data import ETH_P_IP, ETH_P_IPV6

from socket import AF_INET, AF_INET6
from scapy.utils import inet_pton, inet_ntop
from vpp_papi_provider import L2_VTR_OP


def find_gbp_endpoint(test, sw_if_index=None, ip=None, mac=None):
    if ip:
        vip = VppIpAddress(ip)
    if mac:
        vmac = MACAddress(mac)

    eps = test.vapi.gbp_endpoint_dump()

    for ep in eps:
        if sw_if_index:
            if ep.endpoint.sw_if_index != sw_if_index:
                continue
        if ip:
            for eip in ep.endpoint.ips:
                if vip == eip:
                    return True
        if mac:
            if vmac.packed == ep.endpoint.mac:
                return True
    return False


def find_gbp_vxlan(test, vni):
    ts = test.vapi.gbp_vxlan_tunnel_dump()
    for t in ts:
        if t.tunnel.vni == vni:
            return True
    return False


class VppGbpEndpoint(VppObject):
    """
    GBP Endpoint
    """

    @property
    def mac(self):
        return str(self.vmac)

    @property
    def mac(self):
        return self.itf.remote_mac

    @property
    def ip4(self):
        return self._ip4

    @property
    def fip4(self):
        return self._fip4

    @property
    def ip6(self):
        return self._ip6

    @property
    def fip6(self):
        return self._fip6

    @property
    def ips(self):
        return [self.ip4, self.ip6]

    @property
    def fips(self):
        return [self.fip4, self.fip6]

    def __init__(self, test, itf, epg, recirc, ip4, fip4, ip6, fip6,
                 flags=0,
                 tun_src="0.0.0.0",
                 tun_dst="0.0.0.0",
                 mac=True):
        self._test = test
        self.itf = itf
        self.epg = epg
        self.recirc = recirc

        self._ip4 = VppIpAddress(ip4)
        self._fip4 = VppIpAddress(fip4)
        self._ip6 = VppIpAddress(ip6)
        self._fip6 = VppIpAddress(fip6)

        if mac:
            self.vmac = MACAddress(self.itf.remote_mac)
        else:
            self.vmac = MACAddress("00:00:00:00:00:00")

        self.flags = flags
        self.tun_src = VppIpAddress(tun_src)
        self.tun_dst = VppIpAddress(tun_dst)

    def add_vpp_config(self):
        res = self._test.vapi.gbp_endpoint_add(
            self.itf.sw_if_index,
            [self.ip4.encode(), self.ip6.encode()],
            self.vmac.packed,
            self.epg.epg,
            self.flags,
            self.tun_src.encode(),
            self.tun_dst.encode())
        self.handle = res.handle
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_endpoint_del(self.handle)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-endpoint:[%d==%d:%s:%d]" % (self.handle,
                                                self.itf.sw_if_index,
                                                self.ip4.address,
                                                self.epg.epg)

    def query_vpp_config(self):
        return find_gbp_endpoint(self._test,
                                 self.itf.sw_if_index,
                                 self.ip4.address)


class VppGbpRecirc(VppObject):
    """
    GBP Recirculation Interface
    """

    def __init__(self, test, epg, recirc, is_ext=False):
        self._test = test
        self.recirc = recirc
        self.epg = epg
        self.is_ext = is_ext

    def add_vpp_config(self):
        self._test.vapi.gbp_recirc_add_del(
            1,
            self.recirc.sw_if_index,
            self.epg.epg,
            self.is_ext)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_recirc_add_del(
            0,
            self.recirc.sw_if_index,
            self.epg.epg,
            self.is_ext)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-recirc:[%d]" % (self.recirc.sw_if_index)

    def query_vpp_config(self):
        rs = self._test.vapi.gbp_recirc_dump()
        for r in rs:
            if r.recirc.sw_if_index == self.recirc.sw_if_index:
                return True
        return False


class VppGbpExtItf(VppObject):
    """
    GBP ExtItfulation Interface
    """

    def __init__(self, test, itf, bd, rd):
        self._test = test
        self.itf = itf
        self.bd = bd
        self.rd = rd

    def add_vpp_config(self):
        self._test.vapi.gbp_ext_itf_add_del(
            1,
            self.itf.sw_if_index,
            self.bd.bd_id,
            self.rd.rd_id)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_ext_itf_add_del(
            0,
            self.itf.sw_if_index,
            self.bd.bd_id,
            self.rd.rd_id)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-ext-itf:[%d]" % (self.itf.sw_if_index)

    def query_vpp_config(self):
        rs = self._test.vapi.gbp_ext_itf_dump()
        for r in rs:
            if r.ext_itf.sw_if_index == self.itf.sw_if_index:
                return True
        return False


class VppGbpSubnet(VppObject):
    """
    GBP Subnet
    """
    def __init__(self, test, rd, address, address_len,
                 type, sw_if_index=None, epg=None):
        self._test = test
        self.rd_id = rd.rd_id
        self.prefix = VppIpPrefix(address, address_len)
        self.type = type
        self.sw_if_index = sw_if_index
        self.epg = epg

    def add_vpp_config(self):
        self._test.vapi.gbp_subnet_add_del(
            1,
            self.rd_id,
            self.prefix.encode(),
            self.type,
            sw_if_index=self.sw_if_index if self.sw_if_index else 0xffffffff,
            epg_id=self.epg if self.epg else 0xffff)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_subnet_add_del(
            0,
            self.rd_id,
            self.prefix.encode(),
            self.type)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-subnet:[%d-%s]" % (self.rd_id, self.prefix)

    def query_vpp_config(self):
        ss = self._test.vapi.gbp_subnet_dump()
        for s in ss:
            if s.subnet.rd_id == self.rd_id and \
               s.subnet.type == self.type and \
               s.subnet.prefix == self.prefix:
                return True
        return False


class VppGbpEndpointGroup(VppObject):
    """
    GBP Endpoint Group
    """

    def __init__(self, test, epg, rd, bd, uplink,
                 bvi, bvi_ip4, bvi_ip6=None):
        self._test = test
        self.uplink = uplink
        self.bvi = bvi
        self.bvi_ip4 = VppIpAddress(bvi_ip4)
        self.bvi_ip6 = VppIpAddress(bvi_ip6)
        self.epg = epg
        self.bd = bd
        self.rd = rd

    def add_vpp_config(self):
        self._test.vapi.gbp_endpoint_group_add(
            self.epg,
            self.bd.bd.bd_id,
            self.rd.rd_id,
            self.uplink.sw_if_index if self.uplink else INDEX_INVALID)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_endpoint_group_del(
            self.epg)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-endpoint-group:[%d]" % (self.epg)

    def query_vpp_config(self):
        epgs = self._test.vapi.gbp_endpoint_group_dump()
        for epg in epgs:
            if epg.epg.epg_id == self.epg:
                return True
        return False


class VppGbpBridgeDomain(VppObject):
    """
    GBP Bridge Domain
    """

    def __init__(self, test, bd, bvi, uu_flood=None, learn=True):
        self._test = test
        self.bvi = bvi
        self.uu_flood = uu_flood
        self.bd = bd

        e = VppEnum.vl_api_gbp_bridge_domain_flags_t
        if (learn):
            self.learn = e.GBP_BD_API_FLAG_NONE
        else:
            self.learn = e.GBP_BD_API_FLAG_DO_NOT_LEARN

    def add_vpp_config(self):
        self._test.vapi.gbp_bridge_domain_add(
            self.bd.bd_id,
            self.learn,
            self.bvi.sw_if_index,
            self.uu_flood.sw_if_index if self.uu_flood else INDEX_INVALID)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_bridge_domain_del(self.bd.bd_id)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-bridge-domain:[%d]" % (self.bd.bd_id)

    def query_vpp_config(self):
        bds = self._test.vapi.gbp_bridge_domain_dump()
        for bd in bds:
            if bd.bd.bd_id == self.bd.bd_id:
                return True
        return False


class VppGbpRouteDomain(VppObject):
    """
    GBP Route Domain
    """

    def __init__(self, test, rd_id, t4, t6, ip4_uu=None, ip6_uu=None):
        self._test = test
        self.rd_id = rd_id
        self.t4 = t4
        self.t6 = t6
        self.ip4_uu = ip4_uu
        self.ip6_uu = ip6_uu

    def add_vpp_config(self):
        self._test.vapi.gbp_route_domain_add(
            self.rd_id,
            self.t4.table_id,
            self.t6.table_id,
            self.ip4_uu.sw_if_index if self.ip4_uu else INDEX_INVALID,
            self.ip6_uu.sw_if_index if self.ip6_uu else INDEX_INVALID)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_route_domain_del(self.rd_id)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-route-domain:[%d]" % (self.rd_id)

    def query_vpp_config(self):
        rds = self._test.vapi.gbp_route_domain_dump()
        for rd in rds:
            if rd.rd.rd_id == self.rd_id:
                return True
        return False


class VppGbpContractNextHop():
    def __init__(self, mac, bd, ip, rd):
        self.mac = mac
        self.ip = ip
        self.bd = bd
        self.rd = rd

    def encode(self):
        return {'ip': self.ip.encode(),
                'mac': self.mac.packed,
                'bd_id': self.bd.bd.bd_id,
                'rd_id': self.rd.rd_id}


class VppGbpContractRule():
    def __init__(self, action, hash_mode, nhs=[]):
        self.action = action
        self.hash_mode = hash_mode
        self.nhs = nhs

    def encode(self):
        nhs = []
        for nh in self.nhs:
            nhs.append(nh.encode())
        while len(nhs) < 8:
            nhs.append({})
        return {'action': self.action,
                'nh_set': {
                    'hash_mode': self.hash_mode,
                    'n_nhs': len(self.nhs),
                    'nhs': nhs}}


class VppGbpContract(VppObject):
    """
    GBP Contract
    """

    def __init__(self, test, src_epg, dst_epg, acl_index,
                 rules, allowed_ethertypes):
        self._test = test
        self.acl_index = acl_index
        self.src_epg = src_epg
        self.dst_epg = dst_epg
        self.rules = rules
        self.allowed_ethertypes = allowed_ethertypes

    def add_vpp_config(self):
        rules = []
        for r in self.rules:
            rules.append(r.encode())
        self._test.vapi.gbp_contract_add_del(
            1,
            self.src_epg,
            self.dst_epg,
            self.acl_index,
            rules,
            self.allowed_ethertypes)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_contract_add_del(
            0,
            self.src_epg,
            self.dst_epg,
            self.acl_index,
            [], [])

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-contract:[%d:%s:%d]" % (self.src_epg,
                                            self.dst_epg,
                                            self.acl_index)

    def query_vpp_config(self):
        cs = self._test.vapi.gbp_contract_dump()
        for c in cs:
            if c.contract.src_epg == self.src_epg \
               and c.contract.dst_epg == self.dst_epg:
                return True
        return False


class VppGbpVxlanTunnel(VppInterface):
    """
    GBP VXLAN tunnel
    """

    def __init__(self, test, vni, bd_rd_id, mode):
        super(VppGbpVxlanTunnel, self).__init__(test)
        self._test = test
        self.vni = vni
        self.bd_rd_id = bd_rd_id
        self.mode = mode

    def add_vpp_config(self):
        r = self._test.vapi.gbp_vxlan_tunnel_add(
            self.vni,
            self.bd_rd_id,
            self.mode)
        self.set_sw_if_index(r.sw_if_index)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_vxlan_tunnel_del(self.vni)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-vxlan:%d" % (self.vni)

    def query_vpp_config(self):
        return find_gbp_vxlan(self._test, self.vni)


class VppGbpAcl(VppObject):
    """
    GBP Acl
    """

    def __init__(self, test):
        self._test = test
        self.acl_index = 4294967295

    def create_rule(self, is_ipv6=0, permit_deny=0, proto=-1,
                    s_prefix=0, s_ip='\x00\x00\x00\x00', sport_from=0,
                    sport_to=65535, d_prefix=0, d_ip='\x00\x00\x00\x00',
                    dport_from=0, dport_to=65535):
        if proto == -1 or proto == 0:
            sport_to = 0
            dport_to = sport_to
        elif proto == 1 or proto == 58:
            sport_to = 255
            dport_to = sport_to
        rule = ({'is_permit': permit_deny, 'is_ipv6': is_ipv6, 'proto': proto,
                 'srcport_or_icmptype_first': sport_from,
                 'srcport_or_icmptype_last': sport_to,
                 'src_ip_prefix_len': s_prefix,
                 'src_ip_addr': s_ip,
                 'dstport_or_icmpcode_first': dport_from,
                 'dstport_or_icmpcode_last': dport_to,
                 'dst_ip_prefix_len': d_prefix,
                 'dst_ip_addr': d_ip})
        return rule

    def add_vpp_config(self, rules):

        reply = self._test.vapi.acl_add_replace(self.acl_index,
                                                r=rules,
                                                tag='GBPTest')
        self.acl_index = reply.acl_index
        return self.acl_index

    def remove_vpp_config(self):
        self._test.vapi.acl_del(self.acl_index)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-acl:[%d]" % (self.acl_index)

    def query_vpp_config(self):
        cs = self._test.vapi.acl_dump()
        for c in cs:
            if c.acl_index == self.acl_index:
                return True
        return False


class TestGBP(VppTestCase):
    """ GBP Test Case """

    def setUp(self):
        super(TestGBP, self).setUp()

        self.create_pg_interfaces(range(9))
        self.create_loopback_interfaces(8)

        self.router_mac = MACAddress("00:11:22:33:44:55")

        for i in self.pg_interfaces:
            i.admin_up()
        for i in self.lo_interfaces:
            i.admin_up()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()

        super(TestGBP, self).tearDown()

    def send_and_expect_bridged(self, src, tx, dst):
        rx = self.send_and_expect(src, tx, dst)

        for r in rx:
            self.assertEqual(r[Ether].src, tx[0][Ether].src)
            self.assertEqual(r[Ether].dst, tx[0][Ether].dst)
            self.assertEqual(r[IP].src, tx[0][IP].src)
            self.assertEqual(r[IP].dst, tx[0][IP].dst)
        return rx

    def send_and_expect_bridged6(self, src, tx, dst):
        rx = self.send_and_expect(src, tx, dst)

        for r in rx:
            self.assertEqual(r[Ether].src, tx[0][Ether].src)
            self.assertEqual(r[Ether].dst, tx[0][Ether].dst)
            self.assertEqual(r[IPv6].src, tx[0][IPv6].src)
            self.assertEqual(r[IPv6].dst, tx[0][IPv6].dst)
        return rx

    def send_and_expect_routed(self, src, tx, dst, src_mac):
        rx = self.send_and_expect(src, tx, dst)

        for r in rx:
            self.assertEqual(r[Ether].src, src_mac)
            self.assertEqual(r[Ether].dst, dst.remote_mac)
            self.assertEqual(r[IP].src, tx[0][IP].src)
            self.assertEqual(r[IP].dst, tx[0][IP].dst)
        return rx

    def send_and_expect_natted(self, src, tx, dst, src_ip):
        rx = self.send_and_expect(src, tx, dst)

        for r in rx:
            self.assertEqual(r[Ether].src, tx[0][Ether].src)
            self.assertEqual(r[Ether].dst, tx[0][Ether].dst)
            self.assertEqual(r[IP].src, src_ip)
            self.assertEqual(r[IP].dst, tx[0][IP].dst)
        return rx

    def send_and_expect_natted6(self, src, tx, dst, src_ip):
        rx = self.send_and_expect(src, tx, dst)

        for r in rx:
            self.assertEqual(r[Ether].src, tx[0][Ether].src)
            self.assertEqual(r[Ether].dst, tx[0][Ether].dst)
            self.assertEqual(r[IPv6].src, src_ip)
            self.assertEqual(r[IPv6].dst, tx[0][IPv6].dst)
        return rx

    def send_and_expect_unnatted(self, src, tx, dst, dst_ip):
        rx = self.send_and_expect(src, tx, dst)

        for r in rx:
            self.assertEqual(r[Ether].src, tx[0][Ether].src)
            self.assertEqual(r[Ether].dst, tx[0][Ether].dst)
            self.assertEqual(r[IP].dst, dst_ip)
            self.assertEqual(r[IP].src, tx[0][IP].src)
        return rx

    def send_and_expect_unnatted6(self, src, tx, dst, dst_ip):
        rx = self.send_and_expect(src, tx, dst)

        for r in rx:
            self.assertEqual(r[Ether].src, tx[0][Ether].src)
            self.assertEqual(r[Ether].dst, tx[0][Ether].dst)
            self.assertEqual(r[IPv6].dst, dst_ip)
            self.assertEqual(r[IPv6].src, tx[0][IPv6].src)
        return rx

    def send_and_expect_double_natted(self, src, tx, dst, src_ip, dst_ip):
        rx = self.send_and_expect(src, tx, dst)

        for r in rx:
            self.assertEqual(r[Ether].src, str(self.router_mac))
            self.assertEqual(r[Ether].dst, dst.remote_mac)
            self.assertEqual(r[IP].dst, dst_ip)
            self.assertEqual(r[IP].src, src_ip)
        return rx

    def send_and_expect_double_natted6(self, src, tx, dst, src_ip, dst_ip):
        rx = self.send_and_expect(src, tx, dst)

        for r in rx:
            self.assertEqual(r[Ether].src, str(self.router_mac))
            self.assertEqual(r[Ether].dst, dst.remote_mac)
            self.assertEqual(r[IPv6].dst, dst_ip)
            self.assertEqual(r[IPv6].src, src_ip)
        return rx

    def test_gbp(self):
        """ Group Based Policy """

        ep_flags = VppEnum.vl_api_gbp_endpoint_flags_t

        #
        # Bridge Domains
        #
        bd1 = VppBridgeDomain(self, 1)
        bd2 = VppBridgeDomain(self, 2)
        bd20 = VppBridgeDomain(self, 20)

        bd1.add_vpp_config()
        bd2.add_vpp_config()
        bd20.add_vpp_config()

        gbd1 = VppGbpBridgeDomain(self, bd1, self.loop0)
        gbd2 = VppGbpBridgeDomain(self, bd2, self.loop1)
        gbd20 = VppGbpBridgeDomain(self, bd20, self.loop2)

        gbd1.add_vpp_config()
        gbd2.add_vpp_config()
        gbd20.add_vpp_config()

        #
        # Route Domains
        #
        gt4 = VppIpTable(self, 0)
        gt4.add_vpp_config()
        gt6 = VppIpTable(self, 0, is_ip6=True)
        gt6.add_vpp_config()
        nt4 = VppIpTable(self, 20)
        nt4.add_vpp_config()
        nt6 = VppIpTable(self, 20, is_ip6=True)
        nt6.add_vpp_config()

        rd0 = VppGbpRouteDomain(self, 0, gt4, gt6, None, None)
        rd20 = VppGbpRouteDomain(self, 20, nt4, nt6, None, None)

        rd0.add_vpp_config()
        rd20.add_vpp_config()

        #
        # 3 EPGs, 2 of which share a BD.
        # 2 NAT EPGs, one for floating-IP subnets, the other for internet
        #
        epgs = [VppGbpEndpointGroup(self, 220, rd0, gbd1, self.pg4,
                                    self.loop0,
                                    "10.0.0.128",
                                    "2001:10::128"),
                VppGbpEndpointGroup(self, 221, rd0, gbd1, self.pg5,
                                    self.loop0,
                                    "10.0.1.128",
                                    "2001:10:1::128"),
                VppGbpEndpointGroup(self, 222, rd0, gbd2, self.pg6,
                                    self.loop1,
                                    "10.0.2.128",
                                    "2001:10:2::128"),
                VppGbpEndpointGroup(self, 333, rd20, gbd20, self.pg7,
                                    self.loop2,
                                    "11.0.0.128",
                                    "3001::128"),
                VppGbpEndpointGroup(self, 444, rd20, gbd20, self.pg8,
                                    self.loop2,
                                    "11.0.0.129",
                                    "3001::129")]
        recircs = [VppGbpRecirc(self, epgs[0],
                                self.loop3),
                   VppGbpRecirc(self, epgs[1],
                                self.loop4),
                   VppGbpRecirc(self, epgs[2],
                                self.loop5),
                   VppGbpRecirc(self, epgs[3],
                                self.loop6, is_ext=True),
                   VppGbpRecirc(self, epgs[4],
                                self.loop7, is_ext=True)]

        epg_nat = epgs[3]
        recirc_nat = recircs[3]

        #
        # 4 end-points, 2 in the same subnet, 3 in the same BD
        #
        eps = [VppGbpEndpoint(self, self.pg0,
                              epgs[0], recircs[0],
                              "10.0.0.1", "11.0.0.1",
                              "2001:10::1", "3001::1"),
               VppGbpEndpoint(self, self.pg1,
                              epgs[0], recircs[0],
                              "10.0.0.2", "11.0.0.2",
                              "2001:10::2", "3001::2"),
               VppGbpEndpoint(self, self.pg2,
                              epgs[1], recircs[1],
                              "10.0.1.1", "11.0.0.3",
                              "2001:10:1::1", "3001::3"),
               VppGbpEndpoint(self, self.pg3,
                              epgs[2], recircs[2],
                              "10.0.2.1", "11.0.0.4",
                              "2001:10:2::1", "3001::4")]

        #
        # Config related to each of the EPGs
        #
        for epg in epgs:
            # IP config on the BVI interfaces
            if epg != epgs[1] and epg != epgs[4]:
                VppIpInterfaceBind(self, epg.bvi, epg.rd.t4).add_vpp_config()
                VppIpInterfaceBind(self, epg.bvi, epg.rd.t6).add_vpp_config()
                self.vapi.sw_interface_set_mac_address(
                    epg.bvi.sw_if_index,
                    self.router_mac.packed)

                # The BVIs are NAT inside interfaces
                self.vapi.nat44_interface_add_del_feature(epg.bvi.sw_if_index,
                                                          is_inside=1,
                                                          is_add=1)
                self.vapi.nat66_add_del_interface(epg.bvi.sw_if_index,
                                                  is_inside=1,
                                                  is_add=1)

            if_ip4 = VppIpInterfaceAddress(self, epg.bvi, epg.bvi_ip4, 32)
            if_ip6 = VppIpInterfaceAddress(self, epg.bvi, epg.bvi_ip6, 128)
            if_ip4.add_vpp_config()
            if_ip6.add_vpp_config()

            # EPG uplink interfaces in the RD
            VppIpInterfaceBind(self, epg.uplink, epg.rd.t4).add_vpp_config()
            VppIpInterfaceBind(self, epg.uplink, epg.rd.t6).add_vpp_config()

            # add the BD ARP termination entry for BVI IP
            epg.bd_arp_ip4 = VppBridgeDomainArpEntry(self, epg.bd.bd,
                                                     str(self.router_mac),
                                                     epg.bvi_ip4)
            epg.bd_arp_ip6 = VppBridgeDomainArpEntry(self, epg.bd.bd,
                                                     str(self.router_mac),
                                                     epg.bvi_ip6)
            epg.bd_arp_ip4.add_vpp_config()
            epg.bd_arp_ip6.add_vpp_config()

            # EPG in VPP
            epg.add_vpp_config()

        for recirc in recircs:
            # EPG's ingress recirculation interface maps to its RD
            VppIpInterfaceBind(self, recirc.recirc,
                               recirc.epg.rd.t4).add_vpp_config()
            VppIpInterfaceBind(self, recirc.recirc,
                               recirc.epg.rd.t6).add_vpp_config()

            self.vapi.nat44_interface_add_del_feature(
                recirc.recirc.sw_if_index,
                is_inside=0,
                is_add=1)
            self.vapi.nat66_add_del_interface(
                recirc.recirc.sw_if_index,
                is_inside=0,
                is_add=1)

            recirc.add_vpp_config()

        for recirc in recircs:
            self.assertTrue(find_bridge_domain_port(self,
                                                    recirc.epg.bd.bd.bd_id,
                                                    recirc.recirc.sw_if_index))

        for ep in eps:
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            #
            # routes to the endpoints. We need these since there are no
            # adj-fibs due to the fact the the BVI address has /32 and
            # the subnet is not attached.
            #
            for (ip, fip) in zip(ep.ips, ep.fips):
                # Add static mappings for each EP from the 10/8 to 11/8 network
                if ip.af == AF_INET:
                    self.vapi.nat44_add_del_static_mapping(ip.bytes,
                                                           fip.bytes,
                                                           vrf_id=0,
                                                           addr_only=1)
                else:
                    self.vapi.nat66_add_del_static_mapping(ip.bytes,
                                                           fip.bytes,
                                                           vrf_id=0)

            # VPP EP create ...
            ep.add_vpp_config()

            self.logger.info(self.vapi.cli("sh gbp endpoint"))

            # ... results in a Gratuitous ARP/ND on the EPG's uplink
            rx = ep.epg.uplink.get_capture(len(ep.ips), timeout=0.2)

            for ii, ip in enumerate(ep.ips):
                p = rx[ii]

                if ip.is_ip6:
                    self.assertTrue(p.haslayer(ICMPv6ND_NA))
                    self.assertEqual(p[ICMPv6ND_NA].tgt, ip.address)
                else:
                    self.assertTrue(p.haslayer(ARP))
                    self.assertEqual(p[ARP].psrc, ip.address)
                    self.assertEqual(p[ARP].pdst, ip.address)

            # add the BD ARP termination entry for floating IP
            for fip in ep.fips:
                ba = VppBridgeDomainArpEntry(self, epg_nat.bd.bd, ep.mac, fip)
                ba.add_vpp_config()

                # floating IPs route via EPG recirc
                r = VppIpRoute(self, fip.address, fip.length,
                               [VppRoutePath(fip.address,
                                             ep.recirc.recirc.sw_if_index,
                                             is_dvr=1,
                                             proto=fip.dpo_proto)],
                               table_id=20,
                               is_ip6=fip.is_ip6)
                r.add_vpp_config()

            # L2 FIB entries in the NAT EPG BD to bridge the packets from
            # the outside direct to the internal EPG
            lf = VppL2FibEntry(self, epg_nat.bd.bd, ep.mac,
                               ep.recirc.recirc, bvi_mac=0)
            lf.add_vpp_config()

        #
        # ARP packets for unknown IP are sent to the EPG uplink
        #
        pkt_arp = (Ether(dst="ff:ff:ff:ff:ff:ff",
                         src=self.pg0.remote_mac) /
                   ARP(op="who-has",
                       hwdst="ff:ff:ff:ff:ff:ff",
                       hwsrc=self.pg0.remote_mac,
                       pdst="10.0.0.88",
                       psrc="10.0.0.99"))

        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkt_arp)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rxd = epgs[0].uplink.get_capture(1)

        #
        # ARP/ND packets get a response
        #
        pkt_arp = (Ether(dst="ff:ff:ff:ff:ff:ff",
                         src=self.pg0.remote_mac) /
                   ARP(op="who-has",
                       hwdst="ff:ff:ff:ff:ff:ff",
                       hwsrc=self.pg0.remote_mac,
                       pdst=epgs[0].bvi_ip4.address,
                       psrc=eps[0].ip4.address))

        self.send_and_expect(self.pg0, [pkt_arp], self.pg0)

        nsma = in6_getnsma(inet_pton(AF_INET6, eps[0].ip6.address))
        d = inet_ntop(AF_INET6, nsma)
        pkt_nd = (Ether(dst=in6_getnsmac(nsma),
                        src=self.pg0.remote_mac) /
                  IPv6(dst=d, src=eps[0].ip6.address) /
                  ICMPv6ND_NS(tgt=epgs[0].bvi_ip6.address) /
                  ICMPv6NDOptSrcLLAddr(lladdr=self.pg0.remote_mac))
        self.send_and_expect(self.pg0, [pkt_nd], self.pg0)

        #
        # broadcast packets are flooded
        #
        pkt_bcast = (Ether(dst="ff:ff:ff:ff:ff:ff",
                           src=self.pg0.remote_mac) /
                     IP(src=eps[0].ip4.address, dst="232.1.1.1") /
                     UDP(sport=1234, dport=1234) /
                     Raw('\xa5' * 100))

        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkt_bcast)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rxd = eps[1].itf.get_capture(1)
        self.assertEqual(rxd[0][Ether].dst, pkt_bcast[Ether].dst)
        rxd = epgs[0].uplink.get_capture(1)
        self.assertEqual(rxd[0][Ether].dst, pkt_bcast[Ether].dst)

        #
        # packets to non-local L3 destinations dropped
        #
        pkt_intra_epg_220_ip4 = (Ether(src=self.pg0.remote_mac,
                                       dst=str(self.router_mac)) /
                                 IP(src=eps[0].ip4.address,
                                    dst="10.0.0.99") /
                                 UDP(sport=1234, dport=1234) /
                                 Raw('\xa5' * 100))
        pkt_inter_epg_222_ip4 = (Ether(src=self.pg0.remote_mac,
                                       dst=str(self.router_mac)) /
                                 IP(src=eps[0].ip4.address,
                                    dst="10.0.1.99") /
                                 UDP(sport=1234, dport=1234) /
                                 Raw('\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0, pkt_intra_epg_220_ip4 * 65)

        pkt_inter_epg_222_ip6 = (Ether(src=self.pg0.remote_mac,
                                       dst=str(self.router_mac)) /
                                 IPv6(src=eps[0].ip6.address,
                                      dst="2001:10::99") /
                                 UDP(sport=1234, dport=1234) /
                                 Raw('\xa5' * 100))
        self.send_and_assert_no_replies(self.pg0, pkt_inter_epg_222_ip6 * 65)

        #
        # Add the subnet routes
        #
        s41 = VppGbpSubnet(
            self, rd0, "10.0.0.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_INTERNAL)
        s42 = VppGbpSubnet(
            self, rd0, "10.0.1.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_INTERNAL)
        s43 = VppGbpSubnet(
            self, rd0, "10.0.2.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_INTERNAL)
        s61 = VppGbpSubnet(
            self, rd0, "2001:10::1", 64,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_INTERNAL)
        s62 = VppGbpSubnet(
            self, rd0, "2001:10:1::1", 64,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_INTERNAL)
        s63 = VppGbpSubnet(
            self, rd0, "2001:10:2::1", 64,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_INTERNAL)
        s41.add_vpp_config()
        s42.add_vpp_config()
        s43.add_vpp_config()
        s61.add_vpp_config()
        s62.add_vpp_config()
        s63.add_vpp_config()

        self.send_and_expect_bridged(eps[0].itf,
                                     pkt_intra_epg_220_ip4 * 65,
                                     eps[0].epg.uplink)
        self.send_and_expect_bridged(eps[0].itf,
                                     pkt_inter_epg_222_ip4 * 65,
                                     eps[0].epg.uplink)
        self.send_and_expect_bridged6(eps[0].itf,
                                      pkt_inter_epg_222_ip6 * 65,
                                      eps[0].epg.uplink)

        self.logger.info(self.vapi.cli("sh ip fib 11.0.0.2"))
        self.logger.info(self.vapi.cli("sh gbp endpoint-group"))
        self.logger.info(self.vapi.cli("sh gbp endpoint"))
        self.logger.info(self.vapi.cli("sh gbp recirc"))
        self.logger.info(self.vapi.cli("sh int"))
        self.logger.info(self.vapi.cli("sh int addr"))
        self.logger.info(self.vapi.cli("sh int feat loop6"))
        self.logger.info(self.vapi.cli("sh vlib graph ip4-gbp-src-classify"))
        self.logger.info(self.vapi.cli("sh int feat loop3"))
        self.logger.info(self.vapi.cli("sh int feat pg0"))

        #
        # Packet destined to unknown unicast is sent on the epg uplink ...
        #
        pkt_intra_epg_220_to_uplink = (Ether(src=self.pg0.remote_mac,
                                             dst="00:00:00:33:44:55") /
                                       IP(src=eps[0].ip4.address,
                                          dst="10.0.0.99") /
                                       UDP(sport=1234, dport=1234) /
                                       Raw('\xa5' * 100))

        self.send_and_expect_bridged(eps[0].itf,
                                     pkt_intra_epg_220_to_uplink * 65,
                                     eps[0].epg.uplink)
        # ... and nowhere else
        self.pg1.get_capture(0, timeout=0.1)
        self.pg1.assert_nothing_captured(remark="Flood onto other VMS")

        pkt_intra_epg_221_to_uplink = (Ether(src=self.pg2.remote_mac,
                                             dst="00:00:00:33:44:66") /
                                       IP(src=eps[0].ip4.address,
                                          dst="10.0.0.99") /
                                       UDP(sport=1234, dport=1234) /
                                       Raw('\xa5' * 100))

        self.send_and_expect_bridged(eps[2].itf,
                                     pkt_intra_epg_221_to_uplink * 65,
                                     eps[2].epg.uplink)

        #
        # Packets from the uplink are forwarded in the absence of a contract
        #
        pkt_intra_epg_220_from_uplink = (Ether(src="00:00:00:33:44:55",
                                               dst=self.pg0.remote_mac) /
                                         IP(src=eps[0].ip4.address,
                                            dst="10.0.0.99") /
                                         UDP(sport=1234, dport=1234) /
                                         Raw('\xa5' * 100))

        self.send_and_expect_bridged(self.pg4,
                                     pkt_intra_epg_220_from_uplink * 65,
                                     self.pg0)

        #
        # in the absence of policy, endpoints in the same EPG
        # can communicate
        #
        pkt_intra_epg = (Ether(src=self.pg0.remote_mac,
                               dst=self.pg1.remote_mac) /
                         IP(src=eps[0].ip4.address,
                            dst=eps[1].ip4.address) /
                         UDP(sport=1234, dport=1234) /
                         Raw('\xa5' * 100))

        self.send_and_expect_bridged(self.pg0, pkt_intra_epg * 65, self.pg1)

        #
        # in the abscense of policy, endpoints in the different EPG
        # cannot communicate
        #
        pkt_inter_epg_220_to_221 = (Ether(src=self.pg0.remote_mac,
                                          dst=self.pg2.remote_mac) /
                                    IP(src=eps[0].ip4.address,
                                       dst=eps[2].ip4.address) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw('\xa5' * 100))
        pkt_inter_epg_221_to_220 = (Ether(src=self.pg2.remote_mac,
                                          dst=self.pg0.remote_mac) /
                                    IP(src=eps[2].ip4.address,
                                       dst=eps[0].ip4.address) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw('\xa5' * 100))
        pkt_inter_epg_220_to_222 = (Ether(src=self.pg0.remote_mac,
                                          dst=str(self.router_mac)) /
                                    IP(src=eps[0].ip4.address,
                                       dst=eps[3].ip4.address) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw('\xa5' * 100))

        self.send_and_assert_no_replies(eps[0].itf,
                                        pkt_inter_epg_220_to_221 * 65)
        self.send_and_assert_no_replies(eps[0].itf,
                                        pkt_inter_epg_220_to_222 * 65)

        #
        # A uni-directional contract from EPG 220 -> 221
        #
        acl = VppGbpAcl(self)
        rule = acl.create_rule(permit_deny=1, proto=17)
        rule2 = acl.create_rule(is_ipv6=1, permit_deny=1, proto=17)
        acl_index = acl.add_vpp_config([rule, rule2])
        c1 = VppGbpContract(
            self, 220, 221, acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                []),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                 [])],
            [ETH_P_IP, ETH_P_IPV6])
        c1.add_vpp_config()

        self.send_and_expect_bridged(eps[0].itf,
                                     pkt_inter_epg_220_to_221 * 65,
                                     eps[2].itf)
        self.send_and_assert_no_replies(eps[0].itf,
                                        pkt_inter_epg_220_to_222 * 65)

        #
        # contract for the return direction
        #
        c2 = VppGbpContract(
            self, 221, 220, acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                []),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                 [])],
            [ETH_P_IP, ETH_P_IPV6])
        c2.add_vpp_config()

        self.send_and_expect_bridged(eps[0].itf,
                                     pkt_inter_epg_220_to_221 * 65,
                                     eps[2].itf)
        self.send_and_expect_bridged(eps[2].itf,
                                     pkt_inter_epg_221_to_220 * 65,
                                     eps[0].itf)

        #
        # the contract does not allow non-IP
        #
        pkt_non_ip_inter_epg_220_to_221 = (Ether(src=self.pg0.remote_mac,
                                                 dst=self.pg2.remote_mac) /
                                           ARP())
        self.send_and_assert_no_replies(eps[0].itf,
                                        pkt_non_ip_inter_epg_220_to_221 * 17)

        #
        # check that inter group is still disabled for the groups
        # not in the contract.
        #
        self.send_and_assert_no_replies(eps[0].itf,
                                        pkt_inter_epg_220_to_222 * 65)

        #
        # A uni-directional contract from EPG 220 -> 222 'L3 routed'
        #
        c3 = VppGbpContract(
            self, 220, 222, acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                []),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                 [])],
            [ETH_P_IP, ETH_P_IPV6])
        c3.add_vpp_config()

        self.logger.info(self.vapi.cli("sh gbp contract"))

        self.send_and_expect_routed(eps[0].itf,
                                    pkt_inter_epg_220_to_222 * 65,
                                    eps[3].itf,
                                    str(self.router_mac))

        #
        # remove both contracts, traffic stops in both directions
        #
        c2.remove_vpp_config()
        c1.remove_vpp_config()
        c3.remove_vpp_config()
        acl.remove_vpp_config()

        self.send_and_assert_no_replies(eps[2].itf,
                                        pkt_inter_epg_221_to_220 * 65)
        self.send_and_assert_no_replies(eps[0].itf,
                                        pkt_inter_epg_220_to_221 * 65)
        self.send_and_expect_bridged(eps[0].itf,
                                     pkt_intra_epg * 65,
                                     eps[1].itf)

        #
        # EPs to the outside world
        #

        # in the EP's RD an external subnet via the NAT EPG's recirc
        se1 = VppGbpSubnet(
            self, rd0, "0.0.0.0", 0,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_EXTERNAL,
            sw_if_index=recirc_nat.recirc.sw_if_index,
            epg=epg_nat.epg)
        se2 = VppGbpSubnet(
            self, rd0, "11.0.0.0", 8,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_EXTERNAL,
            sw_if_index=recirc_nat.recirc.sw_if_index,
            epg=epg_nat.epg)
        se16 = VppGbpSubnet(
            self, rd0, "::", 0,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_EXTERNAL,
            sw_if_index=recirc_nat.recirc.sw_if_index,
            epg=epg_nat.epg)
        # in the NAT RD an external subnet via the NAT EPG's uplink
        se3 = VppGbpSubnet(
            self, rd20, "0.0.0.0", 0,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_EXTERNAL,
            sw_if_index=epg_nat.uplink.sw_if_index,
            epg=epg_nat.epg)
        se36 = VppGbpSubnet(
            self, rd20, "::", 0,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_EXTERNAL,
            sw_if_index=epg_nat.uplink.sw_if_index,
            epg=epg_nat.epg)
        se4 = VppGbpSubnet(
            self, rd20, "11.0.0.0", 8,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_EXTERNAL,
            sw_if_index=epg_nat.uplink.sw_if_index,
            epg=epg_nat.epg)
        se1.add_vpp_config()
        se2.add_vpp_config()
        se16.add_vpp_config()
        se3.add_vpp_config()
        se36.add_vpp_config()
        se4.add_vpp_config()

        self.logger.info(self.vapi.cli("sh ip fib 0.0.0.0/0"))
        self.logger.info(self.vapi.cli("sh ip fib 11.0.0.1"))
        self.logger.info(self.vapi.cli("sh ip6 fib ::/0"))
        self.logger.info(self.vapi.cli("sh ip6 fib %s" %
                                       eps[0].fip6))

        #
        # From an EP to an outside addess: IN2OUT
        #
        pkt_inter_epg_220_to_global = (Ether(src=self.pg0.remote_mac,
                                             dst=str(self.router_mac)) /
                                       IP(src=eps[0].ip4.address,
                                          dst="1.1.1.1") /
                                       UDP(sport=1234, dport=1234) /
                                       Raw('\xa5' * 100))

        # no policy yet
        self.send_and_assert_no_replies(eps[0].itf,
                                        pkt_inter_epg_220_to_global * 65)

        acl2 = VppGbpAcl(self)
        rule = acl2.create_rule(permit_deny=1, proto=17, sport_from=1234,
                                sport_to=1234, dport_from=1234, dport_to=1234)
        rule2 = acl2.create_rule(is_ipv6=1, permit_deny=1, proto=17,
                                 sport_from=1234, sport_to=1234,
                                 dport_from=1234, dport_to=1234)

        acl_index2 = acl2.add_vpp_config([rule, rule2])
        c4 = VppGbpContract(
            self, 220, 333, acl_index2,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                []),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                 [])],
            [ETH_P_IP, ETH_P_IPV6])
        c4.add_vpp_config()

        self.send_and_expect_natted(eps[0].itf,
                                    pkt_inter_epg_220_to_global * 65,
                                    self.pg7,
                                    eps[0].fip4.address)

        pkt_inter_epg_220_to_global = (Ether(src=self.pg0.remote_mac,
                                             dst=str(self.router_mac)) /
                                       IPv6(src=eps[0].ip6.address,
                                            dst="6001::1") /
                                       UDP(sport=1234, dport=1234) /
                                       Raw('\xa5' * 100))

        self.send_and_expect_natted6(self.pg0,
                                     pkt_inter_epg_220_to_global * 65,
                                     self.pg7,
                                     eps[0].fip6.address)

        #
        # From a global address to an EP: OUT2IN
        #
        pkt_inter_epg_220_from_global = (Ether(src=str(self.router_mac),
                                               dst=self.pg0.remote_mac) /
                                         IP(dst=eps[0].fip4.address,
                                            src="1.1.1.1") /
                                         UDP(sport=1234, dport=1234) /
                                         Raw('\xa5' * 100))

        self.send_and_assert_no_replies(self.pg7,
                                        pkt_inter_epg_220_from_global * 65)

        c5 = VppGbpContract(
            self, 333, 220, acl_index2,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                []),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                 [])],
            [ETH_P_IP, ETH_P_IPV6])
        c5.add_vpp_config()

        self.send_and_expect_unnatted(self.pg7,
                                      pkt_inter_epg_220_from_global * 65,
                                      eps[0].itf,
                                      eps[0].ip4.address)

        pkt_inter_epg_220_from_global = (Ether(src=str(self.router_mac),
                                               dst=self.pg0.remote_mac) /
                                         IPv6(dst=eps[0].fip6.address,
                                              src="6001::1") /
                                         UDP(sport=1234, dport=1234) /
                                         Raw('\xa5' * 100))

        self.send_and_expect_unnatted6(self.pg7,
                                       pkt_inter_epg_220_from_global * 65,
                                       eps[0].itf,
                                       eps[0].ip6.address)

        #
        # From a local VM to another local VM using resp. public addresses:
        #  IN2OUT2IN
        #
        pkt_intra_epg_220_global = (Ether(src=self.pg0.remote_mac,
                                          dst=str(self.router_mac)) /
                                    IP(src=eps[0].ip4.address,
                                       dst=eps[1].fip4.address) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw('\xa5' * 100))

        self.send_and_expect_double_natted(eps[0].itf,
                                           pkt_intra_epg_220_global * 65,
                                           eps[1].itf,
                                           eps[0].fip4.address,
                                           eps[1].ip4.address)

        pkt_intra_epg_220_global = (Ether(src=self.pg0.remote_mac,
                                          dst=str(self.router_mac)) /
                                    IPv6(src=eps[0].ip6.address,
                                         dst=eps[1].fip6.address) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw('\xa5' * 100))

        self.send_and_expect_double_natted6(eps[0].itf,
                                            pkt_intra_epg_220_global * 65,
                                            eps[1].itf,
                                            eps[0].fip6.address,
                                            eps[1].ip6.address)

        #
        # cleanup
        #
        for ep in eps:
            # del static mappings for each EP from the 10/8 to 11/8 network
            self.vapi.nat44_add_del_static_mapping(ep.ip4.bytes,
                                                   ep.fip4.bytes,
                                                   vrf_id=0,
                                                   addr_only=1,
                                                   is_add=0)
            self.vapi.nat66_add_del_static_mapping(ep.ip6.bytes,
                                                   ep.fip6.bytes,
                                                   vrf_id=0,
                                                   is_add=0)

        for epg in epgs:
            # IP config on the BVI interfaces
            if epg != epgs[0] and epg != epgs[3]:
                self.vapi.nat44_interface_add_del_feature(epg.bvi.sw_if_index,
                                                          is_inside=1,
                                                          is_add=0)
                self.vapi.nat66_add_del_interface(epg.bvi.sw_if_index,
                                                  is_inside=1,
                                                  is_add=0)

        for recirc in recircs:
            self.vapi.nat44_interface_add_del_feature(
                recirc.recirc.sw_if_index,
                is_inside=0,
                is_add=0)
            self.vapi.nat66_add_del_interface(
                recirc.recirc.sw_if_index,
                is_inside=0,
                is_add=0)

    def wait_for_ep_timeout(self, sw_if_index=None, ip=None, mac=None,
                            n_tries=100, s_time=1):
        while (n_tries):
            if not find_gbp_endpoint(self, sw_if_index, ip, mac):
                return True
            n_tries = n_tries - 1
            self.sleep(s_time)
        self.assertFalse(find_gbp_endpoint(self, sw_if_index, ip, mac))
        return False

    def test_gbp_learn_l2(self):
        """ GBP L2 Endpoint Learning """

        ep_flags = VppEnum.vl_api_gbp_endpoint_flags_t
        learnt = [{'mac': '00:00:11:11:11:01',
                   'ip': '10.0.0.1',
                   'ip6': '2001:10::2'},
                  {'mac': '00:00:11:11:11:02',
                   'ip': '10.0.0.2',
                   'ip6': '2001:10::3'}]

        #
        # lower the inactive threshold so these tests pass in a
        # reasonable amount of time
        #
        self.vapi.gbp_endpoint_learn_set_inactive_threshold(2)

        #
        # IP tables
        #
        gt4 = VppIpTable(self, 1)
        gt4.add_vpp_config()
        gt6 = VppIpTable(self, 1, is_ip6=True)
        gt6.add_vpp_config()

        rd1 = VppGbpRouteDomain(self, 1, gt4, gt6)
        rd1.add_vpp_config()

        #
        # Pg2 hosts the vxlan tunnel, hosts on pg2 to act as TEPs
        # Pg3 hosts the IP4 UU-flood VXLAN tunnel
        # Pg4 hosts the IP6 UU-flood VXLAN tunnel
        #
        self.pg2.config_ip4()
        self.pg2.resolve_arp()
        self.pg2.generate_remote_hosts(4)
        self.pg2.configure_ipv4_neighbors()
        self.pg3.config_ip4()
        self.pg3.resolve_arp()
        self.pg4.config_ip4()
        self.pg4.resolve_arp()

        #
        # a GBP bridge domain with a BVI and a UU-flood interface
        #
        bd1 = VppBridgeDomain(self, 1)
        bd1.add_vpp_config()
        gbd1 = VppGbpBridgeDomain(self, bd1, self.loop0, self.pg3)
        gbd1.add_vpp_config()

        self.logger.info(self.vapi.cli("sh bridge 1 detail"))
        self.logger.info(self.vapi.cli("sh gbp bridge"))

        # ... and has a /32 applied
        ip_addr = VppIpInterfaceAddress(self, gbd1.bvi, "10.0.0.128", 32)
        ip_addr.add_vpp_config()

        #
        # The Endpoint-group in which we are learning endpoints
        #
        epg_220 = VppGbpEndpointGroup(self, 220, rd1, gbd1,
                                      None, self.loop0,
                                      "10.0.0.128",
                                      "2001:10::128")
        epg_220.add_vpp_config()
        epg_330 = VppGbpEndpointGroup(self, 330, rd1, gbd1,
                                      None, self.loop1,
                                      "10.0.1.128",
                                      "2001:11::128")
        epg_330.add_vpp_config()

        #
        # The VXLAN GBP tunnel is a bridge-port and has L2 endpoint
        # leanring enabled
        #
        vx_tun_l2_1 = VppGbpVxlanTunnel(
            self, 99, bd1.bd_id,
            VppEnum.vl_api_gbp_vxlan_tunnel_mode_t.GBP_VXLAN_TUNNEL_MODE_L2)
        vx_tun_l2_1.add_vpp_config()

        #
        # A static endpoint that the learnt endpoints are trying to
        # talk to
        #
        ep = VppGbpEndpoint(self, self.pg0,
                            epg_220, None,
                            "10.0.0.127", "11.0.0.127",
                            "2001:10::1", "3001::1")
        ep.add_vpp_config()

        self.assertTrue(find_route(self, ep.ip4.address, 32, table_id=1))

        # a packet with an sclass from an unknwon EPG
        p = (Ether(src=self.pg2.remote_mac,
                   dst=self.pg2.local_mac) /
             IP(src=self.pg2.remote_hosts[0].ip4,
                dst=self.pg2.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=99, gpid=88, flags=0x88) /
             Ether(src=learnt[0]["mac"], dst=ep.mac) /
             IP(src=learnt[0]["ip"], dst=ep.ip4.address) /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        self.send_and_assert_no_replies(self.pg2, p)

        #
        # we should not have learnt a new tunnel endpoint, since
        # the EPG was not learnt.
        #
        self.assertEqual(INDEX_INVALID,
                         find_vxlan_gbp_tunnel(self,
                                               self.pg2.local_ip4,
                                               self.pg2.remote_hosts[0].ip4,
                                               99))

        # epg is not learnt, becasue the EPG is unknwon
        self.assertEqual(len(self.vapi.gbp_endpoint_dump()), 1)

        for ii, l in enumerate(learnt):
            # a packet with an sclass from a knwon EPG
            # arriving on an unknown TEP
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=220, flags=0x88) /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IP(src=l['ip'], dst=ep.ip4.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rx = self.send_and_expect(self.pg2, [p], self.pg0)

            # the new TEP
            tep1_sw_if_index = find_vxlan_gbp_tunnel(
                self,
                self.pg2.local_ip4,
                self.pg2.remote_hosts[1].ip4,
                99)
            self.assertNotEqual(INDEX_INVALID, tep1_sw_if_index)

            #
            # the EP is learnt via the learnt TEP
            # both from its MAC and its IP
            #
            self.assertTrue(find_gbp_endpoint(self,
                                              vx_tun_l2_1.sw_if_index,
                                              mac=l['mac']))
            self.assertTrue(find_gbp_endpoint(self,
                                              vx_tun_l2_1.sw_if_index,
                                              ip=l['ip']))

        self.logger.info(self.vapi.cli("show gbp endpoint"))
        self.logger.info(self.vapi.cli("show gbp vxlan"))
        self.logger.info(self.vapi.cli("show vxlan-gbp tunnel"))

        #
        # If we sleep for the threshold time, the learnt endpoints should
        # age out
        #
        for l in learnt:
            self.wait_for_ep_timeout(vx_tun_l2_1.sw_if_index,
                                     mac=l['mac'])

        #
        # repeat. the do not learn bit is set so the EPs are not learnt
        #
        for l in learnt:
            # a packet with an sclass from a knwon EPG
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=220, flags=0x88, gpflags="D") /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IP(src=l['ip'], dst=ep.ip4.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rx = self.send_and_expect(self.pg2, p*65, self.pg0)

        for l in learnt:
            self.assertFalse(find_gbp_endpoint(self,
                                               vx_tun_l2_1.sw_if_index,
                                               mac=l['mac']))

        #
        # repeat
        #
        for l in learnt:
            # a packet with an sclass from a knwon EPG
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=220, flags=0x88) /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IP(src=l['ip'], dst=ep.ip4.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rx = self.send_and_expect(self.pg2, p*65, self.pg0)

            self.assertTrue(find_gbp_endpoint(self,
                                              vx_tun_l2_1.sw_if_index,
                                              mac=l['mac']))

        #
        # Static EP replies to dynamics
        #
        self.logger.info(self.vapi.cli("sh l2fib bd_id 1"))
        for l in learnt:
            p = (Ether(src=ep.mac, dst=l['mac']) /
                 IP(dst=l['ip'], src=ep.ip4.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rxs = self.send_and_expect(self.pg0, p * 17, self.pg2)

            for rx in rxs:
                self.assertEqual(rx[IP].src, self.pg2.local_ip4)
                self.assertEqual(rx[IP].dst, self.pg2.remote_hosts[1].ip4)
                self.assertEqual(rx[UDP].dport, 48879)
                # the UDP source port is a random value for hashing
                self.assertEqual(rx[VXLAN].gpid, 220)
                self.assertEqual(rx[VXLAN].vni, 99)
                self.assertTrue(rx[VXLAN].flags.G)
                self.assertTrue(rx[VXLAN].flags.Instance)
                self.assertTrue(rx[VXLAN].gpflags.A)
                self.assertFalse(rx[VXLAN].gpflags.D)

        for l in learnt:
            self.wait_for_ep_timeout(vx_tun_l2_1.sw_if_index,
                                     mac=l['mac'])

        #
        # repeat in the other EPG
        # there's no contract between 220 and 330, but the A-bit is set
        # so the packet is cleared for delivery
        #
        for l in learnt:
            # a packet with an sclass from a knwon EPG
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=330, flags=0x88, gpflags='A') /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IP(src=l['ip'], dst=ep.ip4.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rx = self.send_and_expect(self.pg2, p*65, self.pg0)

            self.assertTrue(find_gbp_endpoint(self,
                                              vx_tun_l2_1.sw_if_index,
                                              mac=l['mac']))

        #
        # static EP cannot reach the learnt EPs since there is no contract
        # only test 1 EP as the others could timeout
        #
        p = (Ether(src=ep.mac, dst=l['mac']) /
             IP(dst=learnt[0]['ip'], src=ep.ip4.address) /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0, [p])

        #
        # refresh the entries after the check for no replies above
        #
        for l in learnt:
            # a packet with an sclass from a knwon EPG
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=330, flags=0x88, gpflags='A') /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IP(src=l['ip'], dst=ep.ip4.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rx = self.send_and_expect(self.pg2, p*65, self.pg0)

            self.assertTrue(find_gbp_endpoint(self,
                                              vx_tun_l2_1.sw_if_index,
                                              mac=l['mac']))

        #
        # Add the contract so they can talk
        #
        acl = VppGbpAcl(self)
        rule = acl.create_rule(permit_deny=1, proto=17)
        rule2 = acl.create_rule(is_ipv6=1, permit_deny=1, proto=17)
        acl_index = acl.add_vpp_config([rule, rule2])
        c1 = VppGbpContract(
            self, 220, 330, acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                []),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                 [])],
            [ETH_P_IP, ETH_P_IPV6])
        c1.add_vpp_config()

        for l in learnt:
            p = (Ether(src=ep.mac, dst=l['mac']) /
                 IP(dst=l['ip'], src=ep.ip4.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            self.send_and_expect(self.pg0, [p], self.pg2)

        #
        # send UU packets from the local EP
        #
        self.logger.info(self.vapi.cli("sh bridge 1 detail"))
        self.logger.info(self.vapi.cli("sh gbp bridge"))
        p_uu = (Ether(src=ep.mac, dst="00:11:11:11:11:11") /
                IP(dst="10.0.0.133", src=ep.ip4.address) /
                UDP(sport=1234, dport=1234) /
                Raw('\xa5' * 100))
        rxs = self.send_and_expect(ep.itf, [p_uu], gbd1.uu_flood)

        #
        # Add a mcast destination VXLAN-GBP tunnel for B&M traffic
        #
        tun_bm = VppVxlanGbpTunnel(self, self.pg4.local_ip4,
                                   "239.1.1.1", 88,
                                   mcast_itf=self.pg4)
        tun_bm.add_vpp_config()
        bp_bm = VppBridgeDomainPort(self, bd1, tun_bm,
                                    port_type=L2_PORT_TYPE.NORMAL)
        bp_bm.add_vpp_config()

        self.logger.info(self.vapi.cli("sh bridge 1 detail"))

        p_bm = (Ether(src=ep.mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(dst="10.0.0.133", src=ep.ip4.address) /
                UDP(sport=1234, dport=1234) /
                Raw('\xa5' * 100))
        rxs = self.send_and_expect_only(ep.itf, [p_bm], tun_bm.mcast_itf)

        #
        # Check v6 Endpoints
        #
        for l in learnt:
            # a packet with an sclass from a knwon EPG
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=330, flags=0x88, gpflags='A') /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IPv6(src=l['ip6'], dst=ep.ip6.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rx = self.send_and_expect(self.pg2, p*65, self.pg0)

            self.assertTrue(find_gbp_endpoint(self,
                                              vx_tun_l2_1.sw_if_index,
                                              mac=l['mac']))

        #
        # L3 Endpoint Learning
        #  - configured on the bridge's BVI
        #

        #
        # clean up
        #
        for l in learnt:
            self.wait_for_ep_timeout(vx_tun_l2_1.sw_if_index,
                                     mac=l['mac'])

        self.pg2.unconfig_ip4()
        self.pg3.unconfig_ip4()
        self.pg4.unconfig_ip4()

        self.logger.info(self.vapi.cli("sh int"))
        self.logger.info(self.vapi.cli("sh gbp vxlan"))

    @unittest.skipIf(is_skip_aarch64_set and is_platform_aarch64,
                     "test doesn't work on aarch64")
    def test_gbp_learn_vlan_l2(self):
        """ GBP L2 Endpoint w/ VLANs"""

        ep_flags = VppEnum.vl_api_gbp_endpoint_flags_t
        learnt = [{'mac': '00:00:11:11:11:01',
                   'ip': '10.0.0.1',
                   'ip6': '2001:10::2'},
                  {'mac': '00:00:11:11:11:02',
                   'ip': '10.0.0.2',
                   'ip6': '2001:10::3'}]

        #
        # lower the inactive threshold so these tests pass in a
        # reasonable amount of time
        #
        self.vapi.gbp_endpoint_learn_set_inactive_threshold(2)

        #
        # IP tables
        #
        gt4 = VppIpTable(self, 1)
        gt4.add_vpp_config()
        gt6 = VppIpTable(self, 1, is_ip6=True)
        gt6.add_vpp_config()

        rd1 = VppGbpRouteDomain(self, 1, gt4, gt6)
        rd1.add_vpp_config()

        #
        # Pg2 hosts the vxlan tunnel, hosts on pg2 to act as TEPs
        #
        self.pg2.config_ip4()
        self.pg2.resolve_arp()
        self.pg2.generate_remote_hosts(4)
        self.pg2.configure_ipv4_neighbors()
        self.pg3.config_ip4()
        self.pg3.resolve_arp()

        #
        # The EP will be on a vlan sub-interface
        #
        vlan_11 = VppDot1QSubint(self, self.pg0, 11)
        vlan_11.admin_up()
        self.vapi.sw_interface_set_l2_tag_rewrite(vlan_11.sw_if_index,
                                                  L2_VTR_OP.L2_POP_1,
                                                  11)

        bd_uu_fwd = VppVxlanGbpTunnel(self, self.pg3.local_ip4,
                                      self.pg3.remote_ip4, 116)
        bd_uu_fwd.add_vpp_config()

        #
        # a GBP bridge domain with a BVI and a UU-flood interface
        # The BD is marked as do not learn, so no endpoints are ever
        # learnt in this BD.
        #
        bd1 = VppBridgeDomain(self, 1)
        bd1.add_vpp_config()
        gbd1 = VppGbpBridgeDomain(self, bd1, self.loop0, bd_uu_fwd,
                                  learn=False)
        gbd1.add_vpp_config()

        self.logger.info(self.vapi.cli("sh bridge 1 detail"))
        self.logger.info(self.vapi.cli("sh gbp bridge"))

        # ... and has a /32 applied
        ip_addr = VppIpInterfaceAddress(self, gbd1.bvi, "10.0.0.128", 32)
        ip_addr.add_vpp_config()

        #
        # The Endpoint-group in which we are learning endpoints
        #
        epg_220 = VppGbpEndpointGroup(self, 220, rd1, gbd1,
                                      None, self.loop0,
                                      "10.0.0.128",
                                      "2001:10::128")
        epg_220.add_vpp_config()

        #
        # The VXLAN GBP tunnel is a bridge-port and has L2 endpoint
        # leanring enabled
        #
        vx_tun_l2_1 = VppGbpVxlanTunnel(
            self, 99, bd1.bd_id,
            VppEnum.vl_api_gbp_vxlan_tunnel_mode_t.GBP_VXLAN_TUNNEL_MODE_L2)
        vx_tun_l2_1.add_vpp_config()

        #
        # A static endpoint that the learnt endpoints are trying to
        # talk to
        #
        ep = VppGbpEndpoint(self, vlan_11,
                            epg_220, None,
                            "10.0.0.127", "11.0.0.127",
                            "2001:10::1", "3001::1")
        ep.add_vpp_config()

        self.assertTrue(find_route(self, ep.ip4.address, 32, table_id=1))

        #
        # Send to the static EP
        #
        for ii, l in enumerate(learnt):
            # a packet with an sclass from a knwon EPG
            # arriving on an unknown TEP
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=220, flags=0x88) /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IP(src=l['ip'], dst=ep.ip4.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rxs = self.send_and_expect(self.pg2, [p], self.pg0)

            #
            # packet to EP has the EP's vlan tag
            #
            for rx in rxs:
                self.assertEqual(rx[Dot1Q].vlan, 11)

            #
            # the EP is not learnt since the BD setting prevents it
            # also no TEP too
            #
            self.assertFalse(find_gbp_endpoint(self,
                                               vx_tun_l2_1.sw_if_index,
                                               mac=l['mac']))
            self.assertEqual(INDEX_INVALID,
                             find_vxlan_gbp_tunnel(
                                 self,
                                 self.pg2.local_ip4,
                                 self.pg2.remote_hosts[1].ip4,
                                 99))

        self.assertEqual(len(self.vapi.gbp_endpoint_dump()), 1)

        #
        # static to remotes
        # we didn't learn the remotes so they are sent to the UU-fwd
        #
        for l in learnt:
            p = (Ether(src=ep.mac, dst=l['mac']) /
                 Dot1Q(vlan=11) /
                 IP(dst=l['ip'], src=ep.ip4.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rxs = self.send_and_expect(self.pg0, p * 17, self.pg3)

            for rx in rxs:
                self.assertEqual(rx[IP].src, self.pg3.local_ip4)
                self.assertEqual(rx[IP].dst, self.pg3.remote_ip4)
                self.assertEqual(rx[UDP].dport, 48879)
                # the UDP source port is a random value for hashing
                self.assertEqual(rx[VXLAN].gpid, 220)
                self.assertEqual(rx[VXLAN].vni, 116)
                self.assertTrue(rx[VXLAN].flags.G)
                self.assertTrue(rx[VXLAN].flags.Instance)
                self.assertFalse(rx[VXLAN].gpflags.A)
                self.assertFalse(rx[VXLAN].gpflags.D)

        self.pg2.unconfig_ip4()
        self.pg3.unconfig_ip4()

    @unittest.skipIf(is_skip_aarch64_set and is_platform_aarch64,
                     "test doesn't work on aarch64")
    def test_gbp_learn_l3(self):
        """ GBP L3 Endpoint Learning """

        self.vapi.cli("set logging class gbp debug")

        ep_flags = VppEnum.vl_api_gbp_endpoint_flags_t
        routed_dst_mac = "00:0c:0c:0c:0c:0c"
        routed_src_mac = "00:22:bd:f8:19:ff"

        learnt = [{'mac': '00:00:11:11:11:02',
                   'ip': '10.0.1.2',
                   'ip6': '2001:10::2'},
                  {'mac': '00:00:11:11:11:03',
                   'ip': '10.0.1.3',
                   'ip6': '2001:10::3'}]

        #
        # lower the inactive threshold so these tests pass in a
        # reasonable amount of time
        #
        self.vapi.gbp_endpoint_learn_set_inactive_threshold(2)

        #
        # IP tables
        #
        t4 = VppIpTable(self, 1)
        t4.add_vpp_config()
        t6 = VppIpTable(self, 1, True)
        t6.add_vpp_config()

        tun_ip4_uu = VppVxlanGbpTunnel(self, self.pg4.local_ip4,
                                       self.pg4.remote_ip4, 114)
        tun_ip6_uu = VppVxlanGbpTunnel(self, self.pg4.local_ip4,
                                       self.pg4.remote_ip4, 116)
        tun_ip4_uu.add_vpp_config()
        tun_ip6_uu.add_vpp_config()

        rd1 = VppGbpRouteDomain(self, 2, t4, t6, tun_ip4_uu, tun_ip6_uu)
        rd1.add_vpp_config()

        self.loop0.set_mac(self.router_mac)

        #
        # Bind the BVI to the RD
        #
        VppIpInterfaceBind(self, self.loop0, t4).add_vpp_config()
        VppIpInterfaceBind(self, self.loop0, t6).add_vpp_config()

        #
        # Pg2 hosts the vxlan tunnel
        # hosts on pg2 to act as TEPs
        # pg3 is BD uu-fwd
        # pg4 is RD uu-fwd
        #
        self.pg2.config_ip4()
        self.pg2.resolve_arp()
        self.pg2.generate_remote_hosts(4)
        self.pg2.configure_ipv4_neighbors()
        self.pg3.config_ip4()
        self.pg3.resolve_arp()
        self.pg4.config_ip4()
        self.pg4.resolve_arp()

        #
        # a GBP bridge domain with a BVI and a UU-flood interface
        #
        bd1 = VppBridgeDomain(self, 1)
        bd1.add_vpp_config()
        gbd1 = VppGbpBridgeDomain(self, bd1, self.loop0, self.pg3)
        gbd1.add_vpp_config()

        self.logger.info(self.vapi.cli("sh bridge 1 detail"))
        self.logger.info(self.vapi.cli("sh gbp bridge"))
        self.logger.info(self.vapi.cli("sh gbp route"))

        # ... and has a /32 and /128 applied
        ip4_addr = VppIpInterfaceAddress(self, gbd1.bvi, "10.0.0.128", 32)
        ip4_addr.add_vpp_config()
        ip6_addr = VppIpInterfaceAddress(self, gbd1.bvi, "2001:10::128", 128)
        ip6_addr.add_vpp_config()

        #
        # The Endpoint-group in which we are learning endpoints
        #
        epg_220 = VppGbpEndpointGroup(self, 220, rd1, gbd1,
                                      None, self.loop0,
                                      "10.0.0.128",
                                      "2001:10::128")
        epg_220.add_vpp_config()

        #
        # The VXLAN GBP tunnel is a bridge-port and has L2 endpoint
        # leanring enabled
        #
        vx_tun_l3 = VppGbpVxlanTunnel(
            self, 101, rd1.rd_id,
            VppEnum.vl_api_gbp_vxlan_tunnel_mode_t.GBP_VXLAN_TUNNEL_MODE_L3)
        vx_tun_l3.add_vpp_config()

        #
        # A static endpoint that the learnt endpoints are trying to
        # talk to
        #
        ep = VppGbpEndpoint(self, self.pg0,
                            epg_220, None,
                            "10.0.0.127", "11.0.0.127",
                            "2001:10::1", "3001::1")
        ep.add_vpp_config()

        #
        # learn some remote IPv4 EPs
        #
        for ii, l in enumerate(learnt):
            # a packet with an sclass from a knwon EPG
            # arriving on an unknown TEP
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=101, gpid=220, flags=0x88) /
                 Ether(src=l['mac'], dst="00:00:00:11:11:11") /
                 IP(src=l['ip'], dst=ep.ip4.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rx = self.send_and_expect(self.pg2, [p], self.pg0)

            # the new TEP
            tep1_sw_if_index = find_vxlan_gbp_tunnel(
                self,
                self.pg2.local_ip4,
                self.pg2.remote_hosts[1].ip4,
                vx_tun_l3.vni)
            self.assertNotEqual(INDEX_INVALID, tep1_sw_if_index)

            # endpoint learnt via the parent GBP-vxlan interface
            self.assertTrue(find_gbp_endpoint(self,
                                              vx_tun_l3._sw_if_index,
                                              ip=l['ip']))

        #
        # Static IPv4 EP replies to learnt
        #
        for l in learnt:
            p = (Ether(src=ep.mac, dst=self.loop0.local_mac) /
                 IP(dst=l['ip'], src=ep.ip4.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rxs = self.send_and_expect(self.pg0, p*1, self.pg2)

            for rx in rxs:
                self.assertEqual(rx[IP].src, self.pg2.local_ip4)
                self.assertEqual(rx[IP].dst, self.pg2.remote_hosts[1].ip4)
                self.assertEqual(rx[UDP].dport, 48879)
                # the UDP source port is a random value for hashing
                self.assertEqual(rx[VXLAN].gpid, 220)
                self.assertEqual(rx[VXLAN].vni, 101)
                self.assertTrue(rx[VXLAN].flags.G)
                self.assertTrue(rx[VXLAN].flags.Instance)
                self.assertTrue(rx[VXLAN].gpflags.A)
                self.assertFalse(rx[VXLAN].gpflags.D)

                inner = rx[VXLAN].payload

                self.assertEqual(inner[Ether].src, routed_src_mac)
                self.assertEqual(inner[Ether].dst, routed_dst_mac)
                self.assertEqual(inner[IP].src, ep.ip4.address)
                self.assertEqual(inner[IP].dst, l['ip'])

        for l in learnt:
            self.assertFalse(find_gbp_endpoint(self,
                                               tep1_sw_if_index,
                                               ip=l['ip']))

        #
        # learn some remote IPv6 EPs
        #
        for ii, l in enumerate(learnt):
            # a packet with an sclass from a knwon EPG
            # arriving on an unknown TEP
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=101, gpid=220, flags=0x88) /
                 Ether(src=l['mac'], dst="00:00:00:11:11:11") /
                 IPv6(src=l['ip6'], dst=ep.ip6.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rx = self.send_and_expect(self.pg2, [p], self.pg0)

            # the new TEP
            tep1_sw_if_index = find_vxlan_gbp_tunnel(
                self,
                self.pg2.local_ip4,
                self.pg2.remote_hosts[1].ip4,
                vx_tun_l3.vni)
            self.assertNotEqual(INDEX_INVALID, tep1_sw_if_index)

            self.logger.info(self.vapi.cli("show gbp bridge"))
            self.logger.info(self.vapi.cli("show vxlan-gbp tunnel"))
            self.logger.info(self.vapi.cli("show gbp vxlan"))
            self.logger.info(self.vapi.cli("show int addr"))

            # endpoint learnt via the TEP
            self.assertTrue(find_gbp_endpoint(self, ip=l['ip6']))

        self.logger.info(self.vapi.cli("show gbp endpoint"))
        self.logger.info(self.vapi.cli("show ip fib index 1 %s" % l['ip']))

        #
        # Static EP replies to learnt
        #
        for l in learnt:
            p = (Ether(src=ep.mac, dst=self.loop0.local_mac) /
                 IPv6(dst=l['ip6'], src=ep.ip6.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rxs = self.send_and_expect(self.pg0, p*65, self.pg2)

            for rx in rxs:
                self.assertEqual(rx[IP].src, self.pg2.local_ip4)
                self.assertEqual(rx[IP].dst, self.pg2.remote_hosts[1].ip4)
                self.assertEqual(rx[UDP].dport, 48879)
                # the UDP source port is a random value for hashing
                self.assertEqual(rx[VXLAN].gpid, 220)
                self.assertEqual(rx[VXLAN].vni, 101)
                self.assertTrue(rx[VXLAN].flags.G)
                self.assertTrue(rx[VXLAN].flags.Instance)
                self.assertTrue(rx[VXLAN].gpflags.A)
                self.assertFalse(rx[VXLAN].gpflags.D)

                inner = rx[VXLAN].payload

                self.assertEqual(inner[Ether].src, routed_src_mac)
                self.assertEqual(inner[Ether].dst, routed_dst_mac)
                self.assertEqual(inner[IPv6].src, ep.ip6.address)
                self.assertEqual(inner[IPv6].dst, l['ip6'])

        self.logger.info(self.vapi.cli("sh gbp endpoint"))
        for l in learnt:
            self.wait_for_ep_timeout(ip=l['ip'])

        #
        # Static sends to unknown EP with no route
        #
        p = (Ether(src=ep.mac, dst=self.loop0.local_mac) /
             IP(dst="10.0.0.99", src=ep.ip4.address) /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0, [p])

        #
        # Add a route to static EP's v4 and v6 subnet
        #  packets should be sent on the v4/v6 uu=fwd interface resp.
        #
        se_10_24 = VppGbpSubnet(
            self, rd1, "10.0.0.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_TRANSPORT)
        se_10_24.add_vpp_config()

        p = (Ether(src=ep.mac, dst=self.loop0.local_mac) /
             IP(dst="10.0.0.99", src=ep.ip4.address) /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        rxs = self.send_and_expect(self.pg0, [p], self.pg4)
        for rx in rxs:
            self.assertEqual(rx[IP].src, self.pg4.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg4.remote_ip4)
            self.assertEqual(rx[UDP].dport, 48879)
            # the UDP source port is a random value for hashing
            self.assertEqual(rx[VXLAN].gpid, 220)
            self.assertEqual(rx[VXLAN].vni, 114)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # policy is not applied to packets sent to the uu-fwd interfaces
            self.assertFalse(rx[VXLAN].gpflags.A)
            self.assertFalse(rx[VXLAN].gpflags.D)

        #
        # learn some remote IPv4 EPs
        #
        for ii, l in enumerate(learnt):
            # a packet with an sclass from a knwon EPG
            # arriving on an unknown TEP
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=101, gpid=220, flags=0x88) /
                 Ether(src=l['mac'], dst="00:00:00:11:11:11") /
                 IP(src=l['ip'], dst=ep.ip4.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rx = self.send_and_expect(self.pg2, [p], self.pg0)

            # the new TEP
            tep1_sw_if_index = find_vxlan_gbp_tunnel(
                self,
                self.pg2.local_ip4,
                self.pg2.remote_hosts[1].ip4,
                vx_tun_l3.vni)
            self.assertNotEqual(INDEX_INVALID, tep1_sw_if_index)

            # endpoint learnt via the parent GBP-vxlan interface
            self.assertTrue(find_gbp_endpoint(self,
                                              vx_tun_l3._sw_if_index,
                                              ip=l['ip']))

        #
        # Add a remote endpoint from the API
        #
        rep_88 = VppGbpEndpoint(self, vx_tun_l3,
                                epg_220, None,
                                "10.0.0.88", "11.0.0.88",
                                "2001:10::88", "3001::88",
                                ep_flags.GBP_API_ENDPOINT_FLAG_REMOTE,
                                self.pg2.local_ip4,
                                self.pg2.remote_hosts[1].ip4,
                                mac=None)
        rep_88.add_vpp_config()

        #
        # Add a remote endpoint from the API that matches an existing one
        #
        rep_2 = VppGbpEndpoint(self, vx_tun_l3,
                               epg_220, None,
                               learnt[0]['ip'], "11.0.0.101",
                               learnt[0]['ip6'], "3001::101",
                               ep_flags.GBP_API_ENDPOINT_FLAG_REMOTE,
                               self.pg2.local_ip4,
                               self.pg2.remote_hosts[1].ip4,
                               mac=None)
        rep_2.add_vpp_config()

        #
        # Add a route to the leanred EP's v4 subnet
        #  packets should be send on the v4/v6 uu=fwd interface resp.
        #
        se_10_1_24 = VppGbpSubnet(
            self, rd1, "10.0.1.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_TRANSPORT)
        se_10_1_24.add_vpp_config()

        self.logger.info(self.vapi.cli("show gbp endpoint"))

        ips = ["10.0.0.88", learnt[0]['ip']]
        for ip in ips:
            p = (Ether(src=ep.mac, dst=self.loop0.local_mac) /
                 IP(dst=ip, src=ep.ip4.address) /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

            rxs = self.send_and_expect(self.pg0, p*65, self.pg2)

            for rx in rxs:
                self.assertEqual(rx[IP].src, self.pg2.local_ip4)
                self.assertEqual(rx[IP].dst, self.pg2.remote_hosts[1].ip4)
                self.assertEqual(rx[UDP].dport, 48879)
                # the UDP source port is a random value for hashing
                self.assertEqual(rx[VXLAN].gpid, 220)
                self.assertEqual(rx[VXLAN].vni, 101)
                self.assertTrue(rx[VXLAN].flags.G)
                self.assertTrue(rx[VXLAN].flags.Instance)
                self.assertTrue(rx[VXLAN].gpflags.A)
                self.assertFalse(rx[VXLAN].gpflags.D)

                inner = rx[VXLAN].payload

                self.assertEqual(inner[Ether].src, routed_src_mac)
                self.assertEqual(inner[Ether].dst, routed_dst_mac)
                self.assertEqual(inner[IP].src, ep.ip4.address)
                self.assertEqual(inner[IP].dst, ip)

        #
        # remove the API remote EPs, only API sourced is gone, the DP
        # learnt one remains
        #
        rep_88.remove_vpp_config()
        rep_2.remove_vpp_config()

        self.assertTrue(find_gbp_endpoint(self, ip=rep_2.ip4.address))

        p = (Ether(src=ep.mac, dst=self.loop0.local_mac) /
             IP(src=ep.ip4.address, dst=rep_2.ip4.address) /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))
        rxs = self.send_and_expect(self.pg0, [p], self.pg2)

        self.assertFalse(find_gbp_endpoint(self, ip=rep_88.ip4.address))

        p = (Ether(src=ep.mac, dst=self.loop0.local_mac) /
             IP(src=ep.ip4.address, dst=rep_88.ip4.address) /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))
        rxs = self.send_and_expect(self.pg0, [p], self.pg4)

        #
        # to appease the testcase we cannot have the registered EP stll
        # present (because it's DP learnt) when the TC ends so wait until
        # it is removed
        #
        self.wait_for_ep_timeout(ip=rep_88.ip4.address)
        self.wait_for_ep_timeout(ip=rep_2.ip4.address)

        #
        # shutdown with learnt endpoint present
        #
        p = (Ether(src=self.pg2.remote_mac,
                   dst=self.pg2.local_mac) /
             IP(src=self.pg2.remote_hosts[1].ip4,
                dst=self.pg2.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=101, gpid=220, flags=0x88) /
             Ether(src=l['mac'], dst="00:00:00:11:11:11") /
             IP(src=learnt[1]['ip'], dst=ep.ip4.address) /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        rx = self.send_and_expect(self.pg2, [p], self.pg0)

        # endpoint learnt via the parent GBP-vxlan interface
        self.assertTrue(find_gbp_endpoint(self,
                                          vx_tun_l3._sw_if_index,
                                          ip=l['ip']))

        #
        # TODO
        # remote endpoint becomes local
        #
        self.pg2.unconfig_ip4()
        self.pg3.unconfig_ip4()
        self.pg4.unconfig_ip4()

    def test_gbp_redirect(self):
        """ GBP Endpoint Redirect """

        self.vapi.cli("set logging class gbp debug")

        ep_flags = VppEnum.vl_api_gbp_endpoint_flags_t
        routed_dst_mac = "00:0c:0c:0c:0c:0c"
        routed_src_mac = "00:22:bd:f8:19:ff"

        learnt = [{'mac': '00:00:11:11:11:02',
                   'ip': '10.0.1.2',
                   'ip6': '2001:10::2'},
                  {'mac': '00:00:11:11:11:03',
                   'ip': '10.0.1.3',
                   'ip6': '2001:10::3'}]

        #
        # lower the inactive threshold so these tests pass in a
        # reasonable amount of time
        #
        self.vapi.gbp_endpoint_learn_set_inactive_threshold(2)

        #
        # IP tables
        #
        t4 = VppIpTable(self, 1)
        t4.add_vpp_config()
        t6 = VppIpTable(self, 1, True)
        t6.add_vpp_config()

        rd1 = VppGbpRouteDomain(self, 2, t4, t6)
        rd1.add_vpp_config()

        self.loop0.set_mac(self.router_mac)

        #
        # Bind the BVI to the RD
        #
        VppIpInterfaceBind(self, self.loop0, t4).add_vpp_config()
        VppIpInterfaceBind(self, self.loop0, t6).add_vpp_config()

        #
        # Pg7 hosts a BD's UU-fwd
        #
        self.pg7.config_ip4()
        self.pg7.resolve_arp()

        #
        # a GBP bridge domains for the EPs
        #
        bd1 = VppBridgeDomain(self, 1)
        bd1.add_vpp_config()
        gbd1 = VppGbpBridgeDomain(self, bd1, self.loop0)
        gbd1.add_vpp_config()

        bd2 = VppBridgeDomain(self, 2)
        bd2.add_vpp_config()
        gbd2 = VppGbpBridgeDomain(self, bd2, self.loop1)
        gbd2.add_vpp_config()

        # ... and has a /32 and /128 applied
        ip4_addr = VppIpInterfaceAddress(self, gbd1.bvi, "10.0.0.128", 32)
        ip4_addr.add_vpp_config()
        ip6_addr = VppIpInterfaceAddress(self, gbd1.bvi, "2001:10::128", 128)
        ip6_addr.add_vpp_config()
        ip4_addr = VppIpInterfaceAddress(self, gbd2.bvi, "10.0.1.128", 32)
        ip4_addr.add_vpp_config()
        ip6_addr = VppIpInterfaceAddress(self, gbd2.bvi, "2001:11::128", 128)
        ip6_addr.add_vpp_config()

        #
        # The Endpoint-groups in which we are learning endpoints
        #
        epg_220 = VppGbpEndpointGroup(self, 220, rd1, gbd1,
                                      None, gbd1.bvi,
                                      "10.0.0.128",
                                      "2001:10::128")
        epg_220.add_vpp_config()
        epg_221 = VppGbpEndpointGroup(self, 221, rd1, gbd2,
                                      None, gbd2.bvi,
                                      "10.0.1.128",
                                      "2001:11::128")
        epg_221.add_vpp_config()
        epg_222 = VppGbpEndpointGroup(self, 222, rd1, gbd1,
                                      None, gbd1.bvi,
                                      "10.0.2.128",
                                      "2001:12::128")
        epg_222.add_vpp_config()

        #
        # a GBP bridge domains for the SEPs
        #
        bd_uu1 = VppVxlanGbpTunnel(self, self.pg7.local_ip4,
                                   self.pg7.remote_ip4, 116)
        bd_uu1.add_vpp_config()
        bd_uu2 = VppVxlanGbpTunnel(self, self.pg7.local_ip4,
                                   self.pg7.remote_ip4, 117)
        bd_uu2.add_vpp_config()

        bd3 = VppBridgeDomain(self, 3)
        bd3.add_vpp_config()
        gbd3 = VppGbpBridgeDomain(self, bd3, self.loop2, bd_uu1, learn=False)
        gbd3.add_vpp_config()
        bd4 = VppBridgeDomain(self, 4)
        bd4.add_vpp_config()
        gbd4 = VppGbpBridgeDomain(self, bd4, self.loop3, bd_uu2, learn=False)
        gbd4.add_vpp_config()

        #
        # EPGs in which the service endpoints exist
        #
        epg_320 = VppGbpEndpointGroup(self, 320, rd1, gbd3,
                                      None, gbd1.bvi,
                                      "12.0.0.128",
                                      "4001:10::128")
        epg_320.add_vpp_config()
        epg_321 = VppGbpEndpointGroup(self, 321, rd1, gbd4,
                                      None, gbd2.bvi,
                                      "12.0.1.128",
                                      "4001:11::128")
        epg_321.add_vpp_config()

        #
        # three local endpoints
        #
        ep1 = VppGbpEndpoint(self, self.pg0,
                             epg_220, None,
                             "10.0.0.1", "11.0.0.1",
                             "2001:10::1", "3001:10::1")
        ep1.add_vpp_config()
        ep2 = VppGbpEndpoint(self, self.pg1,
                             epg_221, None,
                             "10.0.1.1", "11.0.1.1",
                             "2001:11::1", "3001:11::1")
        ep2.add_vpp_config()
        ep3 = VppGbpEndpoint(self, self.pg2,
                             epg_222, None,
                             "10.0.2.2", "11.0.2.2",
                             "2001:12::1", "3001:12::1")
        ep3.add_vpp_config()

        #
        # service endpoints
        #
        sep1 = VppGbpEndpoint(self, self.pg3,
                              epg_320, None,
                              "12.0.0.1", "13.0.0.1",
                              "4001:10::1", "5001:10::1")
        sep1.add_vpp_config()
        sep2 = VppGbpEndpoint(self, self.pg4,
                              epg_320, None,
                              "12.0.0.2", "13.0.0.2",
                              "4001:10::2", "5001:10::2")
        sep2.add_vpp_config()
        sep3 = VppGbpEndpoint(self, self.pg5,
                              epg_321, None,
                              "12.0.1.1", "13.0.1.1",
                              "4001:11::1", "5001:11::1")
        sep3.add_vpp_config()
        # this EP is not installed immediately
        sep4 = VppGbpEndpoint(self, self.pg6,
                              epg_321, None,
                              "12.0.1.2", "13.0.1.2",
                              "4001:11::2", "5001:11::2")

        #
        # an L2 switch packet between local EPs in different EPGs
        #  different dest ports on each so the are LB hashed differently
        #
        p4 = [(Ether(src=ep1.mac, dst=ep3.mac) /
               IP(src=ep1.ip4.address, dst=ep3.ip4.address) /
               UDP(sport=1234, dport=1234) /
               Raw('\xa5' * 100)),
              (Ether(src=ep3.mac, dst=ep1.mac) /
               IP(src=ep3.ip4.address, dst=ep1.ip4.address) /
               UDP(sport=1234, dport=1234) /
               Raw('\xa5' * 100))]
        p6 = [(Ether(src=ep1.mac, dst=ep3.mac) /
               IPv6(src=ep1.ip6.address, dst=ep3.ip6.address) /
               UDP(sport=1234, dport=1234) /
               Raw('\xa5' * 100)),
              (Ether(src=ep3.mac, dst=ep1.mac) /
               IPv6(src=ep3.ip6.address, dst=ep1.ip6.address) /
               UDP(sport=1234, dport=1230) /
               Raw('\xa5' * 100))]

        # should be dropped since no contract yet
        self.send_and_assert_no_replies(self.pg0, [p4[0]])
        self.send_and_assert_no_replies(self.pg0, [p6[0]])

        #
        # Add a contract with a rule to load-balance redirect via SEP1 and SEP2
        # one of the next-hops is via an EP that is not known
        #
        acl = VppGbpAcl(self)
        rule4 = acl.create_rule(permit_deny=1, proto=17)
        rule6 = acl.create_rule(is_ipv6=1, permit_deny=1, proto=17)
        acl_index = acl.add_vpp_config([rule4, rule6])

        #
        # test the src-ip hash mode
        #
        c1 = VppGbpContract(
            self, 220, 222, acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                [VppGbpContractNextHop(sep1.vmac, sep1.epg.bd,
                                       sep1.ip4, sep1.epg.rd),
                 VppGbpContractNextHop(sep2.vmac, sep2.epg.bd,
                                       sep2.ip4, sep2.epg.rd)]),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                 VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                 [VppGbpContractNextHop(sep3.vmac, sep3.epg.bd,
                                        sep3.ip6, sep3.epg.rd),
                  VppGbpContractNextHop(sep4.vmac, sep4.epg.bd,
                                        sep4.ip6, sep4.epg.rd)])],
            [ETH_P_IP, ETH_P_IPV6])
        c1.add_vpp_config()

        c2 = VppGbpContract(
            self, 222, 220, acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                [VppGbpContractNextHop(sep1.vmac, sep1.epg.bd,
                                       sep1.ip4, sep1.epg.rd),
                 VppGbpContractNextHop(sep2.vmac, sep2.epg.bd,
                                       sep2.ip4, sep2.epg.rd)]),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                 VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                 [VppGbpContractNextHop(sep3.vmac, sep3.epg.bd,
                                        sep3.ip6, sep3.epg.rd),
                  VppGbpContractNextHop(sep4.vmac, sep4.epg.bd,
                                        sep4.ip6, sep4.epg.rd)])],
            [ETH_P_IP, ETH_P_IPV6])
        c2.add_vpp_config()

        #
        # send again with the contract preset, now packets arrive
        # at SEP1 or SEP2 depending on the hashing
        #
        rxs = self.send_and_expect(self.pg0, p4[0] * 17, sep1.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep1.mac)
            self.assertEqual(rx[IP].src, ep1.ip4.address)
            self.assertEqual(rx[IP].dst, ep3.ip4.address)

        rxs = self.send_and_expect(self.pg2, p4[1] * 17, sep2.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep2.mac)
            self.assertEqual(rx[IP].src, ep3.ip4.address)
            self.assertEqual(rx[IP].dst, ep1.ip4.address)

        rxs = self.send_and_expect(self.pg0, p6[0] * 17, self.pg7)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 117)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # redirect policy has been applied
            self.assertTrue(rx[VXLAN].gpflags.A)
            self.assertFalse(rx[VXLAN].gpflags.D)

            inner = rx[VXLAN].payload

            self.assertEqual(inner[Ether].src, routed_src_mac)
            self.assertEqual(inner[Ether].dst, sep4.mac)
            self.assertEqual(inner[IPv6].src, ep1.ip6.address)
            self.assertEqual(inner[IPv6].dst, ep3.ip6.address)

        rxs = self.send_and_expect(self.pg2, p6[1] * 17, sep3.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep3.mac)
            self.assertEqual(rx[IPv6].src, ep3.ip6.address)
            self.assertEqual(rx[IPv6].dst, ep1.ip6.address)

        #
        # programme the unknown EP
        #
        sep4.add_vpp_config()

        rxs = self.send_and_expect(self.pg0, p6[0] * 17, sep4.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep4.mac)
            self.assertEqual(rx[IPv6].src, ep1.ip6.address)
            self.assertEqual(rx[IPv6].dst, ep3.ip6.address)

        #
        # and revert back to unprogrammed
        #
        sep4.remove_vpp_config()

        rxs = self.send_and_expect(self.pg0, p6[0] * 17, self.pg7)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 117)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # redirect policy has been applied
            self.assertTrue(rx[VXLAN].gpflags.A)
            self.assertFalse(rx[VXLAN].gpflags.D)

            inner = rx[VXLAN].payload

            self.assertEqual(inner[Ether].src, routed_src_mac)
            self.assertEqual(inner[Ether].dst, sep4.mac)
            self.assertEqual(inner[IPv6].src, ep1.ip6.address)
            self.assertEqual(inner[IPv6].dst, ep3.ip6.address)

        c1.remove_vpp_config()
        c2.remove_vpp_config()

        #
        # test the symmetric hash mode
        #
        c1 = VppGbpContract(
            self, 220, 222, acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SYMMETRIC,
                [VppGbpContractNextHop(sep1.vmac, sep1.epg.bd,
                                       sep1.ip4, sep1.epg.rd),
                 VppGbpContractNextHop(sep2.vmac, sep2.epg.bd,
                                       sep2.ip4, sep2.epg.rd)]),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                 VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SYMMETRIC,
                 [VppGbpContractNextHop(sep3.vmac, sep3.epg.bd,
                                        sep3.ip6, sep3.epg.rd),
                  VppGbpContractNextHop(sep4.vmac, sep4.epg.bd,
                                        sep4.ip6, sep4.epg.rd)])],
            [ETH_P_IP, ETH_P_IPV6])
        c1.add_vpp_config()

        c2 = VppGbpContract(
            self, 222, 220, acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SYMMETRIC,
                [VppGbpContractNextHop(sep1.vmac, sep1.epg.bd,
                                       sep1.ip4, sep1.epg.rd),
                 VppGbpContractNextHop(sep2.vmac, sep2.epg.bd,
                                       sep2.ip4, sep2.epg.rd)]),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                 VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SYMMETRIC,
                 [VppGbpContractNextHop(sep3.vmac, sep3.epg.bd,
                                        sep3.ip6, sep3.epg.rd),
                  VppGbpContractNextHop(sep4.vmac, sep4.epg.bd,
                                        sep4.ip6, sep4.epg.rd)])],
            [ETH_P_IP, ETH_P_IPV6])
        c2.add_vpp_config()

        #
        # send again with the contract preset, now packets arrive
        # at SEP1 for both directions
        #
        rxs = self.send_and_expect(self.pg0, p4[0] * 17, sep1.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep1.mac)
            self.assertEqual(rx[IP].src, ep1.ip4.address)
            self.assertEqual(rx[IP].dst, ep3.ip4.address)

        rxs = self.send_and_expect(self.pg2, p4[1] * 17, sep1.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep1.mac)
            self.assertEqual(rx[IP].src, ep3.ip4.address)
            self.assertEqual(rx[IP].dst, ep1.ip4.address)

        #
        # programme the unknown EP for the L3 tests
        #
        sep4.add_vpp_config()

        #
        # an L3 switch packet between local EPs in different EPGs
        #  different dest ports on each so the are LB hashed differently
        #
        p4 = [(Ether(src=ep1.mac, dst=str(self.router_mac)) /
               IP(src=ep1.ip4.address, dst=ep2.ip4.address) /
               UDP(sport=1234, dport=1234) /
               Raw('\xa5' * 100)),
              (Ether(src=ep2.mac, dst=str(self.router_mac)) /
               IP(src=ep2.ip4.address, dst=ep1.ip4.address) /
               UDP(sport=1234, dport=1234) /
               Raw('\xa5' * 100))]
        p6 = [(Ether(src=ep1.mac, dst=str(self.router_mac)) /
               IPv6(src=ep1.ip6.address, dst=ep2.ip6.address) /
               UDP(sport=1234, dport=1234) /
               Raw('\xa5' * 100)),
              (Ether(src=ep2.mac, dst=str(self.router_mac)) /
               IPv6(src=ep2.ip6.address, dst=ep1.ip6.address) /
               UDP(sport=1234, dport=1234) /
               Raw('\xa5' * 100))]

        c3 = VppGbpContract(
            self, 220, 221, acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SYMMETRIC,
                [VppGbpContractNextHop(sep1.vmac, sep1.epg.bd,
                                       sep1.ip4, sep1.epg.rd),
                 VppGbpContractNextHop(sep2.vmac, sep2.epg.bd,
                                       sep2.ip4, sep2.epg.rd)]),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                 VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SYMMETRIC,
                 [VppGbpContractNextHop(sep3.vmac, sep3.epg.bd,
                                        sep3.ip6, sep3.epg.rd),
                  VppGbpContractNextHop(sep4.vmac, sep4.epg.bd,
                                        sep4.ip6, sep4.epg.rd)])],
            [ETH_P_IP, ETH_P_IPV6])
        c3.add_vpp_config()

        rxs = self.send_and_expect(self.pg0, p4[0] * 17, sep1.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep1.mac)
            self.assertEqual(rx[IP].src, ep1.ip4.address)
            self.assertEqual(rx[IP].dst, ep2.ip4.address)

        #
        # learn a remote EP in EPG 221
        #
        vx_tun_l3 = VppGbpVxlanTunnel(
            self, 444, rd1.rd_id,
            VppEnum.vl_api_gbp_vxlan_tunnel_mode_t.GBP_VXLAN_TUNNEL_MODE_L3)
        vx_tun_l3.add_vpp_config()

        c4 = VppGbpContract(
            self, 221, 220, acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                []),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                 [])],
            [ETH_P_IP, ETH_P_IPV6])
        c4.add_vpp_config()

        p = (Ether(src=self.pg7.remote_mac,
                   dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4,
                dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=444, gpid=221, flags=0x88) /
             Ether(src="00:22:22:22:22:33", dst=str(self.router_mac)) /
             IP(src="10.0.0.88", dst=ep1.ip4.address) /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        rx = self.send_and_expect(self.pg7, [p], self.pg0)

        # endpoint learnt via the parent GBP-vxlan interface
        self.assertTrue(find_gbp_endpoint(self,
                                          vx_tun_l3._sw_if_index,
                                          ip="10.0.0.88"))

        p = (Ether(src=self.pg7.remote_mac,
                   dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4,
                dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=444, gpid=221, flags=0x88) /
             Ether(src="00:22:22:22:22:33", dst=str(self.router_mac)) /
             IPv6(src="2001:10::88", dst=ep1.ip6.address) /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        rx = self.send_and_expect(self.pg7, [p], self.pg0)

        # endpoint learnt via the parent GBP-vxlan interface
        self.assertTrue(find_gbp_endpoint(self,
                                          vx_tun_l3._sw_if_index,
                                          ip="2001:10::88"))

        #
        # L3 switch from local to remote EP
        #
        p4 = [(Ether(src=ep1.mac, dst=str(self.router_mac)) /
               IP(src=ep1.ip4.address, dst="10.0.0.88") /
               UDP(sport=1234, dport=1234) /
               Raw('\xa5' * 100))]
        p6 = [(Ether(src=ep1.mac, dst=str(self.router_mac)) /
               IPv6(src=ep1.ip6.address, dst="2001:10::88") /
               UDP(sport=1234, dport=1234) /
               Raw('\xa5' * 100))]

        rxs = self.send_and_expect(self.pg0, p4[0] * 17, sep1.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep1.mac)
            self.assertEqual(rx[IP].src, ep1.ip4.address)
            self.assertEqual(rx[IP].dst, "10.0.0.88")

        rxs = self.send_and_expect(self.pg0, p6[0] * 17, sep4.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep4.mac)
            self.assertEqual(rx[IPv6].src, ep1.ip6.address)
            self.assertEqual(rx[IPv6].dst, "2001:10::88")

        #
        # test the dst-ip hash mode
        #
        c5 = VppGbpContract(
            self, 220, 221, acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_DST_IP,
                [VppGbpContractNextHop(sep1.vmac, sep1.epg.bd,
                                       sep1.ip4, sep1.epg.rd),
                 VppGbpContractNextHop(sep2.vmac, sep2.epg.bd,
                                       sep2.ip4, sep2.epg.rd)]),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_DST_IP,
                 [VppGbpContractNextHop(sep3.vmac, sep3.epg.bd,
                                        sep3.ip6, sep3.epg.rd),
                  VppGbpContractNextHop(sep4.vmac, sep4.epg.bd,
                                        sep4.ip6, sep4.epg.rd)])],
            [ETH_P_IP, ETH_P_IPV6])
        c5.add_vpp_config()

        rxs = self.send_and_expect(self.pg0, p4[0] * 17, sep1.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep1.mac)
            self.assertEqual(rx[IP].src, ep1.ip4.address)
            self.assertEqual(rx[IP].dst, "10.0.0.88")

        rxs = self.send_and_expect(self.pg0, p6[0] * 17, sep3.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep3.mac)
            self.assertEqual(rx[IPv6].src, ep1.ip6.address)
            self.assertEqual(rx[IPv6].dst, "2001:10::88")

        #
        # cleanup
        #
        self.pg7.unconfig_ip4()

    def test_gbp_l3_out(self):
        """ GBP L3 Out """

        ep_flags = VppEnum.vl_api_gbp_endpoint_flags_t
        self.vapi.cli("set logging class gbp debug")

        routed_dst_mac = "00:0c:0c:0c:0c:0c"
        routed_src_mac = "00:22:bd:f8:19:ff"

        #
        # IP tables
        #
        t4 = VppIpTable(self, 1)
        t4.add_vpp_config()
        t6 = VppIpTable(self, 1, True)
        t6.add_vpp_config()

        rd1 = VppGbpRouteDomain(self, 2, t4, t6)
        rd1.add_vpp_config()

        self.loop0.set_mac(self.router_mac)

        #
        # Bind the BVI to the RD
        #
        VppIpInterfaceBind(self, self.loop0, t4).add_vpp_config()
        VppIpInterfaceBind(self, self.loop0, t6).add_vpp_config()

        #
        # Pg7 hosts a BD's BUM
        # Pg1 some other l3 interface
        #
        self.pg7.config_ip4()
        self.pg7.resolve_arp()

        #
        # a GBP external bridge domains for the EPs
        #
        bd1 = VppBridgeDomain(self, 1)
        bd1.add_vpp_config()
        gbd1 = VppGbpBridgeDomain(self, bd1, self.loop0)
        gbd1.add_vpp_config()

        #
        # The Endpoint-groups in which the external endpoints exist
        #
        epg_220 = VppGbpEndpointGroup(self, 220, rd1, gbd1,
                                      None, gbd1.bvi,
                                      "10.0.0.128",
                                      "2001:10::128")
        epg_220.add_vpp_config()

        # the BVIs have the subnets applied ...
        ip4_addr = VppIpInterfaceAddress(self, gbd1.bvi, "10.0.0.128", 24)
        ip4_addr.add_vpp_config()
        ip6_addr = VppIpInterfaceAddress(self, gbd1.bvi, "2001:10::128", 64)
        ip6_addr.add_vpp_config()

        # ... which are L3-out subnets
        l3o_1 = VppGbpSubnet(
            self, rd1, "10.0.0.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
            epg=200)
        l3o_1.add_vpp_config()

        #
        # an external interface attached to the outside world and the
        # external BD
        #
        vlan_100 = VppDot1QSubint(self, self.pg0, 100)
        vlan_100.admin_up()
        ext_itf = VppGbpExtItf(self, vlan_100, bd1, rd1)
        ext_itf.add_vpp_config()

        #
        # a multicast vxlan-gbp tunnel for broadcast in the BD
        #
        tun_bm = VppVxlanGbpTunnel(self, self.pg7.local_ip4,
                                   "239.1.1.1", 88,
                                   mcast_itf=self.pg7)
        tun_bm.add_vpp_config()
        bp_bm = VppBridgeDomainPort(self, bd1, tun_bm,
                                    port_type=L2_PORT_TYPE.NORMAL)
        bp_bm.add_vpp_config()

        #
        # an unicast vxlan-gbp for inter-BD traffic
        #
        vx_tun_l3 = VppGbpVxlanTunnel(
            self, 444, rd1.rd_id,
            VppEnum.vl_api_gbp_vxlan_tunnel_mode_t.GBP_VXLAN_TUNNEL_MODE_L3)
        vx_tun_l3.add_vpp_config()

        #
        # packets destined to unkown addresses in the BVI's subnet
        # are ARP'd for
        #
        p4 = (Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
              Dot1Q(vlan=100) /
              IP(src="10.0.0.1", dst="10.0.0.88") /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))
        p6 = (Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
              Dot1Q(vlan=100) /
              IPv6(src="2001:10::1", dst="2001:10::88") /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))

        rxs = self.send_and_expect(self.pg0, p4 * 1, self.pg7)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            # self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, "239.1.1.1")
            self.assertEqual(rx[VXLAN].vni, 88)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # policy was applied to the original IP packet
            self.assertEqual(rx[VXLAN].gpid, 200)
            self.assertTrue(rx[VXLAN].gpflags.A)
            self.assertFalse(rx[VXLAN].gpflags.D)

            inner = rx[VXLAN].payload

            self.assertTrue(inner.haslayer(ARP))

        #
        # An external Endpoint
        #
        eep = VppGbpEndpoint(self, vlan_100,
                             epg_220, None,
                             "10.0.0.1", "11.0.0.1",
                             "2001:10::1", "3001::1",
                             ep_flags.GBP_API_ENDPOINT_FLAG_EXTERNAL)
        eep.add_vpp_config()

        #
        # A remote endpoint
        #
        rep = VppGbpEndpoint(self, vx_tun_l3,
                             epg_220, None,
                             "10.0.0.101", "11.0.0.101",
                             "2001:10::101", "3001::101",
                             ep_flags.GBP_API_ENDPOINT_FLAG_REMOTE,
                             self.pg7.local_ip4,
                             self.pg7.remote_ip4,
                             mac=None)
        rep.add_vpp_config()

        #
        # remote to external
        #
        p = (Ether(src=self.pg7.remote_mac,
                   dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4,
                dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=444, gpid=220, flags=0x88) /
             Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
             IP(src="10.0.0.101", dst="10.0.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        rxs = self.send_and_expect(self.pg7, p * 1, self.pg0)

        #
        # A subnet reachable through the external EP
        #
        ip_220 = VppIpRoute(self, "10.220.0.0", 24,
                            [VppRoutePath(eep.ip4.address,
                                          eep.epg.bvi.sw_if_index)],
                            table_id=t4.table_id)
        ip_220.add_vpp_config()

        l3o_220 = VppGbpSubnet(
            self, rd1, "10.220.0.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
            epg=220)
        l3o_220.add_vpp_config()

        p = (Ether(src=self.pg7.remote_mac,
                   dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4,
                dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=444, gpid=220, flags=0x88) /
             Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
             IP(src="10.0.0.101", dst="10.220.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        rxs = self.send_and_expect(self.pg7, p * 1, self.pg0)

        #
        # another external subnet, this time in a different EPG
        #
        ip_200 = VppIpRoute(self, "10.200.0.0", 24,
                            [VppRoutePath(eep.ip4.address,
                                          eep.epg.bvi.sw_if_index)],
                            table_id=t4.table_id)
        ip_200.add_vpp_config()

        l3o_200 = VppGbpSubnet(
            self, rd1, "10.200.0.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
            epg=200)
        l3o_200.add_vpp_config()

        p = (Ether(src=self.pg7.remote_mac,
                   dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4,
                dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=444, gpid=220, flags=0x88) /
             Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
             IP(src="10.0.0.101", dst="10.200.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        #
        # packets dropped due to lack of contract.
        #
        rxs = self.send_and_assert_no_replies(self.pg7, p * 1)

        #
        # from the the subnet in EPG 220 beyond the external to remote
        #
        p4 = (Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
              Dot1Q(vlan=100) /
              IP(src="10.220.0.1", dst=rep.ip4.address) /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))

        rxs = self.send_and_expect(self.pg0, p4 * 1, self.pg7)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 444)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            self.assertTrue(rx[VXLAN].gpflags.A)
            self.assertFalse(rx[VXLAN].gpflags.D)

        #
        # from the the subnet in EPG 200 beyond the external to remote
        # dropped due to no contract
        #
        p4 = (Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
              Dot1Q(vlan=100) /
              IP(src="10.200.0.1", dst=rep.ip4.address) /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))

        rxs = self.send_and_assert_no_replies(self.pg0, p4 * 1)

        #
        # add a contract
        #
        acl = VppGbpAcl(self)
        rule = acl.create_rule(permit_deny=1, proto=17)
        rule2 = acl.create_rule(is_ipv6=1, permit_deny=1, proto=17)
        acl_index = acl.add_vpp_config([rule, rule2])
        c1 = VppGbpContract(
            self, 200, 220, acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                []),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                 [])],
            [ETH_P_IP, ETH_P_IPV6])
        c1.add_vpp_config()

        rxs = self.send_and_expect(self.pg0, p4 * 1, self.pg7)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 444)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            self.assertTrue(rx[VXLAN].gpflags.A)
            self.assertFalse(rx[VXLAN].gpflags.D)

        #
        # cleanup
        #
        self.pg7.unconfig_ip4()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
