#!/usr/bin/env python3

from socket import AF_INET, AF_INET6, inet_pton, inet_ntop
import unittest
from ipaddress import ip_address, IPv4Network, IPv6Network

from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP, Dot1Q
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, \
    ICMPv6ND_NA, ICMPv6EchoRequest
from scapy.utils6 import in6_getnsma, in6_getnsmac
from scapy.layers.vxlan import VXLAN
from scapy.data import ETH_P_IP, ETH_P_IPV6, ETH_P_ARP

from framework import VppTestCase, VppTestRunner
from vpp_object import VppObject
from vpp_interface import VppInterface
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable, \
    VppIpInterfaceAddress, VppIpInterfaceBind, find_route, FibPathProto, \
    FibPathType
from vpp_l2 import VppBridgeDomain, VppBridgeDomainPort, \
    VppBridgeDomainArpEntry, VppL2FibEntry, find_bridge_domain_port, VppL2Vtr
from vpp_sub_interface import L2_VTR_OP, VppDot1QSubint
from vpp_ip import DpoProto, get_dpo_proto
from vpp_papi import VppEnum, MACAddress
from vpp_vxlan_gbp_tunnel import find_vxlan_gbp_tunnel, INDEX_INVALID, \
    VppVxlanGbpTunnel
from vpp_neighbor import VppNeighbor
from vpp_acl import AclRule, VppAcl
try:
    text_type = unicode
except NameError:
    text_type = str

NUM_PKTS = 67


def find_gbp_endpoint(test, sw_if_index=None, ip=None, mac=None,
                      tep=None, sclass=None, flags=None):
    if ip:
        vip = ip
    if mac:
        vmac = MACAddress(mac)

    eps = test.vapi.gbp_endpoint_dump()

    for ep in eps:
        if tep:
            src = tep[0]
            dst = tep[1]
            if src != str(ep.endpoint.tun.src) or \
               dst != str(ep.endpoint.tun.dst):
                continue
        if sw_if_index:
            if ep.endpoint.sw_if_index != sw_if_index:
                continue
        if sclass:
            if ep.endpoint.sclass != sclass:
                continue
        if flags:
            if flags != (flags & ep.endpoint.flags):
                continue
        if ip:
            for eip in ep.endpoint.ips:
                if vip == str(eip):
                    return True
        if mac:
            if vmac == ep.endpoint.mac:
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

        self._ip4 = ip4
        self._fip4 = fip4
        self._ip6 = ip6
        self._fip6 = fip6

        if mac:
            self.vmac = MACAddress(self.itf.remote_mac)
        else:
            self.vmac = MACAddress("00:00:00:00:00:00")

        self.flags = flags
        self.tun_src = tun_src
        self.tun_dst = tun_dst

    def add_vpp_config(self):
        res = self._test.vapi.gbp_endpoint_add(
            self.itf.sw_if_index,
            [self.ip4, self.ip6],
            self.vmac.packed,
            self.epg.sclass,
            self.flags,
            self.tun_src,
            self.tun_dst)
        self.handle = res.handle
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_endpoint_del(self.handle)

    def object_id(self):
        return "gbp-endpoint:[%d==%d:%s:%d]" % (self.handle,
                                                self.itf.sw_if_index,
                                                self.ip4,
                                                self.epg.sclass)

    def query_vpp_config(self):
        return find_gbp_endpoint(self._test,
                                 self.itf.sw_if_index,
                                 self.ip4)


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
            self.epg.sclass,
            self.is_ext)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_recirc_add_del(
            0,
            self.recirc.sw_if_index,
            self.epg.sclass,
            self.is_ext)

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

    def __init__(self, test, itf, bd, rd, anon=False):
        self._test = test
        self.itf = itf
        self.bd = bd
        self.rd = rd
        self.flags = 1 if anon else 0

    def add_vpp_config(self):
        self._test.vapi.gbp_ext_itf_add_del(
            1, self.itf.sw_if_index, self.bd.bd_id, self.rd.rd_id, self.flags)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_ext_itf_add_del(
            0, self.itf.sw_if_index, self.bd.bd_id, self.rd.rd_id, self.flags)

    def object_id(self):
        return "gbp-ext-itf:[%d]%s" % (self.itf.sw_if_index,
                                       " [anon]" if self.flags else "")

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
                 type, sw_if_index=None, sclass=None):
        self._test = test
        self.rd_id = rd.rd_id
        a = ip_address(address)
        if 4 == a.version:
            self.prefix = IPv4Network("%s/%d" % (address, address_len),
                                      strict=False)
        else:
            self.prefix = IPv6Network("%s/%d" % (address, address_len),
                                      strict=False)
        self.type = type
        self.sw_if_index = sw_if_index
        self.sclass = sclass

    def add_vpp_config(self):
        self._test.vapi.gbp_subnet_add_del(
            1,
            self.rd_id,
            self.prefix,
            self.type,
            sw_if_index=self.sw_if_index if self.sw_if_index else 0xffffffff,
            sclass=self.sclass if self.sclass else 0xffff)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_subnet_add_del(
            0,
            self.rd_id,
            self.prefix,
            self.type)

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


class VppGbpEndpointRetention(object):
    def __init__(self, remote_ep_timeout=0xffffffff):
        self.remote_ep_timeout = remote_ep_timeout

    def encode(self):
        return {'remote_ep_timeout': self.remote_ep_timeout}


class VppGbpEndpointGroup(VppObject):
    """
    GBP Endpoint Group
    """

    def __init__(self, test, vnid, sclass, rd, bd, uplink,
                 bvi, bvi_ip4, bvi_ip6=None,
                 retention=VppGbpEndpointRetention()):
        self._test = test
        self.uplink = uplink
        self.bvi = bvi
        self.bvi_ip4 = bvi_ip4
        self.bvi_ip6 = bvi_ip6
        self.vnid = vnid
        self.bd = bd
        self.rd = rd
        self.sclass = sclass
        if 0 == self.sclass:
            self.sclass = 0xffff
        self.retention = retention

    def add_vpp_config(self):
        self._test.vapi.gbp_endpoint_group_add(
            self.vnid,
            self.sclass,
            self.bd.bd.bd_id,
            self.rd.rd_id,
            self.uplink.sw_if_index if self.uplink else INDEX_INVALID,
            self.retention.encode())
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_endpoint_group_del(self.sclass)

    def object_id(self):
        return "gbp-endpoint-group:[%d]" % (self.vnid)

    def query_vpp_config(self):
        epgs = self._test.vapi.gbp_endpoint_group_dump()
        for epg in epgs:
            if epg.epg.vnid == self.vnid:
                return True
        return False


class VppGbpBridgeDomain(VppObject):
    """
    GBP Bridge Domain
    """

    def __init__(self, test, bd, rd, bvi, uu_fwd=None,
                 bm_flood=None, learn=True,
                 uu_drop=False, bm_drop=False,
                 ucast_arp=False):
        self._test = test
        self.bvi = bvi
        self.uu_fwd = uu_fwd
        self.bm_flood = bm_flood
        self.bd = bd
        self.rd = rd

        e = VppEnum.vl_api_gbp_bridge_domain_flags_t

        self.flags = e.GBP_BD_API_FLAG_NONE
        if not learn:
            self.flags |= e.GBP_BD_API_FLAG_DO_NOT_LEARN
        if uu_drop:
            self.flags |= e.GBP_BD_API_FLAG_UU_FWD_DROP
        if bm_drop:
            self.flags |= e.GBP_BD_API_FLAG_MCAST_DROP
        if ucast_arp:
            self.flags |= e.GBP_BD_API_FLAG_UCAST_ARP

    def add_vpp_config(self):
        self._test.vapi.gbp_bridge_domain_add(
            self.bd.bd_id,
            self.rd.rd_id,
            self.flags,
            self.bvi.sw_if_index,
            self.uu_fwd.sw_if_index if self.uu_fwd else INDEX_INVALID,
            self.bm_flood.sw_if_index if self.bm_flood else INDEX_INVALID)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_bridge_domain_del(self.bd.bd_id)

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

    def __init__(self, test, rd_id, scope, t4, t6, ip4_uu=None, ip6_uu=None):
        self._test = test
        self.rd_id = rd_id
        self.scope = scope
        self.t4 = t4
        self.t6 = t6
        self.ip4_uu = ip4_uu
        self.ip6_uu = ip6_uu

    def add_vpp_config(self):
        self._test.vapi.gbp_route_domain_add(
            self.rd_id,
            self.scope,
            self.t4.table_id,
            self.t6.table_id,
            self.ip4_uu.sw_if_index if self.ip4_uu else INDEX_INVALID,
            self.ip6_uu.sw_if_index if self.ip6_uu else INDEX_INVALID)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_route_domain_del(self.rd_id)

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
        return {'ip': self.ip,
                'mac': self.mac.packed,
                'bd_id': self.bd.bd.bd_id,
                'rd_id': self.rd.rd_id}


class VppGbpContractRule():
    def __init__(self, action, hash_mode, nhs=None):
        self.action = action
        self.hash_mode = hash_mode
        self.nhs = [] if nhs is None else nhs

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

    def __repr__(self):
        return '<VppGbpContractRule action=%s, hash_mode=%s>' % (
            self.action, self.hash_mode)


class VppGbpContract(VppObject):
    """
    GBP Contract
    """

    def __init__(self, test, scope, sclass, dclass, acl_index,
                 rules, allowed_ethertypes):
        self._test = test
        if not isinstance(rules, list):
            raise ValueError("'rules' must be a list.")
        if not isinstance(allowed_ethertypes, list):
            raise ValueError("'allowed_ethertypes' must be a list.")
        self.scope = scope
        self.acl_index = acl_index
        self.sclass = sclass
        self.dclass = dclass
        self.rules = rules
        self.allowed_ethertypes = allowed_ethertypes
        while (len(self.allowed_ethertypes) < 16):
            self.allowed_ethertypes.append(0)

    def add_vpp_config(self):
        rules = []
        for r in self.rules:
            rules.append(r.encode())
        r = self._test.vapi.gbp_contract_add_del(
            is_add=1,
            contract={
                'acl_index': self.acl_index,
                'scope': self.scope,
                'sclass': self.sclass,
                'dclass': self.dclass,
                'n_rules': len(rules),
                'rules': rules,
                'n_ether_types': len(self.allowed_ethertypes),
                'allowed_ethertypes': self.allowed_ethertypes})
        self.stats_index = r.stats_index
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_contract_add_del(
            is_add=0,
            contract={
                'acl_index': self.acl_index,
                'scope': self.scope,
                'sclass': self.sclass,
                'dclass': self.dclass,
                'n_rules': 0,
                'rules': [],
                'n_ether_types': len(self.allowed_ethertypes),
                'allowed_ethertypes': self.allowed_ethertypes})

    def object_id(self):
        return "gbp-contract:[%d:%d:%d:%d]" % (self.scope,
                                               self.sclass,
                                               self.dclass,
                                               self.acl_index)

    def query_vpp_config(self):
        cs = self._test.vapi.gbp_contract_dump()
        for c in cs:
            if c.contract.scope == self.scope \
               and c.contract.sclass == self.sclass \
               and c.contract.dclass == self.dclass:
                return True
        return False

    def get_drop_stats(self):
        c = self._test.statistics.get_counter("/net/gbp/contract/drop")
        return c[0][self.stats_index]

    def get_permit_stats(self):
        c = self._test.statistics.get_counter("/net/gbp/contract/permit")
        return c[0][self.stats_index]


class VppGbpVxlanTunnel(VppInterface):
    """
    GBP VXLAN tunnel
    """

    def __init__(self, test, vni, bd_rd_id, mode, src):
        super(VppGbpVxlanTunnel, self).__init__(test)
        self._test = test
        self.vni = vni
        self.bd_rd_id = bd_rd_id
        self.mode = mode
        self.src = src

    def add_vpp_config(self):
        r = self._test.vapi.gbp_vxlan_tunnel_add(
            self.vni,
            self.bd_rd_id,
            self.mode,
            self.src)
        self.set_sw_if_index(r.sw_if_index)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_vxlan_tunnel_del(self.vni)

    def object_id(self):
        return "gbp-vxlan:%d" % (self.sw_if_index)

    def query_vpp_config(self):
        return find_gbp_vxlan(self._test, self.vni)


class TestGBP(VppTestCase):
    """ GBP Test Case """

    @property
    def nat_config_flags(self):
        return VppEnum.vl_api_nat_config_flags_t

    @property
    def nat44_config_flags(self):
        return VppEnum.vl_api_nat44_config_flags_t

    @classmethod
    def setUpClass(cls):
        super(TestGBP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestGBP, cls).tearDownClass()

    def setUp(self):
        super(TestGBP, self).setUp()

        self.create_pg_interfaces(range(9))
        self.create_loopback_interfaces(8)

        self.router_mac = MACAddress("00:11:22:33:44:55")

        for i in self.pg_interfaces:
            i.admin_up()
        for i in self.lo_interfaces:
            i.admin_up()

        self.vlan_100 = VppDot1QSubint(self, self.pg0, 100)
        self.vlan_100.admin_up()
        self.vlan_101 = VppDot1QSubint(self, self.pg0, 101)
        self.vlan_101.admin_up()
        self.vlan_102 = VppDot1QSubint(self, self.pg0, 102)
        self.vlan_102.admin_up()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()
        super(TestGBP, self).tearDown()
        for i in self.lo_interfaces:
            i.remove_vpp_config()
        self.lo_interfaces = []
        self.vlan_102.remove_vpp_config()
        self.vlan_101.remove_vpp_config()
        self.vlan_100.remove_vpp_config()

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

    def send_and_expect_routed6(self, src, tx, dst, src_mac):
        rx = self.send_and_expect(src, tx, dst)

        for r in rx:
            self.assertEqual(r[Ether].src, src_mac)
            self.assertEqual(r[Ether].dst, dst.remote_mac)
            self.assertEqual(r[IPv6].src, tx[0][IPv6].src)
            self.assertEqual(r[IPv6].dst, tx[0][IPv6].dst)
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

    def send_and_expect_no_arp(self, src, tx, dst):
        self.pg_send(src, tx)
        dst.get_capture(0, timeout=1)
        dst.assert_nothing_captured(remark="")
        timeout = 0.1

    def send_and_expect_arp(self, src, tx, dst):
        rx = self.send_and_expect(src, tx, dst)

        for r in rx:
            self.assertEqual(r[Ether].src, tx[0][Ether].src)
            self.assertEqual(r[Ether].dst, tx[0][Ether].dst)
            self.assertEqual(r[ARP].psrc, tx[0][ARP].psrc)
            self.assertEqual(r[ARP].pdst, tx[0][ARP].pdst)
            self.assertEqual(r[ARP].hwsrc, tx[0][ARP].hwsrc)
            self.assertEqual(r[ARP].hwdst, tx[0][ARP].hwdst)
        return rx

    def test_gbp(self):
        """ Group Based Policy """

        ep_flags = VppEnum.vl_api_gbp_endpoint_flags_t

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

        rd0 = VppGbpRouteDomain(self, 0, 400, gt4, gt6, None, None)
        rd20 = VppGbpRouteDomain(self, 20, 420, nt4, nt6, None, None)

        rd0.add_vpp_config()
        rd20.add_vpp_config()

        #
        # Bridge Domains
        #
        bd1 = VppBridgeDomain(self, 1)
        bd2 = VppBridgeDomain(self, 2)
        bd20 = VppBridgeDomain(self, 20)

        bd1.add_vpp_config()
        bd2.add_vpp_config()
        bd20.add_vpp_config()

        gbd1 = VppGbpBridgeDomain(self, bd1, rd0, self.loop0)
        gbd2 = VppGbpBridgeDomain(self, bd2, rd0, self.loop1)
        gbd20 = VppGbpBridgeDomain(self, bd20, rd20, self.loop2)

        gbd1.add_vpp_config()
        gbd2.add_vpp_config()
        gbd20.add_vpp_config()

        #
        # 3 EPGs, 2 of which share a BD.
        # 2 NAT EPGs, one for floating-IP subnets, the other for internet
        #
        epgs = [VppGbpEndpointGroup(self, 220, 1220, rd0, gbd1,
                                    self.pg4, self.loop0,
                                    "10.0.0.128", "2001:10::128"),
                VppGbpEndpointGroup(self, 221, 1221, rd0, gbd1,
                                    self.pg5, self.loop0,
                                    "10.0.1.128", "2001:10:1::128"),
                VppGbpEndpointGroup(self, 222, 1222, rd0, gbd2,
                                    self.pg6, self.loop1,
                                    "10.0.2.128", "2001:10:2::128"),
                VppGbpEndpointGroup(self, 333, 1333, rd20, gbd20,
                                    self.pg7, self.loop2,
                                    "11.0.0.128", "3001::128"),
                VppGbpEndpointGroup(self, 444, 1444, rd20, gbd20,
                                    self.pg8, self.loop2,
                                    "11.0.0.129", "3001::129")]
        recircs = [VppGbpRecirc(self, epgs[0], self.loop3),
                   VppGbpRecirc(self, epgs[1], self.loop4),
                   VppGbpRecirc(self, epgs[2], self.loop5),
                   VppGbpRecirc(self, epgs[3], self.loop6, is_ext=True),
                   VppGbpRecirc(self, epgs[4], self.loop7, is_ext=True)]

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

        self.vapi.nat44_plugin_enable_disable(enable=1)

        #
        # Config related to each of the EPGs
        #
        for epg in epgs:
            # IP config on the BVI interfaces
            if epg != epgs[1] and epg != epgs[4]:
                b4 = VppIpInterfaceBind(self, epg.bvi,
                                        epg.rd.t4).add_vpp_config()
                b6 = VppIpInterfaceBind(self, epg.bvi,
                                        epg.rd.t6).add_vpp_config()
                epg.bvi.set_mac(self.router_mac)

                # The BVIs are NAT inside interfaces
                flags = self.nat_config_flags.NAT_IS_INSIDE
                self.vapi.nat44_interface_add_del_feature(
                    sw_if_index=epg.bvi.sw_if_index,
                    flags=flags, is_add=1)
                self.vapi.nat66_add_del_interface(
                    is_add=1, flags=flags,
                    sw_if_index=epg.bvi.sw_if_index)

            if_ip4 = VppIpInterfaceAddress(self, epg.bvi,
                                           epg.bvi_ip4, 32,
                                           bind=b4).add_vpp_config()
            if_ip6 = VppIpInterfaceAddress(self, epg.bvi,
                                           epg.bvi_ip6, 128,
                                           bind=b6).add_vpp_config()

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
                sw_if_index=recirc.recirc.sw_if_index, is_add=1)
            self.vapi.nat66_add_del_interface(
                is_add=1,
                sw_if_index=recirc.recirc.sw_if_index)

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
                if ip_address(ip).version == 4:
                    flags = self.nat_config_flags.NAT_IS_ADDR_ONLY
                    self.vapi.nat44_add_del_static_mapping(
                        is_add=1,
                        local_ip_address=ip,
                        external_ip_address=fip,
                        external_sw_if_index=0xFFFFFFFF,
                        vrf_id=0,
                        flags=flags)
                else:
                    self.vapi.nat66_add_del_static_mapping(
                        local_ip_address=ip,
                        external_ip_address=fip,
                        vrf_id=0, is_add=1)

            # VPP EP create ...
            ep.add_vpp_config()

            self.logger.info(self.vapi.cli("sh gbp endpoint"))

            # ... results in a Gratuitous ARP/ND on the EPG's uplink
            rx = ep.epg.uplink.get_capture(len(ep.ips), timeout=0.2)

            for ii, ip in enumerate(ep.ips):
                p = rx[ii]

                if ip_address(ip).version == 6:
                    self.assertTrue(p.haslayer(ICMPv6ND_NA))
                    self.assertEqual(p[ICMPv6ND_NA].tgt, ip)
                else:
                    self.assertTrue(p.haslayer(ARP))
                    self.assertEqual(p[ARP].psrc, ip)
                    self.assertEqual(p[ARP].pdst, ip)

            # add the BD ARP termination entry for floating IP
            for fip in ep.fips:
                ba = VppBridgeDomainArpEntry(self, epg_nat.bd.bd, ep.mac,
                                             fip)
                ba.add_vpp_config()

                # floating IPs route via EPG recirc
                r = VppIpRoute(
                    self, fip, ip_address(fip).max_prefixlen,
                    [VppRoutePath(fip,
                                  ep.recirc.recirc.sw_if_index,
                                  type=FibPathType.FIB_PATH_TYPE_DVR,
                                  proto=get_dpo_proto(fip))],
                    table_id=20)
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
                       pdst=epgs[0].bvi_ip4,
                       psrc=eps[0].ip4))

        self.send_and_expect(self.pg0, [pkt_arp], self.pg0)

        nsma = in6_getnsma(inet_pton(AF_INET6, eps[0].ip6))
        d = inet_ntop(AF_INET6, nsma)
        pkt_nd = (Ether(dst=in6_getnsmac(nsma),
                        src=self.pg0.remote_mac) /
                  IPv6(dst=d, src=eps[0].ip6) /
                  ICMPv6ND_NS(tgt=epgs[0].bvi_ip6) /
                  ICMPv6NDOptSrcLLAddr(lladdr=self.pg0.remote_mac))
        self.send_and_expect(self.pg0, [pkt_nd], self.pg0)

        #
        # broadcast packets are flooded
        #
        pkt_bcast = (Ether(dst="ff:ff:ff:ff:ff:ff",
                           src=self.pg0.remote_mac) /
                     IP(src=eps[0].ip4, dst="232.1.1.1") /
                     UDP(sport=1234, dport=1234) /
                     Raw(b'\xa5' * 100))

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
                                 IP(src=eps[0].ip4,
                                    dst="10.0.0.99") /
                                 UDP(sport=1234, dport=1234) /
                                 Raw(b'\xa5' * 100))
        pkt_inter_epg_222_ip4 = (Ether(src=self.pg0.remote_mac,
                                       dst=str(self.router_mac)) /
                                 IP(src=eps[0].ip4,
                                    dst="10.0.1.99") /
                                 UDP(sport=1234, dport=1234) /
                                 Raw(b'\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0,
                                        pkt_intra_epg_220_ip4 * NUM_PKTS)

        pkt_inter_epg_222_ip6 = (Ether(src=self.pg0.remote_mac,
                                       dst=str(self.router_mac)) /
                                 IPv6(src=eps[0].ip6,
                                      dst="2001:10::99") /
                                 UDP(sport=1234, dport=1234) /
                                 Raw(b'\xa5' * 100))
        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_222_ip6 * NUM_PKTS)

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
                                     pkt_intra_epg_220_ip4 * NUM_PKTS,
                                     eps[0].epg.uplink)
        self.send_and_expect_bridged(eps[0].itf,
                                     pkt_inter_epg_222_ip4 * NUM_PKTS,
                                     eps[0].epg.uplink)
        self.send_and_expect_bridged6(eps[0].itf,
                                      pkt_inter_epg_222_ip6 * NUM_PKTS,
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
                                       IP(src=eps[0].ip4,
                                          dst="10.0.0.99") /
                                       UDP(sport=1234, dport=1234) /
                                       Raw(b'\xa5' * 100))

        self.send_and_expect_bridged(eps[0].itf,
                                     pkt_intra_epg_220_to_uplink * NUM_PKTS,
                                     eps[0].epg.uplink)
        # ... and nowhere else
        self.pg1.get_capture(0, timeout=0.1)
        self.pg1.assert_nothing_captured(remark="Flood onto other VMS")

        pkt_intra_epg_221_to_uplink = (Ether(src=self.pg2.remote_mac,
                                             dst="00:00:00:33:44:66") /
                                       IP(src=eps[0].ip4,
                                          dst="10.0.0.99") /
                                       UDP(sport=1234, dport=1234) /
                                       Raw(b'\xa5' * 100))

        self.send_and_expect_bridged(eps[2].itf,
                                     pkt_intra_epg_221_to_uplink * NUM_PKTS,
                                     eps[2].epg.uplink)

        #
        # Packets from the uplink are forwarded in the absence of a contract
        #
        pkt_intra_epg_220_from_uplink = (Ether(src="00:00:00:33:44:55",
                                               dst=self.pg0.remote_mac) /
                                         IP(src=eps[0].ip4,
                                            dst="10.0.0.99") /
                                         UDP(sport=1234, dport=1234) /
                                         Raw(b'\xa5' * 100))

        self.send_and_expect_bridged(self.pg4,
                                     pkt_intra_epg_220_from_uplink * NUM_PKTS,
                                     self.pg0)

        #
        # in the absence of policy, endpoints in the same EPG
        # can communicate
        #
        pkt_intra_epg = (Ether(src=self.pg0.remote_mac,
                               dst=self.pg1.remote_mac) /
                         IP(src=eps[0].ip4,
                            dst=eps[1].ip4) /
                         UDP(sport=1234, dport=1234) /
                         Raw(b'\xa5' * 100))

        self.send_and_expect_bridged(self.pg0,
                                     pkt_intra_epg * NUM_PKTS,
                                     self.pg1)

        #
        # in the absence of policy, endpoints in the different EPG
        # cannot communicate
        #
        pkt_inter_epg_220_to_221 = (Ether(src=self.pg0.remote_mac,
                                          dst=self.pg2.remote_mac) /
                                    IP(src=eps[0].ip4,
                                       dst=eps[2].ip4) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw(b'\xa5' * 100))
        pkt_inter_epg_221_to_220 = (Ether(src=self.pg2.remote_mac,
                                          dst=self.pg0.remote_mac) /
                                    IP(src=eps[2].ip4,
                                       dst=eps[0].ip4) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw(b'\xa5' * 100))
        pkt_inter_epg_220_to_222 = (Ether(src=self.pg0.remote_mac,
                                          dst=str(self.router_mac)) /
                                    IP(src=eps[0].ip4,
                                       dst=eps[3].ip4) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw(b'\xa5' * 100))

        self.send_and_assert_no_replies(eps[0].itf,
                                        pkt_inter_epg_220_to_221 * NUM_PKTS)
        self.send_and_assert_no_replies(eps[0].itf,
                                        pkt_inter_epg_220_to_222 * NUM_PKTS)

        #
        # A uni-directional contract from EPG 220 -> 221
        #
        rule = AclRule(is_permit=1, proto=17)
        rule2 = AclRule(src_prefix=IPv6Network((0, 0)),
                        dst_prefix=IPv6Network((0, 0)), is_permit=1, proto=17)
        acl = VppAcl(self, rules=[rule, rule2])
        acl.add_vpp_config()

        c1 = VppGbpContract(
            self, 400, epgs[0].sclass, epgs[1].sclass, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                    [])],
            [ETH_P_IP, ETH_P_IPV6])
        c1.add_vpp_config()

        self.send_and_expect_bridged(eps[0].itf,
                                     pkt_inter_epg_220_to_221 * NUM_PKTS,
                                     eps[2].itf)
        self.send_and_assert_no_replies(eps[0].itf,
                                        pkt_inter_epg_220_to_222 * NUM_PKTS)

        #
        # contract for the return direction
        #
        c2 = VppGbpContract(
            self, 400, epgs[1].sclass, epgs[0].sclass, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                    [])],
            [ETH_P_IP, ETH_P_IPV6])
        c2.add_vpp_config()

        self.send_and_expect_bridged(eps[0].itf,
                                     pkt_inter_epg_220_to_221 * NUM_PKTS,
                                     eps[2].itf)
        self.send_and_expect_bridged(eps[2].itf,
                                     pkt_inter_epg_221_to_220 * NUM_PKTS,
                                     eps[0].itf)

        ds = c2.get_drop_stats()
        self.assertEqual(ds['packets'], 0)
        ps = c2.get_permit_stats()
        self.assertEqual(ps['packets'], NUM_PKTS)

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
                                        pkt_inter_epg_220_to_222 * NUM_PKTS)

        #
        # A uni-directional contract from EPG 220 -> 222 'L3 routed'
        #
        c3 = VppGbpContract(
            self, 400, epgs[0].sclass, epgs[2].sclass, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                    [])],
            [ETH_P_IP, ETH_P_IPV6])
        c3.add_vpp_config()

        self.logger.info(self.vapi.cli("sh gbp contract"))

        self.send_and_expect_routed(eps[0].itf,
                                    pkt_inter_epg_220_to_222 * NUM_PKTS,
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
                                        pkt_inter_epg_221_to_220 * NUM_PKTS)
        self.send_and_assert_no_replies(eps[0].itf,
                                        pkt_inter_epg_220_to_221 * NUM_PKTS)
        self.send_and_expect_bridged(eps[0].itf,
                                     pkt_intra_epg * NUM_PKTS,
                                     eps[1].itf)

        #
        # EPs to the outside world
        #

        # in the EP's RD an external subnet via the NAT EPG's recirc
        se1 = VppGbpSubnet(
            self, rd0, "0.0.0.0", 0,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_EXTERNAL,
            sw_if_index=recirc_nat.recirc.sw_if_index,
            sclass=epg_nat.sclass)
        se2 = VppGbpSubnet(
            self, rd0, "11.0.0.0", 8,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_EXTERNAL,
            sw_if_index=recirc_nat.recirc.sw_if_index,
            sclass=epg_nat.sclass)
        se16 = VppGbpSubnet(
            self, rd0, "::", 0,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_EXTERNAL,
            sw_if_index=recirc_nat.recirc.sw_if_index,
            sclass=epg_nat.sclass)
        # in the NAT RD an external subnet via the NAT EPG's uplink
        se3 = VppGbpSubnet(
            self, rd20, "0.0.0.0", 0,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_EXTERNAL,
            sw_if_index=epg_nat.uplink.sw_if_index,
            sclass=epg_nat.sclass)
        se36 = VppGbpSubnet(
            self, rd20, "::", 0,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_EXTERNAL,
            sw_if_index=epg_nat.uplink.sw_if_index,
            sclass=epg_nat.sclass)
        se4 = VppGbpSubnet(
            self, rd20, "11.0.0.0", 8,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_STITCHED_EXTERNAL,
            sw_if_index=epg_nat.uplink.sw_if_index,
            sclass=epg_nat.sclass)
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
        # From an EP to an outside address: IN2OUT
        #
        pkt_inter_epg_220_to_global = (Ether(src=self.pg0.remote_mac,
                                             dst=str(self.router_mac)) /
                                       IP(src=eps[0].ip4,
                                          dst="1.1.1.1") /
                                       UDP(sport=1234, dport=1234) /
                                       Raw(b'\xa5' * 100))

        # no policy yet
        self.send_and_assert_no_replies(eps[0].itf,
                                        pkt_inter_epg_220_to_global * NUM_PKTS)
        rule = AclRule(is_permit=1, proto=17, ports=1234)
        rule2 = AclRule(is_permit=1, proto=17, ports=1234,
                        src_prefix=IPv6Network((0, 0)),
                        dst_prefix=IPv6Network((0, 0)))
        acl2 = VppAcl(self, rules=[rule, rule2])
        acl2.add_vpp_config()

        c4 = VppGbpContract(
            self, 400, epgs[0].sclass, epgs[3].sclass, acl2.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                    [])],
            [ETH_P_IP, ETH_P_IPV6])
        c4.add_vpp_config()

        self.send_and_expect_natted(eps[0].itf,
                                    pkt_inter_epg_220_to_global * NUM_PKTS,
                                    self.pg7,
                                    eps[0].fip4)

        pkt_inter_epg_220_to_global = (Ether(src=self.pg0.remote_mac,
                                             dst=str(self.router_mac)) /
                                       IPv6(src=eps[0].ip6,
                                            dst="6001::1") /
                                       UDP(sport=1234, dport=1234) /
                                       Raw(b'\xa5' * 100))

        self.send_and_expect_natted6(self.pg0,
                                     pkt_inter_epg_220_to_global * NUM_PKTS,
                                     self.pg7,
                                     eps[0].fip6)

        #
        # From a global address to an EP: OUT2IN
        #
        pkt_inter_epg_220_from_global = (Ether(src=str(self.router_mac),
                                               dst=self.pg0.remote_mac) /
                                         IP(dst=eps[0].fip4,
                                            src="1.1.1.1") /
                                         UDP(sport=1234, dport=1234) /
                                         Raw(b'\xa5' * 100))

        self.send_and_assert_no_replies(
            self.pg7, pkt_inter_epg_220_from_global * NUM_PKTS)

        c5 = VppGbpContract(
            self, 400, epgs[3].sclass, epgs[0].sclass, acl2.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                    [])],
            [ETH_P_IP, ETH_P_IPV6])
        c5.add_vpp_config()

        self.send_and_expect_unnatted(self.pg7,
                                      pkt_inter_epg_220_from_global * NUM_PKTS,
                                      eps[0].itf,
                                      eps[0].ip4)

        pkt_inter_epg_220_from_global = (Ether(src=str(self.router_mac),
                                               dst=self.pg0.remote_mac) /
                                         IPv6(dst=eps[0].fip6,
                                              src="6001::1") /
                                         UDP(sport=1234, dport=1234) /
                                         Raw(b'\xa5' * 100))

        self.send_and_expect_unnatted6(
            self.pg7,
            pkt_inter_epg_220_from_global * NUM_PKTS,
            eps[0].itf,
            eps[0].ip6)

        #
        # From a local VM to another local VM using resp. public addresses:
        #  IN2OUT2IN
        #
        pkt_intra_epg_220_global = (Ether(src=self.pg0.remote_mac,
                                          dst=str(self.router_mac)) /
                                    IP(src=eps[0].ip4,
                                       dst=eps[1].fip4) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw(b'\xa5' * 100))

        self.send_and_expect_double_natted(eps[0].itf,
                                           pkt_intra_epg_220_global * NUM_PKTS,
                                           eps[1].itf,
                                           eps[0].fip4,
                                           eps[1].ip4)

        pkt_intra_epg_220_global = (Ether(src=self.pg0.remote_mac,
                                          dst=str(self.router_mac)) /
                                    IPv6(src=eps[0].ip6,
                                         dst=eps[1].fip6) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw(b'\xa5' * 100))

        self.send_and_expect_double_natted6(
            eps[0].itf,
            pkt_intra_epg_220_global * NUM_PKTS,
            eps[1].itf,
            eps[0].fip6,
            eps[1].ip6)

        #
        # cleanup
        #
        self.vapi.nat44_plugin_enable_disable(enable=0)

        for ep in eps:
            # del static mappings for each EP from the 10/8 to 11/8 network
            flags = self.nat_config_flags.NAT_IS_ADDR_ONLY
            self.vapi.nat66_add_del_static_mapping(
                local_ip_address=ep.ip6,
                external_ip_address=ep.fip6,
                vrf_id=0, is_add=0)

        for epg in epgs:
            # IP config on the BVI interfaces
            if epg != epgs[0] and epg != epgs[3]:
                flags = self.nat_config_flags.NAT_IS_INSIDE
                self.vapi.nat66_add_del_interface(
                    sw_if_index=epg.bvi.sw_if_index,
                    flags=flags, is_add=0)

        for recirc in recircs:
            self.vapi.nat66_add_del_interface(
                sw_if_index=recirc.recirc.sw_if_index, is_add=0)

    def wait_for_ep_timeout(self, sw_if_index=None, ip=None, mac=None,
                            tep=None, n_tries=100, s_time=1):
        # only learnt EP can timeout
        ep_flags = VppEnum.vl_api_gbp_endpoint_flags_t
        flags = ep_flags.GBP_API_ENDPOINT_FLAG_LEARNT
        while (n_tries):
            if not find_gbp_endpoint(self, sw_if_index, ip, mac, tep=tep,
                                     flags=flags):
                return True
            n_tries = n_tries - 1
            self.sleep(s_time)
        self.assertFalse(find_gbp_endpoint(self, sw_if_index, ip, mac, tep=tep,
                                           flags=flags))
        return False

    def test_gbp_learn_l2(self):
        """ GBP L2 Endpoint Learning """

        drop_no_contract = self.statistics.get_err_counter(
            '/err/gbp-policy-port/drop-no-contract')
        allow_intra_class = self.statistics.get_err_counter(
            '/err/gbp-policy-port/allow-intra-sclass')

        ep_flags = VppEnum.vl_api_gbp_endpoint_flags_t
        learnt = [{'mac': '00:00:11:11:11:01',
                   'ip': '10.0.0.1',
                   'ip6': '2001:10::2'},
                  {'mac': '00:00:11:11:11:02',
                   'ip': '10.0.0.2',
                   'ip6': '2001:10::3'}]

        #
        # IP tables
        #
        gt4 = VppIpTable(self, 1)
        gt4.add_vpp_config()
        gt6 = VppIpTable(self, 1, is_ip6=True)
        gt6.add_vpp_config()

        rd1 = VppGbpRouteDomain(self, 1, 401, gt4, gt6)
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
        # Add a mcast destination VXLAN-GBP tunnel for B&M traffic
        #
        tun_bm = VppVxlanGbpTunnel(self, self.pg4.local_ip4,
                                   "239.1.1.1", 88,
                                   mcast_itf=self.pg4)
        tun_bm.add_vpp_config()

        #
        # a GBP bridge domain with a BVI and a UU-flood interface
        #
        bd1 = VppBridgeDomain(self, 1)
        bd1.add_vpp_config()
        gbd1 = VppGbpBridgeDomain(self, bd1, rd1, self.loop0,
                                  self.pg3, tun_bm)
        gbd1.add_vpp_config()

        self.logger.info(self.vapi.cli("sh bridge 1 detail"))
        self.logger.info(self.vapi.cli("sh gbp bridge"))

        # ... and has a /32 applied
        ip_addr = VppIpInterfaceAddress(self, gbd1.bvi, "10.0.0.128", 32)
        ip_addr.add_vpp_config()

        #
        # The Endpoint-group in which we are learning endpoints
        #
        epg_220 = VppGbpEndpointGroup(self, 220, 112, rd1, gbd1,
                                      None, self.loop0,
                                      "10.0.0.128",
                                      "2001:10::128",
                                      VppGbpEndpointRetention(4))
        epg_220.add_vpp_config()
        epg_330 = VppGbpEndpointGroup(self, 330, 113, rd1, gbd1,
                                      None, self.loop1,
                                      "10.0.1.128",
                                      "2001:11::128",
                                      VppGbpEndpointRetention(4))
        epg_330.add_vpp_config()

        #
        # The VXLAN GBP tunnel is a bridge-port and has L2 endpoint
        # learning enabled
        #
        vx_tun_l2_1 = VppGbpVxlanTunnel(
            self, 99, bd1.bd_id,
            VppEnum.vl_api_gbp_vxlan_tunnel_mode_t.GBP_VXLAN_TUNNEL_MODE_L2,
            self.pg2.local_ip4)
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

        self.assertTrue(find_route(self, ep.ip4, 32, table_id=1))

        # a packet with an sclass from an unknown EPG
        p = (Ether(src=self.pg2.remote_mac,
                   dst=self.pg2.local_mac) /
             IP(src=self.pg2.remote_hosts[0].ip4,
                dst=self.pg2.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=99, gpid=88, flags=0x88) /
             Ether(src=learnt[0]["mac"], dst=ep.mac) /
             IP(src=learnt[0]["ip"], dst=ep.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        self.send_and_assert_no_replies(self.pg2, p)

        self.logger.info(self.vapi.cli("sh error"))
        self.assert_error_counter_equal(
            '/err/gbp-policy-port/drop-no-contract',
            drop_no_contract + 1)

        #
        # we should not have learnt a new tunnel endpoint, since
        # the EPG was not learnt.
        #
        self.assertEqual(INDEX_INVALID,
                         find_vxlan_gbp_tunnel(self,
                                               self.pg2.local_ip4,
                                               self.pg2.remote_hosts[0].ip4,
                                               99))

        # ep is not learnt, because the EPG is unknown
        self.assertEqual(len(self.vapi.gbp_endpoint_dump()), 1)

        #
        # Learn new EPs from IP packets
        #
        for ii, l in enumerate(learnt):
            # a packet with an sclass from a known EPG
            # arriving on an unknown TEP
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=112, flags=0x88) /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IP(src=l['ip'], dst=ep.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

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

        self.assert_error_counter_equal(
            '/err/gbp-policy-port/allow-intra-sclass',
            allow_intra_class + 2)

        self.logger.info(self.vapi.cli("show gbp endpoint"))
        self.logger.info(self.vapi.cli("show gbp vxlan"))
        self.logger.info(self.vapi.cli("show ip mfib"))

        #
        # If we sleep for the threshold time, the learnt endpoints should
        # age out
        #
        for l in learnt:
            self.wait_for_ep_timeout(vx_tun_l2_1.sw_if_index,
                                     mac=l['mac'])

        #
        # Learn new EPs from GARP packets received on the BD's mcast tunnel
        #
        for ii, l in enumerate(learnt):
            # add some junk in the reserved field of the vxlan-header
            # next to the VNI. we should accept since reserved bits are
            # ignored on rx.
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst="239.1.1.1") /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=88, reserved2=0x80, gpid=112, flags=0x88) /
                 Ether(src=l['mac'], dst="ff:ff:ff:ff:ff:ff") /
                 ARP(op="who-has",
                     psrc=l['ip'], pdst=l['ip'],
                     hwsrc=l['mac'], hwdst="ff:ff:ff:ff:ff:ff"))

            rx = self.send_and_expect(self.pg4, [p], self.pg0)

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

        #
        # wait for the learnt endpoints to age out
        #
        for l in learnt:
            self.wait_for_ep_timeout(vx_tun_l2_1.sw_if_index,
                                     mac=l['mac'])

        #
        # Learn new EPs from L2 packets
        #
        for ii, l in enumerate(learnt):
            # a packet with an sclass from a known EPG
            # arriving on an unknown TEP
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=112, flags=0x88) /
                 Ether(src=l['mac'], dst=ep.mac) /
                 Raw(b'\xa5' * 100))

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

        self.logger.info(self.vapi.cli("show gbp endpoint"))
        self.logger.info(self.vapi.cli("show gbp vxlan"))
        self.logger.info(self.vapi.cli("show vxlan-gbp tunnel"))

        #
        # wait for the learnt endpoints to age out
        #
        for l in learnt:
            self.wait_for_ep_timeout(vx_tun_l2_1.sw_if_index,
                                     mac=l['mac'])

        #
        # repeat. the do not learn bit is set so the EPs are not learnt
        #
        for l in learnt:
            # a packet with an sclass from a known EPG
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=112, flags=0x88, gpflags="D") /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IP(src=l['ip'], dst=ep.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rx = self.send_and_expect(self.pg2, p * NUM_PKTS, self.pg0)

        for l in learnt:
            self.assertFalse(find_gbp_endpoint(self,
                                               vx_tun_l2_1.sw_if_index,
                                               mac=l['mac']))

        #
        # repeat
        #
        for l in learnt:
            # a packet with an sclass from a known EPG
            # set a reserved bit in addition to the G and I
            # reserved bits should not be checked on rx.
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=112, flags=0xc8) /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IP(src=l['ip'], dst=ep.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rx = self.send_and_expect(self.pg2, p * NUM_PKTS, self.pg0)

            self.assertTrue(find_gbp_endpoint(self,
                                              vx_tun_l2_1.sw_if_index,
                                              mac=l['mac']))

        #
        # Static EP replies to dynamics
        #
        self.logger.info(self.vapi.cli("sh l2fib bd_id 1"))
        for l in learnt:
            p = (Ether(src=ep.mac, dst=l['mac']) /
                 IP(dst=l['ip'], src=ep.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rxs = self.send_and_expect(self.pg0, p * 17, self.pg2)

            for rx in rxs:
                self.assertEqual(rx[IP].src, self.pg2.local_ip4)
                self.assertEqual(rx[IP].dst, self.pg2.remote_hosts[1].ip4)
                self.assertEqual(rx[UDP].dport, 48879)
                # the UDP source port is a random value for hashing
                self.assertEqual(rx[VXLAN].gpid, 112)
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
            # a packet with an sclass from a known EPG
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=113, flags=0x88, gpflags='A') /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IP(src=l['ip'], dst=ep.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rx = self.send_and_expect(self.pg2, p * NUM_PKTS, self.pg0)

            self.assertTrue(find_gbp_endpoint(self,
                                              vx_tun_l2_1.sw_if_index,
                                              mac=l['mac']))

        #
        # static EP cannot reach the learnt EPs since there is no contract
        # only test 1 EP as the others could timeout
        #
        p = (Ether(src=ep.mac, dst=l['mac']) /
             IP(dst=learnt[0]['ip'], src=ep.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0, [p])

        #
        # refresh the entries after the check for no replies above
        #
        for l in learnt:
            # a packet with an sclass from a known EPG
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=113, flags=0x88, gpflags='A') /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IP(src=l['ip'], dst=ep.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rx = self.send_and_expect(self.pg2, p * NUM_PKTS, self.pg0)

            self.assertTrue(find_gbp_endpoint(self,
                                              vx_tun_l2_1.sw_if_index,
                                              mac=l['mac']))

        #
        # Add the contract so they can talk
        #
        rule = AclRule(is_permit=1, proto=17)
        rule2 = AclRule(src_prefix=IPv6Network((0, 0)),
                        dst_prefix=IPv6Network((0, 0)), is_permit=1, proto=17)
        acl = VppAcl(self, rules=[rule, rule2])
        acl.add_vpp_config()

        c1 = VppGbpContract(
            self, 401, epg_220.sclass, epg_330.sclass, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                 VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                 [])],
            [ETH_P_IP, ETH_P_IPV6])
        c1.add_vpp_config()

        for l in learnt:
            p = (Ether(src=ep.mac, dst=l['mac']) /
                 IP(dst=l['ip'], src=ep.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            self.send_and_expect(self.pg0, [p], self.pg2)

        #
        # send UU packets from the local EP
        #
        self.logger.info(self.vapi.cli("sh gbp bridge"))
        self.logger.info(self.vapi.cli("sh bridge-domain 1 detail"))
        p_uu = (Ether(src=ep.mac, dst="00:11:11:11:11:11") /
                IP(dst="10.0.0.133", src=ep.ip4) /
                UDP(sport=1234, dport=1234) /
                Raw(b'\xa5' * 100))
        rxs = self.send_and_expect(ep.itf, [p_uu], gbd1.uu_fwd)

        self.logger.info(self.vapi.cli("sh bridge 1 detail"))

        p_bm = (Ether(src=ep.mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(dst="10.0.0.133", src=ep.ip4) /
                UDP(sport=1234, dport=1234) /
                Raw(b'\xa5' * 100))
        rxs = self.send_and_expect_only(ep.itf, [p_bm], tun_bm.mcast_itf)

        for rx in rxs:
            self.assertEqual(rx[IP].src, self.pg4.local_ip4)
            self.assertEqual(rx[IP].dst, "239.1.1.1")
            self.assertEqual(rx[UDP].dport, 48879)
            # the UDP source port is a random value for hashing
            self.assertEqual(rx[VXLAN].gpid, 112)
            self.assertEqual(rx[VXLAN].vni, 88)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            self.assertFalse(rx[VXLAN].gpflags.A)
            self.assertFalse(rx[VXLAN].gpflags.D)

        rule = AclRule(is_permit=1, proto=17)
        rule2 = AclRule(src_prefix=IPv6Network((0, 0)),
                        dst_prefix=IPv6Network((0, 0)), is_permit=1, proto=17)
        acl = VppAcl(self, rules=[rule, rule2])
        acl.add_vpp_config()

        c2 = VppGbpContract(
            self, 401, epg_330.sclass, epg_220.sclass, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                    [])],
            [ETH_P_IP, ETH_P_IPV6])
        c2.add_vpp_config()

        for l in learnt:
            self.wait_for_ep_timeout(vx_tun_l2_1.sw_if_index,
                                     mac=l['mac'])
        #
        # Check v6 Endpoints learning
        #
        for l in learnt:
            # a packet with an sclass from a known EPG
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=113, flags=0x88) /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IPv6(src=l['ip6'], dst=ep.ip6) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rx = self.send_and_expect(self.pg2, p * NUM_PKTS, self.pg0)
            rx = self.send_and_expect(self.pg2, p * NUM_PKTS, self.pg0)

            self.assertTrue(find_gbp_endpoint(
                self,
                vx_tun_l2_1.sw_if_index,
                ip=l['ip6'],
                tep=[self.pg2.local_ip4,
                     self.pg2.remote_hosts[1].ip4]))

        self.logger.info(self.vapi.cli("sh int"))
        self.logger.info(self.vapi.cli("sh vxlan-gbp tunnel"))
        self.logger.info(self.vapi.cli("sh gbp vxlan"))
        self.logger.info(self.vapi.cli("sh gbp endpoint"))
        self.logger.info(self.vapi.cli("sh gbp interface"))

        #
        # EP moves to a different TEP
        #
        for l in learnt:
            # a packet with an sclass from a known EPG
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[2].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=113, flags=0x88) /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IPv6(src=l['ip6'], dst=ep.ip6) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rx = self.send_and_expect(self.pg2, p * 1, self.pg0)
            rx = self.send_and_expect(self.pg2, p * NUM_PKTS, self.pg0)

            self.assertTrue(find_gbp_endpoint(
                self,
                vx_tun_l2_1.sw_if_index,
                sclass=113,
                mac=l['mac'],
                tep=[self.pg2.local_ip4,
                     self.pg2.remote_hosts[2].ip4]))

        #
        # v6 remote EP reachability
        #
        for l in learnt:
            p = (Ether(src=ep.mac, dst=l['mac']) /
                 IPv6(dst=l['ip6'], src=ep.ip6) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rxs = self.send_and_expect(self.pg0, p * NUM_PKTS, self.pg2)

            for rx in rxs:
                self.assertEqual(rx[IP].src, self.pg2.local_ip4)
                self.assertEqual(rx[IP].dst, self.pg2.remote_hosts[2].ip4)
                self.assertEqual(rx[UDP].dport, 48879)
                # the UDP source port is a random value for hashing
                self.assertEqual(rx[VXLAN].gpid, 112)
                self.assertEqual(rx[VXLAN].vni, 99)
                self.assertTrue(rx[VXLAN].flags.G)
                self.assertTrue(rx[VXLAN].flags.Instance)
                self.assertTrue(rx[VXLAN].gpflags.A)
                self.assertFalse(rx[VXLAN].gpflags.D)
                self.assertEqual(rx[IPv6].dst, l['ip6'])

        #
        # EP changes sclass
        #
        for l in learnt:
            # a packet with an sclass from a known EPG
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[2].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=112, flags=0x88) /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IPv6(src=l['ip6'], dst=ep.ip6) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rx = self.send_and_expect(self.pg2, p * 1, self.pg0)
            rx = self.send_and_expect(self.pg2, p * NUM_PKTS, self.pg0)

            self.assertTrue(find_gbp_endpoint(
                self,
                vx_tun_l2_1.sw_if_index,
                mac=l['mac'],
                sclass=112,
                tep=[self.pg2.local_ip4,
                     self.pg2.remote_hosts[2].ip4]))

        #
        # check reachability and contract intra-epg
        #
        allow_intra_class = self.statistics.get_err_counter(
            '/err/gbp-policy-mac/allow-intra-sclass')

        for l in learnt:
            p = (Ether(src=ep.mac, dst=l['mac']) /
                 IPv6(dst=l['ip6'], src=ep.ip6) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rxs = self.send_and_expect(self.pg0, p * NUM_PKTS, self.pg2)

            for rx in rxs:
                self.assertEqual(rx[IP].src, self.pg2.local_ip4)
                self.assertEqual(rx[IP].dst, self.pg2.remote_hosts[2].ip4)
                self.assertEqual(rx[UDP].dport, 48879)
                self.assertEqual(rx[VXLAN].gpid, 112)
                self.assertEqual(rx[VXLAN].vni, 99)
                self.assertTrue(rx[VXLAN].flags.G)
                self.assertTrue(rx[VXLAN].flags.Instance)
                self.assertTrue(rx[VXLAN].gpflags.A)
                self.assertFalse(rx[VXLAN].gpflags.D)
                self.assertEqual(rx[IPv6].dst, l['ip6'])

            allow_intra_class += NUM_PKTS

        self.assert_error_counter_equal(
            '/err/gbp-policy-mac/allow-intra-sclass',
            allow_intra_class)

        #
        # clean up
        #
        for l in learnt:
            self.wait_for_ep_timeout(vx_tun_l2_1.sw_if_index,
                                     mac=l['mac'])
        self.pg2.unconfig_ip4()
        self.pg3.unconfig_ip4()
        self.pg4.unconfig_ip4()

    def test_gbp_contract(self):
        """ GBP Contracts """

        #
        # Route Domains
        #
        gt4 = VppIpTable(self, 0)
        gt4.add_vpp_config()
        gt6 = VppIpTable(self, 0, is_ip6=True)
        gt6.add_vpp_config()

        rd0 = VppGbpRouteDomain(self, 0, 400, gt4, gt6, None, None)

        rd0.add_vpp_config()

        #
        # Bridge Domains
        #
        bd1 = VppBridgeDomain(self, 1, arp_term=0)
        bd2 = VppBridgeDomain(self, 2, arp_term=0)

        bd1.add_vpp_config()
        bd2.add_vpp_config()

        gbd1 = VppGbpBridgeDomain(self, bd1, rd0, self.loop0)
        gbd2 = VppGbpBridgeDomain(self, bd2, rd0, self.loop1)

        gbd1.add_vpp_config()
        gbd2.add_vpp_config()

        #
        # 3 EPGs, 2 of which share a BD.
        #
        epgs = [VppGbpEndpointGroup(self, 220, 1220, rd0, gbd1,
                                    None, self.loop0,
                                    "10.0.0.128", "2001:10::128"),
                VppGbpEndpointGroup(self, 221, 1221, rd0, gbd1,
                                    None, self.loop0,
                                    "10.0.1.128", "2001:10:1::128"),
                VppGbpEndpointGroup(self, 222, 1222, rd0, gbd2,
                                    None, self.loop1,
                                    "10.0.2.128", "2001:10:2::128")]
        #
        # 4 end-points, 2 in the same subnet, 3 in the same BD
        #
        eps = [VppGbpEndpoint(self, self.pg0,
                              epgs[0], None,
                              "10.0.0.1", "11.0.0.1",
                              "2001:10::1", "3001::1"),
               VppGbpEndpoint(self, self.pg1,
                              epgs[0], None,
                              "10.0.0.2", "11.0.0.2",
                              "2001:10::2", "3001::2"),
               VppGbpEndpoint(self, self.pg2,
                              epgs[1], None,
                              "10.0.1.1", "11.0.0.3",
                              "2001:10:1::1", "3001::3"),
               VppGbpEndpoint(self, self.pg3,
                              epgs[2], None,
                              "10.0.2.1", "11.0.0.4",
                              "2001:10:2::1", "3001::4")]

        #
        # Config related to each of the EPGs
        #
        for epg in epgs:
            # IP config on the BVI interfaces
            if epg != epgs[1]:
                b4 = VppIpInterfaceBind(self, epg.bvi,
                                        epg.rd.t4).add_vpp_config()
                b6 = VppIpInterfaceBind(self, epg.bvi,
                                        epg.rd.t6).add_vpp_config()
                epg.bvi.set_mac(self.router_mac)

            if_ip4 = VppIpInterfaceAddress(self, epg.bvi,
                                           epg.bvi_ip4, 32,
                                           bind=b4).add_vpp_config()
            if_ip6 = VppIpInterfaceAddress(self, epg.bvi,
                                           epg.bvi_ip6, 128,
                                           bind=b6).add_vpp_config()

            # add the BD ARP termination entry for BVI IP
            epg.bd_arp_ip4 = VppBridgeDomainArpEntry(self, epg.bd.bd,
                                                     str(self.router_mac),
                                                     epg.bvi_ip4)
            epg.bd_arp_ip4.add_vpp_config()

            # EPG in VPP
            epg.add_vpp_config()

        #
        # config ep
        #
        for ep in eps:
            ep.add_vpp_config()

        self.logger.info(self.vapi.cli("show gbp endpoint"))
        self.logger.info(self.vapi.cli("show interface"))
        self.logger.info(self.vapi.cli("show br"))

        #
        # Intra epg allowed without contract
        #
        pkt_intra_epg_220_to_220 = (Ether(src=self.pg0.remote_mac,
                                          dst=self.pg1.remote_mac) /
                                    IP(src=eps[0].ip4,
                                       dst=eps[1].ip4) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw(b'\xa5' * 100))

        self.send_and_expect_bridged(self.pg0,
                                     pkt_intra_epg_220_to_220 * 65,
                                     self.pg1)

        pkt_intra_epg_220_to_220 = (Ether(src=self.pg0.remote_mac,
                                          dst=self.pg1.remote_mac) /
                                    IPv6(src=eps[0].ip6,
                                         dst=eps[1].ip6) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw(b'\xa5' * 100))

        self.send_and_expect_bridged6(self.pg0,
                                      pkt_intra_epg_220_to_220 * 65,
                                      self.pg1)

        #
        # Inter epg denied without contract
        #
        pkt_inter_epg_220_to_221 = (Ether(src=self.pg0.remote_mac,
                                          dst=self.pg2.remote_mac) /
                                    IP(src=eps[0].ip4,
                                       dst=eps[2].ip4) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw(b'\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0, pkt_inter_epg_220_to_221)

        #
        # A uni-directional contract from EPG 220 -> 221
        #
        rule = AclRule(is_permit=1, proto=17)
        rule2 = AclRule(src_prefix=IPv6Network((0, 0)),
                        dst_prefix=IPv6Network((0, 0)), is_permit=1, proto=17)
        rule3 = AclRule(is_permit=1, proto=1)
        acl = VppAcl(self, rules=[rule, rule2, rule3])
        acl.add_vpp_config()

        c1 = VppGbpContract(
            self, 400, epgs[0].sclass, epgs[1].sclass, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                 VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                 []),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                 VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                 [])],
            [ETH_P_IP, ETH_P_IPV6])
        c1.add_vpp_config()

        self.send_and_expect_bridged(eps[0].itf,
                                     pkt_inter_epg_220_to_221 * 65,
                                     eps[2].itf)

        pkt_inter_epg_220_to_222 = (Ether(src=self.pg0.remote_mac,
                                          dst=str(self.router_mac)) /
                                    IP(src=eps[0].ip4,
                                       dst=eps[3].ip4) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw(b'\xa5' * 100))
        self.send_and_assert_no_replies(eps[0].itf,
                                        pkt_inter_epg_220_to_222 * 65)

        #
        # ping router IP in different BD
        #
        pkt_router_ping_220_to_221 = (Ether(src=self.pg0.remote_mac,
                                            dst=str(self.router_mac)) /
                                      IP(src=eps[0].ip4,
                                         dst=epgs[1].bvi_ip4) /
                                      ICMP(type='echo-request'))

        self.send_and_expect(self.pg0, [pkt_router_ping_220_to_221], self.pg0)

        pkt_router_ping_220_to_221 = (Ether(src=self.pg0.remote_mac,
                                            dst=str(self.router_mac)) /
                                      IPv6(src=eps[0].ip6,
                                           dst=epgs[1].bvi_ip6) /
                                      ICMPv6EchoRequest())

        self.send_and_expect(self.pg0, [pkt_router_ping_220_to_221], self.pg0)

        #
        # contract for the return direction
        #
        c2 = VppGbpContract(
            self, 400, epgs[1].sclass, epgs[0].sclass, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                 VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                 [])],
            [ETH_P_IP, ETH_P_IPV6])
        c2.add_vpp_config()

        self.send_and_expect_bridged(eps[0].itf,
                                     pkt_inter_epg_220_to_221 * 65,
                                     eps[2].itf)
        pkt_inter_epg_221_to_220 = (Ether(src=self.pg2.remote_mac,
                                          dst=self.pg0.remote_mac) /
                                    IP(src=eps[2].ip4,
                                       dst=eps[0].ip4) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw(b'\xa5' * 100))
        self.send_and_expect_bridged(eps[2].itf,
                                     pkt_inter_epg_221_to_220 * 65,
                                     eps[0].itf)
        pkt_inter_epg_221_to_220 = (Ether(src=self.pg2.remote_mac,
                                          dst=str(self.router_mac)) /
                                    IP(src=eps[2].ip4,
                                       dst=eps[0].ip4) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw(b'\xa5' * 100))
        self.send_and_expect_routed(eps[2].itf,
                                    pkt_inter_epg_221_to_220 * 65,
                                    eps[0].itf,
                                    str(self.router_mac))
        pkt_inter_epg_221_to_220 = (Ether(src=self.pg2.remote_mac,
                                          dst=str(self.router_mac)) /
                                    IPv6(src=eps[2].ip6,
                                         dst=eps[0].ip6) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw(b'\xa5' * 100))
        self.send_and_expect_routed6(eps[2].itf,
                                     pkt_inter_epg_221_to_220 * 65,
                                     eps[0].itf,
                                     str(self.router_mac))

        #
        # contract between 220 and 222 uni-direction
        #
        c3 = VppGbpContract(
            self, 400, epgs[0].sclass, epgs[2].sclass, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                 VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                 [])],
            [ETH_P_IP, ETH_P_IPV6])
        c3.add_vpp_config()

        self.send_and_expect(eps[0].itf,
                             pkt_inter_epg_220_to_222 * 65,
                             eps[3].itf)

        c3.remove_vpp_config()
        c1.remove_vpp_config()
        c2.remove_vpp_config()
        acl.remove_vpp_config()

    def test_gbp_bd_drop_flags(self):
        """ GBP BD drop flags """

        #
        # IP tables
        #
        gt4 = VppIpTable(self, 1)
        gt4.add_vpp_config()
        gt6 = VppIpTable(self, 1, is_ip6=True)
        gt6.add_vpp_config()

        rd1 = VppGbpRouteDomain(self, 1, 401, gt4, gt6)
        rd1.add_vpp_config()

        #
        # a GBP bridge domain with a BVI only
        #
        bd1 = VppBridgeDomain(self, 1)
        bd1.add_vpp_config()

        gbd1 = VppGbpBridgeDomain(self, bd1, rd1, self.loop0,
                                  None, None,
                                  uu_drop=True, bm_drop=True)
        gbd1.add_vpp_config()

        self.logger.info(self.vapi.cli("sh bridge 1 detail"))
        self.logger.info(self.vapi.cli("sh gbp bridge"))

        # ... and has a /32 applied
        ip_addr = VppIpInterfaceAddress(self, gbd1.bvi,
                                        "10.0.0.128", 32).add_vpp_config()

        #
        # The Endpoint-group
        #
        epg_220 = VppGbpEndpointGroup(self, 220, 112, rd1, gbd1,
                                      None, self.loop0,
                                      "10.0.0.128",
                                      "2001:10::128",
                                      VppGbpEndpointRetention(3))
        epg_220.add_vpp_config()

        ep = VppGbpEndpoint(self, self.pg0,
                            epg_220, None,
                            "10.0.0.127", "11.0.0.127",
                            "2001:10::1", "3001::1")
        ep.add_vpp_config()

        #
        # send UU/BM packet from the local EP with UU drop and BM drop enabled
        # in bd
        #
        self.logger.info(self.vapi.cli("sh bridge 1 detail"))
        self.logger.info(self.vapi.cli("sh gbp bridge"))
        p_uu = (Ether(src=ep.mac, dst="00:11:11:11:11:11") /
                IP(dst="10.0.0.133", src=ep.ip4) /
                UDP(sport=1234, dport=1234) /
                Raw(b'\xa5' * 100))
        self.send_and_assert_no_replies(ep.itf, [p_uu])

        p_bm = (Ether(src=ep.mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(dst="10.0.0.133", src=ep.ip4) /
                UDP(sport=1234, dport=1234) /
                Raw(b'\xa5' * 100))
        self.send_and_assert_no_replies(ep.itf, [p_bm])

        self.pg3.unconfig_ip4()

        self.logger.info(self.vapi.cli("sh int"))

    def test_gbp_bd_arp_flags(self):
        """ GBP BD arp flags """

        #
        # IP tables
        #
        gt4 = VppIpTable(self, 1)
        gt4.add_vpp_config()
        gt6 = VppIpTable(self, 1, is_ip6=True)
        gt6.add_vpp_config()

        rd1 = VppGbpRouteDomain(self, 1, 401, gt4, gt6)
        rd1.add_vpp_config()

        #
        # Pg4 hosts the IP6 UU-flood VXLAN tunnel
        #
        self.pg4.config_ip4()
        self.pg4.resolve_arp()

        #
        # Add a mcast destination VXLAN-GBP tunnel for B&M traffic
        #
        tun_uu = VppVxlanGbpTunnel(self, self.pg4.local_ip4,
                                   "239.1.1.1", 88,
                                   mcast_itf=self.pg4)
        tun_uu.add_vpp_config()

        #
        # a GBP bridge domain with a BVI and a UU-flood interface
        #
        bd1 = VppBridgeDomain(self, 1)
        bd1.add_vpp_config()

        gbd1 = VppGbpBridgeDomain(self, bd1, rd1, self.loop0,
                                  tun_uu, None,
                                  ucast_arp=True)
        gbd1.add_vpp_config()

        # ... and has a /32 applied
        ip_addr = VppIpInterfaceAddress(self, gbd1.bvi,
                                        "10.0.0.128", 32).add_vpp_config()

        #
        # The Endpoint-group
        #
        epg_220 = VppGbpEndpointGroup(self, 220, 112, rd1, gbd1,
                                      None, self.loop0,
                                      "10.0.0.128",
                                      "2001:10::128",
                                      VppGbpEndpointRetention(2))
        epg_220.add_vpp_config()

        ep = VppGbpEndpoint(self, self.pg0,
                            epg_220, None,
                            "10.0.0.127", "11.0.0.127",
                            "2001:10::1", "3001::1")
        ep.add_vpp_config()

        #
        # send ARP packet from the local EP expect it on the uu interface
        #
        self.logger.info(self.vapi.cli("sh bridge 1 detail"))
        self.logger.info(self.vapi.cli("sh gbp bridge"))
        p_arp = (Ether(src=ep.mac, dst="ff:ff:ff:ff:ff:ff") /
                 ARP(op="who-has",
                     psrc=ep.ip4, pdst="10.0.0.99",
                     hwsrc=ep.mac,
                     hwdst="ff:ff:ff:ff:ff:ff"))
        self.send_and_expect(ep.itf, [p_arp], self.pg4)

        self.pg4.unconfig_ip4()

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
        # IP tables
        #
        gt4 = VppIpTable(self, 1)
        gt4.add_vpp_config()
        gt6 = VppIpTable(self, 1, is_ip6=True)
        gt6.add_vpp_config()

        rd1 = VppGbpRouteDomain(self, 1, 401, gt4, gt6)
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
        self.vapi.l2_interface_vlan_tag_rewrite(
            sw_if_index=vlan_11.sw_if_index, vtr_op=L2_VTR_OP.L2_POP_1,
            push_dot1q=11)

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
        gbd1 = VppGbpBridgeDomain(self, bd1, rd1, self.loop0, bd_uu_fwd,
                                  learn=False)
        gbd1.add_vpp_config()

        self.logger.info(self.vapi.cli("sh bridge 1 detail"))
        self.logger.info(self.vapi.cli("sh gbp bridge"))

        # ... and has a /32 applied
        ip_addr = VppIpInterfaceAddress(self, gbd1.bvi,
                                        "10.0.0.128", 32).add_vpp_config()

        #
        # The Endpoint-group in which we are learning endpoints
        #
        epg_220 = VppGbpEndpointGroup(self, 220, 441, rd1, gbd1,
                                      None, self.loop0,
                                      "10.0.0.128",
                                      "2001:10::128",
                                      VppGbpEndpointRetention(4))
        epg_220.add_vpp_config()

        #
        # The VXLAN GBP tunnel is a bridge-port and has L2 endpoint
        # learning enabled
        #
        vx_tun_l2_1 = VppGbpVxlanTunnel(
            self, 99, bd1.bd_id,
            VppEnum.vl_api_gbp_vxlan_tunnel_mode_t.GBP_VXLAN_TUNNEL_MODE_L2,
            self.pg2.local_ip4)
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

        self.assertTrue(find_route(self, ep.ip4, 32, table_id=1))

        #
        # Send to the static EP
        #
        for ii, l in enumerate(learnt):
            # a packet with an sclass from a known EPG
            # arriving on an unknown TEP
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=99, gpid=441, flags=0x88) /
                 Ether(src=l['mac'], dst=ep.mac) /
                 IP(src=l['ip'], dst=ep.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

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
                 IP(dst=l['ip'], src=ep.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rxs = self.send_and_expect(self.pg0, p * 17, self.pg3)

            for rx in rxs:
                self.assertEqual(rx[IP].src, self.pg3.local_ip4)
                self.assertEqual(rx[IP].dst, self.pg3.remote_ip4)
                self.assertEqual(rx[UDP].dport, 48879)
                # the UDP source port is a random value for hashing
                self.assertEqual(rx[VXLAN].gpid, 441)
                self.assertEqual(rx[VXLAN].vni, 116)
                self.assertTrue(rx[VXLAN].flags.G)
                self.assertTrue(rx[VXLAN].flags.Instance)
                self.assertFalse(rx[VXLAN].gpflags.A)
                self.assertFalse(rx[VXLAN].gpflags.D)

        self.pg2.unconfig_ip4()
        self.pg3.unconfig_ip4()

    def test_gbp_learn_l3(self):
        """ GBP L3 Endpoint Learning """

        self.vapi.cli("set logging class gbp level debug")

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

        rd1 = VppGbpRouteDomain(self, 2, 401, t4, t6, tun_ip4_uu, tun_ip6_uu)
        rd1.add_vpp_config()

        self.loop0.set_mac(self.router_mac)

        #
        # Bind the BVI to the RD
        #
        b4 = VppIpInterfaceBind(self, self.loop0, t4).add_vpp_config()
        b6 = VppIpInterfaceBind(self, self.loop0, t6).add_vpp_config()

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
        gbd1 = VppGbpBridgeDomain(self, bd1, rd1, self.loop0, self.pg3)
        gbd1.add_vpp_config()

        self.logger.info(self.vapi.cli("sh bridge 1 detail"))
        self.logger.info(self.vapi.cli("sh gbp bridge"))
        self.logger.info(self.vapi.cli("sh gbp route"))

        # ... and has a /32 and /128 applied
        ip4_addr = VppIpInterfaceAddress(self, gbd1.bvi,
                                         "10.0.0.128", 32,
                                         bind=b4).add_vpp_config()
        ip6_addr = VppIpInterfaceAddress(self, gbd1.bvi,
                                         "2001:10::128", 128,
                                         bind=b6).add_vpp_config()

        #
        # The Endpoint-group in which we are learning endpoints
        #
        epg_220 = VppGbpEndpointGroup(self, 220, 441, rd1, gbd1,
                                      None, self.loop0,
                                      "10.0.0.128",
                                      "2001:10::128",
                                      VppGbpEndpointRetention(4))
        epg_220.add_vpp_config()

        #
        # The VXLAN GBP tunnel is in L3 mode with learning enabled
        #
        vx_tun_l3 = VppGbpVxlanTunnel(
            self, 101, rd1.rd_id,
            VppEnum.vl_api_gbp_vxlan_tunnel_mode_t.GBP_VXLAN_TUNNEL_MODE_L3,
            self.pg2.local_ip4)
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
            # a packet with an sclass from a known EPG
            # arriving on an unknown TEP
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=101, gpid=441, flags=0x88) /
                 Ether(src=l['mac'], dst="00:00:00:11:11:11") /
                 IP(src=l['ip'], dst=ep.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

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
                 IP(dst=l['ip'], src=ep.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rxs = self.send_and_expect(self.pg0, p * 1, self.pg2)

            for rx in rxs:
                self.assertEqual(rx[IP].src, self.pg2.local_ip4)
                self.assertEqual(rx[IP].dst, self.pg2.remote_hosts[1].ip4)
                self.assertEqual(rx[UDP].dport, 48879)
                # the UDP source port is a random value for hashing
                self.assertEqual(rx[VXLAN].gpid, 441)
                self.assertEqual(rx[VXLAN].vni, 101)
                self.assertTrue(rx[VXLAN].flags.G)
                self.assertTrue(rx[VXLAN].flags.Instance)
                self.assertTrue(rx[VXLAN].gpflags.A)
                self.assertFalse(rx[VXLAN].gpflags.D)

                inner = rx[VXLAN].payload

                self.assertEqual(inner[Ether].src, routed_src_mac)
                self.assertEqual(inner[Ether].dst, routed_dst_mac)
                self.assertEqual(inner[IP].src, ep.ip4)
                self.assertEqual(inner[IP].dst, l['ip'])

        for l in learnt:
            self.assertFalse(find_gbp_endpoint(self,
                                               tep1_sw_if_index,
                                               ip=l['ip']))

        #
        # learn some remote IPv6 EPs
        #
        for ii, l in enumerate(learnt):
            # a packet with an sclass from a known EPG
            # arriving on an unknown TEP
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[1].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=101, gpid=441, flags=0x88) /
                 Ether(src=l['mac'], dst="00:00:00:11:11:11") /
                 IPv6(src=l['ip6'], dst=ep.ip6) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

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
                 IPv6(dst=l['ip6'], src=ep.ip6) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rxs = self.send_and_expect(self.pg0, p * NUM_PKTS, self.pg2)

            for rx in rxs:
                self.assertEqual(rx[IP].src, self.pg2.local_ip4)
                self.assertEqual(rx[IP].dst, self.pg2.remote_hosts[1].ip4)
                self.assertEqual(rx[UDP].dport, 48879)
                # the UDP source port is a random value for hashing
                self.assertEqual(rx[VXLAN].gpid, 441)
                self.assertEqual(rx[VXLAN].vni, 101)
                self.assertTrue(rx[VXLAN].flags.G)
                self.assertTrue(rx[VXLAN].flags.Instance)
                self.assertTrue(rx[VXLAN].gpflags.A)
                self.assertFalse(rx[VXLAN].gpflags.D)

                inner = rx[VXLAN].payload

                self.assertEqual(inner[Ether].src, routed_src_mac)
                self.assertEqual(inner[Ether].dst, routed_dst_mac)
                self.assertEqual(inner[IPv6].src, ep.ip6)
                self.assertEqual(inner[IPv6].dst, l['ip6'])

        self.logger.info(self.vapi.cli("sh gbp endpoint"))
        for l in learnt:
            self.wait_for_ep_timeout(ip=l['ip'])

        #
        # Static sends to unknown EP with no route
        #
        p = (Ether(src=ep.mac, dst=self.loop0.local_mac) /
             IP(dst="10.0.0.99", src=ep.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0, [p])

        #
        # Add a route to static EP's v4 and v6 subnet
        #
        se_10_24 = VppGbpSubnet(
            self, rd1, "10.0.0.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_TRANSPORT)
        se_10_24.add_vpp_config()

        #
        # static pings router
        #
        p = (Ether(src=ep.mac, dst=self.loop0.local_mac) /
             IP(dst=epg_220.bvi_ip4, src=ep.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        self.send_and_expect(self.pg0, p * NUM_PKTS, self.pg0)

        p = (Ether(src=ep.mac, dst=self.loop0.local_mac) /
             IPv6(dst=epg_220.bvi_ip6, src=ep.ip6) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        self.send_and_expect(self.pg0, p * NUM_PKTS, self.pg0)

        #
        # packets to address in the subnet are sent on the uu-fwd
        #
        p = (Ether(src=ep.mac, dst=self.loop0.local_mac) /
             IP(dst="10.0.0.99", src=ep.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg0, [p], self.pg4)
        for rx in rxs:
            self.assertEqual(rx[IP].src, self.pg4.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg4.remote_ip4)
            self.assertEqual(rx[UDP].dport, 48879)
            # the UDP source port is a random value for hashing
            self.assertEqual(rx[VXLAN].gpid, 441)
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
            # a packet with an sclass from a known EPG
            # arriving on an unknown TEP
            p = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_hosts[2].ip4,
                    dst=self.pg2.local_ip4) /
                 UDP(sport=1234, dport=48879) /
                 VXLAN(vni=101, gpid=441, flags=0x88) /
                 Ether(src=l['mac'], dst="00:00:00:11:11:11") /
                 IP(src=l['ip'], dst=ep.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rx = self.send_and_expect(self.pg2, [p], self.pg0)

            # the new TEP
            tep1_sw_if_index = find_vxlan_gbp_tunnel(
                self,
                self.pg2.local_ip4,
                self.pg2.remote_hosts[2].ip4,
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
                                self.pg2.remote_hosts[2].ip4,
                                mac=None)
        rep_88.add_vpp_config()

        #
        # Add a remote endpoint from the API that matches an existing one
        # this is a lower priority, hence the packet is sent to the DP leanrt
        # TEP
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
        # Add a route to the learned EP's v4 subnet
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
                 IP(dst=ip, src=ep.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

            rxs = self.send_and_expect(self.pg0, p * NUM_PKTS, self.pg2)

            for rx in rxs:
                self.assertEqual(rx[IP].src, self.pg2.local_ip4)
                self.assertEqual(rx[IP].dst, self.pg2.remote_hosts[2].ip4)
                self.assertEqual(rx[UDP].dport, 48879)
                # the UDP source port is a random value for hashing
                self.assertEqual(rx[VXLAN].gpid, 441)
                self.assertEqual(rx[VXLAN].vni, 101)
                self.assertTrue(rx[VXLAN].flags.G)
                self.assertTrue(rx[VXLAN].flags.Instance)
                self.assertTrue(rx[VXLAN].gpflags.A)
                self.assertFalse(rx[VXLAN].gpflags.D)

                inner = rx[VXLAN].payload

                self.assertEqual(inner[Ether].src, routed_src_mac)
                self.assertEqual(inner[Ether].dst, routed_dst_mac)
                self.assertEqual(inner[IP].src, ep.ip4)
                self.assertEqual(inner[IP].dst, ip)

        #
        # remove the API remote EPs, only API sourced is gone, the DP
        # learnt one remains
        #
        rep_88.remove_vpp_config()
        rep_2.remove_vpp_config()

        self.assertTrue(find_gbp_endpoint(self, ip=rep_2.ip4))

        p = (Ether(src=ep.mac, dst=self.loop0.local_mac) /
             IP(src=ep.ip4, dst=rep_2.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))
        rxs = self.send_and_expect(self.pg0, [p], self.pg2)

        self.assertFalse(find_gbp_endpoint(self, ip=rep_88.ip4))

        p = (Ether(src=ep.mac, dst=self.loop0.local_mac) /
             IP(src=ep.ip4, dst=rep_88.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))
        rxs = self.send_and_expect(self.pg0, [p], self.pg4)

        #
        # to appease the testcase we cannot have the registered EP still
        # present (because it's DP learnt) when the TC ends so wait until
        # it is removed
        #
        self.wait_for_ep_timeout(ip=rep_88.ip4)
        self.wait_for_ep_timeout(ip=rep_2.ip4)

        #
        # Same as above, learn a remote EP via CP and DP
        # this time remove the DP one first. expect the CP data to remain
        #
        rep_3 = VppGbpEndpoint(self, vx_tun_l3,
                               epg_220, None,
                               "10.0.1.4", "11.0.0.103",
                               "2001::10:3", "3001::103",
                               ep_flags.GBP_API_ENDPOINT_FLAG_REMOTE,
                               self.pg2.local_ip4,
                               self.pg2.remote_hosts[1].ip4,
                               mac=None)
        rep_3.add_vpp_config()

        p = (Ether(src=self.pg2.remote_mac,
                   dst=self.pg2.local_mac) /
             IP(src=self.pg2.remote_hosts[2].ip4,
                dst=self.pg2.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=101, gpid=441, flags=0x88) /
             Ether(src=l['mac'], dst="00:00:00:11:11:11") /
             IP(src="10.0.1.4", dst=ep.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))
        rxs = self.send_and_expect(self.pg2, p * NUM_PKTS, self.pg0)

        self.assertTrue(find_gbp_endpoint(self,
                                          vx_tun_l3._sw_if_index,
                                          ip=rep_3.ip4,
                                          tep=[self.pg2.local_ip4,
                                               self.pg2.remote_hosts[2].ip4]))

        p = (Ether(src=ep.mac, dst=self.loop0.local_mac) /
             IP(dst="10.0.1.4", src=ep.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))
        rxs = self.send_and_expect(self.pg0, p * NUM_PKTS, self.pg2)

        # host 2 is the DP learned TEP
        for rx in rxs:
            self.assertEqual(rx[IP].src, self.pg2.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg2.remote_hosts[2].ip4)

        self.wait_for_ep_timeout(ip=rep_3.ip4,
                                 tep=[self.pg2.local_ip4,
                                      self.pg2.remote_hosts[2].ip4])

        rxs = self.send_and_expect(self.pg0, p * NUM_PKTS, self.pg2)

        # host 1 is the CP learned TEP
        for rx in rxs:
            self.assertEqual(rx[IP].src, self.pg2.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg2.remote_hosts[1].ip4)

        #
        # shutdown with learnt endpoint present
        #
        p = (Ether(src=self.pg2.remote_mac,
                   dst=self.pg2.local_mac) /
             IP(src=self.pg2.remote_hosts[1].ip4,
                dst=self.pg2.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=101, gpid=441, flags=0x88) /
             Ether(src=l['mac'], dst="00:00:00:11:11:11") /
             IP(src=learnt[1]['ip'], dst=ep.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

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

        self.vapi.cli("set logging class gbp level debug")

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
        # IP tables
        #
        t4 = VppIpTable(self, 1)
        t4.add_vpp_config()
        t6 = VppIpTable(self, 1, True)
        t6.add_vpp_config()

        rd1 = VppGbpRouteDomain(self, 2, 402, t4, t6)
        rd1.add_vpp_config()

        self.loop0.set_mac(self.router_mac)

        #
        # Bind the BVI to the RD
        #
        b_ip4 = VppIpInterfaceBind(self, self.loop0, t4).add_vpp_config()
        b_ip6 = VppIpInterfaceBind(self, self.loop0, t6).add_vpp_config()

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
        gbd1 = VppGbpBridgeDomain(self, bd1, rd1, self.loop0)
        gbd1.add_vpp_config()

        bd2 = VppBridgeDomain(self, 2)
        bd2.add_vpp_config()
        gbd2 = VppGbpBridgeDomain(self, bd2, rd1, self.loop1)
        gbd2.add_vpp_config()

        # ... and has a /32 and /128 applied
        ip4_addr = VppIpInterfaceAddress(self, gbd1.bvi,
                                         "10.0.0.128", 32,
                                         bind=b_ip4).add_vpp_config()
        ip6_addr = VppIpInterfaceAddress(self, gbd1.bvi,
                                         "2001:10::128", 128,
                                         bind=b_ip6).add_vpp_config()
        ip4_addr = VppIpInterfaceAddress(self, gbd2.bvi,
                                         "10.0.1.128", 32).add_vpp_config()
        ip6_addr = VppIpInterfaceAddress(self, gbd2.bvi,
                                         "2001:11::128", 128).add_vpp_config()

        #
        # The Endpoint-groups in which we are learning endpoints
        #
        epg_220 = VppGbpEndpointGroup(self, 220, 440, rd1, gbd1,
                                      None, gbd1.bvi,
                                      "10.0.0.128",
                                      "2001:10::128",
                                      VppGbpEndpointRetention(60))
        epg_220.add_vpp_config()
        epg_221 = VppGbpEndpointGroup(self, 221, 441, rd1, gbd2,
                                      None, gbd2.bvi,
                                      "10.0.1.128",
                                      "2001:11::128",
                                      VppGbpEndpointRetention(60))
        epg_221.add_vpp_config()
        epg_222 = VppGbpEndpointGroup(self, 222, 442, rd1, gbd1,
                                      None, gbd1.bvi,
                                      "10.0.2.128",
                                      "2001:12::128",
                                      VppGbpEndpointRetention(60))
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
        gbd3 = VppGbpBridgeDomain(self, bd3, rd1, self.loop2,
                                  bd_uu1, learn=False)
        gbd3.add_vpp_config()
        bd4 = VppBridgeDomain(self, 4)
        bd4.add_vpp_config()
        gbd4 = VppGbpBridgeDomain(self, bd4, rd1, self.loop3,
                                  bd_uu2, learn=False)
        gbd4.add_vpp_config()

        #
        # EPGs in which the service endpoints exist
        #
        epg_320 = VppGbpEndpointGroup(self, 320, 550, rd1, gbd3,
                                      None, gbd1.bvi,
                                      "12.0.0.128",
                                      "4001:10::128",
                                      VppGbpEndpointRetention(60))
        epg_320.add_vpp_config()
        epg_321 = VppGbpEndpointGroup(self, 321, 551, rd1, gbd4,
                                      None, gbd2.bvi,
                                      "12.0.1.128",
                                      "4001:11::128",
                                      VppGbpEndpointRetention(60))
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
               IP(src=ep1.ip4, dst=ep3.ip4) /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100)),
              (Ether(src=ep3.mac, dst=ep1.mac) /
               IP(src=ep3.ip4, dst=ep1.ip4) /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100))]
        p6 = [(Ether(src=ep1.mac, dst=ep3.mac) /
               IPv6(src=ep1.ip6, dst=ep3.ip6) /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100)),
              (Ether(src=ep3.mac, dst=ep1.mac) /
               IPv6(src=ep3.ip6, dst=ep1.ip6) /
               UDP(sport=1234, dport=1230) /
               Raw(b'\xa5' * 100))]

        # should be dropped since no contract yet
        self.send_and_assert_no_replies(self.pg0, [p4[0]])
        self.send_and_assert_no_replies(self.pg0, [p6[0]])

        #
        # Add a contract with a rule to load-balance redirect via SEP1 and SEP2
        # one of the next-hops is via an EP that is not known
        #
        rule4 = AclRule(is_permit=1, proto=17)
        rule6 = AclRule(src_prefix=IPv6Network((0, 0)),
                        dst_prefix=IPv6Network((0, 0)), is_permit=1, proto=17)
        acl = VppAcl(self, rules=[rule4, rule6])
        acl.add_vpp_config()

        #
        # test the src-ip hash mode
        #
        c1 = VppGbpContract(
            self, 402, epg_220.sclass, epg_222.sclass, acl.acl_index,
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
            self, 402, epg_222.sclass, epg_220.sclass, acl.acl_index,
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
            self.assertEqual(rx[IP].src, ep1.ip4)
            self.assertEqual(rx[IP].dst, ep3.ip4)

        rxs = self.send_and_expect(self.pg2, p4[1] * 17, sep2.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep2.mac)
            self.assertEqual(rx[IP].src, ep3.ip4)
            self.assertEqual(rx[IP].dst, ep1.ip4)

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
            self.assertEqual(inner[IPv6].src, ep1.ip6)
            self.assertEqual(inner[IPv6].dst, ep3.ip6)

        rxs = self.send_and_expect(self.pg2, p6[1] * 17, sep3.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep3.mac)
            self.assertEqual(rx[IPv6].src, ep3.ip6)
            self.assertEqual(rx[IPv6].dst, ep1.ip6)

        #
        # programme the unknown EP
        #
        sep4.add_vpp_config()

        rxs = self.send_and_expect(self.pg0, p6[0] * 17, sep4.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep4.mac)
            self.assertEqual(rx[IPv6].src, ep1.ip6)
            self.assertEqual(rx[IPv6].dst, ep3.ip6)

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
            self.assertEqual(inner[IPv6].src, ep1.ip6)
            self.assertEqual(inner[IPv6].dst, ep3.ip6)

        c1.remove_vpp_config()
        c2.remove_vpp_config()

        #
        # test the symmetric hash mode
        #
        c1 = VppGbpContract(
            self, 402, epg_220.sclass, epg_222.sclass, acl.acl_index,
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
            self, 402, epg_222.sclass, epg_220.sclass, acl.acl_index,
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
            self.assertEqual(rx[IP].src, ep1.ip4)
            self.assertEqual(rx[IP].dst, ep3.ip4)

        rxs = self.send_and_expect(self.pg2, p4[1] * 17, sep1.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep1.mac)
            self.assertEqual(rx[IP].src, ep3.ip4)
            self.assertEqual(rx[IP].dst, ep1.ip4)

        #
        # programme the unknown EP for the L3 tests
        #
        sep4.add_vpp_config()

        #
        # an L3 switch packet between local EPs in different EPGs
        #  different dest ports on each so the are LB hashed differently
        #
        p4 = [(Ether(src=ep1.mac, dst=str(self.router_mac)) /
               IP(src=ep1.ip4, dst=ep2.ip4) /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100)),
              (Ether(src=ep2.mac, dst=str(self.router_mac)) /
               IP(src=ep2.ip4, dst=ep1.ip4) /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100))]
        p6 = [(Ether(src=ep1.mac, dst=str(self.router_mac)) /
               IPv6(src=ep1.ip6, dst=ep2.ip6) /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100)),
              (Ether(src=ep2.mac, dst=str(self.router_mac)) /
               IPv6(src=ep2.ip6, dst=ep1.ip6) /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100))]

        c3 = VppGbpContract(
            self, 402, epg_220.sclass, epg_221.sclass, acl.acl_index,
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
            self.assertEqual(rx[IP].src, ep1.ip4)
            self.assertEqual(rx[IP].dst, ep2.ip4)

        #
        # learn a remote EP in EPG 221
        #   packets coming from unknown remote EPs will be leant & redirected
        #
        vx_tun_l3 = VppGbpVxlanTunnel(
            self, 444, rd1.rd_id,
            VppEnum.vl_api_gbp_vxlan_tunnel_mode_t.GBP_VXLAN_TUNNEL_MODE_L3,
            self.pg2.local_ip4)
        vx_tun_l3.add_vpp_config()

        c4 = VppGbpContract(
            self, 402, epg_221.sclass, epg_220.sclass, acl.acl_index,
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
        c4.add_vpp_config()

        p = (Ether(src=self.pg7.remote_mac,
                   dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4,
                dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=444, gpid=441, flags=0x88) /
             Ether(src="00:22:22:22:22:33", dst=str(self.router_mac)) /
             IP(src="10.0.0.88", dst=ep1.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        # unknown remote EP to local EP redirected
        rxs = self.send_and_expect(self.pg7, [p], sep1.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep1.mac)
            self.assertEqual(rx[IP].src, "10.0.0.88")
            self.assertEqual(rx[IP].dst, ep1.ip4)

        # endpoint learnt via the parent GBP-vxlan interface
        self.assertTrue(find_gbp_endpoint(self,
                                          vx_tun_l3._sw_if_index,
                                          ip="10.0.0.88"))

        p = (Ether(src=self.pg7.remote_mac,
                   dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4,
                dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=444, gpid=441, flags=0x88) /
             Ether(src="00:22:22:22:22:33", dst=str(self.router_mac)) /
             IPv6(src="2001:10::88", dst=ep1.ip6) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        # unknown remote EP to local EP redirected (ipv6)
        rxs = self.send_and_expect(self.pg7, [p], sep3.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep3.mac)
            self.assertEqual(rx[IPv6].src, "2001:10::88")
            self.assertEqual(rx[IPv6].dst, ep1.ip6)

        # endpoint learnt via the parent GBP-vxlan interface
        self.assertTrue(find_gbp_endpoint(self,
                                          vx_tun_l3._sw_if_index,
                                          ip="2001:10::88"))

        #
        # L3 switch from local to remote EP
        #
        p4 = [(Ether(src=ep1.mac, dst=str(self.router_mac)) /
               IP(src=ep1.ip4, dst="10.0.0.88") /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100))]
        p6 = [(Ether(src=ep1.mac, dst=str(self.router_mac)) /
               IPv6(src=ep1.ip6, dst="2001:10::88") /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100))]

        rxs = self.send_and_expect(self.pg0, p4[0] * 17, sep1.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep1.mac)
            self.assertEqual(rx[IP].src, ep1.ip4)
            self.assertEqual(rx[IP].dst, "10.0.0.88")

        rxs = self.send_and_expect(self.pg0, p6[0] * 17, sep4.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep4.mac)
            self.assertEqual(rx[IPv6].src, ep1.ip6)
            self.assertEqual(rx[IPv6].dst, "2001:10::88")

        #
        # test the dst-ip hash mode
        #
        c5 = VppGbpContract(
            self, 402, epg_220.sclass, epg_221.sclass, acl.acl_index,
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
            self.assertEqual(rx[IP].src, ep1.ip4)
            self.assertEqual(rx[IP].dst, "10.0.0.88")

        rxs = self.send_and_expect(self.pg0, p6[0] * 17, sep3.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep3.mac)
            self.assertEqual(rx[IPv6].src, ep1.ip6)
            self.assertEqual(rx[IPv6].dst, "2001:10::88")

        #
        # a programmed remote SEP in EPG 320
        #

        # gbp vxlan tunnel for the remote SEP
        vx_tun_l3_sep = VppGbpVxlanTunnel(
            self, 555, rd1.rd_id,
            VppEnum.vl_api_gbp_vxlan_tunnel_mode_t.GBP_VXLAN_TUNNEL_MODE_L3,
            self.pg2.local_ip4)
        vx_tun_l3_sep.add_vpp_config()

        # remote SEP
        sep5 = VppGbpEndpoint(self, vx_tun_l3_sep,
                              epg_320, None,
                              "12.0.0.10", "13.0.0.10",
                              "4001:10::10", "5001:10::10",
                              ep_flags.GBP_API_ENDPOINT_FLAG_REMOTE,
                              self.pg7.local_ip4,
                              self.pg7.remote_ip4,
                              mac=None)
        sep5.add_vpp_config()

        #
        # local l3out redirect tests
        #

        # add local l3out
        # the external bd
        self.loop4.set_mac(self.router_mac)
        b_lo4_ip4 = VppIpInterfaceBind(self, self.loop4, t4).add_vpp_config()
        b_lo4_ip6 = VppIpInterfaceBind(self, self.loop4, t6).add_vpp_config()
        ebd = VppBridgeDomain(self, 100)
        ebd.add_vpp_config()
        gebd = VppGbpBridgeDomain(self, ebd, rd1, self.loop4, None, None)
        gebd.add_vpp_config()
        # the external epg
        eepg = VppGbpEndpointGroup(self, 888, 765, rd1, gebd,
                                   None, gebd.bvi,
                                   "10.1.0.128",
                                   "2001:10:1::128",
                                   VppGbpEndpointRetention(60))
        eepg.add_vpp_config()
        # add subnets to BVI
        VppIpInterfaceAddress(
            self,
            gebd.bvi,
            "10.1.0.128",
            24, bind=b_lo4_ip4).add_vpp_config()
        VppIpInterfaceAddress(
            self,
            gebd.bvi,
            "2001:10:1::128",
            64, bind=b_lo4_ip6).add_vpp_config()
        # ... which are L3-out subnets
        VppGbpSubnet(self, rd1, "10.1.0.0", 24,
                     VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
                     sclass=765).add_vpp_config()
        VppGbpSubnet(self, rd1, "2001:10:1::128", 64,
                     VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
                     sclass=765).add_vpp_config()
        # external endpoints
        VppL2Vtr(self, self.vlan_100, L2_VTR_OP.L2_POP_1).add_vpp_config()
        eep1 = VppGbpEndpoint(self, self.vlan_100, eepg, None, "10.1.0.1",
                              "11.1.0.1", "2001:10:1::1", "3001:10:1::1",
                              ep_flags.GBP_API_ENDPOINT_FLAG_EXTERNAL)
        eep1.add_vpp_config()
        VppL2Vtr(self, self.vlan_101, L2_VTR_OP.L2_POP_1).add_vpp_config()
        eep2 = VppGbpEndpoint(self, self.vlan_101, eepg, None, "10.1.0.2",
                              "11.1.0.2", "2001:10:1::2", "3001:10:1::2",
                              ep_flags.GBP_API_ENDPOINT_FLAG_EXTERNAL)
        eep2.add_vpp_config()

        # external subnets reachable though eep1 and eep2 respectively
        VppIpRoute(self, "10.220.0.0", 24,
                   [VppRoutePath(eep1.ip4, eep1.epg.bvi.sw_if_index)],
                   table_id=t4.table_id).add_vpp_config()
        VppGbpSubnet(self, rd1, "10.220.0.0", 24,
                     VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
                     sclass=4220).add_vpp_config()
        VppIpRoute(self, "10:220::", 64,
                   [VppRoutePath(eep1.ip6, eep1.epg.bvi.sw_if_index)],
                   table_id=t6.table_id).add_vpp_config()
        VppGbpSubnet(self, rd1, "10:220::", 64,
                     VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
                     sclass=4220).add_vpp_config()
        VppIpRoute(self, "10.221.0.0", 24,
                   [VppRoutePath(eep2.ip4, eep2.epg.bvi.sw_if_index)],
                   table_id=t4.table_id).add_vpp_config()
        VppGbpSubnet(self, rd1, "10.221.0.0", 24,
                     VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
                     sclass=4221).add_vpp_config()
        VppIpRoute(self, "10:221::", 64,
                   [VppRoutePath(eep2.ip6, eep2.epg.bvi.sw_if_index)],
                   table_id=t6.table_id).add_vpp_config()
        VppGbpSubnet(self, rd1, "10:221::", 64,
                     VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
                     sclass=4221).add_vpp_config()

        #
        # l3out redirect to remote (known, then unknown) SEP
        #

        # packets from 1 external subnet to the other
        p = [(Ether(src=eep1.mac, dst=self.router_mac) /
              Dot1Q(vlan=100) /
              IP(src="10.220.0.17", dst="10.221.0.65") /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100)),
             (Ether(src=eep1.mac, dst=self.router_mac) /
              Dot1Q(vlan=100) /
              IPv6(src="10:220::17", dst="10:221::65") /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100))]

        # packets should be dropped in absence of contract
        self.send_and_assert_no_replies(self.pg0, p)

        # contract redirecting to sep5
        VppGbpContract(
            self, 402, 4220, 4221, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_DST_IP,
                [VppGbpContractNextHop(sep5.vmac, sep5.epg.bd,
                                       sep5.ip4, sep5.epg.rd)]),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_DST_IP,
                    [VppGbpContractNextHop(sep5.vmac, sep5.epg.bd,
                                           sep5.ip6, sep5.epg.rd)])],
            [ETH_P_IP, ETH_P_IPV6]).add_vpp_config()

        rxs = self.send_and_expect(self.pg0, p, self.pg7)

        for rx, tx in zip(rxs, p):
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            # this should use the programmed remote leaf TEP
            self.assertEqual(rx[VXLAN].vni, 555)
            self.assertEqual(rx[VXLAN].gpid, 4220)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # redirect policy has been applied
            self.assertTrue(rx[VXLAN].gpflags.A)
            self.assertTrue(rx[VXLAN].gpflags.D)
            rxip = rx[VXLAN][Ether].payload
            txip = tx[Dot1Q].payload
            self.assertEqual(rxip.src, txip.src)
            self.assertEqual(rxip.dst, txip.dst)

        # remote SEP: it is now an unknown remote SEP and should go
        # to spine proxy
        sep5.remove_vpp_config()

        rxs = self.send_and_expect(self.pg0, p, self.pg7)

        for rx, tx in zip(rxs, p):
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            # this should use the spine proxy TEP
            self.assertEqual(rx[VXLAN].vni, epg_320.bd.uu_fwd.vni)
            self.assertEqual(rx[VXLAN].gpid, 4220)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # redirect policy has been applied
            self.assertTrue(rx[VXLAN].gpflags.A)
            self.assertTrue(rx[VXLAN].gpflags.D)
            rxip = rx[VXLAN][Ether].payload
            txip = tx[Dot1Q].payload
            self.assertEqual(rxip.src, txip.src)
            self.assertEqual(rxip.dst, txip.dst)

        #
        # l3out redirect to local SEP
        #

        # change the contract between l3out to redirect to local SEPs
        # instead of remote SEP
        VppGbpContract(
            self, 402, 4220, 4221, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_DST_IP,
                [VppGbpContractNextHop(sep1.vmac, sep1.epg.bd,
                                       sep1.ip4, sep1.epg.rd)]),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_DST_IP,
                    [VppGbpContractNextHop(sep1.vmac, sep1.epg.bd,
                                           sep1.ip6, sep1.epg.rd)])],
            [ETH_P_IP, ETH_P_IPV6]).add_vpp_config()

        rxs = self.send_and_expect(self.pg0, p, sep1.itf)
        for rx, tx in zip(rxs, p):
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep1.mac)
            rxip = rx[Ether].payload
            txip = tx[Ether].payload
            self.assertEqual(rxip.src, txip.src)
            self.assertEqual(rxip.dst, txip.dst)

        #
        # redirect remote EP to remote (known then unknown) SEP
        #

        # remote SEP known again
        sep5.add_vpp_config()

        # contract to redirect to learnt SEP
        VppGbpContract(
            self, 402, epg_221.sclass, epg_222.sclass, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_DST_IP,
                [VppGbpContractNextHop(sep5.vmac, sep5.epg.bd,
                                       sep5.ip4, sep5.epg.rd)]),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_DST_IP,
                    [VppGbpContractNextHop(sep5.vmac, sep5.epg.bd,
                                           sep5.ip6, sep5.epg.rd)])],
            [ETH_P_IP, ETH_P_IPV6]).add_vpp_config()

        # packets from unknown EP 221 to known EP in EPG 222
        # should be redirected to known remote SEP
        base = (Ether(src=self.pg7.remote_mac, dst=self.pg7.local_mac) /
                IP(src=self.pg7.remote_ip4, dst=self.pg7.local_ip4) /
                UDP(sport=1234, dport=48879) /
                VXLAN(vni=444, gpid=441, flags=0x88) /
                Ether(src="00:22:22:22:22:44", dst=str(self.router_mac)))
        p = [(base /
              IP(src="10.0.1.100", dst=ep3.ip4) /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100)),
             (base /
              IPv6(src="2001:10::100", dst=ep3.ip6) /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100))]

        # unknown remote EP to local EP redirected to known remote SEP
        rxs = self.send_and_expect(self.pg7, p, self.pg7)

        for rx, tx in zip(rxs, p):
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            # this should use the programmed remote leaf TEP
            self.assertEqual(rx[VXLAN].vni, 555)
            self.assertEqual(rx[VXLAN].gpid, epg_221.sclass)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # redirect policy has been applied
            self.assertTrue(rx[VXLAN].gpflags.A)
            self.assertFalse(rx[VXLAN].gpflags.D)
            rxip = rx[VXLAN][Ether].payload
            txip = tx[VXLAN][Ether].payload
            self.assertEqual(rxip.src, txip.src)
            self.assertEqual(rxip.dst, txip.dst)

        # endpoint learnt via the parent GBP-vxlan interface
        self.assertTrue(find_gbp_endpoint(self,
                                          vx_tun_l3._sw_if_index,
                                          ip="10.0.1.100"))
        self.assertTrue(find_gbp_endpoint(self,
                                          vx_tun_l3._sw_if_index,
                                          ip="2001:10::100"))

        # remote SEP: it is now an unknown remote SEP and should go
        # to spine proxy
        sep5.remove_vpp_config()

        # remote EP (coming from spine proxy) to local EP redirected to
        # known remote SEP
        rxs = self.send_and_expect(self.pg7, p, self.pg7)

        for rx, tx in zip(rxs, p):
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            # this should use the spine proxy TEP
            self.assertEqual(rx[VXLAN].vni, epg_320.bd.uu_fwd.vni)
            self.assertEqual(rx[VXLAN].gpid, epg_221.sclass)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # redirect policy has been applied
            self.assertTrue(rx[VXLAN].gpflags.A)
            self.assertFalse(rx[VXLAN].gpflags.D)
            rxip = rx[VXLAN][Ether].payload
            txip = tx[VXLAN][Ether].payload
            self.assertEqual(rxip.src, txip.src)
            self.assertEqual(rxip.dst, txip.dst)

        #
        # cleanup
        #
        self.pg7.unconfig_ip4()

    def test_gbp_redirect_extended(self):
        """ GBP Endpoint Redirect Extended """

        self.vapi.cli("set logging class gbp level debug")

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
        # IP tables
        #
        t4 = VppIpTable(self, 1)
        t4.add_vpp_config()
        t6 = VppIpTable(self, 1, True)
        t6.add_vpp_config()

        # create IPv4 and IPv6 RD UU VxLAN-GBP TEP and bind them to the right
        # VRF
        rd_uu4 = VppVxlanGbpTunnel(
            self,
            self.pg7.local_ip4,
            self.pg7.remote_ip4,
            114,
            mode=(VppEnum.vl_api_vxlan_gbp_api_tunnel_mode_t.
                  VXLAN_GBP_API_TUNNEL_MODE_L3))
        rd_uu4.add_vpp_config()
        VppIpInterfaceBind(self, rd_uu4, t4).add_vpp_config()

        rd_uu6 = VppVxlanGbpTunnel(
            self,
            self.pg7.local_ip4,
            self.pg7.remote_ip4,
            115,
            mode=(VppEnum.vl_api_vxlan_gbp_api_tunnel_mode_t.
                  VXLAN_GBP_API_TUNNEL_MODE_L3))
        rd_uu6.add_vpp_config()
        VppIpInterfaceBind(self, rd_uu6, t4).add_vpp_config()

        rd1 = VppGbpRouteDomain(self, 2, 402, t4, t6, rd_uu4, rd_uu6)
        rd1.add_vpp_config()

        self.loop0.set_mac(self.router_mac)
        self.loop1.set_mac(self.router_mac)
        self.loop2.set_mac(self.router_mac)

        #
        # Bind the BVI to the RD
        #
        b_lo0_ip4 = VppIpInterfaceBind(self, self.loop0, t4).add_vpp_config()
        b_lo0_ip6 = VppIpInterfaceBind(self, self.loop0, t6).add_vpp_config()
        b_lo1_ip4 = VppIpInterfaceBind(self, self.loop1, t4).add_vpp_config()
        b_lo1_ip6 = VppIpInterfaceBind(self, self.loop1, t6).add_vpp_config()
        b_lo2_ip4 = VppIpInterfaceBind(self, self.loop2, t4).add_vpp_config()
        b_lo2_ip6 = VppIpInterfaceBind(self, self.loop2, t6).add_vpp_config()

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
        gbd1 = VppGbpBridgeDomain(self, bd1, rd1, self.loop0)
        gbd1.add_vpp_config()

        bd2 = VppBridgeDomain(self, 2)
        bd2.add_vpp_config()
        gbd2 = VppGbpBridgeDomain(self, bd2, rd1, self.loop1)
        gbd2.add_vpp_config()

        # ... and has a /32 and /128 applied
        ip4_addr1 = VppIpInterfaceAddress(self, gbd1.bvi,
                                          "10.0.0.128", 32,
                                          bind=b_lo0_ip4).add_vpp_config()
        ip6_addr1 = VppIpInterfaceAddress(self, gbd1.bvi,
                                          "2001:10::128", 128,
                                          bind=b_lo0_ip6).add_vpp_config()
        ip4_addr2 = VppIpInterfaceAddress(self, gbd2.bvi,
                                          "10.0.1.128", 32,
                                          bind=b_lo1_ip4).add_vpp_config()
        ip6_addr2 = VppIpInterfaceAddress(self, gbd2.bvi,
                                          "2001:11::128", 128,
                                          bind=b_lo1_ip6).add_vpp_config()

        #
        # The Endpoint-groups
        #
        epg_220 = VppGbpEndpointGroup(self, 220, 440, rd1, gbd1,
                                      None, gbd1.bvi,
                                      "10.0.0.128",
                                      "2001:10::128",
                                      VppGbpEndpointRetention(60))
        epg_220.add_vpp_config()
        epg_221 = VppGbpEndpointGroup(self, 221, 441, rd1, gbd2,
                                      None, gbd2.bvi,
                                      "10.0.1.128",
                                      "2001:11::128",
                                      VppGbpEndpointRetention(60))
        epg_221.add_vpp_config()

        #
        # a GBP bridge domains for the SEPs
        #
        bd_uu3 = VppVxlanGbpTunnel(self, self.pg7.local_ip4,
                                   self.pg7.remote_ip4, 116)
        bd_uu3.add_vpp_config()

        bd3 = VppBridgeDomain(self, 3)
        bd3.add_vpp_config()
        gbd3 = VppGbpBridgeDomain(self, bd3, rd1, self.loop2,
                                  bd_uu3, learn=False)
        gbd3.add_vpp_config()

        ip4_addr3 = VppIpInterfaceAddress(self, gbd3.bvi,
                                          "12.0.0.128", 32,
                                          bind=b_lo2_ip4).add_vpp_config()
        ip6_addr3 = VppIpInterfaceAddress(self, gbd3.bvi,
                                          "4001:10::128", 128,
                                          bind=b_lo2_ip6).add_vpp_config()

        #
        # self.logger.info(self.vapi.cli("show gbp bridge"))
        # self.logger.info(self.vapi.cli("show vxlan-gbp tunnel"))
        # self.logger.info(self.vapi.cli("show gbp vxlan"))
        # self.logger.info(self.vapi.cli("show int addr"))
        #

        #
        # EPGs in which the service endpoints exist
        #
        epg_320 = VppGbpEndpointGroup(self, 320, 550, rd1, gbd3,
                                      None, gbd3.bvi,
                                      "12.0.0.128",
                                      "4001:10::128",
                                      VppGbpEndpointRetention(60))
        epg_320.add_vpp_config()

        #
        # endpoints
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

        #
        # service endpoints
        #
        sep1 = VppGbpEndpoint(self, self.pg3,
                              epg_320, None,
                              "12.0.0.1", "13.0.0.1",
                              "4001:10::1", "5001:10::1")
        sep2 = VppGbpEndpoint(self, self.pg4,
                              epg_320, None,
                              "12.0.0.2", "13.0.0.2",
                              "4001:10::2", "5001:10::2")

        # sep1 and sep2 are not added to config yet
        # they are unknown for now

        #
        # add routes to EPG subnets
        #
        VppGbpSubnet(self, rd1, "10.0.0.0", 24,
                     VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_TRANSPORT
                     ).add_vpp_config()
        VppGbpSubnet(self, rd1, "10.0.1.0", 24,
                     VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_TRANSPORT
                     ).add_vpp_config()

        #
        # Local host to known local host in different BD
        # with SFC contract (source and destination are in
        # one node and service endpoint in another node)
        #
        p4 = [(Ether(src=ep1.mac, dst=str(self.router_mac)) /
               IP(src=ep1.ip4, dst=ep2.ip4) /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100)),
              (Ether(src=ep2.mac, dst=str(self.router_mac)) /
               IP(src=ep2.ip4, dst=ep1.ip4) /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100))]
        p6 = [(Ether(src=ep1.mac, dst=str(self.router_mac)) /
               IPv6(src=ep1.ip6, dst=ep2.ip6) /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100)),
              (Ether(src=ep2.mac, dst=str(self.router_mac)) /
               IPv6(src=ep2.ip6, dst=ep1.ip6) /
               UDP(sport=1234, dport=1230) /
               Raw(b'\xa5' * 100))]

        # should be dropped since no contract yet
        self.send_and_assert_no_replies(self.pg0, [p4[0]])
        self.send_and_assert_no_replies(self.pg0, [p6[0]])

        #
        # Add a contract with a rule to load-balance redirect via SEP1 and SEP2
        # one of the next-hops is via an EP that is not known
        #
        rule4 = AclRule(is_permit=1, proto=17)
        rule6 = AclRule(src_prefix=IPv6Network((0, 0)),
                        dst_prefix=IPv6Network((0, 0)), is_permit=1, proto=17)
        acl = VppAcl(self, rules=[rule4, rule6])
        acl.add_vpp_config()

        #
        # test the src-ip hash mode
        #
        c1 = VppGbpContract(
            self, 402, epg_220.sclass, epg_221.sclass, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SYMMETRIC,
                [VppGbpContractNextHop(sep1.vmac, sep1.epg.bd,
                                       sep1.ip4, sep1.epg.rd)]),
             VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SYMMETRIC,
                [VppGbpContractNextHop(sep1.vmac, sep1.epg.bd,
                                       sep1.ip6, sep1.epg.rd)])],
            [ETH_P_IP, ETH_P_IPV6])
        c1.add_vpp_config()

        c2 = VppGbpContract(
            self, 402, epg_221.sclass, epg_220.sclass, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SYMMETRIC,
                [VppGbpContractNextHop(sep1.vmac, sep1.epg.bd,
                                       sep1.ip4, sep1.epg.rd)]),
             VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_REDIRECT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SYMMETRIC,
                [VppGbpContractNextHop(sep1.vmac, sep1.epg.bd,
                                       sep1.ip6, sep1.epg.rd)])],
            [ETH_P_IP, ETH_P_IPV6])
        c2.add_vpp_config()

        # ep1 <--> ep2 redirected through sep1
        # sep1 is unknown
        # packet is redirected to sep bd and then go through sep bd UU

        rxs = self.send_and_expect(self.pg0, p4[0] * 17, self.pg7)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 116)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # redirect policy has been applied
            self.assertTrue(rx[VXLAN].gpflags.A)
            self.assertFalse(rx[VXLAN].gpflags.D)

            inner = rx[VXLAN].payload

            self.assertEqual(inner[Ether].src, routed_src_mac)
            self.assertEqual(inner[Ether].dst, sep1.mac)
            self.assertEqual(inner[IP].src, ep1.ip4)
            self.assertEqual(inner[IP].dst, ep2.ip4)

        rxs = self.send_and_expect(self.pg1, p4[1] * 17, self.pg7)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 116)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # redirect policy has been applied
            self.assertTrue(rx[VXLAN].gpflags.A)
            self.assertFalse(rx[VXLAN].gpflags.D)

            inner = rx[VXLAN].payload

            self.assertEqual(inner[Ether].src, routed_src_mac)
            self.assertEqual(inner[Ether].dst, sep1.mac)
            self.assertEqual(inner[IP].src, ep2.ip4)
            self.assertEqual(inner[IP].dst, ep1.ip4)

        rxs = self.send_and_expect(self.pg0, p6[0] * 17, self.pg7)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 116)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # redirect policy has been applied
            inner = rx[VXLAN].payload

            self.assertEqual(inner[Ether].src, routed_src_mac)
            self.assertEqual(inner[Ether].dst, sep1.mac)
            self.assertEqual(inner[IPv6].src, ep1.ip6)
            self.assertEqual(inner[IPv6].dst, ep2.ip6)

        rxs = self.send_and_expect(self.pg1, p6[1] * 17, self.pg7)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 116)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # redirect policy has been applied
            self.assertTrue(rx[VXLAN].gpflags.A)
            self.assertFalse(rx[VXLAN].gpflags.D)

            inner = rx[VXLAN].payload

            self.assertEqual(inner[Ether].src, routed_src_mac)
            self.assertEqual(inner[Ether].dst, sep1.mac)
            self.assertEqual(inner[IPv6].src, ep2.ip6)
            self.assertEqual(inner[IPv6].dst, ep1.ip6)

        # configure sep1: it is now local
        # packets between ep1 and ep2 are redirected locally
        sep1.add_vpp_config()

        rxs = self.send_and_expect(self.pg0, p4[0] * 17, sep1.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep1.mac)
            self.assertEqual(rx[IP].src, ep1.ip4)
            self.assertEqual(rx[IP].dst, ep2.ip4)

        rxs = self.send_and_expect(self.pg1, p6[1] * 17, sep1.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, routed_src_mac)
            self.assertEqual(rx[Ether].dst, sep1.mac)
            self.assertEqual(rx[IPv6].src, ep2.ip6)
            self.assertEqual(rx[IPv6].dst, ep1.ip6)

        # packet coming from the l2 spine-proxy to sep1
        p = (Ether(src=self.pg7.remote_mac,
                   dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4,
                dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=116, gpid=440, gpflags=0x08, flags=0x88) /
             Ether(src=str(self.router_mac), dst=sep1.mac) /
             IP(src=ep1.ip4, dst=ep2.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg7, [p] * 17, sep1.itf)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, str(self.router_mac))
            self.assertEqual(rx[Ether].dst, sep1.mac)
            self.assertEqual(rx[IP].src, ep1.ip4)
            self.assertEqual(rx[IP].dst, ep2.ip4)

        # contract for SEP to communicate with dst EP
        c3 = VppGbpContract(
            self, 402, epg_320.sclass, epg_221.sclass, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SYMMETRIC),
             VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SYMMETRIC)],
            [ETH_P_IP, ETH_P_IPV6])
        c3.add_vpp_config()

        # temporarily remove ep2, so that ep2 is remote & unknown
        ep2.remove_vpp_config()

        # packet going back from sep1 to its original dest (ep2)
        # as ep2 is now unknown (see above), it must go through
        # the rd UU (packet is routed)

        p1 = (Ether(src=sep1.mac, dst=self.router_mac) /
              IP(src=ep1.ip4, dst=ep2.ip4) /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg3, [p1] * 17, self.pg7)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 114)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # redirect policy has been applied
            inner = rx[VXLAN].payload
            self.assertEqual(inner[Ether].src, routed_src_mac)
            self.assertEqual(inner[Ether].dst, routed_dst_mac)
            self.assertEqual(inner[IP].src, ep1.ip4)
            self.assertEqual(inner[IP].dst, ep2.ip4)

        self.logger.info(self.vapi.cli("show bridge 3 detail"))
        sep1.remove_vpp_config()

        self.logger.info(self.vapi.cli("show bridge 1 detail"))
        self.logger.info(self.vapi.cli("show bridge 2 detail"))

        # re-add ep2: it is local again :)
        ep2.add_vpp_config()

        # packet coming back from the remote sep through rd UU
        p2 = (Ether(src=self.pg7.remote_mac,
                    dst=self.pg7.local_mac) /
              IP(src=self.pg7.remote_ip4,
                 dst=self.pg7.local_ip4) /
              UDP(sport=1234, dport=48879) /
              VXLAN(vni=114, gpid=441, gpflags=0x09, flags=0x88) /
              Ether(src=str(self.router_mac), dst=self.router_mac) /
              IP(src=ep1.ip4, dst=ep2.ip4) /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg7, [p2], self.pg1)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, str(self.router_mac))
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, ep1.ip4)
            self.assertEqual(rx[IP].dst, ep2.ip4)

        #
        # bd_uu2.add_vpp_config()
        #

        #
        # cleanup
        #
        c1.remove_vpp_config()
        c2.remove_vpp_config()
        c3.remove_vpp_config()
        self.pg7.unconfig_ip4()

    def test_gbp_l3_out(self):
        """ GBP L3 Out """

        ep_flags = VppEnum.vl_api_gbp_endpoint_flags_t
        self.vapi.cli("set logging class gbp level debug")

        routed_dst_mac = "00:0c:0c:0c:0c:0c"
        routed_src_mac = "00:22:bd:f8:19:ff"

        #
        # IP tables
        #
        t4 = VppIpTable(self, 1)
        t4.add_vpp_config()
        t6 = VppIpTable(self, 1, True)
        t6.add_vpp_config()

        rd1 = VppGbpRouteDomain(self, 2, 55, t4, t6)
        rd1.add_vpp_config()

        self.loop0.set_mac(self.router_mac)

        #
        # Bind the BVI to the RD
        #
        b_ip4 = VppIpInterfaceBind(self, self.loop0, t4).add_vpp_config()
        b_ip6 = VppIpInterfaceBind(self, self.loop0, t6).add_vpp_config()

        #
        # Pg7 hosts a BD's BUM
        # Pg1 some other l3 interface
        #
        self.pg7.config_ip4()
        self.pg7.resolve_arp()

        #
        # a multicast vxlan-gbp tunnel for broadcast in the BD
        #
        tun_bm = VppVxlanGbpTunnel(self, self.pg7.local_ip4,
                                   "239.1.1.1", 88,
                                   mcast_itf=self.pg7)
        tun_bm.add_vpp_config()

        #
        # a GBP external bridge domains for the EPs
        #
        bd1 = VppBridgeDomain(self, 1)
        bd1.add_vpp_config()
        gbd1 = VppGbpBridgeDomain(self, bd1, rd1, self.loop0, None, tun_bm)
        gbd1.add_vpp_config()

        #
        # The Endpoint-groups in which the external endpoints exist
        #
        epg_220 = VppGbpEndpointGroup(self, 220, 113, rd1, gbd1,
                                      None, gbd1.bvi,
                                      "10.0.0.128",
                                      "2001:10::128",
                                      VppGbpEndpointRetention(4))
        epg_220.add_vpp_config()

        # the BVIs have the subnets applied ...
        ip4_addr = VppIpInterfaceAddress(self, gbd1.bvi, "10.0.0.128",
                                         24, bind=b_ip4).add_vpp_config()
        ip6_addr = VppIpInterfaceAddress(self, gbd1.bvi, "2001:10::128",
                                         64, bind=b_ip6).add_vpp_config()

        # ... which are L3-out subnets
        l3o_1 = VppGbpSubnet(
            self, rd1, "10.0.0.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
            sclass=113)
        l3o_1.add_vpp_config()

        #
        # an external interface attached to the outside world and the
        # external BD
        #
        VppL2Vtr(self, self.vlan_100, L2_VTR_OP.L2_POP_1).add_vpp_config()
        VppL2Vtr(self, self.vlan_101, L2_VTR_OP.L2_POP_1).add_vpp_config()
        vlan_144 = VppDot1QSubint(self, self.pg0, 144)
        vlan_144.admin_up()
        # vlan_102 is not poped

        #
        # an unicast vxlan-gbp for inter-RD traffic
        #
        vx_tun_l3 = VppGbpVxlanTunnel(
            self, 444, rd1.rd_id,
            VppEnum.vl_api_gbp_vxlan_tunnel_mode_t.GBP_VXLAN_TUNNEL_MODE_L3,
            self.pg2.local_ip4)
        vx_tun_l3.add_vpp_config()

        #
        # External Endpoints
        #
        eep1 = VppGbpEndpoint(self, self.vlan_100,
                              epg_220, None,
                              "10.0.0.1", "11.0.0.1",
                              "2001:10::1", "3001::1",
                              ep_flags.GBP_API_ENDPOINT_FLAG_EXTERNAL)
        eep1.add_vpp_config()
        eep2 = VppGbpEndpoint(self, self.vlan_101,
                              epg_220, None,
                              "10.0.0.2", "11.0.0.2",
                              "2001:10::2", "3001::2",
                              ep_flags.GBP_API_ENDPOINT_FLAG_EXTERNAL)
        eep2.add_vpp_config()
        eep3 = VppGbpEndpoint(self, self.vlan_102,
                              epg_220, None,
                              "10.0.0.3", "11.0.0.3",
                              "2001:10::3", "3001::3",
                              ep_flags.GBP_API_ENDPOINT_FLAG_EXTERNAL)
        eep3.add_vpp_config()

        #
        # A remote external endpoint
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
        # EP1 impersonating EP3 is dropped
        #
        p = (Ether(src=eep1.mac, dst="ff:ff:ff:ff:ff:ff") /
             Dot1Q(vlan=100) /
             ARP(op="who-has",
                 psrc="10.0.0.3", pdst="10.0.0.128",
                 hwsrc=eep1.mac, hwdst="ff:ff:ff:ff:ff:ff"))
        self.send_and_assert_no_replies(self.pg0, p)

        #
        # ARP packet from External EPs are accepted and replied to
        #
        p_arp = (Ether(src=eep1.mac, dst="ff:ff:ff:ff:ff:ff") /
                 Dot1Q(vlan=100) /
                 ARP(op="who-has",
                     psrc=eep1.ip4, pdst="10.0.0.128",
                     hwsrc=eep1.mac, hwdst="ff:ff:ff:ff:ff:ff"))
        rxs = self.send_and_expect(self.pg0, p_arp * 1, self.pg0)

        #
        # ARP packet from host in remote subnet are accepted and replied to
        #
        p_arp = (Ether(src=eep3.mac, dst="ff:ff:ff:ff:ff:ff") /
                 Dot1Q(vlan=102) /
                 ARP(op="who-has",
                     psrc=eep3.ip4, pdst="10.0.0.128",
                     hwsrc=eep3.mac, hwdst="ff:ff:ff:ff:ff:ff"))
        rxs = self.send_and_expect(self.pg0, p_arp * 1, self.pg0)

        #
        # packets destined to unknown addresses in the BVI's subnet
        # are ARP'd for
        #
        p4 = (Ether(src=eep1.mac, dst=str(self.router_mac)) /
              Dot1Q(vlan=100) /
              IP(src="10.0.0.1", dst="10.0.0.88") /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100))
        p6 = (Ether(src=eep1.mac, dst=str(self.router_mac)) /
              Dot1Q(vlan=100) /
              IPv6(src="2001:10::1", dst="2001:10::88") /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100))

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
            self.assertEqual(rx[VXLAN].gpid, 113)
            self.assertTrue(rx[VXLAN].gpflags.A)
            self.assertFalse(rx[VXLAN].gpflags.D)

            inner = rx[VXLAN].payload

            self.assertTrue(inner.haslayer(ARP))

        #
        # remote to external
        #
        p = (Ether(src=self.pg7.remote_mac,
                   dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4,
                dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=444, gpid=113, flags=0x88) /
             Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
             IP(src="10.0.0.101", dst="10.0.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg7, p * 1, self.pg0)

        #
        # local EP pings router
        #
        p = (Ether(src=eep1.mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=100) /
             IP(src=eep1.ip4, dst="10.0.0.128") /
             ICMP(type='echo-request'))

        rxs = self.send_and_expect(self.pg0, p * 1, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, str(self.router_mac))
            self.assertEqual(rx[Ether].dst, eep1.mac)
            self.assertEqual(rx[Dot1Q].vlan, 100)

        #
        # local EP pings other local EP
        #
        p = (Ether(src=eep1.mac, dst=eep2.mac) /
             Dot1Q(vlan=100) /
             IP(src=eep1.ip4, dst=eep2.ip4) /
             ICMP(type='echo-request'))

        rxs = self.send_and_expect(self.pg0, p * 1, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, eep1.mac)
            self.assertEqual(rx[Ether].dst, eep2.mac)
            self.assertEqual(rx[Dot1Q].vlan, 101)

        #
        # local EP pings router w/o vlan tag poped
        #
        p = (Ether(src=eep3.mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=102) /
             IP(src=eep3.ip4, dst="10.0.0.128") /
             ICMP(type='echo-request'))

        rxs = self.send_and_expect(self.pg0, p * 1, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, str(self.router_mac))
            self.assertEqual(rx[Ether].dst, self.vlan_102.remote_mac)

        #
        # A ip4 subnet reachable through the external EP1
        #
        ip_220 = VppIpRoute(self, "10.220.0.0", 24,
                            [VppRoutePath(eep1.ip4,
                                          eep1.epg.bvi.sw_if_index)],
                            table_id=t4.table_id)
        ip_220.add_vpp_config()

        l3o_220 = VppGbpSubnet(
            self, rd1, "10.220.0.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
            sclass=4220)
        l3o_220.add_vpp_config()

        #
        # An ip6 subnet reachable through the external EP1
        #
        ip6_220 = VppIpRoute(self, "10:220::", 64,
                             [VppRoutePath(eep1.ip6,
                                           eep1.epg.bvi.sw_if_index)],
                             table_id=t6.table_id)
        ip6_220.add_vpp_config()

        l3o6_220 = VppGbpSubnet(
            self, rd1, "10:220::", 64,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
            sclass=4220)
        l3o6_220.add_vpp_config()

        #
        # A subnet reachable through the external EP2
        #
        ip_221 = VppIpRoute(self, "10.221.0.0", 24,
                            [VppRoutePath(eep2.ip4,
                                          eep2.epg.bvi.sw_if_index)],
                            table_id=t4.table_id)
        ip_221.add_vpp_config()

        l3o_221 = VppGbpSubnet(
            self, rd1, "10.221.0.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
            sclass=4221)
        l3o_221.add_vpp_config()

        #
        # ping between hosts in remote subnets
        #  dropped without a contract
        #
        p = (Ether(src=eep1.mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=100) /
             IP(src="10.220.0.1", dst="10.221.0.1") /
             ICMP(type='echo-request'))

        self.send_and_assert_no_replies(self.pg0, p * 1)

        #
        # contract for the external nets to communicate
        #
        rule4 = AclRule(is_permit=1, proto=17)
        rule6 = AclRule(src_prefix=IPv6Network((0, 0)),
                        dst_prefix=IPv6Network((0, 0)), is_permit=1, proto=17)
        acl = VppAcl(self, rules=[rule4, rule6])
        acl.add_vpp_config()

        #
        # A contract with the wrong scope is not matched
        #
        c_44 = VppGbpContract(
            self, 44, 4220, 4221, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
             VppGbpContractRule(
                 VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                 VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                 [])],
            [ETH_P_IP, ETH_P_IPV6])
        c_44.add_vpp_config()
        self.send_and_assert_no_replies(self.pg0, p * 1)

        c1 = VppGbpContract(
            self, 55, 4220, 4221, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                    [])],
            [ETH_P_IP, ETH_P_IPV6])
        c1.add_vpp_config()

        #
        # Contracts allowing ext-net 200 to talk with external EPs
        #
        c2 = VppGbpContract(
            self, 55, 4220, 113, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                    [])],
            [ETH_P_IP, ETH_P_IPV6])
        c2.add_vpp_config()
        c3 = VppGbpContract(
            self, 55, 113, 4220, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                    [])],
            [ETH_P_IP, ETH_P_IPV6])
        c3.add_vpp_config()

        #
        # ping between hosts in remote subnets
        #
        p = (Ether(src=eep1.mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=100) /
             IP(src="10.220.0.1", dst="10.221.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg0, p * 1, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, str(self.router_mac))
            self.assertEqual(rx[Ether].dst, eep2.mac)
            self.assertEqual(rx[Dot1Q].vlan, 101)

        # we did not learn these external hosts
        self.assertFalse(find_gbp_endpoint(self, ip="10.220.0.1"))
        self.assertFalse(find_gbp_endpoint(self, ip="10.221.0.1"))

        #
        # from remote external EP to local external EP
        #
        p = (Ether(src=self.pg7.remote_mac,
                   dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4,
                dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=444, gpid=113, flags=0x88) /
             Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
             IP(src="10.0.0.101", dst="10.220.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg7, p * 1, self.pg0)

        #
        # ping from an external host to the remote external EP
        #
        p = (Ether(src=eep1.mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=100) /
             IP(src="10.220.0.1", dst=rep.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg0, p * 1, self.pg7)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            # self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 444)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # the sclass of the ext-net the packet came from
            self.assertEqual(rx[VXLAN].gpid, 4220)
            # policy was applied to the original IP packet
            self.assertTrue(rx[VXLAN].gpflags.A)
            # since it's an external host the reciever should not learn it
            self.assertTrue(rx[VXLAN].gpflags.D)
            inner = rx[VXLAN].payload
            self.assertEqual(inner[IP].src, "10.220.0.1")
            self.assertEqual(inner[IP].dst, rep.ip4)

        #
        # An external subnet reachable via the remote external EP
        #

        #
        # first the VXLAN-GBP tunnel over which it is reached
        #
        vx_tun_r1 = VppVxlanGbpTunnel(
            self, self.pg7.local_ip4,
            self.pg7.remote_ip4, 445,
            mode=(VppEnum.vl_api_vxlan_gbp_api_tunnel_mode_t.
                  VXLAN_GBP_API_TUNNEL_MODE_L3))
        vx_tun_r1.add_vpp_config()
        VppIpInterfaceBind(self, vx_tun_r1, t4).add_vpp_config()

        self.logger.info(self.vapi.cli("sh vxlan-gbp tunnel"))

        #
        # then the special adj to resolve through on that tunnel
        #
        n1 = VppNeighbor(self,
                         vx_tun_r1.sw_if_index,
                         "00:0c:0c:0c:0c:0c",
                         self.pg7.remote_ip4)
        n1.add_vpp_config()

        #
        # the route via the adj above
        #
        ip_222 = VppIpRoute(self, "10.222.0.0", 24,
                            [VppRoutePath(self.pg7.remote_ip4,
                                          vx_tun_r1.sw_if_index)],
                            table_id=t4.table_id)
        ip_222.add_vpp_config()

        l3o_222 = VppGbpSubnet(
            self, rd1, "10.222.0.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
            sclass=4222)
        l3o_222.add_vpp_config()

        #
        # ping between hosts in local and remote external subnets
        #  dropped without a contract
        #
        p = (Ether(src=eep1.mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=100) /
             IP(src="10.220.0.1", dst="10.222.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_assert_no_replies(self.pg0, p * 1)

        #
        # Add contracts ext-nets for 220 -> 222
        #
        c4 = VppGbpContract(
            self, 55, 4220, 4222, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                    [])],
            [ETH_P_IP, ETH_P_IPV6])
        c4.add_vpp_config()

        #
        # ping from host in local to remote external subnets
        #
        p = (Ether(src=eep1.mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=100) /
             IP(src="10.220.0.1", dst="10.222.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg0, p * 3, self.pg7)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 445)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # the sclass of the ext-net the packet came from
            self.assertEqual(rx[VXLAN].gpid, 4220)
            # policy was applied to the original IP packet
            self.assertTrue(rx[VXLAN].gpflags.A)
            # since it's an external host the reciever should not learn it
            self.assertTrue(rx[VXLAN].gpflags.D)
            inner = rx[VXLAN].payload
            self.assertEqual(inner[Ether].dst, "00:0c:0c:0c:0c:0c")
            self.assertEqual(inner[IP].src, "10.220.0.1")
            self.assertEqual(inner[IP].dst, "10.222.0.1")

        #
        # make the external subnet ECMP
        #
        vx_tun_r2 = VppVxlanGbpTunnel(
            self, self.pg7.local_ip4,
            self.pg7.remote_ip4, 446,
            mode=(VppEnum.vl_api_vxlan_gbp_api_tunnel_mode_t.
                  VXLAN_GBP_API_TUNNEL_MODE_L3))
        vx_tun_r2.add_vpp_config()
        VppIpInterfaceBind(self, vx_tun_r2, t4).add_vpp_config()

        self.logger.info(self.vapi.cli("sh vxlan-gbp tunnel"))

        n2 = VppNeighbor(self,
                         vx_tun_r2.sw_if_index,
                         "00:0c:0c:0c:0c:0c",
                         self.pg7.remote_ip4)
        n2.add_vpp_config()

        ip_222.modify([VppRoutePath(self.pg7.remote_ip4,
                                    vx_tun_r1.sw_if_index),
                       VppRoutePath(self.pg7.remote_ip4,
                                    vx_tun_r2.sw_if_index)])

        #
        # now expect load-balance
        #
        p = [(Ether(src=eep1.mac, dst=str(self.router_mac)) /
              Dot1Q(vlan=100) /
              IP(src="10.220.0.1", dst="10.222.0.1") /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100)),
             (Ether(src=eep1.mac, dst=str(self.router_mac)) /
              Dot1Q(vlan=100) /
              IP(src="10.220.0.1", dst="10.222.0.1") /
              UDP(sport=1222, dport=1235) /
              Raw(b'\xa5' * 100))]

        rxs = self.send_and_expect(self.pg0, p, self.pg7)

        self.assertEqual(rxs[0][VXLAN].vni, 445)
        self.assertEqual(rxs[1][VXLAN].vni, 446)

        #
        # Same LB test for v6
        #
        n3 = VppNeighbor(self,
                         vx_tun_r1.sw_if_index,
                         "00:0c:0c:0c:0c:0c",
                         self.pg7.remote_ip6)
        n3.add_vpp_config()
        n4 = VppNeighbor(self,
                         vx_tun_r2.sw_if_index,
                         "00:0c:0c:0c:0c:0c",
                         self.pg7.remote_ip6)
        n4.add_vpp_config()

        ip_222_6 = VppIpRoute(self, "10:222::", 64,
                              [VppRoutePath(self.pg7.remote_ip6,
                                            vx_tun_r1.sw_if_index),
                               VppRoutePath(self.pg7.remote_ip6,
                                            vx_tun_r2.sw_if_index)],
                              table_id=t6.table_id)
        ip_222_6.add_vpp_config()

        l3o_222_6 = VppGbpSubnet(
            self, rd1, "10:222::", 64,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
            sclass=4222)
        l3o_222_6.add_vpp_config()

        p = [(Ether(src=eep1.mac, dst=str(self.router_mac)) /
              Dot1Q(vlan=100) /
              IPv6(src="10:220::1", dst="10:222::1") /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100)),
             (Ether(src=eep1.mac, dst=str(self.router_mac)) /
              Dot1Q(vlan=100) /
              IPv6(src="10:220::1", dst="10:222::1") /
              UDP(sport=7777, dport=8881) /
              Raw(b'\xa5' * 100))]

        self.logger.info(self.vapi.cli("sh ip6 fib 10:222::1"))
        rxs = self.send_and_expect(self.pg0, p, self.pg7)

        self.assertEqual(rxs[0][VXLAN].vni, 445)
        self.assertEqual(rxs[1][VXLAN].vni, 446)

        #
        # ping from host in remote to local external subnets
        # there's no contract for this, but the A bit is set.
        #
        p = (Ether(src=self.pg7.remote_mac, dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4, dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=445, gpid=4222, flags=0x88, gpflags='A') /
             Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
             IP(src="10.222.0.1", dst="10.220.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg7, p * 3, self.pg0)
        self.assertFalse(find_gbp_endpoint(self, ip="10.222.0.1"))

        #
        # ping from host in remote to remote external subnets
        #   this is dropped by reflection check.
        #
        p = (Ether(src=self.pg7.remote_mac, dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4, dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=445, gpid=4222, flags=0x88, gpflags='A') /
             Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
             IP(src="10.222.0.1", dst="10.222.0.2") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_assert_no_replies(self.pg7, p * 3)

        p = (Ether(src=self.pg7.remote_mac, dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4, dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=445, gpid=4222, flags=0x88, gpflags='A') /
             Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
             IPv6(src="10:222::1", dst="10:222::2") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_assert_no_replies(self.pg7, p * 3)

        #
        # local EP
        #
        lep1 = VppGbpEndpoint(self, vlan_144,
                              epg_220, None,
                              "10.0.0.44", "11.0.0.44",
                              "2001:10::44", "3001::44")
        lep1.add_vpp_config()

        #
        # local EP to local ip4 external subnet
        #
        p = (Ether(src=lep1.mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=144) /
             IP(src=lep1.ip4, dst="10.220.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg0, p * 1, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, str(self.router_mac))
            self.assertEqual(rx[Ether].dst, eep1.mac)
            self.assertEqual(rx[Dot1Q].vlan, 100)

        #
        # local EP to local ip6 external subnet
        #
        p = (Ether(src=lep1.mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=144) /
             IPv6(src=lep1.ip6, dst="10:220::1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg0, p * 1, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, str(self.router_mac))
            self.assertEqual(rx[Ether].dst, eep1.mac)
            self.assertEqual(rx[Dot1Q].vlan, 100)

        #
        # ip4 and ip6 subnets that load-balance
        #
        ip_20 = VppIpRoute(self, "10.20.0.0", 24,
                           [VppRoutePath(eep1.ip4,
                                         eep1.epg.bvi.sw_if_index),
                            VppRoutePath(eep2.ip4,
                                         eep2.epg.bvi.sw_if_index)],
                           table_id=t4.table_id)
        ip_20.add_vpp_config()

        l3o_20 = VppGbpSubnet(
            self, rd1, "10.20.0.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
            sclass=4220)
        l3o_20.add_vpp_config()

        ip6_20 = VppIpRoute(self, "10:20::", 64,
                            [VppRoutePath(eep1.ip6,
                                          eep1.epg.bvi.sw_if_index),
                             VppRoutePath(eep2.ip6,
                                          eep2.epg.bvi.sw_if_index)],
                            table_id=t6.table_id)
        ip6_20.add_vpp_config()

        l3o6_20 = VppGbpSubnet(
            self, rd1, "10:20::", 64,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
            sclass=4220)
        l3o6_20.add_vpp_config()

        self.logger.info(self.vapi.cli("sh ip fib 10.20.0.1"))
        self.logger.info(self.vapi.cli("sh ip6 fib 10:20::1"))

        # two ip6 packets whose port are chosen so they load-balance
        p = [(Ether(src=lep1.mac, dst=str(self.router_mac)) /
              Dot1Q(vlan=144) /
              IPv6(src=lep1.ip6, dst="10:20::1") /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100)),
             (Ether(src=lep1.mac, dst=str(self.router_mac)) /
              Dot1Q(vlan=144) /
              IPv6(src=lep1.ip6, dst="10:20::1") /
              UDP(sport=124, dport=1230) /
              Raw(b'\xa5' * 100))]

        rxs = self.send_and_expect(self.pg0, p, self.pg0, 2)

        self.assertEqual(rxs[0][Dot1Q].vlan, 101)
        self.assertEqual(rxs[1][Dot1Q].vlan, 100)

        # two ip4 packets whose port are chosen so they load-balance
        p = [(Ether(src=lep1.mac, dst=str(self.router_mac)) /
              Dot1Q(vlan=144) /
              IP(src=lep1.ip4, dst="10.20.0.1") /
              UDP(sport=1235, dport=1235) /
              Raw(b'\xa5' * 100)),
             (Ether(src=lep1.mac, dst=str(self.router_mac)) /
              Dot1Q(vlan=144) /
              IP(src=lep1.ip4, dst="10.20.0.1") /
              UDP(sport=124, dport=1230) /
              Raw(b'\xa5' * 100))]

        rxs = self.send_and_expect(self.pg0, p, self.pg0, 2)

        self.assertEqual(rxs[0][Dot1Q].vlan, 101)
        self.assertEqual(rxs[1][Dot1Q].vlan, 100)

        #
        # cleanup
        #
        ip_222.remove_vpp_config()
        self.pg7.unconfig_ip4()
        self.vlan_101.set_vtr(L2_VTR_OP.L2_DISABLED)
        self.vlan_100.set_vtr(L2_VTR_OP.L2_DISABLED)

    def test_gbp_anon_l3_out(self):
        """ GBP Anonymous L3 Out """

        ep_flags = VppEnum.vl_api_gbp_endpoint_flags_t
        self.vapi.cli("set logging class gbp level debug")

        routed_dst_mac = "00:0c:0c:0c:0c:0c"
        routed_src_mac = "00:22:bd:f8:19:ff"

        #
        # IP tables
        #
        t4 = VppIpTable(self, 1)
        t4.add_vpp_config()
        t6 = VppIpTable(self, 1, True)
        t6.add_vpp_config()

        rd1 = VppGbpRouteDomain(self, 2, 55, t4, t6)
        rd1.add_vpp_config()

        self.loop0.set_mac(self.router_mac)

        #
        # Bind the BVI to the RD
        #
        bind_l0_ip4 = VppIpInterfaceBind(self, self.loop0, t4).add_vpp_config()
        bind_l0_ip6 = VppIpInterfaceBind(self, self.loop0, t6).add_vpp_config()

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
        gbd1 = VppGbpBridgeDomain(self, bd1, rd1, self.loop0, None, None)
        gbd1.add_vpp_config()

        #
        # The Endpoint-groups in which the external endpoints exist
        #
        epg_220 = VppGbpEndpointGroup(self, 220, 113, rd1, gbd1,
                                      None, gbd1.bvi,
                                      "10.0.0.128",
                                      "2001:10::128",
                                      VppGbpEndpointRetention(4))
        epg_220.add_vpp_config()

        # the BVIs have the subnet applied ...
        ip4_addr = VppIpInterfaceAddress(self, gbd1.bvi,
                                         "10.0.0.128", 24,
                                         bind=bind_l0_ip4).add_vpp_config()

        # ... which is an Anonymous L3-out subnets
        l3o_1 = VppGbpSubnet(
            self, rd1, "10.0.0.0", 24,
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_ANON_L3_OUT,
            sclass=113)
        l3o_1.add_vpp_config()

        #
        # an external interface attached to the outside world and the
        # external BD
        #
        VppL2Vtr(self, self.vlan_100, L2_VTR_OP.L2_POP_1).add_vpp_config()
        VppL2Vtr(self, self.vlan_101, L2_VTR_OP.L2_POP_1).add_vpp_config()

        #
        # vlan_100 and vlan_101 are anonymous l3-out interfaces
        #
        ext_itf = VppGbpExtItf(self, self.vlan_100, bd1, rd1, anon=True)
        ext_itf.add_vpp_config()
        ext_itf = VppGbpExtItf(self, self.vlan_101, bd1, rd1, anon=True)
        ext_itf.add_vpp_config()

        #
        # an unicast vxlan-gbp for inter-RD traffic
        #
        vx_tun_l3 = VppGbpVxlanTunnel(
            self, 444, rd1.rd_id,
            VppEnum.vl_api_gbp_vxlan_tunnel_mode_t.GBP_VXLAN_TUNNEL_MODE_L3,
            self.pg2.local_ip4)
        vx_tun_l3.add_vpp_config()

        #
        # A remote external endpoint
        #
        rep = VppGbpEndpoint(self, vx_tun_l3,
                             epg_220, None,
                             "10.0.0.201", "11.0.0.201",
                             "2001:10::201", "3001::101",
                             ep_flags.GBP_API_ENDPOINT_FLAG_REMOTE,
                             self.pg7.local_ip4,
                             self.pg7.remote_ip4,
                             mac=None)
        rep.add_vpp_config()

        #
        # ARP packet from host in external subnet are accepted, flooded and
        # replied to. We expect 2 packets:
        #   - APR request flooded over the other vlan subif
        #   - ARP reply from BVI
        #
        p_arp = (Ether(src=self.vlan_100.remote_mac,
                       dst="ff:ff:ff:ff:ff:ff") /
                 Dot1Q(vlan=100) /
                 ARP(op="who-has",
                     psrc="10.0.0.100",
                     pdst="10.0.0.128",
                     hwsrc=self.vlan_100.remote_mac,
                     hwdst="ff:ff:ff:ff:ff:ff"))
        rxs = self.send_and_expect(self.pg0, p_arp * 1, self.pg0, n_rx=2)

        p_arp = (Ether(src=self.vlan_101.remote_mac,
                       dst="ff:ff:ff:ff:ff:ff") /
                 Dot1Q(vlan=101) /
                 ARP(op="who-has",
                     psrc='10.0.0.101',
                     pdst="10.0.0.128",
                     hwsrc=self.vlan_101.remote_mac,
                     hwdst="ff:ff:ff:ff:ff:ff"))
        rxs = self.send_and_expect(self.pg0, p_arp * 1, self.pg0, n_rx=2)

        #
        # remote to external
        #
        p = (Ether(src=self.pg7.remote_mac,
                   dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4,
                dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=vx_tun_l3.vni, gpid=epg_220.sclass, flags=0x88) /
             Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
             IP(src=str(rep.ip4), dst="10.0.0.100") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))
        rxs = self.send_and_expect(self.pg7, p * 1, self.pg0)

        #
        # local EP pings router
        #
        p = (Ether(src=self.vlan_100.remote_mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=100) /
             IP(src="10.0.0.100", dst="10.0.0.128") /
             ICMP(type='echo-request'))
        rxs = self.send_and_expect(self.pg0, p * 1, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, str(self.router_mac))
            self.assertEqual(rx[Ether].dst, self.vlan_100.remote_mac)
            self.assertEqual(rx[Dot1Q].vlan, 100)

        #
        # local EP pings other local EP
        #
        p = (Ether(src=self.vlan_100.remote_mac,
                   dst=self.vlan_101.remote_mac) /
             Dot1Q(vlan=100) /
             IP(src="10.0.0.100", dst="10.0.0.101") /
             ICMP(type='echo-request'))
        rxs = self.send_and_expect(self.pg0, p * 1, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.vlan_100.remote_mac)
            self.assertEqual(rx[Ether].dst, self.vlan_101.remote_mac)
            self.assertEqual(rx[Dot1Q].vlan, 101)

        #
        # A subnet reachable through an external router on vlan 100
        #
        ip_220 = VppIpRoute(self, "10.220.0.0", 24,
                            [VppRoutePath("10.0.0.100",
                                          epg_220.bvi.sw_if_index)],
                            table_id=t4.table_id)
        ip_220.add_vpp_config()

        l3o_220 = VppGbpSubnet(
            self, rd1, "10.220.0.0", 24,
            # note: this a "regular" L3 out subnet (not connected)
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
            sclass=4220)
        l3o_220.add_vpp_config()

        #
        # A subnet reachable through an external router on vlan 101
        #
        ip_221 = VppIpRoute(self, "10.221.0.0", 24,
                            [VppRoutePath("10.0.0.101",
                                          epg_220.bvi.sw_if_index)],
                            table_id=t4.table_id)
        ip_221.add_vpp_config()

        l3o_221 = VppGbpSubnet(
            self, rd1, "10.221.0.0", 24,
            # note: this a "regular" L3 out subnet (not connected)
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
            sclass=4221)
        l3o_221.add_vpp_config()

        #
        # ping between hosts in remote subnets
        #  dropped without a contract
        #
        p = (Ether(src=self.vlan_100.remote_mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=100) /
             IP(src="10.220.0.1", dst="10.221.0.1") /
             ICMP(type='echo-request'))

        rxs = self.send_and_assert_no_replies(self.pg0, p * 1)

        #
        # contract for the external nets to communicate
        #
        rule4 = AclRule(is_permit=1, proto=17)
        rule6 = AclRule(src_prefix=IPv6Network((0, 0)),
                        dst_prefix=IPv6Network((0, 0)), is_permit=1, proto=17)
        acl = VppAcl(self, rules=[rule4, rule6])
        acl.add_vpp_config()

        c1 = VppGbpContract(
            self, 55, 4220, 4221, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                    [])],
            [ETH_P_IP, ETH_P_IPV6])
        c1.add_vpp_config()

        #
        # Contracts allowing ext-net 200 to talk with external EPs
        #
        c2 = VppGbpContract(
            self, 55, 4220, 113, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                    [])],
            [ETH_P_IP, ETH_P_IPV6])
        c2.add_vpp_config()
        c3 = VppGbpContract(
            self, 55, 113, 4220, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                    [])],
            [ETH_P_IP, ETH_P_IPV6])
        c3.add_vpp_config()

        #
        # ping between hosts in remote subnets
        #
        p = (Ether(src=self.vlan_100.remote_mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=100) /
             IP(src="10.220.0.1", dst="10.221.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg0, p * 1, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, str(self.router_mac))
            self.assertEqual(rx[Ether].dst, self.vlan_101.remote_mac)
            self.assertEqual(rx[Dot1Q].vlan, 101)

        # we did not learn these external hosts
        self.assertFalse(find_gbp_endpoint(self, ip="10.220.0.1"))
        self.assertFalse(find_gbp_endpoint(self, ip="10.221.0.1"))

        #
        # from remote external EP to local external EP
        #
        p = (Ether(src=self.pg7.remote_mac,
                   dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4,
                dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=444, gpid=113, flags=0x88) /
             Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
             IP(src=rep.ip4, dst="10.220.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg7, p * 1, self.pg0)

        #
        # ping from an external host to the remote external EP
        #
        p = (Ether(src=self.vlan_100.remote_mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=100) /
             IP(src="10.220.0.1", dst=rep.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg0, p * 1, self.pg7)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            # self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 444)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # the sclass of the ext-net the packet came from
            self.assertEqual(rx[VXLAN].gpid, 4220)
            # policy was applied to the original IP packet
            self.assertTrue(rx[VXLAN].gpflags.A)
            # since it's an external host the reciever should not learn it
            self.assertTrue(rx[VXLAN].gpflags.D)
            inner = rx[VXLAN].payload
            self.assertEqual(inner[IP].src, "10.220.0.1")
            self.assertEqual(inner[IP].dst, rep.ip4)

        #
        # An external subnet reachable via the remote external EP
        #

        #
        # first the VXLAN-GBP tunnel over which it is reached
        #
        vx_tun_r = VppVxlanGbpTunnel(
            self, self.pg7.local_ip4,
            self.pg7.remote_ip4, 445,
            mode=(VppEnum.vl_api_vxlan_gbp_api_tunnel_mode_t.
                  VXLAN_GBP_API_TUNNEL_MODE_L3))
        vx_tun_r.add_vpp_config()
        VppIpInterfaceBind(self, vx_tun_r, t4).add_vpp_config()

        self.logger.info(self.vapi.cli("sh vxlan-gbp tunnel"))

        #
        # then the special adj to resolve through on that tunnel
        #
        n1 = VppNeighbor(self,
                         vx_tun_r.sw_if_index,
                         "00:0c:0c:0c:0c:0c",
                         self.pg7.remote_ip4)
        n1.add_vpp_config()

        #
        # the route via the adj above
        #
        ip_222 = VppIpRoute(self, "10.222.0.0", 24,
                            [VppRoutePath(self.pg7.remote_ip4,
                                          vx_tun_r.sw_if_index)],
                            table_id=t4.table_id)
        ip_222.add_vpp_config()

        l3o_222 = VppGbpSubnet(
            self, rd1, "10.222.0.0", 24,
            # note: this a "regular" l3out subnet (not connected)
            VppEnum.vl_api_gbp_subnet_type_t.GBP_API_SUBNET_L3_OUT,
            sclass=4222)
        l3o_222.add_vpp_config()

        #
        # ping between hosts in local and remote external subnets
        #  dropped without a contract
        #
        p = (Ether(src=self.vlan_100.remote_mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=100) /
             IP(src="10.220.0.1", dst="10.222.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_assert_no_replies(self.pg0, p * 1)

        #
        # Add contracts ext-nets for 220 -> 222
        #
        c4 = VppGbpContract(
            self, 55, 4220, 4222, acl.acl_index,
            [VppGbpContractRule(
                VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                []),
                VppGbpContractRule(
                    VppEnum.vl_api_gbp_rule_action_t.GBP_API_RULE_PERMIT,
                    VppEnum.vl_api_gbp_hash_mode_t.GBP_API_HASH_MODE_SRC_IP,
                    [])],
            [ETH_P_IP, ETH_P_IPV6])
        c4.add_vpp_config()

        #
        # ping from host in local to remote external subnets
        #
        p = (Ether(src=self.vlan_100.remote_mac, dst=str(self.router_mac)) /
             Dot1Q(vlan=100) /
             IP(src="10.220.0.1", dst="10.222.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg0, p * 3, self.pg7)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg7.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg7.remote_mac)
            self.assertEqual(rx[IP].src, self.pg7.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg7.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 445)
            self.assertTrue(rx[VXLAN].flags.G)
            self.assertTrue(rx[VXLAN].flags.Instance)
            # the sclass of the ext-net the packet came from
            self.assertEqual(rx[VXLAN].gpid, 4220)
            # policy was applied to the original IP packet
            self.assertTrue(rx[VXLAN].gpflags.A)
            # since it's an external host the reciever should not learn it
            self.assertTrue(rx[VXLAN].gpflags.D)
            inner = rx[VXLAN].payload
            self.assertEqual(inner[Ether].dst, "00:0c:0c:0c:0c:0c")
            self.assertEqual(inner[IP].src, "10.220.0.1")
            self.assertEqual(inner[IP].dst, "10.222.0.1")

        #
        # ping from host in remote to local external subnets
        # there's no contract for this, but the A bit is set.
        #
        p = (Ether(src=self.pg7.remote_mac, dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4, dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=445, gpid=4222, flags=0x88, gpflags='A') /
             Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
             IP(src="10.222.0.1", dst="10.220.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_expect(self.pg7, p * 3, self.pg0)
        self.assertFalse(find_gbp_endpoint(self, ip="10.222.0.1"))

        #
        # ping from host in remote to remote external subnets
        #   this is dropped by reflection check.
        #
        p = (Ether(src=self.pg7.remote_mac, dst=self.pg7.local_mac) /
             IP(src=self.pg7.remote_ip4, dst=self.pg7.local_ip4) /
             UDP(sport=1234, dport=48879) /
             VXLAN(vni=445, gpid=4222, flags=0x88, gpflags='A') /
             Ether(src=self.pg0.remote_mac, dst=str(self.router_mac)) /
             IP(src="10.222.0.1", dst="10.222.0.2") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        rxs = self.send_and_assert_no_replies(self.pg7, p * 3)

        #
        # cleanup
        #
        self.vlan_101.set_vtr(L2_VTR_OP.L2_DISABLED)
        self.vlan_100.set_vtr(L2_VTR_OP.L2_DISABLED)
        self.pg7.unconfig_ip4()
        # make sure the programmed EP is no longer learnt from DP
        self.wait_for_ep_timeout(sw_if_index=rep.itf.sw_if_index, ip=rep.ip4)


if __name__ == '__main__':
    unittest.main(testRunner=VppTest