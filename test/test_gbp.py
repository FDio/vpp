#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_object import VppObject
from vpp_neighbor import VppNeighbor
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable

from vpp_ip import *
from vpp_mac import *
from vpp_papi_provider import L2_PORT_TYPE
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable, FibPathProto, \
    FibPathType

from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS,  ICMPv6NDOptSrcLLAddr, \
    ICMPv6ND_NA
from scapy.utils6 import in6_getnsma, in6_getnsmac

from socket import AF_INET, AF_INET6
from scapy.utils import inet_pton, inet_ntop
from util import mactobinary


def find_gbp_endpoint(test, sw_if_index, ip=None, mac=None):
    vip = VppIpAddress(ip)

    eps = test.vapi.gbp_endpoint_dump()
    for ep in eps:
        if ep.endpoint.sw_if_index != sw_if_index:
            continue
        for eip in ep.endpoint.ips:
            if vip == eip:
                return True
    return False


class VppGbpEndpoint(VppObject):
    """
    GBP Endpoint
    """

    @property
    def bin_mac(self):
        return mactobinary(self.itf.remote_mac)

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

    def __init__(self, test, itf, epg, recirc, ip4, fip4, ip6, fip6):
        self._test = test
        self.itf = itf
        self.epg = epg
        self.recirc = recirc

        self._ip4 = VppIpAddress(ip4)
        self._fip4 = VppIpAddress(fip4)
        self._ip6 = VppIpAddress(ip6)
        self._fip6 = VppIpAddress(fip6)
        self.vmac = VppMacAddress(self.itf.remote_mac)

    def add_vpp_config(self):
        res = self._test.vapi.gbp_endpoint_add(
            self.itf.sw_if_index,
            [self.ip4.encode(), self.ip6.encode()],
            self.vmac.encode(),
            self.epg.epg)
        self.handle = res.handle
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_endpoint_del(self.handle)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-endpoint;[%d:%s:%d]" % (self.itf.sw_if_index,
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
        return "gbp-recirc;[%d]" % (self.recirc.sw_if_index)

    def query_vpp_config(self):
        rs = self._test.vapi.gbp_recirc_dump()
        for r in rs:
            if r.recirc.sw_if_index == self.recirc.sw_if_index:
                return True
        return False


class VppGbpSubnet(VppObject):
    """
    GBP Subnet
    """

    def __init__(self, test, table_id, address, address_len,
                 is_internal=True,
                 sw_if_index=None, epg=None):
        self._test = test
        self.table_id = table_id
        self.prefix = VppIpPrefix(address, address_len)
        self.is_internal = is_internal
        self.sw_if_index = sw_if_index
        self.epg = epg

    def add_vpp_config(self):
        self._test.vapi.gbp_subnet_add_del(
            1,
            self.table_id,
            self.is_internal,
            self.prefix.encode(),
            sw_if_index=self.sw_if_index if self.sw_if_index else 0xffffffff,
            epg_id=self.epg if self.epg else 0xffff)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_subnet_add_del(
            0,
            self.table_id,
            self.is_internal,
            self.prefix.encode())

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-subnet;[%d-%s]" % (self.table_id,
                                       self.prefix)

    def query_vpp_config(self):
        ss = self._test.vapi.gbp_subnet_dump()
        for s in ss:
            if s.subnet.table_id == self.table_id and \
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
        self.bvi_ip4 = bvi_ip4
        self.bvi_ip4_n = inet_pton(AF_INET, bvi_ip4)
        self.bvi_ip6 = bvi_ip6
        self.bvi_ip6_n = inet_pton(AF_INET6, bvi_ip6)
        self.epg = epg
        self.bd = bd
        self.rd = rd

    def add_vpp_config(self):
        self._test.vapi.gbp_endpoint_group_add_del(
            1,
            self.epg,
            self.bd,
            self.rd,
            self.rd,
            self.uplink.sw_if_index)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_endpoint_group_add_del(
            0,
            self.epg,
            self.bd,
            self.rd,
            self.rd,
            self.uplink.sw_if_index)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-endpoint-group;[%d]" % (self.epg)

    def query_vpp_config(self):
        epgs = self._test.vapi.gbp_endpoint_group_dump()
        for epg in epgs:
            if epg.epg.epg_id == self.epg:
                return True
        return False


class VppGbpContract(VppObject):
    """
    GBP Contract
    """

    def __init__(self, test, src_epg, dst_epg, acl_index):
        self._test = test
        self.acl_index = acl_index
        self.src_epg = src_epg
        self.dst_epg = dst_epg

    def add_vpp_config(self):
        self._test.vapi.gbp_contract_add_del(
            1,
            self.src_epg,
            self.dst_epg,
            self.acl_index)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_contract_add_del(
            0,
            self.src_epg,
            self.dst_epg,
            self.acl_index)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-contract;[%d:%s:%d]" % (self.src_epg,
                                            self.dst_epg,
                                            self.acl_index)

    def query_vpp_config(self):
        cs = self._test.vapi.gbp_contract_dump()
        for c in cs:
            if c.contract.src_epg == self.src_epg \
               and c.contract.dst_epg == self.dst_epg:
                return True
        return False


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
        return "gbp-acl;[%d]" % (self.acl_index)

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
        self.create_loopback_interfaces(9)

        self.router_mac = "00:11:22:33:44:55"

        for i in self.pg_interfaces:
            i.admin_up()
        for i in self.lo_interfaces:
            i.admin_up()
            self.vapi.sw_interface_set_mac_address(
                i.sw_if_index,
                mactobinary(self.router_mac))

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
            self.assertEqual(r[Ether].src, self.router_mac)
            self.assertEqual(r[Ether].dst, dst.remote_mac)
            self.assertEqual(r[IP].dst, dst_ip)
            self.assertEqual(r[IP].src, src_ip)
        return rx

    def send_and_expect_double_natted6(self, src, tx, dst, src_ip, dst_ip):
        rx = self.send_and_expect(src, tx, dst)

        for r in rx:
            self.assertEqual(r[Ether].src, self.router_mac)
            self.assertEqual(r[Ether].dst, dst.remote_mac)
            self.assertEqual(r[IPv6].dst, dst_ip)
            self.assertEqual(r[IPv6].src, src_ip)
        return rx

    def test_gbp(self):
        """ Group Based Policy """

        nat_table = VppIpTable(self, 20)
        nat_table.add_vpp_config()
        nat_table = VppIpTable(self, 20, is_ip6=True)
        nat_table.add_vpp_config()

        #
        # Bridge Domains
        #
        self.vapi.bridge_domain_add_del(1, flood=1, uu_flood=1, forward=1,
                                        learn=0, arp_term=1, is_add=1)
        self.vapi.bridge_domain_add_del(2, flood=1, uu_flood=1, forward=1,
                                        learn=0, arp_term=1, is_add=1)
        self.vapi.bridge_domain_add_del(20, flood=1, uu_flood=1, forward=1,
                                        learn=0, arp_term=1, is_add=1)

        #
        # 3 EPGs, 2 of which share a BD.
        # 2 NAT EPGs, one for floating-IP subnets, the other for internet
        #
        epgs = [VppGbpEndpointGroup(self, 220, 0, 1, self.pg4,
                                    self.loop0,
                                    "10.0.0.128",
                                    "2001:10::128"),
                VppGbpEndpointGroup(self, 221, 0, 1, self.pg5,
                                    self.loop0,
                                    "10.0.1.128",
                                    "2001:10:1::128"),
                VppGbpEndpointGroup(self, 222, 0, 2, self.pg6,
                                    self.loop1,
                                    "10.0.2.128",
                                    "2001:10:2::128"),
                VppGbpEndpointGroup(self, 333, 20, 20, self.pg7,
                                    self.loop2,
                                    "11.0.0.128",
                                    "3001::128"),
                VppGbpEndpointGroup(self, 444, 20, 20, self.pg8,
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
                                self.loop8, is_ext=True)]

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
                epg.bvi.set_table_ip4(epg.rd)
                epg.bvi.set_table_ip6(epg.rd)

                # The BVIs are NAT inside interfaces
                self.vapi.nat44_interface_add_del_feature(epg.bvi.sw_if_index,
                                                          is_inside=1,
                                                          is_add=1)
                self.vapi.nat66_add_del_interface(epg.bvi.sw_if_index,
                                                  is_inside=1,
                                                  is_add=1)

            self.vapi.sw_interface_add_del_address(epg.bvi.sw_if_index,
                                                   epg.bvi_ip4_n,
                                                   32)
            self.vapi.sw_interface_add_del_address(epg.bvi.sw_if_index,
                                                   epg.bvi_ip6_n,
                                                   128,
                                                   is_ipv6=True)

            # EPG uplink interfaces in the BD
            epg.uplink.set_table_ip4(epg.rd)
            epg.uplink.set_table_ip6(epg.rd)
            self.vapi.sw_interface_set_l2_bridge(epg.uplink.sw_if_index,
                                                 epg.bd)

            # add the BD ARP termination entry for BVI IP
            self.vapi.bd_ip_mac_add_del(bd_id=epg.bd,
                                        mac=mactobinary(self.router_mac),
                                        ip=epg.bvi_ip4_n,
                                        is_ipv6=0,
                                        is_add=1)
            self.vapi.bd_ip_mac_add_del(bd_id=epg.bd,
                                        mac=mactobinary(self.router_mac),
                                        ip=epg.bvi_ip6_n,
                                        is_ipv6=1,
                                        is_add=1)

            # epg[1] shares the same BVI to epg[0]
            if epg != epgs[1] and epg != epgs[4]:
                # BVI in BD
                self.vapi.sw_interface_set_l2_bridge(
                    epg.bvi.sw_if_index,
                    epg.bd,
                    port_type=L2_PORT_TYPE.BVI)

                # BVI L2 FIB entry
                self.vapi.l2fib_add_del(self.router_mac,
                                        epg.bd,
                                        epg.bvi.sw_if_index,
                                        is_add=1, bvi_mac=1)

            # EPG in VPP
            epg.add_vpp_config()

        for recirc in recircs:
            # EPG's ingress recirculation interface maps to its RD
            recirc.recirc.set_table_ip4(recirc.epg.rd)
            recirc.recirc.set_table_ip6(recirc.epg.rd)

            # in the bridge to allow DVR. L2 emulation to punt to L3
            self.vapi.sw_interface_set_l2_bridge(recirc.recirc.sw_if_index,
                                                 recirc.epg.bd)
            self.vapi.sw_interface_set_l2_emulation(
                recirc.recirc.sw_if_index)

            self.vapi.nat44_interface_add_del_feature(
                recirc.recirc.sw_if_index,
                is_inside=0,
                is_add=1)
            self.vapi.nat66_add_del_interface(
                recirc.recirc.sw_if_index,
                is_inside=0,
                is_add=1)

            recirc.add_vpp_config()

        ep_routes = []
        ep_arps = []
        for ep in eps:
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            #
            # routes to the endpoints. We need these since there are no
            # adj-fibs due to the fact the the BVI address has /32 and
            # the subnet is not attached.
            #
            for (ip, fip) in zip(ep.ips, ep.fips):
                r = VppIpRoute(self, ip.address, ip.length,
                               [VppRoutePath(ip.address,
                                             ep.epg.bvi.sw_if_index,
                                             proto=ip.dpo_proto)])
                r.add_vpp_config()
                ep_routes.append(r)

                #
                # ARP entries for the endpoints
                #
                a = VppNeighbor(self,
                                ep.epg.bvi.sw_if_index,
                                ep.itf.remote_mac,
                                ip.address)
                a.add_vpp_config()
                ep_arps.append(a)

                # add the BD ARP termination entry
                self.vapi.bd_ip_mac_add_del(bd_id=ep.epg.bd,
                                            mac=ep.bin_mac,
                                            ip=ip.bytes,
                                            is_ipv6=ip.is_ip6,
                                            is_add=1)

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

            # add each EP itf to the its BD
            self.vapi.sw_interface_set_l2_bridge(ep.itf.sw_if_index,
                                                 ep.epg.bd)

            # L2 FIB entry
            self.vapi.l2fib_add_del(ep.mac,
                                    ep.epg.bd,
                                    ep.itf.sw_if_index,
                                    is_add=1)

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
                self.vapi.bd_ip_mac_add_del(bd_id=epg_nat.bd,
                                            mac=ep.bin_mac,
                                            ip=fip.bytes,
                                            is_ipv6=fip.is_ip6,
                                            is_add=1)

                # floating IPs route via EPG recirc
                r = VppIpRoute(
                    self, fip.address, fip.length,
                    [VppRoutePath(fip.address,
                                  ep.recirc.recirc.sw_if_index,
                                  type=FibPathType.FIB_PATH_TYPE_DVR,
                                  proto=fip.dpo_proto)],
                    table_id=20)
                r.add_vpp_config()
                ep_routes.append(r)

            # L2 FIB entries in the NAT EPG BD to bridge the packets from
            # the outside direct to the internal EPG
            self.vapi.l2fib_add_del(ep.mac,
                                    epg_nat.bd,
                                    ep.recirc.recirc.sw_if_index,
                                    is_add=1)

        #
        # ARP packets for unknown IP are flooded
        #
        pkt_arp = (Ether(dst="ff:ff:ff:ff:ff:ff",
                         src=self.pg0.remote_mac) /
                   ARP(op="who-has",
                       hwdst="ff:ff:ff:ff:ff:ff",
                       hwsrc=self.pg0.remote_mac,
                       pdst=epgs[0].bvi_ip4,
                       psrc="10.0.0.88"))

        self.send_and_expect(self.pg0, [pkt_arp], self.pg0)

        #
        # ARP/ND packets get a response
        #
        pkt_arp = (Ether(dst="ff:ff:ff:ff:ff:ff",
                         src=self.pg0.remote_mac) /
                   ARP(op="who-has",
                       hwdst="ff:ff:ff:ff:ff:ff",
                       hwsrc=self.pg0.remote_mac,
                       pdst=epgs[0].bvi_ip4,
                       psrc=eps[0].ip4.address))

        self.send_and_expect(self.pg0, [pkt_arp], self.pg0)

        nsma = in6_getnsma(inet_pton(AF_INET6, eps[0].ip6.address))
        d = inet_ntop(AF_INET6, nsma)
        pkt_nd = (Ether(dst=in6_getnsmac(nsma)) /
                  IPv6(dst=d, src=eps[0].ip6.address) /
                  ICMPv6ND_NS(tgt=epgs[0].bvi_ip6) /
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
                                       dst=self.router_mac) /
                                 IP(src=eps[0].ip4.address,
                                    dst="10.0.0.99") /
                                 UDP(sport=1234, dport=1234) /
                                 Raw('\xa5' * 100))
        pkt_inter_epg_222_ip4 = (Ether(src=self.pg0.remote_mac,
                                       dst=self.router_mac) /
                                 IP(src=eps[0].ip4.address,
                                    dst="10.0.1.99") /
                                 UDP(sport=1234, dport=1234) /
                                 Raw('\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0, pkt_intra_epg_220_ip4 * 65)

        pkt_inter_epg_222_ip6 = (Ether(src=self.pg0.remote_mac,
                                       dst=self.router_mac) /
                                 IPv6(src=eps[0].ip6.address,
                                      dst="2001:10::99") /
                                 UDP(sport=1234, dport=1234) /
                                 Raw('\xa5' * 100))
        self.send_and_assert_no_replies(self.pg0, pkt_inter_epg_222_ip6 * 65)

        #
        # Add the subnet routes
        #
        s41 = VppGbpSubnet(self, 0, "10.0.0.0", 24)
        s42 = VppGbpSubnet(self, 0, "10.0.1.0", 24)
        s43 = VppGbpSubnet(self, 0, "10.0.2.0", 24)
        s41.add_vpp_config()
        s42.add_vpp_config()
        s43.add_vpp_config()
        s61 = VppGbpSubnet(self, 0, "2001:10::1", 64)
        s62 = VppGbpSubnet(self, 0, "2001:10:1::1", 64)
        s63 = VppGbpSubnet(self, 0, "2001:10:2::1", 64)
        s61.add_vpp_config()
        s62.add_vpp_config()
        s63.add_vpp_config()

        self.send_and_expect_bridged(self.pg0,
                                     pkt_intra_epg_220_ip4 * 65,
                                     self.pg4)
        self.send_and_expect_bridged(self.pg3,
                                     pkt_inter_epg_222_ip4 * 65,
                                     self.pg6)
        self.send_and_expect_bridged6(self.pg3,
                                      pkt_inter_epg_222_ip6 * 65,
                                      self.pg6)

        self.logger.info(self.vapi.cli("sh ip fib 11.0.0.2"))
        self.logger.info(self.vapi.cli("sh gbp endpoint-group"))
        self.logger.info(self.vapi.cli("sh gbp endpoint"))
        self.logger.info(self.vapi.cli("sh gbp recirc"))
        self.logger.info(self.vapi.cli("sh int"))
        self.logger.info(self.vapi.cli("sh int addr"))
        self.logger.info(self.vapi.cli("sh int feat loop6"))
        self.logger.info(self.vapi.cli("sh vlib graph ip4-gbp-src-classify"))
        self.logger.info(self.vapi.cli("sh int feat loop3"))

        #
        # Packet destined to unknown unicast is sent on the epg uplink ...
        #
        pkt_intra_epg_220_to_uplink = (Ether(src=self.pg0.remote_mac,
                                             dst="00:00:00:33:44:55") /
                                       IP(src=eps[0].ip4.address,
                                          dst="10.0.0.99") /
                                       UDP(sport=1234, dport=1234) /
                                       Raw('\xa5' * 100))

        self.send_and_expect_bridged(self.pg0,
                                     pkt_intra_epg_220_to_uplink * 65,
                                     self.pg4)
        # ... and nowhere else
        self.pg1.get_capture(0, timeout=0.1)
        self.pg1.assert_nothing_captured(remark="Flood onto other VMS")

        pkt_intra_epg_221_to_uplink = (Ether(src=self.pg2.remote_mac,
                                             dst="00:00:00:33:44:66") /
                                       IP(src=eps[0].ip4.address,
                                          dst="10.0.0.99") /
                                       UDP(sport=1234, dport=1234) /
                                       Raw('\xa5' * 100))

        self.send_and_expect_bridged(self.pg2,
                                     pkt_intra_epg_221_to_uplink * 65,
                                     self.pg5)

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
                                          dst=self.router_mac) /
                                    IP(src=eps[0].ip4.address,
                                       dst=eps[3].ip4.address) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw('\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_220_to_221 * 65)
        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_220_to_222 * 65)

        #
        # A uni-directional contract from EPG 220 -> 221
        #
        acl = VppGbpAcl(self)
        rule = acl.create_rule(permit_deny=1, proto=17)
        rule2 = acl.create_rule(is_ipv6=1, permit_deny=1, proto=17)
        acl_index = acl.add_vpp_config([rule, rule2])
        c1 = VppGbpContract(self, 220, 221, acl_index)
        c1.add_vpp_config()

        self.send_and_expect_bridged(self.pg0,
                                     pkt_inter_epg_220_to_221 * 65,
                                     self.pg2)
        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_220_to_222 * 65)

        #
        # contract for the return direction
        #
        c2 = VppGbpContract(self, 221, 220, acl_index)
        c2.add_vpp_config()

        self.send_and_expect_bridged(self.pg0,
                                     pkt_inter_epg_220_to_221 * 65,
                                     self.pg2)
        self.send_and_expect_bridged(self.pg2,
                                     pkt_inter_epg_221_to_220 * 65,
                                     self.pg0)

        #
        # check that inter group is still disabled for the groups
        # not in the contract.
        #
        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_220_to_222 * 65)

        #
        # A uni-directional contract from EPG 220 -> 222 'L3 routed'
        #
        c3 = VppGbpContract(self, 220, 222, acl_index)
        c3.add_vpp_config()

        self.logger.info(self.vapi.cli("sh gbp contract"))

        self.send_and_expect_routed(self.pg0,
                                    pkt_inter_epg_220_to_222 * 65,
                                    self.pg3,
                                    self.router_mac)

        #
        # remove both contracts, traffic stops in both directions
        #
        c2.remove_vpp_config()
        c1.remove_vpp_config()
        c3.remove_vpp_config()
        acl.remove_vpp_config()

        self.send_and_assert_no_replies(self.pg2,
                                        pkt_inter_epg_221_to_220 * 65)
        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_220_to_221 * 65)
        self.send_and_expect_bridged(self.pg0, pkt_intra_epg * 65, self.pg1)

        #
        # EPs to the outside world
        #

        # in the EP's RD an external subnet via the NAT EPG's recirc
        se1 = VppGbpSubnet(self, 0, "0.0.0.0", 0,
                           is_internal=False,
                           sw_if_index=recirc_nat.recirc.sw_if_index,
                           epg=epg_nat.epg)
        se1.add_vpp_config()
        se2 = VppGbpSubnet(self, 0, "11.0.0.0", 8,
                           is_internal=False,
                           sw_if_index=recirc_nat.recirc.sw_if_index,
                           epg=epg_nat.epg)
        se2.add_vpp_config()
        se16 = VppGbpSubnet(self, 0, "::", 0,
                            is_internal=False,
                            sw_if_index=recirc_nat.recirc.sw_if_index,
                            epg=epg_nat.epg)
        se16.add_vpp_config()
        # in the NAT RD an external subnet via the NAT EPG's uplink
        se3 = VppGbpSubnet(self, 20, "0.0.0.0", 0,
                           is_internal=False,
                           sw_if_index=epg_nat.uplink.sw_if_index,
                           epg=epg_nat.epg)
        se36 = VppGbpSubnet(self, 20, "::", 0,
                            is_internal=False,
                            sw_if_index=epg_nat.uplink.sw_if_index,
                            epg=epg_nat.epg)
        se4 = VppGbpSubnet(self, 20, "11.0.0.0", 8,
                           is_internal=False,
                           sw_if_index=epg_nat.uplink.sw_if_index,
                           epg=epg_nat.epg)
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
                                             dst=self.router_mac) /
                                       IP(src=eps[0].ip4.address,
                                          dst="1.1.1.1") /
                                       UDP(sport=1234, dport=1234) /
                                       Raw('\xa5' * 100))

        # no policy yet
        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_220_to_global * 65)

        acl2 = VppGbpAcl(self)
        rule = acl2.create_rule(permit_deny=1, proto=17, sport_from=1234,
                                sport_to=1234, dport_from=1234, dport_to=1234)
        rule2 = acl2.create_rule(is_ipv6=1, permit_deny=1, proto=17,
                                 sport_from=1234, sport_to=1234,
                                 dport_from=1234, dport_to=1234)

        acl_index2 = acl2.add_vpp_config([rule, rule2])
        c4 = VppGbpContract(self, 220, 333, acl_index2)
        c4.add_vpp_config()

        self.send_and_expect_natted(self.pg0,
                                    pkt_inter_epg_220_to_global * 65,
                                    self.pg7,
                                    eps[0].fip4.address)

        pkt_inter_epg_220_to_global = (Ether(src=self.pg0.remote_mac,
                                             dst=self.router_mac) /
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
        pkt_inter_epg_220_from_global = (Ether(src=self.router_mac,
                                               dst=self.pg0.remote_mac) /
                                         IP(dst=eps[0].fip4.address,
                                            src="1.1.1.1") /
                                         UDP(sport=1234, dport=1234) /
                                         Raw('\xa5' * 100))

        self.send_and_assert_no_replies(self.pg7,
                                        pkt_inter_epg_220_from_global * 65)

        c5 = VppGbpContract(self, 333, 220, acl_index2)
        c5.add_vpp_config()

        self.send_and_expect_unnatted(self.pg7,
                                      pkt_inter_epg_220_from_global * 65,
                                      eps[0].itf,
                                      eps[0].ip4.address)

        pkt_inter_epg_220_from_global = (Ether(src=self.router_mac,
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
                                          dst=self.router_mac) /
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
                                          dst=self.router_mac) /
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
            self.vapi.sw_interface_add_del_address(epg.bvi.sw_if_index,
                                                   epg.bvi_ip4_n,
                                                   32,
                                                   is_add=0)
            self.vapi.sw_interface_add_del_address(epg.bvi.sw_if_index,
                                                   epg.bvi_ip6_n,
                                                   128,
                                                   is_add=0,
                                                   is_ipv6=True)
            self.logger.info(self.vapi.cli("sh int addr"))

            epg.uplink.set_table_ip4(0)
            epg.uplink.set_table_ip6(0)

            if epg != epgs[0] and epg != epgs[3]:
                epg.bvi.set_table_ip4(0)
                epg.bvi.set_table_ip6(0)

                self.vapi.nat44_interface_add_del_feature(epg.bvi.sw_if_index,
                                                          is_inside=1,
                                                          is_add=0)
                self.vapi.nat66_add_del_interface(epg.bvi.sw_if_index,
                                                  is_inside=1,
                                                  is_add=0)

        for recirc in recircs:
            recirc.recirc.set_table_ip4(0)
            recirc.recirc.set_table_ip6(0)

            self.vapi.nat44_interface_add_del_feature(
                recirc.recirc.sw_if_index,
                is_inside=0,
                is_add=0)
            self.vapi.nat66_add_del_interface(
                recirc.recirc.sw_if_index,
                is_inside=0,
                is_add=0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
