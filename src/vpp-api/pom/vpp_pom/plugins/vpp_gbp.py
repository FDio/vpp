from ipaddress import ip_address, IPv4Network, IPv6Network

from vpp_papi import VppEnum, MACAddress
from vpp_pom.vpp_object import VppObject
from vpp_pom.vpp_interface import VppInterface
from vpp_pom.vpp_vxlan_gbp_tunnel import INDEX_INVALID


def find_gbp_endpoint(vclient, sw_if_index=None, ip=None, mac=None,
                      tep=None, sclass=None, flags=None):
    if ip:
        vip = ip
    if mac:
        vmac = MACAddress(mac)

    eps = vclient.gbp_endpoint_dump()

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


def find_gbp_vxlan(vclient, vni):
    ts = vclient.gbp_vxlan_tunnel_dump()
    for t in ts:
        if t.tunnel.vni == vni:
            return True
    return False


class VppGbpEndpointRetention(object):
    def __init__(self, remote_ep_timeout=0xffffffff):
        self.remote_ep_timeout = remote_ep_timeout

    def encode(self):
        return {'remote_ep_timeout': self.remote_ep_timeout}


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

    def __init__(self, vclient, itf, epg, recirc, ip4, fip4, ip6, fip6,
                 flags=0,
                 tun_src="0.0.0.0",
                 tun_dst="0.0.0.0",
                 mac=True):
        self._vclient = vclient
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
        res = self._vclient.gbp_endpoint_add(
            self.itf.sw_if_index,
            [self.ip4, self.ip6],
            self.vmac.packed,
            self.epg.sclass,
            self.flags,
            self.tun_src,
            self.tun_dst)
        self.handle = res.handle
        self._vclient.registry.register(self, self._vclient.logger)

    def remove_vpp_config(self):
        self._vclient.gbp_endpoint_del(self.handle)

    def object_id(self):
        return "gbp-endpoint:[%d==%d:%s:%d]" % (self.handle,
                                                self.itf.sw_if_index,
                                                self.ip4,
                                                self.epg.sclass)

    def query_vpp_config(self):
        return find_gbp_endpoint(self._vclient,
                                 self.itf.sw_if_index,
                                 self.ip4)


class VppGbpRecirc(VppObject):
    """
    GBP Recirculation Interface
    """

    def __init__(self, vclient, epg, recirc, is_ext=False):
        self._vclient = vclient
        self.recirc = recirc
        self.epg = epg
        self.is_ext = is_ext

    def add_vpp_config(self):
        self._vclient.gbp_recirc_add_del(
            1,
            self.recirc.sw_if_index,
            self.epg.sclass,
            self.is_ext)
        self._vclient.registry.register(self, self._vclient.logger)

    def remove_vpp_config(self):
        self._vclient.gbp_recirc_add_del(
            0,
            self.recirc.sw_if_index,
            self.epg.sclass,
            self.is_ext)

    def object_id(self):
        return "gbp-recirc:[%d]" % (self.recirc.sw_if_index)

    def query_vpp_config(self):
        rs = self._vclient.gbp_recirc_dump()
        for r in rs:
            if r.recirc.sw_if_index == self.recirc.sw_if_index:
                return True
        return False


class VppGbpExtItf(VppObject):
    """
    GBP ExtItfulation Interface
    """

    def __init__(self, vclient, itf, bd, rd, anon=False):
        self._vclient = vclient
        self.itf = itf
        self.bd = bd
        self.rd = rd
        self.flags = 1 if anon else 0

    def add_vpp_config(self):
        self._vclient.gbp_ext_itf_add_del(
            1, self.itf.sw_if_index, self.bd.bd_id, self.rd.rd_id, self.flags)
        self._vclient.registry.register(self, self._vclient.logger)

    def remove_vpp_config(self):
        self._vclient.gbp_ext_itf_add_del(
            0, self.itf.sw_if_index, self.bd.bd_id, self.rd.rd_id, self.flags)

    def object_id(self):
        return "gbp-ext-itf:[%d]%s" % (self.itf.sw_if_index,
                                       " [anon]" if self.flags else "")

    def query_vpp_config(self):
        rs = self._vclient.gbp_ext_itf_dump()
        for r in rs:
            if r.ext_itf.sw_if_index == self.itf.sw_if_index:
                return True
        return False


class VppGbpSubnet(VppObject):
    """
    GBP Subnet
    """

    def __init__(self, vclient, rd, address, address_len,
                 type, sw_if_index=None, sclass=None):
        self._vclient = vclient
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
        self._vclient.gbp_subnet_add_del(
            1,
            self.rd_id,
            self.prefix,
            self.type,
            sw_if_index=self.sw_if_index if self.sw_if_index else 0xffffffff,
            sclass=self.sclass if self.sclass else 0xffff)
        self._vclient.registry.register(self, self._vclient.logger)

    def remove_vpp_config(self):
        self._vclient.gbp_subnet_add_del(
            0,
            self.rd_id,
            self.prefix,
            self.type)

    def object_id(self):
        return "gbp-subnet:[%d-%s]" % (self.rd_id, self.prefix)

    def query_vpp_config(self):
        ss = self._vclient.gbp_subnet_dump()
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

    def __init__(self, vclient, vnid, sclass, rd, bd, uplink,
                 bvi, bvi_ip4, bvi_ip6=None,
                 retention=VppGbpEndpointRetention()):
        self._vclient = vclient
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
        self._vclient.gbp_endpoint_group_add(
            self.vnid,
            self.sclass,
            self.bd.bd.bd_id,
            self.rd.rd_id,
            self.uplink.sw_if_index if self.uplink else INDEX_INVALID,
            self.retention.encode())
        self._vclient.registry.register(self, self._vclient.logger)

    def remove_vpp_config(self):
        self._vclient.gbp_endpoint_group_del(self.sclass)

    def object_id(self):
        return "gbp-endpoint-group:[%d]" % (self.vnid)

    def query_vpp_config(self):
        epgs = self._vclient.gbp_endpoint_group_dump()
        for epg in epgs:
            if epg.epg.vnid == self.vnid:
                return True
        return False


class VppGbpBridgeDomain(VppObject):
    """
    GBP Bridge Domain
    """

    def __init__(self, vclient, bd, rd, bvi, uu_fwd=None,
                 bm_flood=None, learn=True,
                 uu_drop=False, bm_drop=False,
                 ucast_arp=False):
        self._vclient = vclient
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
        self._vclient.gbp_bridge_domain_add(
            self.bd.bd_id,
            self.rd.rd_id,
            self.flags,
            self.bvi.sw_if_index,
            self.uu_fwd.sw_if_index if self.uu_fwd else INDEX_INVALID,
            self.bm_flood.sw_if_index if self.bm_flood else INDEX_INVALID)
        self._vclient.registry.register(self, self._vclient.logger)

    def remove_vpp_config(self):
        self._vclient.gbp_bridge_domain_del(self.bd.bd_id)

    def object_id(self):
        return "gbp-bridge-domain:[%d]" % (self.bd.bd_id)

    def query_vpp_config(self):
        bds = self._vclient.gbp_bridge_domain_dump()
        for bd in bds:
            if bd.bd.bd_id == self.bd.bd_id:
                return True
        return False


class VppGbpRouteDomain(VppObject):
    """
    GBP Route Domain
    """

    def __init__(self, vclient, rd_id, scope, t4, t6, ip4_uu=None, ip6_uu=None):
        self._vclient = vclient
        self.rd_id = rd_id
        self.scope = scope
        self.t4 = t4
        self.t6 = t6
        self.ip4_uu = ip4_uu
        self.ip6_uu = ip6_uu

    def add_vpp_config(self):
        self._vclient.gbp_route_domain_add(
            self.rd_id,
            self.scope,
            self.t4.table_id,
            self.t6.table_id,
            self.ip4_uu.sw_if_index if self.ip4_uu else INDEX_INVALID,
            self.ip6_uu.sw_if_index if self.ip6_uu else INDEX_INVALID)
        self._vclient.registry.register(self, self._vclient.logger)

    def remove_vpp_config(self):
        self._vclient.gbp_route_domain_del(self.rd_id)

    def object_id(self):
        return "gbp-route-domain:[%d]" % (self.rd_id)

    def query_vpp_config(self):
        rds = self._vclient.gbp_route_domain_dump()
        for rd in rds:
            if rd.rd.rd_id == self.rd_id:
                return True
        return False


class VppGbpContract(VppObject):
    """
    GBP Contract
    """

    def __init__(self, vclient, scope, sclass, dclass, acl_index,
                 rules, allowed_ethertypes):
        self._vclient = vclient
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
        r = self._vclient.gbp_contract_add_del(
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
        self._vclient.registry.register(self, self._vclient.logger)

    def remove_vpp_config(self):
        self._vclient.gbp_contract_add_del(
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
        cs = self._vclient.gbp_contract_dump()
        for c in cs:
            if c.contract.scope == self.scope \
               and c.contract.sclass == self.sclass \
               and c.contract.dclass == self.dclass:
                return True
        return False

    def get_drop_stats(self):
        c = self._vclient.statistics.get_counter("/net/gbp/contract/drop")
        return c[0][self.stats_index]

    def get_permit_stats(self):
        c = self._vclient.statistics.get_counter("/net/gbp/contract/permit")
        return c[0][self.stats_index]


class VppGbpVxlanTunnel(VppInterface):
    """
    GBP VXLAN tunnel
    """

    def __init__(self, vclient, vni, bd_rd_id, mode, src):
        super(VppGbpVxlanTunnel, self).__init__(vclient)
        self._vclient = vclient
        self.vni = vni
        self.bd_rd_id = bd_rd_id
        self.mode = mode
        self.src = src

    def add_vpp_config(self):
        r = self._vclient.gbp_vxlan_tunnel_add(
            self.vni,
            self.bd_rd_id,
            self.mode,
            self.src)
        self.set_sw_if_index(r.sw_if_index)
        self._vclient.registry.register(self, self._vclient.logger)

    def remove_vpp_config(self):
        self._vclient.gbp_vxlan_tunnel_del(self.vni)

    def object_id(self):
        return "gbp-vxlan:%d" % (self.sw_if_index)

    def query_vpp_config(self):
        return find_gbp_vxlan(self._vclient, self.vni)
